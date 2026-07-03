// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Conversions between the generated proto types and the rust-tap core
//! types, mirroring tapd's marshaling code exactly.
//!
//! # Byte-order and key-encoding rules (with Go references)
//!
//! - `universerpc.ID.asset_id` (bytes): the raw 32 asset ID bytes, no
//!   reversal (Go `MarshalUniID`, rpcserver.go).
//! - `universerpc.ID.group_key` (bytes): the 32-byte x-only key,
//!   Go marshals with `schnorr.SerializePubKey` (`MarshalUniID`) and
//!   unmarshals 32- or 33-byte keys with `rpcutils.ParseUserKey`,
//!   which drops the parity byte. rust-tap's 33-byte
//!   [`SerializedKey`] is therefore truncated to x-only on the way
//!   out and normalized back with an even-parity `0x02` prefix on the
//!   way in.
//! - `universerpc.Outpoint.hash_str`: the txid as a hex string in
//!   DISPLAY order (reversed from internal), Go marshals with
//!   `chainhash.Hash.String()` (`rpcutils.MarshalOutpoint`) and
//!   parses with `chainhash.NewHashFromStr` (`unmarshalLeafKey`).
//! - `universerpc.AssetKey.op_str`: `"<txid>:<vout>"` with the txid
//!   in DISPLAY order (Go `marshalLeafKey` uses
//!   `wire.OutPoint.String()`).
//! - `universerpc.AssetKey.script_key_bytes`: tapd EMITS the 32-byte
//!   x-only key (`marshalLeafKey` uses `schnorr.SerializePubKey`) but
//!   ACCEPTS 32 or 33 bytes (`unmarshalLeafKey` via `ParseUserKey`).
//!   We emit the x-only form for wire equality with tapd and accept
//!   both, normalizing to a `0x02`-prefixed 33-byte key.
//! - `taprpc.OutPoint.txid` (bytes, used by the mailbox tx proof):
//!   raw txid bytes in INTERNAL (little-endian wire) order, per the
//!   proto doc in `tapcommon.proto` and Go `proof.MarshalTxProof`
//!   (`ClaimedOutPoint.Hash[:]`).
//! - `universerpc.MerkleSumNode`: `root_hash` is the raw 32-byte
//!   MS-SMT node hash, `root_sum` is an `int64` on the wire but a
//!   `u64` internally (Go `marshalMssmtNode` casts).
//! - `universerpc.ProofType`: ISSUANCE = 1, TRANSFER = 2. The
//!   supply-commitment proof types (ignore/burn/mint_supply) are not
//!   representable over the universe RPC and map to an error.
//! - `authmailboxrpc.MerkleProof`: `sibling_hashes` are internal-order
//!   node hashes; `bits[i]` = true means the sibling is on the RIGHT
//!   (we are the left child), identical semantics in Go
//!   `proof.TxMerkleProof.Bits` and rust
//!   [`tap_primitives::proof::TxMerkleProof::bits`], so the vectors
//!   copy across 1:1 (Go `proof.MarshalTxProof`).

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;
use tap_primitives::proof::tx_proof::TxProof;
use tap_primitives::proof::types::{AnchorTx, BlockHeader};
use tap_primitives::proof::TxMerkleProof;
use tap_universe::types::{
    LeafKey, ProofType, UniverseError, UniverseId, UniverseRoot,
};

use crate::authmailboxrpc;
use crate::taprpc;
use crate::universerpc;

/// A conversion error: the proto message cannot be represented as (or
/// built from) the corresponding rust-tap type.
#[derive(Debug, Clone)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proto conversion error: {}", self.0)
    }
}

impl std::error::Error for ConvertError {}

impl From<ConvertError> for UniverseError {
    fn from(e: ConvertError) -> Self {
        UniverseError::SyncError(e.to_string())
    }
}

fn err(msg: impl Into<String>) -> ConvertError {
    ConvertError(msg.into())
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, ConvertError> {
    if s.len() % 2 != 0 {
        return Err(err("odd-length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| err(format!("invalid hex: {}", e)))
        })
        .collect()
}

fn to_array<const N: usize>(
    bytes: &[u8],
    what: &str,
) -> Result<[u8; N], ConvertError> {
    let mut out = [0u8; N];
    if bytes.len() != N {
        return Err(err(format!(
            "{}: expected {} bytes, got {}",
            what,
            N,
            bytes.len()
        )));
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Normalizes a 32-byte x-only or 33-byte compressed public key into a
/// 33-byte [`SerializedKey`]. X-only keys get an even-parity `0x02`
/// prefix, matching the effect of Go's `rpcutils.ParseUserKey` (which
/// drops the parity byte and re-parses as a BIP-340 key).
pub fn normalize_user_key(
    bytes: &[u8],
) -> Result<SerializedKey, ConvertError> {
    let mut key = [0u8; 33];
    match bytes.len() {
        33 => key.copy_from_slice(bytes),
        32 => {
            key[0] = 0x02;
            key[1..].copy_from_slice(bytes);
        }
        n => return Err(err(format!("public key has invalid length {}", n))),
    }
    Ok(SerializedKey(key))
}

// ---------------------------------------------------------------------------
// Proof type
// ---------------------------------------------------------------------------

/// Maps a rust-tap [`ProofType`] to the RPC enum. Only issuance and
/// transfer trees are served over the universe RPC (Go
/// `MarshalUniProofType`).
pub fn proof_type_to_proto(
    proof_type: ProofType,
) -> Result<universerpc::ProofType, ConvertError> {
    match proof_type {
        ProofType::Issuance => Ok(universerpc::ProofType::Issuance),
        ProofType::Transfer => Ok(universerpc::ProofType::Transfer),
        ProofType::Ignore | ProofType::Burn | ProofType::MintSupply => {
            Err(err(format!(
                "proof type {} not supported over universe RPC",
                proof_type.as_str()
            )))
        }
    }
}

/// Maps the RPC proof type enum (as the raw i32 prost representation)
/// to a rust-tap [`ProofType`]. Unspecified/unknown values are an
/// error (Go `UnmarshalUniProofType` rejects unknown values; callers
/// that tolerate unspecified handle it before calling this).
pub fn proof_type_from_proto(value: i32) -> Result<ProofType, ConvertError> {
    match universerpc::ProofType::try_from(value) {
        Ok(universerpc::ProofType::Issuance) => Ok(ProofType::Issuance),
        Ok(universerpc::ProofType::Transfer) => Ok(ProofType::Transfer),
        Ok(universerpc::ProofType::Unspecified) => {
            Err(err("proof type must be specified"))
        }
        Err(_) => Err(err(format!("unknown proof type {}", value))),
    }
}

// ---------------------------------------------------------------------------
// Universe ID
// ---------------------------------------------------------------------------

/// Marshals a [`UniverseId`] into the RPC `ID`, mirroring Go's
/// `MarshalUniID`: group-key universes carry the 32-byte x-only group
/// key; otherwise the raw asset ID bytes are used.
pub fn universe_id_to_proto(
    id: &UniverseId,
) -> Result<universerpc::Id, ConvertError> {
    let inner = match &id.group_key {
        // Go: schnorr.SerializePubKey => x-only 32 bytes.
        Some(gk) => universerpc::id::Id::GroupKey(gk.as_bytes()[1..].to_vec()),
        None => universerpc::id::Id::AssetId(id.asset_id.0.to_vec()),
    };
    Ok(universerpc::Id {
        proof_type: proof_type_to_proto(id.proof_type)? as i32,
        id: Some(inner),
    })
}

/// Unmarshals an RPC `ID` into a [`UniverseId`], accepting all four
/// oneof variants like Go's `UnmarshalUniID`. Group-key universes get
/// a zero asset ID (the pair is keyed by the group key).
pub fn universe_id_from_proto(
    id: &universerpc::Id,
) -> Result<UniverseId, ConvertError> {
    let proof_type = proof_type_from_proto(id.proof_type)?;
    universe_id_from_proto_parts(id, proof_type)
}

/// Like [`universe_id_from_proto`] but with the proof type resolved by
/// the caller (for requests where the proof type may legitimately be
/// unspecified and defaulted).
pub fn universe_id_from_proto_parts(
    id: &universerpc::Id,
    proof_type: ProofType,
) -> Result<UniverseId, ConvertError> {
    use universerpc::id::Id as ProtoId;

    let (asset_id, group_key) = match id
        .id
        .as_ref()
        .ok_or_else(|| err("id must set one of asset_id or group_key"))?
    {
        ProtoId::AssetId(bytes) => {
            (AssetId(to_array(bytes, "asset_id")?), None)
        }
        ProtoId::AssetIdStr(s) => {
            let bytes = hex_decode(s)?;
            (AssetId(to_array(&bytes, "asset_id_str")?), None)
        }
        ProtoId::GroupKey(bytes) => {
            (AssetId([0u8; 32]), Some(normalize_user_key(bytes)?))
        }
        ProtoId::GroupKeyStr(s) => {
            let bytes = hex_decode(s)?;
            (AssetId([0u8; 32]), Some(normalize_user_key(&bytes)?))
        }
    };

    Ok(UniverseId {
        asset_id,
        group_key,
        proof_type,
    })
}

// ---------------------------------------------------------------------------
// Leaf key / outpoint
// ---------------------------------------------------------------------------

/// Returns the txid of an internal-order outpoint as a display-order
/// hex string (Go: `chainhash.Hash.String()`).
pub fn txid_display_hex(outpoint: &OutPoint) -> String {
    let mut display = outpoint.txid;
    display.reverse();
    hex_encode(&display)
}

/// Marshals a [`LeafKey`] into the RPC `AssetKey`, mirroring Go's
/// `marshalLeafKey`: the outpoint travels as `op_str` (`"txid:vout"`,
/// display order) and the script key as the 32-byte x-only
/// `script_key_bytes`.
pub fn leaf_key_to_proto(key: &LeafKey) -> universerpc::AssetKey {
    universerpc::AssetKey {
        outpoint: Some(universerpc::asset_key::Outpoint::OpStr(format!(
            "{}:{}",
            txid_display_hex(&key.outpoint),
            key.outpoint.vout
        ))),
        script_key: Some(
            universerpc::asset_key::ScriptKey::ScriptKeyBytes(
                key.script_key.as_bytes()[1..].to_vec(),
            ),
        ),
    }
}

/// Parses a display-order txid hex string into an internal-order 32
/// byte array.
fn txid_from_display_hex(s: &str) -> Result<[u8; 32], ConvertError> {
    let bytes = hex_decode(s)?;
    let mut txid: [u8; 32] = to_array(&bytes, "txid")?;
    txid.reverse();
    Ok(txid)
}

/// Unmarshals an RPC `AssetKey` into a [`LeafKey`], accepting both
/// outpoint forms and both script key forms like Go's
/// `unmarshalLeafKey`.
pub fn leaf_key_from_proto(
    key: &universerpc::AssetKey,
) -> Result<LeafKey, ConvertError> {
    use universerpc::asset_key::{Outpoint as ProtoOp, ScriptKey as ProtoSk};

    let outpoint = match key
        .outpoint
        .as_ref()
        .ok_or_else(|| err("asset key missing outpoint"))?
    {
        ProtoOp::OpStr(s) => {
            let (txid, vout) = s
                .split_once(':')
                .ok_or_else(|| err(format!("malformed op_str {:?}", s)))?;
            OutPoint {
                txid: txid_from_display_hex(txid)?,
                vout: vout.parse::<u32>().map_err(|e| {
                    err(format!("malformed op_str vout: {}", e))
                })?,
            }
        }
        ProtoOp::Op(op) => OutPoint {
            txid: txid_from_display_hex(&op.hash_str)?,
            vout: u32::try_from(op.index)
                .map_err(|_| err("negative outpoint index"))?,
        },
    };

    let script_key = match key
        .script_key
        .as_ref()
        .ok_or_else(|| err("asset key missing script key"))?
    {
        ProtoSk::ScriptKeyBytes(bytes) => normalize_user_key(bytes)?,
        ProtoSk::ScriptKeyStr(s) => normalize_user_key(&hex_decode(s)?)?,
    };

    Ok(LeafKey {
        outpoint,
        script_key,
    })
}

// ---------------------------------------------------------------------------
// MS-SMT nodes / universe roots
// ---------------------------------------------------------------------------

/// Marshals a root hash and sum into a `MerkleSumNode` (Go
/// `marshalMssmtNode`).
pub fn merkle_sum_node_to_proto(
    root_hash: &NodeHash,
    root_sum: u64,
) -> universerpc::MerkleSumNode {
    universerpc::MerkleSumNode {
        root_hash: root_hash.0.to_vec(),
        root_sum: root_sum as i64,
    }
}

/// Unmarshals a `MerkleSumNode`. Negative sums are rejected (Go casts
/// `uint64(root.RootSum)`; a negative value can only appear from a
/// non-tapd peer and would silently wrap there).
pub fn merkle_sum_node_from_proto(
    node: &universerpc::MerkleSumNode,
) -> Result<(NodeHash, u64), ConvertError> {
    let hash = NodeHash(to_array(&node.root_hash, "root_hash")?);
    let sum = u64::try_from(node.root_sum)
        .map_err(|_| err("negative root_sum"))?;
    Ok((hash, sum))
}

/// Marshals a [`UniverseRoot`] (Go `marshalUniverseRoot`; the asset
/// name and grouped amounts are not tracked by rust-tap backends and
/// are left empty).
pub fn universe_root_to_proto(
    root: &UniverseRoot,
) -> Result<universerpc::UniverseRoot, ConvertError> {
    Ok(universerpc::UniverseRoot {
        id: Some(universe_id_to_proto(&root.id)?),
        mssmt_root: Some(merkle_sum_node_to_proto(
            &root.root_hash,
            root.root_sum,
        )),
        asset_name: String::new(),
        amounts_by_asset_id: Default::default(),
    })
}

/// Unmarshals a `UniverseRoot`. Roots without an ID or MS-SMT node are
/// an error; use [`is_empty_universe_root`] first where tapd signals
/// absence with an empty message.
pub fn universe_root_from_proto(
    root: &universerpc::UniverseRoot,
) -> Result<UniverseRoot, ConvertError> {
    let id = universe_id_from_proto(
        root.id.as_ref().ok_or_else(|| err("universe root missing id"))?,
    )?;
    let (root_hash, root_sum) = merkle_sum_node_from_proto(
        root.mssmt_root
            .as_ref()
            .ok_or_else(|| err("universe root missing mssmt_root"))?,
    )?;
    Ok(UniverseRoot {
        id,
        root_hash,
        root_sum,
    })
}

/// True if the root message signals "no such universe": tapd marshals
/// an absent root as an all-empty `UniverseRoot` (Go
/// `marshalUniverseRoot` with a nil node, detected client-side by
/// `universe.IsEmptyRootResponse`).
pub fn is_empty_universe_root(
    root: Option<&universerpc::UniverseRoot>,
) -> bool {
    match root {
        None => true,
        Some(root) => root.id.is_none() && root.mssmt_root.is_none(),
    }
}

// ---------------------------------------------------------------------------
// Mailbox tx proof
// ---------------------------------------------------------------------------

/// Marshals a [`TxProof`] into the mailbox RPC form, mirroring Go's
/// `proof.MarshalTxProof`: the tx and header travel as raw consensus
/// bytes, the claimed outpoint txid in INTERNAL byte order, the
/// internal key compressed (33 bytes), and the merkle root as empty
/// bytes when absent (BIP-86).
pub fn tx_proof_to_proto(
    proof: &TxProof,
) -> authmailboxrpc::BitcoinMerkleInclusionProof {
    authmailboxrpc::BitcoinMerkleInclusionProof {
        raw_tx_data: proof.msg_tx.to_bytes(),
        raw_block_header_data: proof.block_header.as_bytes().to_vec(),
        block_height: proof.block_height,
        merkle_proof: Some(authmailboxrpc::MerkleProof {
            sibling_hashes: proof
                .merkle_proof
                .nodes
                .iter()
                .map(|n| n.to_vec())
                .collect(),
            bits: proof.merkle_proof.bits.clone(),
        }),
        claimed_outpoint: Some(taprpc::OutPoint {
            txid: proof.claimed_outpoint.txid.to_vec(),
            output_index: proof.claimed_outpoint.vout,
        }),
        internal_key: proof.internal_key.as_bytes().to_vec(),
        merkle_root: proof.merkle_root.map(|r| r.to_vec()).unwrap_or_default(),
    }
}

/// Unmarshals a mailbox RPC tx proof, mirroring Go's
/// `proof.UnmarshalTxProof` (used by mailbox servers and tests).
pub fn tx_proof_from_proto(
    proof: &authmailboxrpc::BitcoinMerkleInclusionProof,
) -> Result<TxProof, ConvertError> {
    let msg_tx = AnchorTx::from_bytes(&proof.raw_tx_data)
        .map_err(|e| err(format!("invalid raw_tx_data: {}", e)))?;
    let block_header = BlockHeader(to_array(
        &proof.raw_block_header_data,
        "raw_block_header_data",
    )?);

    let merkle_proof = proof
        .merkle_proof
        .as_ref()
        .ok_or_else(|| err("merkle proof is missing"))?;
    let nodes = merkle_proof
        .sibling_hashes
        .iter()
        .map(|h| to_array(h, "sibling hash"))
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    if nodes.len() != merkle_proof.bits.len() {
        return Err(err("merkle proof nodes/bits length mismatch"));
    }

    let claimed = proof
        .claimed_outpoint
        .as_ref()
        .ok_or_else(|| err("claimed outpoint is missing"))?;

    Ok(TxProof {
        msg_tx,
        block_header,
        block_height: proof.block_height,
        merkle_proof: TxMerkleProof {
            nodes,
            bits: merkle_proof.bits.clone(),
        },
        claimed_outpoint: OutPoint {
            // taprpc.OutPoint.txid is raw internal-order bytes.
            txid: to_array(&claimed.txid, "claimed outpoint txid")?,
            vout: claimed.output_index,
        },
        internal_key: SerializedKey(to_array(
            &proof.internal_key,
            "internal key",
        )?),
        merkle_root: if proof.merkle_root.is_empty() {
            None
        } else {
            Some(to_array(&proof.merkle_root, "merkle root")?)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_universe_id(group: bool) -> UniverseId {
        UniverseId {
            asset_id: AssetId([0x11; 32]),
            group_key: group.then(|| SerializedKey([0x03; 33])),
            proof_type: ProofType::Transfer,
        }
    }

    /// Asset-ID universes: raw bytes, no reversal, proof type enum
    /// values pinned to the proto (ISSUANCE=1, TRANSFER=2).
    #[test]
    fn test_universe_id_roundtrip_asset() {
        let id = UniverseId {
            proof_type: ProofType::Issuance,
            ..test_universe_id(false)
        };
        let proto = universe_id_to_proto(&id).unwrap();
        assert_eq!(proto.proof_type, 1);
        assert_eq!(
            proto.id,
            Some(universerpc::id::Id::AssetId(vec![0x11; 32]))
        );
        assert_eq!(universe_id_from_proto(&proto).unwrap(), id);

        let transfer = test_universe_id(false);
        let proto = universe_id_to_proto(&transfer).unwrap();
        assert_eq!(proto.proof_type, 2);
    }

    /// Group-key universes travel as the 32-byte x-only key (parity
    /// byte dropped, like Go's schnorr.SerializePubKey) and come back
    /// normalized with a 0x02 prefix. The asset ID zeroes out.
    #[test]
    fn test_universe_id_roundtrip_group() {
        let id = test_universe_id(true);
        let proto = universe_id_to_proto(&id).unwrap();
        assert_eq!(
            proto.id,
            Some(universerpc::id::Id::GroupKey(vec![0x03; 32]))
        );

        let back = universe_id_from_proto(&proto).unwrap();
        let gk = back.group_key.expect("group key");
        assert_eq!(gk.0[0], 0x02);
        assert_eq!(&gk.0[1..], &[0x03; 32]);
        assert_eq!(back.asset_id, AssetId([0u8; 32]));
    }

    /// Hex string ID variants (REST form) are accepted too.
    #[test]
    fn test_universe_id_from_hex_variants() {
        let proto = universerpc::Id {
            proof_type: 1,
            id: Some(universerpc::id::Id::AssetIdStr("22".repeat(32))),
        };
        let id = universe_id_from_proto(&proto).unwrap();
        assert_eq!(id.asset_id, AssetId([0x22; 32]));

        let proto = universerpc::Id {
            proof_type: 2,
            id: Some(universerpc::id::Id::GroupKeyStr("44".repeat(32))),
        };
        let id = universe_id_from_proto(&proto).unwrap();
        assert_eq!(id.group_key.unwrap().0[1..], [0x44; 32]);
    }

    /// Supply-commitment proof types cannot travel over universe RPC.
    #[test]
    fn test_unsupported_proof_types_rejected() {
        for pt in [ProofType::Ignore, ProofType::Burn, ProofType::MintSupply]
        {
            assert!(proof_type_to_proto(pt).is_err());
        }
        assert!(proof_type_from_proto(0).is_err());
        assert!(proof_type_from_proto(99).is_err());
    }

    /// Byte-order pin: leaf key outpoints are marshaled in DISPLAY
    /// order ("txid:vout" op_str), and the script key as the x-only
    /// 32-byte form, exactly like tapd's marshalLeafKey.
    #[test]
    fn test_leaf_key_display_order_and_xonly() {
        let mut txid = [0u8; 32];
        txid[0] = 0xAA; // internal order: first byte 0xAA
        txid[31] = 0x01; // internal order: last byte 0x01
        let key = LeafKey {
            outpoint: OutPoint { txid, vout: 5 },
            script_key: SerializedKey([0x02; 33]),
        };

        let proto = leaf_key_to_proto(&key);
        match proto.outpoint.as_ref().unwrap() {
            universerpc::asset_key::Outpoint::OpStr(s) => {
                // Display order: reversed, so 0x01 leads and 0xAA ends.
                assert!(s.starts_with("01"), "op_str: {}", s);
                assert!(s.ends_with("aa:5"), "op_str: {}", s);
            }
            other => panic!("unexpected outpoint form: {:?}", other),
        }
        match proto.script_key.as_ref().unwrap() {
            universerpc::asset_key::ScriptKey::ScriptKeyBytes(b) => {
                assert_eq!(b.as_slice(), &[0x02; 32][..]); // x-only
            }
            other => panic!("unexpected script key form: {:?}", other),
        }

        // Round trip restores internal order and the 33-byte key.
        let back = leaf_key_from_proto(&proto).unwrap();
        assert_eq!(back, key);
    }

    /// The unrolled `op {hash_str, index}` form (also display order)
    /// and 33-byte script keys are accepted.
    #[test]
    fn test_leaf_key_from_op_form() {
        let mut display = [0u8; 32];
        display[0] = 0xEE; // display order leads with 0xEE
        let proto = universerpc::AssetKey {
            outpoint: Some(universerpc::asset_key::Outpoint::Op(
                universerpc::Outpoint {
                    hash_str: hex_encode(&display),
                    index: 7,
                },
            )),
            script_key: Some(
                universerpc::asset_key::ScriptKey::ScriptKeyBytes(
                    vec![0x03; 33],
                ),
            ),
        };
        let key = leaf_key_from_proto(&proto).unwrap();
        // Reversal: display[0] -> internal[31].
        assert_eq!(key.outpoint.txid[31], 0xEE);
        assert_eq!(key.outpoint.vout, 7);
        assert_eq!(key.script_key, SerializedKey([0x03; 33]));
    }

    #[test]
    fn test_merkle_sum_node_roundtrip_and_negative_sum() {
        let proto = merkle_sum_node_to_proto(&NodeHash([0x77; 32]), 1000);
        assert_eq!(proto.root_sum, 1000);
        let (hash, sum) = merkle_sum_node_from_proto(&proto).unwrap();
        assert_eq!(hash, NodeHash([0x77; 32]));
        assert_eq!(sum, 1000);

        let bad = universerpc::MerkleSumNode {
            root_hash: vec![0u8; 32],
            root_sum: -1,
        };
        assert!(merkle_sum_node_from_proto(&bad).is_err());
    }

    #[test]
    fn test_universe_root_roundtrip_and_empty_detection() {
        let root = UniverseRoot {
            id: test_universe_id(false),
            root_hash: NodeHash([0x55; 32]),
            root_sum: 42,
        };
        let proto = universe_root_to_proto(&root).unwrap();
        assert_eq!(universe_root_from_proto(&proto).unwrap(), root);
        assert!(!is_empty_universe_root(Some(&proto)));

        // tapd signals a missing root with an all-empty message.
        assert!(is_empty_universe_root(Some(
            &universerpc::UniverseRoot::default()
        )));
        assert!(is_empty_universe_root(None));
    }

    /// Byte-order pin for the mailbox tx proof: the claimed outpoint
    /// txid travels in INTERNAL order (raw bytes, no reversal), the
    /// header as its raw 80 bytes, and the merkle proof bits copy 1:1.
    #[test]
    fn test_tx_proof_roundtrip_internal_order() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

        let tx = AnchorTx(Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        });
        let txid = tx.txid();

        let mut header = [0u8; 80];
        header[0] = 0x02;
        let proof = TxProof {
            msg_tx: tx,
            block_header: BlockHeader(header),
            block_height: 123,
            merkle_proof: TxMerkleProof {
                nodes: vec![[0xAB; 32], [0xCD; 32]],
                bits: vec![true, false],
            },
            claimed_outpoint: OutPoint { txid, vout: 0 },
            internal_key: SerializedKey([0x02; 33]),
            merkle_root: None,
        };

        let proto = tx_proof_to_proto(&proof);
        // Internal order: the raw txid bytes, unreversed.
        assert_eq!(
            proto.claimed_outpoint.as_ref().unwrap().txid,
            txid.to_vec()
        );
        assert_eq!(proto.raw_block_header_data.len(), 80);
        assert_eq!(
            proto.merkle_proof.as_ref().unwrap().bits,
            vec![true, false]
        );
        // Absent merkle root -> empty bytes (BIP-86 assumed).
        assert!(proto.merkle_root.is_empty());

        let back = tx_proof_from_proto(&proto).unwrap();
        assert_eq!(back, proof);
    }

    #[test]
    fn test_tx_proof_with_merkle_root() {
        let proto = authmailboxrpc::BitcoinMerkleInclusionProof {
            raw_tx_data: AnchorTx::default().to_bytes(),
            raw_block_header_data: vec![0u8; 80],
            block_height: 1,
            merkle_proof: Some(authmailboxrpc::MerkleProof {
                sibling_hashes: vec![],
                bits: vec![],
            }),
            claimed_outpoint: Some(taprpc::OutPoint {
                txid: vec![0x99; 32],
                output_index: 3,
            }),
            internal_key: vec![0x02; 33],
            merkle_root: vec![0x88; 32],
        };
        let proof = tx_proof_from_proto(&proto).unwrap();
        assert_eq!(proof.merkle_root, Some([0x88; 32]));
        assert_eq!(proof.claimed_outpoint.txid, [0x99; 32]);
        assert_eq!(proof.claimed_outpoint.vout, 3);

        let re = tx_proof_to_proto(&proof);
        assert_eq!(re.merkle_root, vec![0x88; 32]);
    }
}
