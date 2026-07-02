//! Shared helpers for the vendored Go BIP test vectors.
//!
//! The serde structs in this module mirror the JSON schemas produced by
//! the Go implementation's mock serializers (`asset/mock.go`,
//! `address/mock.go`, `proof/mock.go`, `commitment/mock.go`,
//! `mssmt/mock.go`). The builder functions convert the JSON
//! representations into the corresponding Rust types, applying the same
//! validation (and error strings) as the Go `To*` helpers so that the
//! error test cases can be asserted loosely by message.

#![allow(dead_code)]

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::Deserialize;

use tap_primitives::asset::{
    Asset, AssetId, AssetType, AssetVersion, Genesis, GroupKey,
    GroupKeyReveal, GroupKeyRevealV0, GroupKeyVersion, OutPoint, PrevId,
    ScriptKey, ScriptVersion, SerializedKey, SplitCommitmentWitness,
    Witness,
};
use tap_primitives::commitment::{
    AssetProof, CommitmentProof, TapCommitmentVersion, TaprootAssetProof,
    TapscriptPreimage,
};
use tap_primitives::encoding::asset::encode_asset;
use tap_primitives::asset::EncodeType;
use tap_primitives::mssmt;
use tap_primitives::proof::types::{
    AnchorTx, BlockHeader, Proof, TaprootProof, TapscriptProof,
    TransitionVersion,
};
use tap_primitives::proof::{File, MetaReveal, MetaType, TxMerkleProof};

// ---------------------------------------------------------------------
// Hex / parsing helpers
// ---------------------------------------------------------------------

pub fn parse_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex in test vector")
}

pub fn parse_hex32(s: &str) -> [u8; 32] {
    if s.is_empty() {
        return [0u8; 32];
    }
    parse_hex(s).try_into().expect("expected 32-byte hex")
}

pub fn parse_hex33(s: &str) -> [u8; 33] {
    parse_hex(s).try_into().expect("expected 33-byte hex")
}

/// Parses a chain hash in display (reversed) byte order into internal
/// byte order, matching Go's `chainhash.NewHashFromStr`.
pub fn parse_chain_hash(s: &str) -> [u8; 32] {
    if s.is_empty() {
        return [0u8; 32];
    }
    let mut bytes = parse_hex32(s);
    bytes.reverse();
    bytes
}

/// Parses an outpoint string `"txid:vout"` (txid in display order),
/// matching Go's `test.ParseOutPoint`.
pub fn parse_out_point(s: &str) -> OutPoint {
    if s.is_empty() {
        return OutPoint {
            txid: [0u8; 32],
            vout: 0,
        };
    }
    let (txid, vout) = s.split_once(':').expect("invalid outpoint");
    OutPoint {
        txid: parse_chain_hash(txid),
        vout: vout.parse().expect("invalid vout"),
    }
}

/// Parses the JSON `unknown_odd_types` map: keys are decimal type
/// numbers, values are base64 (Go marshals `tlv.TypeMap` values as
/// base64 []byte).
pub fn parse_unknown_odd_types(
    map: &Option<BTreeMap<String, String>>,
) -> BTreeMap<u64, Vec<u8>> {
    let mut out = BTreeMap::new();
    if let Some(map) = map {
        for (k, v) in map {
            let type_num: u64 = k.parse().expect("invalid TLV type key");
            let value = base64::engine::general_purpose::STANDARD
                .decode(v)
                .expect("invalid base64 value");
            out.insert(type_num, value);
        }
    }
    out
}

/// Decodes a compressed MS-SMT proof hex string into a full proof,
/// matching Go's `mssmt.ParseProof`.
pub fn parse_mssmt_proof(s: &str) -> Result<mssmt::Proof, String> {
    let bytes = parse_hex(s);
    let compressed = mssmt::CompressedProof::decode(&bytes)?;
    compressed.decompress()
}

/// Parses an optional tapscript sibling hex string (1 byte type + raw
/// preimage), matching Go's `commitment.ParseTapscriptSibling`.
pub fn parse_tapscript_sibling(s: &str) -> Option<TapscriptPreimage> {
    if s.is_empty() {
        return None;
    }
    let bytes = parse_hex(s);
    Some(TapscriptPreimage {
        sibling_type: bytes[0],
        sibling_preimage: bytes[1..].to_vec(),
    })
}

// ---------------------------------------------------------------------
// Asset vectors (asset/mock.go)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AssetVectorFile {
    pub valid_test_cases: Option<Vec<AssetValidCase>>,
    pub error_test_cases: Option<Vec<AssetErrorCase>>,
}

#[derive(Debug, Deserialize)]
pub struct AssetValidCase {
    pub asset: TestAsset,
    pub expected: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssetErrorCase {
    pub asset: TestAsset,
    pub error: String,
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TestAsset {
    pub version: u8,
    pub genesis_first_prev_out: String,
    pub genesis_tag: String,
    pub genesis_meta_hash: String,
    pub genesis_output_index: u32,
    pub genesis_type: u8,
    pub amount: u64,
    pub lock_time: u64,
    pub relative_lock_time: u64,
    pub prev_witnesses: Option<Vec<TestWitness>>,
    pub split_commitment_root: Option<TestNode>,
    pub script_version: u16,
    pub script_key: String,
    pub group_key: Option<TestGroupKey>,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestWitness {
    pub prev_id: Option<TestPrevId>,
    pub tx_witness: Option<Vec<String>>,
    pub split_commitment: Option<TestSplitCommitment>,
}

#[derive(Debug, Deserialize)]
pub struct TestPrevId {
    pub out_point: String,
    pub asset_id: String,
    pub script_key: String,
}

#[derive(Debug, Deserialize)]
pub struct TestSplitCommitment {
    pub proof: String,
    pub root_asset: Option<TestAsset>,
}

#[derive(Debug, Deserialize)]
pub struct TestGroupKey {
    pub group_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TestNode {
    pub hash: String,
    pub sum: String,
}

impl TestNode {
    pub fn to_computed_node(&self) -> (mssmt::NodeHash, u64) {
        (
            mssmt::NodeHash(parse_hex32(&self.hash)),
            self.sum.parse().expect("invalid sum"),
        )
    }
}

/// Hex length of a compressed public key string (33 bytes).
const HEX_COMPRESSED_PUB_KEY_LEN: usize = 66;

/// Builds an [`Asset`] from its JSON test representation, applying the
/// same validation (and error strings) as Go's `TestAsset.ToAsset`.
pub fn build_asset(ta: &TestAsset) -> Result<Asset, String> {
    if ta.genesis_first_prev_out.is_empty()
        || ta.genesis_meta_hash.is_empty()
    {
        return Err("missing genesis fields".into());
    }
    if ta.script_key.is_empty() {
        return Err("missing script key".into());
    }
    if ta.script_key.len() != HEX_COMPRESSED_PUB_KEY_LEN {
        return Err("invalid script key length".into());
    }
    if let Some(ref gk) = ta.group_key {
        match gk.group_key.as_deref() {
            None | Some("") => return Err("missing group key".into()),
            Some(key) if key.len() != HEX_COMPRESSED_PUB_KEY_LEN => {
                return Err("invalid group key length".into())
            }
            _ => {}
        }
    }

    let mut prev_witnesses = Vec::new();
    for tw in ta.prev_witnesses.iter().flatten() {
        prev_witnesses.push(build_witness(tw)?);
    }

    let group_key = ta.group_key.as_ref().map(|gk| {
        let key = SerializedKey(parse_hex33(
            gk.group_key.as_deref().unwrap(),
        ));
        GroupKey {
            version: GroupKeyVersion::V0,
            raw_key: key,
            group_pub_key: key,
            tapscript_root: vec![],
            witness: vec![],
        }
    });

    Ok(Asset {
        version: AssetVersion::from_u8(ta.version)
            .map_err(|e| e.to_string())?,
        genesis: Genesis {
            first_prev_out: parse_out_point(&ta.genesis_first_prev_out),
            tag: ta.genesis_tag.clone(),
            meta_hash: parse_hex32(&ta.genesis_meta_hash),
            output_index: ta.genesis_output_index,
            asset_type: AssetType::from_u8(ta.genesis_type)
                .map_err(|e| e.to_string())?,
        },
        amount: ta.amount,
        lock_time: ta.lock_time,
        relative_lock_time: ta.relative_lock_time,
        prev_witnesses,
        split_commitment_root: ta
            .split_commitment_root
            .as_ref()
            .map(|n| n.to_computed_node()),
        script_version: ScriptVersion(ta.script_version),
        script_key: ScriptKey::from_pub_key(SerializedKey(parse_hex33(
            &ta.script_key,
        ))),
        group_key,
        unknown_odd_types: parse_unknown_odd_types(&ta.unknown_odd_types),
    })
}

pub fn build_witness(tw: &TestWitness) -> Result<Witness, String> {
    let prev_id = tw.prev_id.as_ref().map(|p| PrevId {
        out_point: parse_out_point(&p.out_point),
        id: AssetId(parse_hex32(&p.asset_id)),
        script_key: SerializedKey(parse_hex33(&p.script_key)),
    });

    let tx_witness = tw
        .tx_witness
        .iter()
        .flatten()
        .map(|s| parse_hex(s))
        .collect();

    let split_commitment = match tw.split_commitment {
        Some(ref sc) => {
            let proof = parse_mssmt_proof(&sc.proof)?;
            let root_asset = match sc.root_asset {
                Some(ref ra) => {
                    let asset = build_asset(ra)?;
                    encode_asset(&asset, EncodeType::Normal)
                }
                None => vec![],
            };
            Some(SplitCommitmentWitness { proof, root_asset })
        }
        None => None,
    };

    Ok(Witness {
        prev_id,
        tx_witness,
        split_commitment,
    })
}

// ---------------------------------------------------------------------
// Address vectors (address/mock.go)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddressVectorFile {
    pub valid_test_cases: Option<Vec<AddressValidCase>>,
    pub error_test_cases: Option<Vec<AddressErrorCase>>,
}

#[derive(Debug, Deserialize)]
pub struct AddressValidCase {
    pub address: TestAddress,
    pub expected: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddressErrorCase {
    pub address: TestAddress,
    pub error: String,
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TestAddress {
    pub version: u8,
    pub chain_params_hrp: String,
    pub asset_version: u8,
    pub asset_id: String,
    pub group_key: String,
    pub script_key: String,
    pub internal_key: String,
    pub tapscript_sibling: String,
    pub amount: u64,
    pub proof_courier_addr: String,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

/// Builds a [`tap_primitives::address::TapAddress`] from its JSON test
/// representation, applying the same validation (and error strings) as
/// Go's `TestAddress.ToAddress`.
pub fn build_address(
    ta: &TestAddress,
) -> Result<tap_primitives::address::TapAddress, String> {
    use tap_primitives::address::{TapAddress, TapNetwork};

    if ta.chain_params_hrp.is_empty() {
        return Err("missing chain params HRP".into());
    }
    let network = TapNetwork::from_hrp(&ta.chain_params_hrp)
        .map_err(|_| "invalid chain params HRP".to_string())?;

    if ta.asset_id.is_empty() && ta.group_key.is_empty() {
        return Err("missing asset ID or group key".into());
    }
    if ta.script_key.is_empty() {
        return Err("missing script key".into());
    }
    if ta.script_key.len() != HEX_COMPRESSED_PUB_KEY_LEN {
        return Err("invalid script key length".into());
    }
    if ta.internal_key.is_empty() {
        return Err("missing internal key".into());
    }
    if ta.internal_key.len() != HEX_COMPRESSED_PUB_KEY_LEN {
        return Err("invalid internal key length".into());
    }
    if !ta.group_key.is_empty()
        && ta.group_key.len() != HEX_COMPRESSED_PUB_KEY_LEN
    {
        return Err("invalid group key length".into());
    }

    let asset_id = if ta.asset_id.is_empty() {
        None
    } else {
        Some(AssetId(parse_hex32(&ta.asset_id)))
    };

    let group_key = if ta.group_key.is_empty() {
        None
    } else {
        Some(SerializedKey(parse_hex33(&ta.group_key)))
    };

    // The address tapscript sibling record carries the encoded
    // TapscriptPreimage (type byte + preimage), which is exactly the
    // hex string in the vector.
    let tapscript_sibling = if ta.tapscript_sibling.is_empty() {
        None
    } else {
        Some(parse_hex(&ta.tapscript_sibling))
    };

    Ok(TapAddress {
        version: ta.version,
        asset_version: ta.asset_version,
        asset_id,
        script_key: SerializedKey(parse_hex33(&ta.script_key)),
        internal_key: SerializedKey(parse_hex33(&ta.internal_key)),
        amount: ta.amount,
        network,
        proof_courier_addr: if ta.proof_courier_addr.is_empty() {
            None
        } else {
            Some(ta.proof_courier_addr.clone())
        },
        group_key,
        tapscript_sibling,
        unknown_odd_types: parse_unknown_odd_types(&ta.unknown_odd_types),
    })
}

// ---------------------------------------------------------------------
// MS-SMT vectors (mssmt/mock.go)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MssmtVectorFile {
    pub all_tree_leaves: Option<Vec<MssmtLeaf>>,
    pub valid_test_cases: Option<Vec<MssmtValidCase>>,
    pub error_test_cases: Option<Vec<MssmtErrorCase>>,
}

#[derive(Debug, Deserialize)]
pub struct MssmtLeaf {
    pub key: String,
    pub node: MssmtLeafNode,
}

#[derive(Debug, Deserialize)]
pub struct MssmtLeafNode {
    pub value: String,
    pub sum: String,
}

#[derive(Debug, Deserialize)]
pub struct MssmtValidCase {
    pub root_hash: String,
    pub root_sum: String,
    pub inserted_leaves: Vec<String>,
    pub deleted_leaves: Option<Vec<String>>,
    pub replaced_leaves: Option<Vec<MssmtLeaf>>,
    pub inclusion_proofs: Option<Vec<MssmtProofCase>>,
    pub exclusion_proofs: Option<Vec<MssmtProofCase>>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MssmtErrorCase {
    pub inserted_leaves: Vec<String>,
    pub error: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MssmtProofCase {
    pub proof_key: String,
    pub compressed_proof: String,
}

impl MssmtLeaf {
    pub fn to_key_and_leaf(&self) -> ([u8; 32], mssmt::LeafNode) {
        (
            parse_hex32(&self.key),
            mssmt::LeafNode::new(
                parse_hex(&self.node.value),
                self.node.sum.parse().expect("invalid leaf sum"),
            ),
        )
    }
}

// ---------------------------------------------------------------------
// Proof vectors (proof/mock.go)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ProofVectorFile {
    pub valid_test_cases: Option<Vec<ProofValidCase>>,
    pub error_test_cases: Option<Vec<ProofErrorCase>>,
}

#[derive(Debug, Deserialize)]
pub struct ProofValidCase {
    pub proof: TestProof,
    pub expected: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProofErrorCase {
    pub proof: TestProof,
    pub error: String,
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TestProof {
    pub version: u32,
    pub prev_out: String,
    pub block_header: Option<TestBlockHeader>,
    pub block_height: u32,
    pub anchor_tx: String,
    pub tx_merkle_proof: Option<TestTxMerkleProof>,
    pub asset: Option<TestAsset>,
    pub inclusion_proof: Option<TestTaprootProof>,
    pub exclusion_proofs: Option<Vec<TestTaprootProof>>,
    pub split_root_proof: Option<TestTaprootProof>,
    pub meta_reveal: Option<TestMetaReveal>,
    pub additional_inputs: Option<Vec<String>>,
    pub challenge_witness: Option<Vec<String>>,
    pub genesis_reveal: Option<TestGenesisReveal>,
    pub group_key_reveal: Option<TestGroupKeyReveal>,
    pub alt_leaves: Option<Vec<TestAsset>>,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestBlockHeader {
    pub version: i32,
    pub prev_block: String,
    pub merkle_root: String,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl TestBlockHeader {
    /// Serializes the header fields into the 80-byte Bitcoin wire
    /// format (all integers little-endian, hashes in internal order).
    pub fn to_block_header(&self) -> BlockHeader {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&parse_chain_hash(&self.prev_block));
        bytes.extend_from_slice(&parse_chain_hash(&self.merkle_root));
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.bits.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        BlockHeader(bytes.try_into().unwrap())
    }
}

#[derive(Debug, Deserialize)]
pub struct TestTxMerkleProof {
    pub nodes: Vec<String>,
    pub bits: Vec<bool>,
}

impl TestTxMerkleProof {
    pub fn to_tx_merkle_proof(&self) -> TxMerkleProof {
        TxMerkleProof {
            nodes: self
                .nodes
                .iter()
                .map(|n| parse_chain_hash(n))
                .collect(),
            bits: self.bits.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TestTaprootProof {
    pub output_index: u32,
    pub internal_key: String,
    pub commitment_proof: Option<TestCommitmentProof>,
    pub tapscript_proof: Option<TestTapscriptProof>,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestCommitmentProof {
    pub proof: TestCommitmentInnerProof,
    pub tapscript_sibling: Option<String>,
    pub stxo_proofs: Option<BTreeMap<String, TestCommitmentInnerProof>>,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestCommitmentInnerProof {
    pub asset_proof: Option<TestAssetProof>,
    pub taproot_asset_proof: TestTaprootAssetProof,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestAssetProof {
    pub proof: String,
    pub version: u8,
    pub tap_key: String,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestTaprootAssetProof {
    pub proof: String,
    pub version: u8,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestTapscriptProof {
    pub tap_preimage_1: Option<String>,
    pub tap_preimage_2: Option<String>,
    pub bip86: bool,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestMetaReveal {
    #[serde(rename = "type")]
    pub meta_type: u8,
    pub data: String,
    pub decimal_display: Option<u32>,
    pub universe_commitments: Option<bool>,
    pub canonical_universes: Option<Vec<String>>,
    pub delegation_key: Option<String>,
    pub unknown_odd_types: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct TestGenesisReveal {
    pub first_prev_out: String,
    pub tag: String,
    pub meta_hash: String,
    pub output_index: u32,
    #[serde(rename = "type")]
    pub asset_type: u8,
}

#[derive(Debug, Deserialize)]
pub struct TestGroupKeyReveal {
    pub raw_key: String,
    pub tapscript_root: String,
}

/// Builds the inner commitment proof pair (Go's `commitment.Proof`)
/// used both directly and as STXO map entries.
pub fn build_commitment_inner_proof(
    tp: &TestCommitmentInnerProof,
) -> Result<CommitmentProof, String> {
    let asset_proof = match tp.asset_proof {
        Some(ref ap) => Some(AssetProof {
            proof: parse_mssmt_proof(&ap.proof)?,
            version: AssetVersion::from_u8(ap.version)
                .map_err(|e| e.to_string())?,
            tap_key: parse_hex32(&ap.tap_key),
            unknown_odd_types: parse_unknown_odd_types(
                &ap.unknown_odd_types,
            ),
        }),
        None => None,
    };

    Ok(CommitmentProof {
        asset_proof,
        taproot_asset_proof: TaprootAssetProof {
            proof: parse_mssmt_proof(&tp.taproot_asset_proof.proof)?,
            version: TapCommitmentVersion::from_u8(
                tp.taproot_asset_proof.version,
            )
            .map_err(|e| e.to_string())?,
            unknown_odd_types: parse_unknown_odd_types(
                &tp.taproot_asset_proof.unknown_odd_types,
            ),
        },
        tap_sibling_preimage: None,
        stxo_proofs: BTreeMap::new(),
        unknown_odd_types: parse_unknown_odd_types(&tp.unknown_odd_types),
    })
}

pub fn build_commitment_proof(
    tcp: &TestCommitmentProof,
) -> Result<CommitmentProof, String> {
    let mut proof = build_commitment_inner_proof(&tcp.proof)?;

    proof.tap_sibling_preimage = tcp
        .tapscript_sibling
        .as_deref()
        .and_then(parse_tapscript_sibling);

    if let Some(ref stxo) = tcp.stxo_proofs {
        for (key_hex, inner) in stxo {
            let key = SerializedKey(parse_hex33(key_hex));
            proof
                .stxo_proofs
                .insert(key, build_commitment_inner_proof(inner)?);
        }
    }

    // The commitment proof carries its own unknown odd types map at the
    // outer (proof.CommitmentProof) level in Go; both the embedded
    // commitment.Proof map and the outer map end up in the same TLV
    // stream, so merging them is wire-equivalent.
    let outer_unknown = parse_unknown_odd_types(&tcp.unknown_odd_types);
    proof.unknown_odd_types.extend(outer_unknown);

    Ok(proof)
}

pub fn build_tapscript_proof(
    ttp: &TestTapscriptProof,
) -> Result<TapscriptProof, String> {
    Ok(TapscriptProof {
        tap_preimage_1: ttp
            .tap_preimage_1
            .as_deref()
            .and_then(parse_tapscript_sibling),
        tap_preimage_2: ttp
            .tap_preimage_2
            .as_deref()
            .and_then(parse_tapscript_sibling),
        bip86: ttp.bip86,
        unknown_odd_types: parse_unknown_odd_types(&ttp.unknown_odd_types),
    })
}

pub fn build_taproot_proof(
    ttp: &TestTaprootProof,
) -> Result<TaprootProof, String> {
    Ok(TaprootProof {
        output_index: ttp.output_index,
        internal_key: SerializedKey(parse_hex33(&ttp.internal_key)),
        commitment_proof: match ttp.commitment_proof {
            Some(ref cp) => Some(build_commitment_proof(cp)?),
            None => None,
        },
        tapscript_proof: match ttp.tapscript_proof {
            Some(ref ts) => Some(build_tapscript_proof(ts)?),
            None => None,
        },
        unknown_odd_types: parse_unknown_odd_types(&ttp.unknown_odd_types),
    })
}

pub fn build_meta_reveal(
    tmr: &TestMetaReveal,
) -> Result<MetaReveal, String> {
    let meta_type = match tmr.meta_type {
        0 => MetaType::Opaque,
        1 => MetaType::Json,
        other => return Err(format!("unknown meta type {}", other)),
    };

    Ok(MetaReveal {
        meta_type,
        data: parse_hex(&tmr.data),
        decimal_display: tmr.decimal_display,
        universe_commitments: tmr.universe_commitments.unwrap_or(false),
        canonical_universes: tmr.canonical_universes.clone(),
        delegation_key: tmr
            .delegation_key
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| SerializedKey(parse_hex33(s))),
        unknown_odd_types: parse_unknown_odd_types(&tmr.unknown_odd_types),
    })
}

pub fn build_genesis_reveal(tgr: &TestGenesisReveal) -> Genesis {
    Genesis {
        first_prev_out: parse_out_point(&tgr.first_prev_out),
        tag: tgr.tag.clone(),
        meta_hash: parse_hex32(&tgr.meta_hash),
        output_index: tgr.output_index,
        asset_type: AssetType::from_u8(tgr.asset_type).unwrap(),
    }
}

pub fn build_group_key_reveal(tgkr: &TestGroupKeyReveal) -> GroupKeyReveal {
    GroupKeyReveal::V0(GroupKeyRevealV0 {
        raw_key: SerializedKey(parse_hex33(&tgkr.raw_key)),
        tapscript_root: parse_hex(&tgkr.tapscript_root),
    })
}

/// Builds a [`Proof`] from its JSON test representation, mirroring
/// Go's `TestProof.ToProof`.
pub fn build_proof(tp: &TestProof) -> Result<Proof, String> {
    let mut exclusion_proofs = Vec::new();
    for ep in tp.exclusion_proofs.iter().flatten() {
        exclusion_proofs.push(build_taproot_proof(ep)?);
    }

    let mut additional_inputs = Vec::new();
    for file_hex in tp.additional_inputs.iter().flatten() {
        let bytes = parse_hex(file_hex);
        additional_inputs
            .push(File::decode(&bytes).map_err(|e| e.to_string())?);
    }

    let mut alt_leaves = Vec::new();
    for leaf in tp.alt_leaves.iter().flatten() {
        alt_leaves.push(build_asset(leaf)?);
    }

    Ok(Proof {
        version: TransitionVersion::from_u32(tp.version)
            .map_err(|e| e.to_string())?,
        prev_out: parse_out_point(&tp.prev_out),
        block_header: tp
            .block_header
            .as_ref()
            .map(|h| h.to_block_header())
            .unwrap_or_default(),
        block_height: tp.block_height,
        anchor_tx: AnchorTx(parse_hex(&tp.anchor_tx)),
        tx_merkle_proof: tp
            .tx_merkle_proof
            .as_ref()
            .map(|p| p.to_tx_merkle_proof())
            .unwrap_or(TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            }),
        asset: build_asset(
            tp.asset.as_ref().ok_or("missing asset")?,
        )?,
        inclusion_proof: build_taproot_proof(
            tp.inclusion_proof
                .as_ref()
                .ok_or("missing inclusion proof")?,
        )?,
        exclusion_proofs,
        split_root_proof: match tp.split_root_proof {
            Some(ref srp) => Some(build_taproot_proof(srp)?),
            None => None,
        },
        meta_reveal: match tp.meta_reveal {
            Some(ref mr) => Some(build_meta_reveal(mr)?),
            None => None,
        },
        additional_inputs,
        challenge_witness: tp
            .challenge_witness
            .as_ref()
            .map(|cw| cw.iter().map(|s| parse_hex(s)).collect()),
        genesis_reveal: tp.genesis_reveal.as_ref().map(build_genesis_reveal),
        group_key_reveal: tp
            .group_key_reveal
            .as_ref()
            .map(build_group_key_reveal),
        alt_leaves,
        unknown_odd_types: parse_unknown_odd_types(&tp.unknown_odd_types),
    })
}

/// Loads a JSON test vector file from `tests/testdata/`.
pub fn load_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!(
        "{}/tests/testdata/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path, e))
}

/// Loads a whitespace-trimmed hex file from `tests/testdata/`.
pub fn load_hex_file(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/testdata/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
    parse_hex(data.trim())
}
