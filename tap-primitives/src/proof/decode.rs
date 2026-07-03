// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TLV decoding for transition proofs, the exact inverse of
//! [`super::encode`] and byte-compatible with Go's `tapd`
//! (`proof/proof.go` `Proof.Decode` and friends).

use std::collections::BTreeMap;

use crate::asset::{
    self, Asset, AssetType, AssetVersion, GroupKeyReveal, GroupKeyRevealV0,
    GroupKeyRevealV1, GroupKeyRevealTapscript, OutPoint, ScriptKey,
    ScriptVersion, SerializedKey,
};
use crate::commitment::{
    AssetProof, CommitmentProof, TaprootAssetProof, TapscriptPreimage,
};
use crate::commitment::tap_commitment::TapCommitmentVersion;
use crate::encoding::asset::{
    decode_asset, decode_genesis, decode_tx_witness,
};
use crate::encoding::bigsize::decode_bigsize;
use crate::encoding::tlv::{
    decode_var_bytes, TlvError, TlvRecord, TlvStream,
    MAX_PROOF_TLV_VALUE_LENGTH,
};
use crate::mssmt;
use crate::proof::encode::{commitment_tlv, taproot_tlv, tapscript_tlv, tlv_types};
use crate::proof::file::{File, PROOF_MAGIC_BYTES};
use crate::proof::meta::MetaReveal;
use crate::proof::tx_merkle::{TxMerkleProof, MERKLE_PROOF_MAX_NODES};
use crate::proof::types::{
    AnchorTx, BlockHeader, Proof, TaprootProof, TapscriptProof,
    TransitionVersion,
};
use crate::proof::ProofError;

/// Maximum size of a single record inside nested (P2P-decoded) TLV
/// streams, matching lnd's `tlv.MaxRecordSize` used by Go's
/// `DecodeWithParsedTypesP2P`.
const MAX_NESTED_RECORD_SIZE: u64 = 65535;

fn decode_err(msg: impl Into<String>) -> ProofError {
    ProofError::DecodingError(msg.into())
}

impl From<TlvError> for ProofError {
    fn from(e: TlvError) -> Self {
        ProofError::DecodingError(e.to_string())
    }
}

/// Checks that a fixed-size record has the expected length.
fn expect_len(
    record: &TlvRecord,
    expected: usize,
    what: &str,
) -> Result<(), ProofError> {
    if record.value.len() != expected {
        return Err(decode_err(format!(
            "invalid {} length: expected {}, got {}",
            what,
            expected,
            record.value.len()
        )));
    }
    Ok(())
}

/// Decodes a 36-byte outpoint (32-byte txid + BE u32 vout), Go's
/// `asset.OutPointDecoder`.
fn decode_out_point(value: &[u8]) -> Result<OutPoint, ProofError> {
    if value.len() != 36 {
        return Err(decode_err(format!(
            "invalid outpoint length: {}",
            value.len()
        )));
    }
    Ok(OutPoint {
        txid: value[..32].try_into().unwrap(),
        vout: u32::from_be_bytes(value[32..36].try_into().unwrap()),
    })
}

/// Decodes a `Proof` from tapd-compatible binary TLV format.
///
/// The input must start with the "TAPP" magic bytes. This is the exact
/// inverse of [`super::encode::encode_proof`], matching Go's
/// `Proof.Decode` (proof/proof.go): unknown even types are rejected,
/// unknown odd types are preserved, and absent records leave their
/// fields at default values.
pub fn decode_proof(data: &[u8]) -> Result<Proof, ProofError> {
    if data.len() < 4 {
        return Err(ProofError::FileTooShort);
    }
    if data[..4] != PROOF_MAGIC_BYTES {
        return Err(ProofError::InvalidMagic);
    }

    let stream = TlvStream::decode_with_limit(
        &data[4..],
        MAX_PROOF_TLV_VALUE_LENGTH,
    )?;

    let mut proof = Proof {
        version: TransitionVersion::V0,
        prev_out: OutPoint {
            txid: [0u8; 32],
            vout: 0,
        },
        block_header: BlockHeader::default(),
        block_height: 0,
        anchor_tx: AnchorTx::default(),
        tx_merkle_proof: TxMerkleProof {
            nodes: vec![],
            bits: vec![],
        },
        asset: default_asset(),
        inclusion_proof: default_taproot_proof(),
        exclusion_proofs: vec![],
        split_root_proof: None,
        meta_reveal: None,
        additional_inputs: vec![],
        challenge_witness: None,
        genesis_reveal: None,
        group_key_reveal: None,
        alt_leaves: vec![],
        unknown_odd_types: BTreeMap::new(),
    };

    for record in stream.records() {
        match record.type_num {
            tlv_types::VERSION => {
                expect_len(record, 4, "version")?;
                let v = u32::from_be_bytes(
                    record.value[..4].try_into().unwrap(),
                );
                proof.version = TransitionVersion::from_u32(v)?;
            }
            tlv_types::PREV_OUT => {
                proof.prev_out = decode_out_point(&record.value)?;
            }
            tlv_types::BLOCK_HEADER => {
                expect_len(record, 80, "block header")?;
                let mut header = [0u8; 80];
                header.copy_from_slice(&record.value);
                proof.block_header = BlockHeader(header);
            }
            tlv_types::ANCHOR_TX => {
                proof.anchor_tx = AnchorTx::from_bytes(&record.value)?;
            }
            tlv_types::TX_MERKLE_PROOF => {
                proof.tx_merkle_proof =
                    decode_tx_merkle_proof(&record.value)?;
            }
            tlv_types::ASSET => {
                proof.asset = decode_asset(&record.value)?;
            }
            tlv_types::INCLUSION_PROOF => {
                proof.inclusion_proof =
                    decode_taproot_proof(&record.value)?;
            }
            tlv_types::EXCLUSION_PROOFS => {
                proof.exclusion_proofs =
                    decode_exclusion_proofs(&record.value)?;
            }
            tlv_types::SPLIT_ROOT_PROOF => {
                proof.split_root_proof =
                    Some(decode_taproot_proof(&record.value)?);
            }
            tlv_types::META_REVEAL => {
                proof.meta_reveal =
                    Some(decode_meta_reveal(&record.value)?);
            }
            tlv_types::ADDITIONAL_INPUTS => {
                proof.additional_inputs =
                    decode_additional_inputs(&record.value)?;
            }
            tlv_types::CHALLENGE_WITNESS => {
                proof.challenge_witness =
                    Some(decode_tx_witness(&record.value)?);
            }
            tlv_types::BLOCK_HEIGHT => {
                expect_len(record, 4, "block height")?;
                proof.block_height = u32::from_be_bytes(
                    record.value[..4].try_into().unwrap(),
                );
            }
            tlv_types::GENESIS_REVEAL => {
                proof.genesis_reveal =
                    Some(decode_genesis(&record.value)?);
            }
            tlv_types::GROUP_KEY_REVEAL => {
                proof.group_key_reveal =
                    Some(decode_group_key_reveal(&record.value)?);
            }
            tlv_types::ALT_LEAVES => {
                proof.alt_leaves = decode_alt_leaves(&record.value)?;
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {}",
                    other
                )));
            }
            other => {
                proof
                    .unknown_odd_types
                    .insert(other, record.value.clone());
            }
        }
    }

    Ok(proof)
}

/// Returns the default (all-zero) asset used for absent records,
/// mirroring Go's zero-valued `asset.Asset`.
fn default_asset() -> Asset {
    Asset {
        version: AssetVersion::V0,
        genesis: asset::Genesis {
            first_prev_out: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            tag: String::new(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        },
        amount: 0,
        lock_time: 0,
        relative_lock_time: 0,
        prev_witnesses: vec![],
        split_commitment_root: None,
        script_version: ScriptVersion(0),
        script_key: ScriptKey::from_pub_key(SerializedKey([0u8; 33])),
        group_key: None,
        unknown_odd_types: BTreeMap::new(),
    }
}

fn default_taproot_proof() -> TaprootProof {
    TaprootProof {
        output_index: 0,
        internal_key: SerializedKey([0u8; 33]),
        commitment_proof: None,
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    }
}

/// Decodes the type-13 ExclusionProofs record payload:
/// `BigSize(count) [var_bytes(taproot_proof)]...`, Go's
/// `TaprootProofsDecoder`.
fn decode_exclusion_proofs(
    data: &[u8],
) -> Result<Vec<TaprootProof>, ProofError> {
    let (count, mut offset) =
        decode_bigsize(data).map_err(ProofError::from)?;

    let mut proofs = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let (proof_bytes, consumed) = decode_var_bytes(&data[offset..])
            .map_err(ProofError::from)?;
        offset += consumed;
        proofs.push(decode_taproot_proof(&proof_bytes)?);
    }

    if offset != data.len() {
        return Err(decode_err("trailing bytes after exclusion proofs"));
    }

    Ok(proofs)
}

/// Decodes the type-19 AdditionalInputs record payload:
/// `BigSize(count) [var_bytes(proof_file)]...`, Go's
/// `AdditionalInputsDecoder`.
fn decode_additional_inputs(data: &[u8]) -> Result<Vec<File>, ProofError> {
    let (count, mut offset) =
        decode_bigsize(data).map_err(ProofError::from)?;
    if count > u16::MAX as u64 {
        return Err(decode_err("too many additional inputs"));
    }

    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (file_bytes, consumed) = decode_var_bytes(&data[offset..])
            .map_err(ProofError::from)?;
        offset += consumed;
        files.push(File::decode(&file_bytes)?);
    }

    if offset != data.len() {
        return Err(decode_err("trailing bytes after additional inputs"));
    }

    Ok(files)
}

/// Decodes the type-27 AltLeaves record payload:
/// `BigSize(count) [var_bytes(alt_leaf_tlv)]...`, Go's
/// `asset.AltLeavesDecoder`. Each alt leaf reuses the regular asset
/// decoder (Go's `Asset.DecodeAltLeaf`), so fields not present in the
/// stream keep their defaults.
fn decode_alt_leaves(data: &[u8]) -> Result<Vec<Asset>, ProofError> {
    let (count, mut offset) =
        decode_bigsize(data).map_err(ProofError::from)?;

    // A minimal alt leaf is 39 bytes of inner TLV (script version +
    // script key) plus a 1-byte length prefix, so bound the count by
    // what the record can actually contain (Go's minAltLeafSize).
    const MIN_ALT_LEAF_SIZE: u64 = 40;
    if count > data.len() as u64 / MIN_ALT_LEAF_SIZE {
        return Err(decode_err("too many alt leaves"));
    }

    let mut leaves = Vec::with_capacity(count as usize);
    let mut leaf_keys = std::collections::BTreeSet::new();
    for _ in 0..count {
        let (leaf_bytes, consumed) = decode_var_bytes(&data[offset..])
            .map_err(ProofError::from)?;
        offset += consumed;
        let leaf = decode_asset(&leaf_bytes)?;

        // Each alt leaf must have a unique script key, matching Go's
        // AltLeavesDecoder (asset.ErrDuplicateScriptKeys).
        if !leaf_keys.insert(*leaf.script_key.serialized()) {
            return Err(decode_err("duplicate alt leaf script key"));
        }

        leaves.push(leaf);
    }

    if offset != data.len() {
        return Err(decode_err("trailing bytes after alt leaves"));
    }

    Ok(leaves)
}

/// Decodes a `TaprootProof` from TLV bytes.
///
/// Inverse of [`super::encode::encode_taproot_proof`], matching Go's
/// `TaprootProof.Decode` (proof/taproot.go): known types {0, 2, 3, 5};
/// unknown even types rejected; unknown odd types preserved.
pub fn decode_taproot_proof(data: &[u8]) -> Result<TaprootProof, ProofError> {
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut proof = default_taproot_proof();

    for record in stream.records() {
        match record.type_num {
            taproot_tlv::OUTPUT_INDEX => {
                expect_len(record, 4, "output index")?;
                proof.output_index = u32::from_be_bytes(
                    record.value[..4].try_into().unwrap(),
                );
            }
            taproot_tlv::INTERNAL_KEY => {
                expect_len(record, 33, "internal key")?;
                let key = SerializedKey(
                    record.value[..].try_into().unwrap(),
                );
                // Go's TaprootProofInternalKeyRecord decodes with
                // asset.CompressedPubKeyDecoder (btcec.ParsePubKey),
                // rejecting off-curve keys at decode time.
                key.validate_on_curve().map_err(|e| {
                    decode_err(format!("internal key: {}", e))
                })?;
                proof.internal_key = key;
            }
            taproot_tlv::COMMITMENT_PROOF => {
                proof.commitment_proof =
                    Some(decode_commitment_proof(&record.value)?);
            }
            taproot_tlv::TAPSCRIPT_PROOF => {
                proof.tapscript_proof =
                    Some(decode_tapscript_proof(&record.value)?);
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {} in taproot proof",
                    other
                )));
            }
            other => {
                proof
                    .unknown_odd_types
                    .insert(other, record.value.clone());
            }
        }
    }

    Ok(proof)
}

/// Decodes a compressed MS-SMT tree proof record value into a full
/// proof, Go's `commitment.TreeProofDecoder`.
fn decode_tree_proof(value: &[u8]) -> Result<mssmt::Proof, ProofError> {
    let compressed =
        mssmt::CompressedProof::decode(value).map_err(decode_err)?;
    compressed.decompress().map_err(decode_err)
}

/// Decodes a nested AssetProof record (commitment/encoding.go
/// `AssetProofDecoder`): known types {0 version, 2 asset ID, 4 proof};
/// unknown even rejected, unknown odd preserved.
fn decode_asset_proof(data: &[u8]) -> Result<AssetProof, ProofError> {
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut version = AssetVersion::V0;
    let mut tap_key = [0u8; 32];
    let mut proof: Option<mssmt::Proof> = None;
    let mut unknown_odd_types = BTreeMap::new();

    for record in stream.records() {
        match record.type_num {
            0 => {
                expect_len(record, 1, "asset proof version")?;
                version = AssetVersion::from_u8(record.value[0])
                    .map_err(|e| decode_err(e.to_string()))?;
            }
            2 => {
                expect_len(record, 32, "asset proof asset ID")?;
                tap_key.copy_from_slice(&record.value);
            }
            4 => {
                proof = Some(decode_tree_proof(&record.value)?);
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {} in asset proof",
                    other
                )));
            }
            other => {
                unknown_odd_types.insert(other, record.value.clone());
            }
        }
    }

    Ok(AssetProof {
        proof: proof
            .ok_or_else(|| decode_err("asset proof missing tree proof"))?,
        version,
        tap_key,
        unknown_odd_types,
    })
}

/// Decodes a nested TaprootAssetProof record (commitment/encoding.go
/// `TaprootAssetProofDecoder`): known types {0 version, 2 proof}.
fn decode_taproot_asset_proof(
    data: &[u8],
) -> Result<TaprootAssetProof, ProofError> {
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut version = TapCommitmentVersion::V0;
    let mut proof: Option<mssmt::Proof> = None;
    let mut unknown_odd_types = BTreeMap::new();

    for record in stream.records() {
        match record.type_num {
            0 => {
                expect_len(record, 1, "taproot asset proof version")?;
                version = TapCommitmentVersion::from_u8(record.value[0])
                    .map_err(|e| decode_err(e.to_string()))?;
            }
            2 => {
                proof = Some(decode_tree_proof(&record.value)?);
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {} in taproot asset proof",
                    other
                )));
            }
            other => {
                unknown_odd_types.insert(other, record.value.clone());
            }
        }
    }

    Ok(TaprootAssetProof {
        proof: proof.ok_or_else(|| {
            decode_err("taproot asset proof missing tree proof")
        })?,
        version,
        unknown_odd_types,
    })
}

/// Decodes a `CommitmentProof` from TLV bytes.
///
/// Inverse of [`super::encode::encode_commitment_proof`], matching Go's
/// `CommitmentProof.Decode` (proof/taproot.go): known types {1 asset
/// proof, 2 taproot asset proof, 5 sibling preimage, 7 STXO proofs}.
pub fn decode_commitment_proof(
    data: &[u8],
) -> Result<CommitmentProof, ProofError> {
    decode_commitment_proof_inner(data, true)
}

/// Decodes a bare `commitment.Proof` (types 1 and 2 only), used for
/// STXO map entries. Types 5 and 7 are odd and land in
/// `unknown_odd_types`, matching Go where STXO entries are decoded with
/// `commitment.KnownProofTypes`.
fn decode_commitment_proof_pair(
    data: &[u8],
) -> Result<CommitmentProof, ProofError> {
    decode_commitment_proof_inner(data, false)
}

fn decode_commitment_proof_inner(
    data: &[u8],
    with_extensions: bool,
) -> Result<CommitmentProof, ProofError> {
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut asset_proof: Option<AssetProof> = None;
    let mut taproot_asset_proof: Option<TaprootAssetProof> = None;
    let mut tap_sibling_preimage: Option<TapscriptPreimage> = None;
    let mut stxo_proofs = BTreeMap::new();
    let mut unknown_odd_types = BTreeMap::new();

    for record in stream.records() {
        match record.type_num {
            commitment_tlv::ASSET_PROOF => {
                asset_proof = Some(decode_asset_proof(&record.value)?);
            }
            commitment_tlv::TAP_PROOF => {
                taproot_asset_proof =
                    Some(decode_taproot_asset_proof(&record.value)?);
            }
            commitment_tlv::TAP_SIBLING if with_extensions => {
                tap_sibling_preimage = Some(
                    TapscriptPreimage::decode(&record.value)
                        .map_err(|e| decode_err(e.to_string()))?,
                );
            }
            commitment_tlv::STXO_PROOFS if with_extensions => {
                stxo_proofs = decode_stxo_proofs(&record.value)?;
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {} in commitment proof",
                    other
                )));
            }
            other => {
                unknown_odd_types.insert(other, record.value.clone());
            }
        }
    }

    Ok(CommitmentProof {
        asset_proof,
        taproot_asset_proof: taproot_asset_proof.ok_or_else(|| {
            decode_err("commitment proof missing taproot asset proof")
        })?,
        tap_sibling_preimage,
        stxo_proofs,
        unknown_odd_types,
    })
}

/// Decodes the STXO proofs record payload (Go's
/// `CommitmentProofsDecoder` in proof/encoding.go): `BigSize(count)
/// [33B key || var_bytes(commitment.Proof)]...`.
fn decode_stxo_proofs(
    data: &[u8],
) -> Result<BTreeMap<SerializedKey, CommitmentProof>, ProofError> {
    let (count, mut offset) =
        decode_bigsize(data).map_err(ProofError::from)?;

    let mut proofs = BTreeMap::new();
    for _ in 0..count {
        if offset + 33 > data.len() {
            return Err(decode_err("truncated STXO proof key"));
        }
        let key = SerializedKey(
            data[offset..offset + 33].try_into().unwrap(),
        );
        offset += 33;

        let (proof_bytes, consumed) = decode_var_bytes(&data[offset..])
            .map_err(ProofError::from)?;
        offset += consumed;

        proofs.insert(key, decode_commitment_proof_pair(&proof_bytes)?);
    }

    if offset != data.len() {
        return Err(decode_err("trailing bytes after STXO proofs"));
    }

    Ok(proofs)
}

/// Decodes a `TapscriptProof` from TLV bytes.
///
/// Inverse of [`super::encode::encode_tapscript_proof`], matching Go's
/// `TapscriptProof.Decode` (proof/taproot.go): known types {1, 3, 4}.
pub fn decode_tapscript_proof(
    data: &[u8],
) -> Result<TapscriptProof, ProofError> {
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut proof = TapscriptProof {
        tap_preimage_1: None,
        tap_preimage_2: None,
        bip86: false,
        unknown_odd_types: BTreeMap::new(),
    };

    for record in stream.records() {
        match record.type_num {
            tapscript_tlv::TAP_PREIMAGE_1 => {
                proof.tap_preimage_1 = Some(
                    TapscriptPreimage::decode(&record.value)
                        .map_err(|e| decode_err(e.to_string()))?,
                );
            }
            tapscript_tlv::TAP_PREIMAGE_2 => {
                proof.tap_preimage_2 = Some(
                    TapscriptPreimage::decode(&record.value)
                        .map_err(|e| decode_err(e.to_string()))?,
                );
            }
            tapscript_tlv::BIP86 => {
                expect_len(record, 1, "bip86 flag")?;
                // Go's BoolDecoder maps exactly 1 to true.
                proof.bip86 = record.value[0] == 1;
            }
            other if other % 2 == 0 => {
                return Err(decode_err(format!(
                    "unknown even TLV type {} in tapscript proof",
                    other
                )));
            }
            other => {
                proof
                    .unknown_odd_types
                    .insert(other, record.value.clone());
            }
        }
    }

    Ok(proof)
}

/// Decodes a `MetaReveal` record value, delegating to
/// [`MetaReveal::decode`].
pub fn decode_meta_reveal(data: &[u8]) -> Result<MetaReveal, ProofError> {
    MetaReveal::decode(data)
}

/// Decodes a `GroupKeyReveal` record value.
///
/// Inverse of [`super::encode::encode_group_key_reveal`], matching Go's
/// `GroupKeyRevealDecoder` (asset/encoding.go): values no longer than
/// 33 + 32 bytes decode as V0 (raw key + optional tapscript root),
/// anything longer decodes as the V1 TLV stream.
pub fn decode_group_key_reveal(
    data: &[u8],
) -> Result<GroupKeyReveal, ProofError> {
    const KEY_LEN: usize = 33;
    const ROOT_LEN: usize = 32;

    if data.len() <= KEY_LEN + ROOT_LEN {
        if data.len() < KEY_LEN {
            return Err(decode_err("group key reveal too short"));
        }
        // Go's GroupKeyRevealV0.Decode reads the raw key with
        // SerializedKeyDecoder (btcec.ParsePubKey), rejecting off-curve
        // keys at decode time.
        let raw_key =
            SerializedKey(data[..KEY_LEN].try_into().unwrap());
        raw_key.validate_on_curve().map_err(|e| {
            decode_err(format!("group key reveal raw key: {}", e))
        })?;
        return Ok(GroupKeyReveal::V0(GroupKeyRevealV0 {
            raw_key,
            tapscript_root: data[KEY_LEN..].to_vec(),
        }));
    }

    // V1: TLV stream with version (0), internal key (2), tapscript
    // root (4), and optional custom subtree root (7). Go decodes this
    // with a plain (non-strict) TLV stream, so unknown types are
    // skipped rather than rejected.
    let stream =
        TlvStream::decode_with_limit(data, MAX_NESTED_RECORD_SIZE)?;

    let mut version: u8 = 0;
    let mut internal_key: Option<SerializedKey> = None;
    let mut root: Vec<u8> = Vec::new();
    let mut custom_subtree_root: Option<[u8; 32]> = None;

    for record in stream.records() {
        match record.type_num {
            asset::tlv_types::GKR_VERSION => {
                expect_len(record, 1, "group key reveal version")?;
                version = record.value[0];
            }
            asset::tlv_types::GKR_INTERNAL_KEY => {
                expect_len(record, 33, "group key reveal internal key")?;
                // Deliberately NOT curve-validated: Go decodes the V1
                // internal key as a raw 33-byte primitive record
                // (asset/group_key.go:322, tlv.MakePrimitiveRecord)
                // and only parses it later in Reveal(). Keep raw for
                // parity.
                internal_key = Some(SerializedKey(
                    record.value[..].try_into().unwrap(),
                ));
            }
            asset::tlv_types::GKR_TAPSCRIPT_ROOT => {
                expect_len(record, 32, "group key reveal tapscript root")?;
                root = record.value.clone();
            }
            asset::tlv_types::GKR_CUSTOM_SUBTREE_ROOT => {
                expect_len(record, 32, "custom subtree root")?;
                let hash: [u8; 32] =
                    record.value[..].try_into().unwrap();
                // Go treats an all-zero hash as absent.
                if hash != [0u8; 32] {
                    custom_subtree_root = Some(hash);
                }
            }
            // Unknown types are skipped (not rejected), matching Go's
            // plain DecodeWithParsedTypes in GroupKeyRevealV1.Decode.
            _ => {}
        }
    }

    Ok(GroupKeyReveal::V1(GroupKeyRevealV1 {
        version,
        internal_key: internal_key.ok_or_else(|| {
            decode_err("group key reveal missing internal key")
        })?,
        tapscript: GroupKeyRevealTapscript {
            version,
            root,
            custom_subtree_root,
        },
    }))
}

/// Decodes a `TxMerkleProof` record value.
///
/// Inverse of [`super::encode::encode_tx_merkle_proof`], matching Go's
/// `TxMerkleProof.Decode` (proof/tx.go): `BigSize(count) [32B hash]...
/// [packed bits]` where the bit vector is packed LSB-first into
/// `ceil(count / 8)` bytes.
pub fn decode_tx_merkle_proof(
    data: &[u8],
) -> Result<TxMerkleProof, ProofError> {
    let (count, mut offset) =
        decode_bigsize(data).map_err(ProofError::from)?;
    if count > MERKLE_PROOF_MAX_NODES as u64 {
        return Err(decode_err(format!(
            "too many merkle proof nodes: {}",
            count
        )));
    }
    let count = count as usize;

    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 32 > data.len() {
            return Err(decode_err("truncated merkle proof node"));
        }
        let hash: [u8; 32] =
            data[offset..offset + 32].try_into().unwrap();
        offset += 32;
        nodes.push(hash);
    }

    let packed_len = count.div_ceil(8);
    if offset + packed_len != data.len() {
        return Err(decode_err("invalid merkle proof bits length"));
    }
    let packed = &data[offset..];

    let mut bits = Vec::with_capacity(count);
    for i in 0..count {
        bits.push((packed[i / 8] >> (i % 8)) & 1 == 1);
    }

    Ok(TxMerkleProof { nodes, bits })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{AssetType, Genesis};
    use crate::proof::encode::{
        encode_proof, encode_tapscript_proof, encode_taproot_proof,
        encode_tx_merkle_proof,
    };

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn test_proof() -> Proof {
        let mut proof = decode_proof(&{
            let mut buf = PROOF_MAGIC_BYTES.to_vec();
            buf.extend_from_slice(&TlvStream::new().encode());
            buf
        })
        .unwrap();
        proof.asset = Asset::new_genesis(
            test_genesis(),
            1000,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );
        proof.inclusion_proof.internal_key = SerializedKey([0x02; 33]);
        proof.block_height = 100;
        proof.genesis_reveal = Some(test_genesis());
        proof
    }

    #[test]
    fn test_proof_round_trip_basic() {
        let proof = test_proof();
        let encoded = encode_proof(&proof);
        let decoded = decode_proof(&encoded).unwrap();
        assert_eq!(encode_proof(&decoded), encoded);
    }

    #[test]
    fn test_proof_round_trip_challenge_witness_and_alt_leaves() {
        let mut proof = test_proof();
        proof.challenge_witness = Some(vec![vec![0xab; 64]]);
        let mut alt_leaf = default_asset();
        alt_leaf.script_version = ScriptVersion(1);
        alt_leaf.script_key =
            ScriptKey::from_pub_key(SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k }));
        proof.alt_leaves = vec![alt_leaf];

        let encoded = encode_proof(&proof);
        let decoded = decode_proof(&encoded).unwrap();
        assert_eq!(encode_proof(&decoded), encoded);
        assert_eq!(
            decoded.challenge_witness.as_ref().unwrap()[0],
            vec![0xab; 64]
        );
        assert_eq!(decoded.alt_leaves.len(), 1);
    }

    #[test]
    fn test_tapscript_proof_round_trip() {
        let proof = TapscriptProof {
            tap_preimage_1: Some(TapscriptPreimage {
                sibling_type: 0,
                sibling_preimage: vec![0xc0, 0x01, 0x02],
            }),
            tap_preimage_2: None,
            bip86: false,
            unknown_odd_types: BTreeMap::new(),
        };
        let encoded = encode_tapscript_proof(&proof);
        let decoded = decode_tapscript_proof(&encoded).unwrap();
        assert_eq!(encode_tapscript_proof(&decoded), encoded);
        assert!(!decoded.bip86);
        assert_eq!(
            decoded.tap_preimage_1.unwrap().sibling_preimage,
            vec![0xc0, 0x01, 0x02]
        );
    }

    #[test]
    fn test_taproot_proof_bip86_round_trip() {
        let proof = TaprootProof {
            output_index: 1,
            internal_key: SerializedKey([0x02; 33]),
            commitment_proof: None,
            tapscript_proof: Some(TapscriptProof {
                tap_preimage_1: None,
                tap_preimage_2: None,
                bip86: true,
                unknown_odd_types: BTreeMap::new(),
            }),
            unknown_odd_types: BTreeMap::new(),
        };
        let encoded = encode_taproot_proof(&proof);
        let decoded = decode_taproot_proof(&encoded).unwrap();
        assert_eq!(encode_taproot_proof(&decoded), encoded);
        assert!(decoded.tapscript_proof.unwrap().bip86);
    }

    #[test]
    fn test_tx_merkle_proof_round_trip() {
        let proof = TxMerkleProof {
            nodes: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
            bits: vec![true, false, true],
        };
        let encoded = encode_tx_merkle_proof(&proof);
        let decoded = decode_tx_merkle_proof(&encoded).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_group_key_reveal_v0_round_trip() {
        use crate::proof::encode::encode_group_key_reveal;

        let reveal = GroupKeyReveal::V0(GroupKeyRevealV0 {
            raw_key: SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k }),
            tapscript_root: vec![0x04; 32],
        });
        let encoded = encode_group_key_reveal(&reveal);
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, reveal);

        // Empty tapscript root variant.
        let reveal = GroupKeyReveal::V0(GroupKeyRevealV0 {
            raw_key: SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k }),
            tapscript_root: vec![],
        });
        let encoded = encode_group_key_reveal(&reveal);
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, reveal);
    }

    #[test]
    fn test_group_key_reveal_v1_round_trip() {
        use crate::proof::encode::encode_group_key_reveal;

        let reveal = GroupKeyReveal::V1(GroupKeyRevealV1 {
            version: 2,
            internal_key: SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k }),
            tapscript: GroupKeyRevealTapscript {
                version: 2,
                root: vec![0x05; 32],
                custom_subtree_root: Some([0x06; 32]),
            },
        });
        let encoded = encode_group_key_reveal(&reveal);
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, reveal);
    }

    /// A 33-byte key with a valid compressed prefix whose x coordinate
    /// (0x03 repeated) is not on the curve.
    fn off_curve_key() -> SerializedKey {
        let mut k = [0x03; 33];
        k[0] = 0x02;
        SerializedKey(k)
    }

    #[test]
    fn test_decode_taproot_proof_rejects_off_curve_internal_key() {
        let proof = TaprootProof {
            output_index: 1,
            internal_key: off_curve_key(),
            commitment_proof: None,
            tapscript_proof: Some(TapscriptProof {
                tap_preimage_1: None,
                tap_preimage_2: None,
                bip86: true,
                unknown_odd_types: BTreeMap::new(),
            }),
            unknown_odd_types: BTreeMap::new(),
        };
        let encoded = encode_taproot_proof(&proof);
        assert!(decode_taproot_proof(&encoded).is_err());
    }

    #[test]
    fn test_group_key_reveal_v0_rejects_off_curve_key() {
        use crate::proof::encode::encode_group_key_reveal;

        // V0 validates the raw key on-curve at decode time (Go's
        // SerializedKeyDecoder).
        let reveal = GroupKeyReveal::V0(GroupKeyRevealV0 {
            raw_key: off_curve_key(),
            tapscript_root: vec![0x04; 32],
        });
        let encoded = encode_group_key_reveal(&reveal);
        assert!(decode_group_key_reveal(&encoded).is_err());
    }

    #[test]
    fn test_group_key_reveal_v1_keeps_raw_internal_key() {
        use crate::proof::encode::encode_group_key_reveal;

        // V1 stores the internal key RAW at decode time, like Go's
        // primitive [33]byte record (asset/group_key.go:322); an
        // off-curve key must decode successfully.
        let reveal = GroupKeyReveal::V1(GroupKeyRevealV1 {
            version: 2,
            internal_key: off_curve_key(),
            tapscript: GroupKeyRevealTapscript {
                version: 2,
                root: vec![0x05; 32],
                custom_subtree_root: None,
            },
        });
        let encoded = encode_group_key_reveal(&reveal);
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, reveal);
    }

    #[test]
    fn test_decode_rejects_bad_magic() {
        assert!(matches!(
            decode_proof(&[0x00, 0x01, 0x02, 0x03]),
            Err(ProofError::InvalidMagic)
        ));
    }

    #[test]
    fn test_decode_rejects_unknown_even_type() {
        let mut buf = PROOF_MAGIC_BYTES.to_vec();
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::bytes(100, &[0x01]));
        buf.extend_from_slice(&stream.encode());
        assert!(decode_proof(&buf).is_err());
    }
}
