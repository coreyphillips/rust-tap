// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TLV encoding for Taproot Asset types, compatible with Go's encoding.
//!
//! This implements the wire format used by Go's `asset/encoding.go` so that
//! encoded bytes are identical across implementations.

use super::bigsize::encode_bigsize;
use super::tlv::{encode_var_bytes, TlvRecord, TlvStream};
use crate::asset::{
    tlv_types, Asset, AssetVersion, EncodeType, Genesis, Witness,
};
use crate::mssmt;

/// Encodes a Genesis into its inner wire format (NOT wrapped in TLV).
///
/// Format: `outpoint(36) || var_bytes(tag) || meta_hash(32) || BE(output_index)(4) || type(1)`
///
/// This matches Go's `GenesisEncoder`.
pub fn encode_genesis(genesis: &Genesis) -> Vec<u8> {
    let mut buf = Vec::new();

    // OutPoint: 32-byte hash + 4-byte BE u32 index.
    buf.extend_from_slice(&genesis.first_prev_out.txid);
    buf.extend_from_slice(&genesis.first_prev_out.vout.to_be_bytes());

    // Tag: BigSize-prefixed bytes.
    encode_var_bytes(&mut buf, genesis.tag.as_bytes());

    // MetaHash: 32 raw bytes.
    buf.extend_from_slice(&genesis.meta_hash);

    // OutputIndex: BE u32.
    buf.extend_from_slice(&genesis.output_index.to_be_bytes());

    // Type: u8.
    buf.push(genesis.asset_type as u8);

    buf
}

/// Encodes a witness stack (TxWitness) in Bitcoin wire format.
///
/// Format: `BigSize(num_elements) [BigSize(elem_len) elem_bytes]...`
fn encode_tx_witness(witness: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, witness.len() as u64);
    for elem in witness {
        encode_var_bytes(&mut buf, elem);
    }
    buf
}

/// Encodes a single Witness into wire format using TLV sub-records.
///
/// Sub-record types (matching Go's `Witness.encodeRecords`):
/// - Type 1: PrevID (101 bytes), emitted whenever present
/// - Type 3: TxWitness, emitted when non-empty AND encoding is Normal
/// - Type 5: SplitCommitment (compressed proof + root asset), emitted
///   whenever present
///
/// The three records are independent: a witness carrying both a TxWitness
/// and a SplitCommitment emits both records. Segwit encoding strips only
/// the TxWitness record; PrevID and SplitCommitment are always kept.
fn encode_witness(witness: &Witness, encode_type: EncodeType) -> Vec<u8> {
    use crate::asset::tlv_types;

    let mut stream = TlvStream::new();

    // Type 1: PrevID (36 outpoint + 32 asset ID + 33 script key = 101 bytes).
    if let Some(ref prev_id) = witness.prev_id {
        let mut prev_id_bytes = Vec::with_capacity(101);
        prev_id_bytes.extend_from_slice(&prev_id.out_point.txid);
        prev_id_bytes
            .extend_from_slice(&prev_id.out_point.vout.to_be_bytes());
        prev_id_bytes.extend_from_slice(prev_id.id.as_bytes());
        prev_id_bytes.extend_from_slice(prev_id.script_key.as_bytes());
        stream.push(TlvRecord::bytes(
            tlv_types::WITNESS_PREV_ID,
            &prev_id_bytes,
        ));
    }

    // Type 3: TxWitness (only for Normal encoding; Segwit strips it).
    if !witness.tx_witness.is_empty() && encode_type == EncodeType::Normal {
        let witness_bytes = encode_tx_witness(&witness.tx_witness);
        stream.push(TlvRecord::bytes(
            tlv_types::WITNESS_TX_WITNESS,
            &witness_bytes,
        ));
    }

    // Type 5: SplitCommitment (whenever present, regardless of encoding).
    if let Some(ref split) = witness.split_commitment {
        let mut split_bytes = Vec::new();
        let proof_bytes = split.proof.compress().encode();
        encode_var_bytes(&mut split_bytes, &proof_bytes);
        encode_var_bytes(&mut split_bytes, &split.root_asset);
        stream.push(TlvRecord::bytes(
            tlv_types::WITNESS_SPLIT_COMMITMENT,
            &split_bytes,
        ));
    }

    stream.encode()
}

/// Encodes the PrevWitnesses array for TLV.
///
/// Format: `BigSize(count) [BigSize(witness_len) witness_bytes]...`
fn encode_prev_witnesses(
    witnesses: &[Witness],
    encode_type: EncodeType,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, witnesses.len() as u64);
    for w in witnesses {
        let witness_bytes = encode_witness(w, encode_type);
        encode_var_bytes(&mut buf, &witness_bytes);
    }
    buf
}

/// Encodes an Asset into a TLV stream.
///
/// This matches Go's `Asset.encodeRecords()` / `Asset.Encode()`.
///
/// The PrevWitnesses record (type 11) is emitted whenever the asset has
/// any previous witnesses, for both encoding types. When `encode_type` is
/// `Segwit`, only the raw TxWitness sub-record inside each witness is
/// stripped (signatures are excluded from V1 MS-SMT leaves), while the
/// PrevID and SplitCommitment sub-records are always kept.
pub fn encode_asset(asset: &Asset, encode_type: EncodeType) -> Vec<u8> {
    let mut stream = TlvStream::new();

    // Type 0: Version (always).
    stream.push(TlvRecord::u8(tlv_types::LEAF_VERSION, asset.version as u8));

    // Type 2: Genesis (always).
    stream.push(TlvRecord::bytes(
        tlv_types::LEAF_GENESIS,
        &encode_genesis(&asset.genesis),
    ));

    // Type 4: AssetType (always).
    stream.push(TlvRecord::u8(
        tlv_types::LEAF_TYPE,
        asset.genesis.asset_type as u8,
    ));

    // Type 6: Amount (always, as BigSize varint).
    stream.push(TlvRecord::varint(tlv_types::LEAF_AMOUNT, asset.amount));

    // Type 7: LockTime (only if > 0).
    if asset.lock_time > 0 {
        stream.push(TlvRecord::varint(
            tlv_types::LEAF_LOCK_TIME,
            asset.lock_time,
        ));
    }

    // Type 9: RelativeLockTime (only if > 0).
    if asset.relative_lock_time > 0 {
        stream.push(TlvRecord::varint(
            tlv_types::LEAF_RELATIVE_LOCK_TIME,
            asset.relative_lock_time,
        ));
    }

    // Type 11: PrevWitnesses (whenever non-empty, for both encoding
    // types; the encode type only controls the inner TxWitness records).
    if !asset.prev_witnesses.is_empty() {
        stream.push(TlvRecord::bytes(
            tlv_types::LEAF_PREV_WITNESS,
            &encode_prev_witnesses(&asset.prev_witnesses, encode_type),
        ));
    }

    // Type 13: SplitCommitmentRoot (only if present).
    // 40 bytes: 32-byte hash + 8-byte BE u64 sum.
    if let Some((ref hash, sum)) = asset.split_commitment_root {
        let mut root_bytes = Vec::with_capacity(40);
        root_bytes.extend_from_slice(hash.as_bytes());
        root_bytes.extend_from_slice(&sum.to_be_bytes());
        stream.push(TlvRecord::bytes(
            tlv_types::LEAF_SPLIT_COMMITMENT_ROOT,
            &root_bytes,
        ));
    }

    // Type 14: ScriptVersion (always).
    stream.push(TlvRecord::u16(
        tlv_types::LEAF_SCRIPT_VERSION,
        asset.script_version.0,
    ));

    // Type 16: ScriptKey (always, 33-byte compressed pubkey).
    stream.push(TlvRecord::bytes(
        tlv_types::LEAF_SCRIPT_KEY,
        asset.script_key.serialized().as_bytes(),
    ));

    // Type 17: GroupKey (only if present, 33-byte compressed pubkey).
    if let Some(ref gk) = asset.group_key {
        stream.push(TlvRecord::bytes(
            tlv_types::LEAF_GROUP_KEY,
            gk.group_pub_key.as_bytes(),
        ));
    }

    // Encode unknown odd types (forward compatibility).
    for (&type_num, value) in &asset.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    stream.encode()
}

/// Encodes an asset for use as an MS-SMT leaf value.
///
/// V0 assets: full encoding with witnesses.
/// V1 assets: encoding without witnesses (segwit style).
pub fn encode_asset_leaf(asset: &Asset) -> Vec<u8> {
    match asset.version {
        AssetVersion::V0 => encode_asset(asset, EncodeType::Normal),
        AssetVersion::V1 => encode_asset(asset, EncodeType::Segwit),
    }
}

/// Creates an MS-SMT leaf node from an asset using proper TLV encoding.
///
/// This replaces the placeholder `asset_leaf()` function. The leaf value
/// is the TLV-encoded asset bytes, and the sum is the asset amount.
pub fn asset_to_leaf(asset: &Asset) -> mssmt::LeafNode {
    let encoded = encode_asset_leaf(asset);
    mssmt::LeafNode::new(encoded, asset.amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-asset".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn test_asset() -> Asset {
        Asset::new_genesis(
            test_genesis(),
            1000,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        )
    }

    #[test]
    fn test_genesis_encoding_deterministic() {
        let genesis = test_genesis();
        let enc1 = encode_genesis(&genesis);
        let enc2 = encode_genesis(&genesis);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_genesis_encoding_size() {
        let genesis = test_genesis();
        let encoded = encode_genesis(&genesis);
        // 32 (txid) + 4 (vout BE) + 1 (tag len) + 10 (tag "test-asset")
        // + 32 (meta_hash) + 4 (output_index) + 1 (type) = 84 bytes
        assert_eq!(encoded.len(), 84);
    }

    #[test]
    fn test_asset_encoding_has_all_required_types() {
        let asset = test_asset();
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();

        // Must have: version(0), genesis(2), type(4), amount(6),
        // witnesses(11), script_version(14), script_key(16).
        assert!(stream.get(0).is_some(), "missing version");
        assert!(stream.get(2).is_some(), "missing genesis");
        assert!(stream.get(4).is_some(), "missing type");
        assert!(stream.get(6).is_some(), "missing amount");
        assert!(stream.get(11).is_some(), "missing witnesses");
        assert!(stream.get(14).is_some(), "missing script_version");
        assert!(stream.get(16).is_some(), "missing script_key");
    }

    /// Decodes the type-11 PrevWitnesses record value into the inner
    /// per-witness TLV streams.
    fn decode_witness_streams(
        prev_witness_value: &[u8],
    ) -> Vec<super::super::tlv::TlvStream> {
        use crate::encoding::bigsize::decode_bigsize;

        let (count, mut offset) =
            decode_bigsize(prev_witness_value).unwrap();
        let mut streams = Vec::new();
        for _ in 0..count {
            let (len, consumed) =
                decode_bigsize(&prev_witness_value[offset..]).unwrap();
            offset += consumed;
            let end = offset + len as usize;
            let stream = super::super::tlv::TlvStream::decode(
                &prev_witness_value[offset..end],
            )
            .unwrap();
            streams.push(stream);
            offset = end;
        }
        streams
    }

    #[test]
    fn test_asset_encoding_segwit_keeps_prev_witness_record() {
        let mut asset = test_asset();
        asset.prev_witnesses[0].tx_witness = vec![vec![0xab; 64]];
        let encoded = encode_asset(&asset, EncodeType::Segwit);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();

        // Segwit encoding keeps the type-11 record (matching Go); only
        // the inner TxWitness sub-record (type 3) is stripped.
        let pw = stream
            .get(11)
            .expect("segwit must keep the prev witness record");
        let witnesses = decode_witness_streams(&pw.value);
        assert_eq!(witnesses.len(), 1);
        assert!(witnesses[0].get(1).is_some(), "PrevID must be kept");
        assert!(
            witnesses[0].get(3).is_none(),
            "TxWitness must be stripped for segwit"
        );
        // And should still have everything else.
        assert!(stream.get(0).is_some());
        assert!(stream.get(6).is_some());
        assert!(stream.get(16).is_some());
    }

    #[test]
    fn test_witness_tx_and_split_commitment_both_encoded() {
        use crate::asset::SplitCommitmentWitness;
        use crate::mssmt;

        let mut asset = test_asset();
        asset.prev_witnesses[0].tx_witness = vec![vec![0xab; 64]];
        asset.prev_witnesses[0].split_commitment =
            Some(SplitCommitmentWitness {
                proof: mssmt::Proof::new(vec![
                    mssmt::Node::Computed(
                        mssmt::ComputedNode::new(
                            mssmt::NodeHash::EMPTY,
                            0
                        )
                    );
                    mssmt::MAX_TREE_LEVELS
                ]),
                root_asset: vec![0x01, 0x02, 0x03],
            });

        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();
        let pw = stream.get(11).unwrap();
        let witnesses = decode_witness_streams(&pw.value);
        assert_eq!(witnesses.len(), 1);
        // Both TxWitness (3) and SplitCommitment (5) must be present
        // when both are set (matching Go, which emits both records).
        assert!(witnesses[0].get(3).is_some(), "TxWitness missing");
        assert!(witnesses[0].get(5).is_some(), "SplitCommitment missing");
    }

    #[test]
    fn test_asset_encoding_sorted() {
        let asset = test_asset();
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();

        let types: Vec<u64> =
            stream.records().iter().map(|r| r.type_num).collect();
        let mut sorted = types.clone();
        sorted.sort();
        assert_eq!(types, sorted, "records must be sorted by type");
    }

    #[test]
    fn test_asset_amount_as_varint() {
        let asset = test_asset();
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();

        let amount_record = stream.get(6).unwrap();
        let amount = amount_record.as_varint().unwrap();
        assert_eq!(amount, 1000);
    }

    #[test]
    fn test_asset_leaf_v0_includes_witnesses() {
        let asset = test_asset();
        assert_eq!(asset.version, AssetVersion::V0);
        let leaf = asset_to_leaf(&asset);
        // The leaf value should contain witness data.
        let stream =
            super::super::tlv::TlvStream::decode(&leaf.value).unwrap();
        assert!(stream.get(11).is_some());
        assert_eq!(leaf.sum, 1000);
    }

    #[test]
    fn test_asset_leaf_v1_strips_only_tx_witness() {
        let mut asset = test_asset();
        asset.version = AssetVersion::V1;
        asset.prev_witnesses[0].tx_witness = vec![vec![0xcd; 64]];
        let leaf = asset_to_leaf(&asset);
        let stream =
            super::super::tlv::TlvStream::decode(&leaf.value).unwrap();
        // V1 leaves keep the type-11 record (matching Go); only the raw
        // TxWitness sub-record is stripped so signatures do not affect
        // the leaf hash.
        let pw = stream.get(11).expect("V1 leaf must keep prev witnesses");
        let witnesses = decode_witness_streams(&pw.value);
        assert_eq!(witnesses.len(), 1);
        assert!(witnesses[0].get(1).is_some(), "PrevID must be kept");
        assert!(witnesses[0].get(3).is_none(), "TxWitness must be stripped");
    }

    #[test]
    fn test_optional_fields_omitted_when_zero() {
        let asset = test_asset();
        assert_eq!(asset.lock_time, 0);
        assert_eq!(asset.relative_lock_time, 0);
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();
        assert!(stream.get(7).is_none(), "lock_time should be omitted");
        assert!(
            stream.get(9).is_none(),
            "relative_lock_time should be omitted"
        );
    }

    #[test]
    fn test_optional_fields_present_when_nonzero() {
        let mut asset = test_asset();
        asset.lock_time = 100;
        asset.relative_lock_time = 50;
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();
        assert_eq!(stream.get(7).unwrap().as_varint().unwrap(), 100);
        assert_eq!(stream.get(9).unwrap().as_varint().unwrap(), 50);
    }

    #[test]
    fn test_group_key_included_when_present() {
        let mut asset = test_asset();
        asset.group_key = Some(crate::asset::GroupKey {
            version: crate::asset::GroupKeyVersion::V0,
            raw_key: SerializedKey([0x03; 33]),
            group_pub_key: SerializedKey([0x04; 33]),
            tapscript_root: vec![],
            witness: vec![],
        });

        let encoded = encode_asset(&asset, EncodeType::Normal);
        let stream = super::super::tlv::TlvStream::decode(&encoded).unwrap();
        let gk = stream.get(17).unwrap();
        assert_eq!(gk.value.len(), 33);
        assert_eq!(gk.value[0], 0x04);
    }

    #[test]
    fn test_encoding_deterministic() {
        let asset = test_asset();
        let enc1 = encode_asset(&asset, EncodeType::Normal);
        let enc2 = encode_asset(&asset, EncodeType::Normal);
        assert_eq!(enc1, enc2);
    }
}
