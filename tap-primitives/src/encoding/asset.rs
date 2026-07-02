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

use std::collections::BTreeMap;

use super::bigsize::{decode_bigsize, encode_bigsize};
use super::tlv::{
    decode_var_bytes, encode_var_bytes, TlvError, TlvRecord, TlvStream,
};
use crate::asset::{
    tlv_types, Asset, AssetId, AssetType, AssetVersion, EncodeType, Genesis,
    GroupKey, GroupKeyVersion, OutPoint, PrevId, ScriptKey, ScriptVersion,
    SerializedKey, SplitCommitmentWitness, Witness, MAX_ASSET_NAME_LENGTH,
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
    buf.push(genesis.asset_type.to_u8());

    buf
}

/// Encodes a witness stack (TxWitness) in Bitcoin wire format.
///
/// Format: `BigSize(num_elements) [BigSize(elem_len) elem_bytes]...`
///
/// This matches Go's `TxWitnessEncoder` and is also used for the proof
/// challenge witness record.
pub fn encode_tx_witness(witness: &[Vec<u8>]) -> Vec<u8> {
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
    stream.push(TlvRecord::u8(
        tlv_types::LEAF_VERSION,
        asset.version.to_u8(),
    ));

    // Type 2: Genesis (always).
    stream.push(TlvRecord::bytes(
        tlv_types::LEAF_GENESIS,
        &encode_genesis(&asset.genesis),
    ));

    // Type 4: AssetType (always).
    stream.push(TlvRecord::u8(
        tlv_types::LEAF_TYPE,
        asset.genesis.asset_type.to_u8(),
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
        AssetVersion::V1 => encode_asset(asset, EncodeType::Segwit),
        // V0 (and unknown versions, which Go rejects before leaf
        // creation) use the full encoding.
        _ => encode_asset(asset, EncodeType::Normal),
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

/// Encodes an asset as an AltLeaf TLV stream.
///
/// Matches Go's `Asset.encodeAltLeafRecords` in `asset/asset.go`: only
/// the previous witnesses (type 11, when non-empty), script version
/// (type 14), and script key (type 16) are encoded, plus any unknown
/// odd types. The genesis, group key, amount, and version fields of an
/// alt leaf are static and omitted.
pub fn encode_alt_leaf(asset: &Asset) -> Vec<u8> {
    let mut stream = TlvStream::new();

    if !asset.prev_witnesses.is_empty() {
        stream.push(TlvRecord::bytes(
            tlv_types::LEAF_PREV_WITNESS,
            &encode_prev_witnesses(
                &asset.prev_witnesses,
                EncodeType::Normal,
            ),
        ));
    }

    stream.push(TlvRecord::u16(
        tlv_types::LEAF_SCRIPT_VERSION,
        asset.script_version.0,
    ));

    stream.push(TlvRecord::bytes(
        tlv_types::LEAF_SCRIPT_KEY,
        asset.script_key.serialized().as_bytes(),
    ));

    for (&type_num, value) in &asset.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    stream.encode()
}

/// Maximum number of witnesses / witness stack elements accepted while
/// decoding, matching Go's `math.MaxUint16` bound in `asset/encoding.go`.
const MAX_DECODE_ITEMS: u64 = u16::MAX as u64;

fn decoding_err(msg: impl Into<String>) -> TlvError {
    TlvError::DecodingError(msg.into())
}

/// Reads a fixed number of bytes from `data` at `offset`, advancing it.
fn take<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], TlvError> {
    if *offset + len > data.len() {
        return Err(TlvError::UnexpectedEof);
    }
    let out = &data[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

/// Decodes a Genesis from its inner wire format (NOT wrapped in TLV).
///
/// Inverse of [`encode_genesis`], matching Go's `GenesisDecoder` in
/// `asset/encoding.go`: `outpoint(36) || var_bytes(tag) || meta_hash(32)
/// || BE(output_index)(4) || type(1)`. Trailing bytes are rejected.
pub fn decode_genesis(data: &[u8]) -> Result<Genesis, TlvError> {
    let mut offset = 0;

    // OutPoint: 32-byte hash + 4-byte BE u32 index.
    let txid: [u8; 32] = take(data, &mut offset, 32)?.try_into().unwrap();
    let vout = u32::from_be_bytes(
        take(data, &mut offset, 4)?.try_into().unwrap(),
    );

    // Tag: BigSize-prefixed bytes, limited to the max asset name length
    // (Go passes MaxAssetNameLength to InlineVarBytesDecoder).
    let (tag_bytes, consumed) = decode_var_bytes(&data[offset..])?;
    if tag_bytes.len() > MAX_ASSET_NAME_LENGTH {
        return Err(decoding_err(format!(
            "asset tag too long: {}",
            tag_bytes.len()
        )));
    }
    offset += consumed;
    let tag = String::from_utf8(tag_bytes)
        .map_err(|e| decoding_err(format!("invalid tag: {}", e)))?;

    // MetaHash: 32 raw bytes.
    let meta_hash: [u8; 32] =
        take(data, &mut offset, 32)?.try_into().unwrap();

    // OutputIndex: BE u32.
    let output_index = u32::from_be_bytes(
        take(data, &mut offset, 4)?.try_into().unwrap(),
    );

    // Type: u8 (open value, matching Go's TypeDecoder).
    let asset_type = AssetType::from_u8(take(data, &mut offset, 1)?[0])
        .map_err(|e| decoding_err(e.to_string()))?;

    if offset != data.len() {
        return Err(decoding_err("trailing bytes after genesis"));
    }

    Ok(Genesis {
        first_prev_out: OutPoint { txid, vout },
        tag,
        meta_hash,
        output_index,
        asset_type,
    })
}

/// Decodes a Bitcoin-style witness stack from wire format.
///
/// Inverse of `encode_tx_witness`, matching Go's `TxWitnessDecoder`:
/// `BigSize(num_elements) [BigSize(elem_len) elem_bytes]...`. Trailing
/// bytes are rejected.
pub fn decode_tx_witness(data: &[u8]) -> Result<Vec<Vec<u8>>, TlvError> {
    let (count, mut offset) = decode_bigsize(data)?;
    if count > MAX_DECODE_ITEMS {
        return Err(decoding_err(format!(
            "too many witness elements: {}",
            count
        )));
    }

    let mut witness = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (elem, consumed) = decode_var_bytes(&data[offset..])?;
        offset += consumed;
        witness.push(elem);
    }

    if offset != data.len() {
        return Err(decoding_err("trailing bytes after tx witness"));
    }

    Ok(witness)
}

/// Decodes a PrevID from its 101-byte wire format:
/// `outpoint(36) || asset_id(32) || script_key(33)`.
///
/// Matches Go's `PrevIDDecoder` in `asset/encoding.go`.
fn decode_prev_id(data: &[u8]) -> Result<PrevId, TlvError> {
    if data.len() != PrevId::ENCODED_SIZE {
        return Err(decoding_err(format!(
            "invalid PrevID length: {}",
            data.len()
        )));
    }

    let mut offset = 0;
    let txid: [u8; 32] = take(data, &mut offset, 32)?.try_into().unwrap();
    let vout = u32::from_be_bytes(
        take(data, &mut offset, 4)?.try_into().unwrap(),
    );
    let id: [u8; 32] = take(data, &mut offset, 32)?.try_into().unwrap();
    let script_key: [u8; 33] =
        take(data, &mut offset, 33)?.try_into().unwrap();

    Ok(PrevId {
        out_point: OutPoint { txid, vout },
        id: AssetId(id),
        script_key: SerializedKey(script_key),
    })
}

/// Decodes a SplitCommitment witness sub-record.
///
/// Inverse of the type-5 payload written by `encode_witness`, matching
/// Go's `SplitCommitmentDecoder`: `var_bytes(compressed mssmt proof) ||
/// var_bytes(root_asset)`. The compressed proof is decompressed into a
/// full proof; the root asset is validated but kept as raw bytes.
fn decode_split_commitment(
    data: &[u8],
) -> Result<SplitCommitmentWitness, TlvError> {
    let (proof_bytes, consumed) = decode_var_bytes(data)?;
    let mut offset = consumed;

    let compressed = mssmt::CompressedProof::decode(&proof_bytes)
        .map_err(decoding_err)?;
    let proof = compressed.decompress().map_err(decoding_err)?;

    let (root_asset, consumed) = decode_var_bytes(&data[offset..])?;
    offset += consumed;

    if offset != data.len() {
        return Err(decoding_err("trailing bytes after split commitment"));
    }

    // Go decodes the root asset into a full Asset; we keep the raw bytes
    // (see SplitCommitmentWitness) but still validate that they parse.
    decode_asset(&root_asset)?;

    Ok(SplitCommitmentWitness { proof, root_asset })
}

/// Decodes a single Witness from its TLV wire format.
///
/// Inverse of `encode_witness`, matching Go's `Witness.Decode` /
/// `Witness.DecodeRecords` in `asset/asset.go`: sub-records 1 (PrevID),
/// 3 (TxWitness), and 5 (SplitCommitment). Unknown even types are
/// rejected; unknown odd types are skipped (Go's plain `stream.Decode`
/// does not preserve them for witnesses).
pub fn decode_witness(data: &[u8]) -> Result<Witness, TlvError> {
    let stream = TlvStream::decode(data)?;

    let mut witness = Witness {
        prev_id: None,
        tx_witness: Vec::new(),
        split_commitment: None,
    };

    for record in stream.records() {
        match record.type_num {
            tlv_types::WITNESS_PREV_ID => {
                witness.prev_id = Some(decode_prev_id(&record.value)?);
            }
            tlv_types::WITNESS_TX_WITNESS => {
                witness.tx_witness = decode_tx_witness(&record.value)?;
            }
            tlv_types::WITNESS_SPLIT_COMMITMENT => {
                witness.split_commitment =
                    Some(decode_split_commitment(&record.value)?);
            }
            other if other % 2 == 0 => {
                return Err(TlvError::UnknownRequiredType(other));
            }
            // Unknown odd (optional) types are ignored.
            _ => {}
        }
    }

    Ok(witness)
}

/// Decodes the PrevWitnesses array from the type-11 record payload.
///
/// Inverse of `encode_prev_witnesses`, matching Go's `WitnessDecoder`:
/// `BigSize(count) [BigSize(witness_len) witness_bytes]...`.
pub fn decode_prev_witnesses(
    data: &[u8],
) -> Result<Vec<Witness>, TlvError> {
    let (count, mut offset) = decode_bigsize(data)?;
    if count > MAX_DECODE_ITEMS {
        return Err(decoding_err(format!(
            "too many witnesses: {}",
            count
        )));
    }

    let mut witnesses = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (witness_bytes, consumed) = decode_var_bytes(&data[offset..])?;
        offset += consumed;
        witnesses.push(decode_witness(&witness_bytes)?);
    }

    if offset != data.len() {
        return Err(decoding_err("trailing bytes after witnesses"));
    }

    Ok(witnesses)
}

/// Decodes the type-13 SplitCommitmentRoot record payload:
/// `hash(32) || BE(sum)(8)`.
fn decode_split_commitment_root(
    data: &[u8],
) -> Result<(mssmt::NodeHash, u64), TlvError> {
    if data.len() != 40 {
        return Err(decoding_err(format!(
            "invalid split commitment root length: {}",
            data.len()
        )));
    }
    let hash: [u8; 32] = data[..32].try_into().unwrap();
    let sum = u64::from_be_bytes(data[32..40].try_into().unwrap());
    Ok((mssmt::NodeHash(hash), sum))
}

/// Checks that a fixed-size record has the expected length.
fn expect_len(
    record: &TlvRecord,
    expected: usize,
    what: &str,
) -> Result<(), TlvError> {
    if record.value.len() != expected {
        return Err(decoding_err(format!(
            "invalid {} length: expected {}, got {}",
            what,
            expected,
            record.value.len()
        )));
    }
    Ok(())
}

/// Decodes a BigSize varint record value, rejecting trailing bytes.
fn decode_varint_record(record: &TlvRecord) -> Result<u64, TlvError> {
    let (val, consumed) = decode_bigsize(&record.value)?;
    if consumed != record.value.len() {
        return Err(decoding_err("trailing bytes after varint"));
    }
    Ok(val)
}

/// Decodes an Asset from its TLV wire format.
///
/// Inverse of [`encode_asset`], matching Go's `Asset.Decode` in
/// `asset/asset.go`: known types are {0, 2, 4, 6, 7, 9, 11, 13, 14, 16,
/// 17}; unknown even types are rejected (`TlvStrictDecode` over
/// `KnownAssetLeafTypes`); unknown odd types are preserved in
/// `unknown_odd_types`. Records that are absent leave the corresponding
/// field at its default value, exactly like Go's TLV decoding (this is
/// relied upon by AltLeaf decoding, which reuses the asset decoder for
/// streams that only carry a subset of the records).
pub fn decode_asset(data: &[u8]) -> Result<Asset, TlvError> {
    let stream = TlvStream::decode(data)?;

    let mut asset = Asset {
        version: AssetVersion::V0,
        genesis: Genesis {
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
        prev_witnesses: Vec::new(),
        split_commitment_root: None,
        script_version: ScriptVersion(0),
        script_key: ScriptKey::from_pub_key(SerializedKey([0u8; 33])),
        group_key: None,
        unknown_odd_types: BTreeMap::new(),
    };

    for record in stream.records() {
        match record.type_num {
            tlv_types::LEAF_VERSION => {
                expect_len(record, 1, "version")?;
                asset.version = AssetVersion::from_u8(record.value[0])
                    .map_err(|e| decoding_err(e.to_string()))?;
            }
            tlv_types::LEAF_GENESIS => {
                asset.genesis = decode_genesis(&record.value)?;
            }
            tlv_types::LEAF_TYPE => {
                // The type record overwrites the type carried inside the
                // genesis record, mirroring Go where Asset.Type is the
                // promoted (embedded) Genesis.Type field.
                expect_len(record, 1, "asset type")?;
                asset.genesis.asset_type =
                    AssetType::from_u8(record.value[0])
                        .map_err(|e| decoding_err(e.to_string()))?;
            }
            tlv_types::LEAF_AMOUNT => {
                asset.amount = decode_varint_record(record)?;
            }
            tlv_types::LEAF_LOCK_TIME => {
                asset.lock_time = decode_varint_record(record)?;
            }
            tlv_types::LEAF_RELATIVE_LOCK_TIME => {
                asset.relative_lock_time = decode_varint_record(record)?;
            }
            tlv_types::LEAF_PREV_WITNESS => {
                asset.prev_witnesses =
                    decode_prev_witnesses(&record.value)?;
            }
            tlv_types::LEAF_SPLIT_COMMITMENT_ROOT => {
                asset.split_commitment_root =
                    Some(decode_split_commitment_root(&record.value)?);
            }
            tlv_types::LEAF_SCRIPT_VERSION => {
                expect_len(record, 2, "script version")?;
                asset.script_version = ScriptVersion(u16::from_be_bytes(
                    record.value[..2].try_into().unwrap(),
                ));
            }
            tlv_types::LEAF_SCRIPT_KEY => {
                expect_len(record, 33, "script key")?;
                let key: [u8; 33] =
                    record.value[..].try_into().unwrap();
                asset.script_key =
                    ScriptKey::from_pub_key(SerializedKey(key));
            }
            tlv_types::LEAF_GROUP_KEY => {
                // The wire record only carries the tweaked group public
                // key (Go's GroupKeyDecoder in asset/encoding.go decodes
                // just GroupPubKey into a bare GroupKey). The remaining
                // fields cannot be recovered from a leaf, so we default
                // them: raw_key is set equal to the group public key and
                // the version to V0. This mirrors the Go behavior where
                // the decoded GroupKey has only GroupPubKey populated.
                expect_len(record, 33, "group key")?;
                let key: [u8; 33] =
                    record.value[..].try_into().unwrap();
                asset.group_key = Some(GroupKey {
                    version: GroupKeyVersion::V0,
                    raw_key: SerializedKey(key),
                    group_pub_key: SerializedKey(key),
                    tapscript_root: Vec::new(),
                    witness: Vec::new(),
                });
            }
            other if other % 2 == 0 => {
                return Err(TlvError::UnknownRequiredType(other));
            }
            other => {
                asset
                    .unknown_odd_types
                    .insert(other, record.value.clone());
            }
        }
    }

    Ok(asset)
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

    /// Asserts decode(encode(asset)) re-encodes to identical bytes and
    /// that the decoded struct encodes identically again.
    fn assert_asset_round_trip(asset: &Asset) {
        let encoded = encode_asset(asset, EncodeType::Normal);
        let decoded = decode_asset(&encoded).expect("decode failed");
        let re_encoded = encode_asset(&decoded, EncodeType::Normal);
        assert_eq!(encoded, re_encoded, "asset round-trip mismatch");
    }

    #[test]
    fn test_decode_round_trip_basic() {
        assert_asset_round_trip(&test_asset());
    }

    #[test]
    fn test_decode_round_trip_with_tx_witness() {
        let mut asset = test_asset();
        asset.prev_witnesses[0].tx_witness =
            vec![vec![0xab; 64], vec![0x01, 0x02]];
        assert_asset_round_trip(&asset);

        let encoded = encode_asset(&asset, EncodeType::Normal);
        let decoded = decode_asset(&encoded).unwrap();
        assert_eq!(decoded.prev_witnesses, asset.prev_witnesses);
    }

    #[test]
    fn test_decode_round_trip_with_split_commitment() {
        use crate::asset::SplitCommitmentWitness;

        let root_asset = encode_asset(&test_asset(), EncodeType::Normal);
        let mut asset = test_asset();
        asset.prev_witnesses[0].split_commitment =
            Some(SplitCommitmentWitness {
                proof: mssmt::Proof::new(vec![
                    mssmt::Node::Computed(
                        mssmt::ComputedNode::new(
                            mssmt::NodeHash([0x07; 32]),
                            7,
                        )
                    );
                    mssmt::MAX_TREE_LEVELS
                ]),
                root_asset,
            });
        assert_asset_round_trip(&asset);
    }

    #[test]
    fn test_decode_round_trip_with_group_key_and_lock_times() {
        let mut asset = test_asset();
        asset.lock_time = 1337;
        asset.relative_lock_time = 6;
        asset.group_key = Some(crate::asset::GroupKey {
            version: crate::asset::GroupKeyVersion::V0,
            raw_key: SerializedKey([0x03; 33]),
            group_pub_key: SerializedKey([0x03; 33]),
            tapscript_root: vec![],
            witness: vec![],
        });
        assert_asset_round_trip(&asset);

        let encoded = encode_asset(&asset, EncodeType::Normal);
        let decoded = decode_asset(&encoded).unwrap();
        assert_eq!(decoded.lock_time, 1337);
        assert_eq!(decoded.relative_lock_time, 6);
        assert_eq!(
            decoded.group_key.unwrap().group_pub_key,
            SerializedKey([0x03; 33])
        );
    }

    #[test]
    fn test_decode_round_trip_unknown_odd_types() {
        let mut asset = test_asset();
        asset.unknown_odd_types.insert(31337, b"unknown".to_vec());
        assert_asset_round_trip(&asset);

        let encoded = encode_asset(&asset, EncodeType::Normal);
        let decoded = decode_asset(&encoded).unwrap();
        assert_eq!(
            decoded.unknown_odd_types.get(&31337).unwrap(),
            b"unknown".as_slice()
        );
    }

    #[test]
    fn test_decode_rejects_unknown_even_type() {
        let asset = test_asset();
        let encoded = encode_asset(&asset, EncodeType::Normal);
        let mut stream = TlvStream::decode(&encoded).unwrap();
        stream.push(TlvRecord::bytes(31338, &[0x01]));
        let tampered = stream.encode();
        assert!(matches!(
            decode_asset(&tampered),
            Err(TlvError::UnknownRequiredType(31338))
        ));
    }

    #[test]
    fn test_decode_genesis_round_trip() {
        let genesis = test_genesis();
        let encoded = encode_genesis(&genesis);
        let decoded = decode_genesis(&encoded).unwrap();
        assert_eq!(decoded, genesis);
    }

    #[test]
    fn test_decode_genesis_rejects_truncated() {
        let genesis = test_genesis();
        let encoded = encode_genesis(&genesis);
        assert!(decode_genesis(&encoded[..encoded.len() - 1]).is_err());
        let mut extended = encoded;
        extended.push(0);
        assert!(decode_genesis(&extended).is_err());
    }

    #[test]
    fn test_decode_unknown_version_passthrough() {
        // Go's decoder accepts any version byte; we must round-trip it.
        let mut asset = test_asset();
        asset.version = AssetVersion::from_u8(2).unwrap();
        assert!(asset.version.is_unknown());
        assert_asset_round_trip(&asset);
    }
}
