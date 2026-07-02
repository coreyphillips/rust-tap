// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Send fragments for V2 TAP address sends, mirroring Go's
//! `proof.SendFragment` (proof/send.go).
//!
//! A send fragment is the message a sender transmits (ECIES-encrypted,
//! via the auth mailbox) to the receiver of a V2 TAP address send. It
//! contains everything the receiver needs to re-derive its per-asset
//! script keys, locate the on-chain anchor output, and fetch the
//! transfer proofs from the universe.

use std::collections::BTreeMap;

use crate::asset::{
    AssetId, AssetVersion, OutPoint, ScriptKeyDerivationMethod,
    SerializedKey,
};
use crate::encoding::bigsize::{decode_bigsize, encode_bigsize};
use crate::encoding::tlv::{TlvRecord, TlvStream};

use super::types::BlockHeader;
use super::ProofError;

/// The maximum number of outputs that can be included in a single send
/// fragment. This limits the size of the encrypted message that is sent
/// to the auth mailbox server. Matches Go's `MaxSendFragmentOutputs`.
pub const MAX_SEND_FRAGMENT_OUTPUTS: usize = 256;

/// TLV type numbers for send fragment records, matching Go's
/// `SendFragment*Type` constants in proof/records.go.
mod tlv_types {
    pub const VERSION: u64 = 0;
    pub const BLOCK_HEADER: u64 = 2;
    pub const BLOCK_HEIGHT: u64 = 4;
    pub const OUT_POINT: u64 = 6;
    pub const OUTPUTS: u64 = 8;
    pub const TAPROOT_ASSET_ROOT: u64 = 10;
}

/// The version of a send fragment. Mirrors Go's `SendFragmentVersion`.
///
/// Like Go, the wire format treats this as an open u8: unknown values
/// decode successfully and are rejected by [`SendFragment::validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFragmentVersion {
    /// Indicates an unknown version. Used to signal that the fragment
    /// version is not recognized.
    Unknown,
    /// The first version of the send fragment.
    V1,
    /// A future version we don't understand yet (never 0 or 1).
    Future(u8),
}

/// The latest known send fragment version, matching Go's
/// `LatestVersion`.
pub const LATEST_SEND_FRAGMENT_VERSION: SendFragmentVersion =
    SendFragmentVersion::V1;

impl SendFragmentVersion {
    /// Parses a version byte (open enum, like Go's plain cast).
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => SendFragmentVersion::Unknown,
            1 => SendFragmentVersion::V1,
            other => SendFragmentVersion::Future(other),
        }
    }

    /// Returns the wire byte for this version.
    pub fn to_u8(self) -> u8 {
        match self {
            SendFragmentVersion::Unknown => 0,
            SendFragmentVersion::V1 => 1,
            SendFragmentVersion::Future(v) => v,
        }
    }
}

/// A single asset UTXO or leaf that is being sent to the receiver of a
/// V2 TAP address send. Mirrors Go's `proof.SendOutput`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOutput {
    /// The version of the asset that is being sent.
    pub asset_version: AssetVersion,

    /// The amount of this asset output.
    pub amount: u64,

    /// The method used to derive the script key for this output.
    pub derivation_method: ScriptKeyDerivationMethod,

    /// The serialized script key that can be used to spend the output.
    /// The script key is derived from the recipient's internal key
    /// specified in the TAP address, and the asset ID of the output
    /// (using the derivation method specified in the above field).
    pub script_key: SerializedKey,
}

/// The message that needs to be sent from the sender to the receiver of
/// a V2 TAP address send. Mirrors Go's `proof.SendFragment`.
///
/// It contains all the information required to reconstruct the
/// information required to fetch proofs from the universe, and to
/// materialize the asset outputs on the receiver's side. We assume that
/// the receiver has access to the TAP address that was used to send the
/// assets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendFragment {
    /// The version of the send fragment.
    pub version: SendFragmentVersion,

    /// The block header of the block that contains the transaction.
    /// Useful to fetch the full block to extract the transaction on a
    /// node that doesn't have the transaction index enabled.
    pub block_header: BlockHeader,

    /// The height of the block that contains the transaction.
    pub block_height: u32,

    /// The outpoint of the transaction that contains the asset outputs
    /// that are being sent.
    pub outpoint: OutPoint,

    /// A map of asset IDs to the outputs that are being sent.
    ///
    /// Go uses an unordered map here; a `BTreeMap` gives rust-tap a
    /// canonical (sorted) encoding, which Go's decoder accepts since it
    /// reads the entries into a map.
    pub outputs: BTreeMap<AssetId, SendOutput>,

    /// The root of the Taproot Asset commitment tree.
    pub taproot_asset_root: [u8; 32],

    /// Unknown odd types encountered during decoding, preserved for
    /// forward compatibility (re-encoded when serializing).
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl Default for SendFragment {
    fn default() -> Self {
        SendFragment {
            version: SendFragmentVersion::Unknown,
            block_header: BlockHeader::default(),
            block_height: 0,
            outpoint: OutPoint::default(),
            outputs: BTreeMap::new(),
            taproot_asset_root: [0u8; 32],
            unknown_odd_types: BTreeMap::new(),
        }
    }
}

impl SendFragment {
    /// Ensures the send fragment is formally valid, mirroring Go's
    /// `SendFragment.Validate`: the version must be known and the
    /// number of outputs must be between 1 and
    /// [`MAX_SEND_FRAGMENT_OUTPUTS`].
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.version != LATEST_SEND_FRAGMENT_VERSION {
            return Err(ProofError::VerificationFailed(format!(
                "unknown send fragment version: {}",
                self.version.to_u8()
            )));
        }

        if self.outputs.is_empty()
            || self.outputs.len() > MAX_SEND_FRAGMENT_OUTPUTS
        {
            return Err(ProofError::VerificationFailed(format!(
                "invalid number of outputs: {}, must be between 1 \
                 and {}",
                self.outputs.len(),
                MAX_SEND_FRAGMENT_OUTPUTS
            )));
        }

        Ok(())
    }

    /// Encodes the fragment as a TLV stream, byte-compatible with Go's
    /// `SendFragment.Encode` (up to map ordering, which Go randomizes
    /// and rust-tap canonicalizes by asset ID).
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();

        // Type 0: version (1 byte).
        stream.push(TlvRecord::u8(
            tlv_types::VERSION,
            self.version.to_u8(),
        ));

        // Type 2: block header (80 bytes, Bitcoin wire encoding).
        stream.push(TlvRecord::bytes(
            tlv_types::BLOCK_HEADER,
            self.block_header.as_bytes(),
        ));

        // Type 4: block height (u32 BE).
        stream.push(TlvRecord::u32(
            tlv_types::BLOCK_HEIGHT,
            self.block_height,
        ));

        // Type 6: outpoint (32-byte txid + u32 BE index, matching Go's
        // asset.OutPointEncoder).
        let mut outpoint = Vec::with_capacity(36);
        outpoint.extend_from_slice(&self.outpoint.txid);
        outpoint.extend_from_slice(&self.outpoint.vout.to_be_bytes());
        stream.push(TlvRecord::bytes(tlv_types::OUT_POINT, &outpoint));

        // Type 8: outputs map, matching Go's SendOutputsEncoder:
        // BigSize(count) then per entry 32-byte asset ID followed by
        // the SendOutput fields.
        let mut outputs = Vec::new();
        encode_bigsize(&mut outputs, self.outputs.len() as u64);
        for (asset_id, output) in &self.outputs {
            outputs.extend_from_slice(asset_id.as_bytes());
            outputs.push(output.asset_version.to_u8());
            outputs.extend_from_slice(&output.amount.to_be_bytes());
            outputs.push(output.derivation_method as u8);
            outputs.extend_from_slice(output.script_key.as_bytes());
        }
        stream.push(TlvRecord::bytes(tlv_types::OUTPUTS, &outputs));

        // Type 10: taproot asset root (32 bytes).
        stream.push(TlvRecord::bytes(
            tlv_types::TAPROOT_ASSET_ROOT,
            &self.taproot_asset_root,
        ));

        // Unknown odd types, preserved from decoding.
        for (&type_num, value) in &self.unknown_odd_types {
            stream.push(TlvRecord::bytes(type_num, value));
        }

        stream.encode()
    }

    /// Decodes a fragment from a TLV stream, mirroring Go's
    /// `SendFragment.Decode` with `TlvStrictDecodeP2P`: unknown even
    /// types are rejected, unknown odd types are preserved, and
    /// missing records leave their fields at the zero value.
    pub fn decode(data: &[u8]) -> Result<Self, ProofError> {
        let stream = TlvStream::decode(data)
            .map_err(|e| ProofError::DecodingError(e.to_string()))?;

        let mut fragment = SendFragment::default();

        for record in stream.records() {
            match record.type_num {
                tlv_types::VERSION => {
                    fragment.version = SendFragmentVersion::from_u8(
                        record.as_u8().map_err(decode_err)?,
                    );
                }
                tlv_types::BLOCK_HEADER => {
                    let header: [u8; 80] = record
                        .value
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            ProofError::DecodingError(
                                "send fragment: invalid block header \
                                 length"
                                    .into(),
                            )
                        })?;
                    fragment.block_header = BlockHeader(header);
                }
                tlv_types::BLOCK_HEIGHT => {
                    fragment.block_height =
                        record.as_u32().map_err(decode_err)?;
                }
                tlv_types::OUT_POINT => {
                    if record.value.len() != 36 {
                        return Err(ProofError::DecodingError(
                            "send fragment: invalid outpoint length"
                                .into(),
                        ));
                    }
                    fragment.outpoint = OutPoint {
                        txid: record.value[..32]
                            .try_into()
                            .expect("length checked"),
                        vout: u32::from_be_bytes(
                            record.value[32..36]
                                .try_into()
                                .expect("length checked"),
                        ),
                    };
                }
                tlv_types::OUTPUTS => {
                    fragment.outputs = decode_outputs(&record.value)?;
                }
                tlv_types::TAPROOT_ASSET_ROOT => {
                    fragment.taproot_asset_root = record
                        .value
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            ProofError::DecodingError(
                                "send fragment: invalid taproot asset \
                                 root length"
                                    .into(),
                            )
                        })?;
                }
                other => {
                    // Unknown even (required) types are a hard error,
                    // unknown odd types are preserved (P2P strict
                    // decode, Go's TlvStrictDecodeP2P over
                    // KnownSendFragmentTypes).
                    if other % 2 == 0 {
                        return Err(ProofError::DecodingError(format!(
                            "send fragment: unknown even TLV type {}",
                            other
                        )));
                    }
                    fragment
                        .unknown_odd_types
                        .insert(other, record.value.clone());
                }
            }
        }

        Ok(fragment)
    }
}

fn decode_err(e: impl std::fmt::Display) -> ProofError {
    ProofError::DecodingError(e.to_string())
}

/// Decodes the outputs map value, matching Go's `SendOutputsDecoder`.
fn decode_outputs(
    data: &[u8],
) -> Result<BTreeMap<AssetId, SendOutput>, ProofError> {
    let (num_outputs, mut offset) =
        decode_bigsize(data).map_err(decode_err)?;

    // Avoid OOM by limiting the number of send outputs we accept.
    if num_outputs > MAX_SEND_FRAGMENT_OUTPUTS as u64 {
        return Err(ProofError::DecodingError(
            "too many send outputs".into(),
        ));
    }

    // Per entry: 32B asset ID + 1B asset version + 8B amount +
    // 1B derivation method + 33B script key.
    const ENTRY_SIZE: usize = 32 + 1 + 8 + 1 + 33;

    let mut outputs = BTreeMap::new();
    for _ in 0..num_outputs {
        if offset + ENTRY_SIZE > data.len() {
            return Err(ProofError::DecodingError(
                "send fragment: truncated output entry".into(),
            ));
        }

        let asset_id = AssetId(
            data[offset..offset + 32]
                .try_into()
                .expect("length checked"),
        );
        offset += 32;

        let asset_version = AssetVersion::from_u8(data[offset])
            .map_err(decode_err)?;
        offset += 1;

        let amount = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .expect("length checked"),
        );
        offset += 8;

        let derivation_method = match data[offset] {
            0 => ScriptKeyDerivationMethod::UniquePedersen,
            other => {
                return Err(ProofError::DecodingError(format!(
                    "send fragment: unknown script key derivation \
                     method {}",
                    other
                )));
            }
        };
        offset += 1;

        let script_key = SerializedKey(
            data[offset..offset + 33]
                .try_into()
                .expect("length checked"),
        );
        offset += 33;

        outputs.insert(
            asset_id,
            SendOutput {
                asset_version,
                amount,
                derivation_method,
                script_key,
            },
        );
    }

    if offset != data.len() {
        return Err(ProofError::DecodingError(
            "send fragment: trailing bytes in outputs record".into(),
        ));
    }

    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Builds the block header used by the Go-generated vectors:
    /// version 1, prev block {0x01}, merkle root {0x02}, timestamp
    /// 1234567890, bits 0x1d00ffff, nonce 7 (all Bitcoin wire LE).
    fn vector_header() -> BlockHeader {
        let mut h = [0u8; 80];
        h[..4].copy_from_slice(&1u32.to_le_bytes());
        h[4] = 0x01; // prev block first byte
        h[36] = 0x02; // merkle root first byte
        h[68..72].copy_from_slice(&1234567890u32.to_le_bytes());
        h[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        h[76..80].copy_from_slice(&7u32.to_le_bytes());
        BlockHeader(h)
    }

    fn output1() -> SendOutput {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[1] = 0xAA;
        SendOutput {
            asset_version: AssetVersion::V1,
            amount: 100,
            derivation_method:
                ScriptKeyDerivationMethod::UniquePedersen,
            script_key: SerializedKey(key),
        }
    }

    fn output2() -> SendOutput {
        let mut key = [0u8; 33];
        key[0] = 0x03;
        key[1] = 0xBB;
        SendOutput {
            asset_version: AssetVersion::V0,
            amount: 65536,
            derivation_method:
                ScriptKeyDerivationMethod::UniquePedersen,
            script_key: SerializedKey(key),
        }
    }

    fn vector_fragment_one_output() -> SendFragment {
        let mut id1 = [0u8; 32];
        id1[0] = 0x01;

        let mut root = [0u8; 32];
        root[0] = 0x04;
        root[1] = 0x05;

        let mut txid = [0u8; 32];
        txid[0] = 0x03;

        SendFragment {
            version: SendFragmentVersion::V1,
            block_header: vector_header(),
            block_height: 1234,
            outpoint: OutPoint { txid, vout: 1 },
            outputs: BTreeMap::from([(AssetId(id1), output1())]),
            taproot_asset_root: root,
            unknown_odd_types: BTreeMap::new(),
        }
    }

    // Generated with the Go reference implementation
    // (proof.SendFragment.Encode), single output.
    const GO_FRAGMENT_1: &str =
        "0001010250010000000100000000000000000000000000000000000000000000\
         0000000000000000000200000000000000000000000000000000000000000000\
         000000000000000000d2029649ffff001d070000000404000004d20624030000\
         0000000000000000000000000000000000000000000000000000000000000000\
         01084c0101000000000000000000000000000000000000000000000000000000\
         000000000100000000000000640002aa00000000000000000000000000000000\
         0000000000000000000000000000000a20040500000000000000000000000000\
         0000000000000000000000000000000000";

    // Same fragment but with a second output and an unknown odd type
    // 0x1001 = [0x05, 0x06] appended.
    const GO_FRAGMENT_2: &str =
        "0001010250010000000100000000000000000000000000000000000000000000\
         0000000000000000000200000000000000000000000000000000000000000000\
         000000000000000000d2029649ffff001d070000000404000004d20624030000\
         0000000000000000000000000000000000000000000000000000000000000000\
         0108970201000000000000000000000000000000000000000000000000000000\
         000000000100000000000000640002aa00000000000000000000000000000000\
         0000000000000000000000000000000200000000000000000000000000000000\
         0000000000000000000000000000000000000000000100000003bb0000000000\
         00000000000000000000000000000000000000000000000000000a2004050000\
         00000000000000000000000000000000000000000000000000000000fd100102\
         0506";

    #[test]
    fn test_encode_matches_go_vector_one_output() {
        let fragment = vector_fragment_one_output();
        assert_eq!(fragment.encode(), hex_decode(GO_FRAGMENT_1));
    }

    #[test]
    fn test_encode_matches_go_vector_two_outputs() {
        let mut fragment = vector_fragment_one_output();
        let mut id2 = [0u8; 32];
        id2[0] = 0x02;
        fragment.outputs.insert(AssetId(id2), output2());
        fragment.unknown_odd_types.insert(0x1001, vec![0x05, 0x06]);

        assert_eq!(fragment.encode(), hex_decode(GO_FRAGMENT_2));
    }

    #[test]
    fn test_decode_go_vectors() {
        let fragment =
            SendFragment::decode(&hex_decode(GO_FRAGMENT_1)).unwrap();
        assert_eq!(fragment, vector_fragment_one_output());
        fragment.validate().unwrap();

        let fragment2 =
            SendFragment::decode(&hex_decode(GO_FRAGMENT_2)).unwrap();
        assert_eq!(fragment2.outputs.len(), 2);
        assert_eq!(
            fragment2.unknown_odd_types.get(&0x1001),
            Some(&vec![0x05, 0x06])
        );
        fragment2.validate().unwrap();

        // Re-encode must round-trip byte-exactly.
        assert_eq!(fragment2.encode(), hex_decode(GO_FRAGMENT_2));
    }

    // Ported from Go's TestSendFragmentEncodeDecode "basic fragment".
    #[test]
    fn test_encode_decode_round_trip_basic() {
        let mut fragment = vector_fragment_one_output();
        let mut id2 = [0u8; 32];
        id2[0] = 0x02;
        fragment.outputs.insert(AssetId(id2), output2());
        fragment.unknown_odd_types.insert(0x1001, vec![0x05, 0x06]);

        let encoded = fragment.encode();
        let decoded = SendFragment::decode(&encoded).unwrap();
        assert_eq!(fragment, decoded);
    }

    // Ported from Go's TestSendFragmentEncodeDecode "empty fragment".
    #[test]
    fn test_encode_decode_round_trip_empty() {
        let fragment = SendFragment {
            version: SendFragmentVersion::V1,
            block_header: BlockHeader::default(),
            block_height: 0,
            outpoint: OutPoint::default(),
            outputs: BTreeMap::new(),
            taproot_asset_root: [0u8; 32],
            unknown_odd_types: BTreeMap::new(),
        };

        let encoded = fragment.encode();
        let decoded = SendFragment::decode(&encoded).unwrap();
        assert_eq!(fragment, decoded);

        // Empty fragments fail validation (like Go).
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn test_validate_unknown_version() {
        let mut fragment = vector_fragment_one_output();
        fragment.version = SendFragmentVersion::Unknown;
        assert!(fragment.validate().is_err());

        fragment.version = SendFragmentVersion::Future(2);
        assert!(fragment.validate().is_err());

        fragment.version = SendFragmentVersion::V1;
        fragment.validate().unwrap();
    }

    #[test]
    fn test_validate_output_count() {
        let mut fragment = vector_fragment_one_output();

        // Zero outputs is invalid.
        fragment.outputs.clear();
        assert!(fragment.validate().is_err());

        // 256 outputs is valid, 257 is not.
        for i in 0..=256u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            fragment.outputs.insert(AssetId(id), output1());
        }
        assert_eq!(fragment.outputs.len(), 257);
        assert!(fragment.validate().is_err());

        let extra = *fragment.outputs.keys().next_back().unwrap();
        fragment.outputs.remove(&extra);
        assert_eq!(fragment.outputs.len(), 256);
        fragment.validate().unwrap();
    }

    #[test]
    fn test_decode_rejects_unknown_even_type() {
        let fragment = vector_fragment_one_output();
        let mut encoded = fragment.encode();
        // Append an unknown even type 0x0c (12) with length 1.
        encoded.extend_from_slice(&[0x0c, 0x01, 0xFF]);

        assert!(matches!(
            SendFragment::decode(&encoded),
            Err(ProofError::DecodingError(msg))
                if msg.contains("unknown even TLV type")
        ));
    }

    #[test]
    fn test_decode_rejects_too_many_outputs() {
        // Craft an outputs record claiming 257 entries.
        let mut outputs = Vec::new();
        encode_bigsize(&mut outputs, 257);

        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(tlv_types::VERSION, 1));
        stream.push(TlvRecord::bytes(tlv_types::OUTPUTS, &outputs));

        assert!(matches!(
            SendFragment::decode(&stream.encode()),
            Err(ProofError::DecodingError(msg))
                if msg.contains("too many send outputs")
        ));
    }

    #[test]
    fn test_decode_rejects_truncated_outputs() {
        let mut outputs = Vec::new();
        encode_bigsize(&mut outputs, 1);
        outputs.extend_from_slice(&[0u8; 40]); // less than one entry

        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(tlv_types::VERSION, 1));
        stream.push(TlvRecord::bytes(tlv_types::OUTPUTS, &outputs));

        assert!(matches!(
            SendFragment::decode(&stream.encode()),
            Err(ProofError::DecodingError(msg))
                if msg.contains("truncated output")
        ));
    }
}
