// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset metadata reveals.

use std::collections::BTreeMap;

use bitcoin_hashes::{sha256, Hash};

use crate::asset::SerializedKey;
use crate::encoding::bigsize::{decode_bigsize, encode_bigsize};
use crate::encoding::tlv::{TlvRecord, TlvStream};

/// Maximum size of metadata in bytes (1 MiB).
pub const META_DATA_MAX_SIZE_BYTES: usize = 1024 * 1024;

/// Maximum decimal display value.
pub const MAX_DEC_DISPLAY: u32 = 12;

/// Maximum number of canonical universe URLs.
pub const MAX_NUM_CANONICAL_UNIVERSE_URLS: usize = 16;

/// Maximum length of a single canonical universe URL.
pub const MAX_CANONICAL_UNIVERSE_URL_LENGTH: usize = 255;

/// TLV type numbers for meta reveal fields.
///
/// These must match Go's `proof/records.go`.
mod tlv_types {
    pub const ENCODING_TYPE: u64 = 0;
    pub const DATA: u64 = 2;
    pub const DECIMAL_DISPLAY: u64 = 5;
    pub const UNIVERSE_COMMITMENTS: u64 = 7;
    pub const CANONICAL_UNIVERSES: u64 = 9;
    pub const DELEGATION_KEY: u64 = 11;
}

/// Type of metadata content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MetaType {
    /// Opaque binary data.
    Opaque = 0,
    /// JSON data.
    Json = 1,
}

impl MetaType {
    pub fn from_u8(v: u8) -> Result<Self, super::ProofError> {
        match v {
            0 => Ok(MetaType::Opaque),
            1 => Ok(MetaType::Json),
            _ => Err(super::ProofError::InvalidMetaType(v)),
        }
    }
}

/// Revealed metadata for an asset at genesis.
///
/// Matches Go's `proof.MetaReveal` TLV encoding, including the optional
/// records added for universe supply commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaReveal {
    /// Type of the metadata content.
    pub meta_type: MetaType,
    /// The revealed metadata bytes.
    pub data: Vec<u8>,
    /// Optional decimal display precision (TLV type 5, 4-byte BE u32).
    pub decimal_display: Option<u32>,
    /// Whether the asset issuer commits to the asset supply via universe
    /// supply commitments (TLV type 7; only encoded when true).
    pub universe_commitments: bool,
    /// Optional canonical universe URLs (TLV type 9).
    pub canonical_universes: Option<Vec<String>>,
    /// Optional delegation key used to sign supply commitment updates
    /// (TLV type 11, 33-byte compressed public key).
    pub delegation_key: Option<SerializedKey>,
    /// Unknown odd TLV types preserved for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl Default for MetaReveal {
    fn default() -> Self {
        MetaReveal {
            meta_type: MetaType::Opaque,
            data: Vec::new(),
            decimal_display: None,
            universe_commitments: false,
            canonical_universes: None,
            delegation_key: None,
            unknown_odd_types: BTreeMap::new(),
        }
    }
}

impl MetaReveal {
    /// Creates an opaque meta reveal with the given data.
    pub fn new_opaque(data: Vec<u8>) -> Self {
        MetaReveal {
            meta_type: MetaType::Opaque,
            data,
            ..Default::default()
        }
    }

    /// Encodes the meta reveal as a TLV stream.
    ///
    /// Matches Go's `MetaReveal.Encode`: type (0) and data (2) records
    /// are always present; universe commitments (7) only when true, and
    /// decimal display (5), canonical universes (9), and delegation
    /// key (11) only when set, so that re-encoding older reveals does
    /// not change their bytes. Unknown odd types are re-encoded as-is.
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(
            tlv_types::ENCODING_TYPE,
            self.meta_type as u8,
        ));
        stream.push(TlvRecord::bytes(tlv_types::DATA, &self.data));

        if let Some(dd) = self.decimal_display {
            stream.push(TlvRecord::bytes(
                tlv_types::DECIMAL_DISPLAY,
                &dd.to_be_bytes(),
            ));
        }

        if self.universe_commitments {
            stream.push(TlvRecord::u8(tlv_types::UNIVERSE_COMMITMENTS, 1));
        }

        if let Some(ref urls) = self.canonical_universes {
            let mut buf = Vec::new();
            if !urls.is_empty() {
                encode_bigsize(&mut buf, urls.len() as u64);
                for url in urls {
                    encode_bigsize(&mut buf, url.len() as u64);
                    buf.extend_from_slice(url.as_bytes());
                }
            }
            stream.push(TlvRecord::bytes(
                tlv_types::CANONICAL_UNIVERSES,
                &buf,
            ));
        }

        if let Some(ref key) = self.delegation_key {
            stream.push(TlvRecord::bytes(
                tlv_types::DELEGATION_KEY,
                key.as_bytes(),
            ));
        }

        for (&type_num, value) in &self.unknown_odd_types {
            stream.push(TlvRecord::bytes(type_num, value));
        }

        stream.encode()
    }

    /// Decodes a meta reveal from TLV bytes.
    ///
    /// Unknown even types are rejected; unknown odd types are preserved,
    /// matching Go's `TlvStrictDecode` over `KnownMetaRevealTypes`.
    pub fn decode(data: &[u8]) -> Result<Self, super::ProofError> {
        let stream = TlvStream::decode(data).map_err(|e| {
            super::ProofError::InvalidMetaReveal(e.to_string())
        })?;

        let mut reveal = MetaReveal::default();
        let mut have_type = false;
        let mut have_data = false;

        for record in stream.records() {
            match record.type_num {
                tlv_types::ENCODING_TYPE => {
                    if record.value.len() != 1 {
                        return Err(super::ProofError::InvalidMetaReveal(
                            "meta type must be 1 byte".into(),
                        ));
                    }
                    reveal.meta_type = MetaType::from_u8(record.value[0])?;
                    have_type = true;
                }
                tlv_types::DATA => {
                    if record.value.len() > META_DATA_MAX_SIZE_BYTES {
                        return Err(super::ProofError::MetaTooLarge(
                            record.value.len(),
                        ));
                    }
                    reveal.data = record.value.clone();
                    have_data = true;
                }
                tlv_types::DECIMAL_DISPLAY => {
                    // A zero-length record decodes as None.
                    if record.value.is_empty() {
                        reveal.decimal_display = None;
                    } else if record.value.len() == 4 {
                        let mut be = [0u8; 4];
                        be.copy_from_slice(&record.value);
                        reveal.decimal_display =
                            Some(u32::from_be_bytes(be));
                    } else {
                        return Err(super::ProofError::InvalidMetaReveal(
                            "decimal display must be 4 bytes".into(),
                        ));
                    }
                }
                tlv_types::UNIVERSE_COMMITMENTS => {
                    if record.value.len() != 1 {
                        return Err(super::ProofError::InvalidMetaReveal(
                            "universe commitments must be 1 byte".into(),
                        ));
                    }
                    reveal.universe_commitments = record.value[0] == 1;
                }
                tlv_types::CANONICAL_UNIVERSES => {
                    reveal.canonical_universes =
                        decode_canonical_universes(&record.value)?;
                }
                tlv_types::DELEGATION_KEY => {
                    if record.value.is_empty() {
                        reveal.delegation_key = None;
                    } else if record.value.len() == 33 {
                        let mut key = [0u8; 33];
                        key.copy_from_slice(&record.value);
                        reveal.delegation_key = Some(SerializedKey(key));
                    } else {
                        return Err(super::ProofError::InvalidMetaReveal(
                            "delegation key must be 33 bytes".into(),
                        ));
                    }
                }
                other if other % 2 == 0 => {
                    return Err(super::ProofError::InvalidMetaReveal(
                        format!("unknown even TLV type {}", other),
                    ));
                }
                other => {
                    reveal
                        .unknown_odd_types
                        .insert(other, record.value.clone());
                }
            }
        }

        if !have_type || !have_data {
            return Err(super::ProofError::InvalidMetaReveal(
                "missing required meta reveal records".into(),
            ));
        }

        Ok(reveal)
    }

    /// Computes the metadata hash (SHA-256 of the TLV-encoded reveal).
    ///
    /// Matches Go's `MetaReveal.MetaHash()`.
    pub fn meta_hash(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.encode()).to_byte_array()
    }

    /// Validates the metadata, matching Go's `MetaReveal.Validate`.
    pub fn validate(&self) -> Result<(), super::ProofError> {
        if self.data.is_empty() {
            return Err(super::ProofError::InvalidMetaReveal(
                "meta data missing".into(),
            ));
        }
        if self.data.len() > META_DATA_MAX_SIZE_BYTES {
            return Err(super::ProofError::MetaTooLarge(self.data.len()));
        }

        if self.meta_type == MetaType::Json
            && serde_json::from_slice::<serde_json::Value>(&self.data)
                .is_err()
        {
            return Err(super::ProofError::InvalidMetaReveal(
                "invalid JSON".into(),
            ));
        }

        if let Some(dd) = self.decimal_display {
            if dd > MAX_DEC_DISPLAY {
                return Err(super::ProofError::InvalidDecimalDisplay(dd));
            }
        }

        if let Some(ref urls) = self.canonical_universes {
            if urls.is_empty() {
                return Err(super::ProofError::InvalidMetaReveal(
                    "canonical universes must not be empty".into(),
                ));
            }
            if urls.len() > MAX_NUM_CANONICAL_UNIVERSE_URLS {
                return Err(super::ProofError::InvalidMetaReveal(
                    "too many canonical universe URLs".into(),
                ));
            }
            for url in urls {
                if url.is_empty()
                    || url.len() > MAX_CANONICAL_UNIVERSE_URL_LENGTH
                    || !url.contains("://")
                {
                    return Err(super::ProofError::InvalidMetaReveal(
                        format!("invalid canonical universe URL: {}", url),
                    ));
                }
            }
        }

        if self.universe_commitments && self.delegation_key.is_none() {
            return Err(super::ProofError::InvalidMetaReveal(
                "universe commitments require a delegation key".into(),
            ));
        }

        Ok(())
    }
}

/// Decodes the canonical universes record value.
///
/// Wire format: `BigSize(count) [BigSize(len) url-bytes]...`; a
/// zero-length value decodes as None.
fn decode_canonical_universes(
    value: &[u8],
) -> Result<Option<Vec<String>>, super::ProofError> {
    if value.is_empty() {
        return Ok(None);
    }

    let (count, mut offset) = decode_bigsize(value)
        .map_err(|e| super::ProofError::InvalidMetaReveal(e.to_string()))?;
    if count as usize > MAX_NUM_CANONICAL_UNIVERSE_URLS {
        return Err(super::ProofError::InvalidMetaReveal(
            "too many canonical universe URLs".into(),
        ));
    }

    let mut urls = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (len, consumed) =
            decode_bigsize(&value[offset..]).map_err(|e| {
                super::ProofError::InvalidMetaReveal(e.to_string())
            })?;
        offset += consumed;
        let len = len as usize;
        if len > MAX_CANONICAL_UNIVERSE_URL_LENGTH {
            return Err(super::ProofError::InvalidMetaReveal(
                "canonical universe URL too long".into(),
            ));
        }
        if offset + len > value.len() {
            return Err(super::ProofError::InvalidMetaReveal(
                "truncated canonical universe URL".into(),
            ));
        }
        let url = String::from_utf8(value[offset..offset + len].to_vec())
            .map_err(|e| {
                super::ProofError::InvalidMetaReveal(e.to_string())
            })?;
        offset += len;
        urls.push(url);
    }

    Ok(Some(urls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_hash_deterministic() {
        let meta = MetaReveal::new_opaque(vec![1, 2, 3, 4]);
        assert_eq!(meta.meta_hash(), meta.meta_hash());
    }

    #[test]
    fn test_meta_type_affects_hash() {
        let a = MetaReveal::new_opaque(vec![1, 2, 3, 4]);
        let mut b = a.clone();
        b.meta_type = MetaType::Json;
        assert_ne!(a.meta_hash(), b.meta_hash());
    }

    #[test]
    fn test_decimal_display_type_and_encoding() {
        // Decimal display must be TLV type 5 as a 4-byte BE u32,
        // matching Go's MetaRevealDecimalDisplay record.
        let mut meta = MetaReveal::new_opaque(vec![1, 2, 3]);
        meta.decimal_display = Some(6);
        let encoded = meta.encode();
        let stream =
            crate::encoding::tlv::TlvStream::decode(&encoded).unwrap();
        assert!(stream.get(4).is_none(), "no record at type 4");
        let dd = stream.get(5).expect("decimal display at type 5");
        assert_eq!(dd.value, vec![0, 0, 0, 6]);
    }

    #[test]
    fn test_decimal_display_affects_hash() {
        let a = MetaReveal::new_opaque(vec![1, 2, 3]);
        let mut b = a.clone();
        b.decimal_display = Some(2);
        assert_ne!(a.meta_hash(), b.meta_hash());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut meta = MetaReveal::new_opaque(vec![0xaa; 100]);
        meta.decimal_display = Some(8);
        meta.universe_commitments = true;
        meta.canonical_universes = Some(vec![
            "https://universe.example.com".to_string(),
            "https://backup.example.com".to_string(),
        ]);
        meta.delegation_key = Some(SerializedKey([0x02; 33]));
        meta.unknown_odd_types.insert(99, vec![1, 2, 3]);

        let decoded = MetaReveal::decode(&meta.encode()).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_minimal_roundtrip() {
        let meta = MetaReveal::new_opaque(vec![1]);
        let encoded = meta.encode();
        // Only records 0 and 2 should be present.
        let stream =
            crate::encoding::tlv::TlvStream::decode(&encoded).unwrap();
        assert_eq!(stream.records().len(), 2);
        let decoded = MetaReveal::decode(&encoded).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_unknown_even_type_rejected() {
        let meta = MetaReveal::new_opaque(vec![1]);
        let mut stream = crate::encoding::tlv::TlvStream::new();
        stream.push(crate::encoding::tlv::TlvRecord::u8(0, 0));
        stream.push(crate::encoding::tlv::TlvRecord::bytes(2, &meta.data));
        stream.push(crate::encoding::tlv::TlvRecord::bytes(40, &[1]));
        assert!(MetaReveal::decode(&stream.encode()).is_err());
    }

    #[test]
    fn test_validate_universe_commitments_requires_delegation_key() {
        let mut meta = MetaReveal::new_opaque(vec![1]);
        meta.universe_commitments = true;
        assert!(meta.validate().is_err());
        meta.delegation_key = Some(SerializedKey([0x02; 33]));
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn test_validate_json() {
        let mut meta = MetaReveal {
            meta_type: MetaType::Json,
            data: b"not json".to_vec(),
            ..Default::default()
        };
        assert!(meta.validate().is_err());
        meta.data = b"{\"name\": \"asset\"}".to_vec();
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_data_rejected() {
        let meta = MetaReveal::new_opaque(vec![]);
        assert!(meta.validate().is_err());
    }

    #[test]
    fn test_validate_decimal_display_limit() {
        let mut meta = MetaReveal::new_opaque(vec![1]);
        meta.decimal_display = Some(MAX_DEC_DISPLAY + 1);
        assert!(meta.validate().is_err());
        meta.decimal_display = Some(MAX_DEC_DISPLAY);
        assert!(meta.validate().is_ok());
    }
}
