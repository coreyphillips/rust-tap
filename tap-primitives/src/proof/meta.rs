// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset metadata reveals.

use bitcoin_hashes::{sha256, Hash};

/// Maximum size of metadata in bytes (1 MiB).
pub const META_DATA_MAX_SIZE_BYTES: usize = 1024 * 1024;

/// Maximum decimal display value.
pub const MAX_DEC_DISPLAY: u32 = 12;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaReveal {
    /// Type of the metadata content.
    pub meta_type: MetaType,
    /// The revealed metadata bytes.
    pub data: Vec<u8>,
    /// Optional decimal display precision.
    pub decimal_display: Option<u32>,
}

impl MetaReveal {
    /// Computes the metadata hash (SHA-256 of the TLV-encoded reveal).
    ///
    /// Matches Go's `MetaReveal.MetaHash()` encoding:
    /// TLV stream with type 0 = meta_type, type 2 = data, type 4 = decimal_display.
    pub fn meta_hash(&self) -> [u8; 32] {
        use crate::encoding::tlv::{TlvRecord, TlvStream};

        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(0, self.meta_type as u8));
        stream.push(TlvRecord::bytes(2, &self.data));
        if let Some(dd) = self.decimal_display {
            stream.push(TlvRecord::varint(4, dd as u64));
        }
        sha256::Hash::hash(&stream.encode()).to_byte_array()
    }

    /// Validates the metadata.
    pub fn validate(&self) -> Result<(), super::ProofError> {
        if self.data.len() > META_DATA_MAX_SIZE_BYTES {
            return Err(super::ProofError::MetaTooLarge(self.data.len()));
        }
        if let Some(dd) = self.decimal_display {
            if dd > MAX_DEC_DISPLAY {
                return Err(super::ProofError::InvalidDecimalDisplay(dd));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_hash_deterministic() {
        let meta = MetaReveal {
            meta_type: MetaType::Opaque,
            data: vec![1, 2, 3, 4],
            decimal_display: None,
        };
        assert_eq!(meta.meta_hash(), meta.meta_hash());
    }

    #[test]
    fn test_meta_type_affects_hash() {
        let a = MetaReveal {
            meta_type: MetaType::Opaque,
            data: vec![1, 2, 3],
            decimal_display: None,
        };
        let b = MetaReveal {
            meta_type: MetaType::Json,
            data: vec![1, 2, 3],
            decimal_display: None,
        };
        assert_ne!(a.meta_hash(), b.meta_hash());
    }

    #[test]
    fn test_validate_size_limit() {
        let meta = MetaReveal {
            meta_type: MetaType::Opaque,
            data: vec![0u8; META_DATA_MAX_SIZE_BYTES + 1],
            decimal_display: None,
        };
        assert!(meta.validate().is_err());
    }

    #[test]
    fn test_validate_decimal_display() {
        let meta = MetaReveal {
            meta_type: MetaType::Opaque,
            data: vec![1],
            decimal_display: Some(13),
        };
        assert!(meta.validate().is_err());

        let meta_ok = MetaReveal {
            meta_type: MetaType::Opaque,
            data: vec![1],
            decimal_display: Some(8),
        };
        assert!(meta_ok.validate().is_ok());
    }
}
