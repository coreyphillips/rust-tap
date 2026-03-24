// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset genesis and ID computation.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use super::types::*;

/// A 32-byte asset identifier derived from the genesis metadata.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    pub const ZERO: AssetId = AssetId([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssetId({})", crate::hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for AssetId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Bitcoin outpoint (txid + output index).
///
/// We define our own rather than depending on `bitcoin` crate to keep
/// `tap-primitives` dependency-light. The txid is stored in internal byte
/// order (same as `bitcoin::Txid`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct OutPoint {
    /// Transaction ID in internal byte order (reversed from display order).
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

impl OutPoint {
    /// Writes this outpoint in Bitcoin wire format:
    /// txid (32 bytes, internal byte order) + vout (4 bytes, little-endian).
    pub fn write_wire<W: std::io::Write>(
        &self,
        w: &mut W,
    ) -> std::io::Result<()> {
        w.write_all(&self.txid)?;
        w.write_all(&self.vout.to_le_bytes())?;
        Ok(())
    }
}

/// Genesis metadata that uniquely defines an asset.
///
/// The asset ID is derived as:
/// ```text
/// SHA256(wire(FirstPrevOut) || SHA256(Tag) || MetaHash || BE(OutputIndex) || Type)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// The first previous outpoint — the Bitcoin-level identifier for the
    /// minting transaction input.
    pub first_prev_out: OutPoint,
    /// Human-readable tag for the asset (max 64 bytes).
    pub tag: String,
    /// SHA-256 hash of the asset's metadata.
    pub meta_hash: [u8; 32],
    /// Index of the output containing the TAP commitment.
    pub output_index: u32,
    /// Type of asset being created.
    pub asset_type: AssetType,
}

impl Genesis {
    /// Returns the SHA-256 hash of the tag string.
    pub fn tag_hash(&self) -> [u8; 32] {
        sha256::Hash::hash(self.tag.as_bytes()).to_byte_array()
    }

    /// Computes the unique asset ID from this genesis.
    ///
    /// Format: `SHA256(wire_outpoint || tag_hash || meta_hash || BE(output_index) || type)`
    pub fn id(&self) -> AssetId {
        let tag_hash = self.tag_hash();

        let mut engine = sha256::HashEngine::default();

        // OutPoint in wire format (txid LE + vout LE = 36 bytes).
        engine.input(&self.first_prev_out.txid);
        engine.input(&self.first_prev_out.vout.to_le_bytes());

        // SHA256(tag).
        engine.input(&tag_hash);

        // MetaHash.
        engine.input(&self.meta_hash);

        // OutputIndex (big-endian u32).
        engine.input(&self.output_index.to_be_bytes());

        // AssetType (single byte).
        engine.input(&[self.asset_type as u8]);

        let hash = sha256::Hash::from_engine(engine);
        AssetId(hash.to_byte_array())
    }

    /// Returns an empty genesis with default values.
    pub fn empty() -> Self {
        Genesis {
            first_prev_out: OutPoint::default(),
            tag: String::new(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    /// Validates the genesis fields.
    pub fn validate(&self) -> Result<(), AssetError> {
        if self.tag.len() > MAX_ASSET_NAME_LENGTH {
            return Err(AssetError::TagTooLong(self.tag.len()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_id_deterministic() {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0xAA; 32],
                vout: 1,
            },
            tag: "test-asset".to_string(),
            meta_hash: [0xBB; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let id1 = genesis.id();
        let id2 = genesis.id();
        assert_eq!(id1, id2);
        assert_ne!(id1, AssetId::ZERO);
    }

    #[test]
    fn test_different_genesis_different_id() {
        let gen1 = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "asset-a".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let gen2 = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "asset-b".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        assert_ne!(gen1.id(), gen2.id());
    }

    #[test]
    fn test_asset_type_affects_id() {
        let mut genesis = Genesis {
            first_prev_out: OutPoint::default(),
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let id_normal = genesis.id();
        genesis.asset_type = AssetType::Collectible;
        let id_collectible = genesis.id();
        assert_ne!(id_normal, id_collectible);
    }

    #[test]
    fn test_tag_hash() {
        let genesis = Genesis {
            first_prev_out: OutPoint::default(),
            tag: "hello".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let hash = genesis.tag_hash();
        // SHA256("hello") is a known value.
        let expected = sha256::Hash::hash(b"hello").to_byte_array();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_validate_tag_length() {
        let mut genesis = Genesis::empty();
        genesis.tag = "a".repeat(64);
        assert!(genesis.validate().is_ok());

        genesis.tag = "a".repeat(65);
        assert!(genesis.validate().is_err());
    }
}
