// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Core type definitions for Taproot Assets.

/// Protocol version for an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AssetVersion {
    /// Initial version.
    V0 = 0,
    /// Version 1 - supports segwit-style encoding (the raw TxWitness
    /// sub-records are omitted from the MS-SMT leaf encoding).
    V1 = 1,
}

impl AssetVersion {
    pub fn from_u8(v: u8) -> Result<Self, AssetError> {
        match v {
            0 => Ok(AssetVersion::V0),
            1 => Ok(AssetVersion::V1),
            _ => Err(AssetError::UnknownVersion(v)),
        }
    }
}

/// Type of asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AssetType {
    /// A normal (fungible) asset that can be divided.
    Normal = 0,
    /// A collectible (NFT) - amount is always 1.
    Collectible = 1,
}

impl AssetType {
    pub fn from_u8(v: u8) -> Result<Self, AssetError> {
        match v {
            0 => Ok(AssetType::Normal),
            1 => Ok(AssetType::Collectible),
            _ => Err(AssetError::UnknownType(v)),
        }
    }
}

/// Script version for asset scripts.
///
/// Stored as a raw u16 to support forward compatibility with versions
/// defined in the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScriptVersion(pub u16);

impl ScriptVersion {
    /// Initial version — assets commit to a tweaked Taproot output key.
    pub const V0: ScriptVersion = ScriptVersion(0);

    pub fn from_u16(v: u16) -> Result<Self, AssetError> {
        Ok(ScriptVersion(v))
    }
}

/// Classification of a script key's construction method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptKeyType {
    Unknown = 0,
    Bip86 = 1,
    ScriptPathExternal = 2,
    Burn = 3,
    Tombstone = 4,
    ScriptPathChannel = 5,
    UniquePedersen = 6,
}

/// Version of group key construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GroupKeyVersion {
    /// Group key tweaked with genesis asset ID.
    V0 = 0,
    /// V1 — compatible with PSBT signing, asset ID appended as sibling.
    V1 = 1,
}

impl GroupKeyVersion {
    pub fn from_u8(v: u8) -> Result<Self, AssetError> {
        match v {
            0 => Ok(GroupKeyVersion::V0),
            1 => Ok(GroupKeyVersion::V1),
            _ => Err(AssetError::UnknownGroupKeyVersion(v)),
        }
    }
}

/// Encoding mode for asset serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncodeType {
    /// Normal encoding — includes witness data.
    Normal = 0,
    /// Segwit-style — witness field is omitted (V1 assets only).
    Segwit = 1,
}

/// A 33-byte compressed secp256k1 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SerializedKey(pub [u8; 33]);

impl SerializedKey {
    /// Returns the x-only (Schnorr) representation: bytes [1..33].
    pub fn schnorr_bytes(&self) -> &[u8; 32] {
        self.0[1..].try_into().unwrap()
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

impl std::fmt::Debug for SerializedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SerializedKey({})", crate::hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for SerializedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Maximum length of an asset's human-readable tag.
pub const MAX_ASSET_NAME_LENGTH: usize = 64;

/// Key family for Taproot Asset keys.
pub const TAPROOT_ASSETS_KEY_FAMILY: u16 = 212;

/// Errors related to asset types.
#[derive(Debug, Clone)]
pub enum AssetError {
    UnknownVersion(u8),
    UnknownType(u8),
    UnknownScriptVersion(u16),
    UnknownGroupKeyVersion(u8),
    TagTooLong(usize),
    InvalidKey(String),
    EncodingError(String),
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::UnknownVersion(v) => {
                write!(f, "unknown asset version: {}", v)
            }
            AssetError::UnknownType(v) => {
                write!(f, "unknown asset type: {}", v)
            }
            AssetError::UnknownScriptVersion(v) => {
                write!(f, "unknown script version: {}", v)
            }
            AssetError::UnknownGroupKeyVersion(v) => {
                write!(f, "unknown group key version: {}", v)
            }
            AssetError::TagTooLong(len) => {
                write!(
                    f,
                    "asset tag too long: {} > {}",
                    len, MAX_ASSET_NAME_LENGTH
                )
            }
            AssetError::InvalidKey(msg) => {
                write!(f, "invalid key: {}", msg)
            }
            AssetError::EncodingError(msg) => {
                write!(f, "encoding error: {}", msg)
            }
        }
    }
}

impl std::error::Error for AssetError {}
