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
///
/// The wire format treats the version as an open u8: Go's decoder
/// (`asset/encoding.go` `VersionDecoder`) accepts any byte and only
/// rejects unknown versions when semantic operations require it (for
/// example `asset.go` `Leaf()`). The `Unknown` variant preserves such
/// values so decode/encode round-trips are byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetVersion {
    /// Initial version.
    V0,
    /// Version 1 - supports segwit-style encoding (the raw TxWitness
    /// sub-records are omitted from the MS-SMT leaf encoding).
    V1,
    /// An unknown future version, preserved for wire-format passthrough.
    /// Invariant: never 0 or 1 (use `from_u8` to construct).
    Unknown(u8),
}

impl AssetVersion {
    /// Parses a version byte. Never fails: unknown values are preserved
    /// in the `Unknown` variant, matching Go's open decoding.
    pub fn from_u8(v: u8) -> Result<Self, AssetError> {
        match v {
            0 => Ok(AssetVersion::V0),
            1 => Ok(AssetVersion::V1),
            other => Ok(AssetVersion::Unknown(other)),
        }
    }

    /// Returns the wire byte for this version.
    pub fn to_u8(self) -> u8 {
        match self {
            AssetVersion::V0 => 0,
            AssetVersion::V1 => 1,
            AssetVersion::Unknown(v) => v,
        }
    }

    /// Returns true if this is a version this implementation does not
    /// have semantics for. Matches Go's `Asset.IsUnknownVersion`.
    pub fn is_unknown(self) -> bool {
        matches!(self, AssetVersion::Unknown(_))
    }
}

/// Type of asset.
///
/// Like [`AssetVersion`], the wire format treats this as an open u8
/// (Go's `TypeDecoder` performs no validation), so unknown values are
/// preserved for byte-identical round-trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetType {
    /// A normal (fungible) asset that can be divided.
    Normal,
    /// A collectible (NFT) - amount is always 1.
    Collectible,
    /// An unknown future asset type, preserved for wire passthrough.
    /// Invariant: never 0 or 1 (use `from_u8` to construct).
    Unknown(u8),
}

impl AssetType {
    /// Parses a type byte. Never fails: unknown values are preserved in
    /// the `Unknown` variant, matching Go's open decoding.
    pub fn from_u8(v: u8) -> Result<Self, AssetError> {
        match v {
            0 => Ok(AssetType::Normal),
            1 => Ok(AssetType::Collectible),
            other => Ok(AssetType::Unknown(other)),
        }
    }

    /// Returns the wire byte for this asset type.
    pub fn to_u8(self) -> u8 {
        match self {
            AssetType::Normal => 0,
            AssetType::Collectible => 1,
            AssetType::Unknown(v) => v,
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// An asset does not satisfy the alt leaf constraints (Go's
    /// `Asset.ValidateAltLeaf`).
    InvalidAltLeaf(String),
    /// Two alt leaves share the same asset commitment key (Go's
    /// `asset.ErrDuplicateAltLeafKey`).
    DuplicateAltLeafKey([u8; 32]),
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
            AssetError::InvalidAltLeaf(msg) => {
                write!(f, "invalid alt leaf: {}", msg)
            }
            AssetError::DuplicateAltLeafKey(key) => {
                write!(
                    f,
                    "duplicate alt leaf key: {}",
                    crate::hex::encode(key)
                )
            }
        }
    }
}

impl std::error::Error for AssetError {}
