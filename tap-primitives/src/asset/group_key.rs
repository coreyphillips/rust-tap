// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Group key types for asset groups (reissuable assets).

use super::types::*;

/// A group key that links multiple asset issuances together.
///
/// Assets with the same group key are considered fungible with each other.
/// The group key is tweaked with the genesis asset ID to bind the key to a
/// specific asset lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    /// Construction version (V0 or V1).
    pub version: GroupKeyVersion,
    /// Raw (pre-tweak) public key.
    pub raw_key: SerializedKey,
    /// Tweaked group public key (33 bytes compressed).
    pub group_pub_key: SerializedKey,
    /// Root of the tapscript tree (0 or 32 bytes).
    pub tapscript_root: Vec<u8>,
    /// Witness stack authorizing group membership.
    pub witness: Vec<Vec<u8>>,
}

/// Revealed group key information for proof verification.
///
/// The reveal contains enough information to reconstruct the group public key
/// from the raw key and asset ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupKeyReveal {
    V0(GroupKeyRevealV0),
    V1(GroupKeyRevealV1),
}

impl GroupKeyReveal {
    /// Returns the raw (pre-tweak) key.
    pub fn raw_key(&self) -> &SerializedKey {
        match self {
            GroupKeyReveal::V0(v) => &v.raw_key,
            GroupKeyReveal::V1(v) => &v.internal_key,
        }
    }

    /// Returns the tapscript root bytes (0 or 32 bytes).
    pub fn tapscript_root(&self) -> &[u8] {
        match self {
            GroupKeyReveal::V0(v) => &v.tapscript_root,
            GroupKeyReveal::V1(v) => &v.tapscript.root,
        }
    }
}

/// V0 group key reveal: raw key + optional tapscript root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealV0 {
    /// Raw key before tweaks.
    pub raw_key: SerializedKey,
    /// Tapscript root (0 or 32 bytes).
    pub tapscript_root: Vec<u8>,
}

/// V1 group key reveal: internal key + tapscript details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealV1 {
    /// Non-spend leaf version.
    pub version: u8,
    /// Internal key before tweaks.
    pub internal_key: SerializedKey,
    /// Tapscript details.
    pub tapscript: GroupKeyRevealTapscript,
}

/// Tapscript details for V1 group key reveals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealTapscript {
    /// Non-spend leaf version.
    pub version: u8,
    /// Final tapscript root hash.
    pub root: Vec<u8>,
    /// Optional custom subtree root.
    pub custom_subtree_root: Option<[u8; 32]>,
}
