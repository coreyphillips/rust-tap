// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Core types for the Universe sync system.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;

/// Identifies a specific universe (one tree per asset/proof-type pair).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniverseId {
    /// The asset ID this universe tracks.
    pub asset_id: AssetId,
    /// Optional group key (for grouped assets).
    pub group_key: Option<SerializedKey>,
    /// The type of proofs stored in this universe.
    pub proof_type: ProofType,
}

/// What kind of proofs a universe stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofType {
    /// Only issuance (genesis) proofs.
    Issuance,
    /// All transfer proofs.
    Transfer,
}

/// The type of sync to perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncType {
    /// Sync only issuance proofs (asset discovery).
    IssuanceOnly,
    /// Full sync (issuance + transfers).
    Full,
}

/// A key identifying a leaf in a universe tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeafKey {
    /// The anchor outpoint of the proof.
    pub outpoint: OutPoint,
    /// The script key of the asset.
    pub script_key: SerializedKey,
}

/// A leaf in a universe tree.
#[derive(Clone, Debug)]
pub struct UniverseLeaf {
    /// The asset ID.
    pub asset_id: AssetId,
    /// The amount.
    pub amount: u64,
    /// Encoded proof data.
    pub proof: Vec<u8>,
    /// The leaf key.
    pub key: LeafKey,
}

/// A universe proof: a leaf plus its inclusion proof in the tree.
#[derive(Clone, Debug)]
pub struct UniverseProof {
    /// The leaf data.
    pub leaf: UniverseLeaf,
    /// MS-SMT inclusion proof (compressed).
    pub inclusion_proof: Vec<u8>,
}

/// The root of a universe tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniverseRoot {
    /// Which universe this root belongs to.
    pub id: UniverseId,
    /// The MS-SMT root hash.
    pub root_hash: NodeHash,
    /// The MS-SMT root sum.
    pub root_sum: u64,
}

/// A remote universe server address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerAddr {
    /// The server's host:port.
    pub host: String,
    /// Unique identifier (derived from host if not set).
    pub id: String,
}

impl ServerAddr {
    pub fn new(host: String) -> Self {
        let id = host.clone();
        ServerAddr { host, id }
    }
}

/// A diff resulting from a sync operation.
#[derive(Clone, Debug)]
pub struct AssetSyncDiff {
    /// The universe that was synced.
    pub universe_id: UniverseId,
    /// New leaves added during sync.
    pub new_leaves: Vec<UniverseLeaf>,
}

/// Query parameters for listing leaf keys.
#[derive(Clone, Debug, Default)]
pub struct LeafKeysQuery {
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Query parameters for listing root nodes.
#[derive(Clone, Debug, Default)]
pub struct RootNodesQuery {
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Errors from universe operations.
#[derive(Debug, Clone)]
pub enum UniverseError {
    /// The requested universe does not exist.
    NotFound(String),
    /// Tree operation failed.
    TreeError(String),
    /// Proof validation failed.
    ProofInvalid(String),
    /// Remote sync failed.
    SyncError(String),
    /// Storage error.
    StoreError(String),
}

impl std::fmt::Display for UniverseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UniverseError::NotFound(msg) => {
                write!(f, "universe not found: {}", msg)
            }
            UniverseError::TreeError(msg) => {
                write!(f, "tree error: {}", msg)
            }
            UniverseError::ProofInvalid(msg) => {
                write!(f, "proof invalid: {}", msg)
            }
            UniverseError::SyncError(msg) => {
                write!(f, "sync error: {}", msg)
            }
            UniverseError::StoreError(msg) => {
                write!(f, "store error: {}", msg)
            }
        }
    }
}

impl std::error::Error for UniverseError {}
