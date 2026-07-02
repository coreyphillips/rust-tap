// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Trait definitions for universe storage, sync, and federation.

use crate::types::*;

/// Storage backend for a single universe tree.
///
/// Each universe stores proofs for a single (asset_id, proof_type) pair
/// in an MS-SMT keyed by (outpoint, script_key).
pub trait UniverseBackend {
    /// Returns the root node (hash + sum) of this universe.
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError>;

    /// Inserts or updates a proof leaf in the universe.
    fn upsert_proof_leaf(
        &mut self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<UniverseProof, UniverseError>;

    /// Fetches a proof by its leaf key.
    fn fetch_proof(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError>;

    /// Lists all leaf keys in a universe.
    fn fetch_keys(
        &self,
        id: &UniverseId,
        query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError>;

    /// Lists all leaves in a universe.
    fn fetch_leaves(
        &self,
        id: &UniverseId,
    ) -> Result<Vec<UniverseLeaf>, UniverseError>;

    /// Deletes a universe and all its leaves.
    fn delete_universe(
        &mut self,
        id: &UniverseId,
    ) -> Result<(), UniverseError>;
}

/// Aggregate view across multiple universes.
pub trait MultiverseArchive {
    /// Returns root nodes across all known universes.
    fn root_nodes(
        &self,
        query: &RootNodesQuery,
    ) -> Result<Vec<UniverseRoot>, UniverseError>;

    /// Inserts a proof leaf into the appropriate universe.
    fn upsert_proof_leaf(
        &mut self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<UniverseProof, UniverseError>;

    /// Fetches a proof leaf from a specific universe.
    fn fetch_proof_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError>;

    /// Returns the root of a specific universe.
    fn universe_root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError>;
}

/// Compares local and remote universe state for sync.
pub trait DiffEngine {
    /// Returns the root of a specific universe on the remote.
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError>;

    /// Lists all root nodes on the remote.
    fn root_nodes(
        &self,
        query: &RootNodesQuery,
    ) -> Result<Vec<UniverseRoot>, UniverseError>;

    /// Lists leaf keys in a specific universe on the remote.
    fn universe_leaf_keys(
        &self,
        id: &UniverseId,
        query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError>;

    /// Fetches a proof leaf from the remote.
    fn fetch_proof_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError>;
}

/// Orchestrates sync between local and remote universes.
pub trait Syncer {
    /// Syncs a universe from a remote server into `local`.
    ///
    /// Compares local and remote roots, fetches missing leaves,
    /// verifies them, and inserts them locally. Returns the diff of
    /// new leaves added.
    fn sync_universe(
        &self,
        local: &mut dyn UniverseBackend,
        remote: &dyn DiffEngine,
        id: &UniverseId,
    ) -> Result<AssetSyncDiff, UniverseError>;
}

/// Manages federation membership (known universe servers).
pub trait FederationDb {
    /// Returns all known federation servers.
    fn universe_servers(&self) -> Result<Vec<ServerAddr>, UniverseError>;

    /// Adds servers to the federation.
    fn add_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError>;

    /// Removes servers from the federation.
    fn remove_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError>;
}
