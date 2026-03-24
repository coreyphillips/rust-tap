// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! In-memory universe backend for testing.

use std::collections::HashMap;

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::mssmt::NodeHash;

use crate::traits::{FederationDb, UniverseBackend};
use crate::types::*;

/// In-memory universe backend.
///
/// Stores universe data in `HashMap`s. Suitable for testing and
/// lightweight use. Not intended for production.
#[derive(Default)]
pub struct MemoryUniverseBackend {
    /// Universes keyed by UniverseId, each containing leaves keyed by LeafKey.
    universes: HashMap<UniverseId, HashMap<LeafKey, UniverseLeaf>>,
}

impl MemoryUniverseBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns roots for all known universes. Used by the mock DiffEngine.
    pub fn all_roots(&self) -> Vec<UniverseRoot> {
        self.universes
            .keys()
            .filter_map(|id| self.root_node(id).ok())
            .collect()
    }

    /// Computes a deterministic root hash from the leaves.
    fn compute_root(
        leaves: &HashMap<LeafKey, UniverseLeaf>,
    ) -> (NodeHash, u64) {
        if leaves.is_empty() {
            return (NodeHash::EMPTY, 0);
        }

        let mut sum: u64 = 0;
        let mut engine = sha256::HashEngine::default();

        // Sort keys for deterministic hashing.
        let mut keys: Vec<&LeafKey> = leaves.keys().collect();
        keys.sort_by(|a, b| {
            a.outpoint
                .txid
                .cmp(&b.outpoint.txid)
                .then(a.outpoint.vout.cmp(&b.outpoint.vout))
                .then(a.script_key.0.cmp(&b.script_key.0))
        });

        for key in keys {
            let leaf = &leaves[key];
            engine.input(&leaf.asset_id.0);
            engine.input(&leaf.amount.to_be_bytes());
            engine.input(&key.outpoint.txid);
            engine.input(&key.outpoint.vout.to_be_bytes());
            engine.input(&key.script_key.0);
            sum = sum.saturating_add(leaf.amount);
        }

        let hash = sha256::Hash::from_engine(engine);
        (NodeHash(hash.to_byte_array()), sum)
    }
}

impl UniverseBackend for MemoryUniverseBackend {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        let leaves = self
            .universes
            .get(id)
            .ok_or_else(|| UniverseError::NotFound(format!("{:?}", id)))?;

        let (root_hash, root_sum) = Self::compute_root(leaves);

        Ok(UniverseRoot {
            id: id.clone(),
            root_hash,
            root_sum,
        })
    }

    fn upsert_proof_leaf(
        &mut self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<UniverseProof, UniverseError> {
        let universe = self.universes.entry(id.clone()).or_default();
        universe.insert(key.clone(), leaf.clone());

        Ok(UniverseProof {
            leaf: leaf.clone(),
            inclusion_proof: vec![], // In-memory: no real proof needed.
        })
    }

    fn fetch_proof(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError> {
        let universe = match self.universes.get(id) {
            Some(u) => u,
            None => return Ok(None),
        };

        Ok(universe.get(key).map(|leaf| UniverseProof {
            leaf: leaf.clone(),
            inclusion_proof: vec![],
        }))
    }

    fn fetch_keys(
        &self,
        id: &UniverseId,
        _query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        match self.universes.get(id) {
            Some(u) => Ok(u.keys().cloned().collect()),
            None => Ok(vec![]),
        }
    }

    fn fetch_leaves(
        &self,
        id: &UniverseId,
    ) -> Result<Vec<UniverseLeaf>, UniverseError> {
        match self.universes.get(id) {
            Some(u) => Ok(u.values().cloned().collect()),
            None => Ok(vec![]),
        }
    }

    fn delete_universe(
        &mut self,
        id: &UniverseId,
    ) -> Result<(), UniverseError> {
        self.universes.remove(id);
        Ok(())
    }
}

/// In-memory federation database.
#[derive(Default)]
pub struct MemoryFederationDb {
    servers: Vec<ServerAddr>,
}

impl MemoryFederationDb {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FederationDb for MemoryFederationDb {
    fn universe_servers(&self) -> Result<Vec<ServerAddr>, UniverseError> {
        Ok(self.servers.clone())
    }

    fn add_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        for addr in addrs {
            if !self.servers.contains(addr) {
                self.servers.push(addr.clone());
            }
        }
        Ok(())
    }

    fn remove_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        self.servers.retain(|s| !addrs.contains(s));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

    fn test_id() -> UniverseId {
        UniverseId {
            asset_id: AssetId([0xAA; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        }
    }

    fn test_leaf(vout: u32) -> (LeafKey, UniverseLeaf) {
        let key = LeafKey {
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout,
            },
            script_key: SerializedKey([0x02; 33]),
        };
        let leaf = UniverseLeaf {
            asset_id: AssetId([0xAA; 32]),
            amount: 100,
            proof: vec![0x01, 0x02],
            key: key.clone(),
        };
        (key, leaf)
    }

    #[test]
    fn test_upsert_and_fetch() {
        let mut backend = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let fetched = backend.fetch_proof(&id, &key).unwrap().unwrap();
        assert_eq!(fetched.leaf.amount, 100);
    }

    #[test]
    fn test_root_node() {
        let mut backend = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let root = backend.root_node(&id).unwrap();
        assert_eq!(root.root_sum, 100);
        assert_ne!(root.root_hash, NodeHash::EMPTY);
    }

    #[test]
    fn test_root_deterministic() {
        let mut b1 = MemoryUniverseBackend::new();
        let mut b2 = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        b1.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        b2.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        assert_eq!(b1.root_node(&id).unwrap(), b2.root_node(&id).unwrap());
    }

    #[test]
    fn test_fetch_keys() {
        let mut backend = MemoryUniverseBackend::new();
        let id = test_id();

        let (k0, l0) = test_leaf(0);
        let (k1, l1) = test_leaf(1);
        backend.upsert_proof_leaf(&id, &k0, &l0).unwrap();
        backend.upsert_proof_leaf(&id, &k1, &l1).unwrap();

        let keys = backend
            .fetch_keys(&id, &LeafKeysQuery::default())
            .unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_delete_universe() {
        let mut backend = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        backend.delete_universe(&id).unwrap();

        assert!(backend.root_node(&id).is_err());
    }

    #[test]
    fn test_federation_db() {
        let mut db = MemoryFederationDb::new();

        let addr = ServerAddr::new("localhost:10029".into());
        db.add_servers(&[addr.clone()]).unwrap();
        assert_eq!(db.universe_servers().unwrap().len(), 1);

        // Duplicate add is idempotent.
        db.add_servers(&[addr.clone()]).unwrap();
        assert_eq!(db.universe_servers().unwrap().len(), 1);

        db.remove_servers(&[addr]).unwrap();
        assert!(db.universe_servers().unwrap().is_empty());
    }
}
