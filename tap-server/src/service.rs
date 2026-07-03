// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transport-agnostic universe service.
//!
//! [`UniverseService`] wraps a shared [`UniverseBackend`] and exposes
//! the operations the REST layer needs: multiverse root listing, per
//! universe root/keys/leaves queries, proof queries, and validated
//! proof insertion. All methods are synchronous; the REST layer calls
//! them through `tokio::task::spawn_blocking`.
//!
//! Proof insertion performs full validation before the leaf is
//! persisted: the raw proof must decode, must be consistent with the
//! (asset id, outpoint, script key) it is inserted under, and must
//! pass [`ProofLeafVerifier`] (the same verifier
//! `tap_universe::SimpleSyncer` applies to fetched leaves, including
//! the tx merkle proof against the embedded block header).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::proof::decode_proof;

use tap_universe::syncer::{LeafVerifier, ProofLeafVerifier};
use tap_universe::traits::UniverseBackend;
use tap_universe::types::{
    LeafKey, LeafKeysQuery, ProofType, UniverseError, UniverseId,
    UniverseLeaf, UniverseProof, UniverseRoot,
};

/// The shared, thread-safe backend handle the service operates on.
pub type SharedBackend = Arc<Mutex<dyn UniverseBackend + Send>>;

/// Selects a universe by asset ID or by group key.
#[derive(Clone, Debug)]
pub enum UniverseSelector {
    /// Select by the 32-byte asset ID.
    Asset(AssetId),
    /// Select by group key: 32-byte x-only or 33-byte compressed.
    Group(Vec<u8>),
}

impl UniverseSelector {
    /// Whether a universe ID matches this selector (ignoring proof
    /// type).
    fn matches(&self, id: &UniverseId) -> bool {
        match self {
            UniverseSelector::Asset(asset_id) => id.asset_id == *asset_id,
            UniverseSelector::Group(bytes) => match &id.group_key {
                Some(gk) => match bytes.len() {
                    33 => gk.as_bytes()[..] == bytes[..],
                    32 => gk.as_bytes()[1..] == bytes[..],
                    _ => false,
                },
                None => false,
            },
        }
    }

    /// Builds a concrete universe ID for this selector, used when the
    /// backend has no matching universe on record (lookups against it
    /// will report empty/not-found results).
    fn to_universe_id(&self, proof_type: ProofType) -> UniverseId {
        match self {
            UniverseSelector::Asset(asset_id) => UniverseId {
                asset_id: *asset_id,
                group_key: None,
                proof_type,
            },
            UniverseSelector::Group(bytes) => {
                let mut key = [0u8; 33];
                match bytes.len() {
                    33 => key.copy_from_slice(bytes),
                    32 => {
                        key[0] = 0x02;
                        key[1..].copy_from_slice(bytes);
                    }
                    _ => {}
                }
                UniverseId {
                    asset_id: AssetId([0u8; 32]),
                    group_key: Some(SerializedKey(key)),
                    proof_type,
                }
            }
        }
    }
}

/// The issuance and transfer roots for one asset/group, either of
/// which may be absent.
#[derive(Clone, Debug, Default)]
pub struct QueryRootsResult {
    /// The issuance universe root, if the universe exists.
    pub issuance: Option<UniverseRoot>,
    /// The transfer universe root, if the universe exists.
    pub transfer: Option<UniverseRoot>,
}

/// Basic information about this universe server.
#[derive(Clone, Copy, Debug)]
pub struct ServerInfo {
    /// Pseudo-random ID for this server instance (changes on restart).
    pub runtime_id: i64,
    /// Number of distinct assets known to this server.
    pub num_assets: u64,
}

/// Transport-agnostic universe service over a shared backend.
#[derive(Clone)]
pub struct UniverseService {
    backend: SharedBackend,
    runtime_id: i64,
}

/// Returns `true` for the proof types served over the universe REST
/// API (issuance and transfer trees only).
fn is_served(proof_type: ProofType) -> bool {
    matches!(proof_type, ProofType::Issuance | ProofType::Transfer)
}

/// Deterministic ordering rank for proof types.
fn proof_type_rank(proof_type: ProofType) -> u8 {
    match proof_type {
        ProofType::Issuance => 0,
        ProofType::Transfer => 1,
        ProofType::Ignore => 2,
        ProofType::Burn => 3,
        ProofType::MintSupply => 4,
    }
}

/// Sorts universe IDs deterministically for stable pagination.
fn sort_ids(ids: &mut [UniverseId]) {
    ids.sort_by(|a, b| {
        a.asset_id
            .0
            .cmp(&b.asset_id.0)
            .then_with(|| {
                let ga = a.group_key.as_ref().map(|k| k.0);
                let gb = b.group_key.as_ref().map(|k| k.0);
                ga.cmp(&gb)
            })
            .then_with(|| {
                proof_type_rank(a.proof_type)
                    .cmp(&proof_type_rank(b.proof_type))
            })
    });
}

/// Sorts leaf keys deterministically for stable pagination.
fn sort_keys(keys: &mut [LeafKey]) {
    keys.sort_by(|a, b| {
        a.outpoint
            .txid
            .cmp(&b.outpoint.txid)
            .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
            .then_with(|| a.script_key.0.cmp(&b.script_key.0))
    });
}

/// Applies offset/limit paging to a sorted vector, returning the page
/// and whether more results follow it.
fn page<T>(items: Vec<T>, offset: u32, limit: u32) -> (Vec<T>, bool) {
    let total = items.len();
    let start = (offset as usize).min(total);
    let end = start.saturating_add(limit as usize).min(total);
    let page: Vec<T> = items
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect();
    let has_more = end < total;
    (page, has_more)
}

impl UniverseService {
    /// Creates a service over an already shared backend.
    pub fn new(backend: SharedBackend) -> Self {
        // Pseudo-random runtime ID: wall clock nanos mixed with the
        // process ID (no RNG dependency needed).
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let runtime_id = nanos ^ ((std::process::id() as i64) << 32);
        UniverseService {
            backend,
            runtime_id,
        }
    }

    /// Convenience constructor wrapping a backend in `Arc<Mutex<_>>`.
    pub fn from_backend<B>(backend: B) -> Self
    where
        B: UniverseBackend + Send + 'static,
    {
        UniverseService::new(Arc::new(Mutex::new(backend)))
    }

    /// Returns the shared backend handle (e.g. to pre-populate it).
    pub fn backend(&self) -> SharedBackend {
        Arc::clone(&self.backend)
    }

    fn lock(
        &self,
    ) -> Result<MutexGuard<'_, dyn UniverseBackend + Send + 'static>, UniverseError>
    {
        self.backend.lock().map_err(|_| {
            UniverseError::StoreError("backend mutex poisoned".into())
        })
    }

    /// Lists universe roots (issuance/transfer universes only),
    /// paginated. Returns the page and a `has_more` flag.
    pub fn roots(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<UniverseRoot>, bool), UniverseError> {
        let backend = self.lock()?;
        let mut ids: Vec<UniverseId> = backend
            .universe_ids()?
            .into_iter()
            .filter(|id| is_served(id.proof_type))
            .collect();
        sort_ids(&mut ids);

        let (page_ids, has_more) = page(ids, offset, limit);
        let mut roots = Vec::with_capacity(page_ids.len());
        for id in &page_ids {
            match backend.root_node(id) {
                Ok(root) => roots.push(root),
                // A universe listed but since emptied/deleted is
                // skipped rather than failing the whole listing.
                Err(UniverseError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok((roots, has_more))
    }

    /// Returns the issuance and transfer roots for the selected
    /// asset/group. Roots for universes that do not exist are `None`.
    pub fn query_roots(
        &self,
        selector: &UniverseSelector,
    ) -> Result<QueryRootsResult, UniverseError> {
        let backend = self.lock()?;
        let ids = backend.universe_ids()?;

        let mut result = QueryRootsResult::default();
        for proof_type in [ProofType::Issuance, ProofType::Transfer] {
            let id = ids
                .iter()
                .find(|id| {
                    id.proof_type == proof_type && selector.matches(id)
                })
                .cloned()
                .unwrap_or_else(|| selector.to_universe_id(proof_type));

            let root = match backend.root_node(&id) {
                Ok(root) => Some(root),
                Err(UniverseError::NotFound(_)) => None,
                Err(e) => return Err(e),
            };
            match proof_type {
                ProofType::Issuance => result.issuance = root,
                ProofType::Transfer => result.transfer = root,
                _ => {}
            }
        }
        Ok(result)
    }

    /// Resolves a selector plus proof type to a concrete universe ID,
    /// preferring an ID the backend actually has on record.
    fn resolve_universe(
        backend: &MutexGuard<'_, dyn UniverseBackend + Send + 'static>,
        selector: &UniverseSelector,
        proof_type: ProofType,
    ) -> Result<UniverseId, UniverseError> {
        Ok(backend
            .universe_ids()?
            .into_iter()
            .find(|id| {
                id.proof_type == proof_type && selector.matches(id)
            })
            .unwrap_or_else(|| selector.to_universe_id(proof_type)))
    }

    /// Lists leaf keys in the selected universe, paginated.
    pub fn leaf_keys(
        &self,
        selector: &UniverseSelector,
        proof_type: ProofType,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<LeafKey>, bool), UniverseError> {
        let backend = self.lock()?;
        let id = Self::resolve_universe(&backend, selector, proof_type)?;
        let mut keys =
            backend.fetch_keys(&id, &LeafKeysQuery::default())?;
        sort_keys(&mut keys);
        Ok(page(keys, offset, limit))
    }

    /// Lists all leaves in the selected universe.
    pub fn leaves(
        &self,
        selector: &UniverseSelector,
        proof_type: ProofType,
    ) -> Result<Vec<UniverseLeaf>, UniverseError> {
        let backend = self.lock()?;
        let id = Self::resolve_universe(&backend, selector, proof_type)?;
        let mut leaves = backend.fetch_leaves(&id)?;
        leaves.sort_by(|a, b| {
            a.key
                .outpoint
                .txid
                .cmp(&b.key.outpoint.txid)
                .then_with(|| a.key.outpoint.vout.cmp(&b.key.outpoint.vout))
                .then_with(|| a.key.script_key.0.cmp(&b.key.script_key.0))
        });
        Ok(leaves)
    }

    /// Fetches a single proof leaf, plus the root of its universe for
    /// the response envelope. Returns `None` if the leaf (or its
    /// universe) does not exist.
    pub fn query_proof(
        &self,
        selector: &UniverseSelector,
        proof_type: ProofType,
        key: &LeafKey,
    ) -> Result<Option<(Option<UniverseRoot>, UniverseProof)>, UniverseError>
    {
        let backend = self.lock()?;
        let id = Self::resolve_universe(&backend, selector, proof_type)?;

        let proof = match backend.fetch_proof(&id, key)? {
            Some(proof) => proof,
            None => return Ok(None),
        };
        let root = backend.root_node(&id).ok();
        Ok(Some((root, proof)))
    }

    /// Validates and inserts a proof leaf.
    ///
    /// The raw proof must decode, must be consistent with the asset
    /// ID, outpoint and script key it is inserted under, and must pass
    /// full [`ProofLeafVerifier`] verification (asset TLV integrity,
    /// witness checks, and the tx merkle proof against the embedded
    /// block header). The proof type (issuance vs transfer) is derived
    /// from the proof itself.
    pub fn insert_proof(
        &self,
        asset_id: &AssetId,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
        raw_proof: &[u8],
    ) -> Result<(UniverseRoot, UniverseProof), UniverseError> {
        let proof = decode_proof(raw_proof).map_err(|e| {
            UniverseError::ProofInvalid(format!(
                "proof does not decode: {}",
                e
            ))
        })?;

        // The proof must belong under the key it is inserted at.
        if proof.asset.id() != *asset_id {
            return Err(UniverseError::ProofInvalid(
                "proof asset ID does not match request".into(),
            ));
        }
        if proof.out_point() != *outpoint {
            return Err(UniverseError::ProofInvalid(
                "proof outpoint does not match request".into(),
            ));
        }
        if proof.asset.script_key.serialized() != script_key {
            return Err(UniverseError::ProofInvalid(
                "proof script key does not match request".into(),
            ));
        }

        let proof_type = if proof.asset.is_genesis_asset() {
            ProofType::Issuance
        } else {
            ProofType::Transfer
        };

        let id = UniverseId {
            asset_id: *asset_id,
            group_key: proof
                .asset
                .group_key
                .as_ref()
                .map(|gk| gk.group_pub_key),
            proof_type,
        };
        let key = LeafKey {
            outpoint: *outpoint,
            script_key: *script_key,
        };
        let leaf = UniverseLeaf {
            asset_id: *asset_id,
            amount: proof.asset.amount,
            proof: raw_proof.to_vec(),
            key: key.clone(),
        };

        // Full proof verification, same as SimpleSyncer applies to
        // fetched leaves.
        ProofLeafVerifier.verify_leaf(&id, &key, &leaf)?;

        let mut backend = self.lock()?;
        let inserted = backend.upsert_proof_leaf(&id, &key, &leaf)?;
        let root = backend.root_node(&id)?;
        Ok((root, inserted))
    }

    /// Returns server info (runtime ID and known asset count).
    pub fn info(&self) -> Result<ServerInfo, UniverseError> {
        let backend = self.lock()?;
        let assets: HashSet<AssetId> = backend
            .universe_ids()?
            .into_iter()
            .filter(|id| is_served(id.proof_type))
            .map(|id| id.asset_id)
            .collect();
        Ok(ServerInfo {
            runtime_id: self.runtime_id,
            num_assets: assets.len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_universe::memory::MemoryUniverseBackend;

    fn service_with_leaf() -> (UniverseService, UniverseId, LeafKey) {
        let mut backend = MemoryUniverseBackend::new();
        let id = UniverseId {
            asset_id: AssetId([0xAA; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        };
        let key = LeafKey {
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
            script_key: SerializedKey([0x02; 33]),
        };
        let leaf = UniverseLeaf {
            asset_id: id.asset_id,
            amount: 42,
            proof: vec![0x01],
            key: key.clone(),
        };
        backend
            .upsert_proof_leaf(&id, &key, &leaf)
            .expect("insert");
        (
            UniverseService::from_backend(backend),
            id,
            key,
        )
    }

    #[test]
    fn test_roots_listing_and_paging() {
        let (svc, id, _) = service_with_leaf();
        let (roots, has_more) = svc.roots(0, 10).expect("roots");
        assert_eq!(roots.len(), 1);
        assert!(!has_more);
        assert_eq!(roots[0].id, id);
        assert_eq!(roots[0].root_sum, 42);

        // Offset beyond the end yields an empty page.
        let (roots, has_more) = svc.roots(5, 10).expect("roots");
        assert!(roots.is_empty());
        assert!(!has_more);
    }

    #[test]
    fn test_query_roots_selector() {
        let (svc, id, _) = service_with_leaf();
        let sel = UniverseSelector::Asset(id.asset_id);
        let result = svc.query_roots(&sel).expect("query_roots");
        assert!(result.issuance.is_some());
        assert!(result.transfer.is_none());

        let other = UniverseSelector::Asset(AssetId([0x01; 32]));
        let result = svc.query_roots(&other).expect("query_roots");
        assert!(result.issuance.is_none());
        assert!(result.transfer.is_none());
    }

    #[test]
    fn test_leaf_keys_and_query_proof() {
        let (svc, id, key) = service_with_leaf();
        let sel = UniverseSelector::Asset(id.asset_id);

        let (keys, has_more) = svc
            .leaf_keys(&sel, ProofType::Issuance, 0, 512)
            .expect("keys");
        assert_eq!(keys, vec![key.clone()]);
        assert!(!has_more);

        let found = svc
            .query_proof(&sel, ProofType::Issuance, &key)
            .expect("query");
        assert!(found.is_some());

        let missing_key = LeafKey {
            outpoint: OutPoint {
                txid: [0x00; 32],
                vout: 9,
            },
            script_key: SerializedKey([0x03; 33]),
        };
        let missing = svc
            .query_proof(&sel, ProofType::Issuance, &missing_key)
            .expect("query");
        assert!(missing.is_none());
    }

    #[test]
    fn test_insert_proof_rejects_garbage() {
        let svc =
            UniverseService::from_backend(MemoryUniverseBackend::new());
        let err = svc
            .insert_proof(
                &AssetId([0xAA; 32]),
                &OutPoint {
                    txid: [0xBB; 32],
                    vout: 0,
                },
                &SerializedKey([0x02; 33]),
                &[0xDE, 0xAD],
            )
            .expect_err("garbage proof must be rejected");
        assert!(matches!(err, UniverseError::ProofInvalid(_)));
    }

    #[test]
    fn test_info_counts_assets() {
        let (svc, _, _) = service_with_leaf();
        let info = svc.info().expect("info");
        assert_eq!(info.num_assets, 1);
    }
}
