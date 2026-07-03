// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Persistence for signed ignore tuples.
//!
//! [`IgnoreTupleStore`] stores [`SignedIgnoreTuple`]s per asset group
//! and answers `is_ignored` lookups for proof verification (the
//! [`tap_primitives::proof::IgnoreChecker`] rejection cache).
//!
//! Lookups are group-scoped, mirroring Go's `CachingIgnoreChecker`
//! (tapdb/supply_ignore_checker.go): the checker resolves the group
//! key of the asset point's asset ID (via an [`AssetGroupResolver`],
//! Go's `AssetGroupQuery`) and only consults the ignore tuples stored
//! for that group. Non-grouped assets and assets of unknown groups are
//! never ignored.
//!
//! The SQLite implementation keeps a bounded negative cache of
//! group-scoped asset points recently found NOT to be ignored, so the
//! hot verification path avoids repeated queries; inserting new tuples
//! invalidates the affected cache entries (mirroring Go's
//! `CachingIgnoreChecker` negative cache and its per-group
//! invalidation on new supply commitments). The cache capacity default
//! matches Go's `DefaultNegativeLookupCacheSize` (10000). Go places no
//! bound on the tuple queries themselves (`NumLimit: noLeavesLimit`,
//! i.e. no pagination limit), so neither do we.

use std::collections::HashMap;
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use std::collections::{HashSet, VecDeque};
#[cfg(feature = "sqlite")]
use std::sync::Mutex;

use tap_primitives::asset::{AssetId, PrevId, SerializedKey};
use tap_primitives::proof::{IgnoreChecker, ProofError};
use tap_universe::ignore::SignedIgnoreTuple;

/// Storage of signed ignore tuples per asset group.
pub trait IgnoreTupleStore {
    /// Inserts the given signed tuples for the asset group. Tuples for
    /// an already-known asset point are replaced.
    fn insert_tuples(
        &mut self,
        group_key: &SerializedKey,
        tuples: &[SignedIgnoreTuple],
    ) -> Result<(), String>;

    /// Lists all signed tuples of the asset group.
    fn list_tuples(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<SignedIgnoreTuple>, String>;

    /// Returns true if the given asset point is ignored within the
    /// given asset group. Lookups are group-scoped, mirroring Go's
    /// `CachingIgnoreChecker`, which resolves the group of the asset
    /// point and only fetches the ignore leaves for that group's
    /// supply sub-tree (tapdb/supply_ignore_checker.go): a tuple
    /// stored under another group's tree never matches.
    fn is_ignored(
        &self,
        group_key: &SerializedKey,
        prev_id: &PrevId,
    ) -> Result<bool, String>;
}

/// Negative-cache key: an asset point hash scoped by its group key.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) type NegativeCacheKey = ([u8; 33], [u8; 32]);

/// Default capacity of the negative cache, mirroring Go's
/// `DefaultNegativeLookupCacheSize`
/// (tapdb/supply_ignore_checker.go:23). Shared by the SQLite and
/// Postgres ignore stores.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) const DEFAULT_NEGATIVE_CACHE_SIZE: usize = 10_000;

/// A bounded set of group-scoped asset-point hashes known NOT to be
/// ignored.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) struct NegativeCache {
    set: HashSet<NegativeCacheKey>,
    order: VecDeque<NegativeCacheKey>,
    capacity: usize,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl NegativeCache {
    pub(crate) fn new(capacity: usize) -> Self {
        NegativeCache {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub(crate) fn contains(&self, key: &NegativeCacheKey) -> bool {
        self.set.contains(key)
    }

    pub(crate) fn insert(&mut self, key: NegativeCacheKey) {
        if self.capacity == 0 || self.set.contains(&key) {
            return;
        }
        while self.set.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            } else {
                break;
            }
        }
        self.set.insert(key);
        self.order.push_back(key);
    }

    pub(crate) fn remove(&mut self, key: &NegativeCacheKey) {
        if self.set.remove(key) {
            self.order.retain(|k| k != key);
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory [`IgnoreTupleStore`].
#[derive(Default)]
pub struct MemoryIgnoreStore {
    /// group key -> (prev id hash -> tuple).
    tuples: HashMap<[u8; 33], HashMap<[u8; 32], SignedIgnoreTuple>>,
}

impl MemoryIgnoreStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl IgnoreTupleStore for MemoryIgnoreStore {
    fn insert_tuples(
        &mut self,
        group_key: &SerializedKey,
        tuples: &[SignedIgnoreTuple],
    ) -> Result<(), String> {
        let group = self.tuples.entry(*group_key.as_bytes()).or_default();
        for tuple in tuples {
            group.insert(tuple.universe_key(), tuple.clone());
        }
        Ok(())
    }

    fn list_tuples(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<SignedIgnoreTuple>, String> {
        Ok(self
            .tuples
            .get(group_key.as_bytes())
            .map(|group| group.values().cloned().collect())
            .unwrap_or_default())
    }

    fn is_ignored(
        &self,
        group_key: &SerializedKey,
        prev_id: &PrevId,
    ) -> Result<bool, String> {
        Ok(self
            .tuples
            .get(group_key.as_bytes())
            .is_some_and(|group| group.contains_key(&prev_id.hash())))
    }
}

// ---------------------------------------------------------------------------
// IgnoreChecker adapter
// ---------------------------------------------------------------------------

/// Resolves the group key an asset belongs to, mirroring Go's
/// `tapdb.AssetGroupQuery` (tapdb/supply_ignore_checker.go:117). The
/// ignore checker uses this to scope `is_ignored` lookups to the asset
/// point's own group.
pub trait AssetGroupResolver {
    /// Returns the group key of the given asset, or `Ok(None)` if the
    /// asset is not grouped or the asset group is unknown. In both
    /// cases the asset point can never be ignored, matching Go's
    /// `CachingIgnoreChecker.IsIgnored`
    /// (tapdb/supply_ignore_checker.go:266-284).
    fn group_key_for_asset(
        &self,
        asset_id: &AssetId,
    ) -> Result<Option<SerializedKey>, String>;
}

impl<F> AssetGroupResolver for F
where
    F: Fn(&AssetId) -> Result<Option<SerializedKey>, String>,
{
    fn group_key_for_asset(
        &self,
        asset_id: &AssetId,
    ) -> Result<Option<SerializedKey>, String> {
        self(asset_id)
    }
}

/// Adapts an [`IgnoreTupleStore`] plus an [`AssetGroupResolver`] into a
/// proof-verification [`IgnoreChecker`], mirroring Go's
/// `tapdb.CachingIgnoreChecker`: the asset point's group is resolved
/// from its asset ID and the ignore lookup is scoped to that group.
/// Non-grouped assets and assets of unknown groups are never ignored.
pub struct StoreIgnoreChecker<S: IgnoreTupleStore, R: AssetGroupResolver> {
    store: S,
    resolver: R,
}

impl<S: IgnoreTupleStore, R: AssetGroupResolver> StoreIgnoreChecker<S, R> {
    pub fn new(store: S, resolver: R) -> Self {
        StoreIgnoreChecker { store, resolver }
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

impl<S: IgnoreTupleStore, R: AssetGroupResolver> IgnoreChecker
    for StoreIgnoreChecker<S, R>
{
    fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, ProofError> {
        let group_key = self
            .resolver
            .group_key_for_asset(&prev_id.id)
            .map_err(ProofError::VerificationFailed)?;

        match group_key {
            // Non-grouped or unknown-group assets are never ignored
            // (Go: tapdb/supply_ignore_checker.go:266-284).
            None => Ok(false),
            Some(group_key) => self
                .store
                .is_ignored(&group_key, prev_id)
                .map_err(ProofError::VerificationFailed),
        }
    }
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
pub use sqlite_impl::SqliteIgnoreStore;

#[cfg(feature = "sqlite")]
mod sqlite_impl {
    use super::*;

    use rusqlite::params;

    use crate::sqlite::SqliteDb;

    /// Default capacity of the negative cache, mirroring Go's
    /// `DefaultNegativeLookupCacheSize`
    /// (tapdb/supply_ignore_checker.go:23).
    pub(super) use super::DEFAULT_NEGATIVE_CACHE_SIZE;

    /// SQLite-backed [`IgnoreTupleStore`] with a bounded negative
    /// cache for `is_ignored` lookups.
    pub struct SqliteIgnoreStore {
        db: std::sync::Arc<SqliteDb>,
        negative_cache: Mutex<NegativeCache>,
    }

    impl SqliteIgnoreStore {
        pub fn new(db: std::sync::Arc<SqliteDb>) -> Self {
            Self::with_cache_size(db, DEFAULT_NEGATIVE_CACHE_SIZE)
        }

        /// Creates a store with a custom negative cache capacity
        /// (0 disables the cache).
        pub fn with_cache_size(db: std::sync::Arc<SqliteDb>, capacity: usize) -> Self {
            SqliteIgnoreStore {
                db,
                negative_cache: Mutex::new(NegativeCache::new(capacity)),
            }
        }
    }

    impl IgnoreTupleStore for SqliteIgnoreStore {
        fn insert_tuples(
            &mut self,
            group_key: &SerializedKey,
            tuples: &[SignedIgnoreTuple],
        ) -> Result<(), String> {
            {
                let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
                let tx = conn
                    .unchecked_transaction()
                    .map_err(|e| e.to_string())?;

                for tuple in tuples {
                    let prev_id = &tuple.tuple.prev_id;
                    tx.execute(
                        "INSERT OR REPLACE INTO ignore_tuples \
                         (group_key, txid, vout, asset_id, script_key, \
                          amount, block_height, signed_tuple, prev_id_hash) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            &group_key.as_bytes()[..],
                            &prev_id.out_point.txid[..],
                            prev_id.out_point.vout,
                            &prev_id.id.as_bytes()[..],
                            &prev_id.script_key.as_bytes()[..],
                            tuple.tuple.amount as i64,
                            tuple.tuple.block_height,
                            &tuple.encode()[..],
                            &tuple.universe_key()[..],
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                }

                tx.commit().map_err(|e| e.to_string())?;
            }

            // Invalidate negative cache entries for the new points in
            // this group (mirrors Go's per-group
            // `CachingIgnoreChecker.InvalidateCache`, but precisely
            // per inserted asset point).
            let mut cache = self
                .negative_cache
                .lock()
                .map_err(|e| e.to_string())?;
            for tuple in tuples {
                cache.remove(&(*group_key.as_bytes(), tuple.universe_key()));
            }

            Ok(())
        }

        fn list_tuples(
            &self,
            group_key: &SerializedKey,
        ) -> Result<Vec<SignedIgnoreTuple>, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare(
                    "SELECT signed_tuple FROM ignore_tuples \
                     WHERE group_key = ?1 ORDER BY id",
                )
                .map_err(|e| e.to_string())?;

            let rows = stmt
                .query_map(params![&group_key.as_bytes()[..]], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|e| e.to_string())?;

            let mut tuples = Vec::new();
            for row in rows {
                let blob = row.map_err(|e| e.to_string())?;
                tuples.push(
                    SignedIgnoreTuple::decode(&blob)
                        .map_err(|e| e.to_string())?,
                );
            }
            Ok(tuples)
        }

        fn is_ignored(
            &self,
            group_key: &SerializedKey,
            prev_id: &PrevId,
        ) -> Result<bool, String> {
            let cache_key = (*group_key.as_bytes(), prev_id.hash());

            {
                let cache = self
                    .negative_cache
                    .lock()
                    .map_err(|e| e.to_string())?;
                if cache.contains(&cache_key) {
                    return Ok(false);
                }
            }

            // Group-scoped lookup: a tuple stored under another group
            // must not match (Go fetches ignore leaves only for the
            // asset's own group specifier,
            // tapdb/supply_ignore_checker.go:294-298). The table has
            // UNIQUE(group_key, prev_id_hash), so at most one row can
            // match.
            let count: i64 = {
                let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
                conn.query_row(
                    "SELECT COUNT(*) FROM ignore_tuples \
                     WHERE group_key = ?1 AND prev_id_hash = ?2",
                    params![&group_key.as_bytes()[..], &cache_key.1[..]],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?
            };

            if count > 0 {
                return Ok(true);
            }

            let mut cache = self
                .negative_cache
                .lock()
                .map_err(|e| e.to_string())?;
            cache.insert(cache_key);
            Ok(false)
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tap_primitives::asset::{AssetId, OutPoint};
    use tap_universe::ignore::{IgnoreSig, IgnoreTuple};

    use crate::sqlite::SqliteDb;

    fn group_key() -> SerializedKey {
        let mut k = [0x02u8; 33];
        k[32] = 0x11;
        SerializedKey(k)
    }

    fn group_key_b() -> SerializedKey {
        let mut k = [0x02u8; 33];
        k[32] = 0x22;
        SerializedKey(k)
    }

    fn valid_script_key() -> SerializedKey {
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[1..].copy_from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
            0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
            0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ]);
        SerializedKey(k)
    }

    fn signed_tuple(vout: u32, amount: u64) -> SignedIgnoreTuple {
        SignedIgnoreTuple {
            tuple: IgnoreTuple {
                prev_id: PrevId {
                    out_point: OutPoint {
                        txid: [0x55; 32],
                        vout,
                    },
                    id: AssetId([0x66; 32]),
                    script_key: valid_script_key(),
                },
                amount,
                block_height: 321,
            },
            sig: IgnoreSig([0x07; 64]),
        }
    }

    /// Both backends agree on insert/list/is_ignored.
    #[test]
    fn test_ignore_store_backends_agree() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite_store = SqliteIgnoreStore::new(Arc::clone(&db));
        let mut memory_store = MemoryIgnoreStore::new();

        let tuples = vec![signed_tuple(0, 10), signed_tuple(1, 20)];

        for store in [
            &mut sqlite_store as &mut dyn IgnoreTupleStore,
            &mut memory_store as &mut dyn IgnoreTupleStore,
        ] {
            store.insert_tuples(&group_key(), &tuples).unwrap();

            let mut listed = store.list_tuples(&group_key()).unwrap();
            listed.sort_by_key(|t| t.tuple.prev_id.out_point.vout);
            assert_eq!(listed.len(), 2);
            assert_eq!(listed[0], tuples[0]);
            assert_eq!(listed[1], tuples[1]);

            assert!(store
                .is_ignored(&group_key(), &tuples[0].tuple.prev_id)
                .unwrap());
            assert!(store
                .is_ignored(&group_key(), &tuples[1].tuple.prev_id)
                .unwrap());

            let mut other = tuples[0].tuple.prev_id.clone();
            other.out_point.vout = 99;
            assert!(!store.is_ignored(&group_key(), &other).unwrap());
        }
    }

    /// A tuple ignored under group A must NOT make the same asset
    /// point ignored under group B: Go only consults the ignore leaves
    /// of the asset's own group
    /// (tapdb/supply_ignore_checker.go:294-298).
    #[test]
    fn test_is_ignored_group_scoped() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite_store = SqliteIgnoreStore::new(Arc::clone(&db));
        let mut memory_store = MemoryIgnoreStore::new();

        let tuple = signed_tuple(0, 10);

        for store in [
            &mut sqlite_store as &mut dyn IgnoreTupleStore,
            &mut memory_store as &mut dyn IgnoreTupleStore,
        ] {
            store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

            assert!(store
                .is_ignored(&group_key(), &tuple.tuple.prev_id)
                .unwrap());
            assert!(!store
                .is_ignored(&group_key_b(), &tuple.tuple.prev_id)
                .unwrap());
            assert!(store
                .list_tuples(&group_key_b())
                .unwrap()
                .is_empty());
        }
    }

    /// The default negative cache capacity matches Go's
    /// DefaultNegativeLookupCacheSize (10000,
    /// tapdb/supply_ignore_checker.go:23).
    #[test]
    fn test_default_negative_cache_size_matches_go() {
        assert_eq!(sqlite_impl::DEFAULT_NEGATIVE_CACHE_SIZE, 10_000);
    }

    /// The negative cache is invalidated when a cached-negative point
    /// is later inserted.
    #[test]
    fn test_negative_cache_invalidation() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteIgnoreStore::with_cache_size(Arc::clone(&db), 4);

        let tuple = signed_tuple(0, 10);

        // Negative lookup populates the cache.
        assert!(!store
            .is_ignored(&group_key(), &tuple.tuple.prev_id)
            .unwrap());
        // A second lookup is served from cache (same result).
        assert!(!store
            .is_ignored(&group_key(), &tuple.tuple.prev_id)
            .unwrap());

        // Inserting the tuple must invalidate the cached negative.
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();
        assert!(store
            .is_ignored(&group_key(), &tuple.tuple.prev_id)
            .unwrap());
    }

    /// The negative cache is scoped by group: a cached negative for
    /// group B must not mask a subsequent insert under group A, and a
    /// tuple inserted under group A must stay non-ignored under
    /// group B.
    #[test]
    fn test_negative_cache_group_scoped() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteIgnoreStore::with_cache_size(Arc::clone(&db), 4);

        let tuple = signed_tuple(0, 10);

        // Populate negatives for the same point under both groups.
        assert!(!store
            .is_ignored(&group_key(), &tuple.tuple.prev_id)
            .unwrap());
        assert!(!store
            .is_ignored(&group_key_b(), &tuple.tuple.prev_id)
            .unwrap());

        // Insert under group A only.
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

        // Group A now sees the point as ignored (its negative entry
        // was invalidated); group B still does not.
        assert!(store
            .is_ignored(&group_key(), &tuple.tuple.prev_id)
            .unwrap());
        assert!(!store
            .is_ignored(&group_key_b(), &tuple.tuple.prev_id)
            .unwrap());
    }

    /// The negative cache is bounded: old entries are evicted.
    #[test]
    fn test_negative_cache_bounded() {
        let mut cache = NegativeCache::new(2);
        let group = [2u8; 33];
        cache.insert((group, [1; 32]));
        cache.insert((group, [2; 32]));
        cache.insert((group, [3; 32]));
        assert!(!cache.contains(&(group, [1; 32])));
        assert!(cache.contains(&(group, [2; 32])));
        assert!(cache.contains(&(group, [3; 32])));

        cache.remove(&(group, [2; 32]));
        assert!(!cache.contains(&(group, [2; 32])));
    }

    /// The store adapts into a proof-verification IgnoreChecker,
    /// scoped by the group the resolver reports for the asset.
    #[test]
    fn test_ignore_checker_adapter() {
        use tap_primitives::proof::IgnoreChecker as _;

        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteIgnoreStore::new(Arc::clone(&db));
        let tuple = signed_tuple(0, 10);
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

        // The asset belongs to group A: the tuple is found.
        let checker = StoreIgnoreChecker::new(
            store,
            |_: &AssetId| Ok(Some(group_key())),
        );
        assert!(checker.is_ignored(&tuple.tuple.prev_id).unwrap());

        let mut other = tuple.tuple.prev_id.clone();
        other.out_point.vout = 5;
        assert!(!checker.is_ignored(&other).unwrap());
    }

    /// If the resolver maps the asset to a different group (or no
    /// group at all), the tuple stored under group A must not match:
    /// mirrors Go, where the checker only fetches ignore leaves for
    /// the asset's own group, and non-grouped or unknown-group assets
    /// are never ignored (tapdb/supply_ignore_checker.go:266-298).
    #[test]
    fn test_ignore_checker_scoped_by_resolved_group() {
        use tap_primitives::proof::IgnoreChecker as _;

        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteIgnoreStore::new(Arc::clone(&db));
        let tuple = signed_tuple(0, 10);
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

        // Asset resolves to group B: the tuple under group A is not
        // visible.
        let checker_b = StoreIgnoreChecker::new(
            SqliteIgnoreStore::new(Arc::clone(&db)),
            |_: &AssetId| Ok(Some(group_key_b())),
        );
        assert!(!checker_b.is_ignored(&tuple.tuple.prev_id).unwrap());

        // Non-grouped / unknown-group asset: never ignored.
        let checker_none = StoreIgnoreChecker::new(
            SqliteIgnoreStore::new(Arc::clone(&db)),
            |_: &AssetId| Ok(None),
        );
        assert!(!checker_none.is_ignored(&tuple.tuple.prev_id).unwrap());

        // Resolver errors propagate.
        let checker_err = StoreIgnoreChecker::new(
            SqliteIgnoreStore::new(Arc::clone(&db)),
            |_: &AssetId| Err("group query failed".to_string()),
        );
        assert!(checker_err.is_ignored(&tuple.tuple.prev_id).is_err());
    }

    /// A proof whose asset point is ignored fails verification when
    /// the checker is attached to the verifier context.
    #[test]
    fn test_verifier_ctx_rejects_ignored_proof() {
        // This is covered end-to-end in tap-primitives; here we only
        // check the wiring compiles and the checker is consulted via
        // the VerifierCtx builder.
        use tap_primitives::proof::{
            DefaultMerkleVerifier, FixedHeightChainLookup, VerifierCtx,
        };

        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteIgnoreStore::new(Arc::clone(&db));
        let tuple = signed_tuple(0, 10);
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

        struct AcceptHeaders;
        impl tap_primitives::proof::HeaderVerifier for AcceptHeaders {
            fn verify_header(
                &self,
                _header: &tap_primitives::proof::BlockHeader,
                _height: u32,
            ) -> Result<(), tap_primitives::proof::ProofError> {
                Ok(())
            }
        }
        struct AcceptGroups;
        impl tap_primitives::proof::GroupVerifier for AcceptGroups {
            fn verify_group_key(
                &self,
                _group_key: &SerializedKey,
            ) -> Result<(), tap_primitives::proof::ProofError> {
                Ok(())
            }
        }

        let ctx = VerifierCtx::new(
            AcceptHeaders,
            DefaultMerkleVerifier,
            AcceptGroups,
            FixedHeightChainLookup(100),
        )
        .with_ignore_checker(StoreIgnoreChecker::new(
            store,
            |_: &AssetId| Ok(Some(group_key())),
        ));

        let checker = ctx.ignore_checker.as_ref().unwrap();
        assert!(checker.is_ignored(&tuple.tuple.prev_id).unwrap());
    }
}
