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
//! The SQLite implementation keeps a bounded negative cache of asset
//! points recently found NOT to be ignored, so the hot verification
//! path avoids repeated queries; inserting new tuples invalidates the
//! affected cache entries (mirroring Go's `IgnoreCheckerCache`
//! invalidation on new supply commitments).

use std::collections::{HashMap, HashSet};
#[cfg(feature = "sqlite")]
use std::collections::VecDeque;
#[cfg(feature = "sqlite")]
use std::sync::Mutex;

use tap_primitives::asset::{PrevId, SerializedKey};
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

    /// Returns true if the given asset point is ignored (in any
    /// group).
    fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, String>;
}

/// A bounded set of asset-point hashes known NOT to be ignored.
#[cfg(feature = "sqlite")]
struct NegativeCache {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

#[cfg(feature = "sqlite")]
impl NegativeCache {
    fn new(capacity: usize) -> Self {
        NegativeCache {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn contains(&self, key: &[u8; 32]) -> bool {
        self.set.contains(key)
    }

    fn insert(&mut self, key: [u8; 32]) {
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

    fn remove(&mut self, key: &[u8; 32]) {
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
    /// All ignored prev id hashes across groups.
    ignored: HashSet<[u8; 32]>,
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
            let hash = tuple.universe_key();
            group.insert(hash, tuple.clone());
            self.ignored.insert(hash);
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

    fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, String> {
        Ok(self.ignored.contains(&prev_id.hash()))
    }
}

// ---------------------------------------------------------------------------
// IgnoreChecker adapter
// ---------------------------------------------------------------------------

/// Adapts any [`IgnoreTupleStore`] into a proof-verification
/// [`IgnoreChecker`].
pub struct StoreIgnoreChecker<S: IgnoreTupleStore> {
    store: S,
}

impl<S: IgnoreTupleStore> StoreIgnoreChecker<S> {
    pub fn new(store: S) -> Self {
        StoreIgnoreChecker { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

impl<S: IgnoreTupleStore> IgnoreChecker for StoreIgnoreChecker<S> {
    fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, ProofError> {
        self.store
            .is_ignored(prev_id)
            .map_err(ProofError::VerificationFailed)
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

    /// Default capacity of the negative cache.
    const DEFAULT_NEGATIVE_CACHE_SIZE: usize = 10_000;

    /// SQLite-backed [`IgnoreTupleStore`] with a bounded negative
    /// cache for `is_ignored` lookups.
    pub struct SqliteIgnoreStore<'a> {
        db: &'a SqliteDb,
        negative_cache: Mutex<NegativeCache>,
    }

    impl<'a> SqliteIgnoreStore<'a> {
        pub fn new(db: &'a SqliteDb) -> Self {
            Self::with_cache_size(db, DEFAULT_NEGATIVE_CACHE_SIZE)
        }

        /// Creates a store with a custom negative cache capacity
        /// (0 disables the cache).
        pub fn with_cache_size(db: &'a SqliteDb, capacity: usize) -> Self {
            SqliteIgnoreStore {
                db,
                negative_cache: Mutex::new(NegativeCache::new(capacity)),
            }
        }
    }

    impl IgnoreTupleStore for SqliteIgnoreStore<'_> {
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

            // Invalidate negative cache entries for the new points.
            let mut cache = self
                .negative_cache
                .lock()
                .map_err(|e| e.to_string())?;
            for tuple in tuples {
                cache.remove(&tuple.universe_key());
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

        fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, String> {
            let hash = prev_id.hash();

            {
                let cache = self
                    .negative_cache
                    .lock()
                    .map_err(|e| e.to_string())?;
                if cache.contains(&hash) {
                    return Ok(false);
                }
            }

            let count: i64 = {
                let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
                conn.query_row(
                    "SELECT COUNT(*) FROM ignore_tuples \
                     WHERE prev_id_hash = ?1",
                    params![&hash[..]],
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
            cache.insert(hash);
            Ok(false)
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    use tap_primitives::asset::{AssetId, OutPoint};
    use tap_universe::ignore::{IgnoreSig, IgnoreTuple};

    use crate::sqlite::SqliteDb;

    fn group_key() -> SerializedKey {
        let mut k = [0x02u8; 33];
        k[32] = 0x11;
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
        let db = SqliteDb::open_in_memory().unwrap();
        let mut sqlite_store = SqliteIgnoreStore::new(&db);
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
                .is_ignored(&tuples[0].tuple.prev_id)
                .unwrap());
            assert!(store
                .is_ignored(&tuples[1].tuple.prev_id)
                .unwrap());

            let mut other = tuples[0].tuple.prev_id.clone();
            other.out_point.vout = 99;
            assert!(!store.is_ignored(&other).unwrap());
        }
    }

    /// The negative cache is invalidated when a cached-negative point
    /// is later inserted.
    #[test]
    fn test_negative_cache_invalidation() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteIgnoreStore::with_cache_size(&db, 4);

        let tuple = signed_tuple(0, 10);

        // Negative lookup populates the cache.
        assert!(!store.is_ignored(&tuple.tuple.prev_id).unwrap());
        // A second lookup is served from cache (same result).
        assert!(!store.is_ignored(&tuple.tuple.prev_id).unwrap());

        // Inserting the tuple must invalidate the cached negative.
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();
        assert!(store.is_ignored(&tuple.tuple.prev_id).unwrap());
    }

    /// The negative cache is bounded: old entries are evicted.
    #[test]
    fn test_negative_cache_bounded() {
        let mut cache = NegativeCache::new(2);
        cache.insert([1; 32]);
        cache.insert([2; 32]);
        cache.insert([3; 32]);
        assert!(!cache.contains(&[1; 32]));
        assert!(cache.contains(&[2; 32]));
        assert!(cache.contains(&[3; 32]));

        cache.remove(&[2; 32]);
        assert!(!cache.contains(&[2; 32]));
    }

    /// The store adapts into a proof-verification IgnoreChecker.
    #[test]
    fn test_ignore_checker_adapter() {
        use tap_primitives::proof::IgnoreChecker as _;

        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteIgnoreStore::new(&db);
        let tuple = signed_tuple(0, 10);
        store.insert_tuples(&group_key(), &[tuple.clone()]).unwrap();

        let checker = StoreIgnoreChecker::new(store);
        assert!(checker.is_ignored(&tuple.tuple.prev_id).unwrap());

        let mut other = tuple.tuple.prev_id.clone();
        other.out_point.vout = 5;
        assert!(!checker.is_ignored(&other).unwrap());
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

        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteIgnoreStore::new(&db);
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
        .with_ignore_checker(StoreIgnoreChecker::new(store));

        let checker = ctx.ignore_checker.as_ref().unwrap();
        assert!(checker.is_ignored(&tuple.tuple.prev_id).unwrap());
    }
}
