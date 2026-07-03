// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`IgnoreTupleStore`] with the same bounded negative
//! cache as [`crate::ignore_store::SqliteIgnoreStore`].

use std::sync::{Arc, Mutex};

use tap_primitives::asset::{PrevId, SerializedKey};
use tap_universe::ignore::SignedIgnoreTuple;

use crate::ignore_store::{
    IgnoreTupleStore, NegativeCache, DEFAULT_NEGATIVE_CACHE_SIZE,
};
use crate::postgres::PostgresDb;

/// Postgres-backed [`IgnoreTupleStore`] with a bounded negative cache
/// for `is_ignored` lookups (capacity mirrors Go's
/// `DefaultNegativeLookupCacheSize`).
pub struct PostgresIgnoreStore {
    db: Arc<PostgresDb>,
    negative_cache: Mutex<NegativeCache>,
}

impl PostgresIgnoreStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        Self::with_cache_size(db, DEFAULT_NEGATIVE_CACHE_SIZE)
    }

    /// Creates a store with a custom negative cache capacity
    /// (0 disables the cache).
    pub fn with_cache_size(db: Arc<PostgresDb>, capacity: usize) -> Self {
        PostgresIgnoreStore {
            db,
            negative_cache: Mutex::new(NegativeCache::new(capacity)),
        }
    }
}

impl IgnoreTupleStore for PostgresIgnoreStore {
    fn insert_tuples(
        &mut self,
        group_key: &SerializedKey,
        tuples: &[SignedIgnoreTuple],
    ) -> Result<(), String> {
        {
            let mut client = self.db.lock()?;
            let mut tx = client.transaction().map_err(|e| e.to_string())?;

            for tuple in tuples {
                let prev_id = &tuple.tuple.prev_id;
                tx.execute(
                    "INSERT INTO ignore_tuples \
                     (group_key, txid, vout, asset_id, script_key, \
                      amount, block_height, signed_tuple, prev_id_hash) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                     ON CONFLICT (group_key, prev_id_hash) DO UPDATE SET \
                      txid = EXCLUDED.txid, \
                      vout = EXCLUDED.vout, \
                      asset_id = EXCLUDED.asset_id, \
                      script_key = EXCLUDED.script_key, \
                      amount = EXCLUDED.amount, \
                      block_height = EXCLUDED.block_height, \
                      signed_tuple = EXCLUDED.signed_tuple",
                    &[
                        &&group_key.as_bytes()[..],
                        &&prev_id.out_point.txid[..],
                        &i64::from(prev_id.out_point.vout),
                        &&prev_id.id.as_bytes()[..],
                        &&prev_id.script_key.as_bytes()[..],
                        &(tuple.tuple.amount as i64),
                        &i64::from(tuple.tuple.block_height),
                        &&tuple.encode()[..],
                        &&tuple.universe_key()[..],
                    ],
                )
                .map_err(|e| e.to_string())?;
            }

            tx.commit().map_err(|e| e.to_string())?;
        }

        // Invalidate negative cache entries for the new points in this
        // group (mirrors Go's per-group
        // `CachingIgnoreChecker.InvalidateCache`, but precisely per
        // inserted asset point).
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
        let mut client = self.db.lock()?;
        let rows = client
            .query(
                "SELECT signed_tuple FROM ignore_tuples \
                 WHERE group_key = $1 ORDER BY id",
                &[&&group_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;

        let mut tuples = Vec::new();
        for row in &rows {
            let blob: Vec<u8> =
                row.try_get(0).map_err(|e| e.to_string())?;
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

        // Group-scoped lookup: a tuple stored under another group must
        // not match. The table has UNIQUE(group_key, prev_id_hash), so
        // at most one row can match.
        let count: i64 = {
            let mut client = self.db.lock()?;
            client
                .query_one(
                    "SELECT COUNT(*) FROM ignore_tuples \
                     WHERE group_key = $1 AND prev_id_hash = $2",
                    &[&&group_key.as_bytes()[..], &&cache_key.1[..]],
                )
                .and_then(|row| row.try_get(0))
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
