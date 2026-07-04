// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! SQLite-backed universe storage and federation database.

use rusqlite::params;
use rusqlite::types::Value as SqlValue;

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;
use tap_universe::traits::{FederationDb, UniverseBackend};
use tap_universe::types::*;

use crate::sqlite::SqliteDb;
use crate::universe_common::{
    compute_universe_root, proof_type_from_str, proof_type_str,
};

/// Converts an optional group key to a SQLite value.
fn gk_to_sql(id: &UniverseId) -> SqlValue {
    match &id.group_key {
        Some(k) => SqlValue::Blob(k.0.to_vec()),
        None => SqlValue::Null,
    }
}

/// Finds or creates a universe root row, returns its id.
fn find_or_create_root(
    conn: &rusqlite::Connection,
    id: &UniverseId,
) -> Result<i64, String> {
    let pt = proof_type_str(&id.proof_type);
    let gk = gk_to_sql(id);

    conn.execute(
        "INSERT OR IGNORE INTO universe_roots (asset_id, group_key, proof_type) VALUES (?1, ?2, ?3)",
        params![&id.asset_id.0[..], gk, pt],
    ).map_err(|e| e.to_string())?;

    // Query back — use IS to handle NULL correctly (NULL IS NULL = true).
    conn.query_row(
        "SELECT id FROM universe_roots WHERE asset_id = ?1 AND group_key IS ?2 AND proof_type = ?3",
        params![&id.asset_id.0[..], gk_to_sql(id), pt],
        |row| row.get::<_, i64>(0),
    )
    .map_err(|e| e.to_string())
}

/// Finds the root id for a universe, returns None if not found.
fn find_root_id(conn: &rusqlite::Connection, id: &UniverseId) -> Option<i64> {
    let pt = proof_type_str(&id.proof_type);
    conn.query_row(
        "SELECT id FROM universe_roots WHERE asset_id = ?1 AND group_key IS ?2 AND proof_type = ?3",
        params![&id.asset_id.0[..], gk_to_sql(id), pt],
        |row| row.get::<_, i64>(0),
    )
    .ok()
}

/// Recomputes root hash and sum from all leaves, matching
/// `MemoryUniverseBackend::compute_root` exactly.
fn recompute_root(
    conn: &rusqlite::Connection,
    root_id: i64,
    proof_type: &tap_universe::types::ProofType,
) -> Result<(NodeHash, u64), String> {
    let mut stmt = conn
        .prepare(
            "SELECT outpoint_txid, outpoint_vout, script_key, asset_id, \
             amount, proof_data \
             FROM universe_leaves WHERE universe_root_id = ?1 \
             ORDER BY outpoint_txid, outpoint_vout, script_key",
        )
        .map_err(|e| e.to_string())?;

    let rows: Vec<crate::universe_common::UniverseLeafRow> = stmt
        .query_map(params![root_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    compute_universe_root(proof_type, &rows)
}

// ---------------------------------------------------------------------------
// SqliteUniverseBackend
// ---------------------------------------------------------------------------

/// SQLite-backed universe storage.
pub struct SqliteUniverseBackend {
    db: std::sync::Arc<SqliteDb>,
}

impl SqliteUniverseBackend {
    pub fn new(db: std::sync::Arc<SqliteDb>) -> Self {
        SqliteUniverseBackend { db }
    }
}

impl UniverseBackend for SqliteUniverseBackend {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let pt = proof_type_str(&id.proof_type);

        let result: Result<(Vec<u8>, i64), _> = conn.query_row(
            "SELECT root_hash, root_sum FROM universe_roots \
             WHERE asset_id = ?1 AND group_key IS ?2 AND proof_type = ?3",
            params![&id.asset_id.0[..], gk_to_sql(id), pt],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        );

        match result {
            Ok((hash_bytes, sum)) => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                Ok(UniverseRoot {
                    id: id.clone(),
                    root_hash: NodeHash(hash),
                    root_sum: sum as u64,
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(UniverseError::NotFound(format!("{:?}", id)))
            }
            Err(e) => Err(UniverseError::StoreError(e.to_string())),
        }
    }

    fn upsert_proof_leaf(
        &mut self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<UniverseProof, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        let root_id = find_or_create_root(&tx, id)
            .map_err(UniverseError::StoreError)?;

        tx.execute(
            "INSERT OR REPLACE INTO universe_leaves \
             (universe_root_id, outpoint_txid, outpoint_vout, script_key, asset_id, amount, proof_data) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                root_id,
                &key.outpoint.txid[..],
                key.outpoint.vout,
                &key.script_key.0[..],
                &leaf.asset_id.0[..],
                leaf.amount as i64,
                &leaf.proof[..],
            ],
        )
        .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        // Recompute and update root.
        let (root_hash, root_sum) =
            recompute_root(&tx, root_id, &id.proof_type)
                .map_err(UniverseError::StoreError)?;

        tx.execute(
            "UPDATE universe_roots SET root_hash = ?1, root_sum = ?2 WHERE id = ?3",
            params![&root_hash.0[..], root_sum as i64, root_id],
        )
        .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        tx.commit()
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        Ok(UniverseProof {
            leaf: leaf.clone(),
            inclusion_proof: vec![],
        })
    }

    fn fetch_proof(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let root_id = match find_root_id(&conn, id) {
            Some(id) => id,
            None => return Ok(None),
        };

        let result = conn.query_row(
            "SELECT asset_id, amount, proof_data FROM universe_leaves \
             WHERE universe_root_id = ?1 AND outpoint_txid = ?2 AND outpoint_vout = ?3 AND script_key = ?4",
            params![root_id, &key.outpoint.txid[..], key.outpoint.vout, &key.script_key.0[..]],
            |row| {
                let aid: Vec<u8> = row.get(0)?;
                let amount: i64 = row.get(1)?;
                let proof: Vec<u8> = row.get(2)?;
                Ok((aid, amount, proof))
            },
        );

        match result {
            Ok((aid_bytes, amount, proof)) => {
                let mut aid = [0u8; 32];
                aid.copy_from_slice(&aid_bytes);
                Ok(Some(UniverseProof {
                    leaf: UniverseLeaf {
                        asset_id: AssetId(aid),
                        amount: amount as u64,
                        proof,
                        key: key.clone(),
                    },
                    inclusion_proof: vec![],
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(UniverseError::StoreError(e.to_string())),
        }
    }

    fn fetch_keys(
        &self,
        id: &UniverseId,
        _query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let root_id = match find_root_id(&conn, id) {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        let mut stmt = conn
            .prepare(
                "SELECT outpoint_txid, outpoint_vout, script_key \
                 FROM universe_leaves WHERE universe_root_id = ?1",
            )
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        let keys = stmt
            .query_map(params![root_id], |row| {
                let txid_bytes: Vec<u8> = row.get(0)?;
                let vout: u32 = row.get(1)?;
                let sk_bytes: Vec<u8> = row.get(2)?;
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);
                let mut sk = [0u8; 33];
                sk.copy_from_slice(&sk_bytes);
                Ok(LeafKey {
                    outpoint: OutPoint { txid, vout },
                    script_key: SerializedKey(sk),
                })
            })
            .map_err(|e| UniverseError::StoreError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(keys)
    }

    fn fetch_leaves(
        &self,
        id: &UniverseId,
    ) -> Result<Vec<UniverseLeaf>, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let root_id = match find_root_id(&conn, id) {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        let mut stmt = conn
            .prepare(
                "SELECT outpoint_txid, outpoint_vout, script_key, asset_id, amount, proof_data \
                 FROM universe_leaves WHERE universe_root_id = ?1",
            )
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        let leaves = stmt
            .query_map(params![root_id], |row| {
                let txid_bytes: Vec<u8> = row.get(0)?;
                let vout: u32 = row.get(1)?;
                let sk_bytes: Vec<u8> = row.get(2)?;
                let aid_bytes: Vec<u8> = row.get(3)?;
                let amount: i64 = row.get(4)?;
                let proof: Vec<u8> = row.get(5)?;

                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);
                let mut sk = [0u8; 33];
                sk.copy_from_slice(&sk_bytes);
                let mut aid = [0u8; 32];
                aid.copy_from_slice(&aid_bytes);

                Ok(UniverseLeaf {
                    asset_id: AssetId(aid),
                    amount: amount as u64,
                    proof,
                    key: LeafKey {
                        outpoint: OutPoint { txid, vout },
                        script_key: SerializedKey(sk),
                    },
                })
            })
            .map_err(|e| UniverseError::StoreError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(leaves)
    }

    fn delete_universe(
        &mut self,
        id: &UniverseId,
    ) -> Result<(), UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let pt = proof_type_str(&id.proof_type);

        conn.execute(
            "DELETE FROM universe_roots WHERE asset_id = ?1 AND group_key IS ?2 AND proof_type = ?3",
            params![&id.asset_id.0[..], gk_to_sql(id), pt],
        )
        .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        Ok(())
    }

    fn universe_ids(&self) -> Result<Vec<UniverseId>, UniverseError> {
        let conn = self.db.conn.lock().unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT asset_id, group_key, proof_type FROM universe_roots",
            )
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        let ids = stmt
            .query_map([], |row| {
                let aid_bytes: Vec<u8> = row.get(0)?;
                let gk_bytes: Option<Vec<u8>> = row.get(1)?;
                let pt: String = row.get(2)?;

                let mut aid = [0u8; 32];
                if aid_bytes.len() == 32 {
                    aid.copy_from_slice(&aid_bytes);
                }
                let group_key = gk_bytes.and_then(|gk| {
                    if gk.len() == 33 {
                        let mut key = [0u8; 33];
                        key.copy_from_slice(&gk);
                        Some(SerializedKey(key))
                    } else {
                        None
                    }
                });

                Ok(UniverseId {
                    asset_id: AssetId(aid),
                    group_key,
                    proof_type: proof_type_from_str(&pt),
                })
            })
            .map_err(|e| UniverseError::StoreError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(ids)
    }
}

// ---------------------------------------------------------------------------
// SqliteFederationDb
// ---------------------------------------------------------------------------

/// SQLite-backed federation database.
pub struct SqliteFederationDb {
    db: std::sync::Arc<SqliteDb>,
}

impl SqliteFederationDb {
    pub fn new(db: std::sync::Arc<SqliteDb>) -> Self {
        SqliteFederationDb { db }
    }
}

impl FederationDb for SqliteFederationDb {
    fn universe_servers(&self) -> Result<Vec<ServerAddr>, UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT server_host, server_id FROM universe_servers")
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;

        let servers = stmt
            .query_map([], |row| {
                Ok(ServerAddr {
                    host: row.get(0)?,
                    id: row.get(1)?,
                })
            })
            .map_err(|e| UniverseError::StoreError(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(servers)
    }

    fn add_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        for addr in addrs {
            conn.execute(
                "INSERT OR IGNORE INTO universe_servers (server_host, server_id) VALUES (?1, ?2)",
                params![&addr.host, &addr.id],
            )
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;
        }
        Ok(())
    }

    fn remove_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        let conn = self.db.conn.lock().unwrap();
        for addr in addrs {
            conn.execute(
                "DELETE FROM universe_servers WHERE server_host = ?1",
                params![&addr.host],
            )
            .map_err(|e| UniverseError::StoreError(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tap_universe::MemoryUniverseBackend;

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
    fn test_sqlite_universe_upsert_and_fetch() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteUniverseBackend::new(Arc::clone(&db));
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        store.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let fetched = store.fetch_proof(&id, &key).unwrap().unwrap();
        assert_eq!(fetched.leaf.amount, 100);
    }

    #[test]
    fn test_sqlite_universe_root_node() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteUniverseBackend::new(Arc::clone(&db));
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        store.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let root = store.root_node(&id).unwrap();
        assert_eq!(root.root_sum, 100);
        assert_ne!(root.root_hash, NodeHash::EMPTY);
    }

    #[test]
    fn test_sqlite_universe_fetch_keys() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteUniverseBackend::new(Arc::clone(&db));
        let id = test_id();

        let (k0, l0) = test_leaf(0);
        let (k1, l1) = test_leaf(1);
        store.upsert_proof_leaf(&id, &k0, &l0).unwrap();
        store.upsert_proof_leaf(&id, &k1, &l1).unwrap();

        let keys = store
            .fetch_keys(&id, &LeafKeysQuery::default())
            .unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_sqlite_universe_delete() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteUniverseBackend::new(Arc::clone(&db));
        let id = test_id();
        let (key, leaf) = test_leaf(0);

        store.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        store.delete_universe(&id).unwrap();

        assert!(store.root_node(&id).is_err());
    }

    #[test]
    fn test_sqlite_universe_not_found() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let store = SqliteUniverseBackend::new(Arc::clone(&db));
        assert!(store.root_node(&test_id()).is_err());
    }

    #[test]
    fn test_sqlite_matches_memory_backend() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite = SqliteUniverseBackend::new(Arc::clone(&db));
        let mut memory = MemoryUniverseBackend::new();
        let id = test_id();

        let (k0, l0) = test_leaf(0);
        let (k1, l1) = test_leaf(1);

        sqlite.upsert_proof_leaf(&id, &k0, &l0).unwrap();
        sqlite.upsert_proof_leaf(&id, &k1, &l1).unwrap();
        memory.upsert_proof_leaf(&id, &k0, &l0).unwrap();
        memory.upsert_proof_leaf(&id, &k1, &l1).unwrap();

        let sqlite_root = sqlite.root_node(&id).unwrap();
        let memory_root = memory.root_node(&id).unwrap();

        assert_eq!(sqlite_root.root_hash, memory_root.root_hash);
        assert_eq!(sqlite_root.root_sum, memory_root.root_sum);
    }

    #[test]
    fn test_sqlite_federation_db() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut fed = SqliteFederationDb::new(Arc::clone(&db));

        let addr = ServerAddr::new("localhost:10029".into());
        fed.add_servers(&[addr.clone()]).unwrap();
        assert_eq!(fed.universe_servers().unwrap().len(), 1);

        // Duplicate is idempotent.
        fed.add_servers(&[addr.clone()]).unwrap();
        assert_eq!(fed.universe_servers().unwrap().len(), 1);

        fed.remove_servers(&[addr]).unwrap();
        assert!(fed.universe_servers().unwrap().is_empty());
    }
}
