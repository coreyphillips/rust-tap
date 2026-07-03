// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed universe storage and federation database, mirroring
//! [`crate::universe_store`].

use std::sync::Arc;

use postgres::GenericClient;

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;
use tap_universe::traits::{FederationDb, UniverseBackend};
use tap_universe::types::*;

use crate::postgres::{to_array, PostgresDb};
use crate::universe_common::{
    compute_universe_root, proof_type_from_str, proof_type_str,
    UniverseLeafRow,
};

fn store_err(e: postgres::Error) -> UniverseError {
    UniverseError::StoreError(e.to_string())
}

/// Finds or creates a universe root row, returns its id.
///
/// The group_key comparison uses `IS NOT DISTINCT FROM` (Postgres'
/// null-safe equality, the equivalent of SQLite's `IS`).
fn find_or_create_root(
    client: &mut impl GenericClient,
    id: &UniverseId,
) -> Result<i64, UniverseError> {
    let pt = proof_type_str(&id.proof_type);
    let gk: Option<Vec<u8>> = id.group_key.as_ref().map(|k| k.0.to_vec());

    client
        .execute(
            "INSERT INTO universe_roots (asset_id, group_key, proof_type) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (asset_id, proof_type) DO NOTHING",
            &[&&id.asset_id.0[..], &gk, &pt],
        )
        .map_err(store_err)?;

    client
        .query_one(
            "SELECT id FROM universe_roots WHERE asset_id = $1 \
             AND group_key IS NOT DISTINCT FROM $2 AND proof_type = $3",
            &[&&id.asset_id.0[..], &gk, &pt],
        )
        .and_then(|row| row.try_get(0))
        .map_err(store_err)
}

/// Finds the root id for a universe, returns None if not found.
fn find_root_id(
    client: &mut impl GenericClient,
    id: &UniverseId,
) -> Result<Option<i64>, UniverseError> {
    let pt = proof_type_str(&id.proof_type);
    let gk: Option<Vec<u8>> = id.group_key.as_ref().map(|k| k.0.to_vec());
    let row = client
        .query_opt(
            "SELECT id FROM universe_roots WHERE asset_id = $1 \
             AND group_key IS NOT DISTINCT FROM $2 AND proof_type = $3",
            &[&&id.asset_id.0[..], &gk, &pt],
        )
        .map_err(store_err)?;
    match row {
        Some(row) => Ok(Some(row.try_get(0).map_err(store_err)?)),
        None => Ok(None),
    }
}

/// Recomputes root hash and sum from all leaves, matching
/// `MemoryUniverseBackend::compute_root` exactly (BYTEA ordering is
/// byte-wise, like SQLite BLOB ordering).
fn recompute_root(
    client: &mut impl GenericClient,
    root_id: i64,
) -> Result<(NodeHash, u64), UniverseError> {
    let rows = client
        .query(
            "SELECT outpoint_txid, outpoint_vout, script_key, asset_id, \
             amount FROM universe_leaves WHERE universe_root_id = $1 \
             ORDER BY outpoint_txid, outpoint_vout, script_key",
            &[&root_id],
        )
        .map_err(store_err)?;

    let mut leaf_rows: Vec<UniverseLeafRow> = Vec::with_capacity(rows.len());
    for row in &rows {
        let txid: Vec<u8> = row.try_get(0).map_err(store_err)?;
        let vout: i64 = row.try_get(1).map_err(store_err)?;
        let script_key: Vec<u8> = row.try_get(2).map_err(store_err)?;
        let asset_id: Vec<u8> = row.try_get(3).map_err(store_err)?;
        let amount: i64 = row.try_get(4).map_err(store_err)?;
        leaf_rows.push((
            txid,
            vout as u32,
            script_key,
            asset_id,
            amount as u64,
        ));
    }

    Ok(compute_universe_root(&leaf_rows))
}

// ---------------------------------------------------------------------------
// PostgresUniverseBackend
// ---------------------------------------------------------------------------

/// Postgres-backed universe storage.
pub struct PostgresUniverseBackend {
    db: Arc<PostgresDb>,
}

impl PostgresUniverseBackend {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresUniverseBackend { db }
    }
}

impl UniverseBackend for PostgresUniverseBackend {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let pt = proof_type_str(&id.proof_type);
        let gk: Option<Vec<u8>> =
            id.group_key.as_ref().map(|k| k.0.to_vec());

        let row = client
            .query_opt(
                "SELECT root_hash, root_sum FROM universe_roots \
                 WHERE asset_id = $1 \
                 AND group_key IS NOT DISTINCT FROM $2 \
                 AND proof_type = $3",
                &[&&id.asset_id.0[..], &gk, &pt],
            )
            .map_err(store_err)?;

        match row {
            Some(row) => {
                let hash_bytes: Vec<u8> =
                    row.try_get(0).map_err(store_err)?;
                let sum: i64 = row.try_get(1).map_err(store_err)?;
                let hash = to_array::<32>(hash_bytes, "root_hash")
                    .map_err(UniverseError::StoreError)?;
                Ok(UniverseRoot {
                    id: id.clone(),
                    root_hash: NodeHash(hash),
                    root_sum: sum as u64,
                })
            }
            None => Err(UniverseError::NotFound(format!("{:?}", id))),
        }
    }

    fn upsert_proof_leaf(
        &mut self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<UniverseProof, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let mut tx = client.transaction().map_err(store_err)?;

        let root_id = find_or_create_root(&mut tx, id)?;

        tx.execute(
            "INSERT INTO universe_leaves \
             (universe_root_id, outpoint_txid, outpoint_vout, script_key, \
              asset_id, amount, proof_data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (universe_root_id, outpoint_txid, outpoint_vout, \
                          script_key) \
             DO UPDATE SET \
              asset_id = EXCLUDED.asset_id, \
              amount = EXCLUDED.amount, \
              proof_data = EXCLUDED.proof_data",
            &[
                &root_id,
                &&key.outpoint.txid[..],
                &i64::from(key.outpoint.vout),
                &&key.script_key.0[..],
                &&leaf.asset_id.0[..],
                &(leaf.amount as i64),
                &&leaf.proof[..],
            ],
        )
        .map_err(store_err)?;

        // Recompute and update root.
        let (root_hash, root_sum) = recompute_root(&mut tx, root_id)?;

        tx.execute(
            "UPDATE universe_roots SET root_hash = $1, root_sum = $2 \
             WHERE id = $3",
            &[&&root_hash.0[..], &(root_sum as i64), &root_id],
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)?;

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
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let root_id = match find_root_id(&mut *client, id)? {
            Some(id) => id,
            None => return Ok(None),
        };

        let row = client
            .query_opt(
                "SELECT asset_id, amount, proof_data FROM universe_leaves \
                 WHERE universe_root_id = $1 AND outpoint_txid = $2 \
                 AND outpoint_vout = $3 AND script_key = $4",
                &[
                    &root_id,
                    &&key.outpoint.txid[..],
                    &i64::from(key.outpoint.vout),
                    &&key.script_key.0[..],
                ],
            )
            .map_err(store_err)?;

        match row {
            Some(row) => {
                let aid_bytes: Vec<u8> =
                    row.try_get(0).map_err(store_err)?;
                let amount: i64 = row.try_get(1).map_err(store_err)?;
                let proof: Vec<u8> = row.try_get(2).map_err(store_err)?;
                let aid = to_array::<32>(aid_bytes, "asset_id")
                    .map_err(UniverseError::StoreError)?;
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
            None => Ok(None),
        }
    }

    fn fetch_keys(
        &self,
        id: &UniverseId,
        _query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let root_id = match find_root_id(&mut *client, id)? {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        let rows = client
            .query(
                "SELECT outpoint_txid, outpoint_vout, script_key \
                 FROM universe_leaves WHERE universe_root_id = $1",
                &[&root_id],
            )
            .map_err(store_err)?;

        Ok(rows
            .iter()
            .filter_map(|row| {
                let txid_bytes: Vec<u8> = row.try_get(0).ok()?;
                let vout: i64 = row.try_get(1).ok()?;
                let sk_bytes: Vec<u8> = row.try_get(2).ok()?;
                Some(LeafKey {
                    outpoint: OutPoint {
                        txid: to_array::<32>(txid_bytes, "txid").ok()?,
                        vout: vout as u32,
                    },
                    script_key: SerializedKey(
                        to_array::<33>(sk_bytes, "script_key").ok()?,
                    ),
                })
            })
            .collect())
    }

    fn fetch_leaves(
        &self,
        id: &UniverseId,
    ) -> Result<Vec<UniverseLeaf>, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let root_id = match find_root_id(&mut *client, id)? {
            Some(id) => id,
            None => return Ok(vec![]),
        };

        let rows = client
            .query(
                "SELECT outpoint_txid, outpoint_vout, script_key, asset_id, \
                 amount, proof_data \
                 FROM universe_leaves WHERE universe_root_id = $1",
                &[&root_id],
            )
            .map_err(store_err)?;

        Ok(rows
            .iter()
            .filter_map(|row| {
                let txid_bytes: Vec<u8> = row.try_get(0).ok()?;
                let vout: i64 = row.try_get(1).ok()?;
                let sk_bytes: Vec<u8> = row.try_get(2).ok()?;
                let aid_bytes: Vec<u8> = row.try_get(3).ok()?;
                let amount: i64 = row.try_get(4).ok()?;
                let proof: Vec<u8> = row.try_get(5).ok()?;
                Some(UniverseLeaf {
                    asset_id: AssetId(
                        to_array::<32>(aid_bytes, "asset_id").ok()?,
                    ),
                    amount: amount as u64,
                    proof,
                    key: LeafKey {
                        outpoint: OutPoint {
                            txid: to_array::<32>(txid_bytes, "txid").ok()?,
                            vout: vout as u32,
                        },
                        script_key: SerializedKey(
                            to_array::<33>(sk_bytes, "script_key").ok()?,
                        ),
                    },
                })
            })
            .collect())
    }

    fn delete_universe(
        &mut self,
        id: &UniverseId,
    ) -> Result<(), UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let pt = proof_type_str(&id.proof_type);
        let gk: Option<Vec<u8>> =
            id.group_key.as_ref().map(|k| k.0.to_vec());

        client
            .execute(
                "DELETE FROM universe_roots WHERE asset_id = $1 \
                 AND group_key IS NOT DISTINCT FROM $2 \
                 AND proof_type = $3",
                &[&&id.asset_id.0[..], &gk, &pt],
            )
            .map_err(store_err)?;

        Ok(())
    }

    fn universe_ids(&self) -> Result<Vec<UniverseId>, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;

        let rows = client
            .query(
                "SELECT asset_id, group_key, proof_type FROM universe_roots",
                &[],
            )
            .map_err(store_err)?;

        Ok(rows
            .iter()
            .filter_map(|row| {
                let aid_bytes: Vec<u8> = row.try_get(0).ok()?;
                let gk_bytes: Option<Vec<u8>> = row.try_get(1).ok()?;
                let pt: String = row.try_get(2).ok()?;

                let mut aid = [0u8; 32];
                if aid_bytes.len() == 32 {
                    aid.copy_from_slice(&aid_bytes);
                }
                let group_key = gk_bytes.and_then(|gk| {
                    <[u8; 33]>::try_from(gk).ok().map(SerializedKey)
                });

                Some(UniverseId {
                    asset_id: AssetId(aid),
                    group_key,
                    proof_type: proof_type_from_str(&pt),
                })
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// PostgresFederationDb
// ---------------------------------------------------------------------------

/// Postgres-backed federation database.
pub struct PostgresFederationDb {
    db: Arc<PostgresDb>,
}

impl PostgresFederationDb {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresFederationDb { db }
    }
}

impl FederationDb for PostgresFederationDb {
    fn universe_servers(&self) -> Result<Vec<ServerAddr>, UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        let rows = client
            .query(
                "SELECT server_host, server_id FROM universe_servers",
                &[],
            )
            .map_err(store_err)?;

        Ok(rows
            .iter()
            .filter_map(|row| {
                Some(ServerAddr {
                    host: row.try_get(0).ok()?,
                    id: row.try_get(1).ok()?,
                })
            })
            .collect())
    }

    fn add_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        for addr in addrs {
            client
                .execute(
                    "INSERT INTO universe_servers (server_host, server_id) \
                     VALUES ($1, $2) \
                     ON CONFLICT (server_host) DO NOTHING",
                    &[&addr.host, &addr.id],
                )
                .map_err(store_err)?;
        }
        Ok(())
    }

    fn remove_servers(
        &mut self,
        addrs: &[ServerAddr],
    ) -> Result<(), UniverseError> {
        let mut client = self
            .db
            .lock()
            .map_err(UniverseError::StoreError)?;
        for addr in addrs {
            client
                .execute(
                    "DELETE FROM universe_servers WHERE server_host = $1",
                    &[&addr.host],
                )
                .map_err(store_err)?;
        }
        Ok(())
    }
}
