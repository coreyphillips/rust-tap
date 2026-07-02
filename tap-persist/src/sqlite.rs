// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! SQLite-backed persistence for Taproot Assets.
//!
//! Provides [`SqliteAssetStore`], [`SqliteBatchStore`], and
//! [`SqliteProofStore`] backed by a shared [`SqliteDb`] handle.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use tap_primitives::asset::{
    AssetType, AssetVersion, OutPoint, SerializedKey,
};
use tap_onchain::chain::{KeyDescriptor, TxConfirmation};
use tap_onchain::mint::{BatchState, MintingBatch, Seedling};
use tap_primitives::asset::AssetId;
use tap_primitives::proof;

use crate::asset_store::{AssetStore, OwnedAsset};
use crate::batch_store::BatchStore;
use crate::proof_store::{ProofLocator, ProofStore};

/// Shared SQLite database handle.
///
/// Wraps a `Mutex<Connection>` for thread-safe access. Configures WAL
/// journal mode, foreign keys, and busy timeout on creation.
pub struct SqliteDb {
    pub(crate) conn: Mutex<Connection>,
}

impl SqliteDb {
    /// Opens (or creates) a SQLite database at the given path and runs
    /// pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Self::configure_and_migrate(conn)
    }

    /// Creates an in-memory SQLite database (useful for testing).
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        Self::configure_and_migrate(conn)
    }

    fn configure_and_migrate(conn: Connection) -> Result<Self, String> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = FULL;",
        )
        .map_err(|e| e.to_string())?;

        crate::migrations::run_migrations(&conn)
            .map_err(|e| e.to_string())?;

        Ok(SqliteDb {
            conn: Mutex::new(conn),
        })
    }
}

// ---------------------------------------------------------------------------
// SqliteAssetStore
// ---------------------------------------------------------------------------

/// SQLite-backed asset store.
pub struct SqliteAssetStore<'a> {
    db: &'a SqliteDb,
}

impl<'a> SqliteAssetStore<'a> {
    pub fn new(db: &'a SqliteDb) -> Self {
        SqliteAssetStore { db }
    }
}

impl AssetStore for SqliteAssetStore<'_> {
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String> {
        let conn = self.db.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO owned_assets \
             (asset_id, amount, anchor_txid, anchor_vout, script_key, spent, block_height) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &asset.asset_id.0[..],
                asset.amount as i64,
                &asset.anchor_outpoint.txid[..],
                asset.anchor_outpoint.vout,
                &asset.script_key.0[..],
                asset.spent as i32,
                asset.block_height,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_spent(&mut self, outpoint: &OutPoint) -> Result<(), String> {
        let conn = self.db.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE owned_assets SET spent = 1 \
                 WHERE anchor_txid = ?1 AND anchor_vout = ?2",
                params![&outpoint.txid[..], outpoint.vout],
            )
            .map_err(|e| e.to_string())?;

        if rows == 0 {
            return Err("asset not found".into());
        }
        Ok(())
    }

    fn get_unspent(&self, asset_id: &AssetId) -> Vec<OwnedAsset> {
        let conn = self.db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT asset_id, amount, anchor_txid, anchor_vout, \
                 script_key, spent, block_height \
                 FROM owned_assets WHERE asset_id = ?1 AND spent = 0",
            )
            .unwrap();

        stmt.query_map(params![&asset_id.0[..]], |row| {
            Ok(row_to_owned_asset(row))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn list_unspent(&self) -> Vec<OwnedAsset> {
        let conn = self.db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT asset_id, amount, anchor_txid, anchor_vout, \
                 script_key, spent, block_height \
                 FROM owned_assets WHERE spent = 0",
            )
            .unwrap();

        stmt.query_map([], |row| Ok(row_to_owned_asset(row)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    fn balance(&self, asset_id: &AssetId) -> u64 {
        let conn = self.db.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM owned_assets \
             WHERE asset_id = ?1 AND spent = 0",
            params![&asset_id.0[..]],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    }
}

fn row_to_owned_asset(row: &rusqlite::Row) -> OwnedAsset {
    let asset_id_bytes: Vec<u8> = row.get(0).unwrap();
    let amount: i64 = row.get(1).unwrap();
    let txid_bytes: Vec<u8> = row.get(2).unwrap();
    let vout: u32 = row.get(3).unwrap();
    let script_key_bytes: Vec<u8> = row.get(4).unwrap();
    let spent: i32 = row.get(5).unwrap();
    let block_height: u32 = row.get(6).unwrap();

    let mut asset_id = [0u8; 32];
    asset_id.copy_from_slice(&asset_id_bytes);
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);
    let mut script_key = [0u8; 33];
    script_key.copy_from_slice(&script_key_bytes);

    OwnedAsset {
        asset_id: AssetId(asset_id),
        amount: amount as u64,
        anchor_outpoint: OutPoint { txid, vout },
        script_key: SerializedKey(script_key),
        spent: spent != 0,
        block_height,
    }
}

// ---------------------------------------------------------------------------
// SqliteBatchStore
// ---------------------------------------------------------------------------

/// SQLite-backed minting batch store.
pub struct SqliteBatchStore<'a> {
    db: &'a SqliteDb,
}

impl<'a> SqliteBatchStore<'a> {
    pub fn new(db: &'a SqliteDb) -> Self {
        SqliteBatchStore { db }
    }
}

impl BatchStore for SqliteBatchStore<'_> {
    fn save_batch(&mut self, batch: &MintingBatch) -> Result<(), String> {
        let conn = self.db.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

        // Extract optional fields.
        let (gen_txid, gen_vout) = match &batch.genesis_outpoint {
            Some(op) => (Some(op.txid.to_vec()), Some(op.vout)),
            None => (None, None),
        };
        let (conf_hash, conf_height, conf_tx_idx, conf_tx) =
            match &batch.confirmation {
                Some(c) => (
                    Some(c.block_hash.to_vec()),
                    Some(c.block_height),
                    Some(c.tx_index),
                    Some(c.tx.clone()),
                ),
                None => (None, None, None, None),
            };

        tx.execute(
            "INSERT OR REPLACE INTO minting_batches \
             (batch_key, batch_state, key_family, key_index, \
              genesis_psbt, signed_tx, \
              genesis_outpoint_txid, genesis_outpoint_vout, \
              confirm_block_hash, confirm_block_height, confirm_tx_index, confirm_tx, \
              mint_output_index, height_hint) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                &batch.batch_key.pub_key.0[..],
                batch.state as u8,
                batch.batch_key.family,
                batch.batch_key.index,
                batch.genesis_psbt.as_deref(),
                batch.signed_tx.as_deref(),
                gen_txid.as_deref(),
                gen_vout,
                conf_hash.as_deref(),
                conf_height,
                conf_tx_idx,
                conf_tx.as_deref(),
                batch.mint_output_index,
                batch.height_hint,
            ],
        )
        .map_err(|e| e.to_string())?;

        // Get the batch row id.
        let batch_id: i64 = tx
            .query_row(
                "SELECT id FROM minting_batches WHERE batch_key = ?1",
                params![&batch.batch_key.pub_key.0[..]],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;

        // Delete existing seedlings (in case of replace).
        tx.execute(
            "DELETE FROM seedlings WHERE batch_id = ?1",
            params![batch_id],
        )
        .map_err(|e| e.to_string())?;

        // Insert seedlings.
        for seedling in batch.seedlings.values() {
            tx.execute(
                "INSERT INTO seedlings \
                 (batch_id, asset_name, asset_version, asset_type, amount, enable_emission) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    batch_id,
                    &seedling.asset_name,
                    seedling.asset_version.to_u8(),
                    seedling.asset_type.to_u8(),
                    seedling.amount as i64,
                    seedling.enable_emission as i32,
                ],
            )
            .map_err(|e| e.to_string())?;
        }

        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn load_batch(
        &self,
        batch_key: &SerializedKey,
    ) -> Result<Option<MintingBatch>, String> {
        let conn = self.db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, batch_key, batch_state, key_family, key_index, \
                 genesis_psbt, signed_tx, \
                 genesis_outpoint_txid, genesis_outpoint_vout, \
                 confirm_block_hash, confirm_block_height, confirm_tx_index, confirm_tx, \
                 mint_output_index, height_hint \
                 FROM minting_batches WHERE batch_key = ?1",
            )
            .map_err(|e| e.to_string())?;

        let batch_opt = stmt
            .query_row(params![&batch_key.0[..]], |row| {
                Ok(row_to_batch_header(row))
            })
            .optional()
            .map_err(|e| e.to_string())?;

        let (batch_id, mut batch) = match batch_opt {
            Some(b) => b,
            None => return Ok(None),
        };

        // Load seedlings.
        let mut seed_stmt = conn
            .prepare(
                "SELECT asset_name, asset_version, asset_type, amount, enable_emission \
                 FROM seedlings WHERE batch_id = ?1",
            )
            .map_err(|e| e.to_string())?;

        let seedlings: Vec<Seedling> = seed_stmt
            .query_map(params![batch_id], |row| {
                let name: String = row.get(0)?;
                let version: u8 = row.get(1)?;
                let asset_type: u8 = row.get(2)?;
                let amount: i64 = row.get(3)?;
                let emission: i32 = row.get(4)?;

                Ok(Seedling {
                    asset_version: if version == 1 {
                        AssetVersion::V1
                    } else {
                        AssetVersion::V0
                    },
                    asset_type: if asset_type == 1 {
                        AssetType::Collectible
                    } else {
                        AssetType::Normal
                    },
                    asset_name: name,
                    meta: None,
                    amount: amount as u64,
                    enable_emission: emission != 0,
                    script_key: None,
                    group_anchor: None,
                })
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        for s in seedlings {
            batch.seedlings.insert(s.asset_name.clone(), s);
        }

        Ok(Some(batch))
    }

    fn update_state(
        &mut self,
        batch_key: &SerializedKey,
        state: BatchState,
    ) -> Result<(), String> {
        let conn = self.db.conn.lock().unwrap();
        let rows = conn
            .execute(
                "UPDATE minting_batches SET batch_state = ?1 WHERE batch_key = ?2",
                params![state as u8, &batch_key.0[..]],
            )
            .map_err(|e| e.to_string())?;

        if rows == 0 {
            return Err("batch not found".into());
        }
        Ok(())
    }

    fn list_batches(&self) -> Vec<MintingBatch> {
        let conn = self.db.conn.lock().unwrap();

        // Load all batch headers.
        let mut stmt = conn
            .prepare(
                "SELECT id, batch_key, batch_state, key_family, key_index, \
                 genesis_psbt, signed_tx, \
                 genesis_outpoint_txid, genesis_outpoint_vout, \
                 confirm_block_hash, confirm_block_height, confirm_tx_index, confirm_tx, \
                 mint_output_index, height_hint \
                 FROM minting_batches",
            )
            .unwrap();

        let batches: Vec<(i64, MintingBatch)> = stmt
            .query_map([], |row| Ok(row_to_batch_header(row)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        // Load seedlings for each batch.
        let mut seed_stmt = conn
            .prepare(
                "SELECT asset_name, asset_version, asset_type, amount, enable_emission \
                 FROM seedlings WHERE batch_id = ?1",
            )
            .unwrap();

        batches
            .into_iter()
            .map(|(batch_id, mut batch)| {
                let seedlings: Vec<(String, Seedling)> = seed_stmt
                    .query_map(params![batch_id], |row| {
                        let name: String = row.get(0)?;
                        let version: u8 = row.get(1)?;
                        let asset_type: u8 = row.get(2)?;
                        let amount: i64 = row.get(3)?;
                        let emission: i32 = row.get(4)?;
                        Ok((
                            name.clone(),
                            Seedling {
                                asset_version: if version == 1 {
                                    AssetVersion::V1
                                } else {
                                    AssetVersion::V0
                                },
                                asset_type: if asset_type == 1 {
                                    AssetType::Collectible
                                } else {
                                    AssetType::Normal
                                },
                                asset_name: name,
                                meta: None,
                                amount: amount as u64,
                                enable_emission: emission != 0,
                                script_key: None,
                                group_anchor: None,
                            },
                        ))
                    })
                    .unwrap()
                    .filter_map(|r| r.ok())
                    .collect();

                batch.seedlings = seedlings.into_iter().collect();
                batch
            })
            .collect()
    }
}

fn row_to_batch_header(row: &rusqlite::Row) -> (i64, MintingBatch) {
    let batch_id: i64 = row.get(0).unwrap();
    let batch_key_bytes: Vec<u8> = row.get(1).unwrap();
    let state_u8: u8 = row.get(2).unwrap();
    let family: u16 = row.get::<_, i32>(3).unwrap() as u16;
    let index: u32 = row.get(4).unwrap();
    let genesis_psbt: Option<Vec<u8>> = row.get(5).unwrap();
    let signed_tx: Option<Vec<u8>> = row.get(6).unwrap();
    let gen_txid: Option<Vec<u8>> = row.get(7).unwrap();
    let gen_vout: Option<u32> = row.get(8).unwrap();
    let conf_hash: Option<Vec<u8>> = row.get(9).unwrap();
    let conf_height: Option<u32> = row.get(10).unwrap();
    let conf_tx_idx: Option<u32> = row.get(11).unwrap();
    let conf_tx: Option<Vec<u8>> = row.get(12).unwrap();
    let mint_output_index: Option<u32> = row.get(13).unwrap();
    let height_hint: u32 = row.get(14).unwrap();

    let mut key = [0u8; 33];
    key.copy_from_slice(&batch_key_bytes);

    let state = match state_u8 {
        0 => BatchState::Pending,
        1 => BatchState::Frozen,
        2 => BatchState::Committed,
        3 => BatchState::Broadcast,
        4 => BatchState::Confirmed,
        5 => BatchState::Finalized,
        6 => BatchState::SeedlingCancelled,
        7 => BatchState::SproutCancelled,
        _ => BatchState::Pending,
    };

    let genesis_outpoint = match (gen_txid, gen_vout) {
        (Some(txid_bytes), Some(vout)) => {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);
            Some(OutPoint { txid, vout })
        }
        _ => None,
    };

    let confirmation = match (conf_hash, conf_height, conf_tx_idx, conf_tx) {
        (Some(hash_bytes), Some(height), Some(tx_idx), Some(tx)) => {
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&hash_bytes);
            Some(TxConfirmation {
                block_hash,
                block_height: height,
                tx_index: tx_idx,
                tx,
            })
        }
        _ => None,
    };

    (
        batch_id,
        MintingBatch {
            state,
            batch_key: KeyDescriptor {
                family,
                index,
                pub_key: SerializedKey(key),
            },
            seedlings: HashMap::new(),
            genesis_psbt,
            root_asset_commitment: None,
            signed_tx,
            genesis_outpoint,
            confirmation,
            mint_output_index,
            height_hint,
        },
    )
}

// ---------------------------------------------------------------------------
// SqliteProofStore
// ---------------------------------------------------------------------------

/// SQLite-backed proof file store.
pub struct SqliteProofStore<'a> {
    db: &'a SqliteDb,
}

impl<'a> SqliteProofStore<'a> {
    pub fn new(db: &'a SqliteDb) -> Self {
        SqliteProofStore { db }
    }
}

impl ProofStore for SqliteProofStore<'_> {
    fn insert_proof(
        &mut self,
        locator: ProofLocator,
        file: proof::File,
    ) -> Result<(), String> {
        let conn = self.db.conn.lock().unwrap();
        let encoded = file.encode();
        conn.execute(
            "INSERT OR REPLACE INTO proof_files \
             (anchor_txid, anchor_vout, script_key, proof_data) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &locator.outpoint.txid[..],
                locator.outpoint.vout,
                &locator.script_key.0[..],
                &encoded[..],
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_proof(
        &self,
        locator: &ProofLocator,
    ) -> Result<Option<proof::File>, String> {
        let conn = self.db.conn.lock().unwrap();
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT proof_data FROM proof_files \
                 WHERE anchor_txid = ?1 AND anchor_vout = ?2 AND script_key = ?3",
                params![
                    &locator.outpoint.txid[..],
                    locator.outpoint.vout,
                    &locator.script_key.0[..],
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;

        match result {
            Some(data) => {
                let file =
                    proof::File::decode(&data).map_err(|e| e.to_string())?;
                Ok(Some(file))
            }
            None => Ok(None),
        }
    }

    fn has_proof(&self, locator: &ProofLocator) -> bool {
        let conn = self.db.conn.lock().unwrap();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM proof_files \
             WHERE anchor_txid = ?1 AND anchor_vout = ?2 AND script_key = ?3)",
            params![
                &locator.outpoint.txid[..],
                locator.outpoint.vout,
                &locator.script_key.0[..],
            ],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
    }

    fn list_proofs(&self) -> Vec<ProofLocator> {
        let conn = self.db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT anchor_txid, anchor_vout, script_key FROM proof_files",
            )
            .unwrap();

        stmt.query_map([], |row| {
            let txid_bytes: Vec<u8> = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let key_bytes: Vec<u8> = row.get(2)?;

            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);
            let mut script_key = [0u8; 33];
            script_key.copy_from_slice(&key_bytes);

            Ok(ProofLocator {
                outpoint: OutPoint { txid, vout },
                script_key: SerializedKey(script_key),
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }
}

/// Trait extension for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_asset(id_byte: u8, amount: u64, vout: u32) -> OwnedAsset {
        OwnedAsset {
            asset_id: AssetId([id_byte; 32]),
            amount,
            anchor_outpoint: OutPoint {
                txid: [0xAA; 32],
                vout,
            },
            script_key: SerializedKey([0x02; 33]),
            spent: false,
            block_height: 800_000,
        }
    }

    fn test_batch() -> MintingBatch {
        let mut batch = MintingBatch::new(KeyDescriptor {
            family: 212,
            index: 0,
            pub_key: SerializedKey([0x02; 33]),
        });
        batch
            .add_seedling(Seedling::new_normal("test-token".into(), 1000))
            .unwrap();
        batch
    }

    fn test_locator(vout: u32) -> ProofLocator {
        ProofLocator {
            outpoint: OutPoint {
                txid: [0xAA; 32],
                vout,
            },
            script_key: SerializedKey([0x02; 33]),
        }
    }

    fn test_proof_file() -> proof::File {
        let mut file = proof::File::new();
        file.append_proof(vec![0x01, 0x02, 0x03]);
        file
    }

    // --- AssetStore tests ---

    #[test]
    fn test_sqlite_asset_insert_and_query() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteAssetStore::new(&db);

        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();
        store.insert_asset(test_asset(0xAA, 200, 1)).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 300);
        assert_eq!(store.get_unspent(&AssetId([0xAA; 32])).len(), 2);
    }

    #[test]
    fn test_sqlite_asset_mark_spent() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteAssetStore::new(&db);

        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();

        let outpoint = OutPoint {
            txid: [0xAA; 32],
            vout: 0,
        };
        store.mark_spent(&outpoint).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 0);
        assert!(store.get_unspent(&AssetId([0xAA; 32])).is_empty());
    }

    #[test]
    fn test_sqlite_asset_multiple_types() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteAssetStore::new(&db);

        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();
        store.insert_asset(test_asset(0xBB, 200, 1)).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 100);
        assert_eq!(store.balance(&AssetId([0xBB; 32])), 200);
        assert_eq!(store.list_unspent().len(), 2);
    }

    #[test]
    fn test_sqlite_asset_mark_spent_not_found() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteAssetStore::new(&db);

        let outpoint = OutPoint {
            txid: [0xFF; 32],
            vout: 99,
        };
        assert!(store.mark_spent(&outpoint).is_err());
    }

    // --- BatchStore tests ---

    #[test]
    fn test_sqlite_batch_save_and_load() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteBatchStore::new(&db);

        let batch = test_batch();
        store.save_batch(&batch).unwrap();

        let loaded = store
            .load_batch(&SerializedKey([0x02; 33]))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, BatchState::Pending);
        assert_eq!(loaded.num_seedlings(), 1);
        assert_eq!(loaded.batch_key.family, 212);
        assert_eq!(loaded.batch_key.index, 0);
    }

    #[test]
    fn test_sqlite_batch_update_state() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteBatchStore::new(&db);

        store.save_batch(&test_batch()).unwrap();
        store
            .update_state(&SerializedKey([0x02; 33]), BatchState::Frozen)
            .unwrap();

        let loaded = store
            .load_batch(&SerializedKey([0x02; 33]))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, BatchState::Frozen);
    }

    #[test]
    fn test_sqlite_batch_list() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteBatchStore::new(&db);

        store.save_batch(&test_batch()).unwrap();
        assert_eq!(store.list_batches().len(), 1);
    }

    #[test]
    fn test_sqlite_batch_not_found() {
        let db = SqliteDb::open_in_memory().unwrap();
        let store = SqliteBatchStore::new(&db);

        let result = store
            .load_batch(&SerializedKey([0xFF; 33]))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_sqlite_batch_with_confirmation() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteBatchStore::new(&db);

        let mut batch = test_batch();
        batch.state = BatchState::Confirmed;
        batch.genesis_outpoint = Some(OutPoint {
            txid: [0xBB; 32],
            vout: 0,
        });
        batch.confirmation = Some(TxConfirmation {
            block_hash: [0xCC; 32],
            block_height: 850_000,
            tx_index: 3,
            tx: vec![0x01, 0x02],
        });
        batch.mint_output_index = Some(0);

        store.save_batch(&batch).unwrap();

        let loaded = store
            .load_batch(&SerializedKey([0x02; 33]))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, BatchState::Confirmed);
        assert!(loaded.genesis_outpoint.is_some());
        assert!(loaded.confirmation.is_some());
        let conf = loaded.confirmation.unwrap();
        assert_eq!(conf.block_height, 850_000);
        assert_eq!(conf.tx_index, 3);
    }

    // --- ProofStore tests ---

    #[test]
    fn test_sqlite_proof_insert_and_get() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteProofStore::new(&db);

        let loc = test_locator(0);
        let file = test_proof_file();
        store.insert_proof(loc.clone(), file).unwrap();

        assert!(store.has_proof(&loc));
        let retrieved = store.get_proof(&loc).unwrap().unwrap();
        assert_eq!(retrieved.num_proofs(), 1);
    }

    #[test]
    fn test_sqlite_proof_missing() {
        let db = SqliteDb::open_in_memory().unwrap();
        let store = SqliteProofStore::new(&db);

        let loc = test_locator(99);
        assert!(!store.has_proof(&loc));
        assert!(store.get_proof(&loc).unwrap().is_none());
    }

    #[test]
    fn test_sqlite_proof_list() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteProofStore::new(&db);

        store
            .insert_proof(test_locator(0), test_proof_file())
            .unwrap();
        store
            .insert_proof(test_locator(1), test_proof_file())
            .unwrap();

        assert_eq!(store.list_proofs().len(), 2);
    }

    #[test]
    fn test_sqlite_proof_replace() {
        let db = SqliteDb::open_in_memory().unwrap();
        let mut store = SqliteProofStore::new(&db);

        let loc = test_locator(0);
        let mut file1 = proof::File::new();
        file1.append_proof(vec![0x01]);
        store.insert_proof(loc.clone(), file1).unwrap();

        let mut file2 = proof::File::new();
        file2.append_proof(vec![0x01]);
        file2.append_proof(vec![0x02]);
        store.insert_proof(loc.clone(), file2).unwrap();

        let retrieved = store.get_proof(&loc).unwrap().unwrap();
        assert_eq!(retrieved.num_proofs(), 2);
    }

    // --- Cross-store shared db test ---

    #[test]
    fn test_shared_db_across_stores() {
        let db = SqliteDb::open_in_memory().unwrap();

        let mut asset_store = SqliteAssetStore::new(&db);
        let mut batch_store = SqliteBatchStore::new(&db);
        let mut proof_store = SqliteProofStore::new(&db);

        asset_store
            .insert_asset(test_asset(0xAA, 100, 0))
            .unwrap();
        batch_store.save_batch(&test_batch()).unwrap();
        proof_store
            .insert_proof(test_locator(0), test_proof_file())
            .unwrap();

        assert_eq!(asset_store.balance(&AssetId([0xAA; 32])), 100);
        assert_eq!(batch_store.list_batches().len(), 1);
        assert_eq!(proof_store.list_proofs().len(), 1);
    }
}
