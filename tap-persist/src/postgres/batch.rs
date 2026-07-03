// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`BatchStore`], mirroring
//! [`crate::sqlite::SqliteBatchStore`].

use std::collections::HashMap;
use std::sync::Arc;

use postgres::Row;

use tap_onchain::chain::{KeyDescriptor, TxConfirmation};
use tap_onchain::mint::{BatchState, MintingBatch, Seedling};
use tap_primitives::asset::{
    AssetType, AssetVersion, OutPoint, SerializedKey,
};

use crate::batch_store::BatchStore;
use crate::postgres::{to_array, PostgresDb};

/// Postgres-backed minting batch store.
pub struct PostgresBatchStore {
    db: Arc<PostgresDb>,
}

impl PostgresBatchStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresBatchStore { db }
    }
}

const BATCH_HEADER_COLS: &str = "id, batch_key, batch_state, key_family, \
     key_index, genesis_psbt, signed_tx, \
     genesis_outpoint_txid, genesis_outpoint_vout, \
     confirm_block_hash, confirm_block_height, confirm_tx_index, \
     confirm_tx, mint_output_index, height_hint";

impl BatchStore for PostgresBatchStore {
    fn save_batch(&mut self, batch: &MintingBatch) -> Result<(), String> {
        let mut client = self.db.lock()?;
        let mut tx = client.transaction().map_err(|e| e.to_string())?;

        // Extract optional fields.
        let (gen_txid, gen_vout) = match &batch.genesis_outpoint {
            Some(op) => (Some(op.txid.to_vec()), Some(i64::from(op.vout))),
            None => (None, None),
        };
        let (conf_hash, conf_height, conf_tx_idx, conf_tx) =
            match &batch.confirmation {
                Some(c) => (
                    Some(c.block_hash.to_vec()),
                    Some(i64::from(c.block_height)),
                    Some(i64::from(c.tx_index)),
                    Some(c.tx.clone()),
                ),
                None => (None, None, None, None),
            };

        tx.execute(
            "INSERT INTO minting_batches \
             (batch_key, batch_state, key_family, key_index, \
              genesis_psbt, signed_tx, \
              genesis_outpoint_txid, genesis_outpoint_vout, \
              confirm_block_hash, confirm_block_height, confirm_tx_index, \
              confirm_tx, mint_output_index, height_hint) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                     $13, $14) \
             ON CONFLICT (batch_key) DO UPDATE SET \
              batch_state = EXCLUDED.batch_state, \
              key_family = EXCLUDED.key_family, \
              key_index = EXCLUDED.key_index, \
              genesis_psbt = EXCLUDED.genesis_psbt, \
              signed_tx = EXCLUDED.signed_tx, \
              genesis_outpoint_txid = EXCLUDED.genesis_outpoint_txid, \
              genesis_outpoint_vout = EXCLUDED.genesis_outpoint_vout, \
              confirm_block_hash = EXCLUDED.confirm_block_hash, \
              confirm_block_height = EXCLUDED.confirm_block_height, \
              confirm_tx_index = EXCLUDED.confirm_tx_index, \
              confirm_tx = EXCLUDED.confirm_tx, \
              mint_output_index = EXCLUDED.mint_output_index, \
              height_hint = EXCLUDED.height_hint",
            &[
                &&batch.batch_key.pub_key.0[..],
                &i64::from(batch.state as u8),
                &i64::from(batch.batch_key.family),
                &i64::from(batch.batch_key.index),
                &batch.genesis_psbt.as_deref(),
                &batch.signed_tx.as_deref(),
                &gen_txid,
                &gen_vout,
                &conf_hash,
                &conf_height,
                &conf_tx_idx,
                &conf_tx,
                &batch.mint_output_index.map(i64::from),
                &i64::from(batch.height_hint),
            ],
        )
        .map_err(|e| e.to_string())?;

        // Get the batch row id.
        let batch_id: i64 = tx
            .query_one(
                "SELECT id FROM minting_batches WHERE batch_key = $1",
                &[&&batch.batch_key.pub_key.0[..]],
            )
            .and_then(|row| row.try_get(0))
            .map_err(|e| e.to_string())?;

        // Delete existing seedlings (in case of replace).
        tx.execute(
            "DELETE FROM seedlings WHERE batch_id = $1",
            &[&batch_id],
        )
        .map_err(|e| e.to_string())?;

        // Insert seedlings.
        for seedling in batch.seedlings.values() {
            tx.execute(
                "INSERT INTO seedlings \
                 (batch_id, asset_name, asset_version, asset_type, amount, \
                  enable_emission) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &batch_id,
                    &seedling.asset_name,
                    &i64::from(seedling.asset_version.to_u8()),
                    &i64::from(seedling.asset_type.to_u8()),
                    &(seedling.amount as i64),
                    &i64::from(seedling.enable_emission),
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
        let mut client = self.db.lock()?;

        let query = format!(
            "SELECT {BATCH_HEADER_COLS} FROM minting_batches \
             WHERE batch_key = $1"
        );
        let row = client
            .query_opt(query.as_str(), &[&&batch_key.0[..]])
            .map_err(|e| e.to_string())?;

        let (batch_id, mut batch) = match row {
            Some(row) => row_to_batch_header(&row)?,
            None => return Ok(None),
        };

        let seedlings = load_seedlings(&mut client, batch_id)?;
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
        let mut client = self.db.lock()?;
        let rows = client
            .execute(
                "UPDATE minting_batches SET batch_state = $1 \
                 WHERE batch_key = $2",
                &[&i64::from(state as u8), &&batch_key.0[..]],
            )
            .map_err(|e| e.to_string())?;

        if rows == 0 {
            return Err("batch not found".into());
        }
        Ok(())
    }

    fn list_batches(&self) -> Vec<MintingBatch> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };

        let query =
            format!("SELECT {BATCH_HEADER_COLS} FROM minting_batches");
        let headers: Vec<(i64, MintingBatch)> = match client
            .query(query.as_str(), &[])
        {
            Ok(rows) => rows
                .iter()
                .filter_map(|row| row_to_batch_header(row).ok())
                .collect(),
            Err(_) => return vec![],
        };

        headers
            .into_iter()
            .map(|(batch_id, mut batch)| {
                let seedlings = load_seedlings(&mut client, batch_id)
                    .unwrap_or_default();
                batch.seedlings = seedlings
                    .into_iter()
                    .map(|s| (s.asset_name.clone(), s))
                    .collect();
                batch
            })
            .collect()
    }
}

fn load_seedlings(
    client: &mut postgres::Client,
    batch_id: i64,
) -> Result<Vec<Seedling>, String> {
    let rows = client
        .query(
            "SELECT asset_name, asset_version, asset_type, amount, \
             enable_emission FROM seedlings WHERE batch_id = $1",
            &[&batch_id],
        )
        .map_err(|e| e.to_string())?;

    rows.iter()
        .map(|row| {
            let err = |e: postgres::Error| e.to_string();
            let name: String = row.try_get(0).map_err(err)?;
            let version: i64 = row.try_get(1).map_err(err)?;
            let asset_type: i64 = row.try_get(2).map_err(err)?;
            let amount: i64 = row.try_get(3).map_err(err)?;
            let emission: i64 = row.try_get(4).map_err(err)?;

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
        .collect()
}

fn row_to_batch_header(row: &Row) -> Result<(i64, MintingBatch), String> {
    let err = |e: postgres::Error| e.to_string();

    let batch_id: i64 = row.try_get(0).map_err(err)?;
    let batch_key_bytes: Vec<u8> = row.try_get(1).map_err(err)?;
    let state_val: i64 = row.try_get(2).map_err(err)?;
    let family: i64 = row.try_get(3).map_err(err)?;
    let index: i64 = row.try_get(4).map_err(err)?;
    let genesis_psbt: Option<Vec<u8>> = row.try_get(5).map_err(err)?;
    let signed_tx: Option<Vec<u8>> = row.try_get(6).map_err(err)?;
    let gen_txid: Option<Vec<u8>> = row.try_get(7).map_err(err)?;
    let gen_vout: Option<i64> = row.try_get(8).map_err(err)?;
    let conf_hash: Option<Vec<u8>> = row.try_get(9).map_err(err)?;
    let conf_height: Option<i64> = row.try_get(10).map_err(err)?;
    let conf_tx_idx: Option<i64> = row.try_get(11).map_err(err)?;
    let conf_tx: Option<Vec<u8>> = row.try_get(12).map_err(err)?;
    let mint_output_index: Option<i64> = row.try_get(13).map_err(err)?;
    let height_hint: i64 = row.try_get(14).map_err(err)?;

    let key = to_array::<33>(batch_key_bytes, "batch_key")?;

    let state = match state_val {
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
        (Some(txid_bytes), Some(vout)) => Some(OutPoint {
            txid: to_array::<32>(txid_bytes, "genesis_outpoint_txid")?,
            vout: vout as u32,
        }),
        _ => None,
    };

    let confirmation = match (conf_hash, conf_height, conf_tx_idx, conf_tx) {
        (Some(hash_bytes), Some(height), Some(tx_idx), Some(tx)) => {
            Some(TxConfirmation {
                block_hash: to_array::<32>(hash_bytes, "confirm_block_hash")?,
                block_height: height as u32,
                tx_index: tx_idx as u32,
                tx,
                // The block header and tx hash list are transient
                // confirmation-watch data and are not persisted.
                block_header: [0u8; 80],
                block_tx_hashes: Vec::new(),
            })
        }
        _ => None,
    };

    Ok((
        batch_id,
        MintingBatch {
            state,
            batch_key: KeyDescriptor {
                family: family as u16,
                index: index as u32,
                pub_key: SerializedKey(key),
            },
            seedlings: HashMap::new(),
            genesis_psbt,
            root_asset_commitment: None,
            sprouted_assets: Vec::new(),
            signed_tx,
            genesis_outpoint,
            confirmation,
            mint_output_index: mint_output_index.map(|v| v as u32),
            height_hint: height_hint as u32,
        },
    ))
}
