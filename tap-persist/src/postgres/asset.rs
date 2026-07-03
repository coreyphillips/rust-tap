// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`AssetStore`], mirroring
//! [`crate::sqlite::SqliteAssetStore`].

use std::sync::Arc;

use postgres::Row;

use tap_onchain::chain::KeyDescriptor;
use tap_primitives::asset::{AssetId, AssetType, OutPoint, SerializedKey};

use crate::asset_store::{AssetStore, BurnRecord, OwnedAsset};
use crate::postgres::{to_array, PostgresDb};

/// Postgres-backed asset store.
pub struct PostgresAssetStore {
    db: Arc<PostgresDb>,
}

impl PostgresAssetStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresAssetStore { db }
    }
}

/// The columns of `owned_assets` selected for [`OwnedAsset`] rows, in
/// the order expected by `row_to_owned_asset`.
const OWNED_ASSET_COLS: &str = "asset_id, amount, anchor_txid, \
     anchor_vout, script_key, spent, block_height, \
     script_key_family, script_key_index, script_key_raw, \
     internal_key_family, internal_key_index, internal_key_raw, \
     genesis_tag, genesis_meta_hash, genesis_output_index, \
     genesis_asset_type, genesis_point_txid, genesis_point_vout";

impl AssetStore for PostgresAssetStore {
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String> {
        let mut client = self.db.lock()?;

        let asset_id: &[u8] = &asset.asset_id.0;
        let amount = asset.amount as i64;
        let anchor_txid: &[u8] = &asset.anchor_outpoint.txid;
        let anchor_vout = i64::from(asset.anchor_outpoint.vout);
        let script_key: &[u8] = &asset.script_key.0;
        let spent = i64::from(asset.spent);
        let block_height = i64::from(asset.block_height);
        let sk_family = asset
            .script_key_desc
            .as_ref()
            .map(|k| i64::from(k.family));
        let sk_index =
            asset.script_key_desc.as_ref().map(|k| i64::from(k.index));
        let sk_raw = asset
            .script_key_desc
            .as_ref()
            .map(|k| k.pub_key.0.to_vec());
        let ik_family =
            asset.internal_key.as_ref().map(|k| i64::from(k.family));
        let ik_index =
            asset.internal_key.as_ref().map(|k| i64::from(k.index));
        let ik_raw =
            asset.internal_key.as_ref().map(|k| k.pub_key.0.to_vec());
        let genesis_tag = asset.genesis_tag.as_deref();
        let genesis_meta_hash =
            asset.genesis_meta_hash.as_ref().map(|h| h.to_vec());
        let genesis_output_index =
            asset.genesis_output_index.map(i64::from);
        let genesis_asset_type = asset
            .genesis_asset_type
            .map(|t| i64::from(t.to_u8()));
        let gp_txid =
            asset.genesis_point.as_ref().map(|op| op.txid.to_vec());
        let gp_vout =
            asset.genesis_point.as_ref().map(|op| i64::from(op.vout));

        client
            .execute(
                "INSERT INTO owned_assets \
                 (asset_id, amount, anchor_txid, anchor_vout, script_key, \
                  spent, block_height, \
                  script_key_family, script_key_index, script_key_raw, \
                  internal_key_family, internal_key_index, internal_key_raw, \
                  genesis_tag, genesis_meta_hash, genesis_output_index, \
                  genesis_asset_type, genesis_point_txid, genesis_point_vout) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                         $13, $14, $15, $16, $17, $18, $19) \
                 ON CONFLICT (anchor_txid, anchor_vout, asset_id, script_key) \
                 DO UPDATE SET \
                  amount = EXCLUDED.amount, \
                  spent = EXCLUDED.spent, \
                  block_height = EXCLUDED.block_height, \
                  script_key_family = EXCLUDED.script_key_family, \
                  script_key_index = EXCLUDED.script_key_index, \
                  script_key_raw = EXCLUDED.script_key_raw, \
                  internal_key_family = EXCLUDED.internal_key_family, \
                  internal_key_index = EXCLUDED.internal_key_index, \
                  internal_key_raw = EXCLUDED.internal_key_raw, \
                  genesis_tag = EXCLUDED.genesis_tag, \
                  genesis_meta_hash = EXCLUDED.genesis_meta_hash, \
                  genesis_output_index = EXCLUDED.genesis_output_index, \
                  genesis_asset_type = EXCLUDED.genesis_asset_type, \
                  genesis_point_txid = EXCLUDED.genesis_point_txid, \
                  genesis_point_vout = EXCLUDED.genesis_point_vout",
                &[
                    &asset_id,
                    &amount,
                    &anchor_txid,
                    &anchor_vout,
                    &script_key,
                    &spent,
                    &block_height,
                    &sk_family,
                    &sk_index,
                    &sk_raw,
                    &ik_family,
                    &ik_index,
                    &ik_raw,
                    &genesis_tag,
                    &genesis_meta_hash,
                    &genesis_output_index,
                    &genesis_asset_type,
                    &gp_txid,
                    &gp_vout,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_spent(
        &mut self,
        outpoint: &OutPoint,
        asset_id: &AssetId,
        script_key: &SerializedKey,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        let rows = client
            .execute(
                "UPDATE owned_assets SET spent = 1 \
                 WHERE anchor_txid = $1 AND anchor_vout = $2 \
                 AND asset_id = $3 AND script_key = $4",
                &[
                    &&outpoint.txid[..],
                    &i64::from(outpoint.vout),
                    &&asset_id.0[..],
                    &&script_key.0[..],
                ],
            )
            .map_err(|e| e.to_string())?;

        if rows == 0 {
            return Err("asset not found".into());
        }
        Ok(())
    }

    fn unspent_at_outpoint(&self, outpoint: &OutPoint) -> Vec<OwnedAsset> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };
        client
            .query(
                &format!(
                    "SELECT {OWNED_ASSET_COLS} FROM owned_assets \
                     WHERE anchor_txid = $1 AND anchor_vout = $2 \
                     AND spent = 0"
                ),
                &[&&outpoint.txid[..], &i64::from(outpoint.vout)],
            )
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row_to_owned_asset(row).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_anchor_block_height(
        &mut self,
        outpoint: &OutPoint,
        block_height: u32,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "UPDATE owned_assets SET block_height = $1 \
                 WHERE anchor_txid = $2 AND anchor_vout = $3",
                &[
                    &i64::from(block_height),
                    &&outpoint.txid[..],
                    &i64::from(outpoint.vout),
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_unspent(&self, asset_id: &AssetId) -> Vec<OwnedAsset> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };
        client
            .query(
                &format!(
                    "SELECT {OWNED_ASSET_COLS} FROM owned_assets \
                     WHERE asset_id = $1 AND spent = 0"
                ),
                &[&&asset_id.0[..]],
            )
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row_to_owned_asset(row).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn list_unspent(&self) -> Vec<OwnedAsset> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };
        client
            .query(
                &format!(
                    "SELECT {OWNED_ASSET_COLS} FROM owned_assets \
                     WHERE spent = 0"
                ),
                &[],
            )
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row_to_owned_asset(row).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn balance(&self, asset_id: &AssetId) -> u64 {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return 0,
        };
        client
            .query_one(
                // SUM(BIGINT) is NUMERIC in Postgres; cast back down.
                "SELECT COALESCE(SUM(amount), 0)::BIGINT FROM owned_assets \
                 WHERE asset_id = $1 AND spent = 0",
                &[&&asset_id.0[..]],
            )
            .and_then(|row| row.try_get::<_, i64>(0))
            .map(|sum| sum as u64)
            .unwrap_or(0)
    }

    fn insert_burn(&mut self, burn: BurnRecord) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO asset_burns \
                 (note, asset_id, group_key, amount, anchor_txid, \
                  script_key, outpoint_txid, outpoint_vout, block_height) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (outpoint_txid, outpoint_vout, script_key) \
                 DO UPDATE SET \
                  note = EXCLUDED.note, \
                  asset_id = EXCLUDED.asset_id, \
                  group_key = EXCLUDED.group_key, \
                  amount = EXCLUDED.amount, \
                  anchor_txid = EXCLUDED.anchor_txid, \
                  block_height = EXCLUDED.block_height",
                &[
                    &burn.note.as_deref(),
                    &&burn.asset_id.0[..],
                    &burn.group_key.as_ref().map(|k| k.0.to_vec()),
                    &(burn.amount as i64),
                    &&burn.anchor_txid[..],
                    &&burn.script_key.0[..],
                    &&burn.out_point.txid[..],
                    &i64::from(burn.out_point.vout),
                    &i64::from(burn.block_height),
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn list_burns(&self, asset_id: Option<&AssetId>) -> Vec<BurnRecord> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };

        let base_query = "SELECT note, asset_id, group_key, amount, \
             anchor_txid, script_key, outpoint_txid, outpoint_vout, \
             block_height FROM asset_burns";

        let rows = match asset_id {
            Some(id) => client.query(
                &format!("{base_query} WHERE asset_id = $1"),
                &[&&id.0[..]],
            ),
            None => client.query(base_query, &[]),
        };

        rows.map(|rows| {
            rows.iter()
                .filter_map(|row| row_to_burn_record(row).ok())
                .collect()
        })
        .unwrap_or_default()
    }
}

/// Builds an optional [`KeyDescriptor`] from its three nullable
/// columns. Returns `None` unless all three are present and the raw
/// key is 33 bytes.
fn key_desc_from_cols(
    family: Option<i64>,
    index: Option<i64>,
    raw: Option<Vec<u8>>,
) -> Option<KeyDescriptor> {
    let (family, index, raw) = (family?, index?, raw?);
    let pub_key: [u8; 33] = raw.try_into().ok()?;
    Some(KeyDescriptor {
        family: family as u16,
        index: index as u32,
        pub_key: SerializedKey(pub_key),
    })
}

fn row_to_owned_asset(row: &Row) -> Result<OwnedAsset, String> {
    let err = |e: postgres::Error| e.to_string();

    let asset_id_bytes: Vec<u8> = row.try_get(0).map_err(err)?;
    let amount: i64 = row.try_get(1).map_err(err)?;
    let txid_bytes: Vec<u8> = row.try_get(2).map_err(err)?;
    let vout: i64 = row.try_get(3).map_err(err)?;
    let script_key_bytes: Vec<u8> = row.try_get(4).map_err(err)?;
    let spent: i64 = row.try_get(5).map_err(err)?;
    let block_height: i64 = row.try_get(6).map_err(err)?;
    let sk_family: Option<i64> = row.try_get(7).map_err(err)?;
    let sk_index: Option<i64> = row.try_get(8).map_err(err)?;
    let sk_raw: Option<Vec<u8>> = row.try_get(9).map_err(err)?;
    let ik_family: Option<i64> = row.try_get(10).map_err(err)?;
    let ik_index: Option<i64> = row.try_get(11).map_err(err)?;
    let ik_raw: Option<Vec<u8>> = row.try_get(12).map_err(err)?;
    let genesis_tag: Option<String> = row.try_get(13).map_err(err)?;
    let genesis_meta_hash_bytes: Option<Vec<u8>> =
        row.try_get(14).map_err(err)?;
    let genesis_output_index: Option<i64> = row.try_get(15).map_err(err)?;
    let genesis_asset_type_val: Option<i64> = row.try_get(16).map_err(err)?;
    let genesis_point_txid_bytes: Option<Vec<u8>> =
        row.try_get(17).map_err(err)?;
    let genesis_point_vout: Option<i64> = row.try_get(18).map_err(err)?;

    let asset_id = to_array::<32>(asset_id_bytes, "asset_id")?;
    let txid = to_array::<32>(txid_bytes, "anchor_txid")?;
    let script_key = to_array::<33>(script_key_bytes, "script_key")?;

    let genesis_meta_hash = genesis_meta_hash_bytes
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());

    let genesis_point = match (genesis_point_txid_bytes, genesis_point_vout)
    {
        (Some(bytes), Some(vout)) => {
            <[u8; 32]>::try_from(bytes).ok().map(|gp_txid| OutPoint {
                txid: gp_txid,
                vout: vout as u32,
            })
        }
        _ => None,
    };

    Ok(OwnedAsset {
        asset_id: AssetId(asset_id),
        amount: amount as u64,
        anchor_outpoint: OutPoint {
            txid,
            vout: vout as u32,
        },
        script_key: SerializedKey(script_key),
        spent: spent != 0,
        block_height: block_height as u32,
        script_key_desc: key_desc_from_cols(sk_family, sk_index, sk_raw),
        internal_key: key_desc_from_cols(ik_family, ik_index, ik_raw),
        genesis_point,
        genesis_tag,
        genesis_meta_hash,
        genesis_output_index: genesis_output_index.map(|v| v as u32),
        genesis_asset_type: genesis_asset_type_val
            .and_then(|v| AssetType::from_u8(v as u8).ok()),
    })
}

fn row_to_burn_record(row: &Row) -> Result<BurnRecord, String> {
    let err = |e: postgres::Error| e.to_string();

    let note: Option<String> = row.try_get(0).map_err(err)?;
    let asset_id_bytes: Vec<u8> = row.try_get(1).map_err(err)?;
    let group_key_bytes: Option<Vec<u8>> = row.try_get(2).map_err(err)?;
    let amount: i64 = row.try_get(3).map_err(err)?;
    let anchor_txid_bytes: Vec<u8> = row.try_get(4).map_err(err)?;
    let script_key_bytes: Vec<u8> = row.try_get(5).map_err(err)?;
    let outpoint_txid_bytes: Vec<u8> = row.try_get(6).map_err(err)?;
    let outpoint_vout: i64 = row.try_get(7).map_err(err)?;
    let block_height: i64 = row.try_get(8).map_err(err)?;

    let group_key = match group_key_bytes {
        Some(bytes) => {
            Some(SerializedKey(to_array::<33>(bytes, "group_key")?))
        }
        None => None,
    };

    Ok(BurnRecord {
        note,
        asset_id: AssetId(to_array::<32>(asset_id_bytes, "asset_id")?),
        group_key,
        amount: amount as u64,
        anchor_txid: to_array::<32>(anchor_txid_bytes, "anchor_txid")?,
        script_key: SerializedKey(to_array::<33>(
            script_key_bytes,
            "script_key",
        )?),
        out_point: OutPoint {
            txid: to_array::<32>(outpoint_txid_bytes, "outpoint_txid")?,
            vout: outpoint_vout as u32,
        },
        block_height: block_height as u32,
    })
}
