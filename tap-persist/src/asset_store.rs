// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset ownership tracking store.

use std::collections::HashMap;

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

/// A tracked asset with its on-chain location and proof.
#[derive(Clone, Debug)]
pub struct OwnedAsset {
    /// The asset ID.
    pub asset_id: AssetId,
    /// Amount of this asset.
    pub amount: u64,
    /// The Bitcoin outpoint anchoring this asset.
    pub anchor_outpoint: OutPoint,
    /// The script key controlling this asset.
    pub script_key: SerializedKey,
    /// Whether this asset has been spent.
    pub spent: bool,
    /// Block height at which this asset was confirmed.
    pub block_height: u32,
}

/// A record of a completed asset burn.
///
/// Mirrors the fields Go persists per burn (`tapdb` burn records): the
/// burned asset, amount, the anchor transaction and the burn output
/// location, plus an optional user note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnRecord {
    /// Optional human readable note for the burn.
    pub note: Option<String>,
    /// The asset that was burned.
    pub asset_id: AssetId,
    /// Optional group key of the burned asset.
    pub group_key: Option<SerializedKey>,
    /// Number of units burned.
    pub amount: u64,
    /// The transaction that anchored the burn.
    pub anchor_txid: [u8; 32],
    /// The burn script key (provably un-spendable).
    pub script_key: SerializedKey,
    /// The outpoint of the burn output.
    pub out_point: OutPoint,
    /// Block height at which the burn confirmed.
    pub block_height: u32,
}

/// Trait for persisting owned assets.
pub trait AssetStore {
    /// Stores a newly received/minted asset.
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String>;

    /// Marks an asset as spent.
    fn mark_spent(&mut self, outpoint: &OutPoint) -> Result<(), String>;

    /// Returns all unspent assets for a given asset ID.
    fn get_unspent(&self, asset_id: &AssetId) -> Vec<OwnedAsset>;

    /// Returns all unspent assets across all types.
    fn list_unspent(&self) -> Vec<OwnedAsset>;

    /// Returns the total balance for a given asset ID.
    fn balance(&self, asset_id: &AssetId) -> u64;

    /// Stores a record of a completed burn.
    fn insert_burn(&mut self, burn: BurnRecord) -> Result<(), String>;

    /// Returns all burn records, optionally filtered by asset ID.
    fn list_burns(&self, asset_id: Option<&AssetId>) -> Vec<BurnRecord>;
}

/// In-memory asset store for testing.
#[derive(Default)]
pub struct MemoryAssetStore {
    assets: HashMap<OutPoint, OwnedAsset>,
    burns: Vec<BurnRecord>,
}

impl MemoryAssetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AssetStore for MemoryAssetStore {
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String> {
        self.assets.insert(asset.anchor_outpoint, asset);
        Ok(())
    }

    fn mark_spent(&mut self, outpoint: &OutPoint) -> Result<(), String> {
        if let Some(asset) = self.assets.get_mut(outpoint) {
            asset.spent = true;
            Ok(())
        } else {
            Err("asset not found".into())
        }
    }

    fn get_unspent(&self, asset_id: &AssetId) -> Vec<OwnedAsset> {
        self.assets
            .values()
            .filter(|a| a.asset_id == *asset_id && !a.spent)
            .cloned()
            .collect()
    }

    fn list_unspent(&self) -> Vec<OwnedAsset> {
        self.assets.values().filter(|a| !a.spent).cloned().collect()
    }

    fn balance(&self, asset_id: &AssetId) -> u64 {
        self.assets
            .values()
            .filter(|a| a.asset_id == *asset_id && !a.spent)
            .map(|a| a.amount)
            .sum()
    }

    fn insert_burn(&mut self, burn: BurnRecord) -> Result<(), String> {
        self.burns.push(burn);
        Ok(())
    }

    fn list_burns(&self, asset_id: Option<&AssetId>) -> Vec<BurnRecord> {
        self.burns
            .iter()
            .filter(|b| asset_id.map_or(true, |id| b.asset_id == *id))
            .cloned()
            .collect()
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

    #[test]
    fn test_insert_and_query() {
        let mut store = MemoryAssetStore::new();
        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();
        store.insert_asset(test_asset(0xAA, 200, 1)).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 300);
        assert_eq!(store.get_unspent(&AssetId([0xAA; 32])).len(), 2);
    }

    #[test]
    fn test_mark_spent() {
        let mut store = MemoryAssetStore::new();
        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();

        let outpoint = OutPoint {
            txid: [0xAA; 32],
            vout: 0,
        };
        store.mark_spent(&outpoint).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 0);
        assert!(store.get_unspent(&AssetId([0xAA; 32])).is_empty());
    }

    fn test_burn(id_byte: u8, amount: u64, vout: u32) -> BurnRecord {
        BurnRecord {
            note: Some("goodbye".to_string()),
            asset_id: AssetId([id_byte; 32]),
            group_key: Some(SerializedKey([0x03; 33])),
            amount,
            anchor_txid: [0xDD; 32],
            script_key: SerializedKey([0x02; 33]),
            out_point: OutPoint {
                txid: [0xDD; 32],
                vout,
            },
            block_height: 850_000,
        }
    }

    #[test]
    fn test_burn_round_trip() {
        let mut store = MemoryAssetStore::new();
        let burn = test_burn(0xAA, 100, 0);
        store.insert_burn(burn.clone()).unwrap();

        let burns = store.list_burns(None);
        assert_eq!(burns.len(), 1);
        assert_eq!(burns[0], burn);
    }

    #[test]
    fn test_burn_filter_by_asset_id() {
        let mut store = MemoryAssetStore::new();
        store.insert_burn(test_burn(0xAA, 100, 0)).unwrap();
        store.insert_burn(test_burn(0xBB, 200, 1)).unwrap();

        assert_eq!(store.list_burns(None).len(), 2);
        let filtered = store.list_burns(Some(&AssetId([0xAA; 32])));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].amount, 100);
        assert!(store
            .list_burns(Some(&AssetId([0xCC; 32])))
            .is_empty());
    }

    #[test]
    fn test_burn_optional_fields() {
        let mut store = MemoryAssetStore::new();
        let mut burn = test_burn(0xAA, 100, 0);
        burn.note = None;
        burn.group_key = None;
        store.insert_burn(burn.clone()).unwrap();

        let burns = store.list_burns(None);
        assert_eq!(burns[0], burn);
    }

    #[test]
    fn test_multiple_asset_types() {
        let mut store = MemoryAssetStore::new();
        store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();
        store.insert_asset(test_asset(0xBB, 200, 1)).unwrap();

        assert_eq!(store.balance(&AssetId([0xAA; 32])), 100);
        assert_eq!(store.balance(&AssetId([0xBB; 32])), 200);
        assert_eq!(store.list_unspent().len(), 2);
    }
}
