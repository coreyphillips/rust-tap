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
}

/// In-memory asset store for testing.
#[derive(Default)]
pub struct MemoryAssetStore {
    assets: HashMap<OutPoint, OwnedAsset>,
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
