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

use tap_onchain::chain::KeyDescriptor;
use tap_primitives::asset::{AssetId, AssetType, OutPoint, SerializedKey};

/// A tracked asset with its on-chain location and proof.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Key descriptor (family, index, raw key) behind the script key,
    /// when the script key is derived from a local wallet key.
    pub script_key_desc: Option<KeyDescriptor>,
    /// The taproot internal key of the anchor output, when known.
    pub internal_key: Option<KeyDescriptor>,
    /// The genesis outpoint (`Genesis::first_prev_out`, the first
    /// input of the genesis transaction), when known. Together with
    /// the other genesis fields this allows reconstructing the
    /// `tap_primitives::asset::Genesis` of the asset.
    pub genesis_point: Option<OutPoint>,
    /// The genesis tag (asset name), when known.
    pub genesis_tag: Option<String>,
    /// The genesis meta hash, when known.
    pub genesis_meta_hash: Option<[u8; 32]>,
    /// The genesis output index, when known.
    pub genesis_output_index: Option<u32>,
    /// The asset type (normal/collectible), when known.
    pub genesis_asset_type: Option<AssetType>,
}

impl OwnedAsset {
    /// Creates an owned asset with the required fields; the optional
    /// key descriptors and genesis fields default to `None`.
    pub fn new(
        asset_id: AssetId,
        amount: u64,
        anchor_outpoint: OutPoint,
        script_key: SerializedKey,
        block_height: u32,
    ) -> Self {
        OwnedAsset {
            asset_id,
            amount,
            anchor_outpoint,
            script_key,
            spent: false,
            block_height,
            script_key_desc: None,
            internal_key: None,
            genesis_point: None,
            genesis_tag: None,
            genesis_meta_hash: None,
            genesis_output_index: None,
            genesis_asset_type: None,
        }
    }
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
    /// Stores a newly received/minted asset. A single anchor outpoint
    /// can carry several assets (e.g. a multi-asset mint batch);
    /// implementations must key on at least (outpoint, asset ID,
    /// script key).
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String>;

    /// Marks every asset anchored at the outpoint as spent (spending
    /// an anchor UTXO consumes all assets committed to in it).
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
///
/// Keyed by (anchor outpoint, asset ID, script key): a single anchor
/// output's TAP commitment can carry several assets.
#[derive(Default)]
pub struct MemoryAssetStore {
    assets: HashMap<(OutPoint, AssetId, SerializedKey), OwnedAsset>,
    burns: Vec<BurnRecord>,
}

impl MemoryAssetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AssetStore for MemoryAssetStore {
    fn insert_asset(&mut self, asset: OwnedAsset) -> Result<(), String> {
        self.assets.insert(
            (asset.anchor_outpoint, asset.asset_id, asset.script_key),
            asset,
        );
        Ok(())
    }

    fn mark_spent(&mut self, outpoint: &OutPoint) -> Result<(), String> {
        let mut found = false;
        for asset in self.assets.values_mut() {
            if asset.anchor_outpoint == *outpoint {
                asset.spent = true;
                found = true;
            }
        }
        if found {
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
        OwnedAsset::new(
            AssetId([id_byte; 32]),
            amount,
            OutPoint {
                txid: [0xAA; 32],
                vout,
            },
            SerializedKey([0x02; 33]),
            800_000,
        )
    }

    /// An asset with all optional key descriptor and genesis fields set.
    fn test_asset_full(vout: u32) -> OwnedAsset {
        let mut asset = test_asset(0xAA, 100, vout);
        asset.script_key_desc = Some(KeyDescriptor {
            family: 212,
            index: 7,
            pub_key: SerializedKey([0x02; 33]),
        });
        asset.internal_key = Some(KeyDescriptor {
            family: 212,
            index: 8,
            pub_key: SerializedKey([0x03; 33]),
        });
        asset.genesis_point = Some(OutPoint {
            txid: [0x55; 32],
            vout: 2,
        });
        asset.genesis_tag = Some("test-coin".to_string());
        asset.genesis_meta_hash = Some([0x44; 32]);
        asset.genesis_output_index = Some(1);
        asset.genesis_asset_type = Some(AssetType::Normal);
        asset
    }

    #[test]
    fn test_asset_optional_fields_round_trip() {
        let mut store = MemoryAssetStore::new();
        let full = test_asset_full(0);
        store.insert_asset(full.clone()).unwrap();

        // Bare asset (all optional fields None) alongside.
        let bare = test_asset(0xAA, 50, 1);
        store.insert_asset(bare.clone()).unwrap();

        let mut assets = store.get_unspent(&AssetId([0xAA; 32]));
        assets.sort_by_key(|a| a.anchor_outpoint.vout);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0], full);
        assert_eq!(assets[1], bare);
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
