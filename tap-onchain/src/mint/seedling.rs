// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Seedling — an intent to create a new asset.

use tap_primitives::asset::{
    AssetType, AssetVersion, ScriptKey, MAX_ASSET_NAME_LENGTH,
};
use tap_primitives::proof::MetaReveal;

use super::MintError;

/// An asset issuance request.
///
/// A seedling describes the desired properties of a new asset to be minted.
/// Multiple seedlings can be batched together into a single minting
/// transaction for efficiency.
#[derive(Clone, Debug)]
pub struct Seedling {
    /// Version of the asset to create.
    pub asset_version: AssetVersion,
    /// Type of asset (Normal or Collectible).
    pub asset_type: AssetType,
    /// Human-readable name (max 64 bytes, used as the genesis tag).
    pub asset_name: String,
    /// Optional metadata to attach to the asset.
    pub meta: Option<MetaReveal>,
    /// Total number of units to mint. Must be 1 for collectibles.
    pub amount: u64,
    /// If true, a group key will be created allowing future reissuance.
    pub enable_emission: bool,
    /// Optional script key for the minted asset. If None, one will be
    /// derived during batch finalization.
    pub script_key: Option<ScriptKey>,
    /// Optional name of another seedling in the same batch that serves
    /// as the group anchor (for grouped assets without their own group key).
    pub group_anchor: Option<String>,
}

impl Seedling {
    /// Creates a new seedling for a normal (fungible) asset.
    pub fn new_normal(name: String, amount: u64) -> Self {
        Seedling {
            asset_version: AssetVersion::V0,
            asset_type: AssetType::Normal,
            asset_name: name,
            meta: None,
            amount,
            enable_emission: false,
            script_key: None,
            group_anchor: None,
        }
    }

    /// Creates a new seedling for a collectible (NFT).
    pub fn new_collectible(name: String) -> Self {
        Seedling {
            asset_version: AssetVersion::V0,
            asset_type: AssetType::Collectible,
            asset_name: name,
            meta: None,
            amount: 1,
            enable_emission: false,
            script_key: None,
            group_anchor: None,
        }
    }

    /// Validates the seedling's fields.
    pub fn validate(&self) -> Result<(), MintError> {
        if self.asset_name.is_empty() {
            return Err(MintError::InvalidSeedling(
                "asset name cannot be empty".into(),
            ));
        }
        if self.asset_name.len() > MAX_ASSET_NAME_LENGTH {
            return Err(MintError::InvalidSeedling(format!(
                "asset name too long: {} > {}",
                self.asset_name.len(),
                MAX_ASSET_NAME_LENGTH
            )));
        }
        if self.amount == 0 {
            return Err(MintError::InvalidSeedling(
                "amount must be > 0".into(),
            ));
        }
        if self.asset_type == AssetType::Collectible && self.amount != 1 {
            return Err(MintError::InvalidSeedling(
                "collectible amount must be 1".into(),
            ));
        }
        if let Some(ref meta) = self.meta {
            meta.validate().map_err(|e| {
                MintError::InvalidSeedling(format!(
                    "invalid metadata: {}",
                    e
                ))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_normal_seedling() {
        let s = Seedling::new_normal("my-token".into(), 1_000_000);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_valid_collectible_seedling() {
        let s = Seedling::new_collectible("my-nft".into());
        assert!(s.validate().is_ok());
        assert_eq!(s.amount, 1);
    }

    #[test]
    fn test_empty_name_rejected() {
        let s = Seedling::new_normal("".into(), 100);
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_zero_amount_rejected() {
        let s = Seedling::new_normal("token".into(), 0);
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_collectible_wrong_amount_rejected() {
        let mut s = Seedling::new_collectible("nft".into());
        s.amount = 2;
        assert!(s.validate().is_err());
    }

    #[test]
    fn test_long_name_rejected() {
        let name = "a".repeat(MAX_ASSET_NAME_LENGTH + 1);
        let s = Seedling::new_normal(name, 100);
        assert!(s.validate().is_err());
    }
}
