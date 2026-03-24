// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset leaf creator — produces TAP commitment leaves for commitment
//! transaction outputs.
//!
//! For each commitment state, the asset balances (local, remote, HTLCs)
//! are encoded into TAP commitments and embedded as auxiliary tapscript
//! leaves in the commitment outputs.

use tap_primitives::asset::{
    Asset, AssetVersion, Genesis, ScriptKey, ScriptVersion,
};
use tap_primitives::commitment::{
    AssetCommitment, TapCommitment, TapCommitmentVersion,
};

use super::blobs::{AssetBalance, ChannelBlob, CommitmentBlob};
use super::traits::{AssetChannelError, AssetLeafCreator, ChannelParty};

/// Default implementation of [`AssetLeafCreator`] for Taproot Assets.
///
/// Produces TAP commitment leaves based on the current channel and
/// commitment state. Each non-zero asset balance gets its own commitment
/// embedded as a tapscript leaf.
pub struct TapAssetLeafCreator;

impl AssetLeafCreator for TapAssetLeafCreator {
    fn create_aux_leaves(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        whose_commit: ChannelParty,
    ) -> Result<Vec<(u32, Vec<u8>)>, AssetChannelError> {
        let mut leaves = Vec::new();

        // Determine which balances go to which output indices.
        // In a standard commitment tx:
        //   Output 0: to-local (or to-remote, depending on whose commit)
        //   Output 1: to-remote (or to-local)
        //   Output 2+: HTLCs
        let (local_balances, remote_balances) = match whose_commit {
            ChannelParty::Local => {
                (&commitment_blob.local_assets, &commitment_blob.remote_assets)
            }
            ChannelParty::Remote => {
                (&commitment_blob.remote_assets, &commitment_blob.local_assets)
            }
        };

        // Create TAP commitment leaf for the local output (output 0).
        if let Some(leaf) = create_balance_leaf(
            channel_blob, local_balances, 0,
        )? {
            leaves.push(leaf);
        }

        // Create TAP commitment leaf for the remote output (output 1).
        if let Some(leaf) = create_balance_leaf(
            channel_blob, remote_balances, 1,
        )? {
            leaves.push(leaf);
        }

        // Create TAP commitment leaves for HTLC outputs.
        for htlc in &commitment_blob.outgoing_htlc_assets {
            if let Some(leaf) = create_balance_leaf(
                channel_blob,
                &htlc.balances,
                htlc.htlc_index as u32 + 2, // HTLC outputs start at index 2
            )? {
                leaves.push(leaf);
            }
        }

        for htlc in &commitment_blob.incoming_htlc_assets {
            if let Some(leaf) = create_balance_leaf(
                channel_blob,
                &htlc.balances,
                htlc.htlc_index as u32 + 2,
            )? {
                leaves.push(leaf);
            }
        }

        Ok(leaves)
    }
}

/// Creates a TAP commitment tapscript leaf for a set of asset balances
/// at a given output index.
///
/// Returns `None` if there are no non-zero balances.
fn create_balance_leaf(
    channel_blob: &ChannelBlob,
    balances: &[AssetBalance],
    output_index: u32,
) -> Result<Option<(u32, Vec<u8>)>, AssetChannelError> {
    // Filter out zero balances.
    let non_zero: Vec<_> =
        balances.iter().filter(|b| b.amount > 0).collect();
    if non_zero.is_empty() {
        return Ok(None);
    }

    // Build assets from the balances.
    let mut assets = Vec::new();
    for balance in &non_zero {
        // Find the funded asset info for this asset ID.
        let funded = channel_blob
            .funded_assets
            .iter()
            .find(|f| f.asset_id == balance.asset_id);

        let script_key = funded
            .map(|f| f.script_key)
            .ok_or_else(|| AssetChannelError(format!(
                "no funded asset found for asset_id {:?}",
                balance.asset_id
            )))?;

        // Create a minimal asset for the commitment.
        let asset = Asset {
            version: AssetVersion::V0,
            genesis: Genesis {
                first_prev_out: tap_primitives::asset::OutPoint::default(),
                tag: String::new(),
                meta_hash: [0u8; 32],
                output_index: 0,
                asset_type: tap_primitives::asset::AssetType::Normal,
            },
            amount: balance.amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(script_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };
        assets.push(asset);
    }

    // Build the TAP commitment.
    let asset_refs: Vec<&Asset> = assets.iter().collect();
    let asset_commitment = AssetCommitment::new(&asset_refs)
        .map_err(|e| AssetChannelError(format!("commitment: {}", e)))?;

    let tap_commitment =
        TapCommitment::new(TapCommitmentVersion::V2, &[&asset_commitment])
            .map_err(|e| {
                AssetChannelError(format!("tap commitment: {}", e))
            })?;

    // The leaf data is the 73-byte tapscript leaf.
    let leaf_data = tap_commitment.tap_leaf();

    Ok(Some((output_index, leaf_data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::{FundedAsset, HtlcAssetBalance};
    use tap_primitives::asset::{AssetId, SerializedKey};

    fn test_channel_blob() -> ChannelBlob {
        ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        }
    }

    fn test_commitment_blob() -> CommitmentBlob {
        CommitmentBlob {
            local_assets: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 600,
            }],
            remote_assets: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 400,
            }],
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        }
    }

    #[test]
    fn test_create_leaves_basic() {
        let creator = TapAssetLeafCreator;
        let channel = test_channel_blob();
        let commit = test_commitment_blob();

        let leaves = creator
            .create_aux_leaves(&channel, &commit, ChannelParty::Local)
            .unwrap();

        // Should have 2 leaves: one for local (600), one for remote (400).
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].0, 0); // local output
        assert_eq!(leaves[1].0, 1); // remote output
        // Each leaf should be 73 bytes.
        assert_eq!(leaves[0].1.len(), 73);
        assert_eq!(leaves[1].1.len(), 73);
    }

    #[test]
    fn test_create_leaves_with_htlcs() {
        let creator = TapAssetLeafCreator;
        let channel = test_channel_blob();
        let mut commit = test_commitment_blob();
        commit.outgoing_htlc_assets.push(HtlcAssetBalance {
            htlc_index: 0,
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 100,
            }],
        });

        let leaves = creator
            .create_aux_leaves(&channel, &commit, ChannelParty::Local)
            .unwrap();

        // 2 balance outputs + 1 HTLC output.
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[2].0, 2); // HTLC at output index 2
    }

    #[test]
    fn test_zero_balance_omitted() {
        let creator = TapAssetLeafCreator;
        let channel = test_channel_blob();
        let mut commit = test_commitment_blob();
        commit.remote_assets[0].amount = 0;

        let leaves = creator
            .create_aux_leaves(&channel, &commit, ChannelParty::Local)
            .unwrap();

        // Only local output (remote is zero).
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].0, 0);
    }

    #[test]
    fn test_party_swap() {
        let creator = TapAssetLeafCreator;
        let channel = test_channel_blob();
        let commit = test_commitment_blob();

        let local_leaves = creator
            .create_aux_leaves(&channel, &commit, ChannelParty::Local)
            .unwrap();
        let remote_leaves = creator
            .create_aux_leaves(&channel, &commit, ChannelParty::Remote)
            .unwrap();

        // Both should have 2 leaves, but the data at each index differs.
        assert_eq!(local_leaves.len(), 2);
        assert_eq!(remote_leaves.len(), 2);
        // Local's output 0 should differ from remote's output 0
        // (different amounts → different commitments).
        assert_ne!(local_leaves[0].1, remote_leaves[0].1);
    }
}
