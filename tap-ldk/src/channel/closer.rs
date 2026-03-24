// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset channel closer — handles asset distribution during cooperative
//! and force close.

use tap_primitives::asset::{
    Asset, AssetVersion, Genesis, ScriptKey, ScriptVersion,
};
use tap_primitives::commitment::{
    AssetCommitment, TapCommitment, TapCommitmentVersion,
};

use super::blobs::{ChannelBlob, CommitmentBlob};
use super::traits::{
    AssetChannelCloser, AssetChannelError, CloseOutput, SweepDescriptor,
};
use crate::config::TapConfig;

/// Default implementation of [`AssetChannelCloser`].
pub struct TapAssetChannelCloser {
    config: TapConfig,
}

impl TapAssetChannelCloser {
    /// Creates a new closer with default configuration.
    pub fn new() -> Self {
        Self { config: TapConfig::default() }
    }

    /// Creates a new closer with the given configuration.
    pub fn with_config(config: TapConfig) -> Self {
        Self { config }
    }
}

impl Default for TapAssetChannelCloser {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetChannelCloser for TapAssetChannelCloser {
    fn cooperative_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
    ) -> Result<Vec<CloseOutput>, AssetChannelError> {
        let mut outputs = Vec::new();

        // Local party's asset output.
        if let Some(output) = build_close_output(
            channel_blob,
            &commitment_blob.local_assets,
            self.config.dust_limit_sat,
        )? {
            outputs.push(output);
        }

        // Remote party's asset output.
        if let Some(output) = build_close_output(
            channel_blob,
            &commitment_blob.remote_assets,
            self.config.dust_limit_sat,
        )? {
            outputs.push(output);
        }

        Ok(outputs)
    }

    fn force_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        is_local_commitment: bool,
    ) -> Result<Vec<SweepDescriptor>, AssetChannelError> {
        let mut descriptors = Vec::new();
        let mut output_idx: u32 = 0;

        // For force close, we need to sweep asset outputs from the
        // commitment transaction. The local output may have a CSV delay.
        let balances = if is_local_commitment {
            &commitment_blob.local_assets
        } else {
            &commitment_blob.remote_assets
        };

        let total_amount: u64 = balances.iter().map(|b| b.amount).sum();
        if total_amount > 0 {
            descriptors.push(SweepDescriptor {
                outpoint: tap_primitives::asset::OutPoint::default(),
                asset_data: encode_balance_data(channel_blob, balances),
                csv_delay: if is_local_commitment {
                    Some(self.config.csv_delay_blocks)
                } else {
                    None
                },
            });
            output_idx += 1;
        }

        // Outgoing HTLC outputs need sweeping (timeout path).
        for htlc in &commitment_blob.outgoing_htlc_assets {
            let htlc_amount: u64 =
                htlc.balances.iter().map(|b| b.amount).sum();
            if htlc_amount > 0 {
                descriptors.push(SweepDescriptor {
                    outpoint: tap_primitives::asset::OutPoint::default(),
                    asset_data: encode_balance_data(
                        channel_blob,
                        &htlc.balances,
                    ),
                    csv_delay: None,
                });
                output_idx += 1;
            }
        }

        // Incoming HTLC outputs need sweeping (success path if we have preimage).
        for htlc in &commitment_blob.incoming_htlc_assets {
            let htlc_amount: u64 =
                htlc.balances.iter().map(|b| b.amount).sum();
            if htlc_amount > 0 {
                descriptors.push(SweepDescriptor {
                    outpoint: tap_primitives::asset::OutPoint::default(),
                    asset_data: encode_balance_data(
                        channel_blob,
                        &htlc.balances,
                    ),
                    csv_delay: None,
                });
                output_idx += 1;
            }
        }

        let _ = output_idx; // Will be used when real outpoints are available.
        Ok(descriptors)
    }
}

/// Builds a cooperative close output for the given asset balances.
fn build_close_output(
    channel_blob: &ChannelBlob,
    balances: &[super::blobs::AssetBalance],
    dust_limit_sat: u64,
) -> Result<Option<CloseOutput>, AssetChannelError> {
    let non_zero: Vec<_> = balances.iter().filter(|b| b.amount > 0).collect();
    if non_zero.is_empty() {
        return Ok(None);
    }

    // Build assets from balances.
    let mut assets = Vec::new();
    for balance in &non_zero {
        let script_key = channel_blob
            .funded_assets
            .iter()
            .find(|f| f.asset_id == balance.asset_id)
            .map(|f| f.script_key)
            .ok_or_else(|| AssetChannelError(format!(
                "no funded asset for {:?}",
                balance.asset_id
            )))?;

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

    let asset_refs: Vec<&Asset> = assets.iter().collect();
    let ac = AssetCommitment::new(&asset_refs)
        .map_err(|e| AssetChannelError(format!("commitment: {}", e)))?;
    let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac])
        .map_err(|e| AssetChannelError(format!("tap: {}", e)))?;

    let tap_leaf = tc.tap_leaf();

    Ok(Some(CloseOutput {
        value_sat: dust_limit_sat,
        script: tap_leaf.clone(),
        asset_data: tap_leaf,
    }))
}

/// Encodes balance data for a sweep descriptor.
fn encode_balance_data(
    _channel_blob: &ChannelBlob,
    balances: &[super::blobs::AssetBalance],
) -> Vec<u8> {
    let mut data = Vec::new();
    for balance in balances {
        data.extend_from_slice(balance.asset_id.as_bytes());
        data.extend_from_slice(&balance.amount.to_be_bytes());
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::{AssetBalance, FundedAsset};
    use tap_primitives::asset::{AssetId, SerializedKey};

    fn test_state() -> (ChannelBlob, CommitmentBlob) {
        let channel = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };
        let commitment = CommitmentBlob {
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
        };
        (channel, commitment)
    }

    #[test]
    fn test_cooperative_close() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let outputs = closer
            .cooperative_close_outputs(&channel, &commitment)
            .unwrap();

        // Two outputs: one for local (600), one for remote (400).
        assert_eq!(outputs.len(), 2);
        assert!(outputs[0].value_sat > 0);
    }

    #[test]
    fn test_cooperative_close_one_zero() {
        let closer = TapAssetChannelCloser::new();
        let (channel, mut commitment) = test_state();
        commitment.remote_assets[0].amount = 0;

        let outputs = closer
            .cooperative_close_outputs(&channel, &commitment)
            .unwrap();

        // Only one output (remote is zero).
        assert_eq!(outputs.len(), 1);
    }

    #[test]
    fn test_force_close_local() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, true)
            .unwrap();

        assert_eq!(descriptors.len(), 1);
        // Local commitment → has CSV delay.
        assert_eq!(descriptors[0].csv_delay, Some(144));
    }

    #[test]
    fn test_force_close_remote() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, false)
            .unwrap();

        assert_eq!(descriptors.len(), 1);
        // Remote commitment → no CSV delay.
        assert!(descriptors[0].csv_delay.is_none());
    }

    #[test]
    fn test_force_close_with_htlcs() {
        use crate::channel::blobs::HtlcAssetBalance;

        let closer = TapAssetChannelCloser::new();
        let (channel, mut commitment) = test_state();

        // Add outgoing and incoming HTLCs.
        commitment.outgoing_htlc_assets.push(HtlcAssetBalance {
            htlc_index: 0,
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 50,
            }],
        });
        commitment.incoming_htlc_assets.push(HtlcAssetBalance {
            htlc_index: 1,
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 30,
            }],
        });

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, true)
            .unwrap();

        // 1 local balance + 1 outgoing HTLC + 1 incoming HTLC = 3 descriptors.
        assert_eq!(descriptors.len(), 3);
        assert_eq!(descriptors[0].csv_delay, Some(144));
        assert!(descriptors[1].csv_delay.is_none());
        assert!(descriptors[2].csv_delay.is_none());
    }
}
