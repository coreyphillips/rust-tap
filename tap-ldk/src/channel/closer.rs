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
//!
//! Mirrors the computation in Go's `tapchannel/aux_closer.go`
//! (`AuxCloseOutputs` / `createCloseAlloc`): each party with a non-zero
//! asset balance gets a co-op close output whose script is a REAL P2TR
//! script, `taproot(shutdown_internal_key, tap_commitment_root)`, and
//! whose value comes from the negotiated BTC balances (minus the close
//! fee for the funder).
//!
//! NOTE: only the computation is implemented; execution (adding the
//! outputs to LDK's closing negotiation and sweeping) is blocked on the
//! rust-lightning fork; see `docs/ldk-fork-requirements.md`.

use tap_primitives::asset::{
    Asset, AssetVersion, Genesis, ScriptKey, ScriptVersion, SerializedKey,
};
use tap_primitives::commitment::{
    AssetCommitment, TapCommitment, TapCommitmentVersion,
};

use super::allocation::{Allocation, AllocationType};
use super::blobs::{AssetOutput, ChannelBlob, CommitmentBlob};
use super::traits::{
    AssetChannelCloser, AssetChannelError, CloseOutput, CoopCloseParams,
    SweepDescriptor,
};
use crate::config::TapConfig;

/// Default implementation of [`AssetChannelCloser`].
pub struct TapAssetChannelCloser {
    config: TapConfig,
}

impl TapAssetChannelCloser {
    /// Creates a new closer with default configuration.
    pub fn new() -> Self {
        Self {
            config: TapConfig::default(),
        }
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

/// Builds the TAP commitment for a set of asset outputs, using the
/// channel's funded script keys as a fallback when an output has no
/// proof.
fn build_output_commitment(
    channel_blob: &ChannelBlob,
    outputs: &[AssetOutput],
) -> Result<TapCommitment, AssetChannelError> {
    let mut assets = Vec::new();
    for output in outputs.iter().filter(|o| o.amount > 0) {
        // Prefer the real asset state from the output's proof; fall
        // back to a synthetic asset when only balances are known.
        if let Some(ref proof) = output.proof {
            let mut asset = proof.asset.clone();
            asset.amount = output.amount;
            assets.push(asset);
            continue;
        }

        let script_key = channel_blob
            .funded_assets
            .iter()
            .find(|f| f.asset_id == output.asset_id)
            .map(|f| f.script_key)
            .unwrap_or(output.script_key);
        let genesis = channel_blob
            .funded_assets
            .iter()
            .find(|f| f.asset_id == output.asset_id)
            .and_then(|f| f.proof.as_ref())
            .map(|p| p.asset.genesis.clone())
            .unwrap_or(Genesis {
                first_prev_out: tap_primitives::asset::OutPoint::default(),
                tag: String::new(),
                meta_hash: [0u8; 32],
                output_index: 0,
                asset_type: tap_primitives::asset::AssetType::Normal,
            });

        assets.push(Asset {
            version: AssetVersion::V0,
            genesis,
            amount: output.amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(script_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        });
    }

    let asset_refs: Vec<&Asset> = assets.iter().collect();
    let ac = AssetCommitment::new(&asset_refs)
        .map_err(|e| AssetChannelError(format!("commitment: {}", e)))?;
    TapCommitment::new(TapCommitmentVersion::V2, &[&ac])
        .map_err(|e| AssetChannelError(format!("tap: {}", e)))
}

/// Builds a co-op close output for one party, mirroring Go's
/// `createCloseAlloc` + `Allocation.FinalPkScript`.
fn build_close_output(
    channel_blob: &ChannelBlob,
    outputs: &[AssetOutput],
    internal_key: SerializedKey,
    value_sat: u64,
    is_local: bool,
) -> Result<Option<CloseOutput>, AssetChannelError> {
    let asset_sum: u64 = outputs.iter().map(|o| o.amount).sum();
    if asset_sum == 0 {
        return Ok(None);
    }

    let commitment = build_output_commitment(channel_blob, outputs)?;
    let asset_data = commitment.tap_leaf();

    // Mirror Go: the close allocation carries the shutdown internal
    // key and the tap commitment; the final script is
    // taproot(internal_key, tapscript_root(commitment)).
    let allocation = Allocation {
        alloc_type: if is_local {
            AllocationType::CommitAllocationToLocal
        } else {
            AllocationType::CommitAllocationToRemote
        },
        amount: asset_sum,
        internal_key: Some(internal_key),
        script_key: outputs
            .first()
            .map(|o| ScriptKey::from_pub_key(o.script_key)),
        output_commitment: Some(commitment),
        ..Allocation::default()
    };

    let script = allocation
        .final_pk_script()
        .map_err(|e| AssetChannelError(format!("final pk script: {}", e)))?;

    Ok(Some(CloseOutput {
        value_sat,
        script,
        asset_data,
    }))
}

/// Returns the real output index for a swept output: the output index
/// recorded in the output's own transition proof when present,
/// otherwise the running fallback index.
fn sweep_output_index(output: &AssetOutput, fallback: u32) -> u32 {
    output
        .proof
        .as_ref()
        .map(|p| p.inclusion_proof.output_index)
        .unwrap_or(fallback)
}

impl AssetChannelCloser for TapAssetChannelCloser {
    fn cooperative_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        params: &CoopCloseParams,
    ) -> Result<Vec<CloseOutput>, AssetChannelError> {
        let mut outputs = Vec::new();

        // The funder pays the close fee (Go adjusts the initiator's
        // balance by commit fee minus close fee; the pre-fee balance
        // adjustment is done by the caller through params).
        let (local_fee, remote_fee) = if params.local_is_funder {
            (params.close_fee_sat, 0)
        } else {
            (0, params.close_fee_sat)
        };
        let local_value =
            params.local_btc_balance_sat.saturating_sub(local_fee);
        let remote_value =
            params.remote_btc_balance_sat.saturating_sub(remote_fee);

        if local_value < self.config.dust_limit_sat
            && commitment_blob.local_balance() > 0
        {
            return Err(AssetChannelError(format!(
                "local close output {} sat below dust limit",
                local_value
            )));
        }
        if remote_value < self.config.dust_limit_sat
            && commitment_blob.remote_balance() > 0
        {
            return Err(AssetChannelError(format!(
                "remote close output {} sat below dust limit",
                remote_value
            )));
        }

        // Local party's asset output.
        if let Some(output) = build_close_output(
            channel_blob,
            &commitment_blob.local_assets,
            params.local_internal_key,
            local_value,
            true,
        )? {
            outputs.push(output);
        }

        // Remote party's asset output.
        if let Some(output) = build_close_output(
            channel_blob,
            &commitment_blob.remote_assets,
            params.remote_internal_key,
            remote_value,
            false,
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
        commitment_txid: [u8; 32],
    ) -> Result<Vec<SweepDescriptor>, AssetChannelError> {
        let mut descriptors = Vec::new();
        let mut fallback_idx: u32 = 0;

        // For force close, we need to sweep asset outputs from the
        // commitment transaction. The local output may have a CSV delay.
        let balances = if is_local_commitment {
            &commitment_blob.local_assets
        } else {
            &commitment_blob.remote_assets
        };

        let total_amount: u64 = balances.iter().map(|b| b.amount).sum();
        if total_amount > 0 {
            let vout = balances
                .first()
                .map(|o| sweep_output_index(o, fallback_idx))
                .unwrap_or(fallback_idx);
            descriptors.push(SweepDescriptor {
                outpoint: tap_primitives::asset::OutPoint {
                    txid: commitment_txid,
                    vout,
                },
                asset_data: encode_balance_data(balances),
                csv_delay: if is_local_commitment {
                    Some(self.config.csv_delay_blocks)
                } else {
                    None
                },
            });
            fallback_idx += 1;
        }

        // Outgoing HTLC outputs need sweeping (timeout path).
        for (_, htlc_outputs) in &commitment_blob.outgoing_htlc_assets {
            let htlc_amount: u64 =
                htlc_outputs.iter().map(|b| b.amount).sum();
            if htlc_amount > 0 {
                let vout = htlc_outputs
                    .first()
                    .map(|o| sweep_output_index(o, fallback_idx))
                    .unwrap_or(fallback_idx);
                descriptors.push(SweepDescriptor {
                    outpoint: tap_primitives::asset::OutPoint {
                        txid: commitment_txid,
                        vout,
                    },
                    asset_data: encode_balance_data(htlc_outputs),
                    csv_delay: None,
                });
                fallback_idx += 1;
            }
        }

        // Incoming HTLC outputs need sweeping (success path if we have
        // the preimage).
        for (_, htlc_outputs) in &commitment_blob.incoming_htlc_assets {
            let htlc_amount: u64 =
                htlc_outputs.iter().map(|b| b.amount).sum();
            if htlc_amount > 0 {
                let vout = htlc_outputs
                    .first()
                    .map(|o| sweep_output_index(o, fallback_idx))
                    .unwrap_or(fallback_idx);
                descriptors.push(SweepDescriptor {
                    outpoint: tap_primitives::asset::OutPoint {
                        txid: commitment_txid,
                        vout,
                    },
                    asset_data: encode_balance_data(htlc_outputs),
                    csv_delay: None,
                });
                fallback_idx += 1;
            }
        }

        let _ = channel_blob;
        Ok(descriptors)
    }
}

/// Encodes balance data for a sweep descriptor.
fn encode_balance_data(outputs: &[AssetOutput]) -> Vec<u8> {
    let mut data = Vec::new();
    for output in outputs {
        data.extend_from_slice(output.asset_id.as_bytes());
        data.extend_from_slice(&output.amount.to_be_bytes());
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::tests::test_proof;
    use tap_primitives::asset::AssetId;

    fn asset_output(amount: u64) -> AssetOutput {
        let script_key = SerializedKey([0x02; 33]);
        AssetOutput {
            asset_id: AssetId([0xAA; 32]),
            amount,
            script_key,
            proof: Some(test_proof(0xAA, amount, script_key)),
        }
    }

    fn test_state() -> (ChannelBlob, CommitmentBlob) {
        let channel = ChannelBlob {
            funded_assets: vec![asset_output(1000)],
            decimal_display: 0,
            group_key: None,
        };
        let commitment = CommitmentBlob {
            local_assets: vec![asset_output(600)],
            remote_assets: vec![asset_output(400)],
            ..CommitmentBlob::default()
        };
        (channel, commitment)
    }

    fn pubkey_from_secret(byte: u8) -> SerializedKey {
        use lightning::bitcoin::secp256k1::{
            PublicKey, Secp256k1, SecretKey,
        };
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        SerializedKey(PublicKey::from_secret_key(&secp, &sk).serialize())
    }

    fn test_params() -> CoopCloseParams {
        CoopCloseParams {
            local_internal_key: pubkey_from_secret(0x11),
            remote_internal_key: pubkey_from_secret(0x22),
            local_btc_balance_sat: 50_000,
            remote_btc_balance_sat: 30_000,
            close_fee_sat: 1_000,
            local_is_funder: true,
        }
    }

    #[test]
    fn test_cooperative_close() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let outputs = closer
            .cooperative_close_outputs(&channel, &commitment, &test_params())
            .unwrap();

        // Two outputs: one for local (600), one for remote (400).
        assert_eq!(outputs.len(), 2);
        // Values come from the negotiated balances, not the dust limit;
        // the funder pays the close fee.
        assert_eq!(outputs[0].value_sat, 49_000);
        assert_eq!(outputs[1].value_sat, 30_000);
        // Real P2TR scripts: OP_1 OP_PUSHBYTES_32 <key>.
        for output in &outputs {
            assert_eq!(output.script.len(), 34);
            assert_eq!(output.script[0], 0x51);
            assert_eq!(output.script[1], 0x20);
        }
        // Different internal keys yield different scripts.
        assert_ne!(outputs[0].script, outputs[1].script);
    }

    #[test]
    fn test_cooperative_close_one_zero() {
        let closer = TapAssetChannelCloser::new();
        let (channel, mut commitment) = test_state();
        commitment.remote_assets[0].amount = 0;

        let outputs = closer
            .cooperative_close_outputs(&channel, &commitment, &test_params())
            .unwrap();

        // Only one output (remote is zero).
        assert_eq!(outputs.len(), 1);
    }

    #[test]
    fn test_cooperative_close_dust_rejected() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();
        let mut params = test_params();
        params.local_btc_balance_sat = 1_100; // 100 sat after fee.

        assert!(closer
            .cooperative_close_outputs(&channel, &commitment, &params)
            .is_err());
    }

    #[test]
    fn test_force_close_local() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, true, [0x07; 32])
            .unwrap();

        assert_eq!(descriptors.len(), 1);
        // Local commitment → has CSV delay.
        assert_eq!(descriptors[0].csv_delay, Some(144));
        // Real outpoint txid.
        assert_eq!(descriptors[0].outpoint.txid, [0x07; 32]);
    }

    #[test]
    fn test_force_close_remote() {
        let closer = TapAssetChannelCloser::new();
        let (channel, commitment) = test_state();

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, false, [0x08; 32])
            .unwrap();

        assert_eq!(descriptors.len(), 1);
        // Remote commitment → no CSV delay.
        assert!(descriptors[0].csv_delay.is_none());
    }

    #[test]
    fn test_force_close_with_htlcs() {
        let closer = TapAssetChannelCloser::new();
        let (channel, mut commitment) = test_state();

        commitment
            .outgoing_htlc_assets
            .insert(0, vec![asset_output(50)]);
        commitment
            .incoming_htlc_assets
            .insert(1, vec![asset_output(30)]);

        let descriptors = closer
            .force_close_outputs(&channel, &commitment, true, [0x09; 32])
            .unwrap();

        // 1 local balance + 1 outgoing HTLC + 1 incoming HTLC = 3.
        assert_eq!(descriptors.len(), 3);
        assert_eq!(descriptors[0].csv_delay, Some(144));
        assert!(descriptors[1].csv_delay.is_none());
        assert!(descriptors[2].csv_delay.is_none());
        for d in &descriptors {
            assert_eq!(d.outpoint.txid, [0x09; 32]);
        }
    }
}
