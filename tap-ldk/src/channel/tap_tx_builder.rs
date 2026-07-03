// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TapTxBuilder — wraps LDK's SpecTxBuilder to inject TAP auxiliary data
//! into commitment transactions.
//!
//! This implements LDK's `TxBuilder` trait by delegating all standard
//! commitment logic to `SpecTxBuilder` and then adding TAP-specific
//! auxiliary data via `get_aux_commitment_data()`.

use lightning::ln::chan_utils::{
    CommitmentTransaction, ChannelTransactionParameters, HTLCOutputInCommitment,
};
use lightning::sign::tx_builder::{
    ChannelConstraints, ChannelStats, CommitmentStats, HTLCAmountDirection,
    SpecTxBuilder, TxBuilder,
};
use lightning::types::features::ChannelTypeFeatures;
use lightning::util::logger::Logger;

use lightning::bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use super::blobs::{ChannelBlob, CommitmentBlob};
use super::leaf_creator::TapAssetLeafCreator;
use super::traits::{AssetLeafCreator, ChannelParty};

/// A TxBuilder that augments LDK's standard commitment construction
/// with TAP auxiliary commitment data.
///
/// When `get_aux_commitment_data()` is called by LDK, it uses the
/// [`TapAssetLeafCreator`] to produce auxiliary tapscript leaves based
/// on the current asset channel state.
pub struct TapTxBuilder {
    /// The standard spec-compliant builder we delegate to.
    inner: SpecTxBuilder,
    /// The leaf creator that produces TAP commitment leaves.
    leaf_creator: TapAssetLeafCreator,
    /// Current channel blob (set when the asset channel is funded).
    channel_blob: Option<ChannelBlob>,
    /// Current commitment blob (updated on each state transition).
    commitment_blob: Option<CommitmentBlob>,
}

impl TapTxBuilder {
    /// Creates a new TapTxBuilder.
    pub fn new() -> Self {
        TapTxBuilder {
            inner: SpecTxBuilder {},
            leaf_creator: TapAssetLeafCreator,
            channel_blob: None,
            commitment_blob: None,
        }
    }

    /// Sets the channel-level asset data.
    pub fn set_channel_blob(&mut self, blob: ChannelBlob) {
        self.channel_blob = Some(blob);
    }

    /// Updates the per-commitment asset data.
    pub fn set_commitment_blob(&mut self, blob: CommitmentBlob) {
        self.commitment_blob = Some(blob);
    }
}

impl Default for TapTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TxBuilder for TapTxBuilder {
    fn get_channel_stats(
        &self,
        local: bool,
        is_outbound_from_holder: bool,
        channel_value_satoshis: u64,
        value_to_holder_msat: u64,
        pending_htlcs: &[HTLCAmountDirection],
        addl_nondust_htlc_count: usize,
        feerate_per_kw: u32,
        dust_exposure_limiting_feerate: Option<u32>,
        max_dust_htlc_exposure_msat: u64,
        channel_constraints: ChannelConstraints,
        channel_type: &ChannelTypeFeatures,
    ) -> Result<ChannelStats, ()> {
        self.inner.get_channel_stats(
            local,
            is_outbound_from_holder,
            channel_value_satoshis,
            value_to_holder_msat,
            pending_htlcs,
            addl_nondust_htlc_count,
            feerate_per_kw,
            dust_exposure_limiting_feerate,
            max_dust_htlc_exposure_msat,
            channel_constraints,
            channel_type,
        )
    }

    fn build_commitment_transaction<L: Logger>(
        &self,
        local: bool,
        commitment_number: u64,
        per_commitment_point: &PublicKey,
        channel_parameters: &ChannelTransactionParameters,
        secp_ctx: &Secp256k1<secp256k1::All>,
        value_to_self_msat: u64,
        htlcs_in_tx: Vec<HTLCOutputInCommitment>,
        feerate_per_kw: u32,
        broadcaster_dust_limit_satoshis: u64,
        logger: &L,
    ) -> (CommitmentTransaction, CommitmentStats) {
        self.inner.build_commitment_transaction(
            local,
            commitment_number,
            per_commitment_point,
            channel_parameters,
            secp_ctx,
            value_to_self_msat,
            htlcs_in_tx,
            feerate_per_kw,
            broadcaster_dust_limit_satoshis,
            logger,
        )
    }

    fn get_aux_commitment_data(
        &self,
        local: bool,
        _commitment_number: u64,
        _aux_data: Option<&[u8]>,
    ) -> Vec<(u32, Vec<u8>)> {
        // If we don't have asset channel state, return empty.
        let (channel_blob, commitment_blob) =
            match (&self.channel_blob, &self.commitment_blob) {
                (Some(cb), Some(cmb)) => (cb, cmb),
                _ => return Vec::new(),
            };

        let whose_commit = if local {
            ChannelParty::Local
        } else {
            ChannelParty::Remote
        };

        match self
            .leaf_creator
            .create_aux_leaves(channel_blob, commitment_blob, whose_commit)
        {
            Ok(leaves) => leaves,
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::{AssetOutput, FundedAsset};
    use tap_primitives::asset::{AssetId, SerializedKey};

    fn output(amount: u64) -> AssetOutput {
        AssetOutput {
            asset_id: AssetId([0xAA; 32]),
            amount,
            script_key: SerializedKey([0x02; 33]),
            proof: None,
        }
    }

    #[test]
    fn test_tap_tx_builder_no_asset_state() {
        let builder = TapTxBuilder::new();
        // Without channel/commitment blobs, should return empty.
        let aux = builder.get_aux_commitment_data(true, 0, None);
        assert!(aux.is_empty());
    }

    #[test]
    fn test_tap_tx_builder_with_asset_state() {
        let mut builder = TapTxBuilder::new();
        builder.set_channel_blob(ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: SerializedKey([0x02; 33]),
                proof: None,
            }],
            decimal_display: 0,
            group_key: None,
        });
        builder.set_commitment_blob(CommitmentBlob {
            local_assets: vec![output(600)],
            remote_assets: vec![output(400)],
            ..CommitmentBlob::default()
        });

        let aux = builder.get_aux_commitment_data(true, 0, None);
        assert_eq!(aux.len(), 2);
        // Each leaf should be 73 bytes.
        assert_eq!(aux[0].1.len(), 73);
        assert_eq!(aux[1].1.len(), 73);
    }
}
