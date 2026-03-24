// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Integration traits for asset channel lifecycle hooks.
//!
//! These traits define the interfaces that the TAP layer needs from the
//! Lightning layer (LDK). They mirror LND's auxiliary hook architecture
//! but adapted for LDK's trait-based design.
//!
//! **Current status:** These traits define the TARGET API. Implementing
//! them fully requires upstream LDK changes (Milestone 9 PRs).


use super::blobs::{ChannelBlob, CommitmentBlob, HtlcBlob};

/// Identifies which party's commitment we're building.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelParty {
    Local,
    Remote,
}

/// Error from asset channel operations.
#[derive(Debug, Clone)]
pub struct AssetChannelError(pub String);

impl std::fmt::Display for AssetChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "asset channel error: {}", self.0)
    }
}

impl std::error::Error for AssetChannelError {}

/// Manages asset-specific state for a channel funding flow.
///
/// Equivalent of LND's `AuxFundingController`.
pub trait AssetFundingController {
    /// Validates and processes an incoming asset funding proposal.
    fn handle_funding_msg(
        &self,
        pending_channel_id: &[u8; 32],
        msg: &crate::wire::TapMessage,
    ) -> Result<Option<crate::wire::TapMessage>, AssetChannelError>;

    /// Produces the channel blob for a newly funded asset channel.
    fn finalize_funding(
        &self,
        pending_channel_id: &[u8; 32],
    ) -> Result<ChannelBlob, AssetChannelError>;
}

/// Creates auxiliary tapscript leaves for commitment transactions.
///
/// Equivalent of LND's `AuxLeafCreator`.
pub trait AssetLeafCreator {
    /// Given the current channel and commitment state, produces
    /// auxiliary tapscript leaves to embed in commitment outputs.
    ///
    /// Returns a map of output_index → leaf_script_bytes.
    fn create_aux_leaves(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        whose_commit: ChannelParty,
    ) -> Result<Vec<(u32, Vec<u8>)>, AssetChannelError>;
}

/// Signs asset-specific parts of commitment transactions.
///
/// Equivalent of LND's `AuxLeafSigner`.
pub trait AssetLeafSigner {
    /// Signs the asset portions of second-level HTLC transactions.
    ///
    /// Returns serialized signatures for each HTLC.
    fn sign_htlc_second_level(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        htlc_blobs: &[HtlcBlob],
    ) -> Result<Vec<Vec<u8>>, AssetChannelError>;
}

/// Controls routing decisions for asset channels.
///
/// Equivalent of LND's `AuxTrafficShaper`.
pub trait AssetTrafficShaper {
    /// Returns true if this SCID corresponds to an asset channel.
    fn is_asset_channel(&self, scid: u64) -> bool;

    /// Returns the available asset payment bandwidth in msat-equivalent.
    fn payment_bandwidth(
        &self,
        scid: u64,
        htlc_amt_msat: u64,
    ) -> Result<u64, AssetChannelError>;

    /// Produces the HTLC custom records (asset ID, amount, RFQ ID) and
    /// the adjusted BTC amount for an outgoing asset payment.
    fn shape_outgoing_htlc(
        &self,
        scid: u64,
        original_amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(u64, Vec<(u64, Vec<u8>)>), AssetChannelError>;
}

/// Handles asset distribution during channel closure.
///
/// Equivalent of LND's `AuxChanCloser` + `AuxSweeper`.
pub trait AssetChannelCloser {
    /// For cooperative close: returns additional outputs and scripts
    /// for the closing transaction.
    fn cooperative_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
    ) -> Result<Vec<CloseOutput>, AssetChannelError>;

    /// For force close: identifies asset outputs that need sweeping.
    fn force_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        is_local_commitment: bool,
    ) -> Result<Vec<SweepDescriptor>, AssetChannelError>;
}

/// An output to add to a cooperative close transaction.
#[derive(Clone, Debug)]
pub struct CloseOutput {
    /// Output value in satoshis.
    pub value_sat: u64,
    /// Output script (P2TR with asset commitment).
    pub script: Vec<u8>,
    /// Associated asset data for proof generation.
    pub asset_data: Vec<u8>,
}

/// Describes an asset output that needs to be swept after force close.
#[derive(Clone, Debug)]
pub struct SweepDescriptor {
    /// The outpoint to sweep.
    pub outpoint: tap_primitives::asset::OutPoint,
    /// The asset data needed for sweeping.
    pub asset_data: Vec<u8>,
    /// Whether this output has a CSV delay.
    pub csv_delay: Option<u16>,
}
