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
//! **Current status:** These traits define the TARGET API. Wiring them
//! into LDK fully requires fork changes; see
//! `tap-ldk/docs/ldk-fork-requirements.md`.

use tap_primitives::asset::SerializedKey;

use super::blobs::{ChannelBlob, CommitmentBlob, HtlcBlob};
use super::leaf_signer::AssetSig;

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
/// Equivalent of LND's `AuxLeafSigner` / `AuxSigner`.
pub trait AssetLeafSigner {
    /// Signs the asset portions of second-level HTLC transactions
    /// anchored to the given commitment transaction.
    ///
    /// Returns, per HTLC, the list of per-asset signatures. Pack these
    /// with [`super::leaf_signer::pack_aux_signatures`] to obtain the
    /// Go-compatible `CommitSig` blob for `CommitmentSigned`.
    fn sign_htlc_second_level(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        htlc_blobs: &[HtlcBlob],
        commitment_txid: [u8; 32],
    ) -> Result<Vec<Vec<AssetSig>>, AssetChannelError>;
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

    /// Produces the HTLC custom records (asset balances, RFQ ID) and
    /// the adjusted BTC amount for an outgoing asset payment.
    fn shape_outgoing_htlc(
        &self,
        scid: u64,
        original_amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(u64, Vec<(u64, Vec<u8>)>), AssetChannelError>;
}

/// Parameters for computing cooperative close outputs, carrying the
/// data Go's `AuxCloseDesc` provides (shutdown keys and negotiated
/// balances/fees).
#[derive(Clone, Debug)]
pub struct CoopCloseParams {
    /// The local party's shutdown asset internal key (from the local
    /// `AuxShutdownMsg`).
    pub local_internal_key: SerializedKey,
    /// The remote party's shutdown asset internal key.
    pub remote_internal_key: SerializedKey,
    /// The local party's settled BTC balance in satoshis (before fee
    /// deduction).
    pub local_btc_balance_sat: u64,
    /// The remote party's settled BTC balance in satoshis.
    pub remote_btc_balance_sat: u64,
    /// The closing fee in satoshis, paid by the funder.
    pub close_fee_sat: u64,
    /// Whether the local party funded the channel (and thus pays the
    /// close fee).
    pub local_is_funder: bool,
}

/// Handles asset distribution during channel closure.
///
/// Equivalent of LND's `AuxChanCloser` + `AuxSweeper`.
pub trait AssetChannelCloser {
    /// For cooperative close: returns the asset-carrying outputs for
    /// the closing transaction, at real P2TR scripts committing to the
    /// party's assets, with values from the negotiated balances.
    fn cooperative_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        params: &CoopCloseParams,
    ) -> Result<Vec<CloseOutput>, AssetChannelError>;

    /// For force close: identifies asset outputs that need sweeping
    /// from the given commitment transaction.
    fn force_close_outputs(
        &self,
        channel_blob: &ChannelBlob,
        commitment_blob: &CommitmentBlob,
        is_local_commitment: bool,
        commitment_txid: [u8; 32],
    ) -> Result<Vec<SweepDescriptor>, AssetChannelError>;
}

/// An output to add to a cooperative close transaction.
#[derive(Clone, Debug)]
pub struct CloseOutput {
    /// Output value in satoshis.
    pub value_sat: u64,
    /// Output script (P2TR committing to the asset commitment).
    pub script: Vec<u8>,
    /// Associated asset data for proof generation.
    pub asset_data: Vec<u8>,
}

/// Describes an asset output that needs to be swept after force close.
#[derive(Clone, Debug)]
pub struct SweepDescriptor {
    /// The outpoint to sweep (commitment txid + allocated output
    /// index).
    pub outpoint: tap_primitives::asset::OutPoint,
    /// The asset data needed for sweeping.
    pub asset_data: Vec<u8>,
    /// Whether this output has a CSV delay.
    pub csv_delay: Option<u16>,
}
