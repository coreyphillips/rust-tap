// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Background work: confirmation watching, periodic universe sync, and
//! RFQ quote pruning.
//!
//! [`TapNode::start`](crate::TapNode::start) spawns a worker thread
//! that calls [`tick`] every `config.tick_interval_secs`. Embedders
//! that drive their own event loop can skip `start()` and call
//! [`TapNode::tick`](crate::TapNode::tick) directly.

use std::time::Instant;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{
    AssetSigner, ChainBridge, KeyRing, WalletAnchor,
};
use tap_onchain::mint::MintingBatch;
use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::proof;

use crate::error::TapNodeError;
use crate::node::TapNode;

/// An anchor transaction the node is waiting on for confirmation.
///
/// Registered by the mint and send flows at broadcast time; resolved by
/// [`TapNode::tick`](crate::TapNode::tick) once the chain backend
/// reports at least one confirmation.
#[derive(Clone)]
pub(crate) struct PendingAnchor {
    /// The anchor transaction id in internal (little-endian) byte
    /// order, matching [`tap_onchain::chain::ChainBridge::get_tx_confirmation`].
    pub txid: [u8; 32],
    /// What kind of operation the anchor finishes.
    pub kind: AnchorKind,
}

/// The operation waiting on a [`PendingAnchor`].
#[derive(Clone)]
pub(crate) enum AnchorKind {
    /// A mint (genesis) transaction: on confirmation the batch is
    /// finalized, genesis proofs are generated and stored, and the
    /// proofs are registered with the configured universes.
    Mint(MintAnchor),
    /// An asset transfer: on confirmation the transfer proofs are
    /// finished with real chain data, stored, and delivered to the
    /// recipient courier.
    Transfer(TransferAnchor),
}

/// Context needed to finish a mint after confirmation.
#[derive(Clone)]
pub(crate) struct MintAnchor {
    /// The broadcast batch, including its sprouted assets, seedling
    /// metadata, and tree-retaining root commitment.
    pub batch: MintingBatch,
    /// The taproot internal key of the mint (TAP commitment) output.
    pub internal_key: SerializedKey,
}

/// Context needed to finish a transfer after confirmation.
#[derive(Clone)]
pub(crate) struct TransferAnchor {
    /// The transferred asset.
    pub asset_id: AssetId,
    /// Amount sent to the recipient.
    pub amount: u64,
    /// The recipient's (tweaked) script key.
    pub recipient_script_key: SerializedKey,
    /// The recipient output's anchor outpoint (internal byte order).
    pub recipient_outpoint: OutPoint,
    /// The transition proof suffix for the recipient output, with
    /// placeholder chain data until confirmation.
    pub recipient_suffix: proof::Proof,
    /// The change output's (tweaked) script key, when a change output
    /// exists.
    pub change_script_key: Option<SerializedKey>,
    /// The change output's anchor outpoint, when a change output
    /// exists.
    pub change_outpoint: Option<OutPoint>,
    /// The transition proof suffix for the change output, when a
    /// change output exists.
    pub change_suffix: Option<proof::Proof>,
    /// The proof file of the (first) spent input, used as the base the
    /// new suffixes are appended to. `None` when the input has no
    /// stored proof history.
    pub base_file: Option<proof::File>,
    /// The recipient's proof courier URL, from the destination
    /// address. Delivery is skipped when absent.
    pub courier_url: Option<String>,
    /// Passive assets re-anchored into the change output: their finished
    /// proof suffixes (placeholder chain data) and storage locators.
    /// Stored on confirmation like the change proof.
    pub passive: Vec<PassiveAnchor>,
}

/// A passive asset re-anchored into the change output of a transfer,
/// awaiting the anchor confirmation to finish and store its proof.
#[derive(Clone)]
pub(crate) struct PassiveAnchor {
    /// The change output's anchor outpoint the passive was re-anchored
    /// into (internal byte order).
    pub outpoint: OutPoint,
    /// The passive asset's (unchanged) script key.
    pub script_key: SerializedKey,
    /// The transition proof suffix, with placeholder chain data until
    /// confirmation.
    pub suffix: proof::Proof,
    /// The passive asset's prior proof file, used as the base the new
    /// suffix is appended to. `None` when it had no stored history.
    pub base_file: Option<proof::File>,
}

/// The outcome of one [`TapNode::tick`](crate::TapNode::tick).
#[derive(Clone, Debug, Default)]
pub struct TickSummary {
    /// Anchors that confirmed during this tick and were fully
    /// processed (proofs generated/delivered, stores updated, events
    /// emitted).
    pub confirmed_anchors: usize,
    /// Anchors still waiting for confirmation after this tick.
    pub pending_anchors: usize,
    /// Whether a periodic universe sync ran during this tick.
    pub universe_synced: bool,
    /// New universe leaves discovered by the periodic sync (0 when no
    /// sync ran).
    pub new_universe_leaves: usize,
    /// Non-fatal errors encountered during the tick (failed
    /// confirmation lookups, proof/delivery failures, sync errors).
    /// The affected anchors stay pending and are retried on the next
    /// tick.
    pub errors: Vec<String>,
}

/// Runs one iteration of the node's background work. See
/// [`TapNode::tick`](crate::TapNode::tick).
pub(crate) fn tick<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<TickSummary, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let mut summary = TickSummary::default();

    // -- (a) Poll confirmations for pending anchors. --
    let pending: Vec<PendingAnchor> = {
        let mut anchors =
            node.pending_anchors.lock().expect("pending anchors lock");
        anchors.drain(..).collect()
    };

    let mut still_pending = Vec::new();
    for anchor in pending {
        match node.chain.get_tx_confirmation(&anchor.txid) {
            Ok(Some(conf)) => {
                let result = match &anchor.kind {
                    AnchorKind::Mint(mint) => {
                        crate::mint::finish_mint_confirmation(
                            node,
                            mint.clone(),
                            anchor.txid,
                            &conf,
                        )
                    }
                    AnchorKind::Transfer(transfer) => {
                        crate::send::finish_transfer_confirmation(
                            node,
                            transfer.clone(),
                            anchor.txid,
                            &conf,
                        )
                    }
                };
                match result {
                    Ok(()) => summary.confirmed_anchors += 1,
                    Err(e) => {
                        // Keep the anchor and retry next tick; the
                        // finish steps are idempotent.
                        summary.errors.push(format!(
                            "finishing anchor failed: {}",
                            e
                        ));
                        still_pending.push(anchor);
                    }
                }
            }
            Ok(None) => still_pending.push(anchor),
            Err(e) => {
                summary
                    .errors
                    .push(format!("confirmation lookup failed: {}", e));
                still_pending.push(anchor);
            }
        }
    }

    {
        let mut anchors =
            node.pending_anchors.lock().expect("pending anchors lock");
        // New anchors may have been registered while we were polling;
        // prepend the retained ones.
        still_pending.append(&mut anchors);
        *anchors = still_pending;
        summary.pending_anchors = anchors.len();
    }

    // -- (b) Periodic universe sync. --
    let sync_interval = node.config.universe_sync_interval_secs;
    if sync_interval > 0 && !node.config.universe_servers.is_empty() {
        let due = {
            let last =
                node.last_universe_sync.lock().expect("last sync lock");
            match *last {
                None => true,
                Some(at) => at.elapsed().as_secs() >= sync_interval,
            }
        };
        if due {
            match crate::sync::sync_universe(node) {
                Ok(diffs) => {
                    summary.universe_synced = true;
                    summary.new_universe_leaves = diffs
                        .iter()
                        .map(|d| d.new_leaves.len())
                        .sum();
                }
                Err(e) => summary
                    .errors
                    .push(format!("universe sync failed: {}", e)),
            }
            *node.last_universe_sync.lock().expect("last sync lock") =
                Some(Instant::now());
        }
    }

    // -- (c) Prune expired RFQ quotes. --
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    node.tap_channel_mgr.prune_expired_quotes(now);

    Ok(summary)
}
