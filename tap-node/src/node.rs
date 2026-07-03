// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The main `TapNode` struct and lifecycle management.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tap_ldk::ldk::{LdkChannelOps, TapChannelManager};
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::mint::Planter;
use tap_onchain::proof::courier::Courier;
use tap_onchain::proof::mailbox::{MailboxSigner, MailboxTransport};
use tap_persist::asset_store::AssetStore;
use tap_persist::batch_store::BatchStore;
use tap_persist::mailbox_store::MailboxStore;
use tap_persist::pending_anchor_store::PendingAnchorStore;
use tap_persist::proof_store::ProofStore;
use tap_persist::supply_store::{
    SupplyCommitStore, SupplyStagingStore, SupplyTreeStore,
};
use tap_primitives::address::TapAddress;
use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::proof;

use crate::config::TapNodeConfig;
use crate::error::TapNodeError;
use crate::event::{EventBus, TapEvent};
use crate::types::*;

/// A high-level Taproot Assets node.
///
/// Wraps the entire taproot-ldk workspace into a single managed instance.
/// The user provides chain, wallet, key, LDK, and pricing backends via
/// trait implementations. Everything else (persistence, proof delivery,
/// universe sync) is handled internally with sensible defaults.
///
/// # Usage
///
/// ```ignore
/// let node = TapNodeBuilder::new(config)
///     .set_chain_bridge(my_chain)
///     .set_wallet_anchor(my_wallet)
///     .set_key_ring(my_keys)
///     .set_ldk_ops(my_ldk)
///     .set_price_oracle(my_oracle)
///     .build()?;
///
/// node.start()?;
/// node.queue_mint(Seedling::new_normal("USD-Coin".into(), 1_000_000))?;
/// let result = node.finalize_mint()?;
/// ```
pub struct TapNode<C, W, K, L, P>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // User-provided backends.
    pub(crate) chain: Arc<C>,
    pub(crate) wallet: Arc<W>,
    pub(crate) keys: Arc<K>,

    // Configuration.
    pub(crate) config: TapNodeConfig,

    // Minting pipeline.
    pub(crate) planter: Mutex<Planter<ArcChain<C>, ArcWallet<W>, ArcKeys<K>>>,

    // Lightning integration.
    pub(crate) tap_channel_mgr: TapChannelManager<L, P>,

    // Persistence.
    pub(crate) asset_store: Mutex<Box<dyn AssetStore + Send>>,
    pub(crate) proof_store: Mutex<Box<dyn ProofStore + Send>>,
    pub(crate) batch_store: Mutex<Box<dyn BatchStore + Send>>,

    // Proof courier.
    pub(crate) courier: Box<dyn Courier + Send + Sync>,

    // Auth mailbox (V2 address receives). `None` means mailbox
    // polling is a no-op.
    pub(crate) mailbox_transport:
        Option<Box<dyn MailboxTransport + Send + Sync>>,
    pub(crate) mailbox_signer:
        Option<Box<dyn MailboxSigner + Send + Sync>>,
    pub(crate) mailbox_store: Mutex<Box<dyn MailboxStore + Send>>,

    // Universe sync.
    pub(crate) universe_backend:
        Mutex<Box<dyn tap_universe::traits::UniverseBackend + Send>>,
    pub(crate) federation_db:
        Mutex<Box<dyn tap_universe::traits::FederationDb + Send>>,

    // Universe supply commitments (authoring pipeline).
    pub(crate) supply_tree_store: Mutex<Box<dyn SupplyTreeStore + Send>>,
    pub(crate) supply_commit_store:
        Mutex<Box<dyn SupplyCommitStore + Send>>,
    pub(crate) supply_staging_store:
        Mutex<Box<dyn SupplyStagingStore + Send>>,
    // When the last periodic supply commit sweep ran.
    pub(crate) last_supply_commit: Mutex<Option<Instant>>,

    // Events.
    pub(crate) event_bus: EventBus,
    pub(crate) event_receiver: Mutex<Option<mpsc::Receiver<TapEvent>>>,

    // Anchor transactions awaiting confirmation (mints and transfers
    // broadcast by this node). Resolved by `tick()`. Mirrored in
    // `pending_anchor_store` so a restart between broadcast and
    // confirmation does not lose proof generation/delivery; reloaded
    // from the store when the node is built.
    pub(crate) pending_anchors: Mutex<Vec<crate::tasks::PendingAnchor>>,
    // Durable mirror of `pending_anchors`. Written at broadcast time,
    // rows removed once the anchor is resolved by `tick()`.
    pub(crate) pending_anchor_store:
        Mutex<Box<dyn PendingAnchorStore + Send>>,
    // When the last periodic universe sync ran.
    pub(crate) last_universe_sync: Mutex<Option<Instant>>,
    // The outcome of the most recent tick (worker-driven or direct),
    // for embedders that do not consume the event stream. See
    // `last_tick_summary`.
    pub(crate) last_tick: Mutex<Option<crate::tasks::TickSummary>>,

    // Coarse per-node lock serializing the wallet-mutating flows that
    // read the asset store and write back non-atomically:
    // `send_asset` reads unspent assets during coin selection (and
    // passive-asset collection) but only marks the inputs spent after
    // broadcast, so two concurrent sends could select and double-spend
    // the same inputs at the asset level. The receive import paths
    // (`poll_mailbox`, `import_proof`) take the same lock so their
    // cursor/store read-then-write sequences cannot interleave with a
    // send or with each other. A single wallet has no send parallelism
    // to gain, so one lock held from coin selection through
    // spent-marking and change persistence is the pragmatic fix.
    pub(crate) send_lock: Mutex<()>,

    // Lifecycle.
    pub(crate) running: AtomicBool,
    pub(crate) worker: Mutex<Option<JoinHandle<()>>>,
}

impl<C, W, K, L, P> TapNode<C, W, K, L, P>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    /// Starts the node's background worker thread.
    ///
    /// The worker calls [`tick`](Self::tick) once immediately and then
    /// every `config.tick_interval_secs` (default 30) until
    /// [`stop`](Self::stop) is called, driving confirmation watching
    /// for broadcast mints/transfers, periodic universe sync, and RFQ
    /// quote pruning.
    ///
    /// # Breaking change: `Arc` receiver
    ///
    /// `start` now takes `self: Arc<Self>` so the worker thread can
    /// hold a (weak) handle to the node. Wrap the built node in an
    /// [`Arc`] and start it via a clone:
    ///
    /// ```ignore
    /// let node = Arc::new(builder.build()?);
    /// node.clone().start()?;
    /// // ... use `node` as before ...
    /// node.stop()?;
    /// ```
    ///
    /// The thread only holds a [`std::sync::Weak`] reference, so
    /// dropping every user-held `Arc` also ends the worker.
    pub fn start(self: Arc<Self>) -> Result<(), TapNodeError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(TapNodeError::AlreadyRunning);
        }

        let weak = Arc::downgrade(&self);
        let interval_secs = self.config.tick_interval_secs.max(1);

        let spawned = std::thread::Builder::new()
            .name("tap-node-worker".into())
            .spawn(move || loop {
                // Tick while the node is alive and running.
                match weak.upgrade() {
                    Some(node) => {
                        if !node.running.load(Ordering::SeqCst) {
                            return;
                        }
                        // Tick outcomes (including non-fatal errors)
                        // are recorded in `last_tick` and surfaced via
                        // `TapEvent::TickCompleted` by `tick()` itself,
                        // so the Result is deliberately not propagated
                        // out of the worker thread.
                        let _ = node.tick();
                    }
                    None => return,
                }

                // Sleep in short slices so `stop()` joins promptly.
                let mut slept_ms = 0u64;
                while slept_ms < interval_secs * 1000 {
                    std::thread::sleep(Duration::from_millis(50));
                    slept_ms += 50;
                    match weak.upgrade() {
                        Some(node) => {
                            if !node.running.load(Ordering::SeqCst) {
                                return;
                            }
                        }
                        None => return,
                    }
                }
            });

        match spawned {
            Ok(handle) => {
                *self.worker.lock().expect("worker lock") = Some(handle);
                Ok(())
            }
            Err(e) => {
                self.running.store(false, Ordering::SeqCst);
                Err(TapNodeError::Config(format!(
                    "failed to spawn worker thread: {}",
                    e
                )))
            }
        }
    }

    /// Stops the node's background worker and joins its thread.
    pub fn stop(&self) -> Result<(), TapNodeError> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Err(TapNodeError::NotRunning);
        }
        let handle = self.worker.lock().expect("worker lock").take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        Ok(())
    }

    /// Runs one iteration of the node's background work:
    ///
    /// 1. Polls the chain backend for confirmations of pending anchor
    ///    transactions (broadcast mints and transfers). Once an anchor
    ///    has at least one confirmation, the corresponding proofs are
    ///    finished with real chain data, stored, registered/delivered,
    ///    and the matching events are emitted.
    /// 2. Runs a universe sync against the configured servers when
    ///    `config.universe_sync_interval_secs` has elapsed since the
    ///    last sync.
    /// 3. Prunes expired RFQ quotes.
    ///
    /// Called automatically by the worker thread spawned by
    /// [`start`](Self::start); public so embedders driving their own
    /// scheduler can call it directly without starting the thread.
    ///
    /// The resulting [`TickSummary`](crate::TickSummary) is recorded
    /// (see [`last_tick_summary`](Self::last_tick_summary)) and, when
    /// the tick did any work or hit errors, also emitted as
    /// [`TapEvent::TickCompleted`]. Quiet ticks emit no event.
    pub fn tick(&self) -> Result<crate::TickSummary, TapNodeError> {
        let result = crate::tasks::tick(self);
        let summary = match &result {
            Ok(summary) => summary.clone(),
            // `tasks::tick` reports per-anchor problems as non-fatal
            // summary errors; a hard error still surfaces the same way
            // so worker-driven ticks are never silently dropped.
            Err(e) => {
                let mut summary = crate::TickSummary::default();
                summary.errors.push(e.to_string());
                summary
            }
        };
        *self.last_tick.lock().expect("last tick lock") =
            Some(summary.clone());
        let noteworthy = summary.confirmed_anchors > 0
            || summary.universe_synced
            || !summary.errors.is_empty();
        if noteworthy {
            self.event_bus.emit(TapEvent::TickCompleted { summary });
        }
        result
    }

    /// Returns the outcome of the most recent [`tick`](Self::tick)
    /// (whether driven by the background worker or called directly),
    /// or `None` if no tick has run yet. Lets embedders that do not
    /// consume the event stream inspect confirmation progress and
    /// non-fatal tick errors
    /// ([`TickSummary::errors`](crate::TickSummary)).
    pub fn last_tick_summary(&self) -> Option<crate::TickSummary> {
        self.last_tick.lock().expect("last tick lock").clone()
    }

    /// Returns an event receiver for monitoring node activity.
    ///
    /// Can only be called once -- the receiver is moved out.
    pub fn event_receiver(
        &self,
    ) -> Result<mpsc::Receiver<TapEvent>, TapNodeError> {
        self.event_receiver
            .lock()
            .expect("event receiver lock")
            .take()
            .ok_or(TapNodeError::Config(
                "event receiver already taken".into(),
            ))
    }

    /// Returns true if the node is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // -- Minting (delegates to crate::mint) --

    /// Queues an asset seedling for the next mint batch.
    pub fn queue_mint(
        &self,
        seedling: tap_onchain::mint::Seedling,
    ) -> Result<(), TapNodeError> {
        crate::mint::queue_mint(self, seedling)
    }

    /// Finalizes the pending mint batch: freezes, builds genesis PSBT,
    /// funds, signs, and broadcasts.
    pub fn finalize_mint(&self) -> Result<MintResult, TapNodeError> {
        crate::mint::finalize_mint(self)
    }

    /// Cancels the pending mint batch.
    pub fn cancel_mint(&self) -> Result<(), TapNodeError> {
        crate::mint::cancel_mint(self)
    }

    // -- Asset Management (delegates to crate::receive) --

    /// Lists all owned assets.
    pub fn list_assets(
        &self,
    ) -> Result<Vec<tap_persist::asset_store::OwnedAsset>, TapNodeError> {
        Ok(self
            .asset_store
            .lock()
            .expect("asset store lock")
            .list_unspent())
    }

    /// Returns the spendable balance for an asset.
    pub fn get_balance(&self, asset_id: &AssetId) -> Result<u64, TapNodeError> {
        Ok(self
            .asset_store
            .lock()
            .expect("asset store lock")
            .balance(asset_id))
    }

    /// Generates a new address for receiving an asset.
    pub fn new_address(
        &self,
        asset_id: AssetId,
        amount: u64,
    ) -> Result<TapAddress, TapNodeError> {
        crate::receive::new_address(self, asset_id, amount)
    }

    /// Generates a new V2 (authmailbox) address for receiving an
    /// asset, identified either by asset ID or by group key (grouped
    /// assets; the asset ID is dropped in that case). The configured
    /// courier URL must use the `authmailbox+universerpc` scheme.
    pub fn new_address_v2(
        &self,
        params: crate::receive::V2AddressParams,
    ) -> Result<TapAddress, TapNodeError> {
        crate::receive::new_address_v2(self, params)
    }

    /// Polls the configured auth mailbox for incoming V2 address
    /// sends, importing any completed transfers into the asset store.
    /// Returns the imported assets. A no-op returning an empty vec if
    /// no mailbox transport is configured.
    pub fn poll_mailbox(
        &self,
    ) -> Result<Vec<crate::receive::ReceivedAsset>, TapNodeError> {
        crate::receive::poll_mailbox(self)
    }

    // -- Transfers (delegates to crate::send) --

    /// Sends an asset to a TAP address.
    pub fn send_asset(
        &self,
        asset_id: AssetId,
        amount: u64,
        recipient: &TapAddress,
    ) -> Result<TransferHandle, TapNodeError> {
        crate::send::send_asset(self, asset_id, amount, recipient)
    }

    // -- Proofs --

    /// Imports a proof file, validating and persisting the contained asset.
    pub fn import_proof(
        &self,
        proof_file: proof::file::File,
    ) -> Result<(), TapNodeError> {
        crate::receive::import_proof(self, proof_file)
    }

    /// Exports a proof file for a specific asset output.
    pub fn export_proof(
        &self,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
    ) -> Result<proof::file::File, TapNodeError> {
        crate::receive::export_proof(self, outpoint, script_key)
    }

    // -- Lightning (delegates to crate::lightning) --

    /// Prepares asset state for a new Lightning channel.
    ///
    /// Call this before `ChannelManager::create_channel()`. Returns the
    /// channel ID to use with LDK.
    pub fn open_asset_channel(
        &self,
        channel_id: [u8; 32],
        asset_id: AssetId,
        asset_amount: u64,
    ) -> Result<[u8; 32], TapNodeError> {
        crate::lightning::open_asset_channel(
            self, channel_id, asset_id, asset_amount,
        )
    }

    /// Closes an asset channel's asset-side state.
    pub fn close_asset_channel(
        &self,
        channel_id: &[u8; 32],
    ) -> Result<(), TapNodeError> {
        crate::lightning::close_asset_channel(self, channel_id)
    }

    /// Handles an intercepted HTLC from your LDK event loop.
    pub fn handle_intercepted_htlc(
        &self,
        intercept_id: [u8; 32],
        next_hop_scid: u64,
        next_node_id: [u8; 33],
        amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(), TapNodeError> {
        crate::lightning::handle_intercepted_htlc(
            self,
            intercept_id,
            next_hop_scid,
            next_node_id,
            amt_msat,
            custom_records,
        )
    }

    /// Gets asset channel state for a channel ID.
    pub fn get_asset_channel(
        &self,
        channel_id: &[u8; 32],
    ) -> Result<tap_ldk::ldk::AssetChannelState, TapNodeError> {
        crate::lightning::get_asset_channel(self, channel_id)
    }

    /// Returns whether an SCID belongs to an asset channel.
    pub fn is_asset_channel(&self, scid: u64) -> bool {
        crate::lightning::is_asset_channel(self, scid)
    }

    // -- Universe supply commitments (delegates to crate::supply) --

    /// Builds, funds, signs, and broadcasts a supply commitment
    /// transaction for the given asset group from its staged supply
    /// update events (mints, burns, ignores).
    ///
    /// Returns `Ok(None)` (a no-op) when the group has no staged
    /// updates; otherwise returns the display-order txid of the
    /// broadcast commitment transaction. The commitment is finished by
    /// [`tick`](Self::tick) once it confirms: the commitment block is
    /// attached, the whole commitment is verified with the node's own
    /// supply verifier (initial or incremental path), and only then
    /// are the supply trees updated, the commitment persisted, the
    /// spent pre-commitments marked, and the staged events consumed.
    /// Events staged while a commitment is in flight stay queued for
    /// the next commitment (Go's dangling updates).
    pub fn commit_supply(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<[u8; 32]>, TapNodeError> {
        crate::supply::commit_supply(self, group_key)
    }

    /// Stages an ignore supply update for the given asset previous ID
    /// (outpoint + asset ID + script key) and amount, signing the
    /// ignore tuple with the asset group's delegation key via the
    /// node's [`AssetSigner::sign_message_schnorr`] seam. The node
    /// custodies delegation keys it derived during minting; for groups
    /// whose delegation key is external, use
    /// [`stage_supply_ignore`](Self::stage_supply_ignore) with an
    /// externally signed tuple instead.
    pub fn ignore_asset_outpoint(
        &self,
        prev_id: tap_primitives::asset::PrevId,
        amount: u64,
    ) -> Result<(), TapNodeError> {
        crate::supply::ignore_asset_outpoint(self, prev_id, amount)
    }

    /// Stages an externally signed ignore tuple as a supply update for
    /// its asset group. The signature is verified against the group's
    /// delegation key before staging.
    pub fn stage_supply_ignore(
        &self,
        signed_tuple: tap_universe::ignore::SignedIgnoreTuple,
    ) -> Result<(), TapNodeError> {
        crate::supply::stage_supply_ignore(self, signed_tuple)
    }

    /// Stages a burn supply update from a raw encoded burn proof (the
    /// Go `BurnLeaf` encoding). The proof's asset group must be known.
    ///
    /// Note: the node does not yet have a burn send flow, so burns are
    /// staged through this API by the embedder; once burns are wired
    /// into the send pipeline, its confirmation path will stage the
    /// event automatically, mirroring the mint path.
    pub fn stage_supply_burn(
        &self,
        raw_burn_proof: &[u8],
    ) -> Result<(), TapNodeError> {
        crate::supply::stage_supply_burn(self, raw_burn_proof)
    }

    /// Returns the staged (not yet committed) supply update events of
    /// the given asset group.
    pub fn staged_supply_updates(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<tap_universe::supply::SupplyUpdateEvent>, TapNodeError>
    {
        self.supply_staging_store
            .lock()
            .expect("supply staging store lock")
            .staged_updates(group_key)
            .map_err(TapNodeError::Storage)
    }

    /// Returns the latest persisted (confirmed and verified) supply
    /// commitment of the given asset group, if any.
    pub fn latest_supply_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<tap_universe::supply::RootCommitment>, TapNodeError>
    {
        self.supply_commit_store
            .lock()
            .expect("supply commit store lock")
            .latest_commitment(group_key)
            .map_err(TapNodeError::Storage)
    }

    /// Returns the unspent supply pre-commitment outputs of the given
    /// asset group.
    pub fn unspent_supply_pre_commits(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<tap_universe::supply::PreCommitment>, TapNodeError>
    {
        self.supply_commit_store
            .lock()
            .expect("supply commit store lock")
            .unspent_pre_commits(group_key)
            .map_err(TapNodeError::Storage)
    }

    // -- Universe Sync (delegates to crate::sync) --

    /// Registers a proof with a universe server.
    ///
    /// The proof bytes should be TAPP-encoded (from `encode_proof()`).
    pub fn register_proof_with_universe(
        &self,
        server_url: &str,
        asset_id: &AssetId,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
        proof_bytes: &[u8],
    ) -> Result<(), TapNodeError> {
        let client =
            tap_universe::http_client::HttpUniverseClient::new(server_url);
        client
            .insert_proof(
                asset_id,
                tap_universe::types::ProofType::Issuance,
                outpoint,
                script_key,
                proof_bytes,
            )
            .map_err(|e| TapNodeError::Universe(e.to_string()))
    }

    /// Performs a one-shot universe sync against all configured
    /// universe servers (config plus federation database).
    pub fn sync_universe(
        &self,
    ) -> Result<Vec<tap_universe::types::AssetSyncDiff>, TapNodeError> {
        crate::sync::sync_universe(self)
    }

    /// Performs a one-shot universe sync against a caller-provided
    /// remote (any [`tap_universe::traits::DiffEngine`]), pulling
    /// verified missing leaves into the node's local universe store.
    /// Useful for embedders with custom transports.
    pub fn sync_with_engine(
        &self,
        remote: &dyn tap_universe::traits::DiffEngine,
    ) -> Result<Vec<tap_universe::types::AssetSyncDiff>, TapNodeError> {
        crate::sync::sync_with_engine(self, remote)
    }

    /// Returns the root of one of the node's local universe trees, if
    /// it exists (e.g. after a mint's issuance proof was registered on
    /// confirmation, or after a universe sync).
    pub fn universe_root(
        &self,
        id: &tap_universe::types::UniverseId,
    ) -> Result<tap_universe::types::UniverseRoot, TapNodeError> {
        self.universe_backend
            .lock()
            .expect("universe backend lock")
            .root_node(id)
            .map_err(|e| TapNodeError::Universe(e.to_string()))
    }

    /// Adds a universe federation server.
    pub fn add_universe_server(
        &self,
        addr: &str,
    ) -> Result<(), TapNodeError> {
        crate::sync::add_universe_server(self, addr)
    }

    /// Removes a universe federation server.
    pub fn remove_universe_server(
        &self,
        addr: &str,
    ) -> Result<(), TapNodeError> {
        crate::sync::remove_universe_server(self, addr)
    }

    /// Lists configured universe federation servers.
    pub fn list_universe_servers(
        &self,
    ) -> Result<Vec<tap_universe::types::ServerAddr>, TapNodeError> {
        crate::sync::list_universe_servers(self)
    }
}

// ---------------------------------------------------------------------------
// Newtype wrappers for Arc<T> trait delegation
// ---------------------------------------------------------------------------

/// Wrapper so `Planter` can use `Arc<C>` as a `ChainBridge`.
pub(crate) struct ArcChain<C>(pub Arc<C>);

impl<C: ChainBridge> ChainBridge for ArcChain<C> {
    fn current_height(&self) -> Result<u32, tap_onchain::chain::ChainError> {
        self.0.current_height()
    }
    fn estimate_fee(
        &self,
        conf_target: u32,
    ) -> Result<tap_onchain::chain::FeeRate, tap_onchain::chain::ChainError>
    {
        self.0.estimate_fee(conf_target)
    }
    fn publish_transaction(
        &self,
        tx: &[u8],
    ) -> Result<(), tap_onchain::chain::ChainError> {
        self.0.publish_transaction(tx)
    }
    fn get_block_hash(
        &self,
        height: u32,
    ) -> Result<[u8; 32], tap_onchain::chain::ChainError> {
        self.0.get_block_hash(height)
    }
    fn get_tx_confirmation(
        &self,
        txid: &[u8; 32],
    ) -> Result<
        Option<tap_onchain::chain::TxConfirmation>,
        tap_onchain::chain::ChainError,
    > {
        self.0.get_tx_confirmation(txid)
    }
}

/// Wrapper so `Planter` can use `Arc<W>` as a `WalletAnchor`.
pub(crate) struct ArcWallet<W>(pub Arc<W>);

impl<W: WalletAnchor> WalletAnchor for ArcWallet<W> {
    fn fund_psbt(
        &self,
        raw_psbt: &[u8],
        fee_rate: tap_onchain::chain::FeeRate,
    ) -> Result<Vec<u8>, tap_onchain::chain::ChainError> {
        self.0.fund_psbt(raw_psbt, fee_rate)
    }
    fn sign_and_finalize_psbt(
        &self,
        funded_psbt: &[u8],
    ) -> Result<Vec<u8>, tap_onchain::chain::ChainError> {
        self.0.sign_and_finalize_psbt(funded_psbt)
    }
    fn import_taproot_output(
        &self,
        internal_key: &SerializedKey,
    ) -> Result<(), tap_onchain::chain::ChainError> {
        self.0.import_taproot_output(internal_key)
    }
}

/// Wrapper so `Planter` can use `Arc<K>` as `KeyRing`.
pub(crate) struct ArcKeys<K>(pub Arc<K>);

impl<K: KeyRing> KeyRing for ArcKeys<K> {
    fn derive_next_key(
        &self,
        family: u16,
    ) -> Result<
        tap_onchain::chain::KeyDescriptor,
        tap_onchain::chain::ChainError,
    > {
        self.0.derive_next_key(family)
    }
    fn is_local_key(
        &self,
        key_desc: &tap_onchain::chain::KeyDescriptor,
    ) -> Result<bool, tap_onchain::chain::ChainError> {
        self.0.is_local_key(key_desc)
    }
}
