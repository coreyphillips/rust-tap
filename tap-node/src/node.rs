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

use tap_ldk::ldk::{LdkChannelOps, TapChannelManager};
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::mint::Planter;
use tap_onchain::proof::courier::Courier;
use tap_persist::asset_store::AssetStore;
use tap_persist::batch_store::BatchStore;
use tap_persist::proof_store::ProofStore;
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

    // Universe sync.
    pub(crate) universe_backend:
        Mutex<Box<dyn tap_universe::traits::UniverseBackend + Send>>,
    pub(crate) federation_db:
        Mutex<Box<dyn tap_universe::traits::FederationDb + Send>>,

    // Events.
    pub(crate) event_bus: EventBus,
    pub(crate) event_receiver: Mutex<Option<mpsc::Receiver<TapEvent>>>,

    // Lifecycle.
    pub(crate) running: AtomicBool,
}

impl<C, W, K, L, P> TapNode<C, W, K, L, P>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    /// Starts the node. Enables background tasks (universe sync, etc.).
    pub fn start(&self) -> Result<(), TapNodeError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(TapNodeError::AlreadyRunning);
        }
        Ok(())
    }

    /// Stops the node and background tasks.
    pub fn stop(&self) -> Result<(), TapNodeError> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Err(TapNodeError::NotRunning);
        }
        Ok(())
    }

    /// Returns an event receiver for monitoring node activity.
    ///
    /// Can only be called once -- the receiver is moved out.
    pub fn event_receiver(
        &self,
    ) -> Result<mpsc::Receiver<TapEvent>, TapNodeError> {
        self.event_receiver
            .lock()
            .unwrap()
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
        Ok(self.asset_store.lock().unwrap().list_unspent())
    }

    /// Returns the spendable balance for an asset.
    pub fn get_balance(&self, asset_id: &AssetId) -> Result<u64, TapNodeError> {
        Ok(self.asset_store.lock().unwrap().balance(asset_id))
    }

    /// Generates a new address for receiving an asset.
    pub fn new_address(
        &self,
        asset_id: AssetId,
        amount: u64,
    ) -> Result<TapAddress, TapNodeError> {
        crate::receive::new_address(self, asset_id, amount)
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

    /// Performs a one-shot universe sync.
    pub fn sync_universe(
        &self,
    ) -> Result<Vec<tap_universe::types::AssetSyncDiff>, TapNodeError> {
        crate::sync::sync_universe(self)
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
