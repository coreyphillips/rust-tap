// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Builder for constructing a [`TapNode`] instance.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tap_ldk::ldk::{LdkChannelOps, TapChannelManager};
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::mint::Planter;
use tap_onchain::proof::courier::Courier;
use tap_persist::asset_store::{AssetStore, MemoryAssetStore};
use tap_persist::batch_store::{BatchStore, MemoryBatchStore};
use tap_persist::proof_store::{MemoryProofStore, ProofStore};
use tap_universe::memory::{MemoryFederationDb, MemoryUniverseBackend};

use crate::config::TapNodeConfig;
use crate::error::TapNodeError;
use crate::event::EventBus;
use crate::node::{ArcChain, ArcKeys, ArcWallet, TapNode};

/// A mock courier that always fails. Used as placeholder when no courier
/// is configured.
struct NoCourier;

impl Courier for NoCourier {
    fn deliver_proof(
        &self,
        _recipient: &tap_onchain::proof::courier::Recipient,
        _proof: &tap_onchain::proof::courier::AnnotatedProof,
    ) -> Result<(), tap_onchain::proof::courier::CourierError> {
        Err(tap_onchain::proof::courier::CourierError::Other(
            "no courier configured".into(),
        ))
    }

    fn receive_proof(
        &self,
        _recipient: &tap_onchain::proof::courier::Recipient,
        _locator: &tap_onchain::proof::courier::CourierLocator,
    ) -> Result<
        tap_onchain::proof::courier::AnnotatedProof,
        tap_onchain::proof::courier::CourierError,
    > {
        Err(tap_onchain::proof::courier::CourierError::Other(
            "no courier configured".into(),
        ))
    }
}

/// Builder for constructing a [`TapNode`].
///
/// Collects required backends and optional configuration, then produces
/// a fully wired `TapNode` via [`build()`](TapNodeBuilder::build).
///
/// # Required
///
/// - [`set_chain_bridge`](TapNodeBuilder::set_chain_bridge)
/// - [`set_wallet_anchor`](TapNodeBuilder::set_wallet_anchor)
/// - [`set_key_ring`](TapNodeBuilder::set_key_ring)
/// - [`set_ldk_ops`](TapNodeBuilder::set_ldk_ops)
/// - [`set_price_oracle`](TapNodeBuilder::set_price_oracle)
pub struct TapNodeBuilder<C, W, K, L, P> {
    config: TapNodeConfig,
    chain: Option<C>,
    wallet: Option<W>,
    keys: Option<K>,
    ldk_ops: Option<L>,
    price_oracle: Option<P>,
    asset_store: Option<Box<dyn AssetStore + Send>>,
    proof_store: Option<Box<dyn ProofStore + Send>>,
    batch_store: Option<Box<dyn BatchStore + Send>>,
    courier: Option<Box<dyn Courier + Send + Sync>>,
}

impl<C, W, K, L, P> TapNodeBuilder<C, W, K, L, P>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    /// Creates a new builder with the given configuration.
    pub fn new(config: TapNodeConfig) -> Self {
        TapNodeBuilder {
            config,
            chain: None,
            wallet: None,
            keys: None,
            ldk_ops: None,
            price_oracle: None,
            asset_store: None,
            proof_store: None,
            batch_store: None,
            courier: None,
        }
    }

    /// Sets the chain backend (required).
    pub fn set_chain_bridge(mut self, chain: C) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Sets the wallet backend (required).
    pub fn set_wallet_anchor(mut self, wallet: W) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Sets the key ring and asset signer (required).
    pub fn set_key_ring(mut self, keys: K) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Sets the LDK channel operations backend (required).
    pub fn set_ldk_ops(mut self, ldk_ops: L) -> Self {
        self.ldk_ops = Some(ldk_ops);
        self
    }

    /// Sets the price oracle for RFQ (required).
    pub fn set_price_oracle(mut self, oracle: P) -> Self {
        self.price_oracle = Some(oracle);
        self
    }

    /// Overrides the default asset store.
    pub fn set_asset_store(
        mut self,
        store: Box<dyn AssetStore + Send>,
    ) -> Self {
        self.asset_store = Some(store);
        self
    }

    /// Overrides the default proof store.
    pub fn set_proof_store(
        mut self,
        store: Box<dyn ProofStore + Send>,
    ) -> Self {
        self.proof_store = Some(store);
        self
    }

    /// Overrides the default batch store.
    pub fn set_batch_store(
        mut self,
        store: Box<dyn BatchStore + Send>,
    ) -> Self {
        self.batch_store = Some(store);
        self
    }

    /// Overrides the default proof courier.
    pub fn set_courier(
        mut self,
        courier: Box<dyn Courier + Send + Sync>,
    ) -> Self {
        self.courier = Some(courier);
        self
    }

    /// Builds the [`TapNode`].
    ///
    /// Returns an error if required backends are missing.
    pub fn build(self) -> Result<TapNode<C, W, K, L, P>, TapNodeError> {
        let chain = Arc::new(self.chain.ok_or_else(|| {
            TapNodeError::Config("chain_bridge is required".into())
        })?);
        let wallet = Arc::new(self.wallet.ok_or_else(|| {
            TapNodeError::Config("wallet_anchor is required".into())
        })?);
        let keys = Arc::new(self.keys.ok_or_else(|| {
            TapNodeError::Config("key_ring is required".into())
        })?);
        let ldk_ops = self.ldk_ops.ok_or_else(|| {
            TapNodeError::Config("ldk_ops is required".into())
        })?;
        let price_oracle = self.price_oracle.ok_or_else(|| {
            TapNodeError::Config("price_oracle is required".into())
        })?;

        // Create default stores if not provided.
        let asset_store: Box<dyn AssetStore + Send> = self
            .asset_store
            .unwrap_or_else(|| create_default_asset_store(&self.config));
        let proof_store: Box<dyn ProofStore + Send> = self
            .proof_store
            .unwrap_or_else(|| create_default_proof_store(&self.config));
        let batch_store: Box<dyn BatchStore + Send> = self
            .batch_store
            .unwrap_or_else(|| create_default_batch_store(&self.config));

        // Create courier.
        let courier: Box<dyn Courier + Send + Sync> =
            self.courier.unwrap_or_else(|| Box::new(NoCourier));

        // Create planter with Arc-wrapped backends.
        let planter = Planter::new(
            ArcChain(Arc::clone(&chain)),
            ArcWallet(Arc::clone(&wallet)),
            ArcKeys(Arc::clone(&keys)),
        );

        // Create TapChannelManager.
        let tap_config = tap_ldk::config::TapConfig {
            rfq_quote_lifetime_secs: self.config.rfq_quote_lifetime_secs,
            csv_delay_blocks: self.config.csv_delay_blocks,
            ..Default::default()
        };
        let tap_channel_mgr =
            TapChannelManager::with_config(ldk_ops, price_oracle, tap_config);

        // Create event bus.
        let (event_bus, event_receiver) = EventBus::new();

        // Universe sync backends.
        let universe_backend: Box<
            dyn tap_universe::traits::UniverseBackend + Send,
        > = Box::new(MemoryUniverseBackend::new());
        let federation_db: Box<
            dyn tap_universe::traits::FederationDb + Send,
        > = Box::new(MemoryFederationDb::new());

        Ok(TapNode {
            chain,
            wallet,
            keys,
            config: self.config,
            planter: Mutex::new(planter),
            tap_channel_mgr,
            asset_store: Mutex::new(asset_store),
            proof_store: Mutex::new(proof_store),
            batch_store: Mutex::new(batch_store),
            courier,
            universe_backend: Mutex::new(universe_backend),
            federation_db: Mutex::new(federation_db),
            event_bus,
            event_receiver: Mutex::new(Some(event_receiver)),
            running: AtomicBool::new(false),
        })
    }
}

fn create_default_asset_store(
    _config: &TapNodeConfig,
) -> Box<dyn AssetStore + Send> {
    // For SQLite, the user should provide their own store via the builder
    // since SqliteXxxStore borrows SqliteDb and cannot be owned here.
    Box::new(MemoryAssetStore::new())
}

fn create_default_proof_store(
    _config: &TapNodeConfig,
) -> Box<dyn ProofStore + Send> {
    Box::new(MemoryProofStore::new())
}

fn create_default_batch_store(
    _config: &TapNodeConfig,
) -> Box<dyn BatchStore + Send> {
    Box::new(MemoryBatchStore::new())
}
