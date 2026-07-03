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
use tap_onchain::proof::mailbox::{MailboxSigner, MailboxTransport};
use tap_persist::asset_store::{AssetStore, MemoryAssetStore};
use tap_persist::batch_store::{BatchStore, MemoryBatchStore};
use tap_persist::mailbox_store::{MailboxStore, MemoryMailboxStore};
use tap_persist::pending_anchor_store::{
    MemoryPendingAnchorStore, PendingAnchorStore,
};
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
///
/// # Starting the node (breaking change)
///
/// [`TapNode::start`] now takes `self: Arc<Self>` so its background
/// worker thread can hold a weak handle to the node. Wrap the built
/// node in an [`Arc`] and start it via a clone:
///
/// ```ignore
/// let node = Arc::new(builder.build()?);
/// node.clone().start()?;
/// // ...
/// node.stop()?;
/// ```
///
/// Embedders that drive their own scheduler can skip `start()`
/// entirely and call [`TapNode::tick`] directly.
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
    pending_anchor_store: Option<Box<dyn PendingAnchorStore + Send>>,
    courier: Option<Box<dyn Courier + Send + Sync>>,
    mailbox_transport: Option<Box<dyn MailboxTransport + Send + Sync>>,
    mailbox_signer: Option<Box<dyn MailboxSigner + Send + Sync>>,
    mailbox_store: Option<Box<dyn MailboxStore + Send>>,
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
            pending_anchor_store: None,
            courier: None,
            mailbox_transport: None,
            mailbox_signer: None,
            mailbox_store: None,
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

    /// Overrides the default pending anchor store (the durable watch
    /// list of broadcast mint/transfer anchor transactions awaiting
    /// confirmation).
    pub fn set_pending_anchor_store(
        mut self,
        store: Box<dyn PendingAnchorStore + Send>,
    ) -> Self {
        self.pending_anchor_store = Some(store);
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

    /// Sets the auth mailbox transport used for V2 address receives.
    /// Without a transport, `poll_mailbox` is a documented no-op.
    pub fn set_mailbox_transport(
        mut self,
        transport: Box<dyn MailboxTransport + Send + Sync>,
    ) -> Self {
        self.mailbox_transport = Some(transport);
        self
    }

    /// Sets the mailbox signer (ECDH + challenge signing) used to
    /// decrypt incoming send fragments. Required when a mailbox
    /// transport is configured.
    pub fn set_mailbox_signer(
        mut self,
        signer: Box<dyn MailboxSigner + Send + Sync>,
    ) -> Self {
        self.mailbox_signer = Some(signer);
        self
    }

    /// Overrides the default (in-memory) address book / mailbox cursor
    /// store.
    pub fn set_mailbox_store(
        mut self,
        store: Box<dyn MailboxStore + Send>,
    ) -> Self {
        self.mailbox_store = Some(store);
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

        // Create default stores if not provided. When `db_path` is
        // configured (and the `sqlite` feature is enabled), the default
        // stores are SQLite-backed, sharing one database handle;
        // otherwise they fall back to in-memory stores.
        let default_db = open_default_db(
            &self.config,
            self.asset_store.is_none()
                || self.proof_store.is_none()
                || self.batch_store.is_none()
                || self.pending_anchor_store.is_none(),
        )?;
        let asset_store: Box<dyn AssetStore + Send> = match self
            .asset_store
        {
            Some(store) => store,
            None => default_asset_store(&default_db),
        };
        let proof_store: Box<dyn ProofStore + Send> = match self
            .proof_store
        {
            Some(store) => store,
            None => default_proof_store(&default_db),
        };
        let batch_store: Box<dyn BatchStore + Send> = match self
            .batch_store
        {
            Some(store) => store,
            None => default_batch_store(&default_db),
        };
        let pending_anchor_store: Box<dyn PendingAnchorStore + Send> =
            match self.pending_anchor_store {
                Some(store) => store,
                None => default_pending_anchor_store(&default_db),
            };

        // Reload the durable pending-anchor watch list so a restart
        // between broadcast and confirmation still finishes the mint
        // (genesis proofs + universe registration) or transfer (proof
        // storage + delivery) once the anchor confirms. Mint anchors
        // reload their batch from the batch store by key.
        let pending_anchors = restore_pending_anchors(
            pending_anchor_store.as_ref(),
            batch_store.as_ref(),
        )?;

        // Create the courier. Without an explicit courier, a
        // configured `courier_url` gets an HTTP courier using the URL
        // as its REST base; only an empty URL falls back to the
        // always-failing placeholder.
        let courier: Box<dyn Courier + Send + Sync> = match self.courier {
            Some(courier) => courier,
            None if !self.config.courier_url.is_empty() => {
                Box::new(tap_onchain::proof::http_courier::HttpCourier::new(
                    tap_onchain::proof::http_courier::HttpCourierCfg::new(
                        self.config.courier_url.clone(),
                    ),
                ))
            }
            None => Box::new(NoCourier),
        };

        // Mailbox store (defaults to in-memory).
        let mailbox_store: Box<dyn MailboxStore + Send> = self
            .mailbox_store
            .unwrap_or_else(|| Box::new(MemoryMailboxStore::new()));

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
            pending_anchor_store: Mutex::new(pending_anchor_store),
            courier,
            mailbox_transport: self.mailbox_transport,
            mailbox_signer: self.mailbox_signer,
            mailbox_store: Mutex::new(mailbox_store),
            universe_backend: Mutex::new(universe_backend),
            federation_db: Mutex::new(federation_db),
            event_bus,
            event_receiver: Mutex::new(Some(event_receiver)),
            pending_anchors: Mutex::new(pending_anchors),
            last_universe_sync: Mutex::new(None),
            last_tick: Mutex::new(None),
            send_lock: Mutex::new(()),
            running: AtomicBool::new(false),
            worker: Mutex::new(None),
        })
    }
}

/// The shared database handle behind the default (SQLite) stores.
#[cfg(feature = "sqlite")]
type DefaultDb = Arc<tap_persist::sqlite::SqliteDb>;
/// Placeholder when the `sqlite` feature is disabled: there is never a
/// shared database and defaults are in-memory.
#[cfg(not(feature = "sqlite"))]
type DefaultDb = std::convert::Infallible;

/// Opens the shared SQLite database for default stores, if a `db_path`
/// is configured, any default store is actually needed, and the
/// `sqlite` feature is enabled.
#[cfg(feature = "sqlite")]
fn open_default_db(
    config: &TapNodeConfig,
    any_default_needed: bool,
) -> Result<Option<DefaultDb>, TapNodeError> {
    match (&config.db_path, any_default_needed) {
        (Some(path), true) => Ok(Some(Arc::new(
            tap_persist::sqlite::SqliteDb::open(path)
                .map_err(TapNodeError::Storage)?,
        ))),
        _ => Ok(None),
    }
}

#[cfg(not(feature = "sqlite"))]
fn open_default_db(
    _config: &TapNodeConfig,
    _any_default_needed: bool,
) -> Result<Option<DefaultDb>, TapNodeError> {
    Ok(None)
}

fn default_asset_store(
    db: &Option<DefaultDb>,
) -> Box<dyn AssetStore + Send> {
    match db {
        #[cfg(feature = "sqlite")]
        Some(db) => Box::new(tap_persist::sqlite::SqliteAssetStore::new(
            Arc::clone(db),
        )),
        _ => Box::new(MemoryAssetStore::new()),
    }
}

fn default_proof_store(
    db: &Option<DefaultDb>,
) -> Box<dyn ProofStore + Send> {
    match db {
        #[cfg(feature = "sqlite")]
        Some(db) => Box::new(tap_persist::sqlite::SqliteProofStore::new(
            Arc::clone(db),
        )),
        _ => Box::new(MemoryProofStore::new()),
    }
}

fn default_batch_store(
    db: &Option<DefaultDb>,
) -> Box<dyn BatchStore + Send> {
    match db {
        #[cfg(feature = "sqlite")]
        Some(db) => Box::new(tap_persist::sqlite::SqliteBatchStore::new(
            Arc::clone(db),
        )),
        _ => Box::new(MemoryBatchStore::new()),
    }
}

fn default_pending_anchor_store(
    db: &Option<DefaultDb>,
) -> Box<dyn PendingAnchorStore + Send> {
    match db {
        #[cfg(feature = "sqlite")]
        Some(db) => Box::new(
            tap_persist::pending_anchor_store::SqlitePendingAnchorStore::new(
                Arc::clone(db),
            ),
        ),
        _ => Box::new(MemoryPendingAnchorStore::new()),
    }
}

/// Reloads the persisted pending anchors into the in-memory watch
/// list, deduplicating by txid so a reload can never double-register an
/// anchor. Mint anchors reload their batch from the batch store by
/// batch key; a payload that cannot be decoded (or references a
/// missing batch) fails the build rather than silently dropping the
/// anchor.
fn restore_pending_anchors(
    pending_anchor_store: &dyn PendingAnchorStore,
    batch_store: &dyn BatchStore,
) -> Result<Vec<crate::tasks::PendingAnchor>, TapNodeError> {
    let stored = pending_anchor_store
        .list_anchors()
        .map_err(TapNodeError::Storage)?;

    let mut restored = Vec::with_capacity(stored.len());
    let mut seen = std::collections::HashSet::new();
    for row in stored {
        if !seen.insert(row.txid) {
            continue;
        }
        let anchor =
            crate::anchor_codec::decode_pending_anchor(&row, batch_store)
                .map_err(|e| {
                    TapNodeError::Storage(format!(
                        "restoring pending anchor: {}",
                        e
                    ))
                })?;
        restored.push(anchor);
    }
    Ok(restored)
}
