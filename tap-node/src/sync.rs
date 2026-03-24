// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Universe sync management.
//!
//! Provides on-demand and background sync with universe federation servers
//! for decentralized asset discovery.

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_universe::memory::{MemoryFederationDb, MemoryUniverseBackend};
use tap_universe::syncer::SimpleSyncer;
use tap_universe::traits::{FederationDb, Syncer, UniverseBackend};
use tap_universe::types::{AssetSyncDiff, ServerAddr, SyncType, UniverseError};

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;

/// Performs a one-shot universe sync against all configured servers.
pub(crate) fn sync_universe<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<Vec<AssetSyncDiff>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Universe sync is a placeholder — in production, you'd connect to
    // remote universe servers via HTTP and sync using SimpleSyncer.
    // For now, we just emit the event with zero new assets.
    let diffs: Vec<AssetSyncDiff> = Vec::new();
    let new_count: usize = diffs.iter().map(|d| d.new_leaves.len()).sum();
    node.event_bus.emit(TapEvent::UniverseSyncCompleted {
        new_assets_discovered: new_count,
    });

    Ok(diffs)
}

/// Adds a universe federation server.
pub(crate) fn add_universe_server<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    addr: &str,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let mut federation = node.federation_db.lock().unwrap();
    federation
        .add_servers(&[ServerAddr {
            host: addr.to_string(),
            id: String::new(),
        }])
        .map_err(|e| TapNodeError::Universe(e.to_string()))
}

/// Removes a universe federation server.
pub(crate) fn remove_universe_server<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    addr: &str,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let mut federation = node.federation_db.lock().unwrap();
    federation
        .remove_servers(&[ServerAddr {
            host: addr.to_string(),
            id: String::new(),
        }])
        .map_err(|e| TapNodeError::Universe(e.to_string()))
}

/// Lists configured universe federation servers.
pub(crate) fn list_universe_servers<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<Vec<ServerAddr>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let federation = node.federation_db.lock().unwrap();
    federation
        .universe_servers()
        .map_err(|e| TapNodeError::Universe(e.to_string()))
}
