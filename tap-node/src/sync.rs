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
//! Provides on-demand and background sync with universe federation
//! servers for decentralized asset discovery. Each configured server is
//! contacted via [`HttpUniverseClient`] (a
//! [`DiffEngine`](tap_universe::traits::DiffEngine)) and diffed against
//! the node's local universe store with
//! [`tap_universe::sync_all`]: missing leaves are fetched, their proofs
//! verified, and the valid ones persisted locally.

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_universe::http_client::HttpUniverseClient;
use tap_universe::syncer::SimpleSyncer;
use tap_universe::traits::DiffEngine;
use tap_universe::types::{AssetSyncDiff, ServerAddr, SyncType};

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;

/// Performs a one-shot universe sync against all configured servers
/// (`config.universe_servers` plus the federation database), collecting
/// the per-server diffs. A failing server is skipped: the remaining
/// servers still sync.
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
    // The server set is the configured list plus the federation
    // database, deduplicated.
    let mut servers: Vec<String> = node.config.universe_servers.clone();
    {
        let federation = node.federation_db.lock().expect("federation lock");
        if let Ok(listed) = federation.universe_servers() {
            for server in listed {
                if !servers.contains(&server.host) {
                    servers.push(server.host);
                }
            }
        }
    }

    let syncer = SimpleSyncer::new();
    let mut diffs = Vec::new();

    for host in &servers {
        let client = HttpUniverseClient::new(host);
        let result = {
            let mut backend =
                node.universe_backend.lock().expect("universe lock");
            tap_universe::sync_all(
                &syncer,
                &mut **backend,
                &client,
                SyncType::Full,
            )
        };
        match result {
            Ok(server_result) => diffs.extend(server_result.diffs),
            // Continue with the remaining servers on error, mirroring
            // the Go federation envoy.
            Err(_) => continue,
        }
    }

    let new_count: usize = diffs.iter().map(|d| d.new_leaves.len()).sum();
    node.event_bus.emit(TapEvent::UniverseSyncCompleted {
        new_assets_discovered: new_count,
    });

    Ok(diffs)
}

/// Performs a one-shot universe sync against a caller-provided remote
/// [`DiffEngine`], pulling verified missing leaves into the node's
/// local universe store.
pub(crate) fn sync_with_engine<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    remote: &dyn DiffEngine,
) -> Result<Vec<AssetSyncDiff>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let syncer = SimpleSyncer::new();
    let result = {
        let mut backend =
            node.universe_backend.lock().expect("universe lock");
        tap_universe::sync_all(
            &syncer,
            &mut **backend,
            remote,
            SyncType::Full,
        )
        .map_err(|e| TapNodeError::Universe(e.to_string()))?
    };

    let new_count: usize =
        result.diffs.iter().map(|d| d.new_leaves.len()).sum();
    node.event_bus.emit(TapEvent::UniverseSyncCompleted {
        new_assets_discovered: new_count,
    });

    Ok(result.diffs)
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
    let mut federation = node.federation_db.lock().expect("federation lock");
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
    let mut federation = node.federation_db.lock().expect("federation lock");
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
    let federation = node.federation_db.lock().expect("federation lock");
    federation
        .universe_servers()
        .map_err(|e| TapNodeError::Universe(e.to_string()))
}
