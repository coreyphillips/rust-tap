// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Configuration for a tap-node instance.

use std::path::PathBuf;

use tap_primitives::address::TapNetwork;

/// Configuration for a [`TapNode`](crate::TapNode) instance.
#[derive(Clone, Debug)]
pub struct TapNodeConfig {
    /// Network (mainnet, testnet, regtest, simnet, testnet4).
    pub network: TapNetwork,
    /// SQLite database path. `None` uses in-memory storage.
    pub db_path: Option<PathBuf>,
    /// Default proof courier URL.
    pub courier_url: String,
    /// Universe federation server addresses.
    pub universe_servers: Vec<String>,
    /// Universe sync interval in seconds (0 = disabled).
    pub universe_sync_interval_secs: u64,
    /// Interval between background ticks of the node's worker thread
    /// in seconds (confirmation polling, periodic universe sync, RFQ
    /// quote pruning). See [`TapNode::tick`](crate::TapNode::tick).
    pub tick_interval_secs: u64,
    /// RFQ quote lifetime in seconds.
    pub rfq_quote_lifetime_secs: u64,
    /// CSV delay for force-close outputs (blocks).
    pub csv_delay_blocks: u16,
    /// Default fee rate confirmation target (blocks).
    pub default_conf_target: u32,
}

impl Default for TapNodeConfig {
    fn default() -> Self {
        TapNodeConfig {
            network: TapNetwork::Regtest,
            db_path: None,
            courier_url: String::new(),
            universe_servers: vec![],
            universe_sync_interval_secs: 600,
            tick_interval_secs: 30,
            rfq_quote_lifetime_secs: 3600,
            csv_delay_blocks: 144,
            default_conf_target: 6,
        }
    }
}
