// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! # tap-node
//!
//! High-level Taproot Assets node for Rust application developers.
//!
//! `tap-node` wraps the entire taproot-ldk workspace into a single
//! [`TapNode`] struct with a builder pattern, managed lifecycle, and
//! simple API -- similar to how `ldk-node` wraps `rust-lightning`.
//!
//! ## Quick Start
//!
//! ```ignore
//! use tap_node::*;
//!
//! let config = TapNodeConfig {
//!     network: TapNetwork::Regtest,
//!     ..Default::default()
//! };
//!
//! let node = TapNodeBuilder::new(config)
//!     .set_chain_bridge(my_chain)
//!     .set_wallet_anchor(my_wallet)
//!     .set_key_ring(my_keys)
//!     .set_ldk_ops(my_ldk)
//!     .set_price_oracle(my_oracle)
//!     .build()?;
//!
//! node.start()?;
//!
//! // Mint assets
//! node.queue_mint(Seedling::new_normal("USD-Coin".into(), 1_000_000))?;
//! let result = node.finalize_mint()?;
//!
//! // Check balance
//! let balance = node.get_balance(&result.assets[0].asset_id)?;
//!
//! // Send to a TAP address
//! let handle = node.send_asset(asset_id, 500, &recipient_address)?;
//!
//! // Generate a receive address
//! let addr = node.new_address(asset_id, 100)?;
//! ```

pub mod builder;
pub mod config;
pub mod error;
pub mod event;
pub mod lightning;
pub mod mint;
pub mod node;
pub mod receive;
pub mod send;
pub mod sync;
pub mod types;

// Primary public API.
pub use builder::TapNodeBuilder;
pub use config::TapNodeConfig;
pub use error::TapNodeError;
pub use event::TapEvent;
pub use node::TapNode;
pub use types::*;

// Re-export key types from workspace crates so users don't need to
// depend on them directly.
pub use tap_ldk::ldk::LdkChannelOps;
pub use tap_ldk::rfq::PriceOracle;
pub use tap_onchain::chain::{
    AssetSigner, ChainBridge, ChainError, FeeRate, KeyDescriptor, KeyRing,
    WalletAnchor,
};
pub use tap_onchain::mint::Seedling;
pub use tap_persist::asset_store::OwnedAsset;
pub use tap_primitives::address::{TapAddress, TapNetwork};
pub use tap_primitives::asset::{AssetId, AssetType, SerializedKey};
