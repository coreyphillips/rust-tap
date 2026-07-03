// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Error types for tap-node operations.

use tap_onchain::chain::ChainError;
use tap_onchain::mint::MintError;
use tap_onchain::proof::courier::CourierError;
use tap_onchain::proof::mailbox::MailboxError;
use tap_onchain::send::SendError;
use tap_primitives::address::AddressError;
use tap_primitives::asset::AssetId;

/// Errors from tap-node operations.
#[derive(Debug)]
pub enum TapNodeError {
    /// Node is not started or already stopped.
    NotRunning,
    /// Node is already running.
    AlreadyRunning,
    /// Configuration error.
    Config(String),
    /// Minting error.
    Mint(MintError),
    /// Transfer error.
    Send(SendError),
    /// Chain interaction error.
    Chain(ChainError),
    /// Proof courier error.
    Courier(CourierError),
    /// Lightning/channel error.
    Lightning(String),
    /// RFQ error.
    Rfq(String),
    /// Universe sync error.
    Universe(String),
    /// Storage error.
    Storage(String),
    /// Supply commitment pipeline error.
    Supply(String),
    /// Asset not found.
    AssetNotFound(AssetId),
    /// Insufficient asset balance.
    InsufficientBalance {
        asset_id: AssetId,
        available: u64,
        needed: u64,
    },
    /// Address error.
    Address(AddressError),
    /// Auth mailbox error.
    Mailbox(MailboxError),
}

impl std::fmt::Display for TapNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TapNodeError::NotRunning => write!(f, "node is not running"),
            TapNodeError::AlreadyRunning => {
                write!(f, "node is already running")
            }
            TapNodeError::Config(msg) => {
                write!(f, "config error: {}", msg)
            }
            TapNodeError::Mint(e) => write!(f, "mint error: {}", e),
            TapNodeError::Send(e) => write!(f, "send error: {}", e),
            TapNodeError::Chain(e) => write!(f, "chain error: {}", e),
            TapNodeError::Courier(e) => write!(f, "courier error: {}", e),
            TapNodeError::Lightning(msg) => {
                write!(f, "lightning error: {}", msg)
            }
            TapNodeError::Rfq(msg) => write!(f, "rfq error: {}", msg),
            TapNodeError::Universe(msg) => {
                write!(f, "universe error: {}", msg)
            }
            TapNodeError::Storage(msg) => {
                write!(f, "storage error: {}", msg)
            }
            TapNodeError::Supply(msg) => {
                write!(f, "supply commitment error: {}", msg)
            }
            TapNodeError::AssetNotFound(id) => {
                write!(f, "asset not found: {:?}", id)
            }
            TapNodeError::InsufficientBalance {
                asset_id,
                available,
                needed,
            } => write!(
                f,
                "insufficient balance for {:?}: have {}, need {}",
                asset_id, available, needed
            ),
            TapNodeError::Address(e) => write!(f, "address error: {}", e),
            TapNodeError::Mailbox(e) => write!(f, "mailbox error: {}", e),
        }
    }
}

impl std::error::Error for TapNodeError {}

impl From<MintError> for TapNodeError {
    fn from(e: MintError) -> Self {
        TapNodeError::Mint(e)
    }
}

impl From<SendError> for TapNodeError {
    fn from(e: SendError) -> Self {
        TapNodeError::Send(e)
    }
}

impl From<ChainError> for TapNodeError {
    fn from(e: ChainError) -> Self {
        TapNodeError::Chain(e)
    }
}

impl From<CourierError> for TapNodeError {
    fn from(e: CourierError) -> Self {
        TapNodeError::Courier(e)
    }
}

impl From<AddressError> for TapNodeError {
    fn from(e: AddressError) -> Self {
        TapNodeError::Address(e)
    }
}

impl From<MailboxError> for TapNodeError {
    fn from(e: MailboxError) -> Self {
        TapNodeError::Mailbox(e)
    }
}
