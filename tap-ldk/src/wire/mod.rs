// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Wire message types for TAP-over-Lightning communication.
//!
//! These messages are exchanged between peers as custom Lightning messages
//! (via `CustomMessageHandler`) for asset channel funding negotiation and
//! RFQ price quotes.

pub mod compat;
pub mod messages;

pub use messages::*;

/// Go-compatible message type constants from the `compat` module.
pub use compat::{
    MSG_TYPE_ACCEPT, MSG_TYPE_REJECT, MSG_TYPE_REQUEST, TAP_MSG_BASE_OFFSET,
};

/// Legacy message type constants (for internal/Rust-only use).
pub const TAP_MSG_TYPE_BASE: u16 = 32768;

/// Legacy message type offsets. For Go interoperability, use the
/// [`compat`] module's constants instead.
pub mod msg_type {
    use super::TAP_MSG_TYPE_BASE;

    // Asset funding flow.
    pub const ASSET_FUNDING_CREATED: u16 = TAP_MSG_TYPE_BASE + 1;
    pub const ASSET_FUNDING_ACK: u16 = TAP_MSG_TYPE_BASE + 3;
    pub const ASSET_FUNDING_PROOF: u16 = TAP_MSG_TYPE_BASE + 5;
}
