// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK integration layer for Taproot Assets.
//!
//! This crate bridges the TAP protocol implementation with LDK's Lightning
//! network stack. It provides:
//!
//! - [`wire`]: Custom message types for asset funding and RFQ negotiation
//! - [`rfq`]: Request For Quote system for asset/BTC exchange
//! - [`routing`]: Traffic shaping and HTLC interception for asset channels
//! - [`channel`]: Asset channel state management (blobs, leaves, signing)
//! - [`ldk`]: LDK integration traits mirroring ChannelManager patterns
//!
//! # Architecture
//!
//! The integration works in three tiers:
//!
//! **Tier A (no LDK changes needed):**
//! - Custom peer messages via `CustomMessageHandler`
//! - HTLC interception via `Event::HTLCIntercepted`
//! - Custom TLV records in HTLC onion payloads
//! - RFQ negotiation as a standalone protocol
//!
//! **Tier B (small upstream LDK PRs needed):**
//! - Opaque blob storage in channel state
//! - `TxBuilder` extensibility for auxiliary tapscript leaves
//! - Auxiliary signatures in `CommitmentSigned`
//!
//! **Tier C (significant LDK changes):**
//! - Funding output tapscript hooks
//! - Asset-aware on-chain resolution

pub mod channel;
pub mod config;
pub mod ldk;
pub mod rfq;
pub mod routing;
pub mod wire;
