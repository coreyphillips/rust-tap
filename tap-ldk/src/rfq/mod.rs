// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Request For Quote (RFQ) system for asset/BTC price negotiation.
//!
//! The RFQ protocol allows Lightning nodes to negotiate exchange rates for
//! asset payments across channels. Before routing an asset payment, the
//! sender negotiates a price with the edge node that will convert between
//! BTC and the asset.
//!
//! # Flow
//!
//! 1. Sender requests a quote (buy or sell) via custom message
//! 2. Edge node evaluates via its [`PriceOracle`] and responds
//! 3. If accepted, the quote ID is embedded in the HTLC custom records
//! 4. The edge node uses the quote to determine the asset amount

pub mod math;
pub mod manager;

pub use math::{FixedPoint, FixedPointError};
pub use manager::{
    AcceptSigner, AcceptedQuote, PendingRequest, PriceOracle, QuoteManager,
    RfqError, DEFAULT_QUOTE_LIFETIME_SECS,
};
