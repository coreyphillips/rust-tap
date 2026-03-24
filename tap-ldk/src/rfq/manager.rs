// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! RFQ quote manager — tracks pending and accepted quotes.

use std::collections::HashMap;

use tap_primitives::asset::AssetId;

use super::FixedPoint;
use crate::wire::messages::RfqId;
use crate::wire::{
    RfqBuyAccept, RfqBuyRequest, RfqReject, RfqSellAccept, RfqSellRequest,
};

/// Errors from the RFQ system.
#[derive(Debug, Clone)]
pub enum RfqError {
    /// No quote found for the given ID.
    QuoteNotFound(RfqId),
    /// Quote has expired.
    QuoteExpired { id: RfqId, expiry: u64, now: u64 },
    /// Price oracle returned an error.
    OracleError(String),
    /// Asset not supported.
    UnsupportedAsset(AssetId),
    /// Peer has too many pending quotes.
    PeerQuoteLimitExceeded { peer: [u8; 33], count: usize },
}

impl std::fmt::Display for RfqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RfqError::QuoteNotFound(id) => {
                write!(f, "quote not found: {:?}", id)
            }
            RfqError::QuoteExpired { id, expiry, now } => {
                write!(
                    f,
                    "quote {:?} expired: expiry={}, now={}",
                    id, expiry, now
                )
            }
            RfqError::OracleError(msg) => {
                write!(f, "oracle error: {}", msg)
            }
            RfqError::UnsupportedAsset(id) => {
                write!(f, "unsupported asset: {:?}", id)
            }
            RfqError::PeerQuoteLimitExceeded { count, .. } => {
                write!(f, "peer quote limit exceeded: {} pending", count)
            }
        }
    }
}

impl std::error::Error for RfqError {}

/// A price oracle that provides exchange rates.
pub trait PriceOracle {
    /// Returns the ask price (msat per asset unit) for buying the asset.
    fn ask_price(
        &self,
        asset_id: &AssetId,
        max_amount: u64,
    ) -> Result<FixedPoint, RfqError>;

    /// Returns the bid price (msat per asset unit) for selling the asset.
    fn bid_price(
        &self,
        asset_id: &AssetId,
        max_msat: u64,
    ) -> Result<FixedPoint, RfqError>;
}

/// An accepted quote that can be used for HTLC routing.
#[derive(Clone, Debug)]
pub struct AcceptedQuote {
    /// Quote ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// The asset involved.
    pub asset_id: AssetId,
    /// Price in msat per asset unit.
    pub price: FixedPoint,
    /// Unix timestamp when the quote expires.
    pub expiry: u64,
    /// The peer this quote is with.
    pub peer: [u8; 33],
    /// Whether this is a buy (true) or sell (false) from our perspective.
    pub is_buy: bool,
}

impl AcceptedQuote {
    /// Returns true if the quote is still valid at the given timestamp.
    pub fn is_valid(&self, now: u64) -> bool {
        now < self.expiry
    }
}

/// Maximum number of pending quotes allowed per peer.
pub const MAX_PENDING_QUOTES_PER_PEER: usize = 100;

/// Manages RFQ quotes for asset channel payments.
pub struct QuoteManager<P: PriceOracle> {
    oracle: P,
    /// Accepted buy quotes keyed by quote ID.
    buy_quotes: HashMap<RfqId, AcceptedQuote>,
    /// Accepted sell quotes keyed by quote ID.
    sell_quotes: HashMap<RfqId, AcceptedQuote>,
    /// Maximum pending quotes per peer (buy + sell combined).
    max_quotes_per_peer: usize,
}

impl<P: PriceOracle> QuoteManager<P> {
    /// Creates a new quote manager with the given price oracle.
    pub fn new(oracle: P) -> Self {
        QuoteManager {
            oracle,
            buy_quotes: HashMap::new(),
            sell_quotes: HashMap::new(),
            max_quotes_per_peer: MAX_PENDING_QUOTES_PER_PEER,
        }
    }

    /// Creates a new quote manager with a custom per-peer quote limit.
    pub fn with_max_quotes_per_peer(oracle: P, max_quotes_per_peer: usize) -> Self {
        QuoteManager {
            oracle,
            buy_quotes: HashMap::new(),
            sell_quotes: HashMap::new(),
            max_quotes_per_peer,
        }
    }

    /// Generates a new unique 32-byte quote ID using the OS CSPRNG.
    fn next_quote_id(&mut self) -> RfqId {
        loop {
            let mut id = [0u8; 32];
            getrandom::getrandom(&mut id).expect("OS RNG failed");
            // Ensure no collision (astronomically unlikely).
            if !self.buy_quotes.contains_key(&id)
                && !self.sell_quotes.contains_key(&id)
            {
                return id;
            }
        }
    }

    /// Returns the number of pending quotes for a given peer.
    fn peer_quote_count(&self, peer: &[u8; 33]) -> usize {
        let buy = self.buy_quotes.values().filter(|q| &q.peer == peer).count();
        let sell = self.sell_quotes.values().filter(|q| &q.peer == peer).count();
        buy + sell
    }

    /// Creates a buy request (we want to buy assets).
    pub fn create_buy_request(
        &mut self,
        asset_id: AssetId,
        max_amount: u64,
    ) -> RfqBuyRequest {
        RfqBuyRequest {
            id: self.next_quote_id(),
            asset_id,
            asset_max_amount: max_amount,
            asset_group_key: None,
        }
    }

    /// Creates a sell request (we want to sell assets for BTC).
    pub fn create_sell_request(
        &mut self,
        asset_id: AssetId,
        max_msat: u64,
    ) -> RfqSellRequest {
        RfqSellRequest {
            id: self.next_quote_id(),
            asset_id,
            payment_max_amt_msat: max_msat,
            asset_group_key: None,
        }
    }

    /// Handles an incoming buy request from a peer. Responds with an
    /// accept or reject based on the oracle's ask price.
    ///
    /// Rejects the request if the peer exceeds the per-peer quote limit.
    pub fn handle_buy_request(
        &mut self,
        request: &RfqBuyRequest,
        peer: [u8; 33],
        now: u64,
        quote_lifetime_secs: u64,
    ) -> Result<RfqBuyAccept, RfqReject> {
        let count = self.peer_quote_count(&peer);
        if count >= self.max_quotes_per_peer {
            return Err(RfqReject {
                id: request.id,
                error_code: 2,
                error_message: format!(
                    "peer quote limit exceeded: {} pending",
                    count
                ),
            });
        }

        match self.oracle.ask_price(&request.asset_id, request.asset_max_amount) {
            Ok(price) => {
                let expiry = now + quote_lifetime_secs;
                let accept = RfqBuyAccept {
                    id: request.id,
                    ask_price: price.to_integer(),
                    expiry,
                };

                // Store the accepted quote.
                self.sell_quotes.insert(
                    request.id,
                    AcceptedQuote {
                        id: request.id,
                        asset_id: request.asset_id,
                        price,
                        expiry,
                        peer,
                        is_buy: false,
                    },
                );

                Ok(accept)
            }
            Err(e) => Err(RfqReject {
                id: request.id,
                error_code: 1,
                error_message: e.to_string(),
            }),
        }
    }

    /// Handles an incoming sell request from a peer.
    ///
    /// Rejects the request if the peer exceeds the per-peer quote limit.
    pub fn handle_sell_request(
        &mut self,
        request: &RfqSellRequest,
        peer: [u8; 33],
        now: u64,
        quote_lifetime_secs: u64,
    ) -> Result<RfqSellAccept, RfqReject> {
        let count = self.peer_quote_count(&peer);
        if count >= self.max_quotes_per_peer {
            return Err(RfqReject {
                id: request.id,
                error_code: 2,
                error_message: format!(
                    "peer quote limit exceeded: {} pending",
                    count
                ),
            });
        }

        match self
            .oracle
            .bid_price(&request.asset_id, request.payment_max_amt_msat)
        {
            Ok(price) => {
                let expiry = now + quote_lifetime_secs;
                let accept = RfqSellAccept {
                    id: request.id,
                    bid_price: price.to_integer(),
                    expiry,
                };

                self.buy_quotes.insert(
                    request.id,
                    AcceptedQuote {
                        id: request.id,
                        asset_id: request.asset_id,
                        price,
                        expiry,
                        peer,
                        is_buy: true,
                    },
                );

                Ok(accept)
            }
            Err(e) => Err(RfqReject {
                id: request.id,
                error_code: 1,
                error_message: e.to_string(),
            }),
        }
    }

    /// Records an accepted buy quote (peer accepted our buy request).
    pub fn record_buy_accept(
        &mut self,
        accept: &RfqBuyAccept,
        asset_id: AssetId,
        peer: [u8; 33],
    ) {
        self.buy_quotes.insert(
            accept.id,
            AcceptedQuote {
                id: accept.id,
                asset_id,
                price: FixedPoint::from_integer(accept.ask_price),
                expiry: accept.expiry,
                peer,
                is_buy: true,
            },
        );
    }

    /// Records an accepted sell quote (peer accepted our sell request).
    pub fn record_sell_accept(
        &mut self,
        accept: &RfqSellAccept,
        asset_id: AssetId,
        peer: [u8; 33],
    ) {
        self.sell_quotes.insert(
            accept.id,
            AcceptedQuote {
                id: accept.id,
                asset_id,
                price: FixedPoint::from_integer(accept.bid_price),
                expiry: accept.expiry,
                peer,
                is_buy: false,
            },
        );
    }

    /// Looks up an accepted quote by ID.
    pub fn get_quote(&self, id: &RfqId) -> Option<&AcceptedQuote> {
        self.buy_quotes
            .get(id)
            .or_else(|| self.sell_quotes.get(id))
    }

    /// Returns all accepted buy quotes.
    pub fn buy_quotes(&self) -> &HashMap<RfqId, AcceptedQuote> {
        &self.buy_quotes
    }

    /// Returns all accepted sell quotes.
    pub fn sell_quotes(&self) -> &HashMap<RfqId, AcceptedQuote> {
        &self.sell_quotes
    }

    /// Removes expired quotes.
    pub fn prune_expired(&mut self, now: u64) {
        self.buy_quotes.retain(|_, q| q.is_valid(now));
        self.sell_quotes.retain(|_, q| q.is_valid(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOracle;

    impl PriceOracle for MockOracle {
        fn ask_price(
            &self,
            _asset_id: &AssetId,
            _max_amount: u64,
        ) -> Result<FixedPoint, RfqError> {
            // 1 asset unit = 5000 msat.
            Ok(FixedPoint::from_integer(5000))
        }

        fn bid_price(
            &self,
            _asset_id: &AssetId,
            _max_msat: u64,
        ) -> Result<FixedPoint, RfqError> {
            // 1 asset unit = 4800 msat.
            Ok(FixedPoint::from_integer(4800))
        }
    }

    fn make_id(byte: u8) -> RfqId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn test_create_buy_request() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req = mgr.create_buy_request(AssetId([0xAA; 32]), 1000);
        assert_ne!(req.id, [0u8; 32]);
        assert_eq!(req.asset_max_amount, 1000);

        let req2 = mgr.create_buy_request(AssetId([0xBB; 32]), 500);
        assert_ne!(req.id, req2.id);
    }

    #[test]
    fn test_handle_buy_request() {
        let mut mgr = QuoteManager::new(MockOracle);
        let id = make_id(42);
        let req = RfqBuyRequest {
            id,
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 100,
            asset_group_key: None,
        };

        let now = 1_000_000u64;
        let accept = mgr
            .handle_buy_request(&req, [0x02; 33], now, 3600)
            .unwrap();

        assert_eq!(accept.id, id);
        assert_eq!(accept.ask_price, 5000);
        assert_eq!(accept.expiry, now + 3600);

        // Quote should be stored.
        let quote = mgr.get_quote(&id).unwrap();
        assert_eq!(quote.price.to_integer(), 5000);
    }

    #[test]
    fn test_handle_sell_request() {
        let mut mgr = QuoteManager::new(MockOracle);
        let id = make_id(99);
        let req = RfqSellRequest {
            id,
            asset_id: AssetId([0xBB; 32]),
            payment_max_amt_msat: 500_000,
            asset_group_key: None,
        };

        let accept = mgr
            .handle_sell_request(&req, [0x03; 33], 1_000_000, 3600)
            .unwrap();

        assert_eq!(accept.id, id);
        assert_eq!(accept.bid_price, 4800);
    }

    #[test]
    fn test_prune_expired() {
        let mut mgr = QuoteManager::new(MockOracle);
        let id = make_id(1);
        let req = RfqBuyRequest {
            id,
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 100,
            asset_group_key: None,
        };

        let now = 1_000_000u64;
        mgr.handle_buy_request(&req, [0x02; 33], now, 100).unwrap();
        assert!(mgr.get_quote(&id).is_some());

        mgr.prune_expired(now + 50);
        assert!(mgr.get_quote(&id).is_some());

        mgr.prune_expired(now + 101);
        assert!(mgr.get_quote(&id).is_none());
    }

    #[test]
    fn test_record_buy_accept() {
        let mut mgr = QuoteManager::new(MockOracle);
        let id = make_id(55);
        let accept = RfqBuyAccept {
            id,
            ask_price: 3000,
            expiry: 2_000_000,
        };

        mgr.record_buy_accept(&accept, AssetId([0xCC; 32]), [0x04; 33]);

        let quote = mgr.get_quote(&id).unwrap();
        assert_eq!(quote.price.to_integer(), 3000);
        assert!(quote.is_buy);
    }
}
