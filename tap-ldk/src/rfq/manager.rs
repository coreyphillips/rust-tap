// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! RFQ quote manager — tracks pending requests and accepted quotes.
//!
//! Outgoing requests are recorded in a pending-request map keyed by RFQ
//! ID. Incoming accepts/rejects are validated against that map (peer
//! binding and buy/sell discrimination, mirroring Go's `SessionLookup`)
//! so an accepted quote always carries the real asset ID of the
//! original request.

use std::collections::HashMap;

use tap_primitives::asset::AssetId;

use super::FixedPoint;
use crate::wire::compat::RejectCode;
use crate::wire::messages::RfqId;
use crate::wire::{
    RfqBuyAccept, RfqBuyRequest, RfqReject, RfqSellAccept, RfqSellRequest,
};

/// Default lifetime of an RFQ quote/request in seconds (Go
/// `rfqmsg.DefaultQuoteLifetime` = 10 minutes).
pub const DEFAULT_QUOTE_LIFETIME_SECS: u64 = 600;

/// Errors from the RFQ system.
#[derive(Debug, Clone)]
pub enum RfqError {
    /// No quote found for the given ID.
    QuoteNotFound(RfqId),
    /// Quote has expired.
    QuoteExpired { id: RfqId, expiry: u64, now: u64 },
    /// No pending outgoing request found for the given ID.
    RequestNotFound(RfqId),
    /// The response came from a different peer than the request was
    /// sent to.
    PeerMismatch { id: RfqId, expected: [u8; 33], actual: [u8; 33] },
    /// The response type (buy/sell) does not match the pending request.
    RequestTypeMismatch(RfqId),
    /// Price oracle returned an error.
    OracleError(String),
    /// Asset not supported.
    UnsupportedAsset(AssetId),
    /// Peer has too many pending quotes.
    PeerQuoteLimitExceeded { peer: [u8; 33], count: usize },
    /// Signing the accept message failed.
    SigningError(String),
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
            RfqError::RequestNotFound(id) => {
                write!(f, "no pending request for id: {:?}", id)
            }
            RfqError::PeerMismatch { id, .. } => {
                write!(f, "response peer mismatch for id: {:?}", id)
            }
            RfqError::RequestTypeMismatch(id) => {
                write!(f, "buy/sell type mismatch for id: {:?}", id)
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
            RfqError::SigningError(msg) => {
                write!(f, "accept signing error: {}", msg)
            }
        }
    }
}

impl std::error::Error for RfqError {}

/// A price oracle that provides exchange rates.
///
/// Rates are expressed as *asset units per BTC* (Go `rfqmsg.AssetRate`),
/// NOT msat per unit.
pub trait PriceOracle {
    /// Returns the ask rate (units per BTC) for selling the asset to a
    /// peer that wants to buy `max_amount` units.
    fn ask_price(
        &self,
        asset_id: &AssetId,
        max_amount: u64,
    ) -> Result<FixedPoint, RfqError>;

    /// Returns the bid rate (units per BTC) for buying the asset from a
    /// peer that wants to sell up to `max_msat` worth.
    fn bid_price(
        &self,
        asset_id: &AssetId,
        max_msat: u64,
    ) -> Result<FixedPoint, RfqError>;
}

/// Signs outgoing accept messages (the 64-byte signature record, TLV
/// type 6, in Go's `acceptWireMsgData`).
///
/// Go currently transmits an all-zero signature as well; this hook
/// exists so a real signing scheme can be plugged in later without
/// changing the wire format. When no signer is configured, accepts are
/// sent with a zero signature.
pub trait AcceptSigner: Send + Sync {
    /// Signs the accept message payload (encoded with a zeroed sig
    /// record) and returns the 64-byte signature.
    fn sign_accept(&self, msg: &[u8]) -> Result<[u8; 64], RfqError>;
}

/// An accepted quote that can be used for HTLC routing.
#[derive(Clone, Debug)]
pub struct AcceptedQuote {
    /// Quote ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// The asset involved.
    pub asset_id: AssetId,
    /// Exchange rate in asset units per BTC.
    pub rate: FixedPoint,
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

/// An outgoing request awaiting a response.
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// The request ID.
    pub id: RfqId,
    /// The asset the request is about.
    pub asset_id: AssetId,
    /// The peer the request was sent to.
    pub peer: [u8; 33],
    /// True for buy requests, false for sell requests.
    pub is_buy: bool,
    /// Maximum amount (asset units for buy, msat for sell).
    pub max_amount: u64,
    /// Unix timestamp when the request was created.
    pub created_at: u64,
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
    /// Outgoing requests awaiting a response, keyed by request ID.
    pending_requests: HashMap<RfqId, PendingRequest>,
    /// Maximum pending quotes per peer (buy + sell combined).
    max_quotes_per_peer: usize,
    /// Optional signer for outgoing accept messages.
    signer: Option<Box<dyn AcceptSigner>>,
}

impl<P: PriceOracle> QuoteManager<P> {
    /// Creates a new quote manager with the given price oracle.
    pub fn new(oracle: P) -> Self {
        QuoteManager {
            oracle,
            buy_quotes: HashMap::new(),
            sell_quotes: HashMap::new(),
            pending_requests: HashMap::new(),
            max_quotes_per_peer: MAX_PENDING_QUOTES_PER_PEER,
            signer: None,
        }
    }

    /// Creates a new quote manager with a custom per-peer quote limit.
    pub fn with_max_quotes_per_peer(
        oracle: P,
        max_quotes_per_peer: usize,
    ) -> Self {
        QuoteManager {
            max_quotes_per_peer,
            ..Self::new(oracle)
        }
    }

    /// Sets the signer used for outgoing accept messages.
    pub fn set_accept_signer(&mut self, signer: Box<dyn AcceptSigner>) {
        self.signer = Some(signer);
    }

    /// Generates a new unique 32-byte quote ID using the OS CSPRNG.
    fn next_quote_id(&mut self) -> RfqId {
        loop {
            let mut id = [0u8; 32];
            getrandom::getrandom(&mut id).expect("OS RNG failed");
            // Ensure no collision (astronomically unlikely).
            if !self.buy_quotes.contains_key(&id)
                && !self.sell_quotes.contains_key(&id)
                && !self.pending_requests.contains_key(&id)
            {
                return id;
            }
        }
    }

    /// Returns the number of pending quotes for a given peer.
    fn peer_quote_count(&self, peer: &[u8; 33]) -> usize {
        let buy =
            self.buy_quotes.values().filter(|q| &q.peer == peer).count();
        let sell =
            self.sell_quotes.values().filter(|q| &q.peer == peer).count();
        buy + sell
    }

    /// Signs an accept message with the configured signer, or returns a
    /// zero signature when none is configured.
    fn sign_accept_payload(
        &self,
        payload: &[u8],
    ) -> Result<[u8; 64], RfqError> {
        match &self.signer {
            Some(signer) => signer.sign_accept(payload),
            None => Ok([0u8; 64]),
        }
    }

    /// Creates a buy request (we want to buy assets) and records it as
    /// pending so the matching accept can be validated later.
    pub fn create_buy_request(
        &mut self,
        asset_id: AssetId,
        max_amount: u64,
        peer: [u8; 33],
        now: u64,
    ) -> RfqBuyRequest {
        let id = self.next_quote_id();
        self.pending_requests.insert(
            id,
            PendingRequest {
                id,
                asset_id,
                peer,
                is_buy: true,
                max_amount,
                created_at: now,
            },
        );
        RfqBuyRequest {
            id,
            asset_id,
            asset_max_amount: max_amount,
            asset_group_key: None,
            expiry: now + DEFAULT_QUOTE_LIFETIME_SECS,
            rate_hint: None,
        }
    }

    /// Creates a sell request (we want to sell assets for BTC) and
    /// records it as pending.
    pub fn create_sell_request(
        &mut self,
        asset_id: AssetId,
        max_msat: u64,
        peer: [u8; 33],
        now: u64,
    ) -> RfqSellRequest {
        let id = self.next_quote_id();
        self.pending_requests.insert(
            id,
            PendingRequest {
                id,
                asset_id,
                peer,
                is_buy: false,
                max_amount: max_msat,
                created_at: now,
            },
        );
        RfqSellRequest {
            id,
            asset_id,
            payment_max_amt_msat: max_msat,
            asset_group_key: None,
            expiry: now + DEFAULT_QUOTE_LIFETIME_SECS,
            rate_hint: None,
        }
    }

    /// Looks up a pending outgoing request.
    pub fn get_pending_request(&self, id: &RfqId) -> Option<&PendingRequest> {
        self.pending_requests.get(id)
    }

    /// Returns whether a pending request is a buy (`Some(true)`), a
    /// sell (`Some(false)`), or unknown (`None`). Suitable as the
    /// session lookup for [`crate::wire::TapMessage::decode`].
    pub fn pending_request_is_buy(&self, id: &RfqId) -> Option<bool> {
        self.pending_requests.get(id).map(|p| p.is_buy)
    }

    /// Handles an incoming buy request from a peer. Responds with an
    /// accept or reject based on the oracle's ask rate.
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
                code: RejectCode::PriceOracleUnspecified,
                message: format!(
                    "peer quote limit exceeded: {} pending",
                    count
                ),
            });
        }

        match self
            .oracle
            .ask_price(&request.asset_id, request.asset_max_amount)
        {
            Ok(rate) => {
                let expiry = now + quote_lifetime_secs;
                let mut accept = RfqBuyAccept {
                    id: request.id,
                    asset_rate: rate,
                    expiry,
                    sig: [0u8; 64],
                    max_in_asset: None,
                };
                if let Ok(payload) = accept.to_wire().encode() {
                    if let Ok(sig) = self.sign_accept_payload(&payload) {
                        accept.sig = sig;
                    }
                }

                // Store the accepted quote (the peer buys, we sell).
                self.sell_quotes.insert(
                    request.id,
                    AcceptedQuote {
                        id: request.id,
                        asset_id: request.asset_id,
                        rate,
                        expiry,
                        peer,
                        is_buy: false,
                    },
                );

                Ok(accept)
            }
            Err(e) => Err(RfqReject {
                id: request.id,
                code: RejectCode::PriceOracleUnavailable,
                message: e.to_string(),
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
                code: RejectCode::PriceOracleUnspecified,
                message: format!(
                    "peer quote limit exceeded: {} pending",
                    count
                ),
            });
        }

        match self
            .oracle
            .bid_price(&request.asset_id, request.payment_max_amt_msat)
        {
            Ok(rate) => {
                let expiry = now + quote_lifetime_secs;
                let mut accept = RfqSellAccept {
                    id: request.id,
                    asset_rate: rate,
                    expiry,
                    sig: [0u8; 64],
                    max_in_asset: None,
                };
                if let Ok(payload) = accept.to_wire().encode() {
                    if let Ok(sig) = self.sign_accept_payload(&payload) {
                        accept.sig = sig;
                    }
                }

                // Store the accepted quote (the peer sells, we buy).
                self.buy_quotes.insert(
                    request.id,
                    AcceptedQuote {
                        id: request.id,
                        asset_id: request.asset_id,
                        rate,
                        expiry,
                        peer,
                        is_buy: true,
                    },
                );

                Ok(accept)
            }
            Err(e) => Err(RfqReject {
                id: request.id,
                code: RejectCode::PriceOracleUnavailable,
                message: e.to_string(),
            }),
        }
    }

    /// Handles an incoming buy accept: the peer accepted our buy
    /// request. Validates the pending request (existence, direction and
    /// peer binding, mirroring Go's `NewIncomingAcceptFromWire`) and
    /// produces the accepted quote carrying the real asset ID.
    pub fn handle_buy_accept(
        &mut self,
        accept: &RfqBuyAccept,
        peer: [u8; 33],
        now: u64,
    ) -> Result<AcceptedQuote, RfqError> {
        let pending = self
            .pending_requests
            .get(&accept.id)
            .ok_or(RfqError::RequestNotFound(accept.id))?;
        if !pending.is_buy {
            return Err(RfqError::RequestTypeMismatch(accept.id));
        }
        if pending.peer != peer {
            return Err(RfqError::PeerMismatch {
                id: accept.id,
                expected: pending.peer,
                actual: peer,
            });
        }
        if accept.expiry <= now {
            return Err(RfqError::QuoteExpired {
                id: accept.id,
                expiry: accept.expiry,
                now,
            });
        }

        let quote = AcceptedQuote {
            id: accept.id,
            asset_id: pending.asset_id,
            rate: accept.asset_rate,
            expiry: accept.expiry,
            peer,
            is_buy: true,
        };
        self.pending_requests.remove(&accept.id);
        self.buy_quotes.insert(accept.id, quote.clone());
        Ok(quote)
    }

    /// Handles an incoming sell accept: the peer accepted our sell
    /// request.
    pub fn handle_sell_accept(
        &mut self,
        accept: &RfqSellAccept,
        peer: [u8; 33],
        now: u64,
    ) -> Result<AcceptedQuote, RfqError> {
        let pending = self
            .pending_requests
            .get(&accept.id)
            .ok_or(RfqError::RequestNotFound(accept.id))?;
        if pending.is_buy {
            return Err(RfqError::RequestTypeMismatch(accept.id));
        }
        if pending.peer != peer {
            return Err(RfqError::PeerMismatch {
                id: accept.id,
                expected: pending.peer,
                actual: peer,
            });
        }
        if accept.expiry <= now {
            return Err(RfqError::QuoteExpired {
                id: accept.id,
                expiry: accept.expiry,
                now,
            });
        }

        let quote = AcceptedQuote {
            id: accept.id,
            asset_id: pending.asset_id,
            rate: accept.asset_rate,
            expiry: accept.expiry,
            peer,
            is_buy: false,
        };
        self.pending_requests.remove(&accept.id);
        self.sell_quotes.insert(accept.id, quote.clone());
        Ok(quote)
    }

    /// Handles an incoming reject for one of our outgoing requests,
    /// clearing the pending state. The reject is ignored if it does not
    /// match a pending request from that peer (spoofing protection,
    /// mirroring Go's peer binding).
    pub fn handle_reject(
        &mut self,
        reject: &RfqReject,
        peer: [u8; 33],
    ) -> Result<(), RfqError> {
        let pending = self
            .pending_requests
            .get(&reject.id)
            .ok_or(RfqError::RequestNotFound(reject.id))?;
        if pending.peer != peer {
            return Err(RfqError::PeerMismatch {
                id: reject.id,
                expected: pending.peer,
                actual: peer,
            });
        }
        self.pending_requests.remove(&reject.id);
        Ok(())
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

    /// Removes expired quotes and timed-out pending requests.
    pub fn prune_expired(&mut self, now: u64) {
        self.buy_quotes.retain(|_, q| q.is_valid(now));
        self.sell_quotes.retain(|_, q| q.is_valid(now));
        self.pending_requests.retain(|_, p| {
            now < p.created_at + DEFAULT_QUOTE_LIFETIME_SECS
        });
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
            // 20,000,000 units per BTC (1 unit = 5000 msat).
            Ok(FixedPoint::new(20_000_000, 0))
        }

        fn bid_price(
            &self,
            _asset_id: &AssetId,
            _max_msat: u64,
        ) -> Result<FixedPoint, RfqError> {
            // 25,000,000 units per BTC (1 unit = 4000 msat).
            Ok(FixedPoint::new(25_000_000, 0))
        }
    }

    fn make_id(byte: u8) -> RfqId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    const PEER: [u8; 33] = [0x02; 33];
    const NOW: u64 = 1_000_000;

    #[test]
    fn test_create_buy_request_records_pending() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req =
            mgr.create_buy_request(AssetId([0xAA; 32]), 1000, PEER, NOW);
        assert_ne!(req.id, [0u8; 32]);
        assert_eq!(req.asset_max_amount, 1000);
        assert_eq!(req.expiry, NOW + DEFAULT_QUOTE_LIFETIME_SECS);

        let pending = mgr.get_pending_request(&req.id).unwrap();
        assert!(pending.is_buy);
        assert_eq!(pending.asset_id, AssetId([0xAA; 32]));
        assert_eq!(pending.peer, PEER);
        assert_eq!(mgr.pending_request_is_buy(&req.id), Some(true));

        let req2 =
            mgr.create_buy_request(AssetId([0xBB; 32]), 500, PEER, NOW);
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
            expiry: NOW + 600,
            rate_hint: None,
        };

        let accept = mgr.handle_buy_request(&req, PEER, NOW, 3600).unwrap();

        assert_eq!(accept.id, id);
        assert_eq!(accept.asset_rate, FixedPoint::new(20_000_000, 0));
        assert_eq!(accept.expiry, NOW + 3600);
        // No signer configured: zero signature.
        assert_eq!(accept.sig, [0u8; 64]);

        // Quote should be stored.
        let quote = mgr.get_quote(&id).unwrap();
        assert_eq!(quote.rate, FixedPoint::new(20_000_000, 0));
        assert!(!quote.is_buy);
    }

    #[test]
    fn test_handle_buy_accept_uses_pending_asset_id() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req =
            mgr.create_buy_request(AssetId([0xCC; 32]), 1000, PEER, NOW);

        let accept = RfqBuyAccept {
            id: req.id,
            asset_rate: FixedPoint::new(20_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        };

        let quote = mgr.handle_buy_accept(&accept, PEER, NOW).unwrap();
        assert_eq!(quote.asset_id, AssetId([0xCC; 32]));
        assert!(quote.is_buy);
        // Pending request is consumed.
        assert!(mgr.get_pending_request(&req.id).is_none());
        assert!(mgr.get_quote(&req.id).is_some());
    }

    #[test]
    fn test_handle_buy_accept_validations() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req =
            mgr.create_buy_request(AssetId([0xCC; 32]), 1000, PEER, NOW);
        let accept = RfqBuyAccept {
            id: req.id,
            asset_rate: FixedPoint::new(20_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        };

        // Unknown ID.
        let mut bad = accept.clone();
        bad.id = make_id(9);
        assert!(matches!(
            mgr.handle_buy_accept(&bad, PEER, NOW),
            Err(RfqError::RequestNotFound(_))
        ));

        // Wrong peer.
        assert!(matches!(
            mgr.handle_buy_accept(&accept, [0x03; 33], NOW),
            Err(RfqError::PeerMismatch { .. })
        ));

        // Expired accept.
        assert!(matches!(
            mgr.handle_buy_accept(&accept, PEER, NOW + 601),
            Err(RfqError::QuoteExpired { .. })
        ));

        // Sell accept for a pending buy request.
        let sell_accept = RfqSellAccept {
            id: req.id,
            asset_rate: FixedPoint::new(20_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        };
        assert!(matches!(
            mgr.handle_sell_accept(&sell_accept, PEER, NOW),
            Err(RfqError::RequestTypeMismatch(_))
        ));

        // Pending request survives all the failed attempts.
        assert!(mgr.get_pending_request(&req.id).is_some());
    }

    #[test]
    fn test_handle_sell_accept() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req =
            mgr.create_sell_request(AssetId([0xDD; 32]), 500_000, PEER, NOW);

        let accept = RfqSellAccept {
            id: req.id,
            asset_rate: FixedPoint::new(25_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        };
        let quote = mgr.handle_sell_accept(&accept, PEER, NOW).unwrap();
        assert_eq!(quote.asset_id, AssetId([0xDD; 32]));
        assert!(!quote.is_buy);
    }

    #[test]
    fn test_handle_reject_clears_pending() {
        let mut mgr = QuoteManager::new(MockOracle);
        let req =
            mgr.create_buy_request(AssetId([0xAA; 32]), 100, PEER, NOW);

        let reject = RfqReject {
            id: req.id,
            code: RejectCode::PriceOracleUnavailable,
            message: "no".into(),
        };

        // Wrong peer is refused and pending survives.
        assert!(mgr.handle_reject(&reject, [0x05; 33]).is_err());
        assert!(mgr.get_pending_request(&req.id).is_some());

        mgr.handle_reject(&reject, PEER).unwrap();
        assert!(mgr.get_pending_request(&req.id).is_none());
    }

    #[test]
    fn test_prune_expired_covers_pending() {
        let mut mgr = QuoteManager::new(MockOracle);
        let id = make_id(1);
        let req = RfqBuyRequest {
            id,
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 100,
            asset_group_key: None,
            expiry: NOW + 100,
            rate_hint: None,
        };

        mgr.handle_buy_request(&req, PEER, NOW, 100).unwrap();
        assert!(mgr.get_quote(&id).is_some());

        let out = mgr.create_buy_request(AssetId([0xBB; 32]), 5, PEER, NOW);

        mgr.prune_expired(NOW + 50);
        assert!(mgr.get_quote(&id).is_some());
        assert!(mgr.get_pending_request(&out.id).is_some());

        mgr.prune_expired(NOW + 101);
        assert!(mgr.get_quote(&id).is_none());
        // Pending requests live for DEFAULT_QUOTE_LIFETIME_SECS.
        assert!(mgr.get_pending_request(&out.id).is_some());

        mgr.prune_expired(NOW + DEFAULT_QUOTE_LIFETIME_SECS);
        assert!(mgr.get_pending_request(&out.id).is_none());
    }

    #[test]
    fn test_accept_signer_hook() {
        struct FixedSigner;
        impl AcceptSigner for FixedSigner {
            fn sign_accept(&self, _msg: &[u8]) -> Result<[u8; 64], RfqError> {
                Ok([0x77; 64])
            }
        }

        let mut mgr = QuoteManager::new(MockOracle);
        mgr.set_accept_signer(Box::new(FixedSigner));

        let req = RfqBuyRequest {
            id: make_id(3),
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 100,
            asset_group_key: None,
            expiry: NOW + 600,
            rate_hint: None,
        };
        let accept = mgr.handle_buy_request(&req, PEER, NOW, 600).unwrap();
        assert_eq!(accept.sig, [0x77; 64]);
    }
}
