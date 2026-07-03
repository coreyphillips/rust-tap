// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK ChannelManager wrapper for TAP asset channel management.
//!
//! [`TapChannelManager`] wraps an LDK `ChannelManager` (via trait) and
//! adds asset channel state tracking. It:
//!
//! - Maintains a parallel store of asset channel blobs (keyed by channel ID)
//! - Processes custom messages for asset funding and RFQ
//! - Intercepts HTLCs for asset routing
//! - Manages the RFQ quote lifecycle
//!
//! This works entirely externally to LDK (Tier A) — no upstream changes
//! needed.

use std::collections::HashMap;
use std::sync::Mutex;

use tap_primitives::asset::AssetId;

use crate::channel::blobs::{ChannelBlob, CommitmentBlob};
use crate::channel::traits::{AssetChannelError, AssetTrafficShaper};
use crate::config::TapConfig;
use crate::routing::{AssetHtlcData, DEFAULT_ON_CHAIN_HTLC_MSAT};
use crate::rfq::{AcceptedQuote, QuoteManager, RfqError};
use crate::wire::TapMessage;

/// A channel identifier (32 bytes).
pub type ChannelId = [u8; 32];

/// Trait abstracting the operations we need from LDK's ChannelManager.
///
/// This avoids a direct dependency on the `lightning` crate, allowing
/// the consumer to bridge their concrete `ChannelManager` to this trait.
pub trait LdkChannelOps {
    /// Forwards an intercepted HTLC with the given parameters.
    fn forward_intercepted_htlc(
        &self,
        intercept_id: [u8; 32],
        next_hop_scid: u64,
        next_node_id: [u8; 33],
        amt_to_forward_msat: u64,
    ) -> Result<(), String>;

    /// Fails an intercepted HTLC back.
    fn fail_intercepted_htlc(
        &self,
        intercept_id: [u8; 32],
    ) -> Result<(), String>;
}

/// The TAP channel manager — wraps LDK and adds asset channel awareness.
///
/// Mutex locks use `.unwrap()` intentionally: a poisoned mutex indicates a
/// panicking thread corrupted internal state, making further operation unsafe.
/// This matches LDK's own mutex handling pattern.
pub struct TapChannelManager<L, P>
where
    L: LdkChannelOps,
    P: crate::rfq::manager::PriceOracle,
{
    /// The underlying LDK channel manager.
    ldk: L,
    /// Configuration parameters.
    config: TapConfig,
    /// RFQ quote manager.
    rfq: Mutex<QuoteManager<P>>,
    /// Asset channel state, keyed by channel ID.
    channels: Mutex<HashMap<ChannelId, AssetChannelState>>,
    /// Mapping from SCID to channel ID for asset channels.
    scid_to_channel: Mutex<HashMap<u64, ChannelId>>,
}

/// Asset-specific state tracked alongside an LDK channel.
#[derive(Clone, Debug)]
pub struct AssetChannelState {
    /// Channel-level blob (set at funding).
    pub channel_blob: ChannelBlob,
    /// Latest commitment blob.
    pub commitment_blob: Option<CommitmentBlob>,
    /// The SCID for this channel (set after funding confirmed).
    pub scid: Option<u64>,
}

impl<L, P> TapChannelManager<L, P>
where
    L: LdkChannelOps,
    P: crate::rfq::manager::PriceOracle,
{
    /// Creates a new TAP channel manager with default configuration.
    pub fn new(ldk: L, oracle: P) -> Self {
        Self::with_config(ldk, oracle, TapConfig::default())
    }

    /// Creates a new TAP channel manager with the given configuration.
    pub fn with_config(ldk: L, oracle: P, config: TapConfig) -> Self {
        TapChannelManager {
            ldk,
            config,
            rfq: Mutex::new(QuoteManager::new(oracle)),
            channels: Mutex::new(HashMap::new()),
            scid_to_channel: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a new asset channel after funding.
    pub fn register_asset_channel(
        &self,
        channel_id: ChannelId,
        blob: ChannelBlob,
    ) {
        let mut channels = self.channels.lock().unwrap();
        channels.insert(
            channel_id,
            AssetChannelState {
                channel_blob: blob,
                commitment_blob: None,
                scid: None,
            },
        );
    }

    /// Updates the latest commitment blob for an asset channel.
    pub fn update_commitment_blob(
        &self,
        channel_id: &ChannelId,
        blob: CommitmentBlob,
    ) -> Result<(), AssetChannelError> {
        let mut channels = self.channels.lock().unwrap();
        let state = channels.get_mut(channel_id).ok_or_else(|| {
            AssetChannelError("unknown asset channel".into())
        })?;
        state.commitment_blob = Some(blob);
        Ok(())
    }

    /// Returns true if the given SCID belongs to an asset channel.
    ///
    /// Also available via the [`AssetTrafficShaper`] impl; this
    /// inherent method keeps the call ergonomic without importing the
    /// trait.
    pub fn is_asset_channel(&self, scid: u64) -> bool {
        self.scid_to_channel.lock().unwrap().contains_key(&scid)
    }

    /// Associates an SCID with an asset channel (called after funding
    /// confirms and the channel becomes usable).
    pub fn set_channel_scid(&self, channel_id: &ChannelId, scid: u64) {
        let mut channels = self.channels.lock().unwrap();
        if let Some(state) = channels.get_mut(channel_id) {
            state.scid = Some(scid);
            self.scid_to_channel
                .lock()
                .unwrap()
                .insert(scid, *channel_id);
        }
    }

    /// Returns the asset channel state for a given channel ID.
    pub fn get_channel_state(
        &self,
        channel_id: &ChannelId,
    ) -> Option<AssetChannelState> {
        self.channels.lock().unwrap().get(channel_id).cloned()
    }

    /// Returns the asset channel state for a given SCID.
    fn channel_state_by_scid(&self, scid: u64) -> Option<AssetChannelState> {
        let channel_id = *self.scid_to_channel.lock().unwrap().get(&scid)?;
        self.get_channel_state(&channel_id)
    }

    /// Creates and records an outgoing buy quote request for the given
    /// peer. The returned message should be sent to that peer.
    pub fn request_buy_quote(
        &self,
        asset_id: AssetId,
        max_amount: u64,
        peer: [u8; 33],
        now: u64,
    ) -> TapMessage {
        let mut rfq = self.rfq.lock().unwrap();
        TapMessage::RfqBuyRequest(
            rfq.create_buy_request(asset_id, max_amount, peer, now),
        )
    }

    /// Creates and records an outgoing sell quote request for the given
    /// peer. The returned message should be sent to that peer.
    pub fn request_sell_quote(
        &self,
        asset_id: AssetId,
        max_msat: u64,
        peer: [u8; 33],
        now: u64,
    ) -> TapMessage {
        let mut rfq = self.rfq.lock().unwrap();
        TapMessage::RfqSellRequest(
            rfq.create_sell_request(asset_id, max_msat, peer, now),
        )
    }

    /// Returns whether a pending outgoing request with the given ID is
    /// a buy (`Some(true)`), a sell (`Some(false)`), or unknown. Use as
    /// the session lookup for [`TapMessage::decode`].
    pub fn pending_request_is_buy(
        &self,
        id: &crate::wire::messages::RfqId,
    ) -> Option<bool> {
        self.rfq.lock().unwrap().pending_request_is_buy(id)
    }

    /// Looks up an accepted quote by ID.
    pub fn get_quote(
        &self,
        id: &crate::wire::messages::RfqId,
    ) -> Option<AcceptedQuote> {
        self.rfq.lock().unwrap().get_quote(id).cloned()
    }

    /// Handles an incoming TAP custom message from a peer.
    pub fn handle_tap_message(
        &self,
        peer: [u8; 33],
        msg: TapMessage,
        now: u64,
    ) -> Option<TapMessage> {
        match msg {
            TapMessage::RfqBuyRequest(req) => {
                let mut rfq = self.rfq.lock().unwrap();
                match rfq.handle_buy_request(
                    &req,
                    peer,
                    now,
                    self.config.rfq_quote_lifetime_secs,
                ) {
                    Ok(accept) => Some(TapMessage::RfqBuyAccept(accept)),
                    Err(reject) => Some(TapMessage::RfqBuyReject(reject)),
                }
            }
            TapMessage::RfqSellRequest(req) => {
                let mut rfq = self.rfq.lock().unwrap();
                match rfq.handle_sell_request(
                    &req,
                    peer,
                    now,
                    self.config.rfq_quote_lifetime_secs,
                ) {
                    Ok(accept) => Some(TapMessage::RfqSellAccept(accept)),
                    Err(reject) => Some(TapMessage::RfqSellReject(reject)),
                }
            }
            TapMessage::RfqBuyAccept(accept) => {
                // Peer accepted our buy request: validate against the
                // pending request (peer binding + real asset ID).
                let mut rfq = self.rfq.lock().unwrap();
                let _ = rfq.handle_buy_accept(&accept, peer, now);
                None
            }
            TapMessage::RfqSellAccept(accept) => {
                let mut rfq = self.rfq.lock().unwrap();
                let _ = rfq.handle_sell_accept(&accept, peer, now);
                None
            }
            TapMessage::RfqBuyReject(reject)
            | TapMessage::RfqSellReject(reject) => {
                let mut rfq = self.rfq.lock().unwrap();
                let _ = rfq.handle_reject(&reject, peer);
                None
            }
            // Funding messages are handled by the funding controller.
            _ => None,
        }
    }

    /// Looks up a valid (known and unexpired) quote.
    fn valid_quote(
        &self,
        id: &crate::wire::messages::RfqId,
        now: u64,
    ) -> Result<AcceptedQuote, RfqError> {
        let rfq = self.rfq.lock().unwrap();
        let quote =
            rfq.get_quote(id).ok_or(RfqError::QuoteNotFound(*id))?;
        if !quote.is_valid(now) {
            return Err(RfqError::QuoteExpired {
                id: *id,
                expiry: quote.expiry,
                now,
            });
        }
        Ok(quote.clone())
    }

    /// Handles an intercepted HTLC that may be an asset payment.
    ///
    /// Asset HTLCs are only forwarded when they carry a locked-in RFQ
    /// ID that maps to a known, unexpired quote; the forwarded BTC
    /// amount is computed from the quote's rate (with the on-chain
    /// minimum clamp), mirroring Go's `rfqmath` conversion. Anything
    /// else fails back:
    /// - asset HTLC without an RFQ ID
    /// - unknown or expired quote
    /// - rate conversion failure
    /// - HTLC that would push the quote past its negotiated maximum
    ///   amount, cumulatively across in-flight HTLCs (Go
    ///   `CheckHtlcCompliance`, rfq/order.go)
    ///
    /// Forwarded asset HTLCs count against the quote's maximum until
    /// they are resolved; call [`Self::handle_htlc_resolved`] when the
    /// HTLC settles or fails to release the tracked amount (Go
    /// `TrackAcceptedHtlc` / `UntrackHtlc`, rfq/order.go).
    ///
    /// Non-asset HTLCs are forwarded unchanged.
    pub fn handle_intercepted_htlc(
        &self,
        intercept_id: [u8; 32],
        next_hop_scid: u64,
        next_node_id: [u8; 33],
        amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
        now: u64,
    ) -> Result<(), String> {
        let asset_data = AssetHtlcData::from_custom_tlvs(custom_records);

        // Not an asset HTLC — forward normally.
        let asset_data = match asset_data {
            None => {
                return self.ldk.forward_intercepted_htlc(
                    intercept_id,
                    next_hop_scid,
                    next_node_id,
                    amt_msat,
                );
            }
            Some(data) => data,
        };

        // An asset HTLC without a locked-in quote cannot be valued;
        // forwarding it at the original amount would hand out the
        // asset without compensation. Fail it back.
        let rfq_id = match asset_data.rfq_id {
            Some(id) => id,
            None => {
                self.ldk.fail_intercepted_htlc(intercept_id)?;
                return Err("asset HTLC missing RFQ ID".into());
            }
        };

        let quote = match self.valid_quote(&rfq_id, now) {
            Ok(quote) => quote,
            Err(e) => {
                self.ldk.fail_intercepted_htlc(intercept_id)?;
                return Err(format!("asset HTLC quote invalid: {}", e));
            }
        };

        // The msat value of the assets carried by the HTLC. This is
        // the amount counted against the quote's negotiated maximum
        // (Go compares `htlc.AmountOutMsat`, rfq/order.go) and, once
        // clamped to the on-chain minimum, the amount forwarded (same
        // clamp as `compute_htlc_btc_amount`).
        let asset_amount = asset_data.sum_balances();
        let value_msat = if asset_amount == 0 {
            // No asset units in the HTLC: nothing to convert.
            0
        } else {
            match crate::rfq::math::units_to_milli_satoshi(
                asset_amount,
                &quote.rate,
            ) {
                Ok(amt) => amt,
                Err(e) => {
                    self.ldk.fail_intercepted_htlc(intercept_id)?;
                    return Err(format!(
                        "asset HTLC amount conversion failed: {}",
                        e
                    ));
                }
            }
        };
        let adjusted_amt = value_msat.max(DEFAULT_ON_CHAIN_HTLC_MSAT);

        // Enforce the quote's maximum amount cumulatively across
        // in-flight HTLCs (Go `CheckHtlcCompliance`, rfq/order.go).
        // The amount is tracked under the same lock so concurrent
        // HTLCs cannot jointly exceed the cap; it is released again on
        // resolution via [`Self::handle_htlc_resolved`], or below if
        // the forward fails.
        {
            let mut rfq = self.rfq.lock().unwrap();
            if let Err(e) = rfq.check_htlc_amount(&rfq_id, value_msat) {
                drop(rfq);
                self.ldk.fail_intercepted_htlc(intercept_id)?;
                return Err(format!(
                    "asset HTLC exceeds quote max amount: {}",
                    e
                ));
            }
            rfq.track_accepted_htlc(rfq_id, intercept_id, value_msat);
        }

        let result = self.ldk.forward_intercepted_htlc(
            intercept_id,
            next_hop_scid,
            next_node_id,
            adjusted_amt,
        );
        if result.is_err() {
            self.rfq.lock().unwrap().untrack_htlc(&intercept_id);
        }
        result
    }

    /// Releases an intercepted HTLC's contribution to its quote's
    /// cumulative maximum amount once the HTLC is resolved, whether
    /// settled or failed.
    ///
    /// Mirrors Go's `UntrackHtlc` calls from the HTLC settle and fail
    /// event handlers (rfq/order.go). Unknown intercept IDs are
    /// ignored, so this is safe to call for every resolved HTLC.
    pub fn handle_htlc_resolved(&self, intercept_id: [u8; 32]) {
        self.rfq.lock().unwrap().untrack_htlc(&intercept_id);
    }

    /// Prunes expired RFQ quotes and timed-out pending requests.
    pub fn prune_expired_quotes(&self, now: u64) {
        self.rfq.lock().unwrap().prune_expired(now);
    }
}

impl<L, P> AssetTrafficShaper for TapChannelManager<L, P>
where
    L: LdkChannelOps,
    P: crate::rfq::manager::PriceOracle,
{
    fn is_asset_channel(&self, scid: u64) -> bool {
        self.scid_to_channel.lock().unwrap().contains_key(&scid)
    }

    fn payment_bandwidth(
        &self,
        scid: u64,
        _htlc_amt_msat: u64,
    ) -> Result<u64, AssetChannelError> {
        let state = self.channel_state_by_scid(scid).ok_or_else(|| {
            AssetChannelError(format!("no asset channel for scid {}", scid))
        })?;

        // The channel's local asset balance from the latest commitment
        // blob; without a commitment we cannot report any bandwidth.
        let commitment = match state.commitment_blob {
            Some(c) => c,
            None => return Ok(0),
        };

        let rfq = self.rfq.lock().unwrap();
        let mut total_msat: u64 = 0;
        for output in &commitment.local_assets {
            // Find any quote for this asset; without one, the balance
            // cannot be valued in msat (mirrors Go, which requires an
            // RFQ to derive bandwidth).
            let quote = rfq
                .buy_quotes()
                .values()
                .chain(rfq.sell_quotes().values())
                .find(|q| q.asset_id == output.asset_id);
            if let Some(quote) = quote {
                let msat = crate::rfq::math::units_to_milli_satoshi(
                    output.amount,
                    &quote.rate,
                )
                .map_err(|e| {
                    AssetChannelError(format!("bandwidth: {}", e))
                })?;
                total_msat = total_msat.saturating_add(msat);
            }
        }
        Ok(total_msat)
    }

    fn shape_outgoing_htlc(
        &self,
        scid: u64,
        original_amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(u64, Vec<(u64, Vec<u8>)>), AssetChannelError> {
        // An HTLC that already carries asset units (keysend/forward)
        // passes through unchanged (mirrors Go ProduceHtlcExtraData).
        if let Some(existing) =
            AssetHtlcData::from_custom_tlvs(custom_records)
        {
            if existing.sum_balances() > 0 {
                return Ok((original_amt_msat, custom_records.to_vec()));
            }
        }

        let state = self.channel_state_by_scid(scid).ok_or_else(|| {
            AssetChannelError(format!("no asset channel for scid {}", scid))
        })?;
        let primary_asset = state
            .channel_blob
            .funded_assets
            .first()
            .map(|f| f.asset_id)
            .ok_or_else(|| {
                AssetChannelError("channel has no funded assets".into())
            })?;

        // Find a sell quote for the channel's asset (we are paying out
        // BTC value as assets).
        let rfq = self.rfq.lock().unwrap();
        let quote = rfq
            .sell_quotes()
            .values()
            .chain(rfq.buy_quotes().values())
            .find(|q| q.asset_id == primary_asset)
            .cloned()
            .ok_or_else(|| {
                AssetChannelError("no quote available for asset".into())
            })?;
        drop(rfq);

        let asset_amount = crate::rfq::math::milli_satoshi_to_units(
            original_amt_msat,
            &quote.rate,
        )
        .map_err(|e| AssetChannelError(format!("conversion: {}", e)))?;
        if asset_amount == 0 {
            return Err(AssetChannelError(format!(
                "asset rate {} too high to represent {} msat",
                quote.rate, original_amt_msat
            )));
        }

        let data = AssetHtlcData {
            balances: vec![crate::channel::blobs::AssetBalance {
                asset_id: primary_asset,
                amount: asset_amount,
            }],
            rfq_id: Some(quote.id),
        };

        Ok((DEFAULT_ON_CHAIN_HTLC_MSAT, data.to_custom_tlvs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::{AssetBalance, FundedAsset};
    use crate::rfq::{FixedPoint, RfqError};
    use crate::wire::*;
    use std::sync::Mutex as StdMutex;
    use tap_primitives::asset::SerializedKey;

    struct MockLdk {
        forwarded: StdMutex<Vec<(u64, u64)>>, // (scid, amt)
        failed: StdMutex<Vec<[u8; 32]>>,
    }

    impl MockLdk {
        fn new() -> Self {
            MockLdk {
                forwarded: StdMutex::new(Vec::new()),
                failed: StdMutex::new(Vec::new()),
            }
        }
    }

    impl LdkChannelOps for MockLdk {
        fn forward_intercepted_htlc(
            &self,
            _: [u8; 32],
            next_hop_scid: u64,
            _: [u8; 33],
            amt_msat: u64,
        ) -> Result<(), String> {
            self.forwarded
                .lock()
                .unwrap()
                .push((next_hop_scid, amt_msat));
            Ok(())
        }
        fn fail_intercepted_htlc(
            &self,
            intercept_id: [u8; 32],
        ) -> Result<(), String> {
            self.failed.lock().unwrap().push(intercept_id);
            Ok(())
        }
    }

    struct MockOracle;
    impl crate::rfq::manager::PriceOracle for MockOracle {
        fn ask_price(
            &self,
            _: &AssetId,
            _: u64,
        ) -> Result<FixedPoint, RfqError> {
            // 20,000,000 units per BTC = 5000 msat per unit.
            Ok(FixedPoint::new(20_000_000, 0))
        }
        fn bid_price(
            &self,
            _: &AssetId,
            _: u64,
        ) -> Result<FixedPoint, RfqError> {
            // 25,000,000 units per BTC = 4000 msat per unit.
            Ok(FixedPoint::new(25_000_000, 0))
        }
    }

    const NOW: u64 = 1_000_000;

    fn test_blob(asset_byte: u8, amount: u64) -> ChannelBlob {
        ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([asset_byte; 32]),
                amount,
                script_key: SerializedKey([0x02; 33]),
                proof: None,
            }],
            decimal_display: 0,
            group_key: None,
        }
    }

    fn commitment_with_local(
        asset_byte: u8,
        amount: u64,
    ) -> CommitmentBlob {
        CommitmentBlob {
            local_assets: vec![crate::channel::blobs::AssetOutput {
                asset_id: AssetId([asset_byte; 32]),
                amount,
                script_key: SerializedKey([0x02; 33]),
                proof: None,
            }],
            ..CommitmentBlob::default()
        }
    }

    /// Sets up a manager with a stored sell quote and returns the
    /// quote's RFQ ID.
    fn store_quote(
        mgr: &TapChannelManager<MockLdk, MockOracle>,
        asset_byte: u8,
    ) -> crate::wire::messages::RfqId {
        // Incoming buy request from the peer produces a stored quote
        // at the ask rate (20M units/BTC = 5000 msat/unit).
        let req = RfqBuyRequest {
            id: [0x51; 32],
            asset_id: AssetId([asset_byte; 32]),
            asset_max_amount: 10_000,
            asset_group_key: None,
            expiry: NOW + 600,
            rate_hint: None,
        };
        let resp = mgr
            .handle_tap_message(
                [0x02; 33],
                TapMessage::RfqBuyRequest(req),
                NOW,
            )
            .unwrap();
        assert!(matches!(resp, TapMessage::RfqBuyAccept(_)));
        [0x51; 32]
    }

    #[test]
    fn test_register_asset_channel() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        mgr.register_asset_channel(channel_id, test_blob(0xAA, 1000));
        assert!(mgr.get_channel_state(&channel_id).is_some());
    }

    #[test]
    fn test_scid_mapping() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        mgr.register_asset_channel(channel_id, test_blob(0xAA, 1000));
        assert!(!mgr.is_asset_channel(12345));

        mgr.set_channel_scid(&channel_id, 12345);
        assert!(mgr.is_asset_channel(12345));
    }

    #[test]
    fn test_handle_rfq_buy_request() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);

        let msg = TapMessage::RfqBuyRequest(RfqBuyRequest {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 100,
            asset_group_key: None,
            expiry: NOW + 600,
            rate_hint: None,
        });

        let response = mgr.handle_tap_message([0x02; 33], msg, NOW);
        assert!(matches!(response, Some(TapMessage::RfqBuyAccept(_))));
    }

    #[test]
    fn test_buy_accept_records_real_asset_id() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let peer = [0x02; 33];

        // Create a pending outgoing buy request.
        let msg = mgr.request_buy_quote(AssetId([0xEE; 32]), 500, peer, NOW);
        let id = match msg {
            TapMessage::RfqBuyRequest(ref req) => req.id,
            _ => panic!("expected buy request"),
        };
        assert_eq!(mgr.pending_request_is_buy(&id), Some(true));

        // Peer accepts.
        let accept = TapMessage::RfqBuyAccept(RfqBuyAccept {
            id,
            asset_rate: FixedPoint::new(20_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        });
        mgr.handle_tap_message(peer, accept, NOW);

        // The quote carries the REAL asset id from the pending request.
        let quote = mgr.get_quote(&id).unwrap();
        assert_eq!(quote.asset_id, AssetId([0xEE; 32]));
        assert!(quote.is_buy);
        // Pending request consumed.
        assert_eq!(mgr.pending_request_is_buy(&id), None);
    }

    #[test]
    fn test_buy_accept_wrong_peer_ignored() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let peer = [0x02; 33];
        let msg = mgr.request_buy_quote(AssetId([0xEE; 32]), 500, peer, NOW);
        let id = match msg {
            TapMessage::RfqBuyRequest(ref req) => req.id,
            _ => panic!("expected buy request"),
        };

        // A different peer sends the accept: no quote is recorded.
        let accept = TapMessage::RfqBuyAccept(RfqBuyAccept {
            id,
            asset_rate: FixedPoint::new(20_000_000, 0),
            expiry: NOW + 600,
            sig: [0; 64],
            max_in_asset: None,
        });
        mgr.handle_tap_message([0x03; 33], accept, NOW);
        assert!(mgr.get_quote(&id).is_none());
        // The pending request is still there for the real peer.
        assert_eq!(mgr.pending_request_is_buy(&id), Some(true));
    }

    #[test]
    fn test_reject_clears_pending() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let peer = [0x02; 33];
        let msg =
            mgr.request_sell_quote(AssetId([0xDD; 32]), 100_000, peer, NOW);
        let id = match msg {
            TapMessage::RfqSellRequest(ref req) => req.id,
            _ => panic!("expected sell request"),
        };
        assert_eq!(mgr.pending_request_is_buy(&id), Some(false));

        let reject = TapMessage::RfqSellReject(RfqReject {
            id,
            code: crate::wire::compat::RejectCode::PriceOracleUnavailable,
            message: "no".into(),
        });
        mgr.handle_tap_message(peer, reject, NOW);
        assert_eq!(mgr.pending_request_is_buy(&id), None);
    }

    #[test]
    fn test_handle_intercepted_htlc_normal() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);

        mgr.handle_intercepted_htlc(
            [0; 32],
            999,
            [0x02; 33],
            50_000,
            &[], // No custom records — normal HTLC.
            NOW,
        )
        .unwrap();

        // Should forward with original amount.
        let fwd = mgr.ldk.forwarded.lock().unwrap();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0], (999, 50_000));
    }

    #[test]
    fn test_handle_intercepted_htlc_missing_rfq_fails() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);

        let asset_data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 100,
            }],
            rfq_id: None, // No quote.
        };
        let tlvs = asset_data.to_custom_tlvs();

        let res = mgr.handle_intercepted_htlc(
            [0x0A; 32],
            999,
            [0x02; 33],
            50_000,
            &tlvs,
            NOW,
        );
        assert!(res.is_err());
        // Failed back, not forwarded.
        assert!(mgr.ldk.forwarded.lock().unwrap().is_empty());
        assert_eq!(mgr.ldk.failed.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_intercepted_htlc_unknown_quote_fails() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);

        let asset_data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 100,
            }],
            rfq_id: Some([0x99; 32]),
        };
        let res = mgr.handle_intercepted_htlc(
            [0x0B; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_data.to_custom_tlvs(),
            NOW,
        );
        assert!(res.is_err());
        assert_eq!(mgr.ldk.failed.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_intercepted_htlc_with_valid_quote() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);
        let rfq_id = store_quote(&mgr, 0xAA);

        let asset_data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 200,
            }],
            rfq_id: Some(rfq_id),
        };

        mgr.handle_intercepted_htlc(
            [0x0C; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_data.to_custom_tlvs(),
            NOW,
        )
        .unwrap();

        // Forwarded with the CONVERTED amount, not the original:
        // 200 units * 5000 msat/unit = 1,000,000 msat.
        let fwd = mgr.ldk.forwarded.lock().unwrap();
        assert_eq!(fwd[0].1, 1_000_000);
    }

    #[test]
    fn test_handle_intercepted_htlc_expired_quote_fails() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);
        let rfq_id = store_quote(&mgr, 0xAA);

        let asset_data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 200,
            }],
            rfq_id: Some(rfq_id),
        };

        // Way past the quote's expiry (lifetime is 3600s by default).
        let res = mgr.handle_intercepted_htlc(
            [0x0D; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_data.to_custom_tlvs(),
            NOW + 100_000,
        );
        assert!(res.is_err());
        assert_eq!(mgr.ldk.failed.lock().unwrap().len(), 1);
    }

    /// Builds asset HTLC custom TLVs carrying `amount` units of asset
    /// 0xAA locked to the given quote.
    fn asset_tlvs(
        rfq_id: crate::wire::messages::RfqId,
        amount: u64,
    ) -> Vec<(u64, Vec<u8>)> {
        AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount,
            }],
            rfq_id: Some(rfq_id),
        }
        .to_custom_tlvs()
    }

    #[test]
    fn test_handle_intercepted_htlc_at_quote_max_passes() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        // Quote cap: 10,000 units at 5000 msat/unit = 50,000,000 msat.
        let rfq_id = store_quote(&mgr, 0xAA);

        // 10,000 units lands exactly on the cap and is forwarded.
        mgr.handle_intercepted_htlc(
            [0x10; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 10_000),
            NOW,
        )
        .unwrap();

        let fwd = mgr.ldk.forwarded.lock().unwrap();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].1, 50_000_000);
        assert!(mgr.ldk.failed.lock().unwrap().is_empty());
    }

    #[test]
    fn test_handle_intercepted_htlc_over_quote_max_fails() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let rfq_id = store_quote(&mgr, 0xAA);

        // 10,001 units exceed the 10,000-unit (50M msat) cap by one
        // unit and the HTLC is failed back.
        let res = mgr.handle_intercepted_htlc(
            [0x11; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 10_001),
            NOW,
        );
        assert!(res.unwrap_err().contains("max amount"));
        assert!(mgr.ldk.forwarded.lock().unwrap().is_empty());
        assert_eq!(mgr.ldk.failed.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_handle_intercepted_htlc_cumulative_quote_max() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let rfq_id = store_quote(&mgr, 0xAA);

        // Two HTLCs of 6,000 units (30M msat) each against the 50M
        // msat cap: the first fits, the second would sum to 60M msat
        // and is failed back (Go's cumulative CurrentAmountMsat
        // check).
        mgr.handle_intercepted_htlc(
            [0x12; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 6_000),
            NOW,
        )
        .unwrap();

        let res = mgr.handle_intercepted_htlc(
            [0x13; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 6_000),
            NOW,
        );
        assert!(res.unwrap_err().contains("max amount"));
        assert_eq!(mgr.ldk.forwarded.lock().unwrap().len(), 1);
        assert_eq!(mgr.ldk.failed.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_htlc_resolution_releases_quote_amount() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let rfq_id = store_quote(&mgr, 0xAA);

        mgr.handle_intercepted_htlc(
            [0x14; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 6_000),
            NOW,
        )
        .unwrap();

        // Once the first HTLC resolves (settled or failed), its 30M
        // msat is released and a second 6,000-unit HTLC fits again
        // (Go UntrackHtlc on HTLC resolution).
        mgr.handle_htlc_resolved([0x14; 32]);

        mgr.handle_intercepted_htlc(
            [0x15; 32],
            999,
            [0x02; 33],
            50_000,
            &asset_tlvs(rfq_id, 6_000),
            NOW,
        )
        .unwrap();

        assert_eq!(mgr.ldk.forwarded.lock().unwrap().len(), 2);
        assert!(mgr.ldk.failed.lock().unwrap().is_empty());
    }

    #[test]
    fn test_payment_bandwidth_from_commitment() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        mgr.register_asset_channel(channel_id, test_blob(0xAA, 1000));
        mgr.set_channel_scid(&channel_id, 777);
        store_quote(&mgr, 0xAA);

        // No commitment blob yet: zero bandwidth.
        assert_eq!(mgr.payment_bandwidth(777, 0).unwrap(), 0);

        mgr.update_commitment_blob(
            &channel_id,
            commitment_with_local(0xAA, 300),
        )
        .unwrap();

        // 300 units * 5000 msat = 1,500,000 msat.
        assert_eq!(mgr.payment_bandwidth(777, 0).unwrap(), 1_500_000);
    }

    #[test]
    fn test_shape_outgoing_htlc() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        mgr.register_asset_channel(channel_id, test_blob(0xAA, 1000));
        mgr.set_channel_scid(&channel_id, 777);
        let rfq_id = store_quote(&mgr, 0xAA);

        let (amt, records) =
            mgr.shape_outgoing_htlc(777, 500_000, &[]).unwrap();
        // Amount reduced to on-chain minimum.
        assert_eq!(amt, DEFAULT_ON_CHAIN_HTLC_MSAT);
        let data = AssetHtlcData::from_custom_tlvs(&records).unwrap();
        // 500,000 msat at 5000 msat/unit = 100 units.
        assert_eq!(data.balances[0].amount, 100);
        assert_eq!(data.rfq_id, Some(rfq_id));
    }
}
