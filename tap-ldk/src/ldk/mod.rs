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
use crate::config::TapConfig;
use crate::rfq::QuoteManager;
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

    /// Associates an SCID with an asset channel (called after funding
    /// confirms and the channel becomes usable).
    pub fn set_channel_scid(
        &self,
        channel_id: &ChannelId,
        scid: u64,
    ) {
        let mut channels = self.channels.lock().unwrap();
        if let Some(state) = channels.get_mut(channel_id) {
            state.scid = Some(scid);
            self.scid_to_channel
                .lock()
                .unwrap()
                .insert(scid, *channel_id);
        }
    }

    /// Returns true if the given SCID belongs to an asset channel.
    pub fn is_asset_channel(&self, scid: u64) -> bool {
        self.scid_to_channel.lock().unwrap().contains_key(&scid)
    }

    /// Returns the asset channel state for a given channel ID.
    pub fn get_channel_state(
        &self,
        channel_id: &ChannelId,
    ) -> Option<AssetChannelState> {
        self.channels.lock().unwrap().get(channel_id).cloned()
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
                match rfq.handle_buy_request(&req, peer, now, self.config.rfq_quote_lifetime_secs) {
                    Ok(accept) => {
                        Some(TapMessage::RfqBuyAccept(accept))
                    }
                    Err(reject) => {
                        Some(TapMessage::RfqBuyReject(reject))
                    }
                }
            }
            TapMessage::RfqSellRequest(req) => {
                let mut rfq = self.rfq.lock().unwrap();
                match rfq.handle_sell_request(&req, peer, now, self.config.rfq_quote_lifetime_secs) {
                    Ok(accept) => {
                        Some(TapMessage::RfqSellAccept(accept))
                    }
                    Err(reject) => {
                        Some(TapMessage::RfqSellReject(reject))
                    }
                }
            }
            TapMessage::RfqBuyAccept(accept) => {
                // Peer accepted our buy request.
                let mut rfq = self.rfq.lock().unwrap();
                // We need the asset_id — it would be in our pending
                // request. For now just record it.
                rfq.record_buy_accept(
                    &accept,
                    AssetId([0; 32]), // Looked up from pending requests.
                    peer,
                );
                None
            }
            TapMessage::RfqSellAccept(accept) => {
                let mut rfq = self.rfq.lock().unwrap();
                rfq.record_sell_accept(
                    &accept,
                    AssetId([0; 32]),
                    peer,
                );
                None
            }
            // Funding messages would be handled by the funding controller.
            _ => None,
        }
    }

    /// Handles an intercepted HTLC that may be an asset payment.
    ///
    /// If the HTLC carries asset custom records and we have a valid quote,
    /// forwards it with the adjusted BTC amount. Otherwise, forwards
    /// normally.
    pub fn handle_intercepted_htlc(
        &self,
        intercept_id: [u8; 32],
        next_hop_scid: u64,
        next_node_id: [u8; 33],
        amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(), String> {
        // Check if this is an asset payment.
        if let Some(asset_data) =
            crate::routing::AssetHtlcData::from_custom_tlvs(custom_records)
        {
            // Look up the RFQ quote if present.
            let adjusted_amt = if let Some(ref rfq_id) = asset_data.rfq_id {
                let rfq = self.rfq.lock().unwrap();
                if let Some(quote) = rfq.get_quote(rfq_id) {
                    crate::routing::compute_htlc_btc_amount(
                        asset_data.asset_amount,
                        Some(quote),
                    )
                } else {
                    amt_msat // No quote found, forward original amount.
                }
            } else {
                amt_msat
            };

            return self.ldk.forward_intercepted_htlc(
                intercept_id,
                next_hop_scid,
                next_node_id,
                adjusted_amt,
            );
        }

        // Not an asset HTLC — forward normally.
        self.ldk.forward_intercepted_htlc(
            intercept_id,
            next_hop_scid,
            next_node_id,
            amt_msat,
        )
    }

    /// Prunes expired RFQ quotes.
    pub fn prune_expired_quotes(&self, now: u64) {
        self.rfq.lock().unwrap().prune_expired(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::FundedAsset;
    use crate::rfq::{FixedPoint, RfqError};
    use crate::wire::*;
    use tap_primitives::asset::SerializedKey;
    use std::sync::Mutex as StdMutex;

    struct MockLdk {
        forwarded: StdMutex<Vec<(u64, u64)>>, // (scid, amt)
    }

    impl MockLdk {
        fn new() -> Self {
            MockLdk {
                forwarded: StdMutex::new(Vec::new()),
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
        fn fail_intercepted_htlc(&self, _: [u8; 32]) -> Result<(), String> {
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
            Ok(FixedPoint::from_integer(5000))
        }
        fn bid_price(
            &self,
            _: &AssetId,
            _: u64,
        ) -> Result<FixedPoint, RfqError> {
            Ok(FixedPoint::from_integer(4800))
        }
    }

    #[test]
    fn test_register_asset_channel() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        let blob = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };

        mgr.register_asset_channel(channel_id, blob);
        assert!(mgr.get_channel_state(&channel_id).is_some());
    }

    #[test]
    fn test_scid_mapping() {
        let mgr = TapChannelManager::new(MockLdk::new(), MockOracle);
        let channel_id = [0x01; 32];
        let blob = ChannelBlob {
            funded_assets: vec![],
            decimal_display: None,
            group_key: None,
        };

        mgr.register_asset_channel(channel_id, blob);
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
        });

        let response =
            mgr.handle_tap_message([0x02; 33], msg, 1_000_000);
        assert!(matches!(response, Some(TapMessage::RfqBuyAccept(_))));
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
        )
        .unwrap();

        // Should forward with original amount.
        let fwd = mgr.ldk.forwarded.lock().unwrap();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0], (999, 50_000));
    }

    #[test]
    fn test_handle_intercepted_htlc_with_asset() {
        let ldk = MockLdk::new();
        let mgr = TapChannelManager::new(ldk, MockOracle);

        // Create asset HTLC custom records.
        let asset_data = crate::routing::AssetHtlcData {
            asset_id: AssetId([0xAA; 32]),
            asset_amount: 100,
            rfq_id: None, // No quote.
        };
        let tlvs = asset_data.to_custom_tlvs();

        mgr.handle_intercepted_htlc(
            [0; 32],
            999,
            [0x02; 33],
            50_000,
            &tlvs,
        )
        .unwrap();

        // Should forward with original amount (no quote to adjust).
        let fwd = mgr.ldk.forwarded.lock().unwrap();
        assert_eq!(fwd[0].1, 50_000);
    }
}
