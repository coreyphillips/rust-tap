// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Traffic shaping and HTLC interception for asset channels.
//!
//! This module provides the logic for:
//! - Determining whether an HTLC should be handled as an asset payment
//! - Calculating available bandwidth on asset channels
//! - Producing custom TLV records for asset HTLCs
//! - Modifying BTC amounts based on exchange rates
//!
//! In LDK, this integrates via `Event::HTLCIntercepted` and
//! `ChannelManager::forward_intercepted_htlc`.

use std::collections::HashMap;
use std::sync::Mutex;

use tap_primitives::asset::AssetId;
use crate::channel::blobs::AssetBalance;
use crate::channel::traits::{AssetChannelError, AssetTrafficShaper};
use crate::rfq::AcceptedQuote;
use crate::wire::messages::RfqId;

/// Custom TLV type for asset ID in HTLC onion payload.
pub const HTLC_ASSET_ID_TYPE: u64 = 0xFFFF_0001;
/// Custom TLV type for asset amount in HTLC onion payload.
pub const HTLC_ASSET_AMOUNT_TYPE: u64 = 0xFFFF_0003;
/// Custom TLV type for RFQ ID in HTLC onion payload.
pub const HTLC_RFQ_ID_TYPE: u64 = 0xFFFF_0005;

/// Minimum on-chain HTLC value in msat for asset channels.
///
/// Asset HTLCs use a minimal BTC value since the real value is in the
/// asset amount. This must be above dust limit.
pub const DEFAULT_ON_CHAIN_HTLC_MSAT: u64 = 550_000; // 550 sat

/// Custom TLV records attached to an asset HTLC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetHtlcData {
    /// The asset being transferred.
    pub asset_id: AssetId,
    /// Asset amount in this HTLC.
    pub asset_amount: u64,
    /// RFQ quote ID used for this payment (32 bytes, Go-compatible).
    pub rfq_id: Option<RfqId>,
}

impl AssetHtlcData {
    /// Encodes as custom TLV records for HTLC onion payload.
    pub fn to_custom_tlvs(&self) -> Vec<(u64, Vec<u8>)> {
        let mut tlvs = Vec::new();
        tlvs.push((HTLC_ASSET_ID_TYPE, self.asset_id.0.to_vec()));
        tlvs.push((
            HTLC_ASSET_AMOUNT_TYPE,
            self.asset_amount.to_be_bytes().to_vec(),
        ));
        if let Some(rfq_id) = self.rfq_id {
            tlvs.push((HTLC_RFQ_ID_TYPE, rfq_id.to_vec()));
        }
        tlvs
    }

    /// Decodes from custom TLV records.
    pub fn from_custom_tlvs(
        tlvs: &[(u64, Vec<u8>)],
    ) -> Option<Self> {
        let mut asset_id = None;
        let mut asset_amount = None;
        let mut rfq_id = None;

        for (typ, val) in tlvs {
            match *typ {
                HTLC_ASSET_ID_TYPE if val.len() == 32 => {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(val);
                    asset_id = Some(AssetId(id));
                }
                HTLC_ASSET_AMOUNT_TYPE if val.len() == 8 => {
                    asset_amount = Some(u64::from_be_bytes(
                        val[..8].try_into().unwrap(),
                    ));
                }
                HTLC_RFQ_ID_TYPE if val.len() == 32 => {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(val);
                    rfq_id = Some(id);
                }
                _ => {}
            }
        }

        Some(AssetHtlcData {
            asset_id: asset_id?,
            asset_amount: asset_amount?,
            rfq_id,
        })
    }
}

/// Determines the BTC amount to use for an asset HTLC.
///
/// For asset payments, the on-chain BTC amount is set to a minimal value
/// (above dust) since the real value is in the asset. The actual BTC amount
/// exchanged at the edge node is determined by the RFQ quote.
pub fn compute_htlc_btc_amount(
    asset_amount: u64,
    quote: Option<&AcceptedQuote>,
) -> u64 {
    match quote {
        Some(q) => {
            let msat = q.price.asset_to_msat(asset_amount);
            // Ensure we're above the minimum.
            std::cmp::max(msat, DEFAULT_ON_CHAIN_HTLC_MSAT)
        }
        // No quote — use minimum on-chain value.
        None => DEFAULT_ON_CHAIN_HTLC_MSAT,
    }
}

/// Computes the asset amount for an incoming HTLC based on its BTC amount
/// and the applicable quote.
pub fn compute_incoming_asset_amount(
    btc_msat: u64,
    quote: &AcceptedQuote,
) -> u64 {
    quote.price.msat_to_asset(btc_msat)
}

/// Concrete implementation of [`AssetTrafficShaper`].
///
/// Determines whether HTLCs should be routed as asset payments and
/// shapes outgoing HTLCs with asset-specific custom TLV records.
pub struct TapAssetTrafficShaper {
    /// Asset channel balances keyed by SCID.
    channel_balances: Mutex<HashMap<u64, Vec<AssetBalance>>>,
    /// Accepted quotes keyed by RFQ ID. Shared with the quote manager.
    quotes: Mutex<HashMap<RfqId, AcceptedQuote>>,
}

impl TapAssetTrafficShaper {
    /// Creates a new traffic shaper.
    pub fn new() -> Self {
        TapAssetTrafficShaper {
            channel_balances: Mutex::new(HashMap::new()),
            quotes: Mutex::new(HashMap::new()),
        }
    }

    /// Registers an asset channel with its current balances.
    pub fn register_channel(&self, scid: u64, balances: Vec<AssetBalance>) {
        self.channel_balances.lock().unwrap().insert(scid, balances);
    }

    /// Updates a channel's balances.
    pub fn update_balances(&self, scid: u64, balances: Vec<AssetBalance>) {
        self.channel_balances.lock().unwrap().insert(scid, balances);
    }

    /// Registers an accepted quote for use in traffic shaping.
    pub fn register_quote(&self, quote: AcceptedQuote) {
        self.quotes.lock().unwrap().insert(quote.id, quote);
    }
}

impl Default for TapAssetTrafficShaper {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetTrafficShaper for TapAssetTrafficShaper {
    fn is_asset_channel(&self, scid: u64) -> bool {
        self.channel_balances.lock().unwrap().contains_key(&scid)
    }

    fn payment_bandwidth(
        &self,
        scid: u64,
        _htlc_amt_msat: u64,
    ) -> Result<u64, AssetChannelError> {
        let balances = self.channel_balances.lock().unwrap();
        let channel_balances = balances.get(&scid).ok_or_else(|| {
            AssetChannelError(format!("no asset channel for scid {}", scid))
        })?;

        // Sum all asset balances and convert to msat-equivalent using
        // the best available quote. If no quote is available, use the
        // default minimum HTLC value as a conservative estimate.
        let quotes = self.quotes.lock().unwrap();
        let total_msat: u64 = channel_balances
            .iter()
            .map(|b| {
                // Find a quote for this asset.
                let quote = quotes.values().find(|q| q.asset_id == b.asset_id);
                compute_htlc_btc_amount(b.amount, quote)
            })
            .sum();

        Ok(total_msat)
    }

    fn shape_outgoing_htlc(
        &self,
        scid: u64,
        original_amt_msat: u64,
        custom_records: &[(u64, Vec<u8>)],
    ) -> Result<(u64, Vec<(u64, Vec<u8>)>), AssetChannelError> {
        // If the HTLC already has asset custom records, pass through.
        if let Some(existing) = AssetHtlcData::from_custom_tlvs(custom_records) {
            let quote = existing.rfq_id.as_ref().and_then(|id| {
                self.quotes.lock().unwrap().get(id).cloned()
            });
            let adjusted = compute_htlc_btc_amount(existing.asset_amount, quote.as_ref());
            return Ok((adjusted, custom_records.to_vec()));
        }

        // For a channel without existing asset records, check if it's an
        // asset channel and produce asset TLV records.
        let balances = self.channel_balances.lock().unwrap();
        let channel_balances = balances.get(&scid).ok_or_else(|| {
            AssetChannelError(format!("no asset channel for scid {}", scid))
        })?;

        if channel_balances.is_empty() {
            return Ok((original_amt_msat, custom_records.to_vec()));
        }

        // Use the first asset in the channel for routing.
        let primary = &channel_balances[0];

        // Find a quote for conversion.
        let quotes = self.quotes.lock().unwrap();
        let quote = quotes.values().find(|q| q.asset_id == primary.asset_id);

        let asset_amount = match quote {
            Some(q) => compute_incoming_asset_amount(original_amt_msat, q),
            None => return Err(AssetChannelError("no quote available for asset".into())),
        };

        let rfq_id = quote.map(|q| q.id);
        let data = AssetHtlcData {
            asset_id: primary.asset_id,
            asset_amount,
            rfq_id,
        };

        let adjusted = compute_htlc_btc_amount(asset_amount, quote);
        Ok((adjusted, data.to_custom_tlvs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfq::FixedPoint;

    #[test]
    fn test_asset_htlc_data_roundtrip() {
        let data = AssetHtlcData {
            asset_id: AssetId([0xAA; 32]),
            asset_amount: 1000,
            rfq_id: Some([0x42; 32]),
        };

        let tlvs = data.to_custom_tlvs();
        let decoded = AssetHtlcData::from_custom_tlvs(&tlvs).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_asset_htlc_data_no_rfq() {
        let data = AssetHtlcData {
            asset_id: AssetId([0xBB; 32]),
            asset_amount: 500,
            rfq_id: None,
        };

        let tlvs = data.to_custom_tlvs();
        assert_eq!(tlvs.len(), 2); // No RFQ TLV.
        let decoded = AssetHtlcData::from_custom_tlvs(&tlvs).unwrap();
        assert_eq!(decoded.rfq_id, None);
    }

    #[test]
    fn test_compute_htlc_btc_amount_with_quote() {
        let quote = AcceptedQuote {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            price: FixedPoint::from_integer(5000), // 5000 msat/unit
            expiry: u64::MAX,
            peer: [0x02; 33],
            is_buy: true,
        };

        // 200 units * 5000 msat = 1,000,000 msat (above minimum).
        let amt = compute_htlc_btc_amount(200, Some(&quote));
        assert_eq!(amt, 1_000_000);
    }

    #[test]
    fn test_compute_htlc_btc_amount_below_minimum() {
        let quote = AcceptedQuote {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            price: FixedPoint::from_integer(10), // 10 msat/unit
            expiry: u64::MAX,
            peer: [0x02; 33],
            is_buy: true,
        };

        // 1 unit * 10 msat = 10 msat, but minimum is 550,000.
        let amt = compute_htlc_btc_amount(1, Some(&quote));
        assert_eq!(amt, DEFAULT_ON_CHAIN_HTLC_MSAT);
    }

    #[test]
    fn test_compute_htlc_btc_amount_no_quote() {
        let amt = compute_htlc_btc_amount(1000, None);
        assert_eq!(amt, DEFAULT_ON_CHAIN_HTLC_MSAT);
    }

    #[test]
    fn test_compute_incoming_asset_amount() {
        let quote = AcceptedQuote {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            price: FixedPoint::from_integer(5000),
            expiry: u64::MAX,
            peer: [0x02; 33],
            is_buy: false,
        };

        // 500,000 msat / 5000 = 100 units.
        let units = compute_incoming_asset_amount(500_000, &quote);
        assert_eq!(units, 100);
    }

    #[test]
    fn test_traffic_shaper_is_asset_channel() {
        let shaper = TapAssetTrafficShaper::new();
        assert!(!shaper.is_asset_channel(100));

        shaper.register_channel(100, vec![AssetBalance {
            asset_id: AssetId([0xAA; 32]),
            amount: 500,
        }]);
        assert!(shaper.is_asset_channel(100));
        assert!(!shaper.is_asset_channel(200));
    }

    #[test]
    fn test_traffic_shaper_bandwidth() {
        let shaper = TapAssetTrafficShaper::new();
        shaper.register_channel(100, vec![AssetBalance {
            asset_id: AssetId([0xAA; 32]),
            amount: 200,
        }]);

        let quote = AcceptedQuote {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            price: FixedPoint::from_integer(5000),
            expiry: u64::MAX,
            peer: [0x02; 33],
            is_buy: true,
        };
        shaper.register_quote(quote);

        // 200 units * 5000 msat = 1,000,000 msat.
        let bw = shaper.payment_bandwidth(100, 0).unwrap();
        assert_eq!(bw, 1_000_000);
    }
}
