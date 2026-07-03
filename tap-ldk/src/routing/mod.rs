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
//! The HTLC custom record encoding is byte-compatible with Go's
//! `rfqmsg.Htlc` (`rfqmsg/records.go`).
//!
//! In LDK, this integrates via `Event::HTLCIntercepted` and
//! `ChannelManager::forward_intercepted_htlc`.

use std::collections::HashMap;
use std::sync::Mutex;

use tap_primitives::asset::AssetId;
use tap_primitives::encoding::bigsize::{decode_bigsize, encode_bigsize};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

use crate::channel::blobs::AssetBalance;
use crate::channel::traits::{AssetChannelError, AssetTrafficShaper};
use crate::rfq::math::{
    milli_satoshi_to_units, units_to_milli_satoshi, FixedPointError,
};
use crate::rfq::AcceptedQuote;
use crate::wire::messages::RfqId;

/// Custom TLV type carrying the asset balance list of an HTLC
/// (Go `rfqmsg.HtlcAmountRecordType` = `tlv.TlvType65536`).
pub const HTLC_AMOUNT_RECORD_TYPE: u64 = 65536;
/// Custom TLV type carrying the RFQ ID locked in for an HTLC
/// (Go `rfqmsg.HtlcRfqIDType` = `tlv.TlvType65538`).
pub const HTLC_RFQ_ID_TYPE: u64 = 65538;
/// Custom TLV type carrying the candidate RFQ IDs for an HTLC
/// (Go `rfqmsg.AvailableRfqIDsType` = `tlv.TlvType65540`). Currently
/// tolerated on decode but not modeled.
pub const AVAILABLE_RFQ_IDS_TYPE: u64 = 65540;

/// Maximum number of asset balances allowed in a single HTLC record
/// (Go `rfqmsg.MaxNumOutputs`).
pub const MAX_NUM_BALANCES: u64 = 2048;

/// Minimum on-chain HTLC value in msat for asset channels.
///
/// Matches Go `rfqmath.DefaultOnChainHtlcMSat`, which is
/// `lnwallet.DustLimitForSize(input.UnknownWitnessSize)` = 354 sat.
/// Asset HTLCs use a minimal BTC value since the real value is in the
/// asset amount; the value must be above the dust limit so the HTLC is
/// materialized in an on-chain output the assets can anchor to.
pub const DEFAULT_ON_CHAIN_HTLC_MSAT: u64 = 354_000;

/// Encodes an asset balance list in Go's `AssetBalanceListRecord`
/// format: `varint(count)` followed by, per balance, a varint-length
/// prefixed inner TLV stream `{0: asset_id (32 bytes), 1: amount (u64)}`.
pub fn encode_asset_balance_list(balances: &[AssetBalance]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, balances.len() as u64);
    for balance in balances {
        let mut inner = TlvStream::new();
        inner.push(TlvRecord::bytes(0, &balance.asset_id.0));
        inner.push(TlvRecord::u64(1, balance.amount));
        let encoded = inner.encode();
        encode_bigsize(&mut buf, encoded.len() as u64);
        buf.extend_from_slice(&encoded);
    }
    buf
}

/// Decodes an asset balance list from Go's `AssetBalanceListRecord`
/// format.
pub fn decode_asset_balance_list(
    data: &[u8],
) -> Result<Vec<AssetBalance>, AssetChannelError> {
    let (count, mut offset) = decode_bigsize(data)
        .map_err(|e| AssetChannelError(format!("balance count: {}", e)))?;
    if count > MAX_NUM_BALANCES {
        return Err(AssetChannelError(format!(
            "too many balances: {}",
            count
        )));
    }
    let mut balances = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (len, len_size) = decode_bigsize(&data[offset..])
            .map_err(|e| AssetChannelError(format!("balance len: {}", e)))?;
        offset += len_size;
        let end = offset
            .checked_add(len as usize)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| {
                AssetChannelError("balance entry truncated".into())
            })?;
        let inner = TlvStream::decode(&data[offset..end])
            .map_err(|e| AssetChannelError(format!("balance tlv: {}", e)))?;
        offset = end;

        let id_record = inner.get(0).ok_or_else(|| {
            AssetChannelError("balance missing asset id".into())
        })?;
        if id_record.value.len() != 32 {
            return Err(AssetChannelError(
                "balance asset id must be 32 bytes".into(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_record.value);
        let amount = inner
            .get(1)
            .ok_or_else(|| {
                AssetChannelError("balance missing amount".into())
            })?
            .as_u64()
            .map_err(|e| {
                AssetChannelError(format!("balance amount: {}", e))
            })?;
        balances.push(AssetBalance {
            asset_id: AssetId(id),
            amount,
        });
    }
    if offset != data.len() {
        return Err(AssetChannelError(
            "trailing bytes after balance list".into(),
        ));
    }
    Ok(balances)
}

/// Custom TLV records attached to an asset HTLC, mirroring Go's
/// `rfqmsg.Htlc`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AssetHtlcData {
    /// The asset balances changed by this HTLC (record 65536; omitted
    /// on encode when empty, like Go).
    pub balances: Vec<AssetBalance>,
    /// RFQ quote ID locked in for this payment (record 65538).
    pub rfq_id: Option<RfqId>,
}

impl AssetHtlcData {
    /// Returns the sum of all balance amounts.
    pub fn sum_balances(&self) -> u64 {
        self.balances.iter().map(|b| b.amount).sum()
    }

    /// Encodes as custom TLV records for the HTLC onion payload,
    /// byte-compatible with Go's `Htlc.ToCustomRecords`.
    pub fn to_custom_tlvs(&self) -> Vec<(u64, Vec<u8>)> {
        let mut tlvs = Vec::new();
        if !self.balances.is_empty() {
            tlvs.push((
                HTLC_AMOUNT_RECORD_TYPE,
                encode_asset_balance_list(&self.balances),
            ));
        }
        if let Some(rfq_id) = self.rfq_id {
            tlvs.push((HTLC_RFQ_ID_TYPE, rfq_id.to_vec()));
        }
        tlvs
    }

    /// Encodes as a single TLV blob (Go `Htlc.Bytes`).
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        for (typ, value) in self.to_custom_tlvs() {
            stream.push(TlvRecord::new(typ, value));
        }
        stream.encode()
    }

    /// Decodes from a single TLV blob (Go `rfqmsg.DecodeHtlc`).
    pub fn decode(data: &[u8]) -> Result<Self, AssetChannelError> {
        let stream = TlvStream::decode(data)
            .map_err(|e| AssetChannelError(format!("htlc tlv: {}", e)))?;
        let mut tlvs = Vec::new();
        for record in stream.records() {
            tlvs.push((record.type_num, record.value.clone()));
        }
        Self::from_custom_tlvs(&tlvs).ok_or_else(|| {
            AssetChannelError("no asset HTLC records present".into())
        })
    }

    /// Decodes from custom TLV records. Returns `None` if none of the
    /// asset HTLC record types are present (mirrors Go's
    /// `HasAssetHTLCCustomRecords` gate). Unknown records (including
    /// the available-RFQ-IDs record 65540) are tolerated and ignored.
    pub fn from_custom_tlvs(tlvs: &[(u64, Vec<u8>)]) -> Option<Self> {
        let mut present = false;
        let mut balances = Vec::new();
        let mut rfq_id = None;

        for (typ, val) in tlvs {
            match *typ {
                HTLC_AMOUNT_RECORD_TYPE => {
                    present = true;
                    balances = decode_asset_balance_list(val).ok()?;
                }
                HTLC_RFQ_ID_TYPE if val.len() == 32 => {
                    present = true;
                    let mut id = [0u8; 32];
                    id.copy_from_slice(val);
                    rfq_id = Some(id);
                }
                AVAILABLE_RFQ_IDS_TYPE => {
                    present = true;
                }
                _ => {}
            }
        }

        if !present {
            return None;
        }
        Some(AssetHtlcData { balances, rfq_id })
    }
}

/// Determines the BTC amount to use when forwarding an asset HTLC.
///
/// Converts the asset amount to msat via the quote's rate (asset units
/// per BTC, mirroring Go `rfqmath.UnitsToMilliSatoshi`) and clamps the
/// result to at least [`DEFAULT_ON_CHAIN_HTLC_MSAT`], the same minimum
/// Go's `tapchannel.AuxTrafficShaper` applies.
pub fn compute_htlc_btc_amount(
    asset_amount: u64,
    quote: &AcceptedQuote,
) -> Result<u64, FixedPointError> {
    let msat = units_to_milli_satoshi(asset_amount, &quote.rate)?;
    Ok(msat.max(DEFAULT_ON_CHAIN_HTLC_MSAT))
}

/// Computes the asset amount for an HTLC based on its BTC amount and
/// the applicable quote (Go `rfqmath.MilliSatoshiToUnits`).
pub fn compute_asset_amount(
    btc_msat: u64,
    quote: &AcceptedQuote,
) -> Result<u64, FixedPointError> {
    milli_satoshi_to_units(btc_msat, &quote.rate)
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

        // Convert the local asset balance to a msat-equivalent using
        // the best available quote per asset (mirrors Go
        // paymentBandwidthRFQ, which converts the local balance with
        // UnitsToMilliSatoshi). Assets without a quote contribute zero
        // bandwidth, as their msat value is unknown.
        let quotes = self.quotes.lock().unwrap();
        let mut total_msat: u64 = 0;
        for balance in channel_balances {
            let quote =
                quotes.values().find(|q| q.asset_id == balance.asset_id);
            if let Some(quote) = quote {
                let msat =
                    units_to_milli_satoshi(balance.amount, &quote.rate)
                        .map_err(|e| {
                            AssetChannelError(format!(
                                "bandwidth conversion: {}",
                                e
                            ))
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
        // If the HTLC already has asset custom records with a non-zero
        // asset amount, it is a keysend/forwarded asset HTLC. Mirror Go
        // ProduceHtlcExtraData: keep the original amount and records.
        if let Some(existing) = AssetHtlcData::from_custom_tlvs(custom_records)
        {
            if existing.sum_balances() > 0 {
                return Ok((original_amt_msat, custom_records.to_vec()));
            }
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
        let quote = quotes
            .values()
            .find(|q| q.asset_id == primary.asset_id)
            .ok_or_else(|| {
                AssetChannelError("no quote available for asset".into())
            })?;

        let asset_amount = compute_asset_amount(original_amt_msat, quote)
            .map_err(|e| {
                AssetChannelError(format!("asset conversion: {}", e))
            })?;
        if asset_amount == 0 {
            return Err(AssetChannelError(format!(
                "asset rate {} too high to represent {} msat",
                quote.rate, original_amt_msat
            )));
        }

        let data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: primary.asset_id,
                amount: asset_amount,
            }],
            rfq_id: Some(quote.id),
        };

        // The on-chain BTC amount is reduced to the minimum that can be
        // materialized on chain (Go returns DefaultOnChainHtlcMSat).
        Ok((DEFAULT_ON_CHAIN_HTLC_MSAT, data.to_custom_tlvs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfq::FixedPoint;

    fn quote_with_rate(rate: FixedPoint) -> AcceptedQuote {
        AcceptedQuote {
            id: [0x01; 32],
            asset_id: AssetId([0xAA; 32]),
            rate,
            expiry: u64::MAX,
            peer: [0x02; 33],
            is_buy: true,
            max_amount_msat: u64::MAX,
        }
    }

    #[test]
    fn test_asset_htlc_data_roundtrip() {
        let data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
            }],
            rfq_id: Some([0x42; 32]),
        };

        let tlvs = data.to_custom_tlvs();
        let decoded = AssetHtlcData::from_custom_tlvs(&tlvs).unwrap();
        assert_eq!(data, decoded);

        let blob = data.encode();
        let decoded2 = AssetHtlcData::decode(&blob).unwrap();
        assert_eq!(data, decoded2);
    }

    #[test]
    fn test_asset_htlc_data_no_rfq() {
        let data = AssetHtlcData {
            balances: vec![AssetBalance {
                asset_id: AssetId([0xBB; 32]),
                amount: 500,
            }],
            rfq_id: None,
        };

        let tlvs = data.to_custom_tlvs();
        assert_eq!(tlvs.len(), 1); // No RFQ TLV.
        let decoded = AssetHtlcData::from_custom_tlvs(&tlvs).unwrap();
        assert_eq!(decoded.rfq_id, None);
    }

    #[test]
    fn test_asset_htlc_data_multiple_balances() {
        let data = AssetHtlcData {
            balances: vec![
                AssetBalance {
                    asset_id: AssetId([0xAA; 32]),
                    amount: 1,
                },
                AssetBalance {
                    asset_id: AssetId([0xBB; 32]),
                    amount: u64::MAX,
                },
            ],
            rfq_id: Some([0x42; 32]),
        };
        let blob = data.encode();
        assert_eq!(AssetHtlcData::decode(&blob).unwrap(), data);
    }

    #[test]
    fn test_from_custom_tlvs_non_asset() {
        // Unrelated records only: not an asset HTLC.
        let tlvs = vec![(1234u64, vec![0x01])];
        assert!(AssetHtlcData::from_custom_tlvs(&tlvs).is_none());
    }

    #[test]
    fn test_htlc_record_type_constants() {
        // Verified against Go rfqmsg/records.go.
        assert_eq!(HTLC_AMOUNT_RECORD_TYPE, 65536);
        assert_eq!(HTLC_RFQ_ID_TYPE, 65538);
        assert_eq!(AVAILABLE_RFQ_IDS_TYPE, 65540);
    }

    #[test]
    fn test_compute_htlc_btc_amount_with_quote() {
        // 20,000,000 units per BTC: 1 unit = 5000 msat.
        let quote = quote_with_rate(FixedPoint::new(20_000_000, 0));

        // 200 units * 5000 msat = 1,000,000 msat (above minimum).
        let amt = compute_htlc_btc_amount(200, &quote).unwrap();
        assert_eq!(amt, 1_000_000);
    }

    #[test]
    fn test_compute_htlc_btc_amount_below_minimum() {
        // 10,000,000,000 units per BTC: 1 unit = 10 msat.
        let quote = quote_with_rate(FixedPoint::new(10_000_000_000, 0));

        // 1 unit * 10 msat = 10 msat, clamped to the 354 sat minimum.
        let amt = compute_htlc_btc_amount(1, &quote).unwrap();
        assert_eq!(amt, DEFAULT_ON_CHAIN_HTLC_MSAT);
    }

    #[test]
    fn test_compute_asset_amount() {
        let quote = quote_with_rate(FixedPoint::new(20_000_000, 0));
        // 500,000 msat at 5000 msat/unit = 100 units.
        let units = compute_asset_amount(500_000, &quote).unwrap();
        assert_eq!(units, 100);
    }

    #[test]
    fn test_traffic_shaper_is_asset_channel() {
        let shaper = TapAssetTrafficShaper::new();
        assert!(!shaper.is_asset_channel(100));

        shaper.register_channel(
            100,
            vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 500,
            }],
        );
        assert!(shaper.is_asset_channel(100));
        assert!(!shaper.is_asset_channel(200));
    }

    #[test]
    fn test_traffic_shaper_bandwidth() {
        let shaper = TapAssetTrafficShaper::new();
        shaper.register_channel(
            100,
            vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 200,
            }],
        );

        shaper.register_quote(quote_with_rate(FixedPoint::new(
            20_000_000, 0,
        )));

        // 200 units * 5000 msat = 1,000,000 msat.
        let bw = shaper.payment_bandwidth(100, 0).unwrap();
        assert_eq!(bw, 1_000_000);
    }

    #[test]
    fn test_traffic_shaper_bandwidth_no_quote() {
        let shaper = TapAssetTrafficShaper::new();
        shaper.register_channel(
            100,
            vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 200,
            }],
        );
        // No quote: unknown value, zero bandwidth.
        assert_eq!(shaper.payment_bandwidth(100, 0).unwrap(), 0);
    }

    #[test]
    fn test_shape_outgoing_htlc() {
        let shaper = TapAssetTrafficShaper::new();
        shaper.register_channel(
            100,
            vec![AssetBalance {
                asset_id: AssetId([0xAA; 32]),
                amount: 10_000,
            }],
        );
        shaper.register_quote(quote_with_rate(FixedPoint::new(
            20_000_000, 0,
        )));

        // 500,000 msat -> 100 units, amount reduced to the on-chain
        // minimum.
        let (amt, records) =
            shaper.shape_outgoing_htlc(100, 500_000, &[]).unwrap();
        assert_eq!(amt, DEFAULT_ON_CHAIN_HTLC_MSAT);
        let data = AssetHtlcData::from_custom_tlvs(&records).unwrap();
        assert_eq!(data.balances.len(), 1);
        assert_eq!(data.balances[0].amount, 100);
        assert_eq!(data.rfq_id, Some([0x01; 32]));
    }
}
