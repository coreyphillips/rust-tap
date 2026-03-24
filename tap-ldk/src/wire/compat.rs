// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Go-compatible wire encoding for TAP custom messages.
//!
//! This module implements the exact TLV encoding used by the Go
//! taproot-assets implementation so that messages can be exchanged
//! between Rust and Go Lightning nodes.
//!
//! ## Go Wire Format
//!
//! The Go implementation uses a unified request/accept/reject message
//! type system:
//! - `MsgTypeRequest` (52884): Buy or sell requests
//! - `MsgTypeAccept` (52885): Accept responses
//! - `MsgTypeReject` (52886): Reject responses
//!
//! Each message body is a TLV stream with BigSize varints (big-endian).

use tap_primitives::asset::AssetId;
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

/// Maximum allowed wire message payload size (1 MiB).
///
/// Prevents memory exhaustion from oversized peer messages.
pub const MAX_WIRE_MSG_SIZE: usize = 1024 * 1024;

/// Base offset for TAP custom messages in the Lightning wire protocol.
///
/// Go: `TapMessageTypeBaseOffset = 20116 + lnwire.CustomTypeStart`
/// where `CustomTypeStart = 32768`.
pub const TAP_MSG_BASE_OFFSET: u16 = 20116 + 32768; // = 52884

/// Custom message type for RFQ requests (buy or sell).
pub const MSG_TYPE_REQUEST: u16 = TAP_MSG_BASE_OFFSET;
/// Custom message type for RFQ accept responses.
pub const MSG_TYPE_ACCEPT: u16 = TAP_MSG_BASE_OFFSET + 1;
/// Custom message type for RFQ reject responses.
pub const MSG_TYPE_REJECT: u16 = TAP_MSG_BASE_OFFSET + 2;

/// Transfer types within RFQ requests.
pub const TRANSFER_TYPE_PAY_INVOICE: u8 = 1; // Sell request
pub const TRANSFER_TYPE_RECV_PAYMENT: u8 = 2; // Buy request

/// RFQ request TLV field types (Go-compatible).
pub mod request_tlv {
    pub const VERSION: u64 = 0;
    pub const ID: u64 = 2;
    pub const TRANSFER_TYPE: u64 = 4;
    pub const EXPIRY: u64 = 6;
    pub const IN_ASSET_ID: u64 = 9;
    pub const IN_ASSET_GROUP_KEY: u64 = 11;
    pub const OUT_ASSET_ID: u64 = 13;
    pub const OUT_ASSET_GROUP_KEY: u64 = 15;
    pub const MAX_IN_ASSET: u64 = 16;
    pub const IN_ASSET_RATE_HINT: u64 = 19;
    pub const OUT_ASSET_RATE_HINT: u64 = 21;
}

/// RFQ accept TLV field types (Go-compatible).
pub mod accept_tlv {
    pub const VERSION: u64 = 0;
    pub const ID: u64 = 2;
    pub const EXPIRY: u64 = 4;
    pub const SIG: u64 = 6;
    pub const IN_ASSET_RATE: u64 = 8;
    pub const OUT_ASSET_RATE: u64 = 10;
}

/// RFQ reject TLV field types (Go-compatible).
pub mod reject_tlv {
    pub const VERSION: u64 = 0;
    pub const ID: u64 = 2;
    pub const ERR: u64 = 5;
}

/// HTLC custom record type IDs.
pub const HTLC_AMOUNT_RECORD_TYPE: u64 = 65536;
pub const HTLC_RFQ_ID_TYPE: u64 = 65538;

/// Wire message version.
pub const WIRE_MSG_VERSION_V1: u8 = 1;

/// A 32-byte RFQ message ID (Go uses [32]byte, not u64).
pub use super::messages::RfqId;

/// Encodes a buy request in Go-compatible TLV format.
///
/// This produces bytes identical to Go's `requestWireMsgData.Encode()`.
pub fn encode_buy_request(
    id: &RfqId,
    asset_id: &AssetId,
    max_amount: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut stream = TlvStream::new();

    // Version (required).
    stream.push(TlvRecord::u8(request_tlv::VERSION, WIRE_MSG_VERSION_V1));

    // ID (required, 32 bytes).
    stream.push(TlvRecord::bytes(request_tlv::ID, id));

    // TransferType (required) — buy = RecvPayment = 2.
    stream.push(TlvRecord::u8(
        request_tlv::TRANSFER_TYPE,
        TRANSFER_TYPE_RECV_PAYMENT,
    ));

    // Expiry (required, BigSize varint).
    stream.push(TlvRecord::varint(request_tlv::EXPIRY, expiry));

    // InAssetID (the asset being bought).
    stream.push(TlvRecord::bytes(
        request_tlv::IN_ASSET_ID,
        asset_id.as_bytes(),
    ));

    // OutAssetID = zeros (BTC).
    stream.push(TlvRecord::bytes(
        request_tlv::OUT_ASSET_ID,
        &[0u8; 32],
    ));

    // MaxInAsset (BigSize varint).
    stream.push(TlvRecord::varint(
        request_tlv::MAX_IN_ASSET,
        max_amount,
    ));

    stream.encode()
}

/// Encodes a sell request in Go-compatible TLV format.
pub fn encode_sell_request(
    id: &RfqId,
    asset_id: &AssetId,
    max_msat: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut stream = TlvStream::new();

    stream.push(TlvRecord::u8(request_tlv::VERSION, WIRE_MSG_VERSION_V1));
    stream.push(TlvRecord::bytes(request_tlv::ID, id));
    stream.push(TlvRecord::u8(
        request_tlv::TRANSFER_TYPE,
        TRANSFER_TYPE_PAY_INVOICE,
    ));
    stream.push(TlvRecord::varint(request_tlv::EXPIRY, expiry));

    // InAssetID = zeros (BTC coming in).
    stream.push(TlvRecord::bytes(request_tlv::IN_ASSET_ID, &[0u8; 32]));

    // OutAssetID (the asset being sold).
    stream.push(TlvRecord::bytes(
        request_tlv::OUT_ASSET_ID,
        asset_id.as_bytes(),
    ));

    // MaxInAsset = max BTC amount.
    stream.push(TlvRecord::varint(request_tlv::MAX_IN_ASSET, max_msat));

    stream.encode()
}

/// Encodes a buy accept in Go-compatible TLV format.
pub fn encode_buy_accept(
    id: &RfqId,
    in_asset_rate_msat: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut stream = TlvStream::new();

    stream.push(TlvRecord::u8(accept_tlv::VERSION, WIRE_MSG_VERSION_V1));
    stream.push(TlvRecord::bytes(accept_tlv::ID, id));
    stream.push(TlvRecord::varint(accept_tlv::EXPIRY, expiry));

    // InAssetRate: simplified encoding (just the msat value as varint).
    stream.push(TlvRecord::varint(
        accept_tlv::IN_ASSET_RATE,
        in_asset_rate_msat,
    ));

    // OutAssetRate: MilliSatPerBtc constant (100 * 10^9).
    stream.push(TlvRecord::varint(
        accept_tlv::OUT_ASSET_RATE,
        100_000_000_000,
    ));

    stream.encode()
}

/// Encodes a sell accept in Go-compatible TLV format.
pub fn encode_sell_accept(
    id: &RfqId,
    out_asset_rate_msat: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut stream = TlvStream::new();

    stream.push(TlvRecord::u8(accept_tlv::VERSION, WIRE_MSG_VERSION_V1));
    stream.push(TlvRecord::bytes(accept_tlv::ID, id));
    stream.push(TlvRecord::varint(accept_tlv::EXPIRY, expiry));

    // InAssetRate: MilliSatPerBtc constant.
    stream.push(TlvRecord::varint(
        accept_tlv::IN_ASSET_RATE,
        100_000_000_000,
    ));

    // OutAssetRate: the negotiated rate.
    stream.push(TlvRecord::varint(
        accept_tlv::OUT_ASSET_RATE,
        out_asset_rate_msat,
    ));

    stream.encode()
}

/// Encodes a reject in Go-compatible TLV format.
pub fn encode_reject(id: &RfqId, error_code: u8, message: &str) -> Vec<u8> {
    let mut stream = TlvStream::new();

    stream.push(TlvRecord::u8(reject_tlv::VERSION, WIRE_MSG_VERSION_V1));
    stream.push(TlvRecord::bytes(reject_tlv::ID, id));

    // Err field: error_code(1) + message bytes.
    let mut err_data = vec![error_code];
    err_data.extend_from_slice(message.as_bytes());
    stream.push(TlvRecord::bytes(reject_tlv::ERR, &err_data));

    stream.encode()
}

/// Decodes the message type and RFQ ID from a wire message payload.
///
/// Returns `(version, id, remaining_stream)`.
pub fn decode_msg_header(
    data: &[u8],
) -> Result<(u8, RfqId, TlvStream), String> {
    if data.len() > MAX_WIRE_MSG_SIZE {
        return Err(format!(
            "wire message too large: {} bytes (max {})",
            data.len(),
            MAX_WIRE_MSG_SIZE
        ));
    }

    let stream = TlvStream::decode(data)
        .map_err(|e| format!("TLV decode failed: {}", e))?;

    let version = stream
        .get(0)
        .ok_or("missing version field")?
        .as_u8()
        .map_err(|e| format!("bad version: {}", e))?;

    let id_record = stream.get(2).ok_or("missing ID field")?;
    if id_record.value.len() != 32 {
        return Err(format!(
            "ID field wrong length: {}",
            id_record.value.len()
        ));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_record.value);

    Ok((version, id, stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buy_request_encoding() {
        let id = [0x42; 32];
        let asset_id = AssetId([0xAA; 32]);

        let encoded =
            encode_buy_request(&id, &asset_id, 1000, 1_700_000_000);

        // Should be valid TLV.
        let stream = TlvStream::decode(&encoded).unwrap();

        // Check fields.
        assert_eq!(
            stream.get(request_tlv::VERSION).unwrap().as_u8().unwrap(),
            WIRE_MSG_VERSION_V1
        );
        assert_eq!(stream.get(request_tlv::ID).unwrap().value, id.to_vec());
        assert_eq!(
            stream
                .get(request_tlv::TRANSFER_TYPE)
                .unwrap()
                .as_u8()
                .unwrap(),
            TRANSFER_TYPE_RECV_PAYMENT
        );
        assert_eq!(
            stream
                .get(request_tlv::MAX_IN_ASSET)
                .unwrap()
                .as_varint()
                .unwrap(),
            1000
        );
    }

    #[test]
    fn test_sell_request_encoding() {
        let id = [0x43; 32];
        let asset_id = AssetId([0xBB; 32]);

        let encoded =
            encode_sell_request(&id, &asset_id, 500_000, 1_700_000_000);
        let stream = TlvStream::decode(&encoded).unwrap();

        assert_eq!(
            stream
                .get(request_tlv::TRANSFER_TYPE)
                .unwrap()
                .as_u8()
                .unwrap(),
            TRANSFER_TYPE_PAY_INVOICE
        );
    }

    #[test]
    fn test_accept_encoding() {
        let id = [0x44; 32];
        let encoded = encode_buy_accept(&id, 5000, 1_700_001_000);
        let stream = TlvStream::decode(&encoded).unwrap();

        assert_eq!(
            stream
                .get(accept_tlv::IN_ASSET_RATE)
                .unwrap()
                .as_varint()
                .unwrap(),
            5000
        );
        assert_eq!(
            stream
                .get(accept_tlv::OUT_ASSET_RATE)
                .unwrap()
                .as_varint()
                .unwrap(),
            100_000_000_000
        );
    }

    #[test]
    fn test_reject_encoding() {
        let id = [0x45; 32];
        let encoded = encode_reject(&id, 1, "oracle unavailable");
        let stream = TlvStream::decode(&encoded).unwrap();

        let err = stream.get(reject_tlv::ERR).unwrap();
        assert_eq!(err.value[0], 1); // error code
        assert_eq!(
            std::str::from_utf8(&err.value[1..]).unwrap(),
            "oracle unavailable"
        );
    }

    #[test]
    fn test_decode_msg_header() {
        let id = [0x42; 32];
        let encoded =
            encode_buy_request(&id, &AssetId([0xAA; 32]), 1000, 0);

        let (version, decoded_id, _stream) =
            decode_msg_header(&encoded).unwrap();
        assert_eq!(version, WIRE_MSG_VERSION_V1);
        assert_eq!(decoded_id, id);
    }

    #[test]
    fn test_tlv_records_sorted() {
        let id = [0x42; 32];
        let encoded =
            encode_buy_request(&id, &AssetId([0xAA; 32]), 1000, 0);
        let stream = TlvStream::decode(&encoded).unwrap();

        let types: Vec<u64> =
            stream.records().iter().map(|r| r.type_num).collect();
        let mut sorted = types.clone();
        sorted.sort();
        assert_eq!(types, sorted, "TLV records must be sorted");
    }

    #[test]
    fn test_message_type_constants() {
        assert_eq!(MSG_TYPE_REQUEST, 52884);
        assert_eq!(MSG_TYPE_ACCEPT, 52885);
        assert_eq!(MSG_TYPE_REJECT, 52886);
    }
}
