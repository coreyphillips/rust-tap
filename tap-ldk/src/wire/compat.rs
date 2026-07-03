// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Go-compatible wire encoding for TAP RFQ messages.
//!
//! This module implements the exact TLV encoding used by the Go
//! taproot-assets implementation (`rfqmsg/{messages,request,accept,
//! reject,records}.go`) so that messages can be exchanged between Rust
//! and Go Lightning nodes.
//!
//! The Go implementation uses a unified request/accept/reject message
//! type system:
//! - `MsgTypeRequest` (52884): buy or sell requests
//! - `MsgTypeAccept` (52885): accept responses
//! - `MsgTypeReject` (52886): reject responses
//!
//! Each message body is a TLV stream (BigSize type/length, big-endian
//! values). All TLV type numbers below were verified against Go
//! `rfqmsg/request.go`, `accept.go` and `reject.go`.

use tap_primitives::asset::AssetId;
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

use crate::rfq::math::FixedPoint;

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

/// Transfer types within RFQ requests (Go `rfqmsg.TransferType`).
pub const TRANSFER_TYPE_UNSPECIFIED: u8 = 0;
/// Requesting peer wants to pay an invoice with assets (sell request).
pub const TRANSFER_TYPE_PAY_INVOICE: u8 = 1;
/// Requesting peer wants to receive assets (buy request).
pub const TRANSFER_TYPE_RECV_PAYMENT: u8 = 2;

/// RFQ request TLV field types (verified against Go `rfqmsg/request.go`).
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
    pub const MIN_IN_ASSET: u64 = 23;
    pub const MIN_OUT_ASSET: u64 = 25;
    pub const PRICE_ORACLE_METADATA: u64 = 27;
    pub const ASSET_RATE_LIMIT: u64 = 29;
    pub const EXECUTION_POLICY: u64 = 31;
}

/// RFQ accept TLV field types (verified against Go `rfqmsg/accept.go`).
pub mod accept_tlv {
    pub const VERSION: u64 = 0;
    pub const ID: u64 = 2;
    pub const EXPIRY: u64 = 4;
    pub const SIG: u64 = 6;
    pub const IN_ASSET_RATE: u64 = 8;
    pub const OUT_ASSET_RATE: u64 = 10;
    pub const MAX_IN_ASSET: u64 = 11;
}

/// RFQ reject TLV field types (verified against Go `rfqmsg/reject.go`).
pub mod reject_tlv {
    pub const VERSION: u64 = 0;
    pub const ID: u64 = 2;
    pub const ERR: u64 = 5;
}

/// Wire message version (Go `rfqmsg.V1`).
pub const WIRE_MSG_VERSION_V1: u8 = 1;

/// Maximum length of the price oracle metadata field (Go
/// `rfqmsg.MaxOracleMetadataLength`).
pub const MAX_ORACLE_METADATA_LENGTH: usize = 32_768;

/// A 32-byte RFQ message ID (Go uses [32]byte, not u64).
pub use super::messages::RfqId;

/// Errors from Go-compatible wire encoding/decoding.
#[derive(Debug, Clone)]
pub enum WireError {
    /// The TLV stream could not be decoded.
    Tlv(String),
    /// A required record is missing.
    MissingRecord(u64),
    /// A record has an invalid length or value.
    InvalidRecord { type_num: u64, msg: String },
    /// The message version is not supported.
    UnsupportedVersion(u8),
    /// The transfer type is unknown.
    UnknownTransferType(u8),
    /// The message is too large.
    MessageTooLarge(usize),
    /// No pending outgoing request matches the message ID (needed to
    /// discriminate buy vs sell accepts, mirrors Go's SessionLookup).
    UnknownSession(RfqId),
    /// The message type is unknown.
    UnknownMessageType(u16),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Tlv(msg) => write!(f, "TLV error: {}", msg),
            WireError::MissingRecord(t) => {
                write!(f, "missing required TLV record {}", t)
            }
            WireError::InvalidRecord { type_num, msg } => {
                write!(f, "invalid TLV record {}: {}", type_num, msg)
            }
            WireError::UnsupportedVersion(v) => {
                write!(f, "unsupported wire message version: {}", v)
            }
            WireError::UnknownTransferType(t) => {
                write!(f, "unknown transfer type: {}", t)
            }
            WireError::MessageTooLarge(n) => {
                write!(f, "wire message too large: {} bytes", n)
            }
            WireError::UnknownSession(id) => {
                write!(f, "no outgoing request found for ID {:02x?}", id)
            }
            WireError::UnknownMessageType(t) => {
                write!(f, "unknown message type: {}", t)
            }
        }
    }
}

impl std::error::Error for WireError {}

/// Reject error codes (Go `rfqmsg.RejectCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    /// Rejected without further detail.
    PriceOracleUnspecified,
    /// A price oracle was unavailable.
    PriceOracleUnavailable,
    /// The minimum fill constraint could not be satisfied.
    MinFillNotMet,
    /// The accepted rate violated the requester's rate limit.
    PriceBoundMiss,
    /// The FOK execution policy could not be satisfied.
    FokNotViable,
    /// The negotiated fill exceeds the requester's maximum.
    FillExceedsMax,
    /// An unknown code (forward compatible).
    Unknown(u8),
}

impl RejectCode {
    /// Returns the wire byte for this code.
    pub fn to_u8(self) -> u8 {
        match self {
            RejectCode::PriceOracleUnspecified => 0,
            RejectCode::PriceOracleUnavailable => 1,
            RejectCode::MinFillNotMet => 2,
            RejectCode::PriceBoundMiss => 3,
            RejectCode::FokNotViable => 4,
            RejectCode::FillExceedsMax => 5,
            RejectCode::Unknown(c) => c,
        }
    }

    /// Parses a wire byte into a reject code.
    pub fn from_u8(c: u8) -> Self {
        match c {
            0 => RejectCode::PriceOracleUnspecified,
            1 => RejectCode::PriceOracleUnavailable,
            2 => RejectCode::MinFillNotMet,
            3 => RejectCode::PriceBoundMiss,
            4 => RejectCode::FokNotViable,
            5 => RejectCode::FillExceedsMax,
            other => RejectCode::Unknown(other),
        }
    }
}

// --- helpers ---

fn get_bytes32(
    stream: &TlvStream,
    type_num: u64,
) -> Result<Option<[u8; 32]>, WireError> {
    match stream.get(type_num) {
        None => Ok(None),
        Some(r) => {
            if r.value.len() != 32 {
                return Err(WireError::InvalidRecord {
                    type_num,
                    msg: format!("expected 32 bytes, got {}", r.value.len()),
                });
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&r.value);
            Ok(Some(out))
        }
    }
}

fn get_bytes33(
    stream: &TlvStream,
    type_num: u64,
) -> Result<Option<[u8; 33]>, WireError> {
    match stream.get(type_num) {
        None => Ok(None),
        Some(r) => {
            if r.value.len() != 33 {
                return Err(WireError::InvalidRecord {
                    type_num,
                    msg: format!("expected 33 bytes, got {}", r.value.len()),
                });
            }
            let mut out = [0u8; 33];
            out.copy_from_slice(&r.value);
            Ok(Some(out))
        }
    }
}

fn get_u64(
    stream: &TlvStream,
    type_num: u64,
) -> Result<Option<u64>, WireError> {
    match stream.get(type_num) {
        None => Ok(None),
        Some(r) => r
            .as_u64()
            .map(Some)
            .map_err(|e| WireError::InvalidRecord {
                type_num,
                msg: e.to_string(),
            }),
    }
}

fn get_fixed_point(
    stream: &TlvStream,
    type_num: u64,
) -> Result<Option<FixedPoint>, WireError> {
    match stream.get(type_num) {
        None => Ok(None),
        Some(r) => FixedPoint::decode_tlv(&r.value).map(Some).map_err(|e| {
            WireError::InvalidRecord {
                type_num,
                msg: e.to_string(),
            }
        }),
    }
}

fn require<T>(v: Option<T>, type_num: u64) -> Result<T, WireError> {
    v.ok_or(WireError::MissingRecord(type_num))
}

fn decode_stream(data: &[u8]) -> Result<TlvStream, WireError> {
    if data.len() > MAX_WIRE_MSG_SIZE {
        return Err(WireError::MessageTooLarge(data.len()));
    }
    TlvStream::decode(data).map_err(|e| WireError::Tlv(e.to_string()))
}

// --- Request ---

/// Wire-level RFQ request (Go `requestWireMsgData`).
///
/// All optional records are encoded only when set; unknown odd records
/// are tolerated on decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestWireMsg {
    /// Message data version (type 0).
    pub version: u8,
    /// Unique request ID (type 2).
    pub id: RfqId,
    /// Transfer type (type 4): 1 = pay invoice (sell), 2 = receive
    /// payment (buy).
    pub transfer_type: u8,
    /// Unix expiry timestamp in seconds (type 6, 8-byte u64).
    pub expiry: u64,
    /// Inbound asset ID (type 9); all zeros indicates BTC.
    pub in_asset_id: Option<[u8; 32]>,
    /// Inbound asset group key (type 11, 33 bytes).
    pub in_asset_group_key: Option<[u8; 33]>,
    /// Outbound asset ID (type 13); all zeros indicates BTC.
    pub out_asset_id: Option<[u8; 32]>,
    /// Outbound asset group key (type 15, 33 bytes).
    pub out_asset_group_key: Option<[u8; 33]>,
    /// Maximum in-asset quantity (type 16, 8-byte u64).
    pub max_in_asset: u64,
    /// Optional in-asset to BTC rate hint (type 19, TlvFixedPoint).
    pub in_asset_rate_hint: Option<FixedPoint>,
    /// Optional out-asset to BTC rate hint (type 21, TlvFixedPoint).
    pub out_asset_rate_hint: Option<FixedPoint>,
    /// Optional minimum in-asset quantity (type 23, u64).
    pub min_in_asset: Option<u64>,
    /// Optional minimum out-asset quantity (type 25, u64).
    pub min_out_asset: Option<u64>,
    /// Optional price oracle metadata (type 27, bytes).
    pub price_oracle_metadata: Option<Vec<u8>>,
    /// Optional asset rate limit (type 29, TlvFixedPoint).
    pub asset_rate_limit: Option<FixedPoint>,
    /// Optional execution policy (type 31, u8): 0 = IOC, 1 = FOK.
    pub execution_policy: Option<u8>,
}

impl RequestWireMsg {
    /// Encodes to Go-compatible TLV bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if let Some(ref meta) = self.price_oracle_metadata {
            if meta.len() > MAX_ORACLE_METADATA_LENGTH {
                return Err(WireError::InvalidRecord {
                    type_num: request_tlv::PRICE_ORACLE_METADATA,
                    msg: format!(
                        "oracle metadata too long: {} bytes",
                        meta.len()
                    ),
                });
            }
        }

        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(request_tlv::VERSION, self.version));
        stream.push(TlvRecord::bytes(request_tlv::ID, &self.id));
        stream.push(TlvRecord::u8(
            request_tlv::TRANSFER_TYPE,
            self.transfer_type,
        ));
        stream.push(TlvRecord::u64(request_tlv::EXPIRY, self.expiry));
        if let Some(ref id) = self.in_asset_id {
            stream.push(TlvRecord::bytes(request_tlv::IN_ASSET_ID, id));
        }
        if let Some(ref gk) = self.in_asset_group_key {
            stream.push(TlvRecord::bytes(request_tlv::IN_ASSET_GROUP_KEY, gk));
        }
        if let Some(ref id) = self.out_asset_id {
            stream.push(TlvRecord::bytes(request_tlv::OUT_ASSET_ID, id));
        }
        if let Some(ref gk) = self.out_asset_group_key {
            stream
                .push(TlvRecord::bytes(request_tlv::OUT_ASSET_GROUP_KEY, gk));
        }
        stream.push(TlvRecord::u64(
            request_tlv::MAX_IN_ASSET,
            self.max_in_asset,
        ));
        if let Some(ref fp) = self.in_asset_rate_hint {
            stream.push(TlvRecord::bytes(
                request_tlv::IN_ASSET_RATE_HINT,
                &fp.encode_tlv(),
            ));
        }
        if let Some(ref fp) = self.out_asset_rate_hint {
            stream.push(TlvRecord::bytes(
                request_tlv::OUT_ASSET_RATE_HINT,
                &fp.encode_tlv(),
            ));
        }
        if let Some(min) = self.min_in_asset {
            stream.push(TlvRecord::u64(request_tlv::MIN_IN_ASSET, min));
        }
        if let Some(min) = self.min_out_asset {
            stream.push(TlvRecord::u64(request_tlv::MIN_OUT_ASSET, min));
        }
        if let Some(ref meta) = self.price_oracle_metadata {
            stream.push(TlvRecord::bytes(
                request_tlv::PRICE_ORACLE_METADATA,
                meta,
            ));
        }
        if let Some(ref fp) = self.asset_rate_limit {
            stream.push(TlvRecord::bytes(
                request_tlv::ASSET_RATE_LIMIT,
                &fp.encode_tlv(),
            ));
        }
        if let Some(p) = self.execution_policy {
            stream.push(TlvRecord::u8(request_tlv::EXECUTION_POLICY, p));
        }
        Ok(stream.encode())
    }

    /// Decodes from Go-compatible TLV bytes. Unknown odd records are
    /// ignored; unknown even records are rejected by the TLV layer.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let stream = decode_stream(data)?;

        let version = stream
            .get(request_tlv::VERSION)
            .ok_or(WireError::MissingRecord(request_tlv::VERSION))?
            .as_u8()
            .map_err(|e| WireError::InvalidRecord {
                type_num: request_tlv::VERSION,
                msg: e.to_string(),
            })?;
        let id = require(
            get_bytes32(&stream, request_tlv::ID)?,
            request_tlv::ID,
        )?;
        let transfer_type = stream
            .get(request_tlv::TRANSFER_TYPE)
            .ok_or(WireError::MissingRecord(request_tlv::TRANSFER_TYPE))?
            .as_u8()
            .map_err(|e| WireError::InvalidRecord {
                type_num: request_tlv::TRANSFER_TYPE,
                msg: e.to_string(),
            })?;
        let expiry = require(
            get_u64(&stream, request_tlv::EXPIRY)?,
            request_tlv::EXPIRY,
        )?;
        let max_in_asset = require(
            get_u64(&stream, request_tlv::MAX_IN_ASSET)?,
            request_tlv::MAX_IN_ASSET,
        )?;

        Ok(RequestWireMsg {
            version,
            id,
            transfer_type,
            expiry,
            in_asset_id: get_bytes32(&stream, request_tlv::IN_ASSET_ID)?,
            in_asset_group_key: get_bytes33(
                &stream,
                request_tlv::IN_ASSET_GROUP_KEY,
            )?,
            out_asset_id: get_bytes32(&stream, request_tlv::OUT_ASSET_ID)?,
            out_asset_group_key: get_bytes33(
                &stream,
                request_tlv::OUT_ASSET_GROUP_KEY,
            )?,
            max_in_asset,
            in_asset_rate_hint: get_fixed_point(
                &stream,
                request_tlv::IN_ASSET_RATE_HINT,
            )?,
            out_asset_rate_hint: get_fixed_point(
                &stream,
                request_tlv::OUT_ASSET_RATE_HINT,
            )?,
            min_in_asset: get_u64(&stream, request_tlv::MIN_IN_ASSET)?,
            min_out_asset: get_u64(&stream, request_tlv::MIN_OUT_ASSET)?,
            price_oracle_metadata: stream
                .get(request_tlv::PRICE_ORACLE_METADATA)
                .map(|r| r.value.clone()),
            asset_rate_limit: get_fixed_point(
                &stream,
                request_tlv::ASSET_RATE_LIMIT,
            )?,
            execution_policy: match stream.get(request_tlv::EXECUTION_POLICY)
            {
                None => None,
                Some(r) => Some(r.as_u8().map_err(|e| {
                    WireError::InvalidRecord {
                        type_num: request_tlv::EXECUTION_POLICY,
                        msg: e.to_string(),
                    }
                })?),
            },
        })
    }
}

// --- Accept ---

/// Wire-level RFQ accept (Go `acceptWireMsgData`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptWireMsg {
    /// Message data version (type 0).
    pub version: u8,
    /// The request ID this accept responds to (type 2).
    pub id: RfqId,
    /// Unix expiry timestamp in seconds (type 4, 8-byte u64).
    pub expiry: u64,
    /// Signature over the message contents (type 6, 64 bytes).
    ///
    /// A zero signature is currently allowed; see [`AcceptSigner`] in
    /// the RFQ manager for the signing hook.
    pub sig: [u8; 64],
    /// In-asset to BTC rate (type 8, TlvFixedPoint, units per BTC).
    pub in_asset_rate: FixedPoint,
    /// Out-asset to BTC rate (type 10, TlvFixedPoint, units per BTC).
    pub out_asset_rate: FixedPoint,
    /// Optional maximum in-asset fill quantity (type 11, u64). Go
    /// normalizes a decoded value of 0 to None.
    pub max_in_asset: Option<u64>,
}

impl AcceptWireMsg {
    /// Encodes to Go-compatible TLV bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(accept_tlv::VERSION, self.version));
        stream.push(TlvRecord::bytes(accept_tlv::ID, &self.id));
        stream.push(TlvRecord::u64(accept_tlv::EXPIRY, self.expiry));
        stream.push(TlvRecord::bytes(accept_tlv::SIG, &self.sig));
        stream.push(TlvRecord::bytes(
            accept_tlv::IN_ASSET_RATE,
            &self.in_asset_rate.encode_tlv(),
        ));
        stream.push(TlvRecord::bytes(
            accept_tlv::OUT_ASSET_RATE,
            &self.out_asset_rate.encode_tlv(),
        ));
        if let Some(max) = self.max_in_asset {
            stream.push(TlvRecord::u64(accept_tlv::MAX_IN_ASSET, max));
        }
        Ok(stream.encode())
    }

    /// Decodes from Go-compatible TLV bytes.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let stream = decode_stream(data)?;

        let version = stream
            .get(accept_tlv::VERSION)
            .ok_or(WireError::MissingRecord(accept_tlv::VERSION))?
            .as_u8()
            .map_err(|e| WireError::InvalidRecord {
                type_num: accept_tlv::VERSION,
                msg: e.to_string(),
            })?;
        let id =
            require(get_bytes32(&stream, accept_tlv::ID)?, accept_tlv::ID)?;
        let expiry = require(
            get_u64(&stream, accept_tlv::EXPIRY)?,
            accept_tlv::EXPIRY,
        )?;
        let sig_record = stream
            .get(accept_tlv::SIG)
            .ok_or(WireError::MissingRecord(accept_tlv::SIG))?;
        if sig_record.value.len() != 64 {
            return Err(WireError::InvalidRecord {
                type_num: accept_tlv::SIG,
                msg: format!(
                    "expected 64 bytes, got {}",
                    sig_record.value.len()
                ),
            });
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_record.value);

        let in_asset_rate = require(
            get_fixed_point(&stream, accept_tlv::IN_ASSET_RATE)?,
            accept_tlv::IN_ASSET_RATE,
        )?;
        let out_asset_rate = require(
            get_fixed_point(&stream, accept_tlv::OUT_ASSET_RATE)?,
            accept_tlv::OUT_ASSET_RATE,
        )?;

        // Go normalizes a zero max fill to "unset".
        let max_in_asset = get_u64(&stream, accept_tlv::MAX_IN_ASSET)?
            .filter(|&v| v > 0);

        Ok(AcceptWireMsg {
            version,
            id,
            expiry,
            sig,
            in_asset_rate,
            out_asset_rate,
            max_in_asset,
        })
    }
}

// --- Reject ---

/// Wire-level RFQ reject (Go `rejectWireMsgData`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectWireMsg {
    /// Message data version (type 0).
    pub version: u8,
    /// The request ID this reject responds to (type 2).
    pub id: RfqId,
    /// The reject code (first byte of the type 5 record).
    pub code: RejectCode,
    /// The human-readable reject message (remainder of the type 5
    /// record).
    pub message: String,
}

impl RejectWireMsg {
    /// Encodes to Go-compatible TLV bytes. The type 5 record value is
    /// `u8 code || message bytes` (Go `rejectErrEncoder`).
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(reject_tlv::VERSION, self.version));
        stream.push(TlvRecord::bytes(reject_tlv::ID, &self.id));
        let mut err_data = Vec::with_capacity(1 + self.message.len());
        err_data.push(self.code.to_u8());
        err_data.extend_from_slice(self.message.as_bytes());
        stream.push(TlvRecord::bytes(reject_tlv::ERR, &err_data));
        Ok(stream.encode())
    }

    /// Decodes from Go-compatible TLV bytes.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let stream = decode_stream(data)?;

        let version = stream
            .get(reject_tlv::VERSION)
            .ok_or(WireError::MissingRecord(reject_tlv::VERSION))?
            .as_u8()
            .map_err(|e| WireError::InvalidRecord {
                type_num: reject_tlv::VERSION,
                msg: e.to_string(),
            })?;
        let id =
            require(get_bytes32(&stream, reject_tlv::ID)?, reject_tlv::ID)?;
        let err_record = stream
            .get(reject_tlv::ERR)
            .ok_or(WireError::MissingRecord(reject_tlv::ERR))?;
        if err_record.value.is_empty() {
            return Err(WireError::InvalidRecord {
                type_num: reject_tlv::ERR,
                msg: "empty error record".into(),
            });
        }
        let code = RejectCode::from_u8(err_record.value[0]);
        let message = String::from_utf8_lossy(&err_record.value[1..])
            .into_owned();

        Ok(RejectWireMsg {
            version,
            id,
            code,
            message,
        })
    }
}

// --- Typed decoders ---

/// A decoded RFQ request, discriminated by transfer type.
#[derive(Clone, Debug)]
pub enum DecodedRequest {
    /// The peer wants to buy assets from us (RecvPayment transfer).
    Buy(RequestWireMsg),
    /// The peer wants to sell assets to us (PayInvoice transfer).
    Sell(RequestWireMsg),
}

/// Decodes an RFQ request payload and discriminates buy vs sell via the
/// TRANSFER_TYPE record (mirrors Go `NewIncomingRequestFromWire`).
pub fn decode_request(data: &[u8]) -> Result<DecodedRequest, WireError> {
    let msg = RequestWireMsg::decode(data)?;
    if msg.version != WIRE_MSG_VERSION_V1 {
        return Err(WireError::UnsupportedVersion(msg.version));
    }
    match msg.transfer_type {
        TRANSFER_TYPE_PAY_INVOICE => Ok(DecodedRequest::Sell(msg)),
        TRANSFER_TYPE_RECV_PAYMENT => Ok(DecodedRequest::Buy(msg)),
        other => Err(WireError::UnknownTransferType(other)),
    }
}

/// Decodes an RFQ accept payload. Buy/sell discrimination requires a
/// session lookup and is done by the caller (mirrors Go
/// `NewIncomingAcceptFromWire`).
pub fn decode_accept(data: &[u8]) -> Result<AcceptWireMsg, WireError> {
    let msg = AcceptWireMsg::decode(data)?;
    if msg.version != WIRE_MSG_VERSION_V1 {
        return Err(WireError::UnsupportedVersion(msg.version));
    }
    Ok(msg)
}

/// Decodes an RFQ reject payload.
pub fn decode_reject(data: &[u8]) -> Result<RejectWireMsg, WireError> {
    let msg = RejectWireMsg::decode(data)?;
    if msg.version != WIRE_MSG_VERSION_V1 {
        return Err(WireError::UnsupportedVersion(msg.version));
    }
    Ok(msg)
}

// --- convenience constructors matching Go's outgoing messages ---

/// Builds a Go-compatible buy request wire message (in-asset is the
/// asset being bought, out-asset is BTC).
pub fn new_buy_request(
    id: RfqId,
    asset_id: Option<&AssetId>,
    group_key: Option<[u8; 33]>,
    max_amount: u64,
    expiry: u64,
    rate_hint: Option<FixedPoint>,
) -> RequestWireMsg {
    RequestWireMsg {
        version: WIRE_MSG_VERSION_V1,
        id,
        transfer_type: TRANSFER_TYPE_RECV_PAYMENT,
        expiry,
        in_asset_id: asset_id.map(|a| a.0),
        in_asset_group_key: group_key,
        // Zero out-asset ID indicates BTC.
        out_asset_id: Some([0u8; 32]),
        out_asset_group_key: None,
        max_in_asset: max_amount,
        in_asset_rate_hint: rate_hint,
        out_asset_rate_hint: None,
        min_in_asset: None,
        min_out_asset: None,
        price_oracle_metadata: None,
        asset_rate_limit: None,
        execution_policy: None,
    }
}

/// Builds a Go-compatible sell request wire message (out-asset is the
/// asset being sold, in-asset is BTC, max_in_asset is msat).
pub fn new_sell_request(
    id: RfqId,
    asset_id: Option<&AssetId>,
    group_key: Option<[u8; 33]>,
    max_msat: u64,
    expiry: u64,
    rate_hint: Option<FixedPoint>,
) -> RequestWireMsg {
    RequestWireMsg {
        version: WIRE_MSG_VERSION_V1,
        id,
        transfer_type: TRANSFER_TYPE_PAY_INVOICE,
        expiry,
        // Zero in-asset ID indicates BTC.
        in_asset_id: Some([0u8; 32]),
        in_asset_group_key: None,
        out_asset_id: asset_id.map(|a| a.0),
        out_asset_group_key: group_key,
        max_in_asset: max_msat,
        in_asset_rate_hint: None,
        out_asset_rate_hint: rate_hint,
        min_in_asset: None,
        min_out_asset: None,
        price_oracle_metadata: None,
        asset_rate_limit: None,
        execution_policy: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_constants() {
        assert_eq!(MSG_TYPE_REQUEST, 52884);
        assert_eq!(MSG_TYPE_ACCEPT, 52885);
        assert_eq!(MSG_TYPE_REJECT, 52886);
    }

    #[test]
    fn test_buy_request_roundtrip() {
        let msg = new_buy_request(
            [0x42; 32],
            Some(&AssetId([0xAA; 32])),
            None,
            1000,
            1_700_000_000,
            Some(FixedPoint::new(42000, 2)),
        );
        let encoded = msg.encode().unwrap();
        let decoded = RequestWireMsg::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);

        match decode_request(&encoded).unwrap() {
            DecodedRequest::Buy(m) => assert_eq!(m, msg),
            _ => panic!("expected buy request"),
        }
    }

    #[test]
    fn test_sell_request_roundtrip() {
        let msg = new_sell_request(
            [0x43; 32],
            Some(&AssetId([0xBB; 32])),
            None,
            500_000,
            1_700_000_000,
            None,
        );
        let encoded = msg.encode().unwrap();
        match decode_request(&encoded).unwrap() {
            DecodedRequest::Sell(m) => assert_eq!(m, msg),
            _ => panic!("expected sell request"),
        }
    }

    #[test]
    fn test_unknown_transfer_type_rejected() {
        let mut msg = new_buy_request(
            [0x42; 32],
            Some(&AssetId([0xAA; 32])),
            None,
            1000,
            1_700_000_000,
            None,
        );
        msg.transfer_type = 7;
        let encoded = msg.encode().unwrap();
        assert!(matches!(
            decode_request(&encoded),
            Err(WireError::UnknownTransferType(7))
        ));
    }

    #[test]
    fn test_accept_roundtrip() {
        let msg = AcceptWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: [0x44; 32],
            expiry: 1_700_001_000,
            sig: [0xCC; 64],
            in_asset_rate: FixedPoint::new(42000, 2),
            out_asset_rate: FixedPoint::new(1, 0),
            max_in_asset: Some(5000),
        };
        let encoded = msg.encode().unwrap();
        let decoded = decode_accept(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_accept_zero_max_in_asset_normalized() {
        let msg = AcceptWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: [0x44; 32],
            expiry: 1_700_001_000,
            sig: [0; 64],
            in_asset_rate: FixedPoint::new(1, 0),
            out_asset_rate: FixedPoint::new(1, 0),
            max_in_asset: Some(0),
        };
        let encoded = msg.encode().unwrap();
        let decoded = decode_accept(&encoded).unwrap();
        // Go normalizes a zero fill amount to None.
        assert_eq!(decoded.max_in_asset, None);
    }

    #[test]
    fn test_reject_roundtrip() {
        let msg = RejectWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: [0x45; 32],
            code: RejectCode::PriceOracleUnavailable,
            message: "rates expired".into(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = decode_reject(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_reject_codes_roundtrip() {
        for c in 0u8..=6 {
            assert_eq!(RejectCode::from_u8(c).to_u8(), c);
        }
    }

    #[test]
    fn test_tlv_records_sorted() {
        let msg = new_buy_request(
            [0x42; 32],
            Some(&AssetId([0xAA; 32])),
            None,
            1000,
            0,
            Some(FixedPoint::new(1, 0)),
        );
        let encoded = msg.encode().unwrap();
        let stream = TlvStream::decode(&encoded).unwrap();
        let types: Vec<u64> =
            stream.records().iter().map(|r| r.type_num).collect();
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted, "TLV records must be sorted");
    }
}
