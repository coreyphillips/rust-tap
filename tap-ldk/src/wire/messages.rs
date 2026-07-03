// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Concrete message types for TAP wire protocol.
//!
//! RFQ messages encode to and decode from the Go-compatible wire format
//! implemented in [`super::compat`]. Asset funding messages use internal
//! (Rust-only) message types.

use tap_primitives::asset::{AssetId, SerializedKey};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

use super::compat::{
    self, AcceptWireMsg, DecodedRequest, RejectCode, RejectWireMsg,
    RequestWireMsg, WireError, MSG_TYPE_ACCEPT, MSG_TYPE_REJECT,
    MSG_TYPE_REQUEST, WIRE_MSG_VERSION_V1,
};
use crate::rfq::math::FixedPoint;

/// Maximum allowed proof data size in wire messages (1 MiB).
pub const MAX_PROOF_DATA_SIZE: usize = 1024 * 1024;
/// Maximum allowed error message length in RFQ reject messages (1 KiB).
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 1024;

/// The rate representing one BTC expressed in milli-satoshi, used as the
/// BTC-side rate in accept messages (Go `rfqmsg.MilliSatPerBtc`,
/// `FixedPointFromUint64(100, 9)` = coefficient 100e9 at scale 9).
pub fn msat_per_btc_rate() -> FixedPoint {
    FixedPoint::new(100_000_000_000, 9)
}

/// A TAP custom message exchanged between peers.
#[derive(Clone, Debug)]
pub enum TapMessage {
    /// Initiator sends asset proofs during channel open.
    AssetFundingCreated(AssetFundingCreated),
    /// Responder acknowledges asset funding.
    AssetFundingAck(AssetFundingAck),
    /// Final proof state after funding tx is created.
    AssetFundingProof(AssetFundingProof),

    /// RFQ messages.
    RfqBuyRequest(RfqBuyRequest),
    RfqBuyAccept(RfqBuyAccept),
    RfqBuyReject(RfqReject),
    RfqSellRequest(RfqSellRequest),
    RfqSellAccept(RfqSellAccept),
    RfqSellReject(RfqReject),
}

impl TapMessage {
    /// Returns the wire message type ID.
    ///
    /// RFQ messages use Go-compatible type IDs from the `compat` module.
    /// Funding messages use internal type IDs.
    pub fn msg_type(&self) -> u16 {
        use super::msg_type::*;
        match self {
            TapMessage::AssetFundingCreated(_) => ASSET_FUNDING_CREATED,
            TapMessage::AssetFundingAck(_) => ASSET_FUNDING_ACK,
            TapMessage::AssetFundingProof(_) => ASSET_FUNDING_PROOF,
            TapMessage::RfqBuyRequest(_) => MSG_TYPE_REQUEST,
            TapMessage::RfqBuyAccept(_) => MSG_TYPE_ACCEPT,
            TapMessage::RfqBuyReject(_) => MSG_TYPE_REJECT,
            TapMessage::RfqSellRequest(_) => MSG_TYPE_REQUEST,
            TapMessage::RfqSellAccept(_) => MSG_TYPE_ACCEPT,
            TapMessage::RfqSellReject(_) => MSG_TYPE_REJECT,
        }
    }

    /// Encodes the message to bytes (type + TLV payload).
    ///
    /// Format: `[u16 msg_type][TLV stream body]`. RFQ payloads are
    /// byte-compatible with Go's `rfqmsg` wire encoding.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.msg_type().to_be_bytes());
        buf.extend_from_slice(&self.encode_payload()?);
        Ok(buf)
    }

    /// Encodes just the TLV payload (without the message type prefix).
    pub fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        match self {
            TapMessage::AssetFundingCreated(m) => {
                let mut stream = TlvStream::new();
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::bytes(2, &m.asset_id.0));
                stream.push(TlvRecord::varint(4, m.amount));
                if !m.proof_data.is_empty() {
                    stream.push(TlvRecord::bytes(6, &m.proof_data));
                }
                if let Some(ref gk) = m.group_key {
                    stream.push(TlvRecord::bytes(8, gk.as_bytes()));
                }
                Ok(stream.encode())
            }
            TapMessage::AssetFundingAck(m) => {
                let mut stream = TlvStream::new();
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::u8(2, if m.accepted { 1 } else { 0 }));
                if let Some(ref reason) = m.reject_reason {
                    stream.push(TlvRecord::bytes(4, reason.as_bytes()));
                }
                Ok(stream.encode())
            }
            TapMessage::AssetFundingProof(m) => {
                let mut stream = TlvStream::new();
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::bytes(2, &m.proof_data));
                Ok(stream.encode())
            }
            TapMessage::RfqBuyRequest(m) => m.to_wire().encode(),
            TapMessage::RfqSellRequest(m) => m.to_wire().encode(),
            TapMessage::RfqBuyAccept(m) => m.to_wire().encode(),
            TapMessage::RfqSellAccept(m) => m.to_wire().encode(),
            TapMessage::RfqBuyReject(m) | TapMessage::RfqSellReject(m) => {
                m.to_wire().encode()
            }
        }
    }

    /// Decodes a TAP message from its wire type and TLV payload.
    ///
    /// Accept and reject messages do not carry enough information to
    /// discriminate buy vs sell, so a session lookup is required
    /// (mirrors Go's `SessionLookup`): given the RFQ ID of one of our
    /// outgoing requests, it returns `Some(true)` for a pending buy
    /// request, `Some(false)` for a pending sell request, and `None`
    /// when no request is known.
    pub fn decode<F>(
        msg_type: u16,
        payload: &[u8],
        session_lookup: F,
    ) -> Result<TapMessage, WireError>
    where
        F: Fn(&RfqId) -> Option<bool>,
    {
        use super::msg_type::*;
        match msg_type {
            MSG_TYPE_REQUEST => match compat::decode_request(payload)? {
                DecodedRequest::Buy(m) => Ok(TapMessage::RfqBuyRequest(
                    RfqBuyRequest::from_wire(&m)?,
                )),
                DecodedRequest::Sell(m) => Ok(TapMessage::RfqSellRequest(
                    RfqSellRequest::from_wire(&m)?,
                )),
            },
            MSG_TYPE_ACCEPT => {
                let m = compat::decode_accept(payload)?;
                match session_lookup(&m.id) {
                    Some(true) => Ok(TapMessage::RfqBuyAccept(
                        RfqBuyAccept::from_wire(&m),
                    )),
                    Some(false) => Ok(TapMessage::RfqSellAccept(
                        RfqSellAccept::from_wire(&m),
                    )),
                    None => Err(WireError::UnknownSession(m.id)),
                }
            }
            MSG_TYPE_REJECT => {
                let m = compat::decode_reject(payload)?;
                let reject = RfqReject {
                    id: m.id,
                    code: m.code,
                    message: m.message,
                };
                match session_lookup(&reject.id) {
                    Some(true) => Ok(TapMessage::RfqBuyReject(reject)),
                    Some(false) => Ok(TapMessage::RfqSellReject(reject)),
                    None => Err(WireError::UnknownSession(reject.id)),
                }
            }
            ASSET_FUNDING_CREATED => {
                let stream = TlvStream::decode(payload)
                    .map_err(|e| WireError::Tlv(e.to_string()))?;
                let pending_channel_id = read_bytes32(&stream, 0)?;
                let asset_id = AssetId(read_bytes32(&stream, 2)?);
                let amount = stream
                    .get(4)
                    .ok_or(WireError::MissingRecord(4))?
                    .as_varint()
                    .map_err(|e| WireError::InvalidRecord {
                        type_num: 4,
                        msg: e.to_string(),
                    })?;
                let proof_data = stream
                    .get(6)
                    .map(|r| r.value.clone())
                    .unwrap_or_default();
                if proof_data.len() > MAX_PROOF_DATA_SIZE {
                    return Err(WireError::MessageTooLarge(proof_data.len()));
                }
                let group_key = match stream.get(8) {
                    None => None,
                    Some(r) => {
                        if r.value.len() != 33 {
                            return Err(WireError::InvalidRecord {
                                type_num: 8,
                                msg: "group key must be 33 bytes".into(),
                            });
                        }
                        let mut gk = [0u8; 33];
                        gk.copy_from_slice(&r.value);
                        Some(SerializedKey(gk))
                    }
                };
                Ok(TapMessage::AssetFundingCreated(AssetFundingCreated {
                    pending_channel_id,
                    asset_id,
                    amount,
                    proof_data,
                    group_key,
                }))
            }
            ASSET_FUNDING_ACK => {
                let stream = TlvStream::decode(payload)
                    .map_err(|e| WireError::Tlv(e.to_string()))?;
                let pending_channel_id = read_bytes32(&stream, 0)?;
                let accepted = stream
                    .get(2)
                    .ok_or(WireError::MissingRecord(2))?
                    .as_u8()
                    .map_err(|e| WireError::InvalidRecord {
                        type_num: 2,
                        msg: e.to_string(),
                    })?
                    == 1;
                let reject_reason = stream.get(4).map(|r| {
                    String::from_utf8_lossy(&r.value).into_owned()
                });
                Ok(TapMessage::AssetFundingAck(AssetFundingAck {
                    pending_channel_id,
                    accepted,
                    reject_reason,
                }))
            }
            ASSET_FUNDING_PROOF => {
                let stream = TlvStream::decode(payload)
                    .map_err(|e| WireError::Tlv(e.to_string()))?;
                let pending_channel_id = read_bytes32(&stream, 0)?;
                let proof_data = stream
                    .get(2)
                    .ok_or(WireError::MissingRecord(2))?
                    .value
                    .clone();
                if proof_data.len() > MAX_PROOF_DATA_SIZE {
                    return Err(WireError::MessageTooLarge(proof_data.len()));
                }
                Ok(TapMessage::AssetFundingProof(AssetFundingProof {
                    pending_channel_id,
                    proof_data,
                }))
            }
            other => Err(WireError::UnknownMessageType(other)),
        }
    }
}

fn read_bytes32(
    stream: &TlvStream,
    type_num: u64,
) -> Result<[u8; 32], WireError> {
    let r = stream
        .get(type_num)
        .ok_or(WireError::MissingRecord(type_num))?;
    if r.value.len() != 32 {
        return Err(WireError::InvalidRecord {
            type_num,
            msg: format!("expected 32 bytes, got {}", r.value.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&r.value);
    Ok(out)
}

// --- Asset Funding Messages ---

/// Sent by the initiator to propose an asset channel.
#[derive(Clone, Debug)]
pub struct AssetFundingCreated {
    /// Temporary channel ID.
    pub pending_channel_id: [u8; 32],
    /// Asset to fund the channel with.
    pub asset_id: AssetId,
    /// Amount of asset for the channel.
    pub amount: u64,
    /// Asset proof data (an encoded proof file for the input assets).
    pub proof_data: Vec<u8>,
    /// The group key, if this is a grouped asset.
    pub group_key: Option<SerializedKey>,
}

/// Sent by the responder to accept or reject asset funding.
#[derive(Clone, Debug)]
pub struct AssetFundingAck {
    /// Temporary channel ID.
    pub pending_channel_id: [u8; 32],
    /// Whether the funding was accepted.
    pub accepted: bool,
    /// Rejection reason (if not accepted).
    pub reject_reason: Option<String>,
}

/// Final proof state after the Bitcoin funding tx is constructed.
#[derive(Clone, Debug)]
pub struct AssetFundingProof {
    /// Temporary channel ID.
    pub pending_channel_id: [u8; 32],
    /// Proof data for the funded assets.
    pub proof_data: Vec<u8>,
}

// --- RFQ Messages ---

/// A 32-byte RFQ request/quote identifier, matching Go's wire format.
pub type RfqId = [u8; 32];

/// Request to buy assets (we want to receive assets, Go
/// `RecvPaymentTransferType`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqBuyRequest {
    /// Unique request ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// Asset to buy (the in-asset on the wire).
    pub asset_id: AssetId,
    /// Maximum asset amount to buy.
    pub asset_max_amount: u64,
    /// Optional group key for grouped assets.
    pub asset_group_key: Option<SerializedKey>,
    /// Unix timestamp when the request/quote expires.
    pub expiry: u64,
    /// Optional suggested in-asset to BTC rate (units per BTC).
    pub rate_hint: Option<FixedPoint>,
}

impl RfqBuyRequest {
    /// Converts to the Go wire representation.
    pub fn to_wire(&self) -> RequestWireMsg {
        compat::new_buy_request(
            self.id,
            Some(&self.asset_id),
            self.asset_group_key.map(|k| k.0),
            self.asset_max_amount,
            self.expiry,
            self.rate_hint,
        )
    }

    /// Builds from the Go wire representation.
    pub fn from_wire(m: &RequestWireMsg) -> Result<Self, WireError> {
        let asset_id = m
            .in_asset_id
            .map(AssetId)
            .ok_or(WireError::MissingRecord(
                compat::request_tlv::IN_ASSET_ID,
            ))?;
        Ok(RfqBuyRequest {
            id: m.id,
            asset_id,
            asset_max_amount: m.max_in_asset,
            asset_group_key: m.in_asset_group_key.map(SerializedKey),
            expiry: m.expiry,
            rate_hint: m.in_asset_rate_hint,
        })
    }
}

/// Accept a buy request (peer offers to sell to us at a given rate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqBuyAccept {
    /// Matches the request ID.
    pub id: RfqId,
    /// The in-asset to BTC rate (asset units per BTC).
    pub asset_rate: FixedPoint,
    /// Unix timestamp when this quote expires.
    pub expiry: u64,
    /// Signature over the message (zero when unsigned; see the
    /// `AcceptSigner` hook).
    pub sig: [u8; 64],
    /// Optional maximum fill amount accepted by the responder.
    pub max_in_asset: Option<u64>,
}

impl RfqBuyAccept {
    /// Converts to the Go wire representation. In buy accepts the asset
    /// rate is the in-asset rate; the out asset is BTC.
    pub fn to_wire(&self) -> AcceptWireMsg {
        AcceptWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: self.id,
            expiry: self.expiry,
            sig: self.sig,
            in_asset_rate: self.asset_rate,
            out_asset_rate: msat_per_btc_rate(),
            max_in_asset: self.max_in_asset,
        }
    }

    /// Builds from the Go wire representation.
    pub fn from_wire(m: &AcceptWireMsg) -> Self {
        RfqBuyAccept {
            id: m.id,
            asset_rate: m.in_asset_rate,
            expiry: m.expiry,
            sig: m.sig,
            max_in_asset: m.max_in_asset,
        }
    }
}

/// Request to sell assets (we want to pay an invoice with assets, Go
/// `PayInvoiceTransferType`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqSellRequest {
    /// Unique request ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// Asset to sell (the out-asset on the wire).
    pub asset_id: AssetId,
    /// Maximum BTC payment amount in msat.
    pub payment_max_amt_msat: u64,
    /// Optional group key for grouped assets.
    pub asset_group_key: Option<SerializedKey>,
    /// Unix timestamp when the request/quote expires.
    pub expiry: u64,
    /// Optional suggested out-asset to BTC rate (units per BTC).
    pub rate_hint: Option<FixedPoint>,
}

impl RfqSellRequest {
    /// Converts to the Go wire representation.
    pub fn to_wire(&self) -> RequestWireMsg {
        compat::new_sell_request(
            self.id,
            Some(&self.asset_id),
            self.asset_group_key.map(|k| k.0),
            self.payment_max_amt_msat,
            self.expiry,
            self.rate_hint,
        )
    }

    /// Builds from the Go wire representation.
    pub fn from_wire(m: &RequestWireMsg) -> Result<Self, WireError> {
        let asset_id = m
            .out_asset_id
            .map(AssetId)
            .ok_or(WireError::MissingRecord(
                compat::request_tlv::OUT_ASSET_ID,
            ))?;
        Ok(RfqSellRequest {
            id: m.id,
            asset_id,
            payment_max_amt_msat: m.max_in_asset,
            asset_group_key: m.out_asset_group_key.map(SerializedKey),
            expiry: m.expiry,
            rate_hint: m.out_asset_rate_hint,
        })
    }
}

/// Accept a sell request (peer offers to buy from us at a given rate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqSellAccept {
    /// Matches the request ID.
    pub id: RfqId,
    /// The out-asset to BTC rate (asset units per BTC).
    pub asset_rate: FixedPoint,
    /// Unix timestamp when this quote expires.
    pub expiry: u64,
    /// Signature over the message (zero when unsigned; see the
    /// `AcceptSigner` hook).
    pub sig: [u8; 64],
    /// Optional maximum fill amount accepted by the responder.
    pub max_in_asset: Option<u64>,
}

impl RfqSellAccept {
    /// Converts to the Go wire representation. In sell accepts the
    /// asset rate is the out-asset rate; the in asset is BTC.
    pub fn to_wire(&self) -> AcceptWireMsg {
        AcceptWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: self.id,
            expiry: self.expiry,
            sig: self.sig,
            in_asset_rate: msat_per_btc_rate(),
            out_asset_rate: self.asset_rate,
            max_in_asset: self.max_in_asset,
        }
    }

    /// Builds from the Go wire representation.
    pub fn from_wire(m: &AcceptWireMsg) -> Self {
        RfqSellAccept {
            id: m.id,
            asset_rate: m.out_asset_rate,
            expiry: m.expiry,
            sig: m.sig,
            max_in_asset: m.max_in_asset,
        }
    }
}

/// Reject an RFQ request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqReject {
    /// Matches the request ID.
    pub id: RfqId,
    /// Go-compatible reject code.
    pub code: RejectCode,
    /// Human-readable error message.
    pub message: String,
}

impl RfqReject {
    /// Converts to the Go wire representation.
    pub fn to_wire(&self) -> RejectWireMsg {
        let mut message = self.message.clone();
        message.truncate(MAX_ERROR_MESSAGE_LENGTH);
        RejectWireMsg {
            version: WIRE_MSG_VERSION_V1,
            id: self.id,
            code: self.code,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_ids() {
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: [0; 32],
            asset_id: AssetId([0; 32]),
            amount: 100,
            proof_data: vec![],
            group_key: None,
        });
        assert_eq!(
            msg.msg_type(),
            super::super::msg_type::ASSET_FUNDING_CREATED
        );
    }

    #[test]
    fn test_buy_request_wire_roundtrip() {
        let req = RfqBuyRequest {
            id: [0x42; 32],
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 1000,
            asset_group_key: None,
            expiry: 4_102_444_800,
            rate_hint: None,
        };
        let msg = TapMessage::RfqBuyRequest(req.clone());
        let encoded = msg.encode().unwrap();
        let msg_type = u16::from_be_bytes([encoded[0], encoded[1]]);
        assert_eq!(msg_type, MSG_TYPE_REQUEST);

        let decoded =
            TapMessage::decode(msg_type, &encoded[2..], |_| None).unwrap();
        match decoded {
            TapMessage::RfqBuyRequest(d) => assert_eq!(d, req),
            other => panic!("wrong decode: {:?}", other),
        }
    }

    #[test]
    fn test_accept_decode_discrimination() {
        let accept = RfqBuyAccept {
            id: [0x11; 32],
            asset_rate: FixedPoint::new(42000, 2),
            expiry: 4_102_444_800,
            sig: [0; 64],
            max_in_asset: None,
        };
        let payload = accept.to_wire().encode().unwrap();

        // Session says this ID belongs to a pending buy request.
        let decoded =
            TapMessage::decode(MSG_TYPE_ACCEPT, &payload, |_| Some(true))
                .unwrap();
        assert!(matches!(decoded, TapMessage::RfqBuyAccept(_)));

        // Session says sell.
        let decoded =
            TapMessage::decode(MSG_TYPE_ACCEPT, &payload, |_| Some(false))
                .unwrap();
        match decoded {
            TapMessage::RfqSellAccept(a) => {
                // Sell accepts read the out-asset rate, which for a
                // wire message built from a buy accept is the BTC rate.
                assert_eq!(a.asset_rate, msat_per_btc_rate());
            }
            other => panic!("wrong decode: {:?}", other),
        }

        // Unknown session errors (mirrors Go).
        assert!(matches!(
            TapMessage::decode(MSG_TYPE_ACCEPT, &payload, |_| None),
            Err(WireError::UnknownSession(_))
        ));
    }

    #[test]
    fn test_funding_created_roundtrip() {
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: [0x07; 32],
            asset_id: AssetId([0xAA; 32]),
            amount: 1234,
            proof_data: vec![1, 2, 3, 4],
            group_key: Some(SerializedKey([0x02; 33])),
        });
        let encoded = msg.encode().unwrap();
        let msg_type = u16::from_be_bytes([encoded[0], encoded[1]]);
        let decoded =
            TapMessage::decode(msg_type, &encoded[2..], |_| None).unwrap();
        match decoded {
            TapMessage::AssetFundingCreated(m) => {
                assert_eq!(m.pending_channel_id, [0x07; 32]);
                assert_eq!(m.amount, 1234);
                assert_eq!(m.proof_data, vec![1, 2, 3, 4]);
                assert!(m.group_key.is_some());
            }
            other => panic!("wrong decode: {:?}", other),
        }
    }

    #[test]
    fn test_reject_wire_roundtrip() {
        let reject = RfqReject {
            id: [0x22; 32],
            code: RejectCode::PriceOracleUnavailable,
            message: "oracle down".into(),
        };
        let payload = TapMessage::RfqBuyReject(reject.clone())
            .encode_payload()
            .unwrap();
        let decoded =
            TapMessage::decode(MSG_TYPE_REJECT, &payload, |_| Some(true))
                .unwrap();
        match decoded {
            TapMessage::RfqBuyReject(r) => assert_eq!(r, reject),
            other => panic!("wrong decode: {:?}", other),
        }
    }
}
