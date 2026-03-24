// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Concrete message types for TAP wire protocol.

use tap_primitives::asset::{AssetId, SerializedKey};

/// Maximum allowed proof data size in wire messages (1 MiB).
pub const MAX_PROOF_DATA_SIZE: usize = 1024 * 1024;
/// Maximum allowed error message length in RFQ reject messages (1 KiB).
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 1024;

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
        use super::compat::{MSG_TYPE_ACCEPT, MSG_TYPE_REJECT, MSG_TYPE_REQUEST};
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
    /// Format: `[u16 msg_type][TLV stream body]`
    /// TLV fields are encoded as `[BigSize type][BigSize length][bytes value]`.
    pub fn encode(&self) -> Vec<u8> {
        use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.msg_type().to_be_bytes());

        let mut stream = TlvStream::new();
        match self {
            TapMessage::AssetFundingCreated(m) => {
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::bytes(2, &m.asset_id.0));
                stream.push(TlvRecord::varint(4, m.amount));
                if !m.proof_data.is_empty() {
                    stream.push(TlvRecord::bytes(6, &m.proof_data));
                }
                if let Some(ref gk) = m.group_key {
                    stream.push(TlvRecord::bytes(8, gk.as_bytes()));
                }
            }
            TapMessage::AssetFundingAck(m) => {
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::u8(2, if m.accepted { 1 } else { 0 }));
                if let Some(ref reason) = m.reject_reason {
                    stream.push(TlvRecord::bytes(4, reason.as_bytes()));
                }
            }
            TapMessage::AssetFundingProof(m) => {
                stream.push(TlvRecord::bytes(0, &m.pending_channel_id));
                stream.push(TlvRecord::bytes(2, &m.proof_data));
            }
            TapMessage::RfqBuyRequest(m) => {
                stream.push(TlvRecord::bytes(0, &m.id));
                stream.push(TlvRecord::bytes(2, &m.asset_id.0));
                stream.push(TlvRecord::varint(4, m.asset_max_amount));
                if let Some(ref gk) = m.asset_group_key {
                    stream.push(TlvRecord::bytes(6, gk.as_bytes()));
                }
            }
            TapMessage::RfqBuyAccept(m) => {
                stream.push(TlvRecord::bytes(0, &m.id));
                stream.push(TlvRecord::varint(2, m.ask_price));
                stream.push(TlvRecord::varint(4, m.expiry));
            }
            TapMessage::RfqSellRequest(m) => {
                stream.push(TlvRecord::bytes(0, &m.id));
                stream.push(TlvRecord::bytes(2, &m.asset_id.0));
                stream.push(TlvRecord::varint(4, m.payment_max_amt_msat));
                if let Some(ref gk) = m.asset_group_key {
                    stream.push(TlvRecord::bytes(6, gk.as_bytes()));
                }
            }
            TapMessage::RfqSellAccept(m) => {
                stream.push(TlvRecord::bytes(0, &m.id));
                stream.push(TlvRecord::varint(2, m.bid_price));
                stream.push(TlvRecord::varint(4, m.expiry));
            }
            TapMessage::RfqBuyReject(m) | TapMessage::RfqSellReject(m) => {
                stream.push(TlvRecord::bytes(0, &m.id));
                stream.push(TlvRecord::u16(2, m.error_code));
                if !m.error_message.is_empty() {
                    stream.push(TlvRecord::bytes(4, m.error_message.as_bytes()));
                }
            }
        }
        buf.extend_from_slice(&stream.encode());
        buf
    }
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
    /// Asset proof data (encoded proofs for the input assets).
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

/// Request to buy assets (we want to buy assets with BTC).
#[derive(Clone, Debug)]
pub struct RfqBuyRequest {
    /// Unique request ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// Asset to buy.
    pub asset_id: AssetId,
    /// Maximum asset amount to buy.
    pub asset_max_amount: u64,
    /// Optional group key for grouped assets.
    pub asset_group_key: Option<SerializedKey>,
}

/// Accept a buy request (offer to sell at a given price).
#[derive(Clone, Debug)]
pub struct RfqBuyAccept {
    /// Matches the request ID.
    pub id: RfqId,
    /// Ask price in msat per asset unit.
    pub ask_price: u64,
    /// Unix timestamp when this quote expires.
    pub expiry: u64,
}

/// Request to sell assets (we want to sell assets for BTC).
#[derive(Clone, Debug)]
pub struct RfqSellRequest {
    /// Unique request ID (32 bytes, Go-compatible).
    pub id: RfqId,
    /// Asset to sell.
    pub asset_id: AssetId,
    /// Maximum BTC payment amount in msat.
    pub payment_max_amt_msat: u64,
    /// Optional group key for grouped assets.
    pub asset_group_key: Option<SerializedKey>,
}

/// Accept a sell request (offer to buy at a given price).
#[derive(Clone, Debug)]
pub struct RfqSellAccept {
    /// Matches the request ID.
    pub id: RfqId,
    /// Bid price in msat per asset unit.
    pub bid_price: u64,
    /// Unix timestamp when this quote expires.
    pub expiry: u64,
}

/// Reject an RFQ request.
#[derive(Clone, Debug)]
pub struct RfqReject {
    /// Matches the request ID.
    pub id: RfqId,
    /// Error code.
    pub error_code: u16,
    /// Human-readable error message.
    pub error_message: String,
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
        assert_eq!(msg.msg_type(), super::super::msg_type::ASSET_FUNDING_CREATED);
    }

    #[test]
    fn test_message_encode_nonzero() {
        let msg = TapMessage::RfqBuyRequest(RfqBuyRequest {
            id: [0x42; 32],
            asset_id: AssetId([0xAA; 32]),
            asset_max_amount: 1000,
            asset_group_key: None,
        });
        let encoded = msg.encode();
        assert!(!encoded.is_empty());
        // First 2 bytes should be the message type.
        let msg_type = u16::from_be_bytes([encoded[0], encoded[1]]);
        assert_eq!(msg_type, super::super::compat::MSG_TYPE_REQUEST);
    }
}
