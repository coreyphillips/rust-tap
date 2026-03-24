// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Opaque blob types stored alongside LDK channel state.
//!
//! These blobs are the Rust equivalents of Go's `tapchannelmsg` records:
//! - [`ChannelBlob`]: Per-channel data (set at funding, updated rarely)
//! - [`CommitmentBlob`]: Per-commitment data (updated on each state transition)
//! - [`HtlcBlob`]: Per-HTLC data (asset amounts and RFQ info)
//!
//! Wire encoding must be byte-compatible with the Go implementation for
//! interoperability between Rust and Go Lightning nodes.

use tap_primitives::asset::{AssetId, SerializedKey};

/// Per-channel asset data, created during funding.
///
/// This is stored as an opaque blob alongside LDK's `Channel` state.
/// Equivalent to Go's `OpenChannel` custom blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelBlob {
    /// Assets funded into this channel.
    pub funded_assets: Vec<FundedAsset>,
    /// Decimal display precision (for UI).
    pub decimal_display: Option<u32>,
    /// Group key if all assets share a group.
    pub group_key: Option<SerializedKey>,
}

/// A single asset funded into a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedAsset {
    /// The asset ID.
    pub asset_id: AssetId,
    /// Amount of this asset in the channel.
    pub amount: u64,
    /// The script key for this asset.
    pub script_key: SerializedKey,
}

impl ChannelBlob {
    /// Encodes to bytes. Must be byte-compatible with Go's tapchannelmsg.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Number of funded assets (u16 BE).
        buf.extend_from_slice(
            &(self.funded_assets.len() as u16).to_be_bytes(),
        );
        for asset in &self.funded_assets {
            buf.extend_from_slice(&asset.asset_id.0);
            buf.extend_from_slice(&asset.amount.to_be_bytes());
            buf.extend_from_slice(asset.script_key.as_bytes());
        }
        // Optional decimal display.
        match self.decimal_display {
            Some(dd) => {
                buf.push(1);
                buf.extend_from_slice(&dd.to_be_bytes());
            }
            None => buf.push(0),
        }
        // Optional group key.
        match &self.group_key {
            Some(gk) => {
                buf.push(1);
                buf.extend_from_slice(gk.as_bytes());
            }
            None => buf.push(0),
        }
        buf
    }

    /// Decodes from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        if data.len() < 2 {
            return Err(BlobError::TooShort);
        }
        let num_assets =
            u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;

        let mut funded_assets = Vec::with_capacity(num_assets);
        for _ in 0..num_assets {
            if offset + 32 + 8 + 33 > data.len() {
                return Err(BlobError::TooShort);
            }
            let mut asset_id = [0u8; 32];
            asset_id.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let amount = u64::from_be_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            );
            offset += 8;

            let mut script_key = [0u8; 33];
            script_key.copy_from_slice(&data[offset..offset + 33]);
            offset += 33;

            funded_assets.push(FundedAsset {
                asset_id: AssetId(asset_id),
                amount,
                script_key: SerializedKey(script_key),
            });
        }

        if offset >= data.len() {
            return Err(BlobError::TooShort);
        }

        let decimal_display = if data[offset] == 1 {
            offset += 1;
            if offset + 4 > data.len() {
                return Err(BlobError::TooShort);
            }
            let dd = u32::from_be_bytes(
                data[offset..offset + 4].try_into().unwrap(),
            );
            offset += 4;
            Some(dd)
        } else {
            offset += 1;
            None
        };

        let group_key = if offset < data.len() && data[offset] == 1 {
            offset += 1;
            if offset + 33 > data.len() {
                return Err(BlobError::TooShort);
            }
            let mut gk = [0u8; 33];
            gk.copy_from_slice(&data[offset..offset + 33]);
            Some(SerializedKey(gk))
        } else {
            None
        };

        Ok(ChannelBlob {
            funded_assets,
            decimal_display,
            group_key,
        })
    }
}

/// Per-commitment asset state.
///
/// Updated on each commitment transaction state transition.
/// Equivalent to Go's `Commitment` custom blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlob {
    /// Local asset balances (keyed by asset ID).
    pub local_assets: Vec<AssetBalance>,
    /// Remote asset balances.
    pub remote_assets: Vec<AssetBalance>,
    /// Outgoing HTLC asset amounts.
    pub outgoing_htlc_assets: Vec<HtlcAssetBalance>,
    /// Incoming HTLC asset amounts.
    pub incoming_htlc_assets: Vec<HtlcAssetBalance>,
}

/// An asset balance in a commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: AssetId,
    pub amount: u64,
}

/// An HTLC's asset balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcAssetBalance {
    /// HTLC index.
    pub htlc_index: u64,
    /// Asset amounts in this HTLC.
    pub balances: Vec<AssetBalance>,
}

/// Per-HTLC asset data.
///
/// Equivalent to Go's `Htlc` custom blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcBlob {
    /// Asset amounts carried by this HTLC.
    pub amounts: Vec<AssetBalance>,
    /// RFQ quote ID used for this payment (32 bytes, Go-compatible).
    pub rfq_id: Option<[u8; 32]>,
}

/// Errors from blob encoding/decoding.
#[derive(Debug, Clone)]
pub enum BlobError {
    TooShort,
    InvalidFormat(String),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::TooShort => write!(f, "blob data too short"),
            BlobError::InvalidFormat(msg) => {
                write!(f, "invalid blob format: {}", msg)
            }
        }
    }
}

impl std::error::Error for BlobError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_blob_roundtrip() {
        let blob = ChannelBlob {
            funded_assets: vec![
                FundedAsset {
                    asset_id: AssetId([0xAA; 32]),
                    amount: 1000,
                    script_key: SerializedKey([0x02; 33]),
                },
                FundedAsset {
                    asset_id: AssetId([0xBB; 32]),
                    amount: 500,
                    script_key: SerializedKey([0x03; 33]),
                },
            ],
            decimal_display: Some(8),
            group_key: Some(SerializedKey([0x04; 33])),
        };

        let encoded = blob.encode();
        let decoded = ChannelBlob::decode(&encoded).unwrap();
        assert_eq!(blob, decoded);
    }

    #[test]
    fn test_channel_blob_empty() {
        let blob = ChannelBlob {
            funded_assets: vec![],
            decimal_display: None,
            group_key: None,
        };

        let encoded = blob.encode();
        let decoded = ChannelBlob::decode(&encoded).unwrap();
        assert_eq!(blob, decoded);
    }

    #[test]
    fn test_channel_blob_no_optional_fields() {
        let blob = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xCC; 32]),
                amount: 42,
                script_key: SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };

        let encoded = blob.encode();
        let decoded = ChannelBlob::decode(&encoded).unwrap();
        assert_eq!(blob, decoded);
    }
}
