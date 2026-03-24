// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Taproot Asset addresses for non-interactive transfers.
//!
//! A TAP address encodes the recipient's asset details into a Bech32m string
//! using TLV-encoded fields. The sender uses this to construct a
//! non-interactive transfer without direct coordination.
//!
//! ## Format
//!
//! HRP: `tap` (mainnet), `taptb` (testnet), `taprt` (regtest),
//!       `tapsb` (simnet), `tapbc` (testnet4/mainnet)
//!
//! Payload: TLV records with types:
//! - 0: version (u8)
//! - 2: asset_version (u8)
//! - 4: asset_id (32 bytes)
//! - 6: script_key (33 bytes)
//! - 8: internal_key (33 bytes)
//! - 10: amount (BigSize varint)
//! - 12: proof_courier_addr (string)
//! - 14: group_key (33 bytes, optional)
//! - 16: tapscript_sibling (variable, optional)

use std::collections::BTreeMap;

use bech32::{Bech32m, Hrp};

use crate::asset::{AssetId, SerializedKey};
use crate::encoding::bigsize::{decode_bigsize, encode_bigsize};

/// Human-readable parts for different networks.
pub const HRP_MAINNET: &str = "tap";
pub const HRP_TESTNET: &str = "taptb";
pub const HRP_REGTEST: &str = "taprt";
pub const HRP_SIMNET: &str = "tapsb";
pub const HRP_TESTNET4: &str = "tapbc";

/// TLV type numbers for address fields.
mod tlv_types {
    pub const VERSION: u8 = 0;
    pub const ASSET_VERSION: u8 = 2;
    pub const ASSET_ID: u8 = 4;
    pub const GROUP_KEY: u8 = 5;
    pub const SCRIPT_KEY: u8 = 6;
    pub const INTERNAL_KEY: u8 = 8;
    pub const TAPSCRIPT_SIBLING: u8 = 9;
    pub const AMOUNT: u8 = 10;
    pub const PROOF_COURIER_ADDR: u8 = 12;
}

/// A Taproot Asset address for receiving assets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapAddress {
    /// Address version (0, 1, or 2).
    pub version: u8,
    /// Asset version.
    pub asset_version: u8,
    /// The asset to receive (optional for group-key-only addresses).
    pub asset_id: Option<AssetId>,
    /// The recipient's script key (tweaked Taproot key).
    pub script_key: SerializedKey,
    /// The recipient's internal key for the Taproot output.
    pub internal_key: SerializedKey,
    /// Amount of asset units to receive.
    pub amount: u64,
    /// Network (determines the HRP).
    pub network: TapNetwork,
    /// Proof courier address (URL).
    pub proof_courier_addr: Option<String>,
    /// Optional group key (33 bytes compressed).
    pub group_key: Option<SerializedKey>,
    /// Optional tapscript sibling hash.
    pub tapscript_sibling: Option<Vec<u8>>,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// Network for TAP address encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapNetwork {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
    Testnet4,
}

impl TapNetwork {
    /// Returns the HRP string for this network.
    pub fn hrp(&self) -> &'static str {
        match self {
            TapNetwork::Mainnet => HRP_MAINNET,
            TapNetwork::Testnet => HRP_TESTNET,
            TapNetwork::Regtest => HRP_REGTEST,
            TapNetwork::Simnet => HRP_SIMNET,
            TapNetwork::Testnet4 => HRP_TESTNET4,
        }
    }

    /// Parses a network from an HRP string.
    pub fn from_hrp(hrp: &str) -> Result<Self, AddressError> {
        match hrp {
            HRP_MAINNET => Ok(TapNetwork::Mainnet),
            HRP_TESTNET => Ok(TapNetwork::Testnet),
            HRP_REGTEST => Ok(TapNetwork::Regtest),
            HRP_SIMNET => Ok(TapNetwork::Simnet),
            HRP_TESTNET4 => Ok(TapNetwork::Testnet4),
            _ => Err(AddressError::UnknownHrp(hrp.to_string())),
        }
    }
}

/// Errors from TAP address operations.
#[derive(Debug, Clone)]
pub enum AddressError {
    UnknownHrp(String),
    InvalidPayload(String),
    MissingField(&'static str),
    InvalidFieldLength { field: &'static str, expected: usize, got: usize },
    Bech32Error(String),
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressError::UnknownHrp(hrp) => {
                write!(f, "unknown HRP: {}", hrp)
            }
            AddressError::InvalidPayload(msg) => {
                write!(f, "invalid payload: {}", msg)
            }
            AddressError::MissingField(name) => {
                write!(f, "missing required field: {}", name)
            }
            AddressError::InvalidFieldLength { field, expected, got } => {
                write!(
                    f,
                    "invalid {} length: expected {}, got {}",
                    field, expected, got
                )
            }
            AddressError::Bech32Error(msg) => {
                write!(f, "bech32 error: {}", msg)
            }
        }
    }
}

impl std::error::Error for AddressError {}

impl TapAddress {
    /// Encodes the address as a Bech32m string with TLV payload.
    pub fn encode(&self) -> Result<String, AddressError> {
        let mut payload = Vec::new();

        // TLV records in ascending type order.
        push_tlv(&mut payload, tlv_types::VERSION, &[self.version]);
        push_tlv(
            &mut payload,
            tlv_types::ASSET_VERSION,
            &[self.asset_version],
        );
        if let Some(ref asset_id) = self.asset_id {
            push_tlv(
                &mut payload,
                tlv_types::ASSET_ID,
                asset_id.as_bytes(),
            );
        }

        // Type 5: group_key (optional, before script_key).
        if let Some(ref gk) = self.group_key {
            push_tlv(&mut payload, tlv_types::GROUP_KEY, gk.as_bytes());
        }

        push_tlv(
            &mut payload,
            tlv_types::SCRIPT_KEY,
            self.script_key.as_bytes(),
        );
        push_tlv(
            &mut payload,
            tlv_types::INTERNAL_KEY,
            self.internal_key.as_bytes(),
        );

        // Type 9: tapscript_sibling (optional, before amount).
        if let Some(ref ts) = self.tapscript_sibling {
            push_tlv(&mut payload, tlv_types::TAPSCRIPT_SIBLING, ts);
        }

        // Type 10: amount as BigSize varint.
        let mut amount_buf = Vec::new();
        encode_bigsize(&mut amount_buf, self.amount);
        push_tlv(&mut payload, tlv_types::AMOUNT, &amount_buf);

        if let Some(ref courier) = self.proof_courier_addr {
            push_tlv(
                &mut payload,
                tlv_types::PROOF_COURIER_ADDR,
                courier.as_bytes(),
            );
        }

        // Unknown odd types (use BigSize for type numbers).
        for (&type_num, value) in &self.unknown_odd_types {
            encode_bigsize(&mut payload, type_num);
            payload.push(value.len() as u8);
            payload.extend_from_slice(value);
        }

        let hrp = Hrp::parse(self.network.hrp())
            .map_err(|e| AddressError::Bech32Error(e.to_string()))?;

        bech32::encode::<Bech32m>(hrp, &payload)
            .map_err(|e| AddressError::Bech32Error(e.to_string()))
    }

    /// Decodes a TAP address from a Bech32m string.
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let (hrp, payload) = bech32::decode(s)
            .map_err(|e| AddressError::Bech32Error(e.to_string()))?;

        let network = TapNetwork::from_hrp(hrp.as_str())?;

        // Parse TLV records.
        let mut version: Option<u8> = None;
        let mut asset_version: u8 = 0;
        let mut asset_id: Option<AssetId> = None;
        let mut script_key: Option<SerializedKey> = None;
        let mut internal_key: Option<SerializedKey> = None;
        let mut amount: u64 = 0;
        let mut proof_courier_addr: Option<String> = None;
        let mut group_key: Option<SerializedKey> = None;
        let mut tapscript_sibling: Option<Vec<u8>> = None;
        let mut unknown_odd_types = BTreeMap::new();

        let mut offset = 0;
        while offset < payload.len() {
            // Type number uses BigSize encoding.
            let (typ_u64, typ_bytes) =
                decode_bigsize(&payload[offset..]).map_err(|e| {
                    AddressError::InvalidPayload(e.to_string())
                })?;
            offset += typ_bytes;
            let typ = typ_u64;

            if offset >= payload.len() {
                return Err(AddressError::InvalidPayload(
                    "truncated TLV record".into(),
                ));
            }
            let len = payload[offset] as usize;
            offset += 1;

            if offset + len > payload.len() {
                return Err(AddressError::InvalidPayload(format!(
                    "TLV type {} length {} exceeds payload",
                    typ, len
                )));
            }
            let value = &payload[offset..offset + len];
            offset += len;

            // Handle large type numbers (> u8) as unknown types.
            if typ > 255 {
                if typ % 2 == 0 {
                    return Err(AddressError::InvalidPayload(
                        format!("unknown even TLV type {}", typ),
                    ));
                }
                unknown_odd_types.insert(typ, value.to_vec());
                continue;
            }

            match typ as u8 {
                tlv_types::VERSION => {
                    if len != 1 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "version",
                            expected: 1,
                            got: len,
                        });
                    }
                    version = Some(value[0]);
                }
                tlv_types::ASSET_VERSION => {
                    if len != 1 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "asset_version",
                            expected: 1,
                            got: len,
                        });
                    }
                    asset_version = value[0];
                }
                tlv_types::ASSET_ID => {
                    if len != 32 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "asset_id",
                            expected: 32,
                            got: len,
                        });
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(value);
                    asset_id = Some(AssetId(id));
                }
                tlv_types::SCRIPT_KEY => {
                    if len != 33 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "script_key",
                            expected: 33,
                            got: len,
                        });
                    }
                    let mut key = [0u8; 33];
                    key.copy_from_slice(value);
                    script_key = Some(SerializedKey(key));
                }
                tlv_types::INTERNAL_KEY => {
                    if len != 33 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "internal_key",
                            expected: 33,
                            got: len,
                        });
                    }
                    let mut key = [0u8; 33];
                    key.copy_from_slice(value);
                    internal_key = Some(SerializedKey(key));
                }
                tlv_types::AMOUNT => {
                    let (val, _) = decode_bigsize(value).map_err(
                        |e| AddressError::InvalidPayload(e.to_string()),
                    )?;
                    amount = val;
                }
                tlv_types::PROOF_COURIER_ADDR => {
                    proof_courier_addr = Some(
                        String::from_utf8(value.to_vec())
                            .map_err(|e| {
                                AddressError::InvalidPayload(
                                    e.to_string(),
                                )
                            })?,
                    );
                }
                tlv_types::GROUP_KEY => {
                    if len != 33 {
                        return Err(AddressError::InvalidFieldLength {
                            field: "group_key",
                            expected: 33,
                            got: len,
                        });
                    }
                    let mut key = [0u8; 33];
                    key.copy_from_slice(value);
                    group_key = Some(SerializedKey(key));
                }
                tlv_types::TAPSCRIPT_SIBLING => {
                    tapscript_sibling = Some(value.to_vec());
                }
                other => {
                    // Odd types are preserved; even unknown types are errors.
                    if other % 2 == 0 {
                        return Err(AddressError::InvalidPayload(format!(
                            "unknown even TLV type {}",
                            other
                        )));
                    }
                    unknown_odd_types
                        .insert(other as u64, value.to_vec());
                }
            }
        }

        Ok(TapAddress {
            version: version
                .ok_or(AddressError::MissingField("version"))?,
            asset_version,
            asset_id,
            script_key: script_key
                .ok_or(AddressError::MissingField("script_key"))?,
            internal_key: internal_key
                .ok_or(AddressError::MissingField("internal_key"))?,
            amount,
            network,
            proof_courier_addr,
            group_key,
            tapscript_sibling,
            unknown_odd_types,
        })
    }
}

/// Pushes a TLV record with a u8 type number.
fn push_tlv(buf: &mut Vec<u8>, typ: u8, value: &[u8]) {
    buf.push(typ);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

impl std::fmt::Display for TapAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.encode() {
            Ok(s) => write!(f, "{}", s),
            Err(e) => write!(f, "<invalid: {}>", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> TapAddress {
        TapAddress {
            version: 0,
            asset_version: 0,
            asset_id: Some(AssetId([0xAA; 32])),
            script_key: SerializedKey([0x02; 33]),
            internal_key: SerializedKey([0x03; 33]),
            amount: 1000,
            network: TapNetwork::Regtest,
            proof_courier_addr: None,
            group_key: None,
            tapscript_sibling: None,
            unknown_odd_types: BTreeMap::new(),
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let addr = test_address();
        let encoded = addr.encode().unwrap();
        let decoded = TapAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_regtest_hrp() {
        let addr = test_address();
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("taprt1"));
    }

    #[test]
    fn test_mainnet_hrp() {
        let mut addr = test_address();
        addr.network = TapNetwork::Mainnet;
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tap1"));
    }

    #[test]
    fn test_testnet_hrp() {
        let mut addr = test_address();
        addr.network = TapNetwork::Testnet;
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("taptb1"));
    }

    #[test]
    fn test_simnet_hrp() {
        let mut addr = test_address();
        addr.network = TapNetwork::Simnet;
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tapsb1"));
    }

    #[test]
    fn test_different_amounts() {
        let mut addr1 = test_address();
        addr1.amount = 100;
        let mut addr2 = test_address();
        addr2.amount = 200;

        let enc1 = addr1.encode().unwrap();
        let enc2 = addr2.encode().unwrap();
        assert_ne!(enc1, enc2);

        assert_eq!(TapAddress::decode(&enc1).unwrap().amount, 100);
        assert_eq!(TapAddress::decode(&enc2).unwrap().amount, 200);
    }

    #[test]
    fn test_with_group_key() {
        let mut addr = test_address();
        addr.group_key = Some(SerializedKey([0x03; 33]));
        let encoded = addr.encode().unwrap();
        let decoded = TapAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert!(decoded.group_key.is_some());
    }

    #[test]
    fn test_display() {
        let addr = test_address();
        let display = format!("{}", addr);
        assert!(display.starts_with("taprt1"));
        let decoded = TapAddress::decode(&display).unwrap();
        assert_eq!(addr, decoded);
    }
}
