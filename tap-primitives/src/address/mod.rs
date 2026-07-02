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

use crate::asset::{AssetId, AssetType, SerializedKey};
use crate::commitment::TapCommitmentVersion;
use crate::encoding::bigsize::{decode_bigsize, encode_bigsize};

/// The proof courier scheme required by V2 addresses. Matches Go's
/// `proof.AuthMailboxUniRpcCourierType`.
pub const AUTH_MAILBOX_UNI_RPC_COURIER_TYPE: &str =
    "authmailbox+universerpc";

/// Human-readable parts for different networks.
///
/// These must match Go's `address/params.go`: mainnet is "tapbc" and
/// testnet3, testnet4, and signet all share "taptb".
pub const HRP_MAINNET: &str = "tapbc";
pub const HRP_TESTNET: &str = "taptb";
pub const HRP_REGTEST: &str = "taprt";
pub const HRP_SIMNET: &str = "tapsb";
pub const HRP_TESTNET4: &str = "taptb";
pub const HRP_SIGNET: &str = "taptb";

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

/// The version of a Taproot Asset address format.
///
/// Mirrors Go's `address.Version`: V0 is the initial format, V1
/// addresses use V2 Taproot Asset commitments, and V2 addresses support
/// sending grouped assets and require the authmailbox proof courier
/// address format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AddressVersion {
    /// The initial Taproot Asset address format version.
    V0 = 0,
    /// V1 addresses use V2 Taproot Asset commitments.
    V1 = 1,
    /// V2 addresses support sending grouped assets and require the new
    /// auth mailbox proof courier address format.
    V2 = 2,
}

impl AddressVersion {
    /// Parses an address version byte. Unlike asset versions, address
    /// versions are closed: anything above V2 is rejected, matching
    /// Go's `IsUnknownVersion` / `ErrUnknownVersion`.
    pub fn from_u8(v: u8) -> Result<Self, AddressError> {
        match v {
            0 => Ok(AddressVersion::V0),
            1 => Ok(AddressVersion::V1),
            2 => Ok(AddressVersion::V2),
            other => Err(AddressError::UnknownVersion(other)),
        }
    }

    /// Returns the wire byte for this version.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A Taproot Asset address for receiving assets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapAddress {
    /// Address version (0, 1, or 2).
    pub version: AddressVersion,
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
    Signet,
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
            TapNetwork::Signet => HRP_SIGNET,
        }
    }

    /// Parses a network from an HRP string.
    ///
    /// Testnet3, testnet4, and signet share the "taptb" HRP; this
    /// returns `Testnet` for it, matching Go's `Net()` which resolves
    /// the shared HRP to testnet3 first.
    pub fn from_hrp(hrp: &str) -> Result<Self, AddressError> {
        match hrp {
            "tapbc" => Ok(TapNetwork::Mainnet),
            "taptb" => Ok(TapNetwork::Testnet),
            "taprt" => Ok(TapNetwork::Regtest),
            "tapsb" => Ok(TapNetwork::Simnet),
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
    /// The address version is not recognized. Matches Go's
    /// `ErrUnknownVersion`.
    UnknownVersion(u8),
    /// Collectible addresses must have an amount of exactly 1. Matches
    /// Go's `ErrInvalidAmountCollectible`.
    InvalidAmountCollectible,
    /// Normal asset addresses must have a non-zero amount (except V2).
    /// Matches Go's `ErrInvalidAmountNormal`.
    InvalidAmountNormal,
    /// The asset type is not supported. Matches Go's
    /// `ErrUnsupportedAssetType`.
    UnsupportedAssetType,
    /// The proof courier address is missing or invalid for the address
    /// version. Matches Go's `ErrInvalidProofCourierAddr`.
    InvalidProofCourierAddr(String),
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
            AddressError::UnknownVersion(v) => {
                write!(f, "address: unknown version number {}", v)
            }
            AddressError::InvalidAmountCollectible => {
                write!(
                    f,
                    "address: collectible asset amount must be 1"
                )
            }
            AddressError::InvalidAmountNormal => {
                write!(
                    f,
                    "address: normal asset amount must be non-zero"
                )
            }
            AddressError::UnsupportedAssetType => {
                write!(f, "address: unsupported asset type")
            }
            AddressError::InvalidProofCourierAddr(msg) => {
                write!(
                    f,
                    "address: invalid proof courier address: {}",
                    msg
                )
            }
        }
    }
}

impl std::error::Error for AddressError {}

/// Parameters for creating a new Taproot Asset address. Mirrors the
/// fields of Go's `address.NewAddressParams` used by `address.New`.
#[derive(Clone, Debug)]
pub struct NewAddressParams {
    /// Address format version.
    pub version: AddressVersion,
    /// The asset to receive. Required for non-V2 addresses and for V2
    /// addresses without a group key.
    pub asset_id: Option<AssetId>,
    /// Optional group key. For V2 addresses this makes the address
    /// receive any asset of the group and the asset ID is dropped.
    pub group_key: Option<SerializedKey>,
    /// The recipient's script key.
    pub script_key: SerializedKey,
    /// The recipient's internal key for the Taproot output.
    pub internal_key: SerializedKey,
    /// Amount of asset units to receive.
    pub amount: u64,
    /// The type of the asset being received.
    pub asset_type: AssetType,
    /// Network for the address encoding.
    pub network: TapNetwork,
    /// Proof courier address. Required (with the authmailbox scheme)
    /// for V2 addresses.
    pub proof_courier_addr: Option<String>,
    /// Optional encoded tapscript sibling preimage.
    pub tapscript_sibling: Option<Vec<u8>>,
}

/// Creates an address for receiving a Taproot Asset, applying the same
/// validation (in the same order) as Go's `address.New`.
pub fn new(params: NewAddressParams) -> Result<TapAddress, AddressError> {
    // Check for invalid combinations of asset type and amount.
    // Collectible assets must have an amount of 1, and Normal assets
    // must have a non-zero amount (V2 addresses may omit the amount).
    // We also reject invalid asset types.
    match params.asset_type {
        AssetType::Collectible => {
            if params.amount != 1 {
                return Err(AddressError::InvalidAmountCollectible);
            }
        }
        AssetType::Normal => {
            if params.amount == 0
                && params.version != AddressVersion::V2
            {
                return Err(AddressError::InvalidAmountNormal);
            }
        }
        AssetType::Unknown(_) => {
            return Err(AddressError::UnsupportedAssetType);
        }
    }

    // The version is a closed enum here, so it is known by
    // construction; callers holding a raw byte go through
    // `AddressVersion::from_u8`, which rejects unknown versions.

    // Version 2 addresses behave slightly differently than V0 and V1
    // addresses.
    let mut asset_id = params.asset_id;
    if params.version == AddressVersion::V2 {
        // Addresses with version 2 or later must use the new
        // authmailbox proof courier type.
        let courier = params.proof_courier_addr.as_deref().ok_or_else(
            || {
                AddressError::InvalidProofCourierAddr(format!(
                    "address version 2 must use the '{}' proof courier \
                     type",
                    AUTH_MAILBOX_UNI_RPC_COURIER_TYPE
                ))
            },
        )?;
        let scheme = courier.split_once("://").map(|(s, _)| s);
        if scheme != Some(AUTH_MAILBOX_UNI_RPC_COURIER_TYPE) {
            return Err(AddressError::InvalidProofCourierAddr(format!(
                "address version 2 must use the '{}' proof courier type",
                AUTH_MAILBOX_UNI_RPC_COURIER_TYPE
            )));
        }

        // If a group key is provided, then we zero out the asset ID in
        // the address, as it doesn't make sense (we'll ignore it anyway
        // when sending assets to this address).
        if params.group_key.is_some() {
            asset_id = None;
        }
    }

    // Outside the group-key V2 case, the asset ID is what identifies
    // the asset to receive, so it is required.
    if asset_id.is_none()
        && !(params.version == AddressVersion::V2
            && params.group_key.is_some())
    {
        return Err(AddressError::MissingField("asset_id"));
    }

    Ok(TapAddress {
        version: params.version,
        asset_version: 0,
        asset_id,
        script_key: params.script_key,
        internal_key: params.internal_key,
        amount: params.amount,
        network: params.network,
        proof_courier_addr: params.proof_courier_addr,
        group_key: params.group_key,
        tapscript_sibling: params.tapscript_sibling,
        unknown_odd_types: BTreeMap::new(),
    })
}

impl TapAddress {
    /// Encodes the address as a Bech32m string with TLV payload.
    pub fn encode(&self) -> Result<String, AddressError> {
        let mut payload = Vec::new();

        // TLV records in ascending type order.
        push_tlv(
            &mut payload,
            tlv_types::VERSION,
            &[self.version.to_u8()],
        );
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

        // Unknown odd types (BigSize type numbers and lengths).
        for (&type_num, value) in &self.unknown_odd_types {
            encode_bigsize(&mut payload, type_num);
            encode_bigsize(&mut payload, value.len() as u64);
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
        let mut version: Option<AddressVersion> = None;
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
            // Length uses BigSize encoding, matching lnd's TLV format.
            let (len_u64, len_bytes) =
                decode_bigsize(&payload[offset..]).map_err(|e| {
                    AddressError::InvalidPayload(e.to_string())
                })?;
            offset += len_bytes;
            let len = len_u64 as usize;

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
                    version = Some(AddressVersion::from_u8(value[0])?);
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

        let address = TapAddress {
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
        };

        address.validate()?;

        Ok(address)
    }

    /// Validates version-dependent semantic rules.
    ///
    /// These are the rules that hold for every well-formed address of a
    /// given version (all of Go's generated test vectors satisfy them):
    /// V0/V1 addresses identify the asset by ID and always carry a
    /// non-zero amount; V2 addresses require a proof courier address.
    /// The stricter creation-time rules (courier scheme, asset type vs
    /// amount) only apply in [`new`], mirroring Go where they live in
    /// `address.New` and not in `DecodeAddress`.
    pub fn validate(&self) -> Result<(), AddressError> {
        if self.version != AddressVersion::V2 {
            if self.asset_id.is_none() {
                return Err(AddressError::MissingField("asset_id"));
            }
            if self.amount == 0 {
                return Err(AddressError::InvalidAmountNormal);
            }
        } else if self.proof_courier_addr.is_none() {
            return Err(AddressError::MissingField(
                "proof_courier_addr",
            ));
        }

        Ok(())
    }

    /// Returns the Taproot Asset commitment version that matches the
    /// address version. Mirrors Go's `address.CommitmentVersion`: for
    /// V0 the correct commitment version could be V0 or V1, which can
    /// only be determined from the commitment itself, so `None` is
    /// returned.
    pub fn commitment_version(&self) -> Option<TapCommitmentVersion> {
        match self.version {
            AddressVersion::V0 => None,
            AddressVersion::V1 | AddressVersion::V2 => {
                Some(TapCommitmentVersion::V2)
            }
        }
    }

    /// Returns true if the address supports grouped assets. Mirrors
    /// Go's `Tap.SupportsGroupedAssets`.
    pub fn supports_grouped_assets(&self) -> bool {
        self.version == AddressVersion::V2
    }

    /// Returns true if the address requires the authmailbox proof
    /// courier type to transport a send manifest from the sender to the
    /// receiver. Mirrors Go's `Tap.UsesSendManifests`.
    pub fn uses_send_manifests(&self) -> bool {
        self.version == AddressVersion::V2
    }
}

/// Pushes a TLV record with a u8 type number.
///
/// Both the type and length use BigSize encoding, matching lnd's TLV
/// format (a single byte for values below 253).
fn push_tlv(buf: &mut Vec<u8>, typ: u8, value: &[u8]) {
    encode_bigsize(buf, typ as u64);
    encode_bigsize(buf, value.len() as u64);
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
            version: AddressVersion::V0,
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
        assert!(encoded.starts_with("tapbc1"));
    }

    #[test]
    fn test_signet_hrp_shared_with_testnet() {
        let mut addr = test_address();
        addr.network = TapNetwork::Signet;
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("taptb1"));
        // The shared HRP resolves to testnet on decode, like Go.
        let decoded = TapAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.network, TapNetwork::Testnet);
    }

    #[test]
    fn test_long_courier_addr_roundtrip() {
        // Values of 253 bytes or more exercise the multi-byte BigSize
        // length encoding.
        let mut addr = test_address();
        let long_url =
            format!("hashmail://{}.example.com", "a".repeat(300));
        addr.proof_courier_addr = Some(long_url);
        let encoded = addr.encode().unwrap();
        let decoded = TapAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
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

    // -----------------------------------------------------------------
    // AddressVersion and new() validation tests, ported from the Go
    // address.New error cases in address/address_test.go.
    // -----------------------------------------------------------------

    fn test_params(
        version: AddressVersion,
        asset_type: AssetType,
        amount: u64,
    ) -> NewAddressParams {
        NewAddressParams {
            version,
            asset_id: Some(AssetId([0xAA; 32])),
            group_key: None,
            script_key: SerializedKey([0x02; 33]),
            internal_key: SerializedKey([0x03; 33]),
            amount,
            asset_type,
            network: TapNetwork::Regtest,
            proof_courier_addr: match version {
                AddressVersion::V2 => Some(
                    "authmailbox+universerpc://foo.bar:10029".to_string(),
                ),
                _ => None,
            },
            tapscript_sibling: None,
        }
    }

    #[test]
    fn test_version_from_u8() {
        assert_eq!(
            AddressVersion::from_u8(0).unwrap(),
            AddressVersion::V0
        );
        assert_eq!(
            AddressVersion::from_u8(1).unwrap(),
            AddressVersion::V1
        );
        assert_eq!(
            AddressVersion::from_u8(2).unwrap(),
            AddressVersion::V2
        );
        assert!(matches!(
            AddressVersion::from_u8(3),
            Err(AddressError::UnknownVersion(3))
        ));
        assert!(matches!(
            AddressVersion::from_u8(255),
            Err(AddressError::UnknownVersion(255))
        ));
    }

    #[test]
    fn test_version_to_u8_roundtrip() {
        for v in [
            AddressVersion::V0,
            AddressVersion::V1,
            AddressVersion::V2,
        ] {
            assert_eq!(AddressVersion::from_u8(v.to_u8()).unwrap(), v);
        }
    }

    #[test]
    fn test_new_collectible_wrong_amount() {
        // Go: "collectible addresses need amount of 1".
        for amount in [0u64, 2, 100] {
            let params = test_params(
                AddressVersion::V0,
                AssetType::Collectible,
                amount,
            );
            assert!(matches!(
                new(params),
                Err(AddressError::InvalidAmountCollectible)
            ));
        }
    }

    #[test]
    fn test_new_collectible_amount_one() {
        let params =
            test_params(AddressVersion::V0, AssetType::Collectible, 1);
        assert!(new(params).is_ok());
    }

    #[test]
    fn test_new_normal_zero_amount() {
        // Go: "normal addresses can't have amount of 0" (non-V2).
        for version in [AddressVersion::V0, AddressVersion::V1] {
            let params = test_params(version, AssetType::Normal, 0);
            assert!(matches!(
                new(params),
                Err(AddressError::InvalidAmountNormal)
            ));
        }
    }

    #[test]
    fn test_new_v2_zero_amount_allowed() {
        let params = test_params(AddressVersion::V2, AssetType::Normal, 0);
        let addr = new(params).unwrap();
        assert_eq!(addr.amount, 0);
        assert_eq!(addr.version, AddressVersion::V2);
    }

    #[test]
    fn test_new_unsupported_asset_type() {
        let params = test_params(
            AddressVersion::V0,
            AssetType::Unknown(123),
            100,
        );
        assert!(matches!(
            new(params),
            Err(AddressError::UnsupportedAssetType)
        ));
    }

    #[test]
    fn test_new_v2_requires_courier() {
        let mut params =
            test_params(AddressVersion::V2, AssetType::Normal, 100);
        params.proof_courier_addr = None;
        assert!(matches!(
            new(params),
            Err(AddressError::InvalidProofCourierAddr(_))
        ));
    }

    #[test]
    fn test_new_v2_wrong_courier_scheme() {
        // Go: V2 must use the authmailbox+universerpc courier type.
        for courier in [
            "universerpc://foo.bar:10029",
            "hashmail://foo.bar:10029",
            "authmailbox://foo.bar:10029",
            "not-a-url",
        ] {
            let mut params =
                test_params(AddressVersion::V2, AssetType::Normal, 100);
            params.proof_courier_addr = Some(courier.to_string());
            assert!(
                matches!(
                    new(params),
                    Err(AddressError::InvalidProofCourierAddr(_))
                ),
                "courier {} should be rejected",
                courier
            );
        }
    }

    #[test]
    fn test_new_non_v2_courier_scheme_unchecked() {
        // Non-V2 addresses accept any courier scheme, like Go.
        let mut params =
            test_params(AddressVersion::V0, AssetType::Normal, 100);
        params.proof_courier_addr =
            Some("hashmail://foo.bar:10029".to_string());
        assert!(new(params).is_ok());
    }

    #[test]
    fn test_new_v2_group_key_drops_asset_id() {
        // Go zeroes the asset ID when a group key is set on a V2
        // address; here the ID is dropped from the encoding entirely.
        let mut params =
            test_params(AddressVersion::V2, AssetType::Normal, 100);
        params.group_key = Some(SerializedKey([0x03; 33]));
        let addr = new(params).unwrap();
        assert!(addr.asset_id.is_none());
        assert!(addr.group_key.is_some());
        assert!(addr.supports_grouped_assets());
    }

    #[test]
    fn test_new_missing_asset_id() {
        // Non-V2 addresses require an asset ID; so do V2 addresses
        // without a group key.
        for version in [
            AddressVersion::V0,
            AddressVersion::V1,
            AddressVersion::V2,
        ] {
            let mut params = test_params(version, AssetType::Normal, 100);
            params.asset_id = None;
            assert!(matches!(
                new(params),
                Err(AddressError::MissingField("asset_id"))
            ));
        }
    }

    #[test]
    fn test_commitment_version() {
        let mut addr = test_address();
        addr.version = AddressVersion::V0;
        assert_eq!(addr.commitment_version(), None);
        addr.version = AddressVersion::V1;
        assert_eq!(
            addr.commitment_version(),
            Some(TapCommitmentVersion::V2)
        );
        addr.version = AddressVersion::V2;
        assert_eq!(
            addr.commitment_version(),
            Some(TapCommitmentVersion::V2)
        );
    }

    #[test]
    fn test_v2_capabilities() {
        let mut addr = test_address();
        assert!(!addr.supports_grouped_assets());
        assert!(!addr.uses_send_manifests());

        addr.version = AddressVersion::V2;
        assert!(addr.supports_grouped_assets());
        assert!(addr.uses_send_manifests());
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        // Encode a valid address, then corrupt the version record. The
        // version TLV is the first record: type 0, length 1, value.
        let addr = test_address();
        let encoded = addr.encode().unwrap();
        let (hrp, mut payload) = bech32::decode(&encoded).unwrap();
        assert_eq!(payload[0], 0);
        assert_eq!(payload[1], 1);
        payload[2] = 99;
        let corrupted =
            bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert!(matches!(
            TapAddress::decode(&corrupted),
            Err(AddressError::UnknownVersion(99))
        ));
    }

    #[test]
    fn test_decode_v0_zero_amount_rejected() {
        let mut addr = test_address();
        addr.amount = 0;
        let encoded = addr.encode().unwrap();
        assert!(matches!(
            TapAddress::decode(&encoded),
            Err(AddressError::InvalidAmountNormal)
        ));
    }

    #[test]
    fn test_decode_v0_missing_asset_id_rejected() {
        let mut addr = test_address();
        addr.asset_id = None;
        let encoded = addr.encode().unwrap();
        assert!(matches!(
            TapAddress::decode(&encoded),
            Err(AddressError::MissingField("asset_id"))
        ));
    }

    #[test]
    fn test_decode_v2_requires_courier() {
        let mut addr = test_address();
        addr.version = AddressVersion::V2;
        addr.proof_courier_addr = None;
        let encoded = addr.encode().unwrap();
        assert!(matches!(
            TapAddress::decode(&encoded),
            Err(AddressError::MissingField("proof_courier_addr"))
        ));

        addr.proof_courier_addr =
            Some("authmailbox+universerpc://foo.bar:10029".to_string());
        let encoded = addr.encode().unwrap();
        let decoded = TapAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.version, AddressVersion::V2);
    }
}
