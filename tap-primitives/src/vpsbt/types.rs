// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Type definitions for virtual PSBTs (vPSBTs), mirroring Go's
//! `tappsbt/interface.go` field for field.

use crate::address::{TapAddress, TapNetwork};
use crate::asset::{Asset, PrevId, SerializedKey};
use crate::commitment::{TapCommitmentVersion, TapscriptPreimage};
use crate::proof::types::Proof;

/// Errors from vPSBT encoding/decoding.
#[derive(Debug, Clone)]
pub enum VPsbtError {
    /// The data does not start with the PSBT magic bytes or the general
    /// BIP-174 structure is malformed.
    InvalidFormat(String),
    /// The global `IsVirtualTx` marker is missing or false.
    NotVirtualTx,
    /// The chain params HRP is missing or unknown.
    InvalidChainParamsHrp(String),
    /// The VPacket version is unknown, matching Go's
    /// `ErrInvalidVPacketVersion`.
    InvalidVPacketVersion(u8),
    /// A field failed to encode.
    EncodeError(String),
    /// A field failed to decode.
    DecodeError(String),
}

impl std::fmt::Display for VPsbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VPsbtError::InvalidFormat(msg) => {
                write!(f, "invalid PSBT format: {}", msg)
            }
            VPsbtError::NotVirtualTx => {
                write!(f, "not a virtual transaction")
            }
            VPsbtError::InvalidChainParamsHrp(hrp) => {
                write!(f, "invalid chain params HRP: {}", hrp)
            }
            VPsbtError::InvalidVPacketVersion(v) => {
                write!(f, "tappsbt: invalid version: {}", v)
            }
            VPsbtError::EncodeError(msg) => {
                write!(f, "vPSBT encode error: {}", msg)
            }
            VPsbtError::DecodeError(msg) => {
                write!(f, "vPSBT decode error: {}", msg)
            }
        }
    }
}

impl std::error::Error for VPsbtError {}

/// The version of a virtual transaction, matching Go's
/// `tappsbt.VPacketVersion`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VPacketVersion {
    /// V0 is the initial VPacket version. All VInputs and VOutputs use
    /// TapCommitments with version V0 or V1.
    #[default]
    V0 = 0,
    /// V1 VPackets require V2 TapCommitments for all VOutputs.
    V1 = 1,
}

impl VPacketVersion {
    /// Parses a version byte, rejecting unknown versions like Go's
    /// decoder.
    pub fn from_u8(v: u8) -> Result<Self, VPsbtError> {
        match v {
            0 => Ok(VPacketVersion::V0),
            1 => Ok(VPacketVersion::V1),
            other => Err(VPsbtError::InvalidVPacketVersion(other)),
        }
    }

    /// Returns the wire byte for this version.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Returns the Taproot Asset commitment version that matches the given
/// VPacket version, mirroring Go's `tappsbt.CommitmentVersion`.
///
/// For V0 the correct commitment version could be V0 or V1; it cannot
/// be known without accessing all leaves of the commitment itself, so
/// `None` is returned.
pub fn commitment_version(
    version: VPacketVersion,
) -> Result<Option<TapCommitmentVersion>, VPsbtError> {
    match version {
        VPacketVersion::V0 => Ok(None),
        VPacketVersion::V1 => Ok(Some(TapCommitmentVersion::V2)),
    }
}

/// The type of a virtual output, matching Go's `tappsbt.VOutputType`.
///
/// This is an open u8 on the wire; unknown values survive a decode and
/// re-encode round trip, like in Go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VOutputType(pub u8);

impl VOutputType {
    /// A plain full-value or split output that is not a split root and
    /// does not carry passive assets.
    pub const SIMPLE: VOutputType = VOutputType(0);

    /// A split root output that carries the change from a split or a
    /// tombstone from a non-interactive full value send output.
    pub const SPLIT_ROOT: VOutputType = VOutputType(1);

    /// Returns true if the output type is a split root.
    pub fn is_split_root(self) -> bool {
        self == VOutputType::SPLIT_ROOT
    }
}

/// A BIP-0032 derivation entry, matching Go's `psbt.Bip32Derivation`.
///
/// The public key is kept as raw bytes to stay byte-faithful with the
/// PSBT wire format (a 33-byte compressed public key).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bip32Derivation {
    /// The raw compressed public key (33 bytes).
    pub pub_key: Vec<u8>,
    /// The fingerprint of the master public key.
    pub master_key_fingerprint: u32,
    /// The BIP-0032 path with each child index as a distinct integer.
    pub bip32_path: Vec<u32>,
}

/// A Taproot BIP-0032 derivation entry, matching Go's
/// `psbt.TaprootBip32Derivation`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaprootBip32Derivation {
    /// The raw public key in x-only BIP-340 format (32 bytes).
    pub x_only_pub_key: Vec<u8>,
    /// The leaf hashes the public key is involved in.
    pub leaf_hashes: Vec<Vec<u8>>,
    /// The fingerprint of the master public key.
    pub master_key_fingerprint: u32,
    /// The BIP-0032 path with each child index as a distinct integer.
    pub bip32_path: Vec<u32>,
}

/// The essential parts of lnd's `keychain.KeyDescriptor`: a public key
/// plus its key locator (family and index).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDescriptor {
    /// The raw (pre-tweak) compressed public key.
    pub pub_key: SerializedKey,
    /// The key family of the locator.
    pub family: u32,
    /// The key index of the locator.
    pub index: u32,
}

/// Script key tweak information for a virtual output, mirroring Go's
/// `asset.TweakedScriptKey` together with the key locator carried by
/// its `keychain.KeyDescriptor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TweakedScriptKeyDesc {
    /// The raw key and its locator.
    pub raw_key: KeyDescriptor,
    /// The tweak applied to produce the script key. Empty means BIP-86
    /// style (tweak with no script path).
    pub tweak: Vec<u8>,
}

/// The script key of a virtual output: the tweaked Taproot output key
/// plus optional derivation info needed for signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputScriptKey {
    /// The tweaked Taproot output key (compressed, 33 bytes).
    pub pub_key: SerializedKey,
    /// Optional tweak/derivation information. When set, it is encoded
    /// into the standard PSBT output derivation fields.
    pub tweaked: Option<TweakedScriptKeyDesc>,
}

/// Information about the BTC level anchor output of a virtual input,
/// matching Go's `tappsbt.Anchor`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Anchor {
    /// The output value of the anchor output in satoshis.
    pub value: u64,
    /// The output script of the anchor output.
    pub pk_script: Vec<u8>,
    /// The signature hash type that should be used to sign the anchor
    /// output spend.
    pub sig_hash_type: u32,
    /// The internal key of the anchor output that the input is spending
    /// the asset from (compressed, 33 bytes).
    pub internal_key: Option<SerializedKey>,
    /// The root of the tap script merkle tree that also contains the
    /// Taproot Asset commitment of the anchor output.
    pub merkle_root: Vec<u8>,
    /// The tapscript sibling of the Taproot Asset commitment.
    pub tapscript_sibling: Vec<u8>,
    /// The BIP-0032 derivation of the anchor output's internal key.
    pub bip32_derivation: Vec<Bip32Derivation>,
    /// The Taproot BIP-0032 derivation of the anchor output's internal
    /// key.
    pub taproot_bip32_derivation: Vec<TaprootBip32Derivation>,
}

/// An input to a virtual asset state transition transaction, matching
/// Go's `tappsbt.VInput`.
///
/// The first five fields correspond to the standard BIP-174 PSBT input
/// fields that Go carries via the embedded `psbt.PInput` (the subset a
/// virtual input ever populates).
#[derive(Clone, Debug)]
pub struct VInput {
    /// Standard PSBT field: the BIP-0032 derivations of the input's
    /// script key.
    pub bip32_derivation: Vec<Bip32Derivation>,
    /// Standard PSBT field: the Taproot BIP-0032 derivations of the
    /// input's script key.
    pub taproot_bip32_derivation: Vec<TaprootBip32Derivation>,
    /// Standard PSBT field: the x-only Taproot internal key of the
    /// input's script key (empty when unset).
    pub taproot_internal_key: Vec<u8>,
    /// Standard PSBT field: the Taproot merkle root, which for a
    /// virtual input carries the script key tweak (empty when unset).
    pub taproot_merkle_root: Vec<u8>,
    /// Standard PSBT field: the sighash type (0 means unset and is not
    /// serialized).
    pub sighash_type: u32,
    /// The asset previous ID of the asset being spent.
    pub prev_id: PrevId,
    /// Information about the BTC level anchor transaction that
    /// committed to the asset being spent.
    pub anchor: Anchor,
    /// The full instance of the asset being spent.
    pub asset: Option<Asset>,
    /// A transition proof that proves the asset being spent was
    /// committed to in the anchor transaction above.
    pub proof: Option<Proof>,
}

impl Default for VInput {
    fn default() -> Self {
        VInput {
            bip32_derivation: Vec::new(),
            taproot_bip32_derivation: Vec::new(),
            taproot_internal_key: Vec::new(),
            taproot_merkle_root: Vec::new(),
            sighash_type: 0,
            prev_id: PrevId::ZERO,
            anchor: Anchor::default(),
            asset: None,
            proof: None,
        }
    }
}

impl VInput {
    /// Returns the input's asset that is being spent.
    pub fn asset(&self) -> Option<&Asset> {
        self.asset.as_ref()
    }
}

/// An output of a virtual asset state transition, matching Go's
/// `tappsbt.VOutput`.
#[derive(Clone, Debug)]
pub struct VOutput {
    /// The amount of units of the asset that this output is creating.
    pub amount: u64,
    /// The version of the asset that this output should create (an open
    /// u8 like in Go, so unknown values survive a round trip).
    pub asset_version: u8,
    /// The type of this output.
    pub output_type: VOutputType,
    /// Whether the receiver of the output is aware of the asset
    /// transfer.
    pub interactive: bool,
    /// The output index of the BTC transaction this asset output should
    /// be committed to.
    pub anchor_output_index: u32,
    /// The internal key of the anchor output (compressed, 33 bytes).
    pub anchor_output_internal_key: Option<SerializedKey>,
    /// The BIP-0032 derivation of the anchor output's internal key.
    pub anchor_output_bip32_derivation: Vec<Bip32Derivation>,
    /// The Taproot BIP-0032 derivation of the anchor output's internal
    /// key.
    pub anchor_output_taproot_bip32_derivation: Vec<TaprootBip32Derivation>,
    /// The preimage of the tapscript sibling of the Taproot Asset
    /// commitment.
    pub anchor_output_tapscript_sibling: Option<TapscriptPreimage>,
    /// The actual asset (including witness or split commitment data)
    /// that this output will commit to on chain.
    pub asset: Option<Asset>,
    /// The original split asset that was created when creating the
    /// split commitment. Only set if `asset` is the root asset of a
    /// split.
    pub split_asset: Option<Asset>,
    /// The new script key of the recipient of the asset.
    pub script_key: OutputScriptKey,
    /// The relative lock time of the output asset.
    pub relative_lock_time: u64,
    /// The lock time of the output asset.
    pub lock_time: u64,
    /// The address to which the proof of the asset transfer should be
    /// delivered (a URL, kept as a string).
    pub proof_delivery_address: Option<String>,
    /// The optional new transition proof that is created once the asset
    /// output was committed to the anchor transaction referenced above.
    pub proof_suffix: Option<Proof>,
    /// Alt leaves to be inserted in the output anchor Tap commitment.
    pub alt_leaves: Vec<Asset>,
    /// The Taproot Asset address that was used to create this output.
    pub address: Option<TapAddress>,
}

impl VOutput {
    /// Returns true if this output is a split root output.
    pub fn is_split_root(&self) -> bool {
        self.output_type.is_split_root()
    }
}

/// A PSBT extension packet for a virtual transaction, matching Go's
/// `tappsbt.VPacket`. It represents the virtual asset state transition
/// as validated by the Taproot Asset VM.
#[derive(Clone, Debug)]
pub struct VPacket {
    /// The list of asset inputs that are being spent.
    pub inputs: Vec<VInput>,
    /// The list of new asset outputs that are created by the virtual
    /// transaction.
    pub outputs: Vec<VOutput>,
    /// The Taproot Asset chain parameters (identified by their HRP)
    /// used to encode and decode certain contents of the packet.
    pub chain_params: TapNetwork,
    /// The version of the virtual transaction.
    pub version: VPacketVersion,
}

impl VPacket {
    /// Returns the Taproot Asset commitment version matching this
    /// packet's version, mirroring Go's `tappsbt.CommitmentVersion`.
    pub fn commitment_version(
        &self,
    ) -> Result<Option<TapCommitmentVersion>, VPsbtError> {
        commitment_version(self.version)
    }

    /// Determines if this virtual transaction has a split root output.
    pub fn has_split_root_output(&self) -> bool {
        self.outputs.iter().any(VOutput::is_split_root)
    }

    /// Determines if this virtual transaction has an interactive
    /// output.
    pub fn has_interactive_output(&self) -> bool {
        self.outputs.iter().any(|o| o.interactive)
    }
}

/// Returns the BIP-0044 coin type used for key derivation paths on the
/// given network, matching the `HDCoinType` of Go's
/// `address.ChainParams` (which comes from btcd's `chaincfg`).
pub fn hd_coin_type(network: TapNetwork) -> u32 {
    match network {
        TapNetwork::Mainnet => 0,
        TapNetwork::Testnet
        | TapNetwork::Testnet4
        | TapNetwork::Regtest
        | TapNetwork::Signet => 1,
        TapNetwork::Simnet => 115,
    }
}
