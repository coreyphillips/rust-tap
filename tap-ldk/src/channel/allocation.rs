// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Coin allocation logic for asset channels.
//!
//! This is a port of Go's `tapsend/allocation.go` (and the sorting rules
//! from `tapsend/allocation_sort.go`). An [`Allocation`] is a recipe that
//! describes how many asset units (and how many satoshis) should be
//! assigned to a specific output of an on-chain transaction. The
//! [`distribute_coins`] function deterministically re-distributes
//! heterogeneous asset inputs (asset UTXOs of different sizes from
//! different tranches / asset IDs) across a list of allocations, producing
//! one virtual packet per distinct asset ID.
//!
//! Divergences from the Go implementation (all documented inline as well):
//!
//! - Go's `DistributeCoins` takes `[]*proof.Proof` and builds the virtual
//!   packet inputs via `tappsbt.FromProofs`, which copies anchor
//!   transaction data out of the proofs. The local `tap-primitives` crate
//!   has no `FromProofs` equivalent, so [`distribute_coins`] takes the
//!   input assets directly (`&[Asset]`). The produced `VInput`s carry the
//!   previous ID (asset ID plus script key) and the full input asset, but
//!   the anchor information (previous outpoint, anchor pk script, merkle
//!   root) is left at its default value.
//! - Go generates output script keys through a `ScriptKeyGen` closure that
//!   receives the asset ID. The channel code (`tapchannel/commitment.go`)
//!   only ever uses `StaticScriptKeyGen`, so the port stores a single
//!   static [`ScriptKey`] per allocation instead of a generator function.
//! - Go's `NonAssetLeaves` holds a full list of tapscript leaves and
//!   supports arbitrary tapscript trees when computing the sibling
//!   preimage. Channel outputs only ever produce one or two leaves, so
//!   this port supports zero, one, or two leaves and returns an error for
//!   larger trees.
//! - The Go `Allocation` carries a TAP address (`Address *address.Tap`)
//!   for send flows; that field is not needed for channel allocations and
//!   is omitted here.

use std::collections::BTreeMap;

use tap_primitives::address::TapNetwork;
use tap_primitives::asset::{Asset, AssetId, AssetType, ScriptKey, SerializedKey};
use tap_primitives::commitment::{
    tap_commitment_key, TapCommitment, TapscriptPreimage,
};
use tap_primitives::crypto::keys::{compute_taproot_output_key, parse_pub_key};
use tap_primitives::crypto::tapscript::tap_leaf_hash;
use tap_primitives::vpsbt::{
    Bip32Derivation, KeyDescriptor, OutputScriptKey, TaprootBip32Derivation,
    TweakedScriptKeyDesc, VInput, VOutput, VOutputType, VPacket,
    VPacketVersion,
};

use super::traits::AssetChannelError;

/// The BIP-341 base tapscript leaf version (0xc0) used for all Taproot
/// Asset related leaves.
const BASE_LEAF_VERSION: u8 = 0xc0;

/// Errors that can occur during coin allocation.
///
/// The variants mirror the error variables declared at the top of Go's
/// `tapsend/allocation.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocationError {
    /// No inputs were provided (Go's `ErrMissingInputs`).
    MissingInputs,
    /// No allocations were provided (Go's `ErrMissingAllocations`).
    MissingAllocations,
    /// The input types are not all the same (Go's
    /// `ErrInputTypesNotEqual`).
    InputTypesNotEqual,
    /// The input assets do not all belong to the same asset group (Go's
    /// `ErrInputGroupMismatch`).
    InputGroupMismatch,
    /// The sum of the inputs does not match the sum of the output
    /// allocations (Go's `ErrInputOutputSumMismatch`).
    InputOutputSumMismatch {
        /// Total number of input asset units.
        input: u64,
        /// Total number of allocated output asset units.
        output: u64,
    },
    /// The output commitment is not set for an allocation (Go's
    /// `ErrCommitmentNotSet`).
    CommitmentNotSet,
    /// Both non-asset leaves and a sibling preimage are set for an
    /// allocation (Go's `ErrInvalidSibling`).
    InvalidSibling,
    /// The static script key is not set for an asset-carrying allocation
    /// (Go's `ErrScriptKeyGenMissing`; this port uses a static script
    /// key instead of a generator function).
    ScriptKeyGenMissing,
    /// A non-interactive send does not specify which output should house
    /// the split root asset (Go's `ErrNoSplitRoot`).
    NoSplitRoot,
    /// The internal key of the allocation is not set but is required.
    MissingInternalKey,
    /// A key could not be parsed or tweaked.
    InvalidKey(String),
    /// A sibling preimage could not be constructed or hashed.
    InvalidPreimage(String),
    /// No output commitment was found for the given output index in
    /// [`assign_output_commitments`].
    MissingOutputCommitment(u32),
    /// An arithmetic overflow occurred while summing amounts.
    AmountOverflow,
    /// The virtual packet versions are not all the same.
    MismatchedVPacketVersions,
}

impl std::fmt::Display for AllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocationError::MissingInputs => {
                write!(f, "no inputs provided")
            }
            AllocationError::MissingAllocations => {
                write!(f, "no allocations provided")
            }
            AllocationError::InputTypesNotEqual => {
                write!(f, "input types not all equal")
            }
            AllocationError::InputGroupMismatch => {
                write!(f, "input assets not all of same group")
            }
            AllocationError::InputOutputSumMismatch { input, output } => {
                write!(
                    f,
                    "input and output sum mismatch: input={}, output={}",
                    input, output
                )
            }
            AllocationError::CommitmentNotSet => {
                write!(f, "output commitment not set")
            }
            AllocationError::InvalidSibling => {
                write!(f, "both non-asset leaves and sibling preimage set")
            }
            AllocationError::ScriptKeyGenMissing => {
                write!(
                    f,
                    "script key not set for asset allocation"
                )
            }
            AllocationError::NoSplitRoot => {
                write!(
                    f,
                    "non-interactive transfers must specify which output \
                     should house the split root asset"
                )
            }
            AllocationError::MissingInternalKey => {
                write!(f, "internal key not set for allocation")
            }
            AllocationError::InvalidKey(msg) => {
                write!(f, "invalid key: {}", msg)
            }
            AllocationError::InvalidPreimage(msg) => {
                write!(f, "invalid sibling preimage: {}", msg)
            }
            AllocationError::MissingOutputCommitment(idx) => {
                write!(
                    f,
                    "no output commitment found for output index {}",
                    idx
                )
            }
            AllocationError::AmountOverflow => {
                write!(f, "amount overflow")
            }
            AllocationError::MismatchedVPacketVersions => {
                write!(f, "mismatched virtual packet versions")
            }
        }
    }
}

impl std::error::Error for AllocationError {}

impl From<AllocationError> for AssetChannelError {
    fn from(e: AllocationError) -> Self {
        AssetChannelError(e.to_string())
    }
}

/// The different types of asset allocations that can be created.
///
/// The numeric values mirror the constants in Go's
/// `tapsend/allocation.go` exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AllocationType {
    /// The default allocation type, used when the allocation type is not
    /// important or the allocation does not carry any assets (Go's
    /// `AllocationTypeNoAssets` = 0).
    #[default]
    NoAssets = 0,

    /// Allocates assets to the local party (Go's
    /// `CommitAllocationToLocal` = 1).
    CommitAllocationToLocal = 1,

    /// Allocates assets to the remote party (Go's
    /// `CommitAllocationToRemote` = 2).
    CommitAllocationToRemote = 2,

    /// Allocates assets to an incoming HTLC output (Go's
    /// `CommitAllocationHtlcIncoming` = 3).
    HtlcIncoming = 3,

    /// Allocates assets to an outgoing HTLC output (Go's
    /// `CommitAllocationHtlcOutgoing` = 4).
    HtlcOutgoing = 4,

    /// Allocates assets to a second level HTLC output: HTLC-success for
    /// HTLCs accepted by the local node, HTLC-timeout for HTLCs offered
    /// by the local node (Go's `SecondLevelHtlcAllocation` = 5).
    SecondLevelHtlc = 5,
}

impl AllocationType {
    /// Returns the numeric wire value of this allocation type, matching
    /// the Go constants.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A recipe that tracks how many units of assets should be allocated to
/// a specific output of an on-chain transaction.
///
/// This mirrors Go's `tapsend.Allocation`. The output is mainly
/// identified by its output index but also carries along additional
/// information required to sort the resulting on-chain outputs in a
/// deterministic way (almost but not exactly following the BIP-69 rules
/// for sorting transaction outputs).
#[derive(Debug, Clone, Default)]
pub struct Allocation {
    /// The type of the asset allocation.
    pub alloc_type: AllocationType,

    /// The output index of the on-chain transaction which the asset
    /// allocation is meant for.
    pub output_index: u32,

    /// Whether the virtual output(s) created for the allocation should
    /// house the split root asset.
    pub split_root: bool,

    /// The internal key used for the on-chain transaction output
    /// (compressed, 33 bytes).
    pub internal_key: Option<SerializedKey>,

    /// The BIP-0032 derivation info for the internal key, preserved
    /// through the allocation flow so PSBTs can be properly signed.
    pub bip32_derivation: Vec<Bip32Derivation>,

    /// The taproot BIP-0032 derivation info for the internal key.
    pub taproot_bip32_derivation: Vec<TaprootBip32Derivation>,

    /// The raw scripts of the tapscript leaves that are not asset
    /// commitments (implied leaf version 0xc0). Used to construct the
    /// tapscript sibling for the asset commitment. Mutually exclusive
    /// with `sibling_preimage`; if both are empty for a non-asset
    /// allocation, a BIP-0086 output is assumed.
    ///
    /// Divergence from Go: Go stores full `txscript.TapLeaf` values and
    /// supports arbitrary trees; this port supports at most two leaves
    /// (channel outputs never produce more).
    pub non_asset_leaves: Vec<Vec<u8>>,

    /// The tapscript sibling preimage used to create the tapscript
    /// sibling for the asset commitment. Mutually exclusive with
    /// `non_asset_leaves`.
    pub sibling_preimage: Option<TapscriptPreimage>,

    /// The Taproot tweaked script key encoding the different spend
    /// conditions possible for the asset allocation.
    ///
    /// Divergence from Go: Go uses a `ScriptKeyGen` closure keyed by
    /// asset ID; the channel code only ever uses a static key
    /// (`StaticScriptKeyGen`), which is what this field represents.
    pub script_key: Option<ScriptKey>,

    /// The amount of asset units that should be allocated in total.
    /// Available units from different UTXOs are distributed up to this
    /// total amount in a deterministic way.
    pub amount: u64,

    /// The asset version that the allocation outputs should use (open
    /// u8 like the vpsbt module).
    pub asset_version: u8,

    /// The amount in satoshis that should be sent to the output address
    /// of the anchor transaction.
    pub btc_amount: u64,

    /// The Schnorr serialized (32-byte x-only) Taproot output key of the
    /// on-chain P2TR output that would be created if there was no asset
    /// commitment present. This field is used for sorting purposes.
    pub sort_taproot_key_bytes: Vec<u8>,

    /// The CLTV timeout for the asset allocation, only relevant for
    /// sorting purposes. Expected to be zero for any non-HTLC
    /// allocation.
    pub sort_cltv: u32,

    /// The CSV value for the asset allocation, only relevant for HTLC
    /// second level transactions. Set as the relative time lock on the
    /// virtual output.
    pub sequence: u32,

    /// The actual CLTV value that will be set on the output.
    pub lock_time: u64,

    /// The index of the HTLC that the allocation is for, only relevant
    /// for HTLC allocations.
    pub htlc_index: u64,

    /// The taproot output commitment, set after fully distributing the
    /// coins and creating the asset and TAP trees.
    pub output_commitment: Option<TapCommitment>,

    /// The address (URL) the proof courier should use to upload the
    /// proof for this allocation.
    pub proof_delivery_address: Option<String>,

    /// Alt leaves to be inserted in the output anchor TAP commitment.
    pub alt_leaves: Vec<Asset>,
}

impl Allocation {
    /// Checks that the allocation is correctly set up and that the
    /// fields are consistent with each other, mirroring Go's
    /// `Allocation.Validate`.
    pub fn validate(&self) -> Result<(), AllocationError> {
        // Make sure the two mutually exclusive fields are not set at the
        // same time.
        if !self.non_asset_leaves.is_empty() && self.sibling_preimage.is_some()
        {
            return Err(AllocationError::InvalidSibling);
        }

        // The script key is required for any allocation that carries
        // assets.
        if self.alloc_type != AllocationType::NoAssets
            && self.script_key.is_none()
        {
            return Err(AllocationError::ScriptKeyGenMissing);
        }

        Ok(())
    }

    /// Returns the tapscript sibling preimage, either directly from the
    /// `sibling_preimage` field or derived from the non-asset leaves.
    /// Returns `None` if neither is set, mirroring Go's
    /// `Allocation.tapscriptSibling`.
    pub fn tapscript_sibling(
        &self,
    ) -> Result<Option<TapscriptPreimage>, AllocationError> {
        if self.non_asset_leaves.is_empty() && self.sibling_preimage.is_none()
        {
            return Ok(None);
        }

        // The sibling preimage has precedence. Only one of the two
        // fields should be set in any case.
        if let Some(preimage) = &self.sibling_preimage {
            return Ok(Some(preimage.clone()));
        }

        // Derive the preimage from the non-asset leaves. Go supports
        // arbitrary tapscript trees here; channel outputs only ever
        // create one or two leaves, so this port supports at most two.
        match self.non_asset_leaves.len() {
            1 => {
                // A single leaf becomes a leaf preimage:
                // leaf_version(1) || varbytes(script).
                let script = &self.non_asset_leaves[0];
                let mut preimage =
                    Vec::with_capacity(1 + 9 + script.len());
                preimage.push(BASE_LEAF_VERSION);
                write_var_bytes(&mut preimage, script);
                Ok(Some(TapscriptPreimage {
                    sibling_type: 0,
                    sibling_preimage: preimage,
                }))
            }
            2 => {
                // Two leaves become a branch preimage: the two 32-byte
                // tap leaf hashes. The branch hash itself sorts its
                // children, so the stored order does not affect the
                // final hash.
                let left = tap_leaf_hash(
                    BASE_LEAF_VERSION,
                    &self.non_asset_leaves[0],
                );
                let right = tap_leaf_hash(
                    BASE_LEAF_VERSION,
                    &self.non_asset_leaves[1],
                );
                let mut preimage = Vec::with_capacity(64);
                preimage.extend_from_slice(&left);
                preimage.extend_from_slice(&right);
                Ok(Some(TapscriptPreimage {
                    sibling_type: 1,
                    sibling_preimage: preimage,
                }))
            }
            n => Err(AllocationError::InvalidPreimage(format!(
                "unsupported number of non-asset leaves: {} (this port \
                 supports at most 2)",
                n
            ))),
        }
    }

    /// Returns the pkScript calculated from the internal key, tapscript
    /// sibling and merkle root of the output commitment, mirroring Go's
    /// `Allocation.FinalPkScript`.
    ///
    /// The result is always a 34-byte P2TR script:
    /// `OP_1 OP_PUSHBYTES_32 <32-byte x-only output key>`.
    ///
    /// If the allocation carries assets and the output commitment is not
    /// set, [`AllocationError::CommitmentNotSet`] is returned.
    pub fn final_pk_script(&self) -> Result<Vec<u8>, AllocationError> {
        // If this is a normal commitment anchor output without any
        // assets, then we map the sort Taproot output key to a script
        // directly.
        if self.alloc_type == AllocationType::NoAssets {
            let key_bytes: [u8; 32] = self
                .sort_taproot_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| {
                    AllocationError::InvalidKey(format!(
                        "sort taproot key must be 32 bytes, got {}",
                        self.sort_taproot_key_bytes.len()
                    ))
                })?;

            // Validate that the bytes are a valid x-only public key by
            // parsing them as a compressed key with even parity
            // (mirrors Go's schnorr.ParsePubKey validation).
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&key_bytes);
            parse_pub_key(&SerializedKey(compressed))
                .map_err(|e| AllocationError::InvalidKey(e.to_string()))?;

            return Ok(pay_to_taproot_script(&key_bytes));
        }

        let commitment = self
            .output_commitment
            .as_ref()
            .ok_or(AllocationError::CommitmentNotSet)?;

        let sibling = self.tapscript_sibling()?;
        let sibling_hash = match &sibling {
            Some(preimage) => Some(preimage.tap_hash().map_err(|e| {
                AllocationError::InvalidPreimage(e.to_string())
            })?),
            None => None,
        };

        let tapscript_root = commitment.tapscript_root(sibling_hash.as_ref());

        let internal_key = self
            .internal_key
            .as_ref()
            .ok_or(AllocationError::MissingInternalKey)?;
        let internal_pub_key = parse_pub_key(internal_key)
            .map_err(|e| AllocationError::InvalidKey(e.to_string()))?;
        let (internal_x_only, _) = internal_pub_key.x_only_public_key();

        let output_key =
            compute_taproot_output_key(&internal_x_only, Some(&tapscript_root))
                .map_err(|e| AllocationError::InvalidKey(e.to_string()))?;

        Ok(pay_to_taproot_script(&output_key.serialize()))
    }

    /// Returns the auxiliary tapscript leaf (the serialized TAP
    /// commitment leaf script) for the allocation, mirroring Go's
    /// `Allocation.AuxLeaf`. If the output commitment is not set,
    /// [`AllocationError::CommitmentNotSet`] is returned.
    pub fn aux_leaf(&self) -> Result<Vec<u8>, AllocationError> {
        let commitment = self
            .output_commitment
            .as_ref()
            .ok_or(AllocationError::CommitmentNotSet)?;

        Ok(commitment.tap_leaf())
    }

    /// Returns true if the unique identifying characteristics of an
    /// on-chain commitment output match this allocation, mirroring Go's
    /// `Allocation.MatchesOutput`.
    pub fn matches_output(
        &self,
        pk_script: &[u8],
        value: i64,
        cltv: u32,
        htlc_index: u64,
    ) -> Result<bool, AllocationError> {
        let final_pk_script = self.final_pk_script()?;

        Ok(pk_script == final_pk_script.as_slice()
            && value == self.btc_amount as i64
            && cltv == self.sort_cltv
            && htlc_index == self.htlc_index)
    }
}

/// Builds a 34-byte pay-to-taproot output script from a 32-byte x-only
/// output key: `OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <key>`.
fn pay_to_taproot_script(output_key: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51);
    script.push(0x20);
    script.extend_from_slice(output_key);
    script
}

/// Appends a Bitcoin compact-size-prefixed byte slice to `buf`.
fn write_var_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u64;
    if len < 0xfd {
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&len.to_le_bytes());
    }
    buf.extend_from_slice(bytes);
}

/// Performs an in-place sort of output allocations, mirroring Go's
/// `tapsend.InPlaceAllocationSort` (`allocation_sort.go`).
///
/// The sort applied is a modified BIP-69 sort that uses the CLTV values
/// of HTLCs as a tiebreaker in case two HTLC outputs have an identical
/// amount and pkScript, and the HTLC index as a final tiebreaker (for
/// multiple shards of the same MPP payment). Commitment and commitment
/// anchor outputs should have a zero CLTV and HTLC index value.
pub fn in_place_allocation_sort(allocations: &mut [Allocation]) {
    allocations.sort_by(|i, j| {
        i.btc_amount
            .cmp(&j.btc_amount)
            .then_with(|| {
                i.sort_taproot_key_bytes.cmp(&j.sort_taproot_key_bytes)
            })
            .then_with(|| i.sort_cltv.cmp(&j.sort_cltv))
            .then_with(|| i.htlc_index.cmp(&j.htlc_index))
    });
}

/// Comparison function used to sort asset inputs by amount in reverse
/// order (largest amounts first) and then by script key, mirroring Go's
/// `tapsend.AssetSortForInputs`. Using this everywhere inputs are sorted
/// ensures they are always in a predictable and stable order.
pub fn asset_sort_for_inputs(i: &Asset, j: &Asset) -> std::cmp::Ordering {
    j.amount.cmp(&i.amount).then_with(|| {
        i.script_key
            .pub_key
            .as_bytes()
            .cmp(j.script_key.pub_key.as_bytes())
    })
}

/// Tracks the currently available and allocated assets for a specific
/// asset ID, along with the virtual packet being built for that asset
/// ID. Mirrors Go's `tapsend.piece` (the `proofs` field becomes
/// `inputs`, see the module-level divergence notes).
#[derive(Debug, Clone)]
struct Piece {
    /// The ID of the asset that is being distributed.
    asset_id: AssetId,

    /// The sum of all asset outputs that are available for distribution
    /// per asset ID.
    total_available: u64,

    /// The amount of assets that have been allocated so far.
    allocated: u64,

    /// The input assets that make up this piece (Go keeps the full
    /// proofs here).
    inputs: Vec<Asset>,

    /// The virtual packet that is being built for the asset ID.
    packet: VPacket,
}

impl Piece {
    /// Returns the amount of assets that are still available for
    /// distribution.
    fn available(&self) -> u64 {
        self.total_available - self.allocated
    }
}

/// Sorts the given pieces by asset ID and the contained inputs by amount
/// (in reverse order) and then script key, mirroring Go's
/// `sortPiecesWithProofs`. This gives a stable order for all asset
/// UTXOs.
fn sort_pieces_with_inputs(pieces: &mut [Piece]) {
    // Sort pieces by asset ID.
    pieces.sort_by(|i, j| i.asset_id.as_bytes().cmp(j.asset_id.as_bytes()));

    // Now sort all the inputs within each piece by amount and then
    // script key.
    for piece in pieces.iter_mut() {
        piece.inputs.sort_by(asset_sort_for_inputs);
    }
}

/// Returns the TAP commitment key of the given asset, mirroring Go's
/// `asset.Asset.TapCommitmentKey`.
fn asset_tap_commitment_key(asset: &Asset) -> [u8; 32] {
    tap_commitment_key(
        &asset.id(),
        asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
    )
}

/// Builds a virtual input for the given input asset.
///
/// Divergence from Go: `tappsbt.FromProofs` fills in the anchor
/// transaction data (previous outpoint, anchor value, pk script, merkle
/// root, sibling) from the input proofs. Since this port receives bare
/// assets, only the previous ID (asset ID plus script key) and the input
/// asset itself are populated; the anchor data stays at its default.
fn v_input_from_asset(asset_id: AssetId, asset: &Asset) -> VInput {
    let mut v_in = VInput::default();
    v_in.prev_id.id = asset_id;
    v_in.prev_id.script_key = asset.script_key.pub_key;
    v_in.asset = Some(asset.clone());
    v_in
}

/// Allocates a set of input assets to virtual outputs as specified by
/// the given allocations, mirroring Go's `tapsend.DistributeCoins`.
///
/// It returns a list of virtual packets (one for each distinct asset ID)
/// with virtual outputs that sum up to the amounts specified in the
/// allocations. The main purpose of this function is to
/// deterministically re-distribute heterogeneous asset outputs (asset
/// UTXOs of different sizes from different tranches / asset IDs)
/// according to the distribution rules provided as allocations.
///
/// Divergence from Go: the inputs are the bare input assets instead of
/// full transition proofs (see the module-level notes).
pub fn distribute_coins(
    inputs: &[Asset],
    allocations: &[Allocation],
    chain_params: TapNetwork,
    interactive: bool,
    vpkt_version: VPacketVersion,
) -> Result<Vec<VPacket>, AllocationError> {
    if inputs.is_empty() {
        return Err(AllocationError::MissingInputs);
    }

    if allocations.is_empty() {
        return Err(AllocationError::MissingAllocations);
    }

    // Count how many asset units are available for distribution.
    let first_type = effective_asset_type(&inputs[0]);
    let first_tap_key = asset_tap_commitment_key(&inputs[0]);
    let mut input_sum: u64 = 0;
    for input in inputs {
        // We cannot have mixed types (normal and collectibles) within
        // the same allocation.
        if first_type != effective_asset_type(input) {
            return Err(AllocationError::InputTypesNotEqual);
        }

        // Allocating assets from different asset groups is not allowed.
        if first_tap_key != asset_tap_commitment_key(input) {
            return Err(AllocationError::InputGroupMismatch);
        }

        input_sum = input_sum
            .checked_add(input.amount)
            .ok_or(AllocationError::AmountOverflow)?;
    }

    // Sum up the amounts that are to be allocated to the outputs. We
    // also validate that all the required fields are set and no
    // conflicting fields are set.
    let mut output_sum: u64 = 0;
    let mut have_split_root = false;
    for allocation in allocations {
        allocation.validate()?;

        output_sum = output_sum
            .checked_add(allocation.amount)
            .ok_or(AllocationError::AmountOverflow)?;
        have_split_root = have_split_root || allocation.split_root;
    }

    // Non-interactive transfers need to specify which output should
    // house the split root asset, because that will need to be the
    // output that goes back to the sender (or to a zero-amount tombstone
    // output the sender owns the internal key for). In interactive
    // transfers it does not matter which output houses the split root
    // asset, we will just assign one later if needed.
    if !interactive && !have_split_root {
        return Err(AllocationError::NoSplitRoot);
    }

    // Asset change must be allocated upfront as well. We expect the sum
    // of the inputs to match the sum of the output allocations.
    if input_sum != output_sum {
        return Err(AllocationError::InputOutputSumMismatch {
            input: input_sum,
            output: output_sum,
        });
    }

    // We group the assets by asset ID, since we will want to create a
    // single virtual packet per asset ID (with each virtual packet
    // potentially having multiple inputs and outputs).
    let mut grouped: BTreeMap<AssetId, Vec<Asset>> = BTreeMap::new();
    for input in inputs {
        grouped.entry(input.id()).or_default().push(input.clone());
    }

    // Each piece keeps track of how many assets of a specific asset ID
    // we have already distributed. The pieces are also the main way to
    // reference an asset ID's virtual packet.
    let mut pieces: Vec<Piece> = Vec::with_capacity(grouped.len());
    for (asset_id, mut assets_by_id) in grouped {
        let mut sum_by_id: u64 = 0;
        for asset in &assets_by_id {
            sum_by_id = sum_by_id
                .checked_add(asset.amount)
                .ok_or(AllocationError::AmountOverflow)?;
        }

        // Before creating the virtual packet, sort the inputs by amount
        // (in reverse order) then by script key. This ensures
        // deterministic ordering before assigning them to the virtual
        // packet inputs.
        assets_by_id.sort_by(asset_sort_for_inputs);

        let packet = VPacket {
            inputs: assets_by_id
                .iter()
                .map(|a| v_input_from_asset(asset_id, a))
                .collect(),
            outputs: Vec::new(),
            chain_params,
            version: vpkt_version,
        };

        pieces.push(Piece {
            asset_id,
            total_available: sum_by_id,
            allocated: 0,
            inputs: assets_by_id,
            packet,
        });
    }

    // Make sure the pieces are in a stable and reproducible order before
    // we start the distribution.
    sort_pieces_with_inputs(&mut pieces);

    for allocation in allocations {
        // If the allocation has no assets (commitment anchor output or
        // otherwise), then we can safely skip it.
        if allocation.alloc_type == AllocationType::NoAssets {
            continue;
        }

        // Find the next piece that has assets left to allocate.
        let mut to_fill = allocation.amount;
        for piece in pieces.iter_mut() {
            let fill_delta =
                allocate_piece(piece, allocation, to_fill, interactive)?;

            to_fill -= fill_delta;

            // If the piece has enough assets to fill the allocation, we
            // can exit the loop, unless we also need to create a
            // tombstone output for a non-interactive send. If it only
            // fills part of the allocation, we continue to the next
            // piece.
            if to_fill == 0 && interactive {
                break;
            }
        }
    }

    let mut packets: Vec<VPacket> =
        pieces.into_iter().map(|p| p.packet).collect();
    validate_vpacket_versions(&packets)?;

    // If we are doing a non-interactive transfer, we are done here.
    if !interactive {
        return Ok(packets);
    }

    // For interactive packets we will now assign a split root output (if
    // needed).
    for packet in packets.iter_mut() {
        // If we have more than one output (meaning we are going to split
        // the assets), and we do not have a split root output yet, we
        // select the first output to be the split root. In interactive
        // transfers it does not really matter which output is selected.
        if packet.outputs.len() > 1 && !packet.has_split_root_output() {
            packet.outputs[0].output_type = VOutputType::SPLIT_ROOT;
        }
    }

    Ok(packets)
}

/// Returns the asset type of the given asset (carried on its genesis).
fn effective_asset_type(asset: &Asset) -> AssetType {
    asset.genesis.asset_type
}

/// Verifies that all packets share the same virtual packet version,
/// mirroring Go's `tapsend.ValidateVPacketVersions` for the subset used
/// by the distribution logic.
fn validate_vpacket_versions(
    packets: &[VPacket],
) -> Result<(), AllocationError> {
    if let Some(first) = packets.first() {
        if packets.iter().any(|p| p.version != first.version) {
            return Err(AllocationError::MismatchedVPacketVersions);
        }
    }

    Ok(())
}

/// Allocates assets from the given piece to the given allocation, if
/// there are units left to allocate, mirroring Go's
/// `tapsend.allocatePiece`. This adds a virtual output to the piece's
/// packet and updates the amount of allocated assets. Returns the amount
/// of assets that were allocated.
fn allocate_piece(
    piece: &mut Piece,
    allocation: &Allocation,
    to_fill: u64,
    interactive: bool,
) -> Result<u64, AllocationError> {
    let sibling = allocation.tapscript_sibling()?;

    // Divergence from Go: the script key is static per allocation
    // instead of being generated per asset ID (see module notes).
    let script_key = allocation
        .script_key
        .clone()
        .ok_or(AllocationError::ScriptKeyGenMissing)?;

    let mut v_out = VOutput {
        amount: 0,
        asset_version: allocation.asset_version,
        output_type: VOutputType::SIMPLE,
        interactive,
        anchor_output_index: allocation.output_index,
        anchor_output_internal_key: allocation.internal_key,
        anchor_output_bip32_derivation: allocation.bip32_derivation.clone(),
        anchor_output_taproot_bip32_derivation: allocation
            .taproot_bip32_derivation
            .clone(),
        anchor_output_tapscript_sibling: sibling,
        asset: None,
        split_asset: None,
        script_key: OutputScriptKey {
            pub_key: script_key.pub_key,
            tweaked: script_key.tweaked.map(|t| TweakedScriptKeyDesc {
                raw_key: KeyDescriptor {
                    pub_key: t.raw_key,
                    family: 0,
                    index: 0,
                },
                tweak: t.tweak,
            }),
        },
        relative_lock_time: u64::from(allocation.sequence),
        lock_time: allocation.lock_time,
        proof_delivery_address: allocation.proof_delivery_address.clone(),
        proof_suffix: None,
        alt_leaves: allocation.alt_leaves.clone(),
        address: None,
    };

    // If we have allocated all pieces, or we do not need to allocate
    // anything to this piece, we might only need to create a tombstone
    // output.
    if piece.available() == 0 || to_fill == 0 {
        // We do not need a tombstone output for interactive transfers,
        // or recipient outputs (outputs that do not go back to the
        // sender).
        if interactive || !allocation.split_root {
            return Ok(0);
        }

        // Create a zero-amount tombstone output for the split root, if
        // there is no change.
        v_out.output_type = VOutputType::SPLIT_ROOT;
        piece.packet.outputs.push(v_out);

        return Ok(0);
    }

    // We know we have something to allocate, so let us now create a new
    // virtual output for the allocation.
    let allocating = if piece.available() < to_fill {
        piece.available()
    } else {
        to_fill
    };

    // We only need a split root output if this piece is being split. If
    // we consume it fully in this allocation, we can use a simple
    // output.
    let consume_fully =
        piece.allocated == 0 && to_fill >= piece.available();

    // If we are creating a non-interactive packet (e.g. for a TAP
    // address based send), we definitely need a split root, even if
    // there is no change. If there is change, then we also need a split
    // root, even if we are creating a fully interactive packet.
    let need_split_root =
        allocation.split_root && (!interactive || !consume_fully);

    // The only exception is when the split root output is the only
    // output, because it is not being used at all and goes back to the
    // sender.
    let split_root_is_only_output = allocation.split_root && consume_fully;

    let out_type = if need_split_root && !split_root_is_only_output {
        VOutputType::SPLIT_ROOT
    } else {
        VOutputType::SIMPLE
    };

    // We just need to update the type and amount for this virtual
    // output, everything else can be taken from the allocation itself.
    v_out.output_type = out_type;
    v_out.amount = allocating;
    piece.packet.outputs.push(v_out);

    piece.allocated += allocating;

    Ok(allocating)
}

/// Assigns the output commitments (keyed by the on-chain output index)
/// to the corresponding allocations, mirroring Go's
/// `tapsend.AssignOutputCommitments`.
pub fn assign_output_commitments(
    allocations: &mut [Allocation],
    out_commitments: &BTreeMap<u32, TapCommitment>,
) -> Result<(), AllocationError> {
    for allocation in allocations.iter_mut() {
        // Allocations without any assets will not be mapped to an output
        // commitment.
        if allocation.alloc_type == AllocationType::NoAssets {
            continue;
        }

        let out_commitment = out_commitments
            .get(&allocation.output_index)
            .ok_or(AllocationError::MissingOutputCommitment(
                allocation.output_index,
            ))?;

        allocation.output_commitment = Some(out_commitment.clone());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tap_primitives::asset::{
        Genesis, GroupKey, GroupKeyVersion, OutPoint,
    };
    use tap_primitives::commitment::{AssetCommitment, TapCommitmentVersion};
    use tap_primitives::crypto::tapscript::tap_branch_hash;

    /// The secp256k1 generator point, compressed.
    const G_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];

    fn hex_byte(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex char"),
        }
    }

    fn hex33(s: &str) -> SerializedKey {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 66);
        let mut out = [0u8; 33];
        for i in 0..33 {
            out[i] =
                (hex_byte(bytes[2 * i]) << 4) | hex_byte(bytes[2 * i + 1]);
        }
        SerializedKey(out)
    }

    /// The two fixed script keys from Go's TestSortPiecesWithProofs.
    fn key1() -> SerializedKey {
        hex33(
            "03a15fd6e1fded33270ae01183dfc8f8edd1274644b7d014ac5ab576f\
             bf8328b05",
        )
    }

    fn key2() -> SerializedKey {
        hex33(
            "029191ec924fb3c6bbd0d264d0b3cf97fcb2fc1eb5737184e7e17e35c\
             6609ee853",
        )
    }

    /// A deterministic, distinct (but not necessarily on-curve) script
    /// key. Only used where the key bytes are compared, never parsed.
    fn sk(i: u8) -> ScriptKey {
        let mut bytes = [0x02u8; 33];
        bytes[32] = i;
        ScriptKey::from_pub_key(SerializedKey(bytes))
    }

    fn test_group_key() -> GroupKey {
        GroupKey {
            version: GroupKeyVersion::V0,
            raw_key: SerializedKey(G_COMPRESSED),
            group_pub_key: SerializedKey(G_COMPRESSED),
            tapscript_root: vec![],
            witness: vec![],
        }
    }

    /// Grinds a genesis whose asset ID starts with the given prefix
    /// byte, mirroring Go's `grindAssetID`.
    fn grind_genesis(prefix: u8, asset_type: AssetType) -> Genesis {
        for i in 0u32..100_000 {
            let genesis = Genesis {
                first_prev_out: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                tag: format!("grind-{}-{}", prefix, i),
                meta_hash: [0u8; 32],
                output_index: 0,
                asset_type,
            };
            if genesis.id().as_bytes()[0] == prefix {
                return genesis;
            }
        }
        panic!("failed to grind asset ID prefix {}", prefix);
    }

    fn make_asset(
        genesis: &Genesis,
        amount: u64,
        script_key: ScriptKey,
        group_key: Option<GroupKey>,
    ) -> Asset {
        let mut asset = Asset::new_genesis(genesis.clone(), amount, script_key);
        asset.group_key = group_key;
        asset
    }

    fn alloc(
        alloc_type: AllocationType,
        amount: u64,
        output_index: u32,
        split_root: bool,
    ) -> Allocation {
        Allocation {
            alloc_type,
            amount,
            output_index,
            split_root,
            script_key: Some(sk(0xff)),
            ..Default::default()
        }
    }

    fn make_commitment(amount: u64) -> TapCommitment {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [7u8; 32],
                vout: 0,
            },
            tag: "commitment-test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis,
            amount,
            ScriptKey::from_pub_key(key1()),
        );
        let asset_commitment =
            AssetCommitment::new(&[&asset]).expect("asset commitment");
        TapCommitment::from_asset_commitments(
            Some(TapCommitmentVersion::V2),
            &[&asset_commitment],
        )
        .expect("tap commitment")
    }

    #[test]
    fn allocation_type_values_match_go() {
        // Verified against the const block in Go's
        // tapsend/allocation.go.
        assert_eq!(AllocationType::NoAssets.to_u8(), 0);
        assert_eq!(AllocationType::CommitAllocationToLocal.to_u8(), 1);
        assert_eq!(AllocationType::CommitAllocationToRemote.to_u8(), 2);
        assert_eq!(AllocationType::HtlcIncoming.to_u8(), 3);
        assert_eq!(AllocationType::HtlcOutgoing.to_u8(), 4);
        assert_eq!(AllocationType::SecondLevelHtlc.to_u8(), 5);
    }

    /// Runs distribute_coins and returns the error, panicking if the
    /// call unexpectedly succeeded (VPacket has no PartialEq, so the
    /// full Result cannot be compared directly).
    fn distribute_err(
        inputs: &[Asset],
        allocations: &[Allocation],
        interactive: bool,
    ) -> AllocationError {
        match distribute_coins(
            inputs,
            allocations,
            TapNetwork::Regtest,
            interactive,
            VPacketVersion::V1,
        ) {
            Ok(_) => panic!("expected distribute_coins to fail"),
            Err(e) => e,
        }
    }

    #[test]
    fn distribute_coins_errors() {
        // No inputs.
        assert_eq!(
            distribute_err(&[], &[], true),
            AllocationError::MissingInputs,
        );

        // No allocations.
        let genesis_normal = grind_genesis(0x01, AssetType::Normal);
        let asset_normal =
            make_asset(&genesis_normal, 100, sk(1), None);
        assert_eq!(
            distribute_err(std::slice::from_ref(&asset_normal), &[], true),
            AllocationError::MissingAllocations,
        );

        // Mixed asset types.
        let genesis_collectible =
            grind_genesis(0x02, AssetType::Collectible);
        let asset_collectible =
            make_asset(&genesis_collectible, 1, sk(2), None);
        assert_eq!(
            distribute_err(
                &[asset_normal.clone(), asset_collectible],
                &[Allocation::default()],
                true,
            ),
            AllocationError::InputTypesNotEqual,
        );

        // Different asset groups (two ungrouped assets with different
        // asset IDs have different TAP commitment keys).
        let genesis_normal2 = grind_genesis(0x03, AssetType::Normal);
        let asset_normal2 = make_asset(&genesis_normal2, 100, sk(3), None);
        assert_eq!(
            distribute_err(
                &[asset_normal.clone(), asset_normal2],
                &[Allocation::default()],
                true,
            ),
            AllocationError::InputGroupMismatch,
        );

        // Input and output sums do not match.
        assert_eq!(
            distribute_err(
                std::slice::from_ref(&asset_normal),
                &[Allocation {
                    amount: asset_normal.amount / 2,
                    script_key: Some(sk(9)),
                    ..Default::default()
                }],
                true,
            ),
            AllocationError::InputOutputSumMismatch {
                input: 100,
                output: 50
            },
        );

        // Both non-asset leaves and sibling preimage set.
        assert_eq!(
            distribute_err(
                std::slice::from_ref(&asset_normal),
                &[Allocation {
                    amount: asset_normal.amount,
                    non_asset_leaves: vec![vec![]],
                    sibling_preimage: Some(TapscriptPreimage {
                        sibling_type: 0,
                        sibling_preimage: vec![],
                    }),
                    ..Default::default()
                }],
                true,
            ),
            AllocationError::InvalidSibling,
        );

        // Missing script key for an asset-carrying allocation.
        assert_eq!(
            distribute_err(
                std::slice::from_ref(&asset_normal),
                &[Allocation {
                    alloc_type: AllocationType::CommitAllocationToLocal,
                    amount: asset_normal.amount,
                    ..Default::default()
                }],
                true,
            ),
            AllocationError::ScriptKeyGenMissing,
        );

        // Non-interactive transfer without a split root allocation.
        assert_eq!(
            distribute_err(
                std::slice::from_ref(&asset_normal),
                &[
                    Allocation {
                        alloc_type:
                            AllocationType::CommitAllocationToLocal,
                        amount: asset_normal.amount / 2,
                        script_key: Some(sk(9)),
                        ..Default::default()
                    },
                    Allocation {
                        alloc_type:
                            AllocationType::CommitAllocationToRemote,
                        amount: asset_normal.amount / 2,
                        script_key: Some(sk(9)),
                        ..Default::default()
                    },
                ],
                false,
            ),
            AllocationError::NoSplitRoot,
        );
    }

    /// Expected virtual output: (amount, type, anchor output index).
    type ExpectedOut = (u64, VOutputType, u32);

    struct DistCase {
        name: &'static str,
        inputs: Vec<Asset>,
        interactive: bool,
        allocations: Vec<Allocation>,
        vpkt_version: VPacketVersion,
        /// Per asset ID: the expected input script keys, in order.
        expected_inputs: Vec<(AssetId, Vec<SerializedKey>)>,
        /// Per asset ID: the expected outputs, in order.
        expected_outputs: Vec<(AssetId, Vec<ExpectedOut>)>,
    }

    #[test]
    fn distribute_coins_cases() {
        let simple = VOutputType::SIMPLE;
        let split = VOutputType::SPLIT_ROOT;
        let group = test_group_key();

        // Mirrors Go's grindAssetID(t, 0x0N) calls so the asset IDs
        // sort in a known order.
        let genesis1 = grind_genesis(0x01, AssetType::Normal);
        let genesis2 = grind_genesis(0x02, AssetType::Normal);
        let genesis3 = grind_genesis(0x03, AssetType::Normal);
        let genesis4 = grind_genesis(0x04, AssetType::Normal);
        let genesis5 = grind_genesis(0x05, AssetType::Normal);

        let id1 = genesis1.id();
        let id2 = genesis2.id();
        let id3 = genesis3.id();
        let id4 = genesis4.id();
        let id5 = genesis5.id();

        let a1t1 = make_asset(&genesis1, 100, sk(11), Some(group.clone()));
        let a1t2 = make_asset(&genesis1, 200, sk(12), Some(group.clone()));
        let a1t3 = make_asset(&genesis1, 300, sk(13), Some(group.clone()));

        let a2t1 = make_asset(&genesis2, 1000, sk(21), Some(group.clone()));
        let a2t2 = make_asset(&genesis2, 2000, sk(22), Some(group.clone()));
        let a2t3 = make_asset(&genesis2, 3000, sk(23), Some(group.clone()));

        let a3t1 = make_asset(&genesis3, 10000, sk(31), Some(group.clone()));
        let a3t2 = make_asset(&genesis3, 20000, sk(32), Some(group.clone()));
        let a3t3 = make_asset(&genesis3, 30000, sk(33), Some(group.clone()));

        let a4t1 = make_asset(&genesis4, 25000, sk(41), Some(group.clone()));
        let a5t1 = make_asset(&genesis5, 25000, sk(51), Some(group.clone()));

        let key_of = |a: &Asset| a.script_key.pub_key;

        let cases = vec![
            DistCase {
                name: "single asset, split, interactive",
                inputs: vec![a1t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        50,
                        0,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        50,
                        1,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V1,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(
                    id1,
                    vec![(50, simple, 0), (50, split, 1)],
                )],
            },
            DistCase {
                name: "single asset, split, non-interactive",
                inputs: vec![a1t1.clone()],
                interactive: false,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        50,
                        0,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        50,
                        1,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(
                    id1,
                    vec![(50, simple, 0), (50, split, 1)],
                )],
            },
            DistCase {
                name: "single asset, full value, interactive",
                inputs: vec![a1t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        100,
                        0,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        0,
                        1,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(id1, vec![(100, simple, 0)])],
            },
            DistCase {
                name: "single asset, full value, interactive, has split \
                       output",
                inputs: vec![a1t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        0,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        100,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(id1, vec![(100, simple, 1)])],
            },
            DistCase {
                name: "single asset, full value, non-interactive",
                inputs: vec![a1t1.clone()],
                interactive: false,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        100,
                        0,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        0,
                        1,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(
                    id1,
                    vec![(100, simple, 0), (0, split, 1)],
                )],
            },
            DistCase {
                name: "multiple assets, split, interactive",
                inputs: vec![a2t1.clone(), a2t2.clone()],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        1200,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        1800,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V1,
                expected_inputs: vec![(
                    id2,
                    vec![key_of(&a2t2), key_of(&a2t1)],
                )],
                expected_outputs: vec![(
                    id2,
                    vec![(1200, split, 0), (1800, simple, 1)],
                )],
            },
            DistCase {
                name: "multiple assets, split, non-interactive",
                inputs: vec![a2t1.clone(), a2t2.clone()],
                interactive: false,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        1200,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        1800,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(
                    id2,
                    vec![key_of(&a2t2), key_of(&a2t1)],
                )],
                expected_outputs: vec![(
                    id2,
                    vec![(1200, split, 0), (1800, simple, 1)],
                )],
            },
            DistCase {
                name: "multiple assets, one consumed fully, interactive",
                inputs: vec![a1t1.clone(), a2t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        1050,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        50,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![
                    (id1, vec![key_of(&a1t1)]),
                    (id2, vec![key_of(&a2t1)]),
                ],
                expected_outputs: vec![
                    (id1, vec![(100, simple, 0)]),
                    (id2, vec![(950, split, 0), (50, simple, 1)]),
                ],
            },
            DistCase {
                name: "multiple assets, one consumed fully, \
                       non-interactive",
                inputs: vec![a1t1.clone(), a2t1.clone()],
                interactive: false,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        50,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        1050,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![
                    (id1, vec![key_of(&a1t1)]),
                    (id2, vec![key_of(&a2t1)]),
                ],
                expected_outputs: vec![
                    (id1, vec![(50, split, 0), (50, simple, 1)]),
                    (id2, vec![(0, split, 0), (1000, simple, 1)]),
                ],
            },
            DistCase {
                name: "lots of assets, interactive",
                inputs: vec![
                    a1t1.clone(),
                    a1t2.clone(),
                    a1t3.clone(),
                    a2t1.clone(),
                    a2t2.clone(),
                    a2t3.clone(),
                    a3t1.clone(),
                    a3t2.clone(),
                    a3t3.clone(),
                ],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        3600,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        63000,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![
                    (
                        id1,
                        vec![
                            key_of(&a1t3),
                            key_of(&a1t2),
                            key_of(&a1t1),
                        ],
                    ),
                    (
                        id2,
                        vec![
                            key_of(&a2t3),
                            key_of(&a2t2),
                            key_of(&a2t1),
                        ],
                    ),
                    (
                        id3,
                        vec![
                            key_of(&a3t3),
                            key_of(&a3t2),
                            key_of(&a3t1),
                        ],
                    ),
                ],
                expected_outputs: vec![
                    (id1, vec![(600, simple, 0)]),
                    (id2, vec![(3000, split, 0), (3000, simple, 1)]),
                    (id3, vec![(60000, simple, 1)]),
                ],
            },
            DistCase {
                name: "lots of assets, non-interactive",
                inputs: vec![
                    a1t1.clone(),
                    a1t2.clone(),
                    a1t3.clone(),
                    a2t1.clone(),
                    a2t2.clone(),
                    a2t3.clone(),
                    a3t1.clone(),
                    a3t2.clone(),
                    a3t3.clone(),
                ],
                interactive: false,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        3600,
                        0,
                        true,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        63000,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![
                    (
                        id1,
                        vec![
                            key_of(&a1t3),
                            key_of(&a1t2),
                            key_of(&a1t1),
                        ],
                    ),
                    (
                        id2,
                        vec![
                            key_of(&a2t3),
                            key_of(&a2t2),
                            key_of(&a2t1),
                        ],
                    ),
                    (
                        id3,
                        vec![
                            key_of(&a3t3),
                            key_of(&a3t2),
                            key_of(&a3t1),
                        ],
                    ),
                ],
                expected_outputs: vec![
                    (id1, vec![(600, simple, 0)]),
                    (id2, vec![(3000, split, 0), (3000, simple, 1)]),
                    (id3, vec![(0, split, 0), (60000, simple, 1)]),
                ],
            },
            DistCase {
                name: "lots of assets, interactive, no split root",
                inputs: vec![
                    a1t1.clone(),
                    a1t2.clone(),
                    a1t3.clone(),
                    a2t1.clone(),
                    a2t2.clone(),
                    a2t3.clone(),
                    a3t1.clone(),
                    a3t2.clone(),
                    a3t3.clone(),
                ],
                interactive: true,
                allocations: vec![
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        3600,
                        0,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        63000,
                        1,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![
                    (
                        id1,
                        vec![
                            key_of(&a1t3),
                            key_of(&a1t2),
                            key_of(&a1t1),
                        ],
                    ),
                    (
                        id2,
                        vec![
                            key_of(&a2t3),
                            key_of(&a2t2),
                            key_of(&a2t1),
                        ],
                    ),
                    (
                        id3,
                        vec![
                            key_of(&a3t3),
                            key_of(&a3t2),
                            key_of(&a3t1),
                        ],
                    ),
                ],
                expected_outputs: vec![
                    (id1, vec![(600, simple, 0)]),
                    (id2, vec![(3000, split, 0), (3000, simple, 1)]),
                    (id3, vec![(60000, simple, 1)]),
                ],
            },
            DistCase {
                name: "multiple allocations, no split root defined",
                inputs: vec![a4t1.clone(), a5t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(AllocationType::HtlcOutgoing, 5000, 2, false),
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        20000,
                        3,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        25000,
                        4,
                        false,
                    ),
                ],
                vpkt_version: VPacketVersion::V1,
                expected_inputs: vec![
                    (id4, vec![key_of(&a4t1)]),
                    (id5, vec![key_of(&a5t1)]),
                ],
                expected_outputs: vec![
                    (id4, vec![(5000, split, 2), (20000, simple, 3)]),
                    (id5, vec![(25000, simple, 4)]),
                ],
            },
            DistCase {
                name: "single asset, distributed to three outputs",
                inputs: vec![a1t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(AllocationType::HtlcOutgoing, 50, 2, false),
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        20,
                        3,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        30,
                        4,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V0,
                expected_inputs: vec![(id1, vec![key_of(&a1t1)])],
                expected_outputs: vec![(
                    id1,
                    vec![
                        (50, simple, 2),
                        (20, simple, 3),
                        (30, split, 4),
                    ],
                )],
            },
            DistCase {
                name: "multiple allocations, split root defined on \
                       output that gets full value",
                inputs: vec![a4t1.clone(), a5t1.clone()],
                interactive: true,
                allocations: vec![
                    alloc(AllocationType::HtlcOutgoing, 5000, 2, false),
                    alloc(
                        AllocationType::CommitAllocationToLocal,
                        20000,
                        3,
                        false,
                    ),
                    alloc(
                        AllocationType::CommitAllocationToRemote,
                        25000,
                        4,
                        true,
                    ),
                ],
                vpkt_version: VPacketVersion::V1,
                expected_inputs: vec![
                    (id4, vec![key_of(&a4t1)]),
                    (id5, vec![key_of(&a5t1)]),
                ],
                expected_outputs: vec![
                    (id4, vec![(5000, split, 2), (20000, simple, 3)]),
                    (id5, vec![(25000, simple, 4)]),
                ],
            },
        ];

        for case in cases {
            let packets = distribute_coins(
                &case.inputs,
                &case.allocations,
                TapNetwork::Regtest,
                case.interactive,
                case.vpkt_version,
            )
            .unwrap_or_else(|e| {
                panic!("case '{}' failed: {}", case.name, e)
            });

            for pkt in &packets {
                assert_eq!(
                    pkt.version, case.vpkt_version,
                    "case '{}': wrong packet version",
                    case.name
                );
                assert_eq!(
                    pkt.chain_params,
                    TapNetwork::Regtest,
                    "case '{}': wrong chain params",
                    case.name
                );
            }

            for (asset_id, expected_keys) in &case.expected_inputs {
                let matching: Vec<&VPacket> = packets
                    .iter()
                    .filter(|p| p.inputs[0].prev_id.id == *asset_id)
                    .collect();
                assert_eq!(
                    matching.len(),
                    1,
                    "case '{}': expected exactly one packet for asset",
                    case.name
                );
                let packet = matching[0];

                let input_keys: Vec<SerializedKey> = packet
                    .inputs
                    .iter()
                    .map(|i| i.prev_id.script_key)
                    .collect();
                assert_eq!(
                    &input_keys, expected_keys,
                    "case '{}': input key order mismatch",
                    case.name
                );

                let expected_outs = case
                    .expected_outputs
                    .iter()
                    .find(|(id, _)| id == asset_id)
                    .map(|(_, outs)| outs)
                    .unwrap_or_else(|| {
                        panic!(
                            "case '{}': no expected outputs for asset",
                            case.name
                        )
                    });
                let actual_outs: Vec<ExpectedOut> = packet
                    .outputs
                    .iter()
                    .map(|o| {
                        (o.amount, o.output_type, o.anchor_output_index)
                    })
                    .collect();
                assert_eq!(
                    &actual_outs, expected_outs,
                    "case '{}': output mismatch",
                    case.name
                );

                for output in &packet.outputs {
                    assert_eq!(
                        output.interactive, case.interactive,
                        "case '{}': interactive flag mismatch",
                        case.name
                    );
                }
            }
        }
    }

    #[test]
    fn allocate_piece_cases() {
        // Mirrors Go's TestAllocatePiece.
        struct PieceCase {
            name: &'static str,
            total_available: u64,
            allocated: u64,
            allocation: Allocation,
            to_fill: u64,
            interactive: bool,
            expected_alloc: u64,
            expected_output: bool,
            expected_output_type: VOutputType,
        }

        let cases = vec![
            PieceCase {
                name: "valid allocation",
                total_available: 100,
                allocated: 0,
                allocation: Allocation {
                    amount: 50,
                    script_key: Some(sk(1)),
                    ..Default::default()
                },
                to_fill: 50,
                interactive: true,
                expected_alloc: 50,
                expected_output: true,
                expected_output_type: VOutputType::SIMPLE,
            },
            PieceCase {
                name: "allocation exceeds available",
                total_available: 100,
                allocated: 0,
                allocation: Allocation {
                    amount: 150,
                    script_key: Some(sk(1)),
                    ..Default::default()
                },
                to_fill: 150,
                interactive: true,
                expected_alloc: 100,
                expected_output: true,
                expected_output_type: VOutputType::SIMPLE,
            },
            PieceCase {
                name: "allocation with zero to fill",
                total_available: 100,
                allocated: 0,
                allocation: Allocation {
                    amount: 0,
                    script_key: Some(sk(1)),
                    ..Default::default()
                },
                to_fill: 0,
                interactive: true,
                expected_alloc: 0,
                expected_output: false,
                expected_output_type: VOutputType::SIMPLE,
            },
            PieceCase {
                name: "allocation with split root",
                total_available: 100,
                allocated: 0,
                allocation: Allocation {
                    amount: 50,
                    split_root: true,
                    script_key: Some(sk(1)),
                    ..Default::default()
                },
                to_fill: 50,
                interactive: false,
                expected_alloc: 50,
                expected_output: true,
                expected_output_type: VOutputType::SPLIT_ROOT,
            },
        ];

        for case in cases {
            let mut piece = Piece {
                asset_id: AssetId([1u8; 32]),
                total_available: case.total_available,
                allocated: case.allocated,
                inputs: vec![],
                packet: VPacket {
                    inputs: vec![],
                    outputs: vec![],
                    chain_params: TapNetwork::Regtest,
                    version: VPacketVersion::V0,
                },
            };

            let allocated = allocate_piece(
                &mut piece,
                &case.allocation,
                case.to_fill,
                case.interactive,
            )
            .unwrap_or_else(|e| {
                panic!("case '{}' failed: {}", case.name, e)
            });

            assert_eq!(
                allocated, case.expected_alloc,
                "case '{}': allocated mismatch",
                case.name
            );
            assert_eq!(
                piece.available(),
                case.total_available - case.expected_alloc,
                "case '{}': available mismatch",
                case.name
            );

            if case.expected_output {
                assert_eq!(
                    piece.packet.outputs.len(),
                    1,
                    "case '{}': expected exactly one output",
                    case.name
                );
                assert_eq!(
                    piece.packet.outputs[0].output_type,
                    case.expected_output_type,
                    "case '{}': output type mismatch",
                    case.name
                );
            } else {
                assert!(
                    piece.packet.outputs.is_empty(),
                    "case '{}': expected no outputs",
                    case.name
                );
            }
        }
    }

    fn piece_for_sort(
        asset_id: [u8; 32],
        inputs: Vec<(u64, SerializedKey)>,
    ) -> Piece {
        Piece {
            asset_id: AssetId(asset_id),
            total_available: 0,
            allocated: 0,
            inputs: inputs
                .into_iter()
                .map(|(amount, key)| Asset {
                    amount,
                    script_key: ScriptKey::from_pub_key(key),
                    ..Asset::new_genesis(
                        Genesis {
                            first_prev_out: OutPoint {
                                txid: [0u8; 32],
                                vout: 0,
                            },
                            tag: String::new(),
                            meta_hash: [0u8; 32],
                            output_index: 0,
                            asset_type: AssetType::Normal,
                        },
                        0,
                        sk(0),
                    )
                })
                .collect(),
            packet: VPacket {
                inputs: vec![],
                outputs: vec![],
                chain_params: TapNetwork::Regtest,
                version: VPacketVersion::V0,
            },
        }
    }

    #[test]
    fn sort_pieces_with_inputs_cases() {
        // Mirrors Go's TestSortPiecesWithProofs: sorting is first by
        // asset ID, then the inputs by amount descending, then by
        // script key.
        let mut id_a = [0u8; 32];
        id_a[0] = 0x01;
        let mut id_b = [0u8; 32];
        id_b[0] = 0x02;

        // Case 1: sort by asset ID and inputs by amount.
        let mut pieces = vec![
            piece_for_sort(
                id_b,
                vec![(50, key1().clone()), (300, key2()), (100, key2())],
            ),
            piece_for_sort(id_a, vec![(200, key1()), (150, key2())]),
        ];
        sort_pieces_with_inputs(&mut pieces);

        assert_eq!(pieces[0].asset_id, AssetId(id_a));
        assert_eq!(pieces[1].asset_id, AssetId(id_b));
        let amounts_a: Vec<u64> =
            pieces[0].inputs.iter().map(|a| a.amount).collect();
        assert_eq!(amounts_a, vec![200, 150]);
        let amounts_b: Vec<u64> =
            pieces[1].inputs.iter().map(|a| a.amount).collect();
        assert_eq!(amounts_b, vec![300, 100, 50]);

        // Case 2: script keys break ties after amount. key2 starts with
        // 0x02 and key1 with 0x03, so key2 sorts first.
        let mut pieces = vec![piece_for_sort(
            id_a,
            vec![(50, key1()), (50, key2()), (50, key2())],
        )];
        sort_pieces_with_inputs(&mut pieces);
        let keys: Vec<SerializedKey> = pieces[0]
            .inputs
            .iter()
            .map(|a| a.script_key.pub_key)
            .collect();
        assert_eq!(keys, vec![key2(), key2(), key1()]);

        // Case 3: empty input.
        let mut pieces: Vec<Piece> = vec![];
        sort_pieces_with_inputs(&mut pieces);
        assert!(pieces.is_empty());
    }

    #[test]
    fn asset_sort_for_inputs_ordering() {
        let big = Asset {
            amount: 300,
            ..Asset::new_genesis(
                grind_genesis(0x01, AssetType::Normal),
                300,
                ScriptKey::from_pub_key(key1()),
            )
        };
        let small = Asset {
            amount: 100,
            ..Asset::new_genesis(
                grind_genesis(0x01, AssetType::Normal),
                100,
                ScriptKey::from_pub_key(key2()),
            )
        };

        // Larger amounts sort first.
        assert_eq!(
            asset_sort_for_inputs(&big, &small),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            asset_sort_for_inputs(&small, &big),
            std::cmp::Ordering::Greater
        );

        // Equal amounts: smaller script key bytes sort first.
        let mut tie_a = big.clone();
        tie_a.amount = 100;
        tie_a.script_key = ScriptKey::from_pub_key(key2());
        let mut tie_b = big.clone();
        tie_b.amount = 100;
        tie_b.script_key = ScriptKey::from_pub_key(key1());
        assert_eq!(
            asset_sort_for_inputs(&tie_a, &tie_b),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn in_place_allocation_sort_rules() {
        // The sort is by (btc_amount, sort_taproot_key_bytes,
        // sort_cltv, htlc_index).
        let make = |btc: u64, key: u8, cltv: u32, htlc: u64| Allocation {
            btc_amount: btc,
            sort_taproot_key_bytes: vec![key; 32],
            sort_cltv: cltv,
            htlc_index: htlc,
            ..Default::default()
        };

        let mut allocations = vec![
            make(1000, 5, 0, 0),
            make(500, 9, 0, 0),
            make(1000, 3, 7, 0),
            make(1000, 3, 5, 0),
            make(1000, 3, 5, 2),
            make(1000, 3, 5, 1),
        ];
        in_place_allocation_sort(&mut allocations);

        let order: Vec<(u64, u8, u32, u64)> = allocations
            .iter()
            .map(|a| {
                (
                    a.btc_amount,
                    a.sort_taproot_key_bytes[0],
                    a.sort_cltv,
                    a.htlc_index,
                )
            })
            .collect();
        assert_eq!(
            order,
            vec![
                (500, 9, 0, 0),
                (1000, 3, 5, 0),
                (1000, 3, 5, 1),
                (1000, 3, 5, 2),
                (1000, 3, 7, 0),
                (1000, 5, 0, 0),
            ]
        );
    }

    #[test]
    fn final_pk_script_shape_and_determinism() {
        let commitment = make_commitment(1000);
        let allocation = Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            internal_key: Some(SerializedKey(G_COMPRESSED)),
            script_key: Some(ScriptKey::from_pub_key(key1())),
            output_commitment: Some(commitment),
            ..Default::default()
        };

        let script = allocation.final_pk_script().expect("pk script");
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51);
        assert_eq!(script[1], 0x20);

        // Deterministic.
        let script2 = allocation.final_pk_script().expect("pk script");
        assert_eq!(script, script2);

        // Manually recompute the expected output key.
        let root = allocation
            .output_commitment
            .as_ref()
            .expect("commitment")
            .tapscript_root(None);
        let internal = parse_pub_key(&SerializedKey(G_COMPRESSED))
            .expect("internal key");
        let (x_only, _) = internal.x_only_public_key();
        let expected_key = compute_taproot_output_key(&x_only, Some(&root))
            .expect("output key");
        assert_eq!(&script[2..], expected_key.serialize().as_slice());
    }

    #[test]
    fn final_pk_script_differs_with_roots_and_sibling() {
        let base = Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            internal_key: Some(SerializedKey(G_COMPRESSED)),
            script_key: Some(ScriptKey::from_pub_key(key1())),
            output_commitment: Some(make_commitment(1000)),
            ..Default::default()
        };
        let script_base = base.final_pk_script().expect("pk script");

        // A different commitment root produces a different script.
        let mut other_root = base.clone();
        other_root.output_commitment = Some(make_commitment(2000));
        let script_other = other_root.final_pk_script().expect("pk script");
        assert_ne!(script_base, script_other);

        // Adding a tapscript sibling produces a different script.
        let mut with_sibling = base.clone();
        with_sibling.non_asset_leaves = vec![vec![0x51]];
        let script_sibling =
            with_sibling.final_pk_script().expect("pk script");
        assert_ne!(script_base, script_sibling);
        assert_eq!(script_sibling.len(), 34);
        assert_eq!(script_sibling[0], 0x51);
        assert_eq!(script_sibling[1], 0x20);

        // Missing output commitment is an error.
        let mut no_commitment = base.clone();
        no_commitment.output_commitment = None;
        assert_eq!(
            no_commitment.final_pk_script(),
            Err(AllocationError::CommitmentNotSet)
        );

        // Missing internal key is an error.
        let mut no_key = base.clone();
        no_key.internal_key = None;
        assert_eq!(
            no_key.final_pk_script(),
            Err(AllocationError::MissingInternalKey)
        );
    }

    #[test]
    fn final_pk_script_no_assets() {
        // For a NoAssets allocation the sort taproot key is mapped to
        // the script directly.
        let x_only: Vec<u8> = G_COMPRESSED[1..].to_vec();
        let allocation = Allocation {
            alloc_type: AllocationType::NoAssets,
            sort_taproot_key_bytes: x_only.clone(),
            ..Default::default()
        };

        let script = allocation.final_pk_script().expect("pk script");
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51);
        assert_eq!(script[1], 0x20);
        assert_eq!(&script[2..], x_only.as_slice());

        // An invalid length key is rejected.
        let bad = Allocation {
            alloc_type: AllocationType::NoAssets,
            sort_taproot_key_bytes: vec![0u8; 31],
            ..Default::default()
        };
        assert!(matches!(
            bad.final_pk_script(),
            Err(AllocationError::InvalidKey(_))
        ));
    }

    #[test]
    fn tapscript_sibling_hashes() {
        // No leaves and no preimage: no sibling.
        let empty = Allocation::default();
        assert_eq!(empty.tapscript_sibling().expect("sibling"), None);

        // A single leaf becomes a leaf preimage whose tap hash matches
        // the direct leaf hash.
        let script = vec![0x51u8];
        let one_leaf = Allocation {
            non_asset_leaves: vec![script.clone()],
            ..Default::default()
        };
        let preimage = one_leaf
            .tapscript_sibling()
            .expect("sibling")
            .expect("preimage");
        assert_eq!(preimage.sibling_type, 0);
        assert_eq!(
            preimage.tap_hash().expect("tap hash"),
            tap_leaf_hash(BASE_LEAF_VERSION, &script)
        );

        // Two leaves become a branch preimage whose tap hash matches
        // the branch of the two leaf hashes.
        let script_b = vec![0x52u8];
        let two_leaves = Allocation {
            non_asset_leaves: vec![script.clone(), script_b.clone()],
            ..Default::default()
        };
        let preimage = two_leaves
            .tapscript_sibling()
            .expect("sibling")
            .expect("preimage");
        assert_eq!(preimage.sibling_type, 1);
        let leaf_a = tap_leaf_hash(BASE_LEAF_VERSION, &script);
        let leaf_b = tap_leaf_hash(BASE_LEAF_VERSION, &script_b);
        assert_eq!(
            preimage.tap_hash().expect("tap hash"),
            tap_branch_hash(&leaf_a, &leaf_b)
        );

        // More than two leaves is a documented divergence and errors.
        let three_leaves = Allocation {
            non_asset_leaves: vec![
                script.clone(),
                script_b.clone(),
                vec![0x53],
            ],
            ..Default::default()
        };
        assert!(matches!(
            three_leaves.tapscript_sibling(),
            Err(AllocationError::InvalidPreimage(_))
        ));

        // An explicit sibling preimage takes precedence.
        let explicit = Allocation {
            sibling_preimage: Some(TapscriptPreimage {
                sibling_type: 0,
                sibling_preimage: vec![0xc0, 0x01, 0x51],
            }),
            ..Default::default()
        };
        let preimage = explicit
            .tapscript_sibling()
            .expect("sibling")
            .expect("preimage");
        assert_eq!(preimage.sibling_preimage, vec![0xc0, 0x01, 0x51]);
    }

    #[test]
    fn assign_output_commitments_cases() {
        let mut allocations = vec![
            Allocation {
                alloc_type: AllocationType::CommitAllocationToLocal,
                output_index: 0,
                script_key: Some(sk(1)),
                ..Default::default()
            },
            Allocation {
                alloc_type: AllocationType::NoAssets,
                output_index: 1,
                ..Default::default()
            },
            Allocation {
                alloc_type: AllocationType::CommitAllocationToRemote,
                output_index: 2,
                script_key: Some(sk(2)),
                ..Default::default()
            },
        ];

        let mut commitments = BTreeMap::new();
        commitments.insert(0u32, make_commitment(100));
        commitments.insert(2u32, make_commitment(200));

        assign_output_commitments(&mut allocations, &commitments)
            .expect("assign");

        assert!(allocations[0].output_commitment.is_some());
        // NoAssets allocations are skipped.
        assert!(allocations[1].output_commitment.is_none());
        assert!(allocations[2].output_commitment.is_some());

        // A missing output index is an error.
        let mut missing = vec![Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            output_index: 7,
            script_key: Some(sk(1)),
            ..Default::default()
        }];
        assert_eq!(
            assign_output_commitments(&mut missing, &commitments),
            Err(AllocationError::MissingOutputCommitment(7))
        );
    }

    #[test]
    fn matches_output_and_aux_leaf() {
        let commitment = make_commitment(1000);
        let allocation = Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            internal_key: Some(SerializedKey(G_COMPRESSED)),
            script_key: Some(ScriptKey::from_pub_key(key1())),
            output_commitment: Some(commitment.clone()),
            btc_amount: 354,
            sort_cltv: 0,
            htlc_index: 0,
            ..Default::default()
        };

        let pk_script = allocation.final_pk_script().expect("pk script");
        assert!(allocation
            .matches_output(&pk_script, 354, 0, 0)
            .expect("matches"));
        assert!(!allocation
            .matches_output(&pk_script, 353, 0, 0)
            .expect("matches"));
        assert!(!allocation
            .matches_output(&pk_script, 354, 1, 0)
            .expect("matches"));
        assert!(!allocation
            .matches_output(&pk_script, 354, 0, 1)
            .expect("matches"));
        let other_script = vec![0u8; 34];
        assert!(!allocation
            .matches_output(&other_script, 354, 0, 0)
            .expect("matches"));

        // The aux leaf is the serialized TAP commitment leaf script.
        assert_eq!(allocation.aux_leaf().expect("aux leaf"), commitment.tap_leaf());

        // Without a commitment, the aux leaf errors.
        let no_commitment = Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            script_key: Some(sk(1)),
            ..Default::default()
        };
        assert_eq!(
            no_commitment.aux_leaf(),
            Err(AllocationError::CommitmentNotSet)
        );
    }

    #[test]
    fn validate_rules() {
        // NoAssets allocation without a script key is fine.
        Allocation::default().validate().expect("valid");

        // Asset allocation without a script key errors.
        let missing_key = Allocation {
            alloc_type: AllocationType::CommitAllocationToLocal,
            ..Default::default()
        };
        assert_eq!(
            missing_key.validate(),
            Err(AllocationError::ScriptKeyGenMissing)
        );

        // Setting both sibling fields errors.
        let both_siblings = Allocation {
            non_asset_leaves: vec![vec![0x51]],
            sibling_preimage: Some(TapscriptPreimage {
                sibling_type: 0,
                sibling_preimage: vec![0xc0, 0x01, 0x51],
            }),
            ..Default::default()
        };
        assert_eq!(
            both_siblings.validate(),
            Err(AllocationError::InvalidSibling)
        );
    }
}
