// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Core proof types.

use std::collections::BTreeMap;

use crate::asset::{self, Asset, Genesis, OutPoint, SerializedKey};
use crate::commitment::{CommitmentProof, TapCommitment, TapscriptPreimage};

use super::meta::MetaReveal;
use super::tx_merkle::TxMerkleProof;
use super::ProofError;

/// Version of a transition proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum TransitionVersion {
    /// First version.
    V0 = 0,
    /// Adds STXO inclusion and exclusion proofs.
    V1 = 1,
}

impl TransitionVersion {
    pub fn from_u32(v: u32) -> Result<Self, super::ProofError> {
        match v {
            0 => Ok(TransitionVersion::V0),
            1 => Ok(TransitionVersion::V1),
            _ => Err(super::ProofError::UnknownTransitionVersion(v)),
        }
    }
}

/// A Bitcoin block header (80 bytes).
///
/// We store it as raw bytes to avoid depending on a full Bitcoin library
/// for parsing. The fields are:
/// - version (4 bytes LE)
/// - prev_block_hash (32 bytes)
/// - merkle_root (32 bytes)
/// - timestamp (4 bytes LE)
/// - bits (4 bytes LE)
/// - nonce (4 bytes LE)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader(pub [u8; 80]);

impl BlockHeader {
    /// Extracts the merkle root from the block header (bytes 36..68).
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.0[36..68]);
        root
    }

    /// Returns the block header as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 80] {
        &self.0
    }

    /// Computes the block hash (double-SHA256 of the 80-byte header) in
    /// internal (wire) byte order, matching Go's
    /// `wire.BlockHeader.BlockHash`.
    pub fn block_hash(&self) -> [u8; 32] {
        use bitcoin_hashes::{sha256d, Hash};
        sha256d::Hash::hash(&self.0).to_byte_array()
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader([0u8; 80])
    }
}

/// A proof that a Taproot output does NOT contain a Taproot Asset
/// commitment.
///
/// Taproot Asset commitments must exist at a leaf of depth 0 or 1, so
/// non-inclusion is shown by revealing the preimage of one node at
/// depth 0 or two nodes at depth 1 (or the BIP-86 flag for outputs with
/// no script tree at all). Matches Go's `proof.TapscriptProof`.
#[derive(Clone, Debug)]
pub struct TapscriptProof {
    /// Preimage for a tap node at depth 0 or 1 (TLV type 1).
    pub tap_preimage_1: Option<TapscriptPreimage>,
    /// Pair preimage for `tap_preimage_1` at depth 1 (TLV type 3).
    pub tap_preimage_2: Option<TapscriptPreimage>,
    /// True for a plain BIP-0086 key-spend output that commits to no
    /// script root at all (TLV type 4).
    pub bip86: bool,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// A proof that a Taproot Asset output is committed in a specific
/// Taproot output of the anchor transaction.
///
/// A TaprootProof carries either a `commitment_proof` (the output holds
/// a Taproot Asset commitment that includes/excludes the asset) or a
/// `tapscript_proof` (the output holds no commitment at all).
#[derive(Clone, Debug)]
pub struct TaprootProof {
    /// Index of the output in the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key (33-byte compressed).
    pub internal_key: SerializedKey,
    /// Commitment proof (for inclusion or exclusion in the TAP tree).
    pub commitment_proof: Option<CommitmentProof>,
    /// Tapscript proof showing the output commits to no Taproot Asset
    /// commitment (TLV type 5). Mutually exclusive with
    /// `commitment_proof`.
    pub tapscript_proof: Option<TapscriptProof>,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// The parsed on-chain anchor transaction, mirroring Go's
/// `wire.MsgTx` field on `proof.Proof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorTx(pub bitcoin::Transaction);

impl AnchorTx {
    /// Parses an anchor transaction from raw consensus-encoded bytes.
    /// Trailing bytes are rejected, matching Go's `wire.MsgTx.Decode`
    /// which consumes the record exactly.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(bytes).map_err(|e| {
                ProofError::DecodingError(format!(
                    "invalid anchor transaction: {}",
                    e
                ))
            })?;
        Ok(AnchorTx(tx))
    }

    /// Returns the raw consensus-encoded transaction bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.0)
    }

    /// Returns the txid (double-SHA256 of the legacy serialization) in
    /// internal (wire) byte order, matching Go's `MsgTx.TxHash()` raw
    /// bytes. This is the byte order used by `prev_out.txid` and the tx
    /// merkle proof.
    pub fn txid(&self) -> [u8; 32] {
        *self.0.compute_txid().as_ref()
    }
}

impl Default for AnchorTx {
    /// The zero-value transaction, matching Go's zero `wire.MsgTx`
    /// (version 0, no inputs, no outputs, lock time 0).
    fn default() -> Self {
        AnchorTx(bitcoin::Transaction {
            version: bitcoin::transaction::Version(0),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
    }
}

/// A single transition proof linking an asset to a confirmed Bitcoin
/// transaction.
///
/// Each proof establishes that:
/// 1. The anchor transaction is included in a Bitcoin block
/// 2. The asset is committed in a specific output of that transaction
/// 3. The asset is NOT present in other P2TR outputs (exclusion)
#[derive(Clone, Debug)]
pub struct Proof {
    /// Proof version.
    pub version: TransitionVersion,
    /// The previous on-chain outpoint (input being spent).
    pub prev_out: OutPoint,
    /// Bitcoin block header containing the anchor transaction.
    pub block_header: BlockHeader,
    /// Block height.
    pub block_height: u32,
    /// The on-chain anchor transaction.
    pub anchor_tx: AnchorTx,
    /// Merkle proof that anchor_tx is in the block.
    pub tx_merkle_proof: TxMerkleProof,
    /// The resulting asset after this state transition.
    pub asset: Asset,
    /// Proof that the asset is included in the anchor tx output.
    pub inclusion_proof: TaprootProof,
    /// Proofs that the asset is NOT in other P2TR outputs.
    pub exclusion_proofs: Vec<TaprootProof>,
    /// For split assets: proof of the split root.
    pub split_root_proof: Option<TaprootProof>,
    /// Metadata reveal (present for genesis proofs).
    pub meta_reveal: Option<MetaReveal>,
    /// Proofs for additional inputs (multi-input transfers).
    pub additional_inputs: Vec<super::file::File>,
    /// Ownership challenge witness (TLV type 21): a signed virtual
    /// transaction witness proving the prover can spend the asset.
    /// Encoded as a Bitcoin-style witness stack, Go's
    /// `ChallengeWitnessRecord`.
    pub challenge_witness: Option<Vec<Vec<u8>>>,
    /// Genesis reveal (present for minting proofs).
    pub genesis_reveal: Option<Genesis>,
    /// Group key reveal (present for grouped asset genesis).
    pub group_key_reveal: Option<asset::GroupKeyReveal>,
    /// Alt leaves carried in the anchor commitment (TLV type 27). Each
    /// alt leaf is an Asset that only encodes its previous witnesses,
    /// script version, and script key (Go's `AltLeavesRecord`).
    pub alt_leaves: Vec<Asset>,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl Proof {
    /// Returns the outpoint that commits to the asset associated with
    /// this proof, matching Go's `Proof.OutPoint()`.
    pub fn out_point(&self) -> OutPoint {
        OutPoint {
            txid: self.anchor_tx.txid(),
            vout: self.inclusion_proof.output_index,
        }
    }

    /// Returns true if this is a V1 (STXO-aware) proof.
    pub fn is_version_v1(&self) -> bool {
        self.version == TransitionVersion::V1
    }
}

/// The result of verifying a proof — a snapshot of the asset state at
/// a specific point in the chain. Mirrors Go's `proof.AssetSnapshot`.
#[derive(Clone, Debug)]
pub struct AssetSnapshot {
    /// The verified asset.
    pub asset: Asset,
    /// The outpoint where the asset is committed.
    pub out_point: OutPoint,
    /// Block hash of the anchor block (internal byte order).
    pub anchor_block_hash: [u8; 32],
    /// Block height.
    pub anchor_block_height: u32,
    /// The anchor transaction.
    pub anchor_tx: AnchorTx,
    /// Output index within the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key.
    pub internal_key: SerializedKey,
    /// The Taproot Asset commitment anchored at the output (Go's
    /// `ScriptRoot`).
    pub script_root: Option<TapCommitment>,
    /// The tapscript sibling preimage hashed together with the
    /// commitment leaf, if any.
    pub tapscript_sibling: Option<TapscriptPreimage>,
    /// Whether this asset is the result of a split.
    pub split_asset: bool,
    /// Metadata reveal if this is a genesis asset.
    pub meta_reveal: Option<MetaReveal>,
}
