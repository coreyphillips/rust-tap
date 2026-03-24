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
use crate::commitment::CommitmentProof;

use super::meta::MetaReveal;
use super::tx_merkle::TxMerkleProof;

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
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader([0u8; 80])
    }
}

/// A proof that a Taproot Asset output is committed in a specific
/// Taproot output of the anchor transaction.
#[derive(Clone, Debug)]
pub struct TaprootProof {
    /// Index of the output in the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key (33-byte compressed).
    pub internal_key: SerializedKey,
    /// Commitment proof (for inclusion or exclusion in the TAP tree).
    pub commitment_proof: Option<CommitmentProof>,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// A simplified anchor transaction representation.
///
/// Stores the raw serialized transaction bytes. Full parsing requires
/// a Bitcoin library, but for proof purposes we primarily need the txid
/// and the ability to pass it through to verification functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorTx(pub Vec<u8>);

impl AnchorTx {
    /// Returns the raw transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
    /// Genesis reveal (present for minting proofs).
    pub genesis_reveal: Option<Genesis>,
    /// Group key reveal (present for grouped asset genesis).
    pub group_key_reveal: Option<asset::GroupKeyReveal>,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// The result of verifying a proof — a snapshot of the asset state at
/// a specific point in the chain.
#[derive(Clone, Debug)]
pub struct AssetSnapshot {
    /// The verified asset.
    pub asset: Asset,
    /// The outpoint where the asset is committed.
    pub out_point: OutPoint,
    /// Block hash of the anchor block.
    pub anchor_block_hash: [u8; 32],
    /// Block height.
    pub anchor_block_height: u32,
    /// The anchor transaction.
    pub anchor_tx: AnchorTx,
    /// Output index within the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key.
    pub internal_key: SerializedKey,
    /// Whether this asset is the result of a split.
    pub split_asset: bool,
    /// Metadata reveal if this is a genesis asset.
    pub meta_reveal: Option<MetaReveal>,
}
