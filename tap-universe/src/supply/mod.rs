// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Universe supply commitments (verify-first port).
//!
//! Mirrors the data structures and tree building of Go's
//! `universe/supplycommit` (env.go, states.go, transitions.go) and the
//! commitment verifier of `universe/supplyverifier` (verifier.go).
//!
//! Each asset group maintains a *root supply tree* whose (at most
//! three) leaves commit to the roots of the mint, burn, and ignore
//! *sub-trees*. The root supply tree's root hash is committed on-chain
//! in a P2TR output whose tapscript root is a single Pedersen
//! non-spendable leaf over the 32-byte supply root hash.
//!
//! # Authoring
//!
//! Go's `supplycommit` package also contains a protofsm state machine
//! that *authors* new commitments. In this workspace that flow lives
//! as a synchronous pipeline: transaction shaping and signing in
//! `tap_onchain::supply_commit`, staging/persistence in
//! `tap_persist::supply_store`, and orchestration (staging producers,
//! broadcast, confirmation handling, self-verification against
//! [`SupplyVerifier`]) in tap-node's `supply` module. This module
//! provides the shared data structures, event/tree construction
//! (byte-compatible with Go), and full verification of supply
//! commitments, which the authoring pipeline uses as its oracle.

pub mod events;
pub mod verifier;

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::asset::{
    new_non_spendable_script_leaf, SerializedKey, PEDERSEN_VERSION,
};
use tap_primitives::crypto::{tap_leaf_hash, taproot_output_key};
use tap_primitives::mssmt::{CompactedTree, DefaultStore, LeafNode, NodeHash};
use tap_primitives::proof::{
    tx_spends_prev_out, BlockHeader, HeaderVerifier, MerkleVerifier,
    TxMerkleProof,
};

pub use events::{
    BurnLeaf, NewBurnEvent, NewIgnoreEvent, NewMintEvent, SupplyLeafKey,
    SupplyUpdateEvent,
};
pub use verifier::{
    AssetLookup, SupplyCommitView, SupplyTreeView, SupplyVerifier,
};

/// The default number of satoshis used for supply commitment outputs,
/// matching Go's `tapsend.DummyAmtSats` (tapsend/send.go:42).
pub const DUMMY_AMT_SATS: u64 = 1_000;

/// Errors from supply commitment operations.
#[derive(Debug, Clone)]
pub enum SupplyError {
    /// Encoding or decoding failed.
    Encoding(String),
    /// A tree operation failed.
    Tree(String),
    /// Verification failed.
    Verification(String),
    /// A required piece of data is missing.
    Missing(String),
    /// A store/lookup operation failed.
    Lookup(String),
}

impl std::fmt::Display for SupplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupplyError::Encoding(msg) => {
                write!(f, "supply encoding error: {}", msg)
            }
            SupplyError::Tree(msg) => {
                write!(f, "supply tree error: {}", msg)
            }
            SupplyError::Verification(msg) => {
                write!(f, "supply verification failed: {}", msg)
            }
            SupplyError::Missing(msg) => {
                write!(f, "missing supply data: {}", msg)
            }
            SupplyError::Lookup(msg) => {
                write!(f, "supply lookup error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SupplyError {}

/// The different supply sub-trees within the main supply tree,
/// mirroring Go's `supplycommit.SupplySubTree` (env.go:45).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SupplySubTree {
    /// Tracks mints.
    Mint,
    /// Tracks burns.
    Burn,
    /// Tracks ignores.
    Ignore,
}

/// All possible supply sub-tree types, mirroring Go's
/// `AllSupplySubTrees`.
pub const ALL_SUPPLY_SUB_TREES: [SupplySubTree; 3] = [
    SupplySubTree::Mint,
    SupplySubTree::Burn,
    SupplySubTree::Ignore,
];

impl SupplySubTree {
    /// Returns the Go-compatible string name (env.go `String`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SupplySubTree::Mint => "mint_supply",
            SupplySubTree::Burn => "burn",
            SupplySubTree::Ignore => "ignore",
        }
    }

    /// Parses the Go-compatible string name (env.go
    /// `NewSubtreeTypeFromStr`).
    pub fn from_str_name(s: &str) -> Option<SupplySubTree> {
        match s {
            "mint_supply" => Some(SupplySubTree::Mint),
            "burn" => Some(SupplySubTree::Burn),
            "ignore" => Some(SupplySubTree::Ignore),
            _ => None,
        }
    }

    /// Returns the corresponding universe proof type (env.go
    /// `ToUniverseProofType`).
    pub fn proof_type(&self) -> crate::types::ProofType {
        match self {
            SupplySubTree::Mint => crate::types::ProofType::MintSupply,
            SupplySubTree::Burn => crate::types::ProofType::Burn,
            SupplySubTree::Ignore => crate::types::ProofType::Ignore,
        }
    }

    /// Returns the key identifying this sub-tree within the root supply
    /// tree: `sha256(name)` (env.go:112 `UniverseKey`).
    pub fn universe_key(&self) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(self.as_str().as_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

/// An in-memory supply (sub-)tree.
pub type SupplyTree = CompactedTree<DefaultStore>;

/// Creates a new empty in-memory supply tree.
pub fn new_supply_tree() -> SupplyTree {
    CompactedTree::new(DefaultStore::new())
}

/// The set of supply sub-trees for an asset group, mirroring Go's
/// `supplycommit.SupplyTrees` map (env.go:121).
#[derive(Clone, Default)]
pub struct SupplyTrees {
    trees: std::collections::BTreeMap<SupplySubTree, SupplyTree>,
}

impl SupplyTrees {
    pub fn new() -> Self {
        SupplyTrees::default()
    }

    /// Fetches the sub-tree of the given type, creating an empty one if
    /// it does not yet exist (env.go `FetchOrCreate`).
    pub fn fetch_or_create(&mut self, tree_type: SupplySubTree) -> &mut SupplyTree {
        self.trees.entry(tree_type).or_insert_with(new_supply_tree)
    }

    /// Returns the sub-tree of the given type, if present.
    pub fn get(&self, tree_type: SupplySubTree) -> Option<&SupplyTree> {
        self.trees.get(&tree_type)
    }

    /// Inserts/replaces the sub-tree of the given type.
    pub fn insert(&mut self, tree_type: SupplySubTree, tree: SupplyTree) {
        self.trees.insert(tree_type, tree);
    }

    /// Iterates over the present (type, tree) pairs.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&SupplySubTree, &SupplyTree)> {
        self.trees.iter()
    }
}

/// Applies the given supply update events to (copies of) the supply
/// sub-trees, mirroring Go's `supplycommit.ApplyTreeUpdates`
/// (transitions.go:213). The input trees are not mutated; a new map
/// containing all three sub-tree types is returned.
pub fn apply_tree_updates(
    supply_trees: &SupplyTrees,
    pending_updates: &[SupplyUpdateEvent],
) -> Result<SupplyTrees, SupplyError> {
    let mut updated = SupplyTrees::new();

    // Ensure all sub-tree types exist, copying existing trees.
    for tree_type in ALL_SUPPLY_SUB_TREES {
        match supply_trees.get(tree_type) {
            Some(tree) => updated.insert(tree_type, tree.clone()),
            None => updated.insert(tree_type, new_supply_tree()),
        }
    }

    for update in pending_updates {
        let leaf_key = update.universe_leaf_key();
        let leaf_node = update.universe_leaf_node()?;

        let target = updated.fetch_or_create(update.sub_tree_type());
        target
            .insert(leaf_key, leaf_node)
            .map_err(|e| SupplyError::Tree(e.to_string()))?;
    }

    Ok(updated)
}

/// Updates the given root supply tree with the roots of the given
/// sub-trees, mirroring Go's `supplycommit.UpdateRootSupplyTree`
/// (transitions.go:278). Sub-trees with a zero sum are skipped.
pub fn update_root_supply_tree(
    root_tree: &mut SupplyTree,
    sub_trees: &SupplyTrees,
) -> Result<(), SupplyError> {
    for (tree_type, sub_tree) in sub_trees.iter() {
        let sub_root = sub_tree
            .root()
            .map_err(|e| SupplyError::Tree(e.to_string()))?;

        if sub_root.node_sum() == 0 {
            continue;
        }

        let leaf = LeafNode::new(
            sub_root.node_hash().0.to_vec(),
            sub_root.node_sum(),
        );

        root_tree
            .insert(tree_type.universe_key(), leaf)
            .map_err(|e| SupplyError::Tree(e.to_string()))?;
    }

    Ok(())
}

/// Calculates the total outstanding supply from the given supply
/// sub-trees, mirroring Go's `CalcTotalOutstandingSupply` (util.go:27):
/// minted - burned - ignored, erroring if burns or ignores exceed the
/// outstanding total.
pub fn calc_total_outstanding_supply(
    supply_trees: &SupplyTrees,
) -> Result<u64, SupplyError> {
    let sum = |tree_type: SupplySubTree| -> Result<u64, SupplyError> {
        match supply_trees.get(tree_type) {
            Some(tree) => tree
                .root()
                .map(|r| r.node_sum())
                .map_err(|e| SupplyError::Tree(e.to_string())),
            None => Ok(0),
        }
    };

    let mut total = sum(SupplySubTree::Mint)?;
    if total == 0 {
        return Ok(0);
    }

    let burned = sum(SupplySubTree::Burn)?;
    if burned > total {
        return Err(SupplyError::Tree(format!(
            "total burned {} exceeds total outstanding {}",
            burned, total
        )));
    }
    total -= burned;

    let ignored = sum(SupplySubTree::Ignore)?;
    if ignored > total {
        return Err(SupplyError::Tree(format!(
            "total ignored {} exceeds total outstanding {}",
            ignored, total
        )));
    }
    total -= ignored;

    Ok(total)
}

/// The supply leaves backing a supply commitment, mirroring Go's
/// `supplycommit.SupplyLeaves` (env.go:140).
#[derive(Clone, Debug, Default)]
pub struct SupplyLeaves {
    /// New issuance (mint) leaves.
    pub issuance_leaf_entries: Vec<NewMintEvent>,
    /// New burn leaves.
    pub burn_leaf_entries: Vec<NewBurnEvent>,
    /// New ignore leaves.
    pub ignore_leaf_entries: Vec<NewIgnoreEvent>,
}

impl SupplyLeaves {
    /// Returns all leaves as a flat list of supply update events
    /// (env.go `AllUpdates`).
    pub fn all_updates(&self) -> Vec<SupplyUpdateEvent> {
        let mut updates = Vec::with_capacity(
            self.issuance_leaf_entries.len()
                + self.burn_leaf_entries.len()
                + self.ignore_leaf_entries.len(),
        );
        for e in &self.issuance_leaf_entries {
            updates.push(SupplyUpdateEvent::Mint(e.clone()));
        }
        for e in &self.burn_leaf_entries {
            updates.push(SupplyUpdateEvent::Burn(e.clone()));
        }
        for e in &self.ignore_leaf_entries {
            updates.push(SupplyUpdateEvent::Ignore(e.clone()));
        }
        updates
    }

    /// Ensures that all leaves have a non-zero block height (env.go
    /// `ValidateBlockHeights`).
    pub fn validate_block_heights(&self) -> Result<(), SupplyError> {
        for leaf in &self.issuance_leaf_entries {
            if leaf.block_height() == 0 {
                return Err(SupplyError::Verification(
                    "mint leaf has zero block height".into(),
                ));
            }
        }
        for leaf in &self.burn_leaf_entries {
            if leaf.block_height() == 0 {
                return Err(SupplyError::Verification(
                    "burn leaf has zero block height".into(),
                ));
            }
        }
        for leaf in &self.ignore_leaf_entries {
            if leaf.block_height() == 0 {
                return Err(SupplyError::Verification(
                    "ignore leaf has zero block height".into(),
                ));
            }
        }
        Ok(())
    }
}

/// A pre-commitment output: an extra output in a minting transaction
/// that will later be spent by a supply commitment transaction.
/// Mirrors Go's `supplycommit.PreCommitment` (env.go:346).
#[derive(Clone, Debug)]
pub struct PreCommitment {
    /// Block height of the transaction containing the pre-commitment.
    pub block_height: u32,
    /// The minting transaction that created the pre-commitment.
    pub minting_txn: bitcoin::Transaction,
    /// Index of the pre-commitment output within the minting anchor
    /// transaction.
    pub out_idx: u32,
    /// The Taproot internal public key of the pre-commitment output
    /// (the delegation key).
    pub internal_key: SerializedKey,
    /// The asset group public key associated with this pre-commitment.
    pub group_pub_key: SerializedKey,
}

impl PreCommitment {
    /// Returns the outpoint spent by the supply commitment transaction.
    pub fn out_point(&self) -> tap_primitives::asset::OutPoint {
        let txid: [u8; 32] =
            *AsRef::<[u8; 32]>::as_ref(&self.minting_txn.compute_txid());
        tap_primitives::asset::OutPoint {
            txid,
            vout: self.out_idx,
        }
    }
}

/// Returns the expected pre-commitment output for the given delegation
/// key, mirroring Go's `tapgarden.PreCommitTxOut` (planter.go:3327):
/// a P2TR output for the BIP-86 (no script) tweak of the delegation
/// key, with value `DUMMY_AMT_SATS`.
pub fn pre_commit_tx_out(
    delegation_key: &SerializedKey,
) -> Result<(u64, Vec<u8>), SupplyError> {
    // ComputeTaprootKeyNoScript: taproot tweak with an empty root.
    let output_key = taproot_output_key(delegation_key, &[])
        .map_err(SupplyError::Encoding)?;
    Ok((DUMMY_AMT_SATS, p2tr_script(&output_key)))
}

/// Extracts the supply pre-commitment output from the given issuance
/// proof, mirroring Go's `supplycommit.NewPreCommitFromProof`
/// (env.go:370).
pub fn new_pre_commit_from_proof(
    issuance_proof: &tap_primitives::proof::Proof,
    delegation_key: &SerializedKey,
) -> Result<PreCommitment, SupplyError> {
    let (expected_value, expected_script) =
        pre_commit_tx_out(delegation_key)?;

    let anchor_tx = &issuance_proof.anchor_tx.0;
    let pre_commit_idx = anchor_tx.output.iter().position(|out| {
        out.value.to_sat() == expected_value
            && out.script_pubkey.as_bytes() == expected_script.as_slice()
    });

    let out_idx = pre_commit_idx.ok_or_else(|| {
        SupplyError::Verification(
            "unable to find pre-commit tx out in issuance anchor tx".into(),
        )
    })?;

    let group_key = issuance_proof
        .asset
        .group_key
        .as_ref()
        .ok_or_else(|| {
            SupplyError::Missing("issuance proof has no group key".into())
        })?
        .group_pub_key;

    Ok(PreCommitment {
        block_height: issuance_proof.block_height,
        minting_txn: anchor_tx.clone(),
        out_idx: out_idx as u32,
        internal_key: *delegation_key,
        group_pub_key: group_key,
    })
}

/// Extracts the supply pre-commitment from the given mint event,
/// mirroring Go's `supplycommit.NewPreCommitFromMintEvent`
/// (env.go:421).
pub fn new_pre_commit_from_mint_event(
    mint_event: &NewMintEvent,
    delegation_key: &SerializedKey,
) -> Result<PreCommitment, SupplyError> {
    let proof = tap_primitives::proof::decode_proof(&mint_event.raw_proof)
        .map_err(|e| {
            SupplyError::Encoding(format!(
                "unable to decode issuance proof: {}",
                e
            ))
        })?;
    new_pre_commit_from_proof(&proof, delegation_key)
}

/// The finalized on-chain state of a supply commitment transaction,
/// mirroring Go's `supplycommit.CommitmentBlock` (env.go:461).
#[derive(Clone, Debug)]
pub struct CommitmentBlock {
    /// Height of the block containing the commitment.
    pub height: u32,
    /// Hash of the block containing the commitment (internal byte
    /// order).
    pub hash: [u8; 32],
    /// Index of the commitment transaction within the block.
    pub tx_index: u32,
    /// The block header of the block containing the commitment.
    pub block_header: Option<BlockHeader>,
    /// Merkle proof of the commitment transaction's block inclusion.
    pub merkle_proof: Option<TxMerkleProof>,
    /// On-chain fees paid by the commitment transaction, in satoshis.
    pub chain_fees: i64,
}

/// The root commitment: the on-chain commitment to an asset group's
/// supply tree, mirroring Go's `supplycommit.RootCommitment`
/// (env.go:488).
#[derive(Clone, Debug)]
pub struct RootCommitment {
    /// The transaction that created the root commitment.
    pub txn: bitcoin::Transaction,
    /// The index of the commitment output in the transaction.
    pub tx_out_idx: u32,
    /// The internal key used to create the commitment output.
    pub internal_key: SerializedKey,
    /// The taproot output key of the commitment output (x-only), if
    /// already known.
    pub output_key: Option<[u8; 32]>,
    /// The root hash of the supply tree committed to.
    pub supply_root_hash: NodeHash,
    /// The root sum (outstanding supply) of the supply tree.
    pub supply_root_sum: u64,
    /// The block that contains the commitment, if mined.
    pub commitment_block: Option<CommitmentBlock>,
    /// The outpoint of the previous root commitment spent by this one.
    /// `None` for the first commitment of an asset group.
    pub spent_commitment: Option<tap_primitives::asset::OutPoint>,
}

impl RootCommitment {
    /// Returns the outpoint of this commitment's output (env.go
    /// `CommitPoint`).
    pub fn commit_point(&self) -> tap_primitives::asset::OutPoint {
        let txid: [u8; 32] =
            *AsRef::<[u8; 32]>::as_ref(&self.txn.compute_txid());
        tap_primitives::asset::OutPoint {
            txid,
            vout: self.tx_out_idx,
        }
    }

    /// Returns the tapscript root committing to the supply root
    /// (env.go `TapscriptRoot`).
    pub fn tapscript_root(&self) -> Result<[u8; 32], SupplyError> {
        compute_supply_commit_tapscript_root(&self.supply_root_hash.0)
    }

    /// Checks that the on-chain information of this commitment is
    /// correct, mirroring Go's `RootCommitment.VerifyChainAnchor`
    /// (env.go:576):
    ///
    /// 1. Block info (header + merkle proof) must be present and
    ///    self-consistent.
    /// 2. If a spent commitment is recorded, the transaction must spend
    ///    that outpoint.
    /// 3. The merkle proof must place the transaction in the block, and
    ///    the header must pass the external header verifier.
    /// 4. The committed output must match the expected re-derived
    ///    supply commitment output (value and script).
    pub fn verify_chain_anchor<M, H>(
        &self,
        merkle_verifier: &M,
        header_verifier: &H,
    ) -> Result<(), SupplyError>
    where
        M: MerkleVerifier,
        H: HeaderVerifier,
    {
        let block = self.commitment_block.as_ref().ok_or_else(|| {
            SupplyError::Missing("no block info available".into())
        })?;

        let merkle_proof = block.merkle_proof.as_ref().ok_or_else(|| {
            SupplyError::Missing("merkle proof is missing".into())
        })?;

        let header = block.block_header.as_ref().ok_or_else(|| {
            SupplyError::Missing("block header is missing".into())
        })?;

        if block.hash != header.block_hash() {
            return Err(SupplyError::Verification(
                "block hash does not match block header hash".into(),
            ));
        }

        if let Some(prev_out) = &self.spent_commitment {
            if !tx_spends_prev_out(&self.txn, prev_out) {
                return Err(SupplyError::Verification(
                    "commitment TX doesn't spend previous commitment \
                     outpoint"
                        .into(),
                ));
            }
        }

        let txid: [u8; 32] =
            *AsRef::<[u8; 32]>::as_ref(&self.txn.compute_txid());
        merkle_verifier
            .verify_merkle_proof(&txid, merkle_proof, &header.merkle_root())
            .map_err(|e| {
                SupplyError::Verification(format!(
                    "unable to verify merkle proof: {}",
                    e
                ))
            })?;

        header_verifier
            .verify_header(header, block.height)
            .map_err(|e| {
                SupplyError::Verification(format!(
                    "unable to verify block header: {}",
                    e
                ))
            })?;

        if self.tx_out_idx as usize >= self.txn.output.len() {
            return Err(SupplyError::Verification(format!(
                "tx out index {} is out of bounds for transaction with {} \
                 outputs",
                self.tx_out_idx,
                self.txn.output.len()
            )));
        }

        let tx_out = &self.txn.output[self.tx_out_idx as usize];
        let (expected_value, expected_script, _) = root_commit_tx_out(
            &self.internal_key,
            None,
            &self.supply_root_hash.0,
        )?;

        if tx_out.value.to_sat() != expected_value {
            return Err(SupplyError::Verification(format!(
                "tx out value {} does not match expected value {}",
                tx_out.value.to_sat(),
                expected_value
            )));
        }

        if tx_out.script_pubkey.as_bytes() != expected_script.as_slice() {
            return Err(SupplyError::Verification(
                "tx out pk script does not match expected pk script".into(),
            ));
        }

        Ok(())
    }
}

/// Computes the tapscript root hash for a supply commitment with the
/// given supply root hash, mirroring Go's
/// `computeSupplyCommitTapscriptRoot` (env.go:552): a single
/// non-spendable Pedersen leaf committing to the 32-byte root hash; the
/// tapscript root of a single-leaf tree is the leaf's tap hash.
pub fn compute_supply_commit_tapscript_root(
    supply_root_hash: &[u8; 32],
) -> Result<[u8; 32], SupplyError> {
    let (leaf_version, script) =
        new_non_spendable_script_leaf(PEDERSEN_VERSION, supply_root_hash)
            .map_err(|e| {
                SupplyError::Encoding(format!("unable to create leaf: {}", e))
            })?;
    Ok(tap_leaf_hash(leaf_version, &script))
}

/// Returns a P2TR script for the given x-only output key.
fn p2tr_script(output_key: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1
    script.push(0x20); // OP_DATA_32
    script.extend_from_slice(output_key);
    script
}

/// Returns the transaction output for a root supply commitment,
/// mirroring Go's `supplycommit.RootCommitTxOut` (env.go:663). Returns
/// `(value_sats, pk_script, taproot_output_key)`.
///
/// If `tap_out_key` is `None`, the output key is derived by tweaking
/// the internal key with [`compute_supply_commit_tapscript_root`] of
/// the supply root hash.
pub fn root_commit_tx_out(
    internal_key: &SerializedKey,
    tap_out_key: Option<&[u8; 32]>,
    supply_root_hash: &[u8; 32],
) -> Result<(u64, Vec<u8>, [u8; 32]), SupplyError> {
    let output_key = match tap_out_key {
        Some(key) => *key,
        None => {
            let root =
                compute_supply_commit_tapscript_root(supply_root_hash)?;
            taproot_output_key(internal_key, &root)
                .map_err(SupplyError::Encoding)?
        }
    };

    Ok((DUMMY_AMT_SATS, p2tr_script(&output_key), output_key))
}

/// The chain proof for a supply commitment transaction, mirroring Go's
/// `supplycommit.ChainProof` (env.go:701).
#[derive(Clone, Debug)]
pub struct ChainProof {
    /// The header of the block containing the commitment transaction.
    pub header: BlockHeader,
    /// The height of that block.
    pub block_height: u32,
    /// The merkle proof of the transaction's inclusion in the block.
    pub merkle_proof: TxMerkleProof,
    /// The index of the transaction in the block.
    pub tx_index: u32,
}

/// Rebuilds the root supply tree that a set of sub-trees commits to,
/// starting from the given base root tree. Convenience wrapper used by
/// the verifier and stores.
pub fn root_supply_tree_from(
    base: &SupplyTree,
    sub_trees: &SupplyTrees,
) -> Result<SupplyTree, SupplyError> {
    let mut root_tree = base.clone();
    update_root_supply_tree(&mut root_tree, sub_trees)?;
    Ok(root_tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Go vector: sha256 of the sub-tree names (Go
    /// `SupplySubTree.UniverseKey`).
    #[test]
    fn test_subtree_universe_keys_match_go() {
        let cases = [
            (
                SupplySubTree::Mint,
                "0211447b51f48865720d0e113116967c0890152c811a78c45d4344a166918b58",
            ),
            (
                SupplySubTree::Burn,
                "859facc5a4c9b80ac2eef78916c1953bcccaab6014bb11b9de8337430ea34f0c",
            ),
            (
                SupplySubTree::Ignore,
                "5f0af516936c6ab13dfce52362f84a3c0aa8d87aca8f2bcaf55ad4e1e0178034",
            ),
        ];
        for (tree_type, expected) in cases {
            assert_eq!(hex_encode(&tree_type.universe_key()), expected);
        }
    }

    /// Go vector: a supply root over a fixed set of mint/burn/ignore
    /// leaves, generated by executing Go's `ApplyTreeUpdates` +
    /// `UpdateRootSupplyTree` equivalents on the same fixed leaves.
    #[test]
    fn test_supply_root_matches_go() {
        let mut trees = SupplyTrees::new();

        let mut insert =
            |tree_type: SupplySubTree, key_byte: u8, value: &[u8], sum: u64| {
                let tree = trees.fetch_or_create(tree_type);
                tree.insert([key_byte; 32], LeafNode::new(value.to_vec(), sum))
                    .expect("insert");
            };

        insert(SupplySubTree::Mint, 0x01, &[0xde, 0xad, 0xbe, 0xef], 100);
        insert(SupplySubTree::Mint, 0x02, &[0x01, 0x02, 0x03], 23);
        insert(SupplySubTree::Burn, 0x03, &[0x04, 0x05], 11);
        insert(SupplySubTree::Ignore, 0x04, &[0x06], 5);

        let expected_subtree_roots = [
            (
                SupplySubTree::Mint,
                "b5e5aa60c3749eaf68d991d26cb49d56f4acde82ff7f9a8bee39710dd0f4de61",
                123u64,
            ),
            (
                SupplySubTree::Burn,
                "526b712625229142e931e7d30ecddf4b3cbada34d1b8338376ab64f8ec60603f",
                11,
            ),
            (
                SupplySubTree::Ignore,
                "29b87c94203cba4922d48fe176873dc058a4a1dec5366de1bcb87089f84339b3",
                5,
            ),
        ];
        for (tree_type, expected_hash, expected_sum) in expected_subtree_roots
        {
            let root = trees.get(tree_type).expect("tree").root().unwrap();
            assert_eq!(hex_encode(&root.node_hash().0), expected_hash);
            assert_eq!(root.node_sum(), expected_sum);
        }

        let mut root_tree = new_supply_tree();
        update_root_supply_tree(&mut root_tree, &trees).expect("update");
        let root = root_tree.root().unwrap();
        assert_eq!(
            hex_encode(&root.node_hash().0),
            "9375e99d7978e21c334df3f68a8af061ee3b617675855536be0c22860da36aa9"
        );
        assert_eq!(root.node_sum(), 139);

        assert_eq!(calc_total_outstanding_supply(&trees).unwrap(), 107);
    }

    /// Go vector: `computeSupplyCommitTapscriptRoot` and
    /// `RootCommitTxOut` for a fixed supply root hash and internal key.
    #[test]
    fn test_supply_commit_tapscript_root_matches_go() {
        let fixed_root = [0x77u8; 32];
        let root =
            compute_supply_commit_tapscript_root(&fixed_root).expect("root");
        assert_eq!(
            hex_encode(&root),
            "9af4a99ae78133284fea7415e10b6abaefa775afee324418f9d8a042813518f6"
        );

        // Internal key from Go vector (private key 0x...42).
        let internal_key = SerializedKey(
            hex_decode(
                "03079264c4b4bfcd7fe3a7b7b92b6c439f3a5b3abcd29189bf7b54d781ff03d722",
            )
            .try_into()
            .expect("33 bytes"),
        );
        let (value, pk_script, output_key) =
            root_commit_tx_out(&internal_key, None, &fixed_root)
                .expect("tx out");
        assert_eq!(value, 1000);
        assert_eq!(
            hex_encode(&pk_script),
            "5120544a2cb26fe71c9a3864f5b89dbc97304d7c5ffeba93ed1a4b82f1bb5c6a82b0"
        );
        assert_eq!(
            hex_encode(&output_key),
            "544a2cb26fe71c9a3864f5b89dbc97304d7c5ffeba93ed1a4b82f1bb5c6a82b0"
        );
    }

    /// Go vector: `tapgarden.PreCommitTxOut` (planter.go:3327) executed
    /// against v0.8.99-alpha with the delegation private key 0x..21
    /// (the same key as the signed-ignore-tuple vectors):
    ///
    /// ```text
    /// pub:      021697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5
    /// value:    1000
    /// pkScript: 51209c865d97d3097e3510189cd67944fea034ad394dc7d42656c5d3484f2f6862b2
    /// ```
    #[test]
    fn test_pre_commit_tx_out_matches_go() {
        let delegation_key = SerializedKey(
            hex_decode(
                "021697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5",
            )
            .try_into()
            .expect("33 bytes"),
        );
        let (value, script) =
            pre_commit_tx_out(&delegation_key).expect("tx out");
        assert_eq!(value, 1000);
        assert_eq!(
            hex_encode(&script),
            "51209c865d97d3097e3510189cd67944fea034ad394dc7d42656c5d3484f2f6862b2"
        );
    }

    #[test]
    fn test_zero_sum_subtrees_skipped() {
        // An all-empty sub-tree map must leave the root tree empty,
        // matching Go's skip of zero-sum sub-trees.
        let mut trees = SupplyTrees::new();
        for tree_type in ALL_SUPPLY_SUB_TREES {
            trees.fetch_or_create(tree_type);
        }
        let mut root_tree = new_supply_tree();
        update_root_supply_tree(&mut root_tree, &trees).expect("update");
        let root = root_tree.root().unwrap();
        assert_eq!(root.node_sum(), 0);
        assert_eq!(
            root.node_hash(),
            tap_primitives::mssmt::empty_tree_root_hash()
        );
    }

    #[test]
    fn test_subtree_names_round_trip() {
        for tree_type in ALL_SUPPLY_SUB_TREES {
            assert_eq!(
                SupplySubTree::from_str_name(tree_type.as_str()),
                Some(tree_type)
            );
        }
        assert_eq!(SupplySubTree::from_str_name("bogus"), None);
    }

    /// Ports the deterministic cases of Go's
    /// `TestCalcTotalOutstandingSupply` (supplycommit/util_test.go:35).
    #[test]
    fn test_calc_total_outstanding_supply_cases() {
        let mut insert =
            |trees: &mut SupplyTrees, tt: SupplySubTree, key: u8, sum: u64| {
                trees
                    .fetch_or_create(tt)
                    .insert([key; 32], LeafNode::new(vec![key], sum))
                    .expect("insert");
            };

        // Empty trees: zero supply.
        let trees = SupplyTrees::new();
        assert_eq!(calc_total_outstanding_supply(&trees).unwrap(), 0);

        // No mint tree at all but burns present: still zero (Go
        // returns early when the minted total is zero).
        let mut trees = SupplyTrees::new();
        insert(&mut trees, SupplySubTree::Burn, 0x01, 10);
        assert_eq!(calc_total_outstanding_supply(&trees).unwrap(), 0);

        // Mint only.
        let mut trees = SupplyTrees::new();
        insert(&mut trees, SupplySubTree::Mint, 0x01, 100);
        assert_eq!(calc_total_outstanding_supply(&trees).unwrap(), 100);

        // Mint minus burn minus ignore.
        let mut trees = SupplyTrees::new();
        insert(&mut trees, SupplySubTree::Mint, 0x01, 100);
        insert(&mut trees, SupplySubTree::Burn, 0x02, 30);
        insert(&mut trees, SupplySubTree::Ignore, 0x03, 20);
        assert_eq!(calc_total_outstanding_supply(&trees).unwrap(), 50);

        // Burn exceeding mint errors.
        let mut trees = SupplyTrees::new();
        insert(&mut trees, SupplySubTree::Mint, 0x01, 10);
        insert(&mut trees, SupplySubTree::Burn, 0x02, 30);
        assert!(calc_total_outstanding_supply(&trees).is_err());

        // Ignore exceeding remaining supply errors.
        let mut trees = SupplyTrees::new();
        insert(&mut trees, SupplySubTree::Mint, 0x01, 10);
        insert(&mut trees, SupplySubTree::Ignore, 0x02, 30);
        assert!(calc_total_outstanding_supply(&trees).is_err());
    }
}
