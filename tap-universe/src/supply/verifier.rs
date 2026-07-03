// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Supply commitment verifier, mirroring Go's
//! `universe/supplyverifier/verifier.go`.
//!
//! The verifier checks externally produced supply commitments against
//! the chain and the local view of previously verified commitments:
//!
//! - [`SupplyVerifier::verify_commit`] mirrors `Verifier.VerifyCommit`:
//!   chain-anchor verification, duplicate detection, delegation key
//!   lookup, per-leaf verification, and dispatch to initial or
//!   incremental commitment verification.
//!
//! External dependencies are modeled as traits: [`AssetLookup`] (asset
//! group metadata / delegation keys), [`SupplyCommitView`] (previously
//! verified commitments), and [`SupplyTreeView`] (the locally stored
//! supply trees). Chain access reuses tap-primitives'
//! [`HeaderVerifier`]/[`MerkleVerifier`] and the proof
//! [`VerifierCtx`].
//!
//! # Simplifications relative to Go
//!
//! - Ignore signature verification is done in-process (BIP-340 over
//!   `sha256(tuple digest)`) instead of via lnd's `VerifyMessage` RPC;
//!   the verified bytes are identical.
//! - Issuance/burn leaf checks that compare the decoded proof against
//!   redundant copies of the same data inside Go's `universe.Leaf`
//!   (asset deep-equal, genesis equality, IsBurn flag on the leaf) are
//!   covered by construction here: the Rust events carry only the raw
//!   proof, and all fields are re-derived from it. The cryptographic
//!   checks (full proof verification, group key equivalence, burn key
//!   check, pre-commitment extraction) are all performed.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::proof::{
    decode_proof, ChainLookup, GroupVerifier, HeaderVerifier, IgnoreChecker,
    MerkleVerifier, ProofVerificationOptions, VerifierCtx,
};

use super::events::{NewBurnEvent, NewIgnoreEvent, NewMintEvent};
use super::{
    apply_tree_updates, new_pre_commit_from_proof, root_supply_tree_from,
    new_supply_tree, PreCommitment, RootCommitment, SupplyError, SupplyLeaves,
    SupplyTree, SupplyTrees,
};

/// Asset metadata lookups needed during supply verification, a slimmed
/// down version of Go's `supplycommit.AssetLookup` (env.go:234).
pub trait AssetLookup {
    /// Returns the delegation key for the given asset group, from the
    /// group anchor's asset metadata (`MetaReveal.delegation_key`).
    /// Mirrors Go's `FetchDelegationKey` (supplyverifier/util.go:14).
    fn delegation_key(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SerializedKey, SupplyError>;

    /// Returns the tweaked group key that the given asset ID belongs
    /// to, mirroring Go's `QueryAssetGroupByID`. Returns an error if
    /// the asset group is unknown.
    fn group_key_for_asset(
        &self,
        asset_id: &AssetId,
    ) -> Result<SerializedKey, SupplyError>;
}

/// Lookup of previously verified supply commitments, mirroring Go's
/// `supplyverifier.SupplyCommitView` (supplyverifier/env.go:32).
pub trait SupplyCommitView {
    /// Returns the very first supply commitment of the asset group, or
    /// `None` if no commitment exists yet (Go returns
    /// `ErrCommitmentNotFound`).
    fn fetch_starting_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, SupplyError>;

    /// Returns the supply commitment with the given outpoint, or
    /// `None` if unknown.
    fn fetch_commitment_by_outpoint(
        &self,
        group_key: &SerializedKey,
        outpoint: &OutPoint,
    ) -> Result<Option<RootCommitment>, SupplyError>;
}

/// Lookup of the locally stored supply trees, mirroring Go's
/// `supplyverifier.SupplyTreeView`.
pub trait SupplyTreeView {
    /// Returns the current root supply tree and sub-trees for the
    /// asset group.
    fn fetch_supply_trees(
        &self,
        group_key: &SerializedKey,
    ) -> Result<(SupplyTree, SupplyTrees), SupplyError>;
}

/// Verifies supply commitments for an asset group, mirroring Go's
/// `supplyverifier.Verifier`.
pub struct SupplyVerifier<'a, H, M, G, C, I, L, V, T>
where
    H: HeaderVerifier,
    M: MerkleVerifier,
    G: GroupVerifier,
    C: ChainLookup,
    I: IgnoreChecker,
    L: AssetLookup,
    V: SupplyCommitView,
    T: SupplyTreeView,
{
    /// Proof verification context used for issuance/burn leaf proofs
    /// and for the commitment's own chain anchor.
    pub ctx: &'a VerifierCtx<H, M, G, C, I>,
    /// Options passed to per-leaf proof verification.
    pub proof_opts: ProofVerificationOptions,
    /// Asset metadata lookups.
    pub asset_lookup: &'a L,
    /// Previously verified supply commitments.
    pub commit_view: &'a V,
    /// Locally stored supply trees.
    pub tree_view: &'a T,
}

fn verification_err(msg: impl Into<String>) -> SupplyError {
    SupplyError::Verification(msg.into())
}

/// Reports whether two public keys are equivalent when compared in
/// their BIP-340 (x-only) serialized form, mirroring Go's
/// `IsEquivalentPubKeys` (supplyverifier/verifier.go:428).
pub fn is_equivalent_pub_keys(a: &SerializedKey, b: &SerializedKey) -> bool {
    a.schnorr_bytes() == b.schnorr_bytes()
}

impl<'a, H, M, G, C, I, L, V, T> SupplyVerifier<'a, H, M, G, C, I, L, V, T>
where
    H: HeaderVerifier,
    M: MerkleVerifier,
    G: GroupVerifier,
    C: ChainLookup,
    I: IgnoreChecker,
    L: AssetLookup,
    V: SupplyCommitView,
    T: SupplyTreeView,
{
    /// Verifies a supply commitment for the given asset group,
    /// mirroring Go's `Verifier.VerifyCommit`
    /// (supplyverifier/verifier.go:735).
    pub fn verify_commit(
        &self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
        leaves: &SupplyLeaves,
        unspent_pre_commits: &[PreCommitment],
    ) -> Result<(), SupplyError> {
        // Static on-chain verification of the commitment's anchoring
        // block header and output.
        commitment.verify_chain_anchor(
            &self.ctx.merkle_verifier,
            &self.ctx.header_verifier,
        )?;

        // If the commitment is already known, it has been verified and
        // stored before.
        let existing = self.commit_view.fetch_commitment_by_outpoint(
            group_key,
            &commitment.commit_point(),
        )?;
        if existing.is_some() {
            return Ok(());
        }

        let delegation_key = self.asset_lookup.delegation_key(group_key)?;

        // Each issuance leaf must correspond to a pre-commitment output
        // created at the time of asset issuance.
        if unspent_pre_commits.len() < leaves.issuance_leaf_entries.len() {
            return Err(verification_err(format!(
                "not enough unspent supply pre-commitment outputs for \
                 issuance leaves: have {}, need {}",
                unspent_pre_commits.len(),
                leaves.issuance_leaf_entries.len()
            )));
        }

        self.verify_supply_leaves(group_key, &delegation_key, leaves)?;

        if commitment.spent_commitment.is_none() {
            self.verify_initial_commit(
                group_key,
                commitment,
                leaves,
                unspent_pre_commits,
            )
        } else {
            self.verify_incremental_commit(
                group_key,
                commitment,
                leaves,
                unspent_pre_commits,
            )
        }
    }

    /// Verifies that all eligible unspent pre-commitment outputs are
    /// spent by the supply commitment transaction, mirroring Go's
    /// `verifyPrecommitsSpent` (supplyverifier/verifier.go:105).
    fn verify_precommits_spent(
        &self,
        commitment: &RootCommitment,
        all_pre_commits: &[PreCommitment],
    ) -> Result<(), SupplyError> {
        // The initial supply commitment must spend at least one mint
        // pre-commitment output.
        if commitment.spent_commitment.is_none() && all_pre_commits.is_empty()
        {
            return Err(verification_err(
                "no unspent supply pre-commitment outputs for the initial \
                 supply commitment",
            ));
        }

        let block = commitment.commitment_block.as_ref().ok_or_else(|| {
            SupplyError::Missing("missing commitment block".into())
        })?;

        // Only pre-commitments at or before the commitment's anchor
        // block height must be spent.
        let eligible: Vec<&PreCommitment> = all_pre_commits
            .iter()
            .filter(|pc| pc.block_height <= block.height)
            .collect();

        let mut matched = std::collections::HashSet::new();
        for tx_in in &commitment.txn.input {
            let spent_txid: &[u8; 32] =
                tx_in.previous_output.txid.as_ref();
            for pre_commit in &eligible {
                let op = pre_commit.out_point();
                if *spent_txid == op.txid
                    && tx_in.previous_output.vout == op.vout
                {
                    matched.insert((op.txid, op.vout));
                    break;
                }
            }
        }

        if matched.len() != eligible.len() {
            return Err(verification_err(format!(
                "supply commitment does not spend all known \
                 pre-commitments: expected {}, found {}",
                eligible.len(),
                matched.len()
            )));
        }

        Ok(())
    }

    /// Verifies the first supply commitment for an asset group,
    /// mirroring Go's `verifyInitialCommit`
    /// (supplyverifier/verifier.go:183).
    fn verify_initial_commit(
        &self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
        leaves: &SupplyLeaves,
        unspent_pre_commits: &[PreCommitment],
    ) -> Result<(), SupplyError> {
        // An initial commitment must not specify a spent outpoint.
        if commitment.spent_commitment.is_some() {
            return Err(verification_err(
                "initial supply commitment must not specify a spent \
                 commitment outpoint",
            ));
        }

        // If a starting commitment already exists, the given commitment
        // must be that same commitment.
        if let Some(init_commit) =
            self.commit_view.fetch_starting_commitment(group_key)?
        {
            if init_commit.commit_point() == commitment.commit_point() {
                return Ok(());
            }
            return Err(verification_err(
                "found alternative initial commitment for asset group",
            ));
        }

        self.verify_precommits_spent(commitment, unspent_pre_commits)?;

        // Apply the leaves to empty supply trees and check the
        // resulting root supply tree against the commitment root.
        let supply_trees =
            apply_tree_updates(&SupplyTrees::new(), &leaves.all_updates())?;

        let root_supply_tree =
            root_supply_tree_from(&new_supply_tree(), &supply_trees)?;
        let gen_root = root_supply_tree
            .root()
            .map_err(|e| SupplyError::Tree(e.to_string()))?;

        if gen_root.node_hash() != commitment.supply_root_hash {
            return Err(verification_err(
                "generated supply tree root does not match commitment \
                 supply root",
            ));
        }

        Ok(())
    }

    /// Verifies an incremental supply commitment, mirroring Go's
    /// `verifyIncrementalCommit` (supplyverifier/verifier.go:289).
    fn verify_incremental_commit(
        &self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
        leaves: &SupplyLeaves,
        unspent_pre_commits: &[PreCommitment],
    ) -> Result<(), SupplyError> {
        let spent_out_point =
            commitment.spent_commitment.as_ref().ok_or_else(|| {
                SupplyError::Missing(
                    "missing spent supply commitment outpoint".into(),
                )
            })?;

        // The previous commitment must be known (i.e. already
        // verified).
        let spent_commit = self
            .commit_view
            .fetch_commitment_by_outpoint(group_key, spent_out_point)?
            .ok_or_else(|| {
                verification_err(
                    "previous supply commitment not found",
                )
            })?;

        // The commitment must actually spend the referenced previous
        // commitment outpoint.
        let spends_prev = commitment.txn.input.iter().any(|tx_in| {
            let txid: &[u8; 32] = tx_in.previous_output.txid.as_ref();
            *txid == spent_out_point.txid
                && tx_in.previous_output.vout == spent_out_point.vout
        });
        if !spends_prev {
            return Err(verification_err(
                "supply commitment does not spend provided previous \
                 commitment outpoint",
            ));
        }

        self.verify_precommits_spent(commitment, unspent_pre_commits)?;

        // The locally stored trees must correspond to the spent
        // commitment.
        let (spent_root_tree, spent_sub_trees) =
            self.tree_view.fetch_supply_trees(group_key)?;

        let stored_spent_root = spent_root_tree
            .root()
            .map_err(|e| SupplyError::Tree(e.to_string()))?;
        if stored_spent_root.node_hash() != spent_commit.supply_root_hash {
            return Err(verification_err(
                "local spent supply tree root does not match spent \
                 commitment supply root",
            ));
        }

        // Apply the new leaves on top of the spent sub-trees and root
        // tree, then check the resulting root.
        let new_supply_trees =
            apply_tree_updates(&spent_sub_trees, &leaves.all_updates())?;

        let expected_supply_tree =
            root_supply_tree_from(&spent_root_tree, &new_supply_trees)?;
        let expected_root = expected_supply_tree
            .root()
            .map_err(|e| SupplyError::Tree(e.to_string()))?;

        if expected_root.node_hash() != commitment.supply_root_hash {
            return Err(verification_err(
                "expected supply tree root does not match commitment \
                 supply root",
            ));
        }

        Ok(())
    }

    /// Verifies all provided supply leaves, mirroring Go's
    /// `verifySupplyLeaves` (supplyverifier/verifier.go:674).
    fn verify_supply_leaves(
        &self,
        group_key: &SerializedKey,
        delegation_key: &SerializedKey,
        leaves: &SupplyLeaves,
    ) -> Result<(), SupplyError> {
        leaves.validate_block_heights()?;

        for entry in &leaves.issuance_leaf_entries {
            self.verify_issuance_leaf(group_key, delegation_key, entry)?;
        }

        for entry in &leaves.ignore_leaf_entries {
            self.verify_ignore_leaf(group_key, delegation_key, entry)?;
        }

        for entry in &leaves.burn_leaf_entries {
            self.verify_burn_leaf(group_key, entry)?;
        }

        Ok(())
    }

    /// Verifies a single issuance leaf, mirroring Go's
    /// `verifyIssuanceLeaf` (supplyverifier/verifier.go:436).
    fn verify_issuance_leaf(
        &self,
        group_key: &SerializedKey,
        delegation_key: &SerializedKey,
        entry: &NewMintEvent,
    ) -> Result<(), SupplyError> {
        let proof = decode_proof(&entry.raw_proof).map_err(|e| {
            verification_err(format!(
                "unable to decode issuance proof: {}",
                e
            ))
        })?;

        // Full proof verification (chain anchor, inclusion/exclusion
        // proofs, genesis + group key reveals, state transition).
        proof
            .verify(None, self.ctx, &self.proof_opts)
            .map_err(|e| {
                verification_err(format!(
                    "issuance proof failed verification: {}",
                    e
                ))
            })?;

        // Leaf fields must match the proof.
        if entry.block_height != proof.block_height {
            return Err(verification_err(
                "mint height in issuance leaf does not match issuance \
                 proof block height",
            ));
        }

        if entry.amount != proof.asset.amount {
            return Err(verification_err(
                "amount in issuance leaf does not match amount in \
                 issuance proof",
            ));
        }

        let proof_group_key = proof
            .asset
            .group_key
            .as_ref()
            .ok_or_else(|| {
                verification_err(
                    "missing asset group key in issuance proof",
                )
            })?
            .group_pub_key;

        // The leaf key's asset ID must match the proof.
        if entry.leaf_key.asset_id != proof.asset.id() {
            return Err(verification_err(
                "issuance leaf key asset id does not match issuance \
                 proof asset id",
            ));
        }

        // The proof's asset group must be the expected asset group.
        if !is_equivalent_pub_keys(&proof_group_key, group_key) {
            return Err(verification_err(
                "asset group key in issuance proof does not match \
                 expected asset group key",
            ));
        }

        // The issuance anchor transaction must contain the expected
        // pre-commitment output for the delegation key.
        new_pre_commit_from_proof(&proof, delegation_key).map_err(|e| {
            verification_err(format!(
                "unable to extract pre-commit output from issuance proof \
                 anchor tx: {}",
                e
            ))
        })?;

        Ok(())
    }

    /// Verifies a single ignore leaf, mirroring Go's
    /// `verifyIgnoreLeaf` (supplyverifier/verifier.go:553).
    fn verify_ignore_leaf(
        &self,
        group_key: &SerializedKey,
        delegation_key: &SerializedKey,
        entry: &NewIgnoreEvent,
    ) -> Result<(), SupplyError> {
        // The delegation key must have signed the tuple digest.
        entry
            .signed_tuple
            .verify_sig(delegation_key)
            .map_err(|e| {
                verification_err(format!(
                    "failed to verify signed ignore tuple signature: {}",
                    e
                ))
            })?;

        // The asset ID in the ignore leaf must belong to the expected
        // asset group.
        let asset_group_key = self
            .asset_lookup
            .group_key_for_asset(&entry.signed_tuple.tuple.prev_id.id)?;

        if !is_equivalent_pub_keys(&asset_group_key, group_key) {
            return Err(verification_err(
                "asset group key for ignore leaf asset does not match \
                 expected asset group key",
            ));
        }

        Ok(())
    }

    /// Verifies a single burn leaf, mirroring Go's `verifyBurnLeaf`
    /// (supplyverifier/verifier.go:613).
    fn verify_burn_leaf(
        &self,
        group_key: &SerializedKey,
        entry: &NewBurnEvent,
    ) -> Result<(), SupplyError> {
        let proof =
            decode_proof(&entry.burn_leaf.raw_proof).map_err(|e| {
                verification_err(format!(
                    "unable to decode burn proof: {}",
                    e
                ))
            })?;

        proof
            .verify(None, self.ctx, &self.proof_opts)
            .map_err(|e| {
                verification_err(format!(
                    "burn leaf proof failed verification: {}",
                    e
                ))
            })?;

        // The leaf key's asset ID must match the proof.
        if entry.burn_leaf.leaf_key.asset_id != proof.asset.id() {
            return Err(verification_err(
                "burn leaf key asset id does not match burn proof asset id",
            ));
        }

        // The asset in the burn proof must be a burn.
        if !proof.asset.is_burn() {
            return Err(verification_err(
                "asset in burn proof is not a burn asset",
            ));
        }

        let proof_group_key = proof
            .asset
            .group_key
            .as_ref()
            .ok_or_else(|| {
                verification_err("missing asset group key in burn proof")
            })?
            .group_pub_key;

        if !is_equivalent_pub_keys(&proof_group_key, group_key) {
            return Err(verification_err(
                "asset group key in burn proof does not match expected \
                 asset group key",
            ));
        }

        Ok(())
    }
}
