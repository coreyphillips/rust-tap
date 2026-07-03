// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The universe supply commitment authoring pipeline.
//!
//! Go's `universe/supplycommit` drives commitment authoring through a
//! protofsm state machine (DefaultState -> UpdatesPending ->
//! CommitTreeCreate -> CommitTxCreate -> CommitTxSign ->
//! CommitBroadcast -> CommitFinalize; transitions.go). This port maps
//! those states onto this repo's synchronous pipeline pattern with
//! persistence checkpoints:
//!
//! - Staging (Default/UpdatesPending): supply update events are
//!   persisted in the [`tap_persist::supply_store::SupplyStagingStore`]
//!   as they are produced (mint confirmation, ignore requests, burns).
//! - [`commit_supply`] (CommitTreeCreate + CommitTxCreate +
//!   CommitTxSign + broadcast): computes the new supply root from the
//!   staged events, builds/funds/signs the commitment transaction
//!   (spending all unspent pre-commitments plus, incrementally, the
//!   previous commitment output), broadcasts it, and registers a
//!   durable pending anchor snapshotting the frozen events (Go's
//!   `FreezePendingTransition`). Events staged afterwards stay queued
//!   for the next commitment (Go's dangling updates).
//! - [`finish_supply_commit_confirmation`] (CommitBroadcast conf +
//!   CommitFinalize): on confirmation, attaches the commitment block
//!   (header + merkle proof), verifies the whole commitment with the
//!   node's own [`SupplyVerifier`] (initial and incremental paths) as
//!   the oracle, and only then applies the tree updates, persists the
//!   [`RootCommitment`], marks the spent pre-commitments, and consumes
//!   the frozen staged events. Every step is idempotent, so a replay
//!   after a partial failure or restart is harmless.
//!
//! Simplifications relative to Go's FSM are documented on the
//! individual functions and summarized in the crate-level parity
//! notes.

use std::collections::HashMap;
use std::sync::Arc;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{
    AssetSigner, ChainBridge, KeyRing, TxConfirmation, WalletAnchor,
};
use tap_onchain::supply_commit::{
    build_and_sign_supply_commit_tx, SupplyCommitInput,
};
use tap_primitives::asset::{
    AssetId, PrevId, SerializedKey, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof::{
    decode_proof, tx_spends_prev_out, BlockHeader, DefaultMerkleVerifier,
    FixedHeightChainLookup, GroupVerifier, HeaderVerifier, ProofError,
    ProofVerificationOptions, VerifierCtx,
};
use tap_universe::ignore::{IgnoreSig, IgnoreTuple, SignedIgnoreTuple};
use tap_universe::supply::{
    apply_tree_updates, root_supply_tree_from, AssetLookup, CommitmentBlock,
    NewBurnEvent, NewIgnoreEvent, RootCommitment,
    SupplyCommitView, SupplyError, SupplyLeaves, SupplyTree, SupplyTreeView,
    SupplyTrees, SupplyUpdateEvent, SupplyVerifier,
};

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
use crate::tasks::{AnchorKind, PendingAnchor, SupplyCommitAnchor};

fn supply_err(msg: impl Into<String>) -> TapNodeError {
    TapNodeError::Supply(msg.into())
}

/// Returns whether a supply commitment transaction for the group is
/// already broadcast and awaiting confirmation.
pub(crate) fn supply_commit_in_flight<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    group_key: &SerializedKey,
) -> bool
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    node.pending_anchors
        .lock()
        .expect("pending anchors lock")
        .iter()
        .any(|anchor| {
            matches!(
                &anchor.kind,
                AnchorKind::SupplyCommit(supply)
                    if supply.group_key == *group_key
            )
        })
}

/// Builds, funds, signs, and broadcasts a supply commitment for the
/// group's staged updates. See [`TapNode::commit_supply`].
pub(crate) fn commit_supply<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    group_key: &SerializedKey,
) -> Result<Option<[u8; 32]>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // One in-flight commitment per group: the next commitment must
    // spend the confirmed output of the previous one (Go's single
    // non-finalized transition per group key).
    if supply_commit_in_flight(node, group_key) {
        return Err(supply_err(
            "a supply commitment for this group is already awaiting \
             confirmation",
        ));
    }

    // Freeze the currently staged updates into this commitment. A
    // commitment without pending updates is a no-op (Go's CommitTick
    // only acts in UpdatesPendingState).
    let staged = node
        .supply_staging_store
        .lock()
        .expect("supply staging store lock")
        .staged_updates(group_key)
        .map_err(TapNodeError::Storage)?;
    if staged.is_empty() {
        return Ok(None);
    }

    // CommitTreeCreate: compute the new supply root by applying the
    // frozen updates to (copies of) the stored trees. Nothing is
    // persisted until the commitment confirms and self-verifies.
    let (root_tree, sub_trees) = {
        let trees = node
            .supply_tree_store
            .lock()
            .expect("supply tree store lock");
        (
            trees
                .fetch_root_supply_tree(group_key)
                .map_err(TapNodeError::Storage)?,
            trees
                .fetch_sub_trees(group_key)
                .map_err(TapNodeError::Storage)?,
        )
    };
    let new_sub_trees = apply_tree_updates(&sub_trees, &staged)
        .map_err(|e| supply_err(e.to_string()))?;
    let new_root_tree = root_supply_tree_from(&root_tree, &new_sub_trees)
        .map_err(|e| supply_err(e.to_string()))?;
    let new_root = new_root_tree
        .root()
        .map_err(|e| supply_err(e.to_string()))?;
    let supply_root_hash = new_root.node_hash();
    let supply_root_sum = new_root.node_sum();

    // CommitTxCreate: the inputs are every unspent pre-commitment
    // output plus, when a previous commitment exists, its output
    // (transitions.go:447-526).
    let (prev_commitment, pre_commits) = {
        let commits = node
            .supply_commit_store
            .lock()
            .expect("supply commit store lock");
        (
            commits
                .latest_commitment(group_key)
                .map_err(TapNodeError::Storage)?,
            commits
                .unspent_pre_commits(group_key)
                .map_err(TapNodeError::Storage)?,
        )
    };
    if prev_commitment.is_none() && pre_commits.is_empty() {
        return Err(supply_err(
            "initial supply commitment requires an unspent \
             pre-commitment output",
        ));
    }

    let (inputs, internal_key_desc) = {
        let mut staging = node
            .supply_staging_store
            .lock()
            .expect("supply staging store lock");

        let mut inputs = Vec::with_capacity(pre_commits.len() + 1);
        for pre_commit in &pre_commits {
            let desc = staging
                .key_descriptor(&pre_commit.internal_key)
                .map_err(TapNodeError::Storage)?
                .ok_or_else(|| {
                    supply_err(
                        "no key descriptor for the pre-commitment \
                         delegation key: the node cannot key-spend a \
                         pre-commitment output it does not custody",
                    )
                })?;
            let prev_tx_out = pre_commit
                .minting_txn
                .output
                .get(pre_commit.out_idx as usize)
                .ok_or_else(|| {
                    supply_err("pre-commitment output index out of range")
                })?
                .clone();
            inputs.push(SupplyCommitInput {
                outpoint: pre_commit.out_point(),
                prev_tx_out,
                key_desc: desc,
                tapscript_root: None,
            });
        }

        // The commitment output internal key: reuse the previous
        // commitment's key, or derive (and import) a fresh one for the
        // initial commitment (transitions.go:534-574).
        let internal_key_desc = match &prev_commitment {
            Some(prev) => {
                let desc = staging
                    .key_descriptor(&prev.internal_key)
                    .map_err(TapNodeError::Storage)?
                    .ok_or_else(|| {
                        supply_err(
                            "no key descriptor for the previous supply \
                             commitment internal key",
                        )
                    })?;

                let prev_tx_out = prev
                    .txn
                    .output
                    .get(prev.tx_out_idx as usize)
                    .ok_or_else(|| {
                        supply_err(
                            "previous commitment output index out of range",
                        )
                    })?
                    .clone();
                let tapscript_root = prev
                    .tapscript_root()
                    .map_err(|e| supply_err(e.to_string()))?;
                inputs.push(SupplyCommitInput {
                    outpoint: prev.commit_point(),
                    prev_tx_out,
                    key_desc: desc.clone(),
                    tapscript_root: Some(tapscript_root),
                });
                desc
            }
            None => {
                let desc = node
                    .keys
                    .derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
                staging
                    .save_key_descriptor(&desc)
                    .map_err(TapNodeError::Storage)?;
                desc
            }
        };

        (inputs, internal_key_desc)
    };

    // CommitTxSign: fund via the wallet, key-path sign our inputs via
    // the AssetSigner seam, finalize via the wallet.
    let fee_rate =
        node.chain.estimate_fee(node.config.default_conf_target)?;
    let signed = build_and_sign_supply_commit_tx(
        &*node.wallet,
        &*node.keys,
        fee_rate,
        &inputs,
        &internal_key_desc.pub_key,
        &supply_root_hash.0,
    )?;

    // A freshly derived internal key means a first commitment: import
    // the taproot output key so the wallet tracks the sats (Go's
    // wallet.ImportTaprootOutput on the tapOutKey).
    if prev_commitment.is_none() {
        let mut output_key = [0u8; 33];
        output_key[0] = 0x02;
        output_key[1..].copy_from_slice(&signed.output_key);
        node.wallet.import_taproot_output(&SerializedKey(output_key))?;
    }

    // CommitBroadcast: publish and register the durable pending
    // anchor. The anchor snapshots the frozen events, so updates
    // staged from here on ride the next commitment.
    node.chain.publish_transaction(&signed.signed_tx)?;

    let txn: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&signed.signed_tx).map_err(|e| {
            supply_err(format!("signed commitment tx parse: {}", e))
        })?;
    let commitment = RootCommitment {
        txn,
        tx_out_idx: signed.commit_output_index,
        internal_key: internal_key_desc.pub_key,
        output_key: Some(signed.output_key),
        supply_root_hash,
        supply_root_sum,
        commitment_block: None,
        spent_commitment: prev_commitment.as_ref().map(|p| p.commit_point()),
    };

    let anchor = PendingAnchor {
        txid: signed.txid,
        kind: AnchorKind::SupplyCommit(SupplyCommitAnchor {
            group_key: *group_key,
            commitment,
            events: staged,
        }),
    };
    let stored = crate::anchor_codec::encode_pending_anchor(&anchor);
    node.pending_anchors
        .lock()
        .expect("pending anchors lock")
        .push(anchor);
    node.pending_anchor_store
        .lock()
        .expect("pending anchor store lock")
        .upsert_anchor(&stored)
        .map_err(TapNodeError::Storage)?;

    let mut txid_display = signed.txid;
    txid_display.reverse();
    node.event_bus.emit(TapEvent::SupplyCommitmentBroadcast {
        group_key: *group_key,
        txid: txid_display,
    });

    Ok(Some(txid_display))
}

/// Runs one periodic supply commitment sweep: commits every group that
/// has staged updates and no commitment already in flight. Returns the
/// number of commitment transactions broadcast.
pub(crate) fn sweep_supply_commits<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<usize, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let groups = node
        .supply_staging_store
        .lock()
        .expect("supply staging store lock")
        .groups_with_staged_updates()
        .map_err(TapNodeError::Storage)?;

    let mut committed = 0;
    for group_key in groups {
        if supply_commit_in_flight(node, &group_key) {
            // Dangling updates: they stay staged for the next
            // commitment once the in-flight one confirms.
            continue;
        }
        if commit_supply(node, &group_key)?.is_some() {
            committed += 1;
        }
    }
    Ok(committed)
}

/// Finishes a confirmed supply commitment: attaches the commitment
/// block, verifies the commitment with the node's own supply verifier
/// (fails loudly on rejection, keeping the anchor pending), then
/// atomically-in-effect applies the tree updates, persists the
/// commitment, marks spent pre-commitments, and consumes the frozen
/// staged events (Go's `ApplyStateTransition`). All steps are
/// idempotent, so a replay after a partial failure is harmless.
pub(crate) fn finish_supply_commit_confirmation<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    anchor: SupplyCommitAnchor,
    txid_internal: [u8; 32],
    conf: &TxConfirmation,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let group_key = anchor.group_key;
    let mut commitment = anchor.commitment.clone();

    // Build the commitment block from the confirmation (Go's ConfEvent
    // handling: header, height, tx index, merkle proof;
    // transitions.go:1004-1023).
    if conf.block_header == [0u8; 80] {
        return Err(supply_err(
            "confirmation lacks the block header needed for the \
             commitment block",
        ));
    }
    let header = BlockHeader(conf.block_header);
    let block_tx_hashes = if conf.block_tx_hashes.is_empty() {
        vec![txid_internal]
    } else {
        conf.block_tx_hashes.clone()
    };
    let merkle_proof = tap_onchain::proof::build_tx_merkle_proof(
        &block_tx_hashes,
        conf.tx_index as usize,
    )
    .ok_or_else(|| {
        supply_err("unable to build commitment tx merkle proof")
    })?;

    commitment.commitment_block = Some(CommitmentBlock {
        height: conf.block_height,
        hash: header.block_hash(),
        tx_index: conf.tx_index,
        block_header: Some(header),
        merkle_proof: Some(merkle_proof),
        // Go persists 0 for chain fees as well (supply_commit.go).
        chain_fees: 0,
    });

    // The supply leaves are exactly the frozen staged events.
    let mut leaves = SupplyLeaves::default();
    for event in &anchor.events {
        match event {
            SupplyUpdateEvent::Mint(e) => {
                leaves.issuance_leaf_entries.push(e.clone())
            }
            SupplyUpdateEvent::Burn(e) => {
                leaves.burn_leaf_entries.push(e.clone())
            }
            SupplyUpdateEvent::Ignore(e) => {
                leaves.ignore_leaf_entries.push(e.clone())
            }
        }
    }

    // The oracle: our own supply verifier must accept the commitment
    // (initial or incremental path) BEFORE anything is persisted. The
    // tree view still reflects the pre-transition state at this point,
    // which is exactly what the incremental path verifies against.
    verify_authored_commitment(node, &group_key, &commitment, &leaves)?;

    // Persist. The stores are separate objects, so this is sequential
    // rather than one transaction; every step is idempotent and the
    // anchor stays pending (and is replayed) if any step fails.
    node.supply_tree_store
        .lock()
        .expect("supply tree store lock")
        .apply_supply_updates(&group_key, &anchor.events)
        .map_err(TapNodeError::Storage)?;

    {
        let mut commits = node
            .supply_commit_store
            .lock()
            .expect("supply commit store lock");
        commits
            .insert_commitment(&group_key, &commitment)
            .map_err(TapNodeError::Storage)?;

        let commit_point = commitment.commit_point();
        let unspent = commits
            .unspent_pre_commits(&group_key)
            .map_err(TapNodeError::Storage)?;
        for pre_commit in unspent {
            let out_point = pre_commit.out_point();
            if tx_spends_prev_out(&commitment.txn, &out_point) {
                commits
                    .mark_pre_commit_spent(&out_point, &commit_point)
                    .map_err(TapNodeError::Storage)?;
            }
        }
    }

    node.supply_staging_store
        .lock()
        .expect("supply staging store lock")
        .remove_staged_updates(&group_key, &anchor.events)
        .map_err(TapNodeError::Storage)?;

    let mut txid_display = txid_internal;
    txid_display.reverse();
    node.event_bus.emit(TapEvent::SupplyCommitmentConfirmed {
        group_key,
        txid: txid_display,
        block_height: conf.block_height,
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Supply update producers: ignores and burns
// ---------------------------------------------------------------------------

/// Signs and stages an ignore supply update for the given asset
/// previous ID. See [`TapNode::ignore_asset_outpoint`].
pub(crate) fn ignore_asset_outpoint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    prev_id: PrevId,
    amount: u64,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let (group_key, delegation_key, delegation_desc) = {
        let staging = node
            .supply_staging_store
            .lock()
            .expect("supply staging store lock");
        let group_key = staging
            .asset_group(&prev_id.id)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| {
                supply_err(
                    "unknown asset group: the asset was not minted with \
                     universe supply commitments by this node",
                )
            })?;
        let delegation_key = staging
            .delegation_key(&group_key)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| {
                supply_err("no delegation key recorded for asset group")
            })?;
        let delegation_desc = staging
            .key_descriptor(&delegation_key)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| {
                supply_err(
                    "the node does not custody the group's delegation \
                     key; sign the ignore tuple externally and stage it \
                     via stage_supply_ignore",
                )
            })?;
        (group_key, delegation_key, delegation_desc)
    };

    let block_height = node.chain.current_height()?;
    let tuple = IgnoreTuple {
        prev_id,
        amount,
        block_height,
    };

    // Sign with the RAW delegation key (lnd SignMessageSchnorr
    // semantics): verifiers check the signature against the untweaked
    // delegation public key.
    let digest = tuple.signing_digest();
    let sig_bytes =
        node.keys.sign_message_schnorr(&delegation_desc, &digest)?;
    let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        supply_err("expected a 64-byte Schnorr signature")
    })?;

    let signed_tuple = SignedIgnoreTuple {
        tuple,
        sig: IgnoreSig(sig),
    };

    // Sanity: the signature must verify against the delegation key
    // before it is staged (a bad signature would only surface at
    // commit verification time otherwise).
    signed_tuple
        .verify_sig(&delegation_key)
        .map_err(|e| supply_err(format!("ignore signature invalid: {}", e)))?;

    stage_ignore_for_group(node, &group_key, signed_tuple)
}

/// Verifies and stages an externally signed ignore tuple. See
/// [`TapNode::stage_supply_ignore`].
pub(crate) fn stage_supply_ignore<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    signed_tuple: SignedIgnoreTuple,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let (group_key, delegation_key) = {
        let staging = node
            .supply_staging_store
            .lock()
            .expect("supply staging store lock");
        let group_key = staging
            .asset_group(&signed_tuple.tuple.prev_id.id)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| supply_err("unknown asset group"))?;
        let delegation_key = staging
            .delegation_key(&group_key)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| {
                supply_err("no delegation key recorded for asset group")
            })?;
        (group_key, delegation_key)
    };

    signed_tuple
        .verify_sig(&delegation_key)
        .map_err(|e| supply_err(format!("ignore signature invalid: {}", e)))?;

    stage_ignore_for_group(node, &group_key, signed_tuple)
}

fn stage_ignore_for_group<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    group_key: &SerializedKey,
    signed_tuple: SignedIgnoreTuple,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    node.supply_staging_store
        .lock()
        .expect("supply staging store lock")
        .stage_update(
            group_key,
            &SupplyUpdateEvent::Ignore(NewIgnoreEvent { signed_tuple }),
        )
        .map_err(TapNodeError::Storage)
}

/// Decodes and stages a burn supply update. See
/// [`TapNode::stage_supply_burn`].
pub(crate) fn stage_supply_burn<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    raw_burn_proof: &[u8],
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let event = NewBurnEvent::decode(raw_burn_proof)
        .map_err(|e| supply_err(e.to_string()))?;

    // Resolve the asset group from the burn proof itself.
    let proof = decode_proof(raw_burn_proof)
        .map_err(|e| supply_err(format!("burn proof: {}", e)))?;
    let group_key = proof
        .asset
        .group_key
        .as_ref()
        .map(|gk| gk.group_pub_key)
        .ok_or_else(|| {
            supply_err("burn proof asset has no group key")
        })?;

    node.supply_staging_store
        .lock()
        .expect("supply staging store lock")
        .stage_update(&group_key, &SupplyUpdateEvent::Burn(event))
        .map_err(TapNodeError::Storage)
}

// ---------------------------------------------------------------------------
// Verification plumbing (the SupplyVerifier oracle)
// ---------------------------------------------------------------------------

/// A [`HeaderVerifier`] that checks a header's hash against the chain
/// backend's block hash at the claimed height.
struct BridgeHeaders<C>(Arc<C>);

impl<C: ChainBridge> HeaderVerifier for BridgeHeaders<C> {
    fn verify_header(
        &self,
        header: &BlockHeader,
        height: u32,
    ) -> Result<(), ProofError> {
        let expected = self.0.get_block_hash(height).map_err(|e| {
            ProofError::VerificationFailed(format!(
                "block hash lookup failed: {}",
                e
            ))
        })?;
        if expected != header.block_hash() {
            return Err(ProofError::VerificationFailed(format!(
                "block header hash does not match chain block hash at \
                 height {}",
                height
            )));
        }
        Ok(())
    }
}

/// A [`GroupVerifier`] that accepts exactly the asset group being
/// verified (compared in x-only form). Leaf proofs of a supply
/// commitment must all belong to that group; genesis mint leaves carry
/// a group key reveal and are verified structurally without consulting
/// this verifier.
struct SingleGroupVerifier(SerializedKey);

impl GroupVerifier for SingleGroupVerifier {
    fn verify_group_key(
        &self,
        group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        if group_key.schnorr_bytes() != self.0.schnorr_bytes() {
            return Err(ProofError::VerificationFailed(
                "asset group key is not the committed group".into(),
            ));
        }
        Ok(())
    }
}

/// [`AssetLookup`] over data snapshotted from the staging store.
struct SnapshotLookup {
    delegation_key: SerializedKey,
    asset_groups: HashMap<[u8; 32], SerializedKey>,
}

impl AssetLookup for SnapshotLookup {
    fn delegation_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<SerializedKey, SupplyError> {
        Ok(self.delegation_key)
    }

    fn group_key_for_asset(
        &self,
        asset_id: &AssetId,
    ) -> Result<SerializedKey, SupplyError> {
        self.asset_groups
            .get(asset_id.as_bytes())
            .copied()
            .ok_or_else(|| {
                SupplyError::Lookup(format!(
                    "unknown asset group for asset {:?}",
                    asset_id
                ))
            })
    }
}

/// [`SupplyCommitView`] over commitments snapshotted from the commit
/// store (the verifier only looks up the new commitment's outpoint and
/// the spent commitment's outpoint).
struct SnapshotCommitView {
    starting: Option<RootCommitment>,
    by_outpoint: HashMap<([u8; 32], u32), RootCommitment>,
}

impl SupplyCommitView for SnapshotCommitView {
    fn fetch_starting_commitment(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, SupplyError> {
        Ok(self.starting.clone())
    }

    fn fetch_commitment_by_outpoint(
        &self,
        _group_key: &SerializedKey,
        outpoint: &tap_primitives::asset::OutPoint,
    ) -> Result<Option<RootCommitment>, SupplyError> {
        Ok(self
            .by_outpoint
            .get(&(outpoint.txid, outpoint.vout))
            .cloned())
    }
}

/// [`SupplyTreeView`] over the (pre-transition) stored supply trees.
struct SnapshotTreeView {
    root_tree: SupplyTree,
    sub_trees: SupplyTrees,
}

impl SupplyTreeView for SnapshotTreeView {
    fn fetch_supply_trees(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(SupplyTree, SupplyTrees), SupplyError> {
        Ok((self.root_tree.clone(), self.sub_trees.clone()))
    }
}

/// Verifies an authored commitment with the existing [`SupplyVerifier`]
/// before anything is persisted: chain anchor, per-leaf verification
/// (full proof verification for mint/burn leaves, delegation-key
/// signatures for ignores), pre-commitment spend completeness, and the
/// initial/incremental supply root reconstruction.
fn verify_authored_commitment<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    group_key: &SerializedKey,
    commitment: &RootCommitment,
    leaves: &SupplyLeaves,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Snapshot the asset lookup data.
    let lookup = {
        let staging = node
            .supply_staging_store
            .lock()
            .expect("supply staging store lock");
        let delegation_key = staging
            .delegation_key(group_key)
            .map_err(TapNodeError::Storage)?
            .ok_or_else(|| {
                supply_err("no delegation key recorded for asset group")
            })?;
        let mut asset_groups = HashMap::new();
        for entry in &leaves.ignore_leaf_entries {
            let asset_id = entry.signed_tuple.tuple.prev_id.id;
            if let Some(group) = staging
                .asset_group(&asset_id)
                .map_err(TapNodeError::Storage)?
            {
                asset_groups.insert(*asset_id.as_bytes(), group);
            }
        }
        SnapshotLookup {
            delegation_key,
            asset_groups,
        }
    };

    // Snapshot the commitment view and the unspent pre-commitments.
    let (commit_view, pre_commits) = {
        let commits = node
            .supply_commit_store
            .lock()
            .expect("supply commit store lock");
        let starting = commits
            .starting_commitment(group_key)
            .map_err(TapNodeError::Storage)?;

        let mut by_outpoint = HashMap::new();
        let commit_point = commitment.commit_point();
        if let Some(existing) = commits
            .commitment_by_outpoint(group_key, &commit_point)
            .map_err(TapNodeError::Storage)?
        {
            by_outpoint
                .insert((commit_point.txid, commit_point.vout), existing);
        }
        if let Some(spent) = &commitment.spent_commitment {
            if let Some(prev) = commits
                .commitment_by_outpoint(group_key, spent)
                .map_err(TapNodeError::Storage)?
            {
                by_outpoint.insert((spent.txid, spent.vout), prev);
            }
        }

        (
            SnapshotCommitView {
                starting,
                by_outpoint,
            },
            commits
                .unspent_pre_commits(group_key)
                .map_err(TapNodeError::Storage)?,
        )
    };

    // Snapshot the (pre-transition) supply trees.
    let tree_view = {
        let trees = node
            .supply_tree_store
            .lock()
            .expect("supply tree store lock");
        SnapshotTreeView {
            root_tree: trees
                .fetch_root_supply_tree(group_key)
                .map_err(TapNodeError::Storage)?,
            sub_trees: trees
                .fetch_sub_trees(group_key)
                .map_err(TapNodeError::Storage)?,
        }
    };

    let height = node.chain.current_height()?;
    let ctx = VerifierCtx::new(
        BridgeHeaders(Arc::clone(&node.chain)),
        DefaultMerkleVerifier,
        SingleGroupVerifier(*group_key),
        FixedHeightChainLookup(height),
    );

    let verifier = SupplyVerifier {
        ctx: &ctx,
        proof_opts: ProofVerificationOptions::default(),
        asset_lookup: &lookup,
        commit_view: &commit_view,
        tree_view: &tree_view,
    };

    verifier
        .verify_commit(group_key, commitment, leaves, &pre_commits)
        .map_err(|e| {
            supply_err(format!(
                "authored supply commitment failed self-verification: {}",
                e
            ))
        })
}
