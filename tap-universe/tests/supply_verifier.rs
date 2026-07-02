// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Supply commitment verifier tests, mirroring the deterministic parts
//! of Go's `universe/supplyverifier` tests (verifier_methods_test.go):
//! initial commit ok, incremental commit ok, bad ignore signature
//! fails, unspent pre-commitment fails, and tampered supply root fails.

use std::collections::HashMap;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash as BtcHash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint as BtcOutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};

use tap_primitives::asset::{AssetId, OutPoint, PrevId, SerializedKey};
use tap_primitives::crypto::parse_pub_key;
use tap_primitives::mssmt::NodeHash;
use tap_primitives::proof::{
    BlockHeader, DefaultMerkleVerifier, FixedHeightChainLookup,
    ProofVerificationOptions, TrustAllGroups, TrustAllHeaders, TxMerkleProof,
    VerifierCtx,
};

use tap_universe::ignore::IgnoreTuple;
use tap_universe::supply::{
    apply_tree_updates, new_supply_tree, pre_commit_tx_out,
    root_commit_tx_out, root_supply_tree_from, AssetLookup, CommitmentBlock,
    NewIgnoreEvent, PreCommitment, RootCommitment, SupplyCommitView,
    SupplyError, SupplyLeaves, SupplyTree, SupplyTreeView, SupplyTrees,
    SupplyVerifier,
};

type TestCtx = VerifierCtx<
    TrustAllHeaders,
    DefaultMerkleVerifier,
    TrustAllGroups,
    FixedHeightChainLookup,
>;

fn test_ctx() -> TestCtx {
    VerifierCtx::new(
        TrustAllHeaders,
        DefaultMerkleVerifier,
        TrustAllGroups,
        FixedHeightChainLookup(1_000_000),
    )
}

/// The delegation secret key used by all tests.
const DELEGATION_SK: [u8; 32] = {
    let mut sk = [0u8; 32];
    sk[31] = 0x21;
    sk
};

fn pub_key_of(sk: &[u8; 32]) -> SerializedKey {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(sk).expect("valid key");
    SerializedKey(PublicKey::from_secret_key(&secp, &secret).serialize())
}

fn delegation_key() -> SerializedKey {
    pub_key_of(&DELEGATION_SK)
}

fn group_key() -> SerializedKey {
    let mut sk = [0u8; 32];
    sk[31] = 0x55;
    pub_key_of(&sk)
}

fn internal_key() -> SerializedKey {
    let mut sk = [0u8; 32];
    sk[31] = 0x42;
    pub_key_of(&sk)
}

fn asset_id() -> AssetId {
    AssetId([0xAA; 32])
}

// ---------------------------------------------------------------------
// Mock environment
// ---------------------------------------------------------------------

struct MockLookup {
    delegation_key: SerializedKey,
    group_keys: HashMap<[u8; 32], SerializedKey>,
}

impl AssetLookup for MockLookup {
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
        self.group_keys
            .get(asset_id.as_bytes())
            .copied()
            .ok_or_else(|| SupplyError::Lookup("unknown asset group".into()))
    }
}

#[derive(Default)]
struct MockCommitView {
    starting: Option<RootCommitment>,
    by_outpoint: HashMap<([u8; 32], u32), RootCommitment>,
}

impl MockCommitView {
    fn insert(&mut self, commitment: RootCommitment) {
        let op = commitment.commit_point();
        if self.starting.is_none() {
            self.starting = Some(commitment.clone());
        }
        self.by_outpoint.insert((op.txid, op.vout), commitment);
    }
}

impl SupplyCommitView for MockCommitView {
    fn fetch_starting_commitment(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, SupplyError> {
        Ok(self.starting.clone())
    }

    fn fetch_commitment_by_outpoint(
        &self,
        _group_key: &SerializedKey,
        outpoint: &OutPoint,
    ) -> Result<Option<RootCommitment>, SupplyError> {
        Ok(self
            .by_outpoint
            .get(&(outpoint.txid, outpoint.vout))
            .cloned())
    }
}

struct MockTreeView {
    root_tree: SupplyTree,
    sub_trees: SupplyTrees,
}

impl SupplyTreeView for MockTreeView {
    fn fetch_supply_trees(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(SupplyTree, SupplyTrees), SupplyError> {
        Ok((self.root_tree.clone(), self.sub_trees.clone()))
    }
}

// ---------------------------------------------------------------------
// Transaction / commitment construction helpers
// ---------------------------------------------------------------------

fn to_btc_outpoint(op: &OutPoint) -> BtcOutPoint {
    BtcOutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_byte_array(op.txid)),
        vout: op.vout,
    }
}

fn tx_spending(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|op| TxIn {
                previous_output: to_btc_outpoint(op),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

/// Builds a minting transaction containing a pre-commitment output at
/// index 0.
fn pre_commitment(block_height: u32, input_seed: u8) -> PreCommitment {
    let (value, script) = pre_commit_tx_out(&delegation_key()).expect("txout");
    let minting_txn = tx_spending(
        &[OutPoint {
            txid: [input_seed; 32],
            vout: 0,
        }],
        vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    );
    PreCommitment {
        block_height,
        minting_txn,
        out_idx: 0,
        internal_key: delegation_key(),
        group_pub_key: group_key(),
    }
}

/// Builds a signed ignore leaf for the test asset group.
fn ignore_leaf(vout: u32, amount: u64, block_height: u32) -> NewIgnoreEvent {
    let tuple = IgnoreTuple {
        prev_id: PrevId {
            out_point: OutPoint {
                txid: [0x77; 32],
                vout,
            },
            id: asset_id(),
            script_key: group_key(),
        },
        amount,
        block_height,
    };
    NewIgnoreEvent {
        signed_tuple: tuple.sign(&DELEGATION_SK).expect("sign"),
    }
}

/// Computes the supply root over the given leaves applied on top of the
/// given base trees.
fn supply_root_for(
    base_root: &SupplyTree,
    base_subtrees: &SupplyTrees,
    leaves: &SupplyLeaves,
) -> (NodeHash, u64) {
    let sub_trees =
        apply_tree_updates(base_subtrees, &leaves.all_updates()).unwrap();
    let root_tree = root_supply_tree_from(base_root, &sub_trees).unwrap();
    let root = root_tree.root().unwrap();
    (root.node_hash(), root.node_sum())
}

/// Builds a root commitment anchored in a single-transaction block: the
/// block merkle root is the commitment txid, so an empty merkle proof
/// verifies.
fn root_commitment(
    inputs: &[OutPoint],
    supply_root_hash: NodeHash,
    supply_root_sum: u64,
    block_height: u32,
    spent_commitment: Option<OutPoint>,
) -> RootCommitment {
    let (value, script, output_key) =
        root_commit_tx_out(&internal_key(), None, &supply_root_hash.0)
            .expect("commit txout");

    let txn = tx_spending(
        inputs,
        vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    );

    let txid: [u8; 32] = *AsRef::<[u8; 32]>::as_ref(&txn.compute_txid());
    let mut header_bytes = [0u8; 80];
    header_bytes[36..68].copy_from_slice(&txid);
    let header = BlockHeader(header_bytes);

    RootCommitment {
        txn,
        tx_out_idx: 0,
        internal_key: internal_key(),
        output_key: Some(output_key),
        supply_root_hash,
        supply_root_sum,
        commitment_block: Some(CommitmentBlock {
            height: block_height,
            hash: header.block_hash(),
            tx_index: 0,
            block_header: Some(header),
            merkle_proof: Some(TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            }),
            chain_fees: 0,
        }),
        spent_commitment,
    }
}

fn mock_lookup() -> MockLookup {
    let mut group_keys = HashMap::new();
    group_keys.insert(*asset_id().as_bytes(), group_key());
    MockLookup {
        delegation_key: delegation_key(),
        group_keys,
    }
}

fn empty_tree_view() -> MockTreeView {
    MockTreeView {
        root_tree: new_supply_tree(),
        sub_trees: SupplyTrees::new(),
    }
}

fn verifier<'a>(
    ctx: &'a TestCtx,
    lookup: &'a MockLookup,
    commit_view: &'a MockCommitView,
    tree_view: &'a MockTreeView,
) -> SupplyVerifier<
    'a,
    TrustAllHeaders,
    DefaultMerkleVerifier,
    TrustAllGroups,
    FixedHeightChainLookup,
    tap_primitives::proof::NoIgnoreChecker,
    MockLookup,
    MockCommitView,
    MockTreeView,
> {
    SupplyVerifier {
        ctx,
        proof_opts: ProofVerificationOptions::default(),
        asset_lookup: lookup,
        commit_view,
        tree_view,
    }
}

/// Initial commitment with a valid ignore leaf and a spent
/// pre-commitment verifies.
#[test]
fn test_initial_commit_ok() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let pre_commit = pre_commitment(50, 0x01);
    let commitment = root_commitment(
        &[pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    v.verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect("initial commit verifies");
}

/// A tampered supply root fails: the chain anchor still matches (the
/// output is re-derived from the tampered root), but the reconstructed
/// tree root does not.
#[test]
fn test_tampered_supply_root_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    // Tamper with the root hash and rebuild the commitment output for
    // it so that the chain anchor check alone would pass.
    let mut tampered = root_hash;
    tampered.0[0] ^= 0x01;

    let pre_commit = pre_commitment(50, 0x01);
    let commitment = root_commitment(
        &[pre_commit.out_point()],
        tampered,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect_err("tampered root must fail");
    assert!(
        err.to_string().contains("does not match commitment supply root"),
        "unexpected error: {}",
        err
    );
}

/// A commitment whose output does not commit to the claimed supply
/// root fails the chain anchor check.
#[test]
fn test_output_root_mismatch_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let pre_commit = pre_commitment(50, 0x01);
    let mut commitment = root_commitment(
        &[pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );
    // Claim a different root than the one committed in the output.
    commitment.supply_root_hash.0[0] ^= 0x01;

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect_err("output mismatch must fail");
    assert!(
        err.to_string().contains("pk script"),
        "unexpected error: {}",
        err
    );
}

/// A bad ignore tuple signature fails leaf verification.
#[test]
fn test_bad_ignore_sig_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let mut leaf = ignore_leaf(0, 500, 100);
    // Corrupt the signature.
    leaf.signed_tuple.sig.0[10] ^= 0xFF;

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![leaf],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let pre_commit = pre_commitment(50, 0x01);
    let commitment = root_commitment(
        &[pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect_err("bad signature must fail");
    assert!(
        err.to_string().contains("signed ignore tuple"),
        "unexpected error: {}",
        err
    );
}

/// An eligible pre-commitment that is not spent by the commitment
/// transaction fails verification.
#[test]
fn test_unspent_precommit_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let spent_pre_commit = pre_commitment(50, 0x01);
    let unspent_pre_commit = pre_commitment(60, 0x02);

    // The commitment only spends the first pre-commitment.
    let commitment = root_commitment(
        &[spent_pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(
            &group_key(),
            &commitment,
            &leaves,
            &[spent_pre_commit, unspent_pre_commit],
        )
        .expect_err("unspent pre-commitment must fail");
    assert!(
        err.to_string()
            .contains("does not spend all known pre-commitments"),
        "unexpected error: {}",
        err
    );
}

/// The initial commitment must spend at least one pre-commitment.
#[test]
fn test_initial_commit_without_precommits_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let commitment = root_commitment(
        &[OutPoint {
            txid: [0x09; 32],
            vout: 0,
        }],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[])
        .expect_err("initial commit without pre-commitments must fail");
    assert!(
        err.to_string().contains("no unspent supply pre-commitment"),
        "unexpected error: {}",
        err
    );
}

/// An incremental commitment building on a verified initial commitment
/// verifies, and fails if the previous commitment is unknown or not
/// spent.
#[test]
fn test_incremental_commit() {
    let ctx = test_ctx();
    let lookup = mock_lookup();

    // Initial commitment state.
    let initial_leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (initial_root, initial_sum) = supply_root_for(
        &new_supply_tree(),
        &SupplyTrees::new(),
        &initial_leaves,
    );

    let pre_commit = pre_commitment(50, 0x01);
    let initial_commitment = root_commitment(
        &[pre_commit.out_point()],
        initial_root,
        initial_sum,
        100,
        None,
    );

    // The local store contains the initial commitment and its trees.
    let mut commit_view = MockCommitView::default();
    commit_view.insert(initial_commitment.clone());

    let initial_subtrees = apply_tree_updates(
        &SupplyTrees::new(),
        &initial_leaves.all_updates(),
    )
    .unwrap();
    let initial_root_tree =
        root_supply_tree_from(&new_supply_tree(), &initial_subtrees).unwrap();
    let tree_view = MockTreeView {
        root_tree: initial_root_tree.clone(),
        sub_trees: initial_subtrees.clone(),
    };

    // New incremental leaves on top of the initial state.
    let new_leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(1, 250, 200)],
        ..Default::default()
    };
    let (new_root, new_sum) =
        supply_root_for(&initial_root_tree, &initial_subtrees, &new_leaves);

    let incremental = root_commitment(
        &[initial_commitment.commit_point()],
        new_root,
        new_sum,
        200,
        Some(initial_commitment.commit_point()),
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    v.verify_commit(&group_key(), &incremental, &new_leaves, &[])
        .expect("incremental commit verifies");

    // Unknown previous commitment fails.
    let mut unknown_prev = incremental.clone();
    unknown_prev.spent_commitment = Some(OutPoint {
        txid: [0x0F; 32],
        vout: 0,
    });
    // Rebuild the tx so it spends the bogus outpoint (chain anchor
    // requires the spend).
    let (value, script, _) =
        root_commit_tx_out(&internal_key(), None, &new_root.0).unwrap();
    unknown_prev.txn = tx_spending(
        &[OutPoint {
            txid: [0x0F; 32],
            vout: 0,
        }],
        vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    );
    let txid: [u8; 32] =
        *AsRef::<[u8; 32]>::as_ref(&unknown_prev.txn.compute_txid());
    let mut header_bytes = [0u8; 80];
    header_bytes[36..68].copy_from_slice(&txid);
    let header = BlockHeader(header_bytes);
    if let Some(block) = &mut unknown_prev.commitment_block {
        block.hash = header.block_hash();
        block.block_header = Some(header);
    }

    let err = v
        .verify_commit(&group_key(), &unknown_prev, &new_leaves, &[])
        .expect_err("unknown previous commitment must fail");
    assert!(
        err.to_string().contains("previous supply commitment not found"),
        "unexpected error: {}",
        err
    );
}

/// The ignore leaf's asset must belong to the expected asset group.
#[test]
fn test_ignore_leaf_wrong_group_fails() {
    let ctx = test_ctx();
    let mut lookup = mock_lookup();
    // Map the asset to a different group.
    let mut other_sk = [0u8; 32];
    other_sk[31] = 0x66;
    lookup
        .group_keys
        .insert(*asset_id().as_bytes(), pub_key_of(&other_sk));

    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 100)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let pre_commit = pre_commitment(50, 0x01);
    let commitment = root_commitment(
        &[pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect_err("wrong group must fail");
    assert!(
        err.to_string()
            .contains("does not match expected asset group key"),
        "unexpected error: {}",
        err
    );
}

/// A zero block height on a leaf fails validation.
#[test]
fn test_zero_block_height_leaf_fails() {
    let ctx = test_ctx();
    let lookup = mock_lookup();
    let commit_view = MockCommitView::default();
    let tree_view = empty_tree_view();

    let leaves = SupplyLeaves {
        ignore_leaf_entries: vec![ignore_leaf(0, 500, 0)],
        ..Default::default()
    };
    let (root_hash, root_sum) =
        supply_root_for(&new_supply_tree(), &SupplyTrees::new(), &leaves);

    let pre_commit = pre_commitment(50, 0x01);
    let commitment = root_commitment(
        &[pre_commit.out_point()],
        root_hash,
        root_sum,
        100,
        None,
    );

    let v = verifier(&ctx, &lookup, &commit_view, &tree_view);
    let err = v
        .verify_commit(&group_key(), &commitment, &leaves, &[pre_commit])
        .expect_err("zero block height must fail");
    assert!(
        err.to_string().contains("zero block height"),
        "unexpected error: {}",
        err
    );
}

/// Sanity check: the delegation key parses as a valid public key and
/// the pre-commitment output derivation is stable.
#[test]
fn test_pre_commit_tx_out_shape() {
    let key = delegation_key();
    parse_pub_key(&key).expect("valid delegation key");
    let (value, script) = pre_commit_tx_out(&key).expect("txout");
    assert_eq!(value, 1000);
    assert_eq!(script.len(), 34);
    assert_eq!(script[0], 0x51);
    assert_eq!(script[1], 0x20);
}
