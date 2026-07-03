// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! End-to-end supply commitment authoring over the functional fakes:
//! mint with universe commitments -> pre-commitment output ->
//! confirmation stages the mint event and persists the pre-commitment
//! -> initial supply commitment (spends the pre-commitment, verified
//! by the node's own SupplyVerifier on confirmation) -> ignore event
//! -> incremental commitment (spends the previous commitment output).
//! Plus: no-op commit without staged events, and restart durability of
//! the staged queue and the pending supply anchor over SQLite.

mod common;

use common::*;

use tap_node::*;
use tap_onchain::mint::Seedling;
use tap_primitives::asset::{OutPoint, PrevId};
use tap_primitives::proof::MetaReveal;
use tap_universe::supply::{
    calc_total_outstanding_supply, pre_commit_tx_out, SupplySubTree,
    SupplyUpdateEvent,
};

/// Queues a universe-commitments seedling; the node derives the
/// delegation key (FakeKeys index 0 when queued first) and injects it
/// into the metadata.
fn queue_supply_seedling(node: &SharedTestNode, name: &str, amount: u64) {
    let mut meta = MetaReveal::new_opaque(b"supply-flow-meta".to_vec());
    meta.universe_commitments = true;
    let mut seedling = Seedling::new_normal(name.into(), amount);
    seedling.meta = Some(meta);
    node.queue_mint(seedling).expect("queue");
}

fn spends(tx: &bitcoin::Transaction, outpoint: &OutPoint) -> bool {
    tx.input.iter().any(|txin| {
        let txid: &[u8; 32] = txin.previous_output.txid.as_ref();
        *txid == outpoint.txid && txin.previous_output.vout == outpoint.vout
    })
}

#[test]
fn test_supply_commitment_end_to_end() {
    let harness = default_harness();
    let node = &harness.node;

    // -- Mint with universe commitments. --
    queue_supply_seedling(node, "supply-token", 1_000);

    // The delegation key is the first key derived (queue_mint injects
    // it before the planter derives the batch key).
    let delegation_key = FakeKeys::pub_key_for(0);

    let result = node.finalize_mint().expect("finalize");
    assert_eq!(result.assets.len(), 1);
    let minted = &result.assets[0];
    let group_key = minted.group_key.expect("asset is grouped");

    // The genesis anchor transaction has the pre-commitment output:
    // 1000 sats to the BIP-86 tweak of the delegation key.
    let (pre_value, pre_script) =
        pre_commit_tx_out(&delegation_key).expect("pre-commit out");
    let anchor_tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&result.signed_tx).expect("tx");
    let pre_commit_vout = anchor_tx
        .output
        .iter()
        .position(|out| {
            out.value.to_sat() == pre_value
                && out.script_pubkey.as_bytes() == pre_script.as_slice()
        })
        .expect("genesis anchor has the pre-commitment output")
        as u32;

    // -- Confirm the mint (fully verifiable single-tx block). --
    harness.chain.confirm_tx_valid(&result.signed_tx, 812_000);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    // Confirmation staged the mint supply update...
    let staged = node.staged_supply_updates(&group_key).expect("staged");
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].sub_tree_type(), SupplySubTree::Mint);
    match &staged[0] {
        SupplyUpdateEvent::Mint(event) => {
            assert_eq!(event.amount, 1_000);
            assert_eq!(event.block_height, 812_000);
            assert_eq!(event.leaf_key.asset_id, minted.asset_id);
        }
        other => panic!("expected mint event, got {:?}", other),
    }

    // ... and persisted the pre-commitment output.
    let pre_commits = node
        .unspent_supply_pre_commits(&group_key)
        .expect("pre-commits");
    assert_eq!(pre_commits.len(), 1);
    assert_eq!(pre_commits[0].out_idx, pre_commit_vout);
    assert_eq!(pre_commits[0].internal_key, delegation_key);
    assert_eq!(pre_commits[0].block_height, 812_000);
    let pre_commit_outpoint = pre_commits[0].out_point();

    // -- Initial supply commitment. --
    let commit_txid = node
        .commit_supply(&group_key)
        .expect("commit")
        .expect("staged events produce a commitment");

    // The broadcast commitment transaction spends the pre-commitment.
    let commit_tx_bytes = harness.chain.last_broadcast().expect("broadcast");
    let commit_tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&commit_tx_bytes).expect("tx");
    assert!(spends(&commit_tx, &pre_commit_outpoint));

    // A second commit while one is in flight is rejected (the staged
    // queue was frozen into the pending commitment).
    let err = node.commit_supply(&group_key).expect_err("in flight");
    assert!(err.to_string().contains("already awaiting confirmation"));

    // Nothing persisted before confirmation.
    assert!(node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .is_none());

    // -- Fail loudly: a confirmation whose block data does not verify
    // (zero merkle root, unregistered block hash) is rejected by the
    // node's own supply verifier; nothing is persisted and the anchor
    // stays pending for a retry. --
    harness.chain.confirm_tx(&commit_tx_bytes, 812_100);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 1);
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(
        summary.errors[0].contains("failed self-verification"),
        "{:?}",
        summary.errors
    );
    assert!(node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .is_none());
    assert_eq!(
        node.staged_supply_updates(&group_key).expect("staged").len(),
        1,
        "staged events must not be consumed on a failed finish",
    );

    // -- Confirm the commitment; tick verifies and persists. --
    harness.chain.confirm_tx_valid(&commit_tx_bytes, 812_100);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    let initial = node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .expect("initial commitment persisted");
    assert_eq!(initial.supply_root_sum, 1_000);
    assert!(initial.spent_commitment.is_none());
    let block = initial.commitment_block.as_ref().expect("block");
    assert_eq!(block.height, 812_100);
    assert!(block.block_header.is_some());
    assert!(block.merkle_proof.is_some());

    // Staged events consumed, pre-commitment marked spent.
    assert!(node
        .staged_supply_updates(&group_key)
        .expect("staged")
        .is_empty());
    assert!(node
        .unspent_supply_pre_commits(&group_key)
        .expect("pre-commits")
        .is_empty());

    // -- No staged events: commit is a no-op. --
    assert!(node.commit_supply(&group_key).expect("commit").is_none());
    assert_eq!(
        harness.chain.last_broadcast().expect("broadcast"),
        commit_tx_bytes,
        "no-op commit must not broadcast",
    );

    // -- Stage an ignore event (signed with the delegation key). --
    let owned = &node.list_assets().expect("assets")[0];
    let prev_id = PrevId {
        out_point: owned.anchor_outpoint.clone(),
        id: owned.asset_id,
        script_key: owned.script_key,
    };
    node.ignore_asset_outpoint(prev_id.clone(), 250)
        .expect("ignore");
    let staged = node.staged_supply_updates(&group_key).expect("staged");
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].sub_tree_type(), SupplySubTree::Ignore);

    // -- Incremental commitment spends the previous commitment. --
    node.commit_supply(&group_key)
        .expect("commit")
        .expect("incremental commitment broadcast");
    let commit2_bytes = harness.chain.last_broadcast().expect("broadcast");
    let commit2_tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&commit2_bytes).expect("tx");
    assert!(spends(&commit2_tx, &initial.commit_point()));

    harness.chain.confirm_tx_valid(&commit2_bytes, 812_200);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    let incremental = node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .expect("incremental commitment persisted");
    assert_eq!(
        incremental.spent_commitment,
        Some(initial.commit_point()),
        "incremental commitment records the spent commitment",
    );
    // Root sum = mint sub-tree sum + ignore sub-tree sum.
    assert_eq!(incremental.supply_root_sum, 1_250);
    assert!(node
        .staged_supply_updates(&group_key)
        .expect("staged")
        .is_empty());

    // The persisted supply trees agree: outstanding = 1000 - 250.
    // (Verified indirectly through the incremental self-verification;
    // recompute here for good measure.)
    let events = harness
        .drain_events()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                TapEvent::SupplyCommitmentBroadcast { .. }
                    | TapEvent::SupplyCommitmentConfirmed { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 4, "{:?}", events);
    match &events[0] {
        TapEvent::SupplyCommitmentBroadcast { group_key: g, txid } => {
            assert_eq!(*g, group_key);
            assert_eq!(*txid, commit_txid);
        }
        other => panic!("unexpected event: {:?}", other),
    }
    match &events[1] {
        TapEvent::SupplyCommitmentConfirmed {
            group_key: g,
            block_height,
            ..
        } => {
            assert_eq!(*g, group_key);
            assert_eq!(*block_height, 812_100);
        }
        other => panic!("unexpected event: {:?}", other),
    }
}

/// A tampered commitment must be rejected by the node's own supply
/// verifier at confirmation time: staging an ignore whose asset group
/// is unknown fails up front, and an unsigned (badly signed) tuple is
/// rejected before staging.
#[test]
fn test_supply_ignore_staging_guards() {
    let harness = default_harness();
    let node = &harness.node;

    // Unknown asset: no group mapping exists yet.
    let prev_id = PrevId {
        out_point: OutPoint {
            txid: [0x99; 32],
            vout: 0,
        },
        id: tap_primitives::asset::AssetId([0x77; 32]),
        script_key: FakeKeys::pub_key_for(0),
    };
    let err = node
        .ignore_asset_outpoint(prev_id, 10)
        .expect_err("unknown group");
    assert!(err.to_string().contains("unknown asset group"));

    // Mint a supply-committed asset, then try to stage an ignore with
    // a bad signature.
    queue_supply_seedling(node, "guard-token", 100);
    let result = node.finalize_mint().expect("finalize");
    harness.chain.confirm_tx_valid(&result.signed_tx, 800_100);
    node.tick().expect("tick");

    let owned = &node.list_assets().expect("assets")[0];
    let tuple = tap_universe::ignore::IgnoreTuple {
        prev_id: PrevId {
            out_point: owned.anchor_outpoint.clone(),
            id: owned.asset_id,
            script_key: owned.script_key,
        },
        amount: 10,
        block_height: 800_100,
    };
    let bad = tap_universe::ignore::SignedIgnoreTuple {
        tuple,
        sig: tap_universe::ignore::IgnoreSig([0x01; 64]),
    };
    let err = node.stage_supply_ignore(bad).expect_err("bad signature");
    assert!(err.to_string().contains("ignore signature invalid"));

    // Only the mint event is staged.
    let group_key = result.assets[0].group_key.expect("grouped");
    let staged = node.staged_supply_updates(&group_key).expect("staged");
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].sub_tree_type(), SupplySubTree::Mint);

    // Sanity: total outstanding supply helper agrees with the staged
    // mint amount once applied.
    let trees = tap_universe::supply::apply_tree_updates(
        &tap_universe::supply::SupplyTrees::new(),
        &staged,
    )
    .expect("apply");
    assert_eq!(calc_total_outstanding_supply(&trees).expect("supply"), 100);
}

/// The periodic tick trigger commits staged updates when
/// `supply_commit_interval_secs` is enabled, and only then.
#[test]
fn test_supply_commit_tick_trigger() {
    let mut config = TapNodeConfig::default();
    config.supply_commit_interval_secs = 1;
    let harness = build_harness(config);
    let node = &harness.node;

    queue_supply_seedling(node, "tick-token", 500);
    let result = node.finalize_mint().expect("finalize");
    harness.chain.confirm_tx_valid(&result.signed_tx, 810_000);

    // First tick confirms the mint and stages the event; the supply
    // sweep in the same tick broadcasts the initial commitment.
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(summary.supply_commits, 1);

    let group_key = result.assets[0].group_key.expect("grouped");
    let commit_tx_bytes = harness.chain.last_broadcast().expect("broadcast");
    harness.chain.confirm_tx_valid(&commit_tx_bytes, 810_001);

    // Wait out the interval, then tick: the pending commitment
    // confirms; no new commitment is broadcast (nothing staged).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(summary.supply_commits, 0);

    let commitment = node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .expect("commitment persisted");
    assert_eq!(commitment.supply_root_sum, 500);
}

/// Restart durability over SQLite: staged supply updates and the
/// pending supply commitment anchor survive a node rebuild over the
/// same database, and the rebuilt node finishes the commitment.
#[test]
fn test_supply_restart_durability() {
    let tmp = TempDir::new("supply-restart");

    // -- Node 1: mint, confirm, broadcast the initial commitment. --
    let (group_key, commit_tx_bytes, mint_block) = {
        let harness = build_db_harness(&tmp.db_path());
        let node = &harness.node;

        queue_supply_seedling(node, "restart-token", 750);
        let result = node.finalize_mint().expect("finalize");
        let (_, mint_block_hash) =
            harness.chain.confirm_tx_valid(&result.signed_tx, 813_000);
        let summary = node.tick().expect("tick");
        assert_eq!(summary.confirmed_anchors, 1);
        assert!(summary.errors.is_empty(), "{:?}", summary.errors);

        let group_key = result.assets[0].group_key.expect("grouped");
        assert_eq!(
            node.staged_supply_updates(&group_key)
                .expect("staged")
                .len(),
            1
        );

        node.commit_supply(&group_key)
            .expect("commit")
            .expect("broadcast");
        let commit_tx_bytes =
            harness.chain.last_broadcast().expect("broadcast");

        // "Crash" here: the commitment is broadcast but unconfirmed.
        (group_key, commit_tx_bytes, mint_block_hash)
    };

    // -- Node 2 over the same database. --
    let harness = build_db_harness(&tmp.db_path());
    let node = &harness.node;

    // The staged mint event survived the restart.
    let staged = node.staged_supply_updates(&group_key).expect("staged");
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].sub_tree_type(), SupplySubTree::Mint);

    // The pending supply anchor was restored: without a confirmation
    // it stays pending.
    let summary = node.tick().expect("tick");
    assert_eq!(summary.pending_anchors, 1);
    assert_eq!(summary.confirmed_anchors, 0);

    // The new chain fake needs the mint block hash for the verifier's
    // header check of the issuance leaf proof.
    harness.chain.set_block_hash(813_000, mint_block);
    harness.chain.confirm_tx_valid(&commit_tx_bytes, 813_050);

    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    let commitment = node
        .latest_supply_commitment(&group_key)
        .expect("latest")
        .expect("commitment persisted after restart");
    assert_eq!(commitment.supply_root_sum, 750);
    assert!(node
        .staged_supply_updates(&group_key)
        .expect("staged")
        .is_empty());
    assert!(node
        .unspent_supply_pre_commits(&group_key)
        .expect("pre-commits")
        .is_empty());
}
