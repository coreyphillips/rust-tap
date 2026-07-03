// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Node lifecycle: manual `tick()` confirmation polling,
//! `start()`/`stop()` worker thread management, and pending-anchor
//! persistence across a simulated restart.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;

use tap_node::*;
use tap_onchain::mint::Seedling;
use tap_onchain::proof::courier::{Courier, CourierLocator, Recipient};
use tap_persist::pending_anchor_store::{
    PendingAnchorStore, SqlitePendingAnchorStore,
};
use tap_persist::sqlite::SqliteDb;
use tap_primitives::asset::OutPoint;

/// Opens an independent handle onto the harness database's pending
/// anchor rows (WAL mode allows concurrent connections).
fn pending_rows(db_path: &std::path::Path) -> usize {
    let db = Arc::new(SqliteDb::open(db_path).expect("open db"));
    SqlitePendingAnchorStore::new(db)
        .list_anchors()
        .expect("list anchors")
        .len()
}

#[test]
fn test_tick_none_then_some_confirmation() {
    let harness = default_harness();
    let node = &harness.node;

    // Nothing pending: an empty tick.
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 0);
    assert!(!summary.universe_synced);
    assert!(summary.errors.is_empty());

    // Broadcast a mint; the anchor stays pending while the chain
    // reports no confirmation.
    node.queue_mint(Seedling::new_normal("tick-token".into(), 42))
        .expect("queue");
    let result = node.finalize_mint().expect("finalize");

    for _ in 0..3 {
        let summary = node.tick().expect("tick");
        assert_eq!(summary.confirmed_anchors, 0);
        assert_eq!(summary.pending_anchors, 1);
    }

    // Script the confirmation: the next tick resolves the anchor.
    harness.chain.confirm_tx(&result.signed_tx, 812_000);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert_eq!(summary.pending_anchors, 0);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    // Resolved anchors are gone: subsequent ticks are empty again.
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 0);
}

#[test]
fn test_start_stop_idempotency_and_join() {
    let mut config = TapNodeConfig::default();
    config.tick_interval_secs = 1;
    let harness = build_harness(config);
    let node = &harness.node;

    assert!(!node.is_running());

    // Stop before start fails.
    assert!(matches!(node.stop(), Err(TapNodeError::NotRunning)));

    // Start spawns the worker.
    node.clone().start().expect("start");
    assert!(node.is_running());

    // A second start fails.
    assert!(matches!(
        node.clone().start(),
        Err(TapNodeError::AlreadyRunning)
    ));
    assert!(node.is_running());

    // The worker actually ticks: queue a mint, script its
    // confirmation, and wait for the background thread to finalize it.
    node.queue_mint(Seedling::new_normal("bg-token".into(), 7))
        .expect("queue");
    let result = node.finalize_mint().expect("finalize");
    harness.chain.confirm_tx(&result.signed_tx, 812_100);

    let asset_id = result.assets[0].asset_id;
    let universe_id = tap_universe::types::UniverseId {
        asset_id,
        group_key: None,
        proof_type: tap_universe::types::ProofType::Issuance,
    };
    let mut finalized = false;
    for _ in 0..100 {
        if node.universe_root(&universe_id).is_ok() {
            finalized = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(finalized, "worker thread never finalized the mint");

    // Stop joins the worker.
    node.stop().expect("stop");
    assert!(!node.is_running());

    // A second stop fails.
    assert!(matches!(node.stop(), Err(TapNodeError::NotRunning)));

    // The node can be restarted after a stop.
    node.clone().start().expect("restart");
    assert!(node.is_running());
    node.stop().expect("stop again");
    assert!(!node.is_running());
}

/// A node crash/restart between broadcast and confirmation must not
/// lose pending anchors: a broadcast mint and a broadcast transfer
/// (carrying a passive sibling asset) are reloaded from the SQLite
/// pending-anchor store by a SECOND node over the same database, and a
/// tick on the new node finishes both exactly as if no restart
/// happened. Resolved anchors are removed from the store.
#[test]
fn test_restart_restores_pending_mint_and_transfer_anchors() {
    let tmp = TempDir::new("restart");
    let db_path = tmp.db_path();

    // --- Node 1: mint two assets in one batch (confirmed), then
    // broadcast a full-value send of asset A (re-anchoring passive
    // asset B) and a second mint, leaving BOTH unconfirmed. ---
    let harness1 = build_db_harness(&db_path);
    let node1 = &harness1.node;

    node1
        .queue_mint(Seedling::new_normal("asset-a".into(), 1_000))
        .expect("queue a");
    node1
        .queue_mint(Seedling::new_normal("asset-b".into(), 500))
        .expect("queue b");
    let mint1 = node1.finalize_mint().expect("finalize mint 1");
    harness1.chain.confirm_tx(&mint1.signed_tx, 812_000);
    let summary = node1.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    let asset_a = mint1
        .assets
        .iter()
        .find(|a| a.name == "asset-a")
        .expect("asset-a")
        .asset_id;
    let asset_b = mint1
        .assets
        .iter()
        .find(|a| a.name == "asset-b")
        .expect("asset-b")
        .asset_id;

    // Broadcast (but do not confirm) the transfer. Sending ALL of
    // asset A forces the passive re-anchor of asset B into the change
    // output.
    let addr_a = recipient_address(asset_a, 1_000);
    let handle = node1
        .send_asset(asset_a, 1_000, &addr_a)
        .expect("send A");
    let send_txid = to_internal(handle.txid);
    let transfer_tx =
        harness1.chain.last_broadcast().expect("transfer broadcast");

    // Broadcast (but do not confirm) a second mint.
    node1
        .queue_mint(Seedling::new_normal("late-token".into(), 42))
        .expect("queue late");
    let mint2 = node1.finalize_mint().expect("finalize mint 2");

    // Both anchors are pending in memory and durably stored.
    let summary = node1.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 2);
    assert_eq!(pending_rows(&db_path), 2);

    // --- Simulate the restart: drop node 1, build node 2 over the
    // SAME database (fresh chain, fresh courier, fresh memory). ---
    drop(harness1);
    let harness2 = build_db_harness(&db_path);
    let node2 = &harness2.node;

    // The reloaded anchors are pending; without confirmations a tick
    // keeps them (and does not duplicate them).
    let summary = node2.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 2);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    // Confirmations become available on the new node's chain view.
    harness2.chain.confirm_tx(&transfer_tx, 812_500);
    harness2.chain.confirm_tx(&mint2.signed_tx, 812_600);
    let summary = node2.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 2);
    assert_eq!(summary.pending_anchors, 0);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    // -- The restored MINT finalized: genesis proof stored, universe
    // leaf registered, batch state events emitted. --
    let mint2_outpoint = OutPoint {
        txid: to_internal(mint2.txid.expect("mint2 txid")),
        vout: mint2.tap_output_index,
    };
    let mint2_proof = node2
        .export_proof(&mint2_outpoint, &mint2.assets[0].script_key)
        .expect("mint2 genesis proof stored");
    assert_eq!(mint2_proof.num_proofs(), 1);
    assert!(mint2_proof.verify_hash_chain());

    let universe_id = tap_universe::types::UniverseId {
        asset_id: mint2.assets[0].asset_id,
        group_key: None,
        proof_type: tap_universe::types::ProofType::Issuance,
    };
    node2
        .universe_root(&universe_id)
        .expect("mint2 issuance leaf registered with the universe");

    let events = harness2.drain_events();
    assert!(events.iter().any(|e| matches!(
        e,
        TapEvent::MintBatchStateChanged {
            new_state: tap_onchain::mint::BatchState::Finalized,
            ..
        }
    )));

    // -- The restored TRANSFER completed: recipient proof stored and
    // delivered, passive asset B's proof stored at its re-anchor. --
    assert!(events.iter().any(|e| matches!(
        e,
        TapEvent::TransferConfirmed { amount: 1_000, .. }
    )));
    assert!(events
        .iter()
        .any(|e| matches!(e, TapEvent::ProofDelivered { .. })));

    let recipient_outpoint = OutPoint {
        txid: send_txid,
        vout: 1,
    };
    let recipient_file = node2
        .export_proof(&recipient_outpoint, &addr_a.script_key)
        .expect("recipient proof stored");
    assert_eq!(recipient_file.num_proofs(), 2);
    assert!(recipient_file.verify_hash_chain());

    // Passive asset B was re-anchored into the change output (vout 0)
    // and its proof (genesis -> re-anchor transition) was stored.
    let change_outpoint = OutPoint {
        txid: send_txid,
        vout: 0,
    };
    let reanchored = node2
        .list_assets()
        .expect("list")
        .into_iter()
        .find(|a| a.asset_id == asset_b)
        .expect("asset B survives the restart");
    assert_eq!(reanchored.anchor_outpoint, change_outpoint);
    assert_eq!(reanchored.amount, 500);
    let passive_file = node2
        .export_proof(&change_outpoint, &reanchored.script_key)
        .expect("passive proof stored");
    assert_eq!(passive_file.num_proofs(), 2);
    assert!(passive_file.verify_hash_chain());

    // The courier (node 2's) delivered the recipient proof file.
    let delivered = harness2
        .courier
        .receive_proof(
            &Recipient {
                script_key: addr_a.script_key,
                asset_id: asset_a,
                amount: 1_000,
            },
            &CourierLocator {
                asset_id: asset_a,
                script_key: addr_a.script_key,
                outpoint: recipient_outpoint,
            },
        )
        .expect("courier has the proof");
    assert_eq!(delivered.proof_file.num_proofs(), 2);

    // -- Resolved anchors were removed from the durable store: a third
    // node over the same database restores nothing. --
    assert_eq!(pending_rows(&db_path), 0);
    drop(harness2);
    let harness3 = build_db_harness(&db_path);
    let summary = harness3.node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 0);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
}

/// Building a node over a database with no pending anchors restores
/// nothing: an empty-store reload is a no-op.
#[test]
fn test_restore_from_empty_pending_anchor_store_is_noop() {
    let tmp = TempDir::new("empty-restore");
    let harness = build_db_harness(&tmp.db_path());
    let summary = harness.node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 0);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
}

/// A recipient address over keys unrelated to the node's key ring.
fn recipient_address(
    asset_id: AssetId,
    amount: u64,
) -> tap_primitives::address::TapAddress {
    tap_primitives::address::TapAddress {
        version: tap_primitives::address::AddressVersion::V0,
        asset_version: 0,
        asset_id: Some(asset_id),
        script_key: FakeKeys::pub_key_for(100),
        internal_key: FakeKeys::pub_key_for(101),
        amount,
        network: tap_primitives::address::TapNetwork::Regtest,
        proof_courier_addr: Some("hashmail://courier.test:8080".into()),
        group_key: None,
        tapscript_sibling: None,
        unknown_odd_types: std::collections::BTreeMap::new(),
    }
}
