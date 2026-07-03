// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Node lifecycle: manual `tick()` confirmation polling, and
//! `start()`/`stop()` worker thread management.

mod common;

use std::time::Duration;

use common::*;

use tap_node::*;
use tap_onchain::mint::Seedling;

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
