// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! End-to-end mint flow over functional fakes: freeze -> commit ->
//! recommit with the discovered genesis point -> broadcast -> persist,
//! then confirmation via `tick()` -> genesis proof -> universe
//! registration -> finalized batch.

mod common;

use common::*;

use tap_node::*;
use tap_onchain::mint::{BatchState, Seedling};
use tap_primitives::asset::{OutPoint, ScriptKey};
use tap_primitives::proof::MetaReveal;

#[test]
fn test_mint_end_to_end() {
    let harness = default_harness();
    let node = &harness.node;

    // Queue a seedling with metadata.
    let meta = MetaReveal::new_opaque(b"mint-flow-meta".to_vec());
    let meta_hash = meta.meta_hash();
    let mut seedling = Seedling::new_normal("flow-token".into(), 1_000);
    seedling.meta = Some(meta);
    node.queue_mint(seedling).expect("queue");

    let result = node.finalize_mint().expect("finalize");

    // The genesis point is the fake wallet's deterministic funding
    // input, discovered by the fund-once flow.
    assert_eq!(result.genesis_point, FUNDING_OUTPOINT);
    assert_eq!(result.assets.len(), 1);
    let minted = &result.assets[0];
    assert_eq!(minted.name, "flow-token");
    assert_eq!(minted.amount, 1_000);

    // The batch key is the first key the planter derived (index 0).
    // Each seedling then gets its own wallet-derived BIP-86 script key
    // (the sole seedling here is index 1), so sibling assets in a batch
    // have distinct script keys, proof locators, and descriptors.
    let batch_key = FakeKeys::pub_key_for(0);
    assert_eq!(result.batch_key, batch_key);
    let script_raw_key = FakeKeys::pub_key_for(1);
    let expected_script_key = ScriptKey::bip86(script_raw_key).pub_key;
    assert_eq!(minted.script_key, expected_script_key);

    // The transaction was broadcast, and its TAP output committed by
    // the recommitted batch (patched into the funded PSBT).
    let broadcast = harness.chain.last_broadcast().expect("broadcast");
    assert_eq!(broadcast, result.signed_tx);

    // The minted asset was persisted with the real genesis (including
    // the seedling meta hash) and the script key descriptor.
    let assets = node.list_assets().expect("list");
    assert_eq!(assets.len(), 1);
    let owned = &assets[0];
    assert_eq!(owned.asset_id, minted.asset_id);
    assert_eq!(owned.amount, 1_000);
    assert_eq!(owned.script_key, expected_script_key);
    assert_eq!(owned.genesis_point, Some(FUNDING_OUTPOINT));
    assert_eq!(owned.genesis_tag.as_deref(), Some("flow-token"));
    assert_eq!(owned.genesis_meta_hash, Some(meta_hash));
    assert_eq!(
        owned.genesis_output_index,
        Some(result.tap_output_index)
    );
    let script_desc = owned.script_key_desc.as_ref().expect("desc");
    assert_eq!(script_desc.pub_key, script_raw_key);
    assert_eq!(node.get_balance(&minted.asset_id).expect("bal"), 1_000);

    // The batch was persisted as Broadcast.
    let stored = harness
        .batch_store
        .lock()
        .expect("lock")
        .load_batch(&batch_key)
        .expect("load")
        .expect("batch persisted");
    use tap_persist::batch_store::BatchStore as _;
    assert_eq!(stored.state, BatchState::Broadcast);
    assert_eq!(stored.genesis_outpoint, Some(FUNDING_OUTPOINT));

    // Event sequence so far: Frozen -> Committed -> Broadcast.
    let states: Vec<BatchState> = harness
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            TapEvent::MintBatchStateChanged { new_state, .. } => {
                Some(new_state)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        vec![
            BatchState::Frozen,
            BatchState::Committed,
            BatchState::Broadcast
        ]
    );

    // No confirmation yet: tick keeps the anchor pending.
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 0);
    assert_eq!(summary.pending_anchors, 1);

    // Confirm the mint transaction and tick again.
    harness.chain.confirm_tx(&result.signed_tx, 812_345);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert_eq!(summary.pending_anchors, 0);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    // Confirmation events: Confirmed -> Finalized.
    let states: Vec<BatchState> = harness
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            TapEvent::MintBatchStateChanged { new_state, .. } => {
                Some(new_state)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        vec![BatchState::Confirmed, BatchState::Finalized]
    );

    // The batch store now holds the finalized batch with the
    // confirmation data.
    let stored = harness
        .batch_store
        .lock()
        .expect("lock")
        .load_batch(&batch_key)
        .expect("load")
        .expect("batch persisted");
    assert_eq!(stored.state, BatchState::Finalized);
    assert!(stored.confirmation.is_some());
    assert_eq!(
        stored.confirmation.as_ref().map(|c| c.block_height),
        Some(812_345)
    );

    // The genesis proof was generated and stored under the anchor
    // outpoint + script key.
    let txid_internal = to_internal(result.txid.expect("txid"));
    let anchor_outpoint = OutPoint {
        txid: txid_internal,
        vout: result.tap_output_index,
    };
    let proof_file = node
        .export_proof(&anchor_outpoint, &expected_script_key)
        .expect("genesis proof stored");
    assert_eq!(proof_file.num_proofs(), 1);

    // Universe registration was attempted: the issuance leaf landed in
    // the node's local universe tree.
    let universe_id = tap_universe::types::UniverseId {
        asset_id: minted.asset_id,
        group_key: None,
        proof_type: tap_universe::types::ProofType::Issuance,
    };
    let root = node.universe_root(&universe_id).expect("universe root");
    assert_eq!(root.root_sum, 1_000);
}

#[test]
fn test_mint_multiple_seedlings_share_genesis_point() {
    let harness = default_harness();
    let node = &harness.node;

    node.queue_mint(Seedling::new_normal("token-a".into(), 500))
        .expect("queue a");
    node.queue_mint(Seedling::new_normal("token-b".into(), 300))
        .expect("queue b");

    let result = node.finalize_mint().expect("finalize");
    assert_eq!(result.assets.len(), 2);
    assert_eq!(result.genesis_point, FUNDING_OUTPOINT);

    // Both assets exist, with distinct IDs derived from the same
    // genesis point but different tags.
    assert_ne!(result.assets[0].asset_id, result.assets[1].asset_id);
    for asset in &result.assets {
        assert_eq!(
            node.get_balance(&asset.asset_id).expect("bal"),
            asset.amount
        );
    }

    // Confirm and finalize: two genesis proofs, two universe leaves.
    harness.chain.confirm_tx(&result.signed_tx, 812_400);
    let summary = node.tick().expect("tick");
    assert_eq!(summary.confirmed_anchors, 1);
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);

    for asset in &result.assets {
        let universe_id = tap_universe::types::UniverseId {
            asset_id: asset.asset_id,
            group_key: None,
            proof_type: tap_universe::types::ProofType::Issuance,
        };
        let root =
            node.universe_root(&universe_id).expect("universe root");
        assert_eq!(root.root_sum, asset.amount);
    }
}

#[test]
fn test_mint_failure_resets_batch() {
    let harness = default_harness();
    let node = &harness.node;

    // Finalizing with no queued seedlings fails and leaves the planter
    // ready for the next mint.
    assert!(node.finalize_mint().is_err());

    node.queue_mint(Seedling::new_normal("retry-token".into(), 10))
        .expect("queue after failure");
    let result = node.finalize_mint().expect("finalize");
    assert_eq!(result.assets.len(), 1);
    drop(harness);
}
