// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Shared, backend-agnostic store-trait exercises.
//!
//! Each `exercise_*` function drives one store trait through the same
//! scenario the per-backend unit tests cover, panicking on any
//! divergence. They are used three ways:
//!
//! - by the in-crate unit tests, against the Memory and SQLite
//!   backends;
//! - by the `tests/postgres.rs` integration test, against the Postgres
//!   backend (gated on the `TAP_TEST_PG_URL` environment variable);
//! - by embedders who implement their own store backends and want the
//!   reference semantics checked.
//!
//! The module is compiled for unit tests and whenever the `postgres`
//! feature is enabled (integration tests link the library without
//! `cfg(test)`). It is not part of the crate's stable API.
//!
//! Each exercise touches only its own tables and uses fixed test keys,
//! so the full set can run sequentially against one shared, freshly
//! migrated database. Run an exercise only once per database.

use tap_onchain::chain::{KeyDescriptor, TxConfirmation};
use tap_onchain::mint::{BatchState, MintingBatch, Seedling};
use tap_primitives::address::{AddressVersion, TapAddress, TapNetwork};
use tap_primitives::asset::{
    AssetId, AssetType, OutPoint, PrevId, SerializedKey,
};
use tap_primitives::mssmt::{
    CompactedTree, DefaultStore, LeafNode, NodeHash, TreeStoreUpdateTx,
    TreeStoreViewTx,
};
use tap_primitives::proof::{self, BlockHeader, TxMerkleProof};
use tap_universe::ignore::{IgnoreSig, IgnoreTuple, SignedIgnoreTuple};
use tap_universe::supply::{
    CommitmentBlock, NewIgnoreEvent, PreCommitment, RootCommitment,
    SupplySubTree, SupplyUpdateEvent,
};
use tap_universe::traits::{FederationDb, UniverseBackend};
use tap_universe::types::{
    LeafKey, LeafKeysQuery, ProofType, ServerAddr, UniverseId, UniverseLeaf,
};
use tap_universe::MemoryUniverseBackend;

use crate::asset_store::{AssetStore, BurnRecord, OwnedAsset};
use crate::batch_store::BatchStore;
use crate::ignore_store::IgnoreTupleStore;
use crate::mailbox_store::{MailboxCursor, MailboxStore};
use crate::pending_anchor_store::{PendingAnchorStore, StoredPendingAnchor};
use crate::proof_store::{ProofLocator, ProofStore};
use crate::supply_store::{
    MemorySupplyTreeStore, SupplyCommitStore, SupplyStagingStore,
    SupplyTreeStore,
};

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

fn test_asset(id_byte: u8, amount: u64, vout: u32) -> OwnedAsset {
    OwnedAsset::new(
        AssetId([id_byte; 32]),
        amount,
        OutPoint {
            txid: [0xAA; 32],
            vout,
        },
        SerializedKey([0x02; 33]),
        800_000,
    )
}

/// An asset with all optional key descriptor and genesis fields set.
fn test_asset_full(vout: u32) -> OwnedAsset {
    let mut asset = test_asset(0xAA, 100, vout);
    asset.script_key_desc = Some(KeyDescriptor {
        family: 212,
        index: 7,
        pub_key: SerializedKey([0x02; 33]),
    });
    asset.internal_key = Some(KeyDescriptor {
        family: 212,
        index: 8,
        pub_key: SerializedKey([0x03; 33]),
    });
    asset.genesis_point = Some(OutPoint {
        txid: [0x55; 32],
        vout: 2,
    });
    asset.genesis_tag = Some("test-coin".to_string());
    asset.genesis_meta_hash = Some([0x44; 32]);
    asset.genesis_output_index = Some(1);
    asset.genesis_asset_type = Some(AssetType::Collectible);
    asset
}

fn test_burn(id_byte: u8, amount: u64, vout: u32) -> BurnRecord {
    BurnRecord {
        note: Some("goodbye".to_string()),
        asset_id: AssetId([id_byte; 32]),
        group_key: Some(SerializedKey([0x03; 33])),
        amount,
        anchor_txid: [0xDD; 32],
        script_key: SerializedKey([0x02; 33]),
        out_point: OutPoint {
            txid: [0xDD; 32],
            vout,
        },
        block_height: 850_000,
    }
}

fn test_batch(key_byte: u8) -> MintingBatch {
    let mut batch = MintingBatch::new(KeyDescriptor {
        family: 212,
        index: 0,
        pub_key: SerializedKey([key_byte; 33]),
    });
    batch
        .add_seedling(Seedling::new_normal("test-token".into(), 1000))
        .expect("add seedling");
    batch
}

fn test_locator(vout: u32) -> ProofLocator {
    ProofLocator {
        outpoint: OutPoint {
            txid: [0xAA; 32],
            vout,
        },
        script_key: SerializedKey([0x02; 33]),
    }
}

fn test_proof_file() -> proof::File {
    let mut file = proof::File::new();
    file.append_proof(vec![0x01, 0x02, 0x03]);
    file
}

fn test_address(script_key_byte: u8) -> TapAddress {
    // Address decode validates keys on-curve (like Go), so the test
    // keys must be valid points: x = 0xAA repeated is a valid x
    // coordinate.
    let mut internal_key = [0xAA; 33];
    internal_key[0] = 0x02;
    TapAddress {
        version: AddressVersion::V2,
        asset_version: 0,
        asset_id: Some(AssetId([0xAA; 32])),
        script_key: SerializedKey([script_key_byte; 33]),
        internal_key: SerializedKey(internal_key),
        amount: 1000,
        network: TapNetwork::Regtest,
        proof_courier_addr: Some(
            "authmailbox+universerpc://foo.bar:10029".to_string(),
        ),
        group_key: None,
        tapscript_sibling: None,
        unknown_odd_types: std::collections::BTreeMap::new(),
    }
}

fn test_anchor(txid_byte: u8, kind: u8) -> StoredPendingAnchor {
    StoredPendingAnchor {
        txid: [txid_byte; 32],
        kind,
        payload: vec![0x01, txid_byte, 0x03],
    }
}

fn universe_id() -> UniverseId {
    UniverseId {
        asset_id: AssetId([0xAA; 32]),
        group_key: None,
        proof_type: ProofType::Issuance,
    }
}

fn universe_leaf(vout: u32) -> (LeafKey, UniverseLeaf) {
    let key = LeafKey {
        outpoint: OutPoint {
            txid: [0xBB; 32],
            vout,
        },
        script_key: SerializedKey([0x02; 33]),
    };
    let leaf = UniverseLeaf {
        asset_id: AssetId([0xAA; 32]),
        amount: 100,
        proof: vec![0x01, 0x02],
        key: key.clone(),
    };
    (key, leaf)
}

fn group_key() -> SerializedKey {
    let mut k = [0x02u8; 33];
    k[32] = 0x77;
    SerializedKey(k)
}

fn group_key_b() -> SerializedKey {
    let mut k = [0x02u8; 33];
    k[32] = 0x22;
    SerializedKey(k)
}

fn valid_script_key() -> SerializedKey {
    // The secp256k1 generator point (a known-valid key).
    let mut k = [0u8; 33];
    k[0] = 0x02;
    k[1..].copy_from_slice(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
        0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
        0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ]);
    SerializedKey(k)
}

fn ignore_update(vout: u32, amount: u64) -> SupplyUpdateEvent {
    SupplyUpdateEvent::Ignore(NewIgnoreEvent {
        signed_tuple: SignedIgnoreTuple {
            tuple: IgnoreTuple {
                prev_id: PrevId {
                    out_point: OutPoint {
                        txid: [0x33; 32],
                        vout,
                    },
                    id: AssetId([0x44; 32]),
                    script_key: valid_script_key(),
                },
                amount,
                block_height: 100,
            },
            sig: IgnoreSig([0x01; 64]),
        },
    })
}

fn signed_tuple(vout: u32, amount: u64) -> SignedIgnoreTuple {
    SignedIgnoreTuple {
        tuple: IgnoreTuple {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0x55; 32],
                    vout,
                },
                id: AssetId([0x66; 32]),
                script_key: valid_script_key(),
            },
            amount,
            block_height: 321,
        },
        sig: IgnoreSig([0x07; 64]),
    }
}

fn dummy_tx(seed: u8, value: u64, script: Vec<u8>) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::Hash as BtcHash;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint as BtcOutPoint, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    };

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: BtcOutPoint {
                txid: Txid::from_raw_hash(sha256d::Hash::from_byte_array(
                    [seed; 32],
                )),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    }
}

fn test_commitment(seed: u8, with_block: bool) -> RootCommitment {
    let txn = dummy_tx(seed, 1000, vec![0x51, 0x20, seed, 0x00]);
    let commitment_block = if with_block {
        let mut header_bytes = [0u8; 80];
        header_bytes[0] = seed;
        let header = BlockHeader(header_bytes);
        Some(CommitmentBlock {
            height: 123,
            hash: header.block_hash(),
            tx_index: 1,
            block_header: Some(header),
            merkle_proof: Some(TxMerkleProof {
                nodes: vec![[seed; 32]],
                bits: vec![true],
            }),
            chain_fees: 42,
        })
    } else {
        None
    };

    RootCommitment {
        txn,
        tx_out_idx: 0,
        internal_key: group_key(),
        output_key: Some([seed; 32]),
        supply_root_hash: NodeHash([seed; 32]),
        supply_root_sum: 500,
        commitment_block,
        spent_commitment: if seed % 2 == 0 {
            Some(OutPoint {
                txid: [seed; 32],
                vout: 1,
            })
        } else {
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Exercises
// ---------------------------------------------------------------------------

/// Exercises [`AssetStore`] asset tracking: insert, upsert-replace,
/// balances, identity-scoped mark_spent, passive siblings, and anchor
/// block height updates.
pub fn exercise_asset_store(store: &mut dyn AssetStore) {
    let aa = AssetId([0xAA; 32]);
    let bb = AssetId([0xBB; 32]);

    // Insert + balance + get_unspent.
    store.insert_asset(test_asset(0xAA, 100, 0)).unwrap();
    store.insert_asset(test_asset(0xAA, 200, 1)).unwrap();
    assert_eq!(store.balance(&aa), 300);
    assert_eq!(store.get_unspent(&aa).len(), 2);

    // Optional fields (key descriptors + genesis data) round-trip and
    // legacy rows read back as None.
    let full = test_asset_full(2);
    store.insert_asset(full.clone()).unwrap();
    let mut assets = store.get_unspent(&aa);
    assets.sort_by_key(|a| a.anchor_outpoint.vout);
    assert_eq!(assets.len(), 3);
    assert_eq!(assets[2], full);
    assert_eq!(assets[0], test_asset(0xAA, 100, 0));

    // Re-inserting the same (outpoint, asset, script key) replaces.
    store.insert_asset(test_asset(0xAA, 150, 1)).unwrap();
    assert_eq!(store.balance(&aa), 100 + 150 + 100);

    // A sibling asset at the same anchor outpoint (multi-asset
    // anchor, migration 008).
    let mut sibling = test_asset(0xBB, 200, 0);
    sibling.script_key = SerializedKey([0x03; 33]);
    store.insert_asset(sibling).unwrap();

    // mark_spent flips only the exact identity.
    let outpoint = OutPoint {
        txid: [0xAA; 32],
        vout: 0,
    };
    store
        .mark_spent(&outpoint, &aa, &SerializedKey([0x02; 33]))
        .unwrap();
    assert_eq!(store.balance(&aa), 150 + 100);
    assert_eq!(store.balance(&bb), 200);
    let survivors = store.unspent_at_outpoint(&outpoint);
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].asset_id, bb);

    // mark_spent on a missing identity errors.
    let missing = OutPoint {
        txid: [0xFF; 32],
        vout: 99,
    };
    assert_eq!(
        store
            .mark_spent(&missing, &aa, &SerializedKey([0x02; 33]))
            .unwrap_err(),
        "asset not found"
    );

    // set_anchor_block_height updates every asset at the outpoint and
    // leaves other outpoints alone.
    store.set_anchor_block_height(&outpoint, 812_000).unwrap();
    for asset in store.list_unspent() {
        if asset.anchor_outpoint == outpoint {
            assert_eq!(asset.block_height, 812_000);
        } else {
            assert_eq!(asset.block_height, 800_000);
        }
    }

    // Unknown outpoint: idempotent no-op.
    store.set_anchor_block_height(&missing, 1).unwrap();
}

/// Exercises [`AssetStore`] burn records: round-trip, upsert, asset-id
/// filtering, and optional fields.
pub fn exercise_burn_records(store: &mut dyn AssetStore) {
    let burn_a = test_burn(0xAA, 100, 0);
    store.insert_burn(burn_a.clone()).unwrap();

    let burns = store.list_burns(None);
    assert_eq!(burns.len(), 1);
    assert_eq!(burns[0], burn_a);

    store.insert_burn(test_burn(0xBB, 200, 1)).unwrap();

    // Optional fields absent.
    let mut bare = test_burn(0xAA, 300, 2);
    bare.note = None;
    bare.group_key = None;
    store.insert_burn(bare.clone()).unwrap();

    let mut burns = store.list_burns(None);
    burns.sort_by_key(|b| b.out_point.vout);
    assert_eq!(burns.len(), 3);
    assert_eq!(burns[2], bare);

    let mut filtered = store.list_burns(Some(&AssetId([0xAA; 32])));
    filtered.sort_by_key(|b| b.out_point.vout);
    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered[0].amount, 100);
    assert!(store.list_burns(Some(&AssetId([0xCC; 32]))).is_empty());
}

/// Exercises [`BatchStore`]: save/load, state updates, listing, and
/// confirmation round-trips.
pub fn exercise_batch_store(store: &mut dyn BatchStore) {
    let key_a = SerializedKey([0x02; 33]);

    // Missing batch loads as None.
    assert!(store.load_batch(&SerializedKey([0xFF; 33])).unwrap().is_none());

    store.save_batch(&test_batch(0x02)).unwrap();
    let loaded = store.load_batch(&key_a).unwrap().unwrap();
    assert_eq!(loaded.state, BatchState::Pending);
    assert_eq!(loaded.num_seedlings(), 1);
    assert_eq!(loaded.batch_key.family, 212);
    assert_eq!(loaded.batch_key.index, 0);

    // State updates.
    store.update_state(&key_a, BatchState::Frozen).unwrap();
    let loaded = store.load_batch(&key_a).unwrap().unwrap();
    assert_eq!(loaded.state, BatchState::Frozen);
    assert_eq!(
        store
            .update_state(&SerializedKey([0xFF; 33]), BatchState::Frozen)
            .unwrap_err(),
        "batch not found"
    );

    // A second batch with genesis outpoint + confirmation.
    let key_b = SerializedKey([0x03; 33]);
    let mut batch = test_batch(0x03);
    batch.state = BatchState::Confirmed;
    batch.genesis_outpoint = Some(OutPoint {
        txid: [0xBB; 32],
        vout: 0,
    });
    batch.confirmation = Some(TxConfirmation {
        block_hash: [0xCC; 32],
        block_height: 850_000,
        tx_index: 3,
        tx: vec![0x01, 0x02],
        block_header: [0u8; 80],
        block_tx_hashes: Vec::new(),
    });
    batch.mint_output_index = Some(0);
    store.save_batch(&batch).unwrap();

    let loaded = store.load_batch(&key_b).unwrap().unwrap();
    assert_eq!(loaded.state, BatchState::Confirmed);
    assert!(loaded.genesis_outpoint.is_some());
    let conf = loaded.confirmation.unwrap();
    assert_eq!(conf.block_height, 850_000);
    assert_eq!(conf.tx_index, 3);
    assert_eq!(loaded.mint_output_index, Some(0));

    assert_eq!(store.list_batches().len(), 2);

    // Re-saving a batch replaces it (and its seedlings) rather than
    // duplicating.
    store.save_batch(&test_batch(0x02)).unwrap();
    assert_eq!(store.list_batches().len(), 2);
    let reloaded = store.load_batch(&key_a).unwrap().unwrap();
    assert_eq!(reloaded.num_seedlings(), 1);
}

/// Exercises [`ProofStore`]: insert/get/has/list and replacement.
pub fn exercise_proof_store(store: &mut dyn ProofStore) {
    let loc = test_locator(0);

    // Missing proof.
    assert!(!store.has_proof(&loc));
    assert!(store.get_proof(&loc).unwrap().is_none());

    store.insert_proof(loc.clone(), test_proof_file()).unwrap();
    assert!(store.has_proof(&loc));
    let retrieved = store.get_proof(&loc).unwrap().unwrap();
    assert_eq!(retrieved.num_proofs(), 1);

    store
        .insert_proof(test_locator(1), test_proof_file())
        .unwrap();
    assert_eq!(store.list_proofs().len(), 2);

    // Replacing an existing locator overwrites the file.
    let mut file2 = proof::File::new();
    file2.append_proof(vec![0x01]);
    file2.append_proof(vec![0x02]);
    store.insert_proof(loc.clone(), file2).unwrap();
    let retrieved = store.get_proof(&loc).unwrap().unwrap();
    assert_eq!(retrieved.num_proofs(), 2);
    assert_eq!(store.list_proofs().len(), 2);
}

/// Exercises [`PendingAnchorStore`]: upsert, idempotent removal, and
/// listing.
pub fn exercise_pending_anchor_store(store: &mut dyn PendingAnchorStore) {
    // Empty store lists nothing.
    assert!(store.list_anchors().unwrap().is_empty());

    // Removing a missing txid is a no-op.
    store.remove_anchor(&[0xEE; 32]).unwrap();

    let mint = test_anchor(0xAA, 0);
    let transfer = test_anchor(0xBB, 1);
    store.upsert_anchor(&mint).unwrap();
    store.upsert_anchor(&transfer).unwrap();

    let mut listed = store.list_anchors().unwrap();
    listed.sort_by_key(|a| a.txid);
    assert_eq!(listed, vec![mint.clone(), transfer.clone()]);

    // Upsert replaces the payload for an existing txid (registration
    // after a restart-reload must be idempotent).
    let replaced = StoredPendingAnchor {
        payload: vec![0x09; 8],
        ..mint.clone()
    };
    store.upsert_anchor(&replaced).unwrap();
    let mut listed = store.list_anchors().unwrap();
    listed.sort_by_key(|a| a.txid);
    assert_eq!(listed, vec![replaced, transfer.clone()]);

    // Removal deletes exactly the given txid.
    store.remove_anchor(&mint.txid).unwrap();
    assert_eq!(store.list_anchors().unwrap(), vec![transfer.clone()]);
    store.remove_anchor(&transfer.txid).unwrap();
    assert!(store.list_anchors().unwrap().is_empty());
}

/// Exercises [`MailboxStore`]: addresses, cursors, and key
/// descriptors.
pub fn exercise_mailbox_store(store: &mut dyn MailboxStore) {
    let addr = test_address(0x02);
    store.insert_address(&addr).unwrap();

    // Duplicate script keys are rejected.
    assert!(store.insert_address(&addr).is_err());

    let listed = store.list_addresses().unwrap();
    assert_eq!(listed, vec![addr.clone()]);

    let found = store
        .address_by_script_key(&addr.script_key)
        .unwrap()
        .unwrap();
    assert_eq!(found, addr);
    assert!(store
        .address_by_script_key(&SerializedKey([0x05; 33]))
        .unwrap()
        .is_none());

    // Cursors default to zero, then upsert.
    let key = addr.script_key;
    assert_eq!(store.get_cursor(&key).unwrap(), MailboxCursor::default());
    let cursor = MailboxCursor {
        last_message_id: 42,
        last_block: 800_000,
    };
    store.set_cursor(&key, cursor).unwrap();
    assert_eq!(store.get_cursor(&key).unwrap(), cursor);

    let cursor2 = MailboxCursor {
        last_message_id: 43,
        last_block: 800_001,
    };
    store.set_cursor(&key, cursor2).unwrap();
    assert_eq!(store.get_cursor(&key).unwrap(), cursor2);

    // Key descriptors: none stored yet.
    assert!(store.key_descriptors(&key).unwrap().is_none());

    // Store descriptors whose raw keys differ from the address keys
    // (the tweaked-script-key case) and read them back.
    let script_desc = KeyDescriptor {
        family: 212,
        index: 5,
        pub_key: SerializedKey([0x02; 33]),
    };
    let internal_desc = KeyDescriptor {
        family: 212,
        index: 6,
        pub_key: SerializedKey([0x03; 33]),
    };
    store
        .set_key_descriptors(&key, &script_desc, &internal_desc)
        .unwrap();
    let (s, i) = store.key_descriptors(&key).unwrap().unwrap();
    assert_eq!(s, script_desc);
    assert_eq!(i, internal_desc);

    // Setting descriptors for an unknown address fails.
    assert!(store
        .set_key_descriptors(
            &SerializedKey([0x05; 33]),
            &script_desc,
            &internal_desc,
        )
        .is_err());
    assert!(store
        .key_descriptors(&SerializedKey([0x05; 33]))
        .unwrap()
        .is_none());
}

/// Exercises a [`UniverseBackend`]: upsert/fetch proof leaves, root
/// recomputation (compared against [`MemoryUniverseBackend`]), key and
/// leaf listing, and universe deletion.
pub fn exercise_universe_backend(store: &mut dyn UniverseBackend) {
    let id = universe_id();

    // Unknown universe.
    assert!(store.root_node(&id).is_err());

    let (k0, l0) = universe_leaf(0);
    let (k1, l1) = universe_leaf(1);
    store.upsert_proof_leaf(&id, &k0, &l0).unwrap();
    store.upsert_proof_leaf(&id, &k1, &l1).unwrap();

    let fetched = store.fetch_proof(&id, &k0).unwrap().unwrap();
    assert_eq!(fetched.leaf.amount, 100);
    assert!(store
        .fetch_proof(
            &id,
            &LeafKey {
                outpoint: OutPoint {
                    txid: [0xBB; 32],
                    vout: 99,
                },
                script_key: SerializedKey([0x02; 33]),
            },
        )
        .unwrap()
        .is_none());

    // Root parity with the in-memory reference backend.
    let mut memory = MemoryUniverseBackend::new();
    memory.upsert_proof_leaf(&id, &k0, &l0).unwrap();
    memory.upsert_proof_leaf(&id, &k1, &l1).unwrap();
    let root = store.root_node(&id).unwrap();
    let memory_root = memory.root_node(&id).unwrap();
    assert_eq!(root.root_hash, memory_root.root_hash);
    assert_eq!(root.root_sum, memory_root.root_sum);
    assert_eq!(root.root_sum, 200);
    assert_ne!(root.root_hash, NodeHash::EMPTY);

    // Keys + leaves listing.
    let keys = store.fetch_keys(&id, &LeafKeysQuery::default()).unwrap();
    assert_eq!(keys.len(), 2);
    let leaves = store.fetch_leaves(&id).unwrap();
    assert_eq!(leaves.len(), 2);

    // Universe id listing includes ours.
    let ids = store.universe_ids().unwrap();
    assert!(ids.contains(&id));

    // Deleting the universe removes the root.
    store.delete_universe(&id).unwrap();
    assert!(store.root_node(&id).is_err());
    assert!(store
        .fetch_keys(&id, &LeafKeysQuery::default())
        .unwrap()
        .is_empty());
}

/// Exercises a [`FederationDb`]: add (idempotently) and remove
/// universe servers.
pub fn exercise_federation_db(fed: &mut dyn FederationDb) {
    let addr = ServerAddr::new("localhost:10029".into());
    fed.add_servers(&[addr.clone()]).unwrap();
    assert_eq!(fed.universe_servers().unwrap().len(), 1);

    // Duplicate is idempotent.
    fed.add_servers(&[addr.clone()]).unwrap();
    assert_eq!(fed.universe_servers().unwrap().len(), 1);

    fed.remove_servers(&[addr]).unwrap();
    assert!(fed.universe_servers().unwrap().is_empty());
}

/// Exercises a [`SupplyTreeStore`]: parity with
/// [`MemorySupplyTreeStore`] and incremental/replacement update
/// semantics.
pub fn exercise_supply_tree_store(store: &mut dyn SupplyTreeStore) {
    let mut memory = MemorySupplyTreeStore::new();

    // Parity under one group key.
    let updates = vec![ignore_update(0, 100), ignore_update(1, 250)];
    let (root, sum) = store
        .apply_supply_updates(&group_key(), &updates)
        .expect("apply");
    let (memory_root, memory_sum) = memory
        .apply_supply_updates(&group_key(), &updates)
        .expect("memory apply");
    assert_eq!(root, memory_root);
    assert_eq!(sum, memory_sum);
    assert_eq!(sum, 350);

    // Fetching the trees yields the same roots.
    let root_tree = store.fetch_root_supply_tree(&group_key()).unwrap();
    let mem_root_tree =
        memory.fetch_root_supply_tree(&group_key()).unwrap();
    assert_eq!(
        root_tree.root().unwrap().node_hash(),
        mem_root_tree.root().unwrap().node_hash()
    );

    let sub = store
        .fetch_sub_tree(&group_key(), SupplySubTree::Ignore)
        .unwrap();
    let mem_sub = memory
        .fetch_sub_tree(&group_key(), SupplySubTree::Ignore)
        .unwrap();
    assert_eq!(
        sub.root().unwrap().node_hash(),
        mem_sub.root().unwrap().node_hash()
    );
    assert_eq!(sub.root().unwrap().node_sum(), 350);

    // fetch_sub_trees returns all three sub-tree types, with the
    // ignore sub-tree carrying the applied updates.
    let subs = store.fetch_sub_trees(&group_key()).unwrap();
    assert_eq!(subs.iter().count(), 3);
    assert_eq!(
        subs.get(SupplySubTree::Ignore)
            .expect("ignore sub-tree")
            .root()
            .unwrap()
            .node_sum(),
        350
    );

    // Incremental updates accumulate; replacing a leaf at the same key
    // overwrites instead of adding. Use a second group so the parity
    // state above stays untouched.
    let (_, sum1) = store
        .apply_supply_updates(&group_key_b(), &[ignore_update(0, 100)])
        .unwrap();
    assert_eq!(sum1, 100);
    let (_, sum2) = store
        .apply_supply_updates(&group_key_b(), &[ignore_update(1, 50)])
        .unwrap();
    assert_eq!(sum2, 150);
    let (_, sum3) = store
        .apply_supply_updates(&group_key_b(), &[ignore_update(1, 75)])
        .unwrap();
    assert_eq!(sum3, 175);
}

/// Exercises a [`SupplyCommitStore`]: commitment round-trips
/// (starting/latest/by-outpoint) and pre-commitment lifecycle.
pub fn exercise_supply_commit_store(store: &mut dyn SupplyCommitStore) {
    let first = test_commitment(1, true);
    let second = test_commitment(2, false);

    assert!(store.latest_commitment(&group_key()).unwrap().is_none());

    store.insert_commitment(&group_key(), &first).unwrap();
    store.insert_commitment(&group_key(), &second).unwrap();

    let starting = store.starting_commitment(&group_key()).unwrap().unwrap();
    assert_eq!(starting.commit_point(), first.commit_point());
    assert_eq!(starting.supply_root_hash, first.supply_root_hash);
    assert_eq!(starting.supply_root_sum, 500);

    let block = starting.commitment_block.as_ref().unwrap();
    assert_eq!(block.height, 123);
    assert_eq!(block.tx_index, 1);
    assert_eq!(block.chain_fees, 42);
    assert_eq!(block.merkle_proof.as_ref().unwrap().nodes, vec![[1u8; 32]]);
    assert_eq!(
        block.hash,
        block.block_header.as_ref().unwrap().block_hash()
    );

    let latest = store.latest_commitment(&group_key()).unwrap().unwrap();
    assert_eq!(latest.commit_point(), second.commit_point());
    assert!(latest.commitment_block.is_none());
    assert_eq!(
        latest.spent_commitment,
        Some(OutPoint {
            txid: [2; 32],
            vout: 1
        })
    );

    let by_op = store
        .commitment_by_outpoint(&group_key(), &first.commit_point())
        .unwrap()
        .unwrap();
    assert_eq!(by_op.commit_point(), first.commit_point());

    assert!(store
        .commitment_by_outpoint(
            &group_key(),
            &OutPoint {
                txid: [0xEE; 32],
                vout: 0
            }
        )
        .unwrap()
        .is_none());

    // Pre-commitments: insert, list unspent, mark spent.
    let pre_commit = PreCommitment {
        block_height: 90,
        minting_txn: dummy_tx(9, 1000, vec![0x51, 0x20, 0x09]),
        out_idx: 0,
        internal_key: group_key(),
        group_pub_key: group_key(),
    };
    store.insert_pre_commit(&pre_commit).unwrap();

    let unspent = store.unspent_pre_commits(&group_key()).unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].out_point(), pre_commit.out_point());
    assert_eq!(unspent[0].block_height, 90);

    store
        .mark_pre_commit_spent(
            &pre_commit.out_point(),
            &first.commit_point(),
        )
        .unwrap();
    assert!(store.unspent_pre_commits(&group_key()).unwrap().is_empty());

    // Marking a missing pre-commitment fails.
    assert_eq!(
        store
            .mark_pre_commit_spent(
                &OutPoint {
                    txid: [0xDD; 32],
                    vout: 7
                },
                &first.commit_point(),
            )
            .unwrap_err(),
        "pre-commitment not found"
    );
}

/// Exercises a [`SupplyStagingStore`]: staged update upsert/list/
/// remove semantics plus the key/group metadata.
pub fn exercise_supply_staging_store(store: &mut dyn SupplyStagingStore) {
    // Empty store: no groups, no updates.
    assert!(store.groups_with_staged_updates().unwrap().is_empty());
    assert!(store.staged_updates(&group_key()).unwrap().is_empty());

    let first = ignore_update(0, 100);
    let second = ignore_update(1, 250);
    store.stage_update(&group_key(), &first).unwrap();
    store.stage_update(&group_key(), &second).unwrap();

    // Re-staging the same leaf key upserts instead of adding.
    let first_replaced = ignore_update(0, 175);
    assert_eq!(
        first.universe_leaf_key(),
        first_replaced.universe_leaf_key()
    );
    store.stage_update(&group_key(), &first_replaced).unwrap();

    let staged = store.staged_updates(&group_key()).unwrap();
    assert_eq!(staged.len(), 2);
    let sums: Vec<u64> = staged
        .iter()
        .map(|u| u.universe_leaf_node().unwrap().node_sum())
        .collect();
    assert_eq!(sums, vec![175, 250]);

    // The staged encodings match the event encodings.
    assert_eq!(staged[0].encode(), first_replaced.encode());
    assert_eq!(staged[1].encode(), second.encode());

    assert_eq!(
        store.groups_with_staged_updates().unwrap(),
        vec![group_key()]
    );

    // Consuming a subset removes exactly those rows; removing a
    // missing row is a no-op.
    store
        .remove_staged_updates(
            &group_key(),
            &[first_replaced.clone(), ignore_update(9, 1)],
        )
        .unwrap();
    let staged = store.staged_updates(&group_key()).unwrap();
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].encode(), second.encode());

    store
        .remove_staged_updates(&group_key(), &[second.clone()])
        .unwrap();
    assert!(store.staged_updates(&group_key()).unwrap().is_empty());
    assert!(store.groups_with_staged_updates().unwrap().is_empty());

    // Key descriptors.
    let desc = KeyDescriptor {
        family: 212,
        index: 7,
        pub_key: valid_script_key(),
    };
    assert!(store.key_descriptor(&valid_script_key()).unwrap().is_none());
    store.save_key_descriptor(&desc).unwrap();
    assert_eq!(
        store.key_descriptor(&valid_script_key()).unwrap(),
        Some(desc)
    );

    // Delegation keys and asset groups.
    assert!(store.delegation_key(&group_key()).unwrap().is_none());
    store
        .set_delegation_key(&group_key(), &valid_script_key())
        .unwrap();
    assert_eq!(
        store.delegation_key(&group_key()).unwrap(),
        Some(valid_script_key())
    );

    let asset_id = AssetId([0x5A; 32]);
    assert!(store.asset_group(&asset_id).unwrap().is_none());
    store.map_asset_group(&asset_id, &group_key()).unwrap();
    assert_eq!(store.asset_group(&asset_id).unwrap(), Some(group_key()));
}

/// Exercises an [`IgnoreTupleStore`]: insert/list/is_ignored plus the
/// group-scoping invariant.
pub fn exercise_ignore_store(store: &mut dyn IgnoreTupleStore) {
    let tuples = vec![signed_tuple(0, 10), signed_tuple(1, 20)];

    store.insert_tuples(&group_key(), &tuples).unwrap();

    let mut listed = store.list_tuples(&group_key()).unwrap();
    listed.sort_by_key(|t| t.tuple.prev_id.out_point.vout);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0], tuples[0]);
    assert_eq!(listed[1], tuples[1]);

    assert!(store
        .is_ignored(&group_key(), &tuples[0].tuple.prev_id)
        .unwrap());
    assert!(store
        .is_ignored(&group_key(), &tuples[1].tuple.prev_id)
        .unwrap());

    let mut other = tuples[0].tuple.prev_id.clone();
    other.out_point.vout = 99;
    assert!(!store.is_ignored(&group_key(), &other).unwrap());

    // A tuple ignored under group A must NOT make the same asset point
    // ignored under group B.
    assert!(!store
        .is_ignored(&group_key_b(), &tuples[0].tuple.prev_id)
        .unwrap());
    assert!(store.list_tuples(&group_key_b()).unwrap().is_empty());

    // Re-inserting an already-known asset point replaces the tuple.
    let mut replaced = tuples[0].clone();
    replaced.tuple.amount = 33;
    store
        .insert_tuples(&group_key(), &[replaced.clone()])
        .unwrap();
    let mut listed = store.list_tuples(&group_key()).unwrap();
    listed.sort_by_key(|t| t.tuple.prev_id.out_point.vout);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0], replaced);
}

/// Exercises a namespaced MS-SMT [`TreeStoreViewTx`] +
/// [`TreeStoreUpdateTx`] backend for parity with the in-memory
/// [`DefaultStore`]: identical inserts and deletes must produce
/// identical roots, and leaf lookups must work through the store.
///
/// `take_error` surfaces any latched write error of the store (the
/// update half of the trait is infallible by signature); pass a
/// closure returning `None` for stores that report errors eagerly.
pub fn exercise_tree_store<S>(
    store: S,
    take_error: impl Fn(&S) -> Option<String>,
) where
    S: TreeStoreViewTx + TreeStoreUpdateTx,
{
    fn make_key(byte: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = byte;
        key
    }

    let mut tree = CompactedTree::new(store);
    let mut memory_tree = CompactedTree::new(DefaultStore::new());

    for i in 0..10u8 {
        let key = make_key(i);
        let leaf = LeafNode::new(vec![i, i + 1, i + 2], (i as u64 + 1) * 10);
        tree.insert(key, leaf.clone()).unwrap();
        memory_tree.insert(key, leaf).unwrap();
        assert!(take_error(&tree.store).is_none());
    }

    let root = tree.root().unwrap();
    let memory_root = memory_tree.root().unwrap();
    assert_eq!(root.node_hash(), memory_root.node_hash());
    assert_eq!(root.node_sum(), memory_root.node_sum());

    // Leaf lookup works through the persistent store.
    let leaf = tree.get(make_key(3)).unwrap();
    assert_eq!(leaf.node_sum(), 40);

    // Deleting a leaf keeps the trees in lockstep.
    tree.delete(make_key(1)).unwrap();
    memory_tree.delete(make_key(1)).unwrap();
    assert!(take_error(&tree.store).is_none());
    assert_eq!(
        tree.root().unwrap().node_hash(),
        memory_tree.root().unwrap().node_hash()
    );
    // 10 leaves summing to 550, minus the deleted leaf's 20.
    assert_eq!(tree.root().unwrap().node_sum(), 530);
}

// ---------------------------------------------------------------------------
// Local verification of the exercises against the Memory and SQLite
// backends.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::asset_store::MemoryAssetStore;
    use crate::batch_store::MemoryBatchStore;
    use crate::ignore_store::MemoryIgnoreStore;
    use crate::mailbox_store::MemoryMailboxStore;
    use crate::pending_anchor_store::MemoryPendingAnchorStore;
    use crate::proof_store::MemoryProofStore;
    use crate::supply_store::{
        MemorySupplyCommitStore, MemorySupplyStagingStore,
    };
    use tap_universe::memory::MemoryFederationDb;

    #[test]
    fn test_memory_stores_pass_exercises() {
        exercise_asset_store(&mut MemoryAssetStore::new());
        exercise_burn_records(&mut MemoryAssetStore::new());
        exercise_batch_store(&mut MemoryBatchStore::new());
        exercise_proof_store(&mut MemoryProofStore::new());
        exercise_pending_anchor_store(&mut MemoryPendingAnchorStore::new());
        exercise_mailbox_store(&mut MemoryMailboxStore::new());
        exercise_universe_backend(&mut MemoryUniverseBackend::new());
        exercise_federation_db(&mut MemoryFederationDb::new());
        exercise_supply_tree_store(&mut MemorySupplyTreeStore::new());
        exercise_supply_commit_store(&mut MemorySupplyCommitStore::new());
        exercise_supply_staging_store(&mut MemorySupplyStagingStore::new());
        exercise_ignore_store(&mut MemoryIgnoreStore::new());
        exercise_tree_store(DefaultStore::new(), |_| None);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_sqlite_stores_pass_exercises() {
        use std::sync::Arc;

        use crate::ignore_store::SqliteIgnoreStore;
        use crate::mailbox_store::SqliteMailboxStore;
        use crate::mssmt_store::SqliteTreeStore;
        use crate::pending_anchor_store::SqlitePendingAnchorStore;
        use crate::sqlite::{
            SqliteAssetStore, SqliteBatchStore, SqliteDb, SqliteProofStore,
        };
        use crate::supply_store::{
            SqliteSupplyCommitStore, SqliteSupplyStagingStore,
            SqliteSupplyTreeStore,
        };
        use crate::universe_store::{
            SqliteFederationDb, SqliteUniverseBackend,
        };

        let db = Arc::new(SqliteDb::open_in_memory().unwrap());

        exercise_asset_store(&mut SqliteAssetStore::new(Arc::clone(&db)));
        exercise_burn_records(&mut SqliteAssetStore::new(Arc::clone(&db)));
        exercise_batch_store(&mut SqliteBatchStore::new(Arc::clone(&db)));
        exercise_proof_store(&mut SqliteProofStore::new(Arc::clone(&db)));
        exercise_pending_anchor_store(&mut SqlitePendingAnchorStore::new(
            Arc::clone(&db),
        ));
        exercise_mailbox_store(&mut SqliteMailboxStore::new(Arc::clone(
            &db,
        )));
        exercise_universe_backend(&mut SqliteUniverseBackend::new(
            Arc::clone(&db),
        ));
        exercise_federation_db(&mut SqliteFederationDb::new(Arc::clone(
            &db,
        )));
        exercise_supply_tree_store(&mut SqliteSupplyTreeStore::new(
            Arc::clone(&db),
        ));
        exercise_supply_commit_store(&mut SqliteSupplyCommitStore::new(
            Arc::clone(&db),
        ));
        exercise_supply_staging_store(&mut SqliteSupplyStagingStore::new(
            Arc::clone(&db),
        ));
        exercise_ignore_store(&mut SqliteIgnoreStore::new(Arc::clone(&db)));
        exercise_tree_store(
            SqliteTreeStore::new(Arc::clone(&db), "testkit-ns"),
            |store| store.take_error().map(|e| e.to_string()),
        );
    }
}
