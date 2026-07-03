// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! High-level minting operations, mirroring the Go `tapgarden` planter
//! semantics pragmatically.
//!
//! Full flow: queue seedlings -> freeze -> commit with placeholder ->
//! fund (discovering the real genesis point) -> recommit with the real
//! genesis point -> patch PSBT -> sign -> broadcast -> persist minted
//! assets -> watch for confirmation (via `TapNode::tick`) -> generate
//! genesis proofs -> register with universes -> finalize.

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{
    AssetSigner, ChainBridge, KeyRing, TxConfirmation, WalletAnchor,
};
use tap_onchain::mint::{BatchState, MintingBatch, Seedling};
use tap_onchain::proof::generate::GenesisProofParams;
use tap_onchain::psbt::genesis::create_genesis_template;
use tap_persist::asset_store::OwnedAsset;
use tap_persist::proof_store::ProofLocator;
use tap_primitives::asset::{
    SerializedKey, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof;

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
use crate::tasks::{AnchorKind, MintAnchor, PendingAnchor};
use crate::types::{MintResult, MintedAsset};

/// Queues an asset seedling for the next mint batch.
pub(crate) fn queue_mint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    seedling: Seedling,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let mut planter = node.planter.lock().expect("planter lock");
    planter.queue_seedling(seedling)?;
    Ok(())
}

/// Finalizes the pending mint batch.
///
/// Orchestrates the mint pipeline up to broadcast:
/// 1. Freeze the batch.
/// 2. Derive the internal key for the genesis output.
/// 3. Commit with a placeholder genesis point and fund the PSBT once,
///    discovering the wallet's selected input (the real genesis point)
///    and the TAP output index.
/// 4. Re-commit the SAME batch with the real genesis point
///    ([`tap_onchain::mint::Planter::recommit_batch`]), preserving
///    seedling metadata, script key overrides, and the batch key.
/// 5. Rebuild the TAP output script from the recommitted root
///    commitment and patch it into the funded PSBT.
/// 6. Sign, broadcast, and persist the batch and the minted assets.
/// 7. Register the transaction with the confirmation watcher; the
///    batch is confirmed/finalized (with genesis proof generation and
///    universe registration) by [`TapNode::tick`](crate::TapNode::tick).
pub(crate) fn finalize_mint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<MintResult, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let result = finalize_mint_inner(node);

    // On failure, cancel and clear the batch so the next mint starts
    // fresh. On success the batch was already taken by the inner flow
    // and handed to the confirmation watcher.
    if result.is_err() {
        let mut planter = node.planter.lock().expect("planter lock");
        let _ = planter.cancel_batch();
        let _ = planter.take_batch();
    }

    result
}

fn finalize_mint_inner<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<MintResult, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Concurrency note: the planter lock held for the whole flow (up
    // to the post-broadcast take_batch) serializes concurrent
    // finalize_mint calls, and the mint only INSERTS new asset rows
    // (it never selects-then-spends existing ones), so it does not
    // race with `send_asset` and needs no `send_lock`.
    let mut planter = node.planter.lock().expect("planter lock");

    // Step 1: Freeze the batch.
    planter.freeze_batch()?;

    // Step 1b: Assign each seedling a distinct, wallet-derived BIP-86
    // script key with a stored descriptor (Go derives a fresh
    // NewScriptKeyBip86 per asset). Sibling assets in a multi-asset
    // batch would otherwise share the default batch-key script key,
    // colliding in the proof store (one proof locator per (outpoint,
    // script key)) and lacking independently spendable descriptors. The
    // descriptors are recorded here and attached when the sprouted
    // assets are persisted.
    let seedling_names: Vec<String> = {
        let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
            tap_onchain::mint::MintError::NoPendingBatch,
        ))?;
        batch.seedlings.keys().cloned().collect()
    };
    let mut script_key_descs: std::collections::HashMap<
        SerializedKey,
        tap_onchain::chain::KeyDescriptor,
    > = std::collections::HashMap::new();
    for name in &seedling_names {
        let desc = node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
        let script_key =
            tap_primitives::asset::ScriptKey::bip86(desc.pub_key);
        script_key_descs.insert(script_key.pub_key, desc);
        planter
            .set_seedling_script_key(name, script_key)
            .map_err(TapNodeError::Mint)?;
    }

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    let batch_key = batch.batch_key.clone();
    save_batch(node, batch)?;
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key: batch_key.pub_key,
        new_state: BatchState::Frozen,
    });

    // Step 2: Derive an internal key for the genesis output.
    let internal_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let internal_x_only = x_only_from_serialized(&internal_key_desc.pub_key)?;

    // Step 3: Fund-once genesis point discovery.
    //
    // We fund a PSBT with a placeholder commitment to discover which
    // UTXO the wallet selects. Then we re-commit with the real genesis
    // point (derived from the first input) and patch the TAP output
    // in-place, avoiding a second call to fund_psbt (which could pick
    // a different UTXO).
    let fee_rate = node.chain.estimate_fee(node.config.default_conf_target)?;

    let placeholder = tap_primitives::asset::OutPoint {
        txid: [0u8; 32],
        vout: 0,
    };
    planter.commit_batch(placeholder, 0)?;

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    let dummy_commitment = batch
        .root_asset_commitment
        .as_ref()
        .ok_or(TapNodeError::Storage("no commitment".into()))?;

    let dummy_template = create_genesis_template(
        &internal_x_only,
        dummy_commitment.commitment(),
        Amount::from_sat(330),
    )
    .map_err(|e| TapNodeError::Storage(format!("template: {}", e)))?;

    let dummy_tx = bitcoin::consensus::serialize(&dummy_template.tx);
    let funded = node.wallet.fund_psbt(&dummy_tx, fee_rate)?;

    let mut psbt = bitcoin::psbt::Psbt::deserialize(&funded)
        .map_err(|e| TapNodeError::Storage(format!("PSBT: {}", e)))?;

    let real_genesis_point = {
        let inp = psbt
            .unsigned_tx
            .input
            .first()
            .ok_or(TapNodeError::Storage("no inputs".into()))?;
        let op = inp.previous_output;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(op.txid.as_ref());
        tap_primitives::asset::OutPoint { txid, vout: op.vout }
    };

    // Find the 330-sat P2TR output — this is the TAP commitment output.
    // The wallet may reorder outputs, so we can't assume index 0.
    let tap_output_index = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| {
            o.value == Amount::from_sat(330) && o.script_pubkey.is_p2tr()
        })
        .ok_or(TapNodeError::Storage(
            "no 330-sat P2TR output in funded PSBT".into(),
        ))? as u32;

    // Step 4: Re-commit the SAME batch with the real genesis point and
    // output index. The seedlings (including metadata and script key
    // overrides) and the original batch key are preserved.
    planter.recommit_batch(real_genesis_point, tap_output_index)?;

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    let tap_commitment = batch
        .root_asset_commitment
        .as_ref()
        .ok_or(TapNodeError::Storage("no commitment".into()))?;

    // Step 5: Rebuild the TAP output script from the recommitted root
    // commitment and patch it into the funded PSBT.
    let (real_script, _output_key) =
        tap_onchain::psbt::commitment::create_tap_output_script(
            &internal_x_only,
            tap_commitment.commitment(),
            None,
        )
        .map_err(|e| TapNodeError::Storage(format!("tap output: {}", e)))?;

    psbt.unsigned_tx.output[tap_output_index as usize].script_pubkey =
        real_script;

    let funded = psbt.serialize();

    save_batch(node, batch)?;
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key: batch_key.pub_key,
        new_state: BatchState::Committed,
    });

    // Step 6: Sign and finalize.
    let signed_tx_bytes = node.wallet.sign_and_finalize_psbt(&funded)?;

    // Step 7: Broadcast.
    node.chain.publish_transaction(&signed_tx_bytes)?;

    // Extract the txid. `txid_internal` is the little-endian order
    // used by outpoints and proofs; `txid_display` is the reversed,
    // explorer-facing order used in `MintResult` and events.
    let tx = bitcoin::consensus::deserialize::<bitcoin::Transaction>(
        &signed_tx_bytes,
    )
    .map_err(|e| {
        TapNodeError::Storage(format!("signed tx parse: {}", e))
    })?;
    let mut txid_internal = [0u8; 32];
    txid_internal.copy_from_slice(tx.compute_txid().as_ref());
    let mut txid_display = txid_internal;
    txid_display.reverse();

    // Step 8: Take the batch, mark it broadcast, persist it. From here
    // on, storage failures are non-fatal: the transaction is already
    // on the network.
    let mut batch = planter.take_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    drop(planter);

    batch.genesis_psbt = Some(funded.clone());
    batch.signed_tx = Some(signed_tx_bytes.clone());
    batch.state = BatchState::Broadcast;
    let _ = save_batch(node, &batch);
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key: batch_key.pub_key,
        new_state: BatchState::Broadcast,
    });

    // Step 9: Persist the minted assets from the batch's ACTUAL
    // sprouted assets: real genesis (including the seedling meta hash)
    // and real script keys.
    let anchor_outpoint = tap_primitives::asset::OutPoint {
        txid: txid_internal,
        vout: tap_output_index,
    };
    let mut minted_assets = Vec::with_capacity(batch.sprouted_assets.len());
    for asset in &batch.sprouted_assets {
        let asset_id = asset.genesis.id();

        // The script key descriptor is the one derived for this asset's
        // BIP-86 script key in step 1b (raw key behind the tweak). An
        // asset whose script key was overridden externally has no known
        // descriptor here.
        let script_key_desc =
            script_key_descs.get(&asset.script_key.pub_key).cloned();

        let mut owned = OwnedAsset::new(
            asset_id,
            asset.amount,
            anchor_outpoint,
            asset.script_key.pub_key,
            0,
        );
        owned.script_key_desc = script_key_desc;
        owned.internal_key = Some(internal_key_desc.clone());
        owned.genesis_point = Some(asset.genesis.first_prev_out);
        owned.genesis_tag = Some(asset.genesis.tag.clone());
        owned.genesis_meta_hash = Some(asset.genesis.meta_hash);
        owned.genesis_output_index = Some(asset.genesis.output_index);
        owned.genesis_asset_type = Some(asset.genesis.asset_type);
        node.asset_store
            .lock()
            .expect("asset store lock")
            .insert_asset(owned)
            .map_err(TapNodeError::Storage)?;

        minted_assets.push(MintedAsset {
            asset_id,
            name: asset.genesis.tag.clone(),
            amount: asset.amount,
            script_key: asset.script_key.pub_key,
        });
    }

    // Step 10: Register the mint transaction with the confirmation
    // watcher. Confirmation, genesis proof generation, and universe
    // registration happen in `TapNode::tick`. The anchor is written
    // through to the durable pending-anchor store first, so a restart
    // between broadcast and confirmation still finishes the mint.
    let anchor = PendingAnchor {
        txid: txid_internal,
        kind: AnchorKind::Mint(MintAnchor {
            batch,
            internal_key: internal_key_desc.pub_key,
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

    Ok(MintResult {
        batch_key: batch_key.pub_key,
        txid: Some(txid_display),
        assets: minted_assets,
        internal_key: internal_key_desc.pub_key,
        signed_tx: signed_tx_bytes,
        genesis_point: real_genesis_point,
        funded_psbt: funded,
        tap_output_index,
    })
}

/// Finishes a confirmed mint: updates the batch state, generates the
/// genesis proofs from the real chain data, stores them, registers
/// them with the local universe and the configured universe servers,
/// and finalizes the batch. Called from
/// [`TapNode::tick`](crate::TapNode::tick).
pub(crate) fn finish_mint_confirmation<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    mut anchor: MintAnchor,
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
    let batch = &mut anchor.batch;
    let batch_key = batch.batch_key.pub_key;

    batch.confirmation = Some(conf.clone());
    batch.state = BatchState::Confirmed;
    let _ = save_batch(node, batch);
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key,
        new_state: BatchState::Confirmed,
    });

    let genesis_point = batch.genesis_outpoint.ok_or_else(|| {
        TapNodeError::Storage("broadcast batch has no genesis point".into())
    })?;
    let tap_output_index = batch.mint_output_index.unwrap_or(0);

    let anchor_tx_bytes = if conf.tx.is_empty() {
        batch.signed_tx.clone().ok_or_else(|| {
            TapNodeError::Storage(
                "no anchor transaction bytes for confirmed mint".into(),
            )
        })?
    } else {
        conf.tx.clone()
    };
    let block_tx_hashes = if conf.block_tx_hashes.is_empty() {
        vec![txid_internal]
    } else {
        conf.block_tx_hashes.clone()
    };

    let anchor_outpoint = tap_primitives::asset::OutPoint {
        txid: txid_internal,
        vout: tap_output_index,
    };

    // The minted assets were persisted with block height 0 at
    // broadcast time; record the real confirmation height on every
    // asset at the mint anchor outpoint. Idempotent, like the other
    // finish steps, so a retry after a partial failure is harmless.
    node.asset_store
        .lock()
        .expect("asset store lock")
        .set_anchor_block_height(&anchor_outpoint, conf.block_height)
        .map_err(TapNodeError::Storage)?;

    for asset in &batch.sprouted_assets {
        let asset_id = asset.genesis.id();
        let meta_reveal = batch
            .seedlings
            .get(&asset.genesis.tag)
            .and_then(|s| s.meta.clone());

        // NOTE: exclusion proofs for the wallet's BTC change output
        // are omitted (we do not know its internal key). Go includes
        // them; universe servers only require the inclusion proof.
        let genesis_proof =
            tap_onchain::proof::generate_genesis_proof(GenesisProofParams {
                anchor_tx_bytes: anchor_tx_bytes.clone(),
                block_header: conf.block_header,
                block_height: conf.block_height,
                tx_index: conf.tx_index as usize,
                block_tx_hashes: block_tx_hashes.clone(),
                prev_out: genesis_point,
                asset: asset.clone(),
                tap_output_index,
                internal_key: anchor.internal_key,
                commitment: batch.root_asset_commitment.clone(),
                commitment_proof: None,
                exclusion_proofs: vec![],
                genesis_reveal: asset.genesis.clone(),
                meta_reveal,
                group_key_reveal: None,
            })
            .map_err(TapNodeError::Storage)?;

        let proof_bytes = proof::encode::encode_proof(&genesis_proof);

        // Store the genesis proof file.
        let mut file = proof::file::File::new();
        file.append_proof(proof_bytes.clone());
        node.proof_store
            .lock()
            .expect("proof store lock")
            .insert_proof(
                ProofLocator {
                    outpoint: anchor_outpoint,
                    script_key: asset.script_key.pub_key,
                },
                file,
            )
            .map_err(TapNodeError::Storage)?;

        // Register the issuance proof with the node's local universe.
        let universe_id = tap_universe::types::UniverseId {
            asset_id,
            group_key: None,
            proof_type: tap_universe::types::ProofType::Issuance,
        };
        let leaf_key = tap_universe::types::LeafKey {
            outpoint: anchor_outpoint,
            script_key: asset.script_key.pub_key,
        };
        let leaf = tap_universe::types::UniverseLeaf {
            asset_id,
            amount: asset.amount,
            proof: proof_bytes.clone(),
            key: leaf_key.clone(),
        };
        let _ = node
            .universe_backend
            .lock()
            .expect("universe backend lock")
            .upsert_proof_leaf(&universe_id, &leaf_key, &leaf);

        // Best-effort registration with the configured remote universe
        // servers.
        for server_url in &node.config.universe_servers {
            let client =
                tap_universe::http_client::HttpUniverseClient::new(
                    server_url,
                );
            let _ = client.insert_proof(
                &asset_id,
                tap_universe::types::ProofType::Issuance,
                &anchor_outpoint,
                &asset.script_key.pub_key,
                &proof_bytes,
            );
        }
    }

    batch.state = BatchState::Finalized;
    let _ = save_batch(node, batch);
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key,
        new_state: BatchState::Finalized,
    });

    Ok(())
}

/// Cancels the pending mint batch.
pub(crate) fn cancel_mint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let mut planter = node.planter.lock().expect("planter lock");
    planter.cancel_batch()?;
    Ok(())
}

/// Persists a batch snapshot to the batch store.
fn save_batch<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    batch: &MintingBatch,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    node.batch_store
        .lock()
        .expect("batch store lock")
        .save_batch(batch)
        .map_err(TapNodeError::Storage)
}

/// Extracts an x-only public key from a 33-byte compressed key.
fn x_only_from_serialized(
    key: &SerializedKey,
) -> Result<XOnlyPublicKey, TapNodeError> {
    XOnlyPublicKey::from_slice(&key.0[1..]).map_err(|e| {
        TapNodeError::Storage(format!("invalid x-only key: {}", e))
    })
}
