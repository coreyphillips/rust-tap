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
use tap_onchain::mint::{BatchState, MintError, MintingBatch, Seedling};
use tap_onchain::proof::generate::GenesisProofParams;
use tap_onchain::psbt::genesis::create_genesis_template;
use tap_persist::asset_store::OwnedAsset;
use tap_persist::proof_store::ProofLocator;
use tap_primitives::asset::{
    GroupKey, GroupKeyReveal, GroupKeyRevealV1, GroupKeyVersion,
    SerializedKey, PEDERSEN_VERSION, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof;

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
use crate::tasks::{AnchorKind, MintAnchor, PendingAnchor};
use crate::types::{MintResult, MintedAsset};

/// Queues an asset seedling for the next mint batch.
///
/// When the seedling's metadata opts into universe supply commitments
/// but carries no delegation key, one is derived from the node's key
/// ring and injected (Go's tapgarden equally resolves the delegation
/// key during minting); the descriptor is persisted so the node can
/// later sign with it (pre-commitment spends, ignore tuples).
pub(crate) fn queue_mint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    mut seedling: Seedling,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    if let Some(meta) = seedling.meta.as_mut() {
        if meta.universe_commitments && meta.delegation_key.is_none() {
            let desc =
                node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
            node.supply_staging_store
                .lock()
                .expect("supply staging store lock")
                .save_key_descriptor(&desc)
                .map_err(TapNodeError::Storage)?;
            meta.delegation_key = Some(desc.pub_key);
        }
    }

    let mut planter = node.planter.lock().expect("planter lock");
    planter.queue_seedling(seedling)?;
    Ok(())
}

/// Returns whether the seedling mints into an asset group: explicit
/// emission enablement or universe supply commitments (which are only
/// defined for grouped assets, matching Go).
fn seedling_is_grouped(seedling: &Seedling) -> bool {
    seedling.enable_emission
        || seedling
            .meta
            .as_ref()
            .map(|m| m.universe_commitments)
            .unwrap_or(false)
}

/// Returns whether the seedling opted into universe supply
/// commitments.
fn seedling_wants_supply_commitments(seedling: &Seedling) -> bool {
    seedling
        .meta
        .as_ref()
        .map(|m| m.universe_commitments)
        .unwrap_or(false)
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

    // Universe supply commitments: seedlings that opted in share a
    // single pre-commitment output paying to the delegation key. Go's
    // tapgarden adds one pre-commitment output per batch
    // (unfundedAnchorPsbt, planter.go:718), so a batch supports one
    // universe-commitments delegation key.
    let delegation_key = {
        let mut keys: Vec<SerializedKey> = Vec::new();
        for seedling in batch.seedlings.values() {
            if !seedling_wants_supply_commitments(seedling) {
                continue;
            }
            let key = seedling
                .meta
                .as_ref()
                .and_then(|m| m.delegation_key)
                .ok_or_else(|| {
                    TapNodeError::Supply(
                        "universe commitments require a delegation key \
                         in the seedling metadata"
                            .into(),
                    )
                })?;
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        if keys.len() > 1 {
            return Err(TapNodeError::Supply(
                "a mint batch supports at most one universe-commitments \
                 delegation key"
                    .into(),
            ));
        }
        keys.into_iter().next()
    };

    // Tags of the seedlings minting into asset groups.
    let grouped_tags: Vec<String> = batch
        .seedlings
        .values()
        .filter(|s| seedling_is_grouped(s))
        .map(|s| s.asset_name.clone())
        .collect();

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

    // Universe supply commitments: append the pre-commitment output,
    // a P2TR output paying to the BIP-86 tweak of the delegation key
    // with 1000 sats (Go's tapgarden.PreCommitTxOut, planter.go:3327,
    // appended after the asset anchor output in unfundedAnchorPsbt).
    // It does not depend on the genesis point, so it stays valid
    // through the fund-once re-commit.
    let mut template_tx = dummy_template.tx;
    if let Some(dk) = &delegation_key {
        let (value, script) = tap_universe::supply::pre_commit_tx_out(dk)
            .map_err(|e| TapNodeError::Supply(e.to_string()))?;
        template_tx.output.push(bitcoin::TxOut {
            value: Amount::from_sat(value),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        });
    }

    let dummy_tx = bitcoin::consensus::serialize(&template_tx);
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

    // Step 4b: Attach group keys and group genesis witnesses to the
    // grouped assets, then rebuild the batch commitment (grouped
    // assets are keyed by group key in the TAP commitment). This must
    // happen after the re-commit because the group key derivation
    // commits to the final asset ID, which depends on the real genesis
    // point.
    let mut group_reveals: Vec<(String, GroupKeyReveal)> = Vec::new();
    if !grouped_tags.is_empty() {
        let keys = &node.keys;
        let reveals = &mut group_reveals;
        planter.update_sprouted_assets(|assets| {
            attach_group_keys(&**keys, assets, &grouped_tags, reveals)
        })?;
    }

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
            group_key: asset.group_key.as_ref().map(|gk| gk.group_pub_key),
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
            group_reveals,
            delegation_key,
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

    // When the anchor transaction carries a supply pre-commitment
    // output (an extra P2TR output), the genesis proofs must carry an
    // exclusion proof for it: a BIP-86 tapscript proof for the
    // delegation key (Go equally excludes the pre-commitment output
    // from the asset commitment proofs).
    let pre_commit_exclusion = match &anchor.delegation_key {
        Some(dk) => {
            let anchor_tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&anchor_tx_bytes).map_err(
                    |e| TapNodeError::Storage(format!("anchor tx: {}", e)),
                )?;
            let (value, script) =
                tap_universe::supply::pre_commit_tx_out(dk)
                    .map_err(|e| TapNodeError::Supply(e.to_string()))?;
            let out_idx = anchor_tx
                .output
                .iter()
                .position(|out| {
                    out.value.to_sat() == value
                        && out.script_pubkey.as_bytes() == script.as_slice()
                })
                .ok_or_else(|| {
                    TapNodeError::Supply(
                        "confirmed mint anchor transaction has no \
                         pre-commitment output"
                            .into(),
                    )
                })?;
            Some(proof::TaprootProof {
                output_index: out_idx as u32,
                internal_key: *dk,
                commitment_proof: None,
                tapscript_proof: Some(proof::TapscriptProof {
                    tap_preimage_1: None,
                    tap_preimage_2: None,
                    bip86: true,
                    unknown_odd_types: std::collections::BTreeMap::new(),
                }),
                unknown_odd_types: std::collections::BTreeMap::new(),
            })
        }
        None => None,
    };

    for asset in &batch.sprouted_assets {
        let asset_id = asset.genesis.id();
        let meta_reveal = batch
            .seedlings
            .get(&asset.genesis.tag)
            .and_then(|s| s.meta.clone());
        let group_key_reveal = anchor
            .group_reveals
            .iter()
            .find(|(tag, _)| *tag == asset.genesis.tag)
            .map(|(_, reveal)| reveal.clone());

        // NOTE: exclusion proofs for the wallet's BTC change output
        // are omitted (we do not know its internal key). Go includes
        // them; universe servers only require the inclusion proof.
        // The pre-commitment output (P2TR) does get an exclusion
        // proof, as full proof verification demands one for every
        // other P2TR output.
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
                exclusion_proofs: pre_commit_exclusion
                    .clone()
                    .into_iter()
                    .collect(),
                genesis_reveal: asset.genesis.clone(),
                meta_reveal,
                group_key_reveal,
            })
            .map_err(TapNodeError::Storage)?;

        let proof_bytes = proof::encode::encode_proof(&genesis_proof);

        // Universe supply commitments: stage the mint supply update
        // and persist the pre-commitment output for the asset group
        // (Go's caretaker sends the mint event to the supply commit
        // state machine on confirmation; caretaker.go
        // sendSupplyCommitEvents). Idempotent: staging upserts by
        // leaf key, the pre-commitment by outpoint.
        let wants_supply = batch
            .seedlings
            .get(&asset.genesis.tag)
            .map(seedling_wants_supply_commitments)
            .unwrap_or(false);
        if wants_supply {
            let delegation_key =
                anchor.delegation_key.as_ref().ok_or_else(|| {
                    TapNodeError::Supply(
                        "universe-commitments asset confirmed without a \
                         delegation key"
                            .into(),
                    )
                })?;
            let group_key = asset
                .group_key
                .as_ref()
                .map(|gk| gk.group_pub_key)
                .ok_or_else(|| {
                    TapNodeError::Supply(
                        "universe-commitments asset confirmed without a \
                         group key"
                            .into(),
                    )
                })?;

            let mint_event =
                tap_universe::supply::NewMintEvent::decode(&proof_bytes)
                    .map_err(|e| TapNodeError::Supply(e.to_string()))?;
            let pre_commit = tap_universe::supply::new_pre_commit_from_proof(
                &genesis_proof,
                delegation_key,
            )
            .map_err(|e| TapNodeError::Supply(e.to_string()))?;

            {
                let mut staging = node
                    .supply_staging_store
                    .lock()
                    .expect("supply staging store lock");
                staging
                    .set_delegation_key(&group_key, delegation_key)
                    .map_err(TapNodeError::Storage)?;
                staging
                    .map_asset_group(&asset_id, &group_key)
                    .map_err(TapNodeError::Storage)?;
                staging
                    .stage_update(
                        &group_key,
                        &tap_universe::supply::SupplyUpdateEvent::Mint(
                            mint_event,
                        ),
                    )
                    .map_err(TapNodeError::Storage)?;
            }
            node.supply_commit_store
                .lock()
                .expect("supply commit store lock")
                .insert_pre_commit(&pre_commit)
                .map_err(TapNodeError::Storage)?;
        }

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

/// Attaches a V1 group key and group genesis witness to every sprouted
/// asset whose tag is in `grouped_tags`, recording the group key
/// reveals for the genesis proofs.
///
/// Per asset: a fresh group internal key is derived from the key ring,
/// the tweaked group key is `GroupPubKeyV1(internal, tapscript(asset
/// ID), asset ID)` (asset/group_key.go:849), and the group membership
/// witness is a key-path Schnorr signature with the tweaked group key
/// over the grouped-genesis virtual transaction sighash (the signature
/// the VM checks in `validate_group_genesis_witness`). The signature
/// is produced through [`AssetSigner::sign_virtual_tx_tweaked`] with
/// the group tapscript root, which applies exactly the required
/// BIP-341 tweak to the internal key.
fn attach_group_keys<K>(
    keys: &K,
    assets: &mut [tap_primitives::asset::Asset],
    grouped_tags: &[String],
    reveals: &mut Vec<(String, GroupKeyReveal)>,
) -> Result<(), MintError>
where
    K: KeyRing + AssetSigner,
{
    use tap_primitives::crypto::virtual_tx::{
        input_group_genesis_key_spend_sighash, virtual_tx,
    };

    let commitment_err =
        |e: &dyn std::fmt::Display| MintError::CommitmentError(e.to_string());

    for asset in assets.iter_mut() {
        if !grouped_tags.contains(&asset.genesis.tag) {
            continue;
        }

        let desc = keys
            .derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)
            .map_err(MintError::Chain)?;
        let asset_id = asset.genesis.id();

        let reveal = GroupKeyRevealV1::new(
            PEDERSEN_VERSION,
            desc.pub_key,
            &asset_id,
            None,
        )
        .map_err(|e| commitment_err(&e))?;
        let group_pub = reveal
            .group_pub_key(&asset_id)
            .map_err(|e| commitment_err(&e))?;
        let tapscript_root: [u8; 32] = reveal
            .tapscript
            .root
            .as_slice()
            .try_into()
            .map_err(|_| {
                MintError::CommitmentError(
                    "group key tapscript root is not 32 bytes".into(),
                )
            })?;

        asset.group_key = Some(GroupKey {
            version: GroupKeyVersion::V1,
            raw_key: desc.pub_key,
            group_pub_key: SerializedKey(group_pub.serialize()),
            tapscript_root: tapscript_root.to_vec(),
            witness: vec![],
        });

        // The grouped-genesis virtual tx commits to only the
        // (witnessless) genesis asset itself; the sighash is stable
        // whether or not the witness is already attached.
        let empty = tap_primitives::vm::InputSet::new();
        let (base_tx, _, _) =
            virtual_tx(asset, &empty).map_err(|e| commitment_err(&e))?;
        let sighash = input_group_genesis_key_spend_sighash(
            &base_tx,
            asset,
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|e| commitment_err(&e))?;

        let sig = keys
            .sign_virtual_tx_tweaked(&desc, &sighash, Some(&tapscript_root))
            .map_err(MintError::Chain)?;
        if sig.len() != 64 {
            return Err(MintError::CommitmentError(format!(
                "expected 64-byte group witness signature, got {}",
                sig.len()
            )));
        }
        asset.prev_witnesses[0].tx_witness = vec![sig];

        reveals
            .push((asset.genesis.tag.clone(), GroupKeyReveal::V1(reveal)));
    }

    Ok(())
}

/// Extracts an x-only public key from a 33-byte compressed key.
fn x_only_from_serialized(
    key: &SerializedKey,
) -> Result<XOnlyPublicKey, TapNodeError> {
    XOnlyPublicKey::from_slice(&key.0[1..]).map_err(|e| {
        TapNodeError::Storage(format!("invalid x-only key: {}", e))
    })
}
