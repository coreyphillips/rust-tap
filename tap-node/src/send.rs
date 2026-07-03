// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! High-level asset transfer operations, mirroring Go's `tapfreighter`
//! semantics pragmatically.
//!
//! Full flow: coin select -> reconstruct real genesis + prev assets ->
//! sign virtual tx with the stored key descriptors -> build anchor
//! PSBT -> fund -> sign -> broadcast -> mark inputs spent -> persist
//! change -> watch for confirmation (via `TapNode::tick`) -> finish
//! proofs with real chain data -> store + deliver proofs.

use std::collections::{HashMap, HashSet};

use bitcoin::secp256k1::XOnlyPublicKey;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{
    AssetSigner, ChainBridge, KeyDescriptor, KeyRing, TxConfirmation,
    WalletAnchor,
};
use tap_onchain::proof::courier::{
    AnnotatedProof, CourierLocator, Recipient,
};
use tap_onchain::proof::{
    create_proof_suffix_with_options, update_proof_chain_data,
    BaseProofParams, OutputProofInfo, ProofSuffixOptions,
};
use tap_onchain::send::{
    execute_transfer_with_options, sign_passive_transition, SelectedInput,
    SendError, TransferOptions, TransferOutput, VirtualSigner,
};
use tap_persist::asset_store::OwnedAsset;
use tap_persist::proof_store::ProofLocator;
use tap_primitives::address::TapAddress;
use tap_primitives::asset::{
    derive_unique_script_key, Asset, AssetId, AssetVersion, Genesis,
    OutPoint, PrevId, ScriptKey, ScriptKeyDerivationMethod, ScriptVersion,
    SerializedKey, Witness, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof;
use tap_primitives::vm::InputSet;

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
use crate::tasks::{
    AnchorKind, PassiveAnchor, PendingAnchor, TransferAnchor,
};
use crate::types::TransferHandle;

/// Sends an asset to a TAP address.
///
/// Orchestrates the transfer pipeline up to broadcast:
/// 1. Coin select asset UTXOs.
/// 2. Reconstruct the real [`Genesis`] from the stored asset (error if
///    the genesis fields are absent) and the real previous assets
///    (from the stored proof files where available).
/// 3. Execute the transfer (validate, prepare, sign virtual tx with
///    the keys behind the input script keys, build template).
/// 4. Fund, sign, and broadcast the anchor transaction.
/// 5. Mark inputs spent and persist the change output (with its script
///    key descriptor and genesis fields).
/// 6. Create the transition proof suffixes (placeholder chain data)
///    and register the transfer with the confirmation watcher; the
///    proofs are finished, stored, and delivered by
///    [`TapNode::tick`](crate::TapNode::tick).
///
/// Emits [`TapEvent::TransferBroadcast`] at broadcast;
/// [`TapEvent::TransferConfirmed`] and [`TapEvent::ProofDelivered`]
/// follow from the watcher once the anchor transaction confirms.
pub(crate) fn send_asset<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    asset_id: AssetId,
    amount: u64,
    recipient: &TapAddress,
) -> Result<TransferHandle, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Serialize the whole send pipeline (see `TapNode::send_lock`):
    // coin selection reads unspent assets here, but the inputs are only
    // marked spent after broadcast (step 6), so without this lock two
    // concurrent sends could select and double-spend the same inputs at
    // the asset level. The passive-asset collection (step 1b) must see
    // the same consistent snapshot, so it happens under the same lock.
    let _send_guard = node.send_lock.lock().expect("send lock");

    // Step 1: Coin selection.
    let selected = coin_select(node, &asset_id, amount)?;
    let total: u64 = selected.iter().map(|a| a.amount).sum();
    if total < amount {
        return Err(TapNodeError::InsufficientBalance {
            asset_id,
            available: total,
            needed: amount,
        });
    }
    let change_amount = total - amount;

    // Step 1b: Collect the passive assets. Any OTHER unspent asset
    // anchored at one of the selected inputs' outpoints (a sibling from
    // a multi-asset mint batch, or the change of a prior transfer) would
    // be silently consumed when its anchor UTXO is spent. Mirroring Go's
    // passive assets (tapfreighter), we re-anchor each into the change
    // output instead of dropping it.
    let selected_ids: HashSet<(OutPoint, AssetId, SerializedKey)> = selected
        .iter()
        .map(|a| (a.anchor_outpoint, a.asset_id, a.script_key))
        .collect();
    let passive_owned: Vec<OwnedAsset> = {
        let store = node.asset_store.lock().expect("asset store lock");
        let mut seen_outpoints = HashSet::new();
        let mut passives = Vec::new();
        for input in &selected {
            if !seen_outpoints.insert(input.anchor_outpoint) {
                continue;
            }
            for owned in store.unspent_at_outpoint(&input.anchor_outpoint) {
                let identity =
                    (owned.anchor_outpoint, owned.asset_id, owned.script_key);
                if !selected_ids.contains(&identity) {
                    passives.push(owned);
                }
            }
        }
        passives
    };

    // Step 2: Reconstruct the real genesis from the stored asset. All
    // selected inputs share the asset ID, hence the genesis.
    let genesis = genesis_from_owned(&selected[0])?;
    if genesis.id() != asset_id {
        return Err(TapNodeError::Storage(
            "stored genesis fields do not reproduce the asset id".into(),
        ));
    }

    // The change output gets a freshly derived BIP-86 script key (the
    // transfer builder reads it from the first input's `script_key`
    // field).
    let change_script_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let change_script_key = ScriptKey::bip86(change_script_desc.pub_key);

    let inputs: Vec<SelectedInput> = selected
        .iter()
        .enumerate()
        .map(|(i, owned)| {
            let prev_id = PrevId {
                out_point: owned.anchor_outpoint,
                id: owned.asset_id,
                script_key: owned.script_key,
            };
            SelectedInput {
                prev_id,
                anchor_point: owned.anchor_outpoint,
                amount: owned.amount,
                asset_type: owned
                    .genesis_asset_type
                    .unwrap_or(tap_primitives::asset::AssetType::Normal),
                // The first input's script_key doubles as the change
                // (root) output script key in the transfer builder.
                script_key: if i == 0 {
                    change_script_key.clone()
                } else {
                    ScriptKey::from_pub_key(owned.script_key)
                },
            }
        })
        .collect();

    // Build transfer output for the recipient. Output 0 is change,
    // output 1 is the recipient.
    let outputs = vec![TransferOutput {
        output_index: 1,
        amount,
        script_key: ScriptKey::from_pub_key(recipient.script_key),
        asset_version: AssetVersion::V0,
        interactive: false,
    }];

    // Step 3: Reconstruct the real previous assets for signing.
    let mut prev_assets = InputSet::new();
    for (owned, input) in selected.iter().zip(inputs.iter()) {
        let prev_asset = prev_asset_for(node, owned, &genesis)?;
        prev_assets.insert(input.prev_id.clone(), prev_asset);
    }

    // The signer maps each input's (tweaked) script key to its stored
    // key descriptor plus the taproot tweak the seam must apply (None
    // for BIP-86 keys, the recomputed Pedersen leaf tap hash for V2
    // unique script keys); signing an input whose descriptor is
    // unknown fails with `SendError::UnknownScriptKey`. The passive
    // assets are signed with their own stored script key descriptors,
    // so their keys must be resolvable by the same signer.
    let mut keys_by_script_key: HashMap<
        SerializedKey,
        (KeyDescriptor, Option<[u8; 32]>),
    > = HashMap::new();
    for owned in selected.iter().chain(passive_owned.iter()) {
        if let Some(desc) = &owned.script_key_desc {
            keys_by_script_key.insert(
                owned.script_key,
                (desc.clone(), tapscript_root_for(owned)),
            );
        }
    }
    let signer = NodeVirtualSigner {
        keys: &*node.keys,
        keys_by_script_key,
    };

    // Step 3b: Build and sign a full-value 1-in-1-out re-anchoring
    // transition for each passive asset (Go's CreatePassiveAssets +
    // SignPassiveAssets). Each keeps its script key and amount; its
    // PrevID points at its old anchor outpoint and its witness is signed
    // by its own key. An asset whose script key descriptor or genesis
    // fields are unknown cannot be re-anchored, so the send is refused
    // rather than silently dropping it.
    let mut passive_work: Vec<PassiveWork> = Vec::with_capacity(
        passive_owned.len(),
    );
    for owned in &passive_owned {
        if owned.script_key_desc.is_none() {
            return Err(TapNodeError::Storage(format!(
                "cannot send from an outpoint carrying passive asset {}: \
                 its script key descriptor is unknown, so it cannot be \
                 re-anchored",
                hex_id(&owned.asset_id)
            )));
        }
        let passive_genesis = genesis_from_owned(owned)?;
        let prev_id = PrevId {
            out_point: owned.anchor_outpoint,
            id: owned.asset_id,
            script_key: owned.script_key,
        };
        let prev_asset = prev_asset_for(node, owned, &passive_genesis)?;
        let signed = sign_passive_transition(
            &prev_id,
            &prev_asset,
            &passive_genesis,
            owned.amount,
            AssetVersion::V0,
            &ScriptKey::from_pub_key(owned.script_key),
            &signer,
        )
        .map_err(TapNodeError::Send)?;

        let base_file = node
            .proof_store
            .lock()
            .expect("proof store lock")
            .get_proof(&ProofLocator {
                outpoint: owned.anchor_outpoint,
                script_key: owned.script_key,
            })
            .ok()
            .flatten();

        passive_work.push(PassiveWork {
            owned: owned.clone(),
            genesis: passive_genesis,
            signed,
            base_file,
        });
    }
    let passive_assets: Vec<Asset> =
        passive_work.iter().map(|p| p.signed.clone()).collect();

    // Anchor output internal keys: a fresh key for the change output,
    // and the RECIPIENT's internal key (from the address) for the
    // recipient output, so the recipient controls their anchor.
    let change_internal_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let change_internal_x_only =
        x_only_from_serialized(&change_internal_desc.pub_key)?;
    let recipient_internal_x_only =
        x_only_from_serialized(&recipient.internal_key)?;
    let internal_keys =
        vec![change_internal_x_only, recipient_internal_x_only];

    // Execute the transfer pipeline. The Taproot Asset commitment
    // version is dictated by the recipient's address version (V1 and
    // V2 addresses require V2 commitments). Passive assets are forced
    // into a split (a tombstone change output for a full-value send) and
    // merged into the change output's commitment.
    let result = execute_transfer_with_options(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &signer,
        &internal_keys,
        &TransferOptions {
            commitment_version: recipient.commitment_version(),
            passive_assets,
            ..TransferOptions::default()
        },
    )
    .map_err(TapNodeError::Send)?;

    // Step 4: Fund the anchor transaction.
    let fee_rate = node.chain.estimate_fee(node.config.default_conf_target)?;
    let tx_bytes = bitcoin::consensus::serialize(&result.template.tx);
    let funded = node.wallet.fund_psbt(&tx_bytes, fee_rate)?;

    // Step 5: Sign and broadcast.
    let signed_tx_bytes = node.wallet.sign_and_finalize_psbt(&funded)?;
    node.chain.publish_transaction(&signed_tx_bytes)?;

    let anchor_tx = bitcoin::consensus::deserialize::<bitcoin::Transaction>(
        &signed_tx_bytes,
    )
    .map_err(|e| {
        TapNodeError::Storage(format!("signed tx parse: {}", e))
    })?;
    let mut txid_internal = [0u8; 32];
    txid_internal.copy_from_slice(anchor_tx.compute_txid().as_ref());
    let mut txid_display = txid_internal;
    txid_display.reverse();

    // Locate the change and recipient outputs in the final transaction
    // by their scripts (the funding wallet may reorder outputs). A
    // full-value send has no change TAP output at all: the anchor
    // template carries only the recipient commitment (any BTC change
    // the wallet added is a plain output).
    let (recipient_script, _) =
        tap_onchain::psbt::commitment::create_tap_output_script(
            &recipient_internal_x_only,
            result.prepared.output_commitments[0].commitment(),
            None,
        )
        .map_err(|e| TapNodeError::Storage(format!("tap output: {}", e)))?;
    let recipient_vout = anchor_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == recipient_script)
        .ok_or(TapNodeError::Storage(
            "recipient TAP output missing from signed transaction".into(),
        ))? as u32;
    let recipient_outpoint = OutPoint {
        txid: txid_internal,
        vout: recipient_vout,
    };

    let change_vout = if result.prepared.is_split {
        let (change_script, _) =
            tap_onchain::psbt::commitment::create_tap_output_script(
                &change_internal_x_only,
                result.prepared.change_commitment.commitment(),
                None,
            )
            .map_err(|e| {
                TapNodeError::Storage(format!("tap output: {}", e))
            })?;
        Some(
            anchor_tx
                .output
                .iter()
                .position(|o| o.script_pubkey == change_script)
                .ok_or(TapNodeError::Storage(
                    "change TAP output missing from signed transaction"
                        .into(),
                ))? as u32,
        )
    } else {
        None
    };
    let change_outpoint = change_vout.map(|vout| OutPoint {
        txid: txid_internal,
        vout,
    });

    // Step 6: Mark the spent inputs as spent, scoped to their exact
    // identity so sibling passive assets at the same anchor outpoint are
    // not silently flipped. Each passive asset's OLD identity is spent
    // too (it moves to the change output below).
    {
        let mut store = node.asset_store.lock().expect("asset store lock");
        for input in &selected {
            store
                .mark_spent(
                    &input.anchor_outpoint,
                    &input.asset_id,
                    &input.script_key,
                )
                .map_err(TapNodeError::Storage)?;
        }
        for passive in &passive_work {
            store
                .mark_spent(
                    &passive.owned.anchor_outpoint,
                    &passive.owned.asset_id,
                    &passive.owned.script_key,
                )
                .map_err(TapNodeError::Storage)?;
        }
    }

    // Step 7: Persist the change output as a new owned asset (never a
    // tombstone: zero-change splits use the un-spendable NUMS key).
    let has_change = result.prepared.is_split && change_amount > 0;
    if let (true, Some(change_outpoint)) = (has_change, change_outpoint) {
        let mut owned = OwnedAsset::new(
            asset_id,
            change_amount,
            change_outpoint,
            result.prepared.root_asset.script_key.pub_key,
            0,
        );
        owned.script_key_desc = Some(change_script_desc.clone());
        owned.internal_key = Some(change_internal_desc.clone());
        owned.genesis_point = Some(genesis.first_prev_out);
        owned.genesis_tag = Some(genesis.tag.clone());
        owned.genesis_meta_hash = Some(genesis.meta_hash);
        owned.genesis_output_index = Some(genesis.output_index);
        owned.genesis_asset_type = Some(genesis.asset_type);
        node.asset_store
            .lock()
            .expect("asset store lock")
            .insert_asset(owned)
            .map_err(TapNodeError::Storage)?;
    }

    // Step 7b: Persist each re-anchored passive asset at the change
    // outpoint under its unchanged script key, so it stays spendable
    // (its stored descriptor + genesis fields let follow-up sends sign
    // it). Its old identity was marked spent above. Passive assets
    // force a split, so the change output always exists here.
    for work in &passive_work {
        let change_outpoint = change_outpoint.ok_or_else(|| {
            TapNodeError::Storage(
                "passive assets present but no change output was created"
                    .into(),
            )
        })?;
        let mut owned = OwnedAsset::new(
            work.owned.asset_id,
            work.owned.amount,
            change_outpoint,
            work.owned.script_key,
            0,
        );
        owned.script_key_desc = work.owned.script_key_desc.clone();
        owned.internal_key = Some(change_internal_desc.clone());
        owned.genesis_point = Some(work.genesis.first_prev_out);
        owned.genesis_tag = Some(work.genesis.tag.clone());
        owned.genesis_meta_hash = Some(work.genesis.meta_hash);
        owned.genesis_output_index = Some(work.genesis.output_index);
        owned.genesis_asset_type = Some(work.genesis.asset_type);
        node.asset_store
            .lock()
            .expect("asset store lock")
            .insert_asset(owned)
            .map_err(TapNodeError::Storage)?;
    }

    // Step 8: Create the transition proof suffixes now (all commitment
    // data is at hand); the chain data stays a placeholder until the
    // watcher sees the confirmation.
    let prev_out = selected[0].anchor_outpoint;
    let (recipient_suffix, change_suffix, passive_suffixes) = if result
        .prepared
        .is_split
    {
        let (change_vout, change_outpoint) =
            match (change_vout, change_outpoint) {
                (Some(vout), Some(outpoint)) => (vout, outpoint),
                _ => {
                    return Err(TapNodeError::Storage(
                        "split transfer without a change output".into(),
                    ))
                }
            };
        let asset_outputs = [
            OutputProofInfo {
                asset: &result.prepared.root_asset,
                anchor_output_index: change_vout,
                internal_key: change_internal_desc.pub_key,
                commitment: &result.prepared.change_commitment,
                tapscript_sibling: None,
            },
            OutputProofInfo {
                asset: &result.prepared.recipient_assets[0].asset,
                anchor_output_index: recipient_vout,
                internal_key: recipient.internal_key,
                commitment: &result.prepared.output_commitments[0],
                tapscript_sibling: None,
            },
        ];
        // NOTE: exclusion proofs for the wallet's BTC change output
        // are omitted (its internal key is unknown to the node).
        let recipient_suffix = create_proof_suffix_with_options(
            &anchor_tx,
            prev_out,
            &asset_outputs,
            1,
            &[],
            &ProofSuffixOptions::default(),
        )
        .map_err(TapNodeError::Storage)?;
        let change_suffix = if has_change {
            Some(
                create_proof_suffix_with_options(
                    &anchor_tx,
                    prev_out,
                    &asset_outputs,
                    0,
                    &[],
                    &ProofSuffixOptions::default(),
                )
                .map_err(TapNodeError::Storage)?,
            )
        } else {
            None
        };

        // A proof suffix for each passive asset re-anchored into the
        // change output. Each is an additional asset in the change
        // output's commitment, so its inclusion proof (and the STXO and
        // exclusion proofs) come from the same tree-retaining
        // commitment the change/recipient proofs use. The change output
        // is represented by the passive asset itself (the proof target),
        // the recipient output by the recipient split asset.
        let mut passive_suffixes =
            Vec::with_capacity(passive_work.len());
        for (i, work) in passive_work.iter().enumerate() {
            let passive_asset = &result.prepared.passive_assets[i];
            let asset_outputs = [
                OutputProofInfo {
                    asset: passive_asset,
                    anchor_output_index: change_vout,
                    internal_key: change_internal_desc.pub_key,
                    commitment: &result.prepared.change_commitment,
                    tapscript_sibling: None,
                },
                OutputProofInfo {
                    asset: &result.prepared.recipient_assets[0].asset,
                    anchor_output_index: recipient_vout,
                    internal_key: recipient.internal_key,
                    commitment: &result.prepared.output_commitments[0],
                    tapscript_sibling: None,
                },
            ];
            let suffix = create_proof_suffix_with_options(
                &anchor_tx,
                work.owned.anchor_outpoint,
                &asset_outputs,
                0,
                &[],
                &ProofSuffixOptions::default(),
            )
            .map_err(TapNodeError::Storage)?;
            passive_suffixes.push(PassiveAnchor {
                outpoint: change_outpoint,
                script_key: work.owned.script_key,
                suffix,
                base_file: work.base_file.clone(),
            });
        }

        (recipient_suffix, change_suffix, passive_suffixes)
    } else {
        // Full-value send with no passive assets: the root asset IS
        // the recipient asset and there is no change to prove. The
        // anchor template carries a single TAP-committed output (the
        // recipient's), so exclusion proofs cover every other template
        // output. (A full-value send that carries passive assets is
        // forced into the split branch above.)
        //
        // NOTE: exclusion proofs for a P2TR BTC change output added by
        // the funding wallet are still omitted, since its internal key
        // is unknown to the node (documented limitation; Go adds a
        // BIP-86 tapscript exclusion proof from the funding PSBT's
        // derivation info).
        let asset_outputs = [OutputProofInfo {
            asset: &result.prepared.root_asset,
            anchor_output_index: recipient_vout,
            internal_key: recipient.internal_key,
            commitment: &result.prepared.output_commitments[0],
            tapscript_sibling: None,
        }];
        let recipient_suffix = create_proof_suffix_with_options(
            &anchor_tx,
            prev_out,
            &asset_outputs,
            0,
            &[],
            &ProofSuffixOptions::default(),
        )
        .map_err(TapNodeError::Storage)?;
        (recipient_suffix, None, Vec::new())
    };

    // The (first) input's proof file is the base the new suffixes are
    // appended to, giving the recipient the full provenance chain.
    let base_file = node
        .proof_store
        .lock()
        .expect("proof store lock")
        .get_proof(&ProofLocator {
            outpoint: selected[0].anchor_outpoint,
            script_key: selected[0].script_key,
        })
        .ok()
        .flatten();

    // Step 9: Register with the confirmation watcher and report the
    // broadcast. The anchor is written through to the durable
    // pending-anchor store, so a restart between broadcast and
    // confirmation still finishes and delivers the proofs.
    let anchor = PendingAnchor {
        txid: txid_internal,
        kind: AnchorKind::Transfer(TransferAnchor {
            asset_id,
            amount,
            recipient_script_key: recipient.script_key,
            recipient_outpoint,
            recipient_suffix,
            change_script_key: has_change.then(|| {
                result.prepared.root_asset.script_key.pub_key
            }),
            change_outpoint: if has_change { change_outpoint } else { None },
            change_suffix,
            base_file,
            courier_url: recipient.proof_courier_addr.clone(),
            passive: passive_suffixes,
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

    node.event_bus.emit(TapEvent::TransferBroadcast {
        asset_id,
        amount,
        txid: txid_display,
    });

    Ok(TransferHandle {
        txid: txid_display,
        asset_id,
        amount,
    })
}

/// Finishes a confirmed transfer: updates the proof suffixes with the
/// real chain data, stores the recipient and change proof files, and
/// delivers the recipient proof via the node's courier when the
/// destination address carried a courier URL. Called from
/// [`TapNode::tick`](crate::TapNode::tick).
pub(crate) fn finish_transfer_confirmation<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    mut anchor: TransferAnchor,
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
    let anchor_tx_bytes = if conf.tx.is_empty() {
        bitcoin::consensus::serialize(&anchor.recipient_suffix.anchor_tx.0)
    } else {
        conf.tx.clone()
    };
    let block_tx_hashes = if conf.block_tx_hashes.is_empty() {
        vec![txid_internal]
    } else {
        conf.block_tx_hashes.clone()
    };

    let base = BaseProofParams {
        block_header: conf.block_header,
        block_height: conf.block_height,
        anchor_tx_bytes,
        tx_index: conf.tx_index as usize,
        block_tx_hashes,
        output_index: anchor.recipient_outpoint.vout,
        internal_key: anchor.recipient_script_key,
    };

    update_proof_chain_data(&mut anchor.recipient_suffix, &base)
        .map_err(TapNodeError::Storage)?;
    if let Some(change_suffix) = anchor.change_suffix.as_mut() {
        update_proof_chain_data(change_suffix, &base)
            .map_err(TapNodeError::Storage)?;
    }

    // Build and store the proof files: the input's history plus the
    // new suffix.
    let make_file = |suffix: &proof::Proof| {
        let mut file = anchor
            .base_file
            .clone()
            .unwrap_or_else(proof::file::File::new);
        file.append_proof(proof::encode::encode_proof(suffix));
        file
    };

    let recipient_file = make_file(&anchor.recipient_suffix);
    node.proof_store
        .lock()
        .expect("proof store lock")
        .insert_proof(
            ProofLocator {
                outpoint: anchor.recipient_outpoint,
                script_key: anchor.recipient_script_key,
            },
            recipient_file.clone(),
        )
        .map_err(TapNodeError::Storage)?;

    if let (Some(change_suffix), Some(change_outpoint), Some(change_key)) = (
        anchor.change_suffix.as_ref(),
        anchor.change_outpoint,
        anchor.change_script_key,
    ) {
        let change_file = make_file(change_suffix);
        node.proof_store
            .lock()
            .expect("proof store lock")
            .insert_proof(
                ProofLocator {
                    outpoint: change_outpoint,
                    script_key: change_key,
                },
                change_file,
            )
            .map_err(TapNodeError::Storage)?;
    }

    // Store each re-anchored passive asset's proof: its own prior
    // history plus the new suffix, at the change outpoint under its
    // unchanged script key.
    for passive in anchor.passive.iter_mut() {
        update_proof_chain_data(&mut passive.suffix, &base)
            .map_err(TapNodeError::Storage)?;
        let mut file = passive
            .base_file
            .clone()
            .unwrap_or_else(proof::file::File::new);
        file.append_proof(proof::encode::encode_proof(&passive.suffix));
        node.proof_store
            .lock()
            .expect("proof store lock")
            .insert_proof(
                ProofLocator {
                    outpoint: passive.outpoint,
                    script_key: passive.script_key,
                },
                file,
            )
            .map_err(TapNodeError::Storage)?;
    }

    // The change output (and any passive assets re-anchored into it)
    // was persisted with block height 0 at broadcast time; record the
    // real confirmation height. A full-value send with passive assets
    // has no change_outpoint but the passives still carry the change
    // outpoint they were re-anchored into. Idempotent, like the other
    // finish steps.
    {
        let mut store = node.asset_store.lock().expect("asset store lock");
        if let Some(change_outpoint) = anchor.change_outpoint {
            store
                .set_anchor_block_height(
                    &change_outpoint,
                    conf.block_height,
                )
                .map_err(TapNodeError::Storage)?;
        }
        for passive in &anchor.passive {
            store
                .set_anchor_block_height(
                    &passive.outpoint,
                    conf.block_height,
                )
                .map_err(TapNodeError::Storage)?;
        }
    }

    let mut txid_display = txid_internal;
    txid_display.reverse();
    node.event_bus.emit(TapEvent::TransferConfirmed {
        asset_id: anchor.asset_id,
        amount: anchor.amount,
        txid: txid_display,
    });

    // Deliver the recipient proof via the node's courier when the
    // destination address carried a courier URL.
    if anchor.courier_url.as_deref().is_some_and(|u| !u.is_empty()) {
        let recipient = Recipient {
            script_key: anchor.recipient_script_key,
            asset_id: anchor.asset_id,
            amount: anchor.amount,
        };
        let annotated = AnnotatedProof {
            locator: CourierLocator {
                asset_id: anchor.asset_id,
                script_key: anchor.recipient_script_key,
                outpoint: anchor.recipient_outpoint,
            },
            proof_file: recipient_file,
        };
        node.courier
            .deliver_proof(&recipient, &annotated)
            .map_err(TapNodeError::Courier)?;

        node.event_bus.emit(TapEvent::ProofDelivered {
            asset_id: anchor.asset_id,
            recipient_script_key: anchor.recipient_script_key,
        });
    }

    Ok(())
}

/// Determines the taproot tweak the [`AssetSigner`] seam must apply
/// to the stored raw key to sign for the asset's script key.
///
/// - `None` for the raw descriptor key itself (legacy untweaked
///   script keys) and for the BIP-86 tweak of the descriptor key
///   (mint and change outputs, and V0/V1 address receives): the seam
///   applies the empty-tree BIP-86 tweak
///   ([`AssetSigner::sign_virtual_tx`]).
/// - `Some(leaf tap hash)` when the script key is the V2 unique
///   per-asset-ID script key: the address key tweaked with the
///   Pedersen-commitment tapscript leaf over the asset ID
///   ([`derive_unique_script_key`]). The recomputed leaf tap hash is
///   the tapscript root the seam must apply per BIP-341
///   ([`AssetSigner::sign_virtual_tx_tweaked`]). A signer that does
///   not override that method rejects the send with a precise error
///   naming the required extension.
///
/// An asset with no stored descriptor, or one whose descriptor's
/// relationship to the script key is not recognized, maps to `None`,
/// preserving the existing BIP-86 signing behavior for externally
/// managed keys (an unknown descriptor is later reported as
/// [`SendError::UnknownScriptKey`] by the signer).
fn tapscript_root_for(owned: &OwnedAsset) -> Option<[u8; 32]> {
    let desc = owned.script_key_desc.as_ref()?;
    if owned.script_key == desc.pub_key {
        return None;
    }
    // Only compare against the BIP-86 tweak when the stored raw key is
    // a valid point (ScriptKey::bip86 asserts validity).
    if XOnlyPublicKey::from_slice(&desc.pub_key.0[1..]).is_ok()
        && owned.script_key == ScriptKey::bip86(desc.pub_key).pub_key
    {
        return None;
    }
    if let Ok(unique) = derive_unique_script_key(
        desc.pub_key,
        &owned.asset_id,
        ScriptKeyDerivationMethod::UniquePedersen,
    ) {
        if unique.pub_key == owned.script_key {
            // The recorded tweak is the Pedersen leaf's 32-byte tap
            // hash, i.e. the single-leaf tapscript root.
            let root = unique
                .tweaked
                .and_then(|t| <[u8; 32]>::try_from(t.tweak.as_slice()).ok());
            if root.is_some() {
                return root;
            }
        }
    }
    None
}

/// Simple largest-first coin selection.
fn coin_select<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    asset_id: &AssetId,
    target: u64,
) -> Result<Vec<OwnedAsset>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let store = node.asset_store.lock().expect("asset store lock");
    let mut unspent = store.get_unspent(asset_id);

    if unspent.is_empty() {
        return Err(TapNodeError::AssetNotFound(*asset_id));
    }

    // Sort by amount descending (largest first).
    unspent.sort_by(|a, b| b.amount.cmp(&a.amount));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in unspent {
        selected.push(utxo.clone());
        total += utxo.amount;
        if total >= target {
            break;
        }
    }

    Ok(selected)
}

/// Reconstructs the asset's [`Genesis`] from the stored owned asset,
/// erroring when any of the genesis fields are missing.
fn genesis_from_owned(owned: &OwnedAsset) -> Result<Genesis, TapNodeError> {
    let missing = |field: &str| {
        TapNodeError::Storage(format!(
            "input asset is missing its stored genesis {}; cannot \
             reconstruct the genesis for signing",
            field
        ))
    };
    Ok(Genesis {
        first_prev_out: owned.genesis_point.ok_or_else(|| {
            missing("outpoint")
        })?,
        tag: owned.genesis_tag.clone().ok_or_else(|| missing("tag"))?,
        meta_hash: owned
            .genesis_meta_hash
            .ok_or_else(|| missing("meta hash"))?,
        output_index: owned
            .genesis_output_index
            .ok_or_else(|| missing("output index"))?,
        asset_type: owned
            .genesis_asset_type
            .ok_or_else(|| missing("asset type"))?,
    })
}

/// Reconstructs the previous asset being spent.
///
/// Prefers the exact asset from the stored proof file (matching what
/// any verifier reconstructs); falls back to a genesis-form asset
/// (single zeroed prev witness), which is correct for freshly minted
/// assets that have not transitioned yet.
fn prev_asset_for<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    owned: &OwnedAsset,
    genesis: &Genesis,
) -> Result<Asset, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let stored = node
        .proof_store
        .lock()
        .expect("proof store lock")
        .get_proof(&ProofLocator {
            outpoint: owned.anchor_outpoint,
            script_key: owned.script_key,
        })
        .ok()
        .flatten();

    if let Some(file) = stored {
        if let Some(last) = file.proofs.last() {
            if let Ok(decoded) =
                proof::decode::decode_proof(&last.proof_bytes)
            {
                if decoded.asset.id() == owned.asset_id
                    && decoded.asset.script_key.pub_key == owned.script_key
                    && decoded.asset.amount == owned.amount
                {
                    return Ok(decoded.asset);
                }
            }
        }
    }

    Ok(Asset {
        version: AssetVersion::V0,
        genesis: genesis.clone(),
        amount: owned.amount,
        lock_time: 0,
        relative_lock_time: 0,
        prev_witnesses: vec![Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![],
            split_commitment: None,
        }],
        split_commitment_root: None,
        script_version: ScriptVersion::V0,
        script_key: ScriptKey::from_pub_key(owned.script_key),
        group_key: None,
        unknown_odd_types: std::collections::BTreeMap::new(),
    })
}

/// Adapter that implements [`VirtualSigner`] with the node's
/// [`KeyRing`] + [`AssetSigner`].
///
/// Holds a map from the (tweaked) input script keys to their stored
/// raw key descriptors (from `OwnedAsset::script_key_desc`) plus the
/// taproot tweak the seam must apply (see [`tapscript_root_for`]).
/// Signing resolves the entry for the exact script key being spent
/// and delegates to [`AssetSigner::sign_virtual_tx_tweaked`]: for
/// `None` roots that is by contract the BIP-86 taproot tweak of the
/// raw key (the default implementation delegates to
/// [`AssetSigner::sign_virtual_tx`]); for `Some(root)` (V2 unique
/// Pedersen script keys) the BIP-341
/// `TapTweakHash(internal_key, root)` tweak (see the trait docs in
/// `tap_onchain::chain`). Script keys with no stored descriptor fail
/// with [`SendError::UnknownScriptKey`].
struct NodeVirtualSigner<'a, K> {
    keys: &'a K,
    keys_by_script_key:
        HashMap<SerializedKey, (KeyDescriptor, Option<[u8; 32]>)>,
}

impl<K: KeyRing + AssetSigner> VirtualSigner for NodeVirtualSigner<'_, K> {
    fn sign_virtual_tx(
        &self,
        sighash: &[u8; 32],
        script_key: &ScriptKey,
    ) -> Result<Vec<u8>, SendError> {
        let (desc, tapscript_root) = self
            .keys_by_script_key
            .get(script_key.serialized())
            .ok_or_else(|| {
                SendError::UnknownScriptKey(*script_key.serialized())
            })?;
        self.keys
            .sign_virtual_tx_tweaked(desc, sighash, tapscript_root.as_ref())
            .map_err(SendError::Chain)
    }
}

fn x_only_from_serialized(
    key: &SerializedKey,
) -> Result<XOnlyPublicKey, TapNodeError> {
    XOnlyPublicKey::from_slice(&key.0[1..]).map_err(|e| {
        TapNodeError::Storage(format!("invalid x-only key: {}", e))
    })
}

/// A passive asset being re-anchored: its old owned record, its
/// reconstructed genesis, the signed re-anchoring transition, and its
/// prior proof file (the base the new suffix appends to).
struct PassiveWork {
    owned: OwnedAsset,
    genesis: Genesis,
    signed: Asset,
    base_file: Option<proof::file::File>,
}

/// Short hex of an asset id for error messages.
fn hex_id(asset_id: &AssetId) -> String {
    asset_id.0.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}
