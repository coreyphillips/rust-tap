// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! High-level minting operations.
//!
//! Full flow: queue seedlings → freeze → commit → build PSBT → fund →
//! sign → broadcast → persist minted assets.

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::mint::Seedling;
use tap_onchain::psbt::genesis::create_genesis_template;
use tap_persist::asset_store::OwnedAsset;
use tap_primitives::asset::{
    AssetType, ScriptKey, SerializedKey, TAPROOT_ASSETS_KEY_FAMILY,
};

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
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
    let mut planter = node.planter.lock().unwrap();
    planter.queue_seedling(seedling)?;
    Ok(())
}

/// Finalizes the pending mint batch.
///
/// Orchestrates the complete mint pipeline:
/// 1. Freeze the batch
/// 2. Derive the internal key for the genesis output
/// 3. Commit the batch (build TAP commitment)
/// 4. Build genesis PSBT template
/// 5. Fund the PSBT via wallet
/// 6. Sign and finalize via wallet
/// 7. Broadcast the signed transaction
/// 8. Persist the minted assets
/// 9. Emit events
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

    // Always reset the planter after finalize so the next mint starts fresh.
    // On success, the batch is done. On failure, we cancel it.
    {
        let mut planter = node.planter.lock().unwrap();
        if result.is_err() {
            let _ = planter.cancel_batch();
        }
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
    let mut planter = node.planter.lock().unwrap();

    // Step 1: Freeze the batch.
    planter.freeze_batch()?;

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;

    // Collect seedling info before commit (for the result).
    let seedling_info: Vec<(String, u64, AssetType)> = batch
        .seedlings
        .iter()
        .map(|(name, s)| (name.clone(), s.amount, s.asset_type))
        .collect();

    // Step 2: Derive an internal key for the genesis output.
    let internal_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let internal_x_only = x_only_from_serialized(&internal_key_desc.pub_key);

    // Step 3: Fund-once genesis point discovery.
    //
    // We fund a PSBT with a placeholder commitment to discover which UTXO
    // BDK selects. Then we re-commit with the real genesis point (derived
    // from the first input) and patch the TAP output in-place, avoiding a
    // second call to fund_psbt (which could pick a different UTXO).

    let fee_rate = node.chain.estimate_fee(node.config.default_conf_target)?;

    // -- Fund with placeholder commitment to discover inputs --
    let placeholder = tap_primitives::asset::OutPoint {
        txid: [0u8; 32],
        vout: 0,
    };
    planter.commit_batch(placeholder, 0)?;

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    let dummy_commitment = batch.root_asset_commitment.as_ref().ok_or(
        TapNodeError::Storage("no commitment".into()),
    )?;

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
        let inp = psbt.unsigned_tx.input.first()
            .ok_or(TapNodeError::Storage("no inputs".into()))?;
        let op = inp.previous_output;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(op.txid.as_ref());
        tap_primitives::asset::OutPoint { txid, vout: op.vout }
    };

    // Find the 330-sat P2TR output — this is the TAP commitment output.
    // BDK may reorder outputs, so we can't assume index 0.
    let tap_output_index = psbt.unsigned_tx.output.iter().position(|o| {
        o.value == Amount::from_sat(330) && o.script_pubkey.is_p2tr()
    }).ok_or(TapNodeError::Storage("no 330-sat P2TR output in funded PSBT".into()))?
        as u32;

    // -- Re-commit with real genesis point + correct output index, patch PSBT --
    let _ = planter.cancel_batch();
    let _ = planter.take_batch();

    for (name, amount, asset_type) in &seedling_info {
        let seedling = if *amount == 1 && *asset_type == AssetType::Collectible {
            tap_onchain::mint::Seedling::new_collectible(name.clone())
        } else {
            tap_onchain::mint::Seedling::new_normal(name.clone(), *amount)
        };
        planter.queue_seedling(seedling)?;
    }
    planter.freeze_batch()?;
    planter.commit_batch(real_genesis_point, tap_output_index)?;

    let batch = planter.pending_batch().ok_or(TapNodeError::Mint(
        tap_onchain::mint::MintError::NoPendingBatch,
    ))?;
    // Capture batch_key_pub from the final batch — the first batch used a
    // placeholder genesis point and its commitment is stale.
    let batch_key_pub = batch.batch_key.pub_key;
    let tap_commitment = batch.root_asset_commitment.as_ref().ok_or(
        TapNodeError::Storage("no commitment".into()),
    )?;

    // Build the correct TAP output script and replace it in the funded PSBT.
    let (real_script, _output_key) =
        tap_onchain::psbt::commitment::create_tap_output_script(
            &internal_x_only,
            tap_commitment.commitment(),
            None,
        )
        .map_err(|e| TapNodeError::Storage(format!("tap output: {}", e)))?;

    psbt.unsigned_tx.output[tap_output_index as usize].script_pubkey = real_script;

    let funded = psbt.serialize();

    // Step 4: Sign and finalize.
    let signed_tx_bytes = node.wallet.sign_and_finalize_psbt(&funded)?;

    // Step 5: Broadcast.
    node.chain.publish_transaction(&signed_tx_bytes)?;

    // Extract txid from the signed transaction.
    // Bitcoin txids are displayed in reversed byte order, so we reverse
    // the internal representation for the user-facing hex string.
    let txid = if let Ok(tx) =
        bitcoin::consensus::deserialize::<bitcoin::Transaction>(&signed_tx_bytes)
    {
        let id = tx.compute_txid();
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(id.as_ref());
        txid_bytes.reverse(); // Internal → display byte order.
        Some(txid_bytes)
    } else {
        None
    };

    // Step 8: Persist the minted assets.
    let minted_assets: Vec<MintedAsset> = seedling_info
        .iter()
        .map(|(name, amount, asset_type)| {
            let genesis = tap_primitives::asset::Genesis {
                first_prev_out: real_genesis_point,
                tag: name.clone(),
                meta_hash: [0u8; 32],
                output_index: tap_output_index,
                asset_type: *asset_type,
            };
            let asset_id = genesis.id();

            // Use the BIP-86 tweaked batch key as the script key -- this
            // matches what commit_batch() uses (ScriptKey::bip86).
            let script_key = ScriptKey::bip86(batch_key_pub).pub_key;

            // Persist to asset store.
            let anchor_outpoint = tap_primitives::asset::OutPoint {
                txid: txid.unwrap_or([0u8; 32]),
                vout: tap_output_index,
            };
            let _ = node.asset_store.lock().unwrap().insert_asset(OwnedAsset {
                asset_id,
                amount: *amount,
                anchor_outpoint,
                script_key,
                spent: false,
                block_height: 0,
            });

            MintedAsset {
                asset_id,
                name: name.clone(),
                amount: *amount,
                script_key,
            }
        })
        .collect();

    // Step 9: Register with universe servers (if configured).
    #[cfg(feature = "universe-registration")]
    if !node.config.universe_servers.is_empty() {
        for asset in &minted_assets {
            let anchor_outpoint = tap_primitives::asset::OutPoint {
                txid: txid.unwrap_or([0u8; 32]),
                vout: 0,
            };
            // Build a minimal genesis proof and encode it.
            let genesis = tap_primitives::asset::Genesis {
                first_prev_out: real_genesis_point,
                tag: asset.name.clone(),
                meta_hash: [0u8; 32],
                output_index: 0,
                asset_type: tap_primitives::asset::AssetType::Normal,
            };
            let proof = tap_primitives::proof::types::Proof {
                version: tap_primitives::proof::types::TransitionVersion::V0,
                prev_out: genesis_point,
                block_header: tap_primitives::proof::types::BlockHeader([0; 80]),
                block_height: 0,
                anchor_tx:
                    tap_primitives::proof::types::AnchorTx::from_bytes(
                        &signed_tx_bytes,
                    )
                    .map_err(|e| {
                        TapNodeError::Storage(format!(
                            "anchor tx parse: {}",
                            e
                        ))
                    })?,
                tx_merkle_proof: tap_primitives::proof::tx_merkle::TxMerkleProof {
                    nodes: vec![],
                    bits: vec![],
                },
                asset: tap_primitives::asset::Asset::new_genesis(
                    genesis.clone(),
                    asset.amount,
                    ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
                ),
                inclusion_proof: tap_primitives::proof::types::TaprootProof {
                    output_index: 0,
                    internal_key: internal_key_desc.pub_key,
                    commitment_proof: None,
                    tapscript_proof: None,
                    unknown_odd_types: std::collections::BTreeMap::new(),
                },
                exclusion_proofs: vec![],
                split_root_proof: None,
                meta_reveal: None,
                additional_inputs: vec![],
                challenge_witness: None,
                genesis_reveal: Some(genesis),
                group_key_reveal: None,
                alt_leaves: vec![],
                unknown_odd_types: std::collections::BTreeMap::new(),
            };
            let proof_bytes =
                tap_primitives::proof::encode::encode_proof(&proof);

            let script_key = node
                .keys
                .derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)
                .ok()
                .map(|kd| kd.pub_key)
                .unwrap_or(SerializedKey([0x02; 33]));

            for server_url in &node.config.universe_servers {
                let client =
                    tap_universe::http_client::HttpUniverseClient::new(
                        server_url,
                    );
                let _ = client.insert_proof(
                    &asset.asset_id,
                    tap_universe::types::ProofType::Issuance,
                    &anchor_outpoint,
                    &script_key,
                    &proof_bytes,
                );
            }
        }
    }

    // Step 10: Emit events.
    node.event_bus.emit(TapEvent::MintBatchStateChanged {
        batch_key: batch_key_pub,
        new_state: tap_onchain::mint::BatchState::Broadcast,
    });

    Ok(MintResult {
        batch_key: batch_key_pub,
        txid,
        assets: minted_assets,
        internal_key: internal_key_desc.pub_key,
        signed_tx: signed_tx_bytes,
        genesis_point: real_genesis_point,
        funded_psbt: funded.clone(),
        tap_output_index,
    })
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
    let mut planter = node.planter.lock().unwrap();
    planter.cancel_batch()?;
    Ok(())
}

/// Extracts an x-only public key from a 33-byte compressed key.
fn x_only_from_serialized(key: &SerializedKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&key.0[1..]).expect("valid 32-byte x-only key")
}
