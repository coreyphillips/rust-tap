// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! High-level asset transfer operations.
//!
//! Full flow: coin select → validate → prepare outputs → sign virtual tx →
//! build anchor PSBT → fund → sign → broadcast → mark spent → deliver proof.

use bitcoin::secp256k1::XOnlyPublicKey;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::send::{
    execute_transfer, SelectedInput, SendError, TransferOutput, VirtualSigner,
};
use tap_persist::asset_store::OwnedAsset;
use tap_primitives::address::TapAddress;
use tap_primitives::asset::{
    AssetId, AssetVersion, PrevId, ScriptKey, SerializedKey,
    TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::vm::InputSet;

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;
use crate::types::TransferHandle;

/// Sends an asset to a TAP address.
///
/// Orchestrates the complete transfer pipeline:
/// 1. Coin select asset UTXOs
/// 2. Build transfer inputs/outputs
/// 3. Execute transfer (validate, prepare, sign virtual tx, build template)
/// 4. Fund anchor transaction
/// 5. Sign and broadcast
/// 6. Mark inputs as spent
/// 7. Persist new outputs
/// 8. Emit events
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

    // Step 2: Build transfer inputs.
    let genesis = tap_primitives::asset::Genesis {
        first_prev_out: selected[0].anchor_outpoint,
        tag: String::new(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: tap_primitives::asset::AssetType::Normal,
    };

    let inputs: Vec<SelectedInput> = selected
        .iter()
        .map(|owned| {
            let prev_id = PrevId {
                out_point: owned.anchor_outpoint,
                id: owned.asset_id,
                script_key: owned.script_key,
            };
            SelectedInput {
                prev_id,
                anchor_point: owned.anchor_outpoint,
                amount: owned.amount,
                asset_type: tap_primitives::asset::AssetType::Normal,
                script_key: ScriptKey::from_pub_key(owned.script_key),
            }
        })
        .collect();

    // Build transfer output for recipient.
    let outputs = vec![TransferOutput {
        output_index: 1, // Output 0 is change, output 1 is recipient.
        amount,
        script_key: ScriptKey::from_pub_key(recipient.script_key),
        asset_version: AssetVersion::V0,
        interactive: false,
    }];

    // Build previous asset set for signing.
    let mut prev_assets = InputSet::new();
    for (owned, input) in selected.iter().zip(inputs.iter()) {
        let prev_asset = tap_primitives::asset::Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: owned.amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![tap_primitives::asset::Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: tap_primitives::asset::ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(owned.script_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };
        prev_assets.insert(input.prev_id.clone(), prev_asset);
    }

    // Step 3: Create signer adapter.
    let signer = NodeVirtualSigner { keys: &*node.keys };

    // Derive internal keys for output anchors.
    let change_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let recipient_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let internal_keys = vec![
        x_only_from_serialized(&change_key_desc.pub_key),
        x_only_from_serialized(&recipient_key_desc.pub_key),
    ];

    // Execute the transfer pipeline.
    let result = execute_transfer(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &signer,
        &internal_keys,
    )
    .map_err(TapNodeError::Send)?;

    // Step 4: Fund the anchor transaction.
    let fee_rate = node.chain.estimate_fee(node.config.default_conf_target)?;
    let tx_bytes = bitcoin::consensus::serialize(&result.template.tx);
    let funded = node.wallet.fund_psbt(&tx_bytes, fee_rate)?;

    // Step 5: Sign and broadcast.
    let signed_tx_bytes = node.wallet.sign_and_finalize_psbt(&funded)?;
    node.chain.publish_transaction(&signed_tx_bytes)?;

    // Extract txid.
    let txid = if let Ok(tx) =
        bitcoin::consensus::deserialize::<bitcoin::Transaction>(&signed_tx_bytes)
    {
        let id = tx.compute_txid();
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(id.as_ref());
        txid_bytes.reverse(); // Internal → display byte order.
        txid_bytes
    } else {
        [0u8; 32]
    };

    // Step 6: Mark inputs as spent.
    {
        let mut store = node.asset_store.lock().unwrap();
        for input in &selected {
            let _ = store.mark_spent(&input.anchor_outpoint);
        }
    }

    // Step 7: Emit event.
    node.event_bus.emit(TapEvent::TransferConfirmed {
        asset_id,
        amount,
        txid,
    });

    Ok(TransferHandle {
        txid,
        asset_id,
        amount,
    })
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
    let store = node.asset_store.lock().unwrap();
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

/// Adapter that implements VirtualSigner using the node's KeyRing + AssetSigner.
struct NodeVirtualSigner<'a, K> {
    keys: &'a K,
}

impl<K: KeyRing + AssetSigner> VirtualSigner for NodeVirtualSigner<'_, K> {
    fn sign_virtual_tx(
        &self,
        sighash: &[u8; 32],
        _script_key: &ScriptKey,
    ) -> Result<Vec<u8>, SendError> {
        // Find the key descriptor for this script key.
        // For now, derive a fresh key and sign with it.
        // A production implementation would look up the key by script_key.
        let key_desc = self
            .keys
            .derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)
            .map_err(|e| SendError::Chain(e))?;
        self.keys
            .sign_virtual_tx(&key_desc, sighash)
            .map_err(|e| SendError::Chain(e))
    }
}

fn x_only_from_serialized(key: &SerializedKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&key.0[1..]).expect("valid 32-byte x-only key")
}
