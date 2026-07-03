// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Address generation and proof import/export.

use std::collections::BTreeMap;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_persist::proof_store::ProofLocator;
use tap_primitives::address::{AddressVersion, TapAddress};
use tap_primitives::asset::{
    AssetId, OutPoint, SerializedKey, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof;

use crate::error::TapNodeError;
use crate::node::TapNode;

/// Generates a new TAP address for receiving an asset.
pub(crate) fn new_address<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    asset_id: AssetId,
    amount: u64,
) -> Result<TapAddress, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Derive a new script key.
    let script_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    // Derive a new internal key.
    let internal_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;

    let courier = if node.config.courier_url.is_empty() {
        None
    } else {
        Some(node.config.courier_url.clone())
    };

    let addr = TapAddress {
        version: AddressVersion::V0,
        asset_version: 0,
        asset_id: Some(asset_id),
        script_key: script_key_desc.pub_key,
        internal_key: internal_key_desc.pub_key,
        amount,
        network: node.config.network,
        proof_courier_addr: courier,
        group_key: None,
        tapscript_sibling: None,
        unknown_odd_types: BTreeMap::new(),
    };

    Ok(addr)
}

/// Imports a proof file, persisting the contained asset.
pub(crate) fn import_proof<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    proof_file: proof::file::File,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Verify the proof file hash chain.
    if !proof_file.verify_hash_chain() {
        return Err(TapNodeError::Storage(
            "invalid proof file hash chain".into(),
        ));
    }

    let has_proofs = proof_file.num_proofs() > 0;

    // Store the proof. A proper implementation would extract the asset
    // outpoint and script key from the decoded proof TLV.
    let locator = ProofLocator {
        outpoint: OutPoint::default(),
        script_key: SerializedKey([0u8; 33]),
    };
    node.proof_store
        .lock()
        .unwrap()
        .insert_proof(locator, proof_file)
        .map_err(|e| TapNodeError::Storage(e))?;

    if has_proofs {
        node.event_bus.emit(crate::event::TapEvent::AssetReceived {
            asset_id: tap_primitives::asset::AssetId::ZERO,
            amount: 0,
            outpoint: OutPoint::default(),
        });
    }

    Ok(())
}

/// Exports a proof file for a specific asset output.
pub(crate) fn export_proof<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    outpoint: &OutPoint,
    script_key: &SerializedKey,
) -> Result<proof::file::File, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let locator = ProofLocator {
        outpoint: *outpoint,
        script_key: *script_key,
    };
    let store = node.proof_store.lock().unwrap();
    store
        .get_proof(&locator)
        .map_err(|e| TapNodeError::Storage(e))?
        .ok_or(TapNodeError::Storage("proof not found".into()))
}
