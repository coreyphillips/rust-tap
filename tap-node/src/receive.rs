// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Address generation, proof import/export, and V2 (authmailbox)
//! receive polling.

use std::collections::BTreeMap;

use tap_ldk::ldk::LdkChannelOps;
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_onchain::proof::courier::{CourierLocator, Recipient};
use tap_onchain::proof::mailbox::{
    decrypt_send_fragment, remove_message_challenge, MessageFilter,
};
use tap_persist::asset_store::OwnedAsset;
use tap_persist::proof_store::ProofLocator;
use tap_primitives::address::{
    self, AddressVersion, NewAddressParams, TapAddress,
};
use tap_primitives::asset::{
    derive_unique_script_key, AssetId, AssetType, Genesis, OutPoint,
    ScriptKey, SerializedKey, TAPROOT_ASSETS_KEY_FAMILY,
};
use tap_primitives::proof;

use crate::error::TapNodeError;
use crate::node::TapNode;

/// Parameters for creating a V2 (authmailbox) address.
#[derive(Clone, Debug)]
pub struct V2AddressParams {
    /// The asset to receive. Ignored (dropped) if a group key is set.
    pub asset_id: Option<AssetId>,
    /// Optional group key: the address then accepts any asset of the
    /// group.
    pub group_key: Option<SerializedKey>,
    /// Amount to receive. V2 addresses may use 0 ("any amount").
    pub amount: u64,
    /// The type of the asset being received.
    pub asset_type: AssetType,
}

/// An asset output imported from a V2 address mailbox receive.
#[derive(Clone, Debug)]
pub struct ReceivedAsset {
    /// The received asset.
    pub asset_id: AssetId,
    /// Number of units received.
    pub amount: u64,
    /// The per-asset-ID script key derived from the address.
    pub script_key: SerializedKey,
    /// The anchor outpoint of the transfer.
    pub anchor_outpoint: OutPoint,
    /// Block height the transfer confirmed at.
    pub block_height: u32,
}

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
    // Derive a new script key. The address carries the BIP-86 tweak
    // of the derived key (Go's NewScriptKeyBip86), matching the
    // mint/change convention, so an asset received on it can later be
    // signed through the AssetSigner seam (whose contract is the
    // BIP-86 key-spend tweak of the stored raw key).
    let script_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let script_key = ScriptKey::bip86(script_key_desc.pub_key);
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
        script_key: script_key.pub_key,
        internal_key: internal_key_desc.pub_key,
        amount,
        network: node.config.network,
        proof_courier_addr: courier,
        group_key: None,
        tapscript_sibling: None,
        unknown_odd_types: BTreeMap::new(),
    };

    // Record the address and the descriptors behind its keys in the
    // address book, so the proof import path can attach the signing
    // context to assets received on it. Without the stored descriptor
    // a received asset could never be sent onward (the signer would
    // fail with UnknownScriptKey even though this node derived the
    // key).
    {
        let mut store =
            node.mailbox_store.lock().expect("mailbox store lock");
        store.insert_address(&addr).map_err(TapNodeError::Storage)?;
        store
            .set_key_descriptors(
                &addr.script_key,
                &script_key_desc,
                &internal_key_desc,
            )
            .map_err(TapNodeError::Storage)?;
    }

    Ok(addr)
}

/// Generates a new V2 (authmailbox) address, mirroring the V2 branch
/// of Go's `address.New`: the courier address must use the
/// `authmailbox+universerpc` scheme, grouped assets are supported (the
/// group key drops the asset ID), and a zero amount is allowed. The
/// address is persisted in the mailbox store so `poll_mailbox` can
/// route incoming messages back to it.
pub(crate) fn new_address_v2<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    params: V2AddressParams,
) -> Result<TapAddress, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Derive fresh script and internal keys. For V2 addresses the
    // script key acts as the internal key for the per-asset-ID
    // Pedersen script key derivation, and doubles as the mailbox
    // receiver (message encryption) key.
    let script_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;
    let internal_key_desc =
        node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;

    if node.config.courier_url.is_empty() {
        return Err(TapNodeError::Config(
            "V2 addresses require a courier URL with the \
             authmailbox+universerpc scheme"
                .into(),
        ));
    }

    let addr = address::new(NewAddressParams {
        version: AddressVersion::V2,
        asset_id: params.asset_id,
        group_key: params.group_key,
        script_key: script_key_desc.pub_key,
        internal_key: internal_key_desc.pub_key,
        amount: params.amount,
        asset_type: params.asset_type,
        network: node.config.network,
        proof_courier_addr: Some(node.config.courier_url.clone()),
        tapscript_sibling: None,
    })?;

    // Persist the address plus the descriptors behind its keys: the
    // unique per-asset script keys of incoming sends are derived from
    // the address script key, so the descriptor is the signing context
    // for every asset received on this address.
    {
        let mut store =
            node.mailbox_store.lock().expect("mailbox store lock");
        store.insert_address(&addr).map_err(TapNodeError::Storage)?;
        store
            .set_key_descriptors(
                &addr.script_key,
                &script_key_desc,
                &internal_key_desc,
            )
            .map_err(TapNodeError::Storage)?;
    }

    Ok(addr)
}

/// Polls the auth mailbox for all stored V2 addresses, mirroring the
/// receive path of Go's `tapgarden.Custodian`
/// (`handleMailboxMessages`):
///
/// 1. Fetch messages for the address script key (the mailbox receiver
///    key), starting after the persisted cursor.
/// 2. ECIES-decrypt each message with the node's mailbox signer and
///    decode + validate the contained [`proof::SendFragment`].
/// 3. Verify the fragment's block header against the node chain (the
///    header hash must match the chain's hash at that height).
/// 4. Derive the expected per-asset-ID script keys from the address.
/// 5. Fetch the transfer proof from the proof courier (universe half
///    of the authmailbox+universerpc courier), check it, and import it
///    into the proof and asset stores.
/// 6. Advance and persist the mailbox cursor, then remove processed
///    messages from the server (best-effort).
///
/// Without a configured mailbox transport this is a no-op that returns
/// an empty vec. A transport without a signer is a configuration
/// error.
pub(crate) fn poll_mailbox<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
) -> Result<Vec<ReceivedAsset>, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    // Serialize with the other asset-store-writing flows (see
    // `TapNode::send_lock`): the cursor read/advance and the proof and
    // asset imports below are not atomic, so a concurrent poll (or
    // send) must not interleave.
    let _send_guard = node.send_lock.lock().expect("send lock");

    // No transport configured: documented no-op.
    let transport = match &node.mailbox_transport {
        Some(t) => t.as_ref(),
        None => return Ok(vec![]),
    };
    let signer = node.mailbox_signer.as_deref().ok_or_else(|| {
        TapNodeError::Config(
            "mailbox transport configured without a mailbox signer"
                .into(),
        )
    })?;

    let addresses: Vec<TapAddress> = {
        let store = node.mailbox_store.lock().expect("mailbox store lock");
        store
            .list_addresses()
            .map_err(TapNodeError::Storage)?
            .into_iter()
            .filter(|a| a.version == AddressVersion::V2)
            .collect()
    };

    let mut received = Vec::new();

    for addr in addresses {
        // For V2 addresses the mailbox receiver key is the address
        // script key (Go: SendManifest.Receiver = addr.ScriptKey).
        let receiver_key = addr.script_key;

        // The wallet key descriptors stored when the address was
        // generated: the signing context attached to every asset
        // imported for this address. The unique per-asset script keys
        // below are tweaks of the address script key, so its
        // descriptor is the raw key behind them; the address internal
        // key is the anchor output internal key the sender used.
        let key_descs = node
            .mailbox_store
            .lock()
            .expect("mailbox store lock")
            .key_descriptors(&receiver_key)
            .map_err(TapNodeError::Storage)?;

        let cursor = node
            .mailbox_store
            .lock()
            .expect("mailbox store lock")
            .get_cursor(&receiver_key)
            .map_err(TapNodeError::Storage)?;

        let filter = MessageFilter {
            receiver_key: Some(receiver_key),
            after_id: cursor.last_message_id,
            ..Default::default()
        };
        let messages = transport.fetch_messages(&filter, signer)?;

        let mut new_cursor = cursor;
        let mut processed_ids = Vec::new();

        for msg in &messages {
            // Decryption or validation failures skip the message, so
            // nobody can corrupt our state by sending us a malformed
            // message (Go logs and continues here). The cursor is not
            // advanced for skipped messages.
            let fragment = match decrypt_send_fragment(
                signer,
                &receiver_key,
                &msg.encrypted_payload,
            ) {
                Ok(f) => f,
                Err(_) => continue,
            };

            // Verify the fragment's header against the node chain:
            // the chain's block hash at the claimed height must match
            // the header (Go fetches the block via the chain bridge).
            let chain_hash = node
                .chain
                .get_block_hash(fragment.block_height)
                .map_err(TapNodeError::Chain)?;
            if chain_hash != fragment.block_header.block_hash() {
                continue;
            }

            let mut fragment_ok = true;
            let mut fragment_assets = Vec::new();

            for (asset_id, output) in &fragment.outputs {
                // Derive the expected per-asset-ID script key from
                // the receiver key using the fragment's derivation
                // method (Go: asset.DeriveUniqueScriptKey in
                // handleMailboxMessages).
                let script_key = match derive_unique_script_key(
                    receiver_key,
                    asset_id,
                    output.derivation_method,
                ) {
                    Ok(k) => k.pub_key,
                    Err(_) => {
                        fragment_ok = false;
                        break;
                    }
                };

                // Defensive (not in Go): the sender-provided script
                // key must match our derivation.
                if script_key != output.script_key {
                    fragment_ok = false;
                    break;
                }

                // Fetch the transfer proof from the courier and
                // sanity check it against the fragment.
                let recipient = Recipient {
                    script_key,
                    asset_id: *asset_id,
                    amount: output.amount,
                };
                let locator = CourierLocator {
                    asset_id: *asset_id,
                    script_key,
                    outpoint: fragment.outpoint,
                };
                let annotated =
                    match node.courier.receive_proof(&recipient, &locator)
                    {
                        Ok(p) => p,
                        Err(_) => {
                            // Proof not (yet) available: leave the
                            // message unprocessed so a later poll
                            // retries.
                            fragment_ok = false;
                            break;
                        }
                    };

                let genesis = check_received_proof(
                    &annotated.proof_file,
                    asset_id,
                    &script_key,
                    output.amount,
                )?;

                fragment_assets.push((
                    ReceivedAsset {
                        asset_id: *asset_id,
                        amount: output.amount,
                        script_key,
                        anchor_outpoint: fragment.outpoint,
                        block_height: fragment.block_height,
                    },
                    annotated.proof_file,
                    genesis,
                ));
            }

            if !fragment_ok {
                continue;
            }

            // All outputs of this fragment check out: import them.
            for (asset, proof_file, genesis) in fragment_assets {
                node.proof_store
                    .lock()
                    .expect("proof store lock")
                    .insert_proof(
                        ProofLocator {
                            outpoint: asset.anchor_outpoint,
                            script_key: asset.script_key,
                        },
                        proof_file,
                    )
                    .map_err(TapNodeError::Storage)?;

                // Persist the asset with its full context: the block
                // height from the chain-verified fragment, the genesis
                // fields from the verified proof (needed to
                // reconstruct the Genesis when spending), and the key
                // descriptors stored with the address (the signing
                // context; see the `key_descs` lookup above).
                //
                // NOTE: the unique per-asset script key is a
                // Pedersen-leaf tapscript tweak of the address key.
                // `send_asset` recomputes that leaf's tap hash from
                // the stored descriptor (see `tapscript_root_for` in
                // `send.rs`) and signs through
                // `AssetSigner::sign_virtual_tx_tweaked`; a signer
                // that does not implement the tapscript-tweak
                // extension rejects the send with a precise error.
                let mut owned = OwnedAsset::new(
                    asset.asset_id,
                    asset.amount,
                    asset.anchor_outpoint,
                    asset.script_key,
                    asset.block_height,
                );
                if let Some((script_desc, internal_desc)) = &key_descs {
                    owned.script_key_desc = Some(script_desc.clone());
                    owned.internal_key = Some(internal_desc.clone());
                }
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

                node.event_bus.emit(
                    crate::event::TapEvent::AssetReceived {
                        asset_id: asset.asset_id,
                        amount: asset.amount,
                        outpoint: asset.anchor_outpoint,
                    },
                );

                received.push(asset);
            }

            processed_ids.push(msg.id);
            new_cursor.last_message_id =
                new_cursor.last_message_id.max(msg.id);
            new_cursor.last_block =
                new_cursor.last_block.max(fragment.block_height);
        }

        // Persist the advanced cursor.
        if new_cursor != cursor {
            node.mailbox_store
                .lock()
                .expect("mailbox store lock")
                .set_cursor(&receiver_key, new_cursor)
                .map_err(TapNodeError::Storage)?;
        }

        // Best-effort removal of the processed messages from the
        // server (Go: removeMailboxMessages, warn on failure).
        if !processed_ids.is_empty() {
            let challenge = remove_message_challenge(
                receiver_key.as_bytes(),
                &processed_ids,
            );
            if let Ok(sig) =
                signer.sign_challenge(&receiver_key, &challenge)
            {
                let _ = transport.remove_messages(
                    &receiver_key,
                    &processed_ids,
                    &sig,
                );
            }
        }
    }

    Ok(received)
}

/// Checks a proof file received for a V2 mailbox transfer: the hash
/// chain must verify and the final proof's asset must match the
/// fragment output (asset ID, derived script key, and amount).
/// Returns the asset's [`Genesis`] from the verified proof so the
/// import can persist the genesis fields (needed to reconstruct the
/// `Genesis` when the asset is later spent).
///
/// NOTE: this performs structural validation plus asset binding; full
/// chain verification of every transition (`File::verify` with a
/// `VerifierCtx`) is a follow-up once the node wires header/merkle
/// verifiers from its chain backend.
fn check_received_proof(
    proof_file: &proof::File,
    asset_id: &AssetId,
    script_key: &SerializedKey,
    amount: u64,
) -> Result<Genesis, TapNodeError> {
    if !proof_file.verify_hash_chain() {
        return Err(TapNodeError::Storage(
            "received proof file has an invalid hash chain".into(),
        ));
    }

    let last = proof_file.proofs.last().ok_or_else(|| {
        TapNodeError::Storage("received proof file is empty".into())
    })?;
    let decoded = proof::decode::decode_proof(&last.proof_bytes)
        .map_err(|e| TapNodeError::Storage(e.to_string()))?;

    if decoded.asset.id() != *asset_id {
        return Err(TapNodeError::Storage(
            "received proof asset ID mismatch".into(),
        ));
    }
    if decoded.asset.script_key.pub_key != *script_key {
        return Err(TapNodeError::Storage(
            "received proof script key mismatch".into(),
        ));
    }
    if decoded.asset.amount != amount {
        return Err(TapNodeError::Storage(
            "received proof amount mismatch".into(),
        ));
    }

    Ok(decoded.asset.genesis)
}

/// Imports a proof file, persisting the contained asset (the V0/V1
/// address receive path; V2 authmailbox receives go through
/// [`poll_mailbox`]).
///
/// The final proof of the file identifies the received output: its
/// asset (ID, amount, genesis), script key, and anchor outpoint (the
/// anchor transaction plus the inclusion proof's output index). The
/// proof file is stored under that locator and the asset is persisted
/// with its genesis fields and the verified block height. When the
/// script key belongs to an address this node generated (it is in the
/// address book, see [`new_address`]), the stored key descriptors are
/// attached so the asset can be signed and sent onward.
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
    // Serialize with the other asset-store-writing flows (see
    // `TapNode::send_lock`).
    let _send_guard = node.send_lock.lock().expect("send lock");

    // Verify the proof file hash chain.
    if !proof_file.verify_hash_chain() {
        return Err(TapNodeError::Storage(
            "invalid proof file hash chain".into(),
        ));
    }

    // The final proof carries the asset output being imported.
    let last = proof_file.proofs.last().ok_or_else(|| {
        TapNodeError::Storage(
            "imported proof file contains no proofs".into(),
        )
    })?;
    let decoded = proof::decode::decode_proof(&last.proof_bytes)
        .map_err(|e| {
            TapNodeError::Storage(format!("final proof decode: {}", e))
        })?;

    let asset_id = decoded.asset.id();
    let amount = decoded.asset.amount;
    let script_key = decoded.asset.script_key.pub_key;
    let outpoint = decoded.out_point();

    node.proof_store
        .lock()
        .expect("proof store lock")
        .insert_proof(
            ProofLocator {
                outpoint,
                script_key,
            },
            proof_file,
        )
        .map_err(TapNodeError::Storage)?;

    // If the proof pays an address this node generated, attach the key
    // descriptors stored with it (the signing context); a proof for a
    // foreign/watch-only key imports without them and simply cannot be
    // spent from here.
    let key_descs = node
        .mailbox_store
        .lock()
        .expect("mailbox store lock")
        .key_descriptors(&script_key)
        .map_err(TapNodeError::Storage)?;

    let mut owned = OwnedAsset::new(
        asset_id,
        amount,
        outpoint,
        script_key,
        decoded.block_height,
    );
    if let Some((script_desc, internal_desc)) = key_descs {
        owned.script_key_desc = Some(script_desc);
        owned.internal_key = Some(internal_desc);
    }
    let genesis = &decoded.asset.genesis;
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

    node.event_bus.emit(crate::event::TapEvent::AssetReceived {
        asset_id,
        amount,
        outpoint,
    });

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
    let store = node.proof_store.lock().expect("proof store lock");
    store
        .get_proof(&locator)
        .map_err(|e| TapNodeError::Storage(e))?
        .ok_or(TapNodeError::Storage("proof not found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use bitcoin::secp256k1;
    use tap_ldk::rfq::manager::{PriceOracle, RfqError};
    use tap_ldk::rfq::math::FixedPoint;
    use tap_onchain::chain::{ChainError, FeeRate, KeyDescriptor};
    use tap_onchain::proof::courier::{
        AnnotatedProof, Courier, CourierError, MockCourier,
    };
    use tap_onchain::proof::mailbox::{
        build_send_fragment, build_tx_proof, deliver_send_manifest,
        MockTransport, SendManifest, SoftMailboxSigner,
    };
    use tap_primitives::asset::{
        Asset, AssetVersion, Genesis, ScriptKey,
        ScriptKeyDerivationMethod,
    };
    use tap_primitives::proof::send_fragment::SendOutput;
    use tap_primitives::proof::types::{AnchorTx, BlockHeader};

    use crate::builder::TapNodeBuilder;
    use crate::config::TapNodeConfig;

    // -----------------------------------------------------------------
    // Minimal mock backends for a TapNode under test.
    // -----------------------------------------------------------------

    /// A chain bridge that knows a single block hash per height.
    struct MockChain {
        block_hashes: Mutex<std::collections::HashMap<u32, [u8; 32]>>,
    }

    impl MockChain {
        fn with_block(height: u32, hash: [u8; 32]) -> Self {
            MockChain {
                block_hashes: Mutex::new(
                    std::collections::HashMap::from([(height, hash)]),
                ),
            }
        }
    }

    impl ChainBridge for MockChain {
        fn current_height(&self) -> Result<u32, ChainError> {
            Ok(800_000)
        }
        fn estimate_fee(&self, _: u32) -> Result<FeeRate, ChainError> {
            Ok(FeeRate(2000))
        }
        fn publish_transaction(&self, _: &[u8]) -> Result<(), ChainError> {
            Ok(())
        }
        fn get_block_hash(
            &self,
            height: u32,
        ) -> Result<[u8; 32], ChainError> {
            self.block_hashes
                .lock()
                .unwrap()
                .get(&height)
                .copied()
                .ok_or_else(|| {
                    ChainError::ConfirmationFailed(
                        "unknown block".into(),
                    )
                })
        }
    }

    struct MockWallet;

    impl WalletAnchor for MockWallet {
        fn fund_psbt(
            &self,
            _: &[u8],
            _: FeeRate,
        ) -> Result<Vec<u8>, ChainError> {
            Ok(vec![])
        }
        fn sign_and_finalize_psbt(
            &self,
            _: &[u8],
        ) -> Result<Vec<u8>, ChainError> {
            Ok(vec![])
        }
        fn import_taproot_output(
            &self,
            _: &SerializedKey,
        ) -> Result<(), ChainError> {
            Ok(())
        }
    }

    /// Derives deterministic keys: index N uses secret [N+1; 32].
    struct MockKeys {
        next_index: Mutex<u32>,
    }

    impl MockKeys {
        fn new() -> Self {
            MockKeys {
                next_index: Mutex::new(0),
            }
        }

        fn secret_for(index: u32) -> secp256k1::SecretKey {
            secp256k1::SecretKey::from_slice(&[(index + 1) as u8; 32])
                .expect("valid secret")
        }
    }

    impl KeyRing for MockKeys {
        fn derive_next_key(
            &self,
            family: u16,
        ) -> Result<KeyDescriptor, ChainError> {
            let mut next = self.next_index.lock().unwrap();
            let index = *next;
            *next += 1;

            let secp = secp256k1::Secp256k1::new();
            let pub_key = SerializedKey(
                Self::secret_for(index).public_key(&secp).serialize(),
            );
            Ok(KeyDescriptor {
                family,
                index,
                pub_key,
            })
        }

        fn is_local_key(
            &self,
            _: &KeyDescriptor,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }
    }

    impl AssetSigner for MockKeys {
        fn sign_virtual_tx(
            &self,
            _: &KeyDescriptor,
            _: &[u8],
        ) -> Result<Vec<u8>, ChainError> {
            Ok(vec![])
        }
    }

    struct MockLdk;

    impl LdkChannelOps for MockLdk {
        fn forward_intercepted_htlc(
            &self,
            _: [u8; 32],
            _: u64,
            _: [u8; 33],
            _: u64,
        ) -> Result<(), String> {
            Ok(())
        }
        fn fail_intercepted_htlc(
            &self,
            _: [u8; 32],
        ) -> Result<(), String> {
            Ok(())
        }
    }

    struct MockOracle;

    impl PriceOracle for MockOracle {
        fn ask_price(
            &self,
            _: &AssetId,
            _: u64,
        ) -> Result<FixedPoint, RfqError> {
            Ok(FixedPoint::from_integer(5000))
        }
        fn bid_price(
            &self,
            _: &AssetId,
            _: u64,
        ) -> Result<FixedPoint, RfqError> {
            Ok(FixedPoint::from_integer(5000))
        }
    }

    /// A courier wrapper so the test (sender) and the node (receiver)
    /// share the same in-memory proof store.
    struct SharedCourier(Arc<MockCourier>);

    impl Courier for SharedCourier {
        fn deliver_proof(
            &self,
            recipient: &Recipient,
            proof: &AnnotatedProof,
        ) -> Result<(), CourierError> {
            self.0.deliver_proof(recipient, proof)
        }
        fn receive_proof(
            &self,
            recipient: &Recipient,
            locator: &CourierLocator,
        ) -> Result<AnnotatedProof, CourierError> {
            self.0.receive_proof(recipient, locator)
        }
    }

    // -----------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------

    const COURIER_URL: &str =
        "authmailbox+universerpc://localhost:10029";

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "mailbox-test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn build_node(
        chain: MockChain,
        transport: Arc<MockTransport>,
        courier: Arc<MockCourier>,
        signer: SoftMailboxSigner,
    ) -> crate::TapNode<MockChain, MockWallet, MockKeys, MockLdk, MockOracle>
    {
        let config = TapNodeConfig {
            courier_url: COURIER_URL.to_string(),
            ..Default::default()
        };
        TapNodeBuilder::new(config)
            .set_chain_bridge(chain)
            .set_wallet_anchor(MockWallet)
            .set_key_ring(MockKeys::new())
            .set_ldk_ops(MockLdk)
            .set_price_oracle(MockOracle)
            .set_courier(Box::new(SharedCourier(courier)))
            .set_mailbox_transport(Box::new(transport))
            .set_mailbox_signer(Box::new(signer))
            .build()
            .expect("node builds")
    }

    /// Builds a valid tx proof over a single-tx block whose only
    /// output is a BIP-86 P2TR output for the given anchor key.
    fn test_tx_proof(
        anchor_internal_key: SerializedKey,
        header: BlockHeader,
        height: u32,
    ) -> tap_primitives::proof::TxProof {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
        use tap_primitives::crypto::tapscript::taproot_output_key;

        let output_key =
            taproot_output_key(&anchor_internal_key, &[]).unwrap();
        let mut script = Vec::with_capacity(34);
        script.push(0x51);
        script.push(0x20);
        script.extend_from_slice(&output_key);

        let tx = AnchorTx(Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
        });
        let txid = tx.txid();

        // The tx proof's own header merkle root must commit to the
        // tx (single-tx block), but the fragment header is what the
        // node chain-checks; use the same header for both, patched
        // with the tx merkle root.
        let mut header_bytes = *header.as_bytes();
        header_bytes[36..68].copy_from_slice(&txid);

        build_tx_proof(
            tx,
            BlockHeader(header_bytes),
            height,
            &[txid],
            0,
            anchor_internal_key,
            None,
        )
        .unwrap()
    }

    /// Encodes a minimal single-proof file whose final asset matches
    /// the given ID, amount, and script key.
    fn test_proof_file(
        genesis: Genesis,
        amount: u64,
        script_key: SerializedKey,
    ) -> proof::File {
        let p = proof::Proof {
            version: proof::TransitionVersion::V0,
            prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            block_header: BlockHeader([0u8; 80]),
            block_height: 123,
            anchor_tx: AnchorTx::default(),
            tx_merkle_proof: proof::TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset: Asset::new_genesis(
                genesis,
                amount,
                ScriptKey::from_pub_key(script_key),
            ),
            inclusion_proof: proof::TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                tapscript_proof: None,
                unknown_odd_types: BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: None,
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: BTreeMap::new(),
        };

        let mut file = proof::File::new();
        file.append_proof(proof::encode_proof(&p));
        file
    }

    // -----------------------------------------------------------------
    // End-to-end: sender builds and delivers a manifest, the receiver
    // node polls the mailbox, decrypts, validates, and imports.
    // -----------------------------------------------------------------

    #[test]
    fn test_mailbox_receive_end_to_end() {
        let genesis = test_genesis();
        let asset_id = genesis.id();
        let amount = 42u64;
        let height = 123u32;

        // The fragment's block header; the node's chain knows its
        // hash at the given height (fake chain verifier). The tx
        // proof needs the tx merkle root patched in, so compute the
        // final header first via the tx proof below.
        let anchor_internal_key = {
            let secp = secp256k1::Secp256k1::new();
            let sk =
                secp256k1::SecretKey::from_slice(&[0x77; 32]).unwrap();
            SerializedKey(sk.public_key(&secp).serialize())
        };
        let tx_proof = test_tx_proof(
            anchor_internal_key,
            BlockHeader([0u8; 80]),
            height,
        );
        let header = tx_proof.block_header.clone();
        let anchor_outpoint = tx_proof.claimed_outpoint;

        // The receiver node. Its first derived key (index 0, secret
        // [1; 32]) becomes the V2 address script key, which the
        // mailbox signer must know for ECDH.
        let mut signer = SoftMailboxSigner::new();
        signer.add_key(MockKeys::secret_for(0));

        let transport = Arc::new(MockTransport::new());
        let courier = Arc::new(MockCourier::new());
        let chain = MockChain::with_block(height, header.block_hash());
        let node = build_node(
            chain,
            Arc::clone(&transport),
            Arc::clone(&courier),
            signer,
        );

        let addr = node
            .new_address_v2(V2AddressParams {
                asset_id: Some(asset_id),
                group_key: None,
                amount: 0,
                asset_type: AssetType::Normal,
            })
            .unwrap();
        assert_eq!(addr.version, AddressVersion::V2);
        assert_eq!(
            addr.proof_courier_addr.as_deref(),
            Some(COURIER_URL)
        );

        // ---- Sender side ----
        // Derive the receiver's unique script key for the asset from
        // the address (Go: DeriveUniqueScriptKey in
        // createSendManifests).
        let script_key =
            addr.script_key_for_asset_id(&asset_id).unwrap();

        // Publish the transfer proof to the shared courier.
        let proof_file =
            test_proof_file(genesis, amount, script_key);
        courier
            .deliver_proof(
                &Recipient {
                    script_key,
                    asset_id,
                    amount,
                },
                &AnnotatedProof {
                    locator: CourierLocator {
                        asset_id,
                        script_key,
                        outpoint: anchor_outpoint,
                    },
                    proof_file,
                },
            )
            .unwrap();

        // Build and deliver the manifest through the mailbox.
        let fragment = build_send_fragment(
            header,
            height,
            anchor_outpoint,
            [0xAB; 32],
            BTreeMap::from([(
                asset_id,
                SendOutput {
                    asset_version: AssetVersion::V0,
                    amount,
                    derivation_method:
                        ScriptKeyDerivationMethod::UniquePedersen,
                    script_key,
                },
            )]),
        )
        .unwrap();

        deliver_send_manifest(
            &*transport,
            &SendManifest {
                tx_proof,
                receiver: addr.script_key,
                courier_url: COURIER_URL.to_string(),
                fragment,
            },
        )
        .unwrap();
        assert_eq!(transport.num_messages(), 1);

        // ---- Receiver side ----
        let received = node.poll_mailbox().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].asset_id, asset_id);
        assert_eq!(received[0].amount, amount);
        assert_eq!(received[0].script_key, script_key);
        assert_eq!(received[0].anchor_outpoint, anchor_outpoint);
        assert_eq!(received[0].block_height, height);

        // The asset landed in the asset store.
        assert_eq!(node.get_balance(&asset_id).unwrap(), amount);

        // The imported asset carries its signing and genesis context:
        // the descriptor behind the ADDRESS script key (the raw key
        // the unique per-asset script key is derived from), the
        // address internal key (the anchor output internal key), the
        // genesis fields from the verified proof, and the verified
        // block height.
        let assets = node.list_assets().unwrap();
        assert_eq!(assets.len(), 1);
        let owned = &assets[0];
        let script_desc =
            owned.script_key_desc.as_ref().expect("descriptor stored");
        assert_eq!(script_desc.pub_key, addr.script_key);
        let internal_desc =
            owned.internal_key.as_ref().expect("internal key stored");
        assert_eq!(internal_desc.pub_key, addr.internal_key);
        assert_eq!(owned.genesis_tag.as_deref(), Some("mailbox-test"));
        assert_eq!(
            owned.genesis_point,
            Some(OutPoint {
                txid: [0x01; 32],
                vout: 0,
            })
        );
        assert_eq!(owned.block_height, height);

        // MockKeys does not override
        // `AssetSigner::sign_virtual_tx_tweaked`, so sending a
        // V2-received asset onward is refused by the default
        // implementation with a precise error naming the required
        // extension (NOT a misleading UnknownScriptKey): the send
        // path correctly classified the input as a Pedersen-tweaked
        // unique script key and routed it to the tweaked method.
        // (The full harness signer overrides the method; see the
        // end-to-end onward-send test in tests/receive_flow.rs.)
        let onward = TapAddress {
            version: AddressVersion::V0,
            asset_version: 0,
            asset_id: Some(asset_id),
            script_key: SerializedKey(
                secp256k1::SecretKey::from_slice(&[0x21; 32])
                    .unwrap()
                    .public_key(&secp256k1::Secp256k1::new())
                    .serialize(),
            ),
            internal_key: SerializedKey(
                secp256k1::SecretKey::from_slice(&[0x22; 32])
                    .unwrap()
                    .public_key(&secp256k1::Secp256k1::new())
                    .serialize(),
            ),
            amount,
            network: tap_primitives::address::TapNetwork::Regtest,
            proof_courier_addr: None,
            group_key: None,
            tapscript_sibling: None,
            unknown_odd_types: BTreeMap::new(),
        };
        let err =
            node.send_asset(asset_id, amount, &onward).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("sign_virtual_tx_tweaked"),
            "unexpected error: {}",
            msg
        );
        assert!(
            !msg.contains("unknown script key"),
            "must not degrade to UnknownScriptKey: {}",
            msg
        );
        // The refused send left the asset untouched.
        assert_eq!(node.get_balance(&asset_id).unwrap(), amount);

        // The proof landed in the proof store.
        let exported = node
            .export_proof(&anchor_outpoint, &script_key)
            .unwrap();
        assert_eq!(exported.num_proofs(), 1);

        // The processed message was removed from the server and the
        // cursor advanced: a second poll imports nothing.
        assert_eq!(transport.num_messages(), 0);
        assert!(node.poll_mailbox().unwrap().is_empty());
        assert_eq!(node.get_balance(&asset_id).unwrap(), amount);
    }

    #[test]
    fn test_poll_mailbox_without_transport_is_noop() {
        let config = TapNodeConfig {
            courier_url: COURIER_URL.to_string(),
            ..Default::default()
        };
        let node = TapNodeBuilder::new(config)
            .set_chain_bridge(MockChain::with_block(0, [0u8; 32]))
            .set_wallet_anchor(MockWallet)
            .set_key_ring(MockKeys::new())
            .set_ldk_ops(MockLdk)
            .set_price_oracle(MockOracle)
            .build()
            .unwrap();

        assert!(node.poll_mailbox().unwrap().is_empty());
    }

    #[test]
    fn test_poll_mailbox_keeps_message_until_proof_available() {
        let genesis = test_genesis();
        let asset_id = genesis.id();
        let height = 123u32;

        let anchor_internal_key = {
            let secp = secp256k1::Secp256k1::new();
            let sk =
                secp256k1::SecretKey::from_slice(&[0x78; 32]).unwrap();
            SerializedKey(sk.public_key(&secp).serialize())
        };
        let tx_proof = test_tx_proof(
            anchor_internal_key,
            BlockHeader([0u8; 80]),
            height,
        );
        let header = tx_proof.block_header.clone();

        let mut signer = SoftMailboxSigner::new();
        signer.add_key(MockKeys::secret_for(0));

        let transport = Arc::new(MockTransport::new());
        let courier = Arc::new(MockCourier::new());
        let node = build_node(
            MockChain::with_block(height, header.block_hash()),
            Arc::clone(&transport),
            Arc::clone(&courier),
            signer,
        );

        let addr = node
            .new_address_v2(V2AddressParams {
                asset_id: Some(asset_id),
                group_key: None,
                amount: 0,
                asset_type: AssetType::Normal,
            })
            .unwrap();
        let script_key =
            addr.script_key_for_asset_id(&asset_id).unwrap();

        // Deliver the manifest, but do NOT publish the proof to the
        // courier yet.
        let fragment = build_send_fragment(
            header,
            height,
            tx_proof.claimed_outpoint,
            [0xAB; 32],
            BTreeMap::from([(
                asset_id,
                SendOutput {
                    asset_version: AssetVersion::V0,
                    amount: 42,
                    derivation_method:
                        ScriptKeyDerivationMethod::UniquePedersen,
                    script_key,
                },
            )]),
        )
        .unwrap();
        let outpoint = tx_proof.claimed_outpoint;
        deliver_send_manifest(
            &*transport,
            &SendManifest {
                tx_proof,
                receiver: addr.script_key,
                courier_url: COURIER_URL.to_string(),
                fragment,
            },
        )
        .unwrap();

        // The proof isn't available: nothing is imported, the message
        // stays on the server, and the cursor is not advanced.
        assert!(node.poll_mailbox().unwrap().is_empty());
        assert_eq!(transport.num_messages(), 1);
        assert_eq!(node.get_balance(&asset_id).unwrap(), 0);

        // Once the proof shows up, a later poll imports it.
        courier
            .deliver_proof(
                &Recipient {
                    script_key,
                    asset_id,
                    amount: 42,
                },
                &AnnotatedProof {
                    locator: CourierLocator {
                        asset_id,
                        script_key,
                        outpoint,
                    },
                    proof_file: test_proof_file(
                        genesis, 42, script_key,
                    ),
                },
            )
            .unwrap();

        let received = node.poll_mailbox().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(node.get_balance(&asset_id).unwrap(), 42);
        assert_eq!(transport.num_messages(), 0);
    }
}
