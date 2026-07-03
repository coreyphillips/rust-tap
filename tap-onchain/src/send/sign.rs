// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Virtual transaction signing for asset transfers.
//!
//! After [`TransferBuilder::prepare_outputs`] creates the transfer structure,
//! [`sign_transfer`] fills in the `tx_witness` fields by computing the
//! BIP-341 sighash of the virtual transaction and calling the [`VirtualSigner`].

use std::collections::BTreeMap;

use bitcoin::sighash::TapSighashType;

use tap_primitives::asset::{
    Asset, AssetVersion, Genesis, PrevId, ScriptKey, ScriptVersion, Witness,
};
use tap_primitives::crypto::virtual_tx;
use tap_primitives::vm::InputSet;

use super::transfer::{PreparedTransfer, SendError};

/// Trait for signing virtual TAP transactions.
///
/// Implementations must produce a 64-byte Schnorr signature (BIP-340)
/// over the provided sighash using the private key corresponding to
/// the given script key.
pub trait VirtualSigner {
    fn sign_virtual_tx(
        &self,
        sighash: &[u8; 32],
        script_key: &ScriptKey,
    ) -> Result<Vec<u8>, SendError>;
}

/// Signs a prepared transfer by computing virtual transaction sighashes
/// and calling the signer for each input witness.
///
/// This fills in the `tx_witness` field on each witness in the root
/// asset. The split commitment root is left untouched — it is part of
/// the message being signed.
pub fn sign_transfer(
    prepared: &mut PreparedTransfer,
    prev_assets: &InputSet,
    signer: &dyn VirtualSigner,
) -> Result<(), SendError> {
    // Build the virtual transaction.
    let (base_tx, _, _) = virtual_tx::virtual_tx(&prepared.root_asset, prev_assets)
        .map_err(|e| SendError::InvalidState(format!("virtual tx: {}", e)))?;

    // First pass: compute sighashes and generate signatures (immutable borrow).
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for (idx, witness) in prepared.root_asset.prev_witnesses.iter().enumerate() {
        let prev_id = witness
            .prev_id
            .as_ref()
            .ok_or_else(|| SendError::InvalidState("witness has no prev_id".into()))?;

        let prev_asset = prev_assets
            .get(prev_id)
            .ok_or_else(|| SendError::InvalidState("prev_id not found in input set".into()))?;

        let sighash = virtual_tx::input_key_spend_sighash(
            &base_tx,
            prev_asset,
            &prepared.root_asset,
            idx as u32,
            TapSighashType::Default,
        )
        .map_err(|e| SendError::InvalidState(format!("sighash: {}", e)))?;

        let sig_bytes = signer.sign_virtual_tx(&sighash, &prev_asset.script_key)?;
        signatures.push(sig_bytes);
    }

    // Second pass: apply signatures (mutable borrow).
    for (witness, sig) in prepared.root_asset.prev_witnesses.iter_mut().zip(signatures) {
        witness.tx_witness = vec![sig];
    }

    // Note: the split commitment root is intentionally NOT rebuilt
    // here. The sighash above commits to the split commitment root via
    // the virtual transaction output, so changing it after signing
    // would invalidate the signatures. This mirrors Go, where the split
    // tree is built once (unsigned leaves) during funding and never
    // rebuilt (commitment/split.go NewSplitCommitment).

    Ok(())
}

/// Builds and signs a full-value, 1-input/1-output re-anchoring
/// transition for a passive asset, mirroring Go's `createPassivePacket`
/// + `SignPassiveAssets` (tapfreighter/wallet.go): the output asset
/// keeps the passive asset's script key, amount, and asset version; its
/// genesis/previous witness is replaced by a single witness whose
/// `PrevID` points at the passive asset's old anchor outpoint, and that
/// witness is signed by the passive asset's own key (a BIP-86 key
/// spend), producing a real transition witness with no split commitment.
///
/// `prev_id` is the passive asset's previous identity (old anchor
/// outpoint + asset id + script key); `prev_asset` is the passive asset
/// exactly as it exists on chain (used to compute the sighash and to
/// resolve the signing key via [`VirtualSigner`]).
pub fn sign_passive_transition(
    prev_id: &PrevId,
    prev_asset: &Asset,
    genesis: &Genesis,
    amount: u64,
    asset_version: AssetVersion,
    script_key: &ScriptKey,
    signer: &dyn VirtualSigner,
) -> Result<Asset, SendError> {
    let mut new_asset = Asset {
        version: asset_version,
        genesis: genesis.clone(),
        amount,
        lock_time: 0,
        relative_lock_time: 0,
        prev_witnesses: vec![Witness {
            prev_id: Some(prev_id.clone()),
            tx_witness: vec![],
            split_commitment: None,
        }],
        split_commitment_root: None,
        script_version: ScriptVersion::V0,
        script_key: script_key.clone(),
        group_key: None,
        unknown_odd_types: BTreeMap::new(),
    };

    let mut prev_assets = InputSet::new();
    prev_assets.insert(prev_id.clone(), prev_asset.clone());

    let (base_tx, _, _) = virtual_tx::virtual_tx(&new_asset, &prev_assets)
        .map_err(|e| {
            SendError::InvalidState(format!("passive virtual tx: {}", e))
        })?;
    let sighash = virtual_tx::input_key_spend_sighash(
        &base_tx,
        prev_asset,
        &new_asset,
        0,
        TapSighashType::Default,
    )
    .map_err(|e| {
        SendError::InvalidState(format!("passive sighash: {}", e))
    })?;

    let sig = signer.sign_virtual_tx(&sighash, &prev_asset.script_key)?;
    new_asset.prev_witnesses[0].tx_witness = vec![sig];

    Ok(new_asset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use tap_primitives::asset::*;

    struct TestSigner {
        keypair: Keypair,
    }

    impl VirtualSigner for TestSigner {
        fn sign_virtual_tx(
            &self,
            sighash: &[u8; 32],
            _script_key: &ScriptKey,
        ) -> Result<Vec<u8>, SendError> {
            let secp = Secp256k1::new();
            let msg = Message::from_digest(*sighash);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
            Ok(sig.as_ref().to_vec())
        }
    }

    fn test_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x01;
        let sk = SecretKey::from_slice(&secret).unwrap();
        Keypair::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_sign_full_transfer() {
        let keypair = test_keypair();
        let (x_only, _) = keypair.x_only_public_key();
        let mut pub_key_bytes = [0u8; 33];
        pub_key_bytes[0] = 0x02;
        pub_key_bytes[1..].copy_from_slice(&x_only.serialize());
        let prev_key = SerializedKey(pub_key_bytes);

        let genesis = Genesis {
            first_prev_out: OutPoint { txid: [0x01; 32], vout: 0 },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: OutPoint { txid: [0xBB; 32], vout: 0 },
            id: genesis.id(),
            script_key: prev_key,
        };

        let inputs = vec![super::super::allocation::SelectedInput {
            prev_id: prev_id.clone(),
            anchor_point: OutPoint { txid: [0xBB; 32], vout: 0 },
            amount: 100,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(prev_key),
        }];

        let outputs = vec![super::super::allocation::TransferOutput {
            output_index: 0,
            amount: 100,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }];

        let mut prepared = super::super::transfer::TransferBuilder::prepare_outputs(
            &inputs, &outputs, &genesis,
        )
        .unwrap();

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset);

        let signer = TestSigner { keypair };
        sign_transfer(&mut prepared, &prev_assets, &signer).unwrap();

        // Witness should now be populated.
        assert!(!prepared.root_asset.prev_witnesses[0].tx_witness.is_empty());
        assert_eq!(
            prepared.root_asset.prev_witnesses[0].tx_witness[0].len(),
            64
        );
    }
}
