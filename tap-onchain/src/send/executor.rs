// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transfer executor — end-to-end orchestration of asset transfers.
//!
//! [`execute_transfer`] wires together the full pipeline:
//! 1. Validate allocations
//! 2. Prepare outputs (split commitments if needed)
//! 3. Populate split proofs
//! 4. Sign virtual transactions
//! 5. Build anchor PSBT template
//!
//! The caller is responsible for funding, signing, and broadcasting the
//! anchor transaction, then generating transition proofs after confirmation.

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;
use bitcoin_hashes::Hash;

use tap_primitives::asset::Genesis;
use tap_primitives::commitment::TapCommitmentVersion;
use tap_primitives::vm::InputSet;

use super::allocation::{SelectedInput, TransferOutput};
use super::sign::{sign_transfer, VirtualSigner};
use super::split_proof::populate_split_proofs;
use super::transfer::{PreparedTransfer, SendError, TransferBuilder};
use crate::psbt::transfer::{create_transfer_template, OutputDescriptor, TransferTemplate};

/// The result of executing a transfer.
#[derive(Clone, Debug)]
pub struct TransferResult {
    /// The prepared transfer with signed witnesses and split proofs.
    pub prepared: PreparedTransfer,
    /// The unsigned anchor transaction template with TAP commitments.
    pub template: TransferTemplate,
}

/// Options for the transfer pipeline, the Rust analogue of Go's
/// `tapsend.OutputCommitmentOption` set.
#[derive(Clone, Debug, Default)]
pub struct TransferOptions {
    /// Explicit Taproot Asset commitment version for the created
    /// output commitments. `None` derives the version from the asset
    /// versions. V1 and V2 addresses (and V1 virtual packets) require
    /// V2 commitments.
    pub commitment_version: Option<TapCommitmentVersion>,
    /// Skips merging STXO spent-asset markers (alt leaves) into the
    /// transfer root output commitment, mirroring Go's
    /// `tapsend.WithNoSTXOProofs`. Should only be used for asset
    /// channels to preserve backward compatibility with older peers;
    /// the default (false) matches Go, which merges STXO alt leaves
    /// for every regular send.
    pub no_stxo_proofs: bool,
}

/// Executes an end-to-end asset transfer.
///
/// This is the main entry point for creating asset transfers. It:
/// 1. Validates and prepares output allocations
/// 2. Populates split commitment proofs (for partial sends)
/// 3. Signs virtual transactions with the provided signer
/// 4. Builds the anchor transaction template
///
/// After calling this, the caller must:
/// - Fund the anchor transaction with BTC inputs (via wallet)
/// - Sign the Bitcoin transaction
/// - Broadcast it
/// - Generate transition proofs after confirmation
pub fn execute_transfer(
    inputs: &[SelectedInput],
    outputs: &[TransferOutput],
    genesis: &Genesis,
    prev_assets: &InputSet,
    signer: &dyn VirtualSigner,
    internal_keys: &[XOnlyPublicKey],
) -> Result<TransferResult, SendError> {
    execute_transfer_with_version(
        inputs,
        outputs,
        genesis,
        prev_assets,
        signer,
        internal_keys,
        None,
    )
}

/// Executes an end-to-end asset transfer with an explicit Taproot Asset
/// commitment version for the created output commitments.
///
/// The version comes from the destination: V1 and V2 addresses (and V1
/// virtual packets) require V2 commitments, while `None` derives the
/// version from the asset versions. See
/// [`tap_primitives::address::TapAddress::commitment_version`].
pub fn execute_transfer_with_version(
    inputs: &[SelectedInput],
    outputs: &[TransferOutput],
    genesis: &Genesis,
    prev_assets: &InputSet,
    signer: &dyn VirtualSigner,
    internal_keys: &[XOnlyPublicKey],
    commitment_version: Option<TapCommitmentVersion>,
) -> Result<TransferResult, SendError> {
    execute_transfer_with_options(
        inputs,
        outputs,
        genesis,
        prev_assets,
        signer,
        internal_keys,
        &TransferOptions {
            commitment_version,
            ..TransferOptions::default()
        },
    )
}

/// Executes an end-to-end asset transfer with explicit
/// [`TransferOptions`].
///
/// By default (like Go's `tapsend.CreateOutputCommitments`), STXO
/// spent-asset markers for the transfer inputs are merged into the
/// transfer root output commitment before the anchor output scripts
/// are computed; set [`TransferOptions::no_stxo_proofs`] to opt out
/// (Go's `tapsend.WithNoSTXOProofs`, used for asset channels).
pub fn execute_transfer_with_options(
    inputs: &[SelectedInput],
    outputs: &[TransferOutput],
    genesis: &Genesis,
    prev_assets: &InputSet,
    signer: &dyn VirtualSigner,
    internal_keys: &[XOnlyPublicKey],
    options: &TransferOptions,
) -> Result<TransferResult, SendError> {
    // Step 1: Prepare outputs (allocations + split commitments). This
    // fixes the split commitment root the signatures will commit to.
    let mut prepared = TransferBuilder::prepare_outputs_with_version(
        inputs,
        outputs,
        genesis,
        options.commitment_version,
    )?;

    // Step 2: Sign virtual transactions.
    sign_transfer(&mut prepared, prev_assets, signer)?;

    // Step 3: Populate split proofs if this is a split transfer. Done
    // after signing so each split witness carries the signed root
    // asset (the proofs themselves come from the unsigned split tree
    // committed to in step 1).
    if prepared.is_split {
        populate_split_proofs(&mut prepared)?;
    }

    // Step 4: Rebuild the change output commitment from the signed
    // root asset — its MS-SMT leaf changed when the witnesses were
    // populated. Unless opted out, this also merges the STXO alt
    // leaves for the spent inputs into the commitment.
    prepared
        .rebuild_root_commitment_with_options(options.no_stxo_proofs)?;

    // Step 5: Build anchor transaction template.
    let mut output_descriptors = Vec::new();

    // Change output (index 0) with the root asset's commitment.
    if internal_keys.is_empty() {
        return Err(SendError::InvalidState("no internal keys provided".into()));
    }
    output_descriptors.push(OutputDescriptor {
        internal_key: internal_keys[0],
        commitment: prepared.change_commitment.commitment().clone(),
        value: Amount::from_sat(330),
        sibling_script: None,
    });

    // Recipient outputs.
    for (i, commitment) in prepared.output_commitments.iter().enumerate() {
        let key_idx = (i + 1).min(internal_keys.len() - 1);
        output_descriptors.push(OutputDescriptor {
            internal_key: internal_keys[key_idx],
            commitment: commitment.commitment().clone(),
            value: Amount::from_sat(330),
            sibling_script: None,
        });
    }

    // Collect input anchor outpoints for the transaction template.
    let input_outpoints: Vec<_> = inputs
        .iter()
        .map(|i| bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin_hashes::sha256d::Hash::from_byte_array(i.anchor_point.txid),
            ),
            vout: i.anchor_point.vout,
        })
        .collect();

    let template = create_transfer_template(&input_outpoints, &output_descriptors)
        .map_err(|e| SendError::CommitmentError(e.to_string()))?;

    Ok(TransferResult { prepared, template })
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

    #[test]
    fn test_execute_full_transfer() {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x01;
        let sk = SecretKey::from_slice(&secret).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &sk);
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

        let inputs = vec![SelectedInput {
            prev_id: prev_id.clone(),
            anchor_point: OutPoint { txid: [0xBB; 32], vout: 0 },
            amount: 100,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(prev_key),
        }];

        let outputs = vec![TransferOutput {
            output_index: 0,
            amount: 100,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }];

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset);

        let signer = TestSigner { keypair };

        let result = execute_transfer(
            &inputs,
            &outputs,
            &genesis,
            &prev_assets,
            &signer,
            &[x_only],
        )
        .unwrap();

        // Witnesses should be signed.
        assert!(!result.prepared.root_asset.prev_witnesses[0].tx_witness.is_empty());
        assert_eq!(result.prepared.root_asset.prev_witnesses[0].tx_witness[0].len(), 64);

        // Template should have inputs and outputs.
        assert_eq!(result.template.tx.input.len(), 1);
        assert!(!result.template.tx.output.is_empty());
    }
}
