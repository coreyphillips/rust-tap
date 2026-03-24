// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transfer PSBT construction for asset transfers.
//!
//! Builds Bitcoin transactions that anchor asset state transitions. Each
//! output with a TAP commitment becomes a P2TR output with the commitment
//! embedded as a tapscript leaf.

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

use tap_primitives::commitment::TapCommitment;

use super::commitment::{create_tap_output_script, PsbtError};

/// A transfer output with its TAP commitment and Bitcoin output.
#[derive(Clone, Debug)]
pub struct TransferOutputInfo {
    /// Index in the transaction's output list.
    pub output_index: u32,
    /// The tweaked output key for this P2TR output.
    pub output_key: XOnlyPublicKey,
    /// The TAP commitment embedded in this output.
    pub commitment: TapCommitment,
}

/// The result of creating a transfer template transaction.
#[derive(Clone, Debug)]
pub struct TransferTemplate {
    /// The unsigned template transaction.
    pub tx: Transaction,
    /// Info about each TAP commitment output.
    pub tap_outputs: Vec<TransferOutputInfo>,
}

/// Descriptor for a single output in the transfer transaction.
pub struct OutputDescriptor {
    /// Internal key for the P2TR output.
    pub internal_key: XOnlyPublicKey,
    /// TAP commitment to embed.
    pub commitment: TapCommitment,
    /// Output value in satoshis.
    pub value: Amount,
    /// Optional sibling tapscript (for channel outputs, etc.).
    pub sibling_script: Option<Vec<u8>>,
}

/// Creates an unsigned transfer template transaction.
///
/// # Arguments
/// * `inputs` - Input outpoints being spent (asset UTXOs)
/// * `outputs` - Output descriptors with TAP commitments
///
/// The caller must add change outputs and fund/sign the transaction.
pub fn create_transfer_template(
    inputs: &[OutPoint],
    outputs: &[OutputDescriptor],
) -> Result<TransferTemplate, PsbtError> {
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    for outpoint in inputs {
        tx_inputs.push(TxIn {
            previous_output: *outpoint,
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });
    }

    let mut tx_outputs = Vec::with_capacity(outputs.len());
    let mut tap_output_info = Vec::with_capacity(outputs.len());

    for (idx, desc) in outputs.iter().enumerate() {
        let (script, output_key) = create_tap_output_script(
            &desc.internal_key,
            &desc.commitment,
            desc.sibling_script.as_deref(),
        )?;

        tx_outputs.push(TxOut {
            value: desc.value,
            script_pubkey: script,
        });

        tap_output_info.push(TransferOutputInfo {
            output_index: idx as u32,
            output_key,
            commitment: desc.commitment.clone(),
        });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    Ok(TransferTemplate {
        tx,
        tap_outputs: tap_output_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use tap_primitives::asset::{
        Asset, AssetType, Genesis, ScriptKey, SerializedKey,
    };
    use tap_primitives::commitment::{
        AssetCommitment, TapCommitment, TapCommitmentVersion,
    };

    fn test_key(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = seed;
        let sk = SecretKey::from_slice(&secret).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    fn test_commitment(amount: u64) -> TapCommitment {
        let genesis = Genesis {
            first_prev_out: tap_primitives::asset::OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis,
            amount,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap()
    }

    #[test]
    fn test_create_transfer_template() {
        let input = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xAA; 32]),
            vout: 0,
        };

        let outputs = vec![
            OutputDescriptor {
                internal_key: test_key(1),
                commitment: test_commitment(60),
                value: Amount::from_sat(10_000),
                sibling_script: None,
            },
            OutputDescriptor {
                internal_key: test_key(2),
                commitment: test_commitment(40),
                value: Amount::from_sat(10_000),
                sibling_script: None,
            },
        ];

        let template =
            create_transfer_template(&[input], &outputs).unwrap();

        assert_eq!(template.tx.input.len(), 1);
        assert_eq!(template.tx.output.len(), 2);
        assert_eq!(template.tap_outputs.len(), 2);

        // Both outputs should be P2TR.
        for output in &template.tx.output {
            assert!(output.script_pubkey.is_p2tr());
        }

        // Different keys → different output scripts.
        assert_ne!(
            template.tx.output[0].script_pubkey,
            template.tx.output[1].script_pubkey
        );
    }

    #[test]
    fn test_transfer_with_sibling_script() {
        let input = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xBB; 32]),
            vout: 0,
        };

        let outputs = vec![OutputDescriptor {
            internal_key: test_key(1),
            commitment: test_commitment(100),
            value: Amount::from_sat(10_000),
            sibling_script: Some(vec![0x51]), // OP_TRUE
        }];

        let template =
            create_transfer_template(&[input], &outputs).unwrap();

        assert!(template.tx.output[0].script_pubkey.is_p2tr());
    }
}
