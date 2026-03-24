// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Genesis PSBT construction for minting new Taproot Assets.
//!
//! The genesis transaction creates the first on-chain anchor for new assets.
//! It produces a P2TR output embedding the TAP commitment as a tapscript leaf.

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

use tap_primitives::commitment::TapCommitment;

use super::commitment::{create_tap_output_script, PsbtError};

/// The result of creating a genesis template transaction.
#[derive(Clone, Debug)]
pub struct GenesisTemplate {
    /// The unsigned template transaction. Inputs must be funded by
    /// the wallet.
    pub tx: Transaction,
    /// Index of the output containing the TAP commitment.
    pub tap_output_index: u32,
    /// The tweaked output key.
    pub output_key: XOnlyPublicKey,
}

/// Creates an unsigned genesis template transaction.
///
/// This produces a transaction with:
/// - No inputs (to be funded by the wallet)
/// - One P2TR output embedding the TAP commitment
///
/// The caller is responsible for:
/// 1. Adding inputs via a wallet (e.g., `WalletAnchor::fund_psbt`)
/// 2. Adding a change output
/// 3. Signing and broadcasting
///
/// # Arguments
/// * `internal_key` - The internal key for the TAP commitment output
/// * `tap_commitment` - The commitment containing the minted assets
/// * `output_value` - The satoshi value for the TAP output
pub fn create_genesis_template(
    internal_key: &XOnlyPublicKey,
    tap_commitment: &TapCommitment,
    output_value: Amount,
) -> Result<GenesisTemplate, PsbtError> {
    let (script, output_key) =
        create_tap_output_script(internal_key, tap_commitment, None)?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![], // To be funded by the wallet.
        output: vec![TxOut {
            value: output_value,
            script_pubkey: script,
        }],
    };

    Ok(GenesisTemplate {
        tx,
        tap_output_index: 0,
        output_key,
    })
}

/// Creates a genesis template from an existing outpoint (for known inputs).
///
/// This is useful for testing where we control the input directly.
pub fn create_genesis_with_input(
    internal_key: &XOnlyPublicKey,
    tap_commitment: &TapCommitment,
    funding_outpoint: OutPoint,
    output_value: Amount,
) -> Result<GenesisTemplate, PsbtError> {
    let (script, output_key) =
        create_tap_output_script(internal_key, tap_commitment, None)?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: script,
        }],
    };

    Ok(GenesisTemplate {
        tx,
        tap_output_index: 0,
        output_key,
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

    fn test_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x02;
        let sk = SecretKey::from_slice(&secret).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    fn test_commitment() -> TapCommitment {
        let genesis = Genesis {
            first_prev_out: tap_primitives::asset::OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-mint".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis,
            5000,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap()
    }

    #[test]
    fn test_create_genesis_template() {
        let key = test_key();
        let commitment = test_commitment();

        let template = create_genesis_template(
            &key,
            &commitment,
            Amount::from_sat(10_000),
        )
        .unwrap();

        assert!(template.tx.input.is_empty());
        assert_eq!(template.tx.output.len(), 1);
        assert_eq!(template.tx.output[0].value, Amount::from_sat(10_000));
        assert_eq!(template.tap_output_index, 0);

        // Output should be P2TR.
        assert!(template.tx.output[0].script_pubkey.is_p2tr());
    }

    #[test]
    fn test_create_genesis_with_input() {
        let key = test_key();
        let commitment = test_commitment();

        let funding = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xBB; 32]),
            vout: 0,
        };

        let template = create_genesis_with_input(
            &key,
            &commitment,
            funding,
            Amount::from_sat(10_000),
        )
        .unwrap();

        assert_eq!(template.tx.input.len(), 1);
        assert_eq!(template.tx.input[0].previous_output, funding);
        assert!(template.tx.output[0].script_pubkey.is_p2tr());
    }

    #[test]
    fn test_genesis_txid_deterministic() {
        let key = test_key();
        let commitment = test_commitment();
        let funding = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xCC; 32]),
            vout: 1,
        };

        let t1 = create_genesis_with_input(
            &key, &commitment, funding, Amount::from_sat(5000),
        )
        .unwrap();
        let t2 = create_genesis_with_input(
            &key, &commitment, funding, Amount::from_sat(5000),
        )
        .unwrap();

        assert_eq!(t1.tx.compute_txid(), t2.tx.compute_txid());
    }
}
