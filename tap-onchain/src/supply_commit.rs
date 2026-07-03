// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Supply commitment transaction construction, funding, and signing.
//!
//! Mirrors the transaction-shaping parts of Go's
//! `universe/supplycommit` (`newRootCommitment`, `fundSupplyCommitTx`,
//! and the `CommitTxSignState` PSBT signing;
//! transitions.go:447-674,792-890):
//!
//! - Inputs: every unspent pre-commitment output (a P2TR key-path
//!   output paying to the BIP-86 tweak of the delegation key) plus,
//!   for incremental commitments, the previous commitment output (a
//!   P2TR output whose tapscript root commits to the previous supply
//!   root, so its key-path spend needs the BIP-341 tweak with that
//!   root).
//! - Output: the new root commitment output
//!   ([`tap_universe::supply::root_commit_tx_out`], 1000 sats).
//! - Fees: the wallet adds a fee input and change via
//!   [`WalletAnchor::fund_psbt`], exactly like the mint flow. The
//!   commitment output is re-located by script after funding (Go
//!   re-locates it by PkScript, skipping the change output).
//! - Signing: Go hands the PSBT to lnd, which key-path signs each
//!   input from its `TaprootBip32Derivation` + optional
//!   `TaprootMerkleRoot`. This port computes the BIP-341 key-spend
//!   sighashes directly and signs through the [`AssetSigner`] seam:
//!   [`AssetSigner::sign_virtual_tx`] for pre-commitment inputs
//!   (BIP-86 tweak) and [`AssetSigner::sign_virtual_tx_tweaked`] for
//!   the previous commitment input (tapscript-root tweak). The wallet
//!   then signs its own fee inputs and finalizes via
//!   [`WalletAnchor::sign_and_finalize_psbt`].

use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

use tap_primitives::asset::{OutPoint, SerializedKey};
use tap_universe::supply::root_commit_tx_out;

use crate::chain::{AssetSigner, ChainError, FeeRate, KeyDescriptor, WalletAnchor};

/// One input the supply commitment transaction spends and that this
/// node must sign (a pre-commitment output or the previous commitment
/// output). Wallet-added fee inputs are not represented here; the
/// wallet signs those itself.
#[derive(Clone, Debug)]
pub struct SupplyCommitInput {
    /// The outpoint being spent (internal byte order).
    pub outpoint: OutPoint,
    /// The previous output being spent (value + script), used as the
    /// PSBT `witness_utxo` and for the BIP-341 sighash.
    pub prev_tx_out: TxOut,
    /// The descriptor of the raw internal key of the spent output: the
    /// delegation key for pre-commitment outputs, the commitment
    /// internal key for the previous commitment output.
    pub key_desc: KeyDescriptor,
    /// The tapscript merkle root committed by the spent output:
    /// `None` for pre-commitment outputs (BIP-86, no script root),
    /// `Some(root)` for the previous commitment output (the supply
    /// commit tapscript root of the previous supply root hash).
    pub tapscript_root: Option<[u8; 32]>,
}

/// The result of building, funding, and signing a supply commitment
/// transaction.
#[derive(Clone, Debug)]
pub struct SignedSupplyCommitTx {
    /// The final signed transaction bytes, ready for broadcast.
    pub signed_tx: Vec<u8>,
    /// The transaction id in internal (little-endian) byte order.
    pub txid: [u8; 32],
    /// The index of the new commitment output in the final
    /// transaction.
    pub commit_output_index: u32,
    /// The taproot output key of the new commitment output (x-only).
    pub output_key: [u8; 32],
}

fn chain_err(msg: impl Into<String>) -> ChainError {
    ChainError::PsbtFailed(msg.into())
}

/// Builds the unsigned supply commitment transaction, funds it via the
/// wallet, signs the pre-commitment / previous-commitment inputs via
/// the [`AssetSigner`] seam, and finalizes via the wallet. See the
/// module docs for the Go references this mirrors.
///
/// `inputs` must be non-empty (an initial commitment spends at least
/// one pre-commitment; an incremental one spends the previous
/// commitment output).
pub fn build_and_sign_supply_commit_tx<W, K>(
    wallet: &W,
    signer: &K,
    fee_rate: FeeRate,
    inputs: &[SupplyCommitInput],
    commit_internal_key: &SerializedKey,
    supply_root_hash: &[u8; 32],
) -> Result<SignedSupplyCommitTx, ChainError>
where
    W: WalletAnchor,
    K: AssetSigner,
{
    if inputs.is_empty() {
        return Err(chain_err(
            "supply commitment transaction needs at least one input",
        ));
    }

    // The new commitment output (Go RootCommitTxOut).
    let (commit_value, commit_script, output_key) =
        root_commit_tx_out(commit_internal_key, None, supply_root_hash)
            .map_err(|e| chain_err(e.to_string()))?;
    let commit_script = ScriptBuf::from_bytes(commit_script);

    // Unsigned template: our inputs, the commitment output. The wallet
    // adds fee inputs and change during funding.
    let template = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|input| TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(
                        input.outpoint.txid,
                    ),
                    vout: input.outpoint.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(commit_value),
            script_pubkey: commit_script.clone(),
        }],
    };

    // Fund: same convention as the mint flow (raw unsigned tx bytes
    // in, PSBT bytes out).
    let template_bytes = bitcoin::consensus::serialize(&template);
    let funded = wallet.fund_psbt(&template_bytes, fee_rate)?;
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&funded)
        .map_err(|e| chain_err(format!("funded PSBT: {}", e)))?;

    // Re-locate the commitment output by script (the wallet may
    // reorder outputs; Go re-locates by PkScript skipping the change
    // output).
    let commit_output_index = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|out| out.script_pubkey == commit_script)
        .ok_or_else(|| {
            chain_err("commitment output missing from funded PSBT")
        })? as u32;

    // Attach the witness UTXOs of our inputs, locating each by
    // prevout (the wallet may reorder inputs too).
    let mut our_input_indices: Vec<(usize, &SupplyCommitInput)> =
        Vec::with_capacity(inputs.len());
    for input in inputs {
        let index = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|txin| {
                let txid: &[u8; 32] =
                    txin.previous_output.txid.as_ref();
                *txid == input.outpoint.txid
                    && txin.previous_output.vout == input.outpoint.vout
            })
            .ok_or_else(|| {
                chain_err(
                    "commitment input missing from funded PSBT",
                )
            })?;
        psbt.inputs[index].witness_utxo = Some(input.prev_tx_out.clone());
        our_input_indices.push((index, input));
    }

    // BIP-341 sighashes commit to every spent output, so all inputs
    // (including the wallet's fee inputs) must expose a witness_utxo.
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input.witness_utxo.clone().ok_or_else(|| {
                chain_err(format!(
                    "funded PSBT input {} has no witness_utxo; the \
                     wallet must populate witness UTXOs for its fee \
                     inputs",
                    i
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    // Key-path sign each of our inputs. Pre-commitment outputs are the
    // BIP-86 tweak of the delegation key (no tapscript root); the
    // previous commitment output is the internal key tweaked with the
    // supply commit tapscript root.
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in &our_input_indices {
        let sighash = cache
            .taproot_key_spend_signature_hash(
                *index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .map_err(|e| {
                ChainError::SigningFailed(format!("sighash: {}", e))
            })?;
        let digest: [u8; 32] = sighash.to_byte_array();

        let sig = match &input.tapscript_root {
            None => signer.sign_virtual_tx(&input.key_desc, &digest)?,
            Some(root) => signer.sign_virtual_tx_tweaked(
                &input.key_desc,
                &digest,
                Some(root),
            )?,
        };
        if sig.len() != 64 {
            return Err(ChainError::SigningFailed(format!(
                "expected 64-byte Schnorr signature, got {}",
                sig.len()
            )));
        }

        psbt.inputs[*index].final_script_witness =
            Some(Witness::from_slice(&[&sig[..]]));
    }

    // Let the wallet sign its fee inputs and finalize.
    let signed_tx_bytes =
        wallet.sign_and_finalize_psbt(&psbt.serialize())?;
    let signed_tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&signed_tx_bytes)
            .map_err(|e| chain_err(format!("signed tx parse: {}", e)))?;

    // Sanity: the finalized transaction still contains the commitment
    // output at the located index.
    let commit_out = signed_tx
        .output
        .get(commit_output_index as usize)
        .ok_or_else(|| chain_err("commitment output index out of range"))?;
    if commit_out.script_pubkey != commit_script {
        return Err(chain_err(
            "commitment output script changed during signing",
        ));
    }

    let mut txid = [0u8; 32];
    txid.copy_from_slice(signed_tx.compute_txid().as_ref());

    Ok(SignedSupplyCommitTx {
        signed_tx: signed_tx_bytes,
        txid,
        commit_output_index,
        output_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{self, Secp256k1};

    use tap_universe::supply::{
        compute_supply_commit_tapscript_root, pre_commit_tx_out,
    };

    /// Deterministic keys: index N uses the secret [N+1; 32].
    struct TestSigner;

    fn secret_for(index: u32) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[(index + 1) as u8; 32])
            .expect("valid secret")
    }

    fn pub_key_for(index: u32) -> SerializedKey {
        let secp = Secp256k1::new();
        SerializedKey(secret_for(index).public_key(&secp).serialize())
    }

    fn desc_for(index: u32) -> KeyDescriptor {
        KeyDescriptor {
            family: 212,
            index,
            pub_key: pub_key_for(index),
        }
    }

    impl AssetSigner for TestSigner {
        fn sign_virtual_tx(
            &self,
            signing_key: &KeyDescriptor,
            virtual_tx: &[u8],
        ) -> Result<Vec<u8>, ChainError> {
            self.sign_virtual_tx_tweaked(signing_key, virtual_tx, None)
        }

        fn sign_virtual_tx_tweaked(
            &self,
            signing_key: &KeyDescriptor,
            virtual_tx: &[u8],
            tapscript_root: Option<&[u8; 32]>,
        ) -> Result<Vec<u8>, ChainError> {
            let digest: [u8; 32] = virtual_tx
                .try_into()
                .map_err(|_| ChainError::SigningFailed("digest".into()))?;
            let secp = Secp256k1::new();
            let keypair = secp256k1::Keypair::from_secret_key(
                &secp,
                &secret_for(signing_key.index),
            );
            let merkle_root = tapscript_root.map(|root| {
                bitcoin::taproot::TapNodeHash::from_byte_array(*root)
            });
            let tweaked = keypair.tap_tweak(&secp, merkle_root);
            let msg = secp256k1::Message::from_digest(digest);
            let sig =
                secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
            Ok(sig.serialize().to_vec())
        }
    }

    /// A wallet that appends one fee input (with witness_utxo) and one
    /// change output, then signs nothing (returns the tx with the
    /// caller's final witnesses applied).
    struct TestWallet;

    impl WalletAnchor for TestWallet {
        fn fund_psbt(
            &self,
            raw_tx: &[u8],
            _fee_rate: FeeRate,
        ) -> Result<Vec<u8>, ChainError> {
            let mut tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(raw_tx)
                    .map_err(|e| chain_err(format!("template: {}", e)))?;
            tx.input.push(TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0xF0; 32]),
                    vout: 3,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
            tx.output.push(TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: ScriptBuf::new_op_return([0u8; 4]),
            });
            let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
                .map_err(|e| chain_err(format!("psbt: {}", e)))?;
            let fee_index = psbt.unsigned_tx.input.len() - 1;
            psbt.inputs[fee_index].witness_utxo = Some(TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
            });
            Ok(psbt.serialize())
        }

        fn sign_and_finalize_psbt(
            &self,
            funded_psbt: &[u8],
        ) -> Result<Vec<u8>, ChainError> {
            let psbt = bitcoin::psbt::Psbt::deserialize(funded_psbt)
                .map_err(|e| chain_err(format!("psbt: {}", e)))?;
            let mut tx = psbt.unsigned_tx.clone();
            for (i, input) in psbt.inputs.iter().enumerate() {
                if let Some(witness) = &input.final_script_witness {
                    tx.input[i].witness = witness.clone();
                }
            }
            Ok(bitcoin::consensus::serialize(&tx))
        }

        fn import_taproot_output(
            &self,
            _internal_key: &SerializedKey,
        ) -> Result<(), ChainError> {
            Ok(())
        }
    }

    /// An initial + incremental commitment transaction: the
    /// pre-commitment input is signed BIP-86 with the delegation key,
    /// the previous commitment input is signed with the tapscript-root
    /// tweak, and both signatures verify against the spent outputs'
    /// taproot output keys.
    #[test]
    fn test_build_and_sign_supply_commit_tx() {
        let delegation_desc = desc_for(0);
        let internal_desc = desc_for(1);
        let supply_root = [0x42u8; 32];

        // Initial commitment: spends one pre-commitment output.
        let (pre_value, pre_script) =
            pre_commit_tx_out(&delegation_desc.pub_key).expect("pre out");
        let pre_input = SupplyCommitInput {
            outpoint: OutPoint {
                txid: [0x11; 32],
                vout: 1,
            },
            prev_tx_out: TxOut {
                value: Amount::from_sat(pre_value),
                script_pubkey: ScriptBuf::from_bytes(pre_script.clone()),
            },
            key_desc: delegation_desc.clone(),
            tapscript_root: None,
        };

        let initial = build_and_sign_supply_commit_tx(
            &TestWallet,
            &TestSigner,
            FeeRate(2000),
            &[pre_input.clone()],
            &internal_desc.pub_key,
            &supply_root,
        )
        .expect("initial commit tx");

        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&initial.signed_tx)
                .expect("tx");

        // Spends the pre-commitment outpoint plus the wallet fee
        // input; pays the 1000-sat commitment output.
        assert_eq!(tx.input.len(), 2);
        let spent: &[u8; 32] = tx.input[0].previous_output.txid.as_ref();
        assert_eq!(*spent, [0x11; 32]);
        let commit_out = &tx.output[initial.commit_output_index as usize];
        assert_eq!(commit_out.value.to_sat(), 1000);
        assert_eq!(
            commit_out.script_pubkey.as_bytes()[2..],
            initial.output_key
        );

        // The pre-commitment witness verifies against the BIP-86
        // output key of the delegation key (the pre-commit script).
        let witness = &tx.input[0].witness;
        assert_eq!(witness.len(), 1);
        let sig = witness.nth(0).expect("sig");
        assert_eq!(sig.len(), 64);
        let mut cache = SighashCache::new(&tx);
        let prevouts = [
            pre_input.prev_tx_out.clone(),
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
            },
        ];
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .expect("sighash");
        tap_primitives::crypto::verify_schnorr_key_bytes(
            sig.try_into().expect("64 bytes"),
            &sighash.to_byte_array(),
            &pre_script[2..].try_into().expect("32 bytes"),
        )
        .expect("pre-commitment signature verifies");

        // Incremental commitment: spends the initial commitment
        // output, key path with the supply tapscript root tweak.
        let prev_root = compute_supply_commit_tapscript_root(&supply_root)
            .expect("tapscript root");
        let new_supply_root = [0x43u8; 32];
        let prev_input = SupplyCommitInput {
            outpoint: OutPoint {
                txid: initial.txid,
                vout: initial.commit_output_index,
            },
            prev_tx_out: commit_out.clone(),
            key_desc: internal_desc.clone(),
            tapscript_root: Some(prev_root),
        };

        let incremental = build_and_sign_supply_commit_tx(
            &TestWallet,
            &TestSigner,
            FeeRate(2000),
            &[prev_input.clone()],
            &internal_desc.pub_key,
            &new_supply_root,
        )
        .expect("incremental commit tx");

        let tx2: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&incremental.signed_tx)
                .expect("tx2");
        let spent2: &[u8; 32] =
            tx2.input[0].previous_output.txid.as_ref();
        assert_eq!(*spent2, initial.txid);
        assert_eq!(
            tx2.input[0].previous_output.vout,
            initial.commit_output_index
        );

        // The previous-commitment witness verifies against the
        // previous commitment output key (internal key tweaked with
        // the previous supply tapscript root).
        let witness2 = &tx2.input[0].witness;
        let sig2 = witness2.nth(0).expect("sig");
        let mut cache2 = SighashCache::new(&tx2);
        let prevouts2 = [
            prev_input.prev_tx_out.clone(),
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
            },
        ];
        let sighash2 = cache2
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts2),
                TapSighashType::Default,
            )
            .expect("sighash2");
        tap_primitives::crypto::verify_schnorr_key_bytes(
            sig2.try_into().expect("64 bytes"),
            &sighash2.to_byte_array(),
            &initial.output_key,
        )
        .expect("previous commitment signature verifies");
    }

    /// Empty input sets are rejected.
    #[test]
    fn test_empty_inputs_rejected() {
        let err = build_and_sign_supply_commit_tx(
            &TestWallet,
            &TestSigner,
            FeeRate(2000),
            &[],
            &pub_key_for(1),
            &[0u8; 32],
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("at least one input"));
    }
}
