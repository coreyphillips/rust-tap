// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! BIP-340 Schnorr signature verification for asset state transitions.
//!
//! [`SchnorrWitnessValidator`] implements the [`WitnessValidator`] trait
//! to provide real signature verification against virtual transaction
//! sighashes. This replaces `SkipWitnessValidator` for production use.

use bitcoin::secp256k1::{self, Message, Secp256k1, XOnlyPublicKey};

use crate::asset::{Asset, ScriptVersion, Witness};
use crate::vm::{VmError, WitnessValidator};

/// Verifies BIP-340 Schnorr signatures for Taproot Asset witness validation.
///
/// For ScriptV0 assets, the witness is expected to contain a 64-byte or
/// 65-byte Schnorr signature over the virtual transaction sighash.
pub struct SchnorrWitnessValidator {
    secp: Secp256k1<secp256k1::All>,
}

impl SchnorrWitnessValidator {
    pub fn new() -> Self {
        SchnorrWitnessValidator {
            secp: Secp256k1::new(),
        }
    }
}

impl Default for SchnorrWitnessValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl WitnessValidator for SchnorrWitnessValidator {
    fn validate_witness(
        &self,
        sighash: &[u8; 32],
        witness: &Witness,
        prev_asset: &Asset,
    ) -> Result<(), VmError> {
        // Only ScriptV0 is currently supported.
        if prev_asset.script_version != ScriptVersion::V0 {
            return Err(VmError::InvalidScriptVersion);
        }

        // Must have witness data.
        if witness.tx_witness.is_empty() {
            return Err(VmError::InvalidTransferWitness(
                "empty witness stack".into(),
            ));
        }

        // The first witness element should be the Schnorr signature
        // (64 or 65 bytes — 64 for default sighash, 65 with explicit
        // sighash type byte).
        let sig_bytes = &witness.tx_witness[0];
        if sig_bytes.len() != 64 && sig_bytes.len() != 65 {
            return Err(VmError::WitnessValidationFailed(format!(
                "expected 64 or 65 byte Schnorr signature, got {}",
                sig_bytes.len()
            )));
        }

        // Parse the signature (first 64 bytes).
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes[..64])
            .map_err(|e| {
                VmError::WitnessValidationFailed(format!(
                    "invalid Schnorr signature: {}",
                    e
                ))
            })?;

        // The verification key is the previous asset's script key (x-only).
        let script_key_bytes = prev_asset.script_key.serialized();
        let x_only = XOnlyPublicKey::from_slice(script_key_bytes.schnorr_bytes())
            .map_err(|e| {
                VmError::WitnessValidationFailed(format!(
                    "invalid script key: {}",
                    e
                ))
            })?;

        // Verify the BIP-340 Schnorr signature against the virtual tx sighash.
        let msg = Message::from_digest(*sighash);

        self.secp
            .verify_schnorr(&sig, &msg, &x_only)
            .map_err(|e| {
                VmError::WitnessValidationFailed(format!(
                    "Schnorr signature verification failed: {}",
                    e
                ))
            })
    }
}

/// Verifies a raw BIP-340 Schnorr signature against a message and public key.
///
/// This is a convenience function for verifying signatures outside the
/// VM context (e.g., group key witness verification).
pub fn verify_schnorr(
    sig: &[u8; 64],
    msg: &[u8; 32],
    pubkey: &XOnlyPublicKey,
) -> Result<(), String> {
    let secp = Secp256k1::verification_only();
    let sig = secp256k1::schnorr::Signature::from_slice(sig)
        .map_err(|e| format!("invalid signature: {}", e))?;
    let msg = Message::from_digest(*msg);
    secp.verify_schnorr(&sig, &msg, pubkey)
        .map_err(|e| format!("verification failed: {}", e))
}

/// Verifies a raw BIP-340 Schnorr signature against a message and an
/// x-only public key given as raw bytes.
///
/// This helper lets crates without a direct secp256k1 dependency (e.g.
/// tap-universe) verify signatures such as signed ignore tuples.
pub fn verify_schnorr_key_bytes(
    sig: &[u8; 64],
    msg: &[u8; 32],
    pubkey_x_only: &[u8; 32],
) -> Result<(), String> {
    let pubkey = XOnlyPublicKey::from_slice(pubkey_x_only)
        .map_err(|e| format!("invalid public key: {}", e))?;
    verify_schnorr(sig, msg, &pubkey)
}

/// Signs a 32-byte message with a BIP-340 Schnorr signature using the
/// given secret key bytes. Signing is deterministic (no auxiliary
/// randomness).
///
/// The message is signed as-is; callers are responsible for any
/// pre-hashing convention (e.g. lnd's `SignMessageSchnorr` signs
/// `sha256(msg)`).
pub fn sign_schnorr(
    msg: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<[u8; 64], String> {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| format!("invalid secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(*msg), &keypair);
    Ok(*sig.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use crate::asset::*;

    /// Creates a deterministic keypair from a test seed byte.
    fn test_keypair(seed: u8) -> Keypair {
        let mut secret = [0u8; 32];
        secret[31] = seed;
        secret[0] = 0x01; // ensure non-zero
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).unwrap();
        Keypair::from_secret_key(&secp, &sk)
    }

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    #[test]
    fn test_schnorr_sign_and_verify() {
        let secp = Secp256k1::new();
        let keypair = test_keypair(1);
        let (x_only, _) = keypair.x_only_public_key();

        let msg_bytes = [0xAA; 32];
        let msg = Message::from_digest(msg_bytes);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        assert!(secp.verify_schnorr(&sig, &msg, &x_only).is_ok());

        let wrong_msg = Message::from_digest([0xBB; 32]);
        assert!(secp.verify_schnorr(&sig, &wrong_msg, &x_only).is_err());
    }

    #[test]
    fn test_schnorr_verify_function() {
        let secp = Secp256k1::new();
        let keypair = test_keypair(2);
        let (x_only, _) = keypair.x_only_public_key();

        let msg = [0xCC; 32];
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(msg),
            &keypair,
        );
        let sig_bytes: [u8; 64] = *sig.as_ref();

        assert!(verify_schnorr(&sig_bytes, &msg, &x_only).is_ok());
    }

    #[test]
    fn test_witness_validator_rejects_empty_witness() {
        let validator = SchnorrWitnessValidator::new();
        let prev_asset = Asset::new_genesis(
            test_genesis(),
            100,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        let witness = Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![], // empty
            split_commitment: None,
        };

        let sighash = [0xAA; 32];
        let result = validator.validate_witness(&sighash, &witness, &prev_asset);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_validator_rejects_bad_sig_length() {
        let validator = SchnorrWitnessValidator::new();
        let prev_asset = Asset::new_genesis(
            test_genesis(),
            100,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        let witness = Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![vec![0x01, 0x02, 0x03]], // too short
            split_commitment: None,
        };

        let sighash = [0xAA; 32];
        let result = validator.validate_witness(&sighash, &witness, &prev_asset);
        assert!(matches!(
            result,
            Err(VmError::WitnessValidationFailed(_))
        ));
    }

    #[test]
    fn test_witness_validator_with_real_signature() {
        let secp = Secp256k1::new();
        let keypair = test_keypair(3);
        let (x_only, _) = keypair.x_only_public_key();

        let mut pub_key_bytes = [0u8; 33];
        pub_key_bytes[0] = 0x02;
        pub_key_bytes[1..].copy_from_slice(&x_only.serialize());
        let script_key = ScriptKey::from_pub_key(SerializedKey(pub_key_bytes));

        let prev_asset =
            Asset::new_genesis(test_genesis(), 100, script_key);

        // Sign over a known sighash.
        let sighash = [0xDD; 32];
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        let witness = Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![sig.as_ref().to_vec()],
            split_commitment: None,
        };

        let validator = SchnorrWitnessValidator::new();
        let result = validator.validate_witness(&sighash, &witness, &prev_asset);
        assert!(result.is_ok(), "signature verification should pass: {:?}", result);
    }
}
