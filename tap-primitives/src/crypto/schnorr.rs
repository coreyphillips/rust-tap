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
use bitcoin::sighash::TapSighashType;

use crate::asset::{Asset, ScriptVersion, Witness};
use crate::vm::{VmError, WitnessValidator};

/// Parses the sighash type carried by a taproot witness signature,
/// mirroring btcd's `parseTaprootSigAndPubKey`
/// (txscript/sigvalidate.go:257), which Go's VM relies on when it runs
/// the txscript engine over the virtual transaction:
///
/// - a 64-byte signature implies `SIGHASH_DEFAULT`;
/// - a 65-byte signature carries an explicit sighash byte, which must
///   not be 0x00 (an explicit default type must be encoded as a bare
///   64-byte signature) and must be one of the standard taproot types
///   (0x01, 0x02, 0x03, 0x81, 0x82, 0x83);
/// - any other length is invalid.
///
/// Note btcd accepts any non-zero 65th byte at parse time and only
/// fails non-standard values later when computing the sighash; the
/// observable behavior (witness validation failure) is identical.
pub fn taproot_witness_sig_hash_type(
    sig: &[u8],
) -> Result<TapSighashType, String> {
    match sig.len() {
        64 => Ok(TapSighashType::Default),
        65 if sig[64] != 0 => TapSighashType::from_consensus_u8(sig[64])
            .map_err(|_| {
                format!("invalid taproot sighash type: {}", sig[64])
            }),
        _ => Err(format!("invalid sig len: {}", sig.len())),
    }
}

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
        // non-zero sighash type byte). This mirrors btcd's
        // parseTaprootSigAndPubKey, which rejects a 65-byte signature
        // whose trailing byte is 0x00. The caller (the VM engine) has
        // already computed `sighash` with the type carried by the
        // trailing byte.
        let sig_bytes = &witness.tx_witness[0];
        taproot_witness_sig_hash_type(sig_bytes).map_err(|e| {
            VmError::WitnessValidationFailed(format!(
                "invalid Schnorr signature: {}",
                e
            ))
        })?;

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

    /// Executes a script-path (tapscript) spend of the virtual
    /// transaction with Bitcoin Core's libbitcoinconsensus, mirroring
    /// Go's `validateWitnessV0` running the btcd txscript engine
    /// (vm/vm.go:340) against the canned prevout
    /// (`OP_1 <32-byte script key>`, value = input amount).
    ///
    /// Go passes `txscript.StandardVerifyFlags`; libbitcoinconsensus
    /// only exposes consensus flags, so we use the full consensus set
    /// including taproot (`VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT`).
    #[cfg(feature = "consensus-validation")]
    fn validate_script_spend(
        &self,
        virtual_tx: &bitcoin::Transaction,
        prev_out: &bitcoin::TxOut,
        _witness: &Witness,
        prev_asset: &Asset,
    ) -> Result<(), VmError> {
        if prev_asset.script_version != ScriptVersion::V0 {
            return Err(VmError::InvalidScriptVersion);
        }

        let tx_bytes = bitcoin::consensus::encode::serialize(virtual_tx);
        let script_bytes = prev_out.script_pubkey.as_bytes();
        let value = prev_out.value.to_sat();

        // The virtual transaction has exactly one input, so the spent
        // outputs set is the single synthetic prevout.
        let utxo = bitcoinconsensus::Utxo {
            script_pubkey: script_bytes.as_ptr(),
            script_pubkey_len: script_bytes.len() as u32,
            value: value as i64,
        };

        bitcoinconsensus::verify_with_flags(
            script_bytes,
            value,
            &tx_bytes,
            Some(&[utxo]),
            0,
            bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT
                | bitcoinconsensus::VERIFY_TAPROOT,
        )
        .map_err(|e| {
            VmError::WitnessValidationFailed(format!(
                "tapscript execution failed: {:?}",
                e
            ))
        })
    }

    /// Without the `consensus-validation` feature there is no script
    /// interpreter available, so script-path spends are rejected with a
    /// clear error (Go always executes them via the txscript engine).
    #[cfg(not(feature = "consensus-validation"))]
    fn validate_script_spend(
        &self,
        _virtual_tx: &bitcoin::Transaction,
        _prev_out: &bitcoin::TxOut,
        _witness: &Witness,
        prev_asset: &Asset,
    ) -> Result<(), VmError> {
        if prev_asset.script_version != ScriptVersion::V0 {
            return Err(VmError::InvalidScriptVersion);
        }

        Err(VmError::WitnessValidationFailed(
            "script-path spend validation requires the \
             consensus-validation feature"
                .into(),
        ))
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
    fn test_taproot_witness_sig_hash_type() {
        use bitcoin::sighash::TapSighashType;

        // 64 bytes: default sighash.
        assert_eq!(
            taproot_witness_sig_hash_type(&[0u8; 64]).unwrap(),
            TapSighashType::Default
        );

        // 65 bytes with standard non-zero types.
        for (byte, expected) in [
            (0x01, TapSighashType::All),
            (0x02, TapSighashType::None),
            (0x03, TapSighashType::Single),
            (0x81, TapSighashType::AllPlusAnyoneCanPay),
            (0x82, TapSighashType::NonePlusAnyoneCanPay),
            (0x83, TapSighashType::SinglePlusAnyoneCanPay),
        ] {
            let mut sig = vec![0u8; 65];
            sig[64] = byte;
            assert_eq!(
                taproot_witness_sig_hash_type(&sig).unwrap(),
                expected
            );
        }

        // 65 bytes with a 0x00 trailing byte is invalid (btcd's
        // ErrInvalidTaprootSigLen).
        assert!(taproot_witness_sig_hash_type(&[0u8; 65]).is_err());

        // Non-standard sighash byte fails.
        let mut sig = vec![0u8; 65];
        sig[64] = 0x04;
        assert!(taproot_witness_sig_hash_type(&sig).is_err());

        // Other lengths fail.
        assert!(taproot_witness_sig_hash_type(&[0u8; 63]).is_err());
        assert!(taproot_witness_sig_hash_type(&[0u8; 66]).is_err());
        assert!(taproot_witness_sig_hash_type(&[]).is_err());
    }

    /// Builds a (prev_asset, new_asset, prev_assets) triple where the
    /// previous asset's script key is a taproot output key committing
    /// to a single `<leaf_key> OP_CHECKSIG` tapscript leaf under the
    /// given internal key. Returns everything needed to build the
    /// script-path witness.
    #[cfg(feature = "consensus-validation")]
    fn script_path_fixture() -> (
        Asset,
        Asset,
        crate::vm::InputSet,
        crate::crypto::tapscript::TapscriptLeaf,
        Keypair,
        Vec<u8>,
    ) {
        use bitcoin::secp256k1::Scalar;
        use bitcoin::ScriptBuf;
        use crate::crypto::tapscript::TapscriptLeaf;

        let secp = Secp256k1::new();
        let leaf_keypair = test_keypair(0x11);
        let internal_keypair = test_keypair(0x22);
        let (leaf_x_only, _) = leaf_keypair.x_only_public_key();
        let (internal_x_only, _) = internal_keypair.x_only_public_key();

        // Script: <32-byte leaf key> OP_CHECKSIG.
        let mut script = Vec::with_capacity(34);
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(&leaf_x_only.serialize());
        script.push(0xac); // OP_CHECKSIG
        let leaf = TapscriptLeaf::new(ScriptBuf::from(script));
        let merkle_root = leaf.leaf_hash();

        // Taproot output key = internal key tweaked with the BIP-341
        // TapTweak of the merkle root.
        let tag = bitcoin::hashes::sha256::Hash::hash(b"TapTweak");
        let mut engine = bitcoin::hashes::sha256::HashEngine::default();
        use bitcoin::hashes::{Hash, HashEngine};
        engine.input(tag.as_ref());
        engine.input(tag.as_ref());
        engine.input(&internal_x_only.serialize());
        engine.input(&merkle_root);
        let tweak = bitcoin::hashes::sha256::Hash::from_engine(engine)
            .to_byte_array();
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (output_key, parity) =
            internal_x_only.add_tweak(&secp, &scalar).unwrap();

        // Control block: version|parity byte plus the internal key
        // (single leaf, so no merkle path).
        let parity_bit: u8 = match parity {
            bitcoin::secp256k1::Parity::Even => 0,
            bitcoin::secp256k1::Parity::Odd => 1,
        };
        let mut control_block = Vec::with_capacity(33);
        control_block.push(0xc0 | parity_bit);
        control_block.extend_from_slice(&internal_x_only.serialize());

        // The previous asset is locked to the taproot output key.
        let mut prev_key_bytes = [0u8; 33];
        prev_key_bytes[0] = 0x02;
        prev_key_bytes[1..].copy_from_slice(&output_key.serialize());
        let prev_key = SerializedKey(prev_key_bytes);

        let genesis = test_genesis();
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
            out_point: OutPoint {
                txid: [0xEE; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = crate::vm::InputSet::new();
        prev_assets.insert(prev_id, prev_asset.clone());

        (
            prev_asset,
            new_asset,
            prev_assets,
            leaf,
            leaf_keypair,
            control_block,
        )
    }

    #[test]
    #[cfg(feature = "consensus-validation")]
    fn test_script_path_spend_via_vm() {
        use crate::crypto::tapscript::input_script_spend_sighash;
        use crate::crypto::virtual_tx::virtual_tx;
        use bitcoin::sighash::TapSighashType;

        let secp = Secp256k1::new();
        let (prev_asset, mut new_asset, prev_assets, leaf, leaf_keypair, cb) =
            script_path_fixture();

        // Sign the BIP-342 script-spend sighash with the leaf key.
        let (base_tx, _, _) = virtual_tx(&new_asset, &prev_assets).unwrap();
        let sighash = input_script_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            &leaf,
            TapSighashType::Default,
        )
        .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash),
            &leaf_keypair,
        );

        // Witness stack: [sig, script, control block].
        new_asset.prev_witnesses[0].tx_witness = vec![
            sig.as_ref().to_vec(),
            leaf.script.as_bytes().to_vec(),
            cb,
        ];

        let validator = SchnorrWitnessValidator::new();
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        let result = engine.execute();
        assert!(
            result.is_ok(),
            "script-path spend should verify: {:?}",
            result
        );
    }

    #[test]
    #[cfg(feature = "consensus-validation")]
    fn test_script_path_spend_tampered_witness_fails() {
        use crate::crypto::tapscript::input_script_spend_sighash;
        use crate::crypto::virtual_tx::virtual_tx;
        use bitcoin::sighash::TapSighashType;

        let secp = Secp256k1::new();
        let (prev_asset, mut new_asset, prev_assets, leaf, leaf_keypair, cb) =
            script_path_fixture();

        let (base_tx, _, _) = virtual_tx(&new_asset, &prev_assets).unwrap();
        let sighash = input_script_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            &leaf,
            TapSighashType::Default,
        )
        .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash),
            &leaf_keypair,
        );

        // Tamper with the signature.
        let mut bad_sig = sig.as_ref().to_vec();
        bad_sig[10] ^= 0x01;

        new_asset.prev_witnesses[0].tx_witness = vec![
            bad_sig,
            leaf.script.as_bytes().to_vec(),
            cb.clone(),
        ];

        let validator = SchnorrWitnessValidator::new();
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        assert!(
            engine.execute().is_err(),
            "tampered script-path witness must fail"
        );

        // A tampered control block (wrong internal key) must also fail.
        let mut bad_cb = cb;
        bad_cb[5] ^= 0x01;
        new_asset.prev_witnesses[0].tx_witness = vec![
            sig.as_ref().to_vec(),
            leaf.script.as_bytes().to_vec(),
            bad_cb,
        ];
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        assert!(
            engine.execute().is_err(),
            "tampered control block must fail"
        );
    }

    /// Builds a simple 1-in-1-out key-path transfer where the previous
    /// asset is locked directly to the given keypair's public key.
    fn key_path_fixture(
        keypair: &Keypair,
    ) -> (Asset, Asset, crate::vm::InputSet) {
        let (x_only, _) = keypair.x_only_public_key();
        let mut prev_key_bytes = [0u8; 33];
        prev_key_bytes[0] = 0x02;
        prev_key_bytes[1..].copy_from_slice(&x_only.serialize());
        let prev_key = SerializedKey(prev_key_bytes);

        let genesis = test_genesis();
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
            out_point: OutPoint {
                txid: [0xDD; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = crate::vm::InputSet::new();
        prev_assets.insert(prev_id, prev_asset.clone());
        (prev_asset, new_asset, prev_assets)
    }

    #[test]
    fn test_key_path_65_byte_sig_with_sighash_flag() {
        use crate::crypto::virtual_tx::{input_key_spend_sighash, virtual_tx};
        use bitcoin::sighash::TapSighashType;

        let secp = Secp256k1::new();
        let keypair = test_keypair(0x33);
        let (prev_asset, mut new_asset, prev_assets) =
            key_path_fixture(&keypair);

        let (base_tx, _, _) = virtual_tx(&new_asset, &prev_assets).unwrap();

        // Sign the sighash computed with SIGHASH_ALL (0x01) and append
        // the explicit flag byte; the engine must verify the signature
        // against the sighash computed with that type (btcd semantics).
        let sighash_all = input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::All,
        )
        .unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash_all),
            &keypair,
        );
        let mut sig_with_flag = sig.as_ref().to_vec();
        sig_with_flag.push(0x01);

        let validator = SchnorrWitnessValidator::new();
        new_asset.prev_witnesses[0].tx_witness = vec![sig_with_flag];
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        let result = engine.execute();
        assert!(
            result.is_ok(),
            "65-byte sig with 0x01 flag should verify: {:?}",
            result
        );

        // The same 64-byte signature WITHOUT the flag byte must fail:
        // it would be verified against the default-type sighash, which
        // differs from the SIGHASH_ALL digest that was signed.
        new_asset.prev_witnesses[0].tx_witness =
            vec![sig.as_ref().to_vec()];
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        assert!(engine.execute().is_err());

        // A 65-byte signature with an explicit 0x00 byte is rejected
        // (btcd requires the default type to be encoded as 64 bytes).
        let sighash_default = input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::Default,
        )
        .unwrap();
        let sig_default = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash_default),
            &keypair,
        );
        let mut sig_with_zero = sig_default.as_ref().to_vec();
        sig_with_zero.push(0x00);
        new_asset.prev_witnesses[0].tx_witness = vec![sig_with_zero];
        let engine = crate::vm::Engine::new(
            &new_asset,
            &[],
            &prev_assets,
            &validator,
        );
        assert!(engine.execute().is_err());
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
