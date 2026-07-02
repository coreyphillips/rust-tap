// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Ownership (challenge) proofs.
//!
//! An ownership proof is a signed witness for a well-defined 1-input,
//! 1-output virtual transaction that spends the proven asset into a NUMS
//! key (optionally modified by a challenge), proving the prover can
//! produce a valid signature for the asset without moving it on chain.
//!
//! Mirrors Go's `asset.GenChallengeNUMS` (asset/witness.go:47),
//! `proof.CreateOwnershipProofAsset` and `Proof.verifyChallengeWitness`
//! (proof/verifier.go:688-763).

use std::collections::HashMap;

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};

use crate::asset::{
    Asset, OutPoint, PrevId, ScriptKey, SerializedKey, Witness, NUMS_BYTES,
    NUMS_KEY,
};
use crate::crypto::virtual_tx::{input_key_spend_sighash, virtual_tx};
use crate::vm;

use super::types::Proof;
use super::ProofError;

fn err(msg: impl Into<String>) -> ProofError {
    ProofError::VerificationFailed(msg.into())
}

/// Generates a variant of the NUMS script key that is modified by the
/// provided challenge, mirroring Go's `asset.GenChallengeNUMS`
/// (asset/witness.go:47):
///
/// ```text
/// result = NUMS + challenge*G
/// ```
///
/// With no challenge, the plain NUMS script key is returned.
pub fn gen_challenge_nums(
    challenge: Option<[u8; 32]>,
) -> Result<ScriptKey, ProofError> {
    let Some(challenge_bytes) = challenge else {
        return Ok(ScriptKey::from_pub_key(NUMS_KEY));
    };

    let secp = Secp256k1::new();
    let nums = PublicKey::from_slice(&NUMS_BYTES)
        .map_err(|e| err(format!("invalid NUMS key: {}", e)))?;

    // Go's ModNScalar.SetByteSlice reduces mod n; values >= n are
    // astronomically unlikely for real challenges, so we reject them
    // instead of implementing the reduction.
    let scalar = Scalar::from_be_bytes(challenge_bytes)
        .map_err(|e| err(format!("invalid challenge scalar: {}", e)))?;

    let result = nums
        .add_exp_tweak(&secp, &scalar)
        .map_err(|e| err(format!("challenge tweak failed: {}", e)))?;

    Ok(ScriptKey::from_pub_key(SerializedKey(result.serialize())))
}

/// Creates the virtual 1-in-1-out asset used to prove ownership of an
/// asset, mirroring Go's `CreateOwnershipProofAsset`
/// (proof/verifier.go:726).
///
/// The signature commits to an empty previous outpoint, so the witness
/// can never be reused for an actual on-chain state transition.
pub fn create_ownership_proof_asset(
    owned_asset: &Asset,
    challenge: Option<[u8; 32]>,
) -> Result<(PrevId, Asset), ProofError> {
    let prev_id = PrevId {
        out_point: OutPoint {
            txid: [0u8; 32],
            vout: 0,
        },
        id: owned_asset.id(),
        script_key: *owned_asset.script_key.serialized(),
    };

    // The ownership proof is a 1-in-1-out transaction, so it never has
    // a split commitment; the spend template also clears time locks.
    let mut output_asset = owned_asset.copy_spend_template();
    output_asset.script_key = gen_challenge_nums(challenge)?;
    output_asset.prev_witnesses = vec![Witness {
        prev_id: Some(prev_id.clone()),
        tx_witness: vec![],
        split_commitment: None,
    }];

    Ok((prev_id, output_asset))
}

/// Verifies the challenge witness by constructing the well-defined
/// 1-in-1-out ownership transaction and validating the witness against
/// it, mirroring Go's `Proof.verifyChallengeWitness`
/// (proof/verifier.go:691). Returns whether the proven asset has a
/// split commitment witness (Go's split-asset flag).
pub fn verify_challenge_witness(
    proof: &Proof,
    challenge: Option<[u8; 32]>,
) -> Result<bool, ProofError> {
    let challenge_witness = proof
        .challenge_witness
        .as_ref()
        .ok_or_else(|| err("missing challenge witness"))?;

    let owned_asset = proof.asset.clone();
    let (prev_id, mut proof_asset) =
        create_ownership_proof_asset(&owned_asset, challenge)?;

    // The packet is well-defined; just set the witness and validate.
    proof_asset.prev_witnesses[0].tx_witness = challenge_witness.clone();

    let mut prev_assets: vm::InputSet = HashMap::new();
    prev_assets.insert(prev_id, owned_asset);

    let validator = crate::crypto::SchnorrWitnessValidator::new();
    let engine = vm::Engine::new(&proof_asset, &[], &prev_assets, &validator);
    engine
        .execute()
        .map_err(|e| err(format!("challenge witness invalid: {}", e)))?;

    Ok(proof.asset.has_split_commitment_witness())
}

/// Produces and attaches an ownership challenge witness to the proof.
///
/// The caller provides a signing closure that receives the BIP-341
/// key-spend sighash of the ownership virtual transaction and returns
/// the serialized Schnorr signature (64 bytes, or 65 with an explicit
/// sighash type byte) made with the asset's script key.
pub fn prove_ownership<F>(
    proof: &mut Proof,
    challenge: Option<[u8; 32]>,
    sign: F,
) -> Result<(), ProofError>
where
    F: FnOnce(&[u8; 32]) -> Result<Vec<u8>, String>,
{
    let owned_asset = proof.asset.clone();
    let (prev_id, proof_asset) =
        create_ownership_proof_asset(&owned_asset, challenge)?;

    let mut prev_assets: vm::InputSet = HashMap::new();
    prev_assets.insert(prev_id, owned_asset.clone());

    let (base_tx, _, _) = virtual_tx(&proof_asset, &prev_assets)
        .map_err(|e| err(e.to_string()))?;
    let sighash = input_key_spend_sighash(
        &base_tx,
        &owned_asset,
        &proof_asset,
        0,
        bitcoin::sighash::TapSighashType::Default,
    )
    .map_err(|e| err(e.to_string()))?;

    let signature = sign(&sighash).map_err(err)?;
    proof.challenge_witness = Some(vec![signature]);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_challenge_nums_none_is_nums() {
        let key = gen_challenge_nums(None).unwrap();
        assert_eq!(*key.serialized(), NUMS_KEY);
    }

    #[test]
    fn test_gen_challenge_nums_deterministic_and_distinct() {
        let a = gen_challenge_nums(Some([0x01; 32])).unwrap();
        let b = gen_challenge_nums(Some([0x01; 32])).unwrap();
        let c = gen_challenge_nums(Some([0x02; 32])).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(*a.serialized(), NUMS_KEY);
    }
}
