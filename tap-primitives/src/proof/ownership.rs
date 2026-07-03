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

/// The secp256k1 group order `n`, big-endian.
const CURVE_ORDER_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Reduces a 32-byte big-endian value modulo the secp256k1 group order
/// `n`, matching Go's `ModNScalar.SetByteSlice` semantics used by
/// `asset.GenChallengeNUMS`. Since `2^256 < 2n`, a single conditional
/// subtraction suffices.
fn reduce_mod_n(bytes: [u8; 32]) -> [u8; 32] {
    // Big-endian byte-wise comparison equals numeric comparison.
    if bytes < CURVE_ORDER_N {
        return bytes;
    }

    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let lhs = u16::from(bytes[i]);
        let rhs = u16::from(CURVE_ORDER_N[i]) + borrow;
        if lhs >= rhs {
            out[i] = (lhs - rhs) as u8;
            borrow = 0;
        } else {
            out[i] = (lhs + 256 - rhs) as u8;
            borrow = 1;
        }
    }
    out
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

    // Go's ModNScalar.SetByteSlice reduces the challenge mod n, so
    // challenges >= n are valid and wrap around; mirror that here. A
    // challenge that reduces to zero leaves the NUMS key untweaked,
    // which matches Go (0*G is the identity).
    let reduced = reduce_mod_n(challenge_bytes);
    if reduced == [0u8; 32] {
        return Ok(ScriptKey::from_pub_key(NUMS_KEY));
    }
    let scalar = Scalar::from_be_bytes(reduced)
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

    /// Adds one to a big-endian 32-byte value (wrapping).
    fn be_add_one(mut bytes: [u8; 32]) -> [u8; 32] {
        for i in (0..32).rev() {
            let (v, overflow) = bytes[i].overflowing_add(1);
            bytes[i] = v;
            if !overflow {
                break;
            }
        }
        bytes
    }

    #[test]
    fn test_gen_challenge_nums_reduces_mod_n() {
        // Go's ModNScalar.SetByteSlice reduces mod n, so a challenge of
        // exactly n reduces to zero and leaves the NUMS key untweaked.
        let key = gen_challenge_nums(Some(CURVE_ORDER_N)).unwrap();
        assert_eq!(*key.serialized(), NUMS_KEY);

        // n + 1 reduces to 1, matching an explicit challenge of 1.
        let mut one = [0u8; 32];
        one[31] = 1;
        let from_wrapped =
            gen_challenge_nums(Some(be_add_one(CURVE_ORDER_N))).unwrap();
        let from_one = gen_challenge_nums(Some(one)).unwrap();
        assert_eq!(from_wrapped, from_one);

        // The all-ones challenge (>= n) is accepted, not rejected.
        assert!(gen_challenge_nums(Some([0xFF; 32])).is_ok());
    }

    #[test]
    fn test_reduce_mod_n() {
        assert_eq!(reduce_mod_n([0u8; 32]), [0u8; 32]);
        assert_eq!(reduce_mod_n(CURVE_ORDER_N), [0u8; 32]);

        // n - 1 stays unchanged.
        let mut n_minus_one = CURVE_ORDER_N;
        n_minus_one[31] -= 1;
        assert_eq!(reduce_mod_n(n_minus_one), n_minus_one);

        // 2^256 - 1 reduces to 2^256 - 1 - n
        // = 0x14551231950b75fc4402da1732fc9bebe.
        let reduced = reduce_mod_n([0xFF; 32]);
        let mut expected = [0u8; 32];
        expected[15..].copy_from_slice(&[
            0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xB7, 0x5F, 0xC4, 0x40,
            0x2D, 0xA1, 0x73, 0x2F, 0xC9, 0xBE, 0xBE,
        ]);
        assert_eq!(reduced, expected);
    }
}
