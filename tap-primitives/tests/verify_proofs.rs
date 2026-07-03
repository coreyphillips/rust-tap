//! Full proof verification tests against the vendored Go regtest
//! proofs (`proof/testdata/` in lightninglabs/taproot-assets) plus
//! negative (tamper) tests, mirroring Go's `proof/proof_test.go`
//! verification tests.

mod common;

use common::*;

use tap_primitives::proof::{
    decode_proof, BlockHeader, ChainLookup, DefaultMerkleVerifier, File,
    GroupVerifier, HeaderVerifier, ProofError, ProofVerificationOptions,
    VerifierCtx,
};
use tap_primitives::asset::SerializedKey;

/// Accepts any block header. The actual chain anchoring check is the
/// merkle proof verification against the embedded header's merkle
/// root, which [`DefaultMerkleVerifier`] performs for real.
struct AcceptHeaders;

impl HeaderVerifier for AcceptHeaders {
    fn verify_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// Accepts any group key, like Go's `MockGroupVerifier`.
struct AcceptGroups;

impl GroupVerifier for AcceptGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// Fixed-height chain lookup, like Go's `MockChainLookup`.
struct MockLookup;

impl ChainLookup for MockLookup {
    fn current_height(&self) -> Result<u32, ProofError> {
        Ok(123)
    }
}

fn test_ctx(
) -> VerifierCtx<AcceptHeaders, DefaultMerkleVerifier, AcceptGroups, MockLookup>
{
    VerifierCtx::new(
        AcceptHeaders,
        DefaultMerkleVerifier,
        AcceptGroups,
        MockLookup,
    )
}

fn default_opts() -> ProofVerificationOptions {
    ProofVerificationOptions::default()
}

fn skip_chain_opts() -> ProofVerificationOptions {
    ProofVerificationOptions {
        skip_chain_verification: true,
        ..Default::default()
    }
}

/// The single regtest proof (a transfer proof) must pass integrity
/// verification: inclusion, exclusion, and reveal checks all run for
/// real. Full `verify()` needs the previous snapshot which a single
/// transfer proof does not carry; Go's `TestProofVerification` likewise
/// only calls `VerifyProofIntegrity` on this file. The vendored proof
/// is not yet confirmed (its block header is all zeros), so chain
/// verification is skipped, again matching Go's mock verifier ctx.
#[test]
fn proof_hex_integrity_verification() {
    let proof = decode_proof(&load_hex_file("proof.hex")).unwrap();
    let ctx = test_ctx();

    let tap_commitment = proof
        .verify_integrity(&ctx, &skip_chain_opts())
        .expect("proof.hex must pass integrity verification");
    assert!(tap_commitment.root_sum() >= proof.asset.amount);
}

/// The full regtest proof file must verify end-to-end, chaining
/// snapshots from genesis to the final state.
#[test]
fn proof_file_hex_full_verification() {
    let file = File::decode(&load_hex_file("proof-file.hex")).unwrap();
    let ctx = test_ctx();

    let snapshot = file
        .verify(&ctx, &default_opts())
        .expect("proof-file.hex must pass full verification");

    // The final snapshot corresponds to the last proof in the file.
    let last =
        decode_proof(&file.proofs.last().unwrap().proof_bytes).unwrap();
    assert_eq!(snapshot.asset.id(), last.asset.id());

    // The first proof alone (the genesis proof) must also verify.
    let first = decode_proof(&file.proofs[0].proof_bytes).unwrap();
    first
        .verify(None, &ctx, &default_opts())
        .expect("first proof of proof-file.hex must verify");
}

/// The ownership proof carries a challenge witness; with no previous
/// snapshot the challenge branch is taken. Mirrors Go's
/// `TestOwnershipProofVerification` (no challenge bytes are supplied).
#[test]
fn ownership_proof_hex_full_verification() {
    let proof = decode_proof(&load_hex_file("ownership-proof.hex")).unwrap();
    assert!(proof.challenge_witness.is_some());

    let ctx = test_ctx();
    let snapshot = proof
        .verify(None, &ctx, &default_opts())
        .expect("ownership-proof.hex must pass full verification");
    assert_eq!(snapshot.asset.id(), proof.asset.id());
}

/// All proofs in the regtest JSON vector file are real proofs from a
/// regtest chain: their integrity (chain anchoring, inclusion,
/// exclusion, reveals) must verify. Full state transition verification
/// needs the previous snapshots, which single proofs don't carry, so
/// the full path is exercised for genesis and challenge-witness proofs
/// only (like Go's TestProofVerification).
#[test]
fn regtest_json_proofs_verify() {
    let file: ProofVectorFile =
        load_json("proof_tlv_encoding_regtest.json");
    let cases = file.valid_test_cases.expect("no valid cases");
    assert!(!cases.is_empty());

    let ctx = test_ctx();
    for case in &cases {
        let comment = case.comment.as_deref().unwrap_or("");
        let proof = decode_proof(&parse_hex(&case.expected)).unwrap();

        // Some vendored proofs are unconfirmed (block height 0, no
        // real header/merkle proof); skip chain verification for
        // those, verify the merkle proof for real otherwise.
        let opts = if proof.block_height == 0 {
            skip_chain_opts()
        } else {
            default_opts()
        };

        proof
            .verify_integrity(&ctx, &opts)
            .unwrap_or_else(|e| {
                panic!("{}: integrity verification failed: {}", comment, e)
            });

        if proof.asset.is_genesis_asset()
            || proof.challenge_witness.is_some()
        {
            proof.verify(None, &ctx, &opts).unwrap_or_else(
                |e| panic!("{}: full verification failed: {}", comment, e),
            );
        }
    }
}

// -------------------------------------------------------------------
// Negative (tamper) tests
// -------------------------------------------------------------------

/// Tampering with an exclusion proof's output index must fail
/// verification.
#[test]
fn tampered_exclusion_proof_output_index_fails() {
    let file = File::decode(&load_hex_file("proof-file.hex")).unwrap();
    let ctx = test_ctx();

    // Find a proof that carries exclusion proofs.
    let mut proof = file
        .proofs
        .iter()
        .map(|h| decode_proof(&h.proof_bytes).unwrap())
        .find(|p| !p.exclusion_proofs.is_empty())
        .expect("no proof with exclusion proofs in proof-file.hex");

    // The un-tampered proof's integrity passes.
    proof
        .verify_integrity(&ctx, &default_opts())
        .expect("original must verify");

    // Point the first exclusion proof at a different output.
    let original_index = proof.exclusion_proofs[0].output_index;
    proof.exclusion_proofs[0].output_index = original_index + 100;

    let err = proof
        .verify_integrity(&ctx, &default_opts())
        .expect_err("tampered exclusion proof must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("exclusion") || msg.contains("output"),
        "unexpected error: {}",
        msg
    );
}

/// Tampering with the asset amount must fail the inclusion proof.
#[test]
fn tampered_asset_amount_fails() {
    let mut proof = decode_proof(&load_hex_file("proof.hex")).unwrap();
    let ctx = test_ctx();

    proof.asset.amount += 1;

    let err = proof
        .verify_integrity(&ctx, &skip_chain_opts())
        .expect_err("tampered amount must fail");
    assert!(
        err.to_string().contains("inclusion"),
        "unexpected error: {}",
        err
    );
}

/// Tampering with the tx merkle proof must fail chain verification.
#[test]
fn tampered_merkle_proof_fails() {
    let file = File::decode(&load_hex_file("proof-file.hex")).unwrap();
    let mut proof = decode_proof(&file.proofs[0].proof_bytes).unwrap();
    let ctx = test_ctx();

    // The un-tampered proof passes with real chain verification.
    proof
        .verify_integrity(&ctx, &default_opts())
        .expect("original must verify with real merkle verification");

    if proof.tx_merkle_proof.nodes.is_empty() {
        proof.tx_merkle_proof.nodes.push([0xAA; 32]);
        proof.tx_merkle_proof.bits.push(true);
    } else {
        proof.tx_merkle_proof.nodes[0][0] ^= 0xFF;
    }

    let err = proof
        .verify_integrity(&ctx, &default_opts())
        .expect_err("tampered merkle proof must fail");
    assert!(
        matches!(err, ProofError::InvalidTxMerkleProof),
        "unexpected error: {}",
        err
    );

    // With chain verification skipped, the tampered merkle proof is
    // not checked and integrity passes again.
    let opts = ProofVerificationOptions {
        skip_chain_verification: true,
        ..Default::default()
    };
    proof
        .verify_integrity(&ctx, &opts)
        .expect("skipping chain verification ignores the merkle proof");
}

/// Tampering with the meta reveal data must fail the genesis reveal
/// meta hash check.
#[test]
fn tampered_meta_reveal_fails() {
    let file = File::decode(&load_hex_file("proof-file.hex")).unwrap();
    let mut proof = decode_proof(&file.proofs[0].proof_bytes).unwrap();
    let ctx = test_ctx();

    let meta = proof
        .meta_reveal
        .as_mut()
        .expect("genesis proof must carry a meta reveal");
    meta.data.push(0x42);

    let err = proof
        .verify_integrity(&ctx, &default_opts())
        .expect_err("tampered meta reveal must fail");
    assert!(
        matches!(err, ProofError::MetaHashMismatch),
        "unexpected error: {}",
        err
    );
}

/// proof.hex is a transfer-root proof carrying STXO proofs (which the
/// integrity check verifies for real, see
/// `proof_hex_integrity_verification`). A V1 proof for a transfer-root
/// asset MUST carry them: stripping the STXO proofs from a V1-labelled
/// proof fails with a missing-STXO error, mirroring Go\'s
/// `ErrStxoInputProofMissing` gate (verifier.go:258). Tampering with an
/// STXO proof entry must fail as well.
#[test]
fn v1_transfer_proof_requires_stxo_proofs() {
    let proof = decode_proof(&load_hex_file("proof.hex")).unwrap();
    assert!(proof.asset.is_transfer_root());
    let stxo_count = proof
        .inclusion_proof
        .commitment_proof
        .as_ref()
        .map(|cp| cp.stxo_proofs.len())
        .unwrap_or(0);
    assert!(stxo_count > 0, "proof.hex must carry STXO proofs");
    let ctx = test_ctx();

    // Re-label as V1: still passes, the STXO proofs are present and
    // valid.
    let mut v1_proof = proof.clone();
    v1_proof.version = tap_primitives::proof::TransitionVersion::V1;
    v1_proof
        .verify_integrity(&ctx, &skip_chain_opts())
        .expect("V1 proof with valid STXO proofs must verify");

    // Stripping the STXO proofs from the V1 proof fails the gate.
    let mut stripped = v1_proof.clone();
    stripped
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .unwrap()
        .stxo_proofs
        .clear();
    let err = stripped
        .verify_integrity(&ctx, &skip_chain_opts())
        .expect_err("V1 transfer proof without STXO proofs must fail");
    assert!(
        err.to_string().contains("STXO"),
        "unexpected error: {}",
        err
    );

    // Re-keying an STXO proof entry (so it no longer matches the
    // expected spent-asset marker) must fail.
    let mut tampered = v1_proof.clone();
    let cp = tampered
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .unwrap();
    let (key, entry) = cp.stxo_proofs.iter().next().unwrap();
    let mut wrong_key = *key;
    wrong_key.0[32] ^= 0x01;
    let entry = entry.clone();
    let key = *key;
    cp.stxo_proofs.remove(&key);
    cp.stxo_proofs.insert(wrong_key, entry);

    let err = tampered
        .verify_integrity(&ctx, &skip_chain_opts())
        .expect_err("tampered STXO proof key must fail");
    assert!(
        err.to_string().contains("STXO"),
        "unexpected error: {}",
        err
    );
}

// -------------------------------------------------------------------
// Ownership proof round trip
// -------------------------------------------------------------------

/// Attaching a fresh challenge witness (signed with the asset's script
/// key) to the decoded ownership proof must verify with the same
/// challenge and fail with a different one.
#[test]
fn prove_ownership_round_trip() {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use tap_primitives::asset::{
        Asset, AssetType, Genesis, OutPoint, ScriptKey,
    };
    use tap_primitives::proof::{prove_ownership, verify_challenge_witness};

    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[0] = 0x5f;
    secret[31] = 0x33;
    let sk = SecretKey::from_slice(&secret).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (x_only, _) = keypair.x_only_public_key();

    let mut pub_key = [0u8; 33];
    pub_key[0] = 0x02;
    pub_key[1..].copy_from_slice(&x_only.serialize());

    // An owned asset controlled by our key.
    let genesis = Genesis {
        first_prev_out: OutPoint {
            txid: [0x07; 32],
            vout: 1,
        },
        tag: "ownership-test".to_string(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    };
    let owned = Asset::new_genesis(
        genesis,
        1_000,
        ScriptKey::from_pub_key(SerializedKey(pub_key)),
    );

    // Wrap it in a minimal proof shell (only `asset` and
    // `challenge_witness` are used by the challenge branch).
    let mut proof = decode_proof(&load_hex_file("proof.hex")).unwrap();
    proof.asset = owned;

    let challenge = Some([0x2a; 32]);
    prove_ownership(&mut proof, challenge, |sighash| {
        let msg = Message::from_digest(*sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(sig.as_ref().to_vec())
    })
    .expect("prove_ownership");

    // Correct challenge verifies.
    verify_challenge_witness(&proof, challenge)
        .expect("challenge witness must verify");

    // Wrong challenge fails.
    verify_challenge_witness(&proof, Some([0x2b; 32]))
        .expect_err("wrong challenge must fail");

    // Missing challenge fails too (plain NUMS key output).
    verify_challenge_witness(&proof, None)
        .expect_err("missing challenge must fail");
}
