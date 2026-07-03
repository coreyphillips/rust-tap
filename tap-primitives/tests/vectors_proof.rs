//! Proof TLV encoding tests driven by the vendored Go BIP test vectors
//! (`proof/testdata/` in lightninglabs/taproot-assets).

mod common;

use common::*;
use tap_primitives::proof::{decode_proof, encode_proof, File};

fn run_proof_vector_file(name: &str) {
    let file: ProofVectorFile = load_json(name);
    let cases = file.valid_test_cases.expect("no valid cases");
    assert!(!cases.is_empty());

    for case in &cases {
        let comment = case.comment.as_deref().unwrap_or("");

        // Build the proof from JSON and check the encoding is
        // byte-identical to the expected hex.
        let proof = build_proof(&case.proof).unwrap_or_else(|e| {
            panic!("{}: build failed: {}", comment, e)
        });
        let encoded = encode_proof(&proof);
        assert_eq!(
            hex::encode(&encoded),
            case.expected,
            "{}: encoding mismatch",
            comment
        );

        // Decode the expected bytes and re-encode; must round-trip
        // byte-exactly.
        let expected_bytes = parse_hex(&case.expected);
        let decoded = decode_proof(&expected_bytes).unwrap_or_else(|e| {
            panic!("{}: decode failed: {}", comment, e)
        });
        let re_encoded = encode_proof(&decoded);
        assert_eq!(
            re_encoded, expected_bytes,
            "{}: re-encoding mismatch",
            comment
        );

        // Structural spot checks on directly comparable fields.
        assert_eq!(decoded.version, proof.version, "{}", comment);
        assert_eq!(decoded.prev_out, proof.prev_out, "{}", comment);
        assert_eq!(
            decoded.block_header, proof.block_header,
            "{}",
            comment
        );
        assert_eq!(
            decoded.block_height, proof.block_height,
            "{}",
            comment
        );
        assert_eq!(decoded.anchor_tx, proof.anchor_tx, "{}", comment);
        assert_eq!(
            decoded.tx_merkle_proof, proof.tx_merkle_proof,
            "{}",
            comment
        );
        assert_eq!(
            decoded.genesis_reveal, proof.genesis_reveal,
            "{}",
            comment
        );
        assert_eq!(
            decoded.group_key_reveal, proof.group_key_reveal,
            "{}",
            comment
        );
        assert_eq!(
            decoded.meta_reveal, proof.meta_reveal,
            "{}",
            comment
        );
        assert_eq!(
            decoded.challenge_witness, proof.challenge_witness,
            "{}",
            comment
        );
        assert_eq!(
            decoded.exclusion_proofs.len(),
            proof.exclusion_proofs.len(),
            "{}",
            comment
        );
        assert_eq!(
            decoded.alt_leaves.len(),
            proof.alt_leaves.len(),
            "{}",
            comment
        );
        assert_eq!(
            decoded.unknown_odd_types, proof.unknown_odd_types,
            "{}",
            comment
        );
    }
}

#[test]
fn proof_tlv_encoding_generated() {
    run_proof_vector_file("proof_tlv_encoding_generated.json");
}

#[test]
fn proof_tlv_encoding_regtest() {
    run_proof_vector_file("proof_tlv_encoding_regtest.json");
}

#[test]
fn proof_tlv_encoding_error_cases() {
    // The vendored error-cases file currently contains no cases
    // (`error_test_cases: null`); assert that stays parseable so a
    // future upstream update is noticed.
    let file: ProofVectorFile =
        load_json("proof_tlv_encoding_error_cases.json");
    assert!(file.error_test_cases.is_none()
        || file.error_test_cases.as_ref().unwrap().is_empty());
}

#[test]
fn proof_hex_decodes_and_round_trips() {
    let bytes = load_hex_file("proof.hex");
    let proof = decode_proof(&bytes).expect("proof.hex must decode");
    assert_eq!(
        encode_proof(&proof),
        bytes,
        "proof.hex round-trip mismatch"
    );
    // A regtest transfer proof: must carry an inclusion proof key and
    // a merkle proof.
    assert_ne!(proof.inclusion_proof.internal_key.as_bytes(), &[0u8; 33]);
}

#[test]
fn ownership_proof_hex_decodes_and_round_trips() {
    let bytes = load_hex_file("ownership-proof.hex");
    let proof =
        decode_proof(&bytes).expect("ownership-proof.hex must decode");
    assert_eq!(
        encode_proof(&proof),
        bytes,
        "ownership-proof.hex round-trip mismatch"
    );
    // Ownership proofs carry a challenge witness.
    assert!(proof.challenge_witness.is_some());
}

#[test]
fn proof_file_hex_decodes_and_round_trips() {
    let bytes = load_hex_file("proof-file.hex");
    let file = File::decode(&bytes).expect("proof-file.hex must decode");
    assert!(file.num_proofs() > 0);
    assert!(file.verify_hash_chain());
    assert_eq!(
        file.encode(),
        bytes,
        "proof-file.hex round-trip mismatch"
    );

    // Every proof in the file must decode and round-trip.
    for (i, hashed) in file.proofs.iter().enumerate() {
        let proof = decode_proof(&hashed.proof_bytes)
            .unwrap_or_else(|e| panic!("proof {} decode failed: {}", i, e));
        assert_eq!(
            encode_proof(&proof),
            hashed.proof_bytes,
            "proof {} round-trip mismatch",
            i
        );
    }
}
