//! Round-trip self-check: generate a genesis proof via the tap-onchain
//! proof generation pipeline and verify it with the full tap-primitives
//! verifier (including real merkle proof verification against the
//! embedded block header). Also exercises the ownership (challenge)
//! proof round trip on the generated proof.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use tap_onchain::proof::generate::{
    generate_genesis_proof, GenesisProofParams,
};
use tap_primitives::asset::{
    Asset, AssetType, AssetVersion, Genesis, OutPoint, ScriptKey,
    SerializedKey,
};
use tap_primitives::commitment::{
    AssetCommitment, AssetProof, CommitmentProof, TapCommitment,
    TapCommitmentVersion, TaprootAssetProof,
};
use tap_primitives::mssmt::{DefaultStore, FullTree};
use tap_primitives::proof::{
    decode_proof, encode_proof, prove_ownership, BlockHeader, ChainLookup,
    DefaultMerkleVerifier, GroupVerifier, HeaderVerifier, ProofError,
    ProofVerificationOptions, VerifierCtx,
};

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

struct AcceptGroups;

impl GroupVerifier for AcceptGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

struct MockLookup;

impl ChainLookup for MockLookup {
    fn current_height(&self) -> Result<u32, ProofError> {
        Ok(900_000)
    }
}

fn keypair(seed: u8) -> (Keypair, SerializedKey) {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[0] = 0x01;
    secret[31] = seed;
    let sk = SecretKey::from_slice(&secret).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (x_only, _) = kp.x_only_public_key();
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&x_only.serialize());
    (kp, SerializedKey(compressed))
}

/// Builds a fully verifiable genesis proof through the tap-onchain
/// pipeline and returns it.
fn build_genesis_proof() -> tap_primitives::proof::Proof {
    let (_internal_kp, internal_key) = keypair(0x11);
    let (_script_kp, script_key) = keypair(0x22);

    // The minted asset.
    let genesis = Genesis {
        first_prev_out: OutPoint {
            txid: [0x66; 32],
            vout: 1,
        },
        tag: "roundtrip-asset".to_string(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    };
    let asset = Asset::new_genesis(
        genesis.clone(),
        5_000,
        ScriptKey::from_pub_key(script_key),
    );

    // Commitment trees.
    let ac = AssetCommitment::new(&[&asset]).unwrap();
    let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap();

    // Inner (asset) proof.
    let ack = tap_primitives::commitment::asset_commitment_key(
        &asset.id(),
        asset.script_key.serialized(),
        asset.group_key.is_some(),
    );
    let mut inner_tree = FullTree::new(DefaultStore::new());
    inner_tree
        .insert(ack, tap_primitives::commitment::asset_leaf(&asset))
        .unwrap();
    let inner_proof = inner_tree.merkle_proof(ack).unwrap();

    // Outer (tap) proof.
    let mut outer_tree = FullTree::new(DefaultStore::new());
    outer_tree
        .insert(ac.tap_key, ac.tap_commitment_leaf())
        .unwrap();
    let outer_proof = outer_tree.merkle_proof(ac.tap_key).unwrap();

    let commitment_proof = CommitmentProof {
        asset_proof: Some(AssetProof {
            proof: inner_proof,
            version: AssetVersion::V0,
            tap_key: ac.tap_key,
            unknown_odd_types: BTreeMap::new(),
        }),
        taproot_asset_proof: TaprootAssetProof {
            proof: outer_proof,
            version: TapCommitmentVersion::V2,
            unknown_odd_types: BTreeMap::new(),
        },
        tap_sibling_preimage: None,
        stxo_proofs: BTreeMap::new(),
        unknown_odd_types: BTreeMap::new(),
    };

    // Anchor transaction paying to the commitment output.
    let internal_x_only = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
        internal_key.schnorr_bytes(),
    )
    .unwrap();
    let (anchor_script, _) = tap_onchain::psbt::create_tap_output_script(
        &internal_x_only,
        &tc,
        None,
    )
    .unwrap();

    let anchor_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(
                    genesis.first_prev_out.txid,
                ),
                vout: genesis.first_prev_out.vout,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: anchor_script,
        }],
    };
    let anchor_tx_bytes = bitcoin::consensus::encode::serialize(&anchor_tx);
    let txid: [u8; 32] = *anchor_tx.compute_txid().as_ref();

    // Single-tx block: the header's merkle root is the txid itself.
    let mut block_header = [0u8; 80];
    block_header[36..68].copy_from_slice(&txid);

    let params = GenesisProofParams {
        anchor_tx_bytes,
        block_header,
        block_height: 800_000,
        tx_index: 0,
        block_tx_hashes: vec![txid],
        prev_out: genesis.first_prev_out.clone(),
        asset,
        tap_output_index: 0,
        internal_key,
        commitment_proof: Some(commitment_proof),
        exclusion_proofs: vec![],
        genesis_reveal: genesis,
        meta_reveal: None,
        group_key_reveal: None,
    };

    generate_genesis_proof(params).expect("proof generation")
}

fn ctx() -> VerifierCtx<AcceptHeaders, DefaultMerkleVerifier, AcceptGroups, MockLookup>
{
    VerifierCtx {
        header_verifier: AcceptHeaders,
        merkle_verifier: DefaultMerkleVerifier,
        group_verifier: AcceptGroups,
        chain_lookup: MockLookup,
    }
}

#[test]
fn generated_genesis_proof_verifies() {
    let proof = build_genesis_proof();

    // Encode/decode round trip, then verify the decoded proof with
    // full chain verification (real merkle proof against the embedded
    // header's root).
    let encoded = encode_proof(&proof);
    let decoded = decode_proof(&encoded).expect("decode");
    assert_eq!(encode_proof(&decoded), encoded);

    let snapshot = decoded
        .verify(None, &ctx(), &ProofVerificationOptions::default())
        .expect("generated genesis proof must verify");

    assert_eq!(snapshot.asset.amount, 5_000);
    assert_eq!(snapshot.anchor_block_height, 800_000);
    assert!(!snapshot.split_asset);
}

#[test]
fn generated_proof_ownership_round_trip() {
    let secp = Secp256k1::new();
    let (script_kp, _) = keypair(0x22);

    let mut proof = build_genesis_proof();

    let challenge = Some([0x77; 32]);
    prove_ownership(&mut proof, challenge, |sighash| {
        let msg = Message::from_digest(*sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &script_kp);
        Ok(sig.as_ref().to_vec())
    })
    .expect("prove_ownership");

    // Encode/decode round trip keeps the challenge witness.
    let decoded = decode_proof(&encode_proof(&proof)).expect("decode");
    assert!(decoded.challenge_witness.is_some());

    // Full verification takes the challenge branch (no prev snapshot,
    // challenge witness present) and must pass with the right
    // challenge.
    let opts = ProofVerificationOptions {
        challenge_bytes: challenge,
        ..Default::default()
    };
    decoded
        .verify(None, &ctx(), &opts)
        .expect("ownership proof must verify");

    // A wrong challenge must fail.
    let wrong_opts = ProofVerificationOptions {
        challenge_bytes: Some([0x78; 32]),
        ..Default::default()
    };
    decoded
        .verify(None, &ctx(), &wrong_opts)
        .expect_err("wrong challenge must fail");
}
