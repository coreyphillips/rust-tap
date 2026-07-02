//! Round-trip self-check for transfer proof suffix creation: run a
//! split transfer (2 recipients + change) through the send pipeline,
//! anchor the resulting commitments in a synthetic Bitcoin transaction
//! (plus one unrelated BIP-86 P2TR output), create the proof suffix for
//! every asset output via `create_proof_suffix`, and verify each
//! generated proof with the full tap-primitives verifier — including
//! real Schnorr witness validation of the signed root asset, split
//! commitment proofs, split root proofs, and exclusion proofs for all
//! other P2TR outputs.

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use tap_onchain::proof::suffix::{
    create_proof_suffix, Bip86Output, OutputProofInfo,
};
use tap_onchain::send::{
    execute_transfer_with_version, SelectedInput, TransferOutput,
    VirtualSigner,
};
use tap_primitives::asset::{
    Asset, AssetType, AssetVersion, Genesis, OutPoint, PrevId, ScriptKey,
    ScriptVersion, SerializedKey, Witness,
};
use tap_primitives::commitment::TapCommitmentVersion;
use tap_primitives::proof::{
    decode_proof, encode_proof, AnchorTx, AssetSnapshot, BlockHeader,
    ChainLookup, DefaultMerkleVerifier, GroupVerifier, HeaderVerifier,
    ProofError, ProofVerificationOptions, VerifierCtx,
};
use tap_primitives::vm::InputSet;

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

fn ctx(
) -> VerifierCtx<AcceptHeaders, DefaultMerkleVerifier, AcceptGroups, MockLookup>
{
    VerifierCtx {
        header_verifier: AcceptHeaders,
        merkle_verifier: DefaultMerkleVerifier,
        group_verifier: AcceptGroups,
        chain_lookup: MockLookup,
    }
}

/// A signer that produces real BIP-340 Schnorr signatures, matching the
/// signer used by the send/sign.rs tests.
struct TestSigner {
    keypair: Keypair,
}

impl VirtualSigner for TestSigner {
    fn sign_virtual_tx(
        &self,
        sighash: &[u8; 32],
        _script_key: &ScriptKey,
    ) -> Result<Vec<u8>, tap_onchain::send::SendError> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &self.keypair);
        Ok(sig.as_ref().to_vec())
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

#[test]
fn split_transfer_proofs_verify() {
    let secp = Secp256k1::new();

    // Keys: the input owner (signs the transfer), two recipients, three
    // anchor output internal keys, and one unrelated pure-BTC key.
    let (owner_kp, owner_key) = keypair(0x21);
    let (_, recipient1_key) = keypair(0x22);
    let (_, recipient2_key) = keypair(0x23);
    let (internal0_kp, internal0_key) = keypair(0x31);
    let (internal1_kp, internal1_key) = keypair(0x32);
    let (internal2_kp, internal2_key) = keypair(0x33);
    let (btc_kp, btc_key) = keypair(0x41);

    let genesis = Genesis {
        first_prev_out: OutPoint {
            txid: [0x66; 32],
            vout: 1,
        },
        tag: "transfer-roundtrip".to_string(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    };

    // The previous asset state: 100 units owned by the input key,
    // anchored at some outpoint.
    let prev_anchor = OutPoint {
        txid: [0xBB; 32],
        vout: 0,
    };
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
        script_key: ScriptKey::from_pub_key(owner_key),
        group_key: None,
        unknown_odd_types: std::collections::BTreeMap::new(),
    };
    let prev_id = PrevId {
        out_point: prev_anchor.clone(),
        id: genesis.id(),
        script_key: owner_key,
    };

    // Split transfer: 60 + 25 to the recipients, 15 change. The output
    // indices are the anchor transaction output indices (change is 0).
    let inputs = vec![SelectedInput {
        prev_id: prev_id.clone(),
        anchor_point: prev_anchor.clone(),
        amount: 100,
        asset_type: AssetType::Normal,
        script_key: ScriptKey::from_pub_key(owner_key),
    }];
    let outputs = vec![
        TransferOutput {
            output_index: 1,
            amount: 60,
            script_key: ScriptKey::from_pub_key(recipient1_key),
            asset_version: AssetVersion::V0,
            interactive: false,
        },
        TransferOutput {
            output_index: 2,
            amount: 25,
            script_key: ScriptKey::from_pub_key(recipient2_key),
            asset_version: AssetVersion::V0,
            interactive: false,
        },
    ];

    let mut prev_assets = InputSet::new();
    prev_assets.insert(prev_id, prev_asset.clone());

    let internal_keys = vec![
        internal0_kp.x_only_public_key().0,
        internal1_kp.x_only_public_key().0,
        internal2_kp.x_only_public_key().0,
    ];

    let result = execute_transfer_with_version(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &TestSigner { keypair: owner_kp },
        &internal_keys,
        Some(TapCommitmentVersion::V2),
    )
    .expect("transfer pipeline");

    let prepared = &result.prepared;
    assert!(prepared.is_split);
    assert_eq!(prepared.root_asset.amount, 15);
    assert_eq!(prepared.recipient_assets.len(), 2);

    // Synthetic anchor transaction: the template's three commitment
    // outputs (change at 0, recipients at 1 and 2) plus one unrelated
    // BIP-86 P2TR output at index 3.
    let mut anchor_tx = result.template.tx.clone();
    anchor_tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(5_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr(
            &secp,
            btc_kp.x_only_public_key().0,
            None,
        ),
    });
    assert_eq!(anchor_tx.output.len(), 4);
    for out in &anchor_tx.output {
        assert!(out.script_pubkey.is_p2tr());
    }

    // Describe the asset-carrying outputs for proof creation.
    let asset_outputs = vec![
        OutputProofInfo {
            asset: &prepared.root_asset,
            anchor_output_index: 0,
            internal_key: internal0_key,
            commitment: &prepared.change_commitment,
            tapscript_sibling: None,
        },
        OutputProofInfo {
            asset: &prepared.recipient_assets[0].asset,
            anchor_output_index: prepared.recipient_assets[0].output_index,
            internal_key: internal1_key,
            commitment: &prepared.output_commitments[0],
            tapscript_sibling: None,
        },
        OutputProofInfo {
            asset: &prepared.recipient_assets[1].asset,
            anchor_output_index: prepared.recipient_assets[1].output_index,
            internal_key: internal2_key,
            commitment: &prepared.output_commitments[1],
            tapscript_sibling: None,
        },
    ];
    let bip86_outputs = vec![Bip86Output {
        output_index: 3,
        internal_key: btc_key,
    }];

    // The previous state snapshot handed to the verifier (the state the
    // transfer spends).
    let prev_snapshot = AssetSnapshot {
        asset: prev_asset.clone(),
        out_point: prev_anchor.clone(),
        anchor_block_hash: [0u8; 32],
        anchor_block_height: 0,
        anchor_tx: AnchorTx::default(),
        output_index: prev_anchor.vout,
        internal_key: owner_key,
        script_root: None,
        tapscript_sibling: None,
        split_asset: false,
        meta_reveal: None,
    };

    // The suffix carries placeholder chain data, so chain verification
    // is skipped (Go verifies suffixes the same way before
    // confirmation).
    let opts = ProofVerificationOptions {
        challenge_bytes: None,
        skip_chain_verification: true,
        skip_time_lock_validation: false,
    };

    for (idx, info) in asset_outputs.iter().enumerate() {
        let proof = create_proof_suffix(
            &anchor_tx,
            prev_anchor.clone(),
            &asset_outputs,
            idx,
            &bip86_outputs,
        )
        .unwrap_or_else(|e| panic!("proof suffix for output {}: {}", idx, e));

        // Every proof must carry exclusion proofs for the two other
        // asset outputs and the BIP-86 output.
        assert_eq!(proof.exclusion_proofs.len(), 3);
        let bip86_proof = proof
            .exclusion_proofs
            .iter()
            .find(|ep| ep.output_index == 3)
            .expect("exclusion proof for the BIP-86 output");
        assert!(bip86_proof
            .tapscript_proof
            .as_ref()
            .map(|tp| tp.bip86)
            .unwrap_or(false));
        assert!(bip86_proof.commitment_proof.is_none());
        for ep in &proof.exclusion_proofs {
            if ep.output_index != 3 {
                assert!(ep.commitment_proof.is_some());
            }
        }

        // Split outputs must carry a split root proof pointing at the
        // change output; the root output must not.
        if idx == 0 {
            assert!(proof.split_root_proof.is_none());
        } else {
            let srp = proof
                .split_root_proof
                .as_ref()
                .expect("split root proof for split output");
            assert_eq!(srp.output_index, 0);
        }

        // Encode/decode round trip, then run the decoded proof through
        // the full verifier (inclusion, split root, exclusion proofs,
        // and VM state transition with real Schnorr validation).
        let encoded = encode_proof(&proof);
        let decoded = decode_proof(&encoded).expect("decode");
        assert_eq!(encode_proof(&decoded), encoded);

        let snapshot = decoded
            .verify(Some(&prev_snapshot), &ctx(), &opts)
            .unwrap_or_else(|e| {
                panic!("proof for output {} must verify: {}", idx, e)
            });

        assert_eq!(snapshot.output_index, info.anchor_output_index);
        assert_eq!(snapshot.asset.amount, info.asset.amount);
        assert_eq!(snapshot.split_asset, idx != 0);
        let anchor_txid: [u8; 32] =
            anchor_tx.compute_txid().to_byte_array();
        assert_eq!(snapshot.out_point.txid, anchor_txid);
    }
}

#[test]
fn tampered_split_proof_fails() {
    // Sanity check that the verifier is actually exercising the proofs:
    // moving a split proof to the wrong output index must fail.
    let secp = Secp256k1::new();
    let (owner_kp, owner_key) = keypair(0x21);
    let (_, recipient_key) = keypair(0x22);
    let (internal0_kp, internal0_key) = keypair(0x31);
    let (internal1_kp, internal1_key) = keypair(0x32);
    let (btc_kp, btc_key) = keypair(0x41);

    let genesis = Genesis {
        first_prev_out: OutPoint {
            txid: [0x66; 32],
            vout: 1,
        },
        tag: "transfer-tamper".to_string(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    };

    let prev_anchor = OutPoint {
        txid: [0xCC; 32],
        vout: 1,
    };
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
        script_key: ScriptKey::from_pub_key(owner_key),
        group_key: None,
        unknown_odd_types: std::collections::BTreeMap::new(),
    };
    let prev_id = PrevId {
        out_point: prev_anchor.clone(),
        id: genesis.id(),
        script_key: owner_key,
    };

    let inputs = vec![SelectedInput {
        prev_id: prev_id.clone(),
        anchor_point: prev_anchor.clone(),
        amount: 100,
        asset_type: AssetType::Normal,
        script_key: ScriptKey::from_pub_key(owner_key),
    }];
    let outputs = vec![TransferOutput {
        output_index: 1,
        amount: 60,
        script_key: ScriptKey::from_pub_key(recipient_key),
        asset_version: AssetVersion::V0,
        interactive: false,
    }];

    let mut prev_assets = InputSet::new();
    prev_assets.insert(prev_id, prev_asset.clone());

    let result = execute_transfer_with_version(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &TestSigner { keypair: owner_kp },
        &[
            internal0_kp.x_only_public_key().0,
            internal1_kp.x_only_public_key().0,
        ],
        Some(TapCommitmentVersion::V2),
    )
    .expect("transfer pipeline");
    let prepared = &result.prepared;

    let mut anchor_tx = result.template.tx.clone();
    anchor_tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(5_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr(
            &secp,
            btc_kp.x_only_public_key().0,
            None,
        ),
    });

    let asset_outputs = vec![
        OutputProofInfo {
            asset: &prepared.root_asset,
            anchor_output_index: 0,
            internal_key: internal0_key,
            commitment: &prepared.change_commitment,
            tapscript_sibling: None,
        },
        OutputProofInfo {
            asset: &prepared.recipient_assets[0].asset,
            anchor_output_index: 1,
            internal_key: internal1_key,
            commitment: &prepared.output_commitments[0],
            tapscript_sibling: None,
        },
    ];

    let mut proof = create_proof_suffix(
        &anchor_tx,
        prev_anchor.clone(),
        &asset_outputs,
        1,
        &[Bip86Output {
            output_index: 2,
            internal_key: btc_key,
        }],
    )
    .expect("proof suffix");

    let prev_snapshot = AssetSnapshot {
        asset: prev_asset,
        out_point: prev_anchor.clone(),
        anchor_block_hash: [0u8; 32],
        anchor_block_height: 0,
        anchor_tx: AnchorTx::default(),
        output_index: prev_anchor.vout,
        internal_key: owner_key,
        script_root: None,
        tapscript_sibling: None,
        split_asset: false,
        meta_reveal: None,
    };
    let opts = ProofVerificationOptions {
        challenge_bytes: None,
        skip_chain_verification: true,
        skip_time_lock_validation: false,
    };

    // Unmodified, the proof verifies.
    proof
        .verify(Some(&prev_snapshot), &ctx(), &opts)
        .expect("untampered proof must verify");

    // Point the inclusion proof at the wrong output: verification must
    // fail.
    proof.inclusion_proof.output_index = 0;
    proof
        .verify(Some(&prev_snapshot), &ctx(), &opts)
        .expect_err("tampered proof must fail");
}
