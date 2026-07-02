//! End-to-end STXO proof tests: run a split transfer through the send
//! pipeline (which merges STXO spent-asset markers into the transfer
//! root output commitment by default), create TransitionV1 proof
//! suffixes for every asset output, and verify them with the full
//! tap-primitives verifier, which REQUIRES STXO proofs for V1 transfer
//! roots. Also checks that tampered or missing STXO proofs fail
//! verification and that the opt-out (Go's `WithNoSTXOProofs`)
//! produces V0 proofs that verify without any STXO data.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use tap_onchain::proof::suffix::{
    create_proof_suffix, create_proof_suffix_with_options, Bip86Output,
    OutputProofInfo, ProofSuffixOptions,
};
use tap_onchain::send::{
    execute_transfer_with_options, SelectedInput, TransferOptions,
    TransferOutput, TransferResult, VirtualSigner,
};
use tap_primitives::asset::{
    Asset, AssetType, AssetVersion, Genesis, OutPoint, PrevId, ScriptKey,
    ScriptVersion, SerializedKey, Witness, EMPTY_GENESIS_ID,
};
use tap_primitives::commitment::TapCommitmentVersion;
use tap_primitives::proof::{
    decode_proof, encode_proof, AnchorTx, AssetSnapshot, BlockHeader,
    ChainLookup, DefaultMerkleVerifier, GroupVerifier, HeaderVerifier,
    ProofError, ProofVerificationOptions, TransitionVersion, VerifierCtx,
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
    VerifierCtx::new(
        AcceptHeaders,
        DefaultMerkleVerifier,
        AcceptGroups,
        MockLookup,
    )
}

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

/// The fixed setup: a 100-unit asset owned by the owner key, split into
/// 60 units for a recipient (anchor output 1) with 40 units change
/// (anchor output 0), plus one unrelated BIP-86 P2TR output (index 2).
struct Setup {
    prev_asset: Asset,
    prev_anchor: OutPoint,
    owner_key: SerializedKey,
    internal_keys: [SerializedKey; 2],
    btc_key: SerializedKey,
    result: TransferResult,
    anchor_tx: bitcoin::Transaction,
}

fn run_transfer(no_stxo_proofs: bool) -> Setup {
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
        tag: "transfer-stxo".to_string(),
        meta_hash: [0u8; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    };

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

    let result = execute_transfer_with_options(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &TestSigner { keypair: owner_kp },
        &[
            internal0_kp.x_only_public_key().0,
            internal1_kp.x_only_public_key().0,
        ],
        &TransferOptions {
            commitment_version: Some(TapCommitmentVersion::V2),
            no_stxo_proofs,
        },
    )
    .expect("transfer pipeline");

    // Synthetic anchor transaction: the template's two commitment
    // outputs plus one unrelated BIP-86 P2TR output at index 2.
    let mut anchor_tx = result.template.tx.clone();
    anchor_tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(5_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr(
            &secp,
            btc_kp.x_only_public_key().0,
            None,
        ),
    });
    assert_eq!(anchor_tx.output.len(), 3);

    Setup {
        prev_asset,
        prev_anchor,
        owner_key,
        internal_keys: [internal0_key, internal1_key],
        btc_key,
        result,
        anchor_tx,
    }
}

fn asset_outputs<'a>(setup: &'a Setup) -> Vec<OutputProofInfo<'a>> {
    let prepared = &setup.result.prepared;
    vec![
        OutputProofInfo {
            asset: &prepared.root_asset,
            anchor_output_index: 0,
            internal_key: setup.internal_keys[0],
            commitment: &prepared.change_commitment,
            tapscript_sibling: None,
        },
        OutputProofInfo {
            asset: &prepared.recipient_assets[0].asset,
            anchor_output_index: 1,
            internal_key: setup.internal_keys[1],
            commitment: &prepared.output_commitments[0],
            tapscript_sibling: None,
        },
    ]
}

fn bip86_outputs(setup: &Setup) -> Vec<Bip86Output> {
    vec![Bip86Output {
        output_index: 2,
        internal_key: setup.btc_key,
    }]
}

fn prev_snapshot(setup: &Setup) -> AssetSnapshot {
    AssetSnapshot {
        asset: setup.prev_asset.clone(),
        out_point: setup.prev_anchor.clone(),
        anchor_block_hash: [0u8; 32],
        anchor_block_height: 0,
        anchor_tx: AnchorTx::default(),
        output_index: setup.prev_anchor.vout,
        internal_key: setup.owner_key,
        script_root: None,
        tapscript_sibling: None,
        split_asset: false,
        meta_reveal: None,
    }
}

fn verify_opts() -> ProofVerificationOptions {
    ProofVerificationOptions {
        challenge_bytes: None,
        skip_chain_verification: true,
        skip_time_lock_validation: false,
    }
}

const V1_OPTIONS: ProofSuffixOptions = ProofSuffixOptions {
    transition_version: TransitionVersion::V1,
    no_stxo_proofs: false,
};

#[test]
fn v1_split_transfer_proofs_verify() {
    let setup = run_transfer(false);
    let prepared = &setup.result.prepared;
    assert!(prepared.is_split);

    // The change commitment (transfer root output) must carry exactly
    // one STXO alt leaf (one input), the recipient commitment none.
    assert_eq!(prepared.change_commitment.fetch_alt_leaves().len(), 1);
    assert!(prepared.output_commitments[0].fetch_alt_leaves().is_empty());
    assert!(prepared
        .change_commitment
        .asset_commitments()
        .contains_key(EMPTY_GENESIS_ID.as_bytes()));

    let outputs = asset_outputs(&setup);
    let snapshot = prev_snapshot(&setup);
    let opts = verify_opts();

    for (idx, info) in outputs.iter().enumerate() {
        let proof = create_proof_suffix_with_options(
            &setup.anchor_tx,
            setup.prev_anchor.clone(),
            &outputs,
            idx,
            &bip86_outputs(&setup),
            &V1_OPTIONS,
        )
        .unwrap_or_else(|e| panic!("proof suffix for output {}: {}", idx, e));

        assert_eq!(proof.version, TransitionVersion::V1);

        if idx == 0 {
            // The transfer root proof carries the alt leaves, one STXO
            // inclusion proof, and STXO exclusion proofs against the
            // recipient output (the BIP-86 output is covered by its
            // tapscript proof).
            assert_eq!(proof.alt_leaves.len(), 1);
            assert!(proof.alt_leaves[0].validate_alt_leaf().is_ok());
            let cp = proof
                .inclusion_proof
                .commitment_proof
                .as_ref()
                .expect("inclusion commitment proof");
            assert_eq!(cp.stxo_proofs.len(), 1);

            for ep in &proof.exclusion_proofs {
                match ep.commitment_proof.as_ref() {
                    Some(cp) => assert_eq!(cp.stxo_proofs.len(), 1),
                    None => assert!(ep
                        .tapscript_proof
                        .as_ref()
                        .map(|tp| tp.bip86)
                        .unwrap_or(false)),
                }
            }
        } else {
            // Split leaves are not transfer roots: no alt leaves, no
            // STXO proofs required or generated.
            assert!(proof.alt_leaves.is_empty());
            let cp = proof
                .inclusion_proof
                .commitment_proof
                .as_ref()
                .expect("inclusion commitment proof");
            assert!(cp.stxo_proofs.is_empty());
        }

        // Encode/decode round trip must preserve the STXO data.
        let encoded = encode_proof(&proof);
        let decoded = decode_proof(&encoded).expect("decode");
        assert_eq!(encode_proof(&decoded), encoded);

        // Full verification: for V1 transfer roots the verifier
        // REQUIRES valid STXO inclusion and exclusion proofs.
        let verified = decoded
            .verify(Some(&snapshot), &ctx(), &opts)
            .unwrap_or_else(|e| {
                panic!("V1 proof for output {} must verify: {}", idx, e)
            });
        assert_eq!(verified.output_index, info.anchor_output_index);
        assert_eq!(verified.asset.amount, info.asset.amount);
    }
}

#[test]
fn v1_tampered_stxo_proofs_fail() {
    let setup = run_transfer(false);
    let outputs = asset_outputs(&setup);
    let snapshot = prev_snapshot(&setup);
    let opts = verify_opts();

    // The transfer root proof (change output 0).
    let proof = create_proof_suffix_with_options(
        &setup.anchor_tx,
        setup.prev_anchor.clone(),
        &outputs,
        0,
        &bip86_outputs(&setup),
        &V1_OPTIONS,
    )
    .expect("proof suffix");

    // Untampered, the proof verifies.
    proof
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect("untampered V1 proof must verify");

    // 1) Remove the STXO inclusion proofs: V1 transfer roots require
    // them, so verification must fail.
    let mut missing_inclusion = proof.clone();
    missing_inclusion
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .expect("commitment proof")
        .stxo_proofs
        .clear();
    missing_inclusion
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect_err("V1 proof without STXO inclusion proofs must fail");

    // 2) Remove the STXO exclusion proofs from the recipient output:
    // the completeness check must fail.
    let mut missing_exclusion = proof.clone();
    let mut cleared = false;
    for ep in &mut missing_exclusion.exclusion_proofs {
        if let Some(cp) = ep.commitment_proof.as_mut() {
            cp.stxo_proofs.clear();
            cleared = true;
        }
    }
    assert!(cleared);
    missing_exclusion
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect_err("V1 proof without STXO exclusion proofs must fail");

    // 3) Re-key an STXO inclusion proof to a key that does not match
    // any expected spent asset: verification must fail.
    let mut wrong_key = proof.clone();
    let cp = wrong_key
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .expect("commitment proof");
    let (key, stxo_proof) =
        cp.stxo_proofs.pop_first().expect("one STXO proof");
    let mut tampered_key = *key.as_bytes();
    tampered_key[32] ^= 0x01;
    cp.stxo_proofs
        .insert(SerializedKey(tampered_key), stxo_proof);
    wrong_key
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect_err("V1 proof with re-keyed STXO proof must fail");

    // 4) Swap the inclusion STXO proof with an (exclusion) STXO proof
    // taken from another output: the derived root no longer matches
    // the anchor output key.
    let mut swapped = proof.clone();
    let exclusion_stxo = swapped
        .exclusion_proofs
        .iter()
        .find_map(|ep| ep.commitment_proof.as_ref())
        .map(|cp| cp.stxo_proofs.clone())
        .expect("exclusion STXO proofs");
    swapped
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .expect("commitment proof")
        .stxo_proofs = exclusion_stxo;
    swapped
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect_err("V1 proof with swapped STXO proof must fail");
}

#[test]
fn opt_out_produces_v0_proofs_without_stxo() {
    // The Go analogue of tapsend.WithNoSTXOProofs +
    // proof.WithNoSTXOProofs (asset channels): no alt leaves are
    // merged, no STXO proofs are generated, and the resulting V0
    // proofs still verify.
    let setup = run_transfer(true);
    let prepared = &setup.result.prepared;
    assert!(prepared.change_commitment.fetch_alt_leaves().is_empty());

    let outputs = asset_outputs(&setup);
    let snapshot = prev_snapshot(&setup);
    let opts = verify_opts();
    let suffix_options = ProofSuffixOptions {
        transition_version: TransitionVersion::V0,
        no_stxo_proofs: true,
    };

    for idx in 0..outputs.len() {
        let proof = create_proof_suffix_with_options(
            &setup.anchor_tx,
            setup.prev_anchor.clone(),
            &outputs,
            idx,
            &bip86_outputs(&setup),
            &suffix_options,
        )
        .unwrap_or_else(|e| panic!("proof suffix for output {}: {}", idx, e));

        assert_eq!(proof.version, TransitionVersion::V0);
        assert!(proof.alt_leaves.is_empty());
        let cp = proof
            .inclusion_proof
            .commitment_proof
            .as_ref()
            .expect("inclusion commitment proof");
        assert!(cp.stxo_proofs.is_empty());
        for ep in &proof.exclusion_proofs {
            if let Some(cp) = ep.commitment_proof.as_ref() {
                assert!(cp.stxo_proofs.is_empty());
            }
        }

        proof
            .verify(Some(&snapshot), &ctx(), &opts)
            .unwrap_or_else(|e| {
                panic!("opt-out V0 proof for output {} must verify: {}", idx, e)
            });
    }
}

#[test]
fn default_options_match_go_default() {
    // Go's DefaultGenConfig stamps TransitionV0 but still generates
    // STXO alt leaves and proofs; the verifier validates them when
    // present without requiring them.
    let setup = run_transfer(false);
    let outputs = asset_outputs(&setup);
    let snapshot = prev_snapshot(&setup);
    let opts = verify_opts();

    let proof = create_proof_suffix(
        &setup.anchor_tx,
        setup.prev_anchor.clone(),
        &outputs,
        0,
        &bip86_outputs(&setup),
    )
    .expect("proof suffix");

    assert_eq!(proof.version, TransitionVersion::V0);
    assert_eq!(proof.alt_leaves.len(), 1);
    let cp = proof
        .inclusion_proof
        .commitment_proof
        .as_ref()
        .expect("inclusion commitment proof");
    assert_eq!(cp.stxo_proofs.len(), 1);

    proof
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect("default (V0 + STXO) proof must verify");

    // An invalid STXO proof is rejected even on a V0 proof, because
    // the verifier validates present STXO proofs regardless of
    // version.
    let mut wrong_key = proof.clone();
    let cp = wrong_key
        .inclusion_proof
        .commitment_proof
        .as_mut()
        .expect("commitment proof");
    let (key, stxo_proof) =
        cp.stxo_proofs.pop_first().expect("one STXO proof");
    let mut tampered_key = *key.as_bytes();
    tampered_key[32] ^= 0x01;
    cp.stxo_proofs
        .insert(SerializedKey(tampered_key), stxo_proof);
    wrong_key
        .verify(Some(&snapshot), &ctx(), &opts)
        .expect_err("V0 proof with re-keyed STXO proof must fail");
}

#[test]
fn v1_full_value_send_proofs_verify() {
    // Full-value interactive send: the transfer asset itself is the
    // transfer root, so its output commitment carries the STXO alt
    // leaf and the proof carries STXO inclusion proofs.
    let secp = Secp256k1::new();
    let (owner_kp, owner_key) = keypair(0x51);
    let (_, recipient_key) = keypair(0x52);
    let (internal0_kp, internal0_key) = keypair(0x61);
    let (btc_kp, btc_key) = keypair(0x71);

    let genesis = Genesis {
        first_prev_out: OutPoint {
            txid: [0x77; 32],
            vout: 0,
        },
        tag: "full-send-stxo".to_string(),
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
        output_index: 0,
        amount: 100,
        script_key: ScriptKey::from_pub_key(recipient_key),
        asset_version: AssetVersion::V0,
        interactive: true,
    }];

    let mut prev_assets = InputSet::new();
    prev_assets.insert(prev_id, prev_asset.clone());

    let result = execute_transfer_with_options(
        &inputs,
        &outputs,
        &genesis,
        &prev_assets,
        &TestSigner { keypair: owner_kp },
        &[internal0_kp.x_only_public_key().0],
        &TransferOptions {
            commitment_version: Some(TapCommitmentVersion::V2),
            no_stxo_proofs: false,
        },
    )
    .expect("transfer pipeline");
    let prepared = &result.prepared;
    assert!(!prepared.is_split);
    assert_eq!(prepared.change_commitment.fetch_alt_leaves().len(), 1);

    // Anchor transaction: one commitment output plus one BIP-86 P2TR
    // output.
    let mut anchor_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: result.template.tx.input.clone(),
        output: vec![result.template.tx.output[0].clone()],
    };
    anchor_tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(5_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr(
            &secp,
            btc_kp.x_only_public_key().0,
            None,
        ),
    });

    let asset_outputs = vec![OutputProofInfo {
        asset: &prepared.root_asset,
        anchor_output_index: 0,
        internal_key: internal0_key,
        commitment: &prepared.change_commitment,
        tapscript_sibling: None,
    }];
    let bip86 = vec![Bip86Output {
        output_index: 1,
        internal_key: btc_key,
    }];

    let proof = create_proof_suffix_with_options(
        &anchor_tx,
        prev_anchor.clone(),
        &asset_outputs,
        0,
        &bip86,
        &V1_OPTIONS,
    )
    .expect("proof suffix");

    assert_eq!(proof.version, TransitionVersion::V1);
    assert_eq!(proof.alt_leaves.len(), 1);
    assert_eq!(
        proof
            .inclusion_proof
            .commitment_proof
            .as_ref()
            .expect("commitment proof")
            .stxo_proofs
            .len(),
        1
    );

    let snapshot = AssetSnapshot {
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

    proof
        .verify(Some(&snapshot), &ctx(), &verify_opts())
        .expect("V1 full send proof must verify");
}
