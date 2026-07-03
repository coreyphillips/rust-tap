// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof suffix creation for asset transfers, mirroring Go's
//! `tapsend.CreateProofSuffix` / `proofParams` (tapsend/proof.go) and
//! `proof.CreateTransitionProof` (proof/append.go).
//!
//! A proof suffix is the final state transition proof appended to the
//! receiver's proof file. It carries all the Taproot Asset level proof
//! data (inclusion proof, exclusion proofs, and — for split assets —
//! the split root proof) but only placeholder chain data: the anchor
//! transaction is embedded, while the block header, height, and
//! transaction merkle proof are filled in after confirmation via
//! [`update_proof_chain_data`], mirroring Go's
//! `Proof.UpdateTransitionProof`.

use std::collections::BTreeMap;

use tap_primitives::asset::{
    self, Asset, OutPoint, SerializedKey, EMPTY_GENESIS_ID,
};
use tap_primitives::commitment::{
    asset_commitment_key, tap_commitment_key, CommitmentProof,
    TapCommitmentTree, TapscriptPreimage,
};
use tap_primitives::encoding::asset::encode_asset;
use tap_primitives::proof::{
    self, AnchorTx, BlockHeader, TaprootProof, TransitionVersion,
};

use super::exclusion::{generate_exclusion_proofs, AnchorOutputInfo};
use super::merkle::build_tx_merkle_proof;
use super::transition::BaseProofParams;

/// Describes one asset-carrying output of a transfer for proof
/// creation, the Rust equivalent of a Go `tappsbt.VOutput` plus its
/// entry in `tappsbt.OutputCommitments`.
pub struct OutputProofInfo<'a> {
    /// The final (signed) asset committed to in this output. Split
    /// assets must already carry their split commitment witness.
    pub asset: &'a Asset,
    /// Index of the output in the anchor transaction.
    pub anchor_output_index: u32,
    /// The Taproot internal key of the anchor output.
    pub internal_key: SerializedKey,
    /// The Taproot Asset commitment tree of the anchor output.
    pub commitment: &'a TapCommitmentTree,
    /// The tapscript sibling preimage of the anchor output, if any.
    pub tapscript_sibling: Option<TapscriptPreimage>,
}

/// A plain BIP-86 P2TR output of the anchor transaction that carries no
/// Taproot Asset commitment (e.g. a BTC change output). Gets a
/// `TapscriptProof { bip86: true }` exclusion proof, mirroring Go's
/// `proof.AddExclusionProofs`.
pub struct Bip86Output {
    /// Index of the output in the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key of the output.
    pub internal_key: SerializedKey,
}

/// Options for proof suffix creation, the Rust analogue of Go's
/// `proof.GenConfig` (proof/append.go).
///
/// The defaults mirror Go's `proof.DefaultGenConfig` in v0.8.99: the
/// proof version is stamped `TransitionV0`, while STXO alt leaves and
/// STXO inclusion/exclusion proofs are still generated for transfer
/// root assets (verifiers validate them when present but only require
/// them for V1 proofs). Pass `transition_version: TransitionVersion::V1`
/// (Go's `proof.WithVersion(TransitionV1)`) to stamp V1 and make the
/// STXO proofs mandatory at verification time.
#[derive(Clone, Debug)]
pub struct ProofSuffixOptions {
    /// The transition version stamped on the created proof (Go's
    /// `GenConfig.TransitionVersion`, default `TransitionV0`).
    pub transition_version: TransitionVersion,
    /// Skips the generation of STXO inclusion and exclusion proofs
    /// (Go's `proof.WithNoSTXOProofs`, used for asset channels). The
    /// target output's commitment must then have been built without
    /// STXO alt leaves as well.
    pub no_stxo_proofs: bool,
}

impl Default for ProofSuffixOptions {
    fn default() -> Self {
        ProofSuffixOptions {
            transition_version: TransitionVersion::V0,
            no_stxo_proofs: false,
        }
    }
}

/// Creates the transition proof suffix for the asset output at
/// `out_index` within `asset_outputs` with default
/// [`ProofSuffixOptions`], mirroring Go's `tapsend.CreateProofSuffix`
/// without options:
///
/// - a real inclusion proof from the output's commitment tree,
/// - for split assets, a split root proof pointing at the root asset's
///   output (whose committed root asset must match the split witness),
/// - exclusion proofs for all other asset outputs (non-inclusion
///   commitment proofs) and all `bip86_outputs` (tapscript proofs),
/// - for transfer root assets, STXO alt leaves plus STXO inclusion and
///   exclusion proofs (unless opted out via
///   [`ProofSuffixOptions::no_stxo_proofs`]).
///
/// `prev_out` is the anchor outpoint of the (first) input being spent,
/// Go's `vPacket.Inputs[0].PrevID.OutPoint`. Chain data (block header,
/// height, merkle proof) is left as placeholders; call
/// [`update_proof_chain_data`] once the anchor transaction confirms.
pub fn create_proof_suffix(
    anchor_tx: &bitcoin::Transaction,
    prev_out: OutPoint,
    asset_outputs: &[OutputProofInfo<'_>],
    out_index: usize,
    bip86_outputs: &[Bip86Output],
) -> Result<proof::Proof, String> {
    create_proof_suffix_with_options(
        anchor_tx,
        prev_out,
        asset_outputs,
        out_index,
        bip86_outputs,
        &ProofSuffixOptions::default(),
    )
}

/// Creates the transition proof suffix for the asset output at
/// `out_index` with explicit [`ProofSuffixOptions`], mirroring Go's
/// `tapsend.CreateProofSuffix` with `proof.GenOption`s. See
/// [`create_proof_suffix`].
pub fn create_proof_suffix_with_options(
    anchor_tx: &bitcoin::Transaction,
    prev_out: OutPoint,
    asset_outputs: &[OutputProofInfo<'_>],
    out_index: usize,
    bip86_outputs: &[Bip86Output],
    options: &ProofSuffixOptions,
) -> Result<proof::Proof, String> {
    let target = asset_outputs
        .get(out_index)
        .ok_or_else(|| format!("no asset output at index {}", out_index))?;

    let ack = asset_commitment_key(
        &target.asset.genesis.id(),
        target.asset.script_key.serialized(),
        target.asset.group_key.is_some(),
    );
    let tck = tap_commitment_key(
        &target.asset.genesis.id(),
        target.asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
    );

    // Inclusion proof from the target output's commitment tree
    // (proof/append.go CreateTransitionProof).
    let (committed, mut inclusion_commitment_proof) = target
        .commitment
        .proof(&tck, &ack)
        .map_err(|e| e.to_string())?;
    if committed.is_none() {
        return Err(format!(
            "asset not committed to in output {}",
            target.anchor_output_index
        ));
    }
    inclusion_commitment_proof.tap_sibling_preimage =
        target.tapscript_sibling.clone();

    // Split root proof, if the target is a split asset
    // (proof/append.go:295).
    let split_root_proof = if target.asset.has_split_commitment_witness() {
        Some(create_split_root_proof(target, asset_outputs)?)
    } else {
        None
    };

    // Exclusion proofs for all other outputs: the other asset-carrying
    // outputs (tapsend/proof.go addOtherOutputExclusionProofs) and the
    // plain BIP-86 P2TR outputs (proof/taproot.go AddExclusionProofs).
    let mut other_outputs: Vec<AnchorOutputInfo<'_>> = asset_outputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != out_index)
        .map(|(_, out)| AnchorOutputInfo {
            output_index: out.anchor_output_index,
            internal_key: out.internal_key,
            commitment: Some(out.commitment),
            tapscript_sibling: out.tapscript_sibling.clone(),
        })
        .collect();
    for out in bip86_outputs {
        other_outputs.push(AnchorOutputInfo {
            output_index: out.output_index,
            internal_key: out.internal_key,
            commitment: None,
            tapscript_sibling: None,
        });
    }
    let mut exclusion_proofs = generate_exclusion_proofs(
        target.asset,
        target.anchor_output_index,
        &other_outputs,
    )?;

    // STXO proofs for transfer root assets: inclusion proofs for the
    // spent-asset markers committed to in the target output (Go
    // proof/append.go CreateTransitionProof:209) and exclusion proofs
    // showing they are absent from every other asset-carrying output
    // (Go tapsend/proof.go addSTXOExclusionProofs). Genesis assets and
    // split leaves are exempt (`IsTransferRoot`).
    if target.asset.is_transfer_root() && !options.no_stxo_proofs {
        add_stxo_proofs(
            target,
            &other_outputs,
            &mut inclusion_commitment_proof,
            &mut exclusion_proofs,
        )?;
    }

    let inclusion_proof = TaprootProof {
        output_index: target.anchor_output_index,
        internal_key: target.internal_key,
        commitment_proof: Some(inclusion_commitment_proof),
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    };

    // Copy any alt leaves from the anchor commitment to the proof
    // (Go proof/append.go CreateTransitionProof: FetchAltLeaves).
    let alt_leaves = target.commitment.fetch_alt_leaves();

    // The chain data is not final yet: like Go's `newParams`, we embed
    // the anchor transaction in a pseudo block containing only that
    // transaction. Header and height are placeholders updated after
    // confirmation.
    let txid = *anchor_tx.compute_txid().as_ref();
    let tx_merkle_proof = build_tx_merkle_proof(&[txid], 0)
        .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    Ok(proof::Proof {
        version: options.transition_version,
        prev_out,
        block_header: BlockHeader([0u8; 80]),
        block_height: 0,
        anchor_tx: AnchorTx(anchor_tx.clone()),
        tx_merkle_proof,
        asset: target.asset.clone(),
        inclusion_proof,
        exclusion_proofs,
        split_root_proof,
        meta_reveal: None,
        additional_inputs: vec![],
        challenge_witness: None,
        genesis_reveal: None,
        group_key_reveal: None,
        alt_leaves,
        unknown_odd_types: BTreeMap::new(),
    })
}

/// Generates the STXO inclusion proofs for the target output and the
/// STXO exclusion proofs for all other asset-carrying outputs of a
/// transfer root asset.
///
/// Inclusion (Go proof/append.go CreateTransitionProof): for each
/// previous witness, the spent-asset marker derived from its `PrevId`
/// must be committed to under `EMPTY_GENESIS_ID` in the target
/// output's commitment; the resulting proof is stored in the inclusion
/// commitment proof's `stxo_proofs`, keyed by the marker's serialized
/// burn key.
///
/// Exclusion (Go tapsend/proof.go addSTXOExclusionProofs): for every
/// exclusion proof that carries a commitment proof (i.e. the output
/// holds a Taproot Asset commitment), a non-inclusion proof for each
/// spent-asset marker is stored in that commitment proof's
/// `stxo_proofs`. Outputs covered by tapscript (BIP-86) proofs carry
/// no assets and are skipped.
fn add_stxo_proofs(
    target: &OutputProofInfo<'_>,
    other_outputs: &[AnchorOutputInfo<'_>],
    inclusion_commitment_proof: &mut CommitmentProof,
    exclusion_proofs: &mut [TaprootProof],
) -> Result<(), String> {
    let empty_id = *EMPTY_GENESIS_ID.as_bytes();

    // The commitment construction step must already have merged the
    // STXO alt leaves for this asset (Go: "no alt leaves for transfer
    // root asset").
    let alt_commitment = target
        .commitment
        .asset_commitments()
        .get(&empty_id)
        .ok_or_else(|| {
            "no alt leaves for transfer root asset".to_string()
        })?;

    // A transfer root must have previous witnesses.
    if target.asset.prev_witnesses.is_empty() {
        return Err("no prev witnesses for transfer root asset".to_string());
    }

    // We should have at least as many alt leaves as prev witnesses;
    // additional alt leaves unrelated to STXO proofs are allowed.
    if alt_commitment.assets().len() < target.asset.prev_witnesses.len() {
        return Err(
            "not enough alt leaves for transfer root asset".to_string()
        );
    }

    // The spent-asset markers, one per previous witness.
    let stxo_assets = asset::collect_stxo(target.asset)
        .map_err(|e| format!("error collecting STXO assets: {}", e))?;

    // STXO inclusion proofs from the target output's commitment.
    let mut stxo_inclusion_proofs: BTreeMap<SerializedKey, CommitmentProof> =
        BTreeMap::new();
    for spent_asset in &stxo_assets {
        let (found, stxo_proof) = target
            .commitment
            .proof(&empty_id, &spent_asset.asset_commitment_key())
            .map_err(|e| e.to_string())?;

        // STXO inclusion proofs must prove presence and always include
        // a valid asset-level proof.
        if found.is_none() {
            return Err(format!(
                "STXO asset not committed to in output {}",
                target.anchor_output_index
            ));
        }
        if stxo_proof.asset_proof.is_none() {
            return Err("missing asset proof in STXO inclusion".to_string());
        }

        stxo_inclusion_proofs
            .insert(*spent_asset.script_key.serialized(), stxo_proof);
    }

    // Each spent input corresponds to one entry in prev_witnesses, so
    // the counts must match (duplicate PrevIds would collapse here).
    if stxo_inclusion_proofs.len() != target.asset.prev_witnesses.len() {
        return Err(format!(
            "stxo inclusion proof count mismatch: expected {}, got {}",
            target.asset.prev_witnesses.len(),
            stxo_inclusion_proofs.len()
        ));
    }

    inclusion_commitment_proof.stxo_proofs = stxo_inclusion_proofs;

    // STXO exclusion proofs against every other asset-carrying output.
    for exclusion_proof in exclusion_proofs.iter_mut() {
        let Some(cp) = exclusion_proof.commitment_proof.as_mut() else {
            // Outputs without assets are covered by their tapscript
            // (BIP-86) exclusion proofs.
            continue;
        };

        let out_tree = other_outputs
            .iter()
            .find(|out| {
                out.output_index == exclusion_proof.output_index
            })
            .and_then(|out| out.commitment)
            .ok_or_else(|| {
                format!(
                    "no commitment tree for excluded output {}",
                    exclusion_proof.output_index
                )
            })?;

        let mut stxo_exclusion_proofs: BTreeMap<
            SerializedKey,
            CommitmentProof,
        > = BTreeMap::new();
        for spent_asset in &stxo_assets {
            let (found, stxo_proof) = out_tree
                .proof(&empty_id, &spent_asset.asset_commitment_key())
                .map_err(|e| e.to_string())?;

            // The spent asset must NOT be committed to in any other
            // output, otherwise the transfer double-spends the input.
            if found.is_some() {
                return Err(format!(
                    "STXO asset committed to in output {}; cannot create \
                     exclusion proof",
                    exclusion_proof.output_index
                ));
            }

            stxo_exclusion_proofs
                .insert(*spent_asset.script_key.serialized(), stxo_proof);
        }

        cp.stxo_proofs = stxo_exclusion_proofs;
    }

    Ok(())
}

/// Creates the split root proof for a split asset: an inclusion proof
/// of the root asset within the split root output's commitment,
/// mirroring the `HasSplitCommitmentWitness` branch of Go's
/// `proof.CreateTransitionProof`.
fn create_split_root_proof(
    target: &OutputProofInfo<'_>,
    asset_outputs: &[OutputProofInfo<'_>],
) -> Result<TaprootProof, String> {
    // Locate the split root output: the one carrying the asset with the
    // split commitment root (Go's vPkt.SplitRootOutput()).
    let root_output = asset_outputs
        .iter()
        .find(|out| out.asset.split_commitment_root.is_some())
        .ok_or_else(|| "no split root output found".to_string())?;
    let root_asset = root_output.asset;

    let root_ack = asset_commitment_key(
        &root_asset.genesis.id(),
        root_asset.script_key.serialized(),
        root_asset.group_key.is_some(),
    );
    let root_tck = tap_commitment_key(
        &root_asset.genesis.id(),
        root_asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
    );

    let (committed_root, mut root_commitment_proof) = root_output
        .commitment
        .proof(&root_tck, &root_ack)
        .map_err(|e| e.to_string())?;

    // If the root asset wasn't committed to, the proof is invalid.
    let committed_root = committed_root
        .ok_or_else(|| "no asset commitment found for split root".to_string())?;

    // Make sure the committed asset matches the root asset carried in
    // the split witness exactly (Go compares with DeepEqual, allowing
    // segwit differences; the send pipeline populates both from the
    // same signed root asset, so a byte comparison applies here).
    let witness_root = target
        .asset
        .prev_witnesses
        .first()
        .and_then(|w| w.split_commitment.as_ref())
        .map(|sc| sc.root_asset.clone())
        .ok_or_else(|| "split asset has no split commitment".to_string())?;
    let committed_bytes = encode_asset(
        committed_root,
        tap_primitives::asset::EncodeType::Normal,
    );
    if committed_bytes != witness_root {
        return Err("root asset mismatch: the split witness root asset \
                    differs from the committed root asset"
            .to_string());
    }

    root_commitment_proof.tap_sibling_preimage =
        root_output.tapscript_sibling.clone();

    Ok(TaprootProof {
        output_index: root_output.anchor_output_index,
        internal_key: root_output.internal_key,
        commitment_proof: Some(root_commitment_proof),
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    })
}

/// Updates a proof suffix with the chain data of the confirmed anchor
/// transaction, mirroring Go's `Proof.UpdateTransitionProof`
/// (proof/append.go:142): the block header, height, anchor transaction,
/// and transaction merkle proof are recomputed from the confirmation
/// parameters.
pub fn update_proof_chain_data(
    proof: &mut proof::Proof,
    base: &BaseProofParams,
) -> Result<(), String> {
    let tx_merkle_proof =
        build_tx_merkle_proof(&base.block_tx_hashes, base.tx_index)
            .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    proof.block_header = BlockHeader(base.block_header);
    proof.block_height = base.block_height;
    proof.anchor_tx = AnchorTx::from_bytes(&base.anchor_tx_bytes)
        .map_err(|e| e.to_string())?;
    proof.tx_merkle_proof = tx_merkle_proof;
    Ok(())
}
