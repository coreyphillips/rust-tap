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

use tap_primitives::asset::{Asset, OutPoint, SerializedKey};
use tap_primitives::commitment::{
    asset_commitment_key, tap_commitment_key, TapCommitmentTree,
    TapscriptPreimage,
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

/// Creates the transition proof suffix for the asset output at
/// `out_index` within `asset_outputs`, mirroring Go's
/// `tapsend.CreateProofSuffix`:
///
/// - a real inclusion proof from the output's commitment tree,
/// - for split assets, a split root proof pointing at the root asset's
///   output (whose committed root asset must match the split witness),
/// - exclusion proofs for all other asset outputs (non-inclusion
///   commitment proofs) and all `bip86_outputs` (tapscript proofs).
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

    let inclusion_proof = TaprootProof {
        output_index: target.anchor_output_index,
        internal_key: target.internal_key,
        commitment_proof: Some(inclusion_commitment_proof),
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    };

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
    let exclusion_proofs = generate_exclusion_proofs(
        target.asset,
        target.anchor_output_index,
        &other_outputs,
    )?;

    // The chain data is not final yet: like Go's `newParams`, we embed
    // the anchor transaction in a pseudo block containing only that
    // transaction. Header and height are placeholders updated after
    // confirmation.
    let txid = *anchor_tx.compute_txid().as_ref();
    let tx_merkle_proof = build_tx_merkle_proof(&[txid], 0)
        .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    Ok(proof::Proof {
        version: TransitionVersion::V0,
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
        alt_leaves: vec![],
        unknown_odd_types: BTreeMap::new(),
    })
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
