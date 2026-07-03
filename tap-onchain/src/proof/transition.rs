// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transition proof generation for asset transfers.
//!
//! After a transfer transaction is confirmed on chain, a transition proof
//! links the new asset state to the previous proof chain. This module
//! generates those proofs and appends them to proof files.

use std::collections::BTreeMap;

use tap_primitives::asset::{Asset, OutPoint, SerializedKey};
use tap_primitives::commitment::{CommitmentProof, TapCommitmentTree};
use tap_primitives::proof::{
    self, AnchorTx, BlockHeader, TaprootProof, TransitionVersion,
};

use super::merkle::build_tx_merkle_proof;

/// Parameters shared by genesis and transition proof generation.
pub struct BaseProofParams {
    /// The block header containing the anchor transaction.
    pub block_header: [u8; 80],
    /// Block height.
    pub block_height: u32,
    /// The confirmed anchor transaction (raw serialized bytes).
    pub anchor_tx_bytes: Vec<u8>,
    /// Index of the anchor tx within the block.
    pub tx_index: usize,
    /// All transaction hashes in the block (for Merkle proof).
    pub block_tx_hashes: Vec<[u8; 32]>,
    /// Output index containing this asset's TAP commitment.
    pub output_index: u32,
    /// Internal key for the TAP output.
    pub internal_key: SerializedKey,
}

/// Parameters specific to transition proof generation.
pub struct TransitionProofParams {
    /// Common proof parameters.
    pub base: BaseProofParams,
    /// The previous outpoint being spent (anchor of the input asset).
    pub prev_out: OutPoint,
    /// The new asset after the state transition.
    pub new_asset: Asset,
    /// The tree-holding TAP commitment of the anchor output. When set,
    /// the inclusion proof is derived from it directly and
    /// `commitment_proof` may be left `None`.
    pub commitment: Option<TapCommitmentTree>,
    /// The commitment proof linking the asset to the TAP commitment.
    /// Only needed when `commitment` is not supplied.
    pub commitment_proof: Option<CommitmentProof>,
    /// Exclusion proofs for other P2TR outputs in the anchor tx.
    pub exclusion_proofs: Vec<TaprootProof>,
    /// Split root proof, if this is a split transfer.
    pub split_root_proof: Option<TaprootProof>,
    /// Additional input proof files (for multi-input transfers).
    pub additional_inputs: Vec<proof::File>,
}

/// Generates a transition proof for a confirmed asset transfer.
///
/// This is the transfer equivalent of `generate_genesis_proof` — it links
/// the new asset state to a confirmed Bitcoin transaction and block.
#[deprecated(
    since = "0.1.0",
    note = "use the suffix API instead \
            (`create_proof_suffix`/`create_proof_suffix_with_options` + \
            `update_proof_chain_data`), which derives inclusion, \
            exclusion, split-root, and STXO proofs from the output \
            commitments like Go's tapsend.CreateProofSuffix"
)]
pub fn generate_transition_proof(
    params: TransitionProofParams,
) -> Result<proof::Proof, String> {
    let tx_merkle_proof = build_tx_merkle_proof(
        &params.base.block_tx_hashes,
        params.base.tx_index,
    )
    .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    // Derive the commitment proof from the tree-holding commitment
    // when one was not supplied directly.
    let commitment_proof = match (params.commitment_proof, &params.commitment)
    {
        (Some(proof), _) => Some(proof),
        (None, Some(commitment)) => Some(
            super::generate::derive_inclusion_proof(
                commitment,
                &params.new_asset,
            )?,
        ),
        (None, None) => None,
    };

    let inclusion_proof = TaprootProof {
        output_index: params.base.output_index,
        internal_key: params.base.internal_key,
        commitment_proof,
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    };

    Ok(proof::Proof {
        version: TransitionVersion::V0,
        prev_out: params.prev_out,
        block_header: BlockHeader(params.base.block_header),
        block_height: params.base.block_height,
        anchor_tx: AnchorTx::from_bytes(&params.base.anchor_tx_bytes)
            .map_err(|e| e.to_string())?,
        tx_merkle_proof,
        asset: params.new_asset,
        inclusion_proof,
        exclusion_proofs: params.exclusion_proofs,
        split_root_proof: params.split_root_proof,
        meta_reveal: None,
        additional_inputs: params.additional_inputs,
        challenge_witness: None,
        genesis_reveal: None,
        group_key_reveal: None,
        alt_leaves: vec![],
        unknown_odd_types: BTreeMap::new(),
    })
}

/// Appends a transition proof to an existing proof file.
///
/// The proof is encoded with the full proof encoder
/// ([`tap_primitives::proof::encode::encode_proof`]), so every field of
/// the generated proof (inclusion proof commitment data, exclusion
/// proofs, split root proof, alt leaves, ...) round-trips losslessly.
#[deprecated(
    since = "0.1.0",
    note = "use the suffix API instead \
            (`create_proof_suffix`/`create_proof_suffix_with_options` + \
            `update_proof_chain_data` + `File::append_proof`), which \
            derives complete proofs from the output commitments like \
            Go's tapsend.CreateProofSuffix"
)]
#[allow(deprecated)]
pub fn append_transition(
    file: &mut proof::File,
    params: TransitionProofParams,
) -> Result<(), String> {
    let proof = generate_transition_proof(params)?;

    // Encode with the complete proof encoder (the same one the suffix
    // API and tap-node use); an earlier local encoder here dropped the
    // commitment proof, exclusion proofs, split root proof, and alt
    // leaves, producing proofs that could never verify.
    let proof_bytes = tap_primitives::proof::encode::encode_proof(&proof);
    file.append_proof(proof_bytes);
    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint { txid: [0x01; 32], vout: 0 },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    #[test]
    fn test_generate_transition_proof() {
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_id = PrevId {
            out_point: OutPoint { txid: [0xBB; 32], vout: 0 },
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
                prev_id: Some(prev_id),
                tx_witness: vec![vec![0x01; 64]], // signed
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        };

        let params = TransitionProofParams {
            base: BaseProofParams {
                block_header: [0u8; 80],
                block_height: 800_001,
                // A minimal valid transaction (one default input,
                // no outputs).
                anchor_tx_bytes: bitcoin::consensus::encode::serialize(
                    &bitcoin::Transaction {
                        version: bitcoin::transaction::Version(2),
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: vec![bitcoin::TxIn::default()],
                        output: vec![],
                    },
                ),
                tx_index: 1,
                block_tx_hashes: vec![[0xCC; 32], [0xDD; 32]],
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
            },
            prev_out: OutPoint { txid: [0xBB; 32], vout: 0 },
            new_asset,
            commitment: None,
            commitment_proof: None,
            exclusion_proofs: vec![],
            split_root_proof: None,
            additional_inputs: vec![],
        };

        let proof = generate_transition_proof(params).unwrap();
        assert_eq!(proof.version, TransitionVersion::V0);
        assert_eq!(proof.block_height, 800_001);
        assert!(proof.genesis_reveal.is_none());
        assert!(!proof.asset.is_genesis_asset());
    }

    #[test]
    fn test_append_transition_is_lossless() {
        // append_transition must encode with the full proof encoder:
        // the appended bytes decode back to the exact generated proof
        // (an earlier local encoder dropped the commitment proof,
        // exclusion proofs, and more).
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_id = PrevId {
            out_point: OutPoint { txid: [0xBB; 32], vout: 0 },
            id: genesis.id(),
            script_key: prev_key,
        };

        // An on-curve script key (x = 0xAA repeated is a valid x
        // coordinate); decode now validates keys like Go.
        let mut new_key = [0xAA; 33];
        new_key[0] = 0x02;
        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id),
                tx_witness: vec![vec![0x01; 64]],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey(new_key)),
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        };

        // Build a commitment tree holding the asset so the generated
        // proof carries a real inclusion commitment proof.
        let ac = tap_primitives::commitment::AssetCommitmentTree::new(&[
            &new_asset,
        ])
        .unwrap();
        let tc = tap_primitives::commitment::TapCommitmentTree::new(
            tap_primitives::commitment::TapCommitmentVersion::V0,
            vec![ac],
        )
        .unwrap();

        let make_params = || TransitionProofParams {
            base: BaseProofParams {
                block_header: [0u8; 80],
                block_height: 800_001,
                anchor_tx_bytes: bitcoin::consensus::encode::serialize(
                    &bitcoin::Transaction {
                        version: bitcoin::transaction::Version(2),
                        lock_time: bitcoin::absolute::LockTime::ZERO,
                        input: vec![bitcoin::TxIn::default()],
                        output: vec![],
                    },
                ),
                tx_index: 1,
                block_tx_hashes: vec![[0xCC; 32], [0xDD; 32]],
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
            },
            prev_out: OutPoint { txid: [0xBB; 32], vout: 0 },
            new_asset: new_asset.clone(),
            commitment: Some(tc.clone()),
            commitment_proof: None,
            exclusion_proofs: vec![],
            split_root_proof: None,
            additional_inputs: vec![],
        };

        let expected = generate_transition_proof(make_params()).unwrap();
        assert!(
            expected.inclusion_proof.commitment_proof.is_some(),
            "test setup must produce a commitment proof"
        );

        let mut file = tap_primitives::proof::file::File::new();
        append_transition(&mut file, make_params()).unwrap();

        let appended = file.proofs.last().unwrap();
        let decoded = tap_primitives::proof::decode::decode_proof(
            &appended.proof_bytes,
        )
        .unwrap();

        // Byte-for-byte identical re-encoding proves nothing was lost.
        assert_eq!(
            tap_primitives::proof::encode::encode_proof(&decoded),
            tap_primitives::proof::encode::encode_proof(&expected),
        );
        assert!(decoded.inclusion_proof.commitment_proof.is_some());
    }
}
