// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Generates transition proofs from confirmed transactions.

use std::collections::BTreeMap;

use tap_primitives::asset::{
    Asset, Genesis, GroupKeyReveal, SerializedKey,
};
use tap_primitives::commitment::{CommitmentProof, TapCommitmentTree};
use tap_primitives::proof::{
    self, AnchorTx, BlockHeader, MetaReveal, TaprootProof, TransitionVersion,
};

use super::merkle::build_tx_merkle_proof;

/// Derives the inclusion [`CommitmentProof`] for `asset` from the
/// tree-holding TAP commitment of its anchor output, mirroring Go's
/// `TapCommitment.Proof` usage in `proof.CreateTransitionProof`.
pub(crate) fn derive_inclusion_proof(
    commitment: &TapCommitmentTree,
    asset: &Asset,
) -> Result<CommitmentProof, String> {
    let ack = tap_primitives::commitment::asset_commitment_key(
        &asset.genesis.id(),
        asset.script_key.serialized(),
        asset.group_key.is_some(),
    );
    let tck = tap_primitives::commitment::tap_commitment_key(
        &asset.genesis.id(),
        asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
    );

    let (committed, proof) =
        commitment.proof(&tck, &ack).map_err(|e| e.to_string())?;
    if committed.is_none() {
        return Err(
            "asset not committed to in the anchor output commitment".into(),
        );
    }
    Ok(proof)
}

/// Parameters for generating a genesis (minting) proof.
pub struct GenesisProofParams {
    /// The confirmed genesis transaction (raw serialized bytes).
    pub anchor_tx_bytes: Vec<u8>,
    /// The block header containing the transaction.
    pub block_header: [u8; 80],
    /// Block height.
    pub block_height: u32,
    /// Index of the genesis tx within the block.
    pub tx_index: usize,
    /// All transaction hashes in the block (for Merkle proof).
    pub block_tx_hashes: Vec<[u8; 32]>,
    /// The genesis outpoint (first input of the genesis tx).
    pub prev_out: tap_primitives::asset::OutPoint,
    /// The minted asset.
    pub asset: Asset,
    /// Output index containing the TAP commitment.
    pub tap_output_index: u32,
    /// Internal key for the TAP output.
    pub internal_key: SerializedKey,
    /// The tree-holding TAP commitment of the anchor output. When set,
    /// the inclusion proof is derived from it directly and
    /// `commitment_proof` may be left `None`.
    pub commitment: Option<TapCommitmentTree>,
    /// The commitment (inclusion) proof linking the minted asset to the
    /// anchor output's TAP commitment. Only needed when `commitment` is
    /// not supplied; required for the proof to pass full verification.
    pub commitment_proof: Option<CommitmentProof>,
    /// Exclusion proofs for the other P2TR outputs of the anchor tx.
    pub exclusion_proofs: Vec<TaprootProof>,
    /// The genesis reveal.
    pub genesis_reveal: Genesis,
    /// Optional metadata reveal.
    pub meta_reveal: Option<MetaReveal>,
    /// Optional group key reveal.
    pub group_key_reveal: Option<GroupKeyReveal>,
}

/// Generates a complete genesis (minting) proof.
///
/// This links a newly minted asset to its confirmed genesis transaction
/// and the Bitcoin block containing it.
pub fn generate_genesis_proof(
    params: GenesisProofParams,
) -> Result<proof::Proof, String> {
    // Build the transaction Merkle proof.
    let tx_merkle_proof = build_tx_merkle_proof(
        &params.block_tx_hashes,
        params.tx_index,
    )
    .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    // Build the inclusion proof, deriving the commitment proof from
    // the tree-holding commitment when one was not supplied directly.
    let commitment_proof = match (params.commitment_proof, &params.commitment)
    {
        (Some(proof), _) => Some(proof),
        (None, Some(commitment)) => {
            Some(derive_inclusion_proof(commitment, &params.asset)?)
        }
        (None, None) => None,
    };

    let inclusion_proof = TaprootProof {
        output_index: params.tap_output_index,
        internal_key: params.internal_key,
        commitment_proof,
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    };

    Ok(proof::Proof {
        version: TransitionVersion::V0,
        prev_out: params.prev_out,
        block_header: BlockHeader(params.block_header),
        block_height: params.block_height,
        anchor_tx: AnchorTx::from_bytes(&params.anchor_tx_bytes)
            .map_err(|e| e.to_string())?,
        tx_merkle_proof,
        asset: params.asset,
        inclusion_proof,
        exclusion_proofs: params.exclusion_proofs,
        split_root_proof: None,
        meta_reveal: params.meta_reveal,
        additional_inputs: vec![],
        challenge_witness: None,
        genesis_reveal: Some(params.genesis_reveal),
        group_key_reveal: params.group_key_reveal,
        alt_leaves: vec![],
        unknown_odd_types: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;

    #[test]
    fn test_generate_genesis_proof() {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-asset".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let asset = Asset::new_genesis(
            genesis.clone(),
            1000,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        let tx_hash = [0xAA; 32];

        // A minimal valid transaction (one default input, no
        // outputs).
        let anchor_tx_bytes =
            bitcoin::consensus::encode::serialize(&bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn::default()],
                output: vec![],
            });

        let params = GenesisProofParams {
            anchor_tx_bytes,
            block_header: [0u8; 80],
            block_height: 800_000,
            tx_index: 0,
            block_tx_hashes: vec![tx_hash],
            prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            asset,
            tap_output_index: 0,
            internal_key: SerializedKey([0x02; 33]),
            commitment: None,
            commitment_proof: None,
            exclusion_proofs: vec![],
            genesis_reveal: genesis,
            meta_reveal: None,
            group_key_reveal: None,
        };

        let proof = generate_genesis_proof(params).unwrap();
        assert_eq!(proof.version, TransitionVersion::V0);
        assert_eq!(proof.block_height, 800_000);
        assert!(proof.genesis_reveal.is_some());
        assert!(proof.asset.is_genesis_asset());
    }
}
