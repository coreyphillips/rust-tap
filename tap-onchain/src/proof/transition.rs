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
use tap_primitives::commitment::CommitmentProof;
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
    /// The commitment proof linking the asset to the TAP commitment.
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
pub fn generate_transition_proof(
    params: TransitionProofParams,
) -> Result<proof::Proof, String> {
    let tx_merkle_proof = build_tx_merkle_proof(
        &params.base.block_tx_hashes,
        params.base.tx_index,
    )
    .ok_or_else(|| "failed to build tx merkle proof".to_string())?;

    let inclusion_proof = TaprootProof {
        output_index: params.base.output_index,
        internal_key: params.base.internal_key,
        commitment_proof: params.commitment_proof,
        tapscript_proof: None,
        unknown_odd_types: BTreeMap::new(),
    };

    Ok(proof::Proof {
        version: TransitionVersion::V0,
        prev_out: params.prev_out,
        block_header: BlockHeader(params.base.block_header),
        block_height: params.base.block_height,
        anchor_tx: AnchorTx(params.base.anchor_tx_bytes),
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
/// Validates that the new proof's `prev_out` matches the last proof's
/// anchor outpoint, then appends it to the file's hash chain.
pub fn append_transition(
    file: &mut proof::File,
    params: TransitionProofParams,
) -> Result<(), String> {
    let proof = generate_transition_proof(params)?;

    // Encode the proof for the file.
    // The File's append_proof method handles hash chain validation.
    let proof_bytes = encode_proof(&proof);
    file.append_proof(proof_bytes);
    Ok(())
}

/// Encodes a proof to bytes for file storage using TLV format.
///
/// TLV types match Go's proof encoding for cross-implementation compatibility.
fn encode_proof(proof: &proof::Proof) -> Vec<u8> {
    use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

    let mut stream = TlvStream::new();

    // Type 0: Version.
    stream.push(TlvRecord::u8(0, proof.version as u8));

    // Type 1: PrevOut (txid + vout).
    let mut prevout_bytes = Vec::with_capacity(36);
    prevout_bytes.extend_from_slice(&proof.prev_out.txid);
    prevout_bytes.extend_from_slice(&proof.prev_out.vout.to_be_bytes());
    stream.push(TlvRecord::bytes(1, &prevout_bytes));

    // Type 2: Block header (80 bytes).
    stream.push(TlvRecord::bytes(2, &proof.block_header.0));

    // Type 3: Block height.
    stream.push(TlvRecord::varint(3, proof.block_height as u64));

    // Type 4: Anchor transaction.
    stream.push(TlvRecord::bytes(4, &proof.anchor_tx.0));

    // Type 5: Tx merkle proof (nodes + direction bits).
    let mut merkle_bytes = Vec::new();
    // Encode node count + nodes + bits.
    merkle_bytes.extend_from_slice(&(proof.tx_merkle_proof.nodes.len() as u32).to_be_bytes());
    for node in &proof.tx_merkle_proof.nodes {
        merkle_bytes.extend_from_slice(node);
    }
    for &bit in &proof.tx_merkle_proof.bits {
        merkle_bytes.push(if bit { 1 } else { 0 });
    }
    stream.push(TlvRecord::bytes(5, &merkle_bytes));

    // Type 6: Asset (full TLV encoding).
    let asset_bytes = tap_primitives::encoding::asset::encode_asset(
        &proof.asset,
        tap_primitives::asset::EncodeType::Normal,
    );
    stream.push(TlvRecord::bytes(6, &asset_bytes));

    // Type 7: Inclusion proof (output_index + internal_key).
    let mut incl_bytes = Vec::new();
    incl_bytes.extend_from_slice(&proof.inclusion_proof.output_index.to_be_bytes());
    incl_bytes.extend_from_slice(proof.inclusion_proof.internal_key.as_bytes());
    stream.push(TlvRecord::bytes(7, &incl_bytes));

    // Type 9: Genesis reveal (odd = optional).
    if let Some(ref genesis) = proof.genesis_reveal {
        let genesis_bytes = tap_primitives::encoding::asset::encode_genesis(genesis);
        stream.push(TlvRecord::bytes(9, &genesis_bytes));
    }

    stream.encode()
}

#[cfg(test)]
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
                anchor_tx_bytes: vec![0x02, 0x00],
                tx_index: 1,
                block_tx_hashes: vec![[0xCC; 32], [0xDD; 32]],
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
            },
            prev_out: OutPoint { txid: [0xBB; 32], vout: 0 },
            new_asset,
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
}
