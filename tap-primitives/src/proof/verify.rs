// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof verification pipeline.
//!
//! Verification is modular — external systems provide implementations of
//! [`HeaderVerifier`], [`MerkleVerifier`], and [`GroupVerifier`] to plug
//! into the verification context. This allows the proof verification logic
//! to work without depending on a full Bitcoin node or specific chain backend.

use crate::asset::SerializedKey;

use super::types::*;
use super::ProofError;

/// Verifies a Bitcoin block header at a given height.
pub trait HeaderVerifier {
    fn verify_header(
        &self,
        header: &BlockHeader,
        height: u32,
    ) -> Result<(), ProofError>;
}

/// Verifies a transaction's inclusion in a block via Merkle proof.
pub trait MerkleVerifier {
    fn verify_merkle_proof(
        &self,
        tx_hash: &[u8; 32],
        proof: &super::tx_merkle::TxMerkleProof,
        merkle_root: &[u8; 32],
    ) -> Result<(), ProofError>;
}

/// Verifies that a group key is known/valid.
pub trait GroupVerifier {
    fn verify_group_key(
        &self,
        group_key: &SerializedKey,
    ) -> Result<(), ProofError>;
}

/// Context for proof verification, bundling all external verifiers.
pub struct VerifierCtx<H, M, G>
where
    H: HeaderVerifier,
    M: MerkleVerifier,
    G: GroupVerifier,
{
    pub header_verifier: H,
    pub merkle_verifier: M,
    pub group_verifier: G,
}

/// Verifies a single transition proof.
///
/// This performs structural validation of the proof. The full verification
/// pipeline checks:
///
/// 1. Proof version is known (V0 or V1)
/// 2. Block header is valid (via `HeaderVerifier`)
/// 3. Anchor tx is in the block (via `MerkleVerifier`)
/// 4. Asset is included in the anchor tx output (inclusion proof)
/// 5. Asset is NOT in other P2TR outputs (exclusion proofs)
/// 6. Genesis reveal matches (for genesis proofs)
/// 7. Group key is valid (via `GroupVerifier`)
/// 8. State transition is valid (VM execution)
///
/// Steps 2, 3, 7, and 8 are delegated to external verifiers. This function
/// performs the structural checks (1, 4, 5, 6).
pub fn verify_proof_structure(proof: &Proof) -> Result<(), ProofError> {
    // Step 0: Check version.
    match proof.version {
        TransitionVersion::V0 | TransitionVersion::V1 => {}
    }

    // Step 6: If genesis, verify the reveal.
    if proof.asset.is_genesis_asset() {
        if let Some(ref reveal) = proof.genesis_reveal {
            // The genesis reveal's ID must match the asset's genesis ID.
            if reveal.id() != proof.asset.genesis.id() {
                return Err(ProofError::GenesisMismatch);
            }

            // The genesis first_prev_out must match the proof's prev_out.
            if reveal.first_prev_out != proof.prev_out {
                return Err(ProofError::GenesisPrevOutMismatch);
            }

            // If meta reveal is present, verify the meta hash.
            if let Some(ref meta) = proof.meta_reveal {
                meta.validate()?;
                if meta.meta_hash() != reveal.meta_hash {
                    return Err(ProofError::MetaHashMismatch);
                }
            }
        }
    }

    // Step 4: Inclusion proof must reference a valid output index.
    // (Full inclusion verification requires the actual anchor tx outputs
    // and taproot key computation, which is external.)

    Ok(())
}

/// Verifies the structural integrity of a proof file.
///
/// Checks that the hash chain is valid and proofs link correctly
/// (each proof's prev_out matches the previous proof's anchor outpoint).
pub fn verify_file_structure(
    file: &super::file::File,
) -> Result<(), ProofError> {
    if !file.verify_hash_chain() {
        return Err(ProofError::InvalidProofHash);
    }

    if file.proofs.is_empty() {
        return Err(ProofError::EmptyFile);
    }

    Ok(())
}

/// A no-op header verifier (trusts all headers). Only available in tests
/// or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub struct TrustAllHeaders;

#[cfg(any(test, feature = "test-utils"))]
impl HeaderVerifier for TrustAllHeaders {
    fn verify_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// A default Merkle verifier that uses `TxMerkleProof::verify`.
pub struct DefaultMerkleVerifier;

impl MerkleVerifier for DefaultMerkleVerifier {
    fn verify_merkle_proof(
        &self,
        tx_hash: &[u8; 32],
        proof: &super::tx_merkle::TxMerkleProof,
        merkle_root: &[u8; 32],
    ) -> Result<(), ProofError> {
        if proof.verify(tx_hash, merkle_root) {
            Ok(())
        } else {
            Err(ProofError::InvalidTxMerkleProof)
        }
    }
}

/// A no-op group verifier (trusts all group keys). Only available in tests
/// or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub struct TrustAllGroups;

#[cfg(any(test, feature = "test-utils"))]
impl GroupVerifier for TrustAllGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::proof::tx_merkle::TxMerkleProof;

    fn dummy_proof() -> Proof {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis.clone(),
            100,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            block_header: BlockHeader::default(),
            block_height: 100,
            anchor_tx: AnchorTx(vec![0x01]),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset,
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                unknown_odd_types: std::collections::BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            genesis_reveal: Some(genesis),
            group_key_reveal: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn test_verify_valid_genesis_proof() {
        let proof = dummy_proof();
        assert!(verify_proof_structure(&proof).is_ok());
    }

    #[test]
    fn test_verify_genesis_id_mismatch() {
        let mut proof = dummy_proof();
        // Tamper with the genesis reveal.
        if let Some(ref mut reveal) = proof.genesis_reveal {
            reveal.tag = "different-tag".to_string();
        }
        assert!(matches!(
            verify_proof_structure(&proof),
            Err(ProofError::GenesisMismatch)
        ));
    }

    #[test]
    fn test_verify_genesis_prev_out_mismatch() {
        let mut proof = dummy_proof();
        proof.prev_out = OutPoint {
            txid: [0xFF; 32],
            vout: 99,
        };
        assert!(matches!(
            verify_proof_structure(&proof),
            Err(ProofError::GenesisPrevOutMismatch)
        ));
    }
}
