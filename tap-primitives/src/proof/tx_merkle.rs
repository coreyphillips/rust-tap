// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transaction Merkle proof — proves a transaction is included in a block.

use bitcoin_hashes::{sha256d, Hash, HashEngine};

/// Maximum number of nodes in a transaction Merkle proof.
///
/// `log2(max_txs_in_block) + 1 ≈ 15`
pub const MERKLE_PROOF_MAX_NODES: usize = 15;

/// A Merkle proof that a transaction is included in a Bitcoin block.
///
/// The proof contains sibling hashes at each level of the Merkle tree,
/// plus direction bits indicating whether the sibling is on the left or
/// right at each level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMerkleProof {
    /// Sibling hashes at each level (from leaf to root).
    pub nodes: Vec<[u8; 32]>,
    /// Direction bits: `true` = the sibling is on the right (our node is left).
    pub bits: Vec<bool>,
}

impl TxMerkleProof {
    /// Verifies that `tx_hash` is included in the Merkle tree with
    /// the given `merkle_root`.
    ///
    /// `tx_hash` should be the double-SHA256 hash of the serialized
    /// transaction (i.e., the txid in internal byte order).
    pub fn verify(
        &self,
        tx_hash: &[u8; 32],
        merkle_root: &[u8; 32],
    ) -> bool {
        if self.nodes.len() != self.bits.len() {
            return false;
        }

        let mut current = *tx_hash;

        for (sibling, &is_left) in self.nodes.iter().zip(self.bits.iter()) {
            let mut engine = sha256d::Hash::engine();
            if is_left {
                // We are on the left, sibling on the right.
                engine.input(&current);
                engine.input(sibling);
            } else {
                // Sibling on the left, we are on the right.
                engine.input(sibling);
                engine.input(&current);
            }
            current = sha256d::Hash::from_engine(engine).to_byte_array();
        }

        current == *merkle_root
    }

    /// Returns the number of levels in the proof.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the proof has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_proof_single_tx_block() {
        // In a block with a single transaction, the merkle root IS the txid.
        let tx_hash = [0xAA; 32];
        let proof = TxMerkleProof {
            nodes: vec![],
            bits: vec![],
        };
        assert!(proof.verify(&tx_hash, &tx_hash));
    }

    #[test]
    fn test_proof_wrong_root_fails() {
        let tx_hash = [0xAA; 32];
        let wrong_root = [0xBB; 32];
        let proof = TxMerkleProof {
            nodes: vec![],
            bits: vec![],
        };
        assert!(!proof.verify(&tx_hash, &wrong_root));
    }

    #[test]
    fn test_proof_one_level() {
        // Two-tx block: tx0 and tx1.
        let tx0 = [0x01; 32];
        let tx1 = [0x02; 32];

        // Merkle root = H(tx0 || tx1)
        let mut engine = sha256d::Hash::engine();
        engine.input(&tx0);
        engine.input(&tx1);
        let root = sha256d::Hash::from_engine(engine).to_byte_array();

        // Proof for tx0: sibling is tx1, tx0 is on the left.
        let proof = TxMerkleProof {
            nodes: vec![tx1],
            bits: vec![true],
        };
        assert!(proof.verify(&tx0, &root));

        // Proof for tx1: sibling is tx0, tx1 is on the right.
        let proof_tx1 = TxMerkleProof {
            nodes: vec![tx0],
            bits: vec![false],
        };
        assert!(proof_tx1.verify(&tx1, &root));
    }
}
