// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Bitcoin block Merkle proof construction.

use bitcoin_hashes::{sha256d, Hash, HashEngine};

use tap_primitives::proof::TxMerkleProof;

/// Builds a Merkle proof that a transaction at `tx_index` is included
/// in a block with the given transaction hashes.
///
/// `tx_hashes` is the list of transaction hashes (txids) in the block,
/// in order. Each hash is 32 bytes in internal byte order.
pub fn build_tx_merkle_proof(
    tx_hashes: &[[u8; 32]],
    tx_index: usize,
) -> Option<TxMerkleProof> {
    if tx_hashes.is_empty() || tx_index >= tx_hashes.len() {
        return None;
    }

    // Single transaction — no proof needed.
    if tx_hashes.len() == 1 {
        return Some(TxMerkleProof {
            nodes: vec![],
            bits: vec![],
        });
    }

    let mut proof_nodes = Vec::new();
    let mut proof_bits = Vec::new();
    let mut level = tx_hashes.to_vec();
    let mut index = tx_index;

    while level.len() > 1 {
        // If odd number of items, duplicate the last.
        if level.len() % 2 != 0 {
            let last = *level.last().unwrap();
            level.push(last);
        }

        // Record the sibling.
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        proof_nodes.push(level[sibling_index]);
        proof_bits.push(index % 2 == 0); // true = we are on the left

        // Compute next level.
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut engine = sha256d::Hash::engine();
            engine.input(&pair[0]);
            engine.input(&pair[1]);
            next_level.push(sha256d::Hash::from_engine(engine).to_byte_array());
        }
        level = next_level;
        index /= 2;
    }

    Some(TxMerkleProof {
        nodes: proof_nodes,
        bits: proof_bits,
    })
}

/// Computes the Merkle root from a list of transaction hashes.
pub fn compute_merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    if tx_hashes.len() == 1 {
        return tx_hashes[0];
    }

    let mut level = tx_hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 != 0 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut engine = sha256d::Hash::engine();
            engine.input(&pair[0]);
            engine.input(&pair[1]);
            next.push(sha256d::Hash::from_engine(engine).to_byte_array());
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_tx_proof() {
        let tx_hash = [0xAA; 32];
        let proof = build_tx_merkle_proof(&[tx_hash], 0).unwrap();
        assert!(proof.nodes.is_empty());
        assert!(proof.verify(&tx_hash, &tx_hash));
    }

    #[test]
    fn test_two_tx_proof() {
        let tx0 = [0x01; 32];
        let tx1 = [0x02; 32];
        let root = compute_merkle_root(&[tx0, tx1]);

        // Proof for tx0.
        let proof0 = build_tx_merkle_proof(&[tx0, tx1], 0).unwrap();
        assert_eq!(proof0.nodes.len(), 1);
        assert!(proof0.verify(&tx0, &root));

        // Proof for tx1.
        let proof1 = build_tx_merkle_proof(&[tx0, tx1], 1).unwrap();
        assert!(proof1.verify(&tx1, &root));
    }

    #[test]
    fn test_four_tx_proof() {
        let txs: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&txs);

        for i in 0..4 {
            let proof = build_tx_merkle_proof(&txs, i).unwrap();
            assert!(
                proof.verify(&txs[i], &root),
                "proof failed for tx {}",
                i
            );
        }
    }

    #[test]
    fn test_odd_number_of_txs() {
        let txs: Vec<[u8; 32]> = (0..3u8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&txs);

        for i in 0..3 {
            let proof = build_tx_merkle_proof(&txs, i).unwrap();
            assert!(proof.verify(&txs[i], &root));
        }
    }

    #[test]
    fn test_invalid_index() {
        let txs = vec![[0xAA; 32]];
        assert!(build_tx_merkle_proof(&txs, 1).is_none());
        assert!(build_tx_merkle_proof(&[], 0).is_none());
    }
}
