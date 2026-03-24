// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tapscript tree construction and script-path spend support.
//!
//! Provides [`TapscriptTree`] for building BIP-341 tapscript trees and
//! computing merkle roots, control blocks, and script-path sighashes for
//! TAP virtual transactions.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::LeafVersion;
use bitcoin::{ScriptBuf, Transaction};

use super::virtual_tx::{input_prev_out, virtual_tx_with_input, VirtualTxError};
use crate::asset::Asset;

/// A single tapscript leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapscriptLeaf {
    /// The leaf version (0xC0 for tapscript v0).
    pub version: LeafVersion,
    /// The script bytes.
    pub script: ScriptBuf,
}

impl TapscriptLeaf {
    /// Creates a new tapscript leaf with the default leaf version (0xC0).
    pub fn new(script: ScriptBuf) -> Self {
        TapscriptLeaf {
            version: LeafVersion::TapScript,
            script,
        }
    }

    /// Computes the BIP-341 tagged leaf hash.
    ///
    /// `SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || leaf_version || compact_size(script) || script)`
    pub fn leaf_hash(&self) -> [u8; 32] {
        let tag_hash = sha256::Hash::hash(b"TapLeaf");
        let mut engine = sha256::HashEngine::default();
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine.input(&[self.version.to_consensus()]);
        // Compact size encoding of script length.
        let script_bytes = self.script.as_bytes();
        encode_compact_size(&mut engine, script_bytes.len());
        engine.input(script_bytes);
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

/// Encodes a compact size (Bitcoin varint) into a hash engine.
fn encode_compact_size(engine: &mut sha256::HashEngine, n: usize) {
    if n < 253 {
        engine.input(&[n as u8]);
    } else if n <= 0xFFFF {
        engine.input(&[253]);
        engine.input(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        engine.input(&[254]);
        engine.input(&(n as u32).to_le_bytes());
    } else {
        engine.input(&[255]);
        engine.input(&(n as u64).to_le_bytes());
    }
}

/// A tapscript tree with one or more leaves.
///
/// Currently supports single-leaf and two-leaf trees. For single-leaf
/// trees, the merkle root is the leaf hash. For two leaves, they are
/// combined as a BIP-341 branch.
#[derive(Clone, Debug)]
pub struct TapscriptTree {
    leaves: Vec<TapscriptLeaf>,
}

impl TapscriptTree {
    /// Creates a tree with a single leaf.
    pub fn single(leaf: TapscriptLeaf) -> Self {
        TapscriptTree {
            leaves: vec![leaf],
        }
    }

    /// Creates a tree with two leaves.
    pub fn two_leaves(a: TapscriptLeaf, b: TapscriptLeaf) -> Self {
        TapscriptTree {
            leaves: vec![a, b],
        }
    }

    /// Returns the leaves in this tree.
    pub fn leaves(&self) -> &[TapscriptLeaf] {
        &self.leaves
    }

    /// Computes the BIP-341 merkle root of the tree.
    pub fn merkle_root(&self) -> [u8; 32] {
        match self.leaves.len() {
            0 => [0u8; 32],
            1 => self.leaves[0].leaf_hash(),
            2 => {
                let h0 = self.leaves[0].leaf_hash();
                let h1 = self.leaves[1].leaf_hash();
                tap_branch_hash(&h0, &h1)
            }
            _ => {
                // For >2 leaves, build a balanced binary tree bottom-up.
                let mut hashes: Vec<[u8; 32]> =
                    self.leaves.iter().map(|l| l.leaf_hash()).collect();
                while hashes.len() > 1 {
                    let mut next = Vec::new();
                    for chunk in hashes.chunks(2) {
                        if chunk.len() == 2 {
                            next.push(tap_branch_hash(&chunk[0], &chunk[1]));
                        } else {
                            next.push(chunk[0]);
                        }
                    }
                    hashes = next;
                }
                hashes[0]
            }
        }
    }

    /// Builds a control block for spending via the given leaf.
    ///
    /// The control block contains:
    /// - 1 byte: `leaf_version | output_key_parity`
    /// - 32 bytes: internal key (x-only)
    /// - 32 bytes per level: merkle proof siblings
    ///
    /// Returns `None` if the leaf is not in the tree.
    pub fn control_block(
        &self,
        internal_key: &XOnlyPublicKey,
        leaf_index: usize,
        output_key_parity_even: bool,
    ) -> Option<Vec<u8>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let parity_bit: u8 = if output_key_parity_even { 0 } else { 1 };
        let first_byte =
            self.leaves[leaf_index].version.to_consensus() | parity_bit;

        let mut cb = Vec::with_capacity(33 + 32 * self.merkle_proof_len());
        cb.push(first_byte);
        cb.extend_from_slice(&internal_key.serialize());

        // For a two-leaf tree, the proof is the sibling's leaf hash.
        if self.leaves.len() == 2 {
            let sibling = 1 - leaf_index;
            cb.extend_from_slice(&self.leaves[sibling].leaf_hash());
        }
        // For a single-leaf tree, there's no merkle proof path.
        // For >2 leaves, build the proof path from the balanced tree.
        if self.leaves.len() > 2 {
            let proof = self.merkle_proof_path(leaf_index);
            for sibling in proof {
                cb.extend_from_slice(&sibling);
            }
        }

        Some(cb)
    }

    fn merkle_proof_len(&self) -> usize {
        match self.leaves.len() {
            0 | 1 => 0,
            2 => 1,
            n => {
                // Height of balanced binary tree.
                ((n as f64).log2().ceil()) as usize
            }
        }
    }

    fn merkle_proof_path(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        let mut hashes: Vec<[u8; 32]> =
            self.leaves.iter().map(|l| l.leaf_hash()).collect();
        let mut proof = Vec::new();
        let mut idx = leaf_index;

        while hashes.len() > 1 {
            let sibling = if idx % 2 == 0 {
                if idx + 1 < hashes.len() {
                    hashes[idx + 1]
                } else {
                    // Odd node, no sibling — promoted directly.
                    let mut next = Vec::new();
                    for chunk in hashes.chunks(2) {
                        if chunk.len() == 2 {
                            next.push(tap_branch_hash(&chunk[0], &chunk[1]));
                        } else {
                            next.push(chunk[0]);
                        }
                    }
                    idx /= 2;
                    hashes = next;
                    continue;
                }
            } else {
                hashes[idx - 1]
            };
            proof.push(sibling);

            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                if chunk.len() == 2 {
                    next.push(tap_branch_hash(&chunk[0], &chunk[1]));
                } else {
                    next.push(chunk[0]);
                }
            }
            idx /= 2;
            hashes = next;
        }

        proof
    }
}

/// Computes the BIP-341 `TapBranch` tagged hash of two children.
///
/// The lexicographically smaller hash goes first.
pub fn tap_branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapBranch");
    let mut engine = sha256::HashEngine::default();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());

    // Sort: smaller first.
    if a <= b {
        engine.input(a);
        engine.input(b);
    } else {
        engine.input(b);
        engine.input(a);
    }

    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Computes the BIP-342 taproot script-path sighash for a virtual transaction.
///
/// This is the equivalent of [`input_key_spend_sighash`](super::virtual_tx::input_key_spend_sighash)
/// but for script-path spends where a tapscript leaf is being executed.
pub fn input_script_spend_sighash(
    base_virtual_tx: &Transaction,
    input_asset: &Asset,
    new_asset: &Asset,
    idx: u32,
    leaf: &TapscriptLeaf,
    sig_hash_type: TapSighashType,
) -> Result<[u8; 32], VirtualTxError> {
    let tx = virtual_tx_with_input(
        base_virtual_tx,
        new_asset.lock_time,
        new_asset.relative_lock_time,
        idx,
        bitcoin::Witness::new(),
    );

    let prev_out = input_prev_out(input_asset)?;
    let prevouts = [prev_out];

    let leaf_hash = bitcoin::taproot::TapLeafHash::from_byte_array(
        leaf.leaf_hash(),
    );

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            sig_hash_type,
        )
        .map_err(|e| VirtualTxError::SighashError(e.to_string()))?;

    Ok(sighash.to_byte_array())
}

/// Returns true if the witness stack represents a script-path spend.
///
/// A script-path witness has at least 2 elements where the last element
/// is a valid control block (starts with a leaf version byte that has bit
/// 0xFE set, and length is `33 + 32*n`).
pub fn is_script_path_witness(witness: &[Vec<u8>]) -> bool {
    if witness.len() < 2 {
        return false;
    }

    let last = &witness[witness.len() - 1];
    if last.len() < 33 {
        return false;
    }

    // Control block: first byte is leaf_version | parity.
    // Leaf version has bit 0xFE mask. TapScript is 0xC0.
    let first_byte = last[0];
    let version = first_byte & 0xFE;
    // Known leaf version: 0xC0 (TapScript).
    if version != 0xC0 {
        return false;
    }

    // Remaining bytes: 32 (internal key) + 32*n (merkle path).
    let remaining = last.len() - 1;
    if remaining < 32 {
        return false;
    }
    (remaining - 32) % 32 == 0
}

/// Extracts the script and control block from a script-path witness.
///
/// The second-to-last element is the script, the last is the control block.
/// Returns `(script, control_block)`.
pub fn extract_script_path(
    witness: &[Vec<u8>],
) -> Option<(ScriptBuf, &[u8])> {
    if witness.len() < 2 {
        return None;
    }
    let control_block = &witness[witness.len() - 1];
    let script = &witness[witness.len() - 2];
    Some((ScriptBuf::from(script.clone()), control_block))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_deterministic() {
        let leaf = TapscriptLeaf::new(ScriptBuf::from(vec![0x51])); // OP_1
        let h1 = leaf.leaf_hash();
        let h2 = leaf.leaf_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_different_scripts_different_hashes() {
        let leaf1 = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let leaf2 = TapscriptLeaf::new(ScriptBuf::from(vec![0x52]));
        assert_ne!(leaf1.leaf_hash(), leaf2.leaf_hash());
    }

    #[test]
    fn test_single_leaf_tree_root() {
        let leaf = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let tree = TapscriptTree::single(leaf.clone());
        assert_eq!(tree.merkle_root(), leaf.leaf_hash());
    }

    #[test]
    fn test_two_leaf_tree_root_order_independent() {
        let a = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let b = TapscriptLeaf::new(ScriptBuf::from(vec![0x52]));

        let tree_ab = TapscriptTree::two_leaves(a.clone(), b.clone());
        let tree_ba = TapscriptTree::two_leaves(b.clone(), a.clone());

        // tap_branch_hash sorts internally, so both orders yield same root.
        assert_eq!(tree_ab.merkle_root(), tree_ba.merkle_root());
    }

    #[test]
    fn test_tap_branch_hash_symmetric() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_eq!(tap_branch_hash(&a, &b), tap_branch_hash(&b, &a));
    }

    #[test]
    fn test_control_block_single_leaf() {
        let leaf = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let tree = TapscriptTree::single(leaf);

        let internal_key = XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap();
        let cb = tree.control_block(&internal_key, 0, true).unwrap();

        // Single leaf: 1 byte version+parity + 32 bytes key = 33.
        assert_eq!(cb.len(), 33);
        assert_eq!(cb[0] & 0xFE, 0xC0); // TapScript version
    }

    #[test]
    fn test_control_block_two_leaves() {
        let a = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let b = TapscriptLeaf::new(ScriptBuf::from(vec![0x52]));
        let tree = TapscriptTree::two_leaves(a, b);

        let internal_key = XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap();
        let cb = tree.control_block(&internal_key, 0, true).unwrap();

        // Two leaves: 1 + 32 + 32 (sibling hash) = 65.
        assert_eq!(cb.len(), 65);
    }

    #[test]
    fn test_control_block_out_of_bounds() {
        let leaf = TapscriptLeaf::new(ScriptBuf::from(vec![0x51]));
        let tree = TapscriptTree::single(leaf);
        let internal_key = XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap();
        assert!(tree.control_block(&internal_key, 1, true).is_none());
    }

    #[test]
    fn test_is_script_path_witness_key_path() {
        // Key-path: single 64-byte signature.
        let witness = vec![vec![0u8; 64]];
        assert!(!is_script_path_witness(&witness));
    }

    #[test]
    fn test_is_script_path_witness_valid() {
        // Script-path: [sig, script, control_block].
        let mut control_block = vec![0xC0]; // version + even parity
        control_block.extend_from_slice(&[0x02; 32]); // internal key
        let witness = vec![
            vec![0u8; 64],                       // signature
            vec![0x51],                           // script (OP_TRUE)
            control_block,
        ];
        assert!(is_script_path_witness(&witness));
    }

    #[test]
    fn test_is_script_path_witness_with_merkle_path() {
        let mut control_block = vec![0xC1]; // version + odd parity
        control_block.extend_from_slice(&[0x02; 32]); // internal key
        control_block.extend_from_slice(&[0xAA; 32]); // one merkle sibling
        let witness = vec![
            vec![0u8; 64],
            vec![0x51],
            control_block,
        ];
        assert!(is_script_path_witness(&witness));
    }

    #[test]
    fn test_extract_script_path() {
        let script = vec![0x51, 0x52];
        let control_block = vec![0xC0; 33];
        let witness = vec![vec![0u8; 64], script.clone(), control_block.clone()];

        let (extracted_script, extracted_cb) =
            extract_script_path(&witness).unwrap();
        assert_eq!(extracted_script.as_bytes(), &script);
        assert_eq!(extracted_cb, &control_block);
    }

    #[test]
    fn test_script_spend_sighash() {
        use crate::asset::*;
        use crate::vm::InputSet;

        let genesis = Genesis {
            first_prev_out: crate::asset::OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        let prev_key = SerializedKey([0x02; 33]);
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
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: crate::asset::OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
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
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset.clone());

        let (base_tx, _, _) =
            super::super::virtual_tx::virtual_tx(&new_asset, &prev_assets)
                .unwrap();

        let leaf = TapscriptLeaf::new(ScriptBuf::from(vec![0x51])); // OP_TRUE

        // Script-path sighash should succeed.
        let sighash = input_script_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            &leaf,
            TapSighashType::Default,
        )
        .unwrap();

        assert_ne!(sighash, [0u8; 32]);

        // Should differ from key-path sighash.
        let key_sighash = super::super::virtual_tx::input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::Default,
        )
        .unwrap();

        assert_ne!(sighash, key_sighash);
    }
}
