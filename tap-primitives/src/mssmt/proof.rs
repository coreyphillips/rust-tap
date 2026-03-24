// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Merkle proofs for the MS-SMT.
//!
//! A [`Proof`] contains 256 sibling nodes that, combined with a leaf and its
//! key, allow reconstructing the path from leaf to root. Proofs can be
//! [`compress`](Proof::compress)ed by replacing empty-tree nodes with a bit
//! flag, significantly reducing size for sparse trees.

use super::node::*;

/// An uncompressed Merkle proof consisting of 256 sibling nodes.
///
/// `nodes[0]` is the sibling at the deepest level (level 255),
/// `nodes[255]` is the sibling at the shallowest level (level 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub nodes: Vec<Node>,
}

impl Proof {
    /// Creates a new proof from exactly `MAX_TREE_LEVELS` sibling nodes.
    pub fn new(nodes: Vec<Node>) -> Self {
        assert_eq!(nodes.len(), MAX_TREE_LEVELS);
        Proof { nodes }
    }

    /// Reconstructs the root from this proof, the leaf, and its key.
    ///
    /// Walks from the leaf up to the root using the sibling nodes.
    pub fn root(&self, key: &[u8; HASH_SIZE], leaf: &Node) -> BranchNode {
        let mut current = leaf.clone();

        for i in (0..=LAST_BIT_INDEX).rev() {
            let sibling = &self.nodes[LAST_BIT_INDEX - i];
            let parent = if bit_index(i as u8, key) == 0 {
                BranchNode::new(current, sibling.clone())
            } else {
                BranchNode::new(sibling.clone(), current)
            };
            current = Node::Branch(parent);
        }

        match current {
            Node::Branch(b) => b,
            _ => unreachable!(),
        }
    }

    /// Compresses the proof by replacing empty-tree sibling nodes with bit
    /// flags.
    ///
    /// For each of the 256 sibling nodes, if the node matches the empty tree
    /// at the corresponding level, we set a bit to 1 and omit the node.
    /// Otherwise we include the node in the compressed list.
    pub fn compress(&self) -> CompressedProof {
        let empty = empty_tree();
        let mut bits = [false; MAX_TREE_LEVELS];
        let mut nodes = Vec::new();

        for (i, node) in self.nodes.iter().enumerate() {
            // The proof node at index `i` corresponds to the sibling at
            // level `MAX_TREE_LEVELS - i`. The empty tree node at that level
            // is `empty[MAX_TREE_LEVELS - i]`.
            let empty_level = MAX_TREE_LEVELS - i;
            if is_equal_node(node, &empty[empty_level]) {
                bits[i] = true;
            } else {
                nodes.push(ComputedNode::new(
                    node.node_hash(),
                    node.node_sum(),
                ));
            }
        }

        CompressedProof { bits, nodes }
    }
}

/// A compressed Merkle proof.
///
/// Empty-tree siblings are represented by a single bit (1 = empty), while
/// non-empty siblings are stored as `ComputedNode` (hash + sum).
#[derive(Clone, Debug)]
pub struct CompressedProof {
    pub bits: [bool; MAX_TREE_LEVELS],
    pub nodes: Vec<ComputedNode>,
}

impl CompressedProof {
    /// Decompresses back into a full [`Proof`].
    pub fn decompress(&self) -> Result<Proof, String> {
        let empty = empty_tree();
        let mut proof_nodes = Vec::with_capacity(MAX_TREE_LEVELS);
        let mut node_idx = 0;

        for i in 0..MAX_TREE_LEVELS {
            if self.bits[i] {
                let empty_level = MAX_TREE_LEVELS - i;
                proof_nodes.push(empty[empty_level].clone());
            } else {
                if node_idx >= self.nodes.len() {
                    return Err(format!(
                        "compressed proof has too few nodes: expected more at index {}",
                        i
                    ));
                }
                let cn = &self.nodes[node_idx];
                proof_nodes
                    .push(Node::Computed(ComputedNode::new(cn.hash, cn.sum)));
                node_idx += 1;
            }
        }

        if node_idx != self.nodes.len() {
            return Err(format!(
                "compressed proof has {} unused nodes",
                self.nodes.len() - node_idx
            ));
        }

        Ok(Proof::new(proof_nodes))
    }

    /// Encodes the compressed proof into bytes.
    ///
    /// Format: `[u16 num_nodes] [for each node: [32B hash][8B sum BE]] [32B packed bits]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Number of non-empty nodes (u16 big-endian).
        buf.extend_from_slice(&(self.nodes.len() as u16).to_be_bytes());

        // Each node: 32 bytes hash + 8 bytes sum.
        for node in &self.nodes {
            buf.extend_from_slice(node.hash.as_bytes());
            buf.extend_from_slice(&node.sum.to_be_bytes());
        }

        // Packed bit vector (256 bits = 32 bytes), LSB-first within each byte.
        buf.extend_from_slice(&pack_bits(&self.bits));

        buf
    }

    /// Decodes a compressed proof from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 {
            return Err("compressed proof too short".into());
        }

        let num_nodes =
            u16::from_be_bytes([data[0], data[1]]) as usize;

        let expected_len = 2 + num_nodes * 40 + 32;
        if data.len() < expected_len {
            return Err(format!(
                "compressed proof too short: expected {}, got {}",
                expected_len,
                data.len()
            ));
        }

        let mut nodes = Vec::with_capacity(num_nodes);
        let mut offset = 2;
        for _ in 0..num_nodes {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(&data[offset..offset + HASH_SIZE]);
            offset += HASH_SIZE;

            let sum = u64::from_be_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            );
            offset += 8;

            nodes.push(ComputedNode::new(NodeHash(hash), sum));
        }

        let bits = unpack_bits(&data[offset..offset + 32]);

        Ok(CompressedProof { bits, nodes })
    }
}

/// Packs 256 booleans into 32 bytes, LSB-first within each byte.
fn pack_bits(bits: &[bool; MAX_TREE_LEVELS]) -> [u8; 32] {
    let mut packed = [0u8; 32];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}

/// Unpacks 32 bytes into 256 booleans, LSB-first within each byte.
fn unpack_bits(packed: &[u8]) -> [bool; MAX_TREE_LEVELS] {
    let mut bits = [false; MAX_TREE_LEVELS];
    for i in 0..MAX_TREE_LEVELS {
        bits[i] = (packed[i / 8] >> (i % 8)) & 1 == 1;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mssmt::store::DefaultStore;
    use crate::mssmt::tree::FullTree;

    fn make_key(byte: u8) -> [u8; HASH_SIZE] {
        let mut key = [0u8; HASH_SIZE];
        key[0] = byte;
        key
    }

    #[test]
    fn test_proof_compress_decompress_roundtrip() {
        let mut tree = FullTree::new(DefaultStore::new());

        let key = make_key(0x42);
        let leaf = LeafNode::new(vec![1, 2, 3], 100);
        tree.insert(key, leaf.clone()).unwrap();

        let proof = tree.merkle_proof(key).unwrap();
        let compressed = proof.compress();
        let decompressed = compressed.decompress().unwrap();

        // Both proofs should produce the same root.
        let root1 = proof.root(&key, &Node::Leaf(leaf.clone()));
        let root2 = decompressed.root(&key, &Node::Leaf(leaf));
        assert_eq!(root1.node_hash(), root2.node_hash());
    }

    #[test]
    fn test_compressed_proof_encode_decode_roundtrip() {
        let mut tree = FullTree::new(DefaultStore::new());

        let key = make_key(0xAB);
        let leaf = LeafNode::new(vec![99], 42);
        tree.insert(key, leaf.clone()).unwrap();

        let proof = tree.merkle_proof(key).unwrap();
        let compressed = proof.compress();

        let encoded = compressed.encode();
        let decoded = CompressedProof::decode(&encoded).unwrap();

        // Verify decoded proof works.
        let root_original = compressed
            .decompress()
            .unwrap()
            .root(&key, &Node::Leaf(leaf.clone()));
        let root_decoded = decoded
            .decompress()
            .unwrap()
            .root(&key, &Node::Leaf(leaf));
        assert_eq!(root_original.node_hash(), root_decoded.node_hash());
    }

    #[test]
    fn test_empty_tree_proof_is_all_empty() {
        let tree = FullTree::new(DefaultStore::new());
        let key = make_key(0x00);
        let proof = tree.merkle_proof(key).unwrap();
        let compressed = proof.compress();

        // All bits should be set (all siblings are empty tree nodes).
        assert!(compressed.bits.iter().all(|&b| b));
        assert!(compressed.nodes.is_empty());
    }

    #[test]
    fn test_pack_unpack_bits_roundtrip() {
        let mut bits = [false; MAX_TREE_LEVELS];
        bits[0] = true;
        bits[7] = true;
        bits[8] = true;
        bits[255] = true;

        let packed = pack_bits(&bits);
        let unpacked = unpack_bits(&packed);
        assert_eq!(bits, unpacked);
    }
}
