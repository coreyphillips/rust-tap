// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Go-compatible universe MS-SMT construction.
//!
//! tapd stores each universe as a merkle-sum sparse merkle tree whose
//! root is exchanged during federation sync to decide whether two
//! universes are in sync (universe/interface.go):
//!
//! - key: `sha256(outpoint || schnorr(script_key))` with the outpoint
//!   in Bitcoin wire encoding (txid internal byte order, then 4-byte
//!   little-endian vout) and the script key x-only (32 bytes) -- Go's
//!   `BaseLeafKey.UniverseKey`.
//! - leaf: `LeafNode(raw_proof, amount)` where `amount` is the asset
//!   amount for genesis and burn proofs, and 1 for other transfer
//!   proofs (the transfer tree sums the NUMBER of transfers) -- Go's
//!   `Leaf.SmtLeafNode`.
//!
//! Discovered via live tapd interop: rust-tap's universe backends
//! previously hashed leaves with an ad-hoc scheme, so a root fetched
//! from tapd never matched the local root after a successful sync.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::mssmt::{DefaultStore, FullTree, LeafNode, NodeHash};
use tap_primitives::proof::decode_proof;

use crate::types::{LeafKey, ProofType, UniverseLeaf};

/// Computes the MS-SMT key for a universe leaf, mirroring Go's
/// `BaseLeafKey.UniverseKey`.
pub fn universe_smt_key(key: &LeafKey) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    // wire.WriteOutPoint: txid (internal byte order) || u32 LE vout.
    engine.input(&key.outpoint.txid);
    engine.input(&key.outpoint.vout.to_le_bytes());
    // schnorr.SerializePubKey: x-only, drop the parity byte.
    engine.input(&key.script_key.0[1..33]);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Builds the MS-SMT leaf node for a universe leaf, mirroring Go's
/// `Leaf.SmtLeafNode`: the value is the raw proof, the sum is the
/// asset amount for genesis assets and burns, and 1 for other
/// transfers (the transfer tree counts transfers).
pub fn universe_smt_leaf(
    proof_type: &ProofType,
    leaf: &UniverseLeaf,
) -> LeafNode {
    let mut amount = leaf.amount;

    // Issuance universes only hold genesis proofs, which always sum
    // the amount; skip the decode in that common case.
    if !matches!(proof_type, ProofType::Issuance) {
        let counts_amount = match decode_proof(&leaf.proof) {
            Ok(proof) => {
                proof.asset.is_genesis_asset() || proof.asset.is_burn()
            }
            // An undecodable proof cannot prove a genesis or burn;
            // treat it as a plain transfer like Go would never have
            // accepted in the first place.
            Err(_) => false,
        };
        if !counts_amount {
            amount = 1;
        }
    }

    LeafNode::new(leaf.proof.clone(), amount)
}

/// Computes the universe root (hash and sum) over the given leaves by
/// building the same MS-SMT tapd builds. An empty universe has the
/// empty-tree root hash `NodeHash::EMPTY` and sum 0 (matching the
/// previous rust-tap behavior for empty universes; tapd never serves
/// roots for empty universes).
pub fn compute_universe_root<'a>(
    proof_type: &ProofType,
    leaves: impl IntoIterator<Item = (&'a LeafKey, &'a UniverseLeaf)>,
) -> Result<(NodeHash, u64), String> {
    let mut tree = FullTree::new(DefaultStore::new());
    let mut empty = true;

    for (key, leaf) in leaves {
        empty = false;
        tree.insert(
            universe_smt_key(key),
            universe_smt_leaf(proof_type, leaf),
        )
        .map_err(|e| format!("universe smt insert: {:?}", e))?;
    }

    if empty {
        return Ok((NodeHash::EMPTY, 0));
    }

    let root = tree
        .root()
        .map_err(|e| format!("universe smt root: {:?}", e))?;
    Ok((root.node_hash(), root.node_sum()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

    fn test_key() -> LeafKey {
        let mut txid = [0u8; 32];
        for (i, b) in txid.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut script_key = [0u8; 33];
        script_key[0] = 0x02;
        for (i, b) in script_key[1..].iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        LeafKey {
            outpoint: OutPoint { txid, vout: 7 },
            script_key: SerializedKey(script_key),
        }
    }

    fn test_leaf(key: &LeafKey) -> UniverseLeaf {
        UniverseLeaf {
            asset_id: AssetId([9u8; 32]),
            amount: 5000,
            proof: vec![0xde, 0xad, 0xbe, 0xef],
            key: key.clone(),
        }
    }

    /// Pinned vector for Go's `BaseLeafKey.UniverseKey`:
    /// sha256(txid || vout_le || x_only_script_key), independently
    /// computed (python hashlib). The live Go-compat check for the
    /// whole tree is interop/test-c-universe-sync.sh, which matches a
    /// real tapd root byte for byte.
    #[test]
    fn universe_key_matches_go_construction() {
        let key = universe_smt_key(&test_key());
        let expect = "3b29e9fba253b9902182e6465e2a1ccffb\
                      2d29272eac79c006fbf496193dc760"
            .replace(char::is_whitespace, "");
        let got: String =
            key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(got, expect);
    }

    /// The parity byte of the script key must NOT contribute: Go
    /// serializes the schnorr (x-only) key.
    #[test]
    fn universe_key_ignores_script_key_parity() {
        let key = test_key();
        let mut odd = key.clone();
        odd.script_key.0[0] = 0x03;
        assert_eq!(universe_smt_key(&key), universe_smt_key(&odd));
    }

    /// Issuance leaves sum the asset amount; a transfer leaf whose
    /// proof does not decode to a genesis or burn asset sums 1 (the
    /// transfer tree counts transfers).
    #[test]
    fn leaf_sum_rules() {
        let key = test_key();
        let leaf = test_leaf(&key);
        let issuance =
            universe_smt_leaf(&ProofType::Issuance, &leaf);
        assert_eq!(issuance.sum, 5000);
        assert_eq!(issuance.value, leaf.proof);

        let transfer =
            universe_smt_leaf(&ProofType::Transfer, &leaf);
        assert_eq!(transfer.sum, 1);
    }

    /// Root computation is order independent and sums leaf amounts.
    #[test]
    fn root_is_order_independent() {
        let key_a = test_key();
        let mut key_b = test_key();
        key_b.outpoint.vout = 8;
        let leaf_a = test_leaf(&key_a);
        let mut leaf_b = test_leaf(&key_b);
        leaf_b.key = key_b.clone();
        leaf_b.amount = 11;
        leaf_b.proof = vec![0x01, 0x02];

        let fwd = compute_universe_root(
            &ProofType::Issuance,
            [(&key_a, &leaf_a), (&key_b, &leaf_b)],
        )
        .unwrap();
        let rev = compute_universe_root(
            &ProofType::Issuance,
            [(&key_b, &leaf_b), (&key_a, &leaf_a)],
        )
        .unwrap();
        assert_eq!(fwd, rev);
        assert_eq!(fwd.1, 5011);

        let empty = compute_universe_root(&ProofType::Issuance, [])
            .unwrap();
        assert_eq!(empty, (NodeHash::EMPTY, 0));
    }
}
