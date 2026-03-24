// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Witness types for asset state transitions.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use super::genesis::{AssetId, OutPoint};
use super::types::SerializedKey;
use crate::mssmt;

/// A reference to a previous asset output being spent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrevId {
    /// The Bitcoin UTXO that anchored the previous asset.
    pub out_point: OutPoint,
    /// The asset ID.
    pub id: AssetId,
    /// The script key that controlled the previous asset.
    pub script_key: SerializedKey,
}

impl PrevId {
    /// The zero PrevId — used as sentinel for genesis witnesses.
    pub const ZERO: PrevId = PrevId {
        out_point: OutPoint {
            txid: [0u8; 32],
            vout: 0,
        },
        id: AssetId::ZERO,
        script_key: SerializedKey([0u8; 33]),
    };

    /// Computes the SHA-256 hash of this PrevId.
    ///
    /// Format: `SHA256(wire_outpoint || asset_id || schnorr_key)`
    pub fn hash(&self) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        // OutPoint in wire format.
        engine.input(&self.out_point.txid);
        engine.input(&self.out_point.vout.to_le_bytes());
        // Asset ID.
        engine.input(self.id.as_bytes());
        // Script key in x-only (Schnorr) form — bytes [1..33].
        engine.input(self.script_key.schnorr_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Returns true if this is the zero PrevId (genesis sentinel).
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Total serialized size: 36 (outpoint) + 32 (id) + 33 (key) = 101 bytes.
    pub const ENCODED_SIZE: usize = 36 + 32 + 33;
}

/// A witness proving a valid asset state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    /// Reference to the previous asset being spent. `None` should not normally
    /// occur — genesis assets use `PrevId::ZERO`.
    pub prev_id: Option<PrevId>,
    /// Bitcoin-style witness stack (signatures, scripts, etc.).
    /// Mutually exclusive with `split_commitment` for non-genesis assets.
    pub tx_witness: Vec<Vec<u8>>,
    /// Split commitment proof, present when this witness is for a split output.
    /// Mutually exclusive with `tx_witness` for split outputs.
    pub split_commitment: Option<SplitCommitmentWitness>,
}

impl Witness {
    /// Returns true if this is a genesis witness (zero PrevId, no witness data,
    /// no split commitment).
    pub fn is_genesis(&self) -> bool {
        matches!(&self.prev_id, Some(prev_id) if prev_id.is_zero())
            && self.tx_witness.is_empty()
            && self.split_commitment.is_none()
    }

    /// Returns true if this is a genesis witness for a grouped asset
    /// (zero PrevId with a non-empty witness stack).
    pub fn is_genesis_for_group(&self) -> bool {
        matches!(&self.prev_id, Some(prev_id) if prev_id.is_zero())
            && !self.tx_witness.is_empty()
            && self.split_commitment.is_none()
    }

    /// Returns true if this witness contains a split commitment.
    pub fn is_split_commitment(&self) -> bool {
        self.split_commitment.is_some()
    }
}

/// A split commitment witness — proves this output is part of a valid split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitCommitmentWitness {
    /// MS-SMT proof linking this split output to the split root.
    pub proof: mssmt::Proof,
    /// The root asset that contains the split commitment tree root.
    /// Stored as encoded bytes to avoid circular dependency with `Asset`.
    pub root_asset: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prev_id_hash_deterministic() {
        let prev_id = PrevId {
            out_point: OutPoint {
                txid: [0xAA; 32],
                vout: 1,
            },
            id: AssetId([0xBB; 32]),
            script_key: SerializedKey([0x02; 33]),
        };

        let h1 = prev_id.hash();
        let h2 = prev_id.hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_zero_prev_id() {
        assert!(PrevId::ZERO.is_zero());
        let non_zero = PrevId {
            out_point: OutPoint {
                txid: [1; 32],
                vout: 0,
            },
            id: AssetId::ZERO,
            script_key: SerializedKey([0; 33]),
        };
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_genesis_witness() {
        let w = Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![],
            split_commitment: None,
        };
        assert!(w.is_genesis());
        assert!(!w.is_genesis_for_group());
    }

    #[test]
    fn test_genesis_witness_for_group() {
        let w = Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![vec![0x01, 0x02]],
            split_commitment: None,
        };
        assert!(!w.is_genesis());
        assert!(w.is_genesis_for_group());
    }
}
