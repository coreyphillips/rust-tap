// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Supply update events, mirroring Go's `universe/supplycommit`
//! `NewMintEvent`, `NewBurnEvent`, and `NewIgnoreEvent`
//! (states.go:140-410).
//!
//! These events are persisted and synced between nodes, so their
//! encodings match Go byte-for-byte:
//!
//! - `NewMintEvent.Encode` writes the raw issuance proof bytes
//!   (states.go:352); all other fields are re-derived on decode.
//! - `NewBurnEvent.Encode` writes the encoded burn proof
//!   (`universe.BurnLeaf.Encode`, interface.go:1348).
//! - `NewIgnoreEvent.Encode` writes the TLV-encoded
//!   `SignedIgnoreTuple` (ignore_records.go:263).

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::LeafNode;
use tap_primitives::proof::decode_proof;

use super::{SupplyError, SupplySubTree};
use crate::ignore::SignedIgnoreTuple;

/// The universe leaf key of a mint or burn supply leaf, mirroring Go's
/// `universe.AssetLeafKey` (interface.go:335): the anchor outpoint, the
/// asset's script key, and the asset ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyLeafKey {
    /// The outpoint at which the asset resides.
    pub outpoint: OutPoint,
    /// The script key of the asset.
    pub script_key: SerializedKey,
    /// The asset ID of the asset.
    pub asset_id: AssetId,
}

impl SupplyLeafKey {
    /// Returns the universe key, mirroring Go's
    /// `AssetLeafKey.UniverseKey` (interface.go:349):
    /// `sha256(wire_outpoint || schnorr_script_key || asset_id)`.
    pub fn universe_key(&self) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(&self.outpoint.txid);
        engine.input(&self.outpoint.vout.to_le_bytes());
        engine.input(self.script_key.schnorr_bytes());
        engine.input(self.asset_id.as_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

/// A new mint (issuance) supply update, mirroring Go's
/// `supplycommit.NewMintEvent` (states.go:285).
#[derive(Clone, Debug)]
pub struct NewMintEvent {
    /// The universe leaf key for the issuance.
    pub leaf_key: SupplyLeafKey,
    /// The raw encoded issuance proof. This is the canonical encoding
    /// of the event and the value of the mint sub-tree leaf.
    pub raw_proof: Vec<u8>,
    /// The amount minted.
    pub amount: u64,
    /// The height of the block containing the mint.
    pub block_height: u32,
}

impl NewMintEvent {
    /// Encodes the event, mirroring Go's `NewMintEvent.Encode`: the raw
    /// issuance proof bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.raw_proof.clone()
    }

    /// Decodes a mint event from raw issuance proof bytes, mirroring
    /// Go's `NewMintEvent.Decode` (states.go:359): the leaf key,
    /// amount, and height are re-derived from the decoded proof.
    pub fn decode(data: &[u8]) -> Result<Self, SupplyError> {
        let proof = decode_proof(data).map_err(|e| {
            SupplyError::Encoding(format!("decode mint event: {}", e))
        })?;

        Ok(NewMintEvent {
            leaf_key: SupplyLeafKey {
                outpoint: proof.out_point(),
                script_key: *proof.asset.script_key.serialized(),
                asset_id: proof.asset.id(),
            },
            raw_proof: data.to_vec(),
            amount: proof.asset.amount,
            block_height: proof.block_height,
        })
    }

    /// Returns the block height of the update.
    pub fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Returns the mint sub-tree leaf, mirroring Go's
    /// `universe.Leaf.SmtLeafNode` for a genesis asset: value = raw
    /// proof, sum = minted amount.
    pub fn universe_leaf_node(&self) -> LeafNode {
        LeafNode::new(self.raw_proof.clone(), self.amount)
    }
}

/// A burn leaf within the universe tree, mirroring Go's
/// `universe.BurnLeaf` (interface.go:1327).
#[derive(Clone, Debug)]
pub struct BurnLeaf {
    /// The universe leaf key of the burn.
    pub leaf_key: SupplyLeafKey,
    /// The raw encoded burn proof. This is the canonical encoding of
    /// the leaf and the value of the burn sub-tree leaf.
    pub raw_proof: Vec<u8>,
    /// The amount burned.
    pub amount: u64,
    /// The height of the block containing the burn.
    pub block_height: u32,
}

impl BurnLeaf {
    /// Encodes the burn leaf: the encoded burn proof (interface.go
    /// `BurnLeaf.Encode`).
    pub fn encode(&self) -> Vec<u8> {
        self.raw_proof.clone()
    }

    /// Decodes a burn leaf from encoded burn proof bytes
    /// (interface.go `BurnLeaf.Decode`).
    pub fn decode(data: &[u8]) -> Result<Self, SupplyError> {
        let proof = decode_proof(data).map_err(|e| {
            SupplyError::Encoding(format!("unable to decode burn proof: {}", e))
        })?;

        Ok(BurnLeaf {
            leaf_key: SupplyLeafKey {
                outpoint: proof.out_point(),
                script_key: *proof.asset.script_key.serialized(),
                asset_id: proof.asset.id(),
            },
            raw_proof: data.to_vec(),
            amount: proof.asset.amount,
            block_height: proof.block_height,
        })
    }

    /// Returns the burn sub-tree leaf, mirroring Go's
    /// `BurnLeaf.UniverseLeafNode`: value = encoded burn proof, sum =
    /// burned amount.
    pub fn universe_leaf_node(&self) -> LeafNode {
        LeafNode::new(self.raw_proof.clone(), self.amount)
    }
}

/// A new burn supply update, mirroring Go's `supplycommit.NewBurnEvent`
/// (states.go:212).
#[derive(Clone, Debug)]
pub struct NewBurnEvent {
    /// The burn leaf.
    pub burn_leaf: BurnLeaf,
}

impl NewBurnEvent {
    /// Encodes the event (states.go `NewBurnEvent.Encode`).
    pub fn encode(&self) -> Vec<u8> {
        self.burn_leaf.encode()
    }

    /// Decodes a burn event from encoded burn proof bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SupplyError> {
        Ok(NewBurnEvent {
            burn_leaf: BurnLeaf::decode(data)?,
        })
    }

    /// Returns the block height of the update.
    pub fn block_height(&self) -> u32 {
        self.burn_leaf.block_height
    }
}

/// A new ignore supply update, mirroring Go's
/// `supplycommit.NewIgnoreEvent` (states.go:140).
#[derive(Clone, Debug)]
pub struct NewIgnoreEvent {
    /// The signed ignore tuple.
    pub signed_tuple: SignedIgnoreTuple,
}

impl NewIgnoreEvent {
    /// Encodes the event (states.go `NewIgnoreEvent.Encode`): the TLV
    /// encoding of the signed ignore tuple.
    pub fn encode(&self) -> Vec<u8> {
        self.signed_tuple.encode()
    }

    /// Decodes an ignore event from TLV-encoded signed ignore tuple
    /// bytes.
    pub fn decode(data: &[u8]) -> Result<Self, SupplyError> {
        Ok(NewIgnoreEvent {
            signed_tuple: SignedIgnoreTuple::decode(data)
                .map_err(|e| SupplyError::Encoding(e.to_string()))?,
        })
    }

    /// Returns the block height of the update.
    pub fn block_height(&self) -> u32 {
        self.signed_tuple.tuple.block_height
    }
}

/// A supply update event, the Rust equivalent of Go's sealed
/// `supplycommit.SupplyUpdateEvent` interface (states.go:83).
#[derive(Clone, Debug)]
pub enum SupplyUpdateEvent {
    /// A new mint (issuance).
    Mint(NewMintEvent),
    /// A new burn.
    Burn(NewBurnEvent),
    /// A new ignore.
    Ignore(NewIgnoreEvent),
}

impl SupplyUpdateEvent {
    /// Returns the sub-tree this update affects (Go
    /// `SupplySubTreeType`).
    pub fn sub_tree_type(&self) -> SupplySubTree {
        match self {
            SupplyUpdateEvent::Mint(_) => SupplySubTree::Mint,
            SupplyUpdateEvent::Burn(_) => SupplySubTree::Burn,
            SupplyUpdateEvent::Ignore(_) => SupplySubTree::Ignore,
        }
    }

    /// Returns the leaf key to use when inserting this update into a
    /// supply sub-tree (Go `UniverseLeafKey`).
    pub fn universe_leaf_key(&self) -> [u8; 32] {
        match self {
            SupplyUpdateEvent::Mint(e) => e.leaf_key.universe_key(),
            SupplyUpdateEvent::Burn(e) => {
                e.burn_leaf.leaf_key.universe_key()
            }
            SupplyUpdateEvent::Ignore(e) => e.signed_tuple.universe_key(),
        }
    }

    /// Returns the leaf node to insert into the sub-tree (Go
    /// `UniverseLeafNode`).
    pub fn universe_leaf_node(&self) -> Result<LeafNode, SupplyError> {
        Ok(match self {
            SupplyUpdateEvent::Mint(e) => e.universe_leaf_node(),
            SupplyUpdateEvent::Burn(e) => e.burn_leaf.universe_leaf_node(),
            SupplyUpdateEvent::Ignore(e) => {
                e.signed_tuple.universe_leaf_node()
            }
        })
    }

    /// Returns the block height of the update (Go `BlockHeight`).
    pub fn block_height(&self) -> u32 {
        match self {
            SupplyUpdateEvent::Mint(e) => e.block_height(),
            SupplyUpdateEvent::Burn(e) => e.block_height(),
            SupplyUpdateEvent::Ignore(e) => e.block_height(),
        }
    }

    /// Encodes the event using the per-type Go encoding (Go `Encode`).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SupplyUpdateEvent::Mint(e) => e.encode(),
            SupplyUpdateEvent::Burn(e) => e.encode(),
            SupplyUpdateEvent::Ignore(e) => e.encode(),
        }
    }

    /// Decodes an event of the given sub-tree type from its per-type
    /// encoding.
    pub fn decode(
        tree_type: SupplySubTree,
        data: &[u8],
    ) -> Result<Self, SupplyError> {
        Ok(match tree_type {
            SupplySubTree::Mint => {
                SupplyUpdateEvent::Mint(NewMintEvent::decode(data)?)
            }
            SupplySubTree::Burn => {
                SupplyUpdateEvent::Burn(NewBurnEvent::decode(data)?)
            }
            SupplySubTree::Ignore => {
                SupplyUpdateEvent::Ignore(NewIgnoreEvent::decode(data)?)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ignore::{IgnoreSig, IgnoreTuple};
    use tap_primitives::asset::PrevId;

    fn test_ignore_event() -> NewIgnoreEvent {
        let tuple = IgnoreTuple {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0x11; 32],
                    vout: 3,
                },
                id: AssetId([0x22; 32]),
                script_key: SerializedKey({
                    // A valid generator-point key.
                    let mut k = [0u8; 33];
                    k[0] = 0x02;
                    k[1..].copy_from_slice(
                        &[
                            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
                        ],
                    );
                    k
                }),
            },
            amount: 42,
            block_height: 123,
        };
        NewIgnoreEvent {
            signed_tuple: SignedIgnoreTuple {
                tuple,
                sig: IgnoreSig([0x01; 64]),
            },
        }
    }

    #[test]
    fn test_ignore_event_round_trip() {
        let event = test_ignore_event();
        let encoded = event.encode();
        let decoded = NewIgnoreEvent::decode(&encoded).expect("decode");
        assert_eq!(event.signed_tuple, decoded.signed_tuple);

        let update = SupplyUpdateEvent::Ignore(event.clone());
        assert_eq!(update.sub_tree_type(), SupplySubTree::Ignore);
        assert_eq!(update.block_height(), 123);
        assert_eq!(
            update.universe_leaf_key(),
            event.signed_tuple.universe_key()
        );
        let leaf = update.universe_leaf_node().expect("leaf");
        assert_eq!(leaf.node_sum(), 42);
        assert_eq!(leaf.value, encoded);
    }

    /// Builds a minimal encodable genesis proof for round-trip tests.
    fn minimal_proof() -> tap_primitives::proof::Proof {
        use tap_primitives::asset::{
            Asset, AssetType, Genesis, ScriptKey,
        };
        use tap_primitives::proof::{
            AnchorTx, BlockHeader, Proof, TaprootProof, TransitionVersion,
            TxMerkleProof,
        };

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
            250,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            block_header: BlockHeader::default(),
            block_height: 777,
            anchor_tx: AnchorTx::default(),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset,
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                tapscript_proof: None,
                unknown_odd_types: std::collections::BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: Some(genesis),
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: std::collections::BTreeMap::new(),
        }
    }

    /// A mint event decodes its leaf key, amount, and height from the
    /// raw proof bytes, mirroring Go's `NewMintEvent.Decode`.
    #[test]
    fn test_mint_event_round_trip() {
        let proof = minimal_proof();
        let raw = tap_primitives::proof::encode_proof(&proof);

        let event = NewMintEvent::decode(&raw).expect("decode");
        assert_eq!(event.raw_proof, raw);
        assert_eq!(event.amount, 250);
        assert_eq!(event.block_height, 777);
        assert_eq!(event.leaf_key.asset_id, proof.asset.id());
        assert_eq!(
            event.leaf_key.script_key,
            *proof.asset.script_key.serialized()
        );
        assert_eq!(event.leaf_key.outpoint, proof.out_point());

        // Encode is the identity on the raw proof.
        assert_eq!(event.encode(), raw);

        // The sub-tree leaf commits to the raw proof with the minted
        // amount as sum.
        let leaf = event.universe_leaf_node();
        assert_eq!(leaf.value, raw);
        assert_eq!(leaf.node_sum(), 250);
    }

    /// A burn leaf decodes from encoded proof bytes.
    #[test]
    fn test_burn_leaf_round_trip() {
        let proof = minimal_proof();
        let raw = tap_primitives::proof::encode_proof(&proof);

        let leaf = BurnLeaf::decode(&raw).expect("decode");
        assert_eq!(leaf.raw_proof, raw);
        assert_eq!(leaf.amount, 250);
        assert_eq!(leaf.block_height, 777);
        assert_eq!(leaf.encode(), raw);

        let event = NewBurnEvent { burn_leaf: leaf };
        assert_eq!(event.block_height(), 777);
        let update = SupplyUpdateEvent::Burn(event);
        assert_eq!(update.sub_tree_type(), SupplySubTree::Burn);
        let node = update.universe_leaf_node().expect("leaf node");
        assert_eq!(node.node_sum(), 250);
    }

    #[test]
    fn test_supply_leaf_key_universe_key() {
        // key = sha256(outpoint || schnorr_script_key || asset_id)
        // with the outpoint in wire format (LE index).
        let key = SupplyLeafKey {
            outpoint: OutPoint {
                txid: [0xAB; 32],
                vout: 258,
            },
            script_key: SerializedKey([0x02; 33]),
            asset_id: AssetId([0xCD; 32]),
        };

        let mut engine = sha256::HashEngine::default();
        engine.input(&[0xAB; 32]);
        engine.input(&258u32.to_le_bytes());
        engine.input(&[0x02; 32]);
        engine.input(&[0xCD; 32]);
        let expected =
            sha256::Hash::from_engine(engine).to_byte_array();

        assert_eq!(key.universe_key(), expected);
    }
}
