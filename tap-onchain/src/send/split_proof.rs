// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Split commitment proof population for split transfers.
//!
//! After [`TransferBuilder::prepare_outputs`] creates split assets, this
//! module generates the MS-SMT inclusion proofs linking each split output
//! to the split commitment root, and populates the `split_commitment`
//! field on each split asset's witness.

use tap_primitives::asset::SplitCommitmentWitness;
use tap_primitives::commitment::{asset_leaf, SplitLocator};
use tap_primitives::encoding::asset::encode_asset;
use tap_primitives::asset::EncodeType;
use tap_primitives::mssmt;

use super::transfer::{PreparedTransfer, SendError};

/// Populates split commitment proofs on each recipient split asset.
///
/// Rebuilds the split tree exactly as it was committed to at
/// preparation time — the root leaf is the root asset *without* its
/// transaction witnesses and without the `split_commitment_root` field,
/// and each split leaf is the split asset without its split commitment
/// witness (mirroring Go's `NewSplitCommitment`, where the tree is
/// built before signing and never rebuilt). This makes the function
/// idempotent and safe to call after signing: the generated proofs
/// always verify against the `split_commitment_root` that was set
/// during preparation (and signed over).
///
/// Each recipient witness gets `prev_witnesses[0].split_commitment` set
/// with its proof and the encoded *current* (signed) root asset.
pub fn populate_split_proofs(
    prepared: &mut PreparedTransfer,
) -> Result<(), SendError> {
    if !prepared.is_split {
        return Ok(());
    }

    let asset_id = prepared.root_asset.genesis.id();

    // Build the split commitment tree from the preparation-time leaves.
    let mut tree = mssmt::FullTree::new(mssmt::DefaultStore::new());

    // Insert the root locator: the root asset as it was when the tree
    // was first built (unsigned, no split commitment root).
    let root_locator = SplitLocator {
        output_index: 0,
        asset_id,
        script_key: *prepared.root_asset.script_key.serialized(),
        amount: prepared.root_asset.amount,
    };
    let mut unsigned_root = prepared.root_asset.clone();
    unsigned_root.split_commitment_root = None;
    for witness in &mut unsigned_root.prev_witnesses {
        witness.tx_witness = vec![];
        witness.split_commitment = None;
    }
    let root_leaf = asset_leaf(&unsigned_root);
    tree.insert(root_locator.hash(), root_leaf)
        .map_err(|e| SendError::SplitError(e.to_string()))?;

    // Insert each split output, without its split commitment witness.
    for split in &prepared.recipient_assets {
        let locator = SplitLocator {
            output_index: split.output_index,
            asset_id,
            script_key: *split.asset.script_key.serialized(),
            amount: split.asset.amount,
        };
        let mut split_no_witness = split.asset.clone();
        if let Some(witness) = split_no_witness.prev_witnesses.first_mut() {
            witness.split_commitment = None;
        }
        let leaf = asset_leaf(&split_no_witness);
        tree.insert(locator.hash(), leaf)
            .map_err(|e| SendError::SplitError(e.to_string()))?;
    }

    // The rebuilt tree must match the split commitment root committed
    // to (and signed over) on the root asset.
    let tree_root = tree
        .root()
        .map_err(|e| SendError::SplitError(e.to_string()))?;
    match prepared.root_asset.split_commitment_root {
        Some((hash, sum)) => {
            if hash != tree_root.node_hash()
                || sum != tree_root.node_sum()
            {
                return Err(SendError::SplitError(
                    "rebuilt split tree does not match the committed \
                     split commitment root"
                        .into(),
                ));
            }
        }
        None => {
            return Err(SendError::SplitError(
                "root asset has no split commitment root".into(),
            ));
        }
    }

    // Encode the current (signed) root asset for inclusion in the split
    // commitment witnesses.
    let root_asset_bytes = encode_asset(&prepared.root_asset, EncodeType::Normal);

    // Generate a proof for each split output and set the witness.
    for split in &mut prepared.recipient_assets {
        let locator = SplitLocator {
            output_index: split.output_index,
            asset_id,
            script_key: *split.asset.script_key.serialized(),
            amount: split.asset.amount,
        };

        let proof = tree
            .merkle_proof(locator.hash())
            .map_err(|e| SendError::SplitError(format!("proof generation: {}", e)))?;

        // Set the split commitment on the first (and only) witness.
        if let Some(witness) = split.asset.prev_witnesses.first_mut() {
            witness.split_commitment = Some(SplitCommitmentWitness {
                proof,
                root_asset: root_asset_bytes.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;
    use tap_primitives::mssmt::verify_merkle_proof;

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
    fn test_populate_split_proofs() {
        let genesis = test_genesis();
        let inputs = vec![super::super::allocation::SelectedInput {
            prev_id: PrevId {
                out_point: OutPoint { txid: [0xAA; 32], vout: 0 },
                id: genesis.id(),
                script_key: SerializedKey([0x02; 33]),
            },
            anchor_point: OutPoint { txid: [0xAA; 32], vout: 0 },
            amount: 100,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        }];

        let outputs = vec![super::super::allocation::TransferOutput {
            output_index: 1,
            amount: 60,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }];

        let mut prepared = super::super::transfer::TransferBuilder::prepare_outputs(
            &inputs, &outputs, &genesis,
        )
        .unwrap();

        assert!(prepared.is_split);
        // Before: no split commitment on the split asset.
        assert!(prepared.recipient_assets[0]
            .asset
            .prev_witnesses[0]
            .split_commitment
            .is_none());

        populate_split_proofs(&mut prepared).unwrap();

        // After: split commitment is populated.
        let witness = &prepared.recipient_assets[0].asset.prev_witnesses[0];
        assert!(witness.split_commitment.is_some());

        let sc = witness.split_commitment.as_ref().unwrap();
        // Proof should be non-empty.
        assert!(!sc.proof.nodes.is_empty());
        // Root asset bytes should be non-empty.
        assert!(!sc.root_asset.is_empty());

        // The proof must verify against the split commitment root that
        // was committed to on the root asset — the same invariant the
        // VM checks (vm/mod.rs validate_split).
        let split = &prepared.recipient_assets[0];
        let locator = SplitLocator {
            output_index: split.output_index,
            asset_id: genesis.id(),
            script_key: *split.asset.script_key.serialized(),
            amount: split.asset.amount,
        };

        // Reconstruct the leaf as it was in the tree (without split commitment).
        let mut asset_without_sc = split.asset.clone();
        asset_without_sc.prev_witnesses[0].split_commitment = None;
        let leaf = asset_leaf(&asset_without_sc);

        let (root_hash, root_sum) =
            prepared.root_asset.split_commitment_root.unwrap();
        let root_node = mssmt::Node::Computed(mssmt::ComputedNode::new(
            root_hash, root_sum,
        ));

        assert!(verify_merkle_proof(
            locator.hash(),
            &leaf,
            &sc.proof,
            &root_node,
        ));
    }
}
