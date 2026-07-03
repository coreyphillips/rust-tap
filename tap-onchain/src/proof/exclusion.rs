// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Exclusion proof generation for anchor transactions.
//!
//! When an asset transfer is anchored in a Bitcoin transaction that has
//! multiple P2TR outputs, the transition proof must include exclusion
//! proofs for all P2TR outputs that do NOT contain the asset. This proves
//! the asset was not committed to multiple outputs (no inflation).
//!
//! Mirrors Go's `addOtherOutputExclusionProofs` (tapsend/proof.go:470)
//! for outputs carrying other Taproot Asset commitments, and
//! `proof.AddExclusionProofs` (proof/taproot.go:634) for plain BIP-86
//! P2TR outputs.

use std::collections::BTreeMap;

use tap_primitives::asset::{Asset, SerializedKey};
use tap_primitives::commitment::{
    asset_commitment_key, tap_commitment_key, TapCommitmentTree,
    TapscriptPreimage,
};
use tap_primitives::proof::{TaprootProof, TapscriptProof};

/// Describes one P2TR output of the anchor transaction for exclusion
/// proof purposes.
pub struct AnchorOutputInfo<'a> {
    /// Index of the output in the anchor transaction.
    pub output_index: u32,
    /// The Taproot internal key of the output.
    pub internal_key: SerializedKey,
    /// The Taproot Asset commitment held by this output, or `None` for
    /// a plain BIP-86 P2TR output that carries no commitment at all.
    pub commitment: Option<&'a TapCommitmentTree>,
    /// The tapscript sibling preimage next to the commitment leaf, if
    /// any.
    pub tapscript_sibling: Option<TapscriptPreimage>,
}

/// Generates exclusion proofs for the given asset against all P2TR
/// outputs that do not contain it.
///
/// For each output in `other_outputs` (skipping
/// `inclusion_output_index`):
/// - Outputs holding a Taproot Asset commitment get a real
///   non-inclusion [`CommitmentProof`] derived from the output's
///   commitment tree (asset-level non-inclusion when the asset's tap
///   commitment key sub-tree exists, tap-level non-inclusion
///   otherwise), mirroring Go's `TapCommitment.Proof`.
/// - Plain BIP-86 P2TR outputs get a [`TapscriptProof`] with `bip86:
///   true`, mirroring Go's `proof.AddExclusionProofs`.
///
/// [`CommitmentProof`]: tap_primitives::commitment::CommitmentProof
pub fn generate_exclusion_proofs(
    asset: &Asset,
    inclusion_output_index: u32,
    other_outputs: &[AnchorOutputInfo<'_>],
) -> Result<Vec<TaprootProof>, String> {
    let ack = asset_commitment_key(
        &asset.genesis.id(),
        asset.script_key.serialized(),
        asset.group_key.is_some(),
    );
    let tck = tap_commitment_key(
        &asset.genesis.id(),
        asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
    );

    let mut proofs = Vec::new();

    for output in other_outputs {
        if output.output_index == inclusion_output_index {
            continue;
        }

        let proof = match output.commitment {
            Some(tap_tree) => {
                let (found, mut commitment_proof) = tap_tree
                    .proof(&tck, &ack)
                    .map_err(|e| e.to_string())?;
                if found.is_some() {
                    return Err(format!(
                        "asset is committed to in output {}; cannot \
                         create exclusion proof",
                        output.output_index
                    ));
                }
                commitment_proof.tap_sibling_preimage =
                    output.tapscript_sibling.clone();

                TaprootProof {
                    output_index: output.output_index,
                    internal_key: output.internal_key,
                    commitment_proof: Some(commitment_proof),
                    tapscript_proof: None,
                    unknown_odd_types: BTreeMap::new(),
                }
            }

            // No commitment at all: a BIP-86 tapscript proof shows the
            // output key commits to no script root.
            None => TaprootProof {
                output_index: output.output_index,
                internal_key: output.internal_key,
                commitment_proof: None,
                tapscript_proof: Some(TapscriptProof {
                    tap_preimage_1: None,
                    tap_preimage_2: None,
                    bip86: true,
                    unknown_odd_types: BTreeMap::new(),
                }),
                unknown_odd_types: BTreeMap::new(),
            },
        };

        proofs.push(proof);
    }

    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;
    use tap_primitives::commitment::{
        AssetCommitmentTree, TapCommitmentVersion,
    };

    fn test_asset(amount: u64, key_byte: u8) -> Asset {
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
        let script_key = ScriptKey::from_pub_key(SerializedKey([key_byte; 33]));
        Asset::new_genesis(genesis, amount, script_key)
    }

    fn tap_tree_for(asset: &Asset) -> TapCommitmentTree {
        let ac = AssetCommitmentTree::new(&[&asset]).unwrap();
        TapCommitmentTree::new(TapCommitmentVersion::V2, vec![ac]).unwrap()
    }

    #[test]
    fn skips_inclusion_output_and_marks_bip86() {
        let asset = test_asset(100, 0x02);
        let outputs = vec![
            AnchorOutputInfo {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment: None,
                tapscript_sibling: None,
            },
            AnchorOutputInfo {
                output_index: 1,
                internal_key: SerializedKey([0x03; 33]),
                commitment: None,
                tapscript_sibling: None,
            },
            AnchorOutputInfo {
                output_index: 2,
                internal_key: SerializedKey([0x04; 33]),
                commitment: None,
                tapscript_sibling: None,
            },
        ];

        // Output 1 is the inclusion output — skipped.
        let proofs = generate_exclusion_proofs(&asset, 1, &outputs).unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].output_index, 0);
        assert_eq!(proofs[1].output_index, 2);
        for p in &proofs {
            assert!(p.commitment_proof.is_none());
            assert!(p.tapscript_proof.as_ref().unwrap().bip86);
        }
    }

    #[test]
    fn commitment_output_gets_asset_exclusion_proof() {
        // The other output commits to a different asset (same asset ID,
        // different script key), so the asset-level sub-tree exists but
        // the asset itself is excluded.
        let target = test_asset(100, 0x02);
        let other = test_asset(40, 0x03);
        let tree = tap_tree_for(&other);

        let outputs = vec![AnchorOutputInfo {
            output_index: 0,
            internal_key: SerializedKey([0x02; 33]),
            commitment: Some(&tree),
            tapscript_sibling: None,
        }];

        let proofs = generate_exclusion_proofs(&target, 1, &outputs).unwrap();
        assert_eq!(proofs.len(), 1);
        let cp = proofs[0].commitment_proof.as_ref().unwrap();
        assert!(cp.asset_proof.is_some());

        // The derived (exclusion) root must match the other output's
        // commitment root.
        let ack = asset_commitment_key(
            &target.genesis.id(),
            target.script_key.serialized(),
            false,
        );
        let tck = tap_commitment_key(&target.genesis.id(), None);
        let derived = cp.derive_by_asset_exclusion(&ack, &tck).unwrap();
        assert_eq!(
            derived.node_hash(),
            tree.commitment().root_hash()
        );
    }

    #[test]
    fn included_asset_is_rejected() {
        let target = test_asset(100, 0x02);
        let tree = tap_tree_for(&target);

        let outputs = vec![AnchorOutputInfo {
            output_index: 0,
            internal_key: SerializedKey([0x02; 33]),
            commitment: Some(&tree),
            tapscript_sibling: None,
        }];

        assert!(generate_exclusion_proofs(&target, 1, &outputs).is_err());
    }
}
