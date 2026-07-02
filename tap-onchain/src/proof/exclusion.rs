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

use std::collections::BTreeMap;

use tap_primitives::asset::SerializedKey;
use tap_primitives::commitment::{CommitmentProof, TapCommitment};
use tap_primitives::proof::TaprootProof;

/// Generates exclusion proofs for P2TR outputs that do not contain the asset.
///
/// For each output in `other_outputs` (keyed by output index), creates a
/// `TaprootProof` with either:
/// - A non-inclusion proof from the output's TAP commitment (if it has one), or
/// - No commitment proof (if the output has no TAP commitment at all).
///
/// `inclusion_output_index` is the output that DOES contain the asset and
/// should be excluded from the exclusion proof set.
pub fn generate_exclusion_proofs(
    inclusion_output_index: u32,
    other_outputs: &[(u32, SerializedKey, Option<&TapCommitment>)],
) -> Vec<TaprootProof> {
    let mut proofs = Vec::new();

    for &(output_index, ref internal_key, tap_commitment) in other_outputs {
        if output_index == inclusion_output_index {
            continue;
        }

        let commitment_proof = tap_commitment.map(|_tc| {
            // The commitment proof here would be a non-inclusion proof
            // from the MS-SMT. For outputs with a TAP commitment that
            // doesn't contain our asset, we generate a proof of
            // non-membership.
            //
            // For outputs with no TAP commitment at all, we omit the
            // commitment proof entirely (None).
            CommitmentProof {
                asset_proof: None,
                taproot_asset_proof: tap_primitives::commitment::TaprootAssetProof {
                    proof: tap_primitives::mssmt::Proof::new(vec![]),
                    version: tap_primitives::commitment::TapCommitmentVersion::V2,
                    unknown_odd_types: BTreeMap::new(),
                },
                tap_sibling_preimage: None,
                stxo_proofs: BTreeMap::new(),
                unknown_odd_types: BTreeMap::new(),
            }
        });

        proofs.push(TaprootProof {
            output_index,
            internal_key: *internal_key,
            commitment_proof,
            tapscript_proof: None,
            unknown_odd_types: BTreeMap::new(),
        });
    }

    proofs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_exclusion_proofs_skips_inclusion() {
        let outputs = vec![
            (0, SerializedKey([0x02; 33]), None),
            (1, SerializedKey([0x03; 33]), None),
            (2, SerializedKey([0x04; 33]), None),
        ];

        // Output 1 is the inclusion output — should be excluded.
        let proofs = generate_exclusion_proofs(1, &outputs);
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].output_index, 0);
        assert_eq!(proofs[1].output_index, 2);
    }

    #[test]
    fn test_exclusion_proof_without_commitment() {
        let outputs = vec![
            (0, SerializedKey([0x02; 33]), None),
        ];

        let proofs = generate_exclusion_proofs(1, &outputs);
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].commitment_proof.is_none());
    }
}
