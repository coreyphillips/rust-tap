// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Burn transfer preparation.
//!
//! Mirrors the semantics of Go's `tapfreighter/wallet.go` `FundBurn`: a
//! burn is a transfer whose primary output pays to the provably
//! un-spendable burn key derived from the first input's `PrevId`, with
//! any change handled like a normal split.

use tap_primitives::asset::{
    derive_burn_key, AssetId, AssetVersion, Genesis, ScriptKey,
    SerializedKey,
};

use super::allocation::{SelectedInput, TransferOutput};
use super::transfer::{PreparedTransfer, SendError, TransferBuilder};

/// Parameters describing an asset burn.
#[derive(Clone, Debug)]
pub struct BurnParams {
    /// The asset to burn.
    pub asset_id: AssetId,
    /// Optional group key of the asset to burn.
    pub group_key: Option<SerializedKey>,
    /// Number of units to burn.
    pub amount: u64,
    /// Optional human readable note for the burn record.
    pub note: Option<String>,
}

/// Prepares a burn transfer from pre-selected inputs.
///
/// The burn output's script key is [`derive_burn_key`] of the FIRST
/// input's `PrevId` (matching Go's `FundBurn`, which uses the first
/// input of the funded packet). The output is an interactive, simple
/// output anchored at index 0; change is handled like a normal split.
pub fn prepare_burn(
    inputs: &[SelectedInput],
    params: &BurnParams,
    genesis: &Genesis,
) -> Result<PreparedTransfer, SendError> {
    if params.amount == 0 {
        return Err(SendError::BurnError(
            "burn amount must be greater than zero".into(),
        ));
    }

    if inputs.is_empty() {
        return Err(SendError::NoInputs);
    }

    let input_sum: u64 = inputs.iter().map(|i| i.amount).sum();
    if params.amount > input_sum {
        return Err(SendError::BurnError(format!(
            "burn amount {} exceeds total input amount {}",
            params.amount, input_sum
        )));
    }

    if params.asset_id != genesis.id() {
        return Err(SendError::BurnError(
            "burn asset ID does not match genesis".into(),
        ));
    }

    // The burn key commits to the first input's PrevId, making it unique
    // per burn and provably un-spendable.
    let burn_key = derive_burn_key(&inputs[0].prev_id);

    // The burn output is the interactive, simple (non-split-root) output.
    // Go anchors both the burn output and the change in the same anchor
    // output (index 0).
    let burn_output = TransferOutput {
        output_index: 0,
        amount: params.amount,
        script_key: ScriptKey::from_pub_key(burn_key),
        asset_version: AssetVersion::V0,
        interactive: true,
    };

    // Reuse the normal output preparation, bypassing the burn-key guard
    // that protects the regular send path. Burns always use V2 Taproot
    // Asset commitments, matching Go's FundBurn which selects and funds
    // with commitment.TapCommitmentV2 (tapfreighter/wallet.go).
    TransferBuilder::prepare_outputs_inner(
        inputs,
        &[burn_output],
        genesis,
        Some(tap_primitives::commitment::TapCommitmentVersion::V2),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::{
        AssetType, OutPoint, PrevId, SerializedKey,
    };

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "burn-token".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn test_input(amount: u64, vout: u32) -> SelectedInput {
        SelectedInput {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0xAA; 32],
                    vout,
                },
                id: test_genesis().id(),
                script_key: SerializedKey([0x02; 33]),
            },
            anchor_point: OutPoint {
                txid: [0xAA; 32],
                vout,
            },
            amount,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        }
    }

    fn test_params(amount: u64) -> BurnParams {
        BurnParams {
            asset_id: test_genesis().id(),
            group_key: None,
            amount,
            note: Some("test burn".into()),
        }
    }

    #[test]
    fn test_burn_output_uses_first_input_burn_key() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0), test_input(50, 1)];

        let prepared =
            prepare_burn(&inputs, &test_params(60), &genesis).unwrap();

        // Partial burn: split with one recipient (the burn output).
        assert!(prepared.is_split);
        assert_eq!(prepared.recipient_assets.len(), 1);

        let expected_key = derive_burn_key(&inputs[0].prev_id);
        assert_eq!(
            *prepared.recipient_assets[0].asset.script_key.serialized(),
            expected_key
        );
        assert_eq!(prepared.recipient_assets[0].asset.amount, 60);
    }

    #[test]
    fn test_burn_change_preserved() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        let prepared =
            prepare_burn(&inputs, &test_params(60), &genesis).unwrap();

        // Change goes back to the sender's script key.
        assert_eq!(prepared.root_asset.amount, 40);
        assert_eq!(
            prepared.root_asset.script_key,
            inputs[0].script_key
        );
        assert!(prepared.root_asset.split_commitment_root.is_some());
    }

    #[test]
    fn test_full_burn_no_split() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        let prepared =
            prepare_burn(&inputs, &test_params(100), &genesis).unwrap();

        assert!(!prepared.is_split);
        assert_eq!(prepared.root_asset.amount, 100);
        assert_eq!(
            *prepared.root_asset.script_key.serialized(),
            derive_burn_key(&inputs[0].prev_id)
        );
    }

    #[test]
    fn test_zero_amount_rejected() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        let result = prepare_burn(&inputs, &test_params(0), &genesis);
        assert!(matches!(result, Err(SendError::BurnError(_))));
    }

    #[test]
    fn test_over_amount_rejected() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        let result = prepare_burn(&inputs, &test_params(101), &genesis);
        assert!(matches!(result, Err(SendError::BurnError(_))));
    }

    #[test]
    fn test_no_inputs_rejected() {
        let genesis = test_genesis();
        let result = prepare_burn(&[], &test_params(10), &genesis);
        assert!(matches!(result, Err(SendError::NoInputs)));
    }

    #[test]
    fn test_wrong_asset_id_rejected() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];
        let mut params = test_params(10);
        params.asset_id = AssetId([0xFF; 32]);

        let result = prepare_burn(&inputs, &params, &genesis);
        assert!(matches!(result, Err(SendError::BurnError(_))));
    }

    #[test]
    fn test_normal_send_to_burn_key_rejected() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        // A normal transfer paying to the burn key of one of the inputs
        // must be rejected by the regular send path.
        let burn_key = derive_burn_key(&inputs[0].prev_id);
        let outputs = vec![TransferOutput {
            output_index: 1,
            amount: 60,
            script_key: ScriptKey::from_pub_key(burn_key),
            asset_version: AssetVersion::V0,
            interactive: true,
        }];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis);
        assert!(matches!(result, Err(SendError::BurnError(_))));
    }

    #[test]
    fn test_normal_send_to_regular_key_allowed() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100, 0)];

        let outputs = vec![TransferOutput {
            output_index: 1,
            amount: 60,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis);
        assert!(result.is_ok());
    }
}
