// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Output allocations for asset transfers.

use tap_primitives::asset::{
    AssetId, AssetType, AssetVersion, OutPoint, PrevId, ScriptKey,
    SerializedKey,
};

/// Describes which asset to send and how to find the input UTXOs.
#[derive(Clone, Debug)]
pub struct FundingDescriptor {
    /// The asset to send.
    pub asset_id: AssetId,
    /// Amount to send.
    pub amount: u64,
    /// Optional group key (for grouped assets).
    pub group_key: Option<SerializedKey>,
}

/// A recipient output in a transfer.
#[derive(Clone, Debug)]
pub struct TransferOutput {
    /// Output index in the anchor transaction.
    pub output_index: u32,
    /// Amount allocated to this output.
    pub amount: u64,
    /// The recipient's script key.
    pub script_key: ScriptKey,
    /// Asset version for this output.
    pub asset_version: AssetVersion,
    /// Whether this output is interactive (direct coordination) or
    /// non-interactive (via TAP address).
    pub interactive: bool,
}

/// An input asset selected for spending.
#[derive(Clone, Debug)]
pub struct SelectedInput {
    /// The previous asset.
    pub prev_id: PrevId,
    /// The outpoint anchoring the previous asset.
    pub anchor_point: OutPoint,
    /// The asset amount available.
    pub amount: u64,
    /// The asset type.
    pub asset_type: AssetType,
    /// The script key controlling the input.
    pub script_key: ScriptKey,
}

/// The result of coin selection for a transfer.
#[derive(Clone, Debug)]
pub struct FundingResult {
    /// Selected inputs.
    pub inputs: Vec<SelectedInput>,
    /// Total input amount.
    pub total_input_amount: u64,
    /// Change amount (input - send amount).
    pub change_amount: u64,
}

/// Trait for selecting asset inputs for a transfer.
pub trait CoinSelector {
    /// Selects inputs sufficient to cover the funding descriptor.
    fn select_coins(
        &self,
        descriptor: &FundingDescriptor,
    ) -> Result<FundingResult, super::SendError>;
}

/// Validates that the outputs are consistent with the inputs.
pub fn validate_allocations(
    inputs: &[SelectedInput],
    outputs: &[TransferOutput],
    asset_type: AssetType,
) -> Result<(), super::SendError> {
    let input_sum: u64 = inputs.iter().map(|i| i.amount).sum();
    let output_sum: u64 = outputs.iter().map(|o| o.amount).sum();

    if output_sum > input_sum {
        return Err(super::SendError::InsufficientFunds {
            available: input_sum,
            needed: output_sum,
        });
    }

    // For collectibles, we need exactly 1 unit in and 1 unit out.
    if asset_type == AssetType::Collectible {
        if input_sum != 1 || output_sum != 1 {
            return Err(super::SendError::InvalidCollectibleTransfer);
        }
        if outputs.len() != 1 {
            return Err(super::SendError::InvalidCollectibleTransfer);
        }
    }

    // All outputs must have non-zero amounts (except tombstone roots, which
    // are handled at a higher level).
    for output in outputs {
        if output.amount == 0 {
            return Err(super::SendError::ZeroAmountOutput);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::{
        AssetType, AssetVersion, OutPoint, PrevId, ScriptKey, SerializedKey,
    };

    fn dummy_input(amount: u64) -> SelectedInput {
        SelectedInput {
            prev_id: PrevId::ZERO,
            anchor_point: OutPoint::default(),
            amount,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        }
    }

    fn dummy_output(amount: u64, index: u32) -> TransferOutput {
        TransferOutput {
            output_index: index,
            amount,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }
    }

    #[test]
    fn test_valid_allocation() {
        let inputs = vec![dummy_input(100)];
        let outputs = vec![dummy_output(60, 0), dummy_output(40, 1)];
        assert!(
            validate_allocations(&inputs, &outputs, AssetType::Normal).is_ok()
        );
    }

    #[test]
    fn test_insufficient_funds() {
        let inputs = vec![dummy_input(50)];
        let outputs = vec![dummy_output(60, 0)];
        assert!(matches!(
            validate_allocations(&inputs, &outputs, AssetType::Normal),
            Err(super::super::SendError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_valid_collectible_transfer() {
        let mut input = dummy_input(1);
        input.asset_type = AssetType::Collectible;
        let outputs = vec![dummy_output(1, 0)];
        assert!(validate_allocations(
            &[input],
            &outputs,
            AssetType::Collectible
        )
        .is_ok());
    }

    #[test]
    fn test_collectible_multiple_outputs_rejected() {
        let mut input = dummy_input(1);
        input.asset_type = AssetType::Collectible;
        let outputs = vec![dummy_output(1, 0), dummy_output(1, 1)];
        assert!(validate_allocations(
            &[input],
            &outputs,
            AssetType::Collectible
        )
        .is_err());
    }

    #[test]
    fn test_zero_amount_output_rejected() {
        let inputs = vec![dummy_input(100)];
        let outputs = vec![dummy_output(0, 0)];
        assert!(matches!(
            validate_allocations(&inputs, &outputs, AssetType::Normal),
            Err(super::super::SendError::ZeroAmountOutput)
        ));
    }
}
