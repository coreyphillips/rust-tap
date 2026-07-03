// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transfer construction and state machine.


use tap_primitives::asset::{
    collect_stxo, derive_burn_key, Asset, AssetVersion, Genesis, PrevId,
    ScriptKey, ScriptVersion, Witness, NUMS_KEY,
};
use tap_primitives::commitment::{
    asset_leaf, AssetCommitmentTree, SplitAsset, SplitLocator,
    TapCommitmentTree, TapCommitmentVersion,
};
use tap_primitives::mssmt;

use super::allocation::{SelectedInput, TransferOutput};
use crate::chain::ChainError;

/// Errors from the transfer pipeline.
#[derive(Debug, Clone)]
pub enum SendError {
    /// Not enough asset balance.
    InsufficientFunds { available: u64, needed: u64 },
    /// Collectible transfer validation failed.
    InvalidCollectibleTransfer,
    /// Zero-amount output (not a tombstone).
    ZeroAmountOutput,
    /// No outputs specified.
    NoOutputs,
    /// No inputs available.
    NoInputs,
    /// Chain error.
    Chain(ChainError),
    /// Commitment error.
    CommitmentError(String),
    /// Split commitment error.
    SplitError(String),
    /// Invalid state transition.
    InvalidState(String),
    /// Burn preparation or validation error.
    BurnError(String),
    /// The signer does not know the key behind an input's script key
    /// (no stored key descriptor for it).
    UnknownScriptKey(tap_primitives::asset::SerializedKey),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::InsufficientFunds {
                available,
                needed,
            } => write!(
                f,
                "insufficient funds: available={}, needed={}",
                available, needed
            ),
            SendError::InvalidCollectibleTransfer => {
                write!(f, "invalid collectible transfer")
            }
            SendError::ZeroAmountOutput => {
                write!(f, "zero-amount output")
            }
            SendError::NoOutputs => write!(f, "no outputs specified"),
            SendError::NoInputs => write!(f, "no inputs available"),
            SendError::Chain(e) => write!(f, "chain error: {}", e),
            SendError::CommitmentError(msg) => {
                write!(f, "commitment error: {}", msg)
            }
            SendError::SplitError(msg) => {
                write!(f, "split error: {}", msg)
            }
            SendError::InvalidState(msg) => {
                write!(f, "invalid state: {}", msg)
            }
            SendError::BurnError(msg) => {
                write!(f, "burn error: {}", msg)
            }
            SendError::UnknownScriptKey(key) => {
                write!(
                    f,
                    "unknown script key: no key descriptor stored for {:02x?}",
                    &key.0[..4]
                )
            }
        }
    }
}

impl std::error::Error for SendError {}

impl From<ChainError> for SendError {
    fn from(e: ChainError) -> Self {
        SendError::Chain(e)
    }
}

/// State of a transfer in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SendState {
    /// Select inputs (coin selection).
    VirtualCommitmentSelect = 0,
    /// Sign virtual transactions.
    VirtualSign = 1,
    /// Create and fund anchor PSBT.
    AnchorSign = 2,
    /// Verify before broadcast.
    VerifyPreBroadcast = 3,
    /// Store state to database.
    StorePreBroadcast = 4,
    /// Broadcast anchor transaction.
    Broadcast = 5,
    /// Wait for confirmation.
    WaitForConfirmation = 6,
    /// Store confirmation info.
    StorePostConfirmation = 7,
    /// Transfer proofs to receiver.
    TransferProofs = 8,
    /// Terminal state.
    Complete = 9,
}

/// The result of preparing outputs — the assets and commitments ready
/// for anchoring in a Bitcoin transaction.
///
/// The commitments retain their MS-SMT trees ([`TapCommitmentTree`]) so
/// inclusion and exclusion proofs can be derived after the anchor
/// transaction is built, without hand-assembling proof parts.
#[derive(Clone, Debug)]
pub struct PreparedTransfer {
    /// The root asset for the change/tombstone output.
    pub root_asset: Asset,
    /// Recipient outputs (each becomes a split asset).
    pub recipient_assets: Vec<SplitAsset>,
    /// The TAP commitment for the change output.
    pub change_commitment: TapCommitmentTree,
    /// Per-output TAP commitments for recipient outputs.
    pub output_commitments: Vec<TapCommitmentTree>,
    /// Whether a split was required (partial send).
    pub is_split: bool,
    /// Passive assets re-anchored into the change output alongside the
    /// sender's change/tombstone asset (Go's passive assets). Each is a
    /// fully signed full-value 1-in-1-out transition of an asset that
    /// shared an anchor UTXO with a spent input but was not itself
    /// selected. Empty for a plain transfer. Merged into
    /// [`Self::change_commitment`] by
    /// [`Self::rebuild_root_commitment_with_options`].
    pub passive_assets: Vec<Asset>,
}

impl PreparedTransfer {
    /// Rebuilds the change output commitment from the current root
    /// asset. Must be called after signing: the root asset's leaf
    /// changes once its witnesses are populated, so the commitment
    /// created at preparation time no longer matches. For full-value
    /// sends the single output commitment is refreshed as well.
    ///
    /// STXO alt leaves for the spent inputs are merged into the
    /// commitment, mirroring Go's default behavior in
    /// `tapsend.CreateOutputCommitments`. Use
    /// [`Self::rebuild_root_commitment_with_options`] to opt out (Go's
    /// `tapsend.WithNoSTXOProofs`, used for asset channels).
    pub fn rebuild_root_commitment(&mut self) -> Result<(), SendError> {
        self.rebuild_root_commitment_with_options(false)
    }

    /// Rebuilds the change output commitment, optionally skipping the
    /// STXO alt leaf merge (`no_stxo_proofs`, mirroring Go's
    /// `tapsend.WithNoSTXOProofs`).
    ///
    /// When STXO proofs are enabled and the root asset is a transfer
    /// root, the spent inputs are collected into minimal spent-asset
    /// markers ([`tap_primitives::asset::collect_stxo`]) and merged
    /// into the commitment at `EMPTY_GENESIS_ID` BEFORE the anchor
    /// output script is computed, mirroring Go's
    /// `tapsend.CreateOutputCommitments` (tapsend/send.go:1038).
    pub fn rebuild_root_commitment_with_options(
        &mut self,
        no_stxo_proofs: bool,
    ) -> Result<(), SendError> {
        let version = self.change_commitment.commitment().version;
        let ac = AssetCommitmentTree::new(&[&self.root_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let mut tc = TapCommitmentTree::new(version, vec![ac])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        // Merge the STXO spent-asset markers into the commitment of
        // the output carrying the transfer root asset. Genesis assets
        // and split leaves produce no markers.
        if !no_stxo_proofs {
            let mut stxo_leaves = collect_stxo(&self.root_asset)
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            // Each re-anchored passive asset is itself a transfer root,
            // so its own spent-asset markers must be committed to in the
            // change output for its STXO inclusion proofs to verify
            // (Go commits every output asset's STXO leaves together).
            for passive in &self.passive_assets {
                let passive_stxo = collect_stxo(passive)
                    .map_err(|e| SendError::CommitmentError(e.to_string()))?;
                stxo_leaves.extend(passive_stxo);
            }
            tc.merge_alt_leaves(&stxo_leaves)
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        }

        // Merge each re-anchored passive asset (its own asset id, hence
        // its own asset commitment sub-tree) into the change output's
        // commitment, mirroring Go's `commitPacket`, which merges the
        // passive packets' commitments into the change output's
        // TapCommitment (tapsend/send.go).
        for passive in &self.passive_assets {
            let pac = AssetCommitmentTree::new(&[passive])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            tc.upsert(pac)
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        }

        if !self.is_split {
            // Full send: the transfer asset itself is the root asset. Its
            // recipient (single) output commitment must carry ONLY the
            // recipient asset (plus its STXO markers), never the passive
            // assets — those stay at the sender's change output. Rebuild
            // it from the root asset alone.
            let recipient_ac = AssetCommitmentTree::new(&[&self.root_asset])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            let mut recipient_tc = TapCommitmentTree::new(
                version,
                vec![recipient_ac],
            )
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            if !no_stxo_proofs {
                let stxo_leaves = collect_stxo(&self.root_asset)
                    .map_err(|e| SendError::CommitmentError(e.to_string()))?;
                recipient_tc
                    .merge_alt_leaves(&stxo_leaves)
                    .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            }
            if let Some(first) = self.output_commitments.first_mut() {
                *first = recipient_tc;
            }
        }
        self.change_commitment = tc;
        Ok(())
    }
}

/// Returns the "spend template" copy of a split root asset used as the
/// root locator leaf of the split MS-SMT tree: the root asset with its
/// witnesses replaced by a single zero-`PrevID`, witnessless witness and
/// no split commitment root. Mirrors the leaf Go's
/// `commitment.NewSplitCommitment` inserts for the root locator (built
/// from `CopySpendTemplate`), which is distinct from the returned
/// `RootAsset` that carries the real input `PrevID`s.
///
/// Used by both [`TransferBuilder::prepare_split_outputs`] (when the
/// tree is first built) and
/// [`crate::send::split_proof::populate_split_proofs`] (when the tree is
/// rebuilt to derive the split proofs) so both derive the identical
/// `split_commitment_root`.
pub(crate) fn root_spend_template(root_asset: &Asset) -> Asset {
    let mut template = root_asset.clone();
    template.split_commitment_root = None;
    template.prev_witnesses = vec![Witness {
        prev_id: Some(PrevId::ZERO),
        tx_witness: vec![],
        split_commitment: None,
    }];
    template
}

/// Builds asset transfers from inputs and output allocations.
pub struct TransferBuilder;

impl TransferBuilder {
    /// Prepares output assets for a transfer.
    ///
    /// Handles two cases:
    /// 1. **Full send** (input amount == output amount): direct transfer,
    ///    no split commitment needed.
    /// 2. **Partial send** (input amount > output amount): creates a split
    ///    commitment with a tombstone root and recipient splits.
    pub fn prepare_outputs(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
    ) -> Result<PreparedTransfer, SendError> {
        Self::prepare_outputs_with_version(inputs, outputs, genesis, None)
    }

    /// Prepares output assets for a transfer with an explicit commitment
    /// version.
    ///
    /// The commitment version comes from the destination: V1 and V2
    /// addresses (and V1 virtual packets) require V2 Taproot Asset
    /// commitments, while `None` derives the version from the asset
    /// versions like Go's `NewTapCommitment` (see
    /// `TapAddress::commitment_version` and Go tappsbt
    /// `CommitmentVersion`).
    pub fn prepare_outputs_with_version(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        Self::prepare_outputs_forced(
            inputs,
            outputs,
            genesis,
            commitment_version,
            false,
        )
    }

    /// Prepares output assets with the burn-key guard and an explicit
    /// `force_split` flag. When `force_split` is set, a split (with a
    /// zero-amount tombstone root when there is no change) is produced
    /// even for a full-value single-recipient send, so the sender still
    /// owns a change output to re-anchor passive assets into.
    pub fn prepare_outputs_forced(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
        force_split: bool,
    ) -> Result<PreparedTransfer, SendError> {
        // Burn keys can only be funded through `prepare_burn`; a normal
        // transfer must never pay to a key that provably burns the assets.
        // Mirrors Go, which only derives burn script keys inside FundBurn.
        for output in outputs {
            let is_burn = inputs.iter().any(|input| {
                output.script_key.serialized().schnorr_bytes()
                    == derive_burn_key(&input.prev_id).schnorr_bytes()
            });
            if is_burn {
                return Err(SendError::BurnError(
                    "cannot send to a burn key; use prepare_burn instead"
                        .into(),
                ));
            }
        }

        Self::prepare_outputs_inner(
            inputs,
            outputs,
            genesis,
            commitment_version,
            force_split,
        )
    }

    /// Prepares output assets without the burn-key guard. Used by both
    /// [`Self::prepare_outputs`] and the burn path, which intentionally
    /// pays to a burn key.
    pub(crate) fn prepare_outputs_inner(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
        force_split: bool,
    ) -> Result<PreparedTransfer, SendError> {
        if inputs.is_empty() {
            return Err(SendError::NoInputs);
        }
        if outputs.is_empty() {
            return Err(SendError::NoOutputs);
        }

        let input_sum: u64 = inputs.iter().map(|i| i.amount).sum();
        let output_sum: u64 = outputs.iter().map(|o| o.amount).sum();

        if output_sum > input_sum {
            return Err(SendError::InsufficientFunds {
                available: input_sum,
                needed: output_sum,
            });
        }

        let change_amount = input_sum - output_sum;
        let is_split = change_amount > 0 || outputs.len() > 1 || force_split;

        if is_split {
            Self::prepare_split_outputs(
                inputs,
                outputs,
                genesis,
                change_amount,
                commitment_version,
            )
        } else {
            Self::prepare_full_send(
                inputs,
                outputs,
                genesis,
                commitment_version,
            )
        }
    }

    /// Prepares a full-value send (no split needed).
    fn prepare_full_send(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        let output = &outputs[0];

        // Create the new asset with the recipient's script key.
        let new_asset = Asset {
            version: output.asset_version,
            genesis: genesis.clone(),
            amount: output.amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: inputs
                .iter()
                .map(|input| Witness {
                    prev_id: Some(input.prev_id.clone()),
                    tx_witness: vec![], // Filled during signing.
                    split_commitment: None,
                })
                .collect(),
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: output.script_key.clone(),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        // Build the output commitment.
        let ac = AssetCommitmentTree::new(&[&new_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let tc = TapCommitmentTree::from_asset_commitment_trees(
            commitment_version,
            vec![ac],
        )
        .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        Ok(PreparedTransfer {
            root_asset: new_asset,
            recipient_assets: vec![],
            change_commitment: tc.clone(),
            output_commitments: vec![tc],
            is_split: false,
            passive_assets: vec![],
        })
    }

    /// Prepares a split transfer (partial send with change).
    fn prepare_split_outputs(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        change_amount: u64,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        let asset_id = genesis.id();

        // Create the root (change) asset.
        // If change_amount is 0, it's a tombstone with NUMS key.
        let root_script_key = if change_amount == 0 {
            ScriptKey::from_pub_key(NUMS_KEY)
        } else {
            // Change goes back to the sender using the first input's script key.
            // The caller is responsible for providing a properly derived key
            // via the input's script_key field.
            inputs[0].script_key.clone()
        };

        let root_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: change_amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: inputs
                .iter()
                .map(|input| Witness {
                    prev_id: Some(input.prev_id.clone()),
                    tx_witness: vec![],
                    split_commitment: None,
                })
                .collect(),
            split_commitment_root: None, // Set after building split tree.
            script_version: ScriptVersion::V0,
            script_key: root_script_key,
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        // Create split assets for each recipient output.
        let mut split_assets = Vec::new();
        for output in outputs {
            let split_asset = Asset {
                version: output.asset_version,
                genesis: genesis.clone(),
                amount: output.amount,
                lock_time: 0,
                relative_lock_time: 0,
                prev_witnesses: vec![Witness {
                    prev_id: Some(PrevId::ZERO),
                    tx_witness: vec![],
                    split_commitment: None, // Set after proof generation.
                }],
                split_commitment_root: None,
                script_version: ScriptVersion::V0,
                script_key: output.script_key.clone(),
                group_key: None,
                unknown_odd_types: std::collections::BTreeMap::new(),
            };

            split_assets.push(SplitAsset {
                asset: split_asset,
                output_index: output.output_index,
            });
        }

        // Build the split commitment tree.
        let mut split_tree = mssmt::FullTree::new(mssmt::DefaultStore::new());

        // Insert root locator.
        let root_locator = SplitLocator {
            output_index: 0,
            asset_id,
            script_key: *root_asset.script_key.serialized(),
            amount: change_amount,
        };
        // The root locator leaf inserted into the split tree must be a
        // "spend template" copy of the root asset: a single
        // zero-`PrevID`, witnessless witness, exactly as Go's
        // `commitment.NewSplitCommitment` inserts (it builds every leaf,
        // including the root, from `CopySpendTemplate`, and only writes
        // the real input `PrevID`s onto a separate `RootAsset` copy that
        // is never re-inserted). The V0 leaf hash covers the witness
        // `PrevID`s, so inserting the real input `PrevID`s here would
        // make `split_commitment_root` (and the signature over it)
        // diverge from Go for every split send.
        let root_leaf = asset_leaf(&root_spend_template(&root_asset))
            .map_err(|e| SendError::SplitError(e.to_string()))?;
        split_tree
            .insert(root_locator.hash(), root_leaf)
            .map_err(|e| SendError::SplitError(e.to_string()))?;

        // Insert each split output.
        for split in &split_assets {
            let locator = SplitLocator {
                output_index: split.output_index,
                asset_id,
                script_key: *split.asset.script_key.serialized(),
                amount: split.asset.amount,
            };
            let leaf = asset_leaf(&split.asset)
                .map_err(|e| SendError::SplitError(e.to_string()))?;
            split_tree
                .insert(locator.hash(), leaf)
                .map_err(|e| SendError::SplitError(e.to_string()))?;
        }

        let tree_root = split_tree
            .root()
            .map_err(|e| SendError::SplitError(e.to_string()))?;

        // Set the split commitment root on the root asset.
        let mut root_asset = root_asset;
        root_asset.split_commitment_root =
            Some((tree_root.node_hash(), tree_root.node_sum()));

        // Build output commitments.
        let root_ac = AssetCommitmentTree::new(&[&root_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let change_tc = TapCommitmentTree::from_asset_commitment_trees(
            commitment_version,
            vec![root_ac],
        )
        .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        let mut output_commitments = Vec::new();
        for split in &split_assets {
            let ac = AssetCommitmentTree::new(&[&split.asset])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            let tc = TapCommitmentTree::from_asset_commitment_trees(
                commitment_version,
                vec![ac],
            )
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            output_commitments.push(tc);
        }

        Ok(PreparedTransfer {
            root_asset,
            recipient_assets: split_assets,
            change_commitment: change_tc,
            output_commitments,
            is_split: true,
            passive_assets: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-token".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn test_input(amount: u64) -> SelectedInput {
        SelectedInput {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0xAA; 32],
                    vout: 0,
                },
                id: test_genesis().id(),
                script_key: SerializedKey([0x02; 33]),
            },
            anchor_point: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            amount,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        }
    }

    fn test_output(amount: u64, index: u32) -> TransferOutput {
        TransferOutput {
            output_index: index,
            amount,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }
    }

    #[test]
    fn test_full_send() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(100, 0)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(!result.is_split);
        assert_eq!(result.root_asset.amount, 100);
        assert!(result.recipient_assets.is_empty());
    }

    #[test]
    fn test_commitment_version_from_destination() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(100, 0)];

        // An explicit V2 version (V1/V2 addresses, V1 vPackets) makes
        // every output commitment V2, visible in the tagged leaf format.
        let v2 = TransferBuilder::prepare_outputs_with_version(
            &inputs,
            &outputs,
            &genesis,
            Some(TapCommitmentVersion::V2),
        )
        .unwrap();
        for tc in &v2.output_commitments {
            assert_eq!(tc.commitment().version, TapCommitmentVersion::V2);
            let leaf = tc.commitment().tap_leaf();
            // V2 leaves start with the 32-byte tag, not the version byte.
            assert_ne!(leaf[0], 2u8);
        }

        // With no explicit version, the version derives from the asset
        // versions, like Go's NewTapCommitment: V0 assets give a V0
        // commitment.
        let derived = TransferBuilder::prepare_outputs_with_version(
            &inputs,
            &outputs,
            &genesis,
            None,
        )
        .unwrap();
        for tc in &derived.output_commitments {
            assert_eq!(tc.commitment().version, TapCommitmentVersion::V0);
            assert_eq!(tc.commitment().tap_leaf()[0], 0u8);
        }
    }

    #[test]
    fn test_partial_send_with_change() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(result.is_split);
        assert_eq!(result.root_asset.amount, 40); // change
        assert_eq!(result.recipient_assets.len(), 1);
        assert_eq!(result.recipient_assets[0].asset.amount, 60);
        assert!(result.root_asset.split_commitment_root.is_some());
    }

    #[test]
    fn test_full_send_two_recipients() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 0), test_output(40, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(result.is_split);
        assert_eq!(result.root_asset.amount, 0); // tombstone
        assert!(result.root_asset.is_tombstone());
        assert_eq!(result.recipient_assets.len(), 2);
    }

    #[test]
    fn test_insufficient_funds() {
        let genesis = test_genesis();
        let inputs = vec![test_input(50)];
        let outputs = vec![test_output(100, 0)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis);
        assert!(matches!(
            result,
            Err(SendError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_no_inputs() {
        let genesis = test_genesis();
        let outputs = vec![test_output(100, 0)];
        let result =
            TransferBuilder::prepare_outputs(&[], &outputs, &genesis);
        assert!(matches!(result, Err(SendError::NoInputs)));
    }

    #[test]
    fn test_no_outputs() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let result =
            TransferBuilder::prepare_outputs(&inputs, &[], &genesis);
        assert!(matches!(result, Err(SendError::NoOutputs)));
    }

    #[test]
    fn test_root_locator_leaf_is_spend_template() {
        // The split_commitment_root must be computed from a split tree
        // whose ROOT locator leaf is the spend-template shape of the
        // change asset (a single zero-PrevID, witnessless witness), NOT
        // the change asset carrying the real input PrevIDs. This pins
        // the prover to Go's commitment.NewSplitCommitment convention
        // (commitment/split.go), where the inserted root leaf is a
        // CopySpendTemplate copy and the real-witness RootAsset is never
        // re-inserted.
        use tap_primitives::commitment::asset_leaf;
        use tap_primitives::mssmt;

        let genesis = test_genesis();
        let asset_id = genesis.id();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();
        assert!(result.is_split);
        let (committed_hash, committed_sum) =
            result.root_asset.split_commitment_root.unwrap();

        // Rebuild the expected tree by hand: the root leaf is the
        // spend-template of the change asset, the split leaf is the
        // recipient asset without its split witness.
        let mut tree =
            mssmt::FullTree::new(mssmt::DefaultStore::new());

        let template = root_spend_template(&result.root_asset);
        // The template must carry exactly one zero-PrevID, witnessless
        // witness and no split commitment root.
        assert_eq!(template.prev_witnesses.len(), 1);
        assert_eq!(
            template.prev_witnesses[0].prev_id,
            Some(PrevId::ZERO)
        );
        assert!(template.prev_witnesses[0].tx_witness.is_empty());
        assert!(template.prev_witnesses[0].split_commitment.is_none());
        assert!(template.split_commitment_root.is_none());

        let root_locator = SplitLocator {
            output_index: 0,
            asset_id,
            script_key: *result.root_asset.script_key.serialized(),
            amount: result.root_asset.amount,
        };
        tree.insert(root_locator.hash(), asset_leaf(&template).unwrap())
            .unwrap();

        for split in &result.recipient_assets {
            let locator = SplitLocator {
                output_index: split.output_index,
                asset_id,
                script_key: *split.asset.script_key.serialized(),
                amount: split.asset.amount,
            };
            let mut leaf_asset = split.asset.clone();
            if let Some(w) = leaf_asset.prev_witnesses.first_mut() {
                w.split_commitment = None;
            }
            tree.insert(locator.hash(), asset_leaf(&leaf_asset).unwrap())
                .unwrap();
        }

        let expected = tree.root().unwrap();
        assert_eq!(expected.node_hash(), committed_hash);
        assert_eq!(expected.node_sum(), committed_sum);

        // A sanity check that the shape actually matters: building the
        // root leaf from the real-witness change asset (with the input
        // PrevID) must yield a DIFFERENT root, confirming the leaf hash
        // covers the witness PrevIDs.
        let mut wrong_tree =
            mssmt::FullTree::new(mssmt::DefaultStore::new());
        let mut real_root = result.root_asset.clone();
        real_root.split_commitment_root = None;
        wrong_tree
            .insert(root_locator.hash(), asset_leaf(&real_root).unwrap())
            .unwrap();
        for split in &result.recipient_assets {
            let locator = SplitLocator {
                output_index: split.output_index,
                asset_id,
                script_key: *split.asset.script_key.serialized(),
                amount: split.asset.amount,
            };
            let mut leaf_asset = split.asset.clone();
            if let Some(w) = leaf_asset.prev_witnesses.first_mut() {
                w.split_commitment = None;
            }
            wrong_tree
                .insert(locator.hash(), asset_leaf(&leaf_asset).unwrap())
                .unwrap();
        }
        let wrong = wrong_tree.root().unwrap();
        assert_ne!(wrong.node_hash(), committed_hash);
    }

    /// Byte-for-byte parity with Go's `commitment.NewSplitCommitment`.
    /// The expected root was produced by executing Go (v0.8.99) against
    /// the local taproot-assets checkout for a fixed split: a 100-unit
    /// asset (genesis outpoint 0xAB..0xAB:0, tag "vec-split") split into
    /// 40 change (script key = secp pubkey of secret 0x11..) and 60 to a
    /// recipient (script key = secp pubkey of secret 0x22..). This pins
    /// the prover's split_commitment_root to Go, closing the byte-parity
    /// gap the review called out (the root leaf must be the zero-PrevID
    /// spend template, not the real-witness root asset).
    #[test]
    fn test_split_commitment_root_matches_go_vector() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let to_hex = |bytes: &[u8]| -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        };

        let secp = Secp256k1::new();
        // Taproot script keys are BIP-340 x-only (even-Y); Go encodes
        // them normalized to the even-Y form in asset leaves. Build the
        // same even-Y SerializedKeys (0x02 prefix + x coordinate) so the
        // leaves are byte-identical to Go's.
        let pk = |b: u8| -> SerializedKey {
            let sk = SecretKey::from_slice(&[b; 32]).unwrap();
            let (x_only, _) = sk.public_key(&secp).x_only_public_key();
            let mut ser = [0u8; 33];
            ser[0] = 0x02;
            ser[1..].copy_from_slice(&x_only.serialize());
            SerializedKey(ser)
        };
        let pk1 = pk(0x11);
        let pk2 = pk(0x22);
        assert_eq!(
            to_hex(&pk1.0),
            "024f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
        assert_eq!(
            to_hex(&pk2.0),
            "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"
        );

        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0xAB; 32],
                vout: 0,
            },
            tag: "vec-split".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };

        // Sanity: the asset id must match Go's gen.ID().
        assert_eq!(
            to_hex(genesis.id().as_bytes()),
            "ceb439f322c5d4287335dc48950b32a1dcdf71bcf19e95598053322492f2bba3"
        );

        let inputs = vec![SelectedInput {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0xAB; 32],
                    vout: 0,
                },
                id: genesis.id(),
                script_key: pk1,
            },
            anchor_point: OutPoint {
                txid: [0xAB; 32],
                vout: 0,
            },
            amount: 100,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(pk1),
        }];
        let outputs = vec![TransferOutput {
            output_index: 1,
            amount: 60,
            script_key: ScriptKey::from_pub_key(pk2),
            asset_version: AssetVersion::V0,
            interactive: false,
        }];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();
        let (hash, sum) =
            result.root_asset.split_commitment_root.unwrap();

        assert_eq!(
            to_hex(&hash.0),
            "78944740a368904291b2b27cfbdcef2053ca367900113fd661ec52e9b933ecdf"
        );
        assert_eq!(sum, 100);
    }

    #[test]
    fn test_split_commitment_root_sum() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        // The split tree root sum should equal the total input.
        let (_, root_sum) =
            result.root_asset.split_commitment_root.unwrap();
        assert_eq!(root_sum, 100); // 40 change + 60 recipient
    }
}
