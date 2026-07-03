// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Planter — manages the minting lifecycle.
//!
//! The planter orchestrates the minting process:
//! 1. Queue seedlings into a pending batch
//! 2. Freeze the batch (no more seedlings)
//! 3. Convert seedlings to asset sprouts with genesis info
//! 4. Build the TAP commitment and fund the genesis PSBT
//! 5. Sign and broadcast the genesis transaction
//! 6. Wait for confirmation and generate proofs

use tap_primitives::asset::{
    Asset, Genesis, OutPoint, ScriptKey,
};
use tap_primitives::commitment::{
    AssetCommitmentTree, TapCommitmentTree, TapCommitmentVersion,
};

use super::batch::{BatchState, MintingBatch};
use super::seedling::Seedling;
use crate::chain::{
    ChainBridge, ChainError, KeyRing, WalletAnchor,
};

/// Errors from the minting pipeline.
#[derive(Debug, Clone)]
pub enum MintError {
    /// Seedling validation failed.
    InvalidSeedling(String),
    /// Batch is not in the expected state.
    BatchNotPending(BatchState),
    /// Duplicate seedling name.
    DuplicateSeedling(String),
    /// No pending batch.
    NoPendingBatch,
    /// Batch is empty (no seedlings).
    EmptyBatch,
    /// Chain error.
    Chain(ChainError),
    /// Commitment construction failed.
    CommitmentError(String),
    /// Batch cannot be cancelled in current state.
    CannotCancel(BatchState),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::InvalidSeedling(msg) => {
                write!(f, "invalid seedling: {}", msg)
            }
            MintError::BatchNotPending(state) => {
                write!(f, "batch not pending: {}", state)
            }
            MintError::DuplicateSeedling(name) => {
                write!(f, "duplicate seedling: {}", name)
            }
            MintError::NoPendingBatch => write!(f, "no pending batch"),
            MintError::EmptyBatch => write!(f, "batch has no seedlings"),
            MintError::Chain(e) => write!(f, "chain error: {}", e),
            MintError::CommitmentError(msg) => {
                write!(f, "commitment error: {}", msg)
            }
            MintError::CannotCancel(state) => {
                write!(f, "cannot cancel batch in state: {}", state)
            }
        }
    }
}

impl std::error::Error for MintError {}

impl From<ChainError> for MintError {
    fn from(e: ChainError) -> Self {
        MintError::Chain(e)
    }
}

/// The minting planter — manages batch creation and the minting lifecycle.
///
/// Generic over chain backend, wallet, and key ring implementations.
pub struct Planter<C, W, K>
where
    C: ChainBridge,
    W: WalletAnchor,
    K: KeyRing,
{
    chain: C,
    wallet: W,
    key_ring: K,
    pending_batch: Option<MintingBatch>,
}

impl<C, W, K> Planter<C, W, K>
where
    C: ChainBridge,
    W: WalletAnchor,
    K: KeyRing,
{
    /// Creates a new planter.
    pub fn new(chain: C, wallet: W, key_ring: K) -> Self {
        Planter {
            chain,
            wallet,
            key_ring,
            pending_batch: None,
        }
    }

    /// Queues a new seedling for minting.
    ///
    /// If no pending batch exists, one is created automatically. The
    /// seedling is validated and added to the current pending batch.
    pub fn queue_seedling(
        &mut self,
        seedling: Seedling,
    ) -> Result<(), MintError> {
        seedling.validate()?;

        // Create a new batch if we don't have one.
        if self.pending_batch.is_none() {
            let batch_key = self
                .key_ring
                .derive_next_key(tap_primitives::asset::TAPROOT_ASSETS_KEY_FAMILY)
                .map_err(MintError::Chain)?;
            self.pending_batch = Some(MintingBatch::new(batch_key));
        }

        self.pending_batch
            .as_mut()
            .unwrap()
            .add_seedling(seedling)
    }

    /// Freezes the current pending batch, preventing new seedlings.
    pub fn freeze_batch(&mut self) -> Result<(), MintError> {
        let batch = self
            .pending_batch
            .as_mut()
            .ok_or(MintError::NoPendingBatch)?;

        if batch.seedlings.is_empty() {
            return Err(MintError::EmptyBatch);
        }

        batch.state = BatchState::Frozen;
        Ok(())
    }

    /// Converts seedlings to asset sprouts and builds the TAP commitment.
    ///
    /// `genesis_point` is the first input outpoint of the anchor tx.
    /// `tap_output_index` is the transaction output index where the TAP
    /// commitment lives — all assets in the batch share this value as
    /// their genesis `output_index`.
    ///
    /// Moves the batch from Frozen → Committed.
    pub fn commit_batch(
        &mut self,
        genesis_point: OutPoint,
        tap_output_index: u32,
    ) -> Result<&MintingBatch, MintError> {
        let batch = self
            .pending_batch
            .as_mut()
            .ok_or(MintError::NoPendingBatch)?;

        if batch.state != BatchState::Frozen {
            return Err(MintError::BatchNotPending(batch.state));
        }

        // Convert seedlings to assets.
        let mut assets = Vec::new();
        for (name, seedling) in batch.seedlings.iter() {
            let genesis = Genesis {
                first_prev_out: genesis_point,
                tag: name.clone(),
                meta_hash: seedling
                    .meta
                    .as_ref()
                    .map(|m| m.meta_hash())
                    .unwrap_or([0u8; 32]),
                output_index: tap_output_index,
                asset_type: seedling.asset_type,
            };

            // Use the seedling's script key or derive one with BIP-86 tweak.
            let script_key = seedling
                .script_key
                .clone()
                .unwrap_or_else(|| {
                    // Default to BIP-86 tweaked batch key (matches Go's
                    // NewScriptKeyBip86). The tweak produces an even-y key.
                    ScriptKey::bip86(batch.batch_key.pub_key)
                });

            let asset = Asset::new_genesis(
                genesis,
                seedling.amount,
                script_key,
            );
            assets.push(asset);
        }

        // Build the AssetCommitment and TapCommitment, retaining the
        // MS-SMT trees so genesis inclusion proofs can be derived
        // later.
        let asset_refs: Vec<&Asset> = assets.iter().collect();
        let asset_commitment = AssetCommitmentTree::new(&asset_refs)
            .map_err(|e| MintError::CommitmentError(e.to_string()))?;

        let tap_commitment = TapCommitmentTree::new(
            TapCommitmentVersion::V2,
            vec![asset_commitment],
        )
        .map_err(|e| MintError::CommitmentError(e.to_string()))?;

        batch.root_asset_commitment = Some(tap_commitment);
        batch.genesis_outpoint = Some(genesis_point);
        batch.state = BatchState::Committed;

        Ok(batch)
    }

    /// Cancels the current pending batch.
    pub fn cancel_batch(&mut self) -> Result<(), MintError> {
        let batch = self
            .pending_batch
            .as_mut()
            .ok_or(MintError::NoPendingBatch)?;

        if !batch.state.can_cancel() {
            return Err(MintError::CannotCancel(batch.state));
        }

        batch.state = if batch.state == BatchState::Committed {
            BatchState::SproutCancelled
        } else {
            BatchState::SeedlingCancelled
        };

        Ok(())
    }

    /// Returns a reference to the current pending batch.
    pub fn pending_batch(&self) -> Option<&MintingBatch> {
        self.pending_batch.as_ref()
    }

    /// Takes the pending batch, leaving `None` in its place.
    pub fn take_batch(&mut self) -> Option<MintingBatch> {
        self.pending_batch.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::*;
    use tap_primitives::asset::SerializedKey;

    // Minimal test implementations of the chain traits.
    struct MockChain;
    struct MockWallet;
    struct MockKeyRing {
        next_index: std::cell::Cell<u32>,
    }

    impl ChainBridge for MockChain {
        fn current_height(&self) -> Result<u32, ChainError> {
            Ok(800_000)
        }
        fn estimate_fee(&self, _: u32) -> Result<FeeRate, ChainError> {
            Ok(FeeRate(2000))
        }
        fn publish_transaction(&self, _: &[u8]) -> Result<(), ChainError> {
            Ok(())
        }
        fn get_block_hash(&self, _: u32) -> Result<[u8; 32], ChainError> {
            Ok([0xAA; 32])
        }
    }

    impl WalletAnchor for MockWallet {
        fn fund_psbt(
            &self,
            _: &[u8],
            _: FeeRate,
        ) -> Result<Vec<u8>, ChainError> {
            Ok(vec![0x01])
        }
        fn sign_and_finalize_psbt(
            &self,
            _: &[u8],
        ) -> Result<Vec<u8>, ChainError> {
            Ok(vec![0x02])
        }
        fn import_taproot_output(
            &self,
            _: &SerializedKey,
        ) -> Result<(), ChainError> {
            Ok(())
        }
    }

    impl KeyRing for MockKeyRing {
        fn derive_next_key(
            &self,
            family: u16,
        ) -> Result<KeyDescriptor, ChainError> {
            let idx = self.next_index.get();
            self.next_index.set(idx + 1);
            Ok(KeyDescriptor {
                family,
                index: idx,
                pub_key: SerializedKey([0x02; 33]),
            })
        }
        fn is_local_key(
            &self,
            _: &KeyDescriptor,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }
    }

    fn new_planter() -> Planter<MockChain, MockWallet, MockKeyRing> {
        Planter::new(
            MockChain,
            MockWallet,
            MockKeyRing {
                next_index: std::cell::Cell::new(0),
            },
        )
    }

    #[test]
    fn test_queue_seedling_creates_batch() {
        let mut planter = new_planter();
        assert!(planter.pending_batch().is_none());

        planter
            .queue_seedling(Seedling::new_normal("token".into(), 1000))
            .unwrap();

        assert!(planter.pending_batch().is_some());
        assert_eq!(planter.pending_batch().unwrap().num_seedlings(), 1);
    }

    #[test]
    fn test_queue_multiple_seedlings() {
        let mut planter = new_planter();
        planter
            .queue_seedling(Seedling::new_normal("token-a".into(), 500))
            .unwrap();
        planter
            .queue_seedling(Seedling::new_normal("token-b".into(), 300))
            .unwrap();

        assert_eq!(planter.pending_batch().unwrap().num_seedlings(), 2);
        assert_eq!(planter.pending_batch().unwrap().total_amount(), 800);
    }

    #[test]
    fn test_freeze_and_commit() {
        let mut planter = new_planter();
        planter
            .queue_seedling(Seedling::new_normal("token".into(), 1000))
            .unwrap();

        planter.freeze_batch().unwrap();
        assert_eq!(
            planter.pending_batch().unwrap().state,
            BatchState::Frozen
        );

        let genesis_point = OutPoint {
            txid: [0xAA; 32],
            vout: 0,
        };
        planter.commit_batch(genesis_point, 0).unwrap();
        assert_eq!(
            planter.pending_batch().unwrap().state,
            BatchState::Committed
        );
        assert!(planter
            .pending_batch()
            .unwrap()
            .root_asset_commitment
            .is_some());
    }

    #[test]
    fn test_freeze_empty_batch_fails() {
        let mut planter = new_planter();
        // Create batch by queuing then removing - or just try freeze with
        // no seedlings. We need a batch first.
        planter
            .queue_seedling(Seedling::new_normal("token".into(), 100))
            .unwrap();
        // Remove the seedling to make it empty.
        planter
            .pending_batch
            .as_mut()
            .unwrap()
            .seedlings
            .clear();
        assert!(planter.freeze_batch().is_err());
    }

    #[test]
    fn test_cancel_pending_batch() {
        let mut planter = new_planter();
        planter
            .queue_seedling(Seedling::new_normal("token".into(), 100))
            .unwrap();
        planter.cancel_batch().unwrap();
        assert_eq!(
            planter.pending_batch().unwrap().state,
            BatchState::SeedlingCancelled
        );
    }

    #[test]
    fn test_cancel_committed_batch() {
        let mut planter = new_planter();
        planter
            .queue_seedling(Seedling::new_normal("token".into(), 100))
            .unwrap();
        planter.freeze_batch().unwrap();
        planter
            .commit_batch(OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            }, 0)
            .unwrap();

        planter.cancel_batch().unwrap();
        assert_eq!(
            planter.pending_batch().unwrap().state,
            BatchState::SproutCancelled
        );
    }
}
