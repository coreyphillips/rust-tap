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

        Self::sprout(batch, genesis_point, tap_output_index)?;
        batch.state = BatchState::Committed;

        Ok(batch)
    }

    /// Re-commits an already committed batch with a new genesis point
    /// and TAP output index.
    ///
    /// Used by the fund-once mint flow: the batch is first committed
    /// with a placeholder genesis point to build a fundable PSBT
    /// template; once the wallet has selected the real inputs (fixing
    /// the genesis point and output ordering), the SAME batch is
    /// re-committed. The seedlings — including their metadata and any
    /// script key overrides — and the original batch key are all
    /// preserved; only the sprouted assets and the commitment are
    /// recomputed.
    ///
    /// Only valid in the `Committed` state; the batch stays committed.
    pub fn recommit_batch(
        &mut self,
        genesis_point: OutPoint,
        tap_output_index: u32,
    ) -> Result<&MintingBatch, MintError> {
        let batch = self
            .pending_batch
            .as_mut()
            .ok_or(MintError::NoPendingBatch)?;

        if batch.state != BatchState::Committed {
            return Err(MintError::BatchNotPending(batch.state));
        }

        Self::sprout(batch, genesis_point, tap_output_index)?;

        Ok(batch)
    }

    /// Converts the batch's seedlings into sprouted assets anchored at
    /// `genesis_point` / `tap_output_index` and (re)builds the batch's
    /// Taproot Asset commitment. Shared by [`Self::commit_batch`] and
    /// [`Self::recommit_batch`]; does not touch the batch state.
    fn sprout(
        batch: &mut MintingBatch,
        genesis_point: OutPoint,
        tap_output_index: u32,
    ) -> Result<(), MintError> {
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

        // Build one AssetCommitment per asset ID (each seedling gets
        // its own genesis tag, hence its own asset ID and tap
        // commitment key) and combine them into the TapCommitment,
        // retaining the MS-SMT trees so genesis inclusion proofs can
        // be derived later.
        let mut asset_commitments = Vec::with_capacity(assets.len());
        for asset in &assets {
            let asset_commitment = AssetCommitmentTree::new(&[asset])
                .map_err(|e| MintError::CommitmentError(e.to_string()))?;
            asset_commitments.push(asset_commitment);
        }

        let tap_commitment = TapCommitmentTree::new(
            TapCommitmentVersion::V2,
            asset_commitments,
        )
        .map_err(|e| MintError::CommitmentError(e.to_string()))?;

        batch.root_asset_commitment = Some(tap_commitment);
        batch.sprouted_assets = assets;
        batch.genesis_outpoint = Some(genesis_point);
        batch.mint_output_index = Some(tap_output_index);

        Ok(())
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
    fn test_recommit_preserves_batch_and_updates_genesis() {
        use tap_primitives::proof::MetaReveal;

        let mut planter = new_planter();
        let mut seedling = Seedling::new_normal("token".into(), 1000);
        seedling.meta = Some(MetaReveal::new_opaque(b"hello".to_vec()));
        let meta_hash = seedling.meta.as_ref().unwrap().meta_hash();
        planter.queue_seedling(seedling).unwrap();
        planter.freeze_batch().unwrap();

        let placeholder = OutPoint {
            txid: [0u8; 32],
            vout: 0,
        };
        planter.commit_batch(placeholder, 0).unwrap();
        let batch_key_before =
            planter.pending_batch().unwrap().batch_key.clone();
        let commitment_before = planter
            .pending_batch()
            .unwrap()
            .root_asset_commitment
            .as_ref()
            .unwrap()
            .commitment()
            .tap_leaf();

        let real_point = OutPoint {
            txid: [0xAA; 32],
            vout: 3,
        };
        planter.recommit_batch(real_point, 1).unwrap();

        let batch = planter.pending_batch().unwrap();
        // Same batch: key preserved, still committed.
        assert_eq!(batch.batch_key, batch_key_before);
        assert_eq!(batch.state, BatchState::Committed);
        // Genesis data updated.
        assert_eq!(batch.genesis_outpoint, Some(real_point));
        assert_eq!(batch.mint_output_index, Some(1));
        // Sprouted assets carry the real genesis point, output index,
        // and the seedling's meta hash.
        assert_eq!(batch.sprouted_assets.len(), 1);
        let asset = &batch.sprouted_assets[0];
        assert_eq!(asset.genesis.first_prev_out, real_point);
        assert_eq!(asset.genesis.output_index, 1);
        assert_eq!(asset.genesis.meta_hash, meta_hash);
        // The default script key is the BIP-86 tweaked batch key.
        assert_eq!(
            asset.script_key,
            ScriptKey::bip86(batch.batch_key.pub_key)
        );
        // The commitment changed with the new genesis point.
        let commitment_after = batch
            .root_asset_commitment
            .as_ref()
            .unwrap()
            .commitment()
            .tap_leaf();
        assert_ne!(commitment_before, commitment_after);
    }

    #[test]
    fn test_recommit_preserves_script_key_override() {
        let mut planter = new_planter();
        let override_key =
            ScriptKey::from_pub_key(SerializedKey([0x03; 33]));
        let mut seedling = Seedling::new_normal("token".into(), 5);
        seedling.script_key = Some(override_key.clone());
        planter.queue_seedling(seedling).unwrap();
        planter.freeze_batch().unwrap();
        planter
            .commit_batch(OutPoint { txid: [0u8; 32], vout: 0 }, 0)
            .unwrap();
        planter
            .recommit_batch(OutPoint { txid: [0xBB; 32], vout: 1 }, 0)
            .unwrap();

        let batch = planter.pending_batch().unwrap();
        assert_eq!(batch.sprouted_assets[0].script_key, override_key);
    }

    #[test]
    fn test_recommit_requires_committed_state() {
        let mut planter = new_planter();
        planter
            .queue_seedling(Seedling::new_normal("token".into(), 10))
            .unwrap();

        // Pending: not allowed.
        assert!(planter
            .recommit_batch(OutPoint { txid: [0xAA; 32], vout: 0 }, 0)
            .is_err());

        planter.freeze_batch().unwrap();
        // Frozen: not allowed either.
        assert!(planter
            .recommit_batch(OutPoint { txid: [0xAA; 32], vout: 0 }, 0)
            .is_err());

        planter
            .commit_batch(OutPoint { txid: [0xAA; 32], vout: 0 }, 0)
            .unwrap();
        // Committed: allowed.
        assert!(planter
            .recommit_batch(OutPoint { txid: [0xBB; 32], vout: 0 }, 0)
            .is_ok());
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
