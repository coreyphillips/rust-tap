// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Minting batch — a collection of seedlings being minted in one transaction.

use std::collections::HashMap;

use tap_primitives::asset::Asset;
use tap_primitives::commitment::TapCommitmentTree;

use super::seedling::Seedling;
use crate::chain::KeyDescriptor;

/// State of a minting batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BatchState {
    /// Batch is accepting new seedlings.
    Pending = 0,
    /// No new seedlings can be added.
    Frozen = 1,
    /// Has unsigned genesis PSBT and asset sprouts.
    Committed = 2,
    /// Genesis transaction has been signed and broadcast.
    Broadcast = 3,
    /// Confirmed on-chain, awaiting finalization.
    Confirmed = 4,
    /// Terminal: fully confirmed with proofs generated.
    Finalized = 5,
    /// Cancelled before commitment.
    SeedlingCancelled = 6,
    /// Cancelled after commitment.
    SproutCancelled = 7,
}

impl BatchState {
    /// Returns true if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            BatchState::Finalized
                | BatchState::SeedlingCancelled
                | BatchState::SproutCancelled
        )
    }

    /// Returns true if the batch can accept new seedlings.
    pub fn can_add_seedlings(&self) -> bool {
        *self == BatchState::Pending
    }

    /// Returns true if the batch can be cancelled.
    pub fn can_cancel(&self) -> bool {
        matches!(
            self,
            BatchState::Pending
                | BatchState::Frozen
                | BatchState::Committed
        )
    }
}

impl std::fmt::Display for BatchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchState::Pending => write!(f, "pending"),
            BatchState::Frozen => write!(f, "frozen"),
            BatchState::Committed => write!(f, "committed"),
            BatchState::Broadcast => write!(f, "broadcast"),
            BatchState::Confirmed => write!(f, "confirmed"),
            BatchState::Finalized => write!(f, "finalized"),
            BatchState::SeedlingCancelled => {
                write!(f, "seedling_cancelled")
            }
            BatchState::SproutCancelled => write!(f, "sprout_cancelled"),
        }
    }
}

/// A minting batch: a collection of seedlings being minted together in
/// a single Bitcoin transaction.
#[derive(Clone, Debug)]
pub struct MintingBatch {
    /// Current state of the batch.
    pub state: BatchState,
    /// The batch's internal key (used as the genesis TX internal key).
    pub batch_key: KeyDescriptor,
    /// Seedlings queued for minting, keyed by asset name.
    pub seedlings: HashMap<String, Seedling>,
    /// Funded but unsigned genesis PSBT (set during Committed state).
    pub genesis_psbt: Option<Vec<u8>>,
    /// The Taproot Asset commitment for this batch (set during
    /// Committed). Retains its MS-SMT trees so genesis inclusion
    /// proofs can be derived after confirmation.
    pub root_asset_commitment: Option<TapCommitmentTree>,
    /// The assets sprouted from the batch's seedlings (set during
    /// Committed, alongside `root_asset_commitment`). Each asset
    /// carries the real genesis (including the seedling's meta hash)
    /// and the real script key (the seedling override, or the BIP-86
    /// tweaked batch key). Transient: not persisted by batch stores.
    pub sprouted_assets: Vec<Asset>,
    /// Signed genesis transaction bytes (set during Broadcast).
    pub signed_tx: Option<Vec<u8>>,
    /// The genesis outpoint after signing (set during Broadcast).
    pub genesis_outpoint: Option<tap_primitives::asset::OutPoint>,
    /// Block confirmation info (set during Confirmed).
    pub confirmation: Option<crate::chain::TxConfirmation>,
    /// The output index in the genesis TX containing the TAP commitment.
    pub mint_output_index: Option<u32>,
    /// Height hint for the chain watcher.
    pub height_hint: u32,
}

impl MintingBatch {
    /// Creates a new empty batch in Pending state.
    pub fn new(batch_key: KeyDescriptor) -> Self {
        MintingBatch {
            state: BatchState::Pending,
            batch_key,
            seedlings: HashMap::new(),
            genesis_psbt: None,
            root_asset_commitment: None,
            sprouted_assets: Vec::new(),
            signed_tx: None,
            genesis_outpoint: None,
            confirmation: None,
            mint_output_index: None,
            height_hint: 0,
        }
    }

    /// Adds a seedling to the batch.
    pub fn add_seedling(
        &mut self,
        seedling: Seedling,
    ) -> Result<(), super::MintError> {
        if !self.state.can_add_seedlings() {
            return Err(super::MintError::BatchNotPending(self.state));
        }

        seedling.validate()?;

        if self.seedlings.contains_key(&seedling.asset_name) {
            return Err(super::MintError::DuplicateSeedling(
                seedling.asset_name.clone(),
            ));
        }

        self.seedlings.insert(seedling.asset_name.clone(), seedling);
        Ok(())
    }

    /// Returns the number of seedlings in the batch.
    pub fn num_seedlings(&self) -> usize {
        self.seedlings.len()
    }

    /// Returns the total amount of all seedlings.
    pub fn total_amount(&self) -> u64 {
        self.seedlings.values().map(|s| s.amount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::SerializedKey;

    fn test_key() -> KeyDescriptor {
        KeyDescriptor {
            family: 212,
            index: 0,
            pub_key: SerializedKey([0x02; 33]),
        }
    }

    #[test]
    fn test_new_batch() {
        let batch = MintingBatch::new(test_key());
        assert_eq!(batch.state, BatchState::Pending);
        assert_eq!(batch.num_seedlings(), 0);
    }

    #[test]
    fn test_add_seedling() {
        let mut batch = MintingBatch::new(test_key());
        let seedling = Seedling::new_normal("token-a".into(), 1000);
        batch.add_seedling(seedling).unwrap();
        assert_eq!(batch.num_seedlings(), 1);
        assert_eq!(batch.total_amount(), 1000);
    }

    #[test]
    fn test_add_multiple_seedlings() {
        let mut batch = MintingBatch::new(test_key());
        batch
            .add_seedling(Seedling::new_normal("token-a".into(), 500))
            .unwrap();
        batch
            .add_seedling(Seedling::new_normal("token-b".into(), 300))
            .unwrap();
        assert_eq!(batch.num_seedlings(), 2);
        assert_eq!(batch.total_amount(), 800);
    }

    #[test]
    fn test_duplicate_seedling_rejected() {
        let mut batch = MintingBatch::new(test_key());
        batch
            .add_seedling(Seedling::new_normal("token".into(), 100))
            .unwrap();
        let result =
            batch.add_seedling(Seedling::new_normal("token".into(), 200));
        assert!(result.is_err());
    }

    #[test]
    fn test_frozen_batch_rejects_seedlings() {
        let mut batch = MintingBatch::new(test_key());
        batch.state = BatchState::Frozen;
        let result =
            batch.add_seedling(Seedling::new_normal("token".into(), 100));
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_state_transitions() {
        assert!(BatchState::Pending.can_add_seedlings());
        assert!(!BatchState::Frozen.can_add_seedlings());

        assert!(BatchState::Pending.can_cancel());
        assert!(BatchState::Frozen.can_cancel());
        assert!(BatchState::Committed.can_cancel());
        assert!(!BatchState::Broadcast.can_cancel());
        assert!(!BatchState::Finalized.can_cancel());

        assert!(BatchState::Finalized.is_terminal());
        assert!(BatchState::SeedlingCancelled.is_terminal());
        assert!(!BatchState::Pending.is_terminal());
    }
}
