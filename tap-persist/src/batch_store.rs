// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Minting batch state persistence.

use std::collections::HashMap;

use tap_primitives::asset::SerializedKey;
use tap_onchain::mint::{BatchState, MintingBatch};

/// Trait for persisting minting batch state.
pub trait BatchStore {
    fn save_batch(&mut self, batch: &MintingBatch) -> Result<(), String>;
    fn load_batch(
        &self,
        batch_key: &SerializedKey,
    ) -> Result<Option<MintingBatch>, String>;
    fn update_state(
        &mut self,
        batch_key: &SerializedKey,
        state: BatchState,
    ) -> Result<(), String>;
    fn list_batches(&self) -> Vec<MintingBatch>;
}

/// In-memory batch store for testing.
#[derive(Default)]
pub struct MemoryBatchStore {
    batches: HashMap<SerializedKey, MintingBatch>,
}

impl MemoryBatchStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BatchStore for MemoryBatchStore {
    fn save_batch(&mut self, batch: &MintingBatch) -> Result<(), String> {
        self.batches
            .insert(batch.batch_key.pub_key, batch.clone());
        Ok(())
    }

    fn load_batch(
        &self,
        batch_key: &SerializedKey,
    ) -> Result<Option<MintingBatch>, String> {
        Ok(self.batches.get(batch_key).cloned())
    }

    fn update_state(
        &mut self,
        batch_key: &SerializedKey,
        state: BatchState,
    ) -> Result<(), String> {
        if let Some(batch) = self.batches.get_mut(batch_key) {
            batch.state = state;
            Ok(())
        } else {
            Err("batch not found".into())
        }
    }

    fn list_batches(&self) -> Vec<MintingBatch> {
        self.batches.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_onchain::chain::KeyDescriptor;
    use tap_onchain::mint::Seedling;

    fn test_batch() -> MintingBatch {
        let mut batch = MintingBatch::new(KeyDescriptor {
            family: 212,
            index: 0,
            pub_key: SerializedKey([0x02; 33]),
        });
        batch
            .add_seedling(Seedling::new_normal("test-token".into(), 1000))
            .unwrap();
        batch
    }

    #[test]
    fn test_save_and_load() {
        let mut store = MemoryBatchStore::new();
        let batch = test_batch();
        store.save_batch(&batch).unwrap();

        let loaded = store
            .load_batch(&SerializedKey([0x02; 33]))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, BatchState::Pending);
        assert_eq!(loaded.num_seedlings(), 1);
    }

    #[test]
    fn test_update_state() {
        let mut store = MemoryBatchStore::new();
        let batch = test_batch();
        store.save_batch(&batch).unwrap();

        store
            .update_state(&SerializedKey([0x02; 33]), BatchState::Frozen)
            .unwrap();

        let loaded = store
            .load_batch(&SerializedKey([0x02; 33]))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, BatchState::Frozen);
    }

    #[test]
    fn test_list_batches() {
        let mut store = MemoryBatchStore::new();
        store.save_batch(&test_batch()).unwrap();
        assert_eq!(store.list_batches().len(), 1);
    }
}
