// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof file storage and retrieval.

use std::collections::HashMap;

use tap_primitives::asset::OutPoint;
use tap_primitives::proof;

/// A proof locator identifying a specific proof in the store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProofLocator {
    /// The outpoint where the asset is anchored.
    pub outpoint: OutPoint,
    /// The script key of the asset.
    pub script_key: tap_primitives::asset::SerializedKey,
}

/// Trait for proof file storage.
pub trait ProofStore {
    /// Stores a proof file for the given locator.
    fn insert_proof(
        &mut self,
        locator: ProofLocator,
        file: proof::File,
    ) -> Result<(), String>;

    /// Retrieves a proof file by locator.
    fn get_proof(
        &self,
        locator: &ProofLocator,
    ) -> Result<Option<proof::File>, String>;

    /// Checks if a proof exists for the given locator.
    fn has_proof(&self, locator: &ProofLocator) -> bool;

    /// Lists all stored proof locators.
    fn list_proofs(&self) -> Vec<ProofLocator>;
}

/// In-memory proof store for testing.
#[derive(Default)]
pub struct MemoryProofStore {
    proofs: HashMap<ProofLocator, proof::File>,
}

impl MemoryProofStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProofStore for MemoryProofStore {
    fn insert_proof(
        &mut self,
        locator: ProofLocator,
        file: proof::File,
    ) -> Result<(), String> {
        self.proofs.insert(locator, file);
        Ok(())
    }

    fn get_proof(
        &self,
        locator: &ProofLocator,
    ) -> Result<Option<proof::File>, String> {
        Ok(self.proofs.get(locator).cloned())
    }

    fn has_proof(&self, locator: &ProofLocator) -> bool {
        self.proofs.contains_key(locator)
    }

    fn list_proofs(&self) -> Vec<ProofLocator> {
        self.proofs.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::SerializedKey;

    fn test_locator(vout: u32) -> ProofLocator {
        ProofLocator {
            outpoint: OutPoint {
                txid: [0xAA; 32],
                vout,
            },
            script_key: SerializedKey([0x02; 33]),
        }
    }

    fn test_proof_file() -> proof::File {
        let mut file = proof::File::new();
        file.append_proof(vec![0x01, 0x02, 0x03]);
        file
    }

    #[test]
    fn test_insert_and_get() {
        let mut store = MemoryProofStore::new();
        let loc = test_locator(0);
        let file = test_proof_file();

        store.insert_proof(loc.clone(), file).unwrap();
        assert!(store.has_proof(&loc));

        let retrieved = store.get_proof(&loc).unwrap().unwrap();
        assert_eq!(retrieved.num_proofs(), 1);
    }

    #[test]
    fn test_missing_proof() {
        let store = MemoryProofStore::new();
        let loc = test_locator(99);
        assert!(!store.has_proof(&loc));
        assert!(store.get_proof(&loc).unwrap().is_none());
    }

    #[test]
    fn test_list_proofs() {
        let mut store = MemoryProofStore::new();
        store
            .insert_proof(test_locator(0), test_proof_file())
            .unwrap();
        store
            .insert_proof(test_locator(1), test_proof_file())
            .unwrap();

        assert_eq!(store.list_proofs().len(), 2);
    }
}
