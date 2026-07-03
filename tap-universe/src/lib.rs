// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Universe sync and federation for Taproot Assets.
//!
//! A "universe" is a Merkle-Sum Sparse Merkle Tree (MS-SMT) that stores
//! proofs for a specific (asset_id, proof_type) pair. The universe system
//! enables decentralized asset discovery and provenance verification.
//!
//! - [`types`]: Core data types (UniverseId, LeafKey, UniverseRoot, etc.)
//! - [`traits`]: Backend, sync, and federation trait definitions
//! - [`memory`]: In-memory implementations for testing
//! - [`syncer`]: Simple diff-based sync algorithm
//! - [`ignore`]: Signed ignore tuples (supply commitment ignore leaves)
//! - [`supply`]: Universe supply commitments (trees, events, verifier)

#[cfg(feature = "http-client")]
pub mod http_client;
pub mod ignore;
pub mod memory;
pub mod supply;
pub mod syncer;
pub mod traits;
pub mod types;

pub use ignore::{IgnoreError, IgnoreSig, IgnoreTuple, SignedIgnoreTuple};
pub use memory::{MemoryFederationDb, MemoryUniverseBackend};
pub use syncer::SimpleSyncer;
pub use traits::{DiffEngine, FederationDb, MultiverseArchive, Syncer, UniverseBackend};
pub use types::*;
