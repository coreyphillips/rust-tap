// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Persistence layer for Taproot Assets.
//!
//! Provides storage backends for:
//! - [`asset_store`]: Tracking owned assets and their proofs
//! - [`batch_store`]: Minting batch state persistence
//! - [`proof_store`]: Proof file storage and retrieval
//! - [`ignore_store`]: Signed ignore tuples + is_ignored lookups
//! - [`supply_store`]: Universe supply trees and supply commitments

pub mod asset_store;
pub mod batch_store;
pub mod ignore_store;
pub mod mailbox_store;
pub mod proof_store;
pub mod supply_store;

#[cfg(feature = "sqlite")]
mod migrations;
#[cfg(feature = "sqlite")]
pub mod mssmt_store;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub mod universe_store;
