// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset minting pipeline.
//!
//! Minting follows a state machine:
//! ```text
//! Pending → Frozen → Committed → Broadcast → Confirmed → Finalized
//!                                                ↓
//!                                          (cancelled)
//! ```
//!
//! - [`Seedling`]: An intent to create an asset (name, type, amount, metadata)
//! - [`MintingBatch`]: A collection of seedlings being minted together
//! - [`Planter`]: Manages the minting lifecycle

mod seedling;
mod batch;
mod planter;

pub use seedling::Seedling;
pub use batch::{BatchState, MintingBatch};
pub use planter::{Planter, MintError};
