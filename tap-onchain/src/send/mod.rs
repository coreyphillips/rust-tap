// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset transfer pipeline.
//!
//! Transfers follow a state machine:
//! ```text
//! Select → Sign → Anchor → Verify → Store → Broadcast → Confirm → Proofs → Complete
//! ```
//!
//! - [`FundingDescriptor`]: Specifies which asset to send and how much
//! - [`TransferOutput`]: A recipient output allocation
//! - [`SendState`]: Transfer state machine
//! - [`TransferBuilder`]: Constructs transfers from allocations

mod allocation;
mod burn;
pub mod executor;
pub mod sign;
pub mod split_proof;
mod transfer;

pub use allocation::{FundingDescriptor, SelectedInput, TransferOutput};
pub use burn::{prepare_burn, BurnParams};
pub use executor::{
    execute_transfer, execute_transfer_with_options,
    execute_transfer_with_version, TransferOptions, TransferResult,
};
pub use sign::{sign_transfer, VirtualSigner};
pub use split_proof::populate_split_proofs;
pub use transfer::{PreparedTransfer, SendError, SendState, TransferBuilder};
