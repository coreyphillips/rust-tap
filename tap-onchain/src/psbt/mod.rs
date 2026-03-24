// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Bitcoin PSBT construction with TAP commitment embedding.
//!
//! This module provides functions to create real Bitcoin transactions
//! containing Taproot Asset commitments as tapscript leaves.

pub mod commitment;
pub mod genesis;
pub mod transfer;

pub use commitment::{
    create_tap_address, create_tap_output_script, verify_tap_output, PsbtError,
};
pub use genesis::{create_genesis_template, create_genesis_with_input, GenesisTemplate};
pub use transfer::{
    create_transfer_template, OutputDescriptor, TransferOutputInfo,
    TransferTemplate,
};
