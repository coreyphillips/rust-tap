// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset channel state management.
//!
//! This module manages the asset-specific state for Lightning channels:
//! - [`blobs`]: Opaque data blobs stored alongside LDK channel state
//! - [`traits`]: Integration traits for channel lifecycle hooks

pub mod blobs;
pub mod closer;
pub mod funding;
pub mod leaf_creator;
pub mod leaf_signer;
pub mod tap_tx_builder;
pub mod traits;

pub use blobs::{ChannelBlob, CommitmentBlob, HtlcBlob};
pub use closer::TapAssetChannelCloser;
pub use funding::{initial_commitment_blob, TapAssetFundingController};
pub use leaf_creator::TapAssetLeafCreator;
pub use leaf_signer::{pack_aux_signatures, unpack_aux_signatures, TapAssetLeafSigner};
pub use tap_tx_builder::TapTxBuilder;
pub use traits::*;
