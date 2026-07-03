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

pub mod allocation;
pub mod blobs;
pub mod closer;
pub mod funding;
pub mod leaf_creator;
pub mod leaf_signer;
pub mod tap_tx_builder;
pub mod traits;

pub use allocation::{
    assign_output_commitments, asset_sort_for_inputs, distribute_coins,
    in_place_allocation_sort, Allocation, AllocationError, AllocationType,
};
pub use blobs::{
    AssetBalance, AssetOutput, AuxLeaves, ChannelBlob, CommitmentBlob,
    FundedAsset, HtlcAuxLeaf, HtlcBlob, TapLeaf,
};
pub use closer::TapAssetChannelCloser;
pub use funding::{initial_commitment_blob, TapAssetFundingController};
pub use leaf_creator::TapAssetLeafCreator;
pub use leaf_signer::{
    create_second_level_htlc_allocation, pack_aux_signatures,
    unpack_aux_signatures, AssetSig, SecondLevelHtlcParams,
    TapAssetLeafSigner,
};
pub use tap_tx_builder::TapTxBuilder;
pub use traits::*;
