// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Taproot Asset commitment structures.
//!
//! Assets are committed to Bitcoin UTXOs via a two-level MS-SMT structure:
//!
//! 1. **[`AssetCommitment`]** (inner): An MS-SMT keyed by asset commitment
//!    key, holding assets of one type. The commitment identifier ("tap key")
//!    is derived from the asset ID or group public key.
//!
//! 2. **[`TapCommitment`]** (outer): An MS-SMT keyed by tap key, holding
//!    `AssetCommitment` leaves. Its root is encoded into a tapscript leaf
//!    and embedded in a Bitcoin Taproot output.
//!
//! [`CommitmentProof`] links an individual asset to the Bitcoin output through
//! both tree levels.

pub mod asset_commitment;
pub mod proof;
pub mod split;
pub mod tap_commitment;

pub use asset_commitment::{
    asset_commitment_key, asset_leaf, tap_commitment_key, AssetCommitment,
    CommitmentError,
};
pub use proof::{
    AssetProof, CommitmentProof, TaprootAssetProof, TapscriptPreimage,
};
pub use split::{SplitAsset, SplitCommitment, SplitLocator};
pub use tap_commitment::{
    TapCommitment, TapCommitmentVersion, TAPROOT_ASSETS_MARKER,
    TAPROOT_ASSETS_V2_TAG,
};
