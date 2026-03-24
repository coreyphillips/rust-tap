// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Convenience types for tap-node operations.

use tap_primitives::asset::{AssetId, SerializedKey};

/// Result of a completed mint operation.
#[derive(Clone, Debug)]
pub struct MintResult {
    /// The batch key identifying this mint.
    pub batch_key: SerializedKey,
    /// Transaction ID of the genesis anchor transaction (if broadcast).
    pub txid: Option<[u8; 32]>,
    /// Assets created in this batch.
    pub assets: Vec<MintedAsset>,
    /// Internal key used for the genesis P2TR output.
    pub internal_key: SerializedKey,
    /// Raw signed transaction bytes.
    pub signed_tx: Vec<u8>,
    /// Genesis outpoint (first input of the funding tx).
    pub genesis_point: tap_primitives::asset::OutPoint,
    /// Funded PSBT bytes (contains BIP32 derivation info for all outputs).
    pub funded_psbt: Vec<u8>,
    /// The transaction output index containing the TAP commitment.
    pub tap_output_index: u32,
}

/// A single asset created by a mint operation.
#[derive(Clone, Debug)]
pub struct MintedAsset {
    /// The unique asset identifier.
    pub asset_id: AssetId,
    /// Human-readable name/tag.
    pub name: String,
    /// Amount minted.
    pub amount: u64,
    /// Script key for this asset.
    pub script_key: SerializedKey,
}

/// Handle tracking an in-progress asset transfer.
#[derive(Clone, Debug)]
pub struct TransferHandle {
    /// Transaction ID of the anchor transfer transaction.
    pub txid: [u8; 32],
    /// Asset being transferred.
    pub asset_id: AssetId,
    /// Amount sent.
    pub amount: u64,
}

/// Summary of an asset balance.
#[derive(Clone, Debug)]
pub struct AssetSummary {
    /// The asset identifier.
    pub asset_id: AssetId,
    /// Human-readable name.
    pub name: String,
    /// Total spendable balance.
    pub spendable: u64,
}

/// Information about an asset Lightning channel.
#[derive(Clone, Debug)]
pub struct AssetChannelInfo {
    /// LDK channel identifier.
    pub channel_id: [u8; 32],
    /// Remote peer public key.
    pub peer: [u8; 33],
    /// Asset funded into the channel.
    pub asset_id: AssetId,
    /// Local asset balance.
    pub local_balance: u64,
    /// Remote asset balance.
    pub remote_balance: u64,
    /// Short channel ID (if assigned).
    pub scid: Option<u64>,
}
