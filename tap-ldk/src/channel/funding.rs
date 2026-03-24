// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset funding controller — manages the asset-specific parts of
//! Lightning channel funding.
//!
//! During channel open, the initiator sends asset proofs to the responder.
//! The responder validates the proofs and acknowledges. After the standard
//! LDK funding flow completes, the asset funding info is stored as the
//! channel blob.

use std::collections::HashMap;

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::asset::{AssetId, SerializedKey, NUMS_BYTES};
use tap_primitives::crypto::keys;

use super::blobs::{AssetBalance, ChannelBlob, CommitmentBlob, FundedAsset};
use super::traits::{AssetChannelError, AssetFundingController};
use crate::wire::{
    AssetFundingAck, AssetFundingCreated, TapMessage,
};

/// Default implementation of [`AssetFundingController`].
///
/// Tracks pending asset channel opens and produces the channel/commitment
/// blobs after funding is confirmed.
pub struct TapAssetFundingController {
    /// Pending funding proposals keyed by temporary channel ID.
    pending: HashMap<[u8; 32], PendingFunding>,
}

/// State of a pending asset channel funding.
#[derive(Clone, Debug)]
struct PendingFunding {
    /// The asset being funded.
    asset_id: AssetId,
    /// Total asset amount for the channel.
    amount: u64,
    /// Group key if applicable.
    group_key: Option<SerializedKey>,
}

impl TapAssetFundingController {
    pub fn new() -> Self {
        TapAssetFundingController {
            pending: HashMap::new(),
        }
    }

    /// Initiates an asset channel funding by creating the funding message.
    ///
    /// `proof_data` must contain the encoded asset proofs for the input
    /// assets being committed to the channel. The counterparty uses these
    /// to verify the channel's asset backing.
    pub fn initiate_funding(
        &mut self,
        pending_channel_id: [u8; 32],
        asset_id: AssetId,
        amount: u64,
        group_key: Option<SerializedKey>,
        proof_data: Vec<u8>,
    ) -> TapMessage {
        self.pending.insert(
            pending_channel_id,
            PendingFunding {
                asset_id,
                amount,
                group_key,
            },
        );

        TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id,
            asset_id,
            amount,
            proof_data,
            group_key,
        })
    }
}

impl Default for TapAssetFundingController {
    fn default() -> Self {
        Self::new()
    }
}

/// Derives the funding script key for an asset channel.
///
/// Uses the NUMS internal key + an OP_TRUE tapscript leaf to produce a
/// deterministic output key. This matches Go's `ScriptKeyScriptPathChannel`
/// approach: anyone-can-spend via script path, but the key path is
/// unspendable (NUMS).
///
/// For multi-asset channels, an asset-id–specific leaf can be included
/// as a sibling to make the key unique per asset.
fn derive_funding_script_key(
    asset_id: Option<&AssetId>,
) -> Result<SerializedKey, AssetChannelError> {
    // OP_TRUE (0x51) as the anyone-can-spend tapscript.
    let op_true_script = [0x51u8];

    // BIP-341 tapleaf hash: SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || leaf_version || compact_size(script_len) || script)
    let leaf_version = 0xC0u8; // default tapscript version
    let tapleaf_tag = sha256::Hash::hash(b"TapLeaf");
    let mut engine = sha256::HashEngine::default();
    engine.input(tapleaf_tag.as_ref());
    engine.input(tapleaf_tag.as_ref());
    engine.input(&[leaf_version]);
    engine.input(&[op_true_script.len() as u8]); // compact size
    engine.input(&op_true_script);
    let leaf_hash = sha256::Hash::from_engine(engine);

    // If we have an asset ID, combine with a second leaf to make the key
    // unique per asset. Otherwise, the tapscript root IS the leaf hash.
    let tapscript_root = if let Some(id) = asset_id {
        // Create an OP_RETURN leaf with the asset ID.
        let mut op_return_script = vec![0x6a]; // OP_RETURN
        op_return_script.push(0x20); // OP_PUSHBYTES_32
        op_return_script.extend_from_slice(id.as_bytes());

        let mut engine2 = sha256::HashEngine::default();
        engine2.input(tapleaf_tag.as_ref());
        engine2.input(tapleaf_tag.as_ref());
        engine2.input(&[leaf_version]);
        engine2.input(&[op_return_script.len() as u8]);
        engine2.input(&op_return_script);
        let leaf2_hash = sha256::Hash::from_engine(engine2);

        // BIP-341 tapbranch: SHA256(SHA256("TapBranch") || SHA256("TapBranch") || sorted(left, right))
        let tapbranch_tag = sha256::Hash::hash(b"TapBranch");
        let mut engine3 = sha256::HashEngine::default();
        engine3.input(tapbranch_tag.as_ref());
        engine3.input(tapbranch_tag.as_ref());
        // Lexicographic sort of the two leaf hashes.
        let (first, second) = if leaf_hash.to_byte_array() <= leaf2_hash.to_byte_array() {
            (leaf_hash, leaf2_hash)
        } else {
            (leaf2_hash, leaf_hash)
        };
        engine3.input(first.as_byte_array());
        engine3.input(second.as_byte_array());
        sha256::Hash::from_engine(engine3).to_byte_array()
    } else {
        leaf_hash.to_byte_array()
    };

    // Parse the NUMS key and extract x-only form.
    let nums_pub = keys::parse_pub_key(&SerializedKey(NUMS_BYTES))
        .map_err(|e| AssetChannelError(format!("invalid NUMS key: {}", e)))?;
    let (nums_x_only, _parity) = nums_pub.x_only_public_key();

    // Tweak with the tapscript root to get the output key.
    let (tweaked_key, _parity) = keys::tweak_pub_key(&nums_x_only, Some(&tapscript_root))
        .map_err(|e| AssetChannelError(format!("tweak failed: {}", e)))?;

    // Serialize as compressed public key (even parity prefix).
    let mut serialized = [0u8; 33];
    serialized[0] = 0x02;
    serialized[1..].copy_from_slice(&tweaked_key.serialize());
    Ok(SerializedKey(serialized))
}

impl AssetFundingController for TapAssetFundingController {
    fn handle_funding_msg(
        &self,
        pending_channel_id: &[u8; 32],
        msg: &TapMessage,
    ) -> Result<Option<TapMessage>, AssetChannelError> {
        match msg {
            TapMessage::AssetFundingCreated(_created) => {
                // Responder receives funding proposal.
                // In production: validate proofs, check asset exists, etc.
                Ok(Some(TapMessage::AssetFundingAck(AssetFundingAck {
                    pending_channel_id: *pending_channel_id,
                    accepted: true,
                    reject_reason: None,
                })))
            }
            TapMessage::AssetFundingAck(ack) => {
                if !ack.accepted {
                    return Err(AssetChannelError(format!(
                        "funding rejected: {}",
                        ack.reject_reason.as_deref().unwrap_or("unknown")
                    )));
                }
                // Initiator receives acknowledgment.
                Ok(None)
            }
            TapMessage::AssetFundingProof(_proof) => {
                // Final proof exchange after funding tx is constructed.
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn finalize_funding(
        &self,
        pending_channel_id: &[u8; 32],
    ) -> Result<ChannelBlob, AssetChannelError> {
        let pending = self.pending.get(pending_channel_id).ok_or_else(|| {
            AssetChannelError("no pending funding".into())
        })?;

        let script_key = derive_funding_script_key(Some(&pending.asset_id))?;

        Ok(ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: pending.asset_id,
                amount: pending.amount,
                script_key,
            }],
            decimal_display: None,
            group_key: pending.group_key,
        })
    }
}

/// Creates the initial commitment blob for a newly funded asset channel.
///
/// The initiator gets all the asset balance initially (like BTC in LN).
pub fn initial_commitment_blob(
    channel_blob: &ChannelBlob,
    initiator_is_local: bool,
) -> CommitmentBlob {
    let balances: Vec<AssetBalance> = channel_blob
        .funded_assets
        .iter()
        .map(|fa| AssetBalance {
            asset_id: fa.asset_id,
            amount: fa.amount,
        })
        .collect();

    let empty: Vec<AssetBalance> = channel_blob
        .funded_assets
        .iter()
        .map(|fa| AssetBalance {
            asset_id: fa.asset_id,
            amount: 0,
        })
        .collect();

    if initiator_is_local {
        CommitmentBlob {
            local_assets: balances,
            remote_assets: empty,
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        }
    } else {
        CommitmentBlob {
            local_assets: empty,
            remote_assets: balances,
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiate_funding() {
        let mut controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];

        let msg = controller.initiate_funding(
            channel_id,
            AssetId([0xAA; 32]),
            1000,
            None,
            vec![0x01, 0x02, 0x03], // proof data
        );

        assert!(matches!(msg, TapMessage::AssetFundingCreated(_)));
        if let TapMessage::AssetFundingCreated(created) = msg {
            assert_eq!(created.amount, 1000);
            assert_eq!(created.proof_data, vec![0x01, 0x02, 0x03]);
        }
    }

    #[test]
    fn test_handle_funding_created() {
        let controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];

        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id: AssetId([0xAA; 32]),
            amount: 1000,
            proof_data: vec![],
            group_key: None,
        });

        let response = controller
            .handle_funding_msg(&channel_id, &msg)
            .unwrap();
        assert!(matches!(response, Some(TapMessage::AssetFundingAck(_))));
    }

    #[test]
    fn test_finalize_funding() {
        let mut controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];

        controller.initiate_funding(
            channel_id,
            AssetId([0xAA; 32]),
            1000,
            None,
            vec![],
        );

        let blob = controller.finalize_funding(&channel_id).unwrap();
        assert_eq!(blob.funded_assets.len(), 1);
        assert_eq!(blob.funded_assets[0].amount, 1000);
        // Script key should be derived, not the placeholder.
        assert_ne!(blob.funded_assets[0].script_key, SerializedKey([0x02; 33]));
        // Should start with 0x02 (even y-coordinate).
        assert_eq!(blob.funded_assets[0].script_key.0[0], 0x02);
    }

    #[test]
    fn test_derive_funding_script_key_deterministic() {
        let id = AssetId([0xAA; 32]);
        let key1 = derive_funding_script_key(Some(&id)).unwrap();
        let key2 = derive_funding_script_key(Some(&id)).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_funding_script_key_differs_by_asset() {
        let key1 = derive_funding_script_key(Some(&AssetId([0xAA; 32]))).unwrap();
        let key2 = derive_funding_script_key(Some(&AssetId([0xBB; 32]))).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_initial_commitment_blob() {
        let channel = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };

        let blob = initial_commitment_blob(&channel, true);
        assert_eq!(blob.local_assets[0].amount, 1000);
        assert_eq!(blob.remote_assets[0].amount, 0);

        let blob_remote = initial_commitment_blob(&channel, false);
        assert_eq!(blob_remote.local_assets[0].amount, 0);
        assert_eq!(blob_remote.remote_assets[0].amount, 1000);
    }
}
