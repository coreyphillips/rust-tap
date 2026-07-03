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
use std::sync::Mutex;

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::asset::{AssetId, SerializedKey};
use tap_primitives::crypto::keys;
use tap_primitives::crypto::pedersen::TAPROOT_NUMS_BYTES;
use tap_primitives::proof::{decode_proof, File, Proof};

use super::blobs::{AssetBalance, ChannelBlob, CommitmentBlob, FundedAsset};
use super::traits::{AssetChannelError, AssetFundingController};
use crate::wire::{AssetFundingAck, AssetFundingCreated, TapMessage};

/// Default implementation of [`AssetFundingController`].
///
/// Tracks pending asset channel opens on both the initiator and the
/// responder side and produces the channel blob after funding is
/// confirmed.
pub struct TapAssetFundingController {
    /// Pending funding proposals keyed by temporary channel ID.
    pending: Mutex<HashMap<[u8; 32], PendingFunding>>,
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
    /// The latest transition proof of the funding input, decoded from
    /// the proposal's proof file.
    proof: Option<Proof>,
}

impl TapAssetFundingController {
    pub fn new() -> Self {
        TapAssetFundingController {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Initiates an asset channel funding by creating the funding message.
    ///
    /// `proof_data` must contain the encoded proof FILE for the input
    /// assets being committed to the channel. The counterparty uses it
    /// to verify the channel's asset backing.
    pub fn initiate_funding(
        &self,
        pending_channel_id: [u8; 32],
        asset_id: AssetId,
        amount: u64,
        group_key: Option<SerializedKey>,
        proof_data: Vec<u8>,
    ) -> TapMessage {
        // Keep the decoded final proof for our own channel blob, when
        // the proof data parses.
        let proof = decode_last_proof(&proof_data).ok();

        self.pending.lock().expect("poisoned").insert(
            pending_channel_id,
            PendingFunding {
                asset_id,
                amount,
                group_key,
                proof,
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

/// Decodes `proof_data` as a proof file and returns its final proof.
fn decode_last_proof(proof_data: &[u8]) -> Result<Proof, AssetChannelError> {
    let file = File::decode(proof_data)
        .map_err(|e| AssetChannelError(format!("proof file: {}", e)))?;
    let last = file.last_proof().ok_or_else(|| {
        AssetChannelError("proof file contains no proofs".into())
    })?;
    if !file.verify_hash_chain() {
        return Err(AssetChannelError(
            "proof file hash chain invalid".into(),
        ));
    }
    decode_proof(&last.proof_bytes)
        .map_err(|e| AssetChannelError(format!("final proof: {}", e)))
}

/// Validates an incoming funding proposal's proof data against the
/// proposal fields. Returns the decoded final proof on success.
fn validate_funding_proposal(
    created: &AssetFundingCreated,
) -> Result<Proof, String> {
    if created.proof_data.is_empty() {
        return Err("funding proposal missing proof data".into());
    }
    let proof = decode_last_proof(&created.proof_data)
        .map_err(|e| format!("invalid proof data: {}", e))?;

    let proof_asset_id = proof.asset.genesis.id();
    if proof_asset_id != created.asset_id {
        return Err(format!(
            "proof asset id mismatch: proof {:02x?}, proposal {:02x?}",
            &proof_asset_id.0[..4],
            &created.asset_id.0[..4]
        ));
    }
    if proof.asset.amount < created.amount {
        return Err(format!(
            "proof amount {} below proposed channel amount {}",
            proof.asset.amount, created.amount
        ));
    }
    Ok(proof)
}

/// Derives the funding script key for an asset channel.
///
/// Mirrors Go's `tapscript.NewChannelFundingScriptTreeUniqueID`
/// (tapscript/script.go):
/// - leaf 0: `OP_TRUE` (0x51), leaf version 0xC0
/// - leaf 1: `OP_RETURN <32-byte asset id>` (`6a20 || id`), version 0xC0
/// - tapscript root: BIP-341 TapBranch of the two leaf hashes (sorted
///   lexicographically before hashing)
/// - internal key: lnd's `input.TaprootNUMSKey`
///   (02dca094...a279), NOT the taproot-assets asset NUMS key
/// - output key: BIP-341 taptweak of the internal key with the root
///
/// The returned key is the compressed 33-byte output key with the REAL
/// parity byte from the tweak (0x02 or 0x03).
fn derive_funding_script_key(
    asset_id: Option<&AssetId>,
) -> Result<SerializedKey, AssetChannelError> {
    // OP_TRUE (0x51) as the anyone-can-spend tapscript.
    let op_true_script = [0x51u8];

    // BIP-341 tapleaf hash: SHA256(SHA256("TapLeaf") || SHA256("TapLeaf")
    // || leaf_version || compact_size(script_len) || script)
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

        // BIP-341 tapbranch: SHA256(SHA256("TapBranch") ||
        // SHA256("TapBranch") || sorted(left, right))
        let tapbranch_tag = sha256::Hash::hash(b"TapBranch");
        let mut engine3 = sha256::HashEngine::default();
        engine3.input(tapbranch_tag.as_ref());
        engine3.input(tapbranch_tag.as_ref());
        // Lexicographic sort of the two leaf hashes.
        let (first, second) =
            if leaf_hash.to_byte_array() <= leaf2_hash.to_byte_array() {
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

    // Parse lnd's Taproot NUMS key (input.TaprootNUMSKey) and extract
    // the x-only form. Go uses this key for channel funding outputs,
    // NOT the taproot-assets asset NUMS key.
    let nums_pub = keys::parse_pub_key(&SerializedKey(TAPROOT_NUMS_BYTES))
        .map_err(|e| AssetChannelError(format!("invalid NUMS key: {}", e)))?;
    let (nums_x_only, _parity) = nums_pub.x_only_public_key();

    // Tweak with the tapscript root to get the output key.
    let (tweaked_key, parity) =
        keys::tweak_pub_key(&nums_x_only, Some(&tapscript_root))
            .map_err(|e| AssetChannelError(format!("tweak failed: {}", e)))?;

    // Serialize as a compressed public key using the REAL parity of the
    // tweaked key. Hardcoding 0x02 here would produce a key that fails
    // to match the on-chain output about half the time.
    let mut serialized = [0u8; 33];
    serialized[0] = match parity {
        lightning::bitcoin::secp256k1::Parity::Even => 0x02,
        lightning::bitcoin::secp256k1::Parity::Odd => 0x03,
    };
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
            TapMessage::AssetFundingCreated(created) => {
                // Responder receives the funding proposal: validate the
                // asset proofs against the proposal before accepting.
                match validate_funding_proposal(created) {
                    Ok(proof) => {
                        // Record pending state so finalize_funding
                        // works on the responder side too.
                        self.pending.lock().expect("poisoned").insert(
                            created.pending_channel_id,
                            PendingFunding {
                                asset_id: created.asset_id,
                                amount: created.amount,
                                group_key: created.group_key,
                                proof: Some(proof),
                            },
                        );
                        Ok(Some(TapMessage::AssetFundingAck(
                            AssetFundingAck {
                                pending_channel_id: created
                                    .pending_channel_id,
                                accepted: true,
                                reject_reason: None,
                            },
                        )))
                    }
                    Err(reason) => Ok(Some(TapMessage::AssetFundingAck(
                        AssetFundingAck {
                            pending_channel_id: created.pending_channel_id,
                            accepted: false,
                            reject_reason: Some(reason),
                        },
                    ))),
                }
            }
            TapMessage::AssetFundingAck(ack) => {
                if !ack.accepted {
                    // Clear the pending state for the rejected channel.
                    self.pending
                        .lock()
                        .expect("poisoned")
                        .remove(pending_channel_id);
                    return Err(AssetChannelError(format!(
                        "funding rejected: {}",
                        ack.reject_reason.as_deref().unwrap_or("unknown")
                    )));
                }
                // Initiator receives acknowledgment.
                Ok(None)
            }
            TapMessage::AssetFundingProof(proof_msg) => {
                // Final proof exchange after the funding tx is
                // constructed: update the pending proof state.
                if let Ok(proof) = decode_last_proof(&proof_msg.proof_data) {
                    let mut pending = self.pending.lock().expect("poisoned");
                    if let Some(state) =
                        pending.get_mut(&proof_msg.pending_channel_id)
                    {
                        state.proof = Some(proof);
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn finalize_funding(
        &self,
        pending_channel_id: &[u8; 32],
    ) -> Result<ChannelBlob, AssetChannelError> {
        let pending_map = self.pending.lock().expect("poisoned");
        let pending = pending_map.get(pending_channel_id).ok_or_else(|| {
            AssetChannelError("no pending funding".into())
        })?;

        let script_key = derive_funding_script_key(Some(&pending.asset_id))?;

        Ok(ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: pending.asset_id,
                amount: pending.amount,
                script_key,
                proof: pending.proof.clone(),
            }],
            decimal_display: 0,
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
    let outputs: Vec<FundedAsset> = channel_blob.funded_assets.clone();

    if initiator_is_local {
        CommitmentBlob {
            local_assets: outputs,
            remote_assets: vec![],
            ..CommitmentBlob::default()
        }
    } else {
        CommitmentBlob {
            local_assets: vec![],
            remote_assets: outputs,
            ..CommitmentBlob::default()
        }
    }
}

/// Returns simple (asset id, amount) balances for a set of outputs.
pub fn output_balances(outputs: &[FundedAsset]) -> Vec<AssetBalance> {
    outputs
        .iter()
        .map(|o| AssetBalance {
            asset_id: o.asset_id,
            amount: o.amount,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::tests::test_proof;
    use tap_primitives::proof::encode_proof;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn proof_file_for(asset_id_byte: u8, amount: u64) -> (Vec<u8>, AssetId) {
        let script_key = SerializedKey([0x02; 33]);
        let proof = test_proof(asset_id_byte, amount, script_key);
        let asset_id = proof.asset.genesis.id();
        let mut file = File::new();
        file.append_proof(encode_proof(&proof));
        (file.encode(), asset_id)
    }

    #[test]
    fn test_initiate_funding() {
        let controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];
        let (proof_data, asset_id) = proof_file_for(0xAA, 1000);

        let msg = controller.initiate_funding(
            channel_id,
            asset_id,
            1000,
            None,
            proof_data.clone(),
        );

        assert!(matches!(msg, TapMessage::AssetFundingCreated(_)));
        if let TapMessage::AssetFundingCreated(created) = msg {
            assert_eq!(created.amount, 1000);
            assert_eq!(created.proof_data, proof_data);
        }
    }

    #[test]
    fn test_handle_funding_created_valid_proof() {
        let controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];
        let (proof_data, asset_id) = proof_file_for(0xAA, 1000);

        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id,
            amount: 1000,
            proof_data,
            group_key: None,
        });

        let response =
            controller.handle_funding_msg(&channel_id, &msg).unwrap();
        match response {
            Some(TapMessage::AssetFundingAck(ack)) => {
                assert!(ack.accepted, "{:?}", ack.reject_reason);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // The responder can now finalize the funding.
        let blob = controller.finalize_funding(&channel_id).unwrap();
        assert_eq!(blob.funded_assets.len(), 1);
        assert!(blob.funded_assets[0].proof.is_some());
    }

    #[test]
    fn test_handle_funding_created_rejects_bad_proofs() {
        let controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];

        // Empty proof data.
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id: AssetId([0xAA; 32]),
            amount: 1000,
            proof_data: vec![],
            group_key: None,
        });
        match controller.handle_funding_msg(&channel_id, &msg).unwrap() {
            Some(TapMessage::AssetFundingAck(ack)) => {
                assert!(!ack.accepted);
                assert!(ack.reject_reason.is_some());
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Garbage proof data.
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id: AssetId([0xAA; 32]),
            amount: 1000,
            proof_data: vec![0xde, 0xad, 0xbe, 0xef],
            group_key: None,
        });
        match controller.handle_funding_msg(&channel_id, &msg).unwrap() {
            Some(TapMessage::AssetFundingAck(ack)) => {
                assert!(!ack.accepted);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Asset ID mismatch.
        let (proof_data, _) = proof_file_for(0xAA, 1000);
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id: AssetId([0x11; 32]), // Wrong asset id.
            amount: 1000,
            proof_data: proof_data.clone(),
            group_key: None,
        });
        match controller.handle_funding_msg(&channel_id, &msg).unwrap() {
            Some(TapMessage::AssetFundingAck(ack)) => {
                assert!(!ack.accepted);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // Amount larger than the proof backs.
        let (proof_data, asset_id) = proof_file_for(0xAA, 500);
        let msg = TapMessage::AssetFundingCreated(AssetFundingCreated {
            pending_channel_id: channel_id,
            asset_id,
            amount: 1000,
            proof_data,
            group_key: None,
        });
        match controller.handle_funding_msg(&channel_id, &msg).unwrap() {
            Some(TapMessage::AssetFundingAck(ack)) => {
                assert!(!ack.accepted);
            }
            other => panic!("unexpected response: {:?}", other),
        }

        // No pending state was recorded for the rejected proposals.
        assert!(controller.finalize_funding(&channel_id).is_err());
    }

    #[test]
    fn test_finalize_funding() {
        let controller = TapAssetFundingController::new();
        let channel_id = [0x01; 32];
        let (proof_data, asset_id) = proof_file_for(0xAA, 1000);

        controller.initiate_funding(
            channel_id,
            asset_id,
            1000,
            None,
            proof_data,
        );

        let blob = controller.finalize_funding(&channel_id).unwrap();
        assert_eq!(blob.funded_assets.len(), 1);
        assert_eq!(blob.funded_assets[0].amount, 1000);
        // Script key should be derived, not the placeholder.
        assert_ne!(
            blob.funded_assets[0].script_key,
            SerializedKey([0x02; 33])
        );
        // Proof is carried into the channel blob.
        assert!(blob.funded_assets[0].proof.is_some());
    }

    /// Golden test against Go `tapscript.NewChannelFundingScriptTreeUniqueID`.
    ///
    /// The expected values were generated by executing the real Go
    /// package (a scratch module with a `replace` directive pointing at
    /// the local taproot-assets checkout) for the fixed asset IDs
    /// below. The tree is OP_TRUE leaf + OP_RETURN <asset id> leaf over
    /// lnd's TaprootNUMSKey internal key
    /// (02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279).
    #[test]
    fn test_derive_funding_script_key_golden() {
        // Asset ID 1: 32 bytes of 0xAA.
        let key1 = derive_funding_script_key(Some(&AssetId([0xAA; 32])))
            .unwrap();
        assert_eq!(
            key1.0.to_vec(),
            hex_decode(
                "0398323abe0db235a7d8fb48e0b816fb555806bbe4f4c54084638c61e\
                 64ba04929"
            ),
        );

        // Asset ID 2: bytes 0x00..0x1F.
        let mut id2 = [0u8; 32];
        for (i, b) in id2.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key2 = derive_funding_script_key(Some(&AssetId(id2))).unwrap();
        assert_eq!(
            key2.0.to_vec(),
            hex_decode(
                "03e98f9ea6c53e4eca9c525dc61becf92a9222f89129a5064d6d8e70d\
                 11883ec18"
            ),
        );

        // Both golden keys happen to have odd parity (0x03): the old
        // code that hardcoded 0x02 produced the wrong key here.
        assert_eq!(key1.0[0], 0x03);
        assert_eq!(key2.0[0], 0x03);
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
        let key1 =
            derive_funding_script_key(Some(&AssetId([0xAA; 32]))).unwrap();
        let key2 =
            derive_funding_script_key(Some(&AssetId([0xBB; 32]))).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_initial_commitment_blob() {
        let script_key = SerializedKey([0x02; 33]);
        let channel = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key,
                proof: Some(test_proof(0xAA, 1000, script_key)),
            }],
            decimal_display: 0,
            group_key: None,
        };

        let blob = initial_commitment_blob(&channel, true);
        assert_eq!(blob.local_assets[0].amount, 1000);
        assert!(blob.remote_assets.is_empty());

        let blob_remote = initial_commitment_blob(&channel, false);
        assert!(blob_remote.local_assets.is_empty());
        assert_eq!(blob_remote.remote_assets[0].amount, 1000);
    }
}
