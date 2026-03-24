// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset leaf signer — signs the TAP-specific parts of commitment
//! transactions.
//!
//! For each HTLC that carries asset balances, the signer produces
//! Schnorr signatures over the virtual asset transaction. These
//! signatures are bundled into the `aux_signatures` blob that travels
//! alongside the standard `CommitmentSigned` message.

use std::collections::BTreeMap;

use lightning::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use tap_primitives::asset::{
    Asset, AssetVersion, Genesis, OutPoint, PrevId, ScriptKey, ScriptVersion,
    Witness,
};
use tap_primitives::crypto::virtual_tx;
use tap_primitives::vm::InputSet;

use super::blobs::{ChannelBlob, CommitmentBlob, HtlcBlob};
use super::traits::{AssetChannelError, AssetLeafSigner};

/// Default implementation of [`AssetLeafSigner`].
///
/// Signs virtual asset transactions for HTLC second-level outputs using
/// BIP-340 Schnorr signatures over BIP-341 virtual transaction sighashes.
pub struct TapAssetLeafSigner {
    /// The signing key for this channel's asset outputs.
    signing_key: SecretKey,
}

impl TapAssetLeafSigner {
    /// Creates a new signer with the given secret key.
    pub fn new(signing_key: SecretKey) -> Self {
        TapAssetLeafSigner { signing_key }
    }

    /// Builds a virtual asset for an HTLC and computes its BIP-341 sighash.
    ///
    /// Constructs the synthetic 1-in-1-out virtual transaction matching
    /// Go's `InputKeySpendSigHash` and returns the 32-byte sighash.
    fn compute_htlc_sighash(
        &self,
        channel_blob: &ChannelBlob,
        htlc_blob: &HtlcBlob,
        htlc_index: usize,
    ) -> Result<[u8; 32], AssetChannelError> {
        let funded = channel_blob.funded_assets.first().ok_or_else(|| {
            AssetChannelError("no funded assets in channel".into())
        })?;

        let total_amount: u64 = htlc_blob.amounts.iter().map(|b| b.amount).sum();

        // Build a prev_id referencing the HTLC input.
        let prev_id = PrevId {
            out_point: OutPoint { txid: [0u8; 32], vout: htlc_index as u32 },
            id: funded.asset_id,
            script_key: funded.script_key,
        };

        // Build the input (previous) asset.
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: Genesis {
                first_prev_out: OutPoint::default(),
                tag: String::new(),
                meta_hash: [0u8; 32],
                output_index: 0,
                asset_type: tap_primitives::asset::AssetType::Normal,
            },
            amount: total_amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(funded.script_key),
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        };

        // Build the new (output) asset for the HTLC second-level tx.
        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: prev_asset.genesis.clone(),
            amount: total_amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(funded.script_key),
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        };

        let mut input_set = InputSet::new();
        input_set.insert(prev_id, prev_asset.clone());

        let (base_tx, _, _) = virtual_tx::virtual_tx(&new_asset, &input_set)
            .map_err(|e| AssetChannelError(format!("virtual tx: {}", e)))?;

        virtual_tx::input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|e| AssetChannelError(format!("sighash: {}", e)))
    }
}

impl AssetLeafSigner for TapAssetLeafSigner {
    fn sign_htlc_second_level(
        &self,
        channel_blob: &ChannelBlob,
        _commitment_blob: &CommitmentBlob,
        htlc_blobs: &[HtlcBlob],
    ) -> Result<Vec<Vec<u8>>, AssetChannelError> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &self.signing_key);

        let mut signatures = Vec::with_capacity(htlc_blobs.len());

        for (idx, htlc_blob) in htlc_blobs.iter().enumerate() {
            if htlc_blob.amounts.is_empty() {
                signatures.push(Vec::new());
                continue;
            }

            let sighash =
                self.compute_htlc_sighash(channel_blob, htlc_blob, idx)?;
            let msg = Message::from_digest(sighash);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

            signatures.push(sig.as_ref().to_vec());
        }

        Ok(signatures)
    }
}

/// Packs HTLC asset signatures into the `aux_signatures` blob for
/// `CommitmentSigned`.
///
/// Format: `[u16 count][for each: u16 sig_len, sig_bytes]`
pub fn pack_aux_signatures(sigs: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(sigs.len() as u16).to_be_bytes());
    for sig in sigs {
        buf.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        buf.extend_from_slice(sig);
    }
    buf
}

/// Unpacks HTLC asset signatures from the `aux_signatures` blob.
pub fn unpack_aux_signatures(data: &[u8]) -> Result<Vec<Vec<u8>>, AssetChannelError> {
    if data.len() < 2 {
        return Err(AssetChannelError("aux_signatures too short".into()));
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut sigs = Vec::with_capacity(count);

    for _ in 0..count {
        if offset + 2 > data.len() {
            return Err(AssetChannelError(
                "aux_signatures truncated".into(),
            ));
        }
        let sig_len =
            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_len > data.len() {
            return Err(AssetChannelError(
                "aux_signatures truncated".into(),
            ));
        }
        sigs.push(data[offset..offset + sig_len].to_vec());
        offset += sig_len;
    }

    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::{AssetBalance, FundedAsset};
    use tap_primitives::asset::AssetId;

    fn test_key() -> SecretKey {
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x42;
        SecretKey::from_slice(&secret).unwrap()
    }

    #[test]
    fn test_sign_htlc_signatures() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xAA; 32]),
                amount: 1000,
                script_key: tap_primitives::asset::SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };
        let commitment = CommitmentBlob {
            local_assets: vec![],
            remote_assets: vec![],
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        };
        let htlc_blobs = vec![
            HtlcBlob {
                amounts: vec![AssetBalance {
                    asset_id: AssetId([0xAA; 32]),
                    amount: 100,
                }],
                rfq_id: Some([0x42; 32]),
            },
            HtlcBlob {
                amounts: vec![AssetBalance {
                    asset_id: AssetId([0xAA; 32]),
                    amount: 50,
                }],
                rfq_id: None,
            },
        ];

        let sigs = signer
            .sign_htlc_second_level(&channel, &commitment, &htlc_blobs)
            .unwrap();

        assert_eq!(sigs.len(), 2);
        // Each Schnorr signature is 64 bytes.
        assert_eq!(sigs[0].len(), 64);
        assert_eq!(sigs[1].len(), 64);
        // Different HTLCs should produce different signatures.
        assert_ne!(sigs[0], sigs[1]);
    }

    #[test]
    fn test_sign_empty_htlc() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = ChannelBlob {
            funded_assets: vec![],
            decimal_display: None,
            group_key: None,
        };
        let commitment = CommitmentBlob {
            local_assets: vec![],
            remote_assets: vec![],
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        };
        let htlc_blobs = vec![HtlcBlob {
            amounts: vec![], // No asset amounts.
            rfq_id: None,
        }];

        let sigs = signer
            .sign_htlc_second_level(&channel, &commitment, &htlc_blobs)
            .unwrap();

        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].is_empty()); // No sig for empty HTLC.
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let sigs = vec![vec![0x01; 64], vec![0x02; 64], vec![]];
        let packed = pack_aux_signatures(&sigs);
        let unpacked = unpack_aux_signatures(&packed).unwrap();
        assert_eq!(sigs, unpacked);
    }

    #[test]
    fn test_deterministic_signatures() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = ChannelBlob {
            funded_assets: vec![FundedAsset {
                asset_id: AssetId([0xBB; 32]),
                amount: 500,
                script_key: tap_primitives::asset::SerializedKey([0x02; 33]),
            }],
            decimal_display: None,
            group_key: None,
        };
        let commitment = CommitmentBlob {
            local_assets: vec![],
            remote_assets: vec![],
            outgoing_htlc_assets: vec![],
            incoming_htlc_assets: vec![],
        };
        let htlc_blobs = vec![HtlcBlob {
            amounts: vec![AssetBalance {
                asset_id: AssetId([0xBB; 32]),
                amount: 200,
            }],
            rfq_id: None,
        }];

        let sigs1 = signer
            .sign_htlc_second_level(&channel, &commitment, &htlc_blobs)
            .unwrap();
        let sigs2 = signer
            .sign_htlc_second_level(&channel, &commitment, &htlc_blobs)
            .unwrap();

        assert_eq!(sigs1, sigs2);
    }
}
