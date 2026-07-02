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
//! Schnorr signatures over the second-level virtual asset transaction.
//! These signatures are bundled into the `aux_signatures` blob (Go
//! `tapchannelmsg.CommitSig`) that travels alongside the standard
//! `CommitmentSigned` message.

use std::collections::BTreeMap;

use lightning::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use tap_primitives::asset::{
    Asset, AssetId, AssetVersion, OutPoint, PrevId, ScriptKey,
    ScriptVersion, Witness,
};
use tap_primitives::crypto::virtual_tx;
use tap_primitives::encoding::bigsize::{decode_bigsize, encode_bigsize};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};
use tap_primitives::vm::InputSet;

use super::allocation::{Allocation, AllocationType};
use super::blobs::{ChannelBlob, CommitmentBlob, HtlcBlob};
use super::traits::{AssetChannelError, AssetLeafSigner};

/// The TLV type of the HTLC partial signature record in a Go
/// `tapchannelmsg.CommitSig` (`HtlcSigsRecordType` = `tlv.TlvType65537`).
pub const HTLC_SIGS_RECORD_TYPE: u64 = 65537;

/// Maximum number of HTLC signature lists accepted when unpacking (Go
/// `tapchannelmsg.MaxNumHTLCs`).
pub const MAX_NUM_HTLC_SIGS: u64 = 966;

/// The sequence Go sets on second-level HTLC inputs for anchor
/// channels (`lnwallet.HtlcSecondLevelInputSequence`); taproot asset
/// channels always use anchors.
pub const HTLC_SECOND_LEVEL_INPUT_SEQUENCE: u32 = 1;

/// An asset-level signature for one asset in an HTLC, matching Go
/// `tapchannelmsg.AssetSig`: a TLV stream `{0: asset_id, 1: 64-byte
/// Schnorr sig, 2: u32 sighash type}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetSig {
    /// The asset the signature is for.
    pub asset_id: AssetId,
    /// The 64-byte BIP-340 Schnorr signature.
    pub sig: [u8; 64],
    /// The sighash type used (0 = default).
    pub sighash_type: u32,
}

impl AssetSig {
    /// Encodes as a Go `AssetSig` TLV stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::bytes(0, &self.asset_id.0));
        stream.push(TlvRecord::bytes(1, &self.sig));
        stream.push(TlvRecord::u32(2, self.sighash_type));
        stream.encode()
    }

    /// Decodes from a Go `AssetSig` TLV stream.
    pub fn decode(data: &[u8]) -> Result<Self, AssetChannelError> {
        let stream = TlvStream::decode(data)
            .map_err(|e| AssetChannelError(format!("asset sig: {}", e)))?;
        let id_record = stream.get(0).ok_or_else(|| {
            AssetChannelError("asset sig missing asset id".into())
        })?;
        if id_record.value.len() != 32 {
            return Err(AssetChannelError(
                "asset sig asset id must be 32 bytes".into(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_record.value);
        let sig_record = stream.get(1).ok_or_else(|| {
            AssetChannelError("asset sig missing signature".into())
        })?;
        if sig_record.value.len() != 64 {
            return Err(AssetChannelError(
                "asset sig must be 64 bytes".into(),
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_record.value);
        let sighash_type = stream
            .get(2)
            .ok_or_else(|| {
                AssetChannelError("asset sig missing sighash type".into())
            })?
            .as_u32()
            .map_err(|e| {
                AssetChannelError(format!("asset sig sighash: {}", e))
            })?;
        Ok(AssetSig {
            asset_id: AssetId(id),
            sig,
            sighash_type,
        })
    }
}

fn write_inline_var_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    encode_bigsize(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn read_inline_var_bytes<'a>(
    data: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], AssetChannelError> {
    let (len, len_size) = decode_bigsize(&data[*offset..])
        .map_err(|e| AssetChannelError(format!("var bytes: {}", e)))?;
    *offset += len_size;
    let end = offset
        .checked_add(len as usize)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| AssetChannelError("aux signatures truncated".into()))?;
    let out = &data[*offset..end];
    *offset = end;
    Ok(out)
}

/// Encodes an `AssetSigListRecord` as Go does when nesting it inside
/// the HTLC partial sigs record: a TLV stream containing a single
/// type 0 record whose value is `varint(count) || varbytes(AssetSig)*`.
fn encode_asset_sig_list(sigs: &[AssetSig]) -> Vec<u8> {
    let mut value = Vec::new();
    encode_bigsize(&mut value, sigs.len() as u64);
    for sig in sigs {
        write_inline_var_bytes(&mut value, &sig.encode());
    }
    let mut stream = TlvStream::new();
    stream.push(TlvRecord::new(0, value));
    stream.encode()
}

fn decode_asset_sig_list(
    data: &[u8],
) -> Result<Vec<AssetSig>, AssetChannelError> {
    let stream = TlvStream::decode(data)
        .map_err(|e| AssetChannelError(format!("sig list: {}", e)))?;
    let record = stream.get(0).ok_or_else(|| {
        AssetChannelError("sig list missing record".into())
    })?;
    let value = &record.value;
    let mut offset = 0usize;
    let (count, count_size) = decode_bigsize(value)
        .map_err(|e| AssetChannelError(format!("sig count: {}", e)))?;
    offset += count_size;
    if count > MAX_NUM_HTLC_SIGS {
        return Err(AssetChannelError(format!(
            "too many signatures: {}",
            count
        )));
    }
    let mut sigs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let bytes = read_inline_var_bytes(value, &mut offset)?;
        sigs.push(AssetSig::decode(bytes)?);
    }
    if offset != value.len() {
        return Err(AssetChannelError(
            "trailing bytes after sig list".into(),
        ));
    }
    Ok(sigs)
}

/// Packs per-HTLC asset signatures into the Go-compatible
/// `tapchannelmsg.CommitSig` blob: a TLV stream `{65537: varint(count)
/// || varbytes(AssetSigListRecord)*}`.
pub fn pack_aux_signatures(htlc_sigs: &[Vec<AssetSig>]) -> Vec<u8> {
    let mut value = Vec::new();
    encode_bigsize(&mut value, htlc_sigs.len() as u64);
    for sigs in htlc_sigs {
        write_inline_var_bytes(&mut value, &encode_asset_sig_list(sigs));
    }
    let mut stream = TlvStream::new();
    stream.push(TlvRecord::new(HTLC_SIGS_RECORD_TYPE, value));
    stream.encode()
}

/// Unpacks per-HTLC asset signatures from a Go-compatible
/// `tapchannelmsg.CommitSig` blob.
pub fn unpack_aux_signatures(
    data: &[u8],
) -> Result<Vec<Vec<AssetSig>>, AssetChannelError> {
    let stream = TlvStream::decode(data)
        .map_err(|e| AssetChannelError(format!("commit sig: {}", e)))?;
    let record = stream.get(HTLC_SIGS_RECORD_TYPE).ok_or_else(|| {
        AssetChannelError("commit sig missing HTLC sigs record".into())
    })?;
    let value = &record.value;
    let (count, mut offset) = decode_bigsize(value)
        .map_err(|e| AssetChannelError(format!("htlc count: {}", e)))?;
    if count > MAX_NUM_HTLC_SIGS {
        return Err(AssetChannelError(format!(
            "too many HTLC sig lists: {}",
            count
        )));
    }
    let mut htlc_sigs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let bytes = read_inline_var_bytes(value, &mut offset)?;
        htlc_sigs.push(decode_asset_sig_list(bytes)?);
    }
    if offset != value.len() {
        return Err(AssetChannelError(
            "trailing bytes after commit sig".into(),
        ));
    }
    Ok(htlc_sigs)
}

/// Parameters for building a second-level HTLC allocation, mirroring
/// the inputs of Go `tapchannel.createSecondLevelHtlcAllocations`.
#[derive(Clone, Debug)]
pub struct SecondLevelHtlcParams {
    /// The HTLC index in the commitment.
    pub htlc_index: u64,
    /// The output index of the HTLC output on the commitment tx.
    pub output_index: u32,
    /// The BTC amount of the HTLC output in satoshis.
    pub btc_amount_sat: u64,
    /// The CLTV timeout of the HTLC (outgoing HTLCs; zero for
    /// incoming).
    pub cltv_timeout: Option<u32>,
    /// The internal key of the second-level output.
    pub internal_key: tap_primitives::asset::SerializedKey,
    /// The (tweaked) script key of the second-level asset output.
    pub script_key: tap_primitives::asset::SerializedKey,
}

/// Builds the [`Allocation`] for a second-level HTLC transaction
/// output, mirroring Go `createSecondLevelHtlcAllocations`.
///
/// The `sequence` is set to the anchor-channel second-level input
/// sequence (1), matching `lnwallet.HtlcSecondLevelInputSequence` for
/// taproot channels.
pub fn create_second_level_htlc_allocation(
    params: &SecondLevelHtlcParams,
    htlc_asset_amount: u64,
) -> Allocation {
    Allocation {
        alloc_type: AllocationType::SecondLevelHtlc,
        output_index: params.output_index,
        amount: htlc_asset_amount,
        asset_version: 1,
        btc_amount: params.btc_amount_sat,
        sequence: HTLC_SECOND_LEVEL_INPUT_SEQUENCE,
        internal_key: Some(params.internal_key),
        script_key: Some(ScriptKey::from_pub_key(params.script_key)),
        sort_taproot_key_bytes: params.script_key.0[1..].to_vec(),
        sort_cltv: params.cltv_timeout.unwrap_or(0),
        lock_time: params.cltv_timeout.unwrap_or(0) as u64,
        htlc_index: params.htlc_index,
        ..Allocation::default()
    }
}

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

    /// Builds the 1-in-1-out second-level virtual asset transition for
    /// an HTLC and computes its BIP-341 sighash.
    ///
    /// The previous outpoint is the real HTLC output on the commitment
    /// transaction (`commitment_txid` + the allocation's output index),
    /// the relative lock time is the allocation's sequence, and the
    /// genesis comes from the channel's funded asset proof.
    pub fn compute_htlc_sighash(
        &self,
        channel_blob: &ChannelBlob,
        htlc_blob: &HtlcBlob,
        allocation: &Allocation,
        commitment_txid: [u8; 32],
    ) -> Result<[u8; 32], AssetChannelError> {
        let funded = channel_blob.funded_assets.first().ok_or_else(|| {
            AssetChannelError("no funded assets in channel".into())
        })?;

        // The genesis must be the real one from the channel's funded
        // asset, carried by its funding proof.
        let genesis = funded
            .proof
            .as_ref()
            .map(|p| p.asset.genesis.clone())
            .ok_or_else(|| {
                AssetChannelError(
                    "funded asset missing proof (genesis unknown)".into(),
                )
            })?;

        let total_amount: u64 =
            htlc_blob.amounts.iter().map(|b| b.amount).sum();

        let script_key = allocation
            .script_key
            .as_ref()
            .map(|k| k.pub_key)
            .unwrap_or(funded.script_key);

        // The real previous outpoint: the HTLC output on the commitment
        // transaction.
        let prev_id = PrevId {
            out_point: OutPoint {
                txid: commitment_txid,
                vout: allocation.output_index,
            },
            id: funded.asset_id,
            script_key: funded.script_key,
        };

        // Build the input (previous) asset: the HTLC output asset on
        // the commitment transaction.
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
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
        // The relative lock time mirrors the allocation sequence and
        // the lock time mirrors the CLTV (Go sets vOut.LockTime to the
        // HTLC timeout).
        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis,
            amount: total_amount,
            lock_time: allocation.lock_time,
            relative_lock_time: allocation.sequence as u64,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(script_key),
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
        commitment_txid: [u8; 32],
    ) -> Result<Vec<Vec<AssetSig>>, AssetChannelError> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &self.signing_key);

        let funded = channel_blob.funded_assets.first();

        let mut signatures = Vec::with_capacity(htlc_blobs.len());

        for (idx, htlc_blob) in htlc_blobs.iter().enumerate() {
            if htlc_blob.amounts.is_empty() {
                signatures.push(Vec::new());
                continue;
            }
            let funded = funded.ok_or_else(|| {
                AssetChannelError("no funded assets in channel".into())
            })?;

            let total: u64 =
                htlc_blob.amounts.iter().map(|b| b.amount).sum();
            let params = SecondLevelHtlcParams {
                htlc_index: idx as u64,
                output_index: idx as u32,
                btc_amount_sat: 354,
                cltv_timeout: None,
                internal_key: funded.script_key,
                script_key: funded.script_key,
            };
            let allocation =
                create_second_level_htlc_allocation(&params, total);

            let sighash = self.compute_htlc_sighash(
                channel_blob,
                htlc_blob,
                &allocation,
                commitment_txid,
            )?;
            let msg = Message::from_digest(sighash);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(sig.as_ref());
            signatures.push(vec![AssetSig {
                asset_id: funded.asset_id,
                sig: sig_bytes,
                sighash_type: 0,
            }]);
        }

        Ok(signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::blobs::AssetBalance;
    use tap_primitives::asset::SerializedKey;

    fn test_key() -> SecretKey {
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x42;
        SecretKey::from_slice(&secret).unwrap()
    }

    fn test_channel(asset_byte: u8) -> ChannelBlob {
        let script_key = SerializedKey([0x02; 33]);
        ChannelBlob {
            funded_assets: vec![crate::channel::blobs::AssetOutput {
                asset_id: tap_primitives::asset::AssetId([asset_byte; 32]),
                amount: 1000,
                script_key,
                proof: Some(crate::channel::blobs::tests::test_proof(
                    asset_byte,
                    1000,
                    script_key,
                )),
            }],
            decimal_display: 0,
            group_key: None,
        }
    }

    fn empty_commitment() -> CommitmentBlob {
        CommitmentBlob::default()
    }

    #[test]
    fn test_sign_htlc_signatures() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = test_channel(0xAA);
        let commitment = empty_commitment();
        let htlc_blobs = vec![
            HtlcBlob {
                amounts: vec![AssetBalance {
                    asset_id: tap_primitives::asset::AssetId([0xAA; 32]),
                    amount: 100,
                }],
                rfq_id: Some([0x42; 32]),
            },
            HtlcBlob {
                amounts: vec![AssetBalance {
                    asset_id: tap_primitives::asset::AssetId([0xAA; 32]),
                    amount: 50,
                }],
                rfq_id: None,
            },
        ];

        let sigs = signer
            .sign_htlc_second_level(
                &channel,
                &commitment,
                &htlc_blobs,
                [0x09; 32],
            )
            .unwrap();

        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].len(), 1);
        assert_eq!(sigs[1].len(), 1);
        // Different HTLCs should produce different signatures.
        assert_ne!(sigs[0][0].sig, sigs[1][0].sig);
    }

    #[test]
    fn test_sighash_depends_on_commitment_txid_and_index() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = test_channel(0xAA);
        let htlc = HtlcBlob {
            amounts: vec![AssetBalance {
                asset_id: tap_primitives::asset::AssetId([0xAA; 32]),
                amount: 100,
            }],
            rfq_id: None,
        };
        let funded_key = channel.funded_assets[0].script_key;
        let params = SecondLevelHtlcParams {
            htlc_index: 0,
            output_index: 2,
            btc_amount_sat: 354,
            cltv_timeout: Some(800_000),
            internal_key: funded_key,
            script_key: funded_key,
        };
        let alloc = create_second_level_htlc_allocation(&params, 100);
        assert_eq!(alloc.alloc_type.to_u8(), 5);
        assert_eq!(alloc.sequence, HTLC_SECOND_LEVEL_INPUT_SEQUENCE);

        let h1 = signer
            .compute_htlc_sighash(&channel, &htlc, &alloc, [0x01; 32])
            .unwrap();
        let h2 = signer
            .compute_htlc_sighash(&channel, &htlc, &alloc, [0x02; 32])
            .unwrap();
        assert_ne!(h1, h2, "sighash must commit to the commitment txid");

        let mut alloc_other_index = alloc.clone();
        alloc_other_index.output_index = 3;
        let h3 = signer
            .compute_htlc_sighash(
                &channel,
                &htlc,
                &alloc_other_index,
                [0x01; 32],
            )
            .unwrap();
        assert_ne!(h1, h3, "sighash must commit to the output index");
    }

    #[test]
    fn test_missing_proof_errors() {
        let signer = TapAssetLeafSigner::new(test_key());
        let mut channel = test_channel(0xAA);
        channel.funded_assets[0].proof = None;
        let htlc = HtlcBlob {
            amounts: vec![AssetBalance {
                asset_id: tap_primitives::asset::AssetId([0xAA; 32]),
                amount: 100,
            }],
            rfq_id: None,
        };
        let funded_key = channel.funded_assets[0].script_key;
        let params = SecondLevelHtlcParams {
            htlc_index: 0,
            output_index: 0,
            btc_amount_sat: 354,
            cltv_timeout: None,
            internal_key: funded_key,
            script_key: funded_key,
        };
        let alloc = create_second_level_htlc_allocation(&params, 100);
        assert!(signer
            .compute_htlc_sighash(&channel, &htlc, &alloc, [0; 32])
            .is_err());
    }

    #[test]
    fn test_sign_empty_htlc() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = ChannelBlob {
            funded_assets: vec![],
            decimal_display: 0,
            group_key: None,
        };
        let htlc_blobs = vec![HtlcBlob {
            amounts: vec![],
            rfq_id: None,
        }];

        let sigs = signer
            .sign_htlc_second_level(
                &channel,
                &empty_commitment(),
                &htlc_blobs,
                [0; 32],
            )
            .unwrap();

        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].is_empty()); // No sig for empty HTLC.
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let htlc_sigs = vec![
            vec![AssetSig {
                asset_id: tap_primitives::asset::AssetId([0xAA; 32]),
                sig: [0x01; 64],
                sighash_type: 0,
            }],
            vec![
                AssetSig {
                    asset_id: tap_primitives::asset::AssetId([0xBB; 32]),
                    sig: [0x02; 64],
                    sighash_type: 1,
                },
                AssetSig {
                    asset_id: tap_primitives::asset::AssetId([0xCC; 32]),
                    sig: [0x03; 64],
                    sighash_type: 0,
                },
            ],
            vec![],
        ];
        let packed = pack_aux_signatures(&htlc_sigs);
        let unpacked = unpack_aux_signatures(&packed).unwrap();
        assert_eq!(htlc_sigs, unpacked);
    }

    #[test]
    fn test_pack_format_is_go_commit_sig() {
        // An empty CommitSig is a single TLV record 65537 with a
        // zero-count varint value.
        let packed = pack_aux_signatures(&[]);
        // Type 65537 encodes as BigSize fe 00 01 00 01, length 1,
        // value 00.
        assert_eq!(packed, vec![0xfe, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_deterministic_signatures() {
        let signer = TapAssetLeafSigner::new(test_key());
        let channel = test_channel(0xBB);
        let htlc_blobs = vec![HtlcBlob {
            amounts: vec![AssetBalance {
                asset_id: tap_primitives::asset::AssetId([0xBB; 32]),
                amount: 200,
            }],
            rfq_id: None,
        }];

        let sigs1 = signer
            .sign_htlc_second_level(
                &channel,
                &empty_commitment(),
                &htlc_blobs,
                [0x05; 32],
            )
            .unwrap();
        let sigs2 = signer
            .sign_htlc_second_level(
                &channel,
                &empty_commitment(),
                &htlc_blobs,
                [0x05; 32],
            )
            .unwrap();

        assert_eq!(sigs1, sigs2);
    }
}
