// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TLV encoding for transition proofs, compatible with Go's `tapd`.
//!
//! Produces binary proof data prefixed with the "TAPP" magic bytes,
//! followed by a TLV stream containing all proof fields.

use crate::asset::{EncodeType, GroupKeyReveal};
use crate::commitment::CommitmentProof;
use crate::encoding::asset::{
    encode_alt_leaf, encode_asset, encode_genesis, encode_tx_witness,
};
use crate::encoding::bigsize::encode_bigsize;
use crate::encoding::tlv::{encode_var_bytes, TlvRecord, TlvStream};
use crate::proof::meta::MetaReveal;
use crate::proof::tx_merkle::TxMerkleProof;
use crate::proof::types::{Proof, TaprootProof, TapscriptProof};
use crate::proof::file::PROOF_MAGIC_BYTES;

/// TLV type numbers for proof fields (matches Go's `records.go`).
pub(crate) mod tlv_types {
    pub const VERSION: u64 = 0;
    pub const PREV_OUT: u64 = 2;
    pub const BLOCK_HEADER: u64 = 4;
    pub const ANCHOR_TX: u64 = 6;
    pub const TX_MERKLE_PROOF: u64 = 8;
    pub const ASSET: u64 = 10;
    pub const INCLUSION_PROOF: u64 = 12;
    pub const EXCLUSION_PROOFS: u64 = 13;
    pub const SPLIT_ROOT_PROOF: u64 = 15;
    pub const META_REVEAL: u64 = 17;
    pub const ADDITIONAL_INPUTS: u64 = 19;
    pub const CHALLENGE_WITNESS: u64 = 21;
    pub const BLOCK_HEIGHT: u64 = 22;
    pub const GENESIS_REVEAL: u64 = 23;
    pub const GROUP_KEY_REVEAL: u64 = 25;
    pub const ALT_LEAVES: u64 = 27;
}

/// TLV types for TaprootProof sub-records (Go's proof/records.go).
pub(crate) mod taproot_tlv {
    pub const OUTPUT_INDEX: u64 = 0;
    pub const INTERNAL_KEY: u64 = 2;
    pub const COMMITMENT_PROOF: u64 = 3;
    pub const TAPSCRIPT_PROOF: u64 = 5;
}

/// TLV types for CommitmentProof sub-records. Types 1 and 2 come from
/// Go's commitment/records.go; types 5 and 7 continue the numbering in
/// proof/records.go (`CommitmentProofTapSiblingPreimageType` and
/// `CommitmentProofSTXOProofsType`).
pub(crate) mod commitment_tlv {
    pub const ASSET_PROOF: u64 = 1;
    pub const TAP_PROOF: u64 = 2;
    pub const TAP_SIBLING: u64 = 5;
    pub const STXO_PROOFS: u64 = 7;
}

/// TLV types for TapscriptProof sub-records (Go's proof/records.go
/// TapscriptProofTapPreimage1/2 and TapscriptProofBip86).
pub(crate) mod tapscript_tlv {
    pub const TAP_PREIMAGE_1: u64 = 1;
    pub const TAP_PREIMAGE_2: u64 = 3;
    pub const BIP86: u64 = 4;
}

/// Encodes a `Proof` to tapd-compatible binary TLV format.
///
/// The output starts with the "TAPP" magic bytes followed by a TLV stream
/// containing all proof fields. This matches Go's `Proof.Encode()`.
pub fn encode_proof(proof: &Proof) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PROOF_MAGIC_BYTES);

    let mut stream = TlvStream::new();

    // Type 0: Version (u32 BE).
    stream.push(TlvRecord::u32(tlv_types::VERSION, proof.version as u32));

    // Type 2: PrevOut (32B txid + 4B vout BE = 36 bytes).
    let mut prev_out = Vec::with_capacity(36);
    prev_out.extend_from_slice(&proof.prev_out.txid);
    prev_out.extend_from_slice(&proof.prev_out.vout.to_be_bytes());
    stream.push(TlvRecord::bytes(tlv_types::PREV_OUT, &prev_out));

    // Type 4: BlockHeader (80 bytes raw).
    stream.push(TlvRecord::bytes(
        tlv_types::BLOCK_HEADER,
        proof.block_header.as_bytes(),
    ));

    // Type 6: AnchorTx (variable length raw tx bytes).
    stream.push(TlvRecord::bytes(
        tlv_types::ANCHOR_TX,
        proof.anchor_tx.as_bytes(),
    ));

    // Type 8: TxMerkleProof.
    stream.push(TlvRecord::bytes(
        tlv_types::TX_MERKLE_PROOF,
        &encode_tx_merkle_proof(&proof.tx_merkle_proof),
    ));

    // Type 10: Asset (TLV-encoded).
    stream.push(TlvRecord::bytes(
        tlv_types::ASSET,
        &encode_asset(&proof.asset, EncodeType::Normal),
    ));

    // Type 12: InclusionProof.
    stream.push(TlvRecord::bytes(
        tlv_types::INCLUSION_PROOF,
        &encode_taproot_proof(&proof.inclusion_proof),
    ));

    // Type 13: ExclusionProofs (optional, odd type).
    if !proof.exclusion_proofs.is_empty() {
        let mut ex_buf = Vec::new();
        encode_bigsize(&mut ex_buf, proof.exclusion_proofs.len() as u64);
        for ep in &proof.exclusion_proofs {
            let encoded = encode_taproot_proof(ep);
            encode_var_bytes(&mut ex_buf, &encoded);
        }
        stream.push(TlvRecord::bytes(tlv_types::EXCLUSION_PROOFS, &ex_buf));
    }

    // Type 15: SplitRootProof (optional).
    if let Some(ref srp) = proof.split_root_proof {
        stream.push(TlvRecord::bytes(
            tlv_types::SPLIT_ROOT_PROOF,
            &encode_taproot_proof(srp),
        ));
    }

    // Type 17: MetaReveal (optional).
    if let Some(ref meta) = proof.meta_reveal {
        stream.push(TlvRecord::bytes(
            tlv_types::META_REVEAL,
            &encode_meta_reveal(meta),
        ));
    }

    // Type 19: AdditionalInputs (optional).
    if !proof.additional_inputs.is_empty() {
        let mut ai_buf = Vec::new();
        encode_bigsize(&mut ai_buf, proof.additional_inputs.len() as u64);
        for file in &proof.additional_inputs {
            let encoded = file.encode();
            encode_var_bytes(&mut ai_buf, &encoded);
        }
        stream.push(TlvRecord::bytes(
            tlv_types::ADDITIONAL_INPUTS,
            &ai_buf,
        ));
    }

    // Type 21: ChallengeWitness (optional). Encoded as a Bitcoin-style
    // witness stack, matching Go's ChallengeWitnessRecord which uses
    // asset.TxWitnessEncoder (proof/records.go).
    if let Some(ref witness) = proof.challenge_witness {
        stream.push(TlvRecord::bytes(
            tlv_types::CHALLENGE_WITNESS,
            &encode_tx_witness(witness),
        ));
    }

    // Type 22: BlockHeight (u32 BE).
    stream.push(TlvRecord::u32(tlv_types::BLOCK_HEIGHT, proof.block_height));

    // Type 23: GenesisReveal (optional).
    if let Some(ref genesis) = proof.genesis_reveal {
        stream.push(TlvRecord::bytes(
            tlv_types::GENESIS_REVEAL,
            &encode_genesis(genesis),
        ));
    }

    // Type 25: GroupKeyReveal (optional).
    if let Some(ref gkr) = proof.group_key_reveal {
        stream.push(TlvRecord::bytes(
            tlv_types::GROUP_KEY_REVEAL,
            &encode_group_key_reveal(gkr),
        ));
    }

    // Type 27: AltLeaves (optional). Wire format (Go's
    // asset.AltLeavesEncoder): BigSize count, then per leaf
    // var_bytes(alt-leaf TLV stream).
    if !proof.alt_leaves.is_empty() {
        let mut al_buf = Vec::new();
        encode_bigsize(&mut al_buf, proof.alt_leaves.len() as u64);
        for leaf in &proof.alt_leaves {
            let encoded = encode_alt_leaf(leaf);
            encode_var_bytes(&mut al_buf, &encoded);
        }
        stream.push(TlvRecord::bytes(tlv_types::ALT_LEAVES, &al_buf));
    }

    // Unknown odd types (forward compatibility).
    for (&type_num, value) in &proof.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    buf.extend_from_slice(&stream.encode());
    buf
}

/// Encodes a `TaprootProof` to TLV bytes.
pub fn encode_taproot_proof(tp: &TaprootProof) -> Vec<u8> {
    let mut stream = TlvStream::new();

    // Type 0: OutputIndex (u32 BE).
    stream.push(TlvRecord::u32(taproot_tlv::OUTPUT_INDEX, tp.output_index));

    // Type 2: InternalKey (33 bytes compressed).
    stream.push(TlvRecord::bytes(
        taproot_tlv::INTERNAL_KEY,
        tp.internal_key.as_bytes(),
    ));

    // Type 3: CommitmentProof (optional, for inclusion proofs).
    if let Some(ref cp) = tp.commitment_proof {
        stream.push(TlvRecord::bytes(
            taproot_tlv::COMMITMENT_PROOF,
            &encode_commitment_proof(cp),
        ));
    }

    // Type 5: TapscriptProof (optional, for exclusion proofs on outputs
    // that carry no Taproot Asset commitment). Go only encodes this when
    // no commitment proof is present (proof/taproot.go EncodeRecords).
    if tp.commitment_proof.is_none() {
        if let Some(ref ts) = tp.tapscript_proof {
            stream.push(TlvRecord::bytes(
                taproot_tlv::TAPSCRIPT_PROOF,
                &encode_tapscript_proof(ts),
            ));
        }
    }

    // Unknown odd types.
    for (&type_num, value) in &tp.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    stream.encode()
}

/// Encodes a `TapscriptProof` to TLV bytes.
///
/// Matches Go's `TapscriptProof.EncodeRecords` (proof/taproot.go):
/// preimages 1 and 2 are only emitted when present and non-empty, while
/// the BIP-86 flag record is always emitted.
pub fn encode_tapscript_proof(ts: &TapscriptProof) -> Vec<u8> {
    let mut stream = TlvStream::new();

    if let Some(ref p1) = ts.tap_preimage_1 {
        if !p1.is_empty() {
            stream.push(TlvRecord::bytes(
                tapscript_tlv::TAP_PREIMAGE_1,
                &p1.encode(),
            ));
        }
    }

    if let Some(ref p2) = ts.tap_preimage_2 {
        if !p2.is_empty() {
            stream.push(TlvRecord::bytes(
                tapscript_tlv::TAP_PREIMAGE_2,
                &p2.encode(),
            ));
        }
    }

    // The BIP-86 record is always emitted (Go appends
    // TapscriptProofBip86Record unconditionally).
    stream.push(TlvRecord::u8(
        tapscript_tlv::BIP86,
        u8::from(ts.bip86),
    ));

    for (&type_num, value) in &ts.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    stream.encode()
}

/// Encodes a BIP-86 tapscript exclusion proof.
///
/// This proves a P2TR output is a bare key-spend output (BIP-86) with
/// no tapscript tree, and therefore cannot contain a TAP commitment.
pub fn encode_bip86_exclusion_proof(
    output_index: u32,
    internal_key: &crate::asset::SerializedKey,
) -> Vec<u8> {
    let mut stream = TlvStream::new();

    // Type 0: OutputIndex.
    stream.push(TlvRecord::u32(taproot_tlv::OUTPUT_INDEX, output_index));

    // Type 2: InternalKey.
    stream.push(TlvRecord::bytes(
        taproot_tlv::INTERNAL_KEY,
        internal_key.as_bytes(),
    ));

    // Type 5: TapscriptProof (BIP-86 flag).
    // TapscriptProof is a TLV stream with type 4 = bip86 (bool, 1 byte).
    let mut ts_stream = TlvStream::new();
    ts_stream.push(TlvRecord::u8(4, 1)); // bip86 = true
    stream.push(TlvRecord::bytes(
        taproot_tlv::TAPSCRIPT_PROOF,
        &ts_stream.encode(),
    ));

    stream.encode()
}

/// Encodes a `CommitmentProof` to TLV bytes.
///
/// The CommitmentProof is a TLV stream containing:
/// - Type 0: AssetProof (itself a TLV stream: version, tap_key, proof)
/// - Type 2: TaprootAssetProof (itself a TLV stream: version, proof)
pub fn encode_commitment_proof(cp: &CommitmentProof) -> Vec<u8> {
    let mut stream = TlvStream::new();

    // Type 0: AssetProof -- encoded as a nested TLV.
    if let Some(ref ap) = cp.asset_proof {
        let mut inner = TlvStream::new();
        // Sub-type 0: version (u8).
        inner.push(TlvRecord::u8(0, ap.version.to_u8()));
        // Sub-type 2: tap_key (32 bytes, the asset commitment identifier).
        inner.push(TlvRecord::bytes(2, &ap.tap_key));
        // Sub-type 4: compressed MS-SMT proof.
        let compressed = ap.proof.compress().encode();
        inner.push(TlvRecord::bytes(4, &compressed));
        stream.push(TlvRecord::bytes(
            commitment_tlv::ASSET_PROOF,
            &inner.encode(),
        ));
    }

    // Type 2: TaprootAssetProof -- encoded as a nested TLV.
    {
        let mut inner = TlvStream::new();
        // Sub-type 0: version (u8).
        inner.push(TlvRecord::u8(
            0,
            cp.taproot_asset_proof.version as u8,
        ));
        // Sub-type 2: compressed MS-SMT proof.
        let compressed = cp.taproot_asset_proof.proof.compress().encode();
        inner.push(TlvRecord::bytes(2, &compressed));
        stream.push(TlvRecord::bytes(
            commitment_tlv::TAP_PROOF,
            &inner.encode(),
        ));
    }

    // Type 5: TapSiblingPreimage (optional). Wire format: 1 byte
    // sibling type + raw preimage bytes (Go's
    // commitment.TapscriptPreimageEncoder).
    if let Some(ref preimage) = cp.tap_sibling_preimage {
        stream.push(TlvRecord::bytes(
            commitment_tlv::TAP_SIBLING,
            &preimage.encode(),
        ));
    }

    // Type 7: STXOProofs (optional). Wire format (Go's
    // CommitmentProofsEncoder in proof/encoding.go): BigSize count,
    // then per entry a fixed 33-byte serialized key followed by
    // var_bytes(encoded commitment.Proof). Entries are emitted in key
    // order (the BTreeMap ordering); Go iterates its map in random
    // order, so any deterministic order is wire-compatible.
    if !cp.stxo_proofs.is_empty() {
        let mut stxo_buf = Vec::new();
        encode_bigsize(&mut stxo_buf, cp.stxo_proofs.len() as u64);
        for (key, proof) in &cp.stxo_proofs {
            stxo_buf.extend_from_slice(key.as_bytes());
            let encoded = encode_commitment_proof(proof);
            encode_var_bytes(&mut stxo_buf, &encoded);
        }
        stream.push(TlvRecord::bytes(
            commitment_tlv::STXO_PROOFS,
            &stxo_buf,
        ));
    }

    // Unknown odd types.
    for (&type_num, value) in &cp.unknown_odd_types {
        stream.push(TlvRecord::bytes(type_num, value));
    }

    stream.encode()
}

/// Encodes a `MetaReveal` to TLV bytes.
pub fn encode_meta_reveal(meta: &MetaReveal) -> Vec<u8> {
    meta.encode()
}

/// Encodes a `GroupKeyReveal` to bytes.
///
/// V0 format: raw_key(33) + tapscript_root(0 or 32)
pub fn encode_group_key_reveal(gkr: &GroupKeyReveal) -> Vec<u8> {
    match gkr {
        GroupKeyReveal::V0(v0) => {
            let mut buf = Vec::new();
            buf.extend_from_slice(v0.raw_key.as_bytes());
            buf.extend_from_slice(&v0.tapscript_root);
            buf
        }
        GroupKeyReveal::V1(v1) => {
            // V1: TLV-encoded with version, internal_key, tapscript
            // details. Matches Go's GroupKeyRevealV1.Encode
            // (asset/group_key.go): the version record carries the
            // non-spend leaf version from the struct, and the tapscript
            // root record is always emitted (a 32-byte hash), so the
            // reveal is long enough for the decoder to distinguish it
            // from a V0 reveal.
            let mut stream = TlvStream::new();
            stream.push(TlvRecord::u8(
                crate::asset::tlv_types::GKR_VERSION,
                v1.version,
            ));
            stream.push(TlvRecord::bytes(
                crate::asset::tlv_types::GKR_INTERNAL_KEY,
                v1.internal_key.as_bytes(),
            ));
            stream.push(TlvRecord::bytes(
                crate::asset::tlv_types::GKR_TAPSCRIPT_ROOT,
                &v1.tapscript.root,
            ));
            if let Some(ref csr) = v1.tapscript.custom_subtree_root {
                stream.push(TlvRecord::bytes(
                    crate::asset::tlv_types::GKR_CUSTOM_SUBTREE_ROOT,
                    csr,
                ));
            }
            stream.encode()
        }
    }
}

/// Encodes a `TxMerkleProof` to bytes.
///
/// Format: `BigSize(count) [32B hash]... [packed_bits]`, matching Go's
/// `TxMerkleProof.Encode` in proof/tx.go (bits are packed LSB-first).
pub fn encode_tx_merkle_proof(proof: &TxMerkleProof) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, proof.nodes.len() as u64);
    for node in &proof.nodes {
        buf.extend_from_slice(node);
    }
    // Pack direction bits into bytes.
    let num_bytes = (proof.bits.len() + 7) / 8;
    let mut packed = vec![0u8; num_bytes];
    for (i, &bit) in proof.bits.iter().enumerate() {
        if bit {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    buf.extend_from_slice(&packed);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::proof::types::{
        AnchorTx, BlockHeader, TransitionVersion,
    };
    use std::collections::BTreeMap;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    #[test]
    fn test_encode_proof_has_magic() {
        let proof = Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint { txid: [0; 32], vout: 0 },
            block_header: BlockHeader([0; 80]),
            block_height: 100,
            anchor_tx: AnchorTx(vec![0; 10]),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset: Asset::new_genesis(
                test_genesis(),
                1000,
                ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
            ),
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                tapscript_proof: None,
                unknown_odd_types: BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: Some(test_genesis()),
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: BTreeMap::new(),
        };

        let encoded = encode_proof(&proof);

        // Must start with TAPP magic.
        assert_eq!(&encoded[..4], &PROOF_MAGIC_BYTES);
        assert!(encoded.len() > 100, "proof should be non-trivial");
    }

    #[test]
    fn test_encode_proof_deterministic() {
        let proof = Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint { txid: [0xAA; 32], vout: 1 },
            block_header: BlockHeader([0xBB; 80]),
            block_height: 800_000,
            anchor_tx: AnchorTx(vec![1, 2, 3]),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset: Asset::new_genesis(
                test_genesis(),
                500,
                ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            ),
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x03; 33]),
                commitment_proof: None,
                tapscript_proof: None,
                unknown_odd_types: BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: None,
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: BTreeMap::new(),
        };

        let enc1 = encode_proof(&proof);
        let enc2 = encode_proof(&proof);
        assert_eq!(enc1, enc2);
    }
}
