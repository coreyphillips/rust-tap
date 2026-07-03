// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transaction inclusion proof for the auth mailbox protocol, mirroring
//! Go's `proof.TxProof` (proof/tx.go).
//!
//! A [`TxProof`] proves the existence of a specific P2TR outpoint in a
//! confirmed Bitcoin block: it carries the transaction, the block
//! header and height, a transaction merkle proof, and the construction
//! details (internal key plus optional taproot merkle root) of the
//! claimed output. The auth mailbox server requires such a proof as
//! proof-of-work before accepting a message.

use crate::asset::{OutPoint, SerializedKey};
use crate::crypto::tapscript::taproot_output_key;

use super::tx_merkle::TxMerkleProof;
use super::types::{AnchorTx, BlockHeader};
use super::verify::{HeaderVerifier, MerkleVerifier};
use super::ProofError;

/// A proof that a specific outpoint exists in a block, mirroring Go's
/// `proof.TxProof` (proof/tx.go).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxProof {
    /// The transaction that contains the outpoint (Go: `MsgTx`).
    pub msg_tx: AnchorTx,

    /// The header of the block that contains the transaction.
    pub block_header: BlockHeader,

    /// The height at which the block was mined.
    pub block_height: u32,

    /// The proof that the transaction is included in the block and its
    /// merkle root.
    pub merkle_proof: TxMerkleProof,

    /// The outpoint that is being proved to exist in the transaction.
    pub claimed_outpoint: OutPoint,

    /// The Taproot internal key used to construct the P2TR output that
    /// is claimed by the outpoint above. Must be provided alongside the
    /// Taproot merkle root to prove knowledge of the output's
    /// construction.
    pub internal_key: SerializedKey,

    /// The claimed output's Taproot merkle root, if applicable. This,
    /// alongside the internal key, is used to prove knowledge of the
    /// output's construction. If this is `None`, a BIP-0086 output key
    /// construction is assumed.
    pub merkle_root: Option<[u8; 32]>,
}

impl TxProof {
    /// Validates the Bitcoin merkle inclusion proof, mirroring Go's
    /// `TxProof.Verify` (proof/tx.go:232):
    ///
    /// 1. The claimed outpoint references the provided transaction and
    ///    is within its output bounds.
    /// 2. The claimed output is a P2TR output whose key is constructed
    ///    from the internal key and the (optional) merkle root.
    /// 3. The transaction is included in the given block.
    /// 4. The block header is valid and matches the given block height.
    pub fn verify<H, M>(
        &self,
        header_verifier: &H,
        merkle_verifier: &M,
    ) -> Result<(), ProofError>
    where
        H: HeaderVerifier + ?Sized,
        M: MerkleVerifier + ?Sized,
    {
        let tx_hash = self.msg_tx.txid();

        // Part 1: Verify the claimed outpoint references the provided
        // transaction.
        if self.claimed_outpoint.txid != tx_hash {
            return Err(ProofError::HashMismatch);
        }

        if self.claimed_outpoint.vout as usize
            >= self.msg_tx.0.output.len()
        {
            return Err(ProofError::OutputIndexInvalid);
        }

        // Part 2: Verify the claimed outpoint is indeed a P2TR output
        // and the construction details are valid. An absent merkle root
        // means BIP-0086 (key-spend only) construction, matching Go's
        // ComputeTaprootKeyNoScript.
        let merkle_root: &[u8] = match &self.merkle_root {
            Some(root) => &root[..],
            None => &[],
        };
        let taproot_key =
            taproot_output_key(&self.internal_key, merkle_root)
                .map_err(|e| {
                    ProofError::VerificationFailed(format!(
                        "error computing taproot output: {}",
                        e
                    ))
                })?;

        let mut expected_pk_script = Vec::with_capacity(34);
        expected_pk_script.push(0x51); // OP_1 (witness v1)
        expected_pk_script.push(0x20); // OP_PUSHBYTES_32
        expected_pk_script.extend_from_slice(&taproot_key);

        let claimed_tx_out =
            &self.msg_tx.0.output[self.claimed_outpoint.vout as usize];
        if claimed_tx_out.script_pubkey.as_bytes() != expected_pk_script {
            return Err(ProofError::ClaimedOutputScriptMismatch);
        }

        // Part 3: Verify the transaction is included in the given
        // block.
        merkle_verifier.verify_merkle_proof(
            &tx_hash,
            &self.merkle_proof,
            &self.block_header.merkle_root(),
        )?;

        // Part 4: Verify the block header is valid and matches the
        // given block height.
        header_verifier
            .verify_header(&self.block_header, self.block_height)?;

        Ok(())
    }

    /// Serializes the proof to bytes.
    ///
    /// NOTE: Go has no standalone binary encoding for `TxProof` — its
    /// wire format is the `authmailboxrpc.BitcoinMerkleInclusionProof`
    /// protobuf message (see Go's `MarshalTxProof`). This TLV encoding
    /// is rust-tap internal (used for local persistence and the
    /// transport-agnostic mailbox seam) and mirrors the protobuf field
    /// content one-to-one so a future gRPC transport can map it
    /// directly.
    ///
    /// Record types: 0 = raw tx, 2 = raw block header (80 bytes),
    /// 4 = block height (u32), 6 = merkle proof (Go `TxMerkleProof`
    /// encoding), 8 = claimed outpoint (txid + u32 BE), 10 = internal
    /// key (33 bytes), 11 = merkle root (32 bytes, optional).
    pub fn encode(&self) -> Vec<u8> {
        use crate::encoding::tlv::{TlvRecord, TlvStream};

        let mut stream = TlvStream::new();
        stream.push(TlvRecord::bytes(0, &self.msg_tx.to_bytes()));
        stream.push(TlvRecord::bytes(2, self.block_header.as_bytes()));
        stream.push(TlvRecord::u32(4, self.block_height));
        stream.push(TlvRecord::bytes(
            6,
            &super::encode::encode_tx_merkle_proof(&self.merkle_proof),
        ));

        let mut outpoint = Vec::with_capacity(36);
        outpoint.extend_from_slice(&self.claimed_outpoint.txid);
        outpoint
            .extend_from_slice(&self.claimed_outpoint.vout.to_be_bytes());
        stream.push(TlvRecord::bytes(8, &outpoint));

        stream.push(TlvRecord::bytes(10, self.internal_key.as_bytes()));
        if let Some(root) = &self.merkle_root {
            stream.push(TlvRecord::bytes(11, root));
        }

        stream.encode()
    }

    /// Deserializes a proof from bytes produced by [`TxProof::encode`].
    /// Applies the same validation as Go's `UnmarshalTxProof`: the
    /// block height must be set, the merkle root must be absent or
    /// exactly 32 bytes, and the merkle proof node count is bounded.
    pub fn decode(data: &[u8]) -> Result<Self, ProofError> {
        use crate::encoding::tlv::TlvStream;

        let stream = TlvStream::decode(data)
            .map_err(|e| ProofError::DecodingError(e.to_string()))?;

        let get = |t: u64| {
            stream.get(t).ok_or_else(|| {
                ProofError::DecodingError(format!(
                    "tx proof: missing record {}",
                    t
                ))
            })
        };

        let msg_tx = AnchorTx::from_bytes(&get(0)?.value)?;

        let header_bytes = &get(2)?.value;
        let header: [u8; 80] =
            header_bytes.as_slice().try_into().map_err(|_| {
                ProofError::DecodingError(
                    "tx proof: invalid block header length".into(),
                )
            })?;

        let block_height = get(4)?.as_u32().map_err(|e| {
            ProofError::DecodingError(e.to_string())
        })?;
        if block_height == 0 {
            return Err(ProofError::DecodingError(
                "tx proof: block height is missing".into(),
            ));
        }

        let merkle_proof =
            super::decode::decode_tx_merkle_proof(&get(6)?.value)?;

        let outpoint_bytes = &get(8)?.value;
        if outpoint_bytes.len() != 36 {
            return Err(ProofError::DecodingError(
                "tx proof: invalid outpoint length".into(),
            ));
        }
        let claimed_outpoint = OutPoint {
            txid: outpoint_bytes[..32]
                .try_into()
                .expect("length checked"),
            vout: u32::from_be_bytes(
                outpoint_bytes[32..36]
                    .try_into()
                    .expect("length checked"),
            ),
        };

        let key_bytes = &get(10)?.value;
        let internal_key = SerializedKey(
            key_bytes.as_slice().try_into().map_err(|_| {
                ProofError::DecodingError(
                    "tx proof: invalid internal key length".into(),
                )
            })?,
        );

        // The merkle root is optional. If provided, it must be exactly
        // 32 bytes long, matching Go's UnmarshalTxProof.
        let merkle_root = match stream.get(11) {
            None => None,
            Some(record) => Some(
                record.value.as_slice().try_into().map_err(|_| {
                    ProofError::DecodingError(format!(
                        "merkle root must be empty or exactly 32 \
                         bytes long, got {} bytes",
                        record.value.len()
                    ))
                })?,
            ),
        };

        Ok(TxProof {
            msg_tx,
            block_header: BlockHeader(header),
            block_height,
            merkle_proof,
            claimed_outpoint,
            internal_key,
            merkle_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::verify::{DefaultMerkleVerifier, TrustAllHeaders};

    /// A header verifier that always fails, mirroring the
    /// `errHeaderVerifier` in Go's tx_test.go.
    struct RejectAllHeaders;

    impl HeaderVerifier for RejectAllHeaders {
        fn verify_header(
            &self,
            _header: &BlockHeader,
            _height: u32,
        ) -> Result<(), ProofError> {
            Err(ProofError::VerificationFailed("invalid header".into()))
        }
    }

    /// A merkle verifier that always fails, mirroring the
    /// `errMerkleVerifier` in Go's tx_test.go.
    struct RejectAllMerkle;

    impl MerkleVerifier for RejectAllMerkle {
        fn verify_merkle_proof(
            &self,
            _tx_hash: &[u8; 32],
            _proof: &TxMerkleProof,
            _merkle_root: &[u8; 32],
        ) -> Result<(), ProofError> {
            Err(ProofError::VerificationFailed(
                "invalid merkle proof".into(),
            ))
        }
    }

    /// A merkle verifier that always succeeds, mirroring Go's
    /// `MockMerkleVerifier`.
    struct TrustAllMerkle;

    impl MerkleVerifier for TrustAllMerkle {
        fn verify_merkle_proof(
            &self,
            _tx_hash: &[u8; 32],
            _proof: &TxMerkleProof,
            _merkle_root: &[u8; 32],
        ) -> Result<(), ProofError> {
            Ok(())
        }
    }

    fn test_internal_key() -> SerializedKey {
        // A valid generator-point key.
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        SerializedKey(sk.public_key(&secp).serialize())
    }

    /// Builds a transaction with a single P2TR output paying to the
    /// given taproot output key.
    fn p2tr_tx(output_key: &[u8; 32]) -> AnchorTx {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

        let mut script = Vec::with_capacity(34);
        script.push(0x51);
        script.push(0x20);
        script.extend_from_slice(output_key);

        AnchorTx(Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
        })
    }

    fn bip86_proof() -> TxProof {
        let internal_key = test_internal_key();
        // BIP-86: tweak with empty merkle root.
        let output_key = taproot_output_key(&internal_key, &[]).unwrap();
        let tx = p2tr_tx(&output_key);
        let txid = tx.txid();

        // Single-tx block: merkle root == txid.
        let mut header = [0u8; 80];
        header[36..68].copy_from_slice(&txid);

        TxProof {
            msg_tx: tx,
            block_header: BlockHeader(header),
            block_height: 39493,
            merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            claimed_outpoint: OutPoint { txid, vout: 0 },
            internal_key,
            merkle_root: None,
        }
    }

    fn tapscript_proof() -> TxProof {
        let internal_key = test_internal_key();
        let rand_root = [0x5A; 32];
        let output_key =
            taproot_output_key(&internal_key, &rand_root).unwrap();
        let tx = p2tr_tx(&output_key);
        let txid = tx.txid();

        let mut header = [0u8; 80];
        header[36..68].copy_from_slice(&txid);

        TxProof {
            msg_tx: tx,
            block_header: BlockHeader(header),
            block_height: 39493,
            merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            claimed_outpoint: OutPoint { txid, vout: 0 },
            internal_key,
            merkle_root: Some(rand_root),
        }
    }

    // Ported from Go's TestTxProofVerification "hash mismatch" case.
    #[test]
    fn test_verify_hash_mismatch() {
        let mut proof = bip86_proof();
        proof.claimed_outpoint.txid = [0xEE; 32];

        assert!(matches!(
            proof.verify(&TrustAllHeaders, &TrustAllMerkle),
            Err(ProofError::HashMismatch)
        ));
    }

    // Ported from Go's "index mismatch" case.
    #[test]
    fn test_verify_index_invalid() {
        let mut proof = bip86_proof();
        proof.claimed_outpoint.vout = 123;

        assert!(matches!(
            proof.verify(&TrustAllHeaders, &TrustAllMerkle),
            Err(ProofError::OutputIndexInvalid)
        ));
    }

    // Ported from Go's "pk script mismatch" case.
    #[test]
    fn test_verify_pk_script_mismatch() {
        let mut proof = bip86_proof();
        // Claim a tapscript root that doesn't match the BIP-86 output.
        proof.merkle_root = Some([0x11; 32]);

        assert!(matches!(
            proof.verify(&TrustAllHeaders, &TrustAllMerkle),
            Err(ProofError::ClaimedOutputScriptMismatch)
        ));
    }

    // Ported from Go's "merkle verifier mismatch" case.
    #[test]
    fn test_verify_merkle_verifier_error() {
        let proof = bip86_proof();
        let result = proof.verify(&TrustAllHeaders, &RejectAllMerkle);
        assert!(matches!(
            result,
            Err(ProofError::VerificationFailed(msg))
                if msg == "invalid merkle proof"
        ));
    }

    // Ported from Go's "header verifier mismatch" case.
    #[test]
    fn test_verify_header_verifier_error() {
        let proof = bip86_proof();
        let result = proof.verify(&RejectAllHeaders, &TrustAllMerkle);
        assert!(matches!(
            result,
            Err(ProofError::VerificationFailed(msg))
                if msg == "invalid header"
        ));
    }

    // Ported from Go's "success" case (tapscript output construction),
    // but with a real merkle verifier over a single-tx block.
    #[test]
    fn test_verify_success_tapscript() {
        let proof = tapscript_proof();
        proof
            .verify(&TrustAllHeaders, &DefaultMerkleVerifier)
            .unwrap();
    }

    #[test]
    fn test_verify_success_bip86() {
        let proof = bip86_proof();
        proof
            .verify(&TrustAllHeaders, &DefaultMerkleVerifier)
            .unwrap();
    }

    #[test]
    fn test_verify_two_tx_block_merkle_proof() {
        use bitcoin_hashes::{sha256d, Hash, HashEngine};

        let mut proof = bip86_proof();
        let txid = proof.msg_tx.txid();

        // Two-tx block: our tx on the left, sibling on the right.
        let sibling = [0x77; 32];
        let mut engine = sha256d::Hash::engine();
        engine.input(&txid);
        engine.input(&sibling);
        let root = sha256d::Hash::from_engine(engine).to_byte_array();

        proof.merkle_proof = TxMerkleProof {
            nodes: vec![sibling],
            bits: vec![true],
        };
        proof.block_header.0[36..68].copy_from_slice(&root);

        proof
            .verify(&TrustAllHeaders, &DefaultMerkleVerifier)
            .unwrap();

        // Flipping the direction bit must fail.
        proof.merkle_proof.bits[0] = false;
        assert!(proof
            .verify(&TrustAllHeaders, &DefaultMerkleVerifier)
            .is_err());
    }

    // Mirrors the RPC round-trip assertion in Go's success case
    // (Marshal/UnmarshalTxProof), applied to the rust-tap encoding.
    #[test]
    fn test_encode_decode_round_trip() {
        for proof in [bip86_proof(), tapscript_proof()] {
            let encoded = proof.encode();
            let decoded = TxProof::decode(&encoded).unwrap();
            assert_eq!(proof, decoded);

            decoded
                .verify(&TrustAllHeaders, &DefaultMerkleVerifier)
                .unwrap();
        }
    }

    #[test]
    fn test_decode_rejects_zero_height() {
        let mut proof = bip86_proof();
        proof.block_height = 0;
        let encoded = proof.encode();
        assert!(matches!(
            TxProof::decode(&encoded),
            Err(ProofError::DecodingError(msg))
                if msg.contains("block height")
        ));
    }

    #[test]
    fn test_decode_rejects_bad_merkle_root_length() {
        use crate::encoding::tlv::{TlvRecord, TlvStream};

        let proof = bip86_proof();
        let encoded = proof.encode();
        let stream = TlvStream::decode(&encoded).unwrap();

        // Rebuild the stream with a 16-byte merkle root record.
        let mut bad = TlvStream::new();
        for record in stream.records() {
            bad.push(record.clone());
        }
        bad.push(TlvRecord::bytes(11, &[0xAB; 16]));

        assert!(matches!(
            TxProof::decode(&bad.encode()),
            Err(ProofError::DecodingError(msg))
                if msg.contains("merkle root")
        ));
    }
}
