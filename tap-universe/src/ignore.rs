// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Signed ignore tuples, mirroring Go's `universe/ignore_records.go`.
//!
//! An [`IgnoreTuple`] marks an asset previous ID (outpoint + asset ID +
//! script key) plus an amount as invalid/ignored for supply accounting.
//! The tuple is signed by the asset group's delegation key, producing a
//! [`SignedIgnoreTuple`], and stored as a leaf in the ignore sub-tree of
//! the universe supply tree.
//!
//! # Byte formats (must stay byte-for-byte compatible with Go)
//!
//! The `IgnoreTuple` is a single static TLV record of type 0 inside a
//! TLV stream:
//!
//! ```text
//! 0x00 0x71 || txid(32) || vout(u32 BE) || asset_id(32)
//!           || script_key(33, compressed) || amount(u64 BE)
//!           || block_height(u32 BE)
//! ```
//!
//! Note the TLV outpoint index is big-endian (Go's `tlv.EUint32T`),
//! while the universe key uses the Bitcoin wire outpoint encoding with a
//! little-endian index (Go's `wire.WriteOutPoint` in `PrevID.Hash`).
//!
//! The `SignedIgnoreTuple` appends a 64-byte Schnorr signature as TLV
//! record type 2.
//!
//! # Signature digest
//!
//! `digest()` is `sha256(tlv_encoded_tuple)` (Go's `IgnoreTuple.Digest`).
//! The actual BIP-340 message that is signed is `sha256(digest())`,
//! because lnd's `SignMessageSchnorr`/`VerifyMessage` hash the passed
//! message once more with SHA-256 before signing/verifying.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::asset::{AssetId, OutPoint, PrevId, SerializedKey};
use tap_primitives::crypto::{sign_schnorr, verify_schnorr_key_bytes};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};
use tap_primitives::mssmt::LeafNode;

/// TLV type for the tuple record in a `SignedIgnoreTuple`.
const IGNORE_TUPLE_TYPE: u64 = 0;

/// TLV type for the signature record in a `SignedIgnoreTuple`.
const IGNORE_SIGNATURE_TYPE: u64 = 2;

/// Size of the static tuple record value:
/// 36 (outpoint) + 32 (asset id) + 33 (script key) + 8 (amount) +
/// 4 (block height).
const IGNORE_TUPLE_RECORD_SIZE: usize = 36 + 32 + 33 + 8 + 4;

/// Errors from ignore tuple operations.
#[derive(Debug, Clone)]
pub enum IgnoreError {
    /// The tuple or signature could not be decoded.
    Decode(String),
    /// The signature is invalid.
    InvalidSignature(String),
    /// Signing failed.
    Signing(String),
}

impl std::fmt::Display for IgnoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgnoreError::Decode(msg) => {
                write!(f, "ignore tuple decode error: {}", msg)
            }
            IgnoreError::InvalidSignature(msg) => {
                write!(f, "invalid ignore signature: {}", msg)
            }
            IgnoreError::Signing(msg) => {
                write!(f, "ignore signing error: {}", msg)
            }
        }
    }
}

impl std::error::Error for IgnoreError {}

/// An asset previous ID that should be ignored, plus the associated
/// amount and the block height at which the tuple was created. Mirrors
/// Go's `universe.IgnoreTuple`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgnoreTuple {
    /// The asset point being ignored.
    pub prev_id: PrevId,
    /// The total asset unit amount associated with the previous ID.
    pub amount: u64,
    /// The height of the block at which this ignore tuple was created.
    pub block_height: u32,
}

impl IgnoreTuple {
    /// Encodes the static TLV record value (113 bytes), mirroring Go's
    /// `ignoreTupleEncoder` (universe/ignore_records.go:43).
    fn encode_record_value(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IGNORE_TUPLE_RECORD_SIZE);
        // asset.OutPointEncoder: 32-byte hash, then u32 BE index.
        buf.extend_from_slice(&self.prev_id.out_point.txid);
        buf.extend_from_slice(&self.prev_id.out_point.vout.to_be_bytes());
        // asset.IDEncoder: 32 raw bytes.
        buf.extend_from_slice(self.prev_id.id.as_bytes());
        // asset.SerializedKeyEncoder: 33 compressed key bytes.
        buf.extend_from_slice(self.prev_id.script_key.as_bytes());
        // tlv.EUint64 / tlv.EUint32: big-endian.
        buf.extend_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&self.block_height.to_be_bytes());
        buf
    }

    /// Decodes the static TLV record value, mirroring Go's
    /// `ignoreTupleDecoder`.
    fn decode_record_value(value: &[u8]) -> Result<Self, IgnoreError> {
        if value.len() != IGNORE_TUPLE_RECORD_SIZE {
            return Err(IgnoreError::Decode(format!(
                "invalid ignore tuple record size: {}",
                value.len()
            )));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&value[0..32]);
        let vout = u32::from_be_bytes(
            value[32..36].try_into().expect("4 bytes"),
        );
        let mut id = [0u8; 32];
        id.copy_from_slice(&value[36..68]);
        let mut script_key = [0u8; 33];
        script_key.copy_from_slice(&value[68..101]);

        // Go's SerializedKeyDecoder parses the compressed public key
        // and rejects points that are not on the curve.
        tap_primitives::crypto::parse_pub_key(&SerializedKey(script_key))
            .map_err(|e| {
                IgnoreError::Decode(format!("invalid script key: {}", e))
            })?;

        let amount = u64::from_be_bytes(
            value[101..109].try_into().expect("8 bytes"),
        );
        let block_height = u32::from_be_bytes(
            value[109..113].try_into().expect("4 bytes"),
        );

        Ok(IgnoreTuple {
            prev_id: PrevId {
                out_point: OutPoint { txid, vout },
                id: AssetId(id),
                script_key: SerializedKey(script_key),
            },
            amount,
            block_height,
        })
    }

    /// Serializes the tuple as a TLV stream (a single static record of
    /// type 0), mirroring Go's `IgnoreTuple.Encode`/`Bytes`.
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::new(
            IGNORE_TUPLE_TYPE,
            self.encode_record_value(),
        ));
        stream.encode()
    }

    /// Deserializes a tuple from its TLV stream encoding.
    pub fn decode(data: &[u8]) -> Result<Self, IgnoreError> {
        let stream = TlvStream::decode(data)
            .map_err(|e| IgnoreError::Decode(e.to_string()))?;
        let record = stream.get(IGNORE_TUPLE_TYPE).ok_or_else(|| {
            IgnoreError::Decode("missing ignore tuple record".into())
        })?;
        Self::decode_record_value(&record.value)
    }

    /// Returns the SHA-256 digest of the TLV-serialized tuple,
    /// mirroring Go's `IgnoreTuple.Digest`
    /// (universe/ignore_records.go:137).
    pub fn digest(&self) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(&self.encode());
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Returns the BIP-340 message that the delegation key actually
    /// signs: `sha256(digest())`.
    ///
    /// lnd's `SignMessageSchnorr` (and `VerifyMessage` with
    /// `VerifySchnorr`) hash the caller-provided message once more with
    /// SHA-256, and Go passes `Digest()` as that message.
    pub fn signing_digest(&self) -> [u8; 32] {
        let digest = self.digest();
        let mut engine = sha256::HashEngine::default();
        engine.input(&digest);
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Returns the universe tree key for the tuple, mirroring Go's
    /// `SignedIgnoreTuple.UniverseKey` which delegates to
    /// `asset.PrevID.Hash` (universe/ignore_records.go:306):
    /// `sha256(wire_outpoint || asset_id || schnorr_script_key)`.
    pub fn universe_key(&self) -> [u8; 32] {
        self.prev_id.hash()
    }

    /// Signs the tuple with the given delegation secret key, producing
    /// a [`SignedIgnoreTuple`]. Mirrors Go's
    /// `IgnoreTuple.GenSignedIgnore` combined with lnd's Schnorr message
    /// signing convention.
    pub fn sign(
        &self,
        delegation_secret_key: &[u8; 32],
    ) -> Result<SignedIgnoreTuple, IgnoreError> {
        let msg = self.signing_digest();
        let sig = sign_schnorr(&msg, delegation_secret_key)
            .map_err(IgnoreError::Signing)?;
        Ok(SignedIgnoreTuple {
            tuple: self.clone(),
            sig: IgnoreSig(sig),
        })
    }

    /// Signs the tuple using a caller-provided signing closure, which
    /// receives the 32-byte BIP-340 message (`signing_digest()`) and
    /// must return a 64-byte Schnorr signature. This supports external
    /// signers (e.g. remote wallets) without exposing key material.
    pub fn sign_with<F>(
        &self,
        signer: F,
    ) -> Result<SignedIgnoreTuple, IgnoreError>
    where
        F: FnOnce(&[u8; 32]) -> Result<[u8; 64], String>,
    {
        let msg = self.signing_digest();
        let sig = signer(&msg).map_err(IgnoreError::Signing)?;
        Ok(SignedIgnoreTuple {
            tuple: self.clone(),
            sig: IgnoreSig(sig),
        })
    }
}

/// A 64-byte BIP-340 Schnorr signature over an [`IgnoreTuple`], mirroring
/// Go's `universe.IgnoreSig`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IgnoreSig(pub [u8; 64]);

impl std::fmt::Debug for IgnoreSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IgnoreSig(")?;
        for b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

/// An [`IgnoreTuple`] together with the delegation key's signature over
/// it, mirroring Go's `universe.SignedIgnoreTuple`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIgnoreTuple {
    /// The tuple that is being signed.
    pub tuple: IgnoreTuple,
    /// The signature over the tuple.
    pub sig: IgnoreSig,
}

impl SignedIgnoreTuple {
    /// Serializes the signed tuple as a TLV stream (tuple record type 0
    /// followed by signature record type 2), mirroring Go's
    /// `SignedIgnoreTuple.Encode`/`Bytes`
    /// (universe/ignore_records.go:263).
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::new(
            IGNORE_TUPLE_TYPE,
            self.tuple.encode_record_value(),
        ));
        stream.push(TlvRecord::new(
            IGNORE_SIGNATURE_TYPE,
            self.sig.0.to_vec(),
        ));
        stream.encode()
    }

    /// Deserializes a signed tuple from its TLV stream encoding,
    /// mirroring Go's `DecodeSignedIgnoreTuple`.
    pub fn decode(data: &[u8]) -> Result<Self, IgnoreError> {
        let stream = TlvStream::decode(data)
            .map_err(|e| IgnoreError::Decode(e.to_string()))?;

        let tuple_record = stream.get(IGNORE_TUPLE_TYPE).ok_or_else(|| {
            IgnoreError::Decode("missing ignore tuple record".into())
        })?;
        let tuple = IgnoreTuple::decode_record_value(&tuple_record.value)?;

        let sig_record =
            stream.get(IGNORE_SIGNATURE_TYPE).ok_or_else(|| {
                IgnoreError::Decode("missing ignore signature record".into())
            })?;
        if sig_record.value.len() != 64 {
            return Err(IgnoreError::Decode(format!(
                "invalid signature length: {}",
                sig_record.value.len()
            )));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_record.value);

        Ok(SignedIgnoreTuple {
            tuple,
            sig: IgnoreSig(sig),
        })
    }

    /// Verifies the Schnorr signature against the given delegation
    /// public key, mirroring Go's supplyverifier `verifyIgnoreLeaf`
    /// signature check (universe/supplyverifier/verifier.go:553): the
    /// BIP-340 message is `sha256(tuple.Digest())`.
    pub fn verify_sig(
        &self,
        delegation_key: &SerializedKey,
    ) -> Result<(), IgnoreError> {
        let msg = self.tuple.signing_digest();
        verify_schnorr_key_bytes(
            &self.sig.0,
            &msg,
            delegation_key.schnorr_bytes(),
        )
        .map_err(IgnoreError::InvalidSignature)
    }

    /// Returns the MS-SMT leaf for the signed tuple, mirroring Go's
    /// `SignedIgnoreTuple.UniverseLeafNode`: the leaf value is the TLV
    /// encoding and the sum is the ignored amount.
    pub fn universe_leaf_node(&self) -> LeafNode {
        LeafNode::new(self.encode(), self.tuple.amount)
    }

    /// Returns the universe tree key for the signed tuple.
    pub fn universe_key(&self) -> [u8; 32] {
        self.tuple.universe_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The fixed tuple used by the Go-generated vectors (see report;
    /// generated by executing Go v0.8.99-alpha code).
    fn go_vector_tuple() -> IgnoreTuple {
        let mut txid = [0u8; 32];
        for (i, b) in txid.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let script_key = hex_decode(
            "02463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b",
        );
        IgnoreTuple {
            prev_id: PrevId {
                out_point: OutPoint { txid, vout: 7 },
                id: AssetId([0xAA; 32]),
                script_key: SerializedKey(
                    script_key.try_into().expect("33 bytes"),
                ),
            },
            amount: 1000,
            block_height: 800_000,
        }
    }

    const GO_TUPLE_BYTES: &str = "00710102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b00000000000003e8000c3500";
    const GO_TUPLE_DIGEST: &str =
        "02b770d58c779e565c59415ea3d4bc9cfc8ea1ce6602b0e6547fe2a07f064d35";
    const GO_UNIVERSE_KEY: &str =
        "467ec33205854dcf077fe8c1101af6b6eb6b6020e7c5b6091e253175189146d3";
    const GO_DELEGATION_PUB: &str = "021697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5";
    const GO_SIG: &str = "cdaf20707b4ca7ed72a1f28b7a5908f7eb92cb6a6d2d7fcfe9fa15544f20bb712215724e6f5ca027c90281fe699e8c9193c2813b8359b6a6b46afcd52775d0d9";
    const GO_SIGNED_TUPLE_BYTES: &str = "00710102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b00000000000003e8000c35000240cdaf20707b4ca7ed72a1f28b7a5908f7eb92cb6a6d2d7fcfe9fa15544f20bb712215724e6f5ca027c90281fe699e8c9193c2813b8359b6a6b46afcd52775d0d9";
    const GO_LEAF_HASH: &str =
        "4d4ba5b6ad4206079913d5555000b80c7d8c3c948f5c20a6f4929533639e588d";

    fn go_signed_tuple() -> SignedIgnoreTuple {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&hex_decode(GO_SIG));
        SignedIgnoreTuple {
            tuple: go_vector_tuple(),
            sig: IgnoreSig(sig),
        }
    }

    #[test]
    fn test_go_vector_tuple_encoding() {
        let tuple = go_vector_tuple();
        assert_eq!(tuple.encode(), hex_decode(GO_TUPLE_BYTES));
        assert_eq!(tuple.digest().to_vec(), hex_decode(GO_TUPLE_DIGEST));
        assert_eq!(
            tuple.universe_key().to_vec(),
            hex_decode(GO_UNIVERSE_KEY)
        );
    }

    #[test]
    fn test_go_vector_signed_tuple_encoding() {
        let signed = go_signed_tuple();
        assert_eq!(signed.encode(), hex_decode(GO_SIGNED_TUPLE_BYTES));

        let leaf = signed.universe_leaf_node();
        assert_eq!(leaf.node_hash().0.to_vec(), hex_decode(GO_LEAF_HASH));
        assert_eq!(leaf.node_sum(), 1000);
    }

    #[test]
    fn test_go_vector_signature_verifies() {
        // The Go-produced signature (btcec schnorr.Sign over
        // sha256(digest)) must verify against the Go delegation key.
        let signed = go_signed_tuple();
        let delegation_key = SerializedKey(
            hex_decode(GO_DELEGATION_PUB).try_into().expect("33 bytes"),
        );
        signed.verify_sig(&delegation_key).expect("valid signature");

        // A tampered tuple must fail.
        let mut tampered = signed.clone();
        tampered.tuple.amount += 1;
        assert!(tampered.verify_sig(&delegation_key).is_err());

        // A wrong key must fail.
        let mut wrong_key = delegation_key;
        wrong_key.0[32] ^= 0x01;
        assert!(signed.verify_sig(&wrong_key).is_err());
    }

    #[test]
    fn test_tuple_round_trip() {
        let tuple = go_vector_tuple();
        let decoded = IgnoreTuple::decode(&tuple.encode()).expect("decode");
        assert_eq!(tuple, decoded);
    }

    #[test]
    fn test_signed_tuple_round_trip() {
        let signed = go_signed_tuple();
        let decoded =
            SignedIgnoreTuple::decode(&signed.encode()).expect("decode");
        assert_eq!(signed, decoded);
    }

    #[test]
    fn test_sign_and_verify_locally() {
        // Private key 0x..21 corresponds to GO_DELEGATION_PUB.
        let mut sk = [0u8; 32];
        sk[31] = 0x21;
        let tuple = go_vector_tuple();
        let signed = tuple.sign(&sk).expect("sign");

        let delegation_key = SerializedKey(
            hex_decode(GO_DELEGATION_PUB).try_into().expect("33 bytes"),
        );
        signed.verify_sig(&delegation_key).expect("valid signature");
    }

    #[test]
    fn test_sign_with_closure() {
        let mut sk = [0u8; 32];
        sk[31] = 0x21;
        let tuple = go_vector_tuple();
        let signed = tuple
            .sign_with(|msg| tap_primitives::crypto::sign_schnorr(msg, &sk))
            .expect("sign");
        let delegation_key = SerializedKey(
            hex_decode(GO_DELEGATION_PUB).try_into().expect("33 bytes"),
        );
        signed.verify_sig(&delegation_key).expect("valid signature");
    }

    #[test]
    fn test_decode_rejects_invalid_script_key() {
        // Mirror Go's decoder, which parses the compressed script key
        // and rejects points not on the curve.
        let mut bytes = hex_decode(GO_TUPLE_BYTES);
        // Corrupt the script key x coordinate (offset: 2 TLV header
        // bytes + 36 outpoint + 32 asset id + 1 parity byte).
        for b in bytes.iter_mut().skip(2 + 36 + 32 + 1).take(32) {
            *b = 0xBB;
        }
        assert!(IgnoreTuple::decode(&bytes).is_err());
    }

    #[test]
    fn test_decode_rejects_truncated() {
        let bytes = hex_decode(GO_TUPLE_BYTES);
        assert!(IgnoreTuple::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
