// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof file format — a chained sequence of transition proofs.
//!
//! Each proof file represents the complete provenance chain for an asset,
//! from genesis to its current state. Proofs are chained via SHA-256:
//! each proof's hash depends on the previous proof's hash, forming a
//! time-chain similar to Bitcoin's block headers.
//!
//! ## File format
//!
//! ```text
//! [4B magic "TAPF"] [4B version BE] [BigSize proof_count]
//! For each proof:
//!   [BigSize proof_len] [proof_bytes...] [32B hash]
//! ```
//!
//! The count and length prefixes use lightning-style BigSize varints
//! (big-endian), matching Go's `File.Encode` which calls
//! `tlv.WriteVarInt` (proof/file.go), NOT Bitcoin compact-size varints
//! (which are little-endian for multi-byte values).
//!
//! The hash for proof `i` is: `SHA256(hash_{i-1} || proof_bytes_i)`
//! where `hash_0 = [0u8; 32]`.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use super::ProofError;
use crate::encoding::bigsize::{decode_bigsize, encode_bigsize};

/// Magic bytes for a proof file: "TAPF" (Taproot Assets Protocol File).
pub const FILE_MAGIC_BYTES: [u8; 4] = [0x54, 0x41, 0x50, 0x46];

/// Magic bytes for an individual proof: "TAPP" (Taproot Assets Protocol Proof).
pub const PROOF_MAGIC_BYTES: [u8; 4] = [0x54, 0x41, 0x50, 0x50];

/// File format version.
pub const FILE_VERSION_V0: u32 = 0;

/// Maximum number of proofs in a file.
pub const FILE_MAX_NUM_PROOFS: usize = 420_000;

/// Maximum size of a single encoded proof (128 MiB).
pub const FILE_MAX_PROOF_SIZE_BYTES: usize = 128 * 1024 * 1024;

/// Maximum total file size (500 MiB).
pub const FILE_MAX_SIZE_BYTES: usize = 500 * 1024 * 1024;

/// A hashed proof entry in a proof file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashedProof {
    /// The raw encoded proof bytes (including the "TAPP" magic prefix).
    pub proof_bytes: Vec<u8>,
    /// SHA256(prev_hash || proof_bytes).
    pub hash: [u8; 32],
}

/// A proof file containing a chain of transition proofs.
///
/// The proofs form a hash chain: each proof's hash depends on the
/// previous proof's hash. The first proof uses a zero hash as its
/// predecessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    /// File format version.
    pub version: u32,
    /// Ordered chain of proofs (genesis first, current state last).
    pub proofs: Vec<HashedProof>,
}

impl File {
    /// Creates a new empty proof file.
    pub fn new() -> Self {
        File {
            version: FILE_VERSION_V0,
            proofs: Vec::new(),
        }
    }

    /// Appends a proof to the file, computing its chain hash.
    pub fn append_proof(&mut self, proof_bytes: Vec<u8>) {
        let prev_hash = self
            .proofs
            .last()
            .map(|p| p.hash)
            .unwrap_or([0u8; 32]);

        let hash = compute_proof_hash(&prev_hash, &proof_bytes);
        self.proofs.push(HashedProof { proof_bytes, hash });
    }

    /// Returns the number of proofs in the file.
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }

    /// Returns the last proof in the chain, if any.
    pub fn last_proof(&self) -> Option<&HashedProof> {
        self.proofs.last()
    }

    /// Encodes the proof file to bytes.
    ///
    /// Format:
    /// `[4B magic] [4B version BE] [BigSize count] [for each: BigSize len, bytes, 32B hash]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic bytes.
        buf.extend_from_slice(&FILE_MAGIC_BYTES);

        // Version (big-endian u32).
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Number of proofs (BigSize varint, matching Go's
        // tlv.WriteVarInt in proof/file.go).
        encode_bigsize(&mut buf, self.proofs.len() as u64);

        // Each proof.
        for hashed in &self.proofs {
            encode_bigsize(&mut buf, hashed.proof_bytes.len() as u64);
            buf.extend_from_slice(&hashed.proof_bytes);
            buf.extend_from_slice(&hashed.hash);
        }

        buf
    }

    /// Decodes a proof file from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProofError> {
        let mut offset = 0;

        // Magic bytes.
        if data.len() < 4 {
            return Err(ProofError::FileTooShort);
        }
        if data[..4] != FILE_MAGIC_BYTES {
            return Err(ProofError::InvalidMagic);
        }
        offset += 4;

        // Version.
        if data.len() < offset + 4 {
            return Err(ProofError::FileTooShort);
        }
        let version = u32::from_be_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        );
        offset += 4;

        // Number of proofs (BigSize varint).
        let (count, bytes_read) = decode_bigsize(&data[offset..])
            .map_err(|_| ProofError::FileTooShort)?;
        offset += bytes_read;
        let count = count as usize;

        if count > FILE_MAX_NUM_PROOFS {
            return Err(ProofError::TooManyProofs(count));
        }

        // Read each proof.
        let mut proofs = Vec::with_capacity(count);
        let mut prev_hash = [0u8; 32];

        for _ in 0..count {
            // Proof length (BigSize varint).
            let (proof_len, bytes_read) = decode_bigsize(&data[offset..])
                .map_err(|_| ProofError::FileTooShort)?;
            offset += bytes_read;
            let proof_len = proof_len as usize;

            if proof_len > FILE_MAX_PROOF_SIZE_BYTES {
                return Err(ProofError::ProofTooLarge(proof_len));
            }

            if offset + proof_len + 32 > data.len() {
                return Err(ProofError::FileTooShort);
            }

            // Proof bytes.
            let proof_bytes = data[offset..offset + proof_len].to_vec();
            offset += proof_len;

            // Hash.
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            // Verify the hash chain.
            let expected_hash =
                compute_proof_hash(&prev_hash, &proof_bytes);
            if hash != expected_hash {
                return Err(ProofError::InvalidProofHash);
            }

            prev_hash = hash;
            proofs.push(HashedProof { proof_bytes, hash });
        }

        Ok(File { version, proofs })
    }

    /// Verifies the hash chain integrity without parsing individual proofs.
    pub fn verify_hash_chain(&self) -> bool {
        let mut prev_hash = [0u8; 32];
        for hashed in &self.proofs {
            let expected = compute_proof_hash(&prev_hash, &hashed.proof_bytes);
            if hashed.hash != expected {
                return false;
            }
            prev_hash = hashed.hash;
        }
        true
    }
}

impl Default for File {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes `SHA256(prev_hash || proof_bytes)`.
fn compute_proof_hash(prev_hash: &[u8; 32], proof_bytes: &[u8]) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(prev_hash);
    engine.input(proof_bytes);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_file_encode_decode() {
        let file = File::new();
        let encoded = file.encode();
        let decoded = File::decode(&encoded).unwrap();
        assert_eq!(decoded.version, FILE_VERSION_V0);
        assert_eq!(decoded.num_proofs(), 0);
    }

    #[test]
    fn test_file_with_proofs_roundtrip() {
        let mut file = File::new();
        file.append_proof(vec![0x01, 0x02, 0x03]);
        file.append_proof(vec![0x04, 0x05]);
        file.append_proof(vec![0x06]);

        let encoded = file.encode();
        let decoded = File::decode(&encoded).unwrap();

        assert_eq!(decoded.num_proofs(), 3);
        assert_eq!(decoded.proofs[0].proof_bytes, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.proofs[1].proof_bytes, vec![0x04, 0x05]);
        assert_eq!(decoded.proofs[2].proof_bytes, vec![0x06]);
    }

    #[test]
    fn test_hash_chain() {
        let mut file = File::new();
        file.append_proof(vec![1, 2, 3]);
        file.append_proof(vec![4, 5, 6]);

        assert!(file.verify_hash_chain());

        // First proof hash = SHA256(zeros || [1,2,3]).
        let expected_first =
            compute_proof_hash(&[0u8; 32], &[1, 2, 3]);
        assert_eq!(file.proofs[0].hash, expected_first);

        // Second proof hash = SHA256(first_hash || [4,5,6]).
        let expected_second =
            compute_proof_hash(&expected_first, &[4, 5, 6]);
        assert_eq!(file.proofs[1].hash, expected_second);
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            File::decode(&data),
            Err(ProofError::InvalidMagic)
        ));
    }

    #[test]
    fn test_tampered_hash_detected() {
        let mut file = File::new();
        file.append_proof(vec![1, 2, 3]);

        let mut encoded = file.encode();
        // Tamper with the last byte of the hash.
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        assert!(File::decode(&encoded).is_err());
    }

    #[test]
    fn test_multibyte_length_uses_bigsize() {
        // A proof longer than 252 bytes exercises the multi-byte
        // BigSize length prefix, which is big-endian (0xFD + BE u16),
        // unlike Bitcoin compact size (LE). Matches Go's
        // tlv.WriteVarInt usage in proof/file.go.
        let mut file = File::new();
        file.append_proof(vec![0xAA; 300]);
        let encoded = file.encode();

        // magic(4) + version(4) + count(1) = 9; the length prefix
        // follows.
        assert_eq!(encoded[9], 0xFD);
        assert_eq!(&encoded[10..12], &300u16.to_be_bytes());

        let decoded = File::decode(&encoded).unwrap();
        assert_eq!(decoded.proofs[0].proof_bytes.len(), 300);
    }
}
