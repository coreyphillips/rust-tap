// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof system for the Taproot Assets Protocol.
//!
//! A proof links an individual asset to a confirmed Bitcoin transaction by
//! establishing:
//! 1. The anchor transaction is in a valid Bitcoin block ([`tx_merkle`])
//! 2. The asset is committed in a specific output (inclusion proof)
//! 3. The asset is NOT duplicated in other outputs (exclusion proofs)
//! 4. The state transition is valid (VM execution)
//!
//! Proofs are chained into [`File`]s — each proof's hash depends on the
//! previous proof, forming a provenance chain from genesis to current state.

pub mod encode;
pub mod file;
pub mod meta;
pub mod tx_merkle;
pub mod types;
pub mod verify;

pub use file::{File, HashedProof, FILE_MAGIC_BYTES, PROOF_MAGIC_BYTES};
pub use meta::{MetaReveal, MetaType};
pub use tx_merkle::TxMerkleProof;
pub use types::*;
pub use verify::{
    DefaultMerkleVerifier, GroupVerifier, HeaderVerifier, MerkleVerifier,
    VerifierCtx,
};
#[cfg(any(test, feature = "test-utils"))]
pub use verify::{TrustAllGroups, TrustAllHeaders};

/// Errors from proof operations.
#[derive(Debug, Clone)]
pub enum ProofError {
    FileTooShort,
    InvalidMagic,
    InvalidProofHash,
    TooManyProofs(usize),
    ProofTooLarge(usize),
    EmptyFile,
    UnknownTransitionVersion(u32),
    InvalidMetaType(u8),
    MetaTooLarge(usize),
    InvalidDecimalDisplay(u32),
    InvalidMetaReveal(String),
    GenesisMismatch,
    GenesisPrevOutMismatch,
    MetaHashMismatch,
    InvalidTxMerkleProof,
    InvalidInclusionProof(String),
    InvalidExclusionProof(String),
    VerificationFailed(String),
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::FileTooShort => write!(f, "proof file too short"),
            ProofError::InvalidMagic => write!(f, "invalid magic bytes"),
            ProofError::InvalidProofHash => {
                write!(f, "proof hash chain verification failed")
            }
            ProofError::TooManyProofs(n) => {
                write!(f, "too many proofs: {}", n)
            }
            ProofError::ProofTooLarge(n) => {
                write!(f, "proof too large: {} bytes", n)
            }
            ProofError::EmptyFile => write!(f, "empty proof file"),
            ProofError::UnknownTransitionVersion(v) => {
                write!(f, "unknown transition version: {}", v)
            }
            ProofError::InvalidMetaType(v) => {
                write!(f, "invalid meta type: {}", v)
            }
            ProofError::MetaTooLarge(n) => {
                write!(f, "metadata too large: {} bytes", n)
            }
            ProofError::InvalidDecimalDisplay(v) => {
                write!(f, "invalid decimal display: {}", v)
            }
            ProofError::InvalidMetaReveal(msg) => {
                write!(f, "invalid meta reveal: {}", msg)
            }
            ProofError::GenesisMismatch => {
                write!(f, "genesis reveal doesn't match asset")
            }
            ProofError::GenesisPrevOutMismatch => {
                write!(f, "genesis prev_out doesn't match proof")
            }
            ProofError::MetaHashMismatch => {
                write!(f, "meta hash doesn't match reveal")
            }
            ProofError::InvalidTxMerkleProof => {
                write!(f, "invalid tx merkle proof")
            }
            ProofError::InvalidInclusionProof(msg) => {
                write!(f, "invalid inclusion proof: {}", msg)
            }
            ProofError::InvalidExclusionProof(msg) => {
                write!(f, "invalid exclusion proof: {}", msg)
            }
            ProofError::VerificationFailed(msg) => {
                write!(f, "verification failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for ProofError {}
