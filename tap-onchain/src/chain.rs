// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! External chain interaction traits.
//!
//! These traits abstract the chain backend, wallet, key derivation, and
//! signing operations. Concrete implementations are provided by the
//! integration layer (e.g., `tap-ldk` for LDK).

use tap_primitives::asset::SerializedKey;

/// Errors from chain operations.
#[derive(Debug, Clone)]
pub enum ChainError {
    /// Transaction broadcast failed.
    BroadcastFailed(String),
    /// Fee estimation failed.
    FeeEstimationFailed(String),
    /// Key derivation failed.
    KeyDerivationFailed(String),
    /// Signing failed.
    SigningFailed(String),
    /// PSBT operation failed.
    PsbtFailed(String),
    /// Confirmation wait timed out or failed.
    ConfirmationFailed(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BroadcastFailed(msg) => {
                write!(f, "broadcast failed: {}", msg)
            }
            ChainError::FeeEstimationFailed(msg) => {
                write!(f, "fee estimation failed: {}", msg)
            }
            ChainError::KeyDerivationFailed(msg) => {
                write!(f, "key derivation failed: {}", msg)
            }
            ChainError::SigningFailed(msg) => {
                write!(f, "signing failed: {}", msg)
            }
            ChainError::PsbtFailed(msg) => {
                write!(f, "PSBT failed: {}", msg)
            }
            ChainError::ConfirmationFailed(msg) => {
                write!(f, "confirmation failed: {}", msg)
            }
            ChainError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ChainError {}

/// Fee rate in satoshis per virtual kilobyte (sat/kvB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate(pub u64);

impl FeeRate {
    /// Minimum relay fee rate.
    pub const MIN_RELAY: FeeRate = FeeRate(1000);
}

/// A key descriptor identifying a derived key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyDescriptor {
    /// Key family (e.g., 212 for Taproot Assets).
    pub family: u16,
    /// Key index within the family.
    pub index: u32,
    /// The derived public key (compressed, 33 bytes).
    pub pub_key: SerializedKey,
}

/// Confirmation information for a transaction.
#[derive(Clone, Debug)]
pub struct TxConfirmation {
    /// Block hash containing the transaction.
    pub block_hash: [u8; 32],
    /// Block height.
    pub block_height: u32,
    /// Transaction index within the block.
    pub tx_index: u32,
    /// The confirmed transaction (raw bytes).
    pub tx: Vec<u8>,
}

/// Chain backend interface for blockchain interaction.
pub trait ChainBridge {
    /// Returns the current best block height.
    fn current_height(&self) -> Result<u32, ChainError>;

    /// Estimates the fee rate for confirmation within `conf_target` blocks.
    fn estimate_fee(&self, conf_target: u32) -> Result<FeeRate, ChainError>;

    /// Publishes a signed transaction to the network.
    fn publish_transaction(&self, tx: &[u8]) -> Result<(), ChainError>;

    /// Gets a block header hash by height.
    fn get_block_hash(&self, height: u32) -> Result<[u8; 32], ChainError>;
}

/// Wallet interface for PSBT operations and UTXO management.
pub trait WalletAnchor {
    /// Funds a PSBT by adding inputs and change outputs.
    ///
    /// `raw_psbt` is the unsigned PSBT to fund.
    /// Returns the funded PSBT bytes.
    fn fund_psbt(
        &self,
        raw_psbt: &[u8],
        fee_rate: FeeRate,
    ) -> Result<Vec<u8>, ChainError>;

    /// Signs and finalizes a funded PSBT.
    ///
    /// Returns the fully signed transaction bytes.
    fn sign_and_finalize_psbt(
        &self,
        funded_psbt: &[u8],
    ) -> Result<Vec<u8>, ChainError>;

    /// Imports a Taproot output so the wallet tracks it.
    fn import_taproot_output(
        &self,
        internal_key: &SerializedKey,
    ) -> Result<(), ChainError>;
}

/// Key derivation interface.
pub trait KeyRing {
    /// Derives the next key in the given key family.
    fn derive_next_key(
        &self,
        family: u16,
    ) -> Result<KeyDescriptor, ChainError>;

    /// Checks if a key descriptor belongs to the local wallet.
    fn is_local_key(
        &self,
        key_desc: &KeyDescriptor,
    ) -> Result<bool, ChainError>;
}

/// Signer interface for Taproot Asset virtual transactions.
pub trait AssetSigner {
    /// Signs a virtual transaction input.
    ///
    /// `signing_key` identifies which key to sign with.
    /// `virtual_tx` is the serialized virtual transaction.
    /// Returns the signature bytes.
    fn sign_virtual_tx(
        &self,
        signing_key: &KeyDescriptor,
        virtual_tx: &[u8],
    ) -> Result<Vec<u8>, ChainError>;
}

/// Persistence interface for minting state.
pub trait MintingStore {
    /// Persists a new minting batch.
    fn commit_batch(
        &self,
        batch: &super::mint::MintingBatch,
    ) -> Result<(), ChainError>;

    /// Updates a batch's state.
    fn update_batch_state(
        &self,
        batch_key: &SerializedKey,
        new_state: super::mint::BatchState,
    ) -> Result<(), ChainError>;

    /// Loads a batch by its key.
    fn load_batch(
        &self,
        batch_key: &SerializedKey,
    ) -> Result<Option<super::mint::MintingBatch>, ChainError>;

    /// Lists all batches.
    fn list_batches(
        &self,
    ) -> Result<Vec<super::mint::MintingBatch>, ChainError>;
}
