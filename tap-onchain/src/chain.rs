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
    /// The raw 80-byte header of the block containing the transaction.
    ///
    /// Needed to finish transition/genesis proofs after confirmation.
    /// Stores that persist a `TxConfirmation` may not round-trip this
    /// field (it is transient confirmation-watch data); it is all
    /// zeroes when unknown.
    pub block_header: [u8; 80],
    /// All transaction hashes of the block, in block order and in
    /// internal (little-endian) byte order, for building the
    /// transaction merkle proof. Empty when unknown (see
    /// [`TxConfirmation::block_header`]).
    pub block_tx_hashes: Vec<[u8; 32]>,
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

    /// Looks up the confirmation state of a transaction.
    ///
    /// `txid` is in internal (little-endian) byte order, i.e. the same
    /// order used by [`tap_primitives::asset::OutPoint::txid`] and raw
    /// transaction serialization. Implementations that talk to block
    /// explorers must reverse it to obtain the display hex form.
    ///
    /// Returns `Ok(None)` while the transaction is unconfirmed, and a
    /// fully populated [`TxConfirmation`] (including the block header
    /// and the block's transaction hashes) once it has at least one
    /// confirmation.
    ///
    /// The default implementation reports the operation as
    /// unsupported, so backends without confirmation lookups keep
    /// compiling; confirmation watching is then disabled.
    fn get_tx_confirmation(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<TxConfirmation>, ChainError> {
        let _ = txid;
        Err(ChainError::Other(
            "get_tx_confirmation is not supported by this chain backend"
                .into(),
        ))
    }
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
    /// `signing_key` identifies the raw (pre-tweak) key to sign with,
    /// as previously returned by [`KeyRing::derive_next_key`].
    /// `virtual_tx` is the 32-byte BIP-341 key-spend sighash of the
    /// virtual transaction (not the serialized transaction itself);
    /// implementations should reject inputs that are not exactly 32
    /// bytes.
    ///
    /// # BIP-86 tweak contract
    ///
    /// Asset script keys are taproot output keys: by default they are
    /// derived from the raw key via the BIP-341 key-spend-only tweak
    /// with an empty script tree (`ScriptKey::bip86`, Go's
    /// `NewScriptKeyBip86`). Verifiers check the witness signature
    /// against that tweaked script key, so the signer MUST apply the
    /// same BIP-86 taproot tweak to the private key of `signing_key`
    /// before signing, and return the resulting 64-byte BIP-340
    /// Schnorr signature over the 32-byte digest.
    fn sign_virtual_tx(
        &self,
        signing_key: &KeyDescriptor,
        virtual_tx: &[u8],
    ) -> Result<Vec<u8>, ChainError>;

    /// Signs a virtual transaction input for a script key that commits
    /// to a tapscript tree (key-spend path with a script root).
    ///
    /// Like [`AssetSigner::sign_virtual_tx`], `virtual_tx` is the
    /// 32-byte BIP-341 key-spend sighash and `signing_key` identifies
    /// the raw (pre-tweak) key, but the taproot tweak applied to the
    /// private key before signing depends on `tapscript_root`:
    ///
    /// - `None`: the BIP-86 key-spend-only tweak with an empty script
    ///   tree, i.e. `TapTweakHash(internal_pub)`. Identical to
    ///   [`AssetSigner::sign_virtual_tx`]; the default implementation
    ///   delegates to it.
    /// - `Some(root)`: the BIP-341 tweak with the given 32-byte
    ///   tapscript merkle root, i.e.
    ///   `TapTweakHash(internal_pub, root)` added to the private key
    ///   (negated first if its public key has odd Y). This matches
    ///   Go's `lndclient.SignDescriptor` with
    ///   `TaprootKeySpendSignMethod` and `TapTweak = root`
    ///   (tapsend.CreateTaprootSignature), and is what V2-address
    ///   unique Pedersen script keys require: their script key is the
    ///   taproot output key of the address key tweaked with the
    ///   Pedersen non-spendable leaf's tap hash
    ///   (`derive_unique_script_key`).
    ///
    /// Returns the 64-byte BIP-340 Schnorr signature over the digest.
    ///
    /// The default implementation only supports `None` (it delegates
    /// to [`AssetSigner::sign_virtual_tx`]); for `Some(root)` it fails
    /// with a precise error, so implementations that predate this
    /// method keep working for BIP-86 keys and reject
    /// tapscript-tweaked keys loudly instead of producing invalid
    /// signatures.
    fn sign_virtual_tx_tweaked(
        &self,
        signing_key: &KeyDescriptor,
        virtual_tx: &[u8],
        tapscript_root: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, ChainError> {
        match tapscript_root {
            None => self.sign_virtual_tx(signing_key, virtual_tx),
            Some(_) => Err(ChainError::SigningFailed(
                "this AssetSigner does not implement \
                 sign_virtual_tx_tweaked: signing a script key that \
                 commits to a tapscript root (e.g. a V2-address \
                 unique Pedersen script key) requires overriding \
                 AssetSigner::sign_virtual_tx_tweaked to apply the \
                 BIP-341 TapTweakHash(internal_key, root) tweak"
                    .into(),
            )),
        }
    }
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
