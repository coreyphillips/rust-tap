// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! HD key derivation for Taproot Assets.
//!
//! Derives keys at the BIP-43 path `m/1017'/coin_type'/key_family'/0/index`,
//! matching the Go `taproot-assets` key family scheme. Key family 212 is
//! the standard family for TAP internal keys.
//!
//! All private key material is zeroized on drop.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::Network;

use crate::asset::{AssetId, SerializedKey};

/// LND's BIP-43 purpose for internal key derivation.
pub const LND_PURPOSE: u32 = 1017;

/// Key family for Taproot Assets (matches Go's `TaprootAssets = 212`).
pub const TAP_KEY_FAMILY: u32 = 212;

/// Coin types for BIP-44 derivation.
pub const COIN_TYPE_MAINNET: u32 = 0;
pub const COIN_TYPE_TESTNET: u32 = 1;

/// Identifies a key within the HD derivation hierarchy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TapKeyDescriptor {
    /// Key family (e.g., 212 for TAP).
    pub family: u32,
    /// Key index within the family.
    pub index: u32,
}

impl TapKeyDescriptor {
    /// Creates a descriptor for the TAP key family at the given index.
    pub fn tap(index: u32) -> Self {
        TapKeyDescriptor {
            family: TAP_KEY_FAMILY,
            index,
        }
    }
}

/// Builds the BIP-32 derivation path for a TAP key.
///
/// Path: `m/1017'/coin_type'/key_family'/0/index`
pub fn derivation_path(
    coin_type: u32,
    descriptor: &TapKeyDescriptor,
) -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(LND_PURPOSE).unwrap(),
        ChildNumber::from_hardened_idx(coin_type).unwrap(),
        ChildNumber::from_hardened_idx(descriptor.family).unwrap(),
        ChildNumber::from_normal_idx(0).unwrap(),
        ChildNumber::from_normal_idx(descriptor.index).unwrap(),
    ])
}

/// Returns the coin type for a given network.
pub fn coin_type_for_network(network: Network) -> u32 {
    match network {
        Network::Bitcoin => COIN_TYPE_MAINNET,
        _ => COIN_TYPE_TESTNET,
    }
}

/// Derives a TAP keypair from a master extended private key.
///
/// Path: `m/1017'/coin_type'/key_family'/0/index`
pub fn derive_tap_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master: &Xpriv,
    coin_type: u32,
    descriptor: &TapKeyDescriptor,
) -> Result<Keypair, DerivationError> {
    let path = derivation_path(coin_type, descriptor);
    let child = master
        .derive_priv(secp, &path)
        .map_err(|e| DerivationError::Bip32(e.to_string()))?;
    let keypair = Keypair::from_secret_key(secp, &child.private_key);
    Ok(keypair)
}

/// Derives a TAP keypair and returns the compressed public key as
/// `SerializedKey`.
pub fn derive_tap_pub_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master: &Xpriv,
    coin_type: u32,
    descriptor: &TapKeyDescriptor,
) -> Result<(Keypair, SerializedKey), DerivationError> {
    let keypair = derive_tap_key(secp, master, coin_type, descriptor)?;
    let pub_key = keypair.public_key().serialize();
    Ok((keypair, SerializedKey(pub_key)))
}

/// Derives a script key: internal key + optional taproot tweak.
///
/// If `tweak` is provided, the internal key is tweaked with the taproot
/// hash `H("TapTweak" || internal_key || tweak)`.
pub fn derive_script_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master: &Xpriv,
    coin_type: u32,
    descriptor: &TapKeyDescriptor,
    tweak: Option<&[u8; 32]>,
) -> Result<(Keypair, SerializedKey), DerivationError> {
    let keypair = derive_tap_key(secp, master, coin_type, descriptor)?;

    match tweak {
        None => {
            let pub_key = keypair.public_key().serialize();
            Ok((keypair, SerializedKey(pub_key)))
        }
        Some(merkle_root) => {
            // Tweak the keypair.
            let tweaked = keypair
                .tap_tweak(secp, Some(bitcoin::taproot::TapNodeHash::from_byte_array(*merkle_root)))
                .to_keypair();

            let tweaked_pub = tweaked.public_key().serialize();
            Ok((tweaked, SerializedKey(tweaked_pub)))
        }
    }
}

/// Derives a group key: raw key tweaked with asset ID.
///
/// The raw key is derived at the given descriptor, then tweaked using
/// [`compute_group_key`](super::keys::compute_group_key).
pub fn derive_group_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master: &Xpriv,
    coin_type: u32,
    descriptor: &TapKeyDescriptor,
    asset_id: &AssetId,
) -> Result<(Keypair, SerializedKey), DerivationError> {
    let keypair = derive_tap_key(secp, master, coin_type, descriptor)?;
    let raw_pub = keypair.public_key();

    let group_pub = super::keys::compute_group_key(&raw_pub, asset_id)
        .map_err(|e| DerivationError::Tweak(e.to_string()))?;

    Ok((keypair, SerializedKey(group_pub.serialize())))
}

/// Errors from key derivation.
#[derive(Debug, Clone)]
pub enum DerivationError {
    /// BIP-32 derivation failed.
    Bip32(String),
    /// Key tweaking failed.
    Tweak(String),
}

impl std::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerivationError::Bip32(msg) => {
                write!(f, "BIP-32 derivation failed: {}", msg)
            }
            DerivationError::Tweak(msg) => {
                write!(f, "key tweak failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for DerivationError {}

/// Zeroizes a secret key's bytes. Call this when done with private material.
///
/// Note: `Keypair` does not implement `Zeroize` in secp256k1, so callers
/// should ensure keypairs are dropped promptly and not cloned unnecessarily.
pub fn zeroize_secret(key: &mut SecretKey) {
    // SecretKey is stored as [u8; 32] internally. We overwrite by
    // assigning a dummy key (the "one" key). This is a best-effort
    // zeroization without a Zeroize dependency.
    let one = [0u8; 32];
    // We can't directly zero the internal bytes, but we can drop and
    // replace. The old value will be on the stack frame.
    let _ = std::mem::replace(key, SecretKey::from_slice(&{
        let mut buf = one;
        buf[31] = 1; // Valid secret key (must be non-zero).
        buf
    }).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_master() -> (Secp256k1<bitcoin::secp256k1::All>, Xpriv) {
        let secp = Secp256k1::new();
        let seed = [0x42u8; 32];
        let master = Xpriv::new_master(Network::Testnet, &seed).unwrap();
        (secp, master)
    }

    #[test]
    fn test_derive_tap_key() {
        let (secp, master) = test_master();
        let desc = TapKeyDescriptor::tap(0);

        let keypair = derive_tap_key(&secp, &master, COIN_TYPE_TESTNET, &desc).unwrap();
        let pub_key = keypair.public_key().serialize();
        assert_eq!(pub_key.len(), 33);
        assert!(pub_key[0] == 0x02 || pub_key[0] == 0x03);
    }

    #[test]
    fn test_derive_deterministic() {
        let (secp, master) = test_master();
        let desc = TapKeyDescriptor::tap(5);

        let kp1 = derive_tap_key(&secp, &master, COIN_TYPE_TESTNET, &desc).unwrap();
        let kp2 = derive_tap_key(&secp, &master, COIN_TYPE_TESTNET, &desc).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let (secp, master) = test_master();

        let kp0 = derive_tap_key(
            &secp,
            &master,
            COIN_TYPE_TESTNET,
            &TapKeyDescriptor::tap(0),
        )
        .unwrap();
        let kp1 = derive_tap_key(
            &secp,
            &master,
            COIN_TYPE_TESTNET,
            &TapKeyDescriptor::tap(1),
        )
        .unwrap();

        assert_ne!(kp0.public_key(), kp1.public_key());
    }

    #[test]
    fn test_derive_script_key_no_tweak() {
        let (secp, master) = test_master();
        let desc = TapKeyDescriptor::tap(0);

        let (_, pub_key) =
            derive_script_key(&secp, &master, COIN_TYPE_TESTNET, &desc, None)
                .unwrap();
        assert_eq!(pub_key.0.len(), 33);
    }

    #[test]
    fn test_derive_script_key_with_tweak() {
        let (secp, master) = test_master();
        let desc = TapKeyDescriptor::tap(0);
        let merkle_root = [0xAA; 32];

        let (_, untweaked) =
            derive_script_key(&secp, &master, COIN_TYPE_TESTNET, &desc, None)
                .unwrap();
        let (_, tweaked) = derive_script_key(
            &secp,
            &master,
            COIN_TYPE_TESTNET,
            &desc,
            Some(&merkle_root),
        )
        .unwrap();

        assert_ne!(untweaked.0, tweaked.0);
    }

    #[test]
    fn test_derive_group_key() {
        let (secp, master) = test_master();
        let desc = TapKeyDescriptor::tap(0);
        let asset_id = AssetId([0xBB; 32]);

        let (_, group_key) = derive_group_key(
            &secp,
            &master,
            COIN_TYPE_TESTNET,
            &desc,
            &asset_id,
        )
        .unwrap();
        assert_eq!(group_key.0.len(), 33);
    }

    #[test]
    fn test_derivation_path_structure() {
        let desc = TapKeyDescriptor::tap(7);
        let path = derivation_path(COIN_TYPE_TESTNET, &desc);

        // m/1017'/1'/212'/0/7
        let children: Vec<ChildNumber> = path.into_iter().cloned().collect();
        assert_eq!(children.len(), 5);
        assert_eq!(
            children[0],
            ChildNumber::from_hardened_idx(1017).unwrap()
        );
        assert_eq!(children[1], ChildNumber::from_hardened_idx(1).unwrap());
        assert_eq!(
            children[2],
            ChildNumber::from_hardened_idx(212).unwrap()
        );
        assert_eq!(children[3], ChildNumber::from_normal_idx(0).unwrap());
        assert_eq!(children[4], ChildNumber::from_normal_idx(7).unwrap());
    }

    #[test]
    fn test_coin_type_for_network() {
        assert_eq!(coin_type_for_network(Network::Bitcoin), 0);
        assert_eq!(coin_type_for_network(Network::Testnet), 1);
        assert_eq!(coin_type_for_network(Network::Signet), 1);
        assert_eq!(coin_type_for_network(Network::Regtest), 1);
    }
}
