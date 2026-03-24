// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Key derivation and taproot tweaking for Taproot Assets.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, XOnlyPublicKey};

use crate::asset::{AssetId, SerializedKey};

/// Errors from key operations.
#[derive(Debug, Clone)]
pub enum KeyError {
    InvalidPublicKey(String),
    TweakFailed(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::InvalidPublicKey(msg) => {
                write!(f, "invalid public key: {}", msg)
            }
            KeyError::TweakFailed(msg) => {
                write!(f, "tweak failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// Parses a compressed 33-byte public key from a [`SerializedKey`].
pub fn parse_pub_key(key: &SerializedKey) -> Result<PublicKey, KeyError> {
    PublicKey::from_slice(key.as_bytes())
        .map_err(|e| KeyError::InvalidPublicKey(e.to_string()))
}

/// Serializes a [`PublicKey`] to a [`SerializedKey`] (33-byte compressed).
pub fn serialize_pub_key(key: &PublicKey) -> SerializedKey {
    SerializedKey(key.serialize())
}

/// Computes a taproot-tweaked output key from an internal key and an
/// optional merkle root.
///
/// This implements BIP-341 key tweaking:
/// `output_key = internal_key + H("TapTweak" || internal_key || merkle_root) * G`
///
/// If `merkle_root` is `None`, the tweak is computed with just the internal
/// key (BIP-86 style, no script path).
pub fn tweak_pub_key(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<(XOnlyPublicKey, secp256k1::Parity), KeyError> {
    let secp = Secp256k1::new();
    let tweak = compute_tap_tweak(internal_key, merkle_root);
    let (tweaked, parity) = internal_key
        .add_tweak(
            &secp,
            &secp256k1::Scalar::from_be_bytes(tweak)
                .map_err(|e| KeyError::TweakFailed(e.to_string()))?,
        )
        .map_err(|e| KeyError::TweakFailed(e.to_string()))?;
    Ok((tweaked, parity))
}

/// Computes the taproot output key for a P2TR output.
///
/// Convenience wrapper around [`tweak_pub_key`] that returns just the
/// x-only key.
pub fn compute_taproot_output_key(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> Result<XOnlyPublicKey, KeyError> {
    let (output_key, _) = tweak_pub_key(internal_key, merkle_root)?;
    Ok(output_key)
}

/// Computes the BIP-341 TapTweak hash.
///
/// `H("TapTweak" || internal_key || merkle_root)` or
/// `H("TapTweak" || internal_key)` if no merkle root.
fn compute_tap_tweak(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&[u8; 32]>,
) -> [u8; 32] {
    // BIP-341 tagged hash: SHA256(SHA256("TapTweak") || SHA256("TapTweak") || msg)
    let tag_hash = sha256::Hash::hash(b"TapTweak").to_byte_array();
    let mut engine = sha256::HashEngine::default();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    engine.input(&internal_key.serialize());
    if let Some(root) = merkle_root {
        engine.input(root);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Computes a Taproot Assets group key from a raw key and genesis asset ID.
///
/// For GroupKeyV0: the group key is tweaked with the asset ID.
/// `group_pub_key = raw_key + H("TapTweak" || raw_key || asset_id) * G`
///
/// This matches Go's group key derivation where the asset ID is used as the
/// tapscript merkle root for the tweak.
pub fn compute_group_key(
    raw_key: &PublicKey,
    asset_id: &AssetId,
) -> Result<PublicKey, KeyError> {
    let (x_only, _parity) = raw_key.x_only_public_key();
    let (tweaked_x, parity) =
        tweak_pub_key(&x_only, Some(asset_id.as_bytes()))?;

    // Convert back to a full PublicKey with the correct parity.
    let parity_byte = if parity == secp256k1::Parity::Even {
        0x02
    } else {
        0x03
    };
    let mut full_key = [0u8; 33];
    full_key[0] = parity_byte;
    full_key[1..].copy_from_slice(&tweaked_x.serialize());

    PublicKey::from_slice(&full_key)
        .map_err(|e| KeyError::InvalidPublicKey(e.to_string()))
}

/// Verifies that a group key was correctly derived from a raw key and
/// asset ID.
pub fn verify_group_key(
    group_pub_key: &PublicKey,
    raw_key: &PublicKey,
    asset_id: &AssetId,
) -> Result<bool, KeyError> {
    let expected = compute_group_key(raw_key, asset_id)?;
    Ok(*group_pub_key == expected)
}

/// Verifies the NUMS (Nothing-Up-My-Sleeve) key constant.
///
/// The NUMS key was generated via try-and-increment with "taproot-assets"
/// phrase using SHA-256. This function verifies it's a valid curve point.
pub fn verify_nums_key() -> bool {
    let nums_bytes = crate::asset::NUMS_BYTES;
    PublicKey::from_slice(&nums_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::NUMS_BYTES;

    #[test]
    fn test_nums_key_is_valid_point() {
        assert!(verify_nums_key());
        let key = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        // Should be on the curve — verify by serialization roundtrip.
        let reserialized = key.serialize();
        assert_eq!(reserialized, NUMS_BYTES);
    }

    #[test]
    fn test_parse_serialize_roundtrip() {
        let key_bytes = SerializedKey(NUMS_BYTES);
        let parsed = parse_pub_key(&key_bytes).unwrap();
        let reserialized = serialize_pub_key(&parsed);
        assert_eq!(reserialized, key_bytes);
    }

    #[test]
    fn test_taproot_tweak_deterministic() {
        let key = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let (x_only, _) = key.x_only_public_key();
        let root = [0xAA; 32];

        let (tweaked1, p1) = tweak_pub_key(&x_only, Some(&root)).unwrap();
        let (tweaked2, p2) = tweak_pub_key(&x_only, Some(&root)).unwrap();
        assert_eq!(tweaked1, tweaked2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_taproot_tweak_different_roots() {
        let key = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let (x_only, _) = key.x_only_public_key();

        let (tweaked_a, _) =
            tweak_pub_key(&x_only, Some(&[0xAA; 32])).unwrap();
        let (tweaked_b, _) =
            tweak_pub_key(&x_only, Some(&[0xBB; 32])).unwrap();
        assert_ne!(tweaked_a, tweaked_b);
    }

    #[test]
    fn test_bip86_tweak_no_script() {
        let key = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let (x_only, _) = key.x_only_public_key();

        // BIP-86: tweak with no merkle root.
        let (tweaked, _) = tweak_pub_key(&x_only, None).unwrap();
        // Should differ from untweaked.
        assert_ne!(tweaked, x_only);
    }

    #[test]
    fn test_compute_group_key() {
        let raw = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let asset_id = AssetId([0x42; 32]);

        let group_key = compute_group_key(&raw, &asset_id).unwrap();
        // Should be a valid point different from the raw key.
        assert_ne!(group_key, raw);

        // Verification should pass.
        assert!(verify_group_key(&group_key, &raw, &asset_id).unwrap());
    }

    #[test]
    fn test_group_key_different_ids() {
        let raw = PublicKey::from_slice(&NUMS_BYTES).unwrap();

        let gk1 = compute_group_key(&raw, &AssetId([0x01; 32])).unwrap();
        let gk2 = compute_group_key(&raw, &AssetId([0x02; 32])).unwrap();
        assert_ne!(gk1, gk2);
    }

    #[test]
    fn test_group_key_verification_fails_wrong_id() {
        let raw = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let asset_id = AssetId([0x42; 32]);
        let group_key = compute_group_key(&raw, &asset_id).unwrap();

        let wrong_id = AssetId([0x43; 32]);
        assert!(!verify_group_key(&group_key, &raw, &wrong_id).unwrap());
    }

    #[test]
    fn test_compute_taproot_output_key() {
        let key = PublicKey::from_slice(&NUMS_BYTES).unwrap();
        let (x_only, _) = key.x_only_public_key();
        let root = [0xBB; 32];

        let output_key =
            compute_taproot_output_key(&x_only, Some(&root)).unwrap();
        // Should be a valid x-only key.
        assert_eq!(output_key.serialize().len(), 32);
    }

    #[test]
    fn test_invalid_key_rejected() {
        let bad = SerializedKey([0x00; 33]);
        assert!(parse_pub_key(&bad).is_err());
    }
}
