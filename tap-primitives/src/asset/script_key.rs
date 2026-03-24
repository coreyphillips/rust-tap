// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Script key types and the NUMS (Nothing-Up-My-Sleeve) point.

use super::types::*;

/// The NUMS (Nothing-Up-My-Sleeve) point used for un-spendable script keys.
///
/// Generated via try-and-increment with the phrase "taproot-assets" using
/// SHA2-256. Compressed form (33 bytes):
/// `027c79b9b26e463895eef5679d8558942c86c4ad2233adef01bc3e6d540b3653fe`
pub const NUMS_BYTES: [u8; 33] = [
    0x02, 0x7c, 0x79, 0xb9, 0xb2, 0x6e, 0x46, 0x38, 0x95, 0xee, 0xf5, 0x67,
    0x9d, 0x85, 0x58, 0x94, 0x2c, 0x86, 0xc4, 0xad, 0x22, 0x33, 0xad, 0xef,
    0x01, 0xbc, 0x3e, 0x6d, 0x54, 0x0b, 0x36, 0x53, 0xfe,
];

/// The NUMS point as a [`SerializedKey`].
pub const NUMS_KEY: SerializedKey = SerializedKey(NUMS_BYTES);

/// A script key that authorizes spending of a Taproot Asset.
///
/// This is the tweaked Taproot output key. The optional [`TweakedScriptKey`]
/// contains the internal (pre-tweak) key and tweak details, which are needed
/// for spending but not for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptKey {
    /// The tweaked public key (compressed, 33 bytes).
    pub pub_key: SerializedKey,
    /// Optional tweak information (needed for spending, not for commitment).
    pub tweaked: Option<TweakedScriptKey>,
}

impl ScriptKey {
    /// Creates a new script key from a compressed public key.
    pub fn from_pub_key(pub_key: SerializedKey) -> Self {
        ScriptKey {
            pub_key,
            tweaked: None,
        }
    }

    /// Creates a BIP-86 tweaked script key from a raw internal key.
    ///
    /// This applies the BIP-341 key-spend-only tweak (no script path),
    /// matching Go's `NewScriptKeyBip86`. The resulting public key always
    /// has even-y parity (0x02 prefix).
    pub fn bip86(raw_key: SerializedKey) -> Self {
        use bitcoin::secp256k1::XOnlyPublicKey;
        use crate::crypto::keys::tweak_pub_key;

        let x_only = XOnlyPublicKey::from_slice(&raw_key.0[1..])
            .expect("valid 32-byte x-only key");
        let (tweaked, _parity) = tweak_pub_key(&x_only, None)
            .expect("BIP-86 tweak should not fail");

        // X-only keys always have even-y → 0x02 prefix.
        let mut pub_key_bytes = [0u8; 33];
        pub_key_bytes[0] = 0x02;
        pub_key_bytes[1..].copy_from_slice(&tweaked.serialize());

        ScriptKey {
            pub_key: SerializedKey(pub_key_bytes),
            tweaked: Some(TweakedScriptKey {
                raw_key,
                tweak: vec![],
                key_type: ScriptKeyType::Bip86,
            }),
        }
    }

    /// Returns true if this script key is the NUMS point (un-spendable).
    pub fn is_nums(&self) -> bool {
        self.pub_key == NUMS_KEY
    }

    /// Returns the serialized compressed public key.
    pub fn serialized(&self) -> &SerializedKey {
        &self.pub_key
    }
}

/// Pre-tweak key information for a script key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TweakedScriptKey {
    /// The raw (pre-tweak) public key.
    pub raw_key: SerializedKey,
    /// The tweak applied to produce the script key. Empty means BIP-86 style
    /// (tweak with no script path).
    pub tweak: Vec<u8>,
    /// The type classification of this script key.
    pub key_type: ScriptKeyType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nums_key_constant() {
        // Verify the NUMS key has the expected prefix byte (0x02 = even y).
        assert_eq!(NUMS_BYTES[0], 0x02);
        assert_eq!(NUMS_BYTES.len(), 33);
    }

    #[test]
    fn test_script_key_is_nums() {
        let key = ScriptKey::from_pub_key(NUMS_KEY);
        assert!(key.is_nums());

        let other = ScriptKey::from_pub_key(SerializedKey([0x03; 33]));
        assert!(!other.is_nums());
    }
}
