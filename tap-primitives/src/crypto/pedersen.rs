// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Pedersen commitments and NUMS xpub helpers.
//!
//! Mirrors Go's `internal/pedersen/commitment.go` and the NUMS xpub
//! helpers `NumsXPub` / `TweakedNumsKey` in `asset/group_key.go`.
//! These primitives are used for non-spendable tapscript leaves (group
//! key V1, unique script keys) and later for supply commitments.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::NetworkKind;

/// Errors from Pedersen commitment and NUMS key operations.
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// A scalar or point operation failed.
    InvalidScalar(String),
    /// A public key could not be parsed or derived.
    InvalidPublicKey(String),
    /// The resulting commitment is the point at infinity, which cannot
    /// be represented as a public key.
    PointAtInfinity,
    /// A BIP-32 derivation failed.
    DerivationFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidScalar(msg) => {
                write!(f, "invalid scalar: {}", msg)
            }
            CryptoError::InvalidPublicKey(msg) => {
                write!(f, "invalid public key: {}", msg)
            }
            CryptoError::PointAtInfinity => {
                write!(f, "commitment is the point at infinity")
            }
            CryptoError::DerivationFailed(msg) => {
                write!(f, "derivation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// lnd's Taproot NUMS key (`input.TaprootNUMSKey`), used as the default
/// auxiliary generator `H` for Pedersen commitments.
///
/// This is a NUMS (nothing up my sleeve) point with no known private
/// key, generated with the seed phrase "Lightning Simple Taproot" (see
/// lnd `input/script_utils.go`). Note this is NOT the taproot-assets
/// asset NUMS key (`asset::NUMS_BYTES`).
pub const TAPROOT_NUMS_BYTES: [u8; 33] = [
    0x02, 0xdc, 0xa0, 0x94, 0x75, 0x11, 0x09, 0xd0, 0xbd, 0x05, 0x5d, 0x03,
    0x56, 0x58, 0x74, 0xe8, 0x27, 0x6d, 0xd5, 0x3e, 0x92, 0x6b, 0x44, 0xe3,
    0xbd, 0x1b, 0xb6, 0xbf, 0x4b, 0xc1, 0x30, 0xa2, 0x79,
];

/// Returns lnd's Taproot NUMS key as a parsed public key.
pub fn taproot_nums_key() -> Result<PublicKey, CryptoError> {
    PublicKey::from_slice(&TAPROOT_NUMS_BYTES)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))
}

/// The opening to a Pedersen commitment, mirroring Go's
/// `pedersen.Opening`. It contains a message and an optional mask. If
/// the mask is left off, the commitment loses its hiding property (two
/// identical messages map to the same point) but stays binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The message that is committed to.
    pub msg: [u8; 32],
    /// The mask used to blind the message (`r` in the Pedersen
    /// commitment literature). If absent, the scalar value one is used,
    /// matching Go.
    pub mask: Option<[u8; 32]>,
    /// An optional custom NUMS point to use instead of the default
    /// (lnd's Taproot NUMS key).
    pub nums: Option<PublicKey>,
}

/// The secp256k1 curve order N, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Reduces a 32-byte big-endian value modulo the curve order N,
/// matching Go's `ModNScalar.SetByteSlice` semantics (used via
/// `btcec.PrivKeyFromBytes`). Since the input is below 2^256 < 2N, a
/// single conditional subtraction suffices.
fn reduce_mod_n(bytes: [u8; 32]) -> [u8; 32] {
    if bytes < CURVE_ORDER {
        return bytes;
    }

    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = bytes[i] as i16 - CURVE_ORDER[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// Creates a new Pedersen commitment `C = m*G + r*H` from the given
/// opening, mirroring Go's `pedersen.NewCommitment`:
/// - `m` is the message reduced modulo N,
/// - `r` is the mask reduced modulo N, or the scalar one if no mask is
///   given (binding-only commitment),
/// - `H` is the opening's NUMS point, or lnd's Taproot NUMS key by
///   default.
pub fn new_commitment(op: &Opening) -> Result<PublicKey, CryptoError> {
    let secp = Secp256k1::new();

    let nums = match op.nums {
        Some(nums) => nums,
        None => taproot_nums_key()?,
    };

    // The message point m*G. A zero scalar maps to the point at
    // infinity, which the Rust API cannot represent, so track it as
    // absent (Go handles this transparently in Jacobian arithmetic).
    let msg_scalar = reduce_mod_n(op.msg);
    let msg_point = if msg_scalar == [0u8; 32] {
        None
    } else {
        let sk = SecretKey::from_slice(&msg_scalar)
            .map_err(|e| CryptoError::InvalidScalar(e.to_string()))?;
        Some(PublicKey::from_secret_key(&secp, &sk))
    };

    // The blinding point r*H. With no mask, r is one, so the blinding
    // point is the NUMS point itself.
    let blinding_point = match op.mask {
        None => Some(nums),
        Some(mask) => {
            let r = reduce_mod_n(mask);
            if r == [0u8; 32] {
                None
            } else {
                let scalar = Scalar::from_be_bytes(r).map_err(|e| {
                    CryptoError::InvalidScalar(e.to_string())
                })?;
                Some(nums.mul_tweak(&secp, &scalar).map_err(|e| {
                    CryptoError::InvalidScalar(e.to_string())
                })?)
            }
        }
    };

    match (msg_point, blinding_point) {
        (Some(m), Some(b)) => {
            m.combine(&b).map_err(|_| CryptoError::PointAtInfinity)
        }
        (Some(m), None) => Ok(m),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(CryptoError::PointAtInfinity),
    }
}

/// Verifies that `commitment` is the Pedersen commitment for the given
/// opening, mirroring Go's `Commitment.Verify`.
pub fn verify_commitment(
    commitment: &PublicKey,
    op: &Opening,
) -> Result<bool, CryptoError> {
    let expected = new_commitment(op)?;
    Ok(*commitment == expected)
}

/// Turns the given NUMS key into an extended public key (using the x
/// coordinate of the public key as the chain code), then derives the
/// actual key to use from the derivation path 0/0. Mirrors Go's
/// `asset.NumsXPub`.
///
/// The extended key always has the mainnet version and emulates a
/// depth-3 (BIP-44/49/84/86 style) xpub with a zero parent fingerprint
/// and zero child number.
pub fn nums_xpub(
    nums_key: &PublicKey,
) -> Result<(Xpub, PublicKey), CryptoError> {
    let secp = Secp256k1::new();

    let key_bytes = nums_key.serialize();
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&key_bytes[1..33]);

    let child_zero = ChildNumber::from_normal_idx(0)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;

    let extended_nums_key = Xpub {
        network: NetworkKind::Main,
        depth: 3,
        parent_fingerprint: Fingerprint::from([0u8; 4]),
        child_number: child_zero,
        public_key: *nums_key,
        chain_code: ChainCode::from(chain_code),
    };

    // Derive the actual key to use from the xpub at path 0/0.
    let change_branch = extended_nums_key
        .ckd_pub(&secp, child_zero)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;
    let index_branch = change_branch
        .ckd_pub(&secp, child_zero)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;

    Ok((extended_nums_key, index_branch.public_key))
}

/// Derives the Pedersen NUMS key from the given message (no mask, so
/// binding only), creates the extended key from the commitment point
/// and derives the actual key to use from the derivation path 0/0.
/// Mirrors Go's `asset.TweakedNumsKey`.
pub fn tweaked_nums_key(
    msg: [u8; 32],
) -> Result<(Xpub, PublicKey), CryptoError> {
    let op = Opening {
        msg,
        mask: None,
        nums: None,
    };
    let commit_point = new_commitment(&op)?;
    nums_xpub(&commit_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key_from_hex(s: &str) -> PublicKey {
        PublicKey::from_slice(&hex_decode(s)).unwrap()
    }

    fn seq_msg() -> [u8; 32] {
        let mut msg = [0u8; 32];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        msg
    }

    #[test]
    fn test_taproot_nums_key_constant() {
        // lnd input.TaprootNUMSKey
        // (02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279).
        let key = taproot_nums_key().unwrap();
        assert_eq!(
            key.serialize().to_vec(),
            hex_decode(
                "02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6\
                 bf4bc130a279"
            )
        );
    }

    // The expected commitment points below were generated by executing
    // the Go reference (internal/pedersen/commitment.go, v0.8.99-alpha)
    // with the same inputs.

    #[test]
    fn test_commitment_no_mask_go_vector() {
        let op = Opening {
            msg: seq_msg(),
            mask: None,
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(
            commit,
            key_from_hex(
                "02f15a07f62156c3a52cdea9267aeeae988e202e6e93e5f1e16681\
                 75a17446e8ad"
            )
        );
    }

    #[test]
    fn test_commitment_with_mask_go_vector() {
        let op = Opening {
            msg: seq_msg(),
            mask: Some([0xaa; 32]),
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(
            commit,
            key_from_hex(
                "032d7e3aea15e5ac86cb8da12b3b0419c7d0a0d552c919c8285ce5\
                 e3d675f3ebba"
            )
        );
    }

    #[test]
    fn test_commitment_zero_msg_is_nums() {
        // With a zero message and no mask, the commitment is
        // 0*G + 1*H = H, the NUMS point itself (verified against Go).
        let op = Opening {
            msg: [0u8; 32],
            mask: None,
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(commit, taproot_nums_key().unwrap());
    }

    #[test]
    fn test_commitment_msg_reduced_mod_n_go_vector() {
        // msg = ff..ff >= N is reduced modulo N by Go's
        // btcec.PrivKeyFromBytes; verify we match.
        let op = Opening {
            msg: [0xff; 32],
            mask: None,
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(
            commit,
            key_from_hex(
                "03c1200af171bff1a2538900c0edbf2e9b83dd2958acf540418a69\
                 e6ddce00d703"
            )
        );
    }

    #[test]
    fn test_commitment_mask_reduced_mod_n_go_vector() {
        let op = Opening {
            msg: seq_msg(),
            mask: Some([0xff; 32]),
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(
            commit,
            key_from_hex(
                "0337b364687d5464a1eebb02fa40582b533320916a37c140ace4a7\
                 c65e98e65ef5"
            )
        );
    }

    #[test]
    fn test_commitment_custom_nums_go_vector() {
        // Custom NUMS point: public key of the private key 0x11
        // repeated 32 times.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let custom = PublicKey::from_secret_key(&secp, &sk);

        let op = Opening {
            msg: seq_msg(),
            mask: None,
            nums: Some(custom),
        };
        let commit = new_commitment(&op).unwrap();
        assert_eq!(
            commit,
            key_from_hex(
                "029b97f3e12dac7aa011582c831049640bfcff00adfe003625db4e\
                 34d5220e085e"
            )
        );
    }

    // Deterministic ports of the applicable Go
    // TestPedersenCommitmentProperties sub-cases (the Go tests are
    // property-based; here we exercise the same properties with fixed
    // inputs).

    #[test]
    fn test_correctness_verifies_with_own_opening() {
        let op = Opening {
            msg: seq_msg(),
            mask: Some([0x55; 32]),
            nums: None,
        };
        let commit = new_commitment(&op).unwrap();
        assert!(verify_commitment(&commit, &op).unwrap());
    }

    #[test]
    fn test_uniqueness_different_messages() {
        let mask = Some([0x55; 32]);
        let op1 = Opening {
            msg: [0x01; 32],
            mask,
            nums: None,
        };
        let op2 = Opening {
            msg: [0x02; 32],
            mask,
            nums: None,
        };
        assert_ne!(
            new_commitment(&op1).unwrap(),
            new_commitment(&op2).unwrap()
        );
    }

    #[test]
    fn test_binding_rejects_different_opening() {
        let op1 = Opening {
            msg: [0x01; 32],
            mask: Some([0x11; 32]),
            nums: None,
        };
        let op2 = Opening {
            msg: [0x02; 32],
            mask: Some([0x22; 32]),
            nums: None,
        };
        let commit = new_commitment(&op1).unwrap();
        assert!(!verify_commitment(&commit, &op2).unwrap());
    }

    #[test]
    fn test_no_mask_binding_and_deterministic() {
        let op = Opening {
            msg: seq_msg(),
            mask: None,
            nums: None,
        };
        let c1 = new_commitment(&op).unwrap();
        let c2 = new_commitment(&op).unwrap();
        assert_eq!(c1, c2);
        assert!(verify_commitment(&c1, &op).unwrap());
    }

    #[test]
    fn test_custom_nums_verifies() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let custom = PublicKey::from_secret_key(&secp, &sk);

        let op = Opening {
            msg: seq_msg(),
            mask: Some([0xaa; 32]),
            nums: Some(custom),
        };
        let commit = new_commitment(&op).unwrap();
        assert!(verify_commitment(&commit, &op).unwrap());

        // With the default NUMS instead, verification must fail.
        let op_default = Opening {
            msg: seq_msg(),
            mask: Some([0xaa; 32]),
            nums: None,
        };
        assert!(!verify_commitment(&commit, &op_default).unwrap());
    }

    // NUMS xpub vectors generated by executing the Go reference
    // (asset.NumsXPub / asset.TweakedNumsKey, asset/group_key.go).

    #[test]
    fn test_nums_xpub_go_vector() {
        let nums = taproot_nums_key().unwrap();
        let (xpub, derived) = nums_xpub(&nums).unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub6BemYiVEULcbr3ioaUDFarAjVa3Q3qBNcu1Ngseg7gBjJLZL1WDnoeR\
             3tHYRS67FZz9oZmzPbxQaEbEjz5cgZXrzJPwgX4kdurxxpSAow5k"
        );
        assert_eq!(
            derived,
            key_from_hex(
                "0218e3b554e2fc16d265c00348b395aa6d04d7ce62ef2139d7ed3b\
                 c5b32e62bae3"
            )
        );
    }

    #[test]
    fn test_tweaked_nums_key_zero_msg_go_vector() {
        // Pedersen commit of a zero message is the NUMS point itself,
        // so the tweaked NUMS key of the zero message equals
        // nums_xpub(NUMS).
        let (xpub, key) = tweaked_nums_key([0u8; 32]).unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub6BemYiVEULcbr3ioaUDFarAjVa3Q3qBNcu1Ngseg7gBjJLZL1WDnoeR\
             3tHYRS67FZz9oZmzPbxQaEbEjz5cgZXrzJPwgX4kdurxxpSAow5k"
        );
        assert_eq!(
            key,
            key_from_hex(
                "0218e3b554e2fc16d265c00348b395aa6d04d7ce62ef2139d7ed3b\
                 c5b32e62bae3"
            )
        );
    }

    #[test]
    fn test_tweaked_nums_key_go_vector() {
        let (xpub, key) = tweaked_nums_key(seq_msg()).unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub6BemYiVEULcbrFgucZdfyfF6Yp34nF5wvpJsEA21w5PoUzqwEfzDLRy\
             t1jsNGiHgHaJXWQkCisTAez4zFVj4Gi8g19NvELZ6DZBCQ2gFoMn"
        );
        assert_eq!(
            key,
            key_from_hex(
                "02f564f33583322ffd97284abb8ecdb69959964e90cb0c2855e0de\
                 67e0a10573f6"
            )
        );
    }

    #[test]
    fn test_reduce_mod_n() {
        assert_eq!(reduce_mod_n([0u8; 32]), [0u8; 32]);
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0u8; 32]);

        let mut below = CURVE_ORDER;
        below[31] -= 1;
        assert_eq!(reduce_mod_n(below), below);

        // ff..ff mod N = 2^256 - 1 - N.
        let reduced = reduce_mod_n([0xff; 32]);
        let expected_tail = [
            0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40,
            0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbe,
        ];
        assert_eq!(&reduced[..15], &[0u8; 15]);
        assert_eq!(&reduced[15..], &expected_tail[..]);
    }
}
