// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! ECIES (Elliptic Curve Integrated Encryption Scheme) encryption,
//! byte-compatible with Go's `internal/ecies` package.
//!
//! Uses XChaCha20-Poly1305 for encryption and HKDF-SHA256 for key
//! derivation. Messages are encrypted with a shared secret derived
//! between two parties via ECDH (the sender uses an ephemeral key whose
//! public part travels as the additional data).
//!
//! Wire format of an encrypted message:
//!
//! `<1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
//! <* bytes ciphertext+tag>`

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Protocol name used to salt the HKDF key derivation. Matches Go's
/// `protocolName` (internal/ecies/ecies.go).
const PROTOCOL_NAME: &[u8] = b"ECIES-HKDF-SHA256-XCHA20POLY1305";

/// XChaCha20-Poly1305 extended nonce size in bytes.
const NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size in bytes.
const TAG_SIZE: usize = 16;

/// The version of the ECIES encoding format. Mirrors Go's
/// `ecies.Version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EciesVersion {
    /// The initial version of the ECIES encoding format.
    V1 = 1,
}

/// The latest supported ECIES protocol version, matching Go's
/// `latestVersion`.
pub const LATEST_ECIES_VERSION: EciesVersion = EciesVersion::V1;

/// Errors from ECIES operations.
#[derive(Debug, Clone)]
pub enum EciesError {
    /// The additional data exceeds the 255-byte limit.
    AdditionalDataTooLong(usize),
    /// The ciphertext is shorter than the minimum valid length.
    CiphertextTooShort { given: usize, minimum: usize },
    /// The encoded version byte is not supported.
    UnsupportedVersion(u8),
    /// AEAD decryption failed (wrong key or tampered message).
    DecryptionFailed,
    /// Randomness could not be obtained for the nonce.
    RngFailure(String),
    /// An invalid key was supplied.
    InvalidKey(String),
}

impl std::fmt::Display for EciesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EciesError::AdditionalDataTooLong(n) => write!(
                f,
                "additional data too long: {} bytes given, 255 bytes \
                 maximum",
                n
            ),
            EciesError::CiphertextTooShort { given, minimum } => write!(
                f,
                "ciphertext too short: {} bytes given, {} bytes minimum",
                given, minimum
            ),
            EciesError::UnsupportedVersion(v) => {
                write!(f, "unsupported version: {}", v)
            }
            EciesError::DecryptionFailed => {
                write!(f, "cannot decrypt message")
            }
            EciesError::RngFailure(msg) => {
                write!(f, "cannot read random nonce: {}", msg)
            }
            EciesError::InvalidKey(msg) => {
                write!(f, "invalid key: {}", msg)
            }
        }
    }
}

impl std::error::Error for EciesError {}

/// Performs a scalar multiplication (ECDH-like operation) between the
/// private key and the remote public key, mirroring Go's `ecies.ECDH`.
///
/// If `k` is our private key and `P` the public key:
///
/// ```text
/// sx = k*P
/// s = sha256(sx.SerializeCompressed())
/// ```
///
/// Note this hashes the full compressed point (prefix byte included),
/// unlike some ECDH variants that only hash the x coordinate.
pub fn ecdh(
    priv_key: &SecretKey,
    pub_key: &PublicKey,
) -> Result<[u8; 32], EciesError> {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(priv_key.secret_bytes())
        .map_err(|e| EciesError::InvalidKey(e.to_string()))?;
    let shared_point = pub_key
        .mul_tweak(&secp, &scalar)
        .map_err(|e| EciesError::InvalidKey(e.to_string()))?;

    let digest = Sha256::digest(shared_point.serialize());
    Ok(digest.into())
}

/// Derives a 32-byte key from the given secret and salt using HKDF with
/// SHA256, mirroring Go's `ecies.HkdfSha256`.
pub fn hkdf_sha256(
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], EciesError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).map_err(|e| {
        EciesError::InvalidKey(format!(
            "cannot read secret from HKDF reader: {}",
            e
        ))
    })?;
    Ok(key)
}

/// Encrypts the given message using XChaCha20-Poly1305 with a shared
/// secret (usually derived using ECDH between the sender's ephemeral
/// key and the receiver's public key) that is hardened using HKDF with
/// SHA256. Mirrors Go's `ecies.EncryptSha256ChaCha20Poly1305`.
///
/// The cipher also authenticates the additional data and prepends it to
/// the returned encrypted message. The additional data is limited to at
/// most 255 bytes. The output format is:
///
/// `<1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
/// <* bytes ciphertext+tag>`
pub fn encrypt_sha256_chacha20_poly1305(
    shared_secret: &[u8; 32],
    msg: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>, EciesError> {
    // Select a random nonce.
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| EciesError::RngFailure(e.to_string()))?;

    encrypt_sha256_chacha20_poly1305_with_nonce(
        shared_secret,
        msg,
        additional_data,
        &nonce,
    )
}

/// Deterministic core of [`encrypt_sha256_chacha20_poly1305`] with an
/// explicit nonce. Exposed for tests; production code should use the
/// random-nonce entry point.
pub fn encrypt_sha256_chacha20_poly1305_with_nonce(
    shared_secret: &[u8; 32],
    msg: &[u8],
    additional_data: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, EciesError> {
    if additional_data.len() > u8::MAX as usize {
        return Err(EciesError::AdditionalDataTooLong(
            additional_data.len(),
        ));
    }

    // Derive a strong session key from the shared secret using
    // HKDF-SHA256. The nonce is used as the salt, and the protocol name
    // as the info label. This mitigates risks from weak shared secrets.
    let stretched_key = hkdf_sha256(shared_secret, nonce, PROTOCOL_NAME)?;

    let aead = XChaCha20Poly1305::new((&stretched_key).into());
    let ciphertext = aead
        .encrypt(
            nonce.into(),
            Payload {
                msg,
                aad: additional_data,
            },
        )
        .map_err(|_| EciesError::DecryptionFailed)?;

    // <version> <AD length> <AD> <nonce> <ciphertext+tag>
    let mut result = Vec::with_capacity(
        2 + additional_data.len() + NONCE_SIZE + ciphertext.len(),
    );
    result.push(LATEST_ECIES_VERSION as u8);
    result.push(additional_data.len() as u8);
    result.extend_from_slice(additional_data);
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Extracts the version, additional data, and the remaining bytes
/// (nonce plus ciphertext) from the given message, mirroring Go's
/// `ecies.ExtractAdditionalData`. The message must be in the format:
///
/// `<1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
/// <* bytes ciphertext+tag>`
pub fn extract_additional_data(
    msg: &[u8],
) -> Result<(EciesVersion, &[u8], &[u8]), EciesError> {
    // We need at least 2 bytes for the version and additional data
    // length.
    if msg.len() < 2 {
        return Err(EciesError::CiphertextTooShort {
            given: msg.len(),
            minimum: 2,
        });
    }

    // Check if the version is supported. We currently only support the
    // latest version.
    if msg[0] != LATEST_ECIES_VERSION as u8 {
        return Err(EciesError::UnsupportedVersion(msg[0]));
    }
    let version = EciesVersion::V1;

    let additional_data_len = msg[1] as usize;

    // The ciphertext must be at least 2 + adLength + 24 + 16 bytes
    // long: version (1), AD length (1), AD, nonce (24), tag (16).
    let min_length = 2 + additional_data_len + NONCE_SIZE + TAG_SIZE;
    if msg.len() < min_length {
        return Err(EciesError::CiphertextTooShort {
            given: msg.len(),
            minimum: min_length,
        });
    }

    let additional_data = &msg[2..2 + additional_data_len];
    let remainder = &msg[2 + additional_data_len..];

    Ok((version, additional_data, remainder))
}

/// Decrypts the given ciphertext using XChaCha20-Poly1305 with a shared
/// secret that is hardened using HKDF with SHA256, mirroring Go's
/// `ecies.DecryptSha256ChaCha20Poly1305`. The ciphertext must be in the
/// format:
///
/// `<1 byte version> <1 byte AD length> <* bytes AD> <24 bytes nonce>
/// <* bytes ciphertext+tag>`
pub fn decrypt_sha256_chacha20_poly1305(
    shared_secret: &[u8; 32],
    msg: &[u8],
) -> Result<Vec<u8>, EciesError> {
    // Make sure the message correctly encodes the additional data. The
    // version is validated inside.
    let (_version, additional_data, remainder) =
        extract_additional_data(msg)?;

    // Split nonce and ciphertext.
    let nonce: [u8; NONCE_SIZE] = remainder[..NONCE_SIZE]
        .try_into()
        .expect("length checked in extract_additional_data");
    let ciphertext = &remainder[NONCE_SIZE..];

    // Derive a strong session key from the shared secret using
    // HKDF-SHA256, matching the encryption side.
    let stretched_key = hkdf_sha256(shared_secret, &nonce, PROTOCOL_NAME)?;

    let aead = XChaCha20Poly1305::new((&stretched_key).into());

    // Decrypt the message and check it wasn't tampered with.
    aead.decrypt(
        (&nonce).into(),
        Payload {
            msg: ciphertext,
            aad: additional_data,
        },
    )
    .map_err(|_| EciesError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn test_keys() -> (SecretKey, PublicKey, SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sender_priv = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let receiver_priv = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let sender_pub = sender_priv.public_key(&secp);
        let receiver_pub = receiver_priv.public_key(&secp);
        (sender_priv, sender_pub, receiver_priv, receiver_pub)
    }

    // -----------------------------------------------------------------
    // Deterministic vectors generated from the Go reference
    // implementation (internal/ecies) with sender priv = 0x01*32 and
    // receiver priv = 0x02*32.
    // -----------------------------------------------------------------

    const GO_SENDER_PUB: &str =
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
    const GO_RECEIVER_PUB: &str =
        "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
    const GO_SHARED_SECRET: &str =
        "b7c99dee100e6844572a8d9ee91975af09e602491d4ba32f6781261cd9c99173";
    const GO_HKDF: &str =
        "f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef";
    // EncryptSha256ChaCha20Poly1305(shared, "hello mailbox", sender_pub)
    const GO_CIPHERTEXT: &str =
        "0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5\
         dd078fc4d142bb2a801dba8dc982d925c10af0a6666418f342f6670c1bf215a6\
         dad1f859add29305a5603fb142004bbfde37a9c5d738339e";
    // EncryptSha256ChaCha20Poly1305(shared, "second message", nil)
    const GO_CIPHERTEXT_NO_AD: &str =
        "01009be53e97bda68c707598bc163d82c3340aedfb22b00043553e8911862a31\
         323d472343dce3b3f93927f6da905998d6b658ff1d94d229";

    #[test]
    fn test_ecdh_matches_go_vector() {
        let (sender_priv, sender_pub, receiver_priv, receiver_pub) =
            test_keys();

        assert_eq!(
            sender_pub.serialize().to_vec(),
            hex_decode(GO_SENDER_PUB)
        );
        assert_eq!(
            receiver_pub.serialize().to_vec(),
            hex_decode(GO_RECEIVER_PUB)
        );

        let shared1 = ecdh(&sender_priv, &receiver_pub).unwrap();
        let shared2 = ecdh(&receiver_priv, &sender_pub).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.to_vec(), hex_decode(GO_SHARED_SECRET));
    }

    #[test]
    fn test_hkdf_matches_go_vector() {
        let key = hkdf_sha256(b"secret", b"salt", b"info").unwrap();
        assert_eq!(key.to_vec(), hex_decode(GO_HKDF));
    }

    #[test]
    fn test_decrypt_go_ciphertext_with_ad() {
        let (_, sender_pub, receiver_priv, _) = test_keys();
        let shared = ecdh(&receiver_priv, &sender_pub).unwrap();

        let ciphertext = hex_decode(GO_CIPHERTEXT);

        // The additional data must be the sender's ephemeral public
        // key, per the mailbox protocol.
        let (version, ad, _rest) =
            extract_additional_data(&ciphertext).unwrap();
        assert_eq!(version, EciesVersion::V1);
        assert_eq!(ad.to_vec(), hex_decode(GO_SENDER_PUB));

        let plaintext =
            decrypt_sha256_chacha20_poly1305(&shared, &ciphertext)
                .unwrap();
        assert_eq!(plaintext, b"hello mailbox");
    }

    #[test]
    fn test_decrypt_go_ciphertext_no_ad() {
        let (_, sender_pub, receiver_priv, _) = test_keys();
        let shared = ecdh(&receiver_priv, &sender_pub).unwrap();

        let ciphertext = hex_decode(GO_CIPHERTEXT_NO_AD);
        let (_, ad, _) = extract_additional_data(&ciphertext).unwrap();
        assert!(ad.is_empty());

        let plaintext =
            decrypt_sha256_chacha20_poly1305(&shared, &ciphertext)
                .unwrap();
        assert_eq!(plaintext, b"second message");
    }

    // -----------------------------------------------------------------
    // Round-trip cases, ported from Go's
    // TestEncryptDecryptSha256ChaCha20Poly1305.
    // -----------------------------------------------------------------

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let (sender_priv, _, _, receiver_pub) = test_keys();
        let shared = ecdh(&sender_priv, &receiver_pub).unwrap();

        let cases: &[(&[u8], &[u8])] = &[
            (b"hello", b""),
            (b"hello", b"additional data"),
            (b"", b""),
            (&[b'a'; 1024], b""),
        ];

        for (msg, ad) in cases {
            let ciphertext =
                encrypt_sha256_chacha20_poly1305(&shared, msg, ad)
                    .unwrap();

            // Verify the version byte is correct.
            assert_eq!(ciphertext[0], 1);
            assert!(ciphertext.len() >= 2 + ad.len() + NONCE_SIZE + TAG_SIZE);

            let plaintext =
                decrypt_sha256_chacha20_poly1305(&shared, &ciphertext)
                    .unwrap();
            assert_eq!(&plaintext, msg);
        }
    }

    #[test]
    fn test_additional_data_too_long() {
        let (sender_priv, _, _, receiver_pub) = test_keys();
        let shared = ecdh(&sender_priv, &receiver_pub).unwrap();

        let ad = [b'a'; 256];
        let result =
            encrypt_sha256_chacha20_poly1305(&shared, b"hello", &ad);
        assert!(matches!(
            result,
            Err(EciesError::AdditionalDataTooLong(256))
        ));
    }

    // Ported from Go's TestUnsupportedVersion.
    #[test]
    fn test_unsupported_version() {
        let (sender_priv, _, _, receiver_pub) = test_keys();
        let shared = ecdh(&sender_priv, &receiver_pub).unwrap();

        let mut ciphertext =
            encrypt_sha256_chacha20_poly1305(&shared, b"test", b"ad")
                .unwrap();
        ciphertext[0] = 2;

        assert!(matches!(
            decrypt_sha256_chacha20_poly1305(&shared, &ciphertext),
            Err(EciesError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let (sender_priv, _, _, receiver_pub) = test_keys();
        let shared = ecdh(&sender_priv, &receiver_pub).unwrap();

        let mut ciphertext =
            encrypt_sha256_chacha20_poly1305(&shared, b"test", b"ad")
                .unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;

        assert!(matches!(
            decrypt_sha256_chacha20_poly1305(&shared, &ciphertext),
            Err(EciesError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_ciphertext_too_short() {
        let shared = [0u8; 32];
        assert!(matches!(
            decrypt_sha256_chacha20_poly1305(&shared, &[0x01]),
            Err(EciesError::CiphertextTooShort { .. })
        ));

        // Valid version but AD length exceeding the actual message.
        assert!(matches!(
            decrypt_sha256_chacha20_poly1305(&shared, &[0x01, 0xFF, 0x00]),
            Err(EciesError::CiphertextTooShort { .. })
        ));
    }

    #[test]
    fn test_wrong_shared_secret_fails() {
        let (sender_priv, _, _, receiver_pub) = test_keys();
        let shared = ecdh(&sender_priv, &receiver_pub).unwrap();

        let ciphertext =
            encrypt_sha256_chacha20_poly1305(&shared, b"test", b"ad")
                .unwrap();

        let wrong = [0xAB; 32];
        assert!(matches!(
            decrypt_sha256_chacha20_poly1305(&wrong, &ciphertext),
            Err(EciesError::DecryptionFailed)
        ));
    }
}
