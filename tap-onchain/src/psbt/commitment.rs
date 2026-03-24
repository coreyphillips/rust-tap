// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Embeds TAP commitments into Bitcoin Taproot outputs.
//!
//! A TAP commitment becomes a tapscript leaf in the Taproot output's
//! script tree. The leaf is combined with an internal key to produce
//! the final P2TR output script.

use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Network};

use tap_primitives::commitment::TapCommitment;

/// Error from PSBT commitment operations.
#[derive(Debug, Clone)]
pub enum PsbtError {
    /// Taproot builder error.
    TaprootBuildError(String),
    /// Invalid key.
    InvalidKey(String),
    /// Invalid script.
    InvalidScript(String),
}

impl std::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsbtError::TaprootBuildError(msg) => {
                write!(f, "taproot build error: {}", msg)
            }
            PsbtError::InvalidKey(msg) => {
                write!(f, "invalid key: {}", msg)
            }
            PsbtError::InvalidScript(msg) => {
                write!(f, "invalid script: {}", msg)
            }
        }
    }
}

impl std::error::Error for PsbtError {}

/// Creates a P2TR output script with a TAP commitment embedded as a
/// tapscript leaf.
///
/// The TAP commitment's 73-byte leaf data is placed as a single tapscript
/// leaf. The resulting output is a standard P2TR output that can be spent
/// via key-path (using the tweaked key) or script-path (revealing the
/// TAP commitment leaf).
///
/// # Arguments
/// * `internal_key` - The x-only internal key for the Taproot output
/// * `tap_commitment` - The TAP commitment to embed
/// * `sibling_script` - Optional additional tapscript leaf to include
///   alongside the TAP commitment (e.g., for Lightning channel scripts)
///
/// # Returns
/// The P2TR output script and the tweaked output key.
pub fn create_tap_output_script(
    internal_key: &XOnlyPublicKey,
    tap_commitment: &TapCommitment,
    sibling_script: Option<&[u8]>,
) -> Result<(ScriptBuf, XOnlyPublicKey), PsbtError> {
    let secp = Secp256k1::new();
    let tap_leaf_data = tap_commitment.tap_leaf();

    // Build the tapscript tree.
    let builder = if let Some(sibling) = sibling_script {
        // Two leaves: TAP commitment and sibling script.
        TaprootBuilder::new()
            .add_leaf(1, ScriptBuf::from_bytes(tap_leaf_data))
            .map_err(|e| PsbtError::TaprootBuildError(e.to_string()))?
            .add_leaf(1, ScriptBuf::from_bytes(sibling.to_vec()))
            .map_err(|e| PsbtError::TaprootBuildError(e.to_string()))?
    } else {
        // Single leaf: just the TAP commitment.
        TaprootBuilder::new()
            .add_leaf(0, ScriptBuf::from_bytes(tap_leaf_data))
            .map_err(|e| PsbtError::TaprootBuildError(e.to_string()))?
    };

    let spend_info = builder
        .finalize(&secp, *internal_key)
        .map_err(|e| PsbtError::TaprootBuildError(format!("{:?}", e)))?;

    let output_key = spend_info.output_key();
    let script = ScriptBuf::new_p2tr_tweaked(output_key);

    Ok((script, output_key.into()))
}

/// Creates a P2TR address for a TAP commitment.
pub fn create_tap_address(
    internal_key: &XOnlyPublicKey,
    tap_commitment: &TapCommitment,
    network: Network,
) -> Result<Address, PsbtError> {
    let secp = Secp256k1::new();
    let tap_leaf_data = tap_commitment.tap_leaf();

    let builder = TaprootBuilder::new()
        .add_leaf(0, ScriptBuf::from_bytes(tap_leaf_data))
        .map_err(|e| PsbtError::TaprootBuildError(e.to_string()))?;

    let spend_info = builder
        .finalize(&secp, *internal_key)
        .map_err(|e| PsbtError::TaprootBuildError(format!("{:?}", e)))?;

    let address = Address::p2tr_tweaked(spend_info.output_key(), network);
    Ok(address)
}

/// Verifies that a given script matches a TAP commitment with the given
/// internal key.
pub fn verify_tap_output(
    script: &ScriptBuf,
    internal_key: &XOnlyPublicKey,
    tap_commitment: &TapCommitment,
) -> Result<bool, PsbtError> {
    let (expected_script, _) =
        create_tap_output_script(internal_key, tap_commitment, None)?;
    Ok(*script == expected_script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use tap_primitives::asset::*;
    use tap_primitives::commitment::{
        AssetCommitment, TapCommitment, TapCommitmentVersion,
    };

    fn test_internal_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x01;
        let sk = SecretKey::from_slice(&secret).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn test_commitment() -> TapCommitment {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis,
            1000,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap()
    }

    #[test]
    fn test_create_tap_output_script() {
        let key = test_internal_key();
        let commitment = test_commitment();

        let (script, output_key) =
            create_tap_output_script(&key, &commitment, None).unwrap();

        // Should be a valid P2TR script (34 bytes: OP_1 <32-byte key>).
        assert_eq!(script.len(), 34);
        assert_eq!(script.as_bytes()[0], 0x51); // OP_1
        assert_eq!(script.as_bytes()[1], 0x20); // push 32 bytes

        // Output key should differ from internal key (tweaked).
        assert_ne!(output_key, key);
    }

    #[test]
    fn test_create_tap_output_deterministic() {
        let key = test_internal_key();
        let commitment = test_commitment();

        let (script1, _) =
            create_tap_output_script(&key, &commitment, None).unwrap();
        let (script2, _) =
            create_tap_output_script(&key, &commitment, None).unwrap();
        assert_eq!(script1, script2);
    }

    #[test]
    fn test_create_tap_output_with_sibling() {
        let key = test_internal_key();
        let commitment = test_commitment();
        let sibling = vec![0x51]; // OP_TRUE

        let (script_with, _) =
            create_tap_output_script(&key, &commitment, Some(&sibling))
                .unwrap();
        let (script_without, _) =
            create_tap_output_script(&key, &commitment, None).unwrap();

        // Different sibling should produce different output.
        assert_ne!(script_with, script_without);
    }

    #[test]
    fn test_verify_tap_output() {
        let key = test_internal_key();
        let commitment = test_commitment();

        let (script, _) =
            create_tap_output_script(&key, &commitment, None).unwrap();
        assert!(verify_tap_output(&script, &key, &commitment).unwrap());

        // Wrong script should fail.
        let wrong_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(key),
        );
        assert!(!verify_tap_output(&wrong_script, &key, &commitment).unwrap());
    }

    #[test]
    fn test_create_tap_address() {
        let key = test_internal_key();
        let commitment = test_commitment();

        let addr =
            create_tap_address(&key, &commitment, Network::Regtest).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bcrt1p"));
    }
}
