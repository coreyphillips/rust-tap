// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Virtual PSBTs (vPSBTs) for Taproot Asset state transitions.
//!
//! A virtual packet is a PSBT extension packet representing a virtual
//! asset state transition as validated by the Taproot Asset VM. The
//! wire format is a standard BIP-174 PSBT whose global, input, and
//! output sections carry Taproot Asset specific data in custom
//! (unknown) key-value pairs with single-byte key types in the
//! 0x70-0x7f range, matching Go's `tappsbt` package byte for byte.
//!
//! The serialization is hand-rolled (see `encode.rs`) because the Go
//! implementation relies on `btcutil/psbt`'s exact field ordering and
//! writes custom fields in encoder-mapping order, which differs from
//! how `bitcoin::psbt` orders its unknown-key maps.

mod decode;
mod encode;
mod types;

pub use types::{
    commitment_version, hd_coin_type, Anchor, Bip32Derivation,
    KeyDescriptor, OutputScriptKey, TaprootBip32Derivation,
    TweakedScriptKeyDesc, VInput, VOutput, VOutputType, VPacket,
    VPacketVersion, VPsbtError,
};

/// The standard base64 alphabet.
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes with standard base64 (RFC 4648, with padding).
pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(BASE64_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes a standard base64 string (RFC 4648, padding required for
/// the final quantum like Go's `base64.StdEncoding`).
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a') as u32 + 26),
            b'0'..=b'9' => Ok((c - b'0') as u32 + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 character: {}", c as char)),
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (idx, chunk) in bytes.chunks(4).enumerate() {
        let is_last = (idx + 1) * 4 == bytes.len();
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !is_last) {
            return Err("invalid base64 padding".into());
        }
        if pad > 0 && (chunk[3] != b'=' || (pad == 2 && chunk[2] != b'='))
        {
            return Err("invalid base64 padding".into());
        }

        let mut n: u32 = 0;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;

        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_round_trip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0x00, 0xff, 0x10, 0x88],
        ];
        for case in cases {
            let encoded = base64_encode(case);
            let decoded = base64_decode(&encoded).expect("valid base64");
            assert_eq!(&decoded, case);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn test_base64_decode_rejects_invalid() {
        assert!(base64_decode("Zm9vYmFy!").is_err());
        assert!(base64_decode("Zm9=YmFy").is_err());
        assert!(base64_decode("Zm9").is_err());
    }

    #[test]
    fn test_v1_asset_witness_survives_round_trip() {
        // Regression: Go's tappsbt custom fields always encode assets
        // with Normal encoding (asset.LeafEncoder delegates to
        // Asset.Encode); applying the MS-SMT segwit-for-V1 rule here
        // silently dropped V1 witnesses from virtual packets.
        use crate::asset::{
            Asset, AssetType, AssetVersion, Genesis, OutPoint, PrevId,
            ScriptKey, SerializedKey, Witness,
        };
        use crate::address::TapNetwork;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        // Real curve points are required: the decoder validates keys.
        let secp = Secp256k1::new();
        let key_a = SerializedKey(
            PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[0x11; 32]).expect("valid"),
            )
            .serialize(),
        );
        let key_b = SerializedKey(
            PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[0x22; 32]).expect("valid"),
            )
            .serialize(),
        );

        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "v1-witness".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let mut asset = Asset::new_genesis(
            genesis,
            500,
            ScriptKey::from_pub_key(key_a),
        );
        asset.version = AssetVersion::V1;
        asset.prev_witnesses = vec![Witness {
            prev_id: Some(PrevId {
                out_point: OutPoint {
                    txid: [0xAA; 32],
                    vout: 1,
                },
                id: asset.genesis.id(),
                script_key: key_a,
            }),
            tx_witness: vec![vec![0xEE; 64]],
            split_commitment: None,
        }];

        let mut input = VInput::default();
        input.prev_id = asset.prev_witnesses[0]
            .prev_id
            .clone()
            .expect("prev id set");
        input.asset = Some(asset.clone());

        let output = VOutput {
            amount: 500,
            asset_version: 1,
            output_type: VOutputType::SIMPLE,
            interactive: true,
            anchor_output_index: 0,
            anchor_output_internal_key: None,
            anchor_output_bip32_derivation: vec![],
            anchor_output_taproot_bip32_derivation: vec![],
            anchor_output_tapscript_sibling: None,
            asset: Some(asset.clone()),
            split_asset: None,
            script_key: OutputScriptKey {
                pub_key: key_b,
                tweaked: None,
            },
            relative_lock_time: 0,
            lock_time: 0,
            proof_delivery_address: None,
            proof_suffix: None,
            alt_leaves: vec![],
            address: None,
        };

        let packet = VPacket {
            inputs: vec![input],
            outputs: vec![output],
            chain_params: TapNetwork::Regtest,
            version: VPacketVersion::V1,
        };

        let bytes = packet.serialize().expect("serialize");
        let decoded = VPacket::from_raw_bytes(&bytes).expect("decode");

        let in_asset =
            decoded.inputs[0].asset.as_ref().expect("input asset");
        assert_eq!(in_asset.version, AssetVersion::V1);
        assert_eq!(
            in_asset.prev_witnesses[0].tx_witness,
            vec![vec![0xEE; 64]],
            "V1 input asset witness must survive the vPSBT round trip"
        );

        let out_asset =
            decoded.outputs[0].asset.as_ref().expect("output asset");
        assert_eq!(
            out_asset.prev_witnesses[0].tx_witness,
            vec![vec![0xEE; 64]],
            "V1 output asset witness must survive the vPSBT round trip"
        );
    }

    #[test]
    fn test_commitment_version_mapping() {
        use crate::commitment::TapCommitmentVersion;

        assert_eq!(
            commitment_version(VPacketVersion::V0).expect("valid"),
            None
        );
        assert_eq!(
            commitment_version(VPacketVersion::V1).expect("valid"),
            Some(TapCommitmentVersion::V2)
        );
    }
}
