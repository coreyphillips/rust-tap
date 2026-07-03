// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! vPSBT encoding, byte-compatible with Go's `tappsbt/encode.go`.
//!
//! The BIP-174 container is serialized by hand rather than through
//! `bitcoin::psbt` so that the output is byte-identical to Go's
//! `btcsuite/btcd/btcutil/psbt` serialization: Go writes the custom
//! (unknown) key-value pairs in the exact insertion order of the
//! tappsbt encoder mapping, while `bitcoin::psbt` keeps unknowns in
//! maps and orders fields slightly differently. The Go test vectors
//! are the arbiter, so a focused hand-rolled writer is used.

use crate::address::TapAddress;
use crate::asset::{Asset, EncodeType};
use crate::encoding::asset::{encode_alt_leaf, encode_asset};
use crate::encoding::bigsize::encode_bigsize;
use crate::encoding::tlv::encode_var_bytes;
use crate::proof::encode_proof;

use super::types::{
    hd_coin_type, Bip32Derivation, TaprootBip32Derivation, VInput,
    VOutput, VPacket, VPsbtError,
};

/// The BIP-174 magic bytes: "psbt" followed by 0xff.
pub(super) const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global vPSBT key types (Go's `PsbtKeyTypeGlobal*`).
pub(super) mod global_key {
    pub const TAP_IS_VIRTUAL_TX: u8 = 0x70;
    pub const TAP_CHAIN_PARAMS_HRP: u8 = 0x71;
    pub const TAP_PSBT_VERSION: u8 = 0x72;
}

/// Input vPSBT key types (Go's `PsbtKeyTypeInput*`).
pub(super) mod input_key {
    pub const TAP_PREV_ID: u8 = 0x70;
    pub const TAP_ANCHOR_VALUE: u8 = 0x71;
    pub const TAP_ANCHOR_PK_SCRIPT: u8 = 0x72;
    pub const TAP_ANCHOR_SIGHASH_TYPE: u8 = 0x73;
    pub const TAP_ANCHOR_INTERNAL_KEY: u8 = 0x74;
    pub const TAP_ANCHOR_MERKLE_ROOT: u8 = 0x75;
    pub const TAP_ANCHOR_OUTPUT_BIP32_DERIVATION: u8 = 0x76;
    pub const TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION: u8 = 0x77;
    pub const TAP_ANCHOR_TAPSCRIPT_SIBLING: u8 = 0x78;
    pub const TAP_ASSET: u8 = 0x79;
    pub const TAP_ASSET_PROOF: u8 = 0x7a;
}

/// Output vPSBT key types (Go's `PsbtKeyTypeOutput*`).
pub(super) mod output_key {
    pub const TAP_TYPE: u8 = 0x70;
    pub const TAP_IS_INTERACTIVE: u8 = 0x71;
    pub const TAP_ANCHOR_OUTPUT_INDEX: u8 = 0x72;
    pub const TAP_ANCHOR_OUTPUT_INTERNAL_KEY: u8 = 0x73;
    pub const TAP_ANCHOR_OUTPUT_BIP32_DERIVATION: u8 = 0x74;
    pub const TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION: u8 = 0x75;
    pub const TAP_ASSET: u8 = 0x76;
    pub const TAP_SPLIT_ASSET: u8 = 0x77;
    pub const TAP_ANCHOR_TAPSCRIPT_SIBLING: u8 = 0x78;
    pub const TAP_ASSET_VERSION: u8 = 0x79;
    pub const TAP_PROOF_DELIVERY_ADDRESS: u8 = 0x7a;
    pub const TAP_ASSET_PROOF_SUFFIX: u8 = 0x7b;
    pub const TAP_ASSET_LOCK_TIME: u8 = 0x7c;
    pub const TAP_ASSET_RELATIVE_LOCK_TIME: u8 = 0x7d;
    pub const TAP_ALT_LEAVES: u8 = 0x7e;
    pub const TAP_ADDRESS: u8 = 0x7f;
}

/// Standard BIP-174 input key types used by virtual inputs.
pub(super) mod std_input_key {
    pub const SIGHASH_TYPE: u8 = 0x03;
    pub const BIP32_DERIVATION: u8 = 0x06;
    pub const TAPROOT_BIP32_DERIVATION: u8 = 0x16;
    pub const TAPROOT_INTERNAL_KEY: u8 = 0x17;
    pub const TAPROOT_MERKLE_ROOT: u8 = 0x18;
}

/// Standard BIP-174 output key types used by virtual outputs.
pub(super) mod std_output_key {
    pub const BIP32_DERIVATION: u8 = 0x02;
    pub const TAPROOT_INTERNAL_KEY: u8 = 0x05;
    pub const TAPROOT_BIP32_DERIVATION: u8 = 0x07;
}

/// A raw PSBT key-value pair (the key includes the type byte).
pub(super) struct RawKv {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------
// Low level writers
// ---------------------------------------------------------------------

/// Writes a Bitcoin CompactSize integer.
pub(super) fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => buf.push(n as u8),
        0xfd..=0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buf.push(0xfe);
            buf.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            buf.push(0xff);
            buf.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Writes CompactSize-length-prefixed bytes.
fn write_var_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_compact_size(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Writes a raw key-value pair: `varbytes(key) || varbytes(value)`.
fn write_kv(buf: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    write_var_bytes(buf, key);
    write_var_bytes(buf, value);
}

/// Writes a key-value pair whose key is `type_byte || key_data`.
fn write_kv_typed(
    buf: &mut Vec<u8>,
    type_byte: u8,
    key_data: &[u8],
    value: &[u8],
) {
    let mut key = Vec::with_capacity(1 + key_data.len());
    key.push(type_byte);
    key.extend_from_slice(key_data);
    write_kv(buf, &key, value);
}

// ---------------------------------------------------------------------
// Field value encoders
// ---------------------------------------------------------------------

/// Serializes a BIP-0032 derivation value: 4-byte LE fingerprint
/// followed by 4-byte LE path elements (Go's
/// `psbt.SerializeBIP32Derivation`).
pub(super) fn bip32_derivation_value(d: &Bip32Derivation) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 4 * d.bip32_path.len());
    buf.extend_from_slice(&d.master_key_fingerprint.to_le_bytes());
    for step in &d.bip32_path {
        buf.extend_from_slice(&step.to_le_bytes());
    }
    buf
}

/// Serializes a Taproot BIP-0032 derivation value:
/// `compact_size(num_hashes) || hashes || fingerprint || path` (Go's
/// `psbt.SerializeTaprootBip32Derivation`).
pub(super) fn taproot_bip32_derivation_value(
    d: &TaprootBip32Derivation,
) -> Result<Vec<u8>, VPsbtError> {
    let mut buf = Vec::new();
    write_compact_size(&mut buf, d.leaf_hashes.len() as u64);
    for hash in &d.leaf_hashes {
        if hash.len() != 32 {
            return Err(VPsbtError::EncodeError(format!(
                "invalid taproot bip32 leaf hash length: {}",
                hash.len()
            )));
        }
        buf.extend_from_slice(hash);
    }
    let mut fp_and_path = bip32_derivation_value(&Bip32Derivation {
        pub_key: Vec::new(),
        master_key_fingerprint: d.master_key_fingerprint,
        bip32_path: d.bip32_path.clone(),
    });
    buf.append(&mut fp_and_path);
    Ok(buf)
}

/// Encodes a Taproot Asset address into its raw TLV payload bytes, as
/// written by Go's `address.Tap.Encode`. This routes through the
/// existing Bech32m encoder to reuse the address TLV logic.
pub(super) fn address_raw_bytes(
    addr: &TapAddress,
) -> Result<Vec<u8>, VPsbtError> {
    let encoded = addr
        .encode()
        .map_err(|e| VPsbtError::EncodeError(e.to_string()))?;
    let (_hrp, payload) = bech32::decode(&encoded)
        .map_err(|e| VPsbtError::EncodeError(e.to_string()))?;
    Ok(payload)
}

/// Encodes the alt leaves list: `BigSize(count)` followed by
/// BigSize-length-prefixed alt leaf TLV streams, matching Go's
/// `asset.AltLeavesEncoder` (including the duplicate script key
/// check).
pub(super) fn encode_alt_leaves(
    leaves: &[Asset],
) -> Result<Vec<u8>, VPsbtError> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, leaves.len() as u64);

    let mut seen_keys = std::collections::BTreeSet::new();
    for leaf in leaves {
        let key = leaf.script_key.pub_key.0;
        if !seen_keys.insert(key) {
            return Err(VPsbtError::EncodeError(
                "duplicate script keys for alt leaves".into(),
            ));
        }
        let encoded = encode_alt_leaf(leaf);
        encode_var_bytes(&mut buf, &encoded);
    }
    Ok(buf)
}

/// Builds the P2TR output script for a script key:
/// `OP_1 OP_PUSHBYTES_32 <x-only key>`.
pub(super) fn pay_to_taproot_script(pub_key: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51);
    script.push(0x20);
    script.extend_from_slice(&pub_key[1..]);
    script
}

// ---------------------------------------------------------------------
// Custom (unknown) field construction
// ---------------------------------------------------------------------

/// Builds the custom key-value pairs of a virtual input, in the exact
/// order of Go's `VInput.encode` mapping.
fn input_unknowns(input: &VInput) -> Result<Vec<RawKv>, VPsbtError> {
    let mut unknowns = Vec::new();
    let single =
        |key: u8, value: Vec<u8>| RawKv { key: vec![key], value };

    // PrevID: outpoint (txid || BE vout) || asset ID || script key.
    let mut prev_id = Vec::with_capacity(101);
    prev_id.extend_from_slice(&input.prev_id.out_point.txid);
    prev_id.extend_from_slice(&input.prev_id.out_point.vout.to_be_bytes());
    prev_id.extend_from_slice(input.prev_id.id.as_bytes());
    prev_id.extend_from_slice(input.prev_id.script_key.as_bytes());
    unknowns.push(single(input_key::TAP_PREV_ID, prev_id));

    // Anchor value (u64 BE) and pkScript (raw, possibly empty).
    unknowns.push(single(
        input_key::TAP_ANCHOR_VALUE,
        input.anchor.value.to_be_bytes().to_vec(),
    ));
    unknowns.push(single(
        input_key::TAP_ANCHOR_PK_SCRIPT,
        input.anchor.pk_script.clone(),
    ));

    // Anchor sighash type (u64 BE).
    unknowns.push(single(
        input_key::TAP_ANCHOR_SIGHASH_TYPE,
        (input.anchor.sig_hash_type as u64).to_be_bytes().to_vec(),
    ));

    // Anchor internal key (33-byte compressed, only when set).
    if let Some(ref key) = input.anchor.internal_key {
        unknowns.push(single(
            input_key::TAP_ANCHOR_INTERNAL_KEY,
            key.as_bytes().to_vec(),
        ));
    }

    // Anchor merkle root (raw, possibly empty).
    unknowns.push(single(
        input_key::TAP_ANCHOR_MERKLE_ROOT,
        input.anchor.merkle_root.clone(),
    ));

    // Anchor output BIP-0032 derivations, one pair per derivation with
    // the public key appended to the key type.
    for d in &input.anchor.bip32_derivation {
        unknowns.push(RawKv {
            key: typed_key(
                input_key::TAP_ANCHOR_OUTPUT_BIP32_DERIVATION,
                &d.pub_key,
            ),
            value: bip32_derivation_value(d),
        });
    }
    for d in &input.anchor.taproot_bip32_derivation {
        unknowns.push(RawKv {
            key: typed_key(
                input_key::TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION,
                &d.x_only_pub_key,
            ),
            value: taproot_bip32_derivation_value(d)?,
        });
    }

    // Anchor tapscript sibling (raw, possibly empty).
    unknowns.push(single(
        input_key::TAP_ANCHOR_TAPSCRIPT_SIBLING,
        input.anchor.tapscript_sibling.clone(),
    ));

    // Input asset (leaf encoding) and proof, only when set.
    if let Some(ref asset) = input.asset {
        unknowns.push(single(
            input_key::TAP_ASSET,
            encode_asset_leaf_like_go(asset),
        ));
    }
    if let Some(ref proof) = input.proof {
        unknowns.push(single(input_key::TAP_ASSET_PROOF, encode_proof(proof)));
    }

    Ok(unknowns)
}

/// Builds the custom key-value pairs of a virtual output, in the exact
/// order of Go's `VOutput.encode` mapping.
fn output_unknowns(output: &VOutput) -> Result<Vec<RawKv>, VPsbtError> {
    let mut unknowns = Vec::new();
    let single =
        |key: u8, value: Vec<u8>| RawKv { key: vec![key], value };

    // Output type (u8) and interactive flag.
    unknowns.push(single(output_key::TAP_TYPE, vec![output.output_type.0]));
    unknowns.push(single(
        output_key::TAP_IS_INTERACTIVE,
        vec![u8::from(output.interactive)],
    ));

    // Anchor output index (u64 BE).
    unknowns.push(single(
        output_key::TAP_ANCHOR_OUTPUT_INDEX,
        (output.anchor_output_index as u64).to_be_bytes().to_vec(),
    ));

    // Anchor output internal key (only when set).
    if let Some(ref key) = output.anchor_output_internal_key {
        unknowns.push(single(
            output_key::TAP_ANCHOR_OUTPUT_INTERNAL_KEY,
            key.as_bytes().to_vec(),
        ));
    }

    // Anchor output BIP-0032 derivations.
    for d in &output.anchor_output_bip32_derivation {
        unknowns.push(RawKv {
            key: typed_key(
                output_key::TAP_ANCHOR_OUTPUT_BIP32_DERIVATION,
                &d.pub_key,
            ),
            value: bip32_derivation_value(d),
        });
    }
    for d in &output.anchor_output_taproot_bip32_derivation {
        unknowns.push(RawKv {
            key: typed_key(
                output_key::TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION,
                &d.x_only_pub_key,
            ),
            value: taproot_bip32_derivation_value(d)?,
        });
    }

    // Output asset and split asset (leaf encoding, only when set).
    if let Some(ref asset) = output.asset {
        unknowns.push(single(
            output_key::TAP_ASSET,
            encode_asset_leaf_like_go(asset),
        ));
    }
    if let Some(ref split) = output.split_asset {
        unknowns.push(single(
            output_key::TAP_SPLIT_ASSET,
            encode_asset_leaf_like_go(split),
        ));
    }

    // Anchor output tapscript sibling preimage (only when set).
    if let Some(ref sibling) = output.anchor_output_tapscript_sibling {
        unknowns.push(single(
            output_key::TAP_ANCHOR_TAPSCRIPT_SIBLING,
            sibling.encode(),
        ));
    }

    // Asset version (u8).
    unknowns.push(single(
        output_key::TAP_ASSET_VERSION,
        vec![output.asset_version],
    ));

    // Proof delivery address (URL string, only when set).
    if let Some(ref url) = output.proof_delivery_address {
        unknowns.push(single(
            output_key::TAP_PROOF_DELIVERY_ADDRESS,
            url.as_bytes().to_vec(),
        ));
    }

    // Proof suffix (only when set).
    if let Some(ref proof) = output.proof_suffix {
        unknowns.push(single(
            output_key::TAP_ASSET_PROOF_SUFFIX,
            encode_proof(proof),
        ));
    }

    // Lock time and relative lock time (u64 BE, always written).
    unknowns.push(single(
        output_key::TAP_ASSET_LOCK_TIME,
        output.lock_time.to_be_bytes().to_vec(),
    ));
    unknowns.push(single(
        output_key::TAP_ASSET_RELATIVE_LOCK_TIME,
        output.relative_lock_time.to_be_bytes().to_vec(),
    ));

    // Alt leaves (only when non-empty).
    if !output.alt_leaves.is_empty() {
        unknowns.push(single(
            output_key::TAP_ALT_LEAVES,
            encode_alt_leaves(&output.alt_leaves)?,
        ));
    }

    // Taproot Asset address (raw TLV payload, only when set).
    if let Some(ref address) = output.address {
        unknowns.push(single(
            output_key::TAP_ADDRESS,
            address_raw_bytes(address)?,
        ));
    }

    Ok(unknowns)
}

/// Builds a key of the form `type_byte || key_data`.
fn typed_key(type_byte: u8, key_data: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + key_data.len());
    key.push(type_byte);
    key.extend_from_slice(key_data);
    key
}

/// Encodes an asset the way Go's tappsbt custom fields do.
///
/// Go's `assetEncoder` uses `asset.LeafEncoder`, which despite its
/// name calls `Asset.Encode` and therefore always uses Normal encoding
/// (asset/encoding.go:657 delegating to asset.go EncodeRecords with
/// EncodeNormal). The segwit-for-V1 rule applies only to MS-SMT tree
/// leaves built via `Asset.Leaf()`, not to tappsbt fields; using it
/// here would silently drop the TxWitness of V1 assets from virtual
/// packets.
fn encode_asset_leaf_like_go(asset: &Asset) -> Vec<u8> {
    encode_asset(asset, EncodeType::Normal)
}

// ---------------------------------------------------------------------
// Section serialization
// ---------------------------------------------------------------------

/// Serializes the synthetic unsigned transaction of the packet: empty
/// inputs (zero outpoint, zero sequence) and one P2TR output per
/// virtual output carrying the asset amount as the output value.
fn serialize_unsigned_tx(packet: &VPacket) -> Result<Vec<u8>, VPsbtError> {
    let mut buf = Vec::new();

    // Version 2 (i32 LE).
    buf.extend_from_slice(&2i32.to_le_bytes());

    // Inputs: all fields zero, like Go's `&wire.TxIn{}`.
    write_compact_size(&mut buf, packet.inputs.len() as u64);
    for _ in &packet.inputs {
        buf.extend_from_slice(&[0u8; 36]);
        write_compact_size(&mut buf, 0);
        buf.extend_from_slice(&[0u8; 4]);
    }

    // Outputs: value = asset amount, pkScript = P2TR of the script key.
    write_compact_size(&mut buf, packet.outputs.len() as u64);
    for output in &packet.outputs {
        if output.amount > i64::MAX as u64 {
            return Err(VPsbtError::EncodeError(
                "output amount exceeds maximum value".into(),
            ));
        }
        buf.extend_from_slice(&(output.amount as i64).to_le_bytes());
        let pk_script = pay_to_taproot_script(&output.script_key.pub_key.0);
        write_var_bytes(&mut buf, &pk_script);
    }

    // Lock time 0.
    buf.extend_from_slice(&[0u8; 4]);

    Ok(buf)
}

/// Serializes one PSBT input section (without the trailing separator),
/// matching the field order of Go's `psbt.PInput.serialize`.
fn serialize_input(input: &VInput) -> Result<Vec<u8>, VPsbtError> {
    let mut buf = Vec::new();

    // Sighash type (u32 LE, only when non-zero).
    if input.sighash_type != 0 {
        write_kv_typed(
            &mut buf,
            std_input_key::SIGHASH_TYPE,
            &[],
            &input.sighash_type.to_le_bytes(),
        );
    }

    // BIP-0032 derivations, sorted by public key.
    let mut bip32 = input.bip32_derivation.clone();
    bip32.sort_by(|a, b| a.pub_key.cmp(&b.pub_key));
    for d in &bip32 {
        write_kv_typed(
            &mut buf,
            std_input_key::BIP32_DERIVATION,
            &d.pub_key,
            &bip32_derivation_value(d),
        );
    }

    // Taproot BIP-0032 derivations, sorted by x-only public key.
    let mut tr_bip32 = input.taproot_bip32_derivation.clone();
    tr_bip32.sort_by(|a, b| a.x_only_pub_key.cmp(&b.x_only_pub_key));
    for d in &tr_bip32 {
        write_kv_typed(
            &mut buf,
            std_input_key::TAPROOT_BIP32_DERIVATION,
            &d.x_only_pub_key,
            &taproot_bip32_derivation_value(d)?,
        );
    }

    // Taproot internal key and merkle root (only when set).
    if !input.taproot_internal_key.is_empty() {
        write_kv_typed(
            &mut buf,
            std_input_key::TAPROOT_INTERNAL_KEY,
            &[],
            &input.taproot_internal_key,
        );
    }
    if !input.taproot_merkle_root.is_empty() {
        write_kv_typed(
            &mut buf,
            std_input_key::TAPROOT_MERKLE_ROOT,
            &[],
            &input.taproot_merkle_root,
        );
    }

    // Custom fields, in mapping order.
    for kv in input_unknowns(input)? {
        write_kv(&mut buf, &kv.key, &kv.value);
    }

    Ok(buf)
}

/// Serializes one PSBT output section (without the trailing separator),
/// matching the field order of Go's `psbt.POutput.serialize`. The
/// standard derivation fields are regenerated from the output's script
/// key like Go's `serializeTweakedScriptKey`.
fn serialize_output(
    output: &VOutput,
    coin_type: u32,
) -> Result<Vec<u8>, VPsbtError> {
    let mut buf = Vec::new();

    // Standard fields from the tweaked script key, when present.
    if let Some(ref tweaked) = output.script_key.tweaked {
        const BIP0043_PURPOSE: u32 = 1017;
        const HARDENED: u32 = 0x8000_0000;

        let raw_key = tweaked.raw_key.pub_key.as_bytes();
        let path = vec![
            BIP0043_PURPOSE + HARDENED,
            coin_type.wrapping_add(HARDENED),
            tweaked.raw_key.family.wrapping_add(HARDENED),
            0,
            tweaked.raw_key.index,
        ];

        let bip32 = Bip32Derivation {
            pub_key: raw_key.to_vec(),
            master_key_fingerprint: 0,
            bip32_path: path.clone(),
        };
        let tr_bip32 = TaprootBip32Derivation {
            x_only_pub_key: raw_key[1..].to_vec(),
            // A non-empty tweak means the key is not BIP-86, so the
            // tweak (the script tree root) rides along as a leaf hash.
            leaf_hashes: if tweaked.tweak.is_empty() {
                Vec::new()
            } else {
                vec![tweaked.tweak.clone()]
            },
            master_key_fingerprint: 0,
            bip32_path: path,
        };

        write_kv_typed(
            &mut buf,
            std_output_key::BIP32_DERIVATION,
            &bip32.pub_key,
            &bip32_derivation_value(&bip32),
        );
        write_kv_typed(
            &mut buf,
            std_output_key::TAPROOT_INTERNAL_KEY,
            &[],
            &tr_bip32.x_only_pub_key,
        );
        write_kv_typed(
            &mut buf,
            std_output_key::TAPROOT_BIP32_DERIVATION,
            &tr_bip32.x_only_pub_key,
            &taproot_bip32_derivation_value(&tr_bip32)?,
        );
    }

    // Custom fields, in mapping order.
    for kv in output_unknowns(output)? {
        write_kv(&mut buf, &kv.key, &kv.value);
    }

    Ok(buf)
}

impl VPacket {
    /// Serializes the virtual packet into its binary PSBT
    /// representation, byte-compatible with Go's `VPacket.Serialize`.
    pub fn serialize(&self) -> Result<Vec<u8>, VPsbtError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PSBT_MAGIC);

        // Global unsigned transaction (key type 0x00).
        let unsigned_tx = serialize_unsigned_tx(self)?;
        write_kv(&mut buf, &[0x00], &unsigned_tx);

        // Global custom fields, in Go's insertion order.
        write_kv(&mut buf, &[global_key::TAP_IS_VIRTUAL_TX], &[0x01]);
        write_kv(
            &mut buf,
            &[global_key::TAP_CHAIN_PARAMS_HRP],
            self.chain_params.hrp().as_bytes(),
        );
        write_kv(
            &mut buf,
            &[global_key::TAP_PSBT_VERSION],
            &[self.version.to_u8()],
        );
        buf.push(0x00);

        for input in &self.inputs {
            let section = serialize_input(input)?;
            buf.extend_from_slice(&section);
            buf.push(0x00);
        }

        let coin_type = hd_coin_type(self.chain_params);
        for output in &self.outputs {
            let section = serialize_output(output, coin_type)?;
            buf.extend_from_slice(&section);
            buf.push(0x00);
        }

        Ok(buf)
    }

    /// Returns the base64 encoding of the serialized packet, matching
    /// Go's `VPacket.B64Encode`.
    pub fn b64_encode(&self) -> Result<String, VPsbtError> {
        Ok(super::base64_encode(&self.serialize()?))
    }

    /// Encodes the virtual packet as a `bitcoin::psbt::Psbt` for
    /// interoperability with the rest of the Rust Bitcoin ecosystem.
    ///
    /// Note that re-serializing the returned PSBT through
    /// `bitcoin::psbt` may order the custom key-value pairs
    /// differently than [`VPacket::serialize`]; use the latter for
    /// byte-exact Go compatibility.
    ///
    /// Also note that `bitcoin::psbt` is stricter than Go's
    /// `btcutil/psbt` for some typed fields: for example, it requires
    /// the input Taproot merkle root (which a virtual input uses to
    /// carry the script key tweak) to be exactly 32 bytes, while Go
    /// stores raw bytes. Packets whose fields cannot be represented in
    /// the typed model are rejected with an error here even though
    /// [`VPacket::serialize`] handles them fine.
    pub fn encode_as_psbt(&self) -> Result<bitcoin::Psbt, VPsbtError> {
        let bytes = self.serialize()?;
        bitcoin::Psbt::deserialize(&bytes)
            .map_err(|e| VPsbtError::EncodeError(e.to_string()))
    }
}
