// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! vPSBT decoding, byte-compatible with Go's `tappsbt/decode.go` (which
//! builds on `btcsuite/btcd/btcutil/psbt` for the BIP-174 container).

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};

use crate::address::{TapAddress, TapNetwork};
use crate::asset::{
    Asset, AssetId, OutPoint, PrevId, ScriptKeyType, SerializedKey,
    TweakedScriptKey,
};
use crate::commitment::TapscriptPreimage;
use crate::encoding::asset::decode_asset;
use crate::encoding::bigsize::decode_bigsize;
use crate::encoding::tlv::decode_var_bytes;
use crate::proof::decode_proof;
use crate::proof::types::Proof;

use super::encode::{
    global_key, input_key, output_key, std_input_key, std_output_key,
    RawKv, PSBT_MAGIC,
};
use super::types::{
    Bip32Derivation, KeyDescriptor, OutputScriptKey,
    TaprootBip32Derivation, TweakedScriptKeyDesc, VInput, VOutput,
    VOutputType, VPacket, VPacketVersion, VPsbtError,
};

fn decode_err(msg: impl Into<String>) -> VPsbtError {
    VPsbtError::DecodeError(msg.into())
}

// ---------------------------------------------------------------------
// Low level readers
// ---------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], VPsbtError> {
        if self.pos + len > self.data.len() {
            return Err(decode_err("unexpected end of data"));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn read_compact_size(&mut self) -> Result<u64, VPsbtError> {
        let first = self.take(1)?[0];
        Ok(match first {
            0xfd => u16::from_le_bytes(
                self.take(2)?.try_into().expect("2 bytes"),
            ) as u64,
            0xfe => u32::from_le_bytes(
                self.take(4)?.try_into().expect("4 bytes"),
            ) as u64,
            0xff => u64::from_le_bytes(
                self.take(8)?.try_into().expect("8 bytes"),
            ),
            n => n as u64,
        })
    }

    fn read_var_bytes(&mut self) -> Result<&'a [u8], VPsbtError> {
        let len = self.read_compact_size()?;
        if len > self.data.len() as u64 {
            return Err(decode_err("var bytes length exceeds data"));
        }
        self.take(len as usize)
    }

    /// Reads one key-value section: key-value pairs up to (and
    /// including) the 0x00 separator that terminates the section.
    fn read_section(&mut self) -> Result<Vec<RawKv>, VPsbtError> {
        let mut kvs = Vec::new();
        loop {
            let key = self.read_var_bytes()?;
            if key.is_empty() {
                // Separator: end of section.
                return Ok(kvs);
            }
            let value = self.read_var_bytes()?;
            kvs.push(RawKv {
                key: key.to_vec(),
                value: value.to_vec(),
            });
        }
    }
}

/// A parsed output of the synthetic unsigned transaction.
struct RawTxOut {
    value: i64,
    pk_script: Vec<u8>,
}

/// Parses the synthetic unsigned transaction (non-witness wire
/// format), returning the input count and outputs.
fn parse_unsigned_tx(
    data: &[u8],
) -> Result<(usize, Vec<RawTxOut>), VPsbtError> {
    let mut r = Reader::new(data);

    // Version (i32 LE).
    r.take(4)?;

    let num_inputs = r.read_compact_size()? as usize;
    for _ in 0..num_inputs {
        r.take(36)?;
        let script_sig = r.read_var_bytes()?;
        if !script_sig.is_empty() {
            return Err(decode_err(
                "unsigned tx input has signature script",
            ));
        }
        r.take(4)?;
    }

    let num_outputs = r.read_compact_size()? as usize;
    let mut outputs = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        let value = i64::from_le_bytes(
            r.take(8)?.try_into().expect("8 bytes"),
        );
        let pk_script = r.read_var_bytes()?.to_vec();
        outputs.push(RawTxOut { value, pk_script });
    }

    // Lock time.
    r.take(4)?;

    if r.pos != data.len() {
        return Err(decode_err("trailing bytes after unsigned tx"));
    }

    Ok((num_inputs, outputs))
}

/// Finds the first custom field whose key starts with the given
/// prefix, matching Go's `findCustomFieldsByKeyPrefix`.
fn find_by_key_prefix<'a>(
    kvs: &'a [RawKv],
    prefix: u8,
) -> Option<&'a RawKv> {
    kvs.iter().find(|kv| kv.key.first() == Some(&prefix))
}

// ---------------------------------------------------------------------
// Field value decoders
// ---------------------------------------------------------------------

fn expect_len(
    value: &[u8],
    expected: usize,
    what: &str,
) -> Result<(), VPsbtError> {
    if value.len() != expected {
        return Err(decode_err(format!(
            "invalid {} length: expected {}, got {}",
            what,
            expected,
            value.len()
        )));
    }
    Ok(())
}

fn decode_u64_be(value: &[u8], what: &str) -> Result<u64, VPsbtError> {
    expect_len(value, 8, what)?;
    Ok(u64::from_be_bytes(value.try_into().expect("8 bytes")))
}

fn decode_u8(value: &[u8], what: &str) -> Result<u8, VPsbtError> {
    expect_len(value, 1, what)?;
    Ok(value[0])
}

fn parse_compressed_pub_key(
    value: &[u8],
    what: &str,
) -> Result<SerializedKey, VPsbtError> {
    expect_len(value, 33, what)?;
    PublicKey::from_slice(value)
        .map_err(|e| decode_err(format!("invalid {}: {}", what, e)))?;
    Ok(SerializedKey(value.try_into().expect("33 bytes")))
}

fn validate_x_only_key(value: &[u8], what: &str) -> Result<(), VPsbtError> {
    expect_len(value, 32, what)?;
    XOnlyPublicKey::from_slice(value)
        .map_err(|e| decode_err(format!("invalid {}: {}", what, e)))?;
    Ok(())
}

/// Decodes a 101-byte PrevID value (outpoint, asset ID, script key),
/// Go's `asset.PrevIDDecoder`.
fn decode_prev_id(value: &[u8]) -> Result<PrevId, VPsbtError> {
    expect_len(value, 101, "prev ID")?;
    // Go's PrevIDDecoder decodes the script key with
    // SerializedKeyDecoder (btcec.ParsePubKey), rejecting off-curve
    // keys at decode time.
    let script_key =
        SerializedKey(value[68..101].try_into().expect("33 bytes"));
    script_key.validate_on_curve().map_err(|e| {
        decode_err(format!("prev ID script key: {}", e))
    })?;
    Ok(PrevId {
        out_point: OutPoint {
            txid: value[..32].try_into().expect("32 bytes"),
            vout: u32::from_be_bytes(
                value[32..36].try_into().expect("4 bytes"),
            ),
        },
        id: AssetId(value[36..68].try_into().expect("32 bytes")),
        script_key,
    })
}

/// Decodes a BIP-0032 derivation value (`fingerprint || path`, all LE
/// u32), Go's `psbt.ReadBip32Derivation`.
fn decode_bip32_value(value: &[u8]) -> Result<(u32, Vec<u32>), VPsbtError> {
    if value.len() % 4 != 0 || value.is_empty() {
        return Err(decode_err("invalid bip32 derivation value"));
    }
    let fingerprint =
        u32::from_le_bytes(value[..4].try_into().expect("4 bytes"));
    let path = value[4..]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")))
        .collect();
    Ok((fingerprint, path))
}

/// Decodes a full BIP-0032 derivation from a `type || pubkey` key and
/// its value, mirroring Go's `bip32DerivationDecoder`.
fn decode_bip32_derivation(
    key: &[u8],
    value: &[u8],
) -> Result<Bip32Derivation, VPsbtError> {
    if key.len() != 34 {
        return Err(decode_err("invalid key length for bip32 derivation"));
    }
    PublicKey::from_slice(&key[1..]).map_err(|e| {
        decode_err(format!("invalid public key for bip32 derivation: {}", e))
    })?;
    let (fingerprint, path) = decode_bip32_value(value)?;
    Ok(Bip32Derivation {
        pub_key: key[1..].to_vec(),
        master_key_fingerprint: fingerprint,
        bip32_path: path,
    })
}

/// Decodes a Taproot BIP-0032 derivation from a `type || x-only key`
/// key and its value, mirroring Go's `taprootBip32DerivationDecoder`
/// and `psbt.ReadTaprootBip32Derivation`.
fn decode_taproot_bip32_derivation(
    key: &[u8],
    value: &[u8],
) -> Result<TaprootBip32Derivation, VPsbtError> {
    if key.len() != 33 {
        return Err(decode_err(
            "invalid key length for taproot bip32 derivation",
        ));
    }
    validate_x_only_key(&key[1..], "taproot bip32 derivation key")?;

    let mut r = Reader::new(value);
    let num_hashes = r.read_compact_size()?;
    if num_hashes > value.len() as u64 {
        return Err(decode_err("too many leaf hashes"));
    }
    let mut leaf_hashes = Vec::with_capacity(num_hashes as usize);
    for _ in 0..num_hashes {
        leaf_hashes.push(r.take(32)?.to_vec());
    }
    let (fingerprint, path) = decode_bip32_value(&value[r.pos..])?;

    Ok(TaprootBip32Derivation {
        x_only_pub_key: key[1..].to_vec(),
        leaf_hashes,
        master_key_fingerprint: fingerprint,
        bip32_path: path,
    })
}

/// Extracts the key family and index from a script key BIP-0032 path
/// of the form `m/1017'/coin_type'/key_family'/0/index`, mirroring
/// Go's `extractLocatorFromPath`.
fn extract_locator_from_path(
    path: &[u32],
) -> Result<(u32, u32), VPsbtError> {
    const BIP0043_PURPOSE: u32 = 1017;
    const HARDENED: u32 = 0x8000_0000;

    if path.len() != 5 {
        return Err(decode_err(format!(
            "invalid bip32 derivation path length: {}",
            path.len()
        )));
    }
    if path[0] != BIP0043_PURPOSE + HARDENED {
        return Err(decode_err(format!(
            "invalid purpose, expected internal purpose, got {}",
            path[0]
        )));
    }
    if path[2] < HARDENED {
        return Err(decode_err("key family must be hardened"));
    }
    Ok((path[2] - HARDENED, path[4]))
}

/// Decodes the alt leaves list value, mirroring Go's
/// `asset.AltLeavesDecoder`.
fn decode_alt_leaves(value: &[u8]) -> Result<Vec<Asset>, VPsbtError> {
    if value.len() > u16::MAX as usize {
        return Err(decode_err("alt leaves record too large"));
    }
    let (count, mut offset) =
        decode_bigsize(value).map_err(|e| decode_err(e.to_string()))?;
    if count > value.len() as u64 {
        return Err(decode_err("too many alt leaves"));
    }
    let mut leaves = Vec::with_capacity(count as usize);
    let mut leaf_keys = std::collections::BTreeSet::new();
    for _ in 0..count {
        let (leaf_bytes, consumed) = decode_var_bytes(&value[offset..])
            .map_err(|e| decode_err(e.to_string()))?;
        offset += consumed;
        let leaf = decode_asset(&leaf_bytes)
            .map_err(|e| decode_err(e.to_string()))?;

        // Each alt leaf must have a unique script key, matching Go's
        // AltLeavesDecoder (asset.ErrDuplicateScriptKeys).
        if !leaf_keys.insert(*leaf.script_key.serialized()) {
            return Err(decode_err("duplicate alt leaf script key"));
        }

        leaves.push(leaf);
    }
    if offset != value.len() {
        return Err(decode_err("trailing bytes after alt leaves"));
    }
    Ok(leaves)
}

fn decode_asset_field(value: &[u8]) -> Result<Asset, VPsbtError> {
    decode_asset(value).map_err(|e| decode_err(e.to_string()))
}

fn decode_proof_field(value: &[u8]) -> Result<Proof, VPsbtError> {
    decode_proof(value).map_err(|e| decode_err(e.to_string()))
}

/// Decodes a Taproot Asset address from its raw TLV payload, routing
/// through the Bech32m decoder to reuse the address TLV logic (the
/// inverse of the encoder's `address_raw_bytes`).
fn decode_address_field(
    value: &[u8],
    network: TapNetwork,
) -> Result<TapAddress, VPsbtError> {
    let hrp = bech32::Hrp::parse(network.hrp())
        .map_err(|e| decode_err(e.to_string()))?;
    let encoded = bech32::encode::<bech32::Bech32m>(hrp, value)
        .map_err(|e| decode_err(e.to_string()))?;
    TapAddress::decode(&encoded).map_err(|e| {
        decode_err(format!("error decoding Taproot address: {}", e))
    })
}

// ---------------------------------------------------------------------
// Section decoders
// ---------------------------------------------------------------------

/// Splits the raw key-value pairs of an input section into the
/// standard PSBT fields of a [`VInput`] and the remaining custom
/// fields.
fn decode_input_section(
    kvs: &[RawKv],
) -> Result<(VInput, Vec<RawKv>), VPsbtError> {
    let mut input = VInput::default();
    let mut unknowns = Vec::new();

    for kv in kvs {
        let type_byte = kv.key[0];
        let key_data = &kv.key[1..];
        match type_byte {
            std_input_key::SIGHASH_TYPE if key_data.is_empty() => {
                expect_len(&kv.value, 4, "sighash type")?;
                input.sighash_type = u32::from_le_bytes(
                    kv.value[..].try_into().expect("4 bytes"),
                );
            }
            std_input_key::BIP32_DERIVATION => {
                input
                    .bip32_derivation
                    .push(decode_bip32_derivation(&kv.key, &kv.value)?);
            }
            std_input_key::TAPROOT_BIP32_DERIVATION => {
                input.taproot_bip32_derivation.push(
                    decode_taproot_bip32_derivation(&kv.key, &kv.value)?,
                );
            }
            std_input_key::TAPROOT_INTERNAL_KEY
                if key_data.is_empty() =>
            {
                validate_x_only_key(&kv.value, "taproot internal key")?;
                input.taproot_internal_key = kv.value.clone();
            }
            std_input_key::TAPROOT_MERKLE_ROOT
                if key_data.is_empty() =>
            {
                input.taproot_merkle_root = kv.value.clone();
            }
            _ => unknowns.push(RawKv {
                key: kv.key.clone(),
                value: kv.value.clone(),
            }),
        }
    }

    Ok((input, unknowns))
}

impl VInput {
    /// Decodes the custom fields of an input section into this input,
    /// mirroring Go's `VInput.decode`.
    fn decode_custom_fields(
        &mut self,
        unknowns: &[RawKv],
    ) -> Result<(), VPsbtError> {
        // Like Go, each mapping entry looks up the first custom field
        // whose key starts with the type byte and skips empty values.
        let field = |prefix: u8| -> Option<&RawKv> {
            find_by_key_prefix(unknowns, prefix)
                .filter(|kv| !kv.value.is_empty())
        };

        if let Some(kv) = field(input_key::TAP_PREV_ID) {
            self.prev_id = decode_prev_id(&kv.value)?;
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_VALUE) {
            self.anchor.value = decode_u64_be(&kv.value, "anchor value")?;
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_PK_SCRIPT) {
            self.anchor.pk_script = kv.value.clone();
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_SIGHASH_TYPE) {
            self.anchor.sig_hash_type =
                decode_u64_be(&kv.value, "anchor sighash type")? as u32;
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_INTERNAL_KEY) {
            self.anchor.internal_key = Some(parse_compressed_pub_key(
                &kv.value,
                "anchor internal key",
            )?);
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_MERKLE_ROOT) {
            self.anchor.merkle_root = kv.value.clone();
        }
        if let Some(kv) =
            field(input_key::TAP_ANCHOR_OUTPUT_BIP32_DERIVATION)
        {
            self.anchor
                .bip32_derivation
                .push(decode_bip32_derivation(&kv.key, &kv.value)?);
        }
        if let Some(kv) =
            field(input_key::TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION)
        {
            self.anchor.taproot_bip32_derivation.push(
                decode_taproot_bip32_derivation(&kv.key, &kv.value)?,
            );
        }
        if let Some(kv) = field(input_key::TAP_ANCHOR_TAPSCRIPT_SIBLING) {
            self.anchor.tapscript_sibling = kv.value.clone();
        }
        if let Some(kv) = field(input_key::TAP_ASSET) {
            self.asset = Some(decode_asset_field(&kv.value)?);
        }
        if let Some(kv) = field(input_key::TAP_ASSET_PROOF) {
            self.proof = Some(decode_proof_field(&kv.value)?);
        }

        self.deserialize_script_key()?;

        Ok(())
    }

    /// Restores the input asset's script key tweak information from
    /// the standard PSBT derivation fields, mirroring Go's
    /// `VInput.deserializeScriptKey`.
    fn deserialize_script_key(&mut self) -> Result<(), VPsbtError> {
        let asset = match self.asset {
            Some(ref mut asset) => asset,
            None => return Ok(()),
        };
        if self.taproot_internal_key.is_empty()
            || self.bip32_derivation.is_empty()
        {
            return Ok(());
        }

        let derivation = &self.bip32_derivation[0];
        let raw_key = parse_compressed_pub_key(
            &derivation.pub_key,
            "script key derivation",
        )
        .map_err(|e| {
            decode_err(format!(
                "error decoding script key derivation info: {}",
                e
            ))
        })?;
        extract_locator_from_path(&derivation.bip32_path).map_err(
            |e| {
                decode_err(format!(
                    "error decoding script key derivation info: {}",
                    e
                ))
            },
        )?;

        asset.script_key.tweaked = Some(TweakedScriptKey {
            raw_key,
            tweak: self.taproot_merkle_root.clone(),
            key_type: ScriptKeyType::Unknown,
        });

        Ok(())
    }
}

/// State parsed from the standard fields of an output section.
#[derive(Default)]
struct OutputStdFields {
    bip32_derivation: Vec<Bip32Derivation>,
    taproot_bip32_derivation: Vec<TaprootBip32Derivation>,
    taproot_internal_key: Vec<u8>,
}

/// Splits the raw key-value pairs of an output section into standard
/// PSBT fields and the remaining custom fields.
fn decode_output_section(
    kvs: &[RawKv],
) -> Result<(OutputStdFields, Vec<RawKv>), VPsbtError> {
    let mut std_fields = OutputStdFields::default();
    let mut unknowns = Vec::new();

    for kv in kvs {
        let type_byte = kv.key[0];
        let key_data = &kv.key[1..];
        match type_byte {
            std_output_key::BIP32_DERIVATION => {
                std_fields
                    .bip32_derivation
                    .push(decode_bip32_derivation(&kv.key, &kv.value)?);
            }
            std_output_key::TAPROOT_BIP32_DERIVATION => {
                std_fields.taproot_bip32_derivation.push(
                    decode_taproot_bip32_derivation(&kv.key, &kv.value)?,
                );
            }
            std_output_key::TAPROOT_INTERNAL_KEY
                if key_data.is_empty() =>
            {
                validate_x_only_key(&kv.value, "taproot internal key")?;
                std_fields.taproot_internal_key = kv.value.clone();
            }
            _ => unknowns.push(RawKv {
                key: kv.key.clone(),
                value: kv.value.clone(),
            }),
        }
    }

    Ok((std_fields, unknowns))
}

/// Restores the output script key tweak information from the standard
/// PSBT derivation fields, mirroring Go's
/// `deserializeTweakedScriptKey`.
fn deserialize_tweaked_script_key(
    std_fields: &OutputStdFields,
) -> Result<Option<TweakedScriptKeyDesc>, VPsbtError> {
    // The fields are not mandatory.
    if std_fields.taproot_internal_key.is_empty()
        || std_fields.bip32_derivation.is_empty()
    {
        return Ok(None);
    }

    let derivation = &std_fields.bip32_derivation[0];
    let pub_key = parse_compressed_pub_key(
        &derivation.pub_key,
        "script key derivation",
    )
    .map_err(|e| {
        decode_err(format!(
            "error decoding script key derivation info: {}",
            e
        ))
    })?;
    let (family, index) =
        extract_locator_from_path(&derivation.bip32_path).map_err(|e| {
            decode_err(format!(
                "error decoding script key derivation info: {}",
                e
            ))
        })?;

    let tweak = std_fields
        .taproot_bip32_derivation
        .first()
        .and_then(|d| d.leaf_hashes.first())
        .cloned()
        .unwrap_or_default();

    Ok(Some(TweakedScriptKeyDesc {
        raw_key: KeyDescriptor {
            pub_key,
            family,
            index,
        },
        tweak,
    }))
}

/// Decodes an output section plus its unsigned transaction output into
/// a [`VOutput`], mirroring Go's `VOutput.decode`.
fn decode_output(
    kvs: &[RawKv],
    tx_out: &RawTxOut,
    network: TapNetwork,
) -> Result<VOutput, VPsbtError> {
    // The script key is the x-only key of the P2TR output script.
    if tx_out.pk_script.len() != 34 {
        return Err(decode_err(format!(
            "expected 34 bytes for taproot pkScript, got {}",
            tx_out.pk_script.len()
        )));
    }
    validate_x_only_key(&tx_out.pk_script[2..], "taproot script key")
        .map_err(|e| {
            decode_err(format!("error parsing taproot script key: {}", e))
        })?;
    let mut script_key_bytes = [0u8; 33];
    script_key_bytes[0] = 0x02;
    script_key_bytes[1..].copy_from_slice(&tx_out.pk_script[2..]);

    let (std_fields, unknowns) = decode_output_section(kvs)?;

    let mut output = VOutput {
        amount: tx_out.value as u64,
        asset_version: 0,
        output_type: VOutputType::SIMPLE,
        interactive: false,
        anchor_output_index: 0,
        anchor_output_internal_key: None,
        anchor_output_bip32_derivation: Vec::new(),
        anchor_output_taproot_bip32_derivation: Vec::new(),
        anchor_output_tapscript_sibling: None,
        asset: None,
        split_asset: None,
        script_key: OutputScriptKey {
            pub_key: SerializedKey(script_key_bytes),
            tweaked: deserialize_tweaked_script_key(&std_fields)?,
        },
        relative_lock_time: 0,
        lock_time: 0,
        proof_delivery_address: None,
        proof_suffix: None,
        alt_leaves: Vec::new(),
        address: None,
    };

    // Like Go, each mapping entry looks up the first custom field
    // whose key starts with the type byte and skips empty values.
    let field = |prefix: u8| -> Option<&RawKv> {
        find_by_key_prefix(&unknowns, prefix)
            .filter(|kv| !kv.value.is_empty())
    };

    if let Some(kv) = field(output_key::TAP_TYPE) {
        output.output_type =
            VOutputType(decode_u8(&kv.value, "output type")?);
    }
    if let Some(kv) = field(output_key::TAP_IS_INTERACTIVE) {
        output.interactive = kv.value == [0x01];
    }
    if let Some(kv) = field(output_key::TAP_ANCHOR_OUTPUT_INDEX) {
        output.anchor_output_index =
            decode_u64_be(&kv.value, "anchor output index")? as u32;
    }
    if let Some(kv) = field(output_key::TAP_ANCHOR_OUTPUT_INTERNAL_KEY) {
        output.anchor_output_internal_key =
            Some(parse_compressed_pub_key(
                &kv.value,
                "anchor output internal key",
            )?);
    }
    if let Some(kv) = field(output_key::TAP_ANCHOR_OUTPUT_BIP32_DERIVATION)
    {
        output
            .anchor_output_bip32_derivation
            .push(decode_bip32_derivation(&kv.key, &kv.value)?);
    }
    if let Some(kv) =
        field(output_key::TAP_ANCHOR_OUTPUT_TAPROOT_BIP32_DERIVATION)
    {
        output.anchor_output_taproot_bip32_derivation.push(
            decode_taproot_bip32_derivation(&kv.key, &kv.value)?,
        );
    }
    if let Some(kv) = field(output_key::TAP_ASSET) {
        output.asset = Some(decode_asset_field(&kv.value)?);
    }
    if let Some(kv) = field(output_key::TAP_SPLIT_ASSET) {
        output.split_asset = Some(decode_asset_field(&kv.value)?);
    }
    if let Some(kv) = field(output_key::TAP_ANCHOR_TAPSCRIPT_SIBLING) {
        output.anchor_output_tapscript_sibling = Some(
            TapscriptPreimage::decode(&kv.value)
                .map_err(|e| decode_err(e.to_string()))?,
        );
    }
    if let Some(kv) = field(output_key::TAP_ASSET_VERSION) {
        output.asset_version = decode_u8(&kv.value, "asset version")?;
    }
    if let Some(kv) = field(output_key::TAP_PROOF_DELIVERY_ADDRESS) {
        let url = String::from_utf8(kv.value.clone())
            .map_err(|e| decode_err(e.to_string()))?;
        output.proof_delivery_address = Some(url);
    }
    if let Some(kv) = field(output_key::TAP_ASSET_PROOF_SUFFIX) {
        output.proof_suffix = Some(decode_proof_field(&kv.value)?);
    }
    if let Some(kv) = field(output_key::TAP_ASSET_LOCK_TIME) {
        output.lock_time = decode_u64_be(&kv.value, "lock time")?;
    }
    if let Some(kv) = field(output_key::TAP_ASSET_RELATIVE_LOCK_TIME) {
        output.relative_lock_time =
            decode_u64_be(&kv.value, "relative lock time")?;
    }
    if let Some(kv) = field(output_key::TAP_ALT_LEAVES) {
        output.alt_leaves = decode_alt_leaves(&kv.value)?;
    }
    if let Some(kv) = field(output_key::TAP_ADDRESS) {
        output.address = Some(decode_address_field(&kv.value, network)?);
    }

    Ok(output)
}

// ---------------------------------------------------------------------
// Packet decoding
// ---------------------------------------------------------------------

impl VPacket {
    /// Decodes a virtual packet from its binary PSBT representation,
    /// matching Go's `tappsbt.NewFromRawBytes` (with `b64 == false`).
    pub fn from_raw_bytes(data: &[u8]) -> Result<VPacket, VPsbtError> {
        let mut r = Reader::new(data);

        let magic = r.take(PSBT_MAGIC.len())?;
        if magic != PSBT_MAGIC {
            return Err(VPsbtError::InvalidFormat(
                "invalid magic bytes".into(),
            ));
        }

        // Global section.
        let global_kvs = r.read_section()?;
        let unsigned_tx_kv = global_kvs
            .iter()
            .find(|kv| kv.key == [0x00])
            .ok_or_else(|| {
                VPsbtError::InvalidFormat("missing unsigned tx".into())
            })?;
        let (num_inputs, tx_outs) = parse_unsigned_tx(&unsigned_tx_kv.value)?;

        // Input and output sections.
        let mut input_sections = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            input_sections.push(r.read_section()?);
        }
        let mut output_sections = Vec::with_capacity(tx_outs.len());
        for _ in 0..tx_outs.len() {
            output_sections.push(r.read_section()?);
        }

        // We want an explicit "isVirtual" boolean marker.
        let is_virtual =
            find_by_key_prefix(&global_kvs, global_key::TAP_IS_VIRTUAL_TX)
                .ok_or(VPsbtError::NotVirtualTx)?;
        if is_virtual.value != [0x01] {
            return Err(VPsbtError::NotVirtualTx);
        }

        // We also want the HRP of the Taproot Asset chain params.
        let hrp_kv = find_by_key_prefix(
            &global_kvs,
            global_key::TAP_CHAIN_PARAMS_HRP,
        )
        .ok_or_else(|| {
            VPsbtError::InvalidChainParamsHrp("missing".into())
        })?;
        let hrp = String::from_utf8(hrp_kv.value.clone())
            .map_err(|e| VPsbtError::InvalidChainParamsHrp(e.to_string()))?;
        let chain_params = TapNetwork::from_hrp(&hrp)
            .map_err(|_| VPsbtError::InvalidChainParamsHrp(hrp.clone()))?;

        // We also need the VPacket version.
        let version_kv =
            find_by_key_prefix(&global_kvs, global_key::TAP_PSBT_VERSION)
                .ok_or_else(|| {
                    decode_err("error finding virtual tx version")
                })?;
        if version_kv.value.is_empty() {
            return Err(decode_err("empty virtual tx version"));
        }
        let version = VPacketVersion::from_u8(version_kv.value[0])?;

        let mut packet = VPacket {
            inputs: Vec::with_capacity(num_inputs),
            outputs: Vec::with_capacity(tx_outs.len()),
            chain_params,
            version,
        };

        for section in &input_sections {
            let (mut input, unknowns) = decode_input_section(section)?;
            input.decode_custom_fields(&unknowns)?;
            packet.inputs.push(input);
        }

        for (section, tx_out) in
            output_sections.iter().zip(tx_outs.iter())
        {
            packet
                .outputs
                .push(decode_output(section, tx_out, chain_params)?);
        }

        Ok(packet)
    }

    /// Decodes a virtual packet from a base64 string, matching Go's
    /// `tappsbt.NewFromRawBytes` with `b64 == true`.
    pub fn from_base64(s: &str) -> Result<VPacket, VPsbtError> {
        let bytes = super::base64_decode(s.trim())
            .map_err(VPsbtError::InvalidFormat)?;
        VPacket::from_raw_bytes(&bytes)
    }

    /// Decodes a virtual packet from a `bitcoin::psbt::Psbt`, matching
    /// Go's `tappsbt.NewFromPsbt`.
    pub fn from_psbt(psbt: &bitcoin::Psbt) -> Result<VPacket, VPsbtError> {
        VPacket::from_raw_bytes(&psbt.serialize())
    }
}
