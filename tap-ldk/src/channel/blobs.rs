// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Opaque blob types stored alongside LDK channel state.
//!
//! These blobs are byte-compatible with Go's `tapchannelmsg` records:
//! - [`ChannelBlob`]: Go `OpenChannel` (funding blob), a TLV stream
//!   `{0: AssetOutputListRecord, 1: decimal_display u8, 2: optional
//!   group key}`
//! - [`CommitmentBlob`]: Go `Commitment`, a TLV stream `{0: local
//!   outputs, 1: remote outputs, 2: outgoing HTLC output map, 3:
//!   incoming HTLC output map, 4: AuxLeaves, 5: STXO bool}`
//! - [`HtlcBlob`]: Go `rfqmsg.Htlc` (see [`crate::routing`] for the
//!   custom record encoding)
//!
//! Each asset output is itself a TLV stream `{0: asset_id (32 bytes),
//! 1: amount (u64), 2: proof.Proof}`. The proof record is REQUIRED by
//! the Go decoder, so encoding an output without a proof fails.

use std::collections::BTreeMap;

use tap_primitives::asset::{AssetId, SerializedKey};
use tap_primitives::encoding::bigsize::{decode_bigsize, encode_bigsize};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};
use tap_primitives::proof::{decode_proof, encode_proof, Proof};

/// Maximum number of asset outputs in a single record (Go
/// `rfqmsg.MaxNumOutputs`).
pub const MAX_NUM_OUTPUTS: u64 = 2048;

/// Maximum number of HTLCs in a single record (Go
/// `tapchannelmsg.MaxNumHTLCs`, from lnd `input.MaxHTLCNumber`).
pub const MAX_NUM_HTLCS: u64 = 966;

/// Errors from blob encoding/decoding.
#[derive(Debug, Clone)]
pub enum BlobError {
    TooShort,
    InvalidFormat(String),
    /// An asset output has no proof; the Go wire format requires one.
    MissingProof,
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::TooShort => write!(f, "blob data too short"),
            BlobError::InvalidFormat(msg) => {
                write!(f, "invalid blob format: {}", msg)
            }
            BlobError::MissingProof => {
                write!(f, "asset output missing required proof")
            }
        }
    }
}

impl std::error::Error for BlobError {}

fn fmt_err<E: std::fmt::Display>(ctx: &str) -> impl Fn(E) -> BlobError + '_ {
    move |e| BlobError::InvalidFormat(format!("{}: {}", ctx, e))
}

// --- inline var bytes helpers (Go asset.InlineVarBytesEncoder) ---

fn write_inline_var_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    encode_bigsize(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn read_inline_var_bytes<'a>(
    data: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], BlobError> {
    let (len, len_size) = decode_bigsize(&data[*offset..])
        .map_err(fmt_err("var bytes length"))?;
    *offset += len_size;
    let end = offset
        .checked_add(len as usize)
        .filter(|&e| e <= data.len())
        .ok_or(BlobError::TooShort)?;
    let out = &data[*offset..end];
    *offset = end;
    Ok(out)
}

fn read_varint(data: &[u8], offset: &mut usize) -> Result<u64, BlobError> {
    let (val, size) =
        decode_bigsize(&data[*offset..]).map_err(fmt_err("varint"))?;
    *offset += size;
    Ok(val)
}

// --- AssetBalance ---

/// An (asset id, amount) tuple, matching Go `rfqmsg.AssetBalance`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: AssetId,
    pub amount: u64,
}

// --- AssetOutput / FundedAsset ---

/// A single asset UTXO committed to a channel funding or commitment
/// output, matching Go `tapchannelmsg.AssetOutput`.
///
/// The `script_key` field is a Rust-side convenience (Go derives it
/// from the proof); it is populated from `proof.asset.script_key` on
/// decode and is NOT independently encoded.
#[derive(Clone, Debug)]
pub struct AssetOutput {
    /// The asset ID.
    pub asset_id: AssetId,
    /// Amount of this asset in the output.
    pub amount: u64,
    /// The script key for this asset output.
    pub script_key: SerializedKey,
    /// The last transition proof for this output. REQUIRED on encode.
    pub proof: Option<Proof>,
}

/// A single asset funded into a channel. Alias of [`AssetOutput`], as
/// Go uses the same record for funding and commitment outputs.
pub type FundedAsset = AssetOutput;

impl PartialEq for AssetOutput {
    fn eq(&self, other: &Self) -> bool {
        self.asset_id == other.asset_id
            && self.amount == other.amount
            && self.script_key == other.script_key
            && match (&self.proof, &other.proof) {
                (None, None) => true,
                (Some(a), Some(b)) => encode_proof(a) == encode_proof(b),
                _ => false,
            }
    }
}

impl Eq for AssetOutput {}

impl AssetOutput {
    /// Encodes as a Go `AssetOutput` TLV stream
    /// `{0: asset_id, 1: amount, 2: proof}`. Errors when the proof is
    /// missing, as the Go decoder requires it.
    pub fn encode(&self) -> Result<Vec<u8>, BlobError> {
        let proof = self.proof.as_ref().ok_or(BlobError::MissingProof)?;
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::bytes(0, &self.asset_id.0));
        stream.push(TlvRecord::u64(1, self.amount));
        stream.push(TlvRecord::bytes(2, &encode_proof(proof)));
        Ok(stream.encode())
    }

    /// Decodes from a Go `AssetOutput` TLV stream. The proof record is
    /// required; the script key is populated from the proof's asset.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let stream =
            TlvStream::decode(data).map_err(fmt_err("asset output"))?;
        let id_record = stream.get(0).ok_or_else(|| {
            BlobError::InvalidFormat("asset output missing asset id".into())
        })?;
        if id_record.value.len() != 32 {
            return Err(BlobError::InvalidFormat(
                "asset id must be 32 bytes".into(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_record.value);
        let amount = stream
            .get(1)
            .ok_or_else(|| {
                BlobError::InvalidFormat(
                    "asset output missing amount".into(),
                )
            })?
            .as_u64()
            .map_err(fmt_err("asset output amount"))?;
        let proof_record = stream.get(2).ok_or(BlobError::MissingProof)?;
        let proof = decode_proof(&proof_record.value)
            .map_err(fmt_err("asset output proof"))?;
        let script_key = proof.asset.script_key.pub_key;

        Ok(AssetOutput {
            asset_id: AssetId(id),
            amount,
            script_key,
            proof: Some(proof),
        })
    }
}

/// Encodes a list of asset outputs in Go `AssetOutputListRecord` value
/// format: varint count, then per output a varint-length-prefixed
/// `AssetOutput` TLV stream.
pub fn encode_asset_output_list(
    outputs: &[AssetOutput],
) -> Result<Vec<u8>, BlobError> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, outputs.len() as u64);
    for output in outputs {
        let encoded = output.encode()?;
        write_inline_var_bytes(&mut buf, &encoded);
    }
    Ok(buf)
}

/// Decodes a list of asset outputs from Go `AssetOutputListRecord`
/// value format.
pub fn decode_asset_output_list(
    data: &[u8],
) -> Result<Vec<AssetOutput>, BlobError> {
    let mut offset = 0usize;
    let count = read_varint(data, &mut offset)?;
    if count > MAX_NUM_OUTPUTS {
        return Err(BlobError::InvalidFormat(format!(
            "too many outputs: {}",
            count
        )));
    }
    let mut outputs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let bytes = read_inline_var_bytes(data, &mut offset)?;
        outputs.push(AssetOutput::decode(bytes)?);
    }
    if offset != data.len() {
        return Err(BlobError::InvalidFormat(
            "trailing bytes after output list".into(),
        ));
    }
    Ok(outputs)
}

/// A map of HTLC index to asset outputs, matching Go
/// `tapchannelmsg.HtlcAssetOutput`.
pub type HtlcAssetOutputs = BTreeMap<u64, Vec<AssetOutput>>;

/// Encodes an HTLC output map in Go `HtlcAssetOutput` value format:
/// varint count, then per HTLC a varint index followed by a
/// varint-length-prefixed `AssetOutputListRecord` TLV stream (a stream
/// containing a single type 0 record).
pub fn encode_htlc_asset_outputs(
    htlcs: &HtlcAssetOutputs,
) -> Result<Vec<u8>, BlobError> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, htlcs.len() as u64);
    for (htlc_index, outputs) in htlcs {
        encode_bigsize(&mut buf, *htlc_index);
        // Go encodes the list as a full TLV stream with a single
        // type 0 record (AssetOutputListRecord.Encode).
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::new(0, encode_asset_output_list(outputs)?));
        write_inline_var_bytes(&mut buf, &stream.encode());
    }
    Ok(buf)
}

/// Decodes an HTLC output map from Go `HtlcAssetOutput` value format.
pub fn decode_htlc_asset_outputs(
    data: &[u8],
) -> Result<HtlcAssetOutputs, BlobError> {
    let mut offset = 0usize;
    let count = read_varint(data, &mut offset)?;
    if count > MAX_NUM_HTLCS {
        return Err(BlobError::InvalidFormat(format!(
            "too many HTLCs: {}",
            count
        )));
    }
    let mut htlcs = BTreeMap::new();
    for _ in 0..count {
        let htlc_index = read_varint(data, &mut offset)?;
        let bytes = read_inline_var_bytes(data, &mut offset)?;
        let stream =
            TlvStream::decode(bytes).map_err(fmt_err("htlc output list"))?;
        let record = stream.get(0).ok_or_else(|| {
            BlobError::InvalidFormat("htlc output list missing record".into())
        })?;
        htlcs.insert(htlc_index, decode_asset_output_list(&record.value)?);
    }
    if offset != data.len() {
        return Err(BlobError::InvalidFormat(
            "trailing bytes after htlc output map".into(),
        ));
    }
    Ok(htlcs)
}

// --- ChannelBlob (Go OpenChannel) ---

/// Per-channel asset data, created during funding.
///
/// This is stored as an opaque blob alongside LDK's `Channel` state.
/// Byte-compatible with Go's `tapchannelmsg.OpenChannel`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelBlob {
    /// Assets funded into this channel (record 0, required).
    pub funded_assets: Vec<FundedAsset>,
    /// Decimal display precision (record 1, required u8).
    pub decimal_display: u8,
    /// Group key if all assets share a group (record 2, optional).
    pub group_key: Option<SerializedKey>,
}

impl ChannelBlob {
    /// Encodes to Go `OpenChannel` bytes. Errors if any funded asset is
    /// missing its proof.
    pub fn encode(&self) -> Result<Vec<u8>, BlobError> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::new(
            0,
            encode_asset_output_list(&self.funded_assets)?,
        ));
        stream.push(TlvRecord::u8(1, self.decimal_display));
        if let Some(ref gk) = self.group_key {
            stream.push(TlvRecord::bytes(2, gk.as_bytes()));
        }
        Ok(stream.encode())
    }

    /// Decodes from Go `OpenChannel` bytes.
    ///
    /// Absent records decode to their zero values, mirroring lnd's TLV
    /// stream semantics.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let stream =
            TlvStream::decode(data).map_err(fmt_err("open channel"))?;
        let funded_assets = match stream.get(0) {
            Some(r) => decode_asset_output_list(&r.value)?,
            None => Vec::new(),
        };
        let decimal_display = match stream.get(1) {
            Some(r) => r.as_u8().map_err(fmt_err("decimal display"))?,
            None => 0,
        };
        let group_key = match stream.get(2) {
            None => None,
            Some(r) => {
                if r.value.len() != 33 {
                    return Err(BlobError::InvalidFormat(
                        "group key must be 33 bytes".into(),
                    ));
                }
                let mut gk = [0u8; 33];
                gk.copy_from_slice(&r.value);
                Some(SerializedKey(gk))
            }
        };

        Ok(ChannelBlob {
            funded_assets,
            decimal_display,
            group_key,
        })
    }
}

// --- Aux leaves ---

/// A tapscript leaf, matching Go `tapchannelmsg.TapLeafRecord`.
///
/// The wire encoding is `u8 version || varint(script_len) ||
/// varbytes(script)` (the script length appears twice; this mirrors
/// the Go encoder exactly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapLeaf {
    /// The tapscript leaf version (0xC0 for tapscript v0).
    pub version: u8,
    /// The leaf script.
    pub script: Vec<u8>,
}

impl TapLeaf {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        encode_bigsize(buf, self.script.len() as u64);
        write_inline_var_bytes(buf, &self.script);
    }

    fn decode_from(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<Self, BlobError> {
        if *offset >= data.len() {
            return Err(BlobError::TooShort);
        }
        let version = data[*offset];
        *offset += 1;
        let declared_len = read_varint(data, offset)?;
        let script = read_inline_var_bytes(data, offset)?;
        if declared_len as usize != script.len() {
            return Err(BlobError::InvalidFormat(
                "tap leaf script length mismatch".into(),
            ));
        }
        Ok(TapLeaf {
            version,
            script: script.to_vec(),
        })
    }

    /// Encodes to the Go `TapLeafRecord` value format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Decodes from the Go `TapLeafRecord` value format.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let mut offset = 0usize;
        let leaf = Self::decode_from(data, &mut offset)?;
        if offset != data.len() {
            return Err(BlobError::InvalidFormat(
                "trailing bytes after tap leaf".into(),
            ));
        }
        Ok(leaf)
    }
}

/// The aux leaf pair of an HTLC, matching Go
/// `tapchannelmsg.HtlcAuxLeaf`: a TLV stream `{0: optional aux leaf,
/// 1: optional second level leaf}`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HtlcAuxLeaf {
    /// The first-level aux leaf for the HTLC output.
    pub aux_leaf: Option<TapLeaf>,
    /// The second-level aux leaf (HTLC timeout/success tx output).
    pub second_level_leaf: Option<TapLeaf>,
}

impl HtlcAuxLeaf {
    /// Encodes to Go `HtlcAuxLeaf` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        if let Some(ref leaf) = self.aux_leaf {
            stream.push(TlvRecord::new(0, leaf.encode()));
        }
        if let Some(ref leaf) = self.second_level_leaf {
            stream.push(TlvRecord::new(1, leaf.encode()));
        }
        stream.encode()
    }

    /// Decodes from Go `HtlcAuxLeaf` bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let stream =
            TlvStream::decode(data).map_err(fmt_err("htlc aux leaf"))?;
        let aux_leaf = match stream.get(0) {
            None => None,
            Some(r) => Some(TapLeaf::decode(&r.value)?),
        };
        let second_level_leaf = match stream.get(1) {
            None => None,
            Some(r) => Some(TapLeaf::decode(&r.value)?),
        };
        Ok(HtlcAuxLeaf {
            aux_leaf,
            second_level_leaf,
        })
    }
}

/// Encodes an HTLC aux leaf map in Go `HtlcAuxLeafMapRecord` value
/// format.
fn encode_htlc_aux_leaf_map(map: &BTreeMap<u64, HtlcAuxLeaf>) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bigsize(&mut buf, map.len() as u64);
    for (htlc_index, leaf) in map {
        encode_bigsize(&mut buf, *htlc_index);
        write_inline_var_bytes(&mut buf, &leaf.encode());
    }
    buf
}

/// Decodes an HTLC aux leaf map from Go `HtlcAuxLeafMapRecord` value
/// format.
fn decode_htlc_aux_leaf_map(
    data: &[u8],
) -> Result<BTreeMap<u64, HtlcAuxLeaf>, BlobError> {
    let mut offset = 0usize;
    let count = read_varint(data, &mut offset)?;
    if count > MAX_NUM_HTLCS {
        return Err(BlobError::InvalidFormat(format!(
            "too many HTLC leaves: {}",
            count
        )));
    }
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let htlc_index = read_varint(data, &mut offset)?;
        let bytes = read_inline_var_bytes(data, &mut offset)?;
        map.insert(htlc_index, HtlcAuxLeaf::decode(bytes)?);
    }
    if offset != data.len() {
        return Err(BlobError::InvalidFormat(
            "trailing bytes after leaf map".into(),
        ));
    }
    Ok(map)
}

/// The auxiliary leaves of a commitment, matching Go
/// `tapchannelmsg.AuxLeaves`: a TLV stream `{0: optional local leaf,
/// 1: optional remote leaf, 2: outgoing HTLC leaf map, 3: incoming
/// HTLC leaf map}`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuxLeaves {
    /// Aux leaf of the to_local output.
    pub local_aux_leaf: Option<TapLeaf>,
    /// Aux leaf of the to_remote output.
    pub remote_aux_leaf: Option<TapLeaf>,
    /// Aux leaves of outgoing HTLC outputs, keyed by HTLC index.
    pub outgoing_htlc_leaves: BTreeMap<u64, HtlcAuxLeaf>,
    /// Aux leaves of incoming HTLC outputs, keyed by HTLC index.
    pub incoming_htlc_leaves: BTreeMap<u64, HtlcAuxLeaf>,
}

impl AuxLeaves {
    /// Encodes to Go `AuxLeaves` bytes (the inner TLV stream).
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();
        if let Some(ref leaf) = self.local_aux_leaf {
            stream.push(TlvRecord::new(0, leaf.encode()));
        }
        if let Some(ref leaf) = self.remote_aux_leaf {
            stream.push(TlvRecord::new(1, leaf.encode()));
        }
        stream.push(TlvRecord::new(
            2,
            encode_htlc_aux_leaf_map(&self.outgoing_htlc_leaves),
        ));
        stream.push(TlvRecord::new(
            3,
            encode_htlc_aux_leaf_map(&self.incoming_htlc_leaves),
        ));
        stream.encode()
    }

    /// Decodes from Go `AuxLeaves` bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let stream =
            TlvStream::decode(data).map_err(fmt_err("aux leaves"))?;
        let local_aux_leaf = match stream.get(0) {
            None => None,
            Some(r) => Some(TapLeaf::decode(&r.value)?),
        };
        let remote_aux_leaf = match stream.get(1) {
            None => None,
            Some(r) => Some(TapLeaf::decode(&r.value)?),
        };
        let outgoing_htlc_leaves = match stream.get(2) {
            Some(r) => decode_htlc_aux_leaf_map(&r.value)?,
            None => BTreeMap::new(),
        };
        let incoming_htlc_leaves = match stream.get(3) {
            Some(r) => decode_htlc_aux_leaf_map(&r.value)?,
            None => BTreeMap::new(),
        };
        Ok(AuxLeaves {
            local_aux_leaf,
            remote_aux_leaf,
            outgoing_htlc_leaves,
            incoming_htlc_leaves,
        })
    }
}

// --- CommitmentBlob (Go Commitment) ---

/// Per-commitment asset state, byte-compatible with Go's
/// `tapchannelmsg.Commitment`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommitmentBlob {
    /// Local asset outputs (record 0).
    pub local_assets: Vec<AssetOutput>,
    /// Remote asset outputs (record 1).
    pub remote_assets: Vec<AssetOutput>,
    /// Outgoing HTLC asset outputs by HTLC index (record 2).
    pub outgoing_htlc_assets: HtlcAssetOutputs,
    /// Incoming HTLC asset outputs by HTLC index (record 3).
    pub incoming_htlc_assets: HtlcAssetOutputs,
    /// Auxiliary leaves for the commitment outputs (record 4, encoded
    /// with an inner varint length prefix, mirroring Go `eAuxLeaves`).
    pub aux_leaves: AuxLeaves,
    /// Whether STXO proofs are used (record 5).
    pub stxo: bool,
}

impl CommitmentBlob {
    /// Sums the local output amounts.
    pub fn local_balance(&self) -> u64 {
        self.local_assets.iter().map(|o| o.amount).sum()
    }

    /// Sums the remote output amounts.
    pub fn remote_balance(&self) -> u64 {
        self.remote_assets.iter().map(|o| o.amount).sum()
    }

    /// Encodes to Go `Commitment` bytes. Errors if any output is
    /// missing its proof.
    pub fn encode(&self) -> Result<Vec<u8>, BlobError> {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::new(
            0,
            encode_asset_output_list(&self.local_assets)?,
        ));
        stream.push(TlvRecord::new(
            1,
            encode_asset_output_list(&self.remote_assets)?,
        ));
        stream.push(TlvRecord::new(
            2,
            encode_htlc_asset_outputs(&self.outgoing_htlc_assets)?,
        ));
        stream.push(TlvRecord::new(
            3,
            encode_htlc_asset_outputs(&self.incoming_htlc_assets)?,
        ));
        // The aux leaves record value is the var-bytes wrapped inner
        // stream (Go eAuxLeaves).
        let mut leaves_value = Vec::new();
        write_inline_var_bytes(&mut leaves_value, &self.aux_leaves.encode());
        stream.push(TlvRecord::new(4, leaves_value));
        stream.push(TlvRecord::u8(5, if self.stxo { 1 } else { 0 }));
        Ok(stream.encode())
    }

    /// Decodes from Go `Commitment` bytes.
    ///
    /// Absent records decode to their zero values, mirroring lnd's TLV
    /// stream semantics (older fixtures may lack newer records such as
    /// the STXO flag).
    pub fn decode(data: &[u8]) -> Result<Self, BlobError> {
        let stream =
            TlvStream::decode(data).map_err(fmt_err("commitment"))?;
        let local_assets = match stream.get(0) {
            Some(r) => decode_asset_output_list(&r.value)?,
            None => Vec::new(),
        };
        let remote_assets = match stream.get(1) {
            Some(r) => decode_asset_output_list(&r.value)?,
            None => Vec::new(),
        };
        let outgoing_htlc_assets = match stream.get(2) {
            Some(r) => decode_htlc_asset_outputs(&r.value)?,
            None => BTreeMap::new(),
        };
        let incoming_htlc_assets = match stream.get(3) {
            Some(r) => decode_htlc_asset_outputs(&r.value)?,
            None => BTreeMap::new(),
        };

        let aux_leaves = match stream.get(4) {
            Some(leaves_record) => {
                let mut offset = 0usize;
                let leaves_bytes =
                    read_inline_var_bytes(&leaves_record.value, &mut offset)?;
                AuxLeaves::decode(leaves_bytes)?
            }
            None => AuxLeaves::default(),
        };

        let stxo = match stream.get(5) {
            Some(r) => r.as_u8().map_err(fmt_err("stxo"))? != 0,
            None => false,
        };

        Ok(CommitmentBlob {
            local_assets,
            remote_assets,
            outgoing_htlc_assets,
            incoming_htlc_assets,
            aux_leaves,
            stxo,
        })
    }
}

// --- HtlcBlob ---

/// Per-HTLC asset data (Go `rfqmsg.Htlc`). See [`crate::routing`] for
/// the wire encoding of these records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcBlob {
    /// Asset amounts carried by this HTLC.
    pub amounts: Vec<AssetBalance>,
    /// RFQ quote ID used for this payment (32 bytes, Go-compatible).
    pub rfq_id: Option<[u8; 32]>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tap_primitives::asset::{
        Asset, AssetType, AssetVersion, Genesis, OutPoint, ScriptKey,
        ScriptVersion,
    };
    use tap_primitives::proof::{
        AnchorTx, BlockHeader, TaprootProof, TapscriptProof,
        TransitionVersion, TxMerkleProof,
    };

    /// Builds a minimal structurally-valid proof for round-trip tests.
    pub(crate) fn test_proof(
        asset_id_byte: u8,
        amount: u64,
        script_key: SerializedKey,
    ) -> Proof {
        let genesis = Genesis {
            first_prev_out: OutPoint::default(),
            tag: "test".into(),
            meta_hash: [asset_id_byte; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset {
            version: AssetVersion::V0,
            genesis,
            amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(script_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };
        Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint::default(),
            block_header: BlockHeader::default(),
            block_height: 0,
            anchor_tx: AnchorTx::default(),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset,
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                tapscript_proof: Some(TapscriptProof {
                    tap_preimage_1: None,
                    tap_preimage_2: None,
                    bip86: true,
                    unknown_odd_types: std::collections::BTreeMap::new(),
                }),
                unknown_odd_types: std::collections::BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: None,
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn test_output(
        asset_id_byte: u8,
        amount: u64,
    ) -> AssetOutput {
        let script_key = SerializedKey([0x02; 33]);
        AssetOutput {
            asset_id: AssetId([asset_id_byte; 32]),
            amount,
            script_key,
            proof: Some(test_proof(asset_id_byte, amount, script_key)),
        }
    }

    #[test]
    fn test_channel_blob_roundtrip() {
        let blob = ChannelBlob {
            funded_assets: vec![test_output(0xAA, 1000), test_output(0xBB, 500)],
            decimal_display: 8,
            group_key: Some(SerializedKey([0x03; 33])),
        };

        let encoded = blob.encode().unwrap();
        let decoded = ChannelBlob::decode(&encoded).unwrap();
        // The script key round-trips through the proof's asset.
        assert_eq!(blob.funded_assets.len(), decoded.funded_assets.len());
        assert_eq!(blob.decimal_display, decoded.decimal_display);
        assert_eq!(blob.group_key, decoded.group_key);
        assert_eq!(
            decoded.funded_assets[0].script_key,
            SerializedKey([0x02; 33])
        );
        // Byte-stable re-encode.
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn test_channel_blob_empty() {
        let blob = ChannelBlob {
            funded_assets: vec![],
            decimal_display: 0,
            group_key: None,
        };
        let encoded = blob.encode().unwrap();
        let decoded = ChannelBlob::decode(&encoded).unwrap();
        assert_eq!(blob, decoded);
    }

    #[test]
    fn test_encode_missing_proof_fails() {
        let blob = ChannelBlob {
            funded_assets: vec![AssetOutput {
                asset_id: AssetId([0xCC; 32]),
                amount: 42,
                script_key: SerializedKey([0x02; 33]),
                proof: None,
            }],
            decimal_display: 0,
            group_key: None,
        };
        assert!(matches!(blob.encode(), Err(BlobError::MissingProof)));
    }

    #[test]
    fn test_commitment_blob_roundtrip() {
        let mut outgoing = BTreeMap::new();
        outgoing.insert(3u64, vec![test_output(0xAA, 50)]);
        let mut incoming = BTreeMap::new();
        incoming.insert(7u64, vec![test_output(0xAA, 30)]);

        let mut out_leaves = BTreeMap::new();
        out_leaves.insert(
            3u64,
            HtlcAuxLeaf {
                aux_leaf: Some(TapLeaf {
                    version: 0xC0,
                    script: vec![0x51],
                }),
                second_level_leaf: None,
            },
        );

        let blob = CommitmentBlob {
            local_assets: vec![test_output(0xAA, 600)],
            remote_assets: vec![test_output(0xAA, 400)],
            outgoing_htlc_assets: outgoing,
            incoming_htlc_assets: incoming,
            aux_leaves: AuxLeaves {
                local_aux_leaf: Some(TapLeaf {
                    version: 0xC0,
                    script: vec![0x51, 0x21],
                }),
                remote_aux_leaf: None,
                outgoing_htlc_leaves: out_leaves,
                incoming_htlc_leaves: BTreeMap::new(),
            },
            stxo: true,
        };

        let encoded = blob.encode().unwrap();
        let decoded = CommitmentBlob::decode(&encoded).unwrap();
        assert_eq!(blob.local_balance(), decoded.local_balance());
        assert_eq!(blob.remote_balance(), decoded.remote_balance());
        assert_eq!(blob.aux_leaves, decoded.aux_leaves);
        assert_eq!(blob.stxo, decoded.stxo);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn test_tap_leaf_roundtrip() {
        let leaf = TapLeaf {
            version: 0xC0,
            script: vec![0x6a, 0x20, 0x01, 0x02],
        };
        let encoded = leaf.encode();
        // version || varint(4) || varint(4) || script.
        assert_eq!(encoded[0], 0xC0);
        assert_eq!(encoded[1], 4);
        assert_eq!(encoded[2], 4);
        let decoded = TapLeaf::decode(&encoded).unwrap();
        assert_eq!(leaf, decoded);
    }

    #[test]
    fn test_htlc_aux_leaf_roundtrip() {
        let leaf = HtlcAuxLeaf {
            aux_leaf: Some(TapLeaf {
                version: 0xC0,
                script: vec![0x51],
            }),
            second_level_leaf: Some(TapLeaf {
                version: 0xC0,
                script: vec![0x52],
            }),
        };
        let decoded = HtlcAuxLeaf::decode(&leaf.encode()).unwrap();
        assert_eq!(leaf, decoded);
    }

    #[test]
    fn test_commitment_blob_default_roundtrip() {
        let blob = CommitmentBlob::default();
        let encoded = blob.encode().unwrap();
        let decoded = CommitmentBlob::decode(&encoded).unwrap();
        assert_eq!(blob, decoded);
    }
}
