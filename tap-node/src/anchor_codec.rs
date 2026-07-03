// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Versioned binary serialization of [`PendingAnchor`]s for the
//! [`tap_persist::pending_anchor_store::PendingAnchorStore`].
//!
//! A pending anchor holds everything needed to finish a broadcast mint
//! or transfer once its anchor transaction confirms. Persisting it at
//! broadcast time (and reloading it at node construction) means a crash
//! or restart between broadcast and confirmation no longer loses proof
//! generation and delivery.
//!
//! ## Payload format
//!
//! The store persists `(txid, kind, payload)`; the payload defined here
//! is a length-prefixed binary encoding with a leading format-version
//! byte for forward compatibility. All integers are big-endian;
//! variable-length fields are prefixed with a `u32` length; optional
//! fields are prefixed with a `u8` presence flag. Domain objects reuse
//! the existing Go-compatible TLV codecs: assets via
//! [`encode_asset`]/[`decode_asset`], proofs via
//! [`proof::encode::encode_proof`]/[`proof::decode::decode_proof`],
//! proof files via [`proof::File`] encode/decode, and meta reveals via
//! [`MetaReveal`] encode/decode.
//!
//! ## Mint anchors
//!
//! A mint payload stores only what the batch store cannot reproduce:
//! the batch key (the lookup handle), the mint output's taproot
//! internal key, the sprouted assets, the Taproot Asset commitment
//! version, and the seedlings' meta reveals. At decode time the batch
//! is reloaded from the batch store by key and the transient fields are
//! overlaid: the sprouted assets are decoded and the tree-retaining
//! root commitment is rebuilt from them deterministically, exactly as
//! the planter's sprout step built it.

use tap_persist::batch_store::BatchStore;
use tap_persist::pending_anchor_store::StoredPendingAnchor;
use tap_primitives::asset::{AssetId, EncodeType, OutPoint, SerializedKey};
use tap_primitives::commitment::{
    AssetCommitmentTree, TapCommitmentTree, TapCommitmentVersion,
};
use tap_primitives::encoding::asset::{decode_asset, encode_asset};
use tap_primitives::mssmt::NodeHash;
use tap_primitives::proof::{self, MetaReveal};
use tap_universe::supply::{
    RootCommitment, SupplySubTree, SupplyUpdateEvent,
};

use crate::tasks::{
    AnchorKind, MintAnchor, PassiveAnchor, PendingAnchor,
    SupplyCommitAnchor, TransferAnchor,
};

/// Store discriminator for mint anchors.
pub(crate) const KIND_MINT: u8 = 0;
/// Store discriminator for transfer anchors.
pub(crate) const KIND_TRANSFER: u8 = 1;
/// Store discriminator for supply commitment anchors.
pub(crate) const KIND_SUPPLY_COMMIT: u8 = 2;

/// Current payload format version. Bump when the layout changes;
/// decoders reject versions they do not understand.
const PAYLOAD_VERSION: u8 = 1;

/// Mint payload format version: version 2 appends the group key
/// reveals and the optional delegation key. Version-1 rows (written
/// before supply commitment support) decode with empty defaults.
const MINT_PAYLOAD_VERSION: u8 = 2;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Serializes a pending anchor into its store row.
pub(crate) fn encode_pending_anchor(
    anchor: &PendingAnchor,
) -> StoredPendingAnchor {
    let (kind, payload) = match &anchor.kind {
        AnchorKind::Mint(mint) => (KIND_MINT, encode_mint_payload(mint)),
        AnchorKind::Transfer(transfer) => {
            (KIND_TRANSFER, encode_transfer_payload(transfer))
        }
        AnchorKind::SupplyCommit(supply) => {
            (KIND_SUPPLY_COMMIT, encode_supply_commit_payload(supply))
        }
    };
    StoredPendingAnchor {
        txid: anchor.txid,
        kind,
        payload,
    }
}

/// Deserializes a store row back into a pending anchor. Mint anchors
/// reload their batch from `batch_store` by batch key and overlay the
/// transient fields persisted in the payload.
pub(crate) fn decode_pending_anchor(
    stored: &StoredPendingAnchor,
    batch_store: &dyn BatchStore,
) -> Result<PendingAnchor, String> {
    let kind = match stored.kind {
        KIND_MINT => {
            AnchorKind::Mint(decode_mint_payload(&stored.payload, batch_store)?)
        }
        KIND_TRANSFER => {
            AnchorKind::Transfer(decode_transfer_payload(&stored.payload)?)
        }
        KIND_SUPPLY_COMMIT => AnchorKind::SupplyCommit(
            decode_supply_commit_payload(&stored.payload)?,
        ),
        other => {
            return Err(format!("unknown pending anchor kind: {}", other))
        }
    };
    Ok(PendingAnchor {
        txid: stored.txid,
        kind,
    })
}

// ---------------------------------------------------------------------------
// Mint payload
// ---------------------------------------------------------------------------

fn encode_mint_payload(mint: &MintAnchor) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MINT_PAYLOAD_VERSION);

    buf.extend_from_slice(&mint.batch.batch_key.pub_key.0);
    buf.extend_from_slice(&mint.internal_key.0);

    // The Taproot Asset commitment version, so the tree-retaining
    // commitment can be rebuilt from the sprouted assets.
    write_opt(&mut buf, mint.batch.root_asset_commitment.as_ref(), |b, c| {
        b.push(c.commitment().version as u8)
    });

    // The sprouted assets (transient: not persisted by batch stores).
    write_u32(&mut buf, mint.batch.sprouted_assets.len() as u32);
    for asset in &mint.batch.sprouted_assets {
        write_var_bytes(&mut buf, &encode_asset(asset, EncodeType::Normal));
    }

    // Seedling meta reveals, keyed by tag (transient in SQLite batch
    // stores; needed for the genesis proofs' meta reveal records).
    let metas: Vec<(&String, &MetaReveal)> = mint
        .batch
        .seedlings
        .iter()
        .filter_map(|(tag, s)| s.meta.as_ref().map(|m| (tag, m)))
        .collect();
    write_u32(&mut buf, metas.len() as u32);
    for (tag, meta) in metas {
        write_var_bytes(&mut buf, tag.as_bytes());
        write_var_bytes(&mut buf, &meta.encode());
    }

    // Version 2: group key reveals per tag (for the genesis proofs of
    // grouped assets) and the optional universe-commitments delegation
    // key.
    write_u32(&mut buf, mint.group_reveals.len() as u32);
    for (tag, reveal) in &mint.group_reveals {
        write_var_bytes(&mut buf, tag.as_bytes());
        write_var_bytes(
            &mut buf,
            &proof::encode::encode_group_key_reveal(reveal),
        );
    }
    write_opt(&mut buf, mint.delegation_key.as_ref(), |b, k| {
        b.extend_from_slice(&k.0)
    });

    buf
}

fn decode_mint_payload(
    payload: &[u8],
    batch_store: &dyn BatchStore,
) -> Result<MintAnchor, String> {
    let mut r = Reader::new(payload);
    let version = r.u8()?;
    if version != 1 && version != MINT_PAYLOAD_VERSION {
        return Err(format!(
            "unsupported pending mint anchor payload version: {}",
            version
        ));
    }

    let batch_key = SerializedKey(r.array33()?);
    let internal_key = SerializedKey(r.array33()?);

    let commitment_version = r
        .opt(|r| r.u8())?
        .map(|v| {
            TapCommitmentVersion::from_u8(v).map_err(|e| {
                format!("pending mint anchor commitment version: {}", e)
            })
        })
        .transpose()?;

    let asset_count = r.u32()?;
    let mut sprouted_assets = Vec::with_capacity(asset_count as usize);
    for _ in 0..asset_count {
        let bytes = r.var_bytes()?;
        let asset = decode_asset(bytes).map_err(|e| {
            format!("pending mint anchor sprouted asset: {}", e)
        })?;
        sprouted_assets.push(asset);
    }

    let meta_count = r.u32()?;
    let mut metas = Vec::with_capacity(meta_count as usize);
    for _ in 0..meta_count {
        let tag = String::from_utf8(r.var_bytes()?.to_vec())
            .map_err(|e| format!("pending mint anchor meta tag: {}", e))?;
        let meta = MetaReveal::decode(r.var_bytes()?).map_err(|e| {
            format!("pending mint anchor meta reveal: {}", e)
        })?;
        metas.push((tag, meta));
    }

    // Version 2: group key reveals and the delegation key. Version-1
    // rows predate supply commitments and default to none.
    let mut group_reveals = Vec::new();
    let mut delegation_key = None;
    if version >= 2 {
        let reveal_count = r.u32()?;
        for _ in 0..reveal_count {
            let tag = String::from_utf8(r.var_bytes()?.to_vec()).map_err(
                |e| format!("pending mint anchor group reveal tag: {}", e),
            )?;
            let reveal =
                proof::decode::decode_group_key_reveal(r.var_bytes()?)
                    .map_err(|e| {
                        format!(
                            "pending mint anchor group key reveal: {}",
                            e
                        )
                    })?;
            group_reveals.push((tag, reveal));
        }
        delegation_key = r.opt(|r| r.array33().map(SerializedKey))?;
    }
    r.finish()?;

    // Reload the persisted batch (state, seedlings, genesis outpoint,
    // mint output index, signed tx, ...) and overlay the transient
    // fields the batch store does not keep.
    let mut batch = batch_store
        .load_batch(&batch_key)
        .map_err(|e| format!("loading batch for pending mint anchor: {}", e))?
        .ok_or_else(|| {
            "pending mint anchor references a batch missing from the batch \
             store"
                .to_string()
        })?;

    // Rebuild the tree-retaining root commitment from the sprouted
    // assets, exactly as the planter's sprout step built it (one asset
    // commitment per asset, combined at the persisted version).
    batch.root_asset_commitment = match commitment_version {
        Some(version) => {
            let mut asset_commitments =
                Vec::with_capacity(sprouted_assets.len());
            for asset in &sprouted_assets {
                let ac = AssetCommitmentTree::new(&[asset]).map_err(|e| {
                    format!(
                        "rebuilding mint asset commitment: {}",
                        e
                    )
                })?;
                asset_commitments.push(ac);
            }
            Some(
                TapCommitmentTree::new(version, asset_commitments).map_err(
                    |e| format!("rebuilding mint tap commitment: {}", e),
                )?,
            )
        }
        None => None,
    };
    batch.sprouted_assets = sprouted_assets;
    for (tag, meta) in metas {
        if let Some(seedling) = batch.seedlings.get_mut(&tag) {
            seedling.meta = Some(meta);
        }
    }

    Ok(MintAnchor {
        batch,
        internal_key,
        group_reveals,
        delegation_key,
    })
}

// ---------------------------------------------------------------------------
// Supply commitment payload
// ---------------------------------------------------------------------------

fn encode_supply_commit_payload(supply: &SupplyCommitAnchor) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(PAYLOAD_VERSION);

    buf.extend_from_slice(&supply.group_key.0);

    let commitment = &supply.commitment;
    write_var_bytes(
        &mut buf,
        &bitcoin::consensus::encode::serialize(&commitment.txn),
    );
    write_u32(&mut buf, commitment.tx_out_idx);
    buf.extend_from_slice(&commitment.internal_key.0);
    write_opt(&mut buf, commitment.output_key.as_ref(), |b, k| {
        b.extend_from_slice(k)
    });
    buf.extend_from_slice(&commitment.supply_root_hash.0);
    write_u64(&mut buf, commitment.supply_root_sum);
    write_opt(&mut buf, commitment.spent_commitment.as_ref(), |b, op| {
        write_outpoint(b, op)
    });

    // The staged events frozen into this commitment, with their
    // sub-tree type discriminator and Go per-type encoding.
    write_u32(&mut buf, supply.events.len() as u32);
    for event in &supply.events {
        buf.push(sub_tree_type_byte(event.sub_tree_type()));
        write_var_bytes(&mut buf, &event.encode());
    }

    buf
}

fn decode_supply_commit_payload(
    payload: &[u8],
) -> Result<SupplyCommitAnchor, String> {
    let mut r = Reader::new(payload);
    r.expect_version("supply commit")?;

    let group_key = SerializedKey(r.array33()?);

    let raw_tx = r.var_bytes()?;
    let txn: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(raw_tx).map_err(|e| {
            format!("pending supply commit anchor tx: {}", e)
        })?;
    let tx_out_idx = r.u32()?;
    let internal_key = SerializedKey(r.array33()?);
    let output_key = r.opt(|r| r.array32())?;
    let supply_root_hash = NodeHash(r.array32()?);
    let supply_root_sum = r.u64()?;
    let spent_commitment = r.opt(|r| r.outpoint())?;

    let event_count = r.u32()?;
    let mut events = Vec::with_capacity(event_count as usize);
    for _ in 0..event_count {
        let tree_type = sub_tree_type_from_byte(r.u8()?)?;
        let event = SupplyUpdateEvent::decode(tree_type, r.var_bytes()?)
            .map_err(|e| {
                format!("pending supply commit anchor event: {}", e)
            })?;
        events.push(event);
    }
    r.finish()?;

    Ok(SupplyCommitAnchor {
        group_key,
        commitment: RootCommitment {
            txn,
            tx_out_idx,
            internal_key,
            output_key,
            supply_root_hash,
            supply_root_sum,
            commitment_block: None,
            spent_commitment,
        },
        events,
    })
}

fn sub_tree_type_byte(tree_type: SupplySubTree) -> u8 {
    match tree_type {
        SupplySubTree::Mint => 0,
        SupplySubTree::Burn => 1,
        SupplySubTree::Ignore => 2,
    }
}

fn sub_tree_type_from_byte(byte: u8) -> Result<SupplySubTree, String> {
    match byte {
        0 => Ok(SupplySubTree::Mint),
        1 => Ok(SupplySubTree::Burn),
        2 => Ok(SupplySubTree::Ignore),
        other => Err(format!("unknown supply sub-tree type: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// Transfer payload
// ---------------------------------------------------------------------------

fn encode_transfer_payload(transfer: &TransferAnchor) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(PAYLOAD_VERSION);

    buf.extend_from_slice(&transfer.asset_id.0);
    write_u64(&mut buf, transfer.amount);
    buf.extend_from_slice(&transfer.recipient_script_key.0);
    write_outpoint(&mut buf, &transfer.recipient_outpoint);
    write_var_bytes(
        &mut buf,
        &proof::encode::encode_proof(&transfer.recipient_suffix),
    );

    write_opt(&mut buf, transfer.change_script_key.as_ref(), |b, k| {
        b.extend_from_slice(&k.0)
    });
    write_opt(&mut buf, transfer.change_outpoint.as_ref(), |b, op| {
        write_outpoint(b, op)
    });
    write_opt(&mut buf, transfer.change_suffix.as_ref(), |b, p| {
        write_var_bytes(b, &proof::encode::encode_proof(p))
    });
    write_opt(&mut buf, transfer.base_file.as_ref(), |b, f| {
        write_var_bytes(b, &f.encode())
    });
    write_opt(&mut buf, transfer.courier_url.as_ref(), |b, u| {
        write_var_bytes(b, u.as_bytes())
    });

    write_u32(&mut buf, transfer.passive.len() as u32);
    for passive in &transfer.passive {
        write_outpoint(&mut buf, &passive.outpoint);
        buf.extend_from_slice(&passive.script_key.0);
        write_var_bytes(
            &mut buf,
            &proof::encode::encode_proof(&passive.suffix),
        );
        write_opt(&mut buf, passive.base_file.as_ref(), |b, f| {
            write_var_bytes(b, &f.encode())
        });
    }

    buf
}

fn decode_transfer_payload(
    payload: &[u8],
) -> Result<TransferAnchor, String> {
    let mut r = Reader::new(payload);
    r.expect_version("transfer")?;

    let asset_id = AssetId(r.array32()?);
    let amount = r.u64()?;
    let recipient_script_key = SerializedKey(r.array33()?);
    let recipient_outpoint = r.outpoint()?;
    let recipient_suffix = decode_proof_field(&mut r, "recipient suffix")?;

    let change_script_key =
        r.opt(|r| r.array33().map(SerializedKey))?;
    let change_outpoint = r.opt(|r| r.outpoint())?;
    let change_suffix = r
        .opt(|r| decode_proof_field(r, "change suffix"))?;
    let base_file = r.opt(|r| decode_file_field(r, "base proof file"))?;
    let courier_url = r
        .opt(|r| {
            String::from_utf8(r.var_bytes()?.to_vec()).map_err(|e| {
                format!("pending transfer anchor courier url: {}", e)
            })
        })?;

    let passive_count = r.u32()?;
    let mut passive = Vec::with_capacity(passive_count as usize);
    for _ in 0..passive_count {
        let outpoint = r.outpoint()?;
        let script_key = SerializedKey(r.array33()?);
        let suffix = decode_proof_field(&mut r, "passive suffix")?;
        let base_file =
            r.opt(|r| decode_file_field(r, "passive base proof file"))?;
        passive.push(PassiveAnchor {
            outpoint,
            script_key,
            suffix,
            base_file,
        });
    }
    r.finish()?;

    Ok(TransferAnchor {
        asset_id,
        amount,
        recipient_script_key,
        recipient_outpoint,
        recipient_suffix,
        change_script_key,
        change_outpoint,
        change_suffix,
        base_file,
        courier_url,
        passive,
    })
}

fn decode_proof_field(
    r: &mut Reader,
    what: &str,
) -> Result<proof::Proof, String> {
    let bytes = r.var_bytes()?;
    proof::decode::decode_proof(bytes)
        .map_err(|e| format!("pending anchor {}: {}", what, e))
}

fn decode_file_field(
    r: &mut Reader,
    what: &str,
) -> Result<proof::File, String> {
    let bytes = r.var_bytes()?;
    proof::File::decode(bytes)
        .map_err(|e| format!("pending anchor {}: {}", what, e))
}

// ---------------------------------------------------------------------------
// Primitive writers / reader
// ---------------------------------------------------------------------------

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_var_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn write_outpoint(buf: &mut Vec<u8>, op: &OutPoint) {
    buf.extend_from_slice(&op.txid);
    write_u32(buf, op.vout);
}

/// Writes a `u8` presence flag followed by the encoded value when
/// present.
fn write_opt<T>(
    buf: &mut Vec<u8>,
    value: Option<&T>,
    write: impl FnOnce(&mut Vec<u8>, &T),
) {
    match value {
        Some(v) => {
            buf.push(1);
            write(buf, v);
        }
        None => buf.push(0),
    }
}

/// A bounds-checked cursor over a payload slice.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            "pending anchor payload length overflow".to_string()
        })?;
        if end > self.data.len() {
            return Err("pending anchor payload is truncated".to_string());
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(u32::from_be_bytes(arr))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(arr))
    }

    fn array32(&mut self) -> Result<[u8; 32], String> {
        let bytes = self.take(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    fn array33(&mut self) -> Result<[u8; 33], String> {
        let bytes = self.take(33)?;
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn outpoint(&mut self) -> Result<OutPoint, String> {
        let txid = self.array32()?;
        let vout = self.u32()?;
        Ok(OutPoint { txid, vout })
    }

    /// Reads a `u8` presence flag, then the value when present.
    fn opt<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(read(self)?)),
            other => Err(format!(
                "pending anchor payload has invalid option flag: {}",
                other
            )),
        }
    }

    /// Checks the leading payload format-version byte.
    fn expect_version(&mut self, what: &str) -> Result<(), String> {
        let version = self.u8()?;
        if version != PAYLOAD_VERSION {
            return Err(format!(
                "unsupported pending {} anchor payload version: {}",
                what, version
            ));
        }
        Ok(())
    }

    /// Requires the payload to be fully consumed.
    fn finish(&self) -> Result<(), String> {
        if self.pos != self.data.len() {
            return Err(format!(
                "pending anchor payload has {} trailing bytes",
                self.data.len() - self.pos
            ));
        }
        Ok(())
    }
}
