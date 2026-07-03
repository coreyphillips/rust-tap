// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! tapd-gateway-compatible JSON shapes for the universe REST API.
//!
//! The message shapes follow `taprpc/universerpc/universe.swagger.json`
//! from the Go implementation (`AssetRootResponse`, `QueryRootResponse`,
//! `AssetLeafKeyResponse`, `AssetLeafResponse`, `AssetProofResponse`,
//! `InfoResponse`). The compatibility arbiter, however, is
//! `tap_universe::HttpUniverseClient`: every response emitted here must
//! parse successfully with that client.
//!
//! Conventions (and documented divergences from the Lightning Labs
//! gateway):
//!
//! - Bytes fields are hex encoded (matching the LL gateway's
//!   non-standard `*_str` REST convention) rather than base64
//!   (standard protojson). Incoming bytes fields accept both hex and
//!   base64, like `HttpUniverseClient` does.
//! - 64-bit integers (`root_sum`, `amount`, `runtime_id`) are emitted
//!   as decimal strings, matching protojson.
//! - Proof types use the RPC enum strings `PROOF_TYPE_ISSUANCE` and
//!   `PROOF_TYPE_TRANSFER`.
//! - Outpoint txids in `AssetKey.op.hash_str` fields are in display
//!   order (reversed from internal), matching tapd, both when served
//!   and when received in the `POST proofs/query` body
//!   (`leaf_key.op.hash_str`); tapd parses that field with
//!   `chainhash.NewHashFromStr`, which takes display order. For
//!   backward compatibility with older rust-tap clients that sent the
//!   txid in internal byte order, the query handler retries a failed
//!   lookup with the reversed txid (see `rest::post_query_proof`).
//! - `ID.group_key_str` is served as the full 33-byte compressed key
//!   (hex) to preserve parity; tapd serves the 32-byte x-only key.
//!   `HttpUniverseClient` accepts both. Incoming group keys may be
//!   32-byte x-only (normalized with an even-parity prefix) or
//!   33-byte compressed.

use serde_json::{json, Value};

use tap_universe::types::{
    LeafKey, ProofType, UniverseLeaf, UniverseProof, UniverseRoot,
};

// ---------------------------------------------------------------------------
// Byte-string helpers
// ---------------------------------------------------------------------------

/// Hex encodes a byte slice (lowercase).
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("hex decode at {}: {}", i, e))
        })
        .collect()
}

/// Decodes standard or URL-safe base64, with or without padding.
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn value(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' | b'-' => Ok(62),
            b'/' | b'_' => Ok(63),
            _ => Err(format!("invalid base64 character {:?}", c as char)),
        }
    }

    let trimmed = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;

    for &c in trimmed.as_bytes() {
        buf = (buf << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    if bits >= 6 || (buf & ((1 << bits) - 1)) != 0 {
        return Err("invalid base64 trailing bits".into());
    }

    Ok(out)
}

/// Decodes a bytes field that may be hex (LL gateway convention) or
/// base64 (standard protojson). When `expected_len` is given, a
/// candidate decoding is only accepted if its length matches.
pub fn decode_bytes_field(
    s: &str,
    expected_len: Option<usize>,
) -> Result<Vec<u8>, String> {
    let matches = |bytes: &[u8]| match expected_len {
        Some(len) => bytes.len() == len,
        None => true,
    };

    if let Ok(bytes) = hex_decode(s) {
        if matches(&bytes) {
            return Ok(bytes);
        }
    }
    if let Ok(bytes) = base64_decode(s) {
        if matches(&bytes) {
            return Ok(bytes);
        }
    }

    Err(format!(
        "bytes field {:?} is neither valid hex nor base64{}",
        s,
        expected_len
            .map(|l| format!(" of {} bytes", l))
            .unwrap_or_default()
    ))
}

/// Decodes a fixed-length bytes field into an array.
pub fn decode_bytes_array<const N: usize>(
    s: &str,
) -> Result<[u8; N], String> {
    let bytes = decode_bytes_field(s, Some(N))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Proof type mapping
// ---------------------------------------------------------------------------

/// Maps a [`ProofType`] to its RPC enum string, if it is one of the
/// types served over the universe RPC.
pub fn proof_type_rpc_str(proof_type: ProofType) -> Option<&'static str> {
    match proof_type {
        ProofType::Issuance => Some("PROOF_TYPE_ISSUANCE"),
        ProofType::Transfer => Some("PROOF_TYPE_TRANSFER"),
        _ => None,
    }
}

/// Parses an RPC proof type (enum string or numeric value) into a
/// [`ProofType`]. Only issuance/transfer are served over the REST API.
pub fn parse_proof_type(s: &str) -> Option<ProofType> {
    match s {
        "PROOF_TYPE_ISSUANCE" | "1" => Some(ProofType::Issuance),
        "PROOF_TYPE_TRANSFER" | "2" => Some(ProofType::Transfer),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Response marshaling
// ---------------------------------------------------------------------------

/// Marshals an RPC `ID` message from a universe root's identifier.
fn universe_id_json(root: &UniverseRoot) -> Value {
    let mut id = json!({
        "asset_id_str": hex_encode(root.id.asset_id.as_bytes()),
        "proof_type": proof_type_rpc_str(root.id.proof_type)
            .unwrap_or("PROOF_TYPE_UNSPECIFIED"),
    });
    if let Some(gk) = &root.id.group_key {
        if let Some(obj) = id.as_object_mut() {
            // Full 33-byte compressed key (see module docs).
            obj.insert(
                "group_key_str".into(),
                Value::String(hex_encode(gk.as_bytes())),
            );
        }
    }
    id
}

/// Marshals a `UniverseRoot` message.
pub fn universe_root_json(root: &UniverseRoot) -> Value {
    json!({
        "id": universe_id_json(root),
        "mssmt_root": {
            "root_hash": hex_encode(&root.root_hash.0),
            "root_sum": root.root_sum.to_string(),
        },
        "asset_name": "",
    })
}

/// Marshals an `AssetRootResponse`: a map of universe roots keyed by
/// `{proof_type}-{asset_id_or_group_key_hex}` plus a `has_more` flag.
pub fn roots_response_json(
    roots: &[UniverseRoot],
    has_more: bool,
) -> Value {
    let mut map = serde_json::Map::new();
    for root in roots {
        let key_hex = match &root.id.group_key {
            Some(gk) => hex_encode(&gk.as_bytes()[1..]),
            None => hex_encode(root.id.asset_id.as_bytes()),
        };
        let key = format!("{}-{}", root.id.proof_type.as_str(), key_hex);
        map.insert(key, universe_root_json(root));
    }
    json!({
        "universe_roots": Value::Object(map),
        "has_more": has_more,
    })
}

/// Marshals a `QueryRootResponse` with the issuance and transfer roots
/// for one asset/group. Absent roots are marshaled as empty messages,
/// matching the gateway's marshaling of unset protobuf fields.
pub fn query_root_response_json(
    issuance: Option<&UniverseRoot>,
    transfer: Option<&UniverseRoot>,
) -> Value {
    let marshal = |root: Option<&UniverseRoot>| match root {
        Some(root) => universe_root_json(root),
        None => json!({}),
    };
    json!({
        "issuance_root": marshal(issuance),
        "transfer_root": marshal(transfer),
    })
}

/// Marshals an `AssetKey` message. The txid is emitted in display
/// order (reversed from internal), matching tapd.
pub fn asset_key_json(key: &LeafKey) -> Value {
    let mut txid_display = key.outpoint.txid;
    txid_display.reverse();
    json!({
        "op": {
            "hash_str": hex_encode(&txid_display),
            "index": key.outpoint.vout,
        },
        "script_key_str": hex_encode(key.script_key.as_bytes()),
    })
}

/// Marshals an `AssetLeafKeyResponse`.
pub fn leaf_keys_response_json(
    keys: &[LeafKey],
    has_more: bool,
) -> Value {
    json!({
        "asset_keys": keys.iter().map(asset_key_json).collect::<Vec<_>>(),
        "has_more": has_more,
    })
}

/// Marshals a (minimal) `AssetLeaf` message: the raw proof plus the
/// subset of the `taprpc.Asset` fields a universe leaf carries.
fn asset_leaf_json(leaf: &UniverseLeaf) -> Value {
    json!({
        "asset": {
            "amount": leaf.amount.to_string(),
            "asset_genesis": {
                "asset_id": hex_encode(leaf.asset_id.as_bytes()),
            },
            "script_key": hex_encode(leaf.key.script_key.as_bytes()),
        },
        "proof": hex_encode(&leaf.proof),
    })
}

/// Marshals an `AssetLeafResponse`.
pub fn leaves_response_json(
    leaves: &[UniverseLeaf],
    has_more: bool,
) -> Value {
    json!({
        "leaves": leaves.iter().map(asset_leaf_json).collect::<Vec<_>>(),
        "has_more": has_more,
    })
}

/// Marshals an `AssetProofResponse`.
pub fn asset_proof_response_json(
    root: Option<&UniverseRoot>,
    proof: &UniverseProof,
) -> Value {
    json!({
        "req": {},
        "universe_root": match root {
            Some(root) => universe_root_json(root),
            None => json!({}),
        },
        "universe_inclusion_proof": hex_encode(&proof.inclusion_proof),
        "asset_leaf": asset_leaf_json(&proof.leaf),
    })
}

/// Marshals an `InfoResponse`.
pub fn info_response_json(runtime_id: i64, num_assets: u64) -> Value {
    json!({
        "runtime_id": runtime_id.to_string(),
        "num_assets": num_assets.to_string(),
    })
}

/// Marshals a grpc-gateway style error body.
pub fn error_json(code: u16, message: &str) -> Value {
    json!({
        "code": code,
        "message": message,
        "details": [],
    })
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Extracts the raw proof bytes from an insert-proof request body
/// (`{"asset_leaf": {"proof": <hex-or-base64>}}`), the shape sent by
/// `HttpUniverseClient::insert_proof`.
pub fn parse_insert_proof_body(body: &Value) -> Result<Vec<u8>, String> {
    let proof = body
        .pointer("/asset_leaf/proof")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "request missing asset_leaf.proof".to_string())?;
    if proof.is_empty() {
        return Err("asset_leaf.proof is empty".into());
    }
    decode_bytes_field(proof, None)
}

/// Extracts the leaf key from a `POST proofs/query` request body
/// (`UniverseKey`-like: `{"leaf_key": {"op": {"hash_str", "index"},
/// "script_key_str"}}`), the shape sent by
/// `HttpUniverseClient::query_proof_leaf`.
///
/// `op.hash_str` is interpreted in display byte order (reversed into
/// internal order), matching tapd's `chainhash.NewHashFromStr`; see
/// the module docs.
pub fn parse_query_proof_body(body: &Value) -> Result<LeafKey, String> {
    use tap_primitives::asset::{OutPoint, SerializedKey};

    let op = body
        .pointer("/leaf_key/op")
        .ok_or_else(|| "request missing leaf_key.op".to_string())?;

    let hash_str = op
        .get("hash_str")
        .and_then(|h| h.as_str())
        .ok_or_else(|| "request missing leaf_key.op.hash_str".to_string())?;
    let mut txid: [u8; 32] = decode_bytes_array(hash_str)?;
    // Display order -> internal order.
    txid.reverse();

    let vout = match op.get("index") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) as u32,
        Some(Value::String(s)) => s
            .parse::<u32>()
            .map_err(|e| format!("bad leaf_key.op.index: {}", e))?,
        None => 0,
        Some(_) => return Err("bad leaf_key.op.index".into()),
    };

    let script_key_str = body
        .pointer("/leaf_key/script_key_str")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            body.pointer("/leaf_key/script_key_bytes")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| "request missing leaf_key script key".to_string())?;
    let script_key: [u8; 33] = decode_bytes_array(script_key_str)?;

    Ok(LeafKey {
        outpoint: OutPoint { txid, vout },
        script_key: SerializedKey(script_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
    use tap_primitives::mssmt::NodeHash;
    use tap_universe::types::UniverseId;

    fn test_root() -> UniverseRoot {
        UniverseRoot {
            id: UniverseId {
                asset_id: AssetId([0x11; 32]),
                group_key: None,
                proof_type: ProofType::Issuance,
            },
            root_hash: NodeHash([0x22; 32]),
            root_sum: 5000,
        }
    }

    #[test]
    fn test_universe_root_json_shape() {
        let v = universe_root_json(&test_root());
        assert_eq!(
            v.pointer("/id/asset_id_str").and_then(|s| s.as_str()),
            Some("11".repeat(32).as_str())
        );
        assert_eq!(
            v.pointer("/id/proof_type").and_then(|s| s.as_str()),
            Some("PROOF_TYPE_ISSUANCE")
        );
        assert_eq!(
            v.pointer("/mssmt_root/root_sum").and_then(|s| s.as_str()),
            Some("5000")
        );
    }

    #[test]
    fn test_asset_key_json_display_order() {
        let mut txid = [0u8; 32];
        txid[31] = 0xAA; // internal order: last byte 0xAA
        let key = LeafKey {
            outpoint: OutPoint { txid, vout: 3 },
            script_key: SerializedKey([0x02; 33]),
        };
        let v = asset_key_json(&key);
        let hash = v
            .pointer("/op/hash_str")
            .and_then(|s| s.as_str())
            .expect("hash_str");
        // Display order: 0xAA first.
        assert!(hash.starts_with("aa"));
        assert_eq!(v.pointer("/op/index").and_then(|i| i.as_u64()), Some(3));
    }

    #[test]
    fn test_parse_insert_proof_body() {
        let body = json!({"asset_leaf": {"proof": "deadbeef"}});
        assert_eq!(
            parse_insert_proof_body(&body).expect("parse"),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(parse_insert_proof_body(&json!({})).is_err());
        assert!(parse_insert_proof_body(
            &json!({"asset_leaf": {"proof": ""}})
        )
        .is_err());
    }

    #[test]
    fn test_parse_query_proof_body_roundtrip() {
        // The exact body shape HttpUniverseClient::query_proof_leaf
        // sends: display-order txid hex, hex script key.
        let mut display_txid = [0u8; 32];
        display_txid[0] = 0xAA; // display order: internal txid ends 0xAA
        let body = json!({
            "id": {
                "asset_id_str": "11".repeat(32),
                "proof_type": "PROOF_TYPE_ISSUANCE"
            },
            "leaf_key": {
                "op": {
                    "hash_str": hex_encode(&display_txid),
                    "index": 4
                },
                "script_key_str": "02".repeat(33)
            }
        });
        let key = parse_query_proof_body(&body).expect("parse");
        // Display order -> internal order: display[0] = internal[31].
        assert_eq!(key.outpoint.txid[31], 0xAA);
        assert_eq!(key.outpoint.txid[0], 0x00);
        assert_eq!(key.outpoint.vout, 4);
        assert_eq!(key.script_key, SerializedKey([0x02; 33]));
    }

    #[test]
    fn test_proof_type_mapping() {
        assert_eq!(
            proof_type_rpc_str(ProofType::Issuance),
            Some("PROOF_TYPE_ISSUANCE")
        );
        assert_eq!(proof_type_rpc_str(ProofType::Ignore), None);
        assert_eq!(
            parse_proof_type("PROOF_TYPE_TRANSFER"),
            Some(ProofType::Transfer)
        );
        assert_eq!(parse_proof_type("PROOF_TYPE_UNSPECIFIED"), None);
    }
}
