// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! HTTP client for `tapd` universe REST API.
//!
//! Implements proof insertion and querying against a remote `tapd` universe
//! server, enabling asset registration and discovery. Also implements
//! [`DiffEngine`] so a remote `tapd` universe can be used directly with
//! the [`crate::syncer::SimpleSyncer`].
//!
//! REST paths follow `taprpc/universerpc/universe.yaml` in the Go
//! implementation; in particular proof queries use tapd's native
//! `QueryProof` GET binding (with a one-shot fallback to the legacy
//! rust-tap-only POST query route for older `tap-server` builds, see
//! [`HttpUniverseClient::query_proof`]). The Lightning Labs REST
//! gateway encodes `bytes` fields non-standardly as hex in some
//! responses while standard protojson uses base64; response parsing
//! accepts both.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;

use crate::traits::DiffEngine;
use crate::types::{
    LeafKey, LeafKeysQuery, ProofType, RootNodesQuery, UniverseError,
    UniverseId, UniverseLeaf, UniverseProof, UniverseRoot,
};

/// Page size used when transparently paginating list endpoints,
/// matching Go's `universe.RequestPageSize`.
const PAGE_SIZE: u32 = 512;

/// HTTP client for a `tapd` universe server.
///
/// Communicates with the REST API at `/v1/taproot-assets/universe/`.
pub struct HttpUniverseClient {
    base_url: String,
}

impl HttpUniverseClient {
    /// Creates a new client for the given universe server URL.
    ///
    /// The URL should be the base REST API endpoint, e.g.
    /// `https://testnet.universe.lightning.finance`.
    pub fn new(url: &str) -> Self {
        HttpUniverseClient {
            base_url: url.trim_end_matches('/').to_string(),
        }
    }

    /// Registers a proof with the universe server.
    ///
    /// This inserts a proof leaf into the universe's MS-SMT, making the
    /// asset discoverable by other nodes and explorers (including
    /// Terminal at `terminal.lightning.engineering`).
    pub fn insert_proof(
        &self,
        asset_id: &AssetId,
        _proof_type: ProofType,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
        raw_proof_bytes: &[u8],
    ) -> Result<(), UniverseError> {
        let asset_id_hex = hex_encode(asset_id.as_bytes());

        // Outpoint txid must be in display order (reversed from internal).
        let mut txid_display = outpoint.txid;
        txid_display.reverse();
        let txid_hex = hex_encode(&txid_display);

        let script_key_hex = hex_encode(script_key.as_bytes());

        // Lightning Labs' REST gateway uses hex encoding for bytes fields
        // (non-standard; standard protojson uses base64).
        let proof_hex = hex_encode(raw_proof_bytes);

        let body = serde_json::json!({
            "asset_leaf": {
                "proof": proof_hex
            }
        });

        // Path: /v1/taproot-assets/universe/proofs/asset-id/{asset_id}/{txid}/{vout}/{script_key}
        let url = format!(
            "{}/v1/taproot-assets/universe/proofs/asset-id/{}/{}/{}/{}",
            self.base_url,
            asset_id_hex,
            txid_hex,
            outpoint.vout,
            script_key_hex,
        );

        match ureq::post(&url).send_json(&body) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, response)) => {
                let body = response
                    .into_string()
                    .unwrap_or_else(|_| "unknown".into());
                Err(UniverseError::SyncError(format!(
                    "insert_proof HTTP {}: {}",
                    code,
                    body.trim()
                )))
            }
            Err(e) => Err(UniverseError::SyncError(format!(
                "insert_proof failed: {}",
                e
            ))),
        }
    }

    /// Queries a proof from the universe server.
    ///
    /// Returns the raw proof bytes if found, or `None` if the proof
    /// doesn't exist on this server.
    pub fn query_proof(
        &self,
        asset_id: &AssetId,
        proof_type: ProofType,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
    ) -> Result<Option<Vec<u8>>, UniverseError> {
        let id = UniverseId {
            asset_id: *asset_id,
            group_key: None,
            proof_type,
        };
        Ok(self
            .query_proof_leaf(&id, outpoint, script_key)?
            .map(|parsed| parsed.proof))
    }

    /// Queries a proof leaf (proof bytes plus universe metadata) from
    /// the server. Returns `None` if the proof doesn't exist.
    ///
    /// The primary route is tapd's native `QueryProof` GET binding
    /// (`taprpc/universerpc/universe.yaml`):
    ///
    /// `GET /v1/taproot-assets/universe/proofs/asset-id/{id}/{txid}/{vout}/{script_key}`
    ///
    /// (or `.../proofs/group-key/{key}/...` for group-key universes),
    /// where the txid path segment is in display order (tapd parses it
    /// with `chainhash.NewHashFromStr`, same as the insert path) and
    /// the proof type travels as the `id.proof_type` query parameter.
    ///
    /// Compatibility: older rust-tap `tap-server` builds only exposed
    /// a nonstandard `POST /proofs/query/{id}/{proof_type}` route,
    /// which tapd does not serve. Because those servers answer the GET
    /// with 404 (route unknown), a 404/405 GET response falls back to
    /// one legacy POST attempt (asset-id universes only; the legacy
    /// route never supported group keys). Against tapd (and current
    /// rust-tap servers) a 404 means the proof does not exist, so the
    /// fallback simply 404s again and `None` is returned.
    fn query_proof_leaf(
        &self,
        id: &UniverseId,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
    ) -> Result<Option<ParsedProofLeaf>, UniverseError> {
        let proof_type_str = proof_type_rpc_str(id.proof_type)?;

        let mut txid_display = outpoint.txid;
        txid_display.reverse();
        let txid_hex = hex_encode(&txid_display);
        let script_key_hex = hex_encode(script_key.as_bytes());

        let url = format!(
            "{}/v1/taproot-assets/universe/proofs/{}/{}/{}/{}?id.proof_type={}",
            self.base_url,
            Self::universe_id_path(id),
            txid_hex,
            outpoint.vout,
            script_key_hex,
            proof_type_str,
        );

        let response = match ureq::get(&url).call() {
            Ok(response) => response,
            // 404: the proof does not exist, or (older rust-tap
            // servers) the GET route itself is absent. 405: the route
            // exists but rejects GET. Fall back to the legacy POST
            // query route once.
            Err(ureq::Error::Status(404 | 405, _)) => {
                return self.query_proof_leaf_legacy(
                    id,
                    outpoint,
                    script_key,
                    proof_type_str,
                );
            }
            // tapd reports a missing proof as a plain error
            // (`universe.ErrNoUniverseProofFound`, gRPC code Unknown),
            // which its REST gateway surfaces as a 500 whose message
            // contains "no universe proof found". Map that miss to
            // None instead of a sync error.
            Err(ureq::Error::Status(500, response)) => {
                let body =
                    response.into_string().unwrap_or_default();
                if body.contains("no universe proof found") {
                    return Ok(None);
                }
                return Err(UniverseError::SyncError(format!(
                    "query_proof HTTP 500: {}",
                    body.trim()
                )));
            }
            Err(e) => {
                return Err(UniverseError::SyncError(format!(
                    "query_proof HTTP error: {}",
                    e
                )))
            }
        };

        let json: serde_json::Value = response.into_json().map_err(|e| {
            UniverseError::SyncError(format!("parse response: {}", e))
        })?;

        parse_asset_proof_response(&json).map(Some)
    }

    /// Legacy proof query fallback for older rust-tap `tap-server`
    /// builds: `POST /v1/taproot-assets/universe/proofs/query/{id}/{proof_type}`
    /// with the leaf key in the body (txid in display order). This
    /// route is NOT part of tapd's REST gateway; it is only attempted
    /// after the tapd-native GET failed with 404/405 (see
    /// [`Self::query_proof_leaf`]). Group-key universes never had a
    /// legacy route, so they resolve to `None` directly.
    fn query_proof_leaf_legacy(
        &self,
        id: &UniverseId,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
        proof_type_str: &str,
    ) -> Result<Option<ParsedProofLeaf>, UniverseError> {
        if id.group_key.is_some() {
            return Ok(None);
        }
        let asset_id_hex = hex_encode(id.asset_id.as_bytes());

        let mut txid_display = outpoint.txid;
        txid_display.reverse();
        let txid_hex = hex_encode(&txid_display);
        let script_key_hex = hex_encode(script_key.as_bytes());

        let body = serde_json::json!({
            "id": {
                "asset_id_str": asset_id_hex,
                "proof_type": proof_type_str
            },
            "leaf_key": {
                "op": {
                    "hash_str": txid_hex,
                    "index": outpoint.vout
                },
                "script_key_str": script_key_hex
            }
        });

        let url = format!(
            "{}/v1/taproot-assets/universe/proofs/query/{}/{}",
            self.base_url, asset_id_hex, proof_type_str
        );

        let response = match ureq::post(&url).send_json(&body) {
            // Both "proof not found" and "route not found" (tapd, or a
            // rust-tap server new enough to have dropped the legacy
            // route) map to None: the primary GET already said 404.
            Err(ureq::Error::Status(404 | 405, _)) => return Ok(None),
            Err(e) => {
                return Err(UniverseError::SyncError(format!(
                    "query_proof legacy HTTP error: {}",
                    e
                )))
            }
            Ok(response) => response,
        };

        let json: serde_json::Value = response.into_json().map_err(|e| {
            UniverseError::SyncError(format!("parse response: {}", e))
        })?;

        parse_asset_proof_response(&json).map(Some)
    }

    /// Performs a GET request and parses the response as JSON.
    fn get_json(
        &self,
        path_and_query: &str,
        what: &str,
    ) -> Result<serde_json::Value, UniverseError> {
        let url = format!("{}{}", self.base_url, path_and_query);

        let response = ureq::get(&url).call().map_err(|e| {
            UniverseError::SyncError(format!("{}: {}", what, e))
        })?;

        response.into_json().map_err(|e| {
            UniverseError::SyncError(format!("parse {}: {}", what, e))
        })
    }

    /// Lists all universe roots on the server.
    pub fn list_roots(
        &self,
    ) -> Result<Vec<UniverseRootInfo>, UniverseError> {
        let json =
            self.get_json("/v1/taproot-assets/universe/roots", "list_roots")?;

        let roots = json
            .get("universe_roots")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(key, _val)| UniverseRootInfo {
                        asset_id_hex: key.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(roots)
    }

    /// Returns the path segment identifying a universe: either
    /// `asset-id/{hex}` or `group-key/{hex}`.
    fn universe_id_path(id: &UniverseId) -> String {
        match &id.group_key {
            Some(gk) => {
                // The REST API expects the 32-byte x-only key.
                format!("group-key/{}", hex_encode(&gk.as_bytes()[1..]))
            }
            None => {
                format!("asset-id/{}", hex_encode(id.asset_id.as_bytes()))
            }
        }
    }
}

impl DiffEngine for HttpUniverseClient {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        // GET /v1/taproot-assets/universe/roots/asset-id/{asset_id_hex}
        // returns a QueryRootResponse with both the issuance and the
        // transfer root; select by the requested proof type.
        let path = format!(
            "/v1/taproot-assets/universe/roots/{}",
            Self::universe_id_path(id)
        );
        let json = self.get_json(&path, "root_node")?;
        parse_query_root_response(&json, id)
    }

    fn root_nodes(
        &self,
        query: &RootNodesQuery,
    ) -> Result<Vec<UniverseRoot>, UniverseError> {
        // GET /v1/taproot-assets/universe/roots (paginated). When the
        // caller specifies an explicit page, issue a single request;
        // otherwise transparently walk all pages.
        let mut offset = query.offset.unwrap_or(0);
        let single_page = query.limit.is_some();
        let limit = query.limit.unwrap_or(PAGE_SIZE);

        let mut all_roots = Vec::new();
        loop {
            let path = format!(
                "/v1/taproot-assets/universe/roots?offset={}&limit={}",
                offset, limit
            );
            let json = self.get_json(&path, "root_nodes")?;
            let (roots, has_more) = parse_asset_roots_response(&json)?;
            let page_len = roots.len() as u32;
            all_roots.extend(roots);

            if single_page || !has_more || page_len == 0 {
                break;
            }
            offset += page_len;
        }

        Ok(all_roots)
    }

    fn universe_leaf_keys(
        &self,
        id: &UniverseId,
        query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        // GET /v1/taproot-assets/universe/keys/asset-id/{asset_id_hex}
        let proof_type_str = proof_type_rpc_str(id.proof_type)?;
        let mut offset = query.offset.unwrap_or(0);
        let single_page = query.limit.is_some();
        let limit = query.limit.unwrap_or(PAGE_SIZE);

        let mut all_keys = Vec::new();
        loop {
            let path = format!(
                "/v1/taproot-assets/universe/keys/{}?id.proof_type={}&offset={}&limit={}",
                Self::universe_id_path(id),
                proof_type_str,
                offset,
                limit
            );
            let json = self.get_json(&path, "universe_leaf_keys")?;
            let keys = parse_leaf_keys_response(&json)?;
            let page_len = keys.len() as u32;
            all_keys.extend(keys);

            if single_page || page_len < limit || page_len == 0 {
                break;
            }
            offset += page_len;
        }

        Ok(all_keys)
    }

    fn fetch_proof_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError> {
        let parsed = match self.query_proof_leaf(
            id,
            &key.outpoint,
            &key.script_key,
        )? {
            Some(parsed) => parsed,
            None => return Ok(None),
        };

        // Prefer the amount reported by the server; fall back to
        // decoding the proof itself.
        let amount = match parsed.amount {
            Some(amount) => amount,
            None => tap_primitives::proof::decode_proof(&parsed.proof)
                .map_err(|e| {
                    UniverseError::ProofInvalid(format!(
                        "fetched proof does not decode: {}",
                        e
                    ))
                })?
                .asset
                .amount,
        };

        Ok(Some(UniverseProof {
            leaf: UniverseLeaf {
                asset_id: id.asset_id,
                amount,
                proof: parsed.proof,
                key: key.clone(),
            },
            inclusion_proof: parsed.inclusion_proof,
        }))
    }
}

/// Basic info about a universe root (for listing).
#[derive(Clone, Debug)]
pub struct UniverseRootInfo {
    /// The asset ID in hex.
    pub asset_id_hex: String,
}

// ---------------------------------------------------------------------------
// Response parsing (pure functions, unit-testable without a network)
// ---------------------------------------------------------------------------

/// A proof leaf parsed from an `AssetProofResponse`.
#[derive(Clone, Debug)]
struct ParsedProofLeaf {
    /// The raw (single) mint/transfer proof.
    proof: Vec<u8>,
    /// The asset amount as reported by the server, if present.
    amount: Option<u64>,
    /// The MS-SMT universe inclusion proof, if present.
    inclusion_proof: Vec<u8>,
}

fn sync_err(msg: impl Into<String>) -> UniverseError {
    UniverseError::SyncError(msg.into())
}

/// Maps a [`ProofType`] to its RPC enum string.
fn proof_type_rpc_str(
    proof_type: ProofType,
) -> Result<&'static str, UniverseError> {
    match proof_type {
        ProofType::Issuance => Ok("PROOF_TYPE_ISSUANCE"),
        ProofType::Transfer => Ok("PROOF_TYPE_TRANSFER"),
        // The universe RPC only serves issuance/transfer trees;
        // supply-commitment trees (ignore/burn/mint_supply) are
        // synced via supply commitments instead.
        ProofType::Ignore | ProofType::Burn | ProofType::MintSupply => {
            Err(sync_err(format!(
                "proof type {} not supported over universe RPC",
                proof_type.as_str()
            )))
        }
    }
}

/// Parses an RPC proof type value (enum string or number) into a
/// [`ProofType`]. Returns `None` for unspecified/unknown types.
fn parse_rpc_proof_type(v: &serde_json::Value) -> Option<ProofType> {
    match v {
        serde_json::Value::String(s) => match s.as_str() {
            "PROOF_TYPE_ISSUANCE" => Some(ProofType::Issuance),
            "PROOF_TYPE_TRANSFER" => Some(ProofType::Transfer),
            _ => None,
        },
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(1) => Some(ProofType::Issuance),
            Some(2) => Some(ProofType::Transfer),
            _ => None,
        },
        _ => None,
    }
}

/// Decodes a JSON bytes field that may be hex (Lightning Labs gateway)
/// or base64 (standard protojson). When `expected_len` is given, a
/// candidate decoding is only accepted if its length matches, which
/// disambiguates strings that are valid in both encodings.
fn decode_bytes_field(
    s: &str,
    expected_len: Option<usize>,
) -> Result<Vec<u8>, UniverseError> {
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

    Err(sync_err(format!(
        "bytes field {:?} is neither valid hex nor base64{}",
        s,
        expected_len
            .map(|l| format!(" of {} bytes", l))
            .unwrap_or_default()
    )))
}

/// Parses a JSON value holding a protojson 64-bit integer, which may be
/// a string ("1000") or a plain number.
fn parse_u64_flex(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => {
            n.as_u64().or_else(|| n.as_i64().map(|i| i.max(0) as u64))
        }
        serde_json::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

/// Parses a `MerkleSumNode` (`{root_hash, root_sum}`).
fn parse_merkle_sum_node(
    v: &serde_json::Value,
) -> Result<(NodeHash, u64), UniverseError> {
    let hash_val = v
        .get("root_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| sync_err("mssmt_root missing root_hash"))?;
    let hash_bytes = decode_bytes_field(hash_val, Some(32))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_bytes);

    let sum = v
        .get("root_sum")
        .and_then(parse_u64_flex)
        .ok_or_else(|| sync_err("mssmt_root missing root_sum"))?;

    Ok((NodeHash(hash), sum))
}

/// Parses an RPC `ID` message into a [`UniverseId`].
fn parse_universe_id(
    v: &serde_json::Value,
) -> Result<UniverseId, UniverseError> {
    let proof_type = v
        .get("proof_type")
        .and_then(parse_rpc_proof_type)
        .ok_or_else(|| sync_err("universe id has unknown proof_type"))?;

    // Group key: either raw bytes (32-byte x-only or 33-byte
    // compressed) or a hex string.
    let group_key_val = v
        .get("group_key_str")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            v.get("group_key")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        });

    let group_key = match group_key_val {
        Some(s) => {
            let bytes = decode_bytes_field(&s, None)?;
            Some(normalize_group_key(&bytes)?)
        }
        None => None,
    };

    let asset_id_val = v
        .get("asset_id_str")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            v.get("asset_id")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        });

    let asset_id = match asset_id_val {
        Some(s) => {
            let bytes = decode_bytes_field(&s, Some(32))?;
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            AssetId(id)
        }
        // Group-key universes may omit the asset ID.
        None if group_key.is_some() => AssetId([0u8; 32]),
        None => {
            return Err(sync_err(
                "universe id missing asset_id and group_key",
            ))
        }
    };

    Ok(UniverseId {
        asset_id,
        group_key,
        proof_type,
    })
}

/// Normalizes a 32-byte x-only or 33-byte compressed group key into a
/// 33-byte [`SerializedKey`] (x-only keys get an even-parity prefix).
fn normalize_group_key(
    bytes: &[u8],
) -> Result<SerializedKey, UniverseError> {
    let mut key = [0u8; 33];
    match bytes.len() {
        33 => key.copy_from_slice(bytes),
        32 => {
            key[0] = 0x02;
            key[1..].copy_from_slice(bytes);
        }
        n => {
            return Err(sync_err(format!(
                "group key has invalid length {}",
                n
            )))
        }
    }
    Ok(SerializedKey(key))
}

/// Parses a `UniverseRoot` message.
fn parse_universe_root(
    v: &serde_json::Value,
) -> Result<UniverseRoot, UniverseError> {
    let id = parse_universe_id(
        v.get("id")
            .ok_or_else(|| sync_err("universe root missing id"))?,
    )?;

    let (root_hash, root_sum) = parse_merkle_sum_node(
        v.get("mssmt_root")
            .ok_or_else(|| sync_err("universe root missing mssmt_root"))?,
    )?;

    Ok(UniverseRoot {
        id,
        root_hash,
        root_sum,
    })
}

/// Parses an `AssetRootResponse` (`{universe_roots: {key: UniverseRoot},
/// has_more}`). Roots with unknown/unspecified proof types are skipped.
/// Returns the parsed roots and the `has_more` flag.
fn parse_asset_roots_response(
    v: &serde_json::Value,
) -> Result<(Vec<UniverseRoot>, bool), UniverseError> {
    let mut roots = Vec::new();

    if let Some(map) = v.get("universe_roots").and_then(|m| m.as_object()) {
        for (map_key, root_val) in map {
            match parse_universe_root(root_val) {
                Ok(root) => roots.push(root),
                // Skip roots we cannot represent (e.g. unspecified
                // proof type), but fail loudly on malformed entries.
                Err(_)
                    if root_val
                        .pointer("/id/proof_type")
                        .and_then(parse_rpc_proof_type)
                        .is_none() => {}
                Err(e) => {
                    return Err(sync_err(format!(
                        "universe_roots[{}]: {}",
                        map_key, e
                    )))
                }
            }
        }
    }

    let has_more = v
        .get("has_more")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    Ok((roots, has_more))
}

/// Parses a `QueryRootResponse` (`{issuance_root, transfer_root}`),
/// selecting the root matching the requested universe's proof type.
fn parse_query_root_response(
    v: &serde_json::Value,
    id: &UniverseId,
) -> Result<UniverseRoot, UniverseError> {
    let field = match id.proof_type {
        ProofType::Issuance => "issuance_root",
        ProofType::Transfer => "transfer_root",
        other => {
            return Err(sync_err(format!(
                "proof type {} not supported over universe RPC",
                other.as_str()
            )))
        }
    };

    let root_val = v.get(field).ok_or_else(|| {
        UniverseError::NotFound(format!("response missing {}", field))
    })?;

    // An absent root is marshaled as an empty message.
    if root_val.get("mssmt_root").is_none() {
        return Err(UniverseError::NotFound(format!(
            "no {} for universe",
            field
        )));
    }

    let (root_hash, root_sum) = parse_merkle_sum_node(
        root_val
            .get("mssmt_root")
            .ok_or_else(|| sync_err("universe root missing mssmt_root"))?,
    )?;

    // Trust the requested id: the response id echoes it (and may omit
    // fields for group-key queries).
    Ok(UniverseRoot {
        id: id.clone(),
        root_hash,
        root_sum,
    })
}

/// Parses an `AssetKey` message into a [`LeafKey`].
fn parse_asset_key(
    v: &serde_json::Value,
) -> Result<LeafKey, UniverseError> {
    // Outpoint: either `op {hash_str, index}` or `op_str "txid:vout"`.
    // The txid string is in display order (reversed).
    let (txid_display_hex, vout) = if let Some(op) = v.get("op") {
        let hash_str = op
            .get("hash_str")
            .and_then(|h| h.as_str())
            .ok_or_else(|| sync_err("asset key op missing hash_str"))?;
        let index = op
            .get("index")
            .and_then(parse_u64_flex)
            .unwrap_or(0) as u32;
        (hash_str.to_string(), index)
    } else if let Some(op_str) = v.get("op_str").and_then(|s| s.as_str()) {
        let (txid, vout) = op_str.split_once(':').ok_or_else(|| {
            sync_err(format!("malformed op_str {:?}", op_str))
        })?;
        let vout = vout.parse::<u32>().map_err(|e| {
            sync_err(format!("malformed op_str vout: {}", e))
        })?;
        (txid.to_string(), vout)
    } else {
        return Err(sync_err("asset key missing outpoint"));
    };

    let txid_bytes = decode_bytes_field(&txid_display_hex, Some(32))?;
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);
    // Display order -> internal order.
    txid.reverse();

    let script_key_val = v
        .get("script_key_str")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            v.get("script_key_bytes")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| sync_err("asset key missing script key"))?;
    let script_key_bytes = decode_bytes_field(&script_key_val, Some(33))?;
    let mut script_key = [0u8; 33];
    script_key.copy_from_slice(&script_key_bytes);

    Ok(LeafKey {
        outpoint: OutPoint { txid, vout },
        script_key: SerializedKey(script_key),
    })
}

/// Parses an `AssetLeafKeyResponse` (`{asset_keys: [AssetKey]}`).
fn parse_leaf_keys_response(
    v: &serde_json::Value,
) -> Result<Vec<LeafKey>, UniverseError> {
    let keys = match v.get("asset_keys").and_then(|k| k.as_array()) {
        Some(keys) => keys,
        None => return Ok(vec![]),
    };

    keys.iter().map(parse_asset_key).collect()
}

/// Parses an `AssetProofResponse` into a [`ParsedProofLeaf`].
fn parse_asset_proof_response(
    v: &serde_json::Value,
) -> Result<ParsedProofLeaf, UniverseError> {
    let proof_val = v
        .pointer("/asset_leaf/proof")
        .and_then(|p| p.as_str())
        .ok_or_else(|| sync_err("response missing asset_leaf.proof"))?;
    let proof = decode_bytes_field(proof_val, None)?;

    let amount = v
        .pointer("/asset_leaf/asset/amount")
        .and_then(parse_u64_flex);

    let inclusion_proof = match v
        .get("universe_inclusion_proof")
        .and_then(|p| p.as_str())
    {
        Some(s) if !s.is_empty() => decode_bytes_field(s, None)?,
        _ => Vec::new(),
    };

    Ok(ParsedProofLeaf {
        proof,
        amount,
        inclusion_proof,
    })
}

// ---------------------------------------------------------------------------
// Hex / base64 helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
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

    // Leftover bits must be zero padding.
    if bits >= 6 || (buf & ((1 << bits) - 1)) != 0 {
        return Err("invalid base64 trailing bits".into());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = hex_encode(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert!(base64_decode("!!!").is_err());
    }

    #[test]
    fn test_decode_bytes_field_prefers_expected_length() {
        // 64 hex chars -> 32 bytes via hex.
        let hex32 = "ab".repeat(32);
        assert_eq!(
            decode_bytes_field(&hex32, Some(32)).unwrap(),
            vec![0xAB; 32]
        );

        // Base64 of 32 bytes of 0xAA (44 chars with padding):
        // 10 full groups "qqqq" + final "qqo=".
        let b64 = format!("{}qqo=", "qqqq".repeat(10));
        let decoded = decode_bytes_field(&b64, Some(32)).unwrap();
        assert_eq!(decoded, vec![0xAA; 32]);

        // Wrong length is rejected.
        assert!(decode_bytes_field("abcd", Some(32)).is_err());
    }

    fn test_universe_id() -> UniverseId {
        UniverseId {
            asset_id: AssetId([0x11; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        }
    }

    /// Canned QueryAssetRoots response (hex-encoded bytes, string sums),
    /// as produced by the Lightning Labs REST gateway.
    #[test]
    fn test_parse_query_root_response() {
        let json: serde_json::Value = serde_json::from_str(&format!(
            r#"{{
                "issuance_root": {{
                    "id": {{
                        "asset_id_str": "{aid}",
                        "proof_type": "PROOF_TYPE_ISSUANCE"
                    }},
                    "mssmt_root": {{
                        "root_hash": "{hash}",
                        "root_sum": "5000"
                    }},
                    "asset_name": "test-coin"
                }},
                "transfer_root": {{
                    "id": {{
                        "asset_id_str": "{aid}",
                        "proof_type": "PROOF_TYPE_TRANSFER"
                    }},
                    "mssmt_root": {{
                        "root_hash": "{hash2}",
                        "root_sum": "123"
                    }}
                }}
            }}"#,
            aid = "11".repeat(32),
            hash = "22".repeat(32),
            hash2 = "33".repeat(32),
        ))
        .unwrap();

        let id = test_universe_id();
        let root = parse_query_root_response(&json, &id).unwrap();
        assert_eq!(root.id, id);
        assert_eq!(root.root_hash, NodeHash([0x22; 32]));
        assert_eq!(root.root_sum, 5000);

        let transfer_id = UniverseId {
            proof_type: ProofType::Transfer,
            ..id
        };
        let root =
            parse_query_root_response(&json, &transfer_id).unwrap();
        assert_eq!(root.root_hash, NodeHash([0x33; 32]));
        assert_eq!(root.root_sum, 123);
    }

    /// A missing/empty root maps to NotFound.
    #[test]
    fn test_parse_query_root_response_missing() {
        let json: serde_json::Value =
            serde_json::from_str(r#"{"issuance_root": {}}"#).unwrap();
        let err = parse_query_root_response(&json, &test_universe_id())
            .unwrap_err();
        assert!(matches!(err, UniverseError::NotFound(_)));
    }

    /// Canned AssetRoots response: map of universe roots with proof
    /// type discrimination and base64-encoded bytes (protojson style).
    #[test]
    fn test_parse_asset_roots_response() {
        // 32 bytes of 0x11 / 0x22 in base64.
        let aid_b64 = "ERERERERERERERERERERERERERERERERERERERERERE=";
        let hash_b64 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

        let json: serde_json::Value = serde_json::from_str(&format!(
            r#"{{
                "universe_roots": {{
                    "issuance-1111": {{
                        "id": {{
                            "asset_id": "{aid}",
                            "proof_type": "PROOF_TYPE_ISSUANCE"
                        }},
                        "mssmt_root": {{
                            "root_hash": "{hash}",
                            "root_sum": "777"
                        }}
                    }},
                    "transfer-1111": {{
                        "id": {{
                            "asset_id_str": "{aid_hex}",
                            "proof_type": 2
                        }},
                        "mssmt_root": {{
                            "root_hash": "{hash_hex}",
                            "root_sum": 42
                        }}
                    }},
                    "unspecified-entry": {{
                        "id": {{
                            "proof_type": "PROOF_TYPE_UNSPECIFIED"
                        }}
                    }}
                }},
                "has_more": true
            }}"#,
            aid = aid_b64,
            hash = hash_b64,
            aid_hex = "11".repeat(32),
            hash_hex = "22".repeat(32),
        ))
        .unwrap();

        let (mut roots, has_more) =
            parse_asset_roots_response(&json).unwrap();
        assert!(has_more);
        assert_eq!(roots.len(), 2);
        roots.sort_by_key(|r| r.root_sum);

        assert_eq!(roots[0].id.proof_type, ProofType::Transfer);
        assert_eq!(roots[0].root_sum, 42);
        assert_eq!(roots[1].id.proof_type, ProofType::Issuance);
        assert_eq!(roots[1].id.asset_id, AssetId([0x11; 32]));
        assert_eq!(roots[1].root_hash, NodeHash([0x22; 32]));
        assert_eq!(roots[1].root_sum, 777);
    }

    /// Group-key universes carry a 32-byte x-only key.
    #[test]
    fn test_parse_universe_id_group_key() {
        let json: serde_json::Value = serde_json::from_str(&format!(
            r#"{{
                "group_key_str": "{gk}",
                "proof_type": "PROOF_TYPE_ISSUANCE"
            }}"#,
            gk = "44".repeat(32),
        ))
        .unwrap();

        let id = parse_universe_id(&json).unwrap();
        let gk = id.group_key.expect("group key");
        assert_eq!(gk.0[0], 0x02);
        assert_eq!(&gk.0[1..], &[0x44; 32]);
    }

    /// Canned AssetLeafKeys response: outpoint txid is display order
    /// and must be reversed into internal order.
    #[test]
    fn test_parse_leaf_keys_response() {
        let mut display_txid = [0u8; 32];
        display_txid[0] = 0xAA; // display order: internal txid ends 0xAA
        let json: serde_json::Value = serde_json::from_str(&format!(
            r#"{{
                "asset_keys": [
                    {{
                        "op": {{
                            "hash_str": "{txid}",
                            "index": 3
                        }},
                        "script_key_str": "{sk}"
                    }},
                    {{
                        "op_str": "{txid}:7",
                        "script_key_bytes": "{sk_b64}"
                    }}
                ]
            }}"#,
            txid = hex_encode(&display_txid),
            sk = hex_encode(&[0x02; 33]),
            // 33 bytes of 0x02: eleven complete "AgIC" groups.
            sk_b64 = "AgIC".repeat(11),
        ))
        .unwrap();

        let keys = parse_leaf_keys_response(&json).unwrap();
        assert_eq!(keys.len(), 2);

        // Reversal: display[0] = 0xAA -> internal[31] = 0xAA.
        assert_eq!(keys[0].outpoint.txid[31], 0xAA);
        assert_eq!(keys[0].outpoint.vout, 3);
        assert_eq!(keys[0].script_key, SerializedKey([0x02; 33]));

        assert_eq!(keys[1].outpoint.txid[31], 0xAA);
        assert_eq!(keys[1].outpoint.vout, 7);
        assert_eq!(keys[1].script_key, SerializedKey([0x02; 33]));
    }

    #[test]
    fn test_parse_leaf_keys_response_empty() {
        let json: serde_json::Value =
            serde_json::from_str("{}").unwrap();
        assert!(parse_leaf_keys_response(&json).unwrap().is_empty());
    }

    /// Canned AssetProofResponse: hex proof, string amount, base64
    /// inclusion proof.
    #[test]
    fn test_parse_asset_proof_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
                "req": {},
                "universe_root": {},
                "universe_inclusion_proof": "3q0=",
                "asset_leaf": {
                    "asset": {
                        "amount": "1500"
                    },
                    "proof": "0badc0de"
                }
            }"#,
        )
        .unwrap();

        let parsed = parse_asset_proof_response(&json).unwrap();
        assert_eq!(parsed.proof, vec![0x0B, 0xAD, 0xC0, 0xDE]);
        assert_eq!(parsed.amount, Some(1500));
        assert_eq!(parsed.inclusion_proof, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_parse_asset_proof_response_missing_proof() {
        let json: serde_json::Value =
            serde_json::from_str(r#"{"asset_leaf": {}}"#).unwrap();
        assert!(parse_asset_proof_response(&json).is_err());
    }
}
