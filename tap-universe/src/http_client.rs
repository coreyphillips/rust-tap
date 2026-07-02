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
//! server, enabling asset registration and discovery.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

use crate::types::{ProofType, UniverseError};

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
        let asset_id_hex = hex_encode(asset_id.as_bytes());
        let proof_type_str = match proof_type {
            ProofType::Issuance => "PROOF_TYPE_ISSUANCE",
            ProofType::Transfer => "PROOF_TYPE_TRANSFER",
            // The universe RPC only serves issuance/transfer trees;
            // supply-commitment trees (ignore/burn/mint_supply) are
            // synced via supply commitments instead.
            ProofType::Ignore | ProofType::Burn | ProofType::MintSupply => {
                return Err(UniverseError::SyncError(format!(
                    "proof type {} not supported over universe RPC",
                    proof_type.as_str()
                )))
            }
        };

        let txid_hex = hex_encode(&outpoint.txid);
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

        let response = ureq::post(&url)
            .send_json(&body)
            .map_err(|e| {
                UniverseError::SyncError(format!(
                    "query_proof HTTP error: {}",
                    e
                ))
            })?;

        if response.status() == 404 {
            return Ok(None);
        }

        let json: serde_json::Value = response
            .into_json()
            .map_err(|e| {
                UniverseError::SyncError(format!("parse response: {}", e))
            })?;

        // Extract the proof bytes from the response.
        let proof_hex = json
            .pointer("/asset_leaf/proof")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                UniverseError::SyncError(
                    "response missing asset_leaf.proof".into(),
                )
            })?;

        let proof_bytes = hex_decode(proof_hex).map_err(|e| {
            UniverseError::SyncError(format!("hex decode: {}", e))
        })?;

        Ok(Some(proof_bytes))
    }

    /// Lists all universe roots on the server.
    pub fn list_roots(
        &self,
    ) -> Result<Vec<UniverseRootInfo>, UniverseError> {
        let url = format!(
            "{}/v1/taproot-assets/universe/roots",
            self.base_url
        );

        let response = ureq::get(&url)
            .call()
            .map_err(|e| {
                UniverseError::SyncError(format!("list_roots: {}", e))
            })?;

        let json: serde_json::Value = response
            .into_json()
            .map_err(|e| {
                UniverseError::SyncError(format!("parse roots: {}", e))
            })?;

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
}

/// Basic info about a universe root (for listing).
#[derive(Clone, Debug)]
pub struct UniverseRootInfo {
    /// The asset ID in hex.
    pub asset_id_hex: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
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
}
