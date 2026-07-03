//! In-process REST API tests against a MemoryUniverseBackend.
//!
//! Each endpoint must return JSON that `tap_universe::HttpUniverseClient`
//! can parse: hex-encoded bytes fields, string int64 sums, RPC proof
//! type enum strings, `universe_roots` maps and `has_more` pagination.

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::util::ServiceExt;

use tap_universe::memory::MemoryUniverseBackend;
use tap_universe::traits::UniverseBackend;
use tap_universe::types::{LeafKey, UniverseId, UniverseLeaf};

use tap_server::{router, UniverseService};

use common::hex;

/// Builds an app over a backend pre-populated with the vendored
/// genesis leaf.
fn app_with_genesis_leaf() -> (Router, UniverseId, LeafKey, UniverseLeaf) {
    let (id, key, leaf) = common::load_genesis_proof();
    let mut backend = MemoryUniverseBackend::new();
    backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();
    let service = UniverseService::from_backend(backend);
    (router(service), id, key, leaf)
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn post(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Display-order txid hex for a leaf key (as used in REST paths and
/// served asset keys).
fn display_txid_hex(key: &LeafKey) -> String {
    let mut txid = key.outpoint.txid;
    txid.reverse();
    hex(&txid)
}

#[tokio::test]
async fn roots_endpoint_shape() {
    let (app, id, _, leaf) = app_with_genesis_leaf();

    let (status, body) =
        get(&app, "/v1/taproot-assets/universe/roots?offset=0&limit=512")
            .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body.get("has_more"), Some(&json!(false)));
    let roots = body
        .get("universe_roots")
        .and_then(|v| v.as_object())
        .expect("universe_roots map");
    assert_eq!(roots.len(), 1);

    let (_, root) = roots.iter().next().unwrap();
    assert_eq!(
        root.pointer("/id/asset_id_str").and_then(|v| v.as_str()),
        Some(hex(id.asset_id.as_bytes()).as_str())
    );
    assert_eq!(
        root.pointer("/id/proof_type").and_then(|v| v.as_str()),
        Some("PROOF_TYPE_ISSUANCE")
    );
    let hash = root
        .pointer("/mssmt_root/root_hash")
        .and_then(|v| v.as_str())
        .expect("root_hash");
    assert_eq!(hash.len(), 64, "root_hash must be 32 hex-encoded bytes");
    assert_eq!(
        root.pointer("/mssmt_root/root_sum").and_then(|v| v.as_str()),
        Some(leaf.amount.to_string().as_str()),
        "root_sum must be a string int64"
    );
}

#[tokio::test]
async fn roots_pagination_has_more() {
    let (app, _, _, _) = app_with_genesis_leaf();

    // limit smaller than total: page is full, has_more set.
    let (status, body) =
        get(&app, "/v1/taproot-assets/universe/roots?offset=0&limit=1")
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.get("has_more"), Some(&json!(false)));

    // Offset past the end: empty page.
    let (status, body) =
        get(&app, "/v1/taproot-assets/universe/roots?offset=5&limit=1")
            .await;
    assert_eq!(status, StatusCode::OK);
    let roots = body
        .get("universe_roots")
        .and_then(|v| v.as_object())
        .expect("universe_roots map");
    assert!(roots.is_empty());
}

#[tokio::test]
async fn query_asset_roots_endpoint() {
    let (app, id, _, _) = app_with_genesis_leaf();

    let uri = format!(
        "/v1/taproot-assets/universe/roots/asset-id/{}",
        hex(id.asset_id.as_bytes())
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);

    // Issuance root present, transfer root marshaled empty.
    assert!(body
        .pointer("/issuance_root/mssmt_root/root_hash")
        .is_some());
    assert!(body
        .pointer("/transfer_root/mssmt_root")
        .is_none());

    // Unknown asset: both roots empty (client maps this to NotFound).
    let uri = format!(
        "/v1/taproot-assets/universe/roots/asset-id/{}",
        "77".repeat(32)
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.pointer("/issuance_root/mssmt_root").is_none());

    // Malformed asset ID is a client error.
    let (status, _) = get(
        &app,
        "/v1/taproot-assets/universe/roots/asset-id/nothex",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn leaf_keys_endpoint() {
    let (app, id, key, _) = app_with_genesis_leaf();

    let uri = format!(
        "/v1/taproot-assets/universe/keys/asset-id/{}?id.proof_type=PROOF_TYPE_ISSUANCE&offset=0&limit=512",
        hex(id.asset_id.as_bytes())
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let keys = body
        .get("asset_keys")
        .and_then(|v| v.as_array())
        .expect("asset_keys");
    assert_eq!(keys.len(), 1);
    // Txid is served in display order.
    assert_eq!(
        keys[0].pointer("/op/hash_str").and_then(|v| v.as_str()),
        Some(display_txid_hex(&key).as_str())
    );
    assert_eq!(
        keys[0].pointer("/op/index").and_then(|v| v.as_u64()),
        Some(key.outpoint.vout as u64)
    );
    assert_eq!(
        keys[0].pointer("/script_key_str").and_then(|v| v.as_str()),
        Some(hex(key.script_key.as_bytes()).as_str())
    );

    // Transfer universe is empty for this asset.
    let uri = format!(
        "/v1/taproot-assets/universe/keys/asset-id/{}?id.proof_type=PROOF_TYPE_TRANSFER",
        hex(id.asset_id.as_bytes())
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("asset_keys").and_then(|v| v.as_array()).map(Vec::len),
        Some(0)
    );
}

#[tokio::test]
async fn leaves_endpoint() {
    let (app, id, _, leaf) = app_with_genesis_leaf();

    let uri = format!(
        "/v1/taproot-assets/universe/leaves/asset-id/{}",
        hex(id.asset_id.as_bytes())
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);

    let leaves = body
        .get("leaves")
        .and_then(|v| v.as_array())
        .expect("leaves");
    assert_eq!(leaves.len(), 1);
    assert_eq!(
        leaves[0].pointer("/proof").and_then(|v| v.as_str()),
        Some(hex(&leaf.proof).as_str())
    );
    assert_eq!(
        leaves[0]
            .pointer("/asset/amount")
            .and_then(|v| v.as_str()),
        Some(leaf.amount.to_string().as_str())
    );
}

#[tokio::test]
async fn query_proof_post_endpoint() {
    let (app, id, key, leaf) = app_with_genesis_leaf();

    // The exact body HttpUniverseClient::query_proof_leaf sends:
    // display-order txid hex in leaf_key.op.hash_str, matching tapd.
    let body = json!({
        "id": {
            "asset_id_str": hex(id.asset_id.as_bytes()),
            "proof_type": "PROOF_TYPE_ISSUANCE"
        },
        "leaf_key": {
            "op": {
                "hash_str": display_txid_hex(&key),
                "index": key.outpoint.vout
            },
            "script_key_str": hex(key.script_key.as_bytes())
        }
    });
    let uri = format!(
        "/v1/taproot-assets/universe/proofs/query/{}/PROOF_TYPE_ISSUANCE",
        hex(id.asset_id.as_bytes())
    );
    let (status, response) = post(&app, &uri, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response
            .pointer("/asset_leaf/proof")
            .and_then(|v| v.as_str()),
        Some(hex(&leaf.proof).as_str())
    );
    assert_eq!(
        response
            .pointer("/asset_leaf/asset/amount")
            .and_then(|v| v.as_str()),
        Some(leaf.amount.to_string().as_str())
    );

    // Backward compatibility: older rust-tap clients sent the txid in
    // internal byte order; the server retries the reversed txid.
    let legacy_body = json!({
        "leaf_key": {
            "op": {
                "hash_str": hex(&key.outpoint.txid),
                "index": key.outpoint.vout
            },
            "script_key_str": hex(key.script_key.as_bytes())
        }
    });
    let (status, response) = post(&app, &uri, &legacy_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response
            .pointer("/asset_leaf/proof")
            .and_then(|v| v.as_str()),
        Some(hex(&leaf.proof).as_str())
    );

    // Unknown leaf key: 404 so the client maps it to None.
    let missing = json!({
        "leaf_key": {
            "op": { "hash_str": "00".repeat(32), "index": 0 },
            "script_key_str": "02".repeat(33)
        }
    });
    let (status, _) = post(&app, &uri, &missing).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_proof_by_path_endpoint() {
    let (app, id, key, leaf) = app_with_genesis_leaf();

    let uri = format!(
        "/v1/taproot-assets/universe/proofs/asset-id/{}/{}/{}/{}",
        hex(id.asset_id.as_bytes()),
        display_txid_hex(&key),
        key.outpoint.vout,
        hex(key.script_key.as_bytes()),
    );
    let (status, body) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.pointer("/asset_leaf/proof").and_then(|v| v.as_str()),
        Some(hex(&leaf.proof).as_str())
    );

    // Missing proof: 404.
    let uri = format!(
        "/v1/taproot-assets/universe/proofs/asset-id/{}/{}/{}/{}",
        hex(id.asset_id.as_bytes()),
        "00".repeat(32),
        7,
        hex(key.script_key.as_bytes()),
    );
    let (status, _) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn insert_proof_accepts_valid_and_rejects_invalid() {
    // Start with an EMPTY universe; insert through the REST API only.
    let service = UniverseService::from_backend(MemoryUniverseBackend::new());
    let app = router(service);

    let (id, key, leaf) = common::load_genesis_proof();
    let uri = format!(
        "/v1/taproot-assets/universe/proofs/asset-id/{}/{}/{}/{}",
        hex(id.asset_id.as_bytes()),
        display_txid_hex(&key),
        key.outpoint.vout,
        hex(key.script_key.as_bytes()),
    );

    // Garbage proof bytes are rejected with a 400.
    let bad = json!({"asset_leaf": {"proof": "deadbeef"}});
    let (status, _) = post(&app, &uri, &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Missing proof field is rejected.
    let (status, _) = post(&app, &uri, &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A real, fully verifiable proof under a mismatched key (wrong
    // vout) is rejected.
    let wrong_uri = format!(
        "/v1/taproot-assets/universe/proofs/asset-id/{}/{}/{}/{}",
        hex(id.asset_id.as_bytes()),
        display_txid_hex(&key),
        key.outpoint.vout + 1,
        hex(key.script_key.as_bytes()),
    );
    let good_body = json!({"asset_leaf": {"proof": hex(&leaf.proof)}});
    let (status, _) = post(&app, &wrong_uri, &good_body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The real proof under the right key is accepted.
    let (status, response) = post(&app, &uri, &good_body).await;
    assert_eq!(status, StatusCode::OK, "insert failed: {}", response);
    assert_eq!(
        response
            .pointer("/universe_root/mssmt_root/root_sum")
            .and_then(|v| v.as_str()),
        Some(leaf.amount.to_string().as_str())
    );

    // The inserted proof is now discoverable through the roots list.
    let (status, body) =
        get(&app, "/v1/taproot-assets/universe/roots").await;
    assert_eq!(status, StatusCode::OK);
    let roots = body
        .get("universe_roots")
        .and_then(|v| v.as_object())
        .expect("universe_roots");
    assert_eq!(roots.len(), 1);
}

#[tokio::test]
async fn info_endpoint() {
    let (app, _, _, _) = app_with_genesis_leaf();

    let (status, body) =
        get(&app, "/v1/taproot-assets/universe/info").await;
    assert_eq!(status, StatusCode::OK);

    let runtime_id = body
        .get("runtime_id")
        .and_then(|v| v.as_str())
        .expect("runtime_id string");
    assert!(runtime_id.parse::<i64>().is_ok());
    assert_eq!(
        body.get("num_assets").and_then(|v| v.as_str()),
        Some("1")
    );
}
