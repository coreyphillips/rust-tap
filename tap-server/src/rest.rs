// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Axum router exposing the tapd universe REST API.
//!
//! Routes (paths follow `taprpc/universerpc/universe.yaml`):
//!
//! - `GET  /v1/taproot-assets/universe/roots` (offset/limit query)
//! - `GET  /v1/taproot-assets/universe/roots/asset-id/{id}`
//! - `GET  /v1/taproot-assets/universe/roots/group-key/{id}`
//! - `GET  /v1/taproot-assets/universe/keys/asset-id/{id}` and
//!   `.../keys/group-key/{id}` (`id.proof_type`, offset/limit query)
//! - `GET  /v1/taproot-assets/universe/leaves/asset-id/{id}` and
//!   `.../leaves/group-key/{id}`
//! - `GET/POST /v1/taproot-assets/universe/proofs/asset-id/{id}/{txid}/{vout}/{script_key}`
//!   (GET queries, POST inserts; txid in display order, proof type via
//!   the `id.proof_type` query parameter). The GET is tapd's native
//!   `QueryProof` binding and the PRIMARY proof query route; it is
//!   what `HttpUniverseClient` uses first.
//! - `GET  /v1/taproot-assets/universe/proofs/group-key/{key}/{txid}/{vout}/{script_key}`
//!   (the group-key `QueryProof` binding from `universe.yaml`)
//! - `POST /v1/taproot-assets/universe/proofs/query/{id}/{proof_type}`
//!   (LEGACY, rust-tap only: tapd does not serve this route. Kept so
//!   older `HttpUniverseClient` builds that only knew the POST query
//!   route keep working; leaf key in the body, txid in display order)
//! - `GET  /v1/taproot-assets/universe/info`
//!
//! Handlers run the synchronous [`UniverseService`] methods on the
//! blocking thread pool via `tokio::task::spawn_blocking`, keeping the
//! sync core free of async.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_universe::types::{ProofType, UniverseError};

use crate::json;
use crate::service::{UniverseSelector, UniverseService};

/// Default page size for list endpoints, matching Go's
/// `universe.RequestPageSize`.
const DEFAULT_PAGE_SIZE: u32 = 512;

/// Builds the REST router for a universe service.
pub fn router(service: UniverseService) -> Router {
    Router::new()
        .route("/v1/taproot-assets/universe/roots", get(get_roots))
        .route(
            "/v1/taproot-assets/universe/roots/asset-id/:id",
            get(get_asset_roots),
        )
        .route(
            "/v1/taproot-assets/universe/roots/group-key/:id",
            get(get_group_roots),
        )
        .route(
            "/v1/taproot-assets/universe/keys/asset-id/:id",
            get(get_asset_keys),
        )
        .route(
            "/v1/taproot-assets/universe/keys/group-key/:id",
            get(get_group_keys),
        )
        .route(
            "/v1/taproot-assets/universe/leaves/asset-id/:id",
            get(get_asset_leaves),
        )
        .route(
            "/v1/taproot-assets/universe/leaves/group-key/:id",
            get(get_group_leaves),
        )
        .route(
            "/v1/taproot-assets/universe/proofs/asset-id/:id/:txid/:vout/:script_key",
            get(get_proof).post(post_proof),
        )
        .route(
            "/v1/taproot-assets/universe/proofs/group-key/:id/:txid/:vout/:script_key",
            get(get_group_proof),
        )
        .route(
            "/v1/taproot-assets/universe/proofs/query/:id/:proof_type",
            axum::routing::post(post_query_proof),
        )
        .route("/v1/taproot-assets/universe/info", get(get_info))
        .with_state(service)
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

/// A REST error: status code plus a grpc-gateway style JSON body.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<UniverseError> for ApiError {
    fn from(e: UniverseError) -> Self {
        let status = match &e {
            UniverseError::NotFound(_) => StatusCode::NOT_FOUND,
            UniverseError::ProofInvalid(_) | UniverseError::SyncError(_) => {
                StatusCode::BAD_REQUEST
            }
            UniverseError::TreeError(_) | UniverseError::StoreError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        ApiError {
            status,
            message: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body =
            json::error_json(self.status.as_u16(), &self.message);
        (self.status, Json(body)).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Runs a synchronous service call on the blocking thread pool.
async fn run_blocking<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, UniverseError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::internal(format!("task join: {}", e)))?
        .map_err(ApiError::from)
}

// ---------------------------------------------------------------------------
// Parameter parsing
// ---------------------------------------------------------------------------

fn parse_asset_id(hex: &str) -> Result<AssetId, ApiError> {
    json::decode_bytes_array::<32>(hex)
        .map(AssetId)
        .map_err(|e| ApiError::bad_request(format!("bad asset id: {}", e)))
}

fn parse_group_key(hex: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = json::decode_bytes_field(hex, None)
        .map_err(|e| ApiError::bad_request(format!("bad group key: {}", e)))?;
    if bytes.len() != 32 && bytes.len() != 33 {
        return Err(ApiError::bad_request(format!(
            "group key must be 32 or 33 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parses a display-order txid path segment into internal byte order.
fn parse_txid_display(hex: &str) -> Result<[u8; 32], ApiError> {
    let mut txid = json::decode_bytes_array::<32>(hex)
        .map_err(|e| ApiError::bad_request(format!("bad txid: {}", e)))?;
    txid.reverse();
    Ok(txid)
}

fn parse_script_key(hex: &str) -> Result<SerializedKey, ApiError> {
    json::decode_bytes_array::<33>(hex)
        .map(SerializedKey)
        .map_err(|e| {
            ApiError::bad_request(format!("bad script key: {}", e))
        })
}

/// Extracts `offset`/`limit` pagination query params.
fn pagination(
    params: &HashMap<String, String>,
) -> Result<(u32, u32), ApiError> {
    let parse = |name: &str, default: u32| -> Result<u32, ApiError> {
        match params.get(name) {
            Some(s) => s.parse::<u32>().map_err(|e| {
                ApiError::bad_request(format!("bad {}: {}", name, e))
            }),
            None => Ok(default),
        }
    };
    let offset = parse("offset", 0)?;
    let mut limit = parse("limit", DEFAULT_PAGE_SIZE)?;
    if limit == 0 {
        limit = DEFAULT_PAGE_SIZE;
    }
    Ok((offset, limit))
}

/// Extracts the universe proof type from the `id.proof_type` (or
/// `proof_type`) query param; defaults to issuance.
fn proof_type_param(
    params: &HashMap<String, String>,
) -> Result<ProofType, ApiError> {
    let value = params
        .get("id.proof_type")
        .or_else(|| params.get("proof_type"));
    match value {
        Some(s) => json::parse_proof_type(s).ok_or_else(|| {
            ApiError::bad_request(format!(
                "unsupported proof type {:?}",
                s
            ))
        }),
        None => Ok(ProofType::Issuance),
    }
}

fn proof_type_path(s: &str) -> Result<ProofType, ApiError> {
    json::parse_proof_type(s).ok_or_else(|| {
        ApiError::bad_request(format!("unsupported proof type {:?}", s))
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /v1/taproot-assets/universe/roots
async fn get_roots(
    State(service): State<UniverseService>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let (offset, limit) = pagination(&params)?;
    let (roots, has_more) =
        run_blocking(move || service.roots(offset, limit)).await?;
    Ok(Json(json::roots_response_json(&roots, has_more)))
}

async fn query_roots_response(
    service: UniverseService,
    selector: UniverseSelector,
) -> ApiResult {
    let result =
        run_blocking(move || service.query_roots(&selector)).await?;
    Ok(Json(json::query_root_response_json(
        result.issuance.as_ref(),
        result.transfer.as_ref(),
    )))
}

/// GET /v1/taproot-assets/universe/roots/asset-id/{id}
async fn get_asset_roots(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
) -> ApiResult {
    let selector = UniverseSelector::Asset(parse_asset_id(&id)?);
    query_roots_response(service, selector).await
}

/// GET /v1/taproot-assets/universe/roots/group-key/{id}
async fn get_group_roots(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
) -> ApiResult {
    let selector = UniverseSelector::Group(parse_group_key(&id)?);
    query_roots_response(service, selector).await
}

async fn leaf_keys_response(
    service: UniverseService,
    selector: UniverseSelector,
    params: HashMap<String, String>,
) -> ApiResult {
    let proof_type = proof_type_param(&params)?;
    let (offset, limit) = pagination(&params)?;
    let (keys, has_more) = run_blocking(move || {
        service.leaf_keys(&selector, proof_type, offset, limit)
    })
    .await?;
    Ok(Json(json::leaf_keys_response_json(&keys, has_more)))
}

/// GET /v1/taproot-assets/universe/keys/asset-id/{id}
async fn get_asset_keys(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Asset(parse_asset_id(&id)?);
    leaf_keys_response(service, selector, params).await
}

/// GET /v1/taproot-assets/universe/keys/group-key/{id}
async fn get_group_keys(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Group(parse_group_key(&id)?);
    leaf_keys_response(service, selector, params).await
}

async fn leaves_response(
    service: UniverseService,
    selector: UniverseSelector,
    params: HashMap<String, String>,
) -> ApiResult {
    let proof_type = proof_type_param(&params)?;
    let leaves =
        run_blocking(move || service.leaves(&selector, proof_type))
            .await?;
    Ok(Json(json::leaves_response_json(&leaves, false)))
}

/// GET /v1/taproot-assets/universe/leaves/asset-id/{id}
async fn get_asset_leaves(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Asset(parse_asset_id(&id)?);
    leaves_response(service, selector, params).await
}

/// GET /v1/taproot-assets/universe/leaves/group-key/{id}
async fn get_group_leaves(
    State(service): State<UniverseService>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Group(parse_group_key(&id)?);
    leaves_response(service, selector, params).await
}

/// Shared proof query for the tapd-native `QueryProof` GET bindings:
/// parses the leaf key path segments (txid in display order), runs the
/// query for the selected universe, and marshals the response.
async fn query_proof_response(
    service: UniverseService,
    selector: UniverseSelector,
    txid: String,
    vout: u32,
    script_key: String,
    params: HashMap<String, String>,
) -> ApiResult {
    let proof_type = proof_type_param(&params)?;
    let key = tap_universe::types::LeafKey {
        outpoint: OutPoint {
            txid: parse_txid_display(&txid)?,
            vout,
        },
        script_key: parse_script_key(&script_key)?,
    };

    let found = run_blocking(move || {
        service.query_proof(&selector, proof_type, &key)
    })
    .await?;

    match found {
        Some((root, proof)) => Ok(Json(json::asset_proof_response_json(
            root.as_ref(),
            &proof,
        ))),
        None => Err(ApiError::from(UniverseError::NotFound(
            "no universe proof found".into(),
        ))),
    }
}

/// GET /v1/taproot-assets/universe/proofs/asset-id/{id}/{txid}/{vout}/{script_key}
///
/// tapd's native `QueryProof` binding and the primary proof query
/// route. The txid path segment is in display order, matching tapd;
/// the proof type travels as the `id.proof_type` query parameter.
async fn get_proof(
    State(service): State<UniverseService>,
    Path((id, txid, vout, script_key)): Path<(String, String, u32, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Asset(parse_asset_id(&id)?);
    query_proof_response(service, selector, txid, vout, script_key, params)
        .await
}

/// GET /v1/taproot-assets/universe/proofs/group-key/{key}/{txid}/{vout}/{script_key}
///
/// The group-key variant of tapd's `QueryProof` binding.
async fn get_group_proof(
    State(service): State<UniverseService>,
    Path((id, txid, vout, script_key)): Path<(String, String, u32, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult {
    let selector = UniverseSelector::Group(parse_group_key(&id)?);
    query_proof_response(service, selector, txid, vout, script_key, params)
        .await
}

/// POST /v1/taproot-assets/universe/proofs/asset-id/{id}/{txid}/{vout}/{script_key}
///
/// Inserts a proof. The body carries the raw proof
/// (`{"asset_leaf": {"proof": <hex>}}`); the txid path segment is in
/// display order. The proof is fully validated before insertion.
async fn post_proof(
    State(service): State<UniverseService>,
    Path((id, txid, vout, script_key)): Path<(String, String, u32, String)>,
    Json(body): Json<Value>,
) -> ApiResult {
    let asset_id = parse_asset_id(&id)?;
    let outpoint = OutPoint {
        txid: parse_txid_display(&txid)?,
        vout,
    };
    let script_key = parse_script_key(&script_key)?;
    let raw_proof = json::parse_insert_proof_body(&body)
        .map_err(ApiError::bad_request)?;

    let (root, proof) = run_blocking(move || {
        service.insert_proof(&asset_id, &outpoint, &script_key, &raw_proof)
    })
    .await?;

    Ok(Json(json::asset_proof_response_json(Some(&root), &proof)))
}

/// POST /v1/taproot-assets/universe/proofs/query/{id}/{proof_type}
///
/// LEGACY, rust-tap only: tapd does not serve this route, and current
/// `HttpUniverseClient` builds query proofs through the tapd-native
/// GET binding (see [`get_proof`]), only falling back to this POST
/// when the GET is answered with 404/405. It is kept so older
/// rust-tap clients that only knew the POST query route keep working.
/// The leaf key is carried in the body with the txid in display byte
/// order (see the `json` module docs). For backward compatibility
/// with older rust-tap clients that sent the txid in internal byte
/// order, a failed lookup is retried with the txid reversed.
async fn post_query_proof(
    State(service): State<UniverseService>,
    Path((id, proof_type)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> ApiResult {
    let asset_id = parse_asset_id(&id)?;
    let proof_type = proof_type_path(&proof_type)?;
    let key = json::parse_query_proof_body(&body)
        .map_err(ApiError::bad_request)?;

    let selector = UniverseSelector::Asset(asset_id);
    let found = run_blocking(move || {
        match service.query_proof(&selector, proof_type, &key)? {
            Some(found) => Ok(Some(found)),
            None => {
                // Backward compatibility: older rust-tap clients sent
                // the txid in internal byte order. Retry reversed.
                let mut legacy_key = key.clone();
                legacy_key.outpoint.txid.reverse();
                service.query_proof(&selector, proof_type, &legacy_key)
            }
        }
    })
    .await?;

    match found {
        Some((root, proof)) => Ok(Json(json::asset_proof_response_json(
            root.as_ref(),
            &proof,
        ))),
        None => Err(ApiError::from(UniverseError::NotFound(
            "no universe proof found".into(),
        ))),
    }
}

/// GET /v1/taproot-assets/universe/info
async fn get_info(State(service): State<UniverseService>) -> ApiResult {
    let info = run_blocking(move || service.info()).await?;
    Ok(Json(json::info_response_json(
        info.runtime_id,
        info.num_assets,
    )))
}
