//! Loopback federation integration test: rust-tap to rust-tap sync.
//!
//! Starts the axum universe server on an ephemeral port, populates it
//! with a real verified leaf through the validated insert path, then
//! runs the plain synchronous sync stack (`HttpUniverseClient` +
//! `SimpleSyncer` + `sync_all`) against it from a blocking thread and
//! asserts the local backend receives and persists the leaf with a
//! matching root. This proves end-to-end federation between two
//! rust-tap universes over HTTP.
//!
//! The server is wrapped in a middleware that counts (and fails) any
//! request to the legacy rust-tap-only `POST /proofs/query/...` route,
//! proving the sync is served entirely by the tapd-native GET
//! `QueryProof` binding: rust-to-rust federation must not depend on a
//! route tapd does not serve.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

use tap_server::UniverseService;
use tap_universe::memory::MemoryUniverseBackend;
use tap_universe::traits::UniverseBackend;
use tap_universe::types::SyncType;
use tap_universe::{sync_all, HttpUniverseClient, SimpleSyncer};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_federation_sync() {
    let (id, key, leaf) = common::load_genesis_proof();

    // Server side: an empty universe, populated through the service's
    // validated insert path (decode + full verification).
    let service = UniverseService::from_backend(MemoryUniverseBackend::new());
    {
        let svc = service.clone();
        let (asset_id, outpoint, script_key, proof_bytes) = (
            id.asset_id,
            key.outpoint,
            key.script_key,
            leaf.proof.clone(),
        );
        tokio::task::spawn_blocking(move || {
            svc.insert_proof(&asset_id, &outpoint, &script_key, &proof_bytes)
        })
        .await
        .expect("join insert task")
        .expect("valid genesis proof must be accepted");
    }

    // Serve on an ephemeral loopback port. Any hit on the legacy POST
    // query route is counted and rejected with a 500 (NOT 404/405, so
    // it cannot masquerade as "proof not found" or trigger further
    // fallbacks): the rust-to-rust sync must be served entirely by the
    // tapd-native GET QueryProof route.
    let legacy_post_hits = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let hits = Arc::clone(&legacy_post_hits);
    let app = tap_server::router(service.clone()).layer(
        middleware::from_fn(move |req: Request, next: Next| {
            let hits = Arc::clone(&hits);
            async move {
                if req.method() == Method::POST
                    && req.uri().path().starts_with(
                        "/v1/taproot-assets/universe/proofs/query/",
                    )
                {
                    hits.fetch_add(1, Ordering::SeqCst);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "legacy POST proof query used during \
                         rust-to-rust sync",
                    )
                        .into_response();
                }
                let response: Response = next.run(req).await;
                response
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server run");
    });

    // Client side: the plain synchronous sync stack, on the blocking
    // pool (HttpUniverseClient is ureq/blocking).
    let base_url = format!("http://{}", addr);
    let (sync_id, sync_key) = (id.clone(), key.clone());
    let (first, second, local_root, leaf_persisted) =
        tokio::task::spawn_blocking(move || {
            let remote = HttpUniverseClient::new(&base_url);
            let mut local = MemoryUniverseBackend::new();
            // Proof verification enabled: the leaf must survive the
            // same verification a federation peer would apply.
            let syncer = SimpleSyncer::new();

            let first =
                sync_all(&syncer, &mut local, &remote, SyncType::Full)
                    .expect("first sync_all");
            // Second sync must be a no-op: roots now match.
            let second =
                sync_all(&syncer, &mut local, &remote, SyncType::Full)
                    .expect("second sync_all");

            let local_root =
                local.root_node(&sync_id).expect("local root after sync");
            let leaf_persisted = local
                .fetch_proof(&sync_id, &sync_key)
                .expect("fetch synced proof")
                .is_some();
            (first, second, local_root, leaf_persisted)
        })
        .await
        .expect("join sync task");

    // The first sync pulled exactly our leaf, with no per-universe
    // errors.
    assert!(
        first.errors.is_empty(),
        "sync errors: {:?}",
        first.errors
    );
    assert_eq!(first.diffs.len(), 1);
    assert_eq!(first.diffs[0].universe_id, id);
    assert_eq!(first.diffs[0].new_leaves.len(), 1);
    assert_eq!(first.diffs[0].new_leaves[0].amount, leaf.amount);

    // The leaf is persisted locally.
    assert!(leaf_persisted);

    // The second sync found matching roots and did nothing.
    assert!(second.errors.is_empty());
    assert!(second.diffs.is_empty());

    // Local and server roots match (hash and sum).
    let server_roots = tokio::task::spawn_blocking(move || {
        service.roots(0, 512).expect("server roots")
    })
    .await
    .expect("join roots task")
    .0;
    assert_eq!(server_roots.len(), 1);
    assert_eq!(server_roots[0].root_hash, local_root.root_hash);
    assert_eq!(server_roots[0].root_sum, local_root.root_sum);

    // The legacy POST query route was never needed: the entire sync
    // (including the proof fetch) went through the tapd-native GET
    // QueryProof route.
    assert_eq!(
        legacy_post_hits.load(Ordering::SeqCst),
        0,
        "rust-to-rust sync must not use the legacy POST proof query"
    );

    server.abort();
}

/// Compatibility: against an OLD rust-tap server that lacks the
/// tapd-native GET QueryProof route (simulated by 404-ing GETs on the
/// proofs path), the client transparently falls back to the legacy
/// POST query route and still finds the proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_post_fallback_for_old_servers() {
    let (id, key, leaf) = common::load_genesis_proof();

    let service = UniverseService::from_backend(MemoryUniverseBackend::new());
    {
        let svc = service.clone();
        let (asset_id, outpoint, script_key, proof_bytes) = (
            id.asset_id,
            key.outpoint,
            key.script_key,
            leaf.proof.clone(),
        );
        tokio::task::spawn_blocking(move || {
            svc.insert_proof(&asset_id, &outpoint, &script_key, &proof_bytes)
        })
        .await
        .expect("join insert task")
        .expect("valid genesis proof must be accepted");
    }

    // Simulate a pre-GET-route server: 404 every GET on the proofs
    // path (the POST insert and legacy POST query stay served).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = tap_server::router(service).layer(middleware::from_fn(
        |req: Request, next: Next| async move {
            if req.method() == Method::GET
                && req.uri().path().starts_with(
                    "/v1/taproot-assets/universe/proofs/",
                )
            {
                return StatusCode::NOT_FOUND.into_response();
            }
            next.run(req).await
        },
    ));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server run");
    });

    let base_url = format!("http://{}", addr);
    let (found, missing) = tokio::task::spawn_blocking(move || {
        let client = HttpUniverseClient::new(&base_url);
        let found = client
            .query_proof(
                &id.asset_id,
                id.proof_type,
                &key.outpoint,
                &key.script_key,
            )
            .expect("query with fallback");
        let missing = client
            .query_proof(
                &id.asset_id,
                id.proof_type,
                &tap_primitives::asset::OutPoint {
                    txid: [0u8; 32],
                    vout: 7,
                },
                &key.script_key,
            )
            .expect("missing proof query");
        (found, missing)
    })
    .await
    .expect("join query task");

    assert_eq!(found.expect("proof found via legacy POST"), leaf.proof);
    assert!(missing.is_none(), "absent proof must map to None");

    server.abort();
}
