//! gRPC loopback federation integration test: rust-tap to rust-tap
//! sync over tapd's NATIVE federation protocol (universerpc.Universe).
//!
//! Starts the tonic universe server on an ephemeral port, backed by a
//! `MemoryUniverseBackend` populated with a real verified genesis leaf
//! through the validated insert path, then runs the plain synchronous
//! sync stack (`GrpcUniverseClient` + `SimpleSyncer` + `sync_all`,
//! proof verification ON) against it from a blocking thread. Asserts
//! the local backend receives and persists the leaf with a matching
//! root, proving the gRPC path end to end.

mod common;

use tap_grpc::GrpcUniverseClient;
use tap_server::grpc::grpc_router;
use tap_server::UniverseService;
use tap_universe::memory::MemoryUniverseBackend;
use tap_universe::traits::UniverseBackend;
use tap_universe::types::SyncType;
use tap_universe::{sync_all, SimpleSyncer};

use tokio_stream::wrappers::TcpListenerStream;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_loopback_federation_sync() {
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

    // Serve the tonic universe service on an ephemeral loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(
        grpc_router(service.clone())
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    // Client side: the plain synchronous sync stack, on the blocking
    // pool (GrpcUniverseClient is a blocking wrapper and must not run
    // inside the async context).
    let uri = format!("http://{}", addr);
    let (sync_id, sync_key) = (id.clone(), key.clone());
    let (first, second, local_root, leaf_persisted, remote_info) =
        tokio::task::spawn_blocking(move || {
            let remote =
                GrpcUniverseClient::connect(&uri).expect("connect gRPC");
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
            let remote_info = remote.info().expect("info RPC");
            (first, second, local_root, leaf_persisted, remote_info)
        })
        .await
        .expect("join sync task");

    // The first sync pulled exactly our leaf, with no per-universe
    // errors.
    assert!(first.errors.is_empty(), "sync errors: {:?}", first.errors);
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

    // The Info RPC answered with the server's runtime ID.
    assert_ne!(remote_info, 0);

    server.abort();
}

/// The client-facing query surface against a missing leaf/universe:
/// a proof query for an absent leaf resolves to `None`, and a root
/// query for an unknown asset maps to `NotFound` (tapd signals this
/// with an empty root response).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_missing_proof_and_root() {
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
    use tap_universe::traits::DiffEngine;
    use tap_universe::types::{ProofType, UniverseError, UniverseId};

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
        .expect("insert");
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(
        grpc_router(service)
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    let uri = format!("http://{}", addr);
    tokio::task::spawn_blocking(move || {
        let remote = GrpcUniverseClient::connect(&uri).expect("connect");

        // Present proof resolves through the public query surface.
        let found = remote
            .query_proof(
                &id.asset_id,
                id.proof_type,
                &key.outpoint,
                &key.script_key,
            )
            .expect("query present proof");
        assert_eq!(found.expect("proof bytes"), leaf.proof);

        // Absent leaf (wrong outpoint) maps to None, not an error.
        let missing = remote
            .query_proof(
                &id.asset_id,
                id.proof_type,
                &OutPoint {
                    txid: [0u8; 32],
                    vout: 9,
                },
                &SerializedKey([0x02; 33]),
            )
            .expect("query absent proof");
        assert!(missing.is_none());

        // Unknown universe root maps to NotFound.
        let unknown = UniverseId {
            asset_id: AssetId([0x42; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        };
        let err = remote
            .root_node(&unknown)
            .expect_err("unknown root must be NotFound");
        assert!(matches!(err, UniverseError::NotFound(_)), "{:?}", err);
    })
    .await
    .expect("join query task");

    server.abort();
}
