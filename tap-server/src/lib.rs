// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Universe REST server for Taproot Assets.
//!
//! Serves a universe (proof archive) over tapd's REST gateway paths so
//! that other nodes can sync from it. The scope is REST parity with
//! what our own [`tap_universe::HttpUniverseClient`] consumes, using
//! the Lightning Labs gateway conventions (hex-encoded bytes fields,
//! string-encoded 64-bit integers, `PROOF_TYPE_*` enum strings); see
//! the [`json`] module docs for the exact conventions and the
//! documented divergences from the LL gateway.
//!
//! This enables rust-tap to rust-tap federation over HTTP: a node runs
//! this server over its universe backend, and peers point
//! `HttpUniverseClient` + `SimpleSyncer` at it (`tap_universe::sync_all`).
//!
//! Note on tapd interop: tapd itself federates over gRPC, not REST.
//! With the `grpc` feature (on by default) this crate also serves the
//! `universerpc.Universe` gRPC service (module [`grpc`]) on a separate
//! port, which is the tapd-native federation path: a peer running tapd
//! (or rust-tap's `tap_grpc::GrpcUniverseClient`) can sync from this
//! server over gRPC. REST remains for gateway-style clients (tapd's
//! REST tooling, `HttpUniverseClient`). The gRPC subset served is
//! `AssetRoots`, `QueryAssetRoots`, `AssetLeafKeys`, `AssetLeaves`,
//! `QueryProof`, `InsertProof` and `Info`; all remaining universe RPCs
//! answer `Unimplemented` (see the [`grpc`] module docs for the
//! explicit list and the inclusion-proof interop caveat).
//!
//! Layering:
//!
//! - [`service`]: transport-agnostic [`service::UniverseService`] over
//!   an `Arc<Mutex<dyn UniverseBackend + Send>>`, with full proof
//!   validation on insert.
//! - [`json`]: tapd-gateway-compatible JSON marshaling.
//! - [`rest`]: the axum [`Router`] binding the REST paths to the
//!   service via `spawn_blocking` (the core stays synchronous; tokio
//!   and axum live only in this crate).
//! - [`grpc`] (feature `grpc`): the tonic layer binding the
//!   `universerpc.Universe` service to the same [`UniverseService`];
//!   marshaling only, via `tap_grpc::convert`.
//!
//! The `tap-universe-server` binary (feature `sqlite`) serves a
//! SQLite-backed universe from the command line; with the `grpc`
//! feature, `--grpc-listen <addr>` additionally serves gRPC in the
//! same tokio runtime.

#[cfg(feature = "grpc")]
pub mod grpc;
pub mod json;
pub mod rest;
pub mod service;

use std::net::SocketAddr;

use axum::Router;

pub use rest::router;
pub use service::{
    QueryRootsResult, ServerInfo, SharedBackend, UniverseSelector,
    UniverseService,
};

/// Binds `addr` and serves the universe REST API until the server is
/// shut down (i.e. the future is dropped or the task is aborted).
pub async fn serve(
    addr: SocketAddr,
    service: UniverseService,
) -> std::io::Result<()> {
    let app: Router = router(service);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}
