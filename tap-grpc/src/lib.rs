// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! gRPC transports for Taproot Assets, interoperating with `tapd`'s
//! native gRPC services.
//!
//! Scope: this crate covers the two tapd services rust-tap needs for
//! federation and V2 address sends:
//!
//! - `universerpc.Universe` (client side, [`GrpcUniverseClient`]): the
//!   sync surface tapd's own federation uses - `AssetRoots`,
//!   `QueryAssetRoots`, `AssetLeafKeys`, `QueryProof`, `InsertProof`,
//!   `Info`. The client implements [`tap_universe::DiffEngine`], so it
//!   plugs directly into `tap_universe::SimpleSyncer` / `sync_all`,
//!   plus the insert/query surface `HttpUniverseClient` offers.
//! - `authmailboxrpc.Mailbox` (client side,
//!   [`GrpcMailboxTransport`]): `SendMessage`, `ReceiveMessages` (the
//!   challenge-response subscription stream), `MailboxInfo` and
//!   `RemoveMessage`. The transport implements
//!   [`tap_onchain::proof::mailbox::MailboxTransport`].
//!
//! The gRPC *server* side of `universerpc.Universe` lives in
//! `tap-server` (feature `grpc`), built on the generated service
//! traits re-exported here ([`universerpc`]).
//!
//! # Blocking wrapper design
//!
//! The rust-tap core crates are synchronous by design; tokio is
//! confined to this crate and `tap-server`. Both clients therefore own
//! a small private multi-thread tokio runtime (one worker thread) and
//! `block_on` each RPC, exposing plain blocking methods. This keeps
//! `tap_universe::DiffEngine` and
//! `tap_onchain::proof::mailbox::MailboxTransport` implementable
//! without infecting the sync core with async.
//!
//! Consequence: the blocking clients MUST NOT be called from inside an
//! async context (tokio panics on nested `block_on`); call them from a
//! plain thread or via `tokio::task::spawn_blocking`.
//!
//! # Generated modules
//!
//! The protos are vendored under `proto/` (see `proto/README.md` for
//! the source commit) and compiled at build time:
//!
//! - [`taprpc`]: shared types (`taprootassets.proto`,
//!   `tapcommon.proto` - both share the `taprpc` proto package)
//! - [`universerpc`]: the universe service and messages
//! - [`authmailboxrpc`]: the auth mailbox service and messages
//!
//! # Byte-order conventions
//!
//! All conversions live in [`convert`] and are pinned by unit tests;
//! see that module's docs for the exact rules (outpoint txid byte
//! order per message type, x-only vs compressed keys, proof type
//! enums).

/// Shared taprpc types generated from `taprootassets.proto` and
/// `tapcommon.proto`.
pub mod taprpc {
    #![allow(missing_docs)]
    tonic::include_proto!("taprpc");
}

/// Universe service types generated from `universerpc/universe.proto`.
pub mod universerpc {
    #![allow(missing_docs)]
    tonic::include_proto!("universerpc");
}

/// Auth mailbox service types generated from
/// `authmailboxrpc/mailbox.proto`.
pub mod authmailboxrpc {
    #![allow(missing_docs)]
    tonic::include_proto!("authmailboxrpc");
}

pub mod convert;
pub mod mailbox;
pub mod universe_client;

mod blocking;

pub use mailbox::{sign_remove_challenge, GrpcMailboxTransport};
pub use universe_client::GrpcUniverseClient;

// Re-export the gRPC stack so dependents (tap-server) use the exact
// same tonic/prost versions as the generated code.
pub use prost;
pub use tonic;
