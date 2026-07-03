// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Persistence layer for Taproot Assets.
//!
//! Provides storage backends for:
//! - [`asset_store`]: Tracking owned assets and their proofs
//! - [`batch_store`]: Minting batch state persistence
//! - [`proof_store`]: Proof file storage and retrieval
//! - [`pending_anchor_store`]: Broadcast anchor transactions awaiting
//!   confirmation
//! - [`ignore_store`]: Signed ignore tuples + is_ignored lookups
//! - [`supply_store`]: Universe supply trees and supply commitments
//!
//! # Backends and feature flags
//!
//! Every store trait ships with three interchangeable backends:
//!
//! - **Memory**: always available; the default when no database is
//!   configured. Useful for tests and ephemeral nodes.
//! - **SQLite** (feature `sqlite`, on by default): all stores share
//!   one [`sqlite::SqliteDb`] handle (a `Mutex<rusqlite::Connection>`)
//!   over an embedded database file. Schema managed by the embedded
//!   migrations in `migrations/` (a `schema_version` registry, one
//!   `.sql` file per version).
//! - **PostgreSQL** (feature `postgres`, off by default): all stores
//!   share one [`postgres::PostgresDb`] handle (a
//!   `Mutex<postgres::Client>`, mirroring the SQLite pattern; no
//!   connection pool). Schema managed by `migrations_pg/`, the same
//!   migrations ported to the Postgres dialect with the same version
//!   registry.
//!
//! Both SQL backends implement identical semantics; the shared
//! exercises in [`testkit`] pin them against the Memory reference
//! implementations.
//!
//! # Testing against a live Postgres server
//!
//! `cargo test -p tap-persist --features postgres` runs the Postgres
//! integration suite (`tests/postgres.rs`) when the `TAP_TEST_PG_URL`
//! environment variable holds a connection URL such as
//! `postgres://user:pass@localhost:5432/postgres`, and skips it (with
//! an eprintln notice) otherwise. Each run creates a uniquely named
//! schema via [`postgres::PostgresDb::connect_with_schema`], runs all
//! migrations inside it, exercises every store, and drops the schema
//! (`DROP SCHEMA ... CASCADE`) on success; a schema left behind by a
//! failed run is inert and can be dropped manually.

pub mod asset_store;
pub mod batch_store;
pub mod ignore_store;
pub mod mailbox_store;
pub mod pending_anchor_store;
pub mod proof_store;
pub mod supply_store;

#[cfg(feature = "sqlite")]
mod migrations;
#[cfg(feature = "sqlite")]
pub mod mssmt_store;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sqlite")]
pub mod universe_store;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod universe_common;

// Shared store-trait exercises: compiled for unit tests and whenever
// the `postgres` feature is on (the postgres integration test links
// the library without cfg(test)). Not part of the stable API.
#[cfg(any(test, feature = "postgres"))]
#[doc(hidden)]
pub mod testkit;
