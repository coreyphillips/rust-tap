// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! PostgreSQL-backed persistence for Taproot Assets.
//!
//! Mirrors the SQLite backend ([`crate::sqlite`]) store for store: a
//! shared [`PostgresDb`] handle plus one `Postgres*` implementation of
//! every store trait, with the same semantics and error strings. The
//! schema is the SQLite schema ported to the Postgres dialect (see the
//! `migrations_pg/` directory; every integer column is `BIGINT`, blobs
//! are `BYTEA`, autoincrement ids are `BIGSERIAL`).
//!
//! # Connection handling
//!
//! Like [`crate::sqlite::SqliteDb`] (which wraps one
//! `Mutex<rusqlite::Connection>`), [`PostgresDb`] wraps a single
//! `Mutex<postgres::Client>` shared by all stores. All store access is
//! serialized through that mutex, so a connection pool (r2d2) would
//! add dependencies without adding concurrency; embedders that need
//! parallel access can open several `PostgresDb` handles.
//!
//! Connections use [`postgres::NoTls`]. Point `url` at a server that
//! accepts unencrypted connections (e.g.
//! `postgres://user:pass@localhost:5432/tapdb`).
//!
//! # Integer columns and u64 values
//!
//! Amounts and MS-SMT sums are `u64` in Rust and `BIGINT` in Postgres:
//! they are written with a two's-complement `as i64` cast and read back
//! with `as u64`, exactly like the SQLite backend uses SQLite's 64-bit
//! INTEGER storage class. Values above `i64::MAX` therefore round-trip
//! unchanged (they merely look negative inside the database).
//!
//! # Testing
//!
//! The integration test `tests/postgres.rs` runs the shared
//! [`crate::testkit`] exercises against this backend when the
//! `TAP_TEST_PG_URL` environment variable holds a connection URL, and
//! skips (with a message on stderr) otherwise. Each run isolates
//! itself in a fresh, uniquely named schema via
//! [`PostgresDb::connect_with_schema`] and drops it afterwards.

mod asset;
mod batch;
mod ignore;
mod mailbox;
mod migrations;
mod mssmt;
mod pending_anchor;
mod proof;
mod supply;
mod universe;

pub use asset::PostgresAssetStore;
pub use batch::PostgresBatchStore;
pub use ignore::PostgresIgnoreStore;
pub use mailbox::PostgresMailboxStore;
pub use mssmt::PostgresTreeStore;
pub use pending_anchor::PostgresPendingAnchorStore;
pub use proof::PostgresProofStore;
pub use supply::{
    PostgresSupplyCommitStore, PostgresSupplyStagingStore,
    PostgresSupplyTreeStore,
};
pub use universe::{PostgresFederationDb, PostgresUniverseBackend};

use std::sync::{Mutex, MutexGuard};

/// Shared PostgreSQL database handle.
///
/// Wraps a `Mutex<postgres::Client>` for thread-safe access, mirroring
/// the SQLite backend's `Mutex<Connection>`. Runs pending migrations on
/// connect.
pub struct PostgresDb {
    client: Mutex<postgres::Client>,
}

impl PostgresDb {
    /// Connects to the database at the given URL (using the server's
    /// default schema / `search_path`) and runs pending migrations.
    pub fn connect(url: &str) -> Result<Self, String> {
        let mut client = postgres::Client::connect(url, postgres::NoTls)
            .map_err(|e| e.to_string())?;
        migrations::run_migrations(&mut client)
            .map_err(|e| e.to_string())?;
        Ok(PostgresDb {
            client: Mutex::new(client),
        })
    }

    /// Connects to the database at the given URL, creates the given
    /// schema if needed, sets it as the connection's `search_path`,
    /// and runs pending migrations inside it.
    ///
    /// This is the isolation mechanism used by the test suite: each
    /// test run picks a unique schema name and drops the whole schema
    /// (`DROP SCHEMA <name> CASCADE`) when it is done. The schema name
    /// must consist of ASCII alphanumerics and underscores only.
    pub fn connect_with_schema(
        url: &str,
        schema: &str,
    ) -> Result<Self, String> {
        if schema.is_empty()
            || !schema
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || schema.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return Err(format!("invalid schema name: {schema:?}"));
        }

        let mut client = postgres::Client::connect(url, postgres::NoTls)
            .map_err(|e| e.to_string())?;
        client
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {schema}; \
                 SET search_path TO {schema};"
            ))
            .map_err(|e| e.to_string())?;
        migrations::run_migrations(&mut client)
            .map_err(|e| e.to_string())?;
        Ok(PostgresDb {
            client: Mutex::new(client),
        })
    }

    /// Locks the shared client, mapping a poisoned lock to an error
    /// string.
    pub(crate) fn lock(
        &self,
    ) -> Result<MutexGuard<'_, postgres::Client>, String> {
        self.client
            .lock()
            .map_err(|_| "poisoned postgres client lock".to_string())
    }

    /// Drops the given schema (and everything in it). Intended for
    /// test cleanup after [`PostgresDb::connect_with_schema`].
    pub fn drop_schema(&self, schema: &str) -> Result<(), String> {
        if schema.is_empty()
            || !schema
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(format!("invalid schema name: {schema:?}"));
        }
        let mut client = self.lock()?;
        client
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .map_err(|e| e.to_string())
    }
}

/// Converts a byte column to a fixed-size array, with a descriptive
/// error naming the column.
pub(crate) fn to_array<const N: usize>(
    bytes: Vec<u8>,
    what: &str,
) -> Result<[u8; N], String> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("invalid {what} length: {len} (expected {N})"))
}
