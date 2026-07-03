// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Embedded migration runner for PostgreSQL schema management.
//!
//! The migrations in `migrations_pg/` are the SQLite migrations
//! (`migrations/`) ported to the Postgres dialect, version for
//! version, and use the same `schema_version` registry pattern: each
//! migration file appends its own version row, and the runner applies
//! every migration whose version exceeds `MAX(version)`.

use postgres::Client;

/// Embedded SQL migrations. Each entry is (version, up_sql). Must stay
/// in lockstep with the SQLite migration list in `crate::migrations`.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../../migrations_pg/001_initial.up.sql")),
    (2, include_str!("../../migrations_pg/002_universe.up.sql")),
    (3, include_str!("../../migrations_pg/003_burns.up.sql")),
    (4, include_str!("../../migrations_pg/004_supply.up.sql")),
    (5, include_str!("../../migrations_pg/005_mailbox.up.sql")),
    (6, include_str!("../../migrations_pg/006_asset_keys.up.sql")),
    (7, include_str!("../../migrations_pg/007_genesis_point.up.sql")),
    (8, include_str!("../../migrations_pg/008_multi_asset_anchor.up.sql")),
    (9, include_str!("../../migrations_pg/009_pending_anchors.up.sql")),
    (10, include_str!("../../migrations_pg/010_address_key_descs.up.sql")),
    (11, include_str!("../../migrations_pg/011_supply_staging.up.sql")),
];

/// Runs all pending migrations against the given client.
///
/// Each migration file is executed with `batch_execute` (the simple
/// query protocol), so its statements run in one implicit transaction:
/// a failing migration rolls back as a unit.
pub(crate) fn run_migrations(
    client: &mut Client,
) -> Result<(), postgres::Error> {
    let has_version_table: bool = client
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                 WHERE table_schema = current_schema()
                   AND table_name = 'schema_version'
             )",
            &[],
        )?
        .try_get(0)?;

    let current_version: i64 = if has_version_table {
        client
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                &[],
            )?
            .try_get(0)?
    } else {
        0
    };

    for &(version, up_sql) in MIGRATIONS {
        if i64::from(version) > current_version {
            client.batch_execute(up_sql)?;
        }
    }

    Ok(())
}
