// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Embedded migration runner for SQLite schema management.

use rusqlite::Connection;

/// Embedded SQL migrations. Each entry is (version, up_sql).
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/001_initial.up.sql")),
    (2, include_str!("../migrations/002_universe.up.sql")),
    (3, include_str!("../migrations/003_burns.up.sql")),
    (4, include_str!("../migrations/004_supply.up.sql")),
    (5, include_str!("../migrations/005_mailbox.up.sql")),
    (6, include_str!("../migrations/006_asset_keys.up.sql")),
    (7, include_str!("../migrations/007_genesis_point.up.sql")),
    (8, include_str!("../migrations/008_multi_asset_anchor.up.sql")),
    (9, include_str!("../migrations/009_pending_anchors.up.sql")),
];

/// Runs all pending migrations against the given connection.
///
/// Creates the `schema_version` table if it doesn't exist, then applies
/// each migration whose version is greater than the current version.
/// Each migration runs in its own transaction.
pub fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    // Check if schema_version table exists.
    let has_version_table: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='schema_version'",
        [],
        |row| row.get(0),
    )?;

    let current_version = if has_version_table {
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get::<_, u32>(0),
        )?
    } else {
        0
    };

    for &(version, up_sql) in MIGRATIONS {
        if version > current_version {
            conn.execute_batch(up_sql)?;
        }
    }

    Ok(())
}

/// Returns the current schema version (0 if no migrations applied).
#[cfg(test)]
pub(crate) fn current_version(conn: &Connection) -> Result<u32, rusqlite::Error> {
    let has_table: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='schema_version'",
        [],
        |row| row.get(0),
    )?;

    if !has_table {
        return Ok(0);
    }

    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest_version() -> u32 {
        MIGRATIONS.last().expect("at least one migration").0
    }

    #[test]
    fn test_run_migrations_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), latest_version());
    }

    #[test]
    fn test_run_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        // Running again should not fail.
        run_migrations(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), latest_version());
    }

    #[test]
    fn test_tables_created() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify all tables exist.
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"owned_assets".to_string()));
        assert!(tables.contains(&"minting_batches".to_string()));
        assert!(tables.contains(&"seedlings".to_string()));
        assert!(tables.contains(&"proof_files".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
        assert!(tables.contains(&"universe_roots".to_string()));
        assert!(tables.contains(&"universe_leaves".to_string()));
        assert!(tables.contains(&"universe_servers".to_string()));
        assert!(tables.contains(&"asset_burns".to_string()));
        assert!(tables.contains(&"addresses".to_string()));
        assert!(tables.contains(&"mailbox_cursors".to_string()));
        assert!(tables.contains(&"mssmt_nodes".to_string()));
        assert!(tables.contains(&"mssmt_roots".to_string()));
        assert!(tables.contains(&"universe_supply_roots".to_string()));
        assert!(tables.contains(&"universe_supply_leaves".to_string()));
        assert!(tables.contains(&"supply_commitments".to_string()));
        assert!(tables.contains(&"supply_pre_commits".to_string()));
        assert!(tables.contains(&"ignore_tuples".to_string()));
        assert!(tables.contains(&"pending_anchors".to_string()));
    }

    #[test]
    fn test_constraints_enforced() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        run_migrations(&conn).unwrap();

        // asset_id must be 32 bytes.
        let result = conn.execute(
            "INSERT INTO owned_assets (asset_id, amount, anchor_txid, anchor_vout, script_key, block_height) VALUES (?1, 100, ?2, 0, ?3, 800000)",
            rusqlite::params![&[0u8; 16][..], &[0xAAu8; 32][..], &[0x02u8; 33][..]],
        );
        assert!(result.is_err());

        // UNIQUE on (anchor_txid, anchor_vout, asset_id, script_key):
        // an exact duplicate is rejected ...
        conn.execute(
            "INSERT INTO owned_assets (asset_id, amount, anchor_txid, anchor_vout, script_key, block_height) VALUES (?1, 100, ?2, 0, ?3, 800000)",
            rusqlite::params![&[0xAAu8; 32][..], &[0xBBu8; 32][..], &[0x02u8; 33][..]],
        ).unwrap();
        let dup = conn.execute(
            "INSERT INTO owned_assets (asset_id, amount, anchor_txid, anchor_vout, script_key, block_height) VALUES (?1, 200, ?2, 0, ?3, 800000)",
            rusqlite::params![&[0xAAu8; 32][..], &[0xBBu8; 32][..], &[0x02u8; 33][..]],
        );
        assert!(dup.is_err());

        // ... while a different asset at the same anchor outpoint is
        // allowed (multi-asset anchor outputs, migration 008).
        conn.execute(
            "INSERT INTO owned_assets (asset_id, amount, anchor_txid, anchor_vout, script_key, block_height) VALUES (?1, 200, ?2, 0, ?3, 800000)",
            rusqlite::params![&[0xCCu8; 32][..], &[0xBBu8; 32][..], &[0x02u8; 33][..]],
        ).unwrap();
    }
}
