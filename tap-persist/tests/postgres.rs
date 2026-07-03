// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres backend integration test.
//!
//! Requires a live PostgreSQL server: set `TAP_TEST_PG_URL` to a
//! connection URL (e.g. `postgres://user:pass@localhost:5432/postgres`)
//! to run it; without the variable the test skips with a notice on
//! stderr, so the suite stays green on machines without Postgres.
//!
//! Isolation: each run creates a uniquely named schema
//! (`tap_test_<pid>_<nanos>`), runs all migrations inside it, executes
//! every shared testkit exercise against the Postgres stores, and
//! drops the schema (`DROP SCHEMA ... CASCADE`) at the end. A schema
//! left behind by a failed (panicked) run is inert and can be dropped
//! manually.

#![cfg(feature = "postgres")]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tap_persist::postgres::{
    PostgresAssetStore, PostgresBatchStore, PostgresDb, PostgresFederationDb,
    PostgresIgnoreStore, PostgresMailboxStore, PostgresPendingAnchorStore,
    PostgresProofStore, PostgresSupplyCommitStore,
    PostgresSupplyStagingStore, PostgresSupplyTreeStore, PostgresTreeStore,
    PostgresUniverseBackend,
};
use tap_persist::testkit;

/// Reads the Postgres connection URL from the environment, or `None`
/// (skip) when unset or empty.
fn pg_url() -> Option<String> {
    std::env::var("TAP_TEST_PG_URL")
        .ok()
        .filter(|url| !url.is_empty())
}

/// One test running the full shared suite sequentially: the exercises
/// each touch only their own tables, so they share one freshly
/// migrated schema.
#[test]
fn postgres_store_suite() {
    let url = match pg_url() {
        Some(url) => url,
        None => {
            eprintln!(
                "skipping postgres tests: TAP_TEST_PG_URL is not set"
            );
            return;
        }
    };

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .subsec_nanos();
    let schema = format!("tap_test_{}_{}", std::process::id(), nanos);

    let db = Arc::new(
        PostgresDb::connect_with_schema(&url, &schema)
            .expect("connect + migrate"),
    );

    // Re-running the migrations over the same schema must be a no-op
    // (version registry already at latest).
    drop(
        PostgresDb::connect_with_schema(&url, &schema)
            .expect("migrations are idempotent"),
    );

    testkit::exercise_asset_store(&mut PostgresAssetStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_burn_records(&mut PostgresAssetStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_batch_store(&mut PostgresBatchStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_proof_store(&mut PostgresProofStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_pending_anchor_store(
        &mut PostgresPendingAnchorStore::new(Arc::clone(&db)),
    );
    testkit::exercise_mailbox_store(&mut PostgresMailboxStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_universe_backend(&mut PostgresUniverseBackend::new(
        Arc::clone(&db),
    ));
    testkit::exercise_federation_db(&mut PostgresFederationDb::new(
        Arc::clone(&db),
    ));
    testkit::exercise_supply_tree_store(&mut PostgresSupplyTreeStore::new(
        Arc::clone(&db),
    ));
    testkit::exercise_supply_commit_store(
        &mut PostgresSupplyCommitStore::new(Arc::clone(&db)),
    );
    testkit::exercise_supply_staging_store(
        &mut PostgresSupplyStagingStore::new(Arc::clone(&db)),
    );
    testkit::exercise_ignore_store(&mut PostgresIgnoreStore::new(
        Arc::clone(&db),
    ));

    // MS-SMT tree store parity against the in-memory DefaultStore.
    testkit::exercise_tree_store(
        PostgresTreeStore::new(Arc::clone(&db), "pg-testkit-ns"),
        |store| store.take_error().map(|e| e.to_string()),
    );

    // Cleanup: drop the per-run schema.
    db.drop_schema(&schema).expect("drop schema");
}
