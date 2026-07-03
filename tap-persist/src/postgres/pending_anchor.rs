// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`PendingAnchorStore`], mirroring
//! [`crate::pending_anchor_store::SqlitePendingAnchorStore`].

use std::sync::Arc;

use crate::pending_anchor_store::{PendingAnchorStore, StoredPendingAnchor};
use crate::postgres::PostgresDb;

/// Postgres-backed [`PendingAnchorStore`] over the `pending_anchors`
/// table (migration 009).
pub struct PostgresPendingAnchorStore {
    db: Arc<PostgresDb>,
}

impl PostgresPendingAnchorStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresPendingAnchorStore { db }
    }
}

impl PendingAnchorStore for PostgresPendingAnchorStore {
    fn upsert_anchor(
        &mut self,
        anchor: &StoredPendingAnchor,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO pending_anchors (txid, kind, payload) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (txid) DO UPDATE SET \
                  kind = EXCLUDED.kind, \
                  payload = EXCLUDED.payload",
                &[
                    &&anchor.txid[..],
                    &i64::from(anchor.kind),
                    &&anchor.payload[..],
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn remove_anchor(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "DELETE FROM pending_anchors WHERE txid = $1",
                &[&&txid[..]],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn list_anchors(&self) -> Result<Vec<StoredPendingAnchor>, String> {
        let mut client = self.db.lock()?;
        // Postgres has no rowid; order by txid for a deterministic
        // listing (the trait promises no particular order).
        let rows = client
            .query(
                "SELECT txid, kind, payload FROM pending_anchors \
                 ORDER BY txid",
                &[],
            )
            .map_err(|e| e.to_string())?;

        let mut anchors = Vec::new();
        for row in &rows {
            let err = |e: postgres::Error| e.to_string();
            let txid_bytes: Vec<u8> = row.try_get(0).map_err(err)?;
            let kind: i64 = row.try_get(1).map_err(err)?;
            let payload: Vec<u8> = row.try_get(2).map_err(err)?;
            if txid_bytes.len() != 32 {
                return Err(format!(
                    "pending anchor txid has invalid length {}",
                    txid_bytes.len()
                ));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);
            anchors.push(StoredPendingAnchor {
                txid,
                kind: kind as u8,
                payload,
            });
        }
        Ok(anchors)
    }
}
