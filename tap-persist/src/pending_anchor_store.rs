// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Pending anchor transaction persistence, backed by migration 009
//! (`pending_anchors` table).
//!
//! An anchor transaction (a broadcast mint or transfer) must be watched
//! until it confirms, at which point proofs are generated, stored, and
//! delivered. Keeping that watch list only in memory loses it across a
//! crash or restart, permanently skipping proof generation/delivery.
//! This store persists one row per pending anchor so the watch list can
//! be reloaded at startup.
//!
//! The store is deliberately generic: it persists `(txid, kind,
//! payload)` rows only. The payload is an opaque, versioned blob whose
//! encoding is owned by the embedding layer (tap-node).

use std::collections::BTreeMap;

/// A pending anchor row: the anchor transaction id in internal
/// (little-endian) byte order, a kind discriminator, and an opaque
/// payload blob carrying the context needed to finish the operation
/// after confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPendingAnchor {
    /// The anchor transaction id (internal byte order).
    pub txid: [u8; 32],
    /// Discriminator for the anchor's operation kind. The embedding
    /// layer defines the values (tap-node: 0 = mint, 1 = transfer).
    pub kind: u8,
    /// Opaque, versioned payload encoding the anchor context.
    pub payload: Vec<u8>,
}

/// Trait for persisting pending anchor transactions.
pub trait PendingAnchorStore {
    /// Inserts or replaces the row for the anchor's txid.
    fn upsert_anchor(
        &mut self,
        anchor: &StoredPendingAnchor,
    ) -> Result<(), String>;

    /// Removes the row for the given txid. Removing a txid that is not
    /// stored is a no-op.
    fn remove_anchor(&mut self, txid: &[u8; 32]) -> Result<(), String>;

    /// Returns all stored pending anchors.
    fn list_anchors(&self) -> Result<Vec<StoredPendingAnchor>, String>;
}

/// In-memory [`PendingAnchorStore`] used as the default when no SQLite
/// database is configured.
#[derive(Default)]
pub struct MemoryPendingAnchorStore {
    anchors: BTreeMap<[u8; 32], StoredPendingAnchor>,
}

impl MemoryPendingAnchorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PendingAnchorStore for MemoryPendingAnchorStore {
    fn upsert_anchor(
        &mut self,
        anchor: &StoredPendingAnchor,
    ) -> Result<(), String> {
        self.anchors.insert(anchor.txid, anchor.clone());
        Ok(())
    }

    fn remove_anchor(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        self.anchors.remove(txid);
        Ok(())
    }

    fn list_anchors(&self) -> Result<Vec<StoredPendingAnchor>, String> {
        Ok(self.anchors.values().cloned().collect())
    }
}

/// SQLite-backed [`PendingAnchorStore`] over the `pending_anchors`
/// table (migration 009).
#[cfg(feature = "sqlite")]
pub struct SqlitePendingAnchorStore {
    db: std::sync::Arc<crate::sqlite::SqliteDb>,
}

#[cfg(feature = "sqlite")]
impl SqlitePendingAnchorStore {
    pub fn new(db: std::sync::Arc<crate::sqlite::SqliteDb>) -> Self {
        SqlitePendingAnchorStore { db }
    }
}

#[cfg(feature = "sqlite")]
impl PendingAnchorStore for SqlitePendingAnchorStore {
    fn upsert_anchor(
        &mut self,
        anchor: &StoredPendingAnchor,
    ) -> Result<(), String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO pending_anchors (txid, kind, payload) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                &anchor.txid[..],
                anchor.kind,
                &anchor.payload[..],
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn remove_anchor(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM pending_anchors WHERE txid = ?1",
            rusqlite::params![&txid[..]],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn list_anchors(&self) -> Result<Vec<StoredPendingAnchor>, String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT txid, kind, payload FROM pending_anchors \
                 ORDER BY rowid",
            )
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                let txid_bytes: Vec<u8> = row.get(0)?;
                let kind: u8 = row.get(1)?;
                let payload: Vec<u8> = row.get(2)?;
                Ok((txid_bytes, kind, payload))
            })
            .map_err(|e| e.to_string())?;

        let mut anchors = Vec::new();
        for row in rows {
            let (txid_bytes, kind, payload) =
                row.map_err(|e| e.to_string())?;
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
                kind,
                payload,
            });
        }
        Ok(anchors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shared per-trait exercise lives in the testkit so the same
    // scenario also runs against the Postgres backend.
    use crate::testkit::exercise_pending_anchor_store as exercise_store;

    fn test_anchor(txid_byte: u8, kind: u8) -> StoredPendingAnchor {
        StoredPendingAnchor {
            txid: [txid_byte; 32],
            kind,
            payload: vec![0x01, txid_byte, 0x03],
        }
    }

    #[test]
    fn test_memory_pending_anchor_store() {
        let mut store = MemoryPendingAnchorStore::new();
        exercise_store(&mut store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_sqlite_pending_anchor_store() {
        let db = std::sync::Arc::new(
            crate::sqlite::SqliteDb::open_in_memory().unwrap(),
        );
        let mut store = SqlitePendingAnchorStore::new(db);
        exercise_store(&mut store);
    }

    /// Rows written by one SQLite store handle are visible to a second
    /// handle over the same database (the restart scenario).
    #[cfg(feature = "sqlite")]
    #[test]
    fn test_sqlite_pending_anchor_store_shared_db() {
        let db = std::sync::Arc::new(
            crate::sqlite::SqliteDb::open_in_memory().unwrap(),
        );
        let mut writer =
            SqlitePendingAnchorStore::new(std::sync::Arc::clone(&db));
        let anchor = test_anchor(0xCC, 1);
        writer.upsert_anchor(&anchor).unwrap();

        let reader = SqlitePendingAnchorStore::new(db);
        assert_eq!(reader.list_anchors().unwrap(), vec![anchor]);
    }
}
