// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Address book and mailbox cursor persistence for V2 (authmailbox)
//! receives, backed by migration 005 (`addresses` and
//! `mailbox_cursors` tables).

use std::collections::HashMap;

use tap_primitives::address::TapAddress;
use tap_primitives::asset::SerializedKey;

/// The mailbox polling cursor for a receiver key: the last processed
/// message ID and the proof block height that came with it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MailboxCursor {
    /// The highest mailbox message ID that has been processed.
    pub last_message_id: u64,
    /// The highest proof block height seen among processed messages.
    pub last_block: u32,
}

/// Persistence for generated TAP addresses and per-receiver mailbox
/// cursors.
pub trait MailboxStore {
    /// Persists a generated address. The address script key must be
    /// unique.
    fn insert_address(&mut self, addr: &TapAddress) -> Result<(), String>;

    /// Returns all stored addresses.
    fn list_addresses(&self) -> Result<Vec<TapAddress>, String>;

    /// Looks up an address by its script key.
    fn address_by_script_key(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<TapAddress>, String>;

    /// Returns the mailbox cursor for the given receiver key
    /// (`MailboxCursor::default()` if none is stored yet).
    fn get_cursor(
        &self,
        receiver_key: &SerializedKey,
    ) -> Result<MailboxCursor, String>;

    /// Stores (upserts) the mailbox cursor for the given receiver key.
    fn set_cursor(
        &mut self,
        receiver_key: &SerializedKey,
        cursor: MailboxCursor,
    ) -> Result<(), String>;
}

/// In-memory [`MailboxStore`] used as the default when no SQLite
/// database is configured.
#[derive(Default)]
pub struct MemoryMailboxStore {
    addresses: Vec<TapAddress>,
    cursors: HashMap<[u8; 33], MailboxCursor>,
}

impl MemoryMailboxStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MailboxStore for MemoryMailboxStore {
    fn insert_address(&mut self, addr: &TapAddress) -> Result<(), String> {
        if self
            .addresses
            .iter()
            .any(|a| a.script_key == addr.script_key)
        {
            return Err("address script key already exists".into());
        }
        self.addresses.push(addr.clone());
        Ok(())
    }

    fn list_addresses(&self) -> Result<Vec<TapAddress>, String> {
        Ok(self.addresses.clone())
    }

    fn address_by_script_key(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<TapAddress>, String> {
        Ok(self
            .addresses
            .iter()
            .find(|a| a.script_key == *script_key)
            .cloned())
    }

    fn get_cursor(
        &self,
        receiver_key: &SerializedKey,
    ) -> Result<MailboxCursor, String> {
        Ok(self
            .cursors
            .get(&receiver_key.0)
            .copied()
            .unwrap_or_default())
    }

    fn set_cursor(
        &mut self,
        receiver_key: &SerializedKey,
        cursor: MailboxCursor,
    ) -> Result<(), String> {
        self.cursors.insert(receiver_key.0, cursor);
        Ok(())
    }
}

/// SQLite-backed [`MailboxStore`] over the `addresses` and
/// `mailbox_cursors` tables (migration 005). Addresses are stored both
/// as structured columns (for querying) and as the encoded bech32m
/// string (the source of truth for round-tripping).
#[cfg(feature = "sqlite")]
pub struct SqliteMailboxStore {
    db: std::sync::Arc<crate::sqlite::SqliteDb>,
}

#[cfg(feature = "sqlite")]
impl SqliteMailboxStore {
    pub fn new(db: std::sync::Arc<crate::sqlite::SqliteDb>) -> Self {
        SqliteMailboxStore { db }
    }
}

#[cfg(feature = "sqlite")]
impl MailboxStore for SqliteMailboxStore {
    fn insert_address(&mut self, addr: &TapAddress) -> Result<(), String> {
        let encoded = addr.encode().map_err(|e| e.to_string())?;
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO addresses (version, asset_id, group_key, \
             script_key, internal_key, amount, proof_courier_addr, \
             encoded) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                addr.version.to_u8(),
                addr.asset_id.as_ref().map(|id| id.as_bytes().to_vec()),
                addr.group_key.as_ref().map(|k| k.as_bytes().to_vec()),
                addr.script_key.as_bytes().to_vec(),
                addr.internal_key.as_bytes().to_vec(),
                addr.amount as i64,
                addr.proof_courier_addr,
                encoded,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn list_addresses(&self) -> Result<Vec<TapAddress>, String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT encoded FROM addresses ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;

        let mut addresses = Vec::new();
        for row in rows {
            let encoded = row.map_err(|e| e.to_string())?;
            addresses.push(
                TapAddress::decode(&encoded)
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(addresses)
    }

    fn address_by_script_key(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<TapAddress>, String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let result = conn.query_row(
            "SELECT encoded FROM addresses WHERE script_key = ?1",
            rusqlite::params![script_key.as_bytes().to_vec()],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(encoded) => Ok(Some(
                TapAddress::decode(&encoded)
                    .map_err(|e| e.to_string())?,
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn get_cursor(
        &self,
        receiver_key: &SerializedKey,
    ) -> Result<MailboxCursor, String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let result = conn.query_row(
            "SELECT last_message_id, last_block FROM mailbox_cursors \
             WHERE receiver_key = ?1",
            rusqlite::params![receiver_key.as_bytes().to_vec()],
            |row| {
                Ok(MailboxCursor {
                    last_message_id: row.get::<_, i64>(0)? as u64,
                    last_block: row.get::<_, u32>(1)?,
                })
            },
        );
        match result {
            Ok(cursor) => Ok(cursor),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Ok(MailboxCursor::default())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn set_cursor(
        &mut self,
        receiver_key: &SerializedKey,
        cursor: MailboxCursor,
    ) -> Result<(), String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO mailbox_cursors (receiver_key, \
             last_message_id, last_block) VALUES (?1, ?2, ?3) \
             ON CONFLICT(receiver_key) DO UPDATE SET \
             last_message_id = excluded.last_message_id, \
             last_block = excluded.last_block",
            rusqlite::params![
                receiver_key.as_bytes().to_vec(),
                cursor.last_message_id as i64,
                cursor.last_block,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::collections::BTreeMap;
    use tap_primitives::address::{AddressVersion, TapNetwork};
    use tap_primitives::asset::AssetId;

    fn test_address(script_key_byte: u8) -> TapAddress {
        // Address decode validates keys on-curve (like Go), so the
        // test keys must be valid points: x = 0xAA repeated is a valid
        // x coordinate.
        let mut internal_key = [0xAA; 33];
        internal_key[0] = 0x02;
        TapAddress {
            version: AddressVersion::V2,
            asset_version: 0,
            asset_id: Some(AssetId([0xAA; 32])),
            script_key: SerializedKey([script_key_byte; 33]),
            internal_key: SerializedKey(internal_key),
            amount: 1000,
            network: TapNetwork::Regtest,
            proof_courier_addr: Some(
                "authmailbox+universerpc://foo.bar:10029".to_string(),
            ),
            group_key: None,
            tapscript_sibling: None,
            unknown_odd_types: BTreeMap::new(),
        }
    }

    fn exercise_store(store: &mut dyn MailboxStore) {
        let addr = test_address(0x02);
        store.insert_address(&addr).unwrap();

        // Duplicate script keys are rejected.
        assert!(store.insert_address(&addr).is_err());

        let listed = store.list_addresses().unwrap();
        assert_eq!(listed, vec![addr.clone()]);

        let found = store
            .address_by_script_key(&addr.script_key)
            .unwrap()
            .unwrap();
        assert_eq!(found, addr);
        assert!(store
            .address_by_script_key(&SerializedKey([0x05; 33]))
            .unwrap()
            .is_none());

        // Cursors default to zero, then upsert.
        let key = addr.script_key;
        assert_eq!(
            store.get_cursor(&key).unwrap(),
            MailboxCursor::default()
        );
        let cursor = MailboxCursor {
            last_message_id: 42,
            last_block: 800_000,
        };
        store.set_cursor(&key, cursor).unwrap();
        assert_eq!(store.get_cursor(&key).unwrap(), cursor);

        let cursor2 = MailboxCursor {
            last_message_id: 43,
            last_block: 800_001,
        };
        store.set_cursor(&key, cursor2).unwrap();
        assert_eq!(store.get_cursor(&key).unwrap(), cursor2);
    }

    #[test]
    fn test_memory_mailbox_store() {
        let mut store = MemoryMailboxStore::new();
        exercise_store(&mut store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn test_sqlite_mailbox_store() {
        let db = Arc::new(crate::sqlite::SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteMailboxStore::new(Arc::clone(&db));
        exercise_store(&mut store);
    }
}
