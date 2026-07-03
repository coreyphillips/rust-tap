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

use tap_onchain::chain::KeyDescriptor;
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

    /// Records the wallet key descriptors behind a stored address's
    /// script and internal keys (migration 010), so an asset received
    /// on the address carries enough context to be signed and sent
    /// onward later. `script_key` is the address script key (which may
    /// be a tweak of `script_key_desc.pub_key`, e.g. BIP-86 for V0/V1
    /// addresses). Errors if no address with that script key is
    /// stored.
    fn set_key_descriptors(
        &mut self,
        script_key: &SerializedKey,
        script_key_desc: &KeyDescriptor,
        internal_key_desc: &KeyDescriptor,
    ) -> Result<(), String>;

    /// Returns the `(script key, internal key)` descriptors recorded
    /// for the address with the given script key, or `None` when the
    /// address is unknown or was stored without descriptors.
    fn key_descriptors(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<(KeyDescriptor, KeyDescriptor)>, String>;

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
    key_descs: HashMap<[u8; 33], (KeyDescriptor, KeyDescriptor)>,
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

    fn set_key_descriptors(
        &mut self,
        script_key: &SerializedKey,
        script_key_desc: &KeyDescriptor,
        internal_key_desc: &KeyDescriptor,
    ) -> Result<(), String> {
        if !self
            .addresses
            .iter()
            .any(|a| a.script_key == *script_key)
        {
            return Err("address not found".into());
        }
        self.key_descs.insert(
            script_key.0,
            (script_key_desc.clone(), internal_key_desc.clone()),
        );
        Ok(())
    }

    fn key_descriptors(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<(KeyDescriptor, KeyDescriptor)>, String> {
        Ok(self.key_descs.get(&script_key.0).cloned())
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

    fn set_key_descriptors(
        &mut self,
        script_key: &SerializedKey,
        script_key_desc: &KeyDescriptor,
        internal_key_desc: &KeyDescriptor,
    ) -> Result<(), String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let rows = conn
            .execute(
                "UPDATE addresses SET \
                 script_key_family = ?2, script_key_index = ?3, \
                 script_key_raw = ?4, internal_key_family = ?5, \
                 internal_key_index = ?6, internal_key_raw = ?7 \
                 WHERE script_key = ?1",
                rusqlite::params![
                    script_key.as_bytes().to_vec(),
                    script_key_desc.family as i64,
                    script_key_desc.index as i64,
                    script_key_desc.pub_key.as_bytes().to_vec(),
                    internal_key_desc.family as i64,
                    internal_key_desc.index as i64,
                    internal_key_desc.pub_key.as_bytes().to_vec(),
                ],
            )
            .map_err(|e| e.to_string())?;
        if rows == 0 {
            return Err("address not found".into());
        }
        Ok(())
    }

    fn key_descriptors(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<(KeyDescriptor, KeyDescriptor)>, String> {
        let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
        let result = conn.query_row(
            "SELECT script_key_family, script_key_index, \
             script_key_raw, internal_key_family, internal_key_index, \
             internal_key_raw FROM addresses WHERE script_key = ?1",
            rusqlite::params![script_key.as_bytes().to_vec()],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        );
        let cols = match result {
            Ok(cols) => cols,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let (sk_fam, sk_idx, sk_raw, ik_fam, ik_idx, ik_raw) = cols;
        let script_desc = key_desc_from_parts(sk_fam, sk_idx, sk_raw);
        let internal_desc = key_desc_from_parts(ik_fam, ik_idx, ik_raw);
        Ok(match (script_desc, internal_desc) {
            (Some(s), Some(i)) => Some((s, i)),
            _ => None,
        })
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

/// Builds an optional [`KeyDescriptor`] from its three nullable
/// address-table columns. Returns `None` unless all three are present
/// and the raw key is 33 bytes.
#[cfg(feature = "sqlite")]
fn key_desc_from_parts(
    family: Option<i64>,
    index: Option<i64>,
    raw: Option<Vec<u8>>,
) -> Option<KeyDescriptor> {
    let (family, index, raw) = (family?, index?, raw?);
    if raw.len() != 33 {
        return None;
    }
    let mut pub_key = [0u8; 33];
    pub_key.copy_from_slice(&raw);
    Some(KeyDescriptor {
        family: family as u16,
        index: index as u32,
        pub_key: SerializedKey(pub_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sqlite")]
    use std::sync::Arc;

    // The shared per-trait exercise lives in the testkit so the same
    // scenario also runs against the Postgres backend.
    use crate::testkit::exercise_mailbox_store as exercise_store;

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
