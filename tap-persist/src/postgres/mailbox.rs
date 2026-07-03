// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`MailboxStore`], mirroring
//! [`crate::mailbox_store::SqliteMailboxStore`].

use std::sync::Arc;

use tap_onchain::chain::KeyDescriptor;
use tap_primitives::address::TapAddress;
use tap_primitives::asset::SerializedKey;

use crate::mailbox_store::{MailboxCursor, MailboxStore};
use crate::postgres::{to_array, PostgresDb};

/// Postgres-backed [`MailboxStore`] over the `addresses` and
/// `mailbox_cursors` tables (migration 005). Addresses are stored both
/// as structured columns (for querying) and as the encoded bech32m
/// string (the source of truth for round-tripping).
pub struct PostgresMailboxStore {
    db: Arc<PostgresDb>,
}

impl PostgresMailboxStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresMailboxStore { db }
    }
}

impl MailboxStore for PostgresMailboxStore {
    fn insert_address(&mut self, addr: &TapAddress) -> Result<(), String> {
        let encoded = addr.encode().map_err(|e| e.to_string())?;
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO addresses (version, asset_id, group_key, \
                 script_key, internal_key, amount, proof_courier_addr, \
                 encoded) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &i64::from(addr.version.to_u8()),
                    &addr.asset_id.as_ref().map(|id| id.as_bytes().to_vec()),
                    &addr.group_key.as_ref().map(|k| k.as_bytes().to_vec()),
                    &&addr.script_key.as_bytes()[..],
                    &&addr.internal_key.as_bytes()[..],
                    &(addr.amount as i64),
                    &addr.proof_courier_addr,
                    &encoded,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn list_addresses(&self) -> Result<Vec<TapAddress>, String> {
        let mut client = self.db.lock()?;
        let rows = client
            .query("SELECT encoded FROM addresses ORDER BY id", &[])
            .map_err(|e| e.to_string())?;

        let mut addresses = Vec::new();
        for row in &rows {
            let encoded: String =
                row.try_get(0).map_err(|e| e.to_string())?;
            addresses.push(
                TapAddress::decode(&encoded).map_err(|e| e.to_string())?,
            );
        }
        Ok(addresses)
    }

    fn address_by_script_key(
        &self,
        script_key: &SerializedKey,
    ) -> Result<Option<TapAddress>, String> {
        let mut client = self.db.lock()?;
        let row = client
            .query_opt(
                "SELECT encoded FROM addresses WHERE script_key = $1",
                &[&&script_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;
        match row {
            Some(row) => {
                let encoded: String =
                    row.try_get(0).map_err(|e| e.to_string())?;
                Ok(Some(
                    TapAddress::decode(&encoded)
                        .map_err(|e| e.to_string())?,
                ))
            }
            None => Ok(None),
        }
    }

    fn set_key_descriptors(
        &mut self,
        script_key: &SerializedKey,
        script_key_desc: &KeyDescriptor,
        internal_key_desc: &KeyDescriptor,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        let rows = client
            .execute(
                "UPDATE addresses SET \
                 script_key_family = $2, script_key_index = $3, \
                 script_key_raw = $4, internal_key_family = $5, \
                 internal_key_index = $6, internal_key_raw = $7 \
                 WHERE script_key = $1",
                &[
                    &&script_key.as_bytes()[..],
                    &i64::from(script_key_desc.family),
                    &i64::from(script_key_desc.index),
                    &&script_key_desc.pub_key.as_bytes()[..],
                    &i64::from(internal_key_desc.family),
                    &i64::from(internal_key_desc.index),
                    &&internal_key_desc.pub_key.as_bytes()[..],
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
        let mut client = self.db.lock()?;
        let row = client
            .query_opt(
                "SELECT script_key_family, script_key_index, \
                 script_key_raw, internal_key_family, internal_key_index, \
                 internal_key_raw FROM addresses WHERE script_key = $1",
                &[&&script_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;

        let row = match row {
            Some(row) => row,
            None => return Ok(None),
        };
        let err = |e: postgres::Error| e.to_string();
        let sk_fam: Option<i64> = row.try_get(0).map_err(err)?;
        let sk_idx: Option<i64> = row.try_get(1).map_err(err)?;
        let sk_raw: Option<Vec<u8>> = row.try_get(2).map_err(err)?;
        let ik_fam: Option<i64> = row.try_get(3).map_err(err)?;
        let ik_idx: Option<i64> = row.try_get(4).map_err(err)?;
        let ik_raw: Option<Vec<u8>> = row.try_get(5).map_err(err)?;

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
        let mut client = self.db.lock()?;
        let row = client
            .query_opt(
                "SELECT last_message_id, last_block FROM mailbox_cursors \
                 WHERE receiver_key = $1",
                &[&&receiver_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;
        match row {
            Some(row) => {
                let err = |e: postgres::Error| e.to_string();
                let last_message_id: i64 = row.try_get(0).map_err(err)?;
                let last_block: i64 = row.try_get(1).map_err(err)?;
                Ok(MailboxCursor {
                    last_message_id: last_message_id as u64,
                    last_block: last_block as u32,
                })
            }
            None => Ok(MailboxCursor::default()),
        }
    }

    fn set_cursor(
        &mut self,
        receiver_key: &SerializedKey,
        cursor: MailboxCursor,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO mailbox_cursors (receiver_key, \
                 last_message_id, last_block) VALUES ($1, $2, $3) \
                 ON CONFLICT (receiver_key) DO UPDATE SET \
                 last_message_id = EXCLUDED.last_message_id, \
                 last_block = EXCLUDED.last_block",
                &[
                    &&receiver_key.as_bytes()[..],
                    &(cursor.last_message_id as i64),
                    &i64::from(cursor.last_block),
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Builds an optional [`KeyDescriptor`] from its three nullable
/// address-table columns. Returns `None` unless all three are present
/// and the raw key is 33 bytes.
fn key_desc_from_parts(
    family: Option<i64>,
    index: Option<i64>,
    raw: Option<Vec<u8>>,
) -> Option<KeyDescriptor> {
    let (family, index, raw) = (family?, index?, raw?);
    let pub_key = to_array::<33>(raw, "key_raw").ok()?;
    Some(KeyDescriptor {
        family: family as u16,
        index: index as u32,
        pub_key: SerializedKey(pub_key),
    })
}
