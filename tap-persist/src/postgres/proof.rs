// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed [`ProofStore`], mirroring
//! [`crate::sqlite::SqliteProofStore`].

use std::sync::Arc;

use tap_primitives::asset::{OutPoint, SerializedKey};
use tap_primitives::proof;

use crate::postgres::{to_array, PostgresDb};
use crate::proof_store::{ProofLocator, ProofStore};

/// Postgres-backed proof file store.
pub struct PostgresProofStore {
    db: Arc<PostgresDb>,
}

impl PostgresProofStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresProofStore { db }
    }
}

impl ProofStore for PostgresProofStore {
    fn insert_proof(
        &mut self,
        locator: ProofLocator,
        file: proof::File,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        let encoded = file.encode();
        client
            .execute(
                "INSERT INTO proof_files \
                 (anchor_txid, anchor_vout, script_key, proof_data) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (anchor_txid, anchor_vout, script_key) \
                 DO UPDATE SET proof_data = EXCLUDED.proof_data",
                &[
                    &&locator.outpoint.txid[..],
                    &i64::from(locator.outpoint.vout),
                    &&locator.script_key.0[..],
                    &&encoded[..],
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_proof(
        &self,
        locator: &ProofLocator,
    ) -> Result<Option<proof::File>, String> {
        let mut client = self.db.lock()?;
        let row = client
            .query_opt(
                "SELECT proof_data FROM proof_files \
                 WHERE anchor_txid = $1 AND anchor_vout = $2 \
                 AND script_key = $3",
                &[
                    &&locator.outpoint.txid[..],
                    &i64::from(locator.outpoint.vout),
                    &&locator.script_key.0[..],
                ],
            )
            .map_err(|e| e.to_string())?;

        match row {
            Some(row) => {
                let data: Vec<u8> =
                    row.try_get(0).map_err(|e| e.to_string())?;
                let file =
                    proof::File::decode(&data).map_err(|e| e.to_string())?;
                Ok(Some(file))
            }
            None => Ok(None),
        }
    }

    fn has_proof(&self, locator: &ProofLocator) -> bool {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return false,
        };
        client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM proof_files \
                 WHERE anchor_txid = $1 AND anchor_vout = $2 \
                 AND script_key = $3)",
                &[
                    &&locator.outpoint.txid[..],
                    &i64::from(locator.outpoint.vout),
                    &&locator.script_key.0[..],
                ],
            )
            .and_then(|row| row.try_get::<_, bool>(0))
            .unwrap_or(false)
    }

    fn list_proofs(&self) -> Vec<ProofLocator> {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(_) => return vec![],
        };
        client
            .query(
                "SELECT anchor_txid, anchor_vout, script_key \
                 FROM proof_files",
                &[],
            )
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        let txid_bytes: Vec<u8> = row.try_get(0).ok()?;
                        let vout: i64 = row.try_get(1).ok()?;
                        let key_bytes: Vec<u8> = row.try_get(2).ok()?;
                        Some(ProofLocator {
                            outpoint: OutPoint {
                                txid: to_array::<32>(txid_bytes, "txid")
                                    .ok()?,
                                vout: vout as u32,
                            },
                            script_key: SerializedKey(
                                to_array::<33>(key_bytes, "script_key")
                                    .ok()?,
                            ),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
