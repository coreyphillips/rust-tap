// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Backend-agnostic helpers shared by the SQLite and Postgres
//! universe stores: proof-type string mapping and the universe root
//! recomputation, which must match `MemoryUniverseBackend::compute_root`
//! exactly across all backends.

use bitcoin_hashes::{sha256, Hash, HashEngine};

use tap_primitives::mssmt::NodeHash;
use tap_universe::types::ProofType;

pub(crate) fn proof_type_str(pt: &ProofType) -> &'static str {
    match pt {
        ProofType::Issuance => "issuance",
        ProofType::Transfer => "transfer",
        ProofType::Ignore => "ignore",
        ProofType::Burn => "burn",
        ProofType::MintSupply => "mint_supply",
    }
}

pub(crate) fn proof_type_from_str(s: &str) -> ProofType {
    match s {
        "transfer" => ProofType::Transfer,
        "ignore" => ProofType::Ignore,
        "burn" => ProofType::Burn,
        "mint_supply" => ProofType::MintSupply,
        _ => ProofType::Issuance,
    }
}

/// A universe leaf row as `(outpoint_txid, outpoint_vout, script_key,
/// asset_id, amount)`, ordered by `(outpoint_txid, outpoint_vout,
/// script_key)` ascending (the byte-wise ordering both SQLite BLOB and
/// Postgres BYTEA comparisons produce).
pub(crate) type UniverseLeafRow = (Vec<u8>, u32, Vec<u8>, Vec<u8>, u64);

/// Recomputes the universe root hash and sum from the ordered leaf
/// rows, matching `MemoryUniverseBackend::compute_root` exactly.
pub(crate) fn compute_universe_root(
    rows: &[UniverseLeafRow],
) -> (NodeHash, u64) {
    if rows.is_empty() {
        return (NodeHash::EMPTY, 0);
    }

    let mut sum: u64 = 0;
    let mut engine = sha256::HashEngine::default();

    for (txid, vout, script_key, asset_id, amount) in rows {
        engine.input(asset_id);
        engine.input(&amount.to_be_bytes());
        engine.input(txid);
        engine.input(&vout.to_be_bytes());
        engine.input(script_key);
        sum = sum.saturating_add(*amount);
    }

    let hash = sha256::Hash::from_engine(engine);
    (NodeHash(hash.to_byte_array()), sum)
}
