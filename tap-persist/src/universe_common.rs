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

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;
use tap_universe::types::{LeafKey, ProofType, UniverseLeaf};

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
/// asset_id, amount, proof_data)`.
pub(crate) type UniverseLeafRow =
    (Vec<u8>, u32, Vec<u8>, Vec<u8>, u64, Vec<u8>);

/// Recomputes the universe root hash and sum from the leaf rows by
/// building tapd's universe MS-SMT (`tap_universe::smt`), so the root
/// matches what a real tapd would serve for the same leaves. Must
/// match `MemoryUniverseBackend::compute_root` exactly across all
/// backends.
pub(crate) fn compute_universe_root(
    proof_type: &ProofType,
    rows: &[UniverseLeafRow],
) -> Result<(NodeHash, u64), String> {
    let mut leaves: Vec<(LeafKey, UniverseLeaf)> =
        Vec::with_capacity(rows.len());
    for (txid, vout, script_key, asset_id, amount, proof) in rows {
        let txid: [u8; 32] = txid
            .as_slice()
            .try_into()
            .map_err(|_| "universe leaf txid must be 32 bytes".to_string())?;
        let script_key: [u8; 33] = script_key.as_slice().try_into().map_err(
            |_| "universe leaf script key must be 33 bytes".to_string(),
        )?;
        let asset_id: [u8; 32] = asset_id.as_slice().try_into().map_err(
            |_| "universe leaf asset id must be 32 bytes".to_string(),
        )?;
        let key = LeafKey {
            outpoint: OutPoint { txid, vout: *vout },
            script_key: SerializedKey(script_key),
        };
        let leaf = UniverseLeaf {
            asset_id: AssetId(asset_id),
            amount: *amount,
            proof: proof.clone(),
            key: key.clone(),
        };
        leaves.push((key, leaf));
    }

    tap_universe::smt::compute_universe_root(
        proof_type,
        leaves.iter().map(|(k, l)| (k, l)),
    )
}
