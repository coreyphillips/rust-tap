//! Shared test helpers: loads the vendored regtest genesis proof.

use tap_primitives::proof::{decode_proof, File};
use tap_universe::types::{
    LeafKey, ProofType, UniverseId, UniverseLeaf,
};

/// Loads the first (genesis) proof of the vendored regtest proof file
/// and builds a valid universe leaf from it, mirroring the loader in
/// tap-universe's syncer tests.
pub fn load_genesis_proof() -> (UniverseId, LeafKey, UniverseLeaf) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tap-primitives/tests/testdata/proof-file.hex"
    );
    let hex = std::fs::read_to_string(path)
        .expect("vendored proof-file.hex must exist");
    let hex = hex.trim();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let file = File::decode(&bytes).unwrap();
    let proof_bytes = file.proofs[0].proof_bytes.clone();
    let proof = decode_proof(&proof_bytes).unwrap();

    let id = UniverseId {
        asset_id: proof.asset.id(),
        group_key: None,
        proof_type: ProofType::Issuance,
    };
    let key = LeafKey {
        outpoint: proof.out_point(),
        script_key: *proof.asset.script_key.serialized(),
    };
    let leaf = UniverseLeaf {
        asset_id: proof.asset.id(),
        amount: proof.asset.amount,
        proof: proof_bytes,
        key: key.clone(),
    };
    (id, key, leaf)
}

/// Hex encodes bytes (lowercase).
#[allow(dead_code)] // Not every test binary uses this helper.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
