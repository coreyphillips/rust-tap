//! Burn key derivation tests driven by the vendored Go BIP test
//! vectors (`asset/testdata/asset_burn_key_generated.json` in
//! lightninglabs/taproot-assets), plus ports of the logic tests from
//! Go's `asset/burn_test.go` and `asset/asset_test.go`
//! (`TestAssetIsBurn`).

mod common;

use serde::Deserialize;

use common::*;
use tap_primitives::asset::{
    derive_burn_key, is_burn_key, Asset, AssetId, AssetType, AssetVersion,
    Genesis, OutPoint, PrevId, ScriptKey, ScriptVersion, SerializedKey,
    SplitCommitmentWitness, Witness,
};
use tap_primitives::asset::EncodeType;
use tap_primitives::encoding::asset::encode_asset;
use tap_primitives::mssmt;

#[derive(Debug, Deserialize)]
struct BurnVectorFile {
    valid_test_cases: Vec<BurnValidCase>,
}

#[derive(Debug, Deserialize)]
struct BurnValidCase {
    prev_id: TestPrevId,
    expected: String,
    comment: Option<String>,
}

fn build_prev_id(tp: &TestPrevId) -> PrevId {
    PrevId {
        out_point: parse_out_point(&tp.out_point),
        id: AssetId(parse_hex32(&tp.asset_id)),
        script_key: SerializedKey(parse_hex33(&tp.script_key)),
    }
}

#[test]
fn burn_key_bip_test_vectors() {
    let file: BurnVectorFile = load_json("asset_burn_key_generated.json");
    assert!(!file.valid_test_cases.is_empty());

    for case in &file.valid_test_cases {
        let comment = case.comment.as_deref().unwrap_or("");

        let prev_id = build_prev_id(&case.prev_id);
        let burn_key = derive_burn_key(&prev_id);

        // The expected key is in 32-byte schnorr (x-only) form.
        assert_eq!(
            hex::encode(burn_key.schnorr_bytes()),
            case.expected,
            "{}: burn key mismatch",
            comment
        );
    }
}

// ---------------------------------------------------------------------
// Logic tests ported from Go asset/asset_test.go TestAssetIsBurn.
// ---------------------------------------------------------------------

fn test_genesis() -> Genesis {
    Genesis {
        first_prev_out: OutPoint {
            txid: [0x01; 32],
            vout: 1,
        },
        tag: "burn-test".to_string(),
        meta_hash: [0x02; 32],
        output_index: 0,
        asset_type: AssetType::Normal,
    }
}

fn test_prev_id() -> PrevId {
    PrevId {
        out_point: OutPoint {
            txid: [0xAA; 32],
            vout: 2,
        },
        id: test_genesis().id(),
        script_key: SerializedKey(
            parse_hex33(
                "03c50bfc65dfb20e9b9c1c6d8b435ef91f41eb86434576823eeaf3\
                 a69fa7e1fc78",
            ),
        ),
    }
}

/// Builds a transfer root asset spending `test_prev_id()` with a direct
/// (non-split) witness.
fn root_asset(script_key: SerializedKey) -> Asset {
    Asset {
        version: AssetVersion::V0,
        genesis: test_genesis(),
        amount: 100,
        lock_time: 0,
        relative_lock_time: 0,
        prev_witnesses: vec![Witness {
            prev_id: Some(test_prev_id()),
            tx_witness: vec![vec![0x01, 0x02]],
            split_commitment: None,
        }],
        split_commitment_root: None,
        script_version: ScriptVersion::V0,
        script_key: ScriptKey::from_pub_key(script_key),
        group_key: None,
        unknown_odd_types: Default::default(),
    }
}

/// Builds a split output asset whose split-commitment witness embeds the
/// given root asset.
fn split_asset(script_key: SerializedKey, root: &Asset) -> Asset {
    // Any structurally valid MS-SMT proof works here; the burn detection
    // only decodes the embedded root asset.
    let tree = mssmt::FullTree::new(mssmt::DefaultStore::new());
    let proof = tree.merkle_proof([0u8; 32]).expect("proof");

    Asset {
        version: AssetVersion::V0,
        genesis: test_genesis(),
        amount: 50,
        lock_time: 0,
        relative_lock_time: 0,
        prev_witnesses: vec![Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![],
            split_commitment: Some(SplitCommitmentWitness {
                proof,
                root_asset: encode_asset(root, EncodeType::Normal),
            }),
        }],
        split_commitment_root: None,
        script_version: ScriptVersion::V0,
        script_key: ScriptKey::from_pub_key(script_key),
        group_key: None,
        unknown_odd_types: Default::default(),
    }
}

#[test]
fn asset_is_burn_direct_and_split_witness() {
    let non_burn_key = SerializedKey(parse_hex33(
        "02a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e\
         078f",
    ));

    // Non-burn script keys: neither the root nor the split is a burn.
    let root = root_asset(non_burn_key);
    let split = split_asset(non_burn_key, &root);
    assert!(!root.is_burn());
    assert!(!split.is_burn());

    // Update the script key to a burn script key for both of the assets.
    // The split's burn key is derived from the root asset's first PrevId,
    // exactly like Go's TestAssetIsBurn.
    let burn_key = derive_burn_key(&test_prev_id());
    let root = root_asset(burn_key);
    let split = split_asset(burn_key, &root);
    assert!(root.is_burn());
    assert!(split.is_burn());
}

#[test]
fn asset_is_burn_requires_witness() {
    let burn_key = derive_burn_key(&test_prev_id());
    let mut asset = root_asset(burn_key);
    asset.prev_witnesses.clear();
    assert!(!asset.is_burn());
}

#[test]
fn is_burn_key_split_witness_without_root_prev_id() {
    // A split whose root asset has no prev witnesses can never be
    // detected as a burn.
    let burn_key = derive_burn_key(&test_prev_id());
    let mut root = root_asset(burn_key);
    root.prev_witnesses.clear();
    let split = split_asset(burn_key, &root);
    assert!(!split.is_burn());
}

#[test]
fn is_burn_key_wrong_prev_id() {
    // A burn key derived from a different PrevId must not match.
    let mut other_prev_id = test_prev_id();
    other_prev_id.out_point.vout += 1;
    let wrong_key = derive_burn_key(&other_prev_id);

    let root = root_asset(wrong_key);
    assert!(!root.is_burn());

    let witness = &root.prev_witnesses[0];
    assert!(!is_burn_key(&wrong_key, witness));
    assert!(is_burn_key(&derive_burn_key(&test_prev_id()), witness));
}
