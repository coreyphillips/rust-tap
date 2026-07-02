//! Asset TLV encoding tests driven by the vendored Go BIP test vectors
//! (`asset/testdata/` in lightninglabs/taproot-assets).

mod common;

use common::*;
use tap_primitives::asset::EncodeType;
use tap_primitives::encoding::asset::{decode_asset, encode_asset};

#[test]
fn asset_tlv_encoding_valid_cases() {
    let file: AssetVectorFile =
        load_json("asset_tlv_encoding_generated.json");
    let cases = file.valid_test_cases.expect("no valid cases");
    assert!(!cases.is_empty());

    for case in &cases {
        let comment = case.comment.as_deref().unwrap_or("");

        // Build the asset from JSON and check the encoding is
        // byte-identical to the expected hex.
        let asset = build_asset(&case.asset)
            .unwrap_or_else(|e| panic!("{}: build failed: {}", comment, e));
        let encoded = encode_asset(&asset, EncodeType::Normal);
        assert_eq!(
            hex::encode(&encoded),
            case.expected,
            "{}: encoding mismatch",
            comment
        );

        // Decode the expected bytes and re-encode; must round-trip
        // byte-exactly.
        let expected_bytes = parse_hex(&case.expected);
        let decoded = decode_asset(&expected_bytes)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", comment, e));
        let re_encoded = encode_asset(&decoded, EncodeType::Normal);
        assert_eq!(
            re_encoded, expected_bytes,
            "{}: re-encoding mismatch",
            comment
        );

        // Structural spot checks: the decoded asset must match the one
        // built from JSON for all directly comparable fields. (The
        // decoded group key only carries the group public key, and the
        // built witness proof/root-asset bytes go through the same
        // encoding, so full equality holds here.)
        assert_eq!(decoded.version, asset.version, "{}", comment);
        assert_eq!(decoded.genesis, asset.genesis, "{}", comment);
        assert_eq!(decoded.amount, asset.amount, "{}", comment);
        assert_eq!(decoded.lock_time, asset.lock_time, "{}", comment);
        assert_eq!(
            decoded.relative_lock_time, asset.relative_lock_time,
            "{}",
            comment
        );
        assert_eq!(
            decoded.split_commitment_root, asset.split_commitment_root,
            "{}",
            comment
        );
        assert_eq!(
            decoded.script_version, asset.script_version,
            "{}",
            comment
        );
        assert_eq!(
            decoded.script_key.serialized(),
            asset.script_key.serialized(),
            "{}",
            comment
        );
        assert_eq!(
            decoded.group_key.as_ref().map(|g| g.group_pub_key),
            asset.group_key.as_ref().map(|g| g.group_pub_key),
            "{}",
            comment
        );
        assert_eq!(
            decoded.unknown_odd_types, asset.unknown_odd_types,
            "{}",
            comment
        );
        assert_eq!(
            decoded.prev_witnesses.len(),
            asset.prev_witnesses.len(),
            "{}",
            comment
        );
    }
}

#[test]
fn asset_tlv_encoding_error_cases() {
    let file: AssetVectorFile =
        load_json("asset_tlv_encoding_error_cases.json");
    let cases = file.error_test_cases.expect("no error cases");
    assert!(!cases.is_empty());

    for case in &cases {
        // All asset error cases are builder-level validation failures
        // in Go (TestAsset.ToAsset panics); our builder mirrors the
        // same checks and error strings.
        let result = build_asset(&case.asset);
        let err = result.err().unwrap_or_else(|| {
            panic!("expected error '{}', got success", case.error)
        });
        assert_eq!(err, case.error, "error message mismatch");
    }
}

#[test]
fn asset_hex_decodes_and_round_trips() {
    let bytes = load_hex_file("asset.hex");
    let asset = decode_asset(&bytes).expect("asset.hex must decode");

    // Re-encode must be byte-identical.
    let re_encoded = encode_asset(&asset, EncodeType::Normal);
    assert_eq!(re_encoded, bytes, "asset.hex round-trip mismatch");

    // Light sanity checks on the decoded content.
    assert!(!asset.genesis.tag.is_empty());
    assert!(asset.amount > 0);
}
