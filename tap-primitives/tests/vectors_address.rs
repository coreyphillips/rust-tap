//! TAP address encoding tests driven by the vendored Go BIP test
//! vectors (`address/testdata/` in lightninglabs/taproot-assets).

mod common;

use common::*;
use tap_primitives::address::TapAddress;

#[test]
fn address_tlv_encoding_valid_cases() {
    let file: AddressVectorFile =
        load_json("address_tlv_encoding_generated.json");
    let cases = file.valid_test_cases.expect("no valid cases");
    assert!(!cases.is_empty());

    for case in &cases {
        let comment = case.comment.as_deref().unwrap_or("");

        // Build the address from JSON and check the bech32m string.
        let address = build_address(&case.address)
            .unwrap_or_else(|e| panic!("{}: build failed: {}", comment, e));
        let encoded = address
            .encode()
            .unwrap_or_else(|e| panic!("{}: encode failed: {}", comment, e));
        assert_eq!(encoded, case.expected, "{}: encoding mismatch", comment);

        // Decode the expected string and re-encode; must round-trip.
        let decoded = TapAddress::decode(&case.expected)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", comment, e));
        let re_encoded = decoded
            .encode()
            .unwrap_or_else(|e| panic!("{}: re-encode failed: {}", comment, e));
        assert_eq!(
            re_encoded, case.expected,
            "{}: re-encoding mismatch",
            comment
        );

        // Structural checks. The decoded network can differ from the
        // built one only for HRPs shared between networks (taptb),
        // which still re-encode identically.
        assert_eq!(decoded.version, address.version, "{}", comment);
        assert_eq!(
            decoded.asset_version, address.asset_version,
            "{}",
            comment
        );
        assert_eq!(decoded.asset_id, address.asset_id, "{}", comment);
        assert_eq!(decoded.script_key, address.script_key, "{}", comment);
        assert_eq!(
            decoded.internal_key, address.internal_key,
            "{}",
            comment
        );
        assert_eq!(decoded.amount, address.amount, "{}", comment);
        assert_eq!(decoded.group_key, address.group_key, "{}", comment);
        assert_eq!(
            decoded.tapscript_sibling, address.tapscript_sibling,
            "{}",
            comment
        );
        assert_eq!(
            decoded.proof_courier_addr, address.proof_courier_addr,
            "{}",
            comment
        );
        assert_eq!(
            decoded.unknown_odd_types, address.unknown_odd_types,
            "{}",
            comment
        );
    }
}

#[test]
fn address_tlv_encoding_error_cases() {
    let file: AddressVectorFile =
        load_json("address_tlv_encoding_error_cases.json");
    let cases = file.error_test_cases.expect("no error cases");
    assert!(!cases.is_empty());

    for case in &cases {
        // All address error cases are builder-level validation
        // failures in Go (TestAddress.ToAddress panics); our builder
        // mirrors the same checks and error strings.
        let result = build_address(&case.address);
        let err = result.err().unwrap_or_else(|| {
            panic!("expected error '{}', got success", case.error)
        });
        assert_eq!(err, case.error, "error message mismatch");
    }
}
