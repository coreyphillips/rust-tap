// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Conformance tests against the Go implementation's tappsbt (vPSBT)
//! encoding test vectors (`tappsbt/testdata/psbt_encoding_*.json`).

mod common;

use base64::Engine as _;
use common::*;
use tap_primitives::vpsbt::VPacket;

const GENERATED: &str = "psbt_encoding_generated.json";
const ERROR_CASES: &str = "psbt_encoding_error_cases.json";

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("invalid base64 in test vector")
}

/// Panics with the position and context of the first differing byte,
/// to make tracing encoding mismatches easier.
fn assert_bytes_equal(actual: &[u8], expected: &[u8], context: &str) {
    if actual == expected {
        return;
    }
    let first_diff = actual
        .iter()
        .zip(expected.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    let start = first_diff.saturating_sub(16);
    panic!(
        "{}: byte mismatch at offset {} (actual len {}, expected len {})\n\
         actual:   ...{}\n\
         expected: ...{}",
        context,
        first_diff,
        actual.len(),
        expected.len(),
        hex::encode(&actual[start..actual.len().min(first_diff + 16)]),
        hex::encode(
            &expected[start..expected.len().min(first_diff + 16)]
        ),
    );
}

/// Builds each JSON packet and checks that its serialization matches
/// the expected base64 PSBT byte for byte.
#[test]
fn vpsbt_encode_vectors() {
    let file: VPsbtVectorFile = load_json(GENERATED);
    let cases = file.valid_test_cases.expect("no valid test cases");
    assert!(!cases.is_empty());

    for (idx, case) in cases.iter().enumerate() {
        let comment = case.comment.as_deref().unwrap_or("");
        let context = format!("case {} ({})", idx, comment);

        let packet = build_vpacket(&case.packet)
            .unwrap_or_else(|e| panic!("{}: build failed: {}", context, e));

        let serialized = packet
            .serialize()
            .unwrap_or_else(|e| panic!("{}: encode failed: {}", context, e));
        assert_bytes_equal(
            &serialized,
            &b64_decode(&case.expected),
            &context,
        );

        let b64 = packet
            .b64_encode()
            .unwrap_or_else(|e| panic!("{}: encode failed: {}", context, e));
        assert_eq!(b64, case.expected, "{}: base64 mismatch", context);
    }
}

/// Decodes each expected PSBT and checks that re-encoding it
/// reproduces the exact same bytes.
#[test]
fn vpsbt_decode_vectors() {
    let file: VPsbtVectorFile = load_json(GENERATED);
    let cases = file.valid_test_cases.expect("no valid test cases");

    for (idx, case) in cases.iter().enumerate() {
        let comment = case.comment.as_deref().unwrap_or("");
        let context = format!("case {} ({})", idx, comment);

        let expected_bytes = b64_decode(&case.expected);
        let packet = VPacket::from_raw_bytes(&expected_bytes)
            .unwrap_or_else(|e| {
                panic!("{}: decode failed: {}", context, e)
            });

        let reencoded = packet
            .serialize()
            .unwrap_or_else(|e| panic!("{}: encode failed: {}", context, e));
        assert_bytes_equal(&reencoded, &expected_bytes, &context);

        // The base64 entry point must agree with the raw one.
        let from_b64 = VPacket::from_base64(&case.expected)
            .unwrap_or_else(|e| {
                panic!("{}: base64 decode failed: {}", context, e)
            });
        assert_bytes_equal(
            &from_b64.serialize().expect("reencode"),
            &expected_bytes,
            &context,
        );
    }
}

/// Checks the decoded packet structure against the JSON description
/// for a few scalar fields (spot check on top of the byte-exact round
/// trip).
#[test]
fn vpsbt_decode_structure() {
    let file: VPsbtVectorFile = load_json(GENERATED);
    let cases = file.valid_test_cases.expect("no valid test cases");

    for (idx, case) in cases.iter().enumerate() {
        let context = format!("case {}", idx);
        let packet = VPacket::from_raw_bytes(&b64_decode(&case.expected))
            .expect("decode");

        assert_eq!(
            packet.version.to_u8(),
            case.packet.version,
            "{}: version",
            context
        );
        assert_eq!(
            packet.chain_params.hrp(),
            case.packet.chain_params_hrp,
            "{}: chain params HRP",
            context
        );

        let json_inputs =
            case.packet.inputs.as_deref().unwrap_or_default();
        assert_eq!(
            packet.inputs.len(),
            json_inputs.len(),
            "{}: input count",
            context
        );
        for (input, json_input) in
            packet.inputs.iter().zip(json_inputs.iter())
        {
            let json_anchor =
                json_input.anchor.as_ref().expect("anchor in vector");
            assert_eq!(
                input.anchor.value as i64, json_anchor.value,
                "{}: anchor value",
                context
            );
            assert_eq!(
                input.anchor.sig_hash_type, json_anchor.sig_hash_type,
                "{}: anchor sighash type",
                context
            );
            assert_eq!(
                input.asset.is_some(),
                json_input.asset.is_some(),
                "{}: input asset presence",
                context
            );
            assert_eq!(
                input.proof.is_some(),
                json_input.proof.is_some(),
                "{}: input proof presence",
                context
            );
        }

        let json_outputs =
            case.packet.outputs.as_deref().unwrap_or_default();
        assert_eq!(
            packet.outputs.len(),
            json_outputs.len(),
            "{}: output count",
            context
        );
        for (output, json_output) in
            packet.outputs.iter().zip(json_outputs.iter())
        {
            assert_eq!(
                output.amount, json_output.amount,
                "{}: output amount",
                context
            );
            assert_eq!(
                output.output_type.0, json_output.output_type,
                "{}: output type",
                context
            );
            assert_eq!(
                output.interactive, json_output.interactive,
                "{}: output interactive",
                context
            );
            assert_eq!(
                output.anchor_output_index,
                json_output.anchor_output_index,
                "{}: anchor output index",
                context
            );
            assert_eq!(
                output.lock_time, json_output.lock_time,
                "{}: lock time",
                context
            );
            assert_eq!(
                output.relative_lock_time,
                json_output.relative_lock_time,
                "{}: relative lock time",
                context
            );
            assert_eq!(
                output.alt_leaves.len(),
                json_output
                    .alt_leaves
                    .as_deref()
                    .unwrap_or_default()
                    .len(),
                "{}: alt leaf count",
                context
            );
            assert_eq!(
                output.address.is_some(),
                json_output.address.is_some(),
                "{}: address presence",
                context
            );
        }
    }
}

/// Round-trips each vector through `bitcoin::psbt::Psbt` to make sure
/// the interop entry points work.
///
/// `bitcoin::psbt` requires the input Taproot merkle root to be a
/// 32-byte hash, while Go's mock packets carry the 11-byte literal
/// "merkle root" there, so packets with such synthetic values cannot
/// be represented and are skipped (their byte-exact serialization is
/// covered by the other tests).
#[test]
fn vpsbt_bitcoin_psbt_interop() {
    use tap_primitives::vpsbt::VPsbtError;

    let file: VPsbtVectorFile = load_json(GENERATED);
    let cases = file.valid_test_cases.expect("no valid test cases");

    let mut interop_count = 0;
    for (idx, case) in cases.iter().enumerate() {
        let context = format!("case {}", idx);
        let expected_bytes = b64_decode(&case.expected);

        let packet =
            VPacket::from_raw_bytes(&expected_bytes).expect("decode");
        let psbt = match packet.encode_as_psbt() {
            Ok(psbt) => psbt,
            Err(VPsbtError::EncodeError(msg))
                if msg.contains("invalid hash") =>
            {
                // Known representability limit of bitcoin::psbt's
                // typed fields (see the doc comment above).
                continue;
            }
            Err(e) => {
                panic!("{}: encode_as_psbt failed: {}", context, e)
            }
        };

        // Going back through bitcoin::psbt may reorder unknown fields,
        // but the decoded packet must serialize to the same bytes.
        let round_tripped = VPacket::from_psbt(&psbt)
            .unwrap_or_else(|e| {
                panic!("{}: from_psbt failed: {}", context, e)
            });
        assert_bytes_equal(
            &round_tripped.serialize().expect("reencode"),
            &expected_bytes,
            &context,
        );
        interop_count += 1;
    }

    assert!(
        interop_count >= 1,
        "expected at least one case to round-trip through bitcoin::psbt"
    );
}

/// Error cases: building the packet from JSON must fail with the
/// expected message, matching Go's mock `ToVPacket` panics.
#[test]
fn vpsbt_error_vectors() {
    let file: VPsbtVectorFile = load_json(ERROR_CASES);
    let cases = file.error_test_cases.expect("no error test cases");
    assert!(!cases.is_empty());

    for (idx, case) in cases.iter().enumerate() {
        let comment = case.comment.as_deref().unwrap_or("");
        let result = build_vpacket(&case.packet);
        match result {
            Err(err) => assert!(
                err.contains(&case.error),
                "case {} ({}): expected error containing {:?}, got {:?}",
                idx,
                comment,
                case.error,
                err
            ),
            Ok(_) => panic!(
                "case {} ({}): expected error {:?}, but build succeeded",
                idx, comment, case.error
            ),
        }
    }
}

/// Garbage and truncated inputs must fail to decode, not panic.
#[test]
fn vpsbt_decode_rejects_invalid() {
    assert!(VPacket::from_raw_bytes(b"").is_err());
    assert!(VPacket::from_raw_bytes(b"psbt").is_err());
    assert!(VPacket::from_raw_bytes(b"not a psbt at all").is_err());
    assert!(VPacket::from_base64("!!!not base64!!!").is_err());

    // A valid PSBT prefix but truncated payload.
    let file: VPsbtVectorFile = load_json(GENERATED);
    let cases = file.valid_test_cases.expect("no valid test cases");
    let bytes = b64_decode(&cases[0].expected);
    assert!(VPacket::from_raw_bytes(&bytes[..bytes.len() / 2]).is_err());

    // A regular (non-virtual) PSBT must be rejected.
    let mut plain = Vec::new();
    plain.extend_from_slice(&[0x70, 0x73, 0x62, 0x74, 0xff]);
    // Global: unsigned tx with no inputs/outputs, then separator.
    let tx: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, // version
        0x00, // no inputs
        0x00, // no outputs
        0x00, 0x00, 0x00, 0x00, // lock time
    ];
    plain.push(0x01);
    plain.push(0x00);
    plain.push(tx.len() as u8);
    plain.extend_from_slice(tx);
    plain.push(0x00);
    assert!(VPacket::from_raw_bytes(&plain).is_err());
}
