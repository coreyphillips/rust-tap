#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_primitives::encoding::tlv::{decode_var_bytes, encode_var_bytes};

fuzz_target!(|data: &[u8]| {
    if let Ok((bytes, consumed)) = decode_var_bytes(data) {
        // Re-encode and verify roundtrip.
        let mut buf = Vec::new();
        encode_var_bytes(&mut buf, &bytes);
        let (decoded, _) = decode_var_bytes(&buf).expect("re-encode should decode");
        assert_eq!(bytes, decoded);
        assert!(consumed <= data.len());
    }
});
