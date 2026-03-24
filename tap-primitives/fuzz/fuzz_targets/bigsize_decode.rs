#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_primitives::encoding::bigsize::{decode_bigsize, encode_bigsize};

fuzz_target!(|data: &[u8]| {
    if let Ok((value, consumed)) = decode_bigsize(data) {
        // Re-encode and verify roundtrip.
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, value);
        let (decoded, _) = decode_bigsize(&buf).expect("re-encode should decode");
        assert_eq!(value, decoded);
        assert!(consumed <= data.len());
    }
});
