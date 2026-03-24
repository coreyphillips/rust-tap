#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_primitives::proof::File;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = File::decode(data) {
        // Re-encode and verify roundtrip.
        let encoded = file.encode();
        let decoded = File::decode(&encoded).expect("re-encode should decode");
        assert_eq!(file.num_proofs(), decoded.num_proofs());
    }
});
