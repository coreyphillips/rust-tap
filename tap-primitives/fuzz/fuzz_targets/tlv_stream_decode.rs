#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_primitives::encoding::tlv::TlvStream;

fuzz_target!(|data: &[u8]| {
    if let Ok(stream) = TlvStream::decode(data) {
        // Re-encode and verify roundtrip.
        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).expect("re-encode should decode");
        assert_eq!(stream.records().len(), decoded.records().len());
    }
});
