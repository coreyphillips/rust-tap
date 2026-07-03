#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_ldk::channel::blobs::ChannelBlob;

fuzz_target!(|data: &[u8]| {
    if let Ok(blob) = ChannelBlob::decode(data) {
        // Re-encode and verify roundtrip. A successfully decoded blob
        // always carries proofs, so re-encoding cannot fail.
        let encoded = blob.encode().expect("decoded blob should re-encode");
        let decoded = ChannelBlob::decode(&encoded).expect("re-encode should decode");
        assert_eq!(blob.funded_assets.len(), decoded.funded_assets.len());
    }
});
