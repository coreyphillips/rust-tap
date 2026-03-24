#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_ldk::channel::blobs::ChannelBlob;

fuzz_target!(|data: &[u8]| {
    if let Ok(blob) = ChannelBlob::decode(data) {
        // Re-encode and verify roundtrip.
        let encoded = blob.encode();
        let decoded = ChannelBlob::decode(&encoded).expect("re-encode should decode");
        assert_eq!(blob.funded_assets.len(), decoded.funded_assets.len());
    }
});
