#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_ldk::channel::leaf_signer::{pack_aux_signatures, unpack_aux_signatures};

fuzz_target!(|data: &[u8]| {
    if let Ok(sigs) = unpack_aux_signatures(data) {
        // Re-pack and verify roundtrip.
        let packed = pack_aux_signatures(&sigs);
        let unpacked = unpack_aux_signatures(&packed).expect("re-pack should unpack");
        assert_eq!(sigs.len(), unpacked.len());
    }
});
