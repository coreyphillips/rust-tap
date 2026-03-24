#![no_main]
use libfuzzer_sys::fuzz_target;
use tap_primitives::crypto::tapscript::is_script_path_witness;

fuzz_target!(|data: &[u8]| {
    // Try parsing as a witness stack: split data into elements.
    if data.len() < 4 {
        return;
    }

    // Use first byte as number of elements (capped).
    let num_elements = (data[0] as usize % 5) + 1;
    let remaining = &data[1..];
    let chunk_size = remaining.len() / num_elements;
    if chunk_size == 0 {
        return;
    }

    let witness: Vec<Vec<u8>> = remaining
        .chunks(chunk_size)
        .take(num_elements)
        .map(|c| c.to_vec())
        .collect();

    // Just exercise the detection logic — should never panic.
    let _ = is_script_path_witness(&witness);
});
