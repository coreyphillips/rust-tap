// Property-based tests for encoding modules.

use proptest::prelude::*;
use tap_primitives::encoding::bigsize::{decode_bigsize, encode_bigsize};
use tap_primitives::encoding::tlv::{TlvRecord, TlvStream};

proptest! {
    /// BigSize encode/decode roundtrip for all u64 values.
    #[test]
    fn bigsize_roundtrip(val in any::<u64>()) {
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, val);
        let (decoded, consumed) = decode_bigsize(&buf).unwrap();
        prop_assert_eq!(decoded, val);
        prop_assert_eq!(consumed, buf.len());
    }

    /// TLV stream encode/decode roundtrip with arbitrary records.
    #[test]
    fn tlv_stream_roundtrip(
        type_nums in prop::collection::vec(0..1000u64, 1..10),
        values in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..100), 1..10),
    ) {
        // Deduplicate type numbers.
        let mut unique_types: Vec<u64> = type_nums.into_iter().collect();
        unique_types.sort();
        unique_types.dedup();

        let mut stream = TlvStream::new();
        let count = unique_types.len().min(values.len());
        for i in 0..count {
            stream.push(TlvRecord::new(unique_types[i], values[i].clone()));
        }

        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).unwrap();

        // Records should be sorted by type number.
        let records = decoded.records();
        prop_assert_eq!(records.len(), count);

        for i in 0..count {
            prop_assert_eq!(records[i].type_num, unique_types[i]);
            prop_assert_eq!(&records[i].value, &values[i]);
        }
    }

    /// BigSize encoding is canonical (no redundant bytes).
    #[test]
    fn bigsize_canonical(val in any::<u64>()) {
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, val);

        // Check expected encoding lengths.
        match val {
            0..=0xFC => prop_assert_eq!(buf.len(), 1),
            0xFD..=0xFFFF => prop_assert_eq!(buf.len(), 3),
            0x10000..=0xFFFFFFFF => prop_assert_eq!(buf.len(), 5),
            _ => prop_assert_eq!(buf.len(), 9),
        }
    }

    /// TLV records maintain sorted order after roundtrip.
    #[test]
    fn tlv_sorted_after_roundtrip(
        mut types in prop::collection::vec(0..10000u64, 2..8),
    ) {
        types.sort();
        types.dedup();
        if types.len() < 2 {
            return Ok(());
        }

        let mut stream = TlvStream::new();
        // Insert in reverse order.
        for &t in types.iter().rev() {
            stream.push(TlvRecord::u8(t, 0x42));
        }

        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).unwrap();
        let result_types: Vec<u64> =
            decoded.records().iter().map(|r| r.type_num).collect();

        prop_assert_eq!(result_types, types);
    }
}
