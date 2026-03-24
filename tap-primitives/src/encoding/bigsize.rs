// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Lightning BigSize varint encoding (BOLT #1).
//!
//! BigSize is the variable-length integer format used by the Lightning
//! Network for TLV type and length fields. Unlike Bitcoin's CompactSize,
//! multi-byte values use **big-endian** byte order.

use super::tlv::TlvError;

/// Encodes a u64 value as a BigSize varint, appending to `buf`.
pub fn encode_bigsize(buf: &mut Vec<u8>, val: u64) {
    match val {
        0..=0xFC => {
            buf.push(val as u8);
        }
        0xFD..=0xFFFF => {
            buf.push(0xFD);
            buf.extend_from_slice(&(val as u16).to_be_bytes());
        }
        0x10000..=0xFFFFFFFF => {
            buf.push(0xFE);
            buf.extend_from_slice(&(val as u32).to_be_bytes());
        }
        _ => {
            buf.push(0xFF);
            buf.extend_from_slice(&val.to_be_bytes());
        }
    }
}

/// Decodes a BigSize varint from `data`. Returns `(value, bytes_consumed)`.
pub fn decode_bigsize(data: &[u8]) -> Result<(u64, usize), TlvError> {
    if data.is_empty() {
        return Err(TlvError::UnexpectedEof);
    }
    match data[0] {
        0..=0xFC => Ok((data[0] as u64, 1)),
        0xFD => {
            if data.len() < 3 {
                return Err(TlvError::UnexpectedEof);
            }
            let val = u16::from_be_bytes([data[1], data[2]]) as u64;
            if val < 0xFD {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((val, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(TlvError::UnexpectedEof);
            }
            let val =
                u32::from_be_bytes(data[1..5].try_into().unwrap()) as u64;
            if val < 0x10000 {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((val, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(TlvError::UnexpectedEof);
            }
            let val = u64::from_be_bytes(data[1..9].try_into().unwrap());
            if val < 0x100000000 {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((val, 9))
        }
    }
}

/// Returns the encoded size of a BigSize varint for the given value.
pub fn bigsize_len(val: u64) -> usize {
    match val {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigsize_single_byte() {
        for v in [0u64, 1, 127, 252] {
            let mut buf = Vec::new();
            encode_bigsize(&mut buf, v);
            assert_eq!(buf.len(), 1);
            assert_eq!(buf[0], v as u8);
            let (decoded, consumed) = decode_bigsize(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn test_bigsize_two_byte() {
        for v in [253u64, 255, 1000, 0xFFFF] {
            let mut buf = Vec::new();
            encode_bigsize(&mut buf, v);
            assert_eq!(buf.len(), 3);
            assert_eq!(buf[0], 0xFD);
            let (decoded, consumed) = decode_bigsize(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 3);
        }
    }

    #[test]
    fn test_bigsize_four_byte() {
        for v in [0x10000u64, 0xFFFFFFFF] {
            let mut buf = Vec::new();
            encode_bigsize(&mut buf, v);
            assert_eq!(buf.len(), 5);
            assert_eq!(buf[0], 0xFE);
            let (decoded, consumed) = decode_bigsize(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, 5);
        }
    }

    #[test]
    fn test_bigsize_eight_byte() {
        let v = 0x100000000u64;
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, v);
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0xFF);
        let (decoded, consumed) = decode_bigsize(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 9);
    }

    #[test]
    fn test_bigsize_big_endian() {
        // 0xFD (253) should be encoded as FD 00 FD (big-endian).
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 0x00, 0xFD]);
    }

    #[test]
    fn test_non_canonical_rejected() {
        // 0xFD prefix but value < 0xFD → non-canonical.
        let bad = [0xFD, 0x00, 0x01];
        assert!(matches!(
            decode_bigsize(&bad),
            Err(TlvError::NonCanonicalBigSize)
        ));
    }

    #[test]
    fn test_roundtrip_all_boundaries() {
        for v in [0, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, u64::MAX] {
            let mut buf = Vec::new();
            encode_bigsize(&mut buf, v);
            let (decoded, consumed) = decode_bigsize(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, buf.len());
            assert_eq!(consumed, bigsize_len(v));
        }
    }
}
