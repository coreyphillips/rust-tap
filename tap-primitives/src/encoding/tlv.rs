// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TLV stream encoding/decoding compatible with LND's `tlv` package.

use super::bigsize::{decode_bigsize, encode_bigsize};

/// Errors from TLV operations.
#[derive(Debug, Clone)]
pub enum TlvError {
    UnexpectedEof,
    NonCanonicalBigSize,
    TypeNotSorted { prev: u64, current: u64 },
    DuplicateType(u64),
    UnknownRequiredType(u64),
    ValueTooLarge { type_num: u64, len: u64 },
    DecodingError(String),
}

impl std::fmt::Display for TlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvError::UnexpectedEof => write!(f, "unexpected end of data"),
            TlvError::NonCanonicalBigSize => {
                write!(f, "non-canonical BigSize encoding")
            }
            TlvError::TypeNotSorted { prev, current } => {
                write!(f, "TLV types not sorted: {} >= {}", prev, current)
            }
            TlvError::DuplicateType(t) => {
                write!(f, "duplicate TLV type: {}", t)
            }
            TlvError::UnknownRequiredType(t) => {
                write!(f, "unknown required (even) TLV type: {}", t)
            }
            TlvError::ValueTooLarge { type_num, len } => {
                write!(f, "TLV type {} value too large: {} bytes", type_num, len)
            }
            TlvError::DecodingError(msg) => {
                write!(f, "TLV decoding error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TlvError {}

/// A single TLV record (type number + raw value bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvRecord {
    /// The type number.
    pub type_num: u64,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

impl TlvRecord {
    pub fn new(type_num: u64, value: Vec<u8>) -> Self {
        TlvRecord { type_num, value }
    }

    /// Creates a record with a big-endian u8 value.
    pub fn u8(type_num: u64, val: u8) -> Self {
        TlvRecord::new(type_num, vec![val])
    }

    /// Creates a record with a big-endian u16 value.
    pub fn u16(type_num: u64, val: u16) -> Self {
        TlvRecord::new(type_num, val.to_be_bytes().to_vec())
    }

    /// Creates a record with a big-endian u32 value.
    pub fn u32(type_num: u64, val: u32) -> Self {
        TlvRecord::new(type_num, val.to_be_bytes().to_vec())
    }

    /// Creates a record with a big-endian u64 value.
    pub fn u64(type_num: u64, val: u64) -> Self {
        TlvRecord::new(type_num, val.to_be_bytes().to_vec())
    }

    /// Creates a record with a BigSize-encoded u64 value.
    pub fn varint(type_num: u64, val: u64) -> Self {
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, val);
        TlvRecord::new(type_num, buf)
    }

    /// Creates a record with raw bytes.
    pub fn bytes(type_num: u64, val: &[u8]) -> Self {
        TlvRecord::new(type_num, val.to_vec())
    }

    /// Decodes the value as a big-endian u8.
    pub fn as_u8(&self) -> Result<u8, TlvError> {
        if self.value.len() != 1 {
            return Err(TlvError::DecodingError(format!(
                "expected 1 byte for u8, got {}",
                self.value.len()
            )));
        }
        Ok(self.value[0])
    }

    /// Decodes the value as a big-endian u16.
    pub fn as_u16(&self) -> Result<u16, TlvError> {
        if self.value.len() != 2 {
            return Err(TlvError::DecodingError(format!(
                "expected 2 bytes for u16, got {}",
                self.value.len()
            )));
        }
        Ok(u16::from_be_bytes(self.value[..2].try_into().unwrap()))
    }

    /// Decodes the value as a big-endian u32.
    pub fn as_u32(&self) -> Result<u32, TlvError> {
        if self.value.len() != 4 {
            return Err(TlvError::DecodingError(format!(
                "expected 4 bytes for u32, got {}",
                self.value.len()
            )));
        }
        Ok(u32::from_be_bytes(self.value[..4].try_into().unwrap()))
    }

    /// Decodes the value as a big-endian u64.
    pub fn as_u64(&self) -> Result<u64, TlvError> {
        if self.value.len() != 8 {
            return Err(TlvError::DecodingError(format!(
                "expected 8 bytes for u64, got {}",
                self.value.len()
            )));
        }
        Ok(u64::from_be_bytes(self.value[..8].try_into().unwrap()))
    }

    /// Decodes the value as a BigSize varint.
    pub fn as_varint(&self) -> Result<u64, TlvError> {
        let (val, _) = decode_bigsize(&self.value)?;
        Ok(val)
    }

    /// Returns true if this is an odd (optional) type.
    pub fn is_odd(&self) -> bool {
        self.type_num % 2 == 1
    }
}

/// Default maximum allowed length for a single TLV value.
///
/// This prevents memory exhaustion from maliciously crafted inputs. The
/// default matches Go's `MaxAssetEncodeSizeBytes` (the maximum block
/// weight, 4,000,000 bytes). Contexts with larger legitimate values
/// (e.g. proofs, which Go caps at 128 MiB) should use
/// `TlvStream::decode_with_limit`.
pub const MAX_TLV_VALUE_LENGTH: u64 = 4_000_000;

/// Maximum size of a single proof TLV value (128 MiB), matching Go's
/// `FileMaxProofSizeBytes`.
pub const MAX_PROOF_TLV_VALUE_LENGTH: u64 = 128 * 1024 * 1024;

/// An ordered sequence of TLV records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlvStream {
    records: Vec<TlvRecord>,
}

impl TlvStream {
    pub fn new() -> Self {
        TlvStream {
            records: Vec::new(),
        }
    }

    /// Adds a record to the stream. Records will be sorted on encode.
    pub fn push(&mut self, record: TlvRecord) {
        self.records.push(record);
    }

    /// Adds a record only if the condition is true.
    pub fn push_if(&mut self, record: TlvRecord, condition: bool) {
        if condition {
            self.records.push(record);
        }
    }

    /// Returns the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Looks up a record by type number.
    pub fn get(&self, type_num: u64) -> Option<&TlvRecord> {
        self.records.iter().find(|r| r.type_num == type_num)
    }

    /// Returns all records as a slice.
    pub fn records(&self) -> &[TlvRecord] {
        &self.records
    }

    /// Encodes the TLV stream to bytes.
    ///
    /// Records are sorted by type number in ascending order before encoding.
    /// Format: `[type BigSize][length BigSize][value bytes]` per record.
    pub fn encode(&self) -> Vec<u8> {
        let mut sorted = self.records.clone();
        sorted.sort_by_key(|r| r.type_num);

        let mut buf = Vec::new();
        for record in &sorted {
            encode_bigsize(&mut buf, record.type_num);
            encode_bigsize(&mut buf, record.value.len() as u64);
            buf.extend_from_slice(&record.value);
        }
        buf
    }

    /// Decodes a TLV stream from bytes with the default value size limit.
    ///
    /// Validates that types are strictly ascending (no duplicates).
    /// Unknown even (required) types cause an error.
    /// Unknown odd (optional) types are preserved.
    pub fn decode(data: &[u8]) -> Result<Self, TlvError> {
        Self::decode_with_limit(data, MAX_TLV_VALUE_LENGTH)
    }

    /// Decodes a TLV stream from bytes, rejecting any single value
    /// longer than `max_value_len` bytes.
    pub fn decode_with_limit(
        data: &[u8],
        max_value_len: u64,
    ) -> Result<Self, TlvError> {
        let mut stream = TlvStream::new();
        let mut offset = 0;
        let mut last_type: Option<u64> = None;

        while offset < data.len() {
            // Read type.
            let (type_num, consumed) = decode_bigsize(&data[offset..])?;
            offset += consumed;

            // Read length.
            let (length, consumed) = decode_bigsize(&data[offset..])?;
            offset += consumed;

            // Reject excessively large values to prevent memory exhaustion.
            if length > max_value_len {
                return Err(TlvError::ValueTooLarge {
                    type_num,
                    len: length,
                });
            }

            // Read value.
            let length = length as usize;
            if offset + length > data.len() {
                return Err(TlvError::UnexpectedEof);
            }
            let value = data[offset..offset + length].to_vec();
            offset += length;

            // Validate ordering.
            if let Some(prev) = last_type {
                if type_num <= prev {
                    return Err(TlvError::TypeNotSorted {
                        prev,
                        current: type_num,
                    });
                }
            }
            last_type = Some(type_num);

            stream.push(TlvRecord { type_num, value });
        }

        Ok(stream)
    }
}

/// Encodes a value prefixed with its BigSize length (inline var bytes).
///
/// This matches Go's `InlineVarBytesEncoder`: `[BigSize(len)][bytes]`.
pub fn encode_var_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    encode_bigsize(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Decodes BigSize-prefixed bytes from data. Returns `(bytes, total_consumed)`.
pub fn decode_var_bytes(data: &[u8]) -> Result<(Vec<u8>, usize), TlvError> {
    let (len, consumed) = decode_bigsize(data)?;
    let len = len as usize;
    let start = consumed;
    if start + len > data.len() {
        return Err(TlvError::UnexpectedEof);
    }
    Ok((data[start..start + len].to_vec(), start + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_stream_encode_sorted() {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(4, 0x01));
        stream.push(TlvRecord::u8(0, 0x00));
        stream.push(TlvRecord::u8(2, 0xFF));

        let encoded = stream.encode();
        // Should be sorted: type 0, type 2, type 4.
        let decoded = TlvStream::decode(&encoded).unwrap();
        assert_eq!(decoded.records()[0].type_num, 0);
        assert_eq!(decoded.records()[1].type_num, 2);
        assert_eq!(decoded.records()[2].type_num, 4);
    }

    #[test]
    fn test_tlv_stream_roundtrip() {
        let mut stream = TlvStream::new();
        stream.push(TlvRecord::u8(0, 0x01));
        stream.push(TlvRecord::bytes(2, &[1, 2, 3, 4, 5]));
        stream.push(TlvRecord::u32(4, 42));
        stream.push(TlvRecord::varint(6, 1000));
        stream.push(TlvRecord::u64(8, u64::MAX));

        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).unwrap();

        assert_eq!(decoded.get(0).unwrap().as_u8().unwrap(), 0x01);
        assert_eq!(decoded.get(2).unwrap().value, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.get(4).unwrap().as_u32().unwrap(), 42);
        assert_eq!(decoded.get(6).unwrap().as_varint().unwrap(), 1000);
        assert_eq!(decoded.get(8).unwrap().as_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn test_tlv_duplicate_type_rejected() {
        // Manually construct bytes with duplicate type 0.
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, 0); // type 0
        encode_bigsize(&mut buf, 1); // length 1
        buf.push(0x01); // value
        encode_bigsize(&mut buf, 0); // type 0 again — invalid!
        encode_bigsize(&mut buf, 1);
        buf.push(0x02);

        assert!(matches!(
            TlvStream::decode(&buf),
            Err(TlvError::TypeNotSorted { .. })
        ));
    }

    #[test]
    fn test_tlv_out_of_order_rejected() {
        let mut buf = Vec::new();
        encode_bigsize(&mut buf, 4);
        encode_bigsize(&mut buf, 1);
        buf.push(0x01);
        encode_bigsize(&mut buf, 2); // type 2 after type 4 — invalid!
        encode_bigsize(&mut buf, 1);
        buf.push(0x02);

        assert!(matches!(
            TlvStream::decode(&buf),
            Err(TlvError::TypeNotSorted { .. })
        ));
    }

    #[test]
    fn test_var_bytes_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        encode_var_bytes(&mut buf, data);

        let (decoded, consumed) = decode_var_bytes(&buf).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_empty_stream() {
        let stream = TlvStream::new();
        let encoded = stream.encode();
        assert!(encoded.is_empty());

        let decoded = TlvStream::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_record_helpers() {
        let r = TlvRecord::u16(10, 0x1234);
        assert_eq!(r.as_u16().unwrap(), 0x1234);
        assert_eq!(r.value, vec![0x12, 0x34]); // big-endian
    }
}
