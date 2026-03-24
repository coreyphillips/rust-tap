// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! TLV (Type-Length-Value) encoding framework compatible with LND's `tlv`
//! package.
//!
//! The wire format uses Lightning's BigSize varint encoding for type and
//! length fields. Records are sorted by type number in ascending order.
//!
//! ## BigSize Varint Format
//!
//! - `0x00..=0xFC`: single byte
//! - `0xFD`: followed by 2-byte big-endian u16 (value must be >= 0xFD)
//! - `0xFE`: followed by 4-byte big-endian u32 (value must be >= 0x10000)
//! - `0xFF`: followed by 8-byte big-endian u64 (value must be >= 0x100000000)

pub mod bigsize;
pub mod tlv;
pub mod asset;

pub use bigsize::{encode_bigsize, decode_bigsize};
pub use tlv::{TlvRecord, TlvStream, TlvError};
