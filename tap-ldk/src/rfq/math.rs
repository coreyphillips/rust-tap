// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Fixed-point arithmetic for RFQ exchange rate calculations.
//!
//! Mirrors Go's `rfqmath.BigIntFixedPoint`: a value is represented as
//! `coefficient * 10^(-scale)`. Exchange rates are expressed as *asset
//! units per BTC* (NOT msat per unit), matching Go's `rfqmsg.AssetRate`.
//!
//! The wire encoding (`TlvFixedPoint` in Go `rfqmsg/records.go`) is a
//! `u8` scale followed by the minimal big-endian coefficient bytes
//! (leading zeros trimmed; a zero coefficient encodes as zero bytes).
//!
//! Go uses arbitrary-precision integers for the conversion math. This
//! implementation uses checked `u128` arithmetic and returns
//! [`FixedPointError::Overflow`] where Go would keep going; for all
//! realistic asset amounts and rates the results are identical.

/// Number of milli-satoshis in one bitcoin (Go `rfqmsg.MilliSatPerBtc`).
pub const MSAT_PER_BTC: u128 = 100_000_000_000;

/// The default scale used for arithmetic operations, matching Go
/// `rfqmath.defaultArithmeticScale`.
const DEFAULT_ARITHMETIC_SCALE: u8 = 11;

/// Maximum number of coefficient bytes accepted when decoding a
/// `TlvFixedPoint` (a `u128` holds at most 16 big-endian bytes).
pub const MAX_COEFFICIENT_BYTES: usize = 16;

/// Errors from fixed-point operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedPointError {
    /// Arithmetic overflowed the u128 working type. Go uses big
    /// integers here; values this large are rejected instead.
    Overflow,
    /// Division by a zero rate coefficient.
    DivisionByZero,
    /// The encoded coefficient does not fit into a u128.
    CoefficientTooLarge(usize),
    /// The encoded value is empty (missing the scale byte).
    MissingScale,
}

impl std::fmt::Display for FixedPointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixedPointError::Overflow => {
                write!(f, "fixed-point arithmetic overflow")
            }
            FixedPointError::DivisionByZero => {
                write!(f, "fixed-point division by zero")
            }
            FixedPointError::CoefficientTooLarge(n) => {
                write!(
                    f,
                    "fixed-point coefficient too large: {} bytes (max {})",
                    n, MAX_COEFFICIENT_BYTES
                )
            }
            FixedPointError::MissingScale => {
                write!(f, "fixed-point value missing scale byte")
            }
        }
    }
}

impl std::error::Error for FixedPointError {}

/// A fixed-point number, `coefficient * 10^(-scale)`.
///
/// Matches the representation of Go's `rfqmath.FixedPoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedPoint {
    /// The integer coefficient.
    pub coefficient: u128,
    /// Number of decimal places.
    pub scale: u8,
}

/// Returns 10^exp as u128 if it fits.
fn pow10(exp: u8) -> Result<u128, FixedPointError> {
    10u128
        .checked_pow(exp as u32)
        .ok_or(FixedPointError::Overflow)
}

impl FixedPoint {
    /// Creates a new fixed-point number from a raw coefficient and scale
    /// (Go `rfqmath.NewBigIntFixedPoint`).
    pub fn new(coefficient: u128, scale: u8) -> Self {
        FixedPoint { coefficient, scale }
    }

    /// Creates a fixed-point representing the integer `value` at the
    /// given scale (Go `rfqmath.FixedPointFromUint64`): the coefficient
    /// is `value * 10^scale`.
    pub fn from_scaled_value(
        value: u64,
        scale: u8,
    ) -> Result<Self, FixedPointError> {
        let coefficient = (value as u128)
            .checked_mul(pow10(scale)?)
            .ok_or(FixedPointError::Overflow)?;
        Ok(FixedPoint { coefficient, scale })
    }

    /// Creates a fixed-point number from an integer (scale = 0).
    pub fn from_integer(value: u64) -> Self {
        FixedPoint {
            coefficient: value as u128,
            scale: 0,
        }
    }

    /// Returns true if the coefficient is zero.
    pub fn is_zero(&self) -> bool {
        self.coefficient == 0
    }

    /// Returns the value truncated to an integer (Go `ScaleTo(0)` then
    /// `ToUint64`), erroring if it does not fit in a u64.
    pub fn to_u64_floor(&self) -> Result<u64, FixedPointError> {
        let divisor = pow10(self.scale)?;
        let v = self.coefficient / divisor;
        u64::try_from(v).map_err(|_| FixedPointError::Overflow)
    }

    /// Re-scales the value, truncating when scaling down (Go
    /// `FixedPoint.ScaleTo`).
    pub fn scale_to(&self, new_scale: u8) -> Result<Self, FixedPointError> {
        let coefficient = if new_scale == self.scale {
            self.coefficient
        } else if new_scale > self.scale {
            self.coefficient
                .checked_mul(pow10(new_scale - self.scale)?)
                .ok_or(FixedPointError::Overflow)?
        } else {
            self.coefficient / pow10(self.scale - new_scale)?
        };
        Ok(FixedPoint {
            coefficient,
            scale: new_scale,
        })
    }

    /// Encodes as a Go-compatible `TlvFixedPoint` value: a `u8` scale
    /// followed by the minimal big-endian coefficient bytes (leading
    /// zeros trimmed; zero encodes as no bytes).
    pub fn encode_tlv(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        buf.push(self.scale);
        let be = self.coefficient.to_be_bytes();
        let first_non_zero = be.iter().position(|&b| b != 0);
        if let Some(pos) = first_non_zero {
            buf.extend_from_slice(&be[pos..]);
        }
        buf
    }

    /// Decodes a Go-compatible `TlvFixedPoint` value. Coefficients
    /// longer than 16 bytes (which cannot fit in a u128) are rejected.
    pub fn decode_tlv(data: &[u8]) -> Result<Self, FixedPointError> {
        if data.is_empty() {
            return Err(FixedPointError::MissingScale);
        }
        let scale = data[0];
        let coeff_bytes = &data[1..];
        if coeff_bytes.len() > MAX_COEFFICIENT_BYTES {
            return Err(FixedPointError::CoefficientTooLarge(
                coeff_bytes.len(),
            ));
        }
        let mut be = [0u8; 16];
        be[16 - coeff_bytes.len()..].copy_from_slice(coeff_bytes);
        Ok(FixedPoint {
            coefficient: u128::from_be_bytes(be),
            scale,
        })
    }
}

/// Converts asset units to milli-satoshis given a rate in units per BTC,
/// mirroring Go `rfqmath.UnitsToMilliSatoshi` (including its truncation
/// points):
///
/// `msat = (units / units_per_btc) * 100_000_000_000`
pub fn units_to_milli_satoshi(
    asset_units: u64,
    units_per_btc: &FixedPoint,
) -> Result<u64, FixedPointError> {
    if units_per_btc.coefficient == 0 {
        return Err(FixedPointError::DivisionByZero);
    }

    let s = DEFAULT_ARITHMETIC_SCALE.max(units_per_btc.scale);
    let ten_s = pow10(s)?;

    // assetUnits.ScaleTo(s) from scale 0.
    let units_scaled = (asset_units as u128)
        .checked_mul(ten_s)
        .ok_or(FixedPointError::Overflow)?;

    // unitsPerBtc.ScaleTo(s).
    let rate_scaled = units_per_btc
        .coefficient
        .checked_mul(pow10(s - units_per_btc.scale)?)
        .ok_or(FixedPointError::Overflow)?;

    // amtBTC = units.Div(rate) at scale s: floor(a * 10^s / b).
    let amt_btc = units_scaled
        .checked_mul(ten_s)
        .ok_or(FixedPointError::Overflow)?
        / rate_scaled;

    // amtMsat = amtBTC.Mul(oneBtcInMilliSat) at scale s. Go computes
    // floor(amtBTC * (MSAT_PER_BTC * 10^s) / 10^s), which is exactly
    // amtBTC * MSAT_PER_BTC because the 10^s factors cancel.
    let amt_msat = amt_btc
        .checked_mul(MSAT_PER_BTC)
        .ok_or(FixedPointError::Overflow)?;

    // ScaleTo(0).
    let msat = amt_msat / ten_s;
    u64::try_from(msat).map_err(|_| FixedPointError::Overflow)
}

/// Converts milli-satoshis to asset units given a rate in units per BTC,
/// mirroring Go `rfqmath.MilliSatoshiToUnits` followed by
/// `ScaleTo(0).ToUint64()`:
///
/// `units = (msat / 100_000_000_000) * units_per_btc`
pub fn milli_satoshi_to_units(
    milli_sat: u64,
    units_per_btc: &FixedPoint,
) -> Result<u64, FixedPointError> {
    let s = DEFAULT_ARITHMETIC_SCALE.max(units_per_btc.scale);
    let ten_s = pow10(s)?;

    // mSatFixed = FixedPointFromUint64(msat, s): coeff = msat * 10^s.
    // oneBtcInMilliSat = FixedPointFromUint64(MSAT_PER_BTC, s).
    // amtBTC = mSatFixed.Div(oneBtcInMilliSat)
    //        = floor(msat * 10^s * 10^s / (MSAT_PER_BTC * 10^s))
    //        = floor(msat * 10^s / MSAT_PER_BTC).
    let amt_btc = (milli_sat as u128)
        .checked_mul(ten_s)
        .ok_or(FixedPointError::Overflow)?
        / MSAT_PER_BTC;

    // amtUnits = amtBTC.Mul(rate.ScaleTo(s))
    //          = floor(amtBTC * rate.coeff * 10^(s - rate.scale) / 10^s)
    //          = floor(amtBTC * rate.coeff / 10^rate.scale).
    let amt_units = amt_btc
        .checked_mul(units_per_btc.coefficient)
        .ok_or(FixedPointError::Overflow)?
        / pow10(units_per_btc.scale)?;

    // scaledAmt = amtUnits.ScaleTo(rate.scale): floor divide by
    // 10^(s - rate.scale), then ScaleTo(0): floor divide by
    // 10^rate.scale.
    let units_at_rate_scale = amt_units / pow10(s - units_per_btc.scale)?;
    let units = units_at_rate_scale / pow10(units_per_btc.scale)?;

    u64::try_from(units).map_err(|_| FixedPointError::Overflow)
}

impl std::fmt::Display for FixedPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scale == 0 {
            write!(f, "{}", self.coefficient)
        } else {
            let divisor = match pow10(self.scale) {
                Ok(d) => d,
                Err(_) => return write!(f, "{}e-{}", self.coefficient, self.scale),
            };
            let integer_part = self.coefficient / divisor;
            let frac_part = self.coefficient % divisor;
            write!(
                f,
                "{}.{:0>width$}",
                integer_part,
                frac_part,
                width = self.scale as usize
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_integer() {
        let fp = FixedPoint::from_integer(42);
        assert_eq!(fp.to_u64_floor().unwrap(), 42);
    }

    #[test]
    fn test_display() {
        let fp = FixedPoint::new(150, 2);
        assert_eq!(format!("{}", fp), "1.50");
        let fp2 = FixedPoint::new(1000, 3);
        assert_eq!(format!("{}", fp2), "1.000");
    }

    #[test]
    fn test_scale_to() {
        let fp = FixedPoint::new(150, 2); // 1.50
        assert_eq!(fp.scale_to(4).unwrap(), FixedPoint::new(15000, 4));
        assert_eq!(fp.scale_to(1).unwrap(), FixedPoint::new(15, 1));
        assert_eq!(fp.scale_to(0).unwrap(), FixedPoint::new(1, 0));
    }

    #[test]
    fn test_encode_tlv_matches_go_fixture() {
        // From Go rfqmsg/testdata/compat/v0.8/accept.hex: the in-asset
        // rate record value is 02 a4 10 (scale 2, coefficient 42000).
        let fp = FixedPoint::new(42000, 2);
        assert_eq!(fp.encode_tlv(), vec![0x02, 0xa4, 0x10]);

        // Out-asset rate record value is 00 01 (scale 0, coefficient 1).
        let fp2 = FixedPoint::new(1, 0);
        assert_eq!(fp2.encode_tlv(), vec![0x00, 0x01]);
    }

    #[test]
    fn test_encode_tlv_zero_coefficient() {
        // Zero coefficient trims to no bytes (Go BigInt.Bytes() is empty).
        let fp = FixedPoint::new(0, 5);
        assert_eq!(fp.encode_tlv(), vec![0x05]);
        let decoded = FixedPoint::decode_tlv(&[0x05]).unwrap();
        assert_eq!(decoded, fp);
    }

    #[test]
    fn test_decode_tlv_roundtrip() {
        let cases = [
            FixedPoint::new(0, 0),
            FixedPoint::new(1, 0),
            FixedPoint::new(42000, 2),
            FixedPoint::new(u128::MAX, 18),
            FixedPoint::new(100_000_000_000, 0),
        ];
        for fp in cases {
            let encoded = fp.encode_tlv();
            let decoded = FixedPoint::decode_tlv(&encoded).unwrap();
            assert_eq!(fp, decoded);
        }
    }

    #[test]
    fn test_decode_tlv_errors() {
        assert_eq!(
            FixedPoint::decode_tlv(&[]),
            Err(FixedPointError::MissingScale)
        );
        // 17 coefficient bytes cannot fit in a u128.
        let mut data = vec![0x00];
        data.extend_from_slice(&[0xff; 17]);
        assert_eq!(
            FixedPoint::decode_tlv(&data),
            Err(FixedPointError::CoefficientTooLarge(17))
        );
        // Exactly 16 bytes is fine.
        let mut data16 = vec![0x00];
        data16.extend_from_slice(&[0xff; 16]);
        assert_eq!(
            FixedPoint::decode_tlv(&data16).unwrap(),
            FixedPoint::new(u128::MAX, 0)
        );
    }

    #[test]
    fn test_units_to_msat() {
        // Rate: 20,000,000 units per BTC. 1 unit = 1e11 / 2e7 = 5000 msat.
        let rate = FixedPoint::new(20_000_000, 0);
        assert_eq!(units_to_milli_satoshi(10, &rate).unwrap(), 50_000);
        assert_eq!(units_to_milli_satoshi(200, &rate).unwrap(), 1_000_000);
    }

    #[test]
    fn test_msat_to_units() {
        let rate = FixedPoint::new(20_000_000, 0);
        assert_eq!(milli_satoshi_to_units(50_000, &rate).unwrap(), 10);
        assert_eq!(milli_satoshi_to_units(500_000, &rate).unwrap(), 100);
    }

    #[test]
    fn test_conversion_with_scaled_rate() {
        // Rate 42000 units per BTC with scale 2 (coefficient 4,200,000):
        // matches Go NewBigIntFixedPoint(4_200_000, 2) = 42000.00.
        let rate = FixedPoint::new(4_200_000, 2);
        // 42000 units = exactly 1 BTC = 1e11 msat.
        assert_eq!(
            units_to_milli_satoshi(42_000, &rate).unwrap(),
            100_000_000_000
        );
        assert_eq!(
            milli_satoshi_to_units(100_000_000_000, &rate).unwrap(),
            42_000
        );
    }

    #[test]
    fn test_go_rfqmath_parity_case() {
        // Mirrors Go rfqmath conversion semantics: 5,000,000 units per
        // BTC; 1 unit = 20,000 msat.
        let rate = FixedPoint::new(5_000_000, 0);
        assert_eq!(units_to_milli_satoshi(1, &rate).unwrap(), 20_000);
        assert_eq!(milli_satoshi_to_units(20_000, &rate).unwrap(), 1);
        // Truncation: 19,999 msat is just below one unit.
        assert_eq!(milli_satoshi_to_units(19_999, &rate).unwrap(), 0);
    }

    #[test]
    fn test_zero_rate() {
        let rate = FixedPoint::new(0, 0);
        assert_eq!(
            units_to_milli_satoshi(1000, &rate),
            Err(FixedPointError::DivisionByZero)
        );
        // MilliSatoshiToUnits with a zero rate yields zero units in Go.
        assert_eq!(milli_satoshi_to_units(1000, &rate).unwrap(), 0);
    }

    #[test]
    fn test_overflow_detected() {
        let rate = FixedPoint::new(1, 0);
        // u64::MAX units at 1 unit/BTC = u64::MAX * 1e11 msat, which
        // does not fit into a u64 result.
        assert!(units_to_milli_satoshi(u64::MAX, &rate).is_err());
    }
}
