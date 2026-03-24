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
//! Exchange rates between assets and BTC are represented as fixed-point
//! numbers to avoid floating-point precision issues.

/// A fixed-point number with configurable decimal places.
///
/// Internally stores the value as `mantissa * 10^(-scale)`.
/// For example, a price of "1.50" msat per asset unit would be
/// `FixedPoint { mantissa: 150, scale: 2 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedPoint {
    /// The integer mantissa.
    pub mantissa: u128,
    /// Number of decimal places.
    pub scale: u8,
}

impl FixedPoint {
    /// Creates a new fixed-point number.
    pub fn new(mantissa: u128, scale: u8) -> Self {
        FixedPoint { mantissa, scale }
    }

    /// Creates a fixed-point number from an integer (scale = 0).
    pub fn from_integer(value: u64) -> Self {
        FixedPoint {
            mantissa: value as u128,
            scale: 0,
        }
    }

    /// Returns the value as a u64, truncating any fractional part.
    pub fn to_integer(&self) -> u64 {
        let divisor = 10u128.pow(self.scale as u32);
        (self.mantissa / divisor) as u64
    }

    /// Multiplies this fixed-point by a u64 integer, returning a u64 result
    /// (truncating fractional part).
    ///
    /// Useful for: `asset_amount = msat_amount * rate`
    pub fn mul_integer(&self, value: u64) -> u64 {
        let result = self.mantissa * (value as u128);
        let divisor = 10u128.pow(self.scale as u32);
        (result / divisor) as u64
    }

    /// Divides a u64 integer by this fixed-point, returning a u64 result.
    ///
    /// Useful for: `msat_amount = asset_amount / rate`
    pub fn div_into_integer(&self, value: u64) -> u64 {
        if self.mantissa == 0 {
            return 0;
        }
        let scaled_value =
            (value as u128) * 10u128.pow(self.scale as u32);
        (scaled_value / self.mantissa) as u64
    }

    /// Converts this price to msat amount for a given asset amount.
    ///
    /// `msat = asset_amount * price_msat_per_unit`
    pub fn asset_to_msat(&self, asset_amount: u64) -> u64 {
        self.mul_integer(asset_amount)
    }

    /// Converts an msat amount to asset units at this price.
    ///
    /// `asset_amount = msat / price_msat_per_unit`
    pub fn msat_to_asset(&self, msat_amount: u64) -> u64 {
        self.div_into_integer(msat_amount)
    }
}

impl std::fmt::Display for FixedPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scale == 0 {
            write!(f, "{}", self.mantissa)
        } else {
            let divisor = 10u128.pow(self.scale as u32);
            let integer_part = self.mantissa / divisor;
            let frac_part = self.mantissa % divisor;
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
        assert_eq!(fp.to_integer(), 42);
    }

    #[test]
    fn test_fixed_point_display() {
        let fp = FixedPoint::new(150, 2);
        assert_eq!(format!("{}", fp), "1.50");

        let fp2 = FixedPoint::new(1000, 3);
        assert_eq!(format!("{}", fp2), "1.000");
    }

    #[test]
    fn test_mul_integer() {
        // Price: 1.50 msat per asset unit.
        let price = FixedPoint::new(150, 2);
        // 100 asset units * 1.50 = 150 msat.
        assert_eq!(price.mul_integer(100), 150);
    }

    #[test]
    fn test_div_into_integer() {
        // Price: 2.00 msat per asset unit.
        let price = FixedPoint::new(200, 2);
        // 1000 msat / 2.00 = 500 asset units.
        assert_eq!(price.div_into_integer(1000), 500);
    }

    #[test]
    fn test_asset_to_msat() {
        // 1 asset unit = 5000 msat.
        let price = FixedPoint::from_integer(5000);
        assert_eq!(price.asset_to_msat(10), 50_000);
    }

    #[test]
    fn test_msat_to_asset() {
        // 1 asset unit = 5000 msat.
        let price = FixedPoint::from_integer(5000);
        assert_eq!(price.msat_to_asset(50_000), 10);
    }

    #[test]
    fn test_zero_price() {
        let price = FixedPoint::new(0, 0);
        assert_eq!(price.div_into_integer(1000), 0);
    }

    #[test]
    fn test_fractional_truncation() {
        // 3.33 msat per unit.
        let price = FixedPoint::new(333, 2);
        // 10 * 3.33 = 33.3 → truncated to 33.
        assert_eq!(price.mul_integer(10), 33);
    }
}
