// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Configuration for the TAP LDK integration layer.

/// Configuration parameters for TAP channel operations.
#[derive(Clone, Debug)]
pub struct TapConfig {
    /// Quote lifetime in seconds for RFQ accept messages.
    pub rfq_quote_lifetime_secs: u64,
    /// CSV delay in blocks applied to local force-close outputs.
    pub csv_delay_blocks: u16,
    /// Dust limit in satoshis for P2TR asset outputs.
    pub dust_limit_sat: u64,
}

impl Default for TapConfig {
    fn default() -> Self {
        TapConfig {
            rfq_quote_lifetime_secs: 3600,
            csv_delay_blocks: 144,
            dust_limit_sat: 330,
        }
    }
}
