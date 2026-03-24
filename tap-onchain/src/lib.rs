// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! On-chain minting and transfer pipelines for Taproot Assets.
//!
//! This crate builds on [`tap_primitives`] to provide:
//! - [`mint`]: Asset minting pipeline (seedling → batch → confirmed)
//! - [`send`]: Asset transfer pipeline (coin selection → PSBT → broadcast)
//!
//! External systems provide implementations of the chain interaction traits
//! defined here (wallet, chain backend, key derivation, signing).

// Allow dead code during early development — public API items are used
// by consumers, not internally.
#![allow(dead_code)]

pub mod chain;
pub mod mint;
pub mod proof;
pub mod psbt;
pub mod send;
