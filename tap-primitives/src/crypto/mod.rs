// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Cryptographic operations for Taproot Assets.
//!
//! - [`keys`]: Key derivation, taproot tweaking, group key computation
//! - [`schnorr`]: BIP-340 Schnorr signature verification for asset witnesses

pub mod derivation;
pub mod keys;
pub mod schnorr;
pub mod tapscript;
pub mod virtual_tx;

pub use keys::{
    compute_group_key, compute_taproot_output_key, parse_pub_key,
    serialize_pub_key, tweak_pub_key,
};
pub use schnorr::SchnorrWitnessValidator;
pub use tapscript::{
    create_tap_output_script, tap_branch_hash, tap_leaf_hash,
    taproot_output_key,
};
pub use virtual_tx::{
    input_key_spend_sighash, virtual_tx, virtual_tx_in, virtual_tx_in_prevout,
    virtual_tx_out, virtual_tx_with_input, VirtualTxError,
};
