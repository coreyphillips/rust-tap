// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof generation for confirmed Taproot Asset transactions.

pub mod backoff;
pub mod courier;
pub mod exclusion;
#[cfg(feature = "http-courier")]
pub mod http_courier;
pub mod generate;
pub mod merkle;
pub mod transition;

pub use courier::{
    AnnotatedProof, Courier, CourierError, CourierLocator, MockCourier,
    Recipient, deliver_transfer_proofs,
};
pub use exclusion::generate_exclusion_proofs;
pub use generate::generate_genesis_proof;
pub use merkle::build_tx_merkle_proof;
pub use transition::{
    append_transition, generate_transition_proof, BaseProofParams,
    TransitionProofParams,
};
