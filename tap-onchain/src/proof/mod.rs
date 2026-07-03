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
pub mod mailbox;
pub mod merkle;
pub mod suffix;
pub mod transition;

pub use courier::{
    AnnotatedProof, Courier, CourierError, CourierKind, CourierLocator,
    MockCourier, Recipient, deliver_transfer_proofs,
};
pub use mailbox::{
    build_send_fragment, build_tx_proof, decrypt_send_fragment,
    deliver_send_manifest, remove_message_challenge, MailboxError,
    MailboxMessage, MailboxSigner, MailboxTransport, MessageFilter,
    MockTransport, SendManifest, SoftMailboxSigner, MSG_MAX_SIZE,
};
pub use exclusion::{generate_exclusion_proofs, AnchorOutputInfo};
pub use generate::generate_genesis_proof;
pub use merkle::build_tx_merkle_proof;
pub use suffix::{
    create_proof_suffix, create_proof_suffix_with_options,
    update_proof_chain_data, Bip86Output, OutputProofInfo,
    ProofSuffixOptions,
};
#[allow(deprecated)]
pub use transition::{append_transition, generate_transition_proof};
pub use transition::{BaseProofParams, TransitionProofParams};
