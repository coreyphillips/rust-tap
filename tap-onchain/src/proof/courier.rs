// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof courier system for delivering transition proofs to recipients.
//!
//! After a transfer is confirmed on-chain, the sender must deliver the
//! transition proof to the recipient so they can verify ownership. The
//! [`Courier`] trait abstracts the delivery mechanism.

use std::collections::HashMap;
use std::sync::Mutex;

use tap_primitives::address::AUTH_MAILBOX_UNI_RPC_COURIER_TYPE;
use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::proof;

/// The known proof courier kinds, identified by the courier URL scheme.
/// Mirrors Go's courier type constants in proof/courier.go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CourierKind {
    /// The hashmail courier (Go: `HashmailCourierType`, "hashmail").
    Hashmail,
    /// The universe RPC courier (Go: `UniverseRpcCourierType`,
    /// "universerpc").
    UniverseRpc,
    /// The authmailbox plus universe RPC courier required by V2
    /// addresses (Go: `AuthMailboxUniRpcCourierType`,
    /// "authmailbox+universerpc"). A single connection serves both the
    /// universe proof push/pull and the auth mailbox send-fragment
    /// delivery: V2 deliveries route the encrypted [`SendFragment`]
    /// through the mailbox (see
    /// [`crate::proof::mailbox::deliver_send_manifest`]) while the
    /// transfer proofs themselves are pushed to / fetched from the
    /// universe half, which the existing [`Courier`] trait models.
    ///
    /// [`SendFragment`]: tap_primitives::proof::SendFragment
    AuthMailboxUniRpc,
}

impl CourierKind {
    /// Parses the courier kind from a courier URL (e.g.
    /// `authmailbox+universerpc://host:port`). Returns `None` for
    /// unknown schemes, mirroring Go's scheme switch in
    /// `proof.NewCourier`.
    pub fn from_url(url: &str) -> Option<Self> {
        let (scheme, _) = url.split_once("://")?;
        match scheme {
            "hashmail" => Some(CourierKind::Hashmail),
            "universerpc" => Some(CourierKind::UniverseRpc),
            s if s == AUTH_MAILBOX_UNI_RPC_COURIER_TYPE => {
                Some(CourierKind::AuthMailboxUniRpc)
            }
            _ => None,
        }
    }

    /// Returns true if this courier kind supports transporting V2
    /// address send manifests (auth mailbox messages). Mirrors the
    /// scheme check in Go's `UniverseRpcCourier.deliverFragment`.
    pub fn supports_send_manifests(&self) -> bool {
        matches!(self, CourierKind::AuthMailboxUniRpc)
    }
}

/// Identifies a proof for courier delivery/retrieval.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CourierLocator {
    /// The asset ID.
    pub asset_id: AssetId,
    /// The script key controlling the asset.
    pub script_key: SerializedKey,
    /// The anchor outpoint.
    pub outpoint: OutPoint,
}

/// A proof recipient.
#[derive(Clone, Debug)]
pub struct Recipient {
    /// The recipient's script key (used to derive delivery address).
    pub script_key: SerializedKey,
    /// The asset ID being transferred.
    pub asset_id: AssetId,
    /// Amount being transferred.
    pub amount: u64,
}

/// A proof file annotated with its locator for delivery.
#[derive(Clone, Debug)]
pub struct AnnotatedProof {
    /// The locator identifying this proof.
    pub locator: CourierLocator,
    /// The proof file to deliver.
    pub proof_file: proof::File,
}

/// Errors from courier operations.
#[derive(Debug, Clone)]
pub enum CourierError {
    /// Network/transport failure.
    Transport(String),
    /// Proof not found on the courier service.
    ProofNotFound,
    /// Timeout waiting for delivery/receipt.
    Timeout,
    /// Acknowledgement not received.
    AckFailed(String),
    /// Proof encoding/decoding error.
    Encoding(String),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for CourierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CourierError::Transport(msg) => {
                write!(f, "transport error: {}", msg)
            }
            CourierError::ProofNotFound => write!(f, "proof not found"),
            CourierError::Timeout => write!(f, "timeout"),
            CourierError::AckFailed(msg) => {
                write!(f, "ack failed: {}", msg)
            }
            CourierError::Encoding(msg) => {
                write!(f, "encoding error: {}", msg)
            }
            CourierError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CourierError {}

/// Trait abstracting proof delivery and retrieval.
///
/// Implementations handle the transport layer (HTTP, gRPC, etc.).
/// Methods take `&self` — implementations handle internal mutability.
pub trait Courier {
    /// Delivers a proof to the recipient via the courier service.
    fn deliver_proof(
        &self,
        recipient: &Recipient,
        proof: &AnnotatedProof,
    ) -> Result<(), CourierError>;

    /// Receives a proof identified by the locator from the courier service.
    fn receive_proof(
        &self,
        recipient: &Recipient,
        locator: &CourierLocator,
    ) -> Result<AnnotatedProof, CourierError>;
}

/// Derives a 32-byte stream ID from a script key for courier addressing.
///
/// Uses SHA-256 of the compressed script key bytes.
pub fn derive_stream_id(script_key: &SerializedKey) -> [u8; 32] {
    use bitcoin_hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(&script_key.0);
    let mut id = [0u8; 32];
    id.copy_from_slice(hash.as_ref());
    id
}

/// Delivers proofs to multiple recipients.
///
/// Called after an anchor transaction is confirmed and transition proofs
/// have been generated. This is the integration point with the transfer
/// pipeline's `SendState::TransferProofs` state.
pub fn deliver_transfer_proofs(
    courier: &dyn Courier,
    deliveries: &[(Recipient, AnnotatedProof)],
) -> Result<(), CourierError> {
    for (recipient, proof) in deliveries {
        courier.deliver_proof(recipient, proof)?;
    }
    Ok(())
}

/// In-memory courier for testing.
///
/// Stores proofs in a `HashMap` keyed by stream ID. The sender writes
/// and the receiver reads from the same map.
pub struct MockCourier {
    store: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl MockCourier {
    pub fn new() -> Self {
        MockCourier {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockCourier {
    fn default() -> Self {
        Self::new()
    }
}

impl Courier for MockCourier {
    fn deliver_proof(
        &self,
        recipient: &Recipient,
        proof: &AnnotatedProof,
    ) -> Result<(), CourierError> {
        let stream_id = derive_stream_id(&recipient.script_key);
        let encoded = proof.proof_file.encode();
        self.store.lock().unwrap().insert(stream_id, encoded);
        Ok(())
    }

    fn receive_proof(
        &self,
        recipient: &Recipient,
        locator: &CourierLocator,
    ) -> Result<AnnotatedProof, CourierError> {
        let stream_id = derive_stream_id(&recipient.script_key);
        let store = self.store.lock().unwrap();
        let data = store.get(&stream_id).ok_or(CourierError::ProofNotFound)?;
        let proof_file = proof::File::decode(data)
            .map_err(|e| CourierError::Encoding(e.to_string()))?;

        Ok(AnnotatedProof {
            locator: locator.clone(),
            proof_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_recipient() -> Recipient {
        Recipient {
            script_key: SerializedKey([0x02; 33]),
            asset_id: AssetId([0xAA; 32]),
            amount: 100,
        }
    }

    fn test_locator() -> CourierLocator {
        CourierLocator {
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]),
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
        }
    }

    fn test_proof() -> AnnotatedProof {
        let mut file = proof::File::new();
        file.append_proof(vec![0x01, 0x02, 0x03]);
        AnnotatedProof {
            locator: test_locator(),
            proof_file: file,
        }
    }

    #[test]
    fn test_mock_courier_roundtrip() {
        let courier = MockCourier::new();
        let recipient = test_recipient();
        let proof = test_proof();

        courier.deliver_proof(&recipient, &proof).unwrap();

        let received = courier
            .receive_proof(&recipient, &test_locator())
            .unwrap();
        assert_eq!(received.proof_file.num_proofs(), 1);
    }

    #[test]
    fn test_mock_courier_not_found() {
        let courier = MockCourier::new();
        let recipient = test_recipient();

        let result = courier.receive_proof(&recipient, &test_locator());
        assert!(matches!(result, Err(CourierError::ProofNotFound)));
    }

    #[test]
    fn test_deliver_transfer_proofs_multiple() {
        let courier = MockCourier::new();

        let r1 = Recipient {
            script_key: SerializedKey([0x02; 33]),
            asset_id: AssetId([0xAA; 32]),
            amount: 50,
        };
        let r2 = Recipient {
            script_key: SerializedKey([0x03; 33]),
            asset_id: AssetId([0xAA; 32]),
            amount: 50,
        };

        let p1 = test_proof();
        let mut file2 = proof::File::new();
        file2.append_proof(vec![0x04, 0x05]);
        let p2 = AnnotatedProof {
            locator: CourierLocator {
                asset_id: AssetId([0xAA; 32]),
                script_key: SerializedKey([0x03; 33]),
                outpoint: OutPoint {
                    txid: [0xBB; 32],
                    vout: 1,
                },
            },
            proof_file: file2,
        };

        deliver_transfer_proofs(&courier, &[(r1, p1), (r2, p2)]).unwrap();
    }

    #[test]
    fn test_courier_kind_from_url() {
        assert_eq!(
            CourierKind::from_url("hashmail://foo.bar:10029"),
            Some(CourierKind::Hashmail)
        );
        assert_eq!(
            CourierKind::from_url("universerpc://foo.bar:10029"),
            Some(CourierKind::UniverseRpc)
        );
        assert_eq!(
            CourierKind::from_url(
                "authmailbox+universerpc://foo.bar:10029"
            ),
            Some(CourierKind::AuthMailboxUniRpc)
        );
        assert_eq!(CourierKind::from_url("http://foo.bar"), None);
        assert_eq!(CourierKind::from_url("not-a-url"), None);
    }

    #[test]
    fn test_courier_kind_send_manifest_support() {
        assert!(CourierKind::AuthMailboxUniRpc.supports_send_manifests());
        assert!(!CourierKind::Hashmail.supports_send_manifests());
        assert!(!CourierKind::UniverseRpc.supports_send_manifests());
    }

    #[test]
    fn test_stream_id_deterministic() {
        let key = SerializedKey([0x02; 33]);
        let id1 = derive_stream_id(&key);
        let id2 = derive_stream_id(&key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_stream_id_differs_by_key() {
        let id1 = derive_stream_id(&SerializedKey([0x02; 33]));
        let id2 = derive_stream_id(&SerializedKey([0x03; 33]));
        assert_ne!(id1, id2);
    }
}
