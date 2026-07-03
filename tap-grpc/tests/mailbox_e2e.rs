//! End-to-end test of [`tap_grpc::GrpcMailboxTransport`] against an
//! in-process tonic stub of `authmailboxrpc.Mailbox`.
//!
//! The stub implements the wire protocol the way tapd's server does
//! (`authmailbox/server.go`):
//!
//! - `SendMessage` unmarshals and fully verifies the tx proof
//!   (structure, P2TR construction, tx merkle inclusion) and rejects
//!   reused claimed outpoints.
//! - `ReceiveMessages` runs the 3-way challenge handshake: challenge
//!   `SHA256(receiver_id || nonce)`, then verifies the client's
//!   BIP-340 signature over `SHA256(challenge_hash)` against the
//!   x-only receiver key (lnd `VerifyMessage` Schnorr semantics),
//!   sends `auth_success`, and delivers the existing backlog only
//!   when the filter requests it (`DeliverExisting`).
//! - `RemoveMessage` verifies the Schnorr signature over
//!   `SHA256(remove_message_challenge(receiver, ids))`.
//!
//! The test then round-trips a full `SendManifest`: ECIES encryption
//! and fragment encoding by `deliver_send_manifest`, delivery over
//! gRPC, poll-style fetch with the challenge handshake using
//! `SoftMailboxSigner`, decryption/validation via
//! `decrypt_send_fragment`, and authenticated removal.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin_hashes::{sha256, Hash};

use tap_grpc::authmailboxrpc::mailbox_server::{Mailbox, MailboxServer};
use tap_grpc::authmailboxrpc::{
    receive_messages_request, receive_messages_response, Challenge,
    MailboxInfoRequest, MailboxInfoResponse, MailboxMessage as
    ProtoMailboxMessage, MailboxMessages, ReceiveMessagesRequest,
    ReceiveMessagesResponse, RemoveMessageRequest, RemoveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
use tap_grpc::convert;
use tap_grpc::{sign_remove_challenge, GrpcMailboxTransport};

use tap_onchain::proof::mailbox::{
    build_send_fragment, build_tx_proof, decrypt_send_fragment,
    deliver_send_manifest, remove_message_challenge, MailboxError,
    MailboxSigner, MailboxTransport, MessageFilter, SendManifest,
    SoftMailboxSigner,
};
use tap_primitives::asset::{
    AssetId, AssetVersion, OutPoint, ScriptKeyDerivationMethod,
    SerializedKey,
};
use tap_primitives::crypto::tapscript::taproot_output_key;
use tap_primitives::proof::send_fragment::{SendFragment, SendOutput};
use tap_primitives::proof::tx_proof::TxProof;
use tap_primitives::proof::types::{AnchorTx, BlockHeader};
use tap_primitives::proof::verify::{
    DefaultMerkleVerifier, HeaderVerifier,
};
use tap_primitives::proof::ProofError;

use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status, Streaming};

// ---------------------------------------------------------------------------
// Stub server
// ---------------------------------------------------------------------------

/// A header "verifier" that accepts any header (the stub has no chain
/// access; tapd verifies headers against the chain).
struct AcceptAllHeaders;

impl HeaderVerifier for AcceptAllHeaders {
    fn verify_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

#[derive(Default)]
struct StubState {
    next_id: u64,
    /// (receiver_id, message, proof block height)
    messages: Vec<(Vec<u8>, ProtoMailboxMessage, u32)>,
    claimed_outpoints: Vec<OutPoint>,
}

#[derive(Clone, Default)]
struct StubMailbox {
    state: Arc<Mutex<StubState>>,
}

/// Verifies a BIP-340 signature over SHA256(msg) by the x-only form of
/// the given compressed key, mirroring lnd's `VerifyMessage` with
/// `VerifySchnorr` (`chainhash.HashB` digest).
fn verify_schnorr_over(
    msg: &[u8],
    signature: &[u8],
    receiver_id: &[u8],
) -> Result<(), Status> {
    let secp = secp256k1::Secp256k1::verification_only();
    if receiver_id.len() != 33 {
        return Err(Status::invalid_argument("bad receiver key length"));
    }
    let x_only =
        secp256k1::XOnlyPublicKey::from_slice(&receiver_id[1..])
            .map_err(|e| {
                Status::invalid_argument(format!("bad receiver key: {}", e))
            })?;
    let sig =
        secp256k1::schnorr::Signature::from_slice(signature).map_err(
            |e| Status::invalid_argument(format!("bad signature: {}", e)),
        )?;
    let digest = sha256::Hash::hash(msg).to_byte_array();
    let message = secp256k1::Message::from_digest(digest);
    secp.verify_schnorr(&sig, &message, &x_only).map_err(|_| {
        Status::unauthenticated("signature not valid for receiver key")
    })
}

#[tonic::async_trait]
impl Mailbox for StubMailbox {
    async fn send_message(
        &self,
        request: Request<SendMessageRequest>,
    ) -> Result<Response<SendMessageResponse>, Status> {
        use tap_grpc::authmailboxrpc::send_message_request::Proof;

        let request = request.into_inner();

        let Some(Proof::TxProof(rpc_proof)) = request.proof else {
            return Err(Status::invalid_argument("tx proof required"));
        };

        // Full server-side proof validation, like tapd: unmarshal and
        // verify structure, P2TR construction, and merkle inclusion.
        let tx_proof: TxProof = convert::tx_proof_from_proto(&rpc_proof)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        tx_proof
            .verify(&AcceptAllHeaders, &DefaultMerkleVerifier)
            .map_err(|e| {
                Status::invalid_argument(format!("invalid tx proof: {}", e))
            })?;

        let mut state = self.state.lock().expect("stub lock");
        if state.claimed_outpoints.contains(&tx_proof.claimed_outpoint) {
            return Err(Status::already_exists(
                "tx merkle proof already exists",
            ));
        }

        state.next_id += 1;
        let id = state.next_id;
        state.claimed_outpoints.push(tx_proof.claimed_outpoint);
        state.messages.push((
            request.receiver_id,
            ProtoMailboxMessage {
                message_id: id,
                encrypted_payload: request.encrypted_payload,
                arrival_timestamp: 1_700_000_000 + id as i64,
            },
            tx_proof.block_height,
        ));

        Ok(Response::new(SendMessageResponse { message_id: id }))
    }

    type ReceiveMessagesStream = Pin<
        Box<
            dyn tokio_stream::Stream<
                    Item = Result<ReceiveMessagesResponse, Status>,
                > + Send,
        >,
    >;

    async fn receive_messages(
        &self,
        request: Request<Streaming<ReceiveMessagesRequest>>,
    ) -> Result<Response<Self::ReceiveMessagesStream>, Status> {
        use receive_messages_request::RequestType;
        use receive_messages_response::ResponseType;

        let mut in_stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let state = Arc::clone(&self.state);

        tokio::spawn(async move {
            let send_err = |tx: &tokio::sync::mpsc::Sender<_>,
                            status: Status| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Err(status)).await;
                }
            };

            // Step 1: InitReceive.
            let init = match in_stream.message().await {
                Ok(Some(ReceiveMessagesRequest {
                    request_type: Some(RequestType::Init(init)),
                })) => init,
                _ => {
                    send_err(
                        &tx,
                        Status::invalid_argument("expected init"),
                    )
                    .await;
                    return;
                }
            };

            // Step 2: challenge = SHA256(receiver_id || nonce), like
            // Go's concatAndHash.
            let nonce = [0x5A; 32];
            let mut preimage = init.receiver_id.clone();
            preimage.extend_from_slice(&nonce);
            let challenge_hash =
                sha256::Hash::hash(&preimage).to_byte_array();
            if tx
                .send(Ok(ReceiveMessagesResponse {
                    response_type: Some(ResponseType::Challenge(
                        Challenge {
                            challenge_hash: challenge_hash.to_vec(),
                        },
                    )),
                }))
                .await
                .is_err()
            {
                return;
            }

            // Step 3: the auth signature over SHA256(challenge_hash).
            let sig = match in_stream.message().await {
                Ok(Some(ReceiveMessagesRequest {
                    request_type: Some(RequestType::AuthSig(sig)),
                })) => sig,
                _ => {
                    send_err(
                        &tx,
                        Status::invalid_argument("expected auth sig"),
                    )
                    .await;
                    return;
                }
            };
            if let Err(status) = verify_schnorr_over(
                &challenge_hash,
                &sig.signature,
                &init.receiver_id,
            ) {
                send_err(&tx, status).await;
                return;
            }

            // Step 4: auth success.
            if tx
                .send(Ok(ReceiveMessagesResponse {
                    response_type: Some(ResponseType::AuthSuccess(true)),
                }))
                .await
                .is_err()
            {
                return;
            }

            // Deliver the existing backlog only when the filter asks
            // for it (Go MessageFilter.DeliverExisting).
            let deliver_existing = init.start_message_id_exclusive != 0
                || init.start_block_height_inclusive != 0
                || init.start_timestamp_exclusive != 0;
            if deliver_existing {
                let backlog: Vec<ProtoMailboxMessage> = {
                    let state = state.lock().expect("stub lock");
                    state
                        .messages
                        .iter()
                        .filter(|(receiver, msg, height)| {
                            receiver == &init.receiver_id
                                && msg.message_id
                                    > init.start_message_id_exclusive
                                && (init.start_block_height_inclusive == 0
                                    || *height
                                        >= init
                                            .start_block_height_inclusive)
                                && (init.start_timestamp_exclusive == 0
                                    || msg.arrival_timestamp
                                        > init.start_timestamp_exclusive)
                        })
                        .map(|(_, msg, _)| msg.clone())
                        .collect()
                };
                if !backlog.is_empty()
                    && tx
                        .send(Ok(ReceiveMessagesResponse {
                            response_type: Some(ResponseType::Messages(
                                MailboxMessages { messages: backlog },
                            )),
                        }))
                        .await
                        .is_err()
                {
                    return;
                }
            }

            // Keep the subscription open until the client hangs up
            // (the poll-style client closes after its drain window).
            while let Ok(Some(_)) = in_stream.message().await {}
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn mailbox_info(
        &self,
        _request: Request<MailboxInfoRequest>,
    ) -> Result<Response<MailboxInfoResponse>, Status> {
        let state = self.state.lock().expect("stub lock");
        Ok(Response::new(MailboxInfoResponse {
            server_time: 1_700_000_000,
            message_count: state.messages.len() as u64,
        }))
    }

    async fn remove_message(
        &self,
        request: Request<RemoveMessageRequest>,
    ) -> Result<Response<RemoveMessageResponse>, Status> {
        let request = request.into_inner();

        // tapd verifies the Schnorr signature over
        // SHA256(RemoveMessageChallenge(receiver, ids)).
        let challenge = remove_message_challenge(
            &request.receiver_id,
            &request.message_ids,
        );
        verify_schnorr_over(
            &challenge,
            &request.signature,
            &request.receiver_id,
        )?;

        let mut state = self.state.lock().expect("stub lock");
        let before = state.messages.len();
        state.messages.retain(|(receiver, msg, _)| {
            receiver != &request.receiver_id
                || !request.message_ids.contains(&msg.message_id)
        });
        let removed = (before - state.messages.len()) as u64;

        Ok(Response::new(RemoveMessageResponse {
            num_removed: removed,
        }))
    }
}

/// Starts the stub server on an ephemeral port inside `runtime`,
/// returning its address.
fn start_stub_server(runtime: &tokio::runtime::Runtime) -> SocketAddr {
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MailboxServer::new(StubMailbox::default()))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("stub mailbox server run");
    });

    addr
}

// ---------------------------------------------------------------------------
// Test fixtures (mirroring the MockTransport e2e in tap-onchain)
// ---------------------------------------------------------------------------

fn test_secret(byte: u8) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[byte; 32]).expect("valid key")
}

fn test_pub(byte: u8) -> SerializedKey {
    let secp = secp256k1::Secp256k1::new();
    SerializedKey(test_secret(byte).public_key(&secp).serialize())
}

/// Builds a single-tx-block tx proof whose claimed output is a valid
/// BIP-86 P2TR output for `internal_key`.
fn test_tx_proof(internal_key: SerializedKey, block_height: u32) -> TxProof {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

    let output_key =
        taproot_output_key(&internal_key, &[]).expect("valid key");
    let mut script = Vec::with_capacity(34);
    script.push(0x51);
    script.push(0x20);
    script.extend_from_slice(&output_key);

    let tx = AnchorTx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(script),
        }],
    });
    let txid = tx.txid();

    let mut header = [0u8; 80];
    header[36..68].copy_from_slice(&txid);

    build_tx_proof(
        tx,
        BlockHeader(header),
        block_height,
        &[txid],
        0,
        internal_key,
        None,
    )
    .expect("valid tx proof")
}

fn test_fragment(
    receiver: &SerializedKey,
    anchor_outpoint: OutPoint,
) -> SendFragment {
    let asset_id = AssetId([0x11; 32]);
    let script_key = tap_primitives::asset::derive_unique_script_key(
        *receiver,
        &asset_id,
        ScriptKeyDerivationMethod::UniquePedersen,
    )
    .expect("derivable")
    .pub_key;

    build_send_fragment(
        BlockHeader::default(),
        123,
        anchor_outpoint,
        [0xAB; 32],
        BTreeMap::from([(
            asset_id,
            SendOutput {
                asset_version: AssetVersion::V0,
                amount: 42,
                derivation_method: ScriptKeyDerivationMethod::UniquePedersen,
                script_key,
            },
        )]),
    )
    .expect("valid fragment")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The full SendManifest round trip over gRPC: deliver (ECIES encrypt
/// + tx proof over the wire), subscribe with the challenge handshake,
/// fetch, decrypt, validate, and remove with a signed challenge.
#[test]
fn mailbox_grpc_send_manifest_round_trip() {
    // The stub server runs on its own runtime; the blocking transport
    // owns a separate private runtime (as it would in a sync caller).
    let server_rt = tokio::runtime::Runtime::new().expect("server runtime");
    let addr = start_stub_server(&server_rt);

    let transport =
        GrpcMailboxTransport::connect(&format!("http://{}", addr))
            .expect("connect stub mailbox")
            .with_drain_timeout(Duration::from_millis(300));

    // Receiver key pair (the V2 address script key).
    let mut signer = SoftMailboxSigner::new();
    let receiver_key = signer.add_key(test_secret(0x21));

    let tx_proof = test_tx_proof(test_pub(0x31), 123);
    let fragment = test_fragment(&receiver_key, tx_proof.claimed_outpoint);
    let manifest = SendManifest {
        tx_proof,
        receiver: receiver_key,
        courier_url: format!("authmailbox+universerpc://{}", addr),
        fragment: fragment.clone(),
    };

    // Sender side: encrypt and post through the gRPC transport.
    let msg_id =
        deliver_send_manifest(&transport, &manifest).expect("deliver");
    assert_eq!(msg_id, 1);
    let (_, count) = transport.mailbox_info().expect("info");
    assert_eq!(count, 1);

    // Receiver side: poll with a filter that requests the existing
    // backlog (start_block != 0 => DeliverExisting).
    let filter = MessageFilter {
        receiver_key: Some(receiver_key),
        start_block: 1,
        ..Default::default()
    };
    let messages =
        transport.fetch_messages(&filter, &signer).expect("fetch");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, msg_id);
    assert_eq!(messages[0].receiver_key, receiver_key);

    // Decrypt and validate the fragment (ECDH via the signer).
    let decrypted = decrypt_send_fragment(
        &signer,
        &receiver_key,
        &messages[0].encrypted_payload,
    )
    .expect("decrypt");
    assert_eq!(decrypted, fragment);

    // Cursor-style polling: nothing newer than the last seen ID.
    let filter_after = MessageFilter {
        receiver_key: Some(receiver_key),
        after_id: msg_id,
        ..Default::default()
    };
    assert!(transport
        .fetch_messages(&filter_after, &signer)
        .expect("fetch after")
        .is_empty());

    // ACK: remove the message with the tapd-compatible signed
    // challenge (Schnorr over SHA256 of the remove challenge).
    let sig = sign_remove_challenge(&signer, &receiver_key, &[msg_id])
        .expect("sign remove challenge");
    transport
        .remove_messages(&receiver_key, &[msg_id], &sig)
        .expect("remove");

    let (_, count) = transport.mailbox_info().expect("info");
    assert_eq!(count, 0);
    assert!(transport
        .fetch_messages(&filter, &signer)
        .expect("fetch after remove")
        .is_empty());
}

/// A signer that produces valid-looking Schnorr signatures with the
/// WRONG key: the server must reject the subscription.
struct WrongKeySigner(secp256k1::Keypair);

impl MailboxSigner for WrongKeySigner {
    fn ecdh(
        &self,
        _local_key: &SerializedKey,
        _remote_pub: &SerializedKey,
    ) -> Result<[u8; 32], MailboxError> {
        Err(MailboxError::UnknownKey)
    }

    fn sign_challenge(
        &self,
        _local_key: &SerializedKey,
        challenge: &[u8; 32],
    ) -> Result<Vec<u8>, MailboxError> {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*challenge);
        Ok(secp
            .sign_schnorr_no_aux_rand(&msg, &self.0)
            .as_ref()
            .to_vec())
    }
}

/// The handshake fails (and no messages leak) when the challenge is
/// signed by a key other than the receiver key.
#[test]
fn mailbox_grpc_rejects_wrong_auth_key() {
    let server_rt = tokio::runtime::Runtime::new().expect("server runtime");
    let addr = start_stub_server(&server_rt);

    let transport =
        GrpcMailboxTransport::connect(&format!("http://{}", addr))
            .expect("connect stub mailbox")
            .with_drain_timeout(Duration::from_millis(300));

    let receiver_key = test_pub(0x21);
    let secp = secp256k1::Secp256k1::new();
    let wrong = WrongKeySigner(secp256k1::Keypair::from_secret_key(
        &secp,
        &test_secret(0x99),
    ));

    let filter = MessageFilter {
        receiver_key: Some(receiver_key),
        start_block: 1,
        ..Default::default()
    };
    let result = transport.fetch_messages(&filter, &wrong);
    assert!(
        matches!(result, Err(MailboxError::Transport(_))),
        "wrong-key auth must fail: {:?}",
        result
    );
}

/// The server rejects duplicate claimed outpoints (proof-of-work
/// reuse), surfaced as a transport error by send_message.
#[test]
fn mailbox_grpc_rejects_duplicate_outpoint() {
    let server_rt = tokio::runtime::Runtime::new().expect("server runtime");
    let addr = start_stub_server(&server_rt);

    let transport =
        GrpcMailboxTransport::connect(&format!("http://{}", addr))
            .expect("connect stub mailbox");

    let receiver = test_pub(0x21);
    let tx_proof = test_tx_proof(test_pub(0x31), 7);

    transport
        .send_message(&receiver, &[0u8; 64], &tx_proof)
        .expect("first send");
    let result = transport.send_message(&receiver, &[0u8; 64], &tx_proof);
    assert!(
        matches!(result, Err(MailboxError::Transport(msg))
            if msg.contains("already exists")),
    );
}
