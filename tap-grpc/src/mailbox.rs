// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Blocking gRPC transport for `tapd`'s `authmailboxrpc.Mailbox`
//! service, implementing
//! [`tap_onchain::proof::mailbox::MailboxTransport`].
//!
//! # The receive handshake
//!
//! `ReceiveMessages` is a bidirectional stream with a challenge
//! response handshake (Go `authmailbox/receive_subscription.go` and
//! `authmailbox/server.go`):
//!
//! 1. Client -> Server: `InitReceive{receiver_id, start_*}` (the
//!    receiver's 33-byte compressed key plus backlog filters).
//! 2. Server -> Client: `Challenge{challenge_hash}` where
//!    `challenge_hash = SHA256(receiver_id || auth_nonce)`.
//! 3. Client -> Server: `AuthSignature{signature}`: a BIP-340 Schnorr
//!    signature by the receiver key over `SHA256(challenge_hash)`.
//!    The extra hash is lnd's `SignMessage`/`VerifyMessage` Schnorr
//!    convention (`chainhash.HashB(msg)`, see lnd
//!    `signrpc.Server.VerifyMessage`), which the Go client inherits
//!    by signing through lnd; this transport applies it before
//!    calling [`MailboxSigner::sign_challenge`].
//! 4. Server -> Client: `auth_success = true`, then zero or more
//!    `MailboxMessages` batches, then (eventually) `EndOfStream`.
//!
//! # Poll-over-stream adaptation
//!
//! [`MailboxTransport::fetch_messages`] is a poll-style call, while
//! the wire protocol is a long-lived server-push subscription. This
//! transport adapts by opening the stream, performing the handshake,
//! draining the message batches the server has available (the
//! backlog is only sent when the filter requests existing messages,
//! i.e. one of `after`, `after_id` or `start_block` is non-zero,
//! mirroring Go's `MessageFilter.DeliverExisting`), and closing the
//! stream once no further batch arrives within the configured drain
//! window. Callers poll repeatedly (with `after_id` as a cursor) the
//! same way they would against
//! [`tap_onchain::proof::mailbox::MockTransport`]. A future
//! push-style subscription API can be added without changing the
//! trait.
//!
//! Note: the wire `MailboxMessage` carries no proof block height, so
//! [`MailboxMessage::proof_block_height`] is always 0 on fetched
//! messages; server-side `start_block` filtering still applies.

use std::time::Duration;

use bitcoin_hashes::{sha256, Hash};

use tap_onchain::proof::mailbox::{
    remove_message_challenge, MailboxError, MailboxMessage,
    MailboxSigner, MailboxTransport, MessageFilter,
};
use tap_primitives::asset::SerializedKey;
use tap_primitives::proof::tx_proof::TxProof;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};

use crate::authmailboxrpc;
use crate::authmailboxrpc::mailbox_client::MailboxClient;
use crate::blocking::BlockingRuntime;
use crate::convert;

/// How long the handshake steps (challenge, auth success) may take
/// before the fetch fails.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default wait for the next message batch before a poll-style fetch
/// concludes that no further messages are currently available.
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_millis(1000);

/// Blocking gRPC transport for a tapd auth mailbox server.
#[derive(Clone)]
pub struct GrpcMailboxTransport {
    rt: BlockingRuntime,
    client: MailboxClient<Channel>,
    drain_timeout: Duration,
}

fn transport_err(what: &str, e: impl std::fmt::Display) -> MailboxError {
    MailboxError::Transport(format!("{}: {}", what, e))
}

/// Signs the `RemoveMessage` challenge for the given message IDs the
/// way tapd's mailbox server verifies it: a BIP-340 Schnorr signature
/// over `SHA256(remove_message_challenge(receiver, ids))`. The outer
/// SHA256 is lnd's `SignMessage`/`VerifyMessage` Schnorr convention
/// (Go signs the challenge via lnd, `authmailbox/client.go`
/// `RemoveMessages`; the server verifies via `lndclient.VerifySchnorr`
/// which hashes the message with `chainhash.HashB`).
pub fn sign_remove_challenge(
    signer: &dyn MailboxSigner,
    receiver: &SerializedKey,
    message_ids: &[u64],
) -> Result<Vec<u8>, MailboxError> {
    let challenge =
        remove_message_challenge(receiver.as_bytes(), message_ids);
    let digest = sha256::Hash::hash(&challenge).to_byte_array();
    signer.sign_challenge(receiver, &digest)
}

impl GrpcMailboxTransport {
    /// Connects to a mailbox gRPC server, e.g.
    /// `http://127.0.0.1:10029`. Creates a private single-worker tokio
    /// runtime for this transport.
    pub fn connect(uri: &str) -> Result<Self, MailboxError> {
        let rt = BlockingRuntime::new_owned()
            .map_err(|e| transport_err("create runtime", e))?;
        Self::connect_inner(rt, uri)
    }

    /// Connects using an existing tokio runtime handle instead of
    /// owning one. The runtime must outlive the transport, and the
    /// transport must not be invoked from that runtime's async
    /// context (use `spawn_blocking`).
    pub fn connect_with_handle(
        handle: tokio::runtime::Handle,
        uri: &str,
    ) -> Result<Self, MailboxError> {
        Self::connect_inner(BlockingRuntime::from_handle(handle), uri)
    }

    fn connect_inner(
        rt: BlockingRuntime,
        uri: &str,
    ) -> Result<Self, MailboxError> {
        let endpoint = Endpoint::from_shared(uri.to_string())
            .map_err(|e| transport_err("invalid mailbox server uri", e))?;
        let channel = rt
            .block_on(endpoint.connect())
            .map_err(|e| transport_err("connect mailbox server", e))?;
        Ok(GrpcMailboxTransport {
            rt,
            client: MailboxClient::new(channel),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        })
    }

    /// Overrides how long a poll-style fetch waits for the next
    /// message batch before concluding the drain (default 1s).
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Returns the server time and stored message count
    /// (`MailboxInfo` RPC); also useful as a reachability check.
    pub fn mailbox_info(&self) -> Result<(i64, u64), MailboxError> {
        let mut client = self.client.clone();
        let response = self
            .rt
            .block_on(client.mailbox_info(
                authmailboxrpc::MailboxInfoRequest {},
            ))
            .map_err(|e| transport_err("mailbox_info", e))?
            .into_inner();
        Ok((response.server_time, response.message_count))
    }

    /// Performs the subscription handshake and drains the currently
    /// available messages (see the module docs for the exact message
    /// sequence).
    async fn fetch_messages_async(
        &self,
        receiver: &SerializedKey,
        filter: &MessageFilter,
        signer: &dyn MailboxSigner,
    ) -> Result<Vec<MailboxMessage>, MailboxError> {
        use authmailboxrpc::receive_messages_request::RequestType;
        use authmailboxrpc::receive_messages_response::ResponseType;

        let (tx, rx) = mpsc::channel::<
            authmailboxrpc::ReceiveMessagesRequest,
        >(8);

        // Step 1: the init message must be queued before the stream
        // opens; tonic sends it as the first stream element.
        let init = authmailboxrpc::ReceiveMessagesRequest {
            request_type: Some(RequestType::Init(
                authmailboxrpc::InitReceive {
                    receiver_id: receiver.as_bytes().to_vec(),
                    start_message_id_exclusive: filter.after_id,
                    start_block_height_inclusive: filter.start_block,
                    start_timestamp_exclusive: i64::try_from(filter.after)
                        .unwrap_or(i64::MAX),
                },
            )),
        };
        tx.send(init)
            .await
            .map_err(|e| transport_err("queue init", e))?;

        let mut client = self.client.clone();
        let mut stream = client
            .receive_messages(ReceiverStream::new(rx))
            .await
            .map_err(|e| transport_err("receive_messages", e))?
            .into_inner();

        // Reads the next server message within `timeout`.
        async fn next_msg(
            stream: &mut tonic::Streaming<
                authmailboxrpc::ReceiveMessagesResponse,
            >,
            timeout: Duration,
        ) -> Result<
            Option<authmailboxrpc::receive_messages_response::ResponseType>,
            MailboxError,
        > {
            match tokio::time::timeout(timeout, stream.message()).await {
                Err(_elapsed) => Err(MailboxError::Transport(
                    "timed out waiting for server message".into(),
                )),
                Ok(Err(status)) => Err(transport_err("stream", status)),
                Ok(Ok(None)) => Ok(None),
                Ok(Ok(Some(msg))) => Ok(msg.response_type),
            }
        }

        // Step 2: the server challenge.
        let challenge_hash = match next_msg(&mut stream, HANDSHAKE_TIMEOUT)
            .await?
        {
            Some(ResponseType::Challenge(challenge)) => {
                challenge.challenge_hash
            }
            other => {
                return Err(MailboxError::Transport(format!(
                    "expected challenge, got {:?}",
                    other
                )))
            }
        };

        // Step 3: sign SHA256(challenge_hash) with the receiver key
        // (lnd SignMessage Schnorr convention, see module docs).
        let digest = sha256::Hash::hash(&challenge_hash).to_byte_array();
        let signature = signer.sign_challenge(receiver, &digest)?;
        tx.send(authmailboxrpc::ReceiveMessagesRequest {
            request_type: Some(RequestType::AuthSig(
                authmailboxrpc::AuthSignature { signature },
            )),
        })
        .await
        .map_err(|e| transport_err("queue auth sig", e))?;

        // Step 4: auth confirmation.
        match next_msg(&mut stream, HANDSHAKE_TIMEOUT).await? {
            Some(ResponseType::AuthSuccess(true)) => {}
            other => {
                return Err(MailboxError::Transport(format!(
                    "expected auth success, got {:?}",
                    other
                )))
            }
        }

        // Drain currently-available message batches. The subscription
        // is server-push; a poll-style fetch stops once no batch
        // arrives within the drain window.
        let mut messages = Vec::new();
        loop {
            match tokio::time::timeout(
                self.drain_timeout,
                stream.message(),
            )
            .await
            {
                // No further batch right now: the poll is done.
                Err(_elapsed) => break,
                Ok(Err(status)) => {
                    return Err(transport_err("stream", status))
                }
                // Server closed the stream.
                Ok(Ok(None)) => break,
                Ok(Ok(Some(msg))) => match msg.response_type {
                    Some(ResponseType::Messages(batch)) => {
                        for message in batch.messages {
                            messages.push(MailboxMessage {
                                id: message.message_id,
                                receiver_key: *receiver,
                                encrypted_payload: message
                                    .encrypted_payload,
                                arrival_timestamp: u64::try_from(
                                    message.arrival_timestamp,
                                )
                                .unwrap_or(0),
                                // Not part of the wire message; the
                                // server already applied start_block
                                // filtering.
                                proof_block_height: 0,
                            });
                        }
                    }
                    Some(ResponseType::Eos(_)) | None => break,
                    other => {
                        return Err(MailboxError::Transport(format!(
                            "unexpected server message {:?}",
                            other
                        )))
                    }
                },
            }
        }

        // Closing: dropping the sender ends our half of the stream;
        // dropping the response stream tears the RPC down.
        drop(tx);
        drop(stream);

        Ok(messages)
    }
}

impl MailboxTransport for GrpcMailboxTransport {
    fn send_message(
        &self,
        receiver: &SerializedKey,
        encrypted_payload: &[u8],
        tx_proof: &TxProof,
    ) -> Result<u64, MailboxError> {
        use authmailboxrpc::send_message_request::Proof;

        let request = authmailboxrpc::SendMessageRequest {
            receiver_id: receiver.as_bytes().to_vec(),
            encrypted_payload: encrypted_payload.to_vec(),
            proof: Some(Proof::TxProof(convert::tx_proof_to_proto(
                tx_proof,
            ))),
        };

        let mut client = self.client.clone();
        let response = self
            .rt
            .block_on(client.send_message(request))
            .map_err(|e| transport_err("send_message", e))?
            .into_inner();
        Ok(response.message_id)
    }

    fn fetch_messages(
        &self,
        filter: &MessageFilter,
        signer: &dyn MailboxSigner,
    ) -> Result<Vec<MailboxMessage>, MailboxError> {
        let receiver = match &filter.receiver_key {
            Some(key) => *key,
            // No receiver key matches nothing (same as MockTransport).
            None => return Ok(vec![]),
        };

        self.rt.block_on(self.fetch_messages_async(
            &receiver, filter, signer,
        ))
    }

    fn remove_messages(
        &self,
        receiver: &SerializedKey,
        message_ids: &[u64],
        challenge_sig: &[u8],
    ) -> Result<(), MailboxError> {
        if message_ids.is_empty() {
            return Ok(());
        }

        let request = authmailboxrpc::RemoveMessageRequest {
            receiver_id: receiver.as_bytes().to_vec(),
            message_ids: message_ids.to_vec(),
            signature: challenge_sig.to_vec(),
        };

        let mut client = self.client.clone();
        self.rt
            .block_on(client.remove_message(request))
            .map_err(|e| transport_err("remove_message", e))?;
        Ok(())
    }
}
