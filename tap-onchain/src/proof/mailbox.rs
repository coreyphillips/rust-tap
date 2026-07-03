// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Auth mailbox courier client for V2 TAP address sends, mirroring Go's
//! `authmailbox` package (message/client types) and the send-fragment
//! delivery path of `proof/courier.go`
//! (`UniverseRpcCourier.deliverFragment`).
//!
//! The module is transport-agnostic: [`MailboxTransport`] is the seam a
//! gRPC (authmailboxrpc) implementation plugs into. Only an in-memory
//! [`MockTransport`] is provided here; the gRPC transport is a
//! follow-up.
//!
//! Sender side: [`deliver_send_manifest`] encodes a
//! [`SendFragment`], ECIES-encrypts it to the receiver key with a fresh
//! ephemeral key (whose public part travels as the AEAD additional
//! data), and posts it to the mailbox together with a [`TxProof`] that
//! serves as proof-of-work for the mailbox server.
//!
//! Receiver side: [`decrypt_send_fragment`] mirrors Go's
//! `Custodian.decryptMailboxMsg` — extract the sender's ephemeral key
//! from the additional data, ECDH with the receiver key, decrypt,
//! decode, and validate the fragment.

use std::collections::HashMap;
use std::sync::Mutex;

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::crypto::ecies;
use tap_primitives::proof::send_fragment::{
    SendFragment, SendOutput, SendFragmentVersion,
};
use tap_primitives::proof::tx_proof::TxProof;
use tap_primitives::proof::types::{AnchorTx, BlockHeader};
use tap_primitives::proof::verify::{
    DefaultMerkleVerifier, HeaderVerifier,
};
use tap_primitives::proof::ProofError;

use std::collections::BTreeMap;

/// The maximum size of a mailbox message in bytes. Matches Go's
/// `authmailbox.MsgMaxSize`.
pub const MSG_MAX_SIZE: usize = 65536;

/// Errors from mailbox operations.
#[derive(Debug, Clone)]
pub enum MailboxError {
    /// A message exceeds the maximum allowed length. Matches Go's
    /// `ErrMessageTooLong`.
    MessageTooLong(usize),
    /// A message with the given ID or outpoint cannot be found.
    /// Matches Go's `ErrMessageNotFound`.
    MessageNotFound,
    /// Encryption or decryption failed.
    Crypto(String),
    /// Fragment or proof encoding/decoding failed.
    Encoding(String),
    /// The tx proof or fragment failed validation.
    InvalidProof(String),
    /// Transport-level failure.
    Transport(String),
    /// The signer does not know the requested key.
    UnknownKey,
    /// No transport is configured.
    NoTransport,
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailboxError::MessageTooLong(n) => write!(
                f,
                "message too long: {} bytes, max {} bytes",
                n, MSG_MAX_SIZE
            ),
            MailboxError::MessageNotFound => {
                write!(f, "message not found")
            }
            MailboxError::Crypto(msg) => {
                write!(f, "mailbox crypto error: {}", msg)
            }
            MailboxError::Encoding(msg) => {
                write!(f, "mailbox encoding error: {}", msg)
            }
            MailboxError::InvalidProof(msg) => {
                write!(f, "invalid mailbox proof: {}", msg)
            }
            MailboxError::Transport(msg) => {
                write!(f, "mailbox transport error: {}", msg)
            }
            MailboxError::UnknownKey => {
                write!(f, "signer does not know the requested key")
            }
            MailboxError::NoTransport => {
                write!(f, "no mailbox transport configured")
            }
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<ecies::EciesError> for MailboxError {
    fn from(e: ecies::EciesError) -> Self {
        MailboxError::Crypto(e.to_string())
    }
}

impl From<ProofError> for MailboxError {
    fn from(e: ProofError) -> Self {
        MailboxError::InvalidProof(e.to_string())
    }
}

/// A message in the mailbox, mirroring Go's `authmailbox.Message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxMessage {
    /// The unique identifier for this message, assigned by the mailbox
    /// server.
    pub id: u64,
    /// The intended recipient of the message (the receiver's public
    /// key; for V2 TAP addresses this is the address script key).
    pub receiver_key: SerializedKey,
    /// The encrypted message payload (ECIES).
    pub encrypted_payload: Vec<u8>,
    /// Unix timestamp (seconds) when the message was received and
    /// validated by the mailbox server.
    pub arrival_timestamp: u64,
    /// The block height of the block that was used as the tx proof for
    /// this message.
    pub proof_block_height: u32,
}

/// Filters messages based on certain criteria, mirroring Go's
/// `authmailbox.MessageFilter`. Zero values mean "unset".
#[derive(Clone, Debug, Default)]
pub struct MessageFilter {
    /// The message receiver's public key. A zeroed key matches
    /// nothing.
    pub receiver_key: Option<SerializedKey>,
    /// Unix timestamp (seconds); only messages that arrived after this
    /// time are returned (exclusive).
    pub after: u64,
    /// Only messages with an ID greater than this are returned
    /// (exclusive).
    pub after_id: u64,
    /// Only messages whose proof block height is at this height or
    /// later are returned (inclusive).
    pub start_block: u32,
}

impl MessageFilter {
    /// Returns true if the filter is set to deliver existing messages,
    /// mirroring Go's `MessageFilter.DeliverExisting`.
    pub fn deliver_existing(&self) -> bool {
        self.after != 0 || self.start_block != 0 || self.after_id != 0
    }
}

/// Computes the challenge hash for removing messages:
/// `SHA256(receiver_id || big-endian uint64 msg_id_1 || ...)`.
/// Mirrors Go's `authmailbox.RemoveMessageChallenge`.
pub fn remove_message_challenge(
    receiver_id: &[u8],
    message_ids: &[u64],
) -> [u8; 32] {
    use bitcoin_hashes::{sha256, Hash, HashEngine};

    let mut engine = sha256::Hash::engine();
    engine.input(receiver_id);
    for id in message_ids {
        engine.input(&id.to_be_bytes());
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Key operations the mailbox client needs from the wallet: ECDH for
/// decrypting incoming fragments and Schnorr signing for the remove /
/// subscription challenges. Go performs both through lnd's signer RPC
/// (`DeriveSharedKey` / `SignMessage`).
pub trait MailboxSigner {
    /// Performs ECDH between the local private key identified by
    /// `local_key` (its public key) and `remote_pub`, returning
    /// `sha256(compressed shared point)` per Go's `ecies.ECDH` /
    /// lnd's `DeriveSharedKey`.
    fn ecdh(
        &self,
        local_key: &SerializedKey,
        remote_pub: &SerializedKey,
    ) -> Result<[u8; 32], MailboxError>;

    /// Schnorr-signs a 32-byte challenge with the local key identified
    /// by `local_key`.
    fn sign_challenge(
        &self,
        local_key: &SerializedKey,
        challenge: &[u8; 32],
    ) -> Result<Vec<u8>, MailboxError>;
}

/// A software [`MailboxSigner`] holding raw secret keys in memory.
/// Intended for tests and simple deployments; production wallets should
/// implement [`MailboxSigner`] against their key store.
#[derive(Default)]
pub struct SoftMailboxSigner {
    keys: HashMap<[u8; 33], secp256k1::SecretKey>,
}

impl SoftMailboxSigner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a secret key, returning its public key.
    pub fn add_key(&mut self, sk: secp256k1::SecretKey) -> SerializedKey {
        let secp = secp256k1::Secp256k1::new();
        let pub_key = SerializedKey(sk.public_key(&secp).serialize());
        self.keys.insert(pub_key.0, sk);
        pub_key
    }

    fn key_for(
        &self,
        local_key: &SerializedKey,
    ) -> Result<&secp256k1::SecretKey, MailboxError> {
        self.keys.get(&local_key.0).ok_or(MailboxError::UnknownKey)
    }
}

impl MailboxSigner for SoftMailboxSigner {
    fn ecdh(
        &self,
        local_key: &SerializedKey,
        remote_pub: &SerializedKey,
    ) -> Result<[u8; 32], MailboxError> {
        let sk = self.key_for(local_key)?;
        let pk = secp256k1::PublicKey::from_slice(remote_pub.as_bytes())
            .map_err(|e| MailboxError::Crypto(e.to_string()))?;
        Ok(ecies::ecdh(sk, &pk)?)
    }

    fn sign_challenge(
        &self,
        local_key: &SerializedKey,
        challenge: &[u8; 32],
    ) -> Result<Vec<u8>, MailboxError> {
        use secp256k1::{Keypair, Message, Secp256k1};

        let sk = self.key_for(local_key)?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, sk);
        let msg = Message::from_digest(*challenge);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Ok(sig.as_ref().to_vec())
    }
}

/// Transport abstraction over the auth mailbox server RPCs
/// (`authmailboxrpc.Mailbox`): `SendMessage`, message subscription /
/// fetching, and `RemoveMessage`. A gRPC implementation is a follow-up;
/// tests use [`MockTransport`].
pub trait MailboxTransport {
    /// Sends an encrypted message to the mailbox server for the given
    /// receiver (33-byte compressed key), authenticated by the tx
    /// proof. Returns the server-assigned message ID. Mirrors Go's
    /// `Client.SendMessage`.
    fn send_message(
        &self,
        receiver: &SerializedKey,
        encrypted_payload: &[u8],
        tx_proof: &TxProof,
    ) -> Result<u64, MailboxError>;

    /// Fetches messages matching the filter. The signer authenticates
    /// the receiver key ownership with the server (Go performs a
    /// 3-way handshake on the subscription stream; the mock ignores
    /// it).
    fn fetch_messages(
        &self,
        filter: &MessageFilter,
        signer: &dyn MailboxSigner,
    ) -> Result<Vec<MailboxMessage>, MailboxError>;

    /// Requests the server to delete one or more messages belonging to
    /// the receiver. `challenge_sig` is a Schnorr signature over
    /// [`remove_message_challenge`], proving ownership. Mirrors Go's
    /// `Client.RemoveMessages`.
    fn remove_messages(
        &self,
        receiver: &SerializedKey,
        message_ids: &[u64],
        challenge_sig: &[u8],
    ) -> Result<(), MailboxError>;
}

/// Allows sharing one transport between a sender and a receiver (e.g.
/// in tests, or a node that both sends and receives).
impl<T: MailboxTransport + ?Sized> MailboxTransport
    for std::sync::Arc<T>
{
    fn send_message(
        &self,
        receiver: &SerializedKey,
        encrypted_payload: &[u8],
        tx_proof: &TxProof,
    ) -> Result<u64, MailboxError> {
        (**self).send_message(receiver, encrypted_payload, tx_proof)
    }

    fn fetch_messages(
        &self,
        filter: &MessageFilter,
        signer: &dyn MailboxSigner,
    ) -> Result<Vec<MailboxMessage>, MailboxError> {
        (**self).fetch_messages(filter, signer)
    }

    fn remove_messages(
        &self,
        receiver: &SerializedKey,
        message_ids: &[u64],
        challenge_sig: &[u8],
    ) -> Result<(), MailboxError> {
        (**self).remove_messages(receiver, message_ids, challenge_sig)
    }
}

/// The shipping instruction for a V2 TAP address send, mirroring Go's
/// `proof.SendManifest`. The manifest itself isn't encoded; only the
/// fragment is serialized, encrypted, and sent to the auth mailbox
/// server as a message.
#[derive(Clone, Debug)]
pub struct SendManifest {
    /// Proof of the transaction that contains the asset outputs being
    /// sent. Used as proof-of-work for the auth mailbox server.
    pub tx_proof: TxProof,
    /// The receiver's public key, used to encrypt the send fragment.
    /// For V2 addresses this is the address script key (Go:
    /// `addr.ScriptKey` in `createSendManifests`).
    pub receiver: SerializedKey,
    /// URL of the auth mailbox server that will be used to send the
    /// fragment to the receiver.
    pub courier_url: String,
    /// The send fragment that contains all the information the
    /// receiver needs to reconstruct the asset outputs and fetch proofs
    /// from the universe.
    pub fragment: SendFragment,
}

/// Builds a [`SendFragment`] for a completed transfer, mirroring how
/// Go's tapfreighter fills the fragment in `createSendManifests` and
/// `ChainPorter` (chain_porter.go: outpoint, header, height, and
/// taproot asset root are set once the anchor transaction confirms).
pub fn build_send_fragment(
    block_header: BlockHeader,
    block_height: u32,
    anchor_outpoint: OutPoint,
    taproot_asset_root: [u8; 32],
    outputs: BTreeMap<AssetId, SendOutput>,
) -> Result<SendFragment, MailboxError> {
    let fragment = SendFragment {
        version: SendFragmentVersion::V1,
        block_header,
        block_height,
        outpoint: anchor_outpoint,
        outputs,
        taproot_asset_root,
        unknown_odd_types: BTreeMap::new(),
    };
    fragment.validate()?;
    Ok(fragment)
}

/// Builds a [`TxProof`] for a confirmed anchor transaction, computing
/// the tx merkle proof from the block's transaction hashes. Mirrors the
/// `proof.TxProof` construction in Go's chain porter
/// (tapfreighter/chain_porter.go).
pub fn build_tx_proof(
    anchor_tx: AnchorTx,
    block_header: BlockHeader,
    block_height: u32,
    block_tx_hashes: &[[u8; 32]],
    claimed_vout: u32,
    anchor_internal_key: SerializedKey,
    anchor_merkle_root: Option<[u8; 32]>,
) -> Result<TxProof, MailboxError> {
    let txid = anchor_tx.txid();
    let tx_index = block_tx_hashes
        .iter()
        .position(|h| *h == txid)
        .ok_or_else(|| {
            MailboxError::InvalidProof(
                "anchor tx not found in block".into(),
            )
        })?;

    let merkle_proof =
        super::merkle::build_tx_merkle_proof(block_tx_hashes, tx_index)
            .ok_or_else(|| {
                MailboxError::InvalidProof(
                    "unable to build tx merkle proof".into(),
                )
            })?;

    Ok(TxProof {
        msg_tx: anchor_tx,
        block_header,
        block_height,
        merkle_proof,
        claimed_outpoint: OutPoint {
            txid,
            vout: claimed_vout,
        },
        internal_key: anchor_internal_key,
        merkle_root: anchor_merkle_root,
    })
}

/// Delivers a send manifest to the receiver through the given mailbox
/// transport, mirroring Go's `UniverseRpcCourier.deliverFragment`
/// (proof/courier.go):
///
/// 1. Generate an ephemeral key pair.
/// 2. ECDH between the ephemeral private key and the receiver key.
/// 3. Encode the fragment and ECIES-encrypt it with the shared secret,
///    with the ephemeral public key as the additional data.
/// 4. Post the encrypted payload plus the tx proof to the mailbox.
///
/// Returns the server-assigned message ID.
pub fn deliver_send_manifest(
    transport: &dyn MailboxTransport,
    manifest: &SendManifest,
) -> Result<u64, MailboxError> {
    // We generate an ephemeral key pair to create the shared secret to
    // encrypt the send fragment with. The public key of the pair is
    // part of the encrypted payload (as AEAD additional data), so the
    // private key is thrown away after the ECDH operation.
    let secp = secp256k1::Secp256k1::new();
    let ephemeral_sk = loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| MailboxError::Crypto(e.to_string()))?;
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&bytes) {
            break sk;
        }
    };
    let sender_key_bytes =
        ephemeral_sk.public_key(&secp).serialize();

    let receiver_pub =
        secp256k1::PublicKey::from_slice(manifest.receiver.as_bytes())
            .map_err(|e| MailboxError::Crypto(e.to_string()))?;
    let shared_secret = ecies::ecdh(&ephemeral_sk, &receiver_pub)?;

    let msg = manifest.fragment.encode();

    let encrypted_payload = ecies::encrypt_sha256_chacha20_poly1305(
        &shared_secret,
        &msg,
        &sender_key_bytes,
    )?;

    if encrypted_payload.len() > MSG_MAX_SIZE {
        return Err(MailboxError::MessageTooLong(
            encrypted_payload.len(),
        ));
    }

    transport.send_message(
        &manifest.receiver,
        &encrypted_payload,
        &manifest.tx_proof,
    )
}

/// Decrypts and decodes a mailbox message into a validated
/// [`SendFragment`], mirroring Go's `Custodian.decryptMailboxMsg`
/// (tapgarden/custodian.go): the sender's ephemeral public key is
/// extracted from the ECIES additional data, the shared key is derived
/// via the signer's ECDH, and the decrypted payload is decoded and
/// validated.
pub fn decrypt_send_fragment(
    signer: &dyn MailboxSigner,
    receiver_key: &SerializedKey,
    encrypted_payload: &[u8],
) -> Result<SendFragment, MailboxError> {
    let (_version, additional_data, _remainder) =
        ecies::extract_additional_data(encrypted_payload)?;

    let sender_pub: [u8; 33] =
        additional_data.try_into().map_err(|_| {
            MailboxError::Crypto(
                "unable to parse sender public key from additional \
                 data"
                    .into(),
            )
        })?;

    let shared_key =
        signer.ecdh(receiver_key, &SerializedKey(sender_pub))?;

    let decrypted = ecies::decrypt_sha256_chacha20_poly1305(
        &shared_key,
        encrypted_payload,
    )?;

    let fragment = SendFragment::decode(&decrypted)
        .map_err(|e| MailboxError::Encoding(e.to_string()))?;

    fragment.validate()?;

    Ok(fragment)
}

/// A header "verifier" that accepts any header. The mock mailbox server
/// has no chain access; a real server verifies headers against the
/// chain (Go: the mailbox server's proof verification).
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

/// An in-memory [`MailboxTransport`] for tests, loosely mirroring Go's
/// `authmailbox.MockMsgStore` plus server-side validation: incoming
/// messages must be within [`MSG_MAX_SIZE`], the tx proof must verify
/// structurally (outpoint, P2TR construction, and merkle inclusion; the
/// header itself is trusted since there is no chain), and a claimed
/// outpoint can only be used once.
#[derive(Default)]
pub struct MockTransport {
    inner: Mutex<MockTransportInner>,
}

#[derive(Default)]
struct MockTransportInner {
    next_id: u64,
    messages: Vec<MailboxMessage>,
    claimed_outpoints: Vec<OutPoint>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of messages currently in the mailbox.
    pub fn num_messages(&self) -> usize {
        self.inner.lock().expect("mock lock").messages.len()
    }
}

impl MailboxTransport for MockTransport {
    fn send_message(
        &self,
        receiver: &SerializedKey,
        encrypted_payload: &[u8],
        tx_proof: &TxProof,
    ) -> Result<u64, MailboxError> {
        if encrypted_payload.len() > MSG_MAX_SIZE {
            return Err(MailboxError::MessageTooLong(
                encrypted_payload.len(),
            ));
        }

        // The server verifies the tx proof before accepting a message.
        tx_proof
            .verify(&AcceptAllHeaders, &DefaultMerkleVerifier)
            .map_err(|e| MailboxError::InvalidProof(e.to_string()))?;

        let mut inner = self.inner.lock().expect("mock lock");

        // Each claimed outpoint can only ever be used for one message
        // (Go: ErrTxMerkleProofExists).
        if inner
            .claimed_outpoints
            .contains(&tx_proof.claimed_outpoint)
        {
            return Err(MailboxError::InvalidProof(
                "tx merkle proof already exists".into(),
            ));
        }

        inner.next_id += 1;
        let id = inner.next_id;
        let claimed_outpoint = tx_proof.claimed_outpoint;
        inner.claimed_outpoints.push(claimed_outpoint);
        inner.messages.push(MailboxMessage {
            id,
            receiver_key: *receiver,
            encrypted_payload: encrypted_payload.to_vec(),
            arrival_timestamp: 0,
            proof_block_height: tx_proof.block_height,
        });

        Ok(id)
    }

    fn fetch_messages(
        &self,
        filter: &MessageFilter,
        _signer: &dyn MailboxSigner,
    ) -> Result<Vec<MailboxMessage>, MailboxError> {
        let receiver = match &filter.receiver_key {
            Some(key) => *key,
            None => return Ok(vec![]),
        };

        let inner = self.inner.lock().expect("mock lock");
        Ok(inner
            .messages
            .iter()
            .filter(|m| {
                m.receiver_key == receiver
                    && m.id > filter.after_id
                    && (filter.after == 0
                        || m.arrival_timestamp > filter.after)
                    && (filter.start_block == 0
                        || m.proof_block_height >= filter.start_block)
            })
            .cloned()
            .collect())
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

        // The mock only checks that a plausible Schnorr signature was
        // provided; a real server verifies it against the challenge.
        if challenge_sig.len() != 64 {
            return Err(MailboxError::Transport(
                "invalid challenge signature".into(),
            ));
        }

        let mut inner = self.inner.lock().expect("mock lock");
        inner.messages.retain(|m| {
            m.receiver_key != *receiver || !message_ids.contains(&m.id)
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::AssetVersion;
    use tap_primitives::asset::ScriptKeyDerivationMethod;
    use tap_primitives::crypto::tapscript::taproot_output_key;

    fn test_secret(byte: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[byte; 32]).expect("valid key")
    }

    fn test_pub(byte: u8) -> SerializedKey {
        let secp = secp256k1::Secp256k1::new();
        SerializedKey(
            test_secret(byte).public_key(&secp).serialize(),
        )
    }

    /// Builds a single-tx-block tx proof whose claimed output is a
    /// valid BIP-86 P2TR output for `internal_key`.
    fn test_tx_proof(internal_key: SerializedKey) -> TxProof {
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
            123,
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
        let script_key =
            tap_primitives::asset::derive_unique_script_key(
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
                    derivation_method:
                        ScriptKeyDerivationMethod::UniquePedersen,
                    script_key,
                },
            )]),
        )
        .expect("valid fragment")
    }

    #[test]
    fn test_remove_message_challenge_format() {
        use bitcoin_hashes::{sha256, Hash, HashEngine};

        let receiver = [0x02; 33];
        let ids = [1u64, 2, 0xDEADBEEF];

        // SHA256(receiver_id || BE(id1) || BE(id2) || BE(id3)).
        let mut engine = sha256::Hash::engine();
        engine.input(&receiver);
        engine.input(&1u64.to_be_bytes());
        engine.input(&2u64.to_be_bytes());
        engine.input(&0xDEADBEEFu64.to_be_bytes());
        let expected =
            sha256::Hash::from_engine(engine).to_byte_array();

        assert_eq!(remove_message_challenge(&receiver, &ids), expected);

        // Different ID order yields a different challenge.
        assert_ne!(
            remove_message_challenge(&receiver, &[2, 1, 0xDEADBEEF]),
            expected
        );
    }

    #[test]
    fn test_deliver_and_receive_round_trip() {
        // Receiver key pair (the V2 address script key).
        let receiver_sk = test_secret(0x21);
        let mut signer = SoftMailboxSigner::new();
        let receiver_key = signer.add_key(receiver_sk);

        let anchor_internal_key = test_pub(0x31);
        let tx_proof = test_tx_proof(anchor_internal_key);
        let fragment =
            test_fragment(&receiver_key, tx_proof.claimed_outpoint);

        let manifest = SendManifest {
            tx_proof,
            receiver: receiver_key,
            courier_url:
                "authmailbox+universerpc://localhost:10029".to_string(),
            fragment: fragment.clone(),
        };

        let transport = MockTransport::new();
        let msg_id =
            deliver_send_manifest(&transport, &manifest).unwrap();
        assert_eq!(msg_id, 1);
        assert_eq!(transport.num_messages(), 1);

        // The receiver fetches and decrypts the message.
        let filter = MessageFilter {
            receiver_key: Some(receiver_key),
            ..Default::default()
        };
        let messages =
            transport.fetch_messages(&filter, &signer).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].proof_block_height, 123);

        let decrypted = decrypt_send_fragment(
            &signer,
            &receiver_key,
            &messages[0].encrypted_payload,
        )
        .unwrap();
        assert_eq!(decrypted, fragment);

        // Cursor-style fetching: nothing newer than the last ID.
        let filter_after = MessageFilter {
            receiver_key: Some(receiver_key),
            after_id: msg_id,
            ..Default::default()
        };
        assert!(transport
            .fetch_messages(&filter_after, &signer)
            .unwrap()
            .is_empty());

        // Remove the message with a signed challenge.
        let challenge = remove_message_challenge(
            receiver_key.as_bytes(),
            &[msg_id],
        );
        let sig = signer
            .sign_challenge(&receiver_key, &challenge)
            .unwrap();
        transport
            .remove_messages(&receiver_key, &[msg_id], &sig)
            .unwrap();
        assert_eq!(transport.num_messages(), 0);
    }

    #[test]
    fn test_wrong_receiver_cannot_decrypt() {
        let receiver_sk = test_secret(0x21);
        let mut signer = SoftMailboxSigner::new();
        let receiver_key = signer.add_key(receiver_sk);

        // A different key on the same signer.
        let other_key = signer.add_key(test_secret(0x22));

        let tx_proof = test_tx_proof(test_pub(0x31));
        let fragment =
            test_fragment(&receiver_key, tx_proof.claimed_outpoint);

        let transport = MockTransport::new();
        deliver_send_manifest(
            &transport,
            &SendManifest {
                tx_proof,
                receiver: receiver_key,
                courier_url: String::new(),
                fragment,
            },
        )
        .unwrap();

        let filter = MessageFilter {
            receiver_key: Some(receiver_key),
            ..Default::default()
        };
        let messages =
            transport.fetch_messages(&filter, &signer).unwrap();

        let result = decrypt_send_fragment(
            &signer,
            &other_key,
            &messages[0].encrypted_payload,
        );
        assert!(matches!(result, Err(MailboxError::Crypto(_))));
    }

    #[test]
    fn test_mock_rejects_invalid_tx_proof() {
        let mut tx_proof = test_tx_proof(test_pub(0x31));
        // Corrupt the claimed outpoint.
        tx_proof.claimed_outpoint.txid = [0xEE; 32];

        let transport = MockTransport::new();
        let result = transport.send_message(
            &test_pub(0x21),
            &[0u8; 64],
            &tx_proof,
        );
        assert!(matches!(result, Err(MailboxError::InvalidProof(_))));
    }

    #[test]
    fn test_mock_rejects_duplicate_outpoint() {
        let receiver = test_pub(0x21);
        let tx_proof = test_tx_proof(test_pub(0x31));

        let transport = MockTransport::new();
        transport
            .send_message(&receiver, &[0u8; 64], &tx_proof)
            .unwrap();

        let result =
            transport.send_message(&receiver, &[0u8; 64], &tx_proof);
        assert!(matches!(
            result,
            Err(MailboxError::InvalidProof(msg))
                if msg.contains("already exists")
        ));
    }

    #[test]
    fn test_mock_rejects_oversized_message() {
        let transport = MockTransport::new();
        let tx_proof = test_tx_proof(test_pub(0x31));
        let result = transport.send_message(
            &test_pub(0x21),
            &vec![0u8; MSG_MAX_SIZE + 1],
            &tx_proof,
        );
        assert!(matches!(
            result,
            Err(MailboxError::MessageTooLong(_))
        ));
    }
}
