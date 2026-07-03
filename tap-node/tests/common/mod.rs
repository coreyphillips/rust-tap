// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional fakes shared by the tap-node integration tests.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::absolute::LockTime;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint as BtcOutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness as BtcWitness};

use tap_node::*;
use tap_onchain::chain::{ChainError, FeeRate};
use tap_onchain::proof::courier::{
    AnnotatedProof, Courier, CourierError, CourierLocator, MockCourier,
    Recipient,
};
use tap_persist::batch_store::{BatchStore, MemoryBatchStore};
use tap_primitives::asset::OutPoint;

use tap_ldk::rfq::manager::RfqError;
use tap_ldk::rfq::math::FixedPoint;

// ---------------------------------------------------------------------------
// FakeChain
// ---------------------------------------------------------------------------

/// A chain backend with scriptable confirmations, a fixed fee, and
/// broadcast recording.
pub struct FakeChain {
    pub confirmations: Mutex<HashMap<[u8; 32], TxConfirmation>>,
    pub broadcasts: Mutex<Vec<Vec<u8>>>,
}

impl FakeChain {
    pub fn new() -> Self {
        FakeChain {
            confirmations: Mutex::new(HashMap::new()),
            broadcasts: Mutex::new(Vec::new()),
        }
    }

    /// Scripts a confirmation for the given raw transaction: a
    /// single-transaction block at `height` with a synthetic header.
    /// Returns the internal-order txid.
    pub fn confirm_tx(&self, tx_bytes: &[u8], height: u32) -> [u8; 32] {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(tx_bytes)
                .expect("valid tx bytes");
        let mut txid = [0u8; 32];
        txid.copy_from_slice(tx.compute_txid().as_ref());

        let mut header = [0u8; 80];
        header[0] = 0x20; // synthetic version bytes
        header[68..72].copy_from_slice(&height.to_le_bytes());

        let conf = TxConfirmation {
            block_hash: [height as u8; 32],
            block_height: height,
            tx_index: 0,
            tx: tx_bytes.to_vec(),
            block_header: header,
            block_tx_hashes: vec![txid],
        };
        self.confirmations
            .lock()
            .expect("confirmations lock")
            .insert(txid, conf);
        txid
    }

    /// The most recently broadcast raw transaction.
    pub fn last_broadcast(&self) -> Option<Vec<u8>> {
        self.broadcasts
            .lock()
            .expect("broadcasts lock")
            .last()
            .cloned()
    }
}

impl ChainBridge for FakeChain {
    fn current_height(&self) -> Result<u32, ChainError> {
        Ok(800_000)
    }
    fn estimate_fee(&self, _: u32) -> Result<FeeRate, ChainError> {
        Ok(FeeRate(2000))
    }
    fn publish_transaction(&self, tx: &[u8]) -> Result<(), ChainError> {
        self.broadcasts
            .lock()
            .expect("broadcasts lock")
            .push(tx.to_vec());
        Ok(())
    }
    fn get_block_hash(&self, height: u32) -> Result<[u8; 32], ChainError> {
        Ok([height as u8; 32])
    }
    fn get_tx_confirmation(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<TxConfirmation>, ChainError> {
        Ok(self
            .confirmations
            .lock()
            .expect("confirmations lock")
            .get(txid)
            .cloned())
    }
}

// ---------------------------------------------------------------------------
// FakeWallet
// ---------------------------------------------------------------------------

/// The deterministic funding UTXO the fake wallet always selects
/// (internal byte order).
pub const FUNDING_OUTPOINT: OutPoint = OutPoint {
    txid: [0xF0; 32],
    vout: 7,
};

/// A wallet that "funds" a template transaction by prepending a
/// deterministic input and appending a BTC change output, then wraps
/// the result in a PSBT. Signing returns the (unsigned) transaction
/// bytes.
pub struct FakeWallet;

impl WalletAnchor for FakeWallet {
    fn fund_psbt(
        &self,
        raw_tx: &[u8],
        _fee_rate: FeeRate,
    ) -> Result<Vec<u8>, ChainError> {
        let mut tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(raw_tx).map_err(|e| {
                ChainError::PsbtFailed(format!("template: {}", e))
            })?;

        // Prepend the deterministic funding input.
        let funding = TxIn {
            previous_output: BtcOutPoint {
                txid: bitcoin::Txid::from_raw_hash(
                    <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>
                        ::from_byte_array(FUNDING_OUTPOINT.txid),
                ),
                vout: FUNDING_OUTPOINT.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: BtcWitness::new(),
        };
        tx.input.insert(0, funding);

        // Append a BTC change output (not a 330-sat P2TR output, so it
        // can never be mistaken for a TAP commitment output).
        tx.output.push(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([0u8; 4]),
        });

        // Version 2 with no locktime, like a real funded anchor.
        tx.version = Version::TWO;
        tx.lock_time = LockTime::ZERO;

        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .map_err(|e| ChainError::PsbtFailed(format!("psbt: {}", e)))?;
        Ok(psbt.serialize())
    }

    fn sign_and_finalize_psbt(
        &self,
        funded_psbt: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        let psbt = bitcoin::psbt::Psbt::deserialize(funded_psbt)
            .map_err(|e| ChainError::PsbtFailed(format!("psbt: {}", e)))?;
        Ok(bitcoin::consensus::serialize(&psbt.unsigned_tx))
    }

    fn import_taproot_output(
        &self,
        _internal_key: &SerializedKey,
    ) -> Result<(), ChainError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeKeys
// ---------------------------------------------------------------------------

/// Deterministic secp keys: index N uses the secret [N+1; 32]. The
/// signer honors the `AssetSigner` BIP-86 contract: the 32-byte
/// sighash is signed with the BIP-86 tweaked key for the requested
/// descriptor.
pub struct FakeKeys {
    next_index: Mutex<u32>,
}

impl FakeKeys {
    pub fn new() -> Self {
        FakeKeys {
            next_index: Mutex::new(0),
        }
    }

    pub fn secret_for(index: u32) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[(index + 1) as u8; 32])
            .expect("valid secret")
    }

    pub fn pub_key_for(index: u32) -> SerializedKey {
        let secp = Secp256k1::new();
        SerializedKey(Self::secret_for(index).public_key(&secp).serialize())
    }
}

impl KeyRing for FakeKeys {
    fn derive_next_key(
        &self,
        family: u16,
    ) -> Result<KeyDescriptor, ChainError> {
        let mut next = self.next_index.lock().expect("index lock");
        let index = *next;
        *next += 1;
        Ok(KeyDescriptor {
            family,
            index,
            pub_key: Self::pub_key_for(index),
        })
    }

    fn is_local_key(
        &self,
        key_desc: &KeyDescriptor,
    ) -> Result<bool, ChainError> {
        Ok(*key_desc.pub_key.as_bytes()
            == Self::pub_key_for(key_desc.index).0)
    }
}

impl AssetSigner for FakeKeys {
    fn sign_virtual_tx(
        &self,
        signing_key: &KeyDescriptor,
        virtual_tx: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        let digest: [u8; 32] = virtual_tx.try_into().map_err(|_| {
            ChainError::SigningFailed(
                "expected 32-byte sighash digest".into(),
            )
        })?;

        // Re-derive the secret for the descriptor and check it matches.
        if signing_key.pub_key != Self::pub_key_for(signing_key.index) {
            return Err(ChainError::SigningFailed(
                "unknown key descriptor".into(),
            ));
        }

        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::from_secret_key(
            &secp,
            &Self::secret_for(signing_key.index),
        );
        // BIP-86 taproot tweak (empty script tree), per the contract.
        let tweaked = keypair.tap_tweak(&secp, None);
        let msg = secp256k1::Message::from_digest(digest);
        let sig =
            secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        Ok(sig.serialize().to_vec())
    }
}

// ---------------------------------------------------------------------------
// LDK / oracle stubs
// ---------------------------------------------------------------------------

pub struct FakeLdk;

impl LdkChannelOps for FakeLdk {
    fn forward_intercepted_htlc(
        &self,
        _: [u8; 32],
        _: u64,
        _: [u8; 33],
        _: u64,
    ) -> Result<(), String> {
        Ok(())
    }
    fn fail_intercepted_htlc(&self, _: [u8; 32]) -> Result<(), String> {
        Ok(())
    }
}

pub struct FakeOracle;

impl PriceOracle for FakeOracle {
    fn ask_price(
        &self,
        _: &AssetId,
        _: u64,
    ) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(5000))
    }
    fn bid_price(
        &self,
        _: &AssetId,
        _: u64,
    ) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(5000))
    }
}

// ---------------------------------------------------------------------------
// Shared store / courier wrappers
// ---------------------------------------------------------------------------

/// A batch store handle the test keeps a reference to, so batch state
/// persisted by the node can be asserted on.
pub struct SharedBatchStore(pub Arc<Mutex<MemoryBatchStore>>);

impl BatchStore for SharedBatchStore {
    fn save_batch(
        &mut self,
        batch: &tap_onchain::mint::MintingBatch,
    ) -> Result<(), String> {
        self.0.lock().expect("batch store lock").save_batch(batch)
    }
    fn load_batch(
        &self,
        batch_key: &SerializedKey,
    ) -> Result<Option<tap_onchain::mint::MintingBatch>, String> {
        self.0
            .lock()
            .expect("batch store lock")
            .load_batch(batch_key)
    }
    fn update_state(
        &mut self,
        batch_key: &SerializedKey,
        state: tap_onchain::mint::BatchState,
    ) -> Result<(), String> {
        self.0
            .lock()
            .expect("batch store lock")
            .update_state(batch_key, state)
    }
    fn list_batches(&self) -> Vec<tap_onchain::mint::MintingBatch> {
        self.0.lock().expect("batch store lock").list_batches()
    }
}

/// A courier wrapper so the test and the node share the same
/// in-memory proof mailbox.
pub struct SharedCourier(pub Arc<MockCourier>);

impl Courier for SharedCourier {
    fn deliver_proof(
        &self,
        recipient: &Recipient,
        proof: &AnnotatedProof,
    ) -> Result<(), CourierError> {
        self.0.deliver_proof(recipient, proof)
    }
    fn receive_proof(
        &self,
        recipient: &Recipient,
        locator: &CourierLocator,
    ) -> Result<AnnotatedProof, CourierError> {
        self.0.receive_proof(recipient, locator)
    }
}

// ---------------------------------------------------------------------------
// Node building and event helpers
// ---------------------------------------------------------------------------

/// A chain bridge wrapper so the test keeps a handle to the fake
/// chain the node owns.
pub struct SharedChain(pub Arc<FakeChain>);

impl ChainBridge for SharedChain {
    fn current_height(&self) -> Result<u32, ChainError> {
        self.0.current_height()
    }
    fn estimate_fee(&self, t: u32) -> Result<FeeRate, ChainError> {
        self.0.estimate_fee(t)
    }
    fn publish_transaction(&self, tx: &[u8]) -> Result<(), ChainError> {
        self.0.publish_transaction(tx)
    }
    fn get_block_hash(&self, h: u32) -> Result<[u8; 32], ChainError> {
        self.0.get_block_hash(h)
    }
    fn get_tx_confirmation(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<TxConfirmation>, ChainError> {
        self.0.get_tx_confirmation(txid)
    }
}

pub type SharedTestNode =
    TapNode<SharedChain, FakeWallet, FakeKeys, FakeLdk, FakeOracle>;

/// Builds a node over the shared fakes with the given config.
pub fn build_harness(config: TapNodeConfig) -> Harness {
    let chain = Arc::new(FakeChain::new());
    let batch_store = Arc::new(Mutex::new(MemoryBatchStore::new()));
    let courier = Arc::new(MockCourier::new());

    let node = TapNodeBuilder::new(config)
        .set_chain_bridge(SharedChain(Arc::clone(&chain)))
        .set_wallet_anchor(FakeWallet)
        .set_key_ring(FakeKeys::new())
        .set_ldk_ops(FakeLdk)
        .set_price_oracle(FakeOracle)
        .set_batch_store(Box::new(SharedBatchStore(Arc::clone(
            &batch_store,
        ))))
        .set_courier(Box::new(SharedCourier(Arc::clone(&courier))))
        .build()
        .expect("node builds");

    let events = node.event_receiver().expect("event receiver");

    Harness {
        node: Arc::new(node),
        chain,
        batch_store,
        courier,
        events,
    }
}

/// The default harness with a regtest config.
pub fn default_harness() -> Harness {
    build_harness(TapNodeConfig::default())
}

pub struct Harness {
    pub node: Arc<SharedTestNode>,
    pub chain: Arc<FakeChain>,
    pub batch_store: Arc<Mutex<MemoryBatchStore>>,
    pub courier: Arc<MockCourier>,
    pub events: std::sync::mpsc::Receiver<TapEvent>,
}

impl Harness {
    /// Drains all currently queued events.
    pub fn drain_events(&self) -> Vec<TapEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            events.push(event);
        }
        events
    }
}

/// Converts a display-order txid (as reported in results/events) to
/// the internal byte order used by outpoints and proof locators.
pub fn to_internal(txid_display: [u8; 32]) -> [u8; 32] {
    let mut txid = txid_display;
    txid.reverse();
    txid
}
