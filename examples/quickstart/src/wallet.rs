// Wallet backends: BDK wallet, TAP key ring, chain, stubs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use bdk_esplora::esplora_client;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::{self as bdk_bitcoin, FeeRate as BdkFeeRate, Network};
use bdk_wallet::file_store::Store;
use bdk_wallet::template::Bip86;
use bdk_wallet::{ChangeSet, KeychainKind, PersistedWallet, SignOptions, Wallet};

use bitcoin::secp256k1::{Keypair, Secp256k1};

use tap_ldk::rfq::math::FixedPoint;
use tap_ldk::rfq::{PriceOracle, RfqError};
use tap_node::*;
use tap_primitives::asset::AssetId;
use tap_primitives::crypto::derivation::*;

const BITCOIN_NETWORK: Network = Network::Testnet;

// ============================================================================
// Esplora Chain Backend
// ============================================================================

pub struct EsploraChain {
    base_url: String,
}

impl EsploraChain {
    pub fn new(url: &str) -> Self {
        EsploraChain {
            base_url: url.trim_end_matches('/').to_string(),
        }
    }

    fn get(&self, path: &str) -> Result<String, ChainError> {
        let url = format!("{}{}", self.base_url, path);
        ureq::get(&url)
            .call()
            .map_err(|e| ChainError::Other(format!("HTTP: {}", e)))?
            .into_string()
            .map_err(|e| ChainError::Other(format!("Read: {}", e)))
    }
}

impl ChainBridge for EsploraChain {
    fn current_height(&self) -> Result<u32, ChainError> {
        self.get("/blocks/tip/height")?
            .trim()
            .parse()
            .map_err(|e| ChainError::Other(format!("Parse: {}", e)))
    }

    fn estimate_fee(&self, conf_target: u32) -> Result<FeeRate, ChainError> {
        let body = self.get("/fee-estimates")?;
        let estimates: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| ChainError::FeeEstimationFailed(e.to_string()))?;
        let target_str = conf_target.to_string();
        let sat_per_vb = estimates
            .get(&target_str)
            .or_else(|| estimates.get("6"))
            .or_else(|| estimates.get("3"))
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);
        Ok(FeeRate((sat_per_vb * 1000.0) as u64))
    }

    fn publish_transaction(&self, tx: &[u8]) -> Result<(), ChainError> {
        let hex: String = tx.iter().map(|b| format!("{:02x}", b)).collect();
        let url = format!("{}/tx", self.base_url);
        match ureq::post(&url).send_string(&hex) {
            Ok(response) => {
                // Esplora returns the txid on success.
                if let Ok(txid) = response.into_string() {
                    println!("  Esplora accepted tx: {}", txid.trim());
                }
                Ok(())
            }
            Err(ureq::Error::Status(code, response)) => {
                let body = response
                    .into_string()
                    .unwrap_or_else(|_| "unknown".into());
                Err(ChainError::BroadcastFailed(format!(
                    "HTTP {}: {}",
                    code,
                    body.trim()
                )))
            }
            Err(e) => Err(ChainError::BroadcastFailed(e.to_string())),
        }
    }

    fn get_block_hash(&self, height: u32) -> Result<[u8; 32], ChainError> {
        let body = self.get(&format!("/block-height/{}", height))?;
        let hex = body.trim();
        if hex.len() != 64 {
            return Err(ChainError::Other("bad hash length".into()));
        }
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }
}

/// Transaction confirmation status from Esplora.
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: u32,
    pub block_hash: String,
}

/// Block data needed for proof construction.
pub struct BlockData {
    /// Raw 80-byte block header.
    pub header: [u8; 80],
    /// All txids in the block (display order hex).
    pub txids: Vec<String>,
    /// Block height.
    pub height: u32,
}

impl EsploraChain {
    /// Checks the confirmation status of a transaction.
    pub fn get_tx_status(&self, txid: &str) -> Result<TxStatus, String> {
        let body = self
            .get(&format!("/tx/{}/status", txid))
            .map_err(|e| format!("tx status: {}", e))?;
        let json: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("parse: {}", e))?;

        let confirmed = json["confirmed"].as_bool().unwrap_or(false);
        if !confirmed {
            return Ok(TxStatus {
                confirmed: false,
                block_height: 0,
                block_hash: String::new(),
            });
        }

        Ok(TxStatus {
            confirmed: true,
            block_height: json["block_height"].as_u64().unwrap_or(0) as u32,
            block_hash: json["block_hash"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Fetches block header and txid list for proof construction.
    pub fn get_block_data(
        &self,
        block_hash: &str,
        height: u32,
    ) -> Result<BlockData, String> {
        // Fetch raw block header (160 hex chars = 80 bytes).
        let header_hex = self
            .get(&format!("/block/{}/header", block_hash))
            .map_err(|e| format!("block header: {}", e))?;
        let header_bytes = hex_decode(header_hex.trim())?;
        if header_bytes.len() != 80 {
            return Err(format!(
                "bad header length: {} (expected 80)",
                header_bytes.len()
            ));
        }
        let mut header = [0u8; 80];
        header.copy_from_slice(&header_bytes);

        // Fetch all txids in the block.
        let txids_body = self
            .get(&format!("/block/{}/txids", block_hash))
            .map_err(|e| format!("block txids: {}", e))?;
        let txids: Vec<String> = serde_json::from_str(&txids_body)
            .map_err(|e| format!("parse txids: {}", e))?;

        Ok(BlockData {
            header,
            txids,
            height,
        })
    }

    /// Fetches the raw transaction bytes.
    pub fn get_raw_tx(&self, txid: &str) -> Result<Vec<u8>, String> {
        let hex = self
            .get(&format!("/tx/{}/hex", txid))
            .map_err(|e| format!("raw tx: {}", e))?;
        hex_decode(hex.trim())
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("hex at {}: {}", i, e))
        })
        .collect()
}

/// Decodes a hex string into a Vec<u8>.
pub fn hex_decode_vec(s: &str) -> Result<Vec<u8>, String> {
    hex_decode(s)
}

/// Decodes a hex string into a fixed-size byte array.
pub fn hex_decode_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != N {
        return Err(format!("expected {} bytes, got {}", N, bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ============================================================================
// BDK Wallet
// ============================================================================

const BDK_DB_MAGIC: &str = "tap-quickstart-bdk";

pub struct BdkAnchorWallet {
    wallet: Mutex<PersistedWallet<Store<ChangeSet>>>,
    db: Mutex<Store<ChangeSet>>,
    esplora_url: String,
}

impl BdkAnchorWallet {
    pub fn from_mnemonic(
        mnemonic_str: &str,
        esplora_url: &str,
        db_path: &str,
    ) -> Result<Self, String> {
        let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic_str)
            .map_err(|e| format!("Invalid mnemonic: {}", e))?;
        let seed = mnemonic.to_seed_normalized("");
        let xprv = Xpriv::new_master(BITCOIN_NETWORK, &seed)
            .map_err(|e| format!("Master key: {}", e))?;

        if let Some(parent) = Path::new(db_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut db = Store::<ChangeSet>::open_or_create_new(
            BDK_DB_MAGIC.as_bytes(),
            db_path,
        )
        .map_err(|e| format!("DB open: {}", e))?;

        // Try to load existing wallet, or create a new one.
        let wallet = match Wallet::load()
            .load_wallet(&mut db)
            .map_err(|e| format!("DB load: {}", e))?
        {
            Some(wallet) => wallet,
            None => {
                Wallet::create(
                    Bip86(xprv, KeychainKind::External),
                    Bip86(xprv, KeychainKind::Internal),
                )
                .network(BITCOIN_NETWORK)
                .create_wallet(&mut db)
                .map_err(|e| format!("Wallet create: {}", e))?
            }
        };

        Ok(BdkAnchorWallet {
            wallet: Mutex::new(wallet),
            db: Mutex::new(db),
            esplora_url: esplora_url.to_string(),
        })
    }

    /// Syncs the wallet with Esplora.
    ///
    /// `stop_gap` controls how many consecutive empty addresses to scan
    /// before stopping. Use 20 for normal operation, 200+ for recovering
    /// a mnemonic that may have prior activity on many addresses.
    pub fn sync(&self, stop_gap: usize) -> Result<(), String> {
        let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();
        let mut wallet = self.wallet.lock().unwrap();

        let request = wallet.start_full_scan().build();
        let update = client
            .full_scan(request, stop_gap, 5)
            .map_err(|e| format!("Sync: {}", e))?;
        wallet
            .apply_update(update)
            .map_err(|e| format!("Update: {}", e))?;

        self.persist_inner(&mut wallet)?;
        Ok(())
    }

    pub fn next_address(&self) -> String {
        let mut wallet = self.wallet.lock().unwrap();
        let addr = wallet
            .next_unused_address(KeychainKind::External)
            .to_string();
        // Persist so the address index is remembered.
        let _ = self.persist_inner(&mut wallet);
        addr
    }

    pub fn balance(&self) -> (u64, u64) {
        let wallet = self.wallet.lock().unwrap();
        let bal = wallet.balance();
        (bal.confirmed.to_sat(), bal.untrusted_pending.to_sat())
    }

    /// Persists wallet changes to the file store.
    fn persist(&self) -> Result<(), String> {
        let mut wallet = self.wallet.lock().unwrap();
        self.persist_inner(&mut wallet)
    }

    fn persist_inner(
        &self,
        wallet: &mut PersistedWallet<Store<ChangeSet>>,
    ) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        wallet
            .persist(&mut *db)
            .map_err(|e| format!("Persist: {}", e))?;
        Ok(())
    }
}

impl WalletAnchor for BdkAnchorWallet {
    fn fund_psbt(&self, raw_tx_bytes: &[u8], fee_rate: FeeRate) -> Result<Vec<u8>, ChainError> {
        let template_tx: bdk_bitcoin::Transaction =
            bdk_bitcoin::consensus::deserialize(raw_tx_bytes)
                .map_err(|e| ChainError::PsbtFailed(format!("Deserialize: {}", e)))?;

        let mut wallet = self.wallet.lock().unwrap();
        let mut builder = wallet.build_tx();
        for output in &template_tx.output {
            builder.add_recipient(output.script_pubkey.clone(), output.value);
        }
        let sat_per_vb = std::cmp::max(fee_rate.0 / 1000, 1);
        builder.fee_rate(BdkFeeRate::from_sat_per_vb(sat_per_vb).unwrap());

        let psbt = builder
            .finish()
            .map_err(|e| ChainError::PsbtFailed(format!("BDK: {}", e)))?;

        // Persist after funding (records the change address derivation).
        let _ = self.persist_inner(&mut wallet);

        Ok(psbt.serialize())
    }

    fn sign_and_finalize_psbt(&self, psbt_bytes: &[u8]) -> Result<Vec<u8>, ChainError> {
        let mut psbt = Psbt::deserialize(psbt_bytes)
            .map_err(|e| ChainError::PsbtFailed(format!("PSBT: {}", e)))?;
        let mut wallet = self.wallet.lock().unwrap();

        let sign_opts = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let finalized = wallet
            .sign(&mut psbt, sign_opts)
            .map_err(|e| ChainError::SigningFailed(format!("Sign: {}", e)))?;

        if !finalized {
            return Err(ChainError::SigningFailed(
                "BDK could not finalize all inputs -- check that all UTXOs belong to this wallet".into(),
            ));
        }

        let tx = psbt
            .extract_tx()
            .map_err(|e| ChainError::PsbtFailed(format!("Extract: {}", e)))?;

        // Persist after signing.
        let _ = self.persist_inner(&mut wallet);

        Ok(bdk_bitcoin::consensus::serialize(&tx))
    }

    fn import_taproot_output(&self, _key: &SerializedKey) -> Result<(), ChainError> {
        Ok(())
    }
}

// ============================================================================
// TAP Key Ring
// ============================================================================

pub struct TapKeyRing {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    master: bitcoin::bip32::Xpriv,
    coin_type: u32,
    next_index: AtomicU32,
    keypairs: Mutex<Vec<(KeyDescriptor, Keypair)>>,
}

impl TapKeyRing {
    pub fn from_mnemonic(mnemonic_str: &str) -> Result<Self, String> {
        let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic_str)
            .map_err(|e| format!("Mnemonic: {}", e))?;
        let seed = mnemonic.to_seed_normalized("");
        let secp = Secp256k1::new();
        let master = bitcoin::bip32::Xpriv::new_master(BITCOIN_NETWORK, &seed)
            .map_err(|e| format!("Master: {}", e))?;
        Ok(TapKeyRing {
            secp,
            master,
            coin_type: coin_type_for_network(BITCOIN_NETWORK),
            next_index: AtomicU32::new(0),
            keypairs: Mutex::new(Vec::new()),
        })
    }
}

impl KeyRing for TapKeyRing {
    fn derive_next_key(&self, family: u16) -> Result<KeyDescriptor, ChainError> {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let desc = TapKeyDescriptor { family: family as u32, index };
        let (keypair, pub_key) =
            derive_tap_pub_key(&self.secp, &self.master, self.coin_type, &desc)
                .map_err(|e| ChainError::KeyDerivationFailed(e.to_string()))?;
        let key_desc = KeyDescriptor { family, index, pub_key };
        self.keypairs.lock().unwrap().push((key_desc.clone(), keypair));
        Ok(key_desc)
    }

    fn is_local_key(&self, key_desc: &KeyDescriptor) -> Result<bool, ChainError> {
        Ok(self.keypairs.lock().unwrap().iter().any(|(kd, _)| kd.pub_key == key_desc.pub_key))
    }
}

impl AssetSigner for TapKeyRing {
    fn sign_virtual_tx(
        &self,
        signing_key: &KeyDescriptor,
        virtual_tx: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        let keypairs = self.keypairs.lock().unwrap();
        let (_, keypair) = keypairs
            .iter()
            .find(|(kd, _)| kd.pub_key == signing_key.pub_key)
            .ok_or_else(|| ChainError::SigningFailed("Key not found".into()))?;
        let msg = bitcoin::secp256k1::Message::from_digest({
            use bitcoin::hashes::{sha256, Hash};
            sha256::Hash::hash(virtual_tx).to_byte_array()
        });
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, keypair);
        Ok(sig.serialize().to_vec())
    }
}

// ============================================================================
// Stubs
// ============================================================================

pub struct StubLdk;
impl LdkChannelOps for StubLdk {
    fn forward_intercepted_htlc(&self, _: [u8; 32], _: u64, _: [u8; 33], _: u64) -> Result<(), String> { Ok(()) }
    fn fail_intercepted_htlc(&self, _: [u8; 32]) -> Result<(), String> { Ok(()) }
}

pub struct StubOracle;
impl PriceOracle for StubOracle {
    fn ask_price(&self, _: &AssetId, _: u64) -> Result<FixedPoint, RfqError> { Ok(FixedPoint::from_integer(5000)) }
    fn bid_price(&self, _: &AssetId, _: u64) -> Result<FixedPoint, RfqError> { Ok(FixedPoint::from_integer(4800)) }
}

// ============================================================================
// Builder helpers
// ============================================================================

pub fn create_bdk_wallet_with_path(
    mnemonic: &str,
    esplora_url: &str,
    db_path: &str,
) -> BdkAnchorWallet {
    BdkAnchorWallet::from_mnemonic(mnemonic, esplora_url, db_path)
        .expect("Failed to create BDK wallet")
}

pub fn create_key_ring(mnemonic: &str) -> TapKeyRing {
    TapKeyRing::from_mnemonic(mnemonic).expect("Failed to create key ring")
}

pub fn build_node(
    chain: EsploraChain,
    wallet: BdkAnchorWallet,
    key_ring: TapKeyRing,
) -> TapNode<EsploraChain, BdkAnchorWallet, TapKeyRing, StubLdk, StubOracle> {
    let config = TapNodeConfig {
        network: TapNetwork::Testnet,
        db_path: Some(PathBuf::from("./tap-wallet-data/assets.db")),
        default_conf_target: 3,
        ..Default::default()
    };

    TapNodeBuilder::new(config)
        .set_chain_bridge(chain)
        .set_wallet_anchor(wallet)
        .set_key_ring(key_ring)
        .set_ldk_ops(StubLdk)
        .set_price_oracle(StubOracle)
        .build()
        .expect("Failed to build node")
}
