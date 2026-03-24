// Persistent wallet state backed by a JSON file.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Persistent wallet state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletState {
    /// BTC confirmed balance (sats).
    pub btc_confirmed: u64,
    /// BTC pending balance (sats).
    pub btc_pending: u64,
    /// BTC wallet address.
    pub btc_address: String,
    /// Mint history.
    pub mints: Vec<MintRecord>,
    /// Confirmed assets.
    pub assets: Vec<AssetRecord>,
    /// Generated receive addresses.
    pub addresses: Vec<AddressRecord>,
    /// Send history.
    pub sends: Vec<SendRecord>,

    /// Path to this state file (not serialized).
    #[serde(skip)]
    pub file_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintRecord {
    pub name: String,
    pub amount: u64,
    pub asset_id: String,
    pub txid: String,
    pub status: String,
    /// Block height (set after confirmation).
    #[serde(default)]
    pub block_height: Option<u32>,
    /// Block hash (set after confirmation).
    #[serde(default)]
    pub block_hash: Option<String>,
    /// Internal key hex (33 bytes, for proof building).
    #[serde(default)]
    pub internal_key: Option<String>,
    /// Script key hex (33 bytes, for proof building).
    #[serde(default)]
    pub script_key: Option<String>,
    /// Raw signed transaction hex (for proof building).
    #[serde(default)]
    pub signed_tx_hex: Option<String>,
    /// Genesis outpoint txid hex (internal byte order, for proof building).
    #[serde(default)]
    pub genesis_txid: Option<String>,
    /// Genesis outpoint vout.
    #[serde(default)]
    pub genesis_vout: Option<u32>,
    /// Funded PSBT hex (contains output internal keys for exclusion proofs).
    #[serde(default)]
    pub funded_psbt_hex: Option<String>,
    /// Transaction output index of the TAP commitment (genesis output_index).
    #[serde(default)]
    pub tap_output_index: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetRecord {
    pub asset_id: String,
    pub amount: u64,
    pub outpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressRecord {
    pub asset_id: String,
    pub amount: u64,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendRecord {
    pub asset_id: String,
    pub amount: u64,
    pub txid: String,
}

impl WalletState {
    /// Loads state from a JSON file, or returns a fresh state if the file
    /// doesn't exist.
    pub fn load(path: &str) -> Self {
        let mut state = if Path::new(path).exists() {
            let data = fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_else(|_| Self::new())
        } else {
            Self::new()
        };
        state.file_path = path.to_string();
        state
    }

    /// Saves state to its file.
    pub fn save(&self) {
        if self.file_path.is_empty() {
            return;
        }
        if let Some(parent) = Path::new(&self.file_path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self).unwrap();
        let _ = fs::write(&self.file_path, json);
    }

    fn new() -> Self {
        WalletState {
            btc_confirmed: 0,
            btc_pending: 0,
            btc_address: String::new(),
            mints: Vec::new(),
            assets: Vec::new(),
            addresses: Vec::new(),
            sends: Vec::new(),
            file_path: String::new(),
        }
    }

    pub fn add_mint(
        &mut self,
        name: String,
        amount: u64,
        asset_id: String,
        txid: String,
    ) {
        self.mints.push(MintRecord {
            name,
            amount,
            asset_id,
            txid,
            status: "broadcast".into(),
            block_height: None,
            block_hash: None,
            internal_key: None,
            script_key: None,
            signed_tx_hex: None,
            genesis_txid: None,
            genesis_vout: None,
            funded_psbt_hex: None,
            tap_output_index: None,
        });
    }

    pub fn add_address(
        &mut self,
        asset_id: String,
        amount: u64,
        address: String,
    ) {
        self.addresses.push(AddressRecord {
            asset_id,
            amount,
            address,
        });
    }

    pub fn add_send(
        &mut self,
        asset_id: String,
        amount: u64,
        txid: String,
    ) {
        self.sends.push(SendRecord {
            asset_id,
            amount,
            txid,
        });
    }
}
