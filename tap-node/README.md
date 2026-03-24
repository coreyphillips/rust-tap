# tap-node

High-level Taproot Assets node for Rust developers. Wraps the [taproot-ldk](https://github.com/example/taproot-ldk) workspace into a single `TapNode` with a builder pattern, managed lifecycle, and straightforward API -- the same pattern [ldk-node](https://github.com/lightningdevkit/ldk-node) uses for LDK.

**You provide**: chain backend, wallet, key ring, LDK channel ops, price oracle.
**tap-node handles**: minting, transfers, proof delivery, persistence, Lightning asset channels, universe sync.

## Add to Your Project

```toml
[dependencies]
tap-node = { path = "tap-node" }

# You'll also need bitcoin for raw types
bitcoin = { version = "0.32", features = ["std"] }
```

## Implement the Required Traits

tap-node needs 5 backends from you. Here are minimal stub implementations to get started -- replace the bodies with your real chain/wallet integration.

### 1. Chain Backend

Connects to a Bitcoin node or Electrum/Esplora server for blockchain queries.

**Testnet Electrum servers you can use:**

| Network | Server | Protocol |
|---------|--------|----------|
| Testnet3 | `electrum.blockstream.info:60002` | SSL |
| Testnet3 | `testnet.aranguren.org:51002` | SSL |
| Testnet4 | `electrum.testnet4.io:50002` | SSL |
| Signet | `electrum.mutinynet.com:50001` | TCP |
| Regtest | `localhost:50001` | TCP (local) |

**Esplora REST APIs:**

| Network | URL |
|---------|-----|
| Testnet3 | `https://blockstream.info/testnet/api` |
| Testnet4 | `https://mempool.space/testnet4/api` |
| Signet | `https://mutinynet.com/api` |
| Mainnet | `https://blockstream.info/api` |

```rust
use tap_node::*;

struct MyChain {
    // Your Electrum client, Esplora HTTP client, or bitcoind RPC connection.
    // Example with esplora: esplora_url: String,
    // Example with electrum: electrum_client: electrum_client::Client,
}

impl ChainBridge for MyChain {
    fn current_height(&self) -> Result<u32, ChainError> {
        // Electrum: self.client.block_headers_subscribe().unwrap().height as u32
        // Esplora:  GET /blocks/tip/height
        todo!("Return current best block height")
    }

    fn estimate_fee(&self, conf_target: u32) -> Result<FeeRate, ChainError> {
        // Electrum: self.client.estimate_fee(conf_target)
        // Esplora:  GET /fee-estimates -> pick target
        // FeeRate is in sat/kvB (1000 = 1 sat/vB)
        Ok(FeeRate(1000)) // 1 sat/vB minimum
    }

    fn publish_transaction(&self, tx: &[u8]) -> Result<(), ChainError> {
        // Electrum: self.client.transaction_broadcast_raw(tx)
        // Esplora:  POST /tx with hex-encoded tx
        todo!("Broadcast raw transaction bytes")
    }

    fn get_block_hash(&self, height: u32) -> Result<[u8; 32], ChainError> {
        // Electrum: self.client.block_header(height).block_hash()
        // Esplora:  GET /block-height/{height}
        todo!("Return block hash at given height")
    }
}
```

### 2. Wallet (PSBT Funding + Signing)

Manages UTXOs and signs transactions. If you use BDK, this maps directly to its wallet API.

```rust
struct MyWallet {
    // Your BDK wallet, bitcoind wallet, or custom UTXO manager.
}

impl WalletAnchor for MyWallet {
    fn fund_psbt(
        &self,
        raw_psbt: &[u8],
        fee_rate: FeeRate,
    ) -> Result<Vec<u8>, ChainError> {
        // BDK: wallet.fund_psbt(psbt, fee_rate)
        // bitcoind: walletprocesspsbt + walletcreatefundedpsbt
        todo!("Add inputs and change outputs to the PSBT")
    }

    fn sign_and_finalize_psbt(
        &self,
        funded_psbt: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        // BDK: wallet.sign(&mut psbt, SignOptions::default())
        // bitcoind: walletprocesspsbt -> finalizepsbt
        todo!("Sign all inputs and return finalized tx bytes")
    }

    fn import_taproot_output(
        &self,
        _internal_key: &SerializedKey,
    ) -> Result<(), ChainError> {
        // Tell your wallet to watch this Taproot output.
        // BDK: add to address book / descriptor
        // bitcoind: importdescriptors
        Ok(())
    }
}
```

### 3. Key Ring + Asset Signer

Derives keys for Taproot Assets (BIP-86 key family 212) and signs virtual transactions.

```rust
struct MyKeys {
    // Your HD wallet / key manager.
    // Derivation path: m/1017'/{coin_type}'/212'/0/{index}
}

impl KeyRing for MyKeys {
    fn derive_next_key(
        &self,
        family: u16,
    ) -> Result<KeyDescriptor, ChainError> {
        // Derive the next key in the family.
        // family=212 is the Taproot Assets key family.
        todo!("Return KeyDescriptor { family, index, pub_key }")
    }

    fn is_local_key(
        &self,
        _key_desc: &KeyDescriptor,
    ) -> Result<bool, ChainError> {
        // Check if this key belongs to your wallet.
        Ok(true)
    }
}

impl AssetSigner for MyKeys {
    fn sign_virtual_tx(
        &self,
        _signing_key: &KeyDescriptor,
        _virtual_tx: &[u8],
    ) -> Result<Vec<u8>, ChainError> {
        // Sign the virtual transaction with the specified key.
        // This produces a Schnorr signature for the asset state transition.
        todo!("Return 64-byte Schnorr signature")
    }
}
```

### 4. LDK Channel Ops

Bridges tap-node to your LDK `ChannelManager` for Lightning asset channels.

```rust
struct MyLdk {
    // Reference to your LDK ChannelManager.
}

impl LdkChannelOps for MyLdk {
    fn forward_intercepted_htlc(
        &self,
        _intercept_id: [u8; 32],
        _next_hop_scid: u64,
        _next_node_id: [u8; 33],
        _amt_to_forward_msat: u64,
    ) -> Result<(), String> {
        // Forward an intercepted HTLC with asset routing info.
        // Calls channel_manager.forward_intercepted_htlc()
        todo!("Forward HTLC via your LDK ChannelManager")
    }

    fn fail_intercepted_htlc(
        &self,
        _intercept_id: [u8; 32],
    ) -> Result<(), String> {
        // Fail an intercepted HTLC.
        // Calls channel_manager.fail_intercepted_htlc()
        todo!("Fail HTLC via your LDK ChannelManager")
    }
}
```

### 5. Price Oracle

Provides asset prices for RFQ (Request For Quote) negotiations over Lightning.

```rust
use tap_node::tap_ldk::rfq::*;

struct MyOracle;

impl PriceOracle for MyOracle {
    fn ask_price(
        &self,
        _asset_id: &AssetId,
        _max_amount: u64,
    ) -> Result<FixedPoint, RfqError> {
        // Return the price you're willing to sell at (msat per asset unit).
        Ok(FixedPoint::from_integer(5000)) // 5000 msat per unit
    }

    fn bid_price(
        &self,
        _asset_id: &AssetId,
        _max_msat: u64,
    ) -> Result<FixedPoint, RfqError> {
        // Return the price you're willing to buy at.
        Ok(FixedPoint::from_integer(4800))
    }
}
```

## Build and Start the Node

```rust
use tap_node::*;
use std::path::PathBuf;

fn main() -> Result<(), TapNodeError> {
    // Configure for testnet.
    let config = TapNodeConfig {
        network: TapNetwork::Testnet,
        db_path: Some(PathBuf::from("./tap-data/assets.db")),
        courier_url: "https://courier.example.com".into(),
        default_conf_target: 6,
        ..Default::default()
    };

    // Build the node with your backends.
    let node = TapNodeBuilder::new(config)
        .set_chain_bridge(MyChain { /* ... */ })
        .set_wallet_anchor(MyWallet { /* ... */ })
        .set_key_ring(MyKeys { /* ... */ })
        .set_ldk_ops(MyLdk { /* ... */ })
        .set_price_oracle(MyOracle)
        .build()?;

    // Start the node.
    node.start()?;

    // Get the event receiver for monitoring.
    let events = node.event_receiver()?;

    // ... use the node ...

    // Clean shutdown.
    node.stop()?;
    Ok(())
}
```

## Mint Assets

```rust
// Queue assets for minting.
node.queue_mint(Seedling::new_normal("USD-Coin".into(), 1_000_000))?;
node.queue_mint(Seedling::new_collectible("Rare-Art-001".into()))?;

// Finalize: freezes batch, builds genesis tx, funds, signs, broadcasts.
let result = node.finalize_mint()?;

println!("Minted {} assets:", result.assets.len());
for asset in &result.assets {
    println!("  {} - {} units", asset.name, asset.amount);
}

// Or cancel if you change your mind.
// node.cancel_mint()?;
```

## Check Balances

```rust
// List all owned assets.
let assets = node.list_assets()?;
for asset in &assets {
    println!(
        "Asset {:?}: {} units (outpoint: {:?})",
        asset.asset_id, asset.amount, asset.anchor_outpoint
    );
}

// Check a specific asset's balance.
let balance = node.get_balance(&asset_id)?;
println!("Spendable: {} units", balance);
```

## Receive Assets

```rust
// Generate a TAP address to receive an asset.
let address = node.new_address(asset_id, 500)?;
println!("Send to: {}", address);
// Output: taprt1qqqsqqspqqzz...

// When you receive a proof file from the sender:
let proof_bytes = std::fs::read("received_proof.tap")?;
let proof_file = tap_node::tap_primitives::proof::file::File::decode(&proof_bytes)
    .map_err(|e| TapNodeError::Storage(e.to_string()))?;
node.import_proof(proof_file)?;
```

## Send Assets

```rust
// Parse the recipient's TAP address.
let recipient = TapAddress::decode("taprt1qqqsqqspqqzz...")?;

// Send 500 units.
let handle = node.send_asset(asset_id, 500, &recipient)?;
println!("Transfer broadcast: txid={:?}", handle.txid);
```

## Monitor Events

```rust
use std::thread;

let events = node.event_receiver()?;

thread::spawn(move || {
    while let Ok(event) = events.recv() {
        match event {
            TapEvent::AssetReceived { asset_id, amount, .. } => {
                println!("Received {} units of {:?}", amount, asset_id);
            }
            TapEvent::TransferConfirmed { asset_id, amount, txid } => {
                println!("Transfer confirmed: {} units, txid={:?}", amount, txid);
            }
            TapEvent::MintBatchStateChanged { new_state, .. } => {
                println!("Mint batch state: {:?}", new_state);
            }
            _ => {}
        }
    }
});
```

## Export and Import Proofs

```rust
// Export a proof for a specific asset output.
let proof = node.export_proof(&outpoint, &script_key)?;
let encoded = proof.encode();
std::fs::write("my_asset_proof.tap", &encoded)?;

// Import a proof received out-of-band.
let bytes = std::fs::read("received_proof.tap")?;
let proof = tap_node::tap_primitives::proof::file::File::decode(&bytes)
    .map_err(|e| TapNodeError::Storage(e.to_string()))?;
node.import_proof(proof)?;
```

## Configuration Reference

| Field | Default | Description |
|-------|---------|-------------|
| `network` | `Regtest` | Bitcoin network (`Mainnet`, `Testnet`, `Regtest`, `Simnet`, `Testnet4`) |
| `db_path` | `None` | SQLite database path. `None` = in-memory (data lost on restart) |
| `courier_url` | `""` | Proof courier server URL for non-interactive transfers |
| `universe_servers` | `[]` | Universe federation servers for asset discovery |
| `universe_sync_interval_secs` | `600` | How often to sync with universe servers (0 = disabled) |
| `rfq_quote_lifetime_secs` | `3600` | How long RFQ quotes are valid |
| `csv_delay_blocks` | `144` | Force-close CSV delay (~1 day) |
| `default_conf_target` | `6` | Default fee estimation target in blocks |

## Testnet Quick Start

Here's a complete setup for testnet development using public infrastructure:

```rust
use tap_node::*;
use std::path::PathBuf;

// 1. Connect to a public testnet Electrum server.
//
//    Testnet3 Electrum SSL servers:
//      - electrum.blockstream.info:60002
//      - testnet.aranguren.org:51002
//
//    Testnet3 Esplora REST:
//      - https://blockstream.info/testnet/api
//
//    Signet Esplora REST:
//      - https://mutinynet.com/api
//
//    Testnet4 Esplora REST:
//      - https://mempool.space/testnet4/api

let config = TapNodeConfig {
    network: TapNetwork::Testnet,
    db_path: Some(PathBuf::from("./testnet-tap-data/assets.db")),
    courier_url: String::new(),
    default_conf_target: 3, // Faster for testnet
    ..Default::default()
};

let node = TapNodeBuilder::new(config)
    .set_chain_bridge(MyEsploraChain::new(
        "https://blockstream.info/testnet/api",
    ))
    .set_wallet_anchor(MyBdkWallet::new_testnet())
    .set_key_ring(MyHdKeys::new_testnet())
    .set_ldk_ops(MyLdkBridge::new())
    .set_price_oracle(MyOracle)
    .build()
    .expect("Failed to build tap-node");

node.start().expect("Failed to start");

// Get some testnet BTC from a faucet first:
//   https://coinfaucet.eu/en/btc-testnet/
//   https://testnet-faucet.com/btc-testnet/
//   https://signetfaucet.com/ (for signet)

// Then mint your first asset!
node.queue_mint(Seedling::new_normal("Test-Token".into(), 21_000_000))
    .expect("Failed to queue mint");

let result = node.finalize_mint().expect("Failed to mint");
println!("Minted: {:?}", result);
```

## Architecture

```
Your App
    |
    v
TapNode<C, W, K, L, P>        <-- You provide these 5 backends
    |
    +-- Minting pipeline        (tap-onchain: Planter)
    +-- Transfer pipeline       (tap-onchain: TransferBuilder)
    +-- Lightning channels      (tap-ldk: TapChannelManager)  [in progress]
    +-- RFQ negotiation         (tap-ldk: QuoteManager)       [in progress]
    +-- Persistence             (tap-persist: SQLite or in-memory)
    +-- Proof delivery          (tap-onchain: HttpCourier)
    +-- Universe sync           (tap-universe: SimpleSyncer)
```

## Road Map

- **Phase 1** (current): On-chain operations -- mint, send, receive, balance queries
- **Phase 2**: Lightning integration -- asset channels, RFQ, HTLC routing
- **Phase 3**: Background tasks -- universe sync, automated proof polling

## License

Licensed under the [MIT License](../LICENSE).
