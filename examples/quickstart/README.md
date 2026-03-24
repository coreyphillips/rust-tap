# tap-quickstart

Interactive Taproot Assets wallet powered by `tap-node`. Persistent state via JSON file, real BDK Taproot wallet with Esplora sync.

## Run It

```bash
# Interactive menu
cargo run -p tap-quickstart -- "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Subcommands
cargo run -p tap-quickstart -- "your mnemonic here" mint "MyToken" 1000000
cargo run -p tap-quickstart -- "your mnemonic here" status
cargo run -p tap-quickstart -- "your mnemonic here" list
cargo run -p tap-quickstart -- "your mnemonic here" receive <asset_id_hex> 100
cargo run -p tap-quickstart -- "your mnemonic here" send <asset_id_hex> 50 <tap_address>
cargo run -p tap-quickstart -- "your mnemonic here" sync
cargo run -p tap-quickstart -- "your mnemonic here" deep-sync
```

The mnemonic is **never stored** -- pass it every time. Wallet state (mints, assets, addresses) persists in `./tap-wallets/<fingerprint>/state.json`, where `<fingerprint>` is derived from your mnemonic so each wallet gets its own directory.

## Interactive Menu

```
=== tap-node wallet ===

BTC: 15000 sats | Mints: 2 | Assets: 2

  1. Mint a new asset
  2. Check pending mints
  3. List my assets
  4. Send an asset
  5. Generate receive address
  6. Sync wallet
  7. Deep sync (imported mnemonic recovery)
  8. Exit

>
```

## First Time Setup

1. Run the wallet -- it will show your BTC address:
   ```
   Fund: tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj
   ```

2. Get testnet BTC from a faucet:
   - https://coinfaucet.eu/en/btc-testnet/
   - https://testnet-faucet.com/btc-testnet/
   - https://signetfaucet.com/ (for signet)

3. Wait for confirmation, then run again and mint:
   ```
   > 1
   Asset name: MyToken
   Amount (1 for collectible): 1000000
   Minting 1000000 units of 'MyToken'...
   Mint broadcast! Txid: abc123...
   ```

## State File

`./tap-wallets/<fingerprint>/state.json` tracks:
- BTC balance (confirmed and pending)
- BTC wallet address
- Mint history (name, amount, asset_id, txid, status, block height/hash, keys, signed tx, genesis outpoint)
- Confirmed assets (asset_id, amount, outpoint)
- Generated receive addresses
- Send history

The file is human-readable JSON. Delete the wallet's directory to start fresh.

## Network Configuration

Edit the constants in `src/main.rs`:

```rust
// Testnet3 (default)
const ESPLORA_URL: &str = "https://blockstream.info/testnet/api";

// Signet
const ESPLORA_URL: &str = "https://mutinynet.com/api";

// Testnet4
const ESPLORA_URL: &str = "https://mempool.space/testnet4/api";
```
