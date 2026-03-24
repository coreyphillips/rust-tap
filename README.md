# taproot-ldk

A Rust implementation of the [Taproot Assets Protocol](https://docs.lightning.engineering/the-lightning-network/taproot-assets) (TAP) for [LDK](https://lightningdevkit.org/). Issue, transfer, and manage digital assets on Bitcoin using Taproot -- without requiring LND.

## Status

On-chain functionality is testnet-ready. Lightning asset channel integration is in progress. **Not yet recommended for mainnet** without a security audit and live `tapd` interop testing.

| Area | Status |
|------|--------|
| Core protocol (MS-SMT, assets, commitments, VM, proofs) | Complete |
| Cryptography (BIP-340/341/342, HD derivation, group keys) | Complete |
| On-chain pipelines (minting, transfers, PSBT construction) | Complete |
| Universe sync (diff-based MS-SMT federation) | Complete |
| SQLite + in-memory persistence | Complete |
| TLV wire encoding (Go `tapd`-compatible) | Complete |
| Proof courier | Trait + HTTP implementation |
| LDK integration (channels, HTLC signing, cooperative/force close) | In progress -- individual components built, not yet wired end-to-end |
| RFQ (Request For Quote) with per-peer rate limiting | In progress -- standalone negotiation works, not yet connected to channel lifecycle |
| External security audit | Not started |
| Live `tapd` interop testing | Encoding vectors only |

## Quick Start

Add the crates you need:

```toml
[dependencies]
tap-primitives = { path = "tap-primitives" }
tap-onchain    = { path = "tap-onchain" }
tap-ldk        = { path = "tap-ldk" }
tap-persist    = { path = "tap-persist" }
tap-universe   = { path = "tap-universe" }
```

Mint an asset:

```rust
use tap_onchain::mint::*;
use tap_onchain::chain::*;
use tap_primitives::asset::*;

let mut planter = Planter::new(my_chain, my_wallet, my_key_ring);

planter.queue_seedling(Seedling::new_normal("USD-Coin".into(), 1_000_000))?;
planter.queue_seedling(Seedling::new_collectible("Rare-NFT".into()))?;

planter.freeze_batch()?;
planter.commit_batch(genesis_outpoint, 0)?;

let batch = planter.pending_batch().unwrap();
let tap_commitment = batch.root_asset_commitment.as_ref().unwrap();
```

## Workspace

```
taproot-ldk/
├── tap-primitives/       Core protocol: MS-SMT, assets, commitments, VM, proofs, crypto, encoding
├── tap-onchain/          On-chain pipelines: minting, transfers, PSBT, proof courier
├── tap-ldk/              LDK integration (in progress): channels, RFQ, routing, wire messages
├── tap-persist/          Storage traits + in-memory and SQLite backends
├── tap-universe/         Universe sync: decentralized asset discovery and federation
├── tap-node/             High-level node: builder pattern, managed lifecycle, simple API
└── examples/quickstart/  Interactive CLI wallet for testnet experimentation
```

## Architecture

```
┌───────────────────────────────────────────────────┐
│                     tap-ldk                        │
│   Wire Messages  │  RFQ  │  Routing  │  Channels  │
├───────────────────────────────────────────────────┤
│                    tap-onchain                      │
│   Minting  │  Transfers  │  PSBT  │  Proof Courier │
├───────────────────────────────────────────────────┤
│                   tap-primitives                    │
│   MS-SMT  │  Assets  │  Commitments  │  VM  │      │
│   Crypto  │  Encoding  │  Addresses  │  Tapscript   │
├───────────────────────────────────────────────────┤
│              tap-persist  │  tap-universe           │
│   SQLite  │  Asset/Batch/Proof Store  │  Sync       │
└───────────────────────────────────────────────────┘
```

### How Assets Live on Bitcoin

Assets are TLV-encoded and committed into Bitcoin P2TR outputs via a two-level Merkle-Sum Sparse Merkle Tree:

```
Bitcoin UTXO (P2TR output)
  └── Taproot Script Tree
        ├── Spend path (key-path or Lightning script)
        └── TAP Commitment Leaf
              └── TapCommitment (outer MS-SMT)
                    └── AssetCommitment (inner MS-SMT, keyed by asset ID)
                          └── Asset (TLV-encoded)
```

## Examples

### Mint Assets

```rust
use tap_onchain::mint::*;
use tap_onchain::chain::*;
use tap_primitives::asset::*;

let mut planter = Planter::new(my_chain, my_wallet, my_key_ring);

planter.queue_seedling(Seedling::new_normal("USD-Coin".into(), 1_000_000))?;
planter.freeze_batch()?;
planter.commit_batch(genesis_outpoint, 0)?;
```

### Transfer Assets

```rust
use tap_onchain::send::*;

let prepared = TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)?;
// Handles coin selection, splits, change, commitments, and tombstones automatically.
```

### Verify Proofs and State Transitions

```rust
use tap_primitives::proof::*;
use tap_primitives::vm::*;
use tap_primitives::crypto::SchnorrWitnessValidator;

let proof_file = File::decode(&proof_bytes)?;
verify_file_structure(&proof_file)?;

let engine = Engine::new(&new_asset, &splits, &prev_assets, &SchnorrWitnessValidator::new());
engine.execute()?;
```

### RFQ (Request For Quote)

> **Note:** RFQ negotiation works as a standalone protocol but is not yet connected to the Lightning channel lifecycle.

```rust
use tap_ldk::rfq::*;

struct MyOracle;
impl PriceOracle for MyOracle {
    fn ask_price(&self, _id: &AssetId, _max: u64) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(5000)) // 5000 msat per unit
    }
    fn bid_price(&self, _id: &AssetId, _max: u64) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(4800))
    }
}

let mut quotes = QuoteManager::new(MyOracle);
let accept = quotes.handle_buy_request(&request, peer_id, now, 3600)?;
```

### Asset Lightning Channels (In Progress)

> **Note:** The building blocks below (channel registration, HTLC interception, TLV parsing, leaf creation, signing) are implemented and unit-tested individually, but are **not yet wired into a working end-to-end Lightning flow**. Full integration requires upstream LDK changes that are still in progress.

```rust
use tap_ldk::channel::*;
use tap_ldk::ldk::*;

let tap_mgr = TapChannelManager::new(my_ldk_channel_ops, MyOracle);
tap_mgr.register_asset_channel(channel_id, channel_blob);

// Intercept HTLCs for asset routing
tap_mgr.handle_intercepted_htlc(
    intercept_id, next_hop_scid, next_node_id, amt_msat, &custom_records,
)?;
```

## Security

**Implemented:**

- BIP-340/341/342 Schnorr verification for key-path and script-path spends via `libsecp256k1`
- Amount conservation enforced by VM on every state transition
- Split commitment proofs prevent asset duplication across outputs
- Cryptographic quote IDs via OS CSPRNG (`getrandom`)
- Per-peer rate limiting on RFQ to prevent flooding
- TLV size limits (4 MiB max value, 1 MiB max wire message)
- Partial `zeroize` support via custom `zeroize_secret()` for secret key material
- Test-only validators (`SkipWitnessValidator` and similar) gated behind `#[cfg(test)]`

**Outstanding:**

- External security audit (critical before mainnet)
- Full `zeroize` crate integration for all secret types

## Testing

```bash
# Full unit test suite (~329 tests across all crates)
cargo test -p tap-primitives -p tap-onchain -p tap-ldk -p tap-persist -p tap-universe --lib

# Property-based encoding round-trip tests
cargo test -p tap-primitives --test proptest_encoding

# Property-based MS-SMT tests (slow, ~10 min for 256-level trees)
cargo test -p tap-primitives --test proptest_mssmt

# Fuzz targets (requires nightly)
cd tap-primitives/fuzz && cargo +nightly fuzz run tlv_stream_decode -- -max_total_time=60
cd tap-primitives/fuzz && cargo +nightly fuzz run proof_file_decode -- -max_total_time=60
```

## Road to Mainnet

- **Lightning integration** -- wire individual tap-ldk components into a working end-to-end channel lifecycle (requires upstream LDK extension points)
- **Security audit** -- external review of cryptographic and protocol-critical code
- **Live `tapd` interop testing** -- end-to-end validation against Lightning Labs' Go implementation (encoding vectors already verified)
- **Async API variants** -- all APIs are currently synchronous

## License

Licensed under the [MIT License](LICENSE).
