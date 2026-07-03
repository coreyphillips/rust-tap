# taproot-ldk

A Rust implementation of the [Taproot Assets Protocol](https://docs.lightning.engineering/the-lightning-network/taproot-assets) (TAP) for [LDK](https://lightningdevkit.org/). Issue, transfer, and manage digital assets on Bitcoin using Taproot -- without requiring LND.

## Status

On-chain functionality is testnet-ready. Lightning asset channel integration is in progress. **Not yet recommended for mainnet** without a security audit and live `tapd` interop testing.

| Area | Status |
|------|--------|
| Core protocol (MS-SMT, assets, commitments, VM, proofs) | Complete, validated against Go `tapd` test vectors |
| Full proof verification (inclusion/exclusion vs anchor outputs, STXO, reveals, state transitions) | Complete -- verifies real `tapd` proof files end to end |
| Cryptography (BIP-340/341/342, HD derivation, group keys V0/V1, Pedersen commitments) | Complete |
| On-chain pipelines (minting, transfers, burns, PSBT construction, proof suffix creation) | Complete |
| vPSBT (Go `tappsbt`-compatible virtual packets) | Complete, byte-exact against Go vectors |
| STXO proofs / alt leaves (TransitionV1) | Complete, Go-default semantics |
| Supply commitments | Verification complete; authoring state machine deferred |
| Address V0/V1/V2 + authmailbox courier client (ECIES) | Complete; gRPC mailbox transport is a follow-up |
| Universe sync (diff-based MS-SMT federation, verified inserts) | Complete |
| Universe server (`tap-server`, tapd-compatible REST) | Complete -- rust-tap to rust-tap federation proven; gRPC follow-up for tapd-native sync |
| SQLite + in-memory persistence | Complete (8 migrations) |
| TLV wire encoding (Go `tapd`-compatible) | Complete, byte-exact against Go vectors |
| Node lifecycle (mint/send/confirmation watching via `tick()` or background thread) | Complete |
| LDK integration (channels, HTLC signing, cooperative/force close) | Data structures and signing at Go wire parity; live channel flow blocked on rust-lightning extension points (see `tap-ldk/docs/ldk-fork-requirements.md`) |
| RFQ (Go `rfqmsg`-compatible wire format, pending-request tracking, HTLC interception) | Complete against Go v0.8 compatibility fixtures |
| External security audit | Not started |
| Live `tapd` interop testing | Go test vectors + real `tapd` proof files verified; live daemon testing recommended before mainnet |

### Async

The core crates are intentionally synchronous (small dependency tree,
mobile-friendly). Async lives only at the edges: the `tap-server` crate
wraps the sync core with `tokio::task::spawn_blocking`. If a public
async API is needed later, the plan is a thin wrapper crate around
`Arc<TapNode>` using the same pattern, never async plumbing inside the
protocol crates.

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
    // Rates are asset units per BTC (Go rfqmsg.AssetRate semantics).
    fn ask_price(&self, _id: &AssetId, _max: u64) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(20_000_000)) // 5000 msat per unit
    }
    fn bid_price(&self, _id: &AssetId, _max: u64) -> Result<FixedPoint, RfqError> {
        Ok(FixedPoint::from_integer(25_000_000)) // 4000 msat per unit
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
# Full test suite (700+ tests across all crates, including Go tapd
# test vector conformance suites)
cargo test --workspace

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
