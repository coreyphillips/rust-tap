# tapd interop harness

Live cross-implementation interoperability testing between rust-tap
and Lightning Labs' tapd (Go reference implementation) on a local
regtest network.

## Stack

| Component | Version used | How it runs |
|-----------|--------------|-------------|
| bitcoind  | bitcoin/bitcoin:29 (Docker) | regtest, `-txindex`, ZMQ raw block/tx |
| electrs   | mempool/electrs:latest (Docker) | Esplora HTTP API on `:3002`, `--jsonrpc-import` |
| lnd       | v0.19.2-beta, built from source | native binary, `--noseedbackup`, bitcoind backend |
| tapd      | v0.8.99-alpha (local taproot-assets checkout, commit d82c7b41) | native binary against lnd |
| rust-tap  | this branch | quickstart CLI + `examples/interop-verify` + `examples/interop-sync` |

Notes on versions:

- tapd v0.8.99-alpha requires lnd >= 0.19.0 **built with the
  `signrpc walletrpc chainrpc invoicesrpc` tags**
  (`tapcfg/config.go: minimalCompatibleVersion`). A plain
  `go install lnd` does not include them; `01-build-binaries.sh`
  clones lnd and builds with the right tags. `go install @tag` also
  fails outright because lnd's go.mod contains replace directives.
- mempool/electrs serves the subset of the Esplora REST API the
  quickstart's `EsploraChain` uses: `/blocks/tip/height`,
  `/block-height/:h`, `/block/:hash/header`, `/block/:hash/txids`,
  `/tx/:txid/{status,hex}`, `/fee-estimates`, `POST /tx`.

## Usage

```sh
# 0. Prereqs: docker running, go >= 1.24, rust toolchain, python3,
#    openssl. The taproot-assets checkout is expected as a sibling
#    directory of this repo (override with TAPROOT_ASSETS_DIR).

# 1. Build lnd, tapd, and the rust binaries.
interop/01-build-binaries.sh

# 2. Start bitcoind, electrs, lnd, tapd; mine 150 blocks; fund lnd.
interop/02-start-stack.sh

# 3. Run the interop tests (in order).
interop/test-a-tapd-mint-rust-verify.sh
interop/test-b-rust-mint-tapd-verify.sh
interop/test-c-universe-sync.sh
interop/test-d-tapd-send-to-rust-addr.sh   # stretch, see below

# 4. Tear down (keeps data in $INTEROP_DIR; rm -rf it for a reset).
interop/stop-all.sh
```

All runtime state (chain data, wallets, logs, built binaries) lives
under `INTEROP_DIR` (default `/tmp/tap-interop`) and is never
committed. Configuration knobs are in `env.sh`.

## The tests

### A. tapd mints, rust-tap verifies live (PASS)

`tapcli assets mint` a normal asset, mine, `tapcli proofs export` the
genesis proof file. `interop-verify` (examples/interop-verify) decodes
the TAPF file and runs the full `File::verify` pipeline with a
`HeaderVerifier` backed by the live chain through esplora: the
anchor header's hash must equal the chain's block hash at the claimed
height. Two negative controls (dead esplora endpoint, corrupted proof
byte) must fail.

### B. rust-tap mints, tapd verifies (headline PASS)

The quickstart CLI (driven on regtest via `TAP_NETWORK` /
`TAP_ESPLORA_URL`) mints an asset, the node's confirmation watcher
generates and stores the genesis proof, `export-proof` writes the
TAPF file. Then:

- `tapcli universe proofs insert` pushes it into tapd's universe
  (tapd fully re-verifies the proof server-side on insert), and
- `tapcli proofs verify` reports `"valid": true`.

Caveat: `tapcli proofs verify` on an asset tapd has never seen fails
AFTER successful verification while marshaling the RPC response
(`DecDisplayForAssetID` cannot fetch the asset meta). The universe
insert is done first so the response marshals; the tapd log's absence
of "Proof verification failed" plus `valid: true` is the actual
verification signal.

### C. rust-tap syncs from tapd's universe over gRPC (PASS)

`interop-sync` (examples/interop-sync) uses `GrpcUniverseClient` with
the new TLS + macaroon support to connect to tapd's TLS gRPC
endpoint, `SimpleSyncer` fetches + verifies the issuance leaf, and
the locally rebuilt universe MS-SMT root must match tapd's root byte
for byte.

### D. tapd sends to a rust-tap address (stretch: delivery leg PASS)

`test-d` generates a V1 address with the quickstart (courier URL
pointing at rust-tap's `tap-universe-server` with its new TLS gRPC
listener), has tapd decode it and `tapcli assets send` to it, mines,
confirms tapd delivers the full proof chain (genesis + transfer) to
the rust-tap courier (whose `InsertProof` validates each proof), then
reassembles the delivered chain into a TAPF file and verifies it live
with `interop-verify`. Detection/import of the inbound asset by the
quickstart node is NOT automated (the receive-side polling flow is
not wired into the quickstart example).

## rust-tap changes made for/because of this exercise

Bug fixes (found by live interop):

1. `examples/quickstart/src/wallet.rs`: reloading a persisted BDK
   wallet restored only public descriptors, so every mint/send in a
   second process run silently produced no signatures and failed with
   "could not finalize". Fixed by re-attaching the mnemonic-derived
   descriptors + `extract_keys()` on load.
2. `tap-node/src/mint.rs`: genesis proofs omitted exclusion proofs
   for the wallet's own change P2TR output. Both rust-tap's own
   `File::verify` and tapd (`invalid exclusion proof: ... missing
   exclusion proofs for outputs`) reject such proofs. Fixed by
   building BIP-86 exclusion proofs for every other P2TR output from
   the funded PSBT's output internal keys.
3. `tap-universe/src/smt.rs` (new) + memory/sqlite/postgres backends:
   universe roots were computed with an ad-hoc hash, so a root
   fetched from tapd never matched the local root after a sync. Now
   all backends build tapd's actual universe MS-SMT
   (key = sha256(outpoint || schnorr(script_key)), leaf =
   LeafNode(raw_proof, amount), amount 1 for non-genesis non-burn
   transfer leaves).

Interop features:

4. `tap-grpc`: `ConnectOptions` (TLS cert pinning + macaroon) for
   `GrpcUniverseClient`. tapd certs are lnd-style self-signed with
   CA:TRUE, which rustls/webpki rejects as an end entity, so the
   client pins the exact cert with a custom verifier
   (`tap-grpc/src/tls.rs`) instead of using tonic's CA-based config.
   The macaroon goes in the `macaroon` metadata header via a tonic
   interceptor.
5. `tap-server`: optional TLS on the universe gRPC listener
   (`--grpc-tls-cert/--grpc-tls-key`). Required for tapd courier
   interop: tapd's universerpc proof courier only dials TLS
   (`proof/courier.go serverDialOpts`, verification skipped).
6. `tap-node`: `new_address` now issues V1 addresses (Go's default;
   V1 accepts V2 TapCommitments). A V0 address cannot be paid by a
   modern tapd at all: its coins live in V2 commitments and the send
   fails with "no compatible commitments for max version 1".
7. `examples/quickstart`: regtest support (`TAP_NETWORK`,
   `TAP_ESPLORA_URL`, `TAP_UNIVERSE_URL`, `TAP_DATA_DIR`,
   `TAP_COURIER_URL` env vars) and an `export-proof` command.
