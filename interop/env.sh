# Shared configuration for the tapd interop harness. Source this from
# the other scripts or your shell:
#
#   source interop/env.sh
#
# Everything runtime-generated (chain data, wallets, logs, binaries)
# lives under INTEROP_DIR, which is NOT committed.

# Where runtime state goes (daemDirs, logs, built binaries).
export INTEROP_DIR="${INTEROP_DIR:-/tmp/tap-interop}"

# Path to the Lightning Labs taproot-assets checkout to build
# tapd/tapcli from (v0.8.99-alpha, commit d82c7b41 at the time this
# harness was written).
export TAPROOT_ASSETS_DIR="${TAPROOT_ASSETS_DIR:-$PWD/../taproot-assets}"

# lnd version to build. tapd v0.8.99-alpha requires lnd >= 0.19.0 built
# with the signrpc, walletrpc, chainrpc and invoicesrpc subserver tags
# (tapcfg/config.go: minimalCompatibleVersion). A stock `go install`
# without tags does NOT satisfy the build-tag check.
export LND_VERSION="${LND_VERSION:-v0.19.2-beta}"
export LND_BUILD_TAGS="signrpc walletrpc chainrpc invoicesrpc routerrpc peersrpc"

# Docker resources.
export DOCKER_NETWORK=tapnet
export BITCOIND_CONTAINER=tap-bitcoind
export ELECTRS_CONTAINER=tap-electrs
export BITCOIND_IMAGE="${BITCOIND_IMAGE:-bitcoin/bitcoin:29}"
export ELECTRS_IMAGE="${ELECTRS_IMAGE:-mempool/electrs:latest}"

# Ports (host side).
export BITCOIND_RPC_PORT=18443
export BITCOIND_P2P_PORT=18444
export ZMQ_BLOCK_PORT=28332
export ZMQ_TX_PORT=28333
export ESPLORA_PORT=3002
export LND_RPC_PORT=10009
export LND_P2P_PORT=9735
export LND_REST_PORT=8080
export TAPD_RPC_PORT=10029
export TAPD_REST_PORT=8089

# bitcoind RPC credentials (regtest only; do not reuse anywhere real).
export BTC_RPCUSER=tap
export BTC_RPCPASS=tap

# Derived paths.
export BIN_DIR="$INTEROP_DIR/bin"
export LOG_DIR="$INTEROP_DIR/logs"
export LND_DIR="$INTEROP_DIR/lnd"
export TAPD_DIR="$INTEROP_DIR/tapd"
export RUST_WALLET_DIR="$INTEROP_DIR/rust-wallets"

# The quickstart wallet mnemonic used by the test scripts. Regtest
# only; publicly known BIP-39 test vector.
export INTEROP_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Environment for the rust-tap quickstart CLI.
export TAP_NETWORK=regtest
export TAP_ESPLORA_URL="http://127.0.0.1:$ESPLORA_PORT"
export TAP_UNIVERSE_URL=none
export TAP_DATA_DIR="$RUST_WALLET_DIR"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$LND_DIR" "$TAPD_DIR" "$RUST_WALLET_DIR"

# Helper CLIs.
btccli() {
    docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest \
        -rpcuser="$BTC_RPCUSER" -rpcpassword="$BTC_RPCPASS" \
        -rpcwallet=miner "$@"
}

lcli() {
    "$BIN_DIR/lncli" --lnddir="$LND_DIR" --network regtest \
        --rpcserver="127.0.0.1:$LND_RPC_PORT" "$@"
}

tcli() {
    "$BIN_DIR/tapcli" --network=regtest --tapddir="$TAPD_DIR" \
        --rpcserver="127.0.0.1:$TAPD_RPC_PORT" "$@"
}

mine() {
    docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest \
        -rpcuser="$BTC_RPCUSER" -rpcpassword="$BTC_RPCPASS" \
        -rpcwallet=miner -generate "${1:-1}" > /dev/null
}
