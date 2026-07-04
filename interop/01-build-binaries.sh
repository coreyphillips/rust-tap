#!/usr/bin/env bash
# Builds lnd/lncli (compatible version + subserver tags) and
# tapd/tapcli (from the local taproot-assets checkout) into
# $INTEROP_DIR/bin, plus the rust-tap interop binaries.
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

echo "== Building lnd $LND_VERSION with tags: $LND_BUILD_TAGS"
if [ ! -x "$BIN_DIR/lnd" ]; then
    if [ ! -d "$INTEROP_DIR/lnd-src" ]; then
        git clone --depth 1 --branch "$LND_VERSION" \
            https://github.com/lightningnetwork/lnd "$INTEROP_DIR/lnd-src"
    fi
    (
        cd "$INTEROP_DIR/lnd-src"
        go build -tags="$LND_BUILD_TAGS" -o "$BIN_DIR/lnd" ./cmd/lnd
        go build -tags="$LND_BUILD_TAGS" -o "$BIN_DIR/lncli" ./cmd/lncli
    )
else
    echo "   already built, skipping"
fi

echo "== Building tapd/tapcli from $TAPROOT_ASSETS_DIR"
(
    cd "$TAPROOT_ASSETS_DIR"
    go build -o "$BIN_DIR/tapd" ./cmd/tapd
    go build -o "$BIN_DIR/tapcli" ./cmd/tapcli
)

echo "== Building rust-tap interop binaries"
cargo build -p tap-quickstart -p tap-interop-verify -p tap-interop-sync
# The universe server binary (test D proof courier) needs the sqlite
# feature.
cargo build -p tap-server --features sqlite

echo "OK: binaries in $BIN_DIR and target/debug"
