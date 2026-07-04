#!/usr/bin/env bash
# Test C: rust-tap syncs an asset's issuance proof from a REAL tapd
# universe over tapd's native gRPC interface (TLS + macaroon), using
# GrpcUniverseClient + SimpleSyncer.
#
# PASS = interop-sync exits 0: leaf fetched, proof verified by the
# rust pipeline, and the locally rebuilt universe MS-SMT root matches
# tapd's root byte for byte.
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

# Sync the most recently minted tapd asset.
ASSET_ID=$(tcli assets list | python3 -c "
import json,sys
assets = json.load(sys.stdin)['assets']
print(assets[-1]['asset_genesis']['asset_id'])")
echo "== syncing asset $ASSET_ID from tapd's universe"

./target/debug/interop-sync \
    "https://127.0.0.1:$TAPD_RPC_PORT" \
    "$TAPD_DIR/tls.cert" \
    "$TAPD_DIR/data/regtest/admin.macaroon" \
    "$ASSET_ID"

echo "TEST C: PASS"
