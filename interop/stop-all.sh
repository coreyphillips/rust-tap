#!/usr/bin/env bash
# Stops tapd, lnd, and the docker containers. Chain/wallet data under
# $INTEROP_DIR is left in place; delete the directory for a full reset.
set -uo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

if [ -f "$INTEROP_DIR/tapd.pid" ]; then
    kill "$(cat "$INTEROP_DIR/tapd.pid")" 2>/dev/null || true
    rm -f "$INTEROP_DIR/tapd.pid"
fi
if [ -f "$INTEROP_DIR/lnd.pid" ]; then
    kill "$(cat "$INTEROP_DIR/lnd.pid")" 2>/dev/null || true
    rm -f "$INTEROP_DIR/lnd.pid"
fi
docker rm -f "$ELECTRS_CONTAINER" "$BITCOIND_CONTAINER" 2>/dev/null || true
echo "stack stopped (data kept in $INTEROP_DIR)"
