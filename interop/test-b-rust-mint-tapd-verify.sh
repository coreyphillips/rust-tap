#!/usr/bin/env bash
# Test B (headline): rust-tap mints an asset via the quickstart CLI;
# tapd verifies the rust-authored proof file.
#
# PASS = `tapcli proofs verify` returns "valid": true, and tapd's
# universe accepts the proof via `tapcli universe proofs insert`
# (which runs its own full verification on insert).
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

QS=./target/debug/tap-quickstart
NAME="rust-copper-$(date +%s)"
AMOUNT=4242

echo "== rust wallet: sync + address"
ADDR=$($QS "$INTEROP_MNEMONIC" sync | sed -n 's/^Address: //p' | head -1)
echo "   address: $ADDR"

echo "== funding rust wallet with 1 BTC"
btccli sendtoaddress "$ADDR" 1 > /dev/null
mine 2
sleep 3

echo "== rust-tap: minting $AMOUNT $NAME"
$QS "$INTEROP_MNEMONIC" mint "$NAME" "$AMOUNT" | tail -3
mine 2
sleep 4

STATE_FILE=$(ls -d "$RUST_WALLET_DIR"/*/state.json | head -1)
ASSET_ID=$(python3 -c "
import json
mints = json.load(open('$STATE_FILE'))['mints']
print([m for m in mints if m['name'] == '$NAME'][0]['asset_id'])")
echo "   asset_id: $ASSET_ID"

PROOF_FILE="$INTEROP_DIR/$NAME.tapf"
echo "== rust-tap: export proof (node tick generates it on confirmation)"
$QS "$INTEROP_MNEMONIC" export-proof "$ASSET_ID" "$PROOF_FILE" | tail -1

echo "== rust-tap: self-verify"
./target/debug/interop-verify "$PROOF_FILE" "$TAP_ESPLORA_URL" | tail -3

echo "== tapd: universe insert (full verification server-side)"
TXID=$(python3 -c "
import json
mints = json.load(open('$STATE_FILE'))['mints']
m = [m for m in mints if m['name'] == '$NAME'][0]
print(m['txid'])")
VOUT=$(python3 -c "
import json
mints = json.load(open('$STATE_FILE'))['mints']
m = [m for m in mints if m['name'] == '$NAME'][0]
print(m['tap_output_index'])")
SCRIPT_KEY=$(python3 -c "
import json
mints = json.load(open('$STATE_FILE'))['mints']
m = [m for m in mints if m['name'] == '$NAME'][0]
print(m['script_key'])")
tcli universe proofs insert \
    --asset_id "$ASSET_ID" --script_key "$SCRIPT_KEY" \
    --outpoint "$TXID:$VOUT" --proof_type issuance \
    --proof_file "$PROOF_FILE" > /dev/null
echo "   universe accepted the proof"

echo "== tapd: tapcli proofs verify"
RESULT=$(tcli proofs verify --proof_file "$PROOF_FILE")
echo "$RESULT" | head -3
if ! echo "$RESULT" | grep -q '"valid": true'; then
    echo "TEST B: FAIL (tapd did not report valid: true)"
    exit 1
fi

echo "TEST B: PASS"
