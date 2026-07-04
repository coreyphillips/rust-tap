#!/usr/bin/env bash
# Test A: tapd mints an asset; rust-tap verifies the exported proof
# LIVE against the regtest chain (block headers via esplora).
#
# PASS = interop-verify exits 0 (full File::verify pipeline including
# real header verification), plus two negative controls fail.
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

NAME="interop-gold-$(date +%s)"

echo "== tapd: minting 5000 $NAME"
tcli assets mint --type normal --name "$NAME" --supply 5000 > /dev/null
tcli assets mint finalize > /dev/null
mine 2
sleep 6

ASSET_JSON=$(tcli assets list)
ASSET_ID=$(echo "$ASSET_JSON" | python3 -c "
import json,sys
assets = json.load(sys.stdin)['assets']
a = [x for x in assets if x['asset_genesis']['name'] == '$NAME'][0]
print(a['asset_genesis']['asset_id'])")
SCRIPT_KEY=$(echo "$ASSET_JSON" | python3 -c "
import json,sys
assets = json.load(sys.stdin)['assets']
a = [x for x in assets if x['asset_genesis']['name'] == '$NAME'][0]
print(a['script_key'])")
echo "   asset_id:   $ASSET_ID"
echo "   script_key: $SCRIPT_KEY"

PROOF_FILE="$INTEROP_DIR/$NAME.proof"
tcli proofs export --asset_id "$ASSET_ID" --script_key "$SCRIPT_KEY" \
    --proof_file "$PROOF_FILE" > /dev/null
echo "   exported $(wc -c < "$PROOF_FILE") bytes to $PROOF_FILE"

echo "== rust-tap: live verification"
./target/debug/interop-verify "$PROOF_FILE" "$TAP_ESPLORA_URL"

echo "== negative control: dead esplora must fail"
if ./target/debug/interop-verify "$PROOF_FILE" http://127.0.0.1:9 \
    > /dev/null 2>&1; then
    echo "FAIL: verification passed without chain access"
    exit 1
fi
echo "   failed as expected"

echo "== negative control: corrupted proof must fail"
python3 - "$PROOF_FILE" <<'EOF'
import sys
d = bytearray(open(sys.argv[1], 'rb').read())
d[100] ^= 0xff
open(sys.argv[1] + '.corrupt', 'wb').write(bytes(d))
EOF
if ./target/debug/interop-verify "$PROOF_FILE.corrupt" "$TAP_ESPLORA_URL" \
    > /dev/null 2>&1; then
    echo "FAIL: corrupted proof verified"
    exit 1
fi
echo "   failed as expected"

echo "TEST A: PASS"
