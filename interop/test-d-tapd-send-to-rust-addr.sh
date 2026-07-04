#!/usr/bin/env bash
# Test D (stretch): tapd sends an asset to a rust-tap address, with
# rust-tap's tap-universe-server (TLS gRPC) as the proof courier.
#
# Coverage:
#   1. rust-tap generates a V1 address embedding the courier URL.
#   2. tapd decodes the address (cross-implementation address codec).
#   3. tapd sends to it (the courier ping requires the TLS gRPC
#      listener; tapd's courier never dials plaintext).
#   4. tapd delivers the full proof chain (genesis + transfer) to the
#      rust-tap courier, whose InsertProof validates each proof.
#   5. The delivered chain is reassembled into a TAPF file and
#      verified live with interop-verify.
#
# NOT covered: automatic detection/import of the inbound asset by the
# quickstart node (the V0/V1 receive-side polling flow is not wired
# into the quickstart example).
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

QS=./target/debug/tap-quickstart
COURIER_GRPC_PORT=8095
COURIER_REST_PORT=8094
export TAP_COURIER_URL="universerpc://127.0.0.1:$COURIER_GRPC_PORT"

echo "== starting rust-tap universe server (courier) with TLS gRPC"
pkill -f tap-universe-server 2>/dev/null || true
sleep 1
if [ ! -f "$INTEROP_DIR/tap-server.cert" ]; then
    # Any self-signed cert works: tapd's courier skips verification.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$INTEROP_DIR/tap-server.key" \
        -out "$INTEROP_DIR/tap-server.cert" \
        -days 30 -nodes -subj "/O=tap-server/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi
nohup ./target/debug/tap-universe-server \
    --listen "127.0.0.1:$COURIER_REST_PORT" \
    --grpc-listen "127.0.0.1:$COURIER_GRPC_PORT" \
    --grpc-tls-cert "$INTEROP_DIR/tap-server.cert" \
    --grpc-tls-key "$INTEROP_DIR/tap-server.key" \
    --db "$INTEROP_DIR/tap-server-universe.db3" \
    > "$LOG_DIR/tap-server.log" 2>&1 &
echo $! > "$INTEROP_DIR/tap-server.pid"
sleep 2

echo "== picking a tapd-owned asset"
ASSET_ID=$(tcli assets list | python3 -c "
import json,sys
assets = [a for a in json.load(sys.stdin)['assets'] if not a['is_spent']]
print(assets[-1]['asset_genesis']['asset_id'])")
echo "   asset_id: $ASSET_ID"

echo "== rust-tap: generating receive address (amount 100)"
ADDR=$($QS "$INTEROP_MNEMONIC" receive "$ASSET_ID" 100 \
    | sed -n 's/^Receive address: //p')
echo "   $ADDR"

echo "== tapd: decoding the rust address"
SCRIPT_KEY=$(tcli addrs decode --addr "$ADDR" | python3 -c "
import json,sys
d = json.load(sys.stdin)
assert d['asset_id'] == '$ASSET_ID', 'asset id mismatch'
assert d['amount'] == '100', 'amount mismatch'
assert d['proof_courier_addr'] == '$TAP_COURIER_URL', 'courier mismatch'
assert d['address_version'] == 'ADDR_VERSION_V1', d['address_version']
print(d['script_key'])")
echo "   decode OK, script key $SCRIPT_KEY"

echo "== tapd: sending to the rust address"
tcli assets send --addr "$ADDR" > "$INTEROP_DIR/test-d-send.json"
python3 -c "
import json
d = json.load(open('$INTEROP_DIR/test-d-send.json'))
print('   anchor tx:', d['transfer']['anchor_tx_hash'])"
mine 2
sleep 10

echo "== checking courier delivery"
if ! grep -q "Transfer output proof delivery complete" "$LOG_DIR/tapd.log"
then
    echo "TEST D: FAIL (tapd did not report proof delivery)"
    exit 1
fi
echo "   tapd reports delivery complete"

echo "== reassembling the delivered proof chain and verifying live"
python3 - "$ASSET_ID" "$COURIER_REST_PORT" \
    "$INTEROP_DIR/test-d-received.tapf" <<'EOF'
import json, urllib.request, struct, hashlib, sys

asset_id, port, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
base = ("http://127.0.0.1:%s/v1/taproot-assets/universe/leaves/asset-id/%s"
        % (port, asset_id))
proofs = []
for pt in ["PROOF_TYPE_ISSUANCE", "PROOF_TYPE_TRANSFER"]:
    d = json.load(urllib.request.urlopen(base + "?proof_type=" + pt))
    for leaf in d.get("leaves", []):
        proofs.append(bytes.fromhex(leaf["proof"]))
assert len(proofs) >= 2, "expected issuance + transfer proofs"

def bigsize(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('>H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('>I', n)
    return b'\xff' + struct.pack('>Q', n)

out = b'TAPF' + b'\x00\x00\x00\x00' + bigsize(len(proofs))
prev = b'\x00' * 32
for p in proofs:
    h = hashlib.sha256(prev + p).digest()
    out += bigsize(len(p)) + p + h
    prev = h
open(out_path, 'wb').write(out)
print("   assembled %d proofs (%d bytes)" % (len(proofs), len(out)))
EOF
./target/debug/interop-verify "$INTEROP_DIR/test-d-received.tapf" \
    "$TAP_ESPLORA_URL"

echo "TEST D: PASS (delivery + verification; wallet auto-import not automated)"
