#!/usr/bin/env bash
# Starts the full regtest stack:
#   bitcoind (docker) -> electrs esplora API (docker) -> lnd -> tapd
# Mines 150 blocks and funds the lnd wallet with 5 BTC.
set -euo pipefail
cd "$(dirname "$0")/.."
source interop/env.sh

echo "== docker network"
docker network create "$DOCKER_NETWORK" 2>/dev/null || true

echo "== bitcoind (regtest, txindex, ZMQ)"
docker rm -f "$BITCOIND_CONTAINER" 2>/dev/null || true
docker run -d --name "$BITCOIND_CONTAINER" --network "$DOCKER_NETWORK" \
    -p "$BITCOIND_RPC_PORT:18443" -p "$BITCOIND_P2P_PORT:18444" \
    -p "$ZMQ_BLOCK_PORT:28332" -p "$ZMQ_TX_PORT:28333" \
    "$BITCOIND_IMAGE" \
    -regtest -server=1 -txindex=1 \
    -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
    -rpcuser="$BTC_RPCUSER" -rpcpassword="$BTC_RPCPASS" \
    -zmqpubrawblock=tcp://0.0.0.0:28332 -zmqpubrawtx=tcp://0.0.0.0:28333 \
    -fallbackfee=0.0001 -listen=1 -bind=0.0.0.0

sleep 3
docker exec "$BITCOIND_CONTAINER" bitcoin-cli -regtest \
    -rpcuser="$BTC_RPCUSER" -rpcpassword="$BTC_RPCPASS" \
    createwallet miner >/dev/null 2>&1 || true
MINE_ADDR=$(btccli getnewaddress)
btccli generatetoaddress 150 "$MINE_ADDR" > /dev/null
echo "   height: $(btccli getblockcount)"

echo "== electrs (esplora HTTP API on :$ESPLORA_PORT)"
docker rm -f "$ELECTRS_CONTAINER" 2>/dev/null || true
docker run -d --name "$ELECTRS_CONTAINER" --network "$DOCKER_NETWORK" \
    -p "$ESPLORA_PORT:3000" \
    "$ELECTRS_IMAGE" \
    --network regtest \
    --daemon-rpc-addr "$BITCOIND_CONTAINER:18443" \
    --cookie "$BTC_RPCUSER:$BTC_RPCPASS" \
    --jsonrpc-import \
    --http-addr 0.0.0.0:3000 \
    --db-dir /data -vv
sleep 5
echo "   esplora tip: $(curl -s http://127.0.0.1:$ESPLORA_PORT/blocks/tip/height)"

echo "== lnd"
cat > "$LND_DIR/lnd.conf" <<EOF
[Application Options]
debuglevel=info
noseedbackup=true
listen=127.0.0.1:$LND_P2P_PORT
rpclisten=127.0.0.1:$LND_RPC_PORT
restlisten=127.0.0.1:$LND_REST_PORT

[Bitcoin]
bitcoin.regtest=true
bitcoin.node=bitcoind

[Bitcoind]
bitcoind.rpchost=127.0.0.1:$BITCOIND_RPC_PORT
bitcoind.rpcuser=$BTC_RPCUSER
bitcoind.rpcpass=$BTC_RPCPASS
bitcoind.zmqpubrawblock=tcp://127.0.0.1:$ZMQ_BLOCK_PORT
bitcoind.zmqpubrawtx=tcp://127.0.0.1:$ZMQ_TX_PORT
EOF
nohup "$BIN_DIR/lnd" --lnddir="$LND_DIR" \
    --configfile="$LND_DIR/lnd.conf" > "$LOG_DIR/lnd.log" 2>&1 &
echo $! > "$INTEROP_DIR/lnd.pid"
# Wait for lnd's wallet RPC to answer.
for i in $(seq 1 60); do
    if lcli getinfo > /dev/null 2>&1; then break; fi
    sleep 2
done

echo "== funding lnd"
LND_ADDR=$(lcli newaddress p2tr | sed -n 's/.*"address": *"\(.*\)".*/\1/p')
btccli sendtoaddress "$LND_ADDR" 5 > /dev/null
mine 3
sleep 3
lcli walletbalance | head -3

echo "== tapd"
nohup "$BIN_DIR/tapd" --network=regtest --debuglevel=debug \
    --tapddir="$TAPD_DIR" \
    --lnd.host="127.0.0.1:$LND_RPC_PORT" \
    --lnd.macaroonpath="$LND_DIR/data/chain/bitcoin/regtest/admin.macaroon" \
    --lnd.tlspath="$LND_DIR/tls.cert" \
    --rpclisten="127.0.0.1:$TAPD_RPC_PORT" \
    --restlisten="127.0.0.1:$TAPD_REST_PORT" \
    --universe.public-access=rw \
    --allow-public-uni-proof-courier \
    --universe.no-default-federation \
    > "$LOG_DIR/tapd.log" 2>&1 &
echo $! > "$INTEROP_DIR/tapd.pid"
# Wait for tapd to come up (TLS cert appears, then RPC answers).
for i in $(seq 1 60); do
    if tcli getinfo > /dev/null 2>&1; then break; fi
    sleep 2
done
tcli getinfo | head -8

# Allow proof pushes into tapd's universe (used by test B and the
# universe insert flows; off by default in tapd).
tcli universe federation config global --proof_type issuance \
    --allow_insert true --allow_export true > /dev/null
tcli universe federation config global --proof_type transfer \
    --allow_insert true --allow_export true > /dev/null

echo "OK: stack is up (logs in $LOG_DIR)"
