#!/usr/bin/env bash
set -euo pipefail

BITCO=/d/bitcoboost
SRC="$BITCO/src"
NODEA="$BITCO/bb_nodeA"
NODEB="$BITCO/bb_nodeB"
CLI="$SRC/bitcoin-cli.exe"
DAE="$SRC/bitcoind.exe"
ACONF="$BITCO/emptyA.conf"
BCONF="$BITCO/bb_nodeB.conf"

BLOCKS="${1:-120}"   # usa un argomento per cambiare il numero di blocchi

# 0) stop eventuali bitcoind e pulizia peer-list
taskkill //IM bitcoind.exe //F >/dev/null 2>&1 || true
rm -f "$NODEA/peers.dat" "$NODEA/anchors.dat" "$NODEB/peers.dat" "$NODEB/anchors.dat"

# 1) avvia Node B (inbound locale)
"$DAE" -datadir="$NODEB" -conf="$BCONF" \
  -dnsseed=0 -fixedseeds=0 -listen=1 -bind=127.0.0.1 \
  -onlynet=ipv4 -listenonion=0 \
  -whitebind=127.0.0.1:39202 -whitelist=127.0.0.1 -maxconnections=32 \
  -port=39202 -rpcport=39212 -debug=net -logips=1 \
  >"$BITCO/bb_nodeB.log" 2>&1 &

# 2) avvia Node A (outbound -> B)
"$DAE" -datadir="$NODEA" -conf="$ACONF" \
  -dnsseed=0 -fixedseeds=0 -listen=1 -bind=127.0.0.1 \
  -onlynet=ipv4 -listenonion=0 \
  -addnode=127.0.0.1:39202 -whitelist=127.0.0.1 -maxconnections=32 \
  -port=39201 -rpcport=39211 -debug=net -logips=1 \
  >"$BITCO/bb_nodeA.log" 2>&1 &

# 3) attendi che le RPC siano su
until "$CLI" -rpcconnect=127.0.0.1 -rpcport=39211 -datadir="$NODEA" -conf="$ACONF" getblockcount >/dev/null 2>&1; do sleep 1; done
until "$CLI" -rpcconnect=127.0.0.1 -rpcport=39212 -datadir="$NODEB" -conf="$BCONF" getblockcount >/dev/null 2>&1; do sleep 1; done

# 4) assicurati che A veda B (se serve, un colpettino)
A_CONN=$("$CLI" -rpcconnect=127.0.0.1 -rpcport=39211 -datadir="$NODEA" -conf="$ACONF" getconnectioncount || echo 0)
if [ "$A_CONN" -lt 1 ]; then
  "$CLI" -rpcconnect=127.0.0.1 -rpcport=39211 -datadir="$NODEA" -conf="$ACONF" addnode 127.0.0.1:39202 onetry || true
fi

# 5) premine automatico
python3 "$BITCO/tools/bb_miner.py" --blocks "$BLOCKS"

# 6) riepilogo finale
echo "=== SUMMARY (Node A) ==="
"$CLI" -rpcconnect=127.0.0.1 -rpcport=39211 -datadir="$NODEA" -conf="$ACONF" getblockcount
"$CLI" -rpcconnect=127.0.0.1 -rpcport=39211 -datadir="$NODEA" -conf="$ACONF" getbalances
echo "Log files: $BITCO/bb_nodeA.log  |  $BITCO/bb_nodeB.log"
