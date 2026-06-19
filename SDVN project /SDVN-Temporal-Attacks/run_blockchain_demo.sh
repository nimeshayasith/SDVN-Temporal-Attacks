#!/bin/bash
# run_blockchain_demo.sh
#
# Full NS-3 → Blockchain pipeline (no TGN, no Dilithium2 signing required).
#
# Usage:
#   bash run_blockchain_demo.sh [attack_scenario_id]
#
# Examples:
#   bash run_blockchain_demo.sh           # uses latest PEM CSV (default scenario 1)
#   bash run_blockchain_demo.sh 1         # TTW-S1: Malicious Vehicle
#   bash run_blockchain_demo.sh 5         # BSHH-S1: Malicious Vehicle
#   bash run_blockchain_demo.sh 9         # ME-S1: Malicious Vehicles
#
# Prerequisites (run once):
#   1. docker-compose -f blockchain/network/docker-compose-teta.yaml up -d
#   2. bash blockchain/scripts/create_channel.sh
#   3. bash blockchain/scripts/deploy_chaincode.sh
#   4. cd blockchain/client && npm install && node enrollAdmin.js && cd ../..

set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"
SCENARIO="${1:-}"  # optional scenario ID

echo "════════════════════════════════════════════════════════"
echo "  TETA-Guard Blockchain Demo"
echo "  NS-3 PEM output → Hyperledger Fabric"
echo "════════════════════════════════════════════════════════"

# ── Step 1: Verify tgn_alerts.json from routing.cc ───────────────────────────
# routing.cc now writes tgn_alerts.json directly via PemWriteAlertsJson() at
# simulation end (scheduled at simTime-0.001s).  pem_to_alerts.py is only a
# fallback for older CSV-only runs and must NOT overwrite the routing.cc file.
echo ""
echo "[1/3] Checking tgn_alerts.json from NS-3 simulation..."
cd "$PROJ"

if [ ! -s "$PROJ/tgn_alerts.json" ]; then
    echo "[WARN] tgn_alerts.json is empty or missing — trying pem_to_alerts.py fallback..."
    if [ -n "$SCENARIO" ]; then
        python3 pem_to_alerts.py --scenario "$SCENARIO"
    else
        python3 pem_to_alerts.py
    fi
fi

if [ ! -s "$PROJ/tgn_alerts.json" ]; then
    echo "[ERROR] tgn_alerts.json is empty or missing."
    echo "        Run routing.cc first with an attack scenario:"
    echo "        cd ~/ns-allinone-3.35/ns-3.35"
    echo "        ./waf --run 'scratch/routing --simTime=30 --N_Vehicles=2 --attack_scenario=1'"
    exit 1
fi

echo "      tgn_alerts.json OK  ($(python3 -c "import json; d=json.load(open('$PROJ/tgn_alerts.json')); print(len(d),'alert(s)')" 2>/dev/null || echo "?"))"

# ── Step 2: Start event listener (background) ────────────────────────────────
echo ""
echo "[2/3] Starting event listener..."
cd "$PROJ/blockchain/client"

node eventListener.js > /tmp/teta_events.log 2>&1 &
LISTENER_PID=$!
echo "      PID=$LISTENER_PID  (logs: /tmp/teta_events.log)"
sleep 4  # wait for listener to connect

# ── Step 3: Submit to blockchain ─────────────────────────────────────────────
echo ""
echo "[3/3] Submitting to Hyperledger Fabric..."
node submitToFabric.js --alerts "$PROJ/tgn_alerts.json" 2>&1

# ── Show events ──────────────────────────────────────────────────────────────
sleep 3
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Blockchain events received:"
echo "════════════════════════════════════════════════════════"
cat /tmp/teta_events.log

kill "$LISTENER_PID" 2>/dev/null

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Demo complete."
echo "  tgn_alerts.json  — alert sent to blockchain"
echo "  /tmp/teta_events.log  — events received"
echo "════════════════════════════════════════════════════════"
