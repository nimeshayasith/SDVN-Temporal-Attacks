#!/bin/bash
# =============================================================================
# run_integration_test.sh
#
# End-to-end integration test for the TETA-Guard framework.
# Tests the complete pipeline for one scenario:
#
#   NS-3 simulation (routing.cc)
#     → PEM_EVENT_LOG/  (output directory)
#     → [handoff: copy to pem_event_log_s{N}.csv]
#     → crypto_pipeline  (Alg. 3: HMAC + freshness + nonce)
#     → crypto_verified_events.csv
#     → tgn_detector.cc  (Alg. 2: GRU + message passing + Alg. 3 inline)
#     → tgn_alerts.json  (Eq. 3.36 AlertObject)
#     → submit_alerts.py (peer chaincode invoke SubmitAlert)
#     → Hyperledger Fabric / TemporalEchoMitigator (TetaGuardMSP)
#     → eventListener.js (off-chain FlowMod HTTP POST to Ryu)
#
# MSP name: TetaGuardMSP  (note: was "TetagaurdMSP" typo — fixed)
#
# Prerequisites for blockchain steps:
#   cd blockchain/network && docker-compose -f docker-compose-teta.yaml up -d
#   cd blockchain/scripts && bash bootstrap.sh  (first time only)
#   submitToFabric.js checks cert files exist before SDK init — run bootstrap.sh first
#
# Usage:
#   bash run_integration_test.sh [options]
#
# Options:
#   --ns3_home PATH      NS-3.35 root (default: ~/ns-allinone-3.35/ns-3.35)
#   --scenario N         Attack scenario 1-12 (default: 1 = TTW-S1)
#   --skip_crypto        Skip standalone crypto_pipeline step
#   --skip_blockchain    Skip blockchain submission step
#   --dry_run            Use submit_alerts.py --dry-run (no live Fabric needed)
#   --tgn_weights FILE   Path to pre-trained tgn_weights.bin (optional)
#                        Without this flag, tgn_detector runs in heuristic mode.
# =============================================================================

set -e

# ── Defaults ─────────────────────────────────────────────────────────────────
NS3_HOME="${NS3_HOME:-$HOME/ns-allinone-3.35/ns-3.35}"
SCENARIO=1
SKIP_CRYPTO=0
SKIP_BLOCKCHAIN=0
DRY_RUN=0
TGN_WEIGHTS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ns3_home)       NS3_HOME="$2";      shift 2 ;;
        --scenario)       SCENARIO="$2";      shift 2 ;;
        --skip_crypto)    SKIP_CRYPTO=1;      shift ;;
        --skip_blockchain) SKIP_BLOCKCHAIN=1; shift ;;
        --dry_run)        DRY_RUN=1;          shift ;;
        --tgn_weights)    TGN_WEIGHTS="$2";   shift 2 ;;
        *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────
check() {
    local label="$1"; local cond="$2"
    if [ "$cond" -eq 1 ]; then
        echo "  ✓  $label"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $label  ← FAIL"
        FAIL=$((FAIL + 1))
    fi
}

file_exists()    { [ -f "$1" ] && echo 1 || echo 0; }
file_nonempty()  { [ -s "$1" ] && echo 1 || echo 0; }
csv_has_rows()   { [ "$(wc -l < "$1" 2>/dev/null || echo 0)" -gt 1 ] && echo 1 || echo 0; }
json_nonempty()  { python3 -c "import json,sys; d=json.load(open('$1')); sys.exit(0 if d else 1)" 2>/dev/null && echo 1 || echo 0; }

# ── N_RSUs for scenario ───────────────────────────────────────────────────────
N_RSU=0
case $SCENARIO in 2|4|6|8|10|12) N_RSU=1 ;; esac

# ── N_Vehicles ────────────────────────────────────────────────────────────────
N_VEH=6
case $SCENARIO in 9|10|11|12) N_VEH=6 ;; esac

echo ""
echo "================================================================"
echo "  TETA-Guard End-to-End Integration Test"
echo "  Scenario   : $SCENARIO  (N_Vehicles=$N_VEH  N_RSUs=$N_RSU)"
echo "  NS-3 home  : $NS3_HOME"
echo "  Dry run    : $([ $DRY_RUN -eq 1 ] && echo yes || echo no)"
echo "================================================================"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — NS-3 Simulation (routing.cc)
# ═════════════════════════════════════════════════════════════════════════════
echo "── STEP 1: NS-3 simulation (routing.cc) ──"

cd "$NS3_HOME"
rm -f pem_event_log*.csv pem_run_summary*.csv

./waf --run "scratch/routing \
    --simTime=30 \
    --N_Vehicles=${N_VEH} \
    --N_RSUs=${N_RSU} \
    --attack_scenario=${SCENARIO} \
    --RngRun=42" 2>&1 | tail -10

PEM_CSV="$NS3_HOME/PEM_EVENT_LOG/$(ls $NS3_HOME/PEM_EVENT_LOG/ 2>/dev/null | head -1)"
# Fallback: look in cwd
[ ! -f "$PEM_CSV" ] && PEM_CSV=$(ls pem_event_log*.csv 2>/dev/null | head -1)

check "pem_event_log.csv generated"    "$(file_exists "${PEM_CSV:-/dev/null}")"
check "pem_event_log.csv has data rows" "$(csv_has_rows "${PEM_CSV:-/dev/null}")"

PEM_SUMMARY=$(ls pem_run_summary*.csv 2>/dev/null | head -1)
check "pem_run_summary.csv generated"  "$(file_exists "${PEM_SUMMARY:-/dev/null}")"

if [ -n "$PEM_SUMMARY" ] && [ -f "$PEM_SUMMARY" ]; then
    MCC=$(awk -F',' 'NR==2{print $9}' "$PEM_SUMMARY" 2>/dev/null || echo "?")
    TDET=$(awk -F',' 'NR==2{print $11}' "$PEM_SUMMARY" 2>/dev/null || echo "?")
    echo "     MCC=$MCC  Tdet_ms=$TDET"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 — Crypto Pipeline (standalone)
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── STEP 2: Crypto pipeline ──"

if [ "$SKIP_CRYPTO" -eq 1 ]; then
    echo "   (skipped via --skip_crypto)"
else
    CRYPTO_BIN="$SCRIPT_DIR/crypto_pipeline"

    # Build if not present
    if [ ! -f "$CRYPTO_BIN" ]; then
        echo "   Building crypto_pipeline..."
        g++ -std=c++17 -O2 "$SCRIPT_DIR/crypto_pipeline.cc" \
            -lssl -lcrypto -lm -o "$CRYPTO_BIN" 2>&1 | tail -5
    fi

    if [ -f "$CRYPTO_BIN" ]; then
        "$CRYPTO_BIN" "${PEM_CSV:-pem_event_log.csv}" tgn_alerts.json 2>&1 | tail -5

        check "crypto_verified_events.csv generated" \
              "$(file_exists crypto_verified_events.csv)"
        check "crypto_drop_log.csv generated" \
              "$(file_exists crypto_drop_log.csv)"
        check "crypto_layer_log.txt generated" \
              "$(file_exists crypto_layer_log.txt)"

        if [ -f crypto_verified_events.csv ]; then
            PASS_LINES=$(wc -l < crypto_verified_events.csv)
            DROP_LINES=$(wc -l < crypto_drop_log.csv 2>/dev/null || echo 0)
            echo "     Passed: $PASS_LINES events  Dropped: $DROP_LINES events"
        fi
    else
        echo "   [WARN] crypto_pipeline binary not found — skipping"
        echo "          Build: g++ -std=c++17 -O2 crypto_pipeline.cc -lssl -lcrypto -o crypto_pipeline"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — TGN Detector (tgn_detector.cc)
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── STEP 3: TGN detector (tgn_detector.cc) ──"

TGN_WEIGHTS_FLAG=""
if [ -n "$TGN_WEIGHTS" ] && [ -f "$TGN_WEIGHTS" ]; then
    TGN_WEIGHTS_FLAG="--tgn_weights=$TGN_WEIGHTS"
    echo "   Using pre-trained weights: $TGN_WEIGHTS"
else
    echo "   [WARN] No tgn_weights.bin — running in heuristic mode"
    echo "          Run generate_training_data.sh to produce weights."
fi

cd "$NS3_HOME"
rm -f tgn_events.csv tgn_alerts.json tgn_summary.csv

./waf --run "scratch/tgn_detector \
    --simTime=30 \
    --N_Vehicles=${N_VEH} \
    --N_RSUs=${N_RSU} \
    --attack_scenario=${SCENARIO} \
    --RngRun=42 \
    $TGN_WEIGHTS_FLAG" 2>&1 | tail -10

check "tgn_events.csv generated"   "$(file_exists tgn_events.csv)"
check "tgn_events.csv has data"    "$(csv_has_rows tgn_events.csv)"
check "tgn_summary.csv generated"  "$(file_exists tgn_summary.csv)"
check "tgn_alerts.json generated"  "$(file_exists tgn_alerts.json)"
check "crypto_filter_log.txt generated" "$(file_exists crypto_filter_log.txt)"

if [ -f tgn_summary.csv ]; then
    TGN_MCC=$(awk -F',' 'NR==2{print $7}' tgn_summary.csv 2>/dev/null || echo "?")
    TGN_AUROC=$(awk -F',' 'NR==2{print $8}' tgn_summary.csv 2>/dev/null || echo "?")
    TGN_TDET=$(awk -F',' 'NR==2{print $11}' tgn_summary.csv 2>/dev/null || echo "?")
    echo "     TGN MCC=$TGN_MCC  AUROC=$TGN_AUROC  Tdet_ms=$TGN_TDET"
fi

ALERT_COUNT=0
if [ -f tgn_alerts.json ]; then
    ALERT_COUNT=$(python3 -c "import json; d=json.load(open('tgn_alerts.json')); print(len(d))" 2>/dev/null || echo 0)
    echo "     tgn_alerts.json: $ALERT_COUNT alert(s)"
fi
check "tgn_alerts.json has alerts (attack scenario)" \
      "$([ "$ALERT_COUNT" -gt 0 ] && echo 1 || echo 0)"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 — Blockchain Submission
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── STEP 4: Blockchain submission ──"

if [ "$SKIP_BLOCKCHAIN" -eq 1 ]; then
    echo "   (skipped via --skip_blockchain)"
else
    cd "$SCRIPT_DIR"

    # Pass N_RSU so submit_alerts.py selects the correct peer set:
    #   N_RSU=0 → OBU mode (peer0.obu1..3, OutOf(2,3))
    #   N_RSU>0 → RSU mode (peer0.rsu1..5, OutOf(3,5))
    SUBMIT_FLAGS="--alerts $NS3_HOME/tgn_alerts.json --n_rsus ${N_RSU}"
    if [ "$DRY_RUN" -eq 1 ]; then
        SUBMIT_FLAGS="$SUBMIT_FLAGS --dry_run"
        echo "   Running in dry-run mode (no live Fabric needed)"
    fi

    MODE_DESC="RSU mode (peer0.rsu1..5)"; [ "$N_RSU" -eq 0 ] && MODE_DESC="OBU mode (peer0.obu1..3)"
    echo "   Peer mode: $MODE_DESC"

    if python3 submit_alerts.py $SUBMIT_FLAGS 2>&1 | tail -10; then
        check "submit_alerts.py completed" 1
    else
        check "submit_alerts.py completed" 0
        if [ "$N_RSU" -eq 0 ]; then
            echo "     [HINT] Start OBU Fabric: cd blockchain/network && docker-compose up -d orderer.tetaguard.net peer0.obu1.tetaguard.net peer0.obu2.tetaguard.net peer0.obu3.tetaguard.net"
        else
            echo "     [HINT] Start RSU Fabric: cd blockchain/network && docker-compose -f docker-compose-teta.yaml up -d"
        fi
        echo "            Or re-run with --dry_run to skip live Fabric."
    fi

    check "blockchain_submission_log.txt generated" \
          "$(file_exists blockchain_submission_log.txt)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# RESULTS
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "================================================================"
echo "  Integration Test Results — Scenario $SCENARIO"
echo "================================================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "  ✓  ALL CHECKS PASSED — pipeline is end-to-end functional"
else
    echo "  ✗  $FAIL CHECK(S) FAILED — see output above"
fi

echo ""
echo "  Output files:"
echo "    pem_event_log       → $NS3_HOME/PEM_EVENT_LOG/"
echo "    tgn_events.csv      → $NS3_HOME/tgn_events.csv"
echo "    tgn_alerts.json     → $NS3_HOME/tgn_alerts.json"
echo "    crypto_filter_log   → $NS3_HOME/crypto_filter_log.txt"
echo "    blockchain_log      → $SCRIPT_DIR/blockchain_submission_log.txt"
echo "================================================================"

exit $FAIL
