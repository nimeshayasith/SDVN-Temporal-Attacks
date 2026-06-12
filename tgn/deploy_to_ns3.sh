#!/bin/bash
# tgn/deploy_to_ns3.sh — Deploy TGN detector to NS-3.35 scratch/ and run
#
# Usage (from project root or tgn/ folder):
#   bash tgn/deploy_to_ns3.sh [ns3_root] [attack_scenario] [simTime] [N_Vehicles]
#
# Defaults:
#   ns3_root       = ~/ns-allinone-3.35/ns-3.35
#   attack_scenario = 1   (TTW-S1)
#   simTime         = 60
#   N_Vehicles      = 6

NS3_ROOT="${1:-$HOME/ns-allinone-3.35/ns-3.35}"
SCENARIO="${2:-1}"
SIM_TIME="${3:-60}"
N_VEH="${4:-6}"
N_RSU="${5:-0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== TETA-Guard TGN Deployment Script ==="
echo "  Project root  : $PROJECT_ROOT"
echo "  NS-3 root     : $NS3_ROOT"
echo "  Attack scenario: $SCENARIO"
echo "  simTime        : $SIM_TIME s"
echo "  Vehicles       : $N_VEH   RSUs: $N_RSU"
echo ""

# ── Verify NS-3 installation ──────────────────────────────────────────────────
if [ ! -d "$NS3_ROOT/scratch" ]; then
    echo "ERROR: NS-3 scratch/ not found at $NS3_ROOT"
    echo "  Please install NS-3.35:  cd ~ && tar xf ns-allinone-3.35.tar.bz2"
    exit 1
fi

# ── Copy source files to scratch/ ────────────────────────────────────────────
echo "[deploy] Copying routing.cc to scratch/"
cp "$PROJECT_ROOT/routing.cc" "$NS3_ROOT/scratch/routing.cc"

echo "[deploy] Copying tgn_detector.cc to scratch/"
cp "$SCRIPT_DIR/tgn_detector.cc" "$NS3_ROOT/scratch/tgn_detector.cc"

# Fix include path: tgn/ uses "../routing.cc"; in scratch/ both files are siblings
sed -i 's|#include "\.\./routing\.cc"|#include "routing.cc"|' \
    "$NS3_ROOT/scratch/tgn_detector.cc"
echo "[deploy] Patched #include '../routing.cc' → 'routing.cc' in scratch copy"

# Copy Python training/comparison scripts (no path changes needed)
echo "[deploy] Copying tgn_train.py and tgn_compare.py to scratch/"
cp "$SCRIPT_DIR/tgn_train.py"   "$NS3_ROOT/scratch/tgn_train.py"
cp "$SCRIPT_DIR/tgn_compare.py" "$NS3_ROOT/scratch/tgn_compare.py"

# ── Build ─────────────────────────────────────────────────────────────────────
echo ""
echo "[deploy] Building NS-3 (waf)..."
cd "$NS3_ROOT" || exit 1
./waf build 2>&1 | tail -5
if [ $? -ne 0 ]; then
    echo "ERROR: waf build failed — check build log above"
    exit 1
fi

# ── Run TGN detector ─────────────────────────────────────────────────────────
echo ""
echo "[deploy] Running tgn_detector (attack_scenario=$SCENARIO)..."
./waf --run "scratch/tgn_detector \
    --simTime=$SIM_TIME \
    --N_Vehicles=$N_VEH \
    --N_RSUs=$N_RSU \
    --attack_scenario=$SCENARIO"

# ── Copy results back ─────────────────────────────────────────────────────────
echo ""
echo "[deploy] Copying output files back to project..."
for f in tgn_events.csv tgn_summary.csv pem_event_log.csv pem_run_summary.csv tgn_alerts.json; do
    [ -f "$NS3_ROOT/$f" ] && cp "$NS3_ROOT/$f" "$PROJECT_ROOT/$f" && echo "  copied $f"
done

echo ""
echo "=== Done. Results in $PROJECT_ROOT ==="
echo "  tgn_events.csv   — per-event TGN scores + features"
echo "  tgn_summary.csv  — MCC/AUROC/Tdet summary"
echo "  tgn_alerts.json  — alerts for blockchain submission"
echo ""
echo "Next: run crypto pipeline on the events:"
echo "  cd $PROJECT_ROOT/crypto && make pipeline"
echo ""
echo "Next: submit alerts to Fabric:"
echo "  python3 $PROJECT_ROOT/submit_alerts.py tgn_alerts.json"
