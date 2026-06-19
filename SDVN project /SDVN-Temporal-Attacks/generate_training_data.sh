#!/bin/bash
# =============================================================================
# generate_training_data.sh
#
# Runs all 13 scenarios (baseline + 12 attacks) × N seeds through tgn_detector,
# collects tgn_events.csv from each run, concatenates into all_events.csv, then
# trains TGN weights and saves tgn_weights.bin.
#
# This script is REQUIRED before running tgn_detector with real GNN scoring.
# Without tgn_weights.bin the detector falls back to HeuristicScore() mode
# and prints a WARNING banner — the paper's GNN is not active until weights exist.
#
# N_RSUs is set automatically per scenario:
#   Scenarios 2,4,6,8,10,12 (RSU-based) → N_RSUs=1
#   All others                           → N_RSUs=0
#
# Usage:
#   bash generate_training_data.sh [options]
#
# Options:
#   --ns3_home PATH     Path to ns-3.35 root (default: ~/ns-allinone-3.35/ns-3.35)
#   --sim_time N        Simulation time in seconds per run (default: 60)
#   --n_vehicles N      Number of vehicles (default: 6)
#   --seeds "1 2 3"     Space-separated random seeds (default: "1 2 3")
#   --epochs N          Training epochs (default: 50)
#   --output FILE       Output weights file (default: tgn_weights.bin)
#   --skip_training     Only generate all_events.csv, skip tgn_train.py
#
# Prerequisites:
#   ./waf build  (NS-3 must be built with tgn_detector.cc in scratch/)
#   pip3 install torch pandas numpy scikit-learn
# =============================================================================

set -e

# ── Defaults ────────────────────────────────────────────────────────────────
NS3_HOME="${NS3_HOME:-$HOME/ns-allinone-3.35/ns-3.35}"
SIM_TIME=60
N_VEHICLES=6
SEEDS="1 2 3"
EPOCHS=50
OUTPUT="tgn_weights.bin"
SKIP_TRAINING=0

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ns3_home)    NS3_HOME="$2";    shift 2 ;;
        --sim_time)    SIM_TIME="$2";    shift 2 ;;
        --n_vehicles)  N_VEHICLES="$2";  shift 2 ;;
        --seeds)       SEEDS="$2";       shift 2 ;;
        --epochs)      EPOCHS="$2";      shift 2 ;;
        --output)      OUTPUT="$2";      shift 2 ;;
        --skip_training) SKIP_TRAINING=1; shift ;;
        *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate environment ─────────────────────────────────────────────────────
echo "================================================================"
echo "  TETA-Guard TGN Training Data Generator"
echo "  NS-3 home   : $NS3_HOME"
echo "  sim_time    : ${SIM_TIME}s"
echo "  N_Vehicles  : $N_VEHICLES"
echo "  Seeds       : $SEEDS"
echo "  Epochs      : $EPOCHS"
echo "  Output      : $OUTPUT"
echo "================================================================"

if [ ! -d "$NS3_HOME" ]; then
    echo "[ERROR] NS-3 home not found: $NS3_HOME"
    echo "        Set --ns3_home or export NS3_HOME=/path/to/ns-3.35"
    exit 1
fi

if [ ! -f "$NS3_HOME/waf" ]; then
    echo "[ERROR] waf not found in $NS3_HOME — is NS-3.35 installed?"
    exit 1
fi

# Copy tgn_detector.cc to scratch if needed
if [ ! -f "$NS3_HOME/scratch/tgn_detector.cc" ]; then
    echo "[setup] Copying tgn_detector.cc to $NS3_HOME/scratch/"
    cp "$SCRIPT_DIR/tgn_detector.cc" "$NS3_HOME/scratch/"
fi

# Build
echo ""
echo "[build] Running ./waf build ..."
cd "$NS3_HOME"
./waf build 2>&1 | grep -E "error:|warning:|Compiling|Linking" | tail -20
echo "[build] Build complete."

# ── Output directory ─────────────────────────────────────────────────────────
OUTDIR="$SCRIPT_DIR/training_data"
mkdir -p "$OUTDIR"
ALL_EVENTS="$OUTDIR/all_events.csv"
rm -f "$ALL_EVENTS"
HEADER_WRITTEN=0

# ── Scenario/RSU config ───────────────────────────────────────────────────────
# scenario_id → (N_RSUs needed, description)
declare -A SCENARIO_RSU
SCENARIO_RSU[0]=0   # Baseline
SCENARIO_RSU[1]=0   # TTW-S1
SCENARIO_RSU[2]=1   # TTW-S2
SCENARIO_RSU[3]=0   # TTW-S3
SCENARIO_RSU[4]=1   # TTW-S4
SCENARIO_RSU[5]=0   # BSHH-S1
SCENARIO_RSU[6]=1   # BSHH-S2
SCENARIO_RSU[7]=0   # BSHH-S3
SCENARIO_RSU[8]=1   # BSHH-S4
SCENARIO_RSU[9]=0   # ME-S1
SCENARIO_RSU[10]=1  # ME-S2
SCENARIO_RSU[11]=0  # ME-S3
SCENARIO_RSU[12]=1  # ME-S4

declare -A SCENARIO_NAME
SCENARIO_NAME[0]="Baseline"
SCENARIO_NAME[1]="TTW-S1"  SCENARIO_NAME[2]="TTW-S2"
SCENARIO_NAME[3]="TTW-S3"  SCENARIO_NAME[4]="TTW-S4"
SCENARIO_NAME[5]="BSHH-S1" SCENARIO_NAME[6]="BSHH-S2"
SCENARIO_NAME[7]="BSHH-S3" SCENARIO_NAME[8]="BSHH-S4"
SCENARIO_NAME[9]="ME-S1"   SCENARIO_NAME[10]="ME-S2"
SCENARIO_NAME[11]="ME-S3"  SCENARIO_NAME[12]="ME-S4"

TOTAL_RUNS=0
FAILED_RUNS=0

# ── Run all scenarios × seeds ────────────────────────────────────────────────
for SCENARIO in 0 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSU="${SCENARIO_RSU[$SCENARIO]}"
    NAME="${SCENARIO_NAME[$SCENARIO]}"

    for SEED in $SEEDS; do
        TOTAL_RUNS=$((TOTAL_RUNS + 1))
        echo ""
        echo "── Scenario ${SCENARIO} (${NAME})  seed=${SEED}  N_RSUs=${N_RSU} ──"

        # Clean previous outputs
        rm -f tgn_events.csv tgn_alerts.json tgn_summary.csv

        # Run tgn_detector
        if ./waf --run "scratch/tgn_detector \
                --simTime=${SIM_TIME} \
                --N_Vehicles=${N_VEHICLES} \
                --N_RSUs=${N_RSU} \
                --attack_scenario=${SCENARIO} \
                --RngRun=${SEED}" 2>&1 | tail -5; then

            if [ -f "tgn_events.csv" ]; then
                # Append to all_events.csv (header only once)
                if [ "$HEADER_WRITTEN" -eq 0 ]; then
                    cat tgn_events.csv >> "$ALL_EVENTS"
                    HEADER_WRITTEN=1
                else
                    tail -n +2 tgn_events.csv >> "$ALL_EVENTS"
                fi
                LINES=$(wc -l < tgn_events.csv)
                echo "   → appended ${LINES} lines to all_events.csv"

                # Save per-scenario copy
                cp tgn_events.csv "$OUTDIR/scenario${SCENARIO}_seed${SEED}_events.csv"
            else
                echo "   [WARN] tgn_events.csv not generated — skipping"
                FAILED_RUNS=$((FAILED_RUNS + 1))
            fi
        else
            echo "   [ERROR] waf run failed for scenario=${SCENARIO} seed=${SEED}"
            FAILED_RUNS=$((FAILED_RUNS + 1))
        fi
    done
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
TOTAL_LINES=$(wc -l < "$ALL_EVENTS" 2>/dev/null || echo 0)
echo "  Runs completed : $((TOTAL_RUNS - FAILED_RUNS)) / $TOTAL_RUNS"
echo "  Failed runs    : $FAILED_RUNS"
echo "  all_events.csv : $TOTAL_LINES lines  →  $ALL_EVENTS"
echo "================================================================"

if [ "$TOTAL_LINES" -lt 100 ]; then
    echo "[ERROR] all_events.csv has fewer than 100 lines — insufficient training data."
    echo "        Check that the scenarios ran successfully."
    exit 1
fi

# ── Train TGN weights ────────────────────────────────────────────────────────
if [ "$SKIP_TRAINING" -eq 1 ]; then
    echo "[info] --skip_training set — skipping tgn_train.py"
    echo "       Run manually: python3 tgn_train.py $ALL_EVENTS --output $OUTPUT"
    exit 0
fi

echo ""
echo "[train] Training TGN on $ALL_EVENTS ..."
echo "        epochs=${EPOCHS}  output=${OUTPUT}"

cd "$SCRIPT_DIR"
python3 tgn_train.py "$ALL_EVENTS" \
    --epochs "$EPOCHS" \
    --lr 0.001 \
    --dim 32 \
    --layers 2 \
    --output "$OUTPUT"

if [ -f "$OUTPUT" ]; then
    SIZE=$(du -sh "$OUTPUT" | cut -f1)
    echo ""
    echo "================================================================"
    echo "  Training complete."
    echo "  Weights saved : $OUTPUT  ($SIZE)"
    echo ""
    echo "  Use with tgn_detector:"
    echo "    ./waf --run \"scratch/tgn_detector \\"
    echo "        --simTime=60 --N_Vehicles=6 --attack_scenario=1 \\"
    echo "        --tgn_weights=$OUTPUT\""
    echo "================================================================"
else
    echo "[ERROR] tgn_weights.bin was not created — check tgn_train.py output above."
    exit 1
fi
