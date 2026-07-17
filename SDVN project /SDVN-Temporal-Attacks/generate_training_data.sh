#!/bin/bash
# =============================================================================
# generate_training_data.sh
#
# Runs all 13 scenarios (baseline + 12 attacks) × N seeds through routing
# (which includes tgn_core.cc), collects tgn_events.csv from each run,
# concatenates into all_events.csv, then trains TGN weights and saves tgn_weights.bin.
#
# This script is REQUIRED before running routing with real GNN scoring.
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
#   --ns3_home PATH          Path to ns-3.35 root (default: ~/ns-allinone-3.35/ns-3.35)
#   --sim_time N             Simulation time in seconds per run (default: 300)
#   --n_vehicles N           Number of vehicles (default: 200)
#   --seeds "1 2 3 4 5"      Space-separated random seeds (default: "1 2 3 4 5")
#   --epochs N               Training epochs (default: 50)
#   --output FILE            Output weights file (default: tgn_weights.bin)
#   --mobility_scenario N    0=urban 1=rural 2=highway (default: 0)
#   --maxspeed N             Max vehicle speed km/h — must match SUMO trace (default: 80)
#   --skip_training          Only generate all_events.csv, skip tgn_train.py
#
# Prerequisites:
#   ./waf build  (NS-3 must be built — routing.cc includes tgn_core.cc)
#   pip3 install torch pandas numpy scikit-learn
# =============================================================================

set -e

# ── Defaults ────────────────────────────────────────────────────────────────
NS3_HOME="${NS3_HOME:-$HOME/ns-allinone-3.35/ns-3.35}"
SIM_TIME=300
N_VEHICLES=200
N_RSU_COUNT=64      # RSUs for RSU-based scenarios (2,4,6,8,10,12)
N_CONTROLLERS=4
LAMBDA=30
SEEDS="1 2 3 4 5"
EPOCHS=50
OUTPUT="tgn_weights.bin"
SKIP_TRAINING=0
APPEND=0            # if 1, do not wipe all_events.csv before starting
MOBILITY_SCENARIO=0   # 0=urban, 1=rural, 2=highway
MAXSPEED=60           # km/h — must match SUMO trace file (only urban/60kmph trace exists)

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ns3_home)          NS3_HOME="$2";          shift 2 ;;
        --sim_time)          SIM_TIME="$2";          shift 2 ;;
        --n_vehicles)        N_VEHICLES="$2";        shift 2 ;;
        --n_rsus)            N_RSU_COUNT="$2";       shift 2 ;;
        --n_controllers)     N_CONTROLLERS="$2";     shift 2 ;;
        --lambda)            LAMBDA="$2";            shift 2 ;;
        --seeds)             SEEDS="$2";             shift 2 ;;
        --epochs)            EPOCHS="$2";            shift 2 ;;
        --output)            OUTPUT="$2";            shift 2 ;;
        --mobility_scenario) MOBILITY_SCENARIO="$2"; shift 2 ;;
        --maxspeed)          MAXSPEED="$2";          shift 2 ;;
        --skip_training)     SKIP_TRAINING=1;        shift ;;
        --append)            APPEND=1;               shift ;;
        *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate environment ─────────────────────────────────────────────────────
echo "================================================================"
echo "  TETA-Guard TGN Training Data Generator"
echo "  NS-3 home         : $NS3_HOME"
echo "  sim_time          : ${SIM_TIME}s"
echo "  N_Vehicles        : $N_VEHICLES"
echo "  N_RSUs (RSU scen) : $N_RSU_COUNT"
echo "  N_Controllers     : $N_CONTROLLERS"
echo "  lambda (flows)    : $LAMBDA"
echo "  mobility_scenario : $MOBILITY_SCENARIO  (0=urban 1=rural 2=highway)"
echo "  maxspeed          : ${MAXSPEED} km/h"
echo "  Seeds             : $SEEDS"
echo "  Epochs            : $EPOCHS"
echo "  Append mode       : $APPEND"
echo "  Output            : $OUTPUT"
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

# Build — capture output to temp file so we can check exit status AND filter output
echo ""
echo "[build] Running ./waf build ..."
cd "$NS3_HOME"
WAF_LOG=$(mktemp /tmp/waf_build_XXXXXX.log)
if ! ./waf build > "$WAF_LOG" 2>&1; then
    grep -E "error:" "$WAF_LOG" | head -10
    echo "[ERROR] ./waf build failed — see $WAF_LOG for full output"
    exit 1
fi
grep -E "warning:|Compiling|Linking" "$WAF_LOG" | tail -20 || true
rm -f "$WAF_LOG"
echo "[build] Build complete."

# ── Output directory ─────────────────────────────────────────────────────────
OUTDIR="$SCRIPT_DIR/training_data"
mkdir -p "$OUTDIR"
ALL_EVENTS="$OUTDIR/all_events.csv"
if [ "$APPEND" -eq 0 ]; then
    rm -f "$ALL_EVENTS"
    HEADER_WRITTEN=0
else
    # Append mode: keep existing data, skip header if file already has content
    if [ -f "$ALL_EVENTS" ] && [ "$(wc -l < "$ALL_EVENTS")" -gt 1 ]; then
        HEADER_WRITTEN=1
        echo "[info] --append mode: preserving existing $(wc -l < "$ALL_EVENTS") lines in all_events.csv"
    else
        HEADER_WRITTEN=0
    fi
fi

# ── Scenario/RSU config ───────────────────────────────────────────────────────
# scenario_id → (N_RSUs needed, description)
declare -A SCENARIO_RSU
SCENARIO_RSU[0]=0              # Baseline
SCENARIO_RSU[1]=0              # TTW-S1
SCENARIO_RSU[2]=$N_RSU_COUNT   # TTW-S2
SCENARIO_RSU[3]=0              # TTW-S3
SCENARIO_RSU[4]=$N_RSU_COUNT   # TTW-S4
SCENARIO_RSU[5]=0              # BSHH-S1
SCENARIO_RSU[6]=$N_RSU_COUNT   # BSHH-S2
SCENARIO_RSU[7]=0              # BSHH-S3
SCENARIO_RSU[8]=$N_RSU_COUNT   # BSHH-S4
SCENARIO_RSU[9]=0              # ME-S1
SCENARIO_RSU[10]=$N_RSU_COUNT  # ME-S2
SCENARIO_RSU[11]=0             # ME-S3
SCENARIO_RSU[12]=$N_RSU_COUNT  # ME-S4

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
        rm -f tgn_events.csv tgn_alerts.json

        # Run routing (tgn_core.cc is included inside routing.cc)
        if ./waf --run "scratch/routing \
                --simTime=${SIM_TIME} \
                --N_Vehicles=${N_VEHICLES} \
                --N_RSUs=${N_RSU} \
                --N_Controllers=${N_CONTROLLERS} \
                --lambda=${LAMBDA} \
                --attack_scenario=${SCENARIO} \
                --mobility_scenario=${MOBILITY_SCENARIO} \
                --maxspeed=${MAXSPEED} \
                --RngRun=${SEED}" 2>&1 | tail -5; then

            if [ -f "tgn_events.csv" ]; then
                # Inject seed_id as second column (after sim_time_s) for multi-seed tracking
                awk -v seed="$SEED" -F',' 'BEGIN{OFS=","}
                    NR==1 { print $1,"seed_id",$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21 }
                    NR>1  { print $1,seed,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21 }
                ' tgn_events.csv > tgn_events_seeded.csv

                # Append to all_events.csv (header only once)
                if [ "$HEADER_WRITTEN" -eq 0 ]; then
                    cat tgn_events_seeded.csv >> "$ALL_EVENTS"
                    HEADER_WRITTEN=1
                else
                    tail -n +2 tgn_events_seeded.csv >> "$ALL_EVENTS"
                fi
                LINES=$(wc -l < tgn_events_seeded.csv)
                echo "   → appended ${LINES} lines to all_events.csv (seed_id=${SEED})"

                # Save per-scenario copy (with seed_id column)
                cp tgn_events_seeded.csv "$OUTDIR/scenario${SCENARIO}_seed${SEED}_events.csv"
                rm -f tgn_events_seeded.csv
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
# L_link (expected link lifetime) depends on mobility scenario:
#   Urban (0):   ~43s at 80 km/h within 300m DSRC range
#   Rural  (1):  ~43s  (same range, similar speed)
#   Highway (2): ~9s   (higher relative speed, shorter link lifetime)
if [ "$MOBILITY_SCENARIO" -eq 2 ]; then
    L_LINK=9
else
    L_LINK=43
fi

if [ "$SKIP_TRAINING" -eq 1 ]; then
    echo "[info] --skip_training set — skipping tgn_train.py"
    echo "       Run manually:"
    echo "         cd \"$SCRIPT_DIR/tgn\""
    echo "         python3 tgn_train.py \"$ALL_EVENTS\" --l_link $L_LINK --output $OUTPUT"
    exit 0
fi

echo ""
echo "[train] Training TGN on $ALL_EVENTS ..."
echo "        epochs=${EPOCHS}  l_link=${L_LINK}s  output=${OUTPUT}"

cd "$SCRIPT_DIR/tgn"
python3 tgn_train.py "$ALL_EVENTS" \
    --epochs "$EPOCHS" \
    --lr 0.001 \
    --dim 32 \
    --layers 2 \
    --l_link "$L_LINK" \
    --output "$OUTPUT"

if [ -f "$OUTPUT" ]; then
    SIZE=$(du -sh "$OUTPUT" | cut -f1)
    echo ""
    echo "================================================================"
    echo "  Training complete."
    echo "  Weights saved : $OUTPUT  ($SIZE)"
    echo ""
    echo "  Use with routing (tgn_core included):"
    echo "    ./waf --run \"scratch/routing \\"
    echo "        --simTime=${SIM_TIME} --N_Vehicles=${N_VEHICLES} --attack_scenario=1 \\"
    echo "        --mobility_scenario=${MOBILITY_SCENARIO} --maxspeed=${MAXSPEED} \\"
    echo "        --tgn_weights=$(realpath $OUTPUT 2>/dev/null || echo $OUTPUT)\""
    echo "================================================================"
else
    echo "[ERROR] tgn_weights.bin was not created — check tgn_train.py output above."
    exit 1
fi
