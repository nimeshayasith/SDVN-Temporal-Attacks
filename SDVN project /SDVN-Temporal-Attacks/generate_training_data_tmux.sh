#!/bin/bash
# =============================================================================
# generate_training_data_tmux.sh
#
# Tmux-safe version of generate_training_data.sh.
# Runs all 13 scenarios (baseline + 12 attacks) × N seeds, collects
# tgn_events.csv from each run, concatenates into all_events.csv.
# Training is SKIPPED by default (--skip_training); run tgn_train.py
# manually after all seeds are collected.
#
# N_RSUs is set automatically per scenario:
#   Scenarios 2,4,6,8,10,12 (RSU-based) → N_RSUs=64
#   All others                           → N_RSUs=0
#
# Usage:
#   bash generate_training_data_tmux.sh [options]
#
# Options:
#   --ns3_home PATH          Path to ns-3.35 root (default: ~/ns-allinone-3.35/ns-3.35)
#   --sim_time N             Simulation time in seconds per run (default: 150)
#   --n_vehicles N           Number of vehicles (default: 200)
#   --seeds "1 2"            Space-separated random seeds (default: "1 2")
#   --epochs N               Training epochs (default: 50)
#   --output FILE            Output weights file (default: tgn_weights.bin)
#   --mobility_scenario N    0=urban 1=rural 2=highway (default: 0)
#   --maxspeed N             Max vehicle speed km/h — must match SUMO trace (default: 80)
#   --skip_training          Only generate all_events.csv, skip tgn_train.py (DEFAULT ON)
#   --do_training            Run tgn_train.py after data collection
#
# Prerequisites:
#   ./waf build  (NS-3 must be built — routing.cc includes tgn_core.cc)
#   pip3 install torch pandas numpy scikit-learn
# =============================================================================

set -e

# ── Defaults ────────────────────────────────────────────────────────────────
NS3_HOME="${NS3_HOME:-$HOME/ns-allinone-3.35/ns-3.35}"
SIM_TIME=150
N_VEHICLES=200
SEEDS="1 2"
EPOCHS=50
OUTPUT="tgn_weights.bin"
SKIP_TRAINING=1        # default: skip training, just collect data
APPEND=0               # if 1, preserve existing all_events.csv (for multi-seed runs)
MOBILITY_SCENARIO=0    # 0=urban, 1=rural, 2=highway
MAXSPEED=80            # km/h — must match SUMO trace file
OUTDIR_OVERRIDE=""     # if set, overrides default training_data/ output folder

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ns3_home)          NS3_HOME="$2";          shift 2 ;;
        --sim_time)          SIM_TIME="$2";          shift 2 ;;
        --n_vehicles)        N_VEHICLES="$2";        shift 2 ;;
        --seeds)             SEEDS="$2";             shift 2 ;;
        --epochs)            EPOCHS="$2";            shift 2 ;;
        --output)            OUTPUT="$2";            shift 2 ;;
        --mobility_scenario) MOBILITY_SCENARIO="$2"; shift 2 ;;
        --maxspeed)          MAXSPEED="$2";          shift 2 ;;
        --skip_training)     SKIP_TRAINING=1;        shift ;;
        --do_training)       SKIP_TRAINING=0;        shift ;;
        --append)            APPEND=1;               shift ;;
        --outdir)            OUTDIR_OVERRIDE="$2";   shift 2 ;;
        *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Validate environment ─────────────────────────────────────────────────────
echo "================================================================"
echo "  TETA-Guard TGN Training Data Generator (tmux edition)"
echo "  NS-3 home         : $NS3_HOME"
echo "  sim_time          : ${SIM_TIME}s"
echo "  N_Vehicles        : $N_VEHICLES"
echo "  mobility_scenario : $MOBILITY_SCENARIO  (0=urban 1=rural 2=highway)"
echo "  maxspeed          : ${MAXSPEED} km/h"
echo "  Seeds             : $SEEDS"
echo "  Skip training     : $SKIP_TRAINING"
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

# Build
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
OUTDIR="${OUTDIR_OVERRIDE:-$SCRIPT_DIR/training_data}"
mkdir -p "$OUTDIR"
ALL_EVENTS="$OUTDIR/all_events.csv"
if [ "$APPEND" -eq 0 ]; then
    rm -f "$ALL_EVENTS"
    HEADER_WRITTEN=0
else
    if [ -f "$ALL_EVENTS" ] && [ "$(wc -l < "$ALL_EVENTS")" -gt 1 ]; then
        HEADER_WRITTEN=1
        echo "[info] --append mode: preserving existing $(wc -l < "$ALL_EVENTS") lines in all_events.csv"
    else
        HEADER_WRITTEN=0
    fi
fi

# ── Scenario/RSU config ───────────────────────────────────────────────────────
# RSU-based scenarios use 64 RSUs; non-RSU scenarios use 0
declare -A SCENARIO_RSU
SCENARIO_RSU[0]=0    # Baseline         (no RSU)
SCENARIO_RSU[1]=0    # TTW-S1           (no RSU)
SCENARIO_RSU[2]=64   # TTW-S2           (RSU-based)
SCENARIO_RSU[3]=0    # TTW-S3           (no RSU)
SCENARIO_RSU[4]=64   # TTW-S4           (RSU-based)
SCENARIO_RSU[5]=0    # BSHH-S1          (no RSU)
SCENARIO_RSU[6]=64   # BSHH-S2          (RSU-based)
SCENARIO_RSU[7]=0    # BSHH-S3          (no RSU)
SCENARIO_RSU[8]=64   # BSHH-S4          (RSU-based)
SCENARIO_RSU[9]=0    # ME-S1            (no RSU)
SCENARIO_RSU[10]=64  # ME-S2            (RSU-based)
SCENARIO_RSU[11]=0   # ME-S3            (no RSU)
SCENARIO_RSU[12]=64  # ME-S4            (RSU-based)

declare -A SCENARIO_NAME
SCENARIO_NAME[0]="Baseline"
SCENARIO_NAME[1]="TTW-S1"   SCENARIO_NAME[2]="TTW-S2"
SCENARIO_NAME[3]="TTW-S3"   SCENARIO_NAME[4]="TTW-S4"
SCENARIO_NAME[5]="BSHH-S1"  SCENARIO_NAME[6]="BSHH-S2"
SCENARIO_NAME[7]="BSHH-S3"  SCENARIO_NAME[8]="BSHH-S4"
SCENARIO_NAME[9]="ME-S1"    SCENARIO_NAME[10]="ME-S2"
SCENARIO_NAME[11]="ME-S3"   SCENARIO_NAME[12]="ME-S4"

TOTAL_RUNS=0
FAILED_RUNS=0
START_TIME=$(date +%s)
echo "[timer] Started at $(date '+%Y-%m-%d %H:%M:%S')"

# Scenario 0 is run twice: once without RSUs and once with 64 RSUs
# to give the model baseline examples in both infrastructure configurations.
# We encode the second baseline as scenario "0r" internally.
SCENARIO_RSU["0r"]=64
SCENARIO_NAME["0r"]="Baseline-RSU"

# ── Run all scenarios × seeds ────────────────────────────────────────────────
for SCENARIO in 0 0r 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSU="${SCENARIO_RSU[$SCENARIO]}"
    NAME="${SCENARIO_NAME[$SCENARIO]}"
    # Map "0r" back to scenario ID 0 for the waf command
    SCENARIO_ID="${SCENARIO/0r/0}"

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
                --N_Controllers=4 \
                --attack_scenario=${SCENARIO_ID} \
                --mobility_scenario=${MOBILITY_SCENARIO} \
                --maxspeed=${MAXSPEED} \
                --skip_npfads=1 \
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

                # Save per-scenario copy (safe across sessions — seed in filename)
                cp tgn_events.csv "$OUTDIR/scenario${SCENARIO}_seed${SEED}_events.csv"
                # "0r" saves as scenario0r_seed1_events.csv to distinguish from no-RSU baseline
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
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
HOURS=$((ELAPSED / 3600))
MINUTES=$(( (ELAPSED % 3600) / 60 ))
SECONDS=$((ELAPSED % 60))
echo "  Runs completed : $((TOTAL_RUNS - FAILED_RUNS)) / $TOTAL_RUNS"
echo "  Failed runs    : $FAILED_RUNS"
echo "  all_events.csv : $TOTAL_LINES lines  →  $ALL_EVENTS"
echo "  Total time     : ${HOURS}h ${MINUTES}m ${SECONDS}s"
echo "  Finished at    : $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"

if [ "$TOTAL_LINES" -lt 100 ]; then
    echo "[ERROR] all_events.csv has fewer than 100 lines — insufficient training data."
    echo "        Check that the scenarios ran successfully."
    exit 1
fi

# ── L_link ───────────────────────────────────────────────────────────────────
if [ "$MOBILITY_SCENARIO" -eq 2 ]; then
    L_LINK=9
else
    L_LINK=43
fi

if [ "$SKIP_TRAINING" -eq 1 ]; then
    echo ""
    echo "[info] Training skipped (default). When all seeds are collected, run:"
    echo "         cd \"$SCRIPT_DIR/tgn\""
    echo "         python3 tgn_train.py \"$ALL_EVENTS\" \\"
    echo "             --epochs $EPOCHS --lr 0.001 --dim 32 --layers 2 \\"
    echo "             --l_link $L_LINK --output $OUTPUT"
    exit 0
fi

# ── Train TGN weights ────────────────────────────────────────────────────────
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
    echo "================================================================"
else
    echo "[ERROR] tgn_weights.bin was not created — check tgn_train.py output above."
    exit 1
fi
