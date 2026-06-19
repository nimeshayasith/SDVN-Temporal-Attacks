#!/bin/bash
# run_s2_s6_all_pct.sh
# Runs S2 and S6 × 5 attack percentages × 3 detectors (VeReMi + MBSM + KNN+Bagging)
# Total: 20 NS-3 runs (VeReMi+MBSM) + 10 KNN inference calls.
# KNN is pre-trained ONCE on the official VeReMi dataset before the main loop.
#
# SimTime=30, N_Vehicles=200, N_RSUs=64, N_Controllers=4, maxspeed=60

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks"
EM_DIR="$PROJ_DIR/existing_methods"
VEREMI_DATASET="$EM_DIR/bagging dataset/False_Position_Attack_Detection_Data"
KNN_MODEL="$EM_DIR/knn_veremi_model.pkl"
KNN_SCRIPT="$EM_DIR/temporal_veremi_compare_knn.py"

# Use pyenv python3 which has pandas/sklearn installed
PYTHON3="/home/sdvn_echo_topology/.pyenv/versions/3.10.14/bin/python3"
if [ ! -x "$PYTHON3" ]; then
    PYTHON3="$(which python3)"  # fallback
fi

cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

# ── Remove ALL existing outputs ───────────────────────────────────────────────
echo "Removing existing outputs..."

# NS-3 simulation outputs (written to NS3_DIR)
rm -f comparison_veremi_summary.csv
rm -f comparison_mbsm_summary.csv
rm -f comparison_knn_summary.csv
rm -f comparison_veremi_pairs.csv
rm -f pem_event_log.csv
rm -f pem_run_summary.csv
rm -f routing-animation.xml
rm -f optimization_link_lifetime_data.csv
rm -f channel_delivery_analysis.csv
rm -f ttw_attack_scenario*.txt
rm -f bshh_s*_attack_log.txt
rm -f me_s*_attack_log.txt

# KNN pre-trained model cache
rm -f "$KNN_MODEL"

# Python/chart output files (written to EM_DIR)
rm -f "$EM_DIR/temporal_compare_knn_results.csv"
rm -f "$EM_DIR/temporal_compare_cv_results.csv"
rm -f "$EM_DIR/temporal_compare_permutation_importance.csv"
rm -f "$EM_DIR/temporal_compare_grid_search.csv"

# Chart and results directories
rm -rf "$EM_DIR/results/veremi_raw"
rm -rf "$EM_DIR/results/mbsm_raw"
rm -rf "$EM_DIR/results/knn_raw"
rm -rf "$EM_DIR/results/charts"

echo "Done. All old outputs removed."
echo ""

SCENARIOS=(2 6)
ATK_PCTS=(0 25 50 75 100)
N_VEH=200
N_RSU=64
N_CTRL=4
SIM_TIME=30
MAXSPEED=60
MOB=0

# ── Pre-train KNN on VeReMi dataset (once, saved to pickle) ──────────────────
echo "══════════════════════════════════════════════════════════"
echo " Pre-training KNN+Bagging on VeReMi official dataset..."
echo "══════════════════════════════════════════════════════════"
if [ -d "$VEREMI_DATASET" ]; then
    cd "$EM_DIR" || { echo "ERROR: cannot cd to $EM_DIR"; exit 1; }
    $PYTHON3 temporal_veremi_compare_knn.py \
        --dataset "$VEREMI_DATASET" \
        --save-model "$KNN_MODEL" \
        --holdout-only && echo "KNN pre-training done." || { echo "KNN pre-training failed."; exit 1; }
    cd "$NS3_DIR" || exit 1
else
    echo "ERROR: VeReMi dataset not found at: $VEREMI_DATASET"
    exit 1
fi
echo ""

# ── Main simulation loop ─────────────────────────────────────────────────────
TOTAL_NS3=$(( ${#SCENARIOS[@]} * 2 * ${#ATK_PCTS[@]} ))
RUN=0
OVERALL_START=$(date +%s)

for SC in "${SCENARIOS[@]}"; do
    [ "$SC" -eq 2 ] && SC_NAME="TTW-S2" || SC_NAME="BSHH-S6"

    for ATK_PCT in "${ATK_PCTS[@]}"; do

        # ── VeReMi detector (also generates comparison_veremi_pairs.csv) ─────
        RUN=$(( RUN + 1 ))
        echo "══════════════════════════════════════════════════════════"
        echo " Run $RUN / $TOTAL_NS3  |  VeReMi  |  $SC_NAME  |  ATK=${ATK_PCT}%"
        echo "══════════════════════════════════════════════════════════"
        T_START=$(date +%s)

        ./waf --run "scratch/routing \
            --simTime=$SIM_TIME \
            --N_Vehicles=$N_VEH \
            --N_RSUs=$N_RSU \
            --N_Controllers=$N_CTRL \
            --attack_scenario=$SC \
            --attack_percentage=$ATK_PCT \
            --maxspeed=$MAXSPEED \
            --mobility_scenario=$MOB \
            --comparison_detector=1" 2>&1 \
            | grep -E "^\[CD\]|TP=|MCC=|PDR|detector=|scenario=|Output:|error:|Error"

        T_END=$(date +%s)
        echo "  → VeReMi done in $(( T_END - T_START ))s"

        # ── KNN inference on this run's pairs CSV ────────────────────────────
        echo "  → Running KNN+Bagging inference..."
        cd "$EM_DIR" || { echo "ERROR: cannot cd to $EM_DIR"; exit 1; }
        $PYTHON3 temporal_veremi_compare_knn.py \
            --load-model "$KNN_MODEL" \
            --test-csv "$NS3_DIR/comparison_veremi_pairs.csv" \
            --scenario "$SC" \
            --attack-pct "$ATK_PCT" \
            --output-summary "$NS3_DIR/comparison_knn_summary.csv" \
            2>&1 | grep -E "CD-KNN|Appended|ERROR"
        cd "$NS3_DIR" || exit 1
        echo ""

        # ── MBSM detector ────────────────────────────────────────────────────
        RUN=$(( RUN + 1 ))
        echo "══════════════════════════════════════════════════════════"
        echo " Run $RUN / $TOTAL_NS3  |  MBSM  |  $SC_NAME  |  ATK=${ATK_PCT}%"
        echo "══════════════════════════════════════════════════════════"
        T_START=$(date +%s)

        ./waf --run "scratch/routing \
            --simTime=$SIM_TIME \
            --N_Vehicles=$N_VEH \
            --N_RSUs=$N_RSU \
            --N_Controllers=$N_CTRL \
            --attack_scenario=$SC \
            --attack_percentage=$ATK_PCT \
            --maxspeed=$MAXSPEED \
            --mobility_scenario=$MOB \
            --comparison_detector=2" 2>&1 \
            | grep -E "^\[CD\]|TP=|MCC=|PDR|detector=|scenario=|Output:|error:|Error"

        T_END=$(date +%s)
        echo "  → MBSM done in $(( T_END - T_START ))s"
        echo ""

    done
done

OVERALL_END=$(date +%s)
TOTAL_TIME=$(( OVERALL_END - OVERALL_START ))
echo "══════════════════════════════════════════════════════════"
echo " ALL $TOTAL_NS3 NS-3 RUNS COMPLETE  (total: ${TOTAL_TIME}s)"
echo "══════════════════════════════════════════════════════════"
echo ""

# ── Print summaries ──────────────────────────────────────────────────────────
echo "=== VeReMi summary ==="
cat comparison_veremi_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== MBSM summary ==="
cat comparison_mbsm_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== KNN+Bagging summary ==="
cat comparison_knn_summary.csv 2>/dev/null || echo "(not found)"
echo ""

# ── Copy CSV files to results dirs for chart scripts ────────────────────────
VEREMI_RAW="$EM_DIR/results/veremi_raw"
MBSM_RAW="$EM_DIR/results/mbsm_raw"
KNN_RAW="$EM_DIR/results/knn_raw"
mkdir -p "$VEREMI_RAW" "$MBSM_RAW" "$KNN_RAW"

cp comparison_veremi_summary.csv \
    "$VEREMI_RAW/temporal_veremi_compare_pem_summary.csv" 2>/dev/null && \
    echo "Copied VeReMi CSV → veremi_raw/"

cp comparison_mbsm_summary.csv \
    "$MBSM_RAW/temporal_mbsm_compare_summary.csv" 2>/dev/null && \
    echo "Copied MBSM CSV → mbsm_raw/"

cp comparison_knn_summary.csv \
    "$KNN_RAW/temporal_compare_knn_summary.csv" 2>/dev/null && \
    echo "Copied KNN CSV → knn_raw/"

echo ""

# ── Generate charts (all 3 methods) ──────────────────────────────────────────
echo "══════════════════════════════════════════════════════════"
echo " Generating charts (VeReMi + MBSM + KNN+Bagging)..."
echo "══════════════════════════════════════════════════════════"
cd "$EM_DIR" || { echo "ERROR: cannot cd to $EM_DIR"; exit 1; }
$PYTHON3 generate_charts.py && echo "Charts done." || echo "Chart generation failed."
echo ""

echo "══════════════════════════════════════════════════════════"
echo " ALL STEPS COMPLETE"
echo "══════════════════════════════════════════════════════════"
