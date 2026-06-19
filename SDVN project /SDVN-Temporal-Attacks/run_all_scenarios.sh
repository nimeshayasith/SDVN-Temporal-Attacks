#!/bin/bash
# run_all_scenarios.sh
# Runs ALL 12 attack scenarios × 5 attack percentages × 3 detectors
# (VeReMi + MBSM + KNN+Bagging) from scratch.
#
# Config:
#   Scenarios    : S1–S12 (all TTW, BSHH, ME variants)
#   Attack %     : 0, 25, 50, 75, 100
#   N_Vehicles   : 200
#   N_RSUs       : 64 for RSU-present scenarios (S2,S4,S6,S8,S10,S12); 0 otherwise
#   N_Controllers: 4
#   mobility     : 0 (urban Colombo OSM)
#   maxspeed     : 60 km/h
#   SimTime      : 30 s
#
# Total NS-3 runs : 12 × 5 × 2 = 120
# KNN calls       : 12 × 5    = 60
# Estimated time  : ~16–20 hours

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks"
EM_DIR="$PROJ_DIR/existing_methods"
VEREMI_DATASET="$EM_DIR/bagging dataset/False_Position_Attack_Detection_Data"
KNN_MODEL="$EM_DIR/knn_veremi_model.pkl"

PYTHON3="/home/sdvn_echo_topology/.pyenv/versions/3.10.14/bin/python3"
[ ! -x "$PYTHON3" ] && PYTHON3="$(which python3)"

cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

# ── RSU count per scenario ────────────────────────────────────────────────────
# S2,S4,S6,S8,S10,S12 have RSU infrastructure; all others have none.
get_n_rsu() {
    case $1 in
        2|4|6|8|10|12) echo 64 ;;
        *)              echo 0  ;;
    esac
}

get_sc_name() {
    case $1 in
        1)  echo "TTW-S1  (Mal.Vehicle,     No RSU)" ;;
        2)  echo "TTW-S2  (Mal.RSU)"                 ;;
        3)  echo "TTW-S3  (Mal.Controller,  No RSU)" ;;
        4)  echo "TTW-S4  (Mal.Controller,  RSU)"    ;;
        5)  echo "BSHH-S5 (Mal.Vehicle,     No RSU)" ;;
        6)  echo "BSHH-S6 (Mal.RSU)"                 ;;
        7)  echo "BSHH-S7 (Mal.Controller,  No RSU)" ;;
        8)  echo "BSHH-S8 (Mal.Controller,  RSU)"    ;;
        9)  echo "ME-S9   (Mal.Vehicles,    No RSU)" ;;
        10) echo "ME-S10  (Mal.RSU)"                 ;;
        11) echo "ME-S11  (Mal.Controller,  No RSU)" ;;
        12) echo "ME-S12  (Mal.Controller,  RSU)"    ;;
        *)  echo "Scenario $1"                       ;;
    esac
}

SCENARIOS=(1 2 3 4 5 6 7 8 9 10 11 12)
ATK_PCTS=(0 25 50 75 100)
N_VEH=200
N_CTRL=4
SIM_TIME=30
MAXSPEED=60
MOB=0

# ── Remove ALL existing outputs ───────────────────────────────────────────────
echo "════════════════════════════════════════════════════"
echo " Removing existing outputs..."
echo "════════════════════════════════════════════════════"

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

rm -f "$EM_DIR/temporal_compare_knn_results.csv"
rm -f "$EM_DIR/temporal_compare_cv_results.csv"
rm -f "$EM_DIR/temporal_compare_permutation_importance.csv"
rm -f "$EM_DIR/temporal_compare_grid_search.csv"

rm -rf "$EM_DIR/results/veremi_raw"
rm -rf "$EM_DIR/results/mbsm_raw"
rm -rf "$EM_DIR/results/knn_raw"
rm -rf "$EM_DIR/results/charts"

echo " Done. All old outputs removed."
echo ""

# ── Pre-train KNN on VeReMi dataset (skip if model already exists) ───────────
if [ -f "$KNN_MODEL" ]; then
    echo "KNN model already exists ($(du -sh "$KNN_MODEL" | cut -f1)) — skipping training."
else
    echo "════════════════════════════════════════════════════"
    echo " Pre-training KNN+Bagging on VeReMi dataset..."
    echo "════════════════════════════════════════════════════"
    if [ ! -d "$VEREMI_DATASET" ]; then
        echo "ERROR: VeReMi dataset not found at: $VEREMI_DATASET"
        exit 1
    fi
    cd "$EM_DIR" || exit 1
    $PYTHON3 temporal_veremi_compare_knn.py \
        --dataset "$VEREMI_DATASET" \
        --save-model "$KNN_MODEL" \
        --holdout-only || { echo "ERROR: KNN pre-training failed."; exit 1; }
    cd "$NS3_DIR" || exit 1
    echo " KNN pre-training done."
fi
echo ""

# ── Main loop ─────────────────────────────────────────────────────────────────
TOTAL_NS3=$(( ${#SCENARIOS[@]} * 2 * ${#ATK_PCTS[@]} ))
RUN=0
OVERALL_START=$(date +%s)

for SC in "${SCENARIOS[@]}"; do
    N_RSU=$(get_n_rsu $SC)
    SC_NAME=$(get_sc_name $SC)

    echo ""
    echo "════════════════════════════════════════════════════"
    echo " SCENARIO $SC — $SC_NAME   RSUs=$N_RSU"
    echo "════════════════════════════════════════════════════"

    for ATK_PCT in "${ATK_PCTS[@]}"; do

        # ── VeReMi detector ───────────────────────────────────────────────────
        RUN=$(( RUN + 1 ))
        ELAPSED=$(( $(date +%s) - OVERALL_START ))
        echo "──────────────────────────────────────────────────"
        echo " Run $RUN/$TOTAL_NS3  |  VeReMi  |  $SC_NAME  |  ATK=${ATK_PCT}%  |  elapsed=${ELAPSED}s"
        echo "──────────────────────────────────────────────────"
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
            | grep -E "^\[CD\]|TP=|MCC=|detector=|scenario=|declare_att|error:|Error"

        echo "  → VeReMi done in $(( $(date +%s) - T_START ))s"

        # ── KNN+Bagging inference on this run's pairs CSV ─────────────────────
        echo "  → KNN+Bagging inference..."
        cd "$EM_DIR" || exit 1
        $PYTHON3 temporal_veremi_compare_knn.py \
            --load-model "$KNN_MODEL" \
            --test-csv "$NS3_DIR/comparison_veremi_pairs.csv" \
            --scenario "$SC" \
            --attack-pct "$ATK_PCT" \
            --output-summary "$NS3_DIR/comparison_knn_summary.csv" \
            2>&1 | grep -E "CD-KNN|Appended|ERROR|empty"
        cd "$NS3_DIR" || exit 1
        echo ""

        # ── MBSM detector ─────────────────────────────────────────────────────
        RUN=$(( RUN + 1 ))
        ELAPSED=$(( $(date +%s) - OVERALL_START ))
        echo "──────────────────────────────────────────────────"
        echo " Run $RUN/$TOTAL_NS3  |  MBSM    |  $SC_NAME  |  ATK=${ATK_PCT}%  |  elapsed=${ELAPSED}s"
        echo "──────────────────────────────────────────────────"
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
            | grep -E "^\[CD\]|TP=|MCC=|detector=|scenario=|declare_att|error:|Error"

        echo "  → MBSM done in $(( $(date +%s) - T_START ))s"
        echo ""

    done
done

OVERALL_END=$(date +%s)
echo ""
echo "════════════════════════════════════════════════════"
echo " ALL $TOTAL_NS3 NS-3 RUNS COMPLETE"
echo " Total time: $(( (OVERALL_END - OVERALL_START) / 3600 ))h $(( ((OVERALL_END - OVERALL_START) % 3600) / 60 ))m"
echo "════════════════════════════════════════════════════"
echo ""

# ── Print summaries ───────────────────────────────────────────────────────────
echo "=== VeReMi summary ==="
cat comparison_veremi_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== MBSM summary ==="
cat comparison_mbsm_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== KNN+Bagging summary ==="
cat comparison_knn_summary.csv 2>/dev/null || echo "(not found)"
echo ""

# ── Copy CSVs to results dirs ─────────────────────────────────────────────────
VEREMI_RAW="$EM_DIR/results/veremi_raw"
MBSM_RAW="$EM_DIR/results/mbsm_raw"
KNN_RAW="$EM_DIR/results/knn_raw"
mkdir -p "$VEREMI_RAW" "$MBSM_RAW" "$KNN_RAW"

cp comparison_veremi_summary.csv "$VEREMI_RAW/temporal_veremi_compare_pem_summary.csv" \
    && echo "Copied VeReMi CSV"
cp comparison_mbsm_summary.csv   "$MBSM_RAW/temporal_mbsm_compare_summary.csv" \
    && echo "Copied MBSM CSV"
cp comparison_knn_summary.csv    "$KNN_RAW/temporal_compare_knn_summary.csv" \
    && echo "Copied KNN CSV"
echo ""

# ── Generate charts ───────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════"
echo " Generating charts (all 12 scenarios, 3 methods)..."
echo "════════════════════════════════════════════════════"
cd "$EM_DIR" || exit 1
rm -rf results/charts
$PYTHON3 generate_charts.py && echo " Charts done." || echo " Chart generation failed."

echo ""
echo "════════════════════════════════════════════════════"
echo " ALL STEPS COMPLETE"
echo " Results: $EM_DIR/results/"
echo "════════════════════════════════════════════════════"
