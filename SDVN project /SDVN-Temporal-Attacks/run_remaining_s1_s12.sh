#!/bin/bash
# run_remaining_s1_s12.sh
# Runs S1, S3, S4, S5, S7, S8, S9, S10, S11, S12
# (S2 and S6 already done — existing CSV results are preserved and appended to)
#
# Per scenario: VeReMi detector (+ KNN inference on pairs) + MBSM detector
# Total: 10 scenarios × 5 attack% × 2 detectors = 100 NS-3 runs + 50 KNN calls
#
# After all runs: copies all 3 CSVs and regenerates charts for S1–S12

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks"
EM_DIR="$PROJ_DIR/existing_methods"
VEREMI_DATASET="$EM_DIR/bagging dataset/False_Position_Attack_Detection_Data"
KNN_MODEL="$EM_DIR/knn_veremi_model.pkl"

PYTHON3="/home/sdvn_echo_topology/.pyenv/versions/3.10.14/bin/python3"
[ ! -x "$PYTHON3" ] && PYTHON3="$(which python3)"

cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

# ── Per-scenario config ───────────────────────────────────────────────────────
# RSU count: with-RSU variants (S4, S8, S10, S12) get 64; others get 0
get_n_rsu() {
    case $1 in
        4|8|10|12) echo 64 ;;
        *)         echo 0  ;;
    esac
}

get_sc_name() {
    case $1 in
        1)  echo "TTW-S1  (Mal.Vehicle, No RSU)"      ;;
        3)  echo "TTW-S3  (Mal.Controller, No RSU)"   ;;
        4)  echo "TTW-S4  (Mal.Controller, RSU)"      ;;
        5)  echo "BSHH-S5 (Mal.Vehicle, No RSU)"      ;;
        7)  echo "BSHH-S7 (Mal.Controller, No RSU)"   ;;
        8)  echo "BSHH-S8 (Mal.Controller, RSU)"      ;;
        9)  echo "ME-S9   (Mal.Vehicles, No RSU)"     ;;
        10) echo "ME-S10  (Mal.RSU)"                  ;;
        11) echo "ME-S11  (Mal.Controller, No RSU)"   ;;
        12) echo "ME-S12  (Mal.Controller, RSU)"      ;;
        *)  echo "Scenario $1"                        ;;
    esac
}

# Remaining scenarios only (S2 and S6 already complete)
SCENARIOS=(1 3 4 5 7 8 9 10 11 12)
ATK_PCTS=(0 25 50 75 100)
N_VEH=200
N_CTRL=4
SIM_TIME=30
MAXSPEED=60
MOB=0

echo "══════════════════════════════════════════════════════════"
echo " Existing results preserved: S2 and S6 (not cleared)"
echo " Running: S1, S3, S4, S5, S7, S8, S9, S10, S11, S12"
echo "══════════════════════════════════════════════════════════"
echo ""

# ── Remove any existing rows for S1,S3,S4,S5,S7,S8,S9-S12 from all CSVs ─────
# Keeps only header + S2 + S6 rows. Safe to run even if those rows don't exist.
echo "Checking and cleaning any existing S1/S3/S4/S5/S7-S12 rows from CSVs..."
for CSV in comparison_veremi_summary.csv comparison_mbsm_summary.csv comparison_knn_summary.csv; do
    if [ -f "$CSV" ]; then
        # Keep header (line 1) + any line whose first field is 2 or 6
        awk -F',' 'NR==1 || $1=="2" || $1=="6"' "$CSV" > "${CSV}.tmp" && mv "${CSV}.tmp" "$CSV"
        echo "  $CSV → $(( $(wc -l < "$CSV") - 1 )) data rows kept (S2+S6 only)"
    else
        echo "  $CSV not found — will be created fresh"
    fi
done
echo ""

# ── Check / re-train KNN model ────────────────────────────────────────────────
if [ -f "$KNN_MODEL" ]; then
    echo "KNN model found ($(du -sh "$KNN_MODEL" | cut -f1)) — skipping re-train."
else
    echo "KNN model not found — pre-training on VeReMi dataset..."
    cd "$EM_DIR" || exit 1
    $PYTHON3 temporal_veremi_compare_knn.py \
        --dataset "$VEREMI_DATASET" \
        --save-model "$KNN_MODEL" \
        --holdout-only || { echo "ERROR: KNN pre-training failed."; exit 1; }
    cd "$NS3_DIR" || exit 1
    echo "KNN pre-training done."
fi
echo ""

# ── Main loop ─────────────────────────────────────────────────────────────────
TOTAL_NS3=$(( ${#SCENARIOS[@]} * 2 * ${#ATK_PCTS[@]} ))
RUN=0
OVERALL_START=$(date +%s)

for SC in "${SCENARIOS[@]}"; do
    N_RSU=$(get_n_rsu $SC)
    SC_NAME=$(get_sc_name $SC)

    for ATK_PCT in "${ATK_PCTS[@]}"; do

        # ── VeReMi detector ───────────────────────────────────────────────────
        RUN=$(( RUN + 1 ))
        echo "══════════════════════════════════════════════════════════"
        echo " Run $RUN / $TOTAL_NS3  |  VeReMi  |  $SC_NAME  |  ATK=${ATK_PCT}%  |  RSUs=$N_RSU"
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
            | grep -E "^\[CD\]|TP=|MCC=|detector=|scenario=|error:|Error"

        echo "  → VeReMi done in $(( $(date +%s) - T_START ))s"

        # ── KNN inference on this run's pairs CSV ─────────────────────────────
        echo "  → KNN+Bagging inference..."
        cd "$EM_DIR" || exit 1
        $PYTHON3 temporal_veremi_compare_knn.py \
            --load-model "$KNN_MODEL" \
            --test-csv "$NS3_DIR/comparison_veremi_pairs.csv" \
            --scenario "$SC" \
            --attack-pct "$ATK_PCT" \
            --output-summary "$NS3_DIR/comparison_knn_summary.csv" \
            2>&1 | grep -E "CD-KNN|Appended|ERROR"
        cd "$NS3_DIR" || exit 1
        echo ""

        # ── MBSM detector ─────────────────────────────────────────────────────
        RUN=$(( RUN + 1 ))
        echo "══════════════════════════════════════════════════════════"
        echo " Run $RUN / $TOTAL_NS3  |  MBSM    |  $SC_NAME  |  ATK=${ATK_PCT}%  |  RSUs=$N_RSU"
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
            | grep -E "^\[CD\]|TP=|MCC=|detector=|scenario=|error:|Error"

        echo "  → MBSM done in $(( $(date +%s) - T_START ))s"
        echo ""

    done
done

OVERALL_END=$(date +%s)
echo "══════════════════════════════════════════════════════════"
echo " ALL $TOTAL_NS3 NS-3 RUNS COMPLETE  ($(( OVERALL_END - OVERALL_START ))s)"
echo "══════════════════════════════════════════════════════════"
echo ""

# ── Print summaries ───────────────────────────────────────────────────────────
echo "=== VeReMi summary (all scenarios) ==="
cat comparison_veremi_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== MBSM summary (all scenarios) ==="
cat comparison_mbsm_summary.csv 2>/dev/null || echo "(not found)"
echo ""
echo "=== KNN+Bagging summary (all scenarios) ==="
cat comparison_knn_summary.csv 2>/dev/null || echo "(not found)"
echo ""

# ── Copy complete CSVs to results dirs ───────────────────────────────────────
VEREMI_RAW="$EM_DIR/results/veremi_raw"
MBSM_RAW="$EM_DIR/results/mbsm_raw"
KNN_RAW="$EM_DIR/results/knn_raw"
mkdir -p "$VEREMI_RAW" "$MBSM_RAW" "$KNN_RAW"

cp comparison_veremi_summary.csv \
    "$VEREMI_RAW/temporal_veremi_compare_pem_summary.csv" && echo "Copied VeReMi CSV"
cp comparison_mbsm_summary.csv \
    "$MBSM_RAW/temporal_mbsm_compare_summary.csv" && echo "Copied MBSM CSV"
cp comparison_knn_summary.csv \
    "$KNN_RAW/temporal_compare_knn_summary.csv" && echo "Copied KNN CSV"
echo ""

# ── Regenerate all charts (S1–S12) ───────────────────────────────────────────
echo "══════════════════════════════════════════════════════════"
echo " Regenerating charts for all S1–S12 scenarios..."
echo "══════════════════════════════════════════════════════════"
cd "$EM_DIR" || exit 1
rm -rf results/charts
$PYTHON3 generate_charts.py && echo "Charts done." || echo "Chart generation failed."

echo ""
echo "══════════════════════════════════════════════════════════"
echo " ALL STEPS COMPLETE"
echo "══════════════════════════════════════════════════════════"
