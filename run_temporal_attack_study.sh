#!/bin/bash
# ============================================================
# run_temporal_attack_study.sh
# Runs ALL 12 attack scenarios × 11 attack percentages (0–100%)
# for BOTH detectors:
#   1. MBSM_Detect (Trabelsi 2022)  — C++ only
#   2. VeReMi KNN+Bagging (Mekonen 2025) — C++ + Python per scenario
#
# Total C++ runs : 264  (12 × 11 × 2 detectors)
# Total Python runs: 12  (1 per scenario, after all percentages done)
#
# Usage:
#   bash run_temporal_attack_study.sh [ns3_dir]
#   default ns3_dir: ~/ns-3.35
#
# Setup (run once before this script):
#   cp temporal_mbsm_compare.cc      ~/ns-3.35/scratch/
#   cp temporal_veremi_compare.cc    ~/ns-3.35/scratch/
#   cp temporal_veremi_compare_knn.py ~/ns-3.35/
#   pip install scikit-learn pandas numpy
# ============================================================

set -uo pipefail

NS3_DIR="${1:-$HOME/ns-3.35}"
SCRATCH_DIR="$NS3_DIR/scratch"
PY_SCRIPT="$NS3_DIR/temporal_veremi_compare_knn.py"
RESULTS_BASE="$HOME/temporal_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$RESULTS_BASE/$TIMESTAMP"

SIM_TIME=250          # covers 10 malicious × 20s stagger + buffer
PERCENTAGES=(0 10 20 30 40 50 60 70 80 90 100)
DETECTORS=(temporal_mbsm_compare temporal_veremi_compare)

# ── Scenario parameters ─────────────────────────────────────────
# S1/S5/S9   : malicious vehicles, no RSU
# S2/S6/S10  : malicious RSU, 10 RSUs
# S3/S7/S11  : malicious controller, no RSU
# S4/S8/S12  : malicious controller, with RSU
declare -A SC_NV SC_NR SC_NC
for SC in 1 5 9;   do SC_NV[$SC]=10; SC_NR[$SC]=0;  SC_NC[$SC]=1;  done  # malicious vehicles
for SC in 2 6 10;  do SC_NV[$SC]=10; SC_NR[$SC]=10; SC_NC[$SC]=1;  done  # malicious RSUs
for SC in 3 7 11;  do SC_NV[$SC]=10; SC_NR[$SC]=0;  SC_NC[$SC]=10; done  # malicious controllers, no RSU
for SC in 4 8 12;  do SC_NV[$SC]=10; SC_NR[$SC]=10; SC_NC[$SC]=10; done  # malicious controllers, with RSU

# ── Sanity checks ───────────────────────────────────────────────
echo ""
echo "[$(date +%T)] Pre-flight checks..."

if [ ! -d "$NS3_DIR" ]; then
    echo "[ERROR] NS-3 directory not found: $NS3_DIR"
    echo "  Usage: bash $0 /path/to/ns-3.35"
    exit 1
fi

for DET in "${DETECTORS[@]}"; do
    if [ ! -f "$SCRATCH_DIR/${DET}.cc" ]; then
        echo "[ERROR] Missing: $SCRATCH_DIR/${DET}.cc"
        echo "  cp ${DET}.cc $SCRATCH_DIR/"
        exit 1
    fi
done

if [ ! -f "$PY_SCRIPT" ]; then
    echo "[ERROR] Missing: $PY_SCRIPT"
    echo "  cp temporal_veremi_compare_knn.py $NS3_DIR/"
    exit 1
fi

# Check Python + scikit-learn
if ! python3 -c "import sklearn, pandas, numpy" 2>/dev/null; then
    echo "[ERROR] Python dependencies missing."
    echo "  pip install scikit-learn pandas numpy"
    exit 1
fi
echo "[$(date +%T)] Python OK (scikit-learn $(python3 -c 'import sklearn; print(sklearn.__version__)'))"

# ── Build ───────────────────────────────────────────────────────
echo "[$(date +%T)] Building NS-3 programs..."
cd "$NS3_DIR"
if ! ./waf build 2>&1 | tail -3; then
    echo "[ERROR] Build failed."
    exit 1
fi
echo "[$(date +%T)] Build OK."

# ── Create results tree ─────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
echo "[$(date +%T)] Results → $RESULTS_DIR"

# ── Delete old accumulated CSVs ─────────────────────────────────
rm -f temporal_mbsm_compare_summary.csv
rm -f temporal_veremi_compare_pem_summary.csv
rm -f temporal_compare_knn_results.csv
rm -f temporal_compare_cv_results.csv

# ── Master KNN CSVs (accumulate all 12 scenarios) ───────────────
MASTER_KNN_HOLDOUT="$RESULTS_DIR/knn_holdout_all_scenarios.csv"
MASTER_KNN_CV="$RESULTS_DIR/knn_cv_all_scenarios.csv"
KNN_HEADER_WRITTEN=false

# ── Progress counters ────────────────────────────────────────────
TOTAL_CPP=$(( ${#DETECTORS[@]} * 12 * ${#PERCENTAGES[@]} ))
TOTAL_PY=12
CPP_RUN=0
CPP_FAIL=0
PY_RUN=0
PY_FAIL=0
START_TIME=$(date +%s)

elapsed_str() {
    local s=$(( $(date +%s) - START_TIME ))
    printf "%dm%02ds" "$(( s/60 ))" "$(( s%60 ))"
}

# ═══════════════════════════════════════════════════════════════
# ── MBSM detector (C++ only, no Python) ─────────────────────────
# ═══════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  DETECTOR 1/2 : temporal_mbsm_compare (MBSM_Detect)"
echo "  Trabelsi et al., Electronics 2022"
echo "════════════════════════════════════════════════════════════"

MBSM_DIR="$RESULTS_DIR/temporal_mbsm_compare"
mkdir -p "$MBSM_DIR"

for SC in {1..12}; do
    NV=${SC_NV[$SC]}; NR=${SC_NR[$SC]}; NC=${SC_NC[$SC]}
    SC_DIR="$MBSM_DIR/scenario_${SC}"
    mkdir -p "$SC_DIR"

    echo ""
    echo "  ── Scenario $SC | N_Vehicles=$NV  N_RSUs=$NR ──"

    for PCT in "${PERCENTAGES[@]}"; do
        CPP_RUN=$(( CPP_RUN + 1 ))
        printf "    [CPP %3d/%d | %s] SC=%-2d PCT=%-3d%%  ... " \
            "$CPP_RUN" "$TOTAL_CPP" "$(elapsed_str)" "$SC" "$PCT"

        rm -f temporal_mbsm_compare_events.csv

        ARGS="scratch/temporal_mbsm_compare \
            --simTime=$SIM_TIME \
            --N_Vehicles=$NV \
            --N_RSUs=$NR \
            --N_Controllers=$NC \
            --attack_scenario=$SC \
            --attack_percentage=$PCT"

        if ./waf --run "$ARGS" > "$SC_DIR/stdout_pct${PCT}.txt" 2>&1; then
            echo "OK"
        else
            echo "FAILED"
            CPP_FAIL=$(( CPP_FAIL + 1 ))
            continue
        fi

        cp "temporal_mbsm_compare_attack${SC}.txt" \
           "$SC_DIR/attack_log_pct${PCT}.txt" 2>/dev/null || true
        [ -f "temporal_mbsm_compare_events.csv" ] && \
            cp "temporal_mbsm_compare_events.csv" \
               "$SC_DIR/events_pct${PCT}.csv"
    done
    echo "    Scenario $SC complete."
done

# Save MBSM summary (all 132 rows)
[ -f "temporal_mbsm_compare_summary.csv" ] && \
    cp "temporal_mbsm_compare_summary.csv" \
       "$MBSM_DIR/mbsm_summary_all.csv"
MBSM_ROWS=$(wc -l < "$MBSM_DIR/mbsm_summary_all.csv" 2>/dev/null || echo "?")
echo ""
echo "  ✓ MBSM summary: $MBSM_DIR/mbsm_summary_all.csv  ($MBSM_ROWS rows)"

# ═══════════════════════════════════════════════════════════════
# ── VeReMi detector (C++ + Python per scenario) ────────────────
# ═══════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  DETECTOR 2/2 : temporal_veremi_compare (VeReMi KNN+Bagging)"
echo "  Mekonen et al., PLOS ONE 2025"
echo "  Python KNN runs: 1 per scenario (after all percentages done)"
echo "════════════════════════════════════════════════════════════"

VREM_DIR="$RESULTS_DIR/temporal_veremi_compare"
mkdir -p "$VREM_DIR"

for SC in {1..12}; do
    NV=${SC_NV[$SC]}; NR=${SC_NR[$SC]}; NC=${SC_NC[$SC]}
    SC_DIR="$VREM_DIR/scenario_${SC}"
    mkdir -p "$SC_DIR"

    echo ""
    echo "  ── Scenario $SC | N_Vehicles=$NV  N_RSUs=$NR ──"

    # ── C++ runs for all 11 percentages ──────────────────────────
    for PCT in "${PERCENTAGES[@]}"; do
        CPP_RUN=$(( CPP_RUN + 1 ))
        printf "    [CPP %3d/%d | %s] SC=%-2d PCT=%-3d%%  ... " \
            "$CPP_RUN" "$TOTAL_CPP" "$(elapsed_str)" "$SC" "$PCT"

        # Delete pairs CSV before each run → each archived copy is clean (single-pct data)
        rm -f temporal_veremi_compare_pairs.csv

        ARGS="scratch/temporal_veremi_compare \
            --simTime=$SIM_TIME \
            --N_Vehicles=$NV \
            --N_RSUs=$NR \
            --N_Controllers=$NC \
            --attack_scenario=$SC \
            --attack_percentage=$PCT"

        if ./waf --run "$ARGS" > "$SC_DIR/stdout_pct${PCT}.txt" 2>&1; then
            echo "OK"
        else
            echo "FAILED"
            CPP_FAIL=$(( CPP_FAIL + 1 ))
            continue
        fi

        cp "temporal_veremi_compare_attack${SC}.txt" \
           "$SC_DIR/attack_log_pct${PCT}.txt" 2>/dev/null || true
        [ -f "temporal_veremi_compare_pairs.csv" ] && \
            cp "temporal_veremi_compare_pairs.csv" \
               "$SC_DIR/pairs_pct${PCT}.csv"
    done

    # ── Combine all per-pct pairs CSVs into one file for Python ──
    COMBINED_PAIRS="$SC_DIR/pairs_combined_sc${SC}.csv"
    HEADER_WRITTEN=false
    echo "    Combining pairs CSVs for Python..."
    for PCT in "${PERCENTAGES[@]}"; do
        PAIR_FILE="$SC_DIR/pairs_pct${PCT}.csv"
        if [ ! -f "$PAIR_FILE" ]; then
            continue
        fi
        if [ "$HEADER_WRITTEN" = false ]; then
            head -1 "$PAIR_FILE" > "$COMBINED_PAIRS"
            HEADER_WRITTEN=true
        fi
        tail -n +2 "$PAIR_FILE" >> "$COMBINED_PAIRS" 2>/dev/null || true
    done

    PAIR_COUNT=$(wc -l < "$COMBINED_PAIRS" 2>/dev/null || echo 0)
    if [ "$PAIR_COUNT" -lt 2 ]; then
        echo "    [SKIP] Not enough pairs data for Python (scenario $SC)"
        continue
    fi

    # ── Python KNN+Bagging run (once per scenario) ────────────────
    PY_RUN=$(( PY_RUN + 1 ))
    printf "    [PY  %2d/%d | %s] SC=%-2d  Python KNN+Bagging ... " \
        "$PY_RUN" "$TOTAL_PY" "$(elapsed_str)" "$SC"

    PY_STDOUT="$SC_DIR/python_knn_sc${SC}.txt"
    rm -f temporal_compare_knn_results.csv temporal_compare_cv_results.csv

    if python3 "$PY_SCRIPT" "$COMBINED_PAIRS" \
        > "$PY_STDOUT" 2>&1; then
        echo "OK"
    else
        echo "FAILED  (see $PY_STDOUT)"
        PY_FAIL=$(( PY_FAIL + 1 ))
        continue
    fi

    # Archive Python output CSVs to scenario dir
    [ -f "temporal_compare_knn_results.csv" ] && \
        cp "temporal_compare_knn_results.csv" \
           "$SC_DIR/knn_holdout_sc${SC}.csv"
    [ -f "temporal_compare_cv_results.csv" ] && \
        cp "temporal_compare_cv_results.csv" \
           "$SC_DIR/knn_cv_sc${SC}.csv"

    # Append to master KNN CSVs (header only on first scenario)
    if [ "$KNN_HEADER_WRITTEN" = false ]; then
        [ -f "temporal_compare_knn_results.csv" ] && \
            head -1 "temporal_compare_knn_results.csv" > "$MASTER_KNN_HOLDOUT"
        [ -f "temporal_compare_cv_results.csv" ] && \
            head -1 "temporal_compare_cv_results.csv" > "$MASTER_KNN_CV"
        KNN_HEADER_WRITTEN=true
    fi
    [ -f "temporal_compare_knn_results.csv" ] && \
        tail -n +2 "temporal_compare_knn_results.csv" >> "$MASTER_KNN_HOLDOUT"
    [ -f "temporal_compare_cv_results.csv" ] && \
        tail -n +2 "temporal_compare_cv_results.csv" >> "$MASTER_KNN_CV"

    echo "    Scenario $SC KNN complete."
done

# Save VeReMi rule-based summary (all 132 rows)
[ -f "temporal_veremi_compare_pem_summary.csv" ] && \
    cp "temporal_veremi_compare_pem_summary.csv" \
       "$VREM_DIR/veremi_summary_all.csv"
VREM_ROWS=$(wc -l < "$VREM_DIR/veremi_summary_all.csv" 2>/dev/null || echo "?")
echo ""
echo "  ✓ VeReMi rule-based summary: $VREM_DIR/veremi_summary_all.csv  ($VREM_ROWS rows)"

# ── Final report ─────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  STUDY COMPLETE"
printf "  C++ runs     : %d total  (%d failed)\n" "$TOTAL_CPP" "$CPP_FAIL"
printf "  Python runs  : %d total  (%d failed)\n" "$TOTAL_PY"  "$PY_FAIL"
printf "  Elapsed time : %dm %02ds\n" "$(( ELAPSED/60 ))" "$(( ELAPSED%60 ))"
echo "  Results dir  : $RESULTS_DIR"
echo ""
echo "  Key output files:"
echo "  ┌─ MBSM rule-based (132 rows, all scenarios × all %):"
echo "  │    $MBSM_DIR/mbsm_summary_all.csv"
echo "  │"
echo "  ├─ VeReMi rule-based (132 rows):"
echo "  │    $VREM_DIR/veremi_summary_all.csv"
echo "  │"
echo "  ├─ KNN+Bagging holdout (4 classifiers × 12 scenarios):"
echo "  │    $MASTER_KNN_HOLDOUT"
echo "  │"
echo "  ├─ KNN+Bagging 5-fold CV (4 classifiers × 12 scenarios):"
echo "  │    $MASTER_KNN_CV"
echo "  │"
echo "  └─ Per-scenario detail:"
echo "       $MBSM_DIR/scenario_{1..12}/"
echo "       $VREM_DIR/scenario_{1..12}/"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Columns in mbsm_summary_all.csv / veremi_summary_all.csv:"
echo "    attack_scenario, scenario_name, N_Vehicles, N_RSUs,"
echo "    N_Controllers, attack_percentage, n_malicious, detector,"
echo "    tp, tn, fp, fn, mcc, auroc, tdet_ms, ..."
echo ""
echo "  Columns in knn_holdout_all_scenarios.csv:"
echo "    attack_type, type_name, classifier, tp, tn, fp, fn,"
echo "    accuracy, precision, recall, f1, mcc, auroc, tdet_ms"
echo "════════════════════════════════════════════════════════════"
