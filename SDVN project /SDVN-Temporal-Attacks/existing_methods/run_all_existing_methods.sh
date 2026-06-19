#!/bin/bash
# run_all_existing_methods.sh
# Runs temporal_veremi_compare and temporal_mbsm_compare across all
# 12 attack scenarios × attack_percentage 10..100 (step 10) with 200 vehicles.
#
# S1 (scenarios 1,5,9)  : malicious vehicles, N_RSUs=0
# S2 (scenarios 2,6,10) : malicious RSU,      N_RSUs=1
# S3 (scenarios 3,7,11) : malicious controller, N_RSUs=0  → MCC=0 (undetectable)
# S4 (scenarios 4,8,12) : malicious controller, N_RSUs=1  → MCC=0 (undetectable)

set -e

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="${NS3_DIR}/scratch/SDVN project /SDVN-Temporal-Attacks/existing_methods"
RESULTS_DIR="${PROJ_DIR}/results"

mkdir -p "${RESULTS_DIR}/veremi_raw"
mkdir -p "${RESULTS_DIR}/mbsm_raw"
mkdir -p "${RESULTS_DIR}/knn_raw"
mkdir -p "${RESULTS_DIR}/npfads"

# Remove old accumulated CSVs so we start fresh
rm -f "${RESULTS_DIR}/veremi_raw/temporal_veremi_compare_pem_summary.csv"
rm -f "${RESULTS_DIR}/mbsm_raw/temporal_mbsm_compare_summary.csv"
rm -f "${RESULTS_DIR}/knn_raw/pairs_scenario"*.csv
rm -f "${RESULTS_DIR}/knn_raw/knn_all_scenarios.csv"
rm -f "${RESULTS_DIR}/npfads/npfads_NPFADS_PEM_Run_Summary.csv"
rm -f "${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv"

cd "${NS3_DIR}"

N_VEH=200
SIM_TIME=30
ATTACK_PCTS="0 20 40 60 80 100"

# Scenario → N_RSUs mapping
# S2/S4 variants (even scenarios) have RSU infrastructure: 64 RSUs
# S1/S3 variants (odd scenarios) have no RSU: 0 RSUs
rsu_for_scenario() {
    local s=$1
    case $s in
        2|4|6|8|10|12) echo 64 ;;
        *) echo 0 ;;
    esac
}

echo "============================================================"
echo "  Running temporal_veremi_compare  (12 scenarios × 10 pcts)"
echo "============================================================"
rm -f temporal_veremi_compare_pem_summary.csv temporal_veremi_compare_pairs.csv

for scenario in 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSUS=$(rsu_for_scenario $scenario)
    for pct in $ATTACK_PCTS; do
        echo -n "  veremi  scenario=${scenario}  pct=${pct}%  RSUs=${N_RSUS} ... "
        ./waf --run "scratch/temporal_veremi_compare \
            --simTime=${SIM_TIME} \
            --N_Vehicles=${N_VEH} \
            --N_RSUs=${N_RSUS} \
            --attack_scenario=${scenario} \
            --attack_percentage=${pct}" > /dev/null 2>&1
        echo "done"
        # Accumulate pairs CSV per scenario for KNN
        if [ -f temporal_veremi_compare_pairs.csv ]; then
            cat temporal_veremi_compare_pairs.csv >> \
                "${RESULTS_DIR}/knn_raw/pairs_scenario${scenario}.csv"
        fi
    done
done

cp temporal_veremi_compare_pem_summary.csv \
   "${RESULTS_DIR}/veremi_raw/temporal_veremi_compare_pem_summary.csv" 2>/dev/null || true
echo "  VeReMi summary saved."

echo ""
echo "============================================================"
echo "  Running temporal_mbsm_compare  (12 scenarios × 10 pcts)"
echo "============================================================"
rm -f temporal_mbsm_compare_summary.csv

for scenario in 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSUS=$(rsu_for_scenario $scenario)
    for pct in $ATTACK_PCTS; do
        echo -n "  mbsm    scenario=${scenario}  pct=${pct}%  RSUs=${N_RSUS} ... "
        ./waf --run "scratch/temporal_mbsm_compare \
            --simTime=${SIM_TIME} \
            --N_Vehicles=${N_VEH} \
            --N_RSUs=${N_RSUS} \
            --attack_scenario=${scenario} \
            --attack_percentage=${pct}" > /dev/null 2>&1
        echo "done"
    done
done

cp temporal_mbsm_compare_summary.csv \
   "${RESULTS_DIR}/mbsm_raw/temporal_mbsm_compare_summary.csv" 2>/dev/null || true
echo "  MBSM summary saved."

echo ""
echo "============================================================"
echo "  Running KNN classifier on accumulated pairs CSVs"
echo "============================================================"
KNN_SCRIPT="${PROJ_DIR}/temporal_veremi_compare_knn.py"
KNN_RESULTS="${RESULTS_DIR}/knn_raw"

rm -f temporal_compare_knn_results.csv temporal_compare_cv_results.csv

for scenario in 1 2 3 4 5 6 7 8 9 10 11 12; do
    PAIRS="${KNN_RESULTS}/pairs_scenario${scenario}.csv"
    if [ -f "${PAIRS}" ] && [ -s "${PAIRS}" ]; then
        echo -n "  knn     scenario=${scenario} ... "
        python3 "${KNN_SCRIPT}" "${PAIRS}" --holdout-only > \
            "${KNN_RESULTS}/knn_output_scenario${scenario}.txt" 2>&1 || true
        # Tag the knn results CSV with the scenario
        if [ -f temporal_compare_knn_results.csv ]; then
            # Add scenario column if not present, then accumulate
            awk -v s="${scenario}" 'NR==1{print $0",knn_scenario"}NR>1{print $0","s}' \
                temporal_compare_knn_results.csv >> \
                "${KNN_RESULTS}/knn_all_scenarios.csv" 2>/dev/null || true
        fi
        echo "done"
    else
        echo "  knn     scenario=${scenario} ... no pairs data (skipped)"
    fi
done

echo ""
echo "============================================================"
echo "  Running NPFADS via scratch/routing  (12 scenarios × 6 pcts)"
echo "  Proves NPFADS (position-based) is complementary to PEM (temporal)"
echo "============================================================"

for scenario in 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSUS=$(rsu_for_scenario $scenario)
    for pct in $ATTACK_PCTS; do
        echo -n "  npfads  scenario=${scenario}  pct=${pct}%  RSUs=${N_RSUS} ... "
        ./waf --run "scratch/routing \
            --simTime=${SIM_TIME} \
            --N_Vehicles=${N_VEH} \
            --N_RSUs=${N_RSUS} \
            --attack_scenario=${scenario} \
            --attack_percentage=${pct}" > /dev/null 2>&1 || true
        echo "done"
    done
done

# RunNpfadsDetection() appends each run's row to npfads_NPFADS_PEM_Run_Summary.csv.
# After all 72 runs, copy the fully-accumulated file to the final summary name.
if [ -f "${RESULTS_DIR}/npfads/npfads_NPFADS_PEM_Run_Summary.csv" ]; then
    cp "${RESULTS_DIR}/npfads/npfads_NPFADS_PEM_Run_Summary.csv" \
       "${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv"
    NROWS=$(wc -l < "${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv")
    echo "  NPFADS all-scenario summary saved (${NROWS} rows incl. header)."
else
    echo "  WARNING: npfads_NPFADS_PEM_Run_Summary.csv not found — check routing runs."
fi

echo ""
echo "All runs complete."
echo "Results:"
echo "  ${RESULTS_DIR}/veremi_raw/temporal_veremi_compare_pem_summary.csv"
echo "  ${RESULTS_DIR}/mbsm_raw/temporal_mbsm_compare_summary.csv"
echo "  ${RESULTS_DIR}/knn_raw/"
echo "  ${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv"
echo ""
echo "Next: python3 generate_charts.py"
