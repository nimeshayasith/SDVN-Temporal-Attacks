#!/bin/bash
# ============================================================
# run_temporal_quick_test.sh
# Runs 4 quick test cases (one from each attack family, each detector)
# to verify setup BEFORE running the full 264-run study.
#
# Usage:
#   bash run_temporal_quick_test.sh [ns3_dir]
# ============================================================

NS3_DIR="${1:-$HOME/ns-3.35}"
SCRATCH_DIR="$NS3_DIR/scratch"

echo "Quick-test: verifying both detectors work correctly"
echo "NS3_DIR = $NS3_DIR"
echo ""

cd "$NS3_DIR"

PASS=0
FAIL=0

run_test() {
    local DETECTOR=$1
    local SC=$2
    local NV=$3
    local NR=$4
    local PCT=$5
    local NC=$6
    local LABEL="$DETECTOR SC=$SC NV=$NV NR=$NR NC=$NC PCT=${PCT}%"

    printf "  %-70s ... " "$LABEL"

    ./waf --run "scratch/$DETECTOR \
        --simTime=40 \
        --N_Vehicles=$NV \
        --N_RSUs=$NR \
        --N_Controllers=$NC \
        --attack_scenario=$SC \
        --attack_percentage=$PCT" \
        > /tmp/qt_out.txt 2>&1

    if [ $? -eq 0 ]; then
        echo "OK"
        PASS=$(( PASS + 1 ))
    else
        echo "FAIL"
        tail -3 /tmp/qt_out.txt | sed 's/^/    /'
        FAIL=$(( FAIL + 1 ))
    fi
}

# DETECTOR  SC  NV  NR  PCT  NC
# TTW
run_test temporal_mbsm_compare   1 10  0  50  1   # TTW-S1: 50% vehicles, MBSM
run_test temporal_mbsm_compare   2 10 10  50  1   # TTW-S2: 50% RSUs, MBSM
run_test temporal_veremi_compare 1 10  0  50  1   # TTW-S1: 50% vehicles, VeReMi
run_test temporal_veremi_compare 2 10 10  50  1   # TTW-S2: 50% RSUs, VeReMi
# BSHH
run_test temporal_mbsm_compare   5 10  0  30  1   # BSHH-S1: 30% vehicles
run_test temporal_mbsm_compare   6 10 10  30  1   # BSHH-S2: 30% RSUs
# Controller scenarios (NC=10 so attack_percentage is meaningful)
run_test temporal_mbsm_compare   3 10  0  50 10   # TTW-S3: 50% controllers, no RSU
run_test temporal_mbsm_compare   4 10 10  50 10   # TTW-S4: 50% controllers, with RSU
# ME
run_test temporal_mbsm_compare   9 10  0  40  1   # ME-S1: 40% vehicles
run_test temporal_mbsm_compare  10 10 10  40  1   # ME-S2: 40% RSUs
# Baseline
run_test temporal_mbsm_compare   1 10  0   0  1   # baseline (attack_percentage=0)
run_test temporal_veremi_compare 9 10  0   0  1   # baseline ME

echo ""
echo "Quick-test results: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
    echo "All tests passed — safe to run the full study."
    echo "  bash run_temporal_attack_study.sh $NS3_DIR"
else
    echo "Fix the failures above before running the full study."
fi
