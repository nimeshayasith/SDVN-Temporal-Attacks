#!/bin/bash
# run_comparison_detectors.sh
# Runs all 12 attack scenarios × 6 attack_percentage values × 2 detectors.
# Total: 144 runs (sequential).
#
# Parameters:
#   N_Vehicles=200, simTime=30, maxspeed=60, mobility_scenario=0
#   RSU scenarios (S2,S4,S6,S8,S10,S12): N_RSUs=64
#   Non-RSU scenarios (S1,S3,S5,S7,S9,S11): N_RSUs=0
#   attack_percentage: 0 20 40 60 80 100

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

# Remove old summary files so we start fresh
rm -f comparison_veremi_summary.csv comparison_mbsm_summary.csv
echo "Cleared old summary files."

# Scenario → RSU count
declare -A RSU_COUNT
RSU_COUNT[1]=0;  RSU_COUNT[2]=64;  RSU_COUNT[3]=0;   RSU_COUNT[4]=64
RSU_COUNT[5]=0;  RSU_COUNT[6]=64;  RSU_COUNT[7]=0;   RSU_COUNT[8]=64
RSU_COUNT[9]=0;  RSU_COUNT[10]=64; RSU_COUNT[11]=0;  RSU_COUNT[12]=64

SCENARIOS=(1 2 3 4 5 6 7 8 9 10 11 12)
DETECTORS=(1 2)
ATK_PCTS=(0 20 40 60 80 100)
N_VEH=200
SIM_TIME=30
MAXSPEED=60
MOB=0

TOTAL=$(( ${#SCENARIOS[@]} * ${#DETECTORS[@]} * ${#ATK_PCTS[@]} ))
RUN=0

for CD in "${DETECTORS[@]}"; do
    DET_NAME="VeReMi"
    if [ "$CD" -eq 2 ]; then DET_NAME="MBSM"; fi

    for SC in "${SCENARIOS[@]}"; do
        N_RSU=${RSU_COUNT[$SC]}

        for ATK_PCT in "${ATK_PCTS[@]}"; do
            RUN=$(( RUN + 1 ))
            echo ""
            echo "══════════════════════════════════════════════════════════"
            echo " Run $RUN / $TOTAL  |  $DET_NAME  |  S=$SC  |  ATK=$ATK_PCT%  |  RSUs=$N_RSU"
            echo "══════════════════════════════════════════════════════════"

            T_START=$(date +%s)

            ./waf --run "scratch/routing \
                --simTime=$SIM_TIME \
                --N_Vehicles=$N_VEH \
                --N_RSUs=$N_RSU \
                --attack_scenario=$SC \
                --attack_percentage=$ATK_PCT \
                --maxspeed=$MAXSPEED \
                --mobility_scenario=$MOB \
                --comparison_detector=$CD" 2>&1 \
                | grep -E "\[CD\]|TP=|MCC=|Detector|Scenario|written|error:|Error"

            T_END=$(date +%s)
            ELAPSED=$(( T_END - T_START ))
            echo "  → S$SC  ATK=${ATK_PCT}%  $DET_NAME  done.  Time: ${ELAPSED}s"
        done
    done
done

echo ""
echo "══════════════════════════════════════════════════════════"
echo " ALL $TOTAL RUNS COMPLETE"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "=== VeReMi summary ==="
cat comparison_veremi_summary.csv
echo ""
echo "=== MBSM summary ==="
cat comparison_mbsm_summary.csv
