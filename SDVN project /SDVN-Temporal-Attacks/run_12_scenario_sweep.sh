#!/bin/bash
# run_12_scenario_sweep.sh
#
# Runs all 12 SDVN Temporal-Echo attack scenarios sequentially with a fixed
# configuration (200 vehicles, 4 controllers, 40s sim time, continuous
# neighborhood beaconing on by default as of routing.cc's current default).
# This is a lighter, single-run-per-scenario sweep for checking pipeline
# behavior/timing/detection metrics — NOT the full VeReMi/MBSM/KNN
# comparison-detector benchmark (that's the separate, pre-existing
# run_all_scenarios.sh, ~120 runs / 16-20h — untouched by this script).
#
# N_RSUs is set PER SCENARIO, not uniformly, via get_n_rsu() below — matching
# the existing run_all_scenarios.sh's convention. This matters beyond just
# node count: routing.cc's TrustGetTrustedPeers() (line ~2923) gates on
# RSU_Nodes.GetN()==0 directly (not on attack_scenario), to decide whether
# trusted OBU vehicles get bucketed into the synthetic no-RSU trust-evidence
# peer (TRUST_OBU_PEER_ID). Uniformly passing N_RSUs=64 to every scenario
# would silently break that Trust/Fabric peer-selection path for the six
# no-RSU scenarios (1,3,5,7,9,11) — has_RSU_infrastructure (the mitigation-
# tier flag) stays correctly false either way since it's gated on
# attack_scenario, but the *trust peer set* is gated on the actual RSU node
# count, so it must be 0 for those six scenarios to test what they're meant
# to test.
#
# Must run sequentially, NOT in parallel — several output files
# (crypto_drop_log.csv, crypto_verified_events.csv, ctrl_topo.json,
# scenario_config.json, tgn_alerts.json, tgn_alerts_crypto.json,
# vehicle_macs.json, witness_records.json, beacon_evidence.csv,
# crypto_latency_summary.csv, crypto_latency_sumo.csv, and the /tmp blacklist
# IPC files) are fixed-path and shared/overwritten across runs rather than
# scenario-tagged, so concurrent runs would corrupt each other's data.
#
# The scenario-tagged outputs (outputs/PEM_RUN_SUMMARY/, outputs/PEM_EVENT_LOG/,
# outputs/CHANNEL_DELIVERY_ANALYSIS/, outputs/XML/, outputs/Logs_attacks/) are
# already uniquely named per scenario by BuildScenarioCsvPath()/
# GetScenarioOutputName() and do NOT need archiving here — they survive the
# next scenario's run untouched. This script only archives the FIXED-name
# files that would otherwise be overwritten by the next iteration,
# snapshotting each into results_sweep/scenario_<N>/ before moving on.
#
# Usage:
#   bash run_12_scenario_sweep.sh                 # runs scenarios 1-12
#   bash run_12_scenario_sweep.sh "0 1 2"          # runs only the listed scenarios
#   N_VEHICLES=100 RSU_ON_COUNT=32 SIM_TIME=60 bash run_12_scenario_sweep.sh   # override config
#   (scenario 0 = baseline/no-attack; treated as no-RSU, N_RSUs=0)

set -uo pipefail

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJECT_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks"
RESULTS_DIR="${PROJECT_DIR}/results_sweep"

SCENARIOS="${1:-1 2 3 4 5 6 7 8 9 10 11 12}"
N_VEHICLES="${N_VEHICLES:-200}"
RSU_ON_COUNT="${RSU_ON_COUNT:-64}"   # N_RSUs used for the six RSU-family scenarios
N_CONTROLLERS="${N_CONTROLLERS:-4}"
SIM_TIME="${SIM_TIME:-40}"

# Per-scenario RSU count — scenarios 2,4,6,8,10,12 (TTW-S2/S4, BSHH-S2/S4,
# ME-S2/S4) are the RSU-present family; everything else (0,1,3,5,7,9,11) is
# no-RSU and MUST get N_RSUs=0, not just "0 by convention" — see the header
# comment above re: TrustGetTrustedPeers() gating on RSU_Nodes.GetN()==0.
get_n_rsu() {
    case $1 in
        2|4|6|8|10|12) echo "$RSU_ON_COUNT" ;;
        *)              echo 0 ;;
    esac
}

# Fixed-name files that get overwritten each run — snapshotted per scenario.
# Paths are relative to PROJECT_DIR (where the simulation actually writes them).
SHARED_FILES=(
    "crypto_drop_log.csv"
    "crypto_layer_log.txt"
    "crypto_verified_events.csv"
    "ctrl_topo.json"
    "scenario_config.json"
    "tgn_alerts.json"
    "tgn_alerts_crypto.json"
    "vehicle_macs.json"
    "witness_records.json"
    "beacon_evidence.csv"
    "crypto_latency_summary.csv"
    "crypto_latency_sumo.csv"
)

mkdir -p "$RESULTS_DIR"

echo "=========================================================="
echo " SDVN Temporal-Echo — 12-Scenario Sweep"
echo " Scenarios     : $SCENARIOS"
echo " N_Vehicles    : $N_VEHICLES"
echo " N_RSUs        : $RSU_ON_COUNT for scenarios 2,4,6,8,10,12; 0 for all others"
echo " N_Controllers : $N_CONTROLLERS"
echo " simTime       : $SIM_TIME"
echo " Results dir   : $RESULTS_DIR"
echo "=========================================================="
echo ""

TOTAL_START=$(date +%s)

cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

for s in $SCENARIOS; do
    N_RSU=$(get_n_rsu "$s")
    echo "=========== SCENARIO $s (N_RSUs=$N_RSU) — starting $(date '+%Y-%m-%d %H:%M:%S') ==========="
    RUN_START=$(date +%s)

    ./waf --run "scratch/routing --simTime=${SIM_TIME} --N_Vehicles=${N_VEHICLES} --N_RSUs=${N_RSU} --N_Controllers=${N_CONTROLLERS} --attack_scenario=${s}"
    RUN_STATUS=$?

    RUN_END=$(date +%s)
    echo "=========== SCENARIO $s — finished in $((RUN_END - RUN_START))s, exit code $RUN_STATUS ==========="

    SCEN_RESULTS="${RESULTS_DIR}/scenario_${s}"
    mkdir -p "$SCEN_RESULTS"

    for f in "${SHARED_FILES[@]}"; do
        if [ -f "${PROJECT_DIR}/${f}" ]; then
            cp "${PROJECT_DIR}/${f}" "${SCEN_RESULTS}/${f}"
        fi
    done

    if [ $RUN_STATUS -ne 0 ]; then
        echo "!!! WARNING: scenario $s exited with non-zero status $RUN_STATUS — check output above before trusting its results."
    fi

    echo ""
done

TOTAL_END=$(date +%s)
echo "=========================================================="
echo " All scenarios complete. Total time: $((TOTAL_END - TOTAL_START))s"
echo " Scenario-tagged outputs (unaffected by overwrite, no copy needed):"
echo "   ${PROJECT_DIR}/outputs/PEM_RUN_SUMMARY/<NN_ScenarioName>.csv"
echo "   ${PROJECT_DIR}/outputs/PEM_EVENT_LOG/<NN_ScenarioName>.csv"
echo "   ${PROJECT_DIR}/outputs/CHANNEL_DELIVERY_ANALYSIS/<NN_ScenarioName>.csv"
echo "   ${PROJECT_DIR}/outputs/XML/<NN_ScenarioName>.xml"
echo "   ${PROJECT_DIR}/outputs/Logs_attacks/terminal_output_scenario_<N>.txt"
echo " Fixed-name files snapshotted per scenario into:"
echo "   ${RESULTS_DIR}/scenario_<N>/"
echo "=========================================================="
