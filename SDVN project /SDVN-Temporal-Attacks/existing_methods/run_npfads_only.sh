#!/bin/bash
# run_npfads_only.sh
# Re-runs only the NPFADS section with reduced simTime=10 and N_Vehicles=50
# to regenerate npfads_NPFADS_PEM_Run_Summary.csv with fixed MCC (nan→0).
#
# Expected result: MCC=0 for ALL scenarios — NPFADS is a position-based detector
# and temporal-echo attacks never falsify GPS coordinates. This proves complementarity
# with PEM (which achieves MCC~1.0 for the same scenarios).

set -e

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="${NS3_DIR}/scratch/SDVN project /SDVN-Temporal-Attacks/existing_methods"
RESULTS_DIR="${PROJ_DIR}/results"

mkdir -p "${RESULTS_DIR}/npfads"

# Always wipe the accumulated summary before starting a fresh batch.
# Per-run CSV (npfads_NPFADS_PEM_Run_Summary.csv) is now TRUNCATED by C++ on
# every run, so each simulation writes exactly one clean header + data rows.
# We accumulate here manually using tail -n +2 to skip the repeated header.
rm -f "${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv"

ACCUMULATED="${RESULTS_DIR}/npfads/npfads_all_PEM_Summary.csv"
PER_RUN="${RESULTS_DIR}/npfads/npfads_NPFADS_PEM_Run_Summary.csv"
HEADER_WRITTEN=0

cd "${NS3_DIR}"

N_VEH=50
SIM_TIME=10
ATTACK_PCTS="0 20 40 60 80 100"

rsu_for_scenario() {
    local s=$1
    case $s in
        2|4|6|8|10|12) echo 4 ;;
        *) echo 0 ;;
    esac
}

echo "============================================================"
echo "  NPFADS-only re-run: N_VEH=${N_VEH}, simTime=${SIM_TIME}"
echo "  12 scenarios × 6 pcts = 72 runs"
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

        # Append this run's rows into the accumulated file.
        # C++ always writes a fresh header+rows, so:
        #   - First run: copy the whole file (header + rows).
        #   - Subsequent runs: skip the header line (tail -n +2).
        if [ -f "${PER_RUN}" ]; then
            if [ "${HEADER_WRITTEN}" -eq 0 ]; then
                cat "${PER_RUN}" >> "${ACCUMULATED}"
                HEADER_WRITTEN=1
            else
                tail -n +2 "${PER_RUN}" >> "${ACCUMULATED}"
            fi
        fi
        echo "done"
    done
done

if [ -f "${ACCUMULATED}" ]; then
    NROWS=$(wc -l < "${ACCUMULATED}")
    echo ""
    echo "NPFADS summary saved: ${NROWS} rows (incl. header)"
    echo "File: ${ACCUMULATED}"
else
    echo "WARNING: No output rows were collected — check simulation output."
fi

echo ""
echo "Expected: mcc=0.0 for all rows (NPFADS cannot detect temporal-echo attacks)."
echo "This confirms complementarity — use PEM results for actual detection metrics."
