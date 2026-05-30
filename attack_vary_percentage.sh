#!/bin/bash
# =============================================================================
# attack_vary_percentage.sh
# For every attack scenario (1–12), runs the simulation at each attack
# percentage: 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100.
#
# All 12 scenarios × 11 percentages = 132 total runs.
# Scenarios run one by one; within each scenario all percentages run
# one by one before moving to the next scenario.
#
# Copy this script to ~/ns-allinone-3.35/ns-3.35/ before running.
#
# Usage:
#   bash attack_vary_percentage.sh             # detection ON (default)
#   bash attack_vary_percentage.sh --det 0     # attack-only mode
#
# Output per run (appended, NOT overwritten — multiple percentage rows
# accumulate in the same scenario file):
#   PEM_RUN_SUMMARY/<scenario>.csv
#   PEM_EVENT_LOG/<scenario>.csv
#   CHANNEL_DELIVERY_ANALYSIS/<scenario>.csv
#   NPFADS_RESULTS/<scenario>/<scenario>_NPFADS_PEM_Run_Summary.csv
#   XML/<scenario>.xml
# =============================================================================

# ── Defaults ─────────────────────────────────────────────────────────────────
DET_ENABLED=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --det) DET_ENABLED="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Attack percentage sweep ───────────────────────────────────────────────────
PERCENTAGES=(0 10 20 30 40 50 60 70 80 90 100)

# ── Scenario table ────────────────────────────────────────────────────────────
# Format: "SCENARIO  simTime  N_Vehicles  N_RSUs  LABEL"
declare -a SCENARIOS=(
    "1   30  10  0  TTW-S1  (Malicious Vehicle, No RSU)"
    "2   30  10  1  TTW-S2  (Malicious RSU)"
    "3   30  10  0  TTW-S3  (Malicious Controller, No RSU)"
    "4   30  10  1  TTW-S4  (Malicious Controller, With RSU)"
    "5   20  10  0  BSHH-S1 (Malicious Vehicle, No RSU)"
    "6   20  10  1  BSHH-S2 (Malicious RSU)"
    "7   20  10  0  BSHH-S3 (Malicious Controller, No RSU)"
    "8   20  10  1  BSHH-S4 (Malicious Controller, With RSU)"
    "9   20  10  0  ME-S1   (Malicious Vehicles, No RSU)"
    "10  20  10  1  ME-S2   (Malicious RSU)"
    "11  20  10  0  ME-S3   (Malicious Controller, No RSU)"
    "12  20  10  1  ME-S4   (Malicious Controller, With RSU)"
)

TOTAL_SCENARIOS=${#SCENARIOS[@]}
TOTAL_PCTS=${#PERCENTAGES[@]}
GRAND_TOTAL=$((TOTAL_SCENARIOS * TOTAL_PCTS))
RUN_NUM=0
PASSED=0
FAILED=0
declare -a FAILED_LIST=()

# ── Logging ───────────────────────────────────────────────────────────────────
LOGDIR="$HOME/ns-allinone-3.35/ns-3.35/vary_pct_logs"
mkdir -p "$LOGDIR"
MASTER_LOG="$LOGDIR/vary_pct_$(date +%Y%m%d_%H%M%S).log"

log() { echo "$@" | tee -a "$MASTER_LOG"; }

# ── Banner ────────────────────────────────────────────────────────────────────
log ""
log "╔══════════════════════════════════════════════════════════════════╗"
log "║     SDVN Attack — Vary Attack Percentage Across All Scenarios   ║"
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  Percentages tested : ${PERCENTAGES[*]}"
log "║  detection_enabled  : $DET_ENABLED"
log "║  Total runs         : $GRAND_TOTAL  ($TOTAL_SCENARIOS scenarios × $TOTAL_PCTS percentages)"
log "║  Started at         : $(date)"
log "╚══════════════════════════════════════════════════════════════════╝"
log ""

# ── Main loop: scenario → percentage ─────────────────────────────────────────
SCEN_IDX=0
for entry in "${SCENARIOS[@]}"; do
    SCEN_IDX=$((SCEN_IDX + 1))
    read -r SCENARIO simTime N_Vehicles N_RSUs LABEL <<< "$entry"

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  SCENARIO $SCENARIO / $TOTAL_SCENARIOS — $LABEL"
    log "  simTime=$simTime  N_Vehicles=$N_Vehicles  N_RSUs=$N_RSUs"
    log "  Running ${TOTAL_PCTS} attack percentages: ${PERCENTAGES[*]}"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for PCT in "${PERCENTAGES[@]}"; do
        RUN_NUM=$((RUN_NUM + 1))
        log ""
        log "  ── [$RUN_NUM/$GRAND_TOTAL] Scenario $SCENARIO | attack_percentage=$PCT ──"
        log "     $(date +%H:%M:%S)"

        RUN_LOG="$LOGDIR/s${SCENARIO}_pct${PCT}_$(date +%Y%m%d_%H%M%S).log"

        ./waf --run "scratch/routing \
            --simTime=${simTime} \
            --N_Vehicles=${N_Vehicles} \
            --N_RSUs=${N_RSUs} \
            --attack_scenario=${SCENARIO} \
            --attack_percentage=${PCT} \
            --detection_enabled=${DET_ENABLED}" \
            2>&1 | tee -a "$RUN_LOG" "$MASTER_LOG"

        EXIT_CODE=${PIPESTATUS[0]}

        if [ $EXIT_CODE -eq 0 ]; then
            log "     ✔ PASSED"
            PASSED=$((PASSED + 1))
        else
            log "     ✘ FAILED (exit code: $EXIT_CODE)"
            FAILED=$((FAILED + 1))
            FAILED_LIST+=("Scenario $SCENARIO pct=$PCT")
        fi
    done

    log ""
    log "  Scenario $SCENARIO complete — all $TOTAL_PCTS percentages done."
    log ""
done

# ── Final summary ─────────────────────────────────────────────────────────────
log "╔══════════════════════════════════════════════════════════════════╗"
log "║                     VARY-PERCENTAGE COMPLETE                    ║"
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  Finished at  : $(date)"
log "║  Passed       : $PASSED / $GRAND_TOTAL"
log "║  Failed       : $FAILED / $GRAND_TOTAL"
if [ ${#FAILED_LIST[@]} -gt 0 ]; then
    log "║  Failed runs  :"
    for item in "${FAILED_LIST[@]}"; do
        log "║    ✘ $item"
    done
fi
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  Results (one CSV per scenario, rows = percentage runs):"
log "║    PEM_RUN_SUMMARY/<scenario>.csv"
log "║    NPFADS_RESULTS/<scenario>/<scenario>_NPFADS_PEM_Run_Summary.csv"
log "║  Full log: $MASTER_LOG"
log "╚══════════════════════════════════════════════════════════════════╝"

[ $FAILED -eq 0 ] && exit 0 || exit 1
