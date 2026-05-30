#!/bin/bash
# =============================================================================
# run_all_attacks.sh
# Runs all 12 SDVN Temporal-Echo attack scenarios (1–12) sequentially.
#
# Copy this script to ~/ns-3.35/ before running.
#
# Usage:
#   bash run_all_attacks.sh                   # default: attack_percentage=20
#   bash run_all_attacks.sh --pct 50          # override attack_percentage
#   bash run_all_attacks.sh --det 0           # attack-only mode (no mitigation)
#   bash run_all_attacks.sh --pct 50 --det 0  # both overrides
#
# Output per scenario (created automatically by routing.cc):
#   PEM_RUN_SUMMARY/<scenario>.csv
#   PEM_EVENT_LOG/<scenario>.csv
#   CHANNEL_DELIVERY_ANALYSIS/<scenario>.csv
#   NPFADS_RESULTS/<scenario>/<scenario>_NPFADS_*.csv
#   XML/<scenario>.xml
#   Logs_attacks/*_attack_log.txt
# =============================================================================

# ── Defaults ─────────────────────────────────────────────────────────────────
ATTACK_PCT=20
DET_ENABLED=1

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --pct)  ATTACK_PCT="$2";   shift 2 ;;
        --det)  DET_ENABLED="$2";  shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

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

TOTAL=${#SCENARIOS[@]}
PASSED=0
FAILED=0
declare -a FAILED_SCENARIOS=()

# ── Logging setup ─────────────────────────────────────────────────────────────
LOGDIR="run_all_attacks_logs"
mkdir -p "$LOGDIR"
MASTER_LOG="$LOGDIR/run_all_attacks_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "$@" | tee -a "$MASTER_LOG"
}

# ── Banner ────────────────────────────────────────────────────────────────────
log ""
log "╔══════════════════════════════════════════════════════════════════╗"
log "║      SDVN Temporal-Echo Attack — Full Scenario Runner           ║"
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  attack_percentage : $ATTACK_PCT"
log "║  detection_enabled : $DET_ENABLED  (1=detect+mitigate, 0=attack-only)"
log "║  Total scenarios   : $TOTAL"
log "║  Started at        : $(date)"
log "╚══════════════════════════════════════════════════════════════════╝"
log ""

# ── Main loop ─────────────────────────────────────────────────────────────────
IDX=0
for entry in "${SCENARIOS[@]}"; do
    IDX=$((IDX + 1))

    # Parse the scenario entry
    read -r SCENARIO simTime N_Vehicles N_RSUs LABEL <<< "$entry"

    log "──────────────────────────────────────────────────────────────────"
    log "  [$IDX/$TOTAL]  Scenario $SCENARIO — $LABEL"
    log "  simTime=$simTime  N_Vehicles=$N_Vehicles  N_RSUs=$N_RSUs"
    log "  attack_percentage=$ATTACK_PCT  detection_enabled=$DET_ENABLED"
    log "  Started: $(date +%H:%M:%S)"
    log "──────────────────────────────────────────────────────────────────"

    SCENARIO_LOG="$LOGDIR/scenario_${SCENARIO}_$(date +%Y%m%d_%H%M%S).log"

    ./waf --run "scratch/routing \
        --simTime=${simTime} \
        --N_Vehicles=${N_Vehicles} \
        --N_RSUs=${N_RSUs} \
        --attack_scenario=${SCENARIO} \
        --attack_percentage=${ATTACK_PCT} \
        --detection_enabled=${DET_ENABLED}" \
        2>&1 | tee -a "$SCENARIO_LOG" "$MASTER_LOG"

    EXIT_CODE=${PIPESTATUS[0]}

    if [ $EXIT_CODE -eq 0 ]; then
        log ""
        log "  ✔  Scenario $SCENARIO PASSED  (finished: $(date +%H:%M:%S))"
        PASSED=$((PASSED + 1))
    else
        log ""
        log "  ✘  Scenario $SCENARIO FAILED  (exit code: $EXIT_CODE)"
        FAILED=$((FAILED + 1))
        FAILED_SCENARIOS+=("$SCENARIO — $LABEL")
    fi

    log ""
done

# ── Final summary ─────────────────────────────────────────────────────────────
log "╔══════════════════════════════════════════════════════════════════╗"
log "║                     RUN COMPLETE SUMMARY                        ║"
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  Finished at  : $(date)"
log "║  Passed       : $PASSED / $TOTAL"
log "║  Failed       : $FAILED / $TOTAL"
if [ ${#FAILED_SCENARIOS[@]} -gt 0 ]; then
    log "║  Failed list  :"
    for fs in "${FAILED_SCENARIOS[@]}"; do
        log "║    ✘ Scenario $fs"
    done
fi
log "╠══════════════════════════════════════════════════════════════════╣"
log "║  Results are in:"
log "║    PEM_RUN_SUMMARY/          — detection metrics per scenario"
log "║    PEM_EVENT_LOG/            — per-event PEM log"
log "║    CHANNEL_DELIVERY_ANALYSIS/ — per-channel TX/RX fanout"
log "║    NPFADS_RESULTS/           — NPFADS position-attack baseline"
log "║    XML/                      — NetAnim animation per scenario"
log "║    Logs_attacks/             — human-readable attack step logs"
log "║  Full run log: $MASTER_LOG"
log "╚══════════════════════════════════════════════════════════════════╝"

# Exit with failure if any scenario failed
[ $FAILED -eq 0 ] && exit 0 || exit 1
