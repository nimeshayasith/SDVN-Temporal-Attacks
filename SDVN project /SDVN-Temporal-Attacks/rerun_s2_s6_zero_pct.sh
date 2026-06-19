#!/bin/bash
# rerun_s2_s6_zero_pct.sh
# Reruns ONLY S2 (TTW-S2) and S6 (BSHH-S6) at attack_percentage=0.
# Fixes the clamping bug that forced ≥1 malicious RSU even at 0% attack.
# After rerun, removes the old S2/S6 0% rows from all three summary CSVs
# and appends the corrected rows, then regenerates charts.

NS3_DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35"
PROJ_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks"
EM_DIR="$PROJ_DIR/existing_methods"
KNN_MODEL="$EM_DIR/knn_veremi_model.pkl"
PYTHON3="/home/sdvn_echo_topology/.pyenv/versions/3.10.14/bin/python3"
[ ! -x "$PYTHON3" ] && PYTHON3="$(which python3)"

VEREMI_CSV="$NS3_DIR/comparison_veremi_summary.csv"
MBSM_CSV="$NS3_DIR/comparison_mbsm_summary.csv"
KNN_CSV="$NS3_DIR/comparison_knn_summary.csv"

N_VEH=200
N_RSU=64
N_CTRL=4
SIM_TIME=30
MAXSPEED=60
MOB=0
ATK_PCT=0

cd "$NS3_DIR" || { echo "ERROR: cannot cd to $NS3_DIR"; exit 1; }

patch_csv() {
    local CSV="$1"
    local SC="$2"
    local NEW_ROW_FILE="$3"

    if [ ! -f "$CSV" ]; then
        echo "  [WARN] $CSV not found — skipping patch."
        return
    fi

    # Remove all existing rows for this scenario at attack_pct=0.
    # Column 1 = attack_scenario, column 5 = attack_percentage.
    HEADER=$(head -1 "$CSV")
    TMP=$(mktemp)
    echo "$HEADER" > "$TMP"
    tail -n +2 "$CSV" | awk -F',' -v sc="$SC" -v pct="$ATK_PCT" \
        '{ if ($1 == sc && $5 == pct) next; print }' >> "$TMP"
    # Append new row(s)
    if [ -f "$NEW_ROW_FILE" ]; then
        tail -n +2 "$NEW_ROW_FILE" >> "$TMP"
    fi
    # Sort by scenario then attack_pct (columns 1,5) keeping header
    SORTED=$(mktemp)
    echo "$HEADER" > "$SORTED"
    tail -n +2 "$TMP" | sort -t',' -k1,1n -k5,5n >> "$SORTED"
    mv "$SORTED" "$CSV"
    rm -f "$TMP"
    echo "  [OK] $CSV patched for scenario=$SC attack_pct=$ATK_PCT"
}

run_scenario() {
    local SC="$1"
    local DETECTOR_ID="$2"
    local DETECTOR_NAME="$3"
    local OUT_CSV="$4"

    echo "────────────────────────────────────────────"
    echo " Scenario S${SC} | ${DETECTOR_NAME} | attack_pct=0"
    echo "────────────────────────────────────────────"

    # Clear per-run outputs so the append logic only sees the new row.
    rm -f comparison_veremi_summary.csv comparison_mbsm_summary.csv \
          comparison_veremi_pairs.csv pem_run_summary.csv pem_event_log.csv \
          routing-animation.xml

    ./waf --run "scratch/routing \
        --simTime=$SIM_TIME \
        --N_Vehicles=$N_VEH \
        --N_RSUs=$N_RSU \
        --N_Controllers=$N_CTRL \
        --attack_scenario=$SC \
        --attack_percentage=$ATK_PCT \
        --maxspeed=$MAXSPEED \
        --mobility_scenario=$MOB \
        --comparison_detector=$DETECTOR_ID" 2>&1 \
        | grep -E "^\[CD\]|TP=|MCC=|detector=|scenario=|declare_att|error:|Error"

    echo "  NS-3 done."
}

# ── Backup existing CSVs ──────────────────────────────────────────────────────
TS=$(date +%Y%m%d_%H%M%S)
for F in "$VEREMI_CSV" "$MBSM_CSV" "$KNN_CSV"; do
    [ -f "$F" ] && cp "$F" "${F%.csv}_backup_${TS}.csv" && echo "Backed up: $F"
done
echo ""

# ── S2 VeReMi ────────────────────────────────────────────────────────────────
run_scenario 2 1 "VeReMi"
NEW_VEREMI_S2=$(mktemp)
[ -f comparison_veremi_summary.csv ] && cp comparison_veremi_summary.csv "$NEW_VEREMI_S2"

# ── S2 MBSM ──────────────────────────────────────────────────────────────────
run_scenario 2 2 "MBSM"
NEW_MBSM_S2=$(mktemp)
[ -f comparison_mbsm_summary.csv ] && cp comparison_mbsm_summary.csv "$NEW_MBSM_S2"

# ── S2 KNN ───────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────"
echo " Scenario S2 | KNN+Bagging | attack_pct=0"
echo "────────────────────────────────────────────"
# KNN needs the pairs CSV produced by the VeReMi run — rerun VeReMi to get it.
rm -f comparison_veremi_summary.csv comparison_mbsm_summary.csv \
      comparison_veremi_pairs.csv pem_run_summary.csv pem_event_log.csv
./waf --run "scratch/routing \
    --simTime=$SIM_TIME \
    --N_Vehicles=$N_VEH \
    --N_RSUs=$N_RSU \
    --N_Controllers=$N_CTRL \
    --attack_scenario=2 \
    --attack_percentage=$ATK_PCT \
    --maxspeed=$MAXSPEED \
    --mobility_scenario=$MOB \
    --comparison_detector=1" 2>&1 | grep -E "^\[CD\]|error:" > /dev/null

NEW_KNN_S2=$(mktemp)
rm -f "$NS3_DIR/comparison_knn_summary.csv"
cd "$EM_DIR" || exit 1
$PYTHON3 temporal_veremi_compare_knn.py \
    --load-model "$KNN_MODEL" \
    --test-csv "$NS3_DIR/comparison_veremi_pairs.csv" \
    --scenario 2 \
    --attack-pct 0 \
    --output-summary "$NS3_DIR/comparison_knn_summary.csv" \
    2>&1 | grep -E "CD-KNN|Appended|ERROR|empty"
cd "$NS3_DIR" || exit 1
[ -f comparison_knn_summary.csv ] && cp comparison_knn_summary.csv "$NEW_KNN_S2"

# ── S6 VeReMi ────────────────────────────────────────────────────────────────
run_scenario 6 1 "VeReMi"
NEW_VEREMI_S6=$(mktemp)
[ -f comparison_veremi_summary.csv ] && cp comparison_veremi_summary.csv "$NEW_VEREMI_S6"

# ── S6 MBSM ──────────────────────────────────────────────────────────────────
run_scenario 6 2 "MBSM"
NEW_MBSM_S6=$(mktemp)
[ -f comparison_mbsm_summary.csv ] && cp comparison_mbsm_summary.csv "$NEW_MBSM_S6"

# ── S6 KNN ───────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────"
echo " Scenario S6 | KNN+Bagging | attack_pct=0"
echo "────────────────────────────────────────────"
rm -f comparison_veremi_summary.csv comparison_mbsm_summary.csv \
      comparison_veremi_pairs.csv pem_run_summary.csv pem_event_log.csv
./waf --run "scratch/routing \
    --simTime=$SIM_TIME \
    --N_Vehicles=$N_VEH \
    --N_RSUs=$N_RSU \
    --N_Controllers=$N_CTRL \
    --attack_scenario=6 \
    --attack_percentage=$ATK_PCT \
    --maxspeed=$MAXSPEED \
    --mobility_scenario=$MOB \
    --comparison_detector=1" 2>&1 | grep -E "^\[CD\]|error:" > /dev/null

NEW_KNN_S6=$(mktemp)
rm -f "$NS3_DIR/comparison_knn_summary.csv"
cd "$EM_DIR" || exit 1
$PYTHON3 temporal_veremi_compare_knn.py \
    --load-model "$KNN_MODEL" \
    --test-csv "$NS3_DIR/comparison_veremi_pairs.csv" \
    --scenario 6 \
    --attack-pct 0 \
    --output-summary "$NS3_DIR/comparison_knn_summary.csv" \
    2>&1 | grep -E "CD-KNN|Appended|ERROR|empty"
cd "$NS3_DIR" || exit 1
[ -f comparison_knn_summary.csv ] && cp comparison_knn_summary.csv "$NEW_KNN_S6"

# ── Restore full CSVs from backups and patch in new rows ─────────────────────
echo ""
echo "Patching CSVs..."

# Restore backups as base
cp "${VEREMI_CSV%.csv}_backup_${TS}.csv" "$VEREMI_CSV"
cp "${MBSM_CSV%.csv}_backup_${TS}.csv"  "$MBSM_CSV"
cp "${KNN_CSV%.csv}_backup_${TS}.csv"   "$KNN_CSV"

# Patch S2 rows
patch_csv "$VEREMI_CSV" 2 "$NEW_VEREMI_S2"
patch_csv "$MBSM_CSV"   2 "$NEW_MBSM_S2"
patch_csv "$KNN_CSV"    2 "$NEW_KNN_S2"

# Patch S6 rows
patch_csv "$VEREMI_CSV" 6 "$NEW_VEREMI_S6"
patch_csv "$MBSM_CSV"   6 "$NEW_MBSM_S6"
patch_csv "$KNN_CSV"    6 "$NEW_KNN_S6"

# Cleanup temp files
rm -f "$NEW_VEREMI_S2" "$NEW_MBSM_S2" "$NEW_KNN_S2" \
      "$NEW_VEREMI_S6" "$NEW_MBSM_S6" "$NEW_KNN_S6"

# ── Verify the patched rows ───────────────────────────────────────────────────
echo ""
echo "Verification — S2 and S6 at attack_pct=0 after patch:"
echo ""
echo "VeReMi:"
grep -E "^2,|^6," "$VEREMI_CSV" | awk -F',' '$5==0' | \
    awk -F',' '{printf "  S%-2s pct=%-3s  tp=%-6s tn=%-7s fp=%-6s fn=%-4s mcc=%-7s auroc=%s\n", $1,$5,$8,$9,$10,$11,$12,$13}'
echo ""
echo "MBSM:"
grep -E "^2,|^6," "$MBSM_CSV" | awk -F',' '$5==0' | \
    awk -F',' '{printf "  S%-2s pct=%-3s  tp=%-6s tn=%-7s fp=%-6s fn=%-4s mcc=%-7s auroc=%s\n", $1,$5,$8,$9,$10,$11,$12,$13}'
echo ""
echo "KNN:"
grep -E "^2,|^6," "$KNN_CSV" | awk -F',' '$5==0' | \
    awk -F',' '{printf "  S%-2s pct=%-3s  mcc=%-7s auroc=%s\n", $1,$5,$8,$9}'

# ── Regenerate charts ─────────────────────────────────────────────────────────
echo ""
echo "Regenerating charts..."
cd "$EM_DIR" || exit 1
$PYTHON3 generate_charts.py \
    --veremi-csv "$VEREMI_CSV" \
    --mbsm-csv   "$MBSM_CSV" \
    --knn-csv    "$KNN_CSV" \
    --out-dir    "$EM_DIR/results/charts" \
    2>&1 | tail -5
echo ""
echo "════════════════════════════════════════════════════"
echo " Done. S2 and S6 at 0% attack corrected."
echo " Charts in: $EM_DIR/results/charts/"
echo "════════════════════════════════════════════════════"
