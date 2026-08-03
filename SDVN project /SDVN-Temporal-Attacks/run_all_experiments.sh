#!/usr/bin/env bash
# =============================================================================
# run_all_experiments.sh
# Temporal-Echo Topology Attack — Full Experimental Pipeline
#
# Runs both comparison detectors (Multi-BSM and VeReMi/KNN+Bagging) against
# all 12 attack scenarios × 11 attack percentages (0–100 % step 10) × 5 seeds.
# Trains KNN+Bagging on accumulated VeReMi pairs CSV.
# Generates MCC vs attack%, T_det vs attack%, PDR vs attack% graphs.
#
# Usage (from project root on the Linux NS-3 machine):
#   chmod +x run_all_experiments.sh
#   ./run_all_experiments.sh
#
# Optional environment overrides:
#   NS3_DIR=/path/to/ns-3.35  SRC_DIR=/path/to/project  ./run_all_experiments.sh
#
# Output structure:
#   ~/temporal_echo_results/
#     mbsm/
#       scenario_{N}/pct_{P}/seed_{S}/  ← per-run raw files
#     veremi/
#       scenario_{N}/pct_{P}/seed_{S}/
#     knn/                               ← KNN training outputs
#     plots/                             ← final graphs
#     temporal_mbsm_compare_summary_all.csv    ← aggregated across all runs
#     temporal_veremi_compare_pem_summary_all.csv
#     temporal_veremi_compare_pairs_all.csv    ← concatenated for KNN training
# =============================================================================
set -euo pipefail

# ── Configurable paths ────────────────────────────────────────────────────────
NS3_DIR="${NS3_DIR:-$HOME/ns-3.35}"
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "$0")" && pwd)}"   # directory of this script
RESULTS="${RESULTS:-$HOME/temporal_echo_results}"
PYTHON="${PYTHON:-python3}"

# ── Sweep parameters ─────────────────────────────────────────────────────────
ATTACK_PERCENTAGES=(0 10 20 30 40 50 60 70 80 90 100)
# Q49 fix (2026-08-02): was (1 2 3), inconsistent with CLAUDE.md Section 14's
# documented 5-seed experimental protocol (run_5_experiments.sh). Running
# only 3 seeds here would silently invalidate any "5-seed" claim in reported
# results even though the mean/std aggregation logic itself (per-seed MCC,
# not a pooled confusion matrix) is correct.
SEEDS=(1 2 3 4 5)
ALL_SCENARIOS=(0 1 2 3 4 5 6 7 8 9 10 11 12)   # 0 = baseline

# ── Per-scenario NS-3 parameters ─────────────────────────────────────────────
# Index = attack_scenario number
N_RSU=(0  0 1 0 1  0 1 0 1  0 1 0 1)   # [0]=baseline, [1..12]=scenarios
N_VEH=(4  4 4 4 4  4 4 4 4  6 6 6 6)
SIM_T=(45 40 40 40 40 30 30 30 30 30 30 30 30)

# ── Colour codes ─────────────────────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; N='\033[0m'

log()  { echo -e "${G}[$(date '+%H:%M:%S')]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
die()  { echo -e "${R}[ERROR]${N} $*" >&2; exit 1; }

# ── Step 0: Sanity checks ────────────────────────────────────────────────────
log "=== Temporal-Echo Experiment Pipeline ==="
log "NS3_DIR  : $NS3_DIR"
log "SRC_DIR  : $SRC_DIR"
log "RESULTS  : $RESULTS"

[ -d "$NS3_DIR" ]              || die "NS3_DIR not found: $NS3_DIR"
[ -f "$NS3_DIR/waf" ]          || die "waf not found in $NS3_DIR"
[ -f "$SRC_DIR/temporal_mbsm_compare.cc" ]   || die "temporal_mbsm_compare.cc not found in $SRC_DIR"
[ -f "$SRC_DIR/temporal_veremi_compare.cc" ] || die "temporal_veremi_compare.cc not found in $SRC_DIR"

$PYTHON -c "import sklearn, pandas, numpy, matplotlib" 2>/dev/null \
    || die "Missing Python deps — run: pip install scikit-learn pandas numpy matplotlib"

# ── Step 1: Copy source files and build ──────────────────────────────────────
log "Step 1: Copying source files to NS-3 scratch and building …"

cp -f "$SRC_DIR/temporal_mbsm_compare.cc"   "$NS3_DIR/scratch/"
cp -f "$SRC_DIR/temporal_veremi_compare.cc" "$NS3_DIR/scratch/"

cd "$NS3_DIR"
./waf build 2>&1 | grep -E "(error|warning|Build)" | head -40 || true
./waf build --check 2>&1 | grep -iE "ok|fail|error" | head -10 || true

# Quick build check — make sure binaries exist
BUILD_OK=0
for sim in temporal_mbsm_compare temporal_veremi_compare; do
    if find "$NS3_DIR/build" -name "$sim" -type f 2>/dev/null | grep -q .; then
        BUILD_OK=$((BUILD_OK+1))
    fi
done
# waf may embed both into a single debug binary; do a test run instead
if ! ./waf --run "scratch/temporal_mbsm_compare --simTime=5 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=0" > /dev/null 2>&1; then
    die "Test run of temporal_mbsm_compare failed — check waf build output"
fi
log "Build OK"

# ── Step 2: Create result directory structure ────────────────────────────────
log "Step 2: Creating directory structure under $RESULTS …"
mkdir -p "$RESULTS"/{mbsm,veremi,knn,plots}

# Remove old aggregated files so we start fresh
rm -f "$RESULTS/temporal_mbsm_compare_summary_all.csv"
rm -f "$RESULTS/temporal_veremi_compare_pem_summary_all.csv"
rm -f "$RESULTS/temporal_veremi_compare_pairs_all.csv"

TOTAL=$(( ${#ALL_SCENARIOS[@]} * ${#ATTACK_PERCENTAGES[@]} * ${#SEEDS[@]} * 2 ))
DONE=0

# ── Helper: run one simulation ───────────────────────────────────────────────
run_sim() {
    local SIM="$1"       # temporal_mbsm_compare or temporal_veremi_compare
    local SCENARIO="$2"
    local PCT="$3"
    local SEED="$4"
    local NV="${N_VEH[$SCENARIO]}"
    local NR="${N_RSU[$SCENARIO]}"
    local ST="${SIM_T[$SCENARIO]}"

    # Baseline (scenario=0): attack_percentage is irrelevant but we run only once
    # at pct=0 — skip pct>0 for scenario 0 to avoid redundant runs
    if [ "$SCENARIO" -eq 0 ] && [ "$PCT" -gt 0 ]; then
        return 0
    fi

    local OUTDIR="$RESULTS/${SIM##*_}/scenario_${SCENARIO}/pct_${PCT}/seed_${SEED}"
    mkdir -p "$OUTDIR"

    cd "$NS3_DIR"

    # Run simulation (capture stdout/stderr to log file)
    ./waf --run "scratch/$SIM \
        --simTime=${ST} \
        --N_Vehicles=${NV} \
        --N_RSUs=${NR} \
        --attack_scenario=${SCENARIO} \
        --attack_percentage=${PCT} \
        --RngRun=${SEED}" \
        > "$OUTDIR/ns3_stdout.log" 2>&1 || {
        warn "Simulation failed: $SIM scenario=$SCENARIO pct=$PCT seed=$SEED"
        return 0
    }

    # ── Collect output files ──────────────────────────────────────────────
    local STAMP="${SIM}_s${SCENARIO}_p${PCT}_r${SEED}"

    if [ "$SIM" = "temporal_mbsm_compare" ]; then
        # Summary CSV (append mode — NS-3 already appends; we copy the new line)
        [ -f temporal_mbsm_compare_summary.csv ] && {
            # Copy entire file on first seed, then just append the last data line
            if [ ! -f "$RESULTS/temporal_mbsm_compare_summary_all.csv" ]; then
                cp temporal_mbsm_compare_summary.csv "$RESULTS/temporal_mbsm_compare_summary_all.csv"
            else
                tail -1 temporal_mbsm_compare_summary.csv \
                    >> "$RESULTS/temporal_mbsm_compare_summary_all.csv"
            fi
            cp temporal_mbsm_compare_summary.csv "$OUTDIR/${STAMP}_summary.csv"
        }
        # Events CSV
        [ -f temporal_mbsm_compare_events.csv ] && \
            cp temporal_mbsm_compare_events.csv "$OUTDIR/${STAMP}_events.csv"
        # Attack log TXT
        for txt in temporal_mbsm_compare_attack*.txt; do
            [ -f "$txt" ] && cp "$txt" "$OUTDIR/${STAMP}_$(basename $txt)"
        done
        # Clean NS-3 output files so next run starts fresh
        rm -f temporal_mbsm_compare_summary.csv \
              temporal_mbsm_compare_events.csv \
              temporal_mbsm_compare_attack*.txt

    else
        # VeReMi
        [ -f temporal_veremi_compare_pem_summary.csv ] && {
            if [ ! -f "$RESULTS/temporal_veremi_compare_pem_summary_all.csv" ]; then
                cp temporal_veremi_compare_pem_summary.csv \
                   "$RESULTS/temporal_veremi_compare_pem_summary_all.csv"
            else
                tail -1 temporal_veremi_compare_pem_summary.csv \
                    >> "$RESULTS/temporal_veremi_compare_pem_summary_all.csv"
            fi
            cp temporal_veremi_compare_pem_summary.csv "$OUTDIR/${STAMP}_pem_summary.csv"
        }
        [ -f temporal_veremi_compare_pairs.csv ] && {
            # Accumulate ALL pairs for KNN training (append without repeating header)
            if [ ! -f "$RESULTS/temporal_veremi_compare_pairs_all.csv" ]; then
                cp temporal_veremi_compare_pairs.csv \
                   "$RESULTS/temporal_veremi_compare_pairs_all.csv"
            else
                tail -n +2 temporal_veremi_compare_pairs.csv \
                    >> "$RESULTS/temporal_veremi_compare_pairs_all.csv"
            fi
            cp temporal_veremi_compare_pairs.csv "$OUTDIR/${STAMP}_pairs.csv"
        }
        for txt in temporal_veremi_compare_attack*.txt; do
            [ -f "$txt" ] && cp "$txt" "$OUTDIR/${STAMP}_$(basename $txt)"
        done
        rm -f temporal_veremi_compare_pem_summary.csv \
              temporal_veremi_compare_pairs.csv \
              temporal_veremi_compare_attack*.txt
    fi
}

# ── Step 3: Run all simulations ──────────────────────────────────────────────
log "Step 3: Running simulations ($TOTAL total simulation calls) …"
log "  Scenarios: ${ALL_SCENARIOS[*]}"
log "  Percentages: ${ATTACK_PERCENTAGES[*]}"
log "  Seeds: ${SEEDS[*]}"
echo ""

for SCENARIO in "${ALL_SCENARIOS[@]}"; do
    for PCT in "${ATTACK_PERCENTAGES[@]}"; do
        for SEED in "${SEEDS[@]}"; do
            DONE=$((DONE+1))
            echo -e "${C}[${DONE}/${TOTAL}]${N} MBSM  scenario=${SCENARIO} pct=${PCT}% seed=${SEED}"
            run_sim "temporal_mbsm_compare"   "$SCENARIO" "$PCT" "$SEED"

            DONE=$((DONE+1))
            echo -e "${C}[${DONE}/${TOTAL}]${N} VeReMi scenario=${SCENARIO} pct=${PCT}% seed=${SEED}"
            run_sim "temporal_veremi_compare" "$SCENARIO" "$PCT" "$SEED"
        done
        echo ""
    done
done

log "All simulations complete."
log "Aggregated MBSM summary   : $RESULTS/temporal_mbsm_compare_summary_all.csv"
log "Aggregated VeReMi summary : $RESULTS/temporal_veremi_compare_pem_summary_all.csv"
log "Concatenated pairs CSV    : $RESULTS/temporal_veremi_compare_pairs_all.csv"

# ── Step 4: Train KNN+Bagging on accumulated VeReMi pairs ───────────────────
log "Step 4: Training KNN+Bagging (all 4 classifiers) on accumulated pairs CSV …"

cd "$RESULTS/knn"

KNN_SCRIPT="$SRC_DIR/temporal_veremi_compare_knn.py"
[ -f "$KNN_SCRIPT" ] || die "KNN script not found: $KNN_SCRIPT"
[ -f "$RESULTS/temporal_veremi_compare_pairs_all.csv" ] || {
    warn "No pairs CSV found — skipping KNN training"
    KNN_SCRIPT=""
}

if [ -n "$KNN_SCRIPT" ]; then
    $PYTHON "$KNN_SCRIPT" \
        "$RESULTS/temporal_veremi_compare_pairs_all.csv" \
        --n-estimators 10 \
        --n-neighbors  3 \
        --n-folds      5 \
        2>&1 | tee knn_training.log

    # Move outputs
    for f in temporal_compare_knn_results.csv temporal_compare_cv_results.csv \
              temporal_compare_permutation_importance.csv temporal_compare_grid_search.csv; do
        [ -f "$f" ] && mv -f "$f" "$RESULTS/knn/"
    done
    log "KNN training complete — results in $RESULTS/knn/"
fi

# ── Step 5: Generate graphs ──────────────────────────────────────────────────
log "Step 5: Generating MCC / T_det / PDR vs attack-percentage graphs …"

PLOT_SCRIPT="$SRC_DIR/plot_mcc_vs_attack_pct.py"

$PYTHON "$PLOT_SCRIPT" \
    --mbsm   "$RESULTS/temporal_mbsm_compare_summary_all.csv" \
    --veremi "$RESULTS/temporal_veremi_compare_pem_summary_all.csv" \
    --knn    "$RESULTS/knn/temporal_compare_knn_results.csv" \
    --out-dir "$RESULTS/plots/" \
    2>&1 | tee "$RESULTS/plots/plot_log.txt" || warn "Plotting script encountered an issue (check plot_log.txt)"

log "Graphs saved to $RESULTS/plots/"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${G}═══════════════════════════════════════════════════════════${N}"
echo -e "${G}  Pipeline complete.${N}"
echo -e "${G}  Results : $RESULTS${N}"
echo -e "${G}  Plots   : $RESULTS/plots/${N}"
echo -e "${G}═══════════════════════════════════════════════════════════${N}"
