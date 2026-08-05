#!/bin/bash
# calibrate_theta_fs.sh
#
# TGN Stage-2 decision threshold (theta_fs / TGN_THETA_FS, tgn_core.cc)
# calibration sweep. X variable: theta_fs in {0.00, 0.05, 0.10, ..., 1.00}
# -- 21 equal 0.05 steps, full [0,1] range. For EACH theta_fs value, all 12
# attack scenarios are run SEQUENTIALLY (so that value's own pooled
# tp/tn/fp/fn/mcc can be aggregated across the full 12-scenario set, not
# just one representative per family -- this is a real calibration sweep,
# not a per-family ablation probe). theta_fs is baked into the run itself
# via --tgn_theta=<value>, so TGN's alert decision during the simulation
# genuinely uses that threshold -- this is NOT a post-hoc reanalysis of
# stored scores from a single fixed-theta run.
#
# Concurrency model (per explicit instruction): up to 11 theta_fs VALUES
# run in parallel; INSIDE one theta_fs value, its 12 scenarios run
# strictly sequentially (one at a time). As soon as one theta_fs value's
# full 12-scenario sequential run finishes, the next remaining theta_fs
# value from the queue immediately starts (job-pool refill), rather than
# waiting for the whole batch of 11 to finish together. Implemented via
# `xargs -P 11`, which is exactly this refill-on-completion pool
# semantics (not a fixed batch-of-11-then-batch-of-10 split).
#
# simTime=60 (per instruction, not the production 310s), attack_percentage=40.
#
# This script only CREATES the calibration run -- it does not analyze
# results. After it completes, pool TGN_EVENTS/*.csv's tgn_score + is_attack
# columns per theta_fs directory (same analytical-sweep methodology already
# used for the PEM_WEIGHTS/theta_LW recalibration) to find the empirically
# best theta_fs, rather than trusting any single run's on-the-fly
# TGN_SUMMARY confusion matrix in isolation.
#
# Per explicit instruction: DO NOT RUN THIS SCRIPT -- created for review /
# manual invocation only.

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT_ROOT="$HOME/theta_fs_sweep"
mkdir -p "$OUT_ROOT"
cd "$NS3_DIR"

# RSU presence per scenario -- same convention as sweep_a9/a10/a12/a14.sh:
# even-numbered scenarios (S2/S4 per family) are RSU-present (64), odd
# (S1/S3 per family) are RSU-less (0). Inline case/lookup, NOT an
# associative array: bash associative arrays cannot be exported into the
# subshells xargs -P spawns for run_theta (export -A is not a real bash
# construct -- an earlier draft of this script tried it and it silently
# produces an empty/unset N_RSUs in every worker subshell). A plain
# function using `case` needs no export beyond `export -f`.
rsu_for_scenario() {
  case "$1" in
    2|4|6|8|10|12) echo 64 ;;
    *)             echo 0  ;;
  esac
}
export -f rsu_for_scenario

run_theta() {
  local THETA="$1"
  local TDIR="$OUT_ROOT/theta_${THETA}"
  mkdir -p "$TDIR"
  echo "=== theta_fs=${THETA} STARTING (12 scenarios, sequential) ==="
  for SC in 1 2 3 4 5 6 7 8 9 10 11 12; do
    local NRSU
    NRSU=$(rsu_for_scenario "$SC")
    echo "=== theta_fs=${THETA} scenario=${SC} (N_RSUs=${NRSU}) ==="
    local ISO="$TDIR/sc${SC}"
    mkdir -p "$ISO"
    "$BIN" --simTime=60 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 \
      --attack_scenario=${SC} --attack_percentage=40 --RngRun=1 \
      --skip_npfads=true --skip_logs=1 \
      --tgn_weights=$TGN --tgn_theta=${THETA} \
      --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
  echo "=== theta_fs=${THETA} COMPLETE (all 12 scenarios done) ==="
}
export -f run_theta
export OUT_ROOT BIN TGN

# xargs -P 11: maintains a pool of up to 11 concurrent `run_theta` workers;
# as soon as one theta_fs value's 12-scenario sequential run finishes, the
# next remaining theta_fs value from this list is immediately dispatched
# into the freed slot -- this is the "when one finishes, start next
# remaining" refill behaviour, not a fixed batch split.
printf '%s\n' 0.00 0.05 0.10 0.15 0.20 0.25 0.30 0.35 0.40 0.45 0.50 \
              0.55 0.60 0.65 0.70 0.75 0.80 0.85 0.90 0.95 1.00 \
  | xargs -P 11 -I{} bash -c 'run_theta "$@"' _ {}

echo "=== theta_fs calibration sweep complete (all 21 values) ==="
