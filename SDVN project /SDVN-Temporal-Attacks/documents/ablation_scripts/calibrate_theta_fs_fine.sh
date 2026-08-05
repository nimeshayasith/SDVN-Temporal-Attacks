#!/bin/bash
# calibrate_theta_fs_fine.sh
#
# Fine-grained follow-up to calibrate_theta_fs.sh's coarse 0.05-step sweep,
# which found a broad MCC plateau (0.9115-0.9136) across theta_fs in
# {0.25,0.30,0.35}, peaking at 0.25. This sweep zooms into that region at
# 0.01 resolution: theta_fs in {0.20, 0.21, 0.22, ..., 0.40} -- 21 equal
# 0.01 steps -- to pin down the true optimum inside the plateau rather than
# relying on the coarse sweep's 0.05 granularity.
#
# --no_crypto=1 --no_lw=1 (NEW vs the coarse sweep): isolates PURE TGN/FS
# detection performance for this finer calibration -- no_crypto removes the
# Stage-0 HMAC/timestamp/nonce pre-filter (so events aren't silently dropped
# before ever reaching TGN, which matters most for ME scenarios that are
# otherwise Stage-0-starved almost to zero events -- see this session's
# earlier A5/A2 findings), and no_lw disables the Stage-1 rule-based scorer
# so alert_raised reflects ONLY the TGN/FS decision at this theta_fs, not a
# combined LW-or-TGN outcome. Together these isolate exactly the quantity
# theta_fs is meant to threshold: TGN's own raw score, unconfounded by
# upstream filtering or a separate detector's alerts.
#
# theta_fs is baked into the run itself via --tgn_theta=<value>, so TGN's
# alert decision during the simulation genuinely uses that threshold --
# this is NOT a post-hoc reanalysis of stored scores from a single
# fixed-theta run.
#
# Concurrency model (same pattern as calibrate_theta_fs.sh, pool size
# updated to 12 per explicit instruction): up to 12 theta_fs VALUES run in
# parallel; INSIDE one theta_fs value, its 12 scenarios run strictly
# sequentially (one at a time). As soon as one theta_fs value's full
# 12-scenario sequential run finishes, the next remaining theta_fs value
# from the queue immediately starts (job-pool refill via `xargs -P 12`),
# rather than waiting for the whole batch to finish together.
#
# simTime=60, attack_percentage=40 (same as the coarse sweep, for direct
# comparability).
#
# This script only CREATES the calibration run -- it does not analyze
# results. Output goes to ~/theta_fs_sweep_fine/theta_<value>/sc<N>/,
# a SEPARATE directory from the coarse sweep's ~/theta_fs_sweep/, so
# neither run's data can collide/overwrite the other.

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT_ROOT="$HOME/theta_fs_sweep_fine"
mkdir -p "$OUT_ROOT"
cd "$NS3_DIR"

# RSU presence per scenario -- same convention as the coarse sweep. Inline
# case/lookup, NOT an associative array: bash associative arrays cannot be
# exported into the subshells xargs -P spawns (see calibrate_theta_fs.sh's
# own comment for the earlier draft that got this wrong).
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
      --no_crypto=1 --no_lw=1 \
      --skip_npfads=true --skip_logs=1 \
      --tgn_weights=$TGN --tgn_theta=${THETA} \
      --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
  echo "=== theta_fs=${THETA} COMPLETE (all 12 scenarios done) ==="
}
export -f run_theta
export OUT_ROOT BIN TGN

# xargs -P 12: maintains a pool of up to 12 concurrent `run_theta` workers;
# as soon as one theta_fs value's 12-scenario sequential run finishes, the
# next remaining theta_fs value from this list is immediately dispatched
# into the freed slot.
printf '%s\n' 0.20 0.21 0.22 0.23 0.24 0.25 0.26 0.27 0.28 0.29 0.30 \
              0.31 0.32 0.33 0.34 0.35 0.36 0.37 0.38 0.39 0.40 \
  | xargs -P 12 -I{} bash -c 'run_theta "$@"' _ {}

echo "=== theta_fs fine calibration sweep complete (all 21 values) ==="
