#!/bin/bash
# sweep_a12.sh
# A12 (Table 4.2): No Topology Divergence Detector (Controller-Origin Blind),
# via --no_divergence_detector=1. X variable: controller-origin injection
# rate rinj in {1%, 5%, 10%} -- "controller scenarios only" per the PDF, and
# applicable PEMs explicitly span TTW-MC/BSHH-MC/ME-MC together. Now covers
# all 6 controller-origin scenarios (3=TTW-S3, 4=TTW-S4, 7=BSHH-S3,
# 8=BSHH-S4, 11=ME-S3, 12=ME-S4), matching A6's all-4-BSHH-variant pattern,
# instead of TTW-S3 only. --no_divergence_detector gates PemController
# DivergenceGate, a function shared by all 6 of these scenarios already --
# no new code needed, just wider scenario coverage.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a12"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [3]=0 [4]=64 [7]=0 [8]=64 [11]=0 [12]=64 )

for SC in 3 4 7 8 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  # FIX (audit 2026-07-26): X must be rinj, not attack_percentage -- see sweep_a1.sh.
  for X in 0.01 0.05 0.10; do
    echo "=== a12 scenario=${SC} rinj=${X} ==="
    ISO="$OUT/sc${SC}_rinj${X}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --rinj=${X} --RngRun=1 --no_divergence_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a12 sweep complete ==="
