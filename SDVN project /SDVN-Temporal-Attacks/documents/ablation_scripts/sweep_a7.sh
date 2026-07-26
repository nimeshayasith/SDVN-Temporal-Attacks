#!/bin/bash
# sweep_a7.sh
# A7 (Table 4.2): No Location-Binding + Quorum (ME Defence), via
# --echo_dist_ratio (echo-reporter distance from claimed link, ratio of
# r_comm, X in {1.0, 1.5, 3.0}). PDF scopes this to the ME defence
# specifically -- now covers all 4 ME variants (9=ME-S1, 10=ME-S2, 11=ME-S3,
# 12=ME-S4), matching A6's existing all-4-BSHH-variant pattern, instead of
# ME-S1 only. The --echo_dist_ratio reorder hook (MeReorderEchoCandidatesBy
# DistanceRatio) is now wired into all 4 ME scheduling blocks, not just
# ME-S1 -- confirmed firing via smoke test on sc10/11/12 before this sweep
# was expanded.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_sc1_12_capped.bin"
OUT="$HOME/ablation_sweep/a7"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [9]=0 [10]=64 [11]=0 [12]=64 )

for SC in 9 10 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 1.0 1.5 3.0; do
    echo "=== a7 scenario=${SC} x=${X} ==="
    ISO="$OUT/sc${SC}_x${X}"
    mkdir -p "$ISO"
    # FIX (audit 2026-07-26): --no_lbs=1 added -- without it the location-binding
    # +quorum defence (Eq 3.11/3.29/3.32) stays fully active and echo_dist_ratio
    # only reorders candidates against an intact defence, not an ablated one.
    ./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_lbs=1 --echo_dist_ratio=${X} --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a7 sweep complete ==="
