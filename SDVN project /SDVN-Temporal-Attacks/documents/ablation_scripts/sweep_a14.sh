#!/bin/bash
# sweep_a14.sh
# A14 (Table 4.2): No Controller Reassignment Mechanism, via
# --compromised_controllers=nC (nC out of N_Controllers=4, X in {1,2,3}).
# Applicable PEMs explicitly span TTW-MC/BSHH-MC/ME-MC. Now covers all 6
# controller-origin scenarios (3,4,7,8,11,12), matching A12's expansion --
# --no_reassign/--compromised_controllers is wired into TrustReassignController
# and the shared trust-gate call sites already present in all 6 scenarios'
# own detection functions, so no new code needed, just wider coverage.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_sc1_12_capped.bin"
OUT="$HOME/ablation_sweep/a14"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [3]=0 [4]=64 [7]=0 [8]=64 [11]=0 [12]=64 )

for SC in 3 4 7 8 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 1 2 3; do
    echo "=== a14 scenario=${SC} x=${X} ==="
    ISO="$OUT/sc${SC}_x${X}"
    mkdir -p "$ISO"
    # FIX (audit 2026-07-26): --no_reassign=1 added -- without it
    # TrustReassignController still runs normally, so this measured ordinary
    # reassignment behavior under varying compromise count, not "No
    # Controller Reassignment Mechanism" as A14's title states.
    ./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_reassign=1 --compromised_controllers=${X} --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a14 sweep complete ==="
