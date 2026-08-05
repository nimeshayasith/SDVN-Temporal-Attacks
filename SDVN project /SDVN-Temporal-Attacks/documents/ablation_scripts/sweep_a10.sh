#!/bin/bash
# sweep_a10.sh
# A10 (Table 4.2): Immediate Removal (No Quarantine Pipeline), via
# --no_quarantine=1. X variable: false-positive detection rate pFP in
# {0%, 1%, 2%, 3%, 4%, 5%} -- 6 equal 1% steps (updated 2026-08-04, was 3
# unequal points {0,2,5}). Applicable PEMs: M2, M12 -- general, no
# single-family restriction.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Uses the RSU-present
# representative per family (S2=TTW-S2, S6=BSHH-S2, S10=ME-S2), matching
# sweep_a9.sh's reasoning -- quarantine/removal is a controller/RSU-layer
# mechanism, needs RSU infrastructure present.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a10"
mkdir -p "$OUT"
cd "$NS3_DIR"

for SC in 2 6 10; do
  for X in 0.0 0.01 0.02 0.03 0.04 0.05; do
    echo "=== a10 scenario=${SC} x=${X} ==="
    ISO="$OUT/sc${SC}_x${X}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_quarantine=1 --detector_fp_rate=${X} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a10 sweep complete ==="
