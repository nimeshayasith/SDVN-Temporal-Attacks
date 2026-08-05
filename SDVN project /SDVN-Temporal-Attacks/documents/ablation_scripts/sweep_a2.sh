#!/bin/bash
# sweep_a2.sh
# A2 (Table 4.2): FS/TGN Detection Stage Only (--no_lw=1). X variable: attack
# injection rate rinj in {0%,20%,40%,60%,80%,100%} -- 6 equal steps
# (updated 2026-08-04, was 3 unequal points {1%,5%,10%}). Same PDF-scope
# rationale as sweep_a1.sh -- applicable PEMs are M3 (TTW/BSHH) AND M4 (ME),
# no single-family restriction.
#
# UPDATED (dropped combined mode): see sweep_a1.sh's comment for the full
# rationale -- attack_scenario=13 was never a PDF requirement. Runs one
# representative isolated scenario per family (S1=TTW-S1, S5=BSHH-S1,
# S9=ME-S1) at each rinj value.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a2"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [1]=0 [5]=0 [9]=0 )

for SC in 1 5 9; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 0.0 0.2 0.4 0.6 0.8 1.0; do
    echo "=== a2 scenario=${SC} rinj=${X} ==="
    ISO="$OUT/sc${SC}_rinj${X}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --RngRun=1 --no_lw=1 --attack_percentage=60 --rinj=${X} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a2 sweep complete ==="
