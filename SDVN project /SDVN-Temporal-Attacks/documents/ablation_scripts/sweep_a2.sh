#!/bin/bash
# sweep_a2.sh
# A2 (Table 4.2): FS/TGN Detection Stage Only (--no_lw=1). X variable: attack
# injection rate rinj in {1%, 5%, 10%}. Same PDF-scope rationale as sweep_a1.sh
# -- applicable PEMs are M3 (TTW/BSHH) AND M4 (ME), no single-family
# restriction -- so this uses attack_scenario=13 (combined) instead of
# sc1/sc5/sc9 separately.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_dim192_final.bin"
OUT="$HOME/ablation_sweep/a2"
mkdir -p "$OUT"
cd "$NS3_DIR"

for X in 1 5 10; do
  echo "=== a2 scenario=13 x=${X} ==="
  ISO="$OUT/sc13_x${X}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --RngRun=999 --no_lw=1 --attack_percentage=${X} --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a2 sweep complete ==="
