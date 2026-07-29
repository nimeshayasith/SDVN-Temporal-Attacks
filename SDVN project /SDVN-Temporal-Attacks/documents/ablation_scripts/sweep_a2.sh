#!/bin/bash
# sweep_a2.sh
# A2 (Table 4.2): FS/TGN Detection Stage Only (--no_lw=1). X variable: attack
# injection rate rinj in {1%, 5%, 10%}. Same PDF-scope rationale as sweep_a1.sh
# -- applicable PEMs are M3 (TTW/BSHH) AND M4 (ME), no single-family
# restriction -- so this uses attack_scenario=13 (combined) instead of
# sc1/sc5/sc9 separately.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_170m_dim192_pw0.3191_seed5.bin"
OUT="$HOME/ablation_sweep/a2"
mkdir -p "$OUT"
cd "$NS3_DIR"

# FIX (audit 2026-07-26): X must be rinj, not attack_percentage -- see sweep_a1.sh.
for X in 0.01 0.05 0.10; do
  echo "=== a2 scenario=13 rinj=${X} ==="
  ISO="$OUT/sc13_rinj${X}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --RngRun=1 --no_lw=1 --attack_percentage=60 --rinj=${X} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a2 sweep complete ==="
