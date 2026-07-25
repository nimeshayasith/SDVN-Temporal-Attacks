#!/bin/bash
# rinj_verify_sc11.sh
# Verifies the adaptive rinj mechanism across attack_percentage in {20,40,80,100}
# for scenario 11, N_RSUs=0. Run alongside the other 12 scenario
# scripts in parallel; each runs its own 4 percentages sequentially.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_dim192_final.bin"
OUT="$HOME/rinj_verify/sc11"
mkdir -p "$OUT"
cd "$NS3_DIR"

for PCT in 20 40 80 100; do
  echo "=== sc11 pct=${PCT} ==="
  ISO="$OUT/pct${PCT}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=60 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=11 --attack_percentage=${PCT} --RngRun=999 --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  echo "sc=11 pct=${PCT} exit=$?"
done

echo "=== sc11 rinj_verify complete ==="
