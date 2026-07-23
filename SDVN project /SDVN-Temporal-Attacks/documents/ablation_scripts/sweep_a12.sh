#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a12"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a12 x=1 ==="
mkdir -p "$OUT/x1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=3 --attack_percentage=50 --RngRun=999 --no_divergence_detector=1 --attack_percentage=1 --output_root=$OUT/x1" > "$OUT/x1.log" 2>&1
rm -rf "$OUT/x1/PCAP_FILES" "$OUT/x1/XML"

echo "=== a12 x=5 ==="
mkdir -p "$OUT/x5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=3 --attack_percentage=50 --RngRun=999 --no_divergence_detector=1 --attack_percentage=5 --output_root=$OUT/x5" > "$OUT/x5.log" 2>&1
rm -rf "$OUT/x5/PCAP_FILES" "$OUT/x5/XML"

echo "=== a12 x=10 ==="
mkdir -p "$OUT/x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=3 --attack_percentage=50 --RngRun=999 --no_divergence_detector=1 --attack_percentage=10 --output_root=$OUT/x10" > "$OUT/x10.log" 2>&1
rm -rf "$OUT/x10/PCAP_FILES" "$OUT/x10/XML"

echo "=== a12 sweep complete ==="
