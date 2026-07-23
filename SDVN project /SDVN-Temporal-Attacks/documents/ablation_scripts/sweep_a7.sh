#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a7"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a7 x=1.0 ==="
mkdir -p "$OUT/x1.0"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --attack_percentage=50 --RngRun=999 --echo_dist_ratio=1.0 --output_root=$OUT/x1.0" > "$OUT/x1.0.log" 2>&1
rm -rf "$OUT/x1.0/PCAP_FILES" "$OUT/x1.0/XML"

echo "=== a7 x=1.5 ==="
mkdir -p "$OUT/x1.5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --attack_percentage=50 --RngRun=999 --echo_dist_ratio=1.5 --output_root=$OUT/x1.5" > "$OUT/x1.5.log" 2>&1
rm -rf "$OUT/x1.5/PCAP_FILES" "$OUT/x1.5/XML"

echo "=== a7 x=3.0 ==="
mkdir -p "$OUT/x3.0"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --attack_percentage=50 --RngRun=999 --echo_dist_ratio=3.0 --output_root=$OUT/x3.0" > "$OUT/x3.0.log" 2>&1
rm -rf "$OUT/x3.0/PCAP_FILES" "$OUT/x3.0/XML"

echo "=== a7 sweep complete ==="
