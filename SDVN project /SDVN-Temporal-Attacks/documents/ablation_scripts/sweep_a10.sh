#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a10"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a10 x=0.0 ==="
mkdir -p "$OUT/x0.0"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --detector_fp_rate=0.0 --output_root=$OUT/x0.0" > "$OUT/x0.0.log" 2>&1
rm -rf "$OUT/x0.0/PCAP_FILES" "$OUT/x0.0/XML"

echo "=== a10 x=0.02 ==="
mkdir -p "$OUT/x0.02"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --detector_fp_rate=0.02 --output_root=$OUT/x0.02" > "$OUT/x0.02.log" 2>&1
rm -rf "$OUT/x0.02/PCAP_FILES" "$OUT/x0.02/XML"

echo "=== a10 x=0.05 ==="
mkdir -p "$OUT/x0.05"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --detector_fp_rate=0.05 --output_root=$OUT/x0.05" > "$OUT/x0.05.log" 2>&1
rm -rf "$OUT/x0.05/PCAP_FILES" "$OUT/x0.05/XML"

echo "=== a10 sweep complete ==="
