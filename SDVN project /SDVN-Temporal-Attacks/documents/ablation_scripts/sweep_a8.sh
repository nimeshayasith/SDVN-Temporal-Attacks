#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a8"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a8 x=0 ==="
mkdir -p "$OUT/x0"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --mitigation_delay_intervals=0 --output_root=$OUT/x0" > "$OUT/x0.log" 2>&1
rm -rf "$OUT/x0/PCAP_FILES" "$OUT/x0/XML"

echo "=== a8 x=1 ==="
mkdir -p "$OUT/x1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --mitigation_delay_intervals=1 --output_root=$OUT/x1" > "$OUT/x1.log" 2>&1
rm -rf "$OUT/x1/PCAP_FILES" "$OUT/x1/XML"

echo "=== a8 x=5 ==="
mkdir -p "$OUT/x5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --mitigation_delay_intervals=5 --output_root=$OUT/x5" > "$OUT/x5.log" 2>&1
rm -rf "$OUT/x5/PCAP_FILES" "$OUT/x5/XML"

echo "=== a8 x=10 ==="
mkdir -p "$OUT/x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --mitigation_delay_intervals=10 --output_root=$OUT/x10" > "$OUT/x10.log" 2>&1
rm -rf "$OUT/x10/PCAP_FILES" "$OUT/x10/XML"

echo "=== a8 sweep complete ==="
