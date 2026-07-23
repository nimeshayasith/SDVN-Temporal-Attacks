#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a3"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a3 Tobs=50 ==="
mkdir -p "$OUT/sc1_tobs50"
./waf --run "scratch/routing --simTime=50 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --static_gcn=1 --output_root=$OUT/sc1_tobs50" > "$OUT/sc1_tobs50.log" 2>&1
rm -rf "$OUT/sc1_tobs50/PCAP_FILES" "$OUT/sc1_tobs50/XML"

echo "=== a3 Tobs=150 ==="
mkdir -p "$OUT/sc1_tobs150"
./waf --run "scratch/routing --simTime=150 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --static_gcn=1 --output_root=$OUT/sc1_tobs150" > "$OUT/sc1_tobs150.log" 2>&1
rm -rf "$OUT/sc1_tobs150/PCAP_FILES" "$OUT/sc1_tobs150/XML"

echo "=== a3 Tobs=300 ==="
mkdir -p "$OUT/sc1_tobs300"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=50 --RngRun=999 --static_gcn=1 --output_root=$OUT/sc1_tobs300" > "$OUT/sc1_tobs300.log" 2>&1
rm -rf "$OUT/sc1_tobs300/PCAP_FILES" "$OUT/sc1_tobs300/XML"

echo "=== a3 sweep complete ==="
