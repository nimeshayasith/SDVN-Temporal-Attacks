#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/ablation_sweep/a2"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a2 scenario=1 x=1 ==="
mkdir -p "$OUT/sc1_x1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --RngRun=999 --no_lw=1 --attack_percentage=1 --output_root=$OUT/sc1_x1" > "$OUT/sc1_x1.log" 2>&1
rm -rf "$OUT/sc1_x1/PCAP_FILES" "$OUT/sc1_x1/XML"

echo "=== a2 scenario=1 x=5 ==="
mkdir -p "$OUT/sc1_x5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --RngRun=999 --no_lw=1 --attack_percentage=5 --output_root=$OUT/sc1_x5" > "$OUT/sc1_x5.log" 2>&1
rm -rf "$OUT/sc1_x5/PCAP_FILES" "$OUT/sc1_x5/XML"

echo "=== a2 scenario=1 x=10 ==="
mkdir -p "$OUT/sc1_x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --RngRun=999 --no_lw=1 --attack_percentage=10 --output_root=$OUT/sc1_x10" > "$OUT/sc1_x10.log" 2>&1
rm -rf "$OUT/sc1_x10/PCAP_FILES" "$OUT/sc1_x10/XML"

echo "=== a2 scenario=5 x=1 ==="
mkdir -p "$OUT/sc5_x1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --RngRun=999 --no_lw=1 --attack_percentage=1 --output_root=$OUT/sc5_x1" > "$OUT/sc5_x1.log" 2>&1
rm -rf "$OUT/sc5_x1/PCAP_FILES" "$OUT/sc5_x1/XML"

echo "=== a2 scenario=5 x=5 ==="
mkdir -p "$OUT/sc5_x5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --RngRun=999 --no_lw=1 --attack_percentage=5 --output_root=$OUT/sc5_x5" > "$OUT/sc5_x5.log" 2>&1
rm -rf "$OUT/sc5_x5/PCAP_FILES" "$OUT/sc5_x5/XML"

echo "=== a2 scenario=5 x=10 ==="
mkdir -p "$OUT/sc5_x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --RngRun=999 --no_lw=1 --attack_percentage=10 --output_root=$OUT/sc5_x10" > "$OUT/sc5_x10.log" 2>&1
rm -rf "$OUT/sc5_x10/PCAP_FILES" "$OUT/sc5_x10/XML"

echo "=== a2 scenario=9 x=1 ==="
mkdir -p "$OUT/sc9_x1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --RngRun=999 --no_lw=1 --attack_percentage=1 --output_root=$OUT/sc9_x1" > "$OUT/sc9_x1.log" 2>&1
rm -rf "$OUT/sc9_x1/PCAP_FILES" "$OUT/sc9_x1/XML"

echo "=== a2 scenario=9 x=5 ==="
mkdir -p "$OUT/sc9_x5"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --RngRun=999 --no_lw=1 --attack_percentage=5 --output_root=$OUT/sc9_x5" > "$OUT/sc9_x5.log" 2>&1
rm -rf "$OUT/sc9_x5/PCAP_FILES" "$OUT/sc9_x5/XML"

echo "=== a2 scenario=9 x=10 ==="
mkdir -p "$OUT/sc9_x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --RngRun=999 --no_lw=1 --attack_percentage=10 --output_root=$OUT/sc9_x10" > "$OUT/sc9_x10.log" 2>&1
rm -rf "$OUT/sc9_x10/PCAP_FILES" "$OUT/sc9_x10/XML"

echo "=== a2 sweep complete ==="
