#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_sc1_12_capped.bin"
OUT="$HOME/ablation_sweep/a6"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a6 (f_c auto-sweep) scenario=5 ==="
mkdir -p "$OUT/sc5"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --attack_percentage=60 --RngRun=1 --no_threshold_sig=1 --tgn_weights=$TGN --output_root=$OUT/sc5" > "$OUT/sc5.log" 2>&1
rm -rf "$OUT/sc5/PCAP_FILES" "$OUT/sc5/XML"

echo "=== a6 (f_c auto-sweep) scenario=6 ==="
mkdir -p "$OUT/sc6"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=6 --attack_percentage=60 --RngRun=1 --no_threshold_sig=1 --tgn_weights=$TGN --output_root=$OUT/sc6" > "$OUT/sc6.log" 2>&1
rm -rf "$OUT/sc6/PCAP_FILES" "$OUT/sc6/XML"

echo "=== a6 (f_c auto-sweep) scenario=7 ==="
mkdir -p "$OUT/sc7"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=7 --attack_percentage=60 --RngRun=1 --no_threshold_sig=1 --tgn_weights=$TGN --output_root=$OUT/sc7" > "$OUT/sc7.log" 2>&1
rm -rf "$OUT/sc7/PCAP_FILES" "$OUT/sc7/XML"

echo "=== a6 (f_c auto-sweep) scenario=8 ==="
mkdir -p "$OUT/sc8"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=8 --attack_percentage=60 --RngRun=1 --no_threshold_sig=1 --tgn_weights=$TGN --output_root=$OUT/sc8" > "$OUT/sc8.log" 2>&1
rm -rf "$OUT/sc8/PCAP_FILES" "$OUT/sc8/XML"

echo "=== a6 sweep complete (check M11_FSR_SWEEP CSVs) ==="
