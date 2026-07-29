#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_170m_dim192_pw0.3191_seed5.bin"
OUT="$HOME/ablation_sweep/a11"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a11 N_Vehicles=50 ==="
mkdir -p "$OUT/n50"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=50 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_lkh=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/n50" > "$OUT/n50.log" 2>&1
rm -rf "$OUT/n50/PCAP_FILES" "$OUT/n50/XML"

echo "=== a11 N_Vehicles=100 ==="
mkdir -p "$OUT/n100"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=100 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_lkh=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/n100" > "$OUT/n100.log" 2>&1
rm -rf "$OUT/n100/PCAP_FILES" "$OUT/n100/XML"

echo "=== a11 N_Vehicles=150 ==="
mkdir -p "$OUT/n150"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=150 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_lkh=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/n150" > "$OUT/n150.log" 2>&1
rm -rf "$OUT/n150/PCAP_FILES" "$OUT/n150/XML"

echo "=== a11 N_Vehicles=200 ==="
mkdir -p "$OUT/n200"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_lkh=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/n200" > "$OUT/n200.log" 2>&1
rm -rf "$OUT/n200/PCAP_FILES" "$OUT/n200/XML"

echo "=== a11 sweep complete ==="
