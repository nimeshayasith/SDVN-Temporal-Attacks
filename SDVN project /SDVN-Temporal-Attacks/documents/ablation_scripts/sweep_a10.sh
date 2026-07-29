#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_170m_dim192_pw0.3191_seed5.bin"
OUT="$HOME/ablation_sweep/a10"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a10 x=0.0 ==="
mkdir -p "$OUT/x0.0"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_quarantine=1 --detector_fp_rate=0.0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x0.0" > "$OUT/x0.0.log" 2>&1
rm -rf "$OUT/x0.0/PCAP_FILES" "$OUT/x0.0/XML"

echo "=== a10 x=0.02 ==="
mkdir -p "$OUT/x0.02"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_quarantine=1 --detector_fp_rate=0.02 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x0.02" > "$OUT/x0.02.log" 2>&1
rm -rf "$OUT/x0.02/PCAP_FILES" "$OUT/x0.02/XML"

echo "=== a10 x=0.05 ==="
mkdir -p "$OUT/x0.05"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_quarantine=1 --detector_fp_rate=0.05 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x0.05" > "$OUT/x0.05.log" 2>&1
rm -rf "$OUT/x0.05/PCAP_FILES" "$OUT/x0.05/XML"

echo "=== a10 sweep complete ==="
