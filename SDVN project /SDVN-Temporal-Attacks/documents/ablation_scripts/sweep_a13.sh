#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_dim192_final.bin"
OUT="$HOME/ablation_sweep/a13"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a13 x=10 ==="
mkdir -p "$OUT/x10"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=50 --RngRun=999 --single_kem=1 --kem_handshake_rate=10 --tgn_weights=$TGN --output_root=$OUT/x10" > "$OUT/x10.log" 2>&1
rm -rf "$OUT/x10/PCAP_FILES" "$OUT/x10/XML"

echo "=== a13 x=50 ==="
mkdir -p "$OUT/x50"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=50 --RngRun=999 --single_kem=1 --kem_handshake_rate=50 --tgn_weights=$TGN --output_root=$OUT/x50" > "$OUT/x50.log" 2>&1
rm -rf "$OUT/x50/PCAP_FILES" "$OUT/x50/XML"

echo "=== a13 x=100 ==="
mkdir -p "$OUT/x100"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=50 --RngRun=999 --single_kem=1 --kem_handshake_rate=100 --tgn_weights=$TGN --output_root=$OUT/x100" > "$OUT/x100.log" 2>&1
rm -rf "$OUT/x100/PCAP_FILES" "$OUT/x100/XML"

echo "=== a13 x=200 ==="
mkdir -p "$OUT/x200"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=50 --RngRun=999 --single_kem=1 --kem_handshake_rate=200 --tgn_weights=$TGN --output_root=$OUT/x200" > "$OUT/x200.log" 2>&1
rm -rf "$OUT/x200/PCAP_FILES" "$OUT/x200/XML"

echo "=== a13 sweep complete ==="
