#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_sc1_12_capped.bin"
OUT="$HOME/ablation_sweep/a9"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a9 x=0 ==="
mkdir -p "$OUT/x0"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --equal_weight_pbft=1 --byzantine_peer_count=0 --tgn_weights=$TGN --output_root=$OUT/x0" > "$OUT/x0.log" 2>&1
rm -rf "$OUT/x0/PCAP_FILES" "$OUT/x0/XML"

echo "=== a9 x=1 ==="
mkdir -p "$OUT/x1"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --equal_weight_pbft=1 --byzantine_peer_count=1 --tgn_weights=$TGN --output_root=$OUT/x1" > "$OUT/x1.log" 2>&1
rm -rf "$OUT/x1/PCAP_FILES" "$OUT/x1/XML"

echo "=== a9 x=2 ==="
mkdir -p "$OUT/x2"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --equal_weight_pbft=1 --byzantine_peer_count=2 --tgn_weights=$TGN --output_root=$OUT/x2" > "$OUT/x2.log" 2>&1
rm -rf "$OUT/x2/PCAP_FILES" "$OUT/x2/XML"

echo "=== a9 sweep complete ==="
