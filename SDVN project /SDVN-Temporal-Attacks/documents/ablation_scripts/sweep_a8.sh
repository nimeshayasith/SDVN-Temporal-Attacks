#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_170m_dim192_pw0.3191_seed5.bin"
OUT="$HOME/ablation_sweep/a8"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a8 x=0 ==="
mkdir -p "$OUT/x0"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x0" > "$OUT/x0.log" 2>&1
rm -rf "$OUT/x0/PCAP_FILES" "$OUT/x0/XML"

echo "=== a8 x=1 ==="
mkdir -p "$OUT/x1"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x1" > "$OUT/x1.log" 2>&1
rm -rf "$OUT/x1/PCAP_FILES" "$OUT/x1/XML"

echo "=== a8 x=5 ==="
mkdir -p "$OUT/x5"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=5 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x5" > "$OUT/x5.log" 2>&1
rm -rf "$OUT/x5/PCAP_FILES" "$OUT/x5/XML"

echo "=== a8 x=10 ==="
mkdir -p "$OUT/x10"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=10 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/x10" > "$OUT/x10.log" 2>&1
rm -rf "$OUT/x10/PCAP_FILES" "$OUT/x10/XML"

# FIX (audit 2026-07-26): the PDF's A8 title ("Disable...smart contract
# execution...no enforcement") describes full removal, distinct from a
# bounded k-interval delay. Add the true "Detection Only, never enforced"
# endpoint via --no_blockchain=1 so this ablation actually reaches what its
# title claims, alongside the existing k-sweep (which stays as its own
# valid delay-sensitivity curve).
echo "=== a8 no_blockchain (Detection Only, true endpoint) ==="
mkdir -p "$OUT/no_blockchain"
./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --no_blockchain=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$OUT/no_blockchain" > "$OUT/no_blockchain.log" 2>&1
rm -rf "$OUT/no_blockchain/PCAP_FILES" "$OUT/no_blockchain/XML"

echo "=== a8 sweep complete ==="
