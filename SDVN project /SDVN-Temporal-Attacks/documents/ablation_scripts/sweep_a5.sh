#!/bin/bash
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a5"
mkdir -p "$OUT"
cd "$NS3_DIR"

echo "=== a5 origin=veh scenario=1 ==="
mkdir -p "$OUT/veh_sc1"
"$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=60 --RngRun=1 --no_crypto=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$OUT/veh_sc1 > /dev/null 2>&1
rm -rf "$OUT/veh_sc1/PCAP_FILES" "$OUT/veh_sc1/XML"

echo "=== a5 origin=rsu scenario=2 ==="
mkdir -p "$OUT/rsu_sc2"
"$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=2 --attack_percentage=60 --RngRun=1 --no_crypto=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$OUT/rsu_sc2 > /dev/null 2>&1
rm -rf "$OUT/rsu_sc2/PCAP_FILES" "$OUT/rsu_sc2/XML"

echo "=== a5 origin=ctrl scenario=3 ==="
mkdir -p "$OUT/ctrl_sc3"
"$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=3 --attack_percentage=60 --RngRun=1 --no_crypto=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$OUT/ctrl_sc3 > /dev/null 2>&1
rm -rf "$OUT/ctrl_sc3/PCAP_FILES" "$OUT/ctrl_sc3/XML"

echo "=== a5 sweep complete ==="
