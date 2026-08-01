#!/bin/bash
# sweep_a3.sh
# A3 (Table 4.2): Static GCN (No Temporal Memory), via --static_gcn=1. X
# variable: observation window length Tobs in {50s, 150s, 300s}. Applicable
# PEMs: M1, M3 (TTW/BSHH only -- no ME), M9 -- so scoped to a TTW/BSHH
# representative scenario.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Uses attack_scenario=1
# (TTW-S1), matching this script's own pre-existing "sc1_tobsXX" folder
# naming, which was already the intended scenario even before this fix.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a3"
mkdir -p "$OUT"
cd "$NS3_DIR"

WARMUP=10
for TOBS in 50 150 300; do
  echo "=== a3 scenario=1 Tobs=${TOBS} ==="
  ISO="$OUT/sc1_tobs${TOBS}"
  mkdir -p "$ISO"
  "$BIN" --simTime=$((TOBS + WARMUP)) --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=60 --RngRun=1 --static_gcn=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a3 sweep complete ==="
