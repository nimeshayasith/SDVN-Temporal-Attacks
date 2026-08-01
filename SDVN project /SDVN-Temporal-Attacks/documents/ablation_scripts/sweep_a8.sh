#!/bin/bash
# sweep_a8.sh
# A8 (Table 4.2): No Smart Contract Mitigation (Detection Only), via
# --mitigation_delay_intervals=k (post-alert enforcement delay, k in
# {0,1,5,10} beacon intervals) plus --no_blockchain=1 (the true "never
# enforced" endpoint the PDF's title describes). Applicable PEMs: M2, M3,
# M4, M6 -- general, no single-family restriction.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Runs one representative
# isolated scenario per family (S1=TTW-S1, S5=BSHH-S1, S9=ME-S1) at each k
# value plus the no_blockchain endpoint.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a8"
mkdir -p "$OUT"
cd "$NS3_DIR"

for SC in 1 5 9; do
  for K in 0 1 5 10; do
    echo "=== a8 scenario=${SC} x=${K} ==="
    ISO="$OUT/sc${SC}_x${K}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=${K} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done

  echo "=== a8 scenario=${SC} no_blockchain (Detection Only, true endpoint) ==="
  ISO="$OUT/sc${SC}_no_blockchain"
  mkdir -p "$ISO"
  "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_blockchain=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a8 sweep complete ==="
