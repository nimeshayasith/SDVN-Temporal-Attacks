#!/bin/bash
# sweep_a13.sh
# A13 (Table 4.2): Single KEM (ML-KEM-1024 Only, No HQC-5), via
# --single_kem=1. X variable: KEM handshake rate rhs in {10,55,100,145,190}/s
# -- 5 equal 45/s steps (updated 2026-08-04, was 4 unequal points
# {10,50,100,200}). Applicable PEMs: M7 (Omega), M5 (Tpipeline, KEM
# sub-component). Per the PDF's own text: "This does not test detection
# quality (unaffected) but evaluates the latency and overhead cost" -- so
# scenario choice barely matters for this ablation.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Uses attack_scenario=2
# (TTW-S2, RSU-present -- KEM handshakes happen on the RSU/controller CSMA
# path) as the representative, matching sweep_a11.sh's reasoning.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a13"
mkdir -p "$OUT"
cd "$NS3_DIR"

for X in 10 55 100 145 190; do
  echo "=== a13 x=${X} ==="
  ISO="$OUT/x${X}"
  mkdir -p "$ISO"
  "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=2 --attack_percentage=60 --RngRun=1 --single_kem=1 --kem_handshake_rate=${X} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a13 sweep complete ==="
