#!/bin/bash
# sweep_comparison_mbsm.sh
# Runs routing.cc with --comparison_detector=2 (MBSM_Detect, via the embedded
# comparison_detector.h) across all 13 scenarios x 6 attack percentages, at
# the SAME topology as our own method (N_Vehicles=200, N_RSUs=64,
# N_Controllers=4). Safe to run concurrently with sweep_comparison_veremi.sh
# (different filenames: comparison_mbsm_summary.csv, no pairs CSV for MBSM),
# but NOT concurrently with another copy of itself.

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/comparison_sweep/mbsm"
mkdir -p "$OUT/pem_our_method"

cd "$NS3_DIR"

PCTS="0 20 40 60 80 100"

for SC in 4 5 6 7 8 9 10 11 12 13; do
  for PCT in $PCTS; do
    echo "=== MBSM scenario=$SC pct=$PCT ==="
    ISO="$OUT/pem_our_method/sc${SC}_p${PCT}"
    mkdir -p "$ISO"
    ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=$SC --attack_percentage=$PCT --RngRun=999 --comparison_detector=2 --output_root=$ISO" \
      > "$OUT/log_sc${SC}_p${PCT}.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

cp "$NS3_DIR/comparison_mbsm_summary.csv" "$OUT/comparison_mbsm_summary_ALL.csv"
echo ""
echo "=== MBSM sweep complete ==="
echo "Summary : $OUT/comparison_mbsm_summary_ALL.csv"
echo "Ours    : $OUT/pem_our_method/sc<N>_p<PCT>/PEM_RUN_SUMMARY/"
