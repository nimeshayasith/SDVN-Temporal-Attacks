#!/bin/bash
# sweep_comparison_veremi.sh
# Runs routing.cc with --comparison_detector=1 (VeReMi/VREM_Detect, via the
# embedded comparison_detector.h) across all 13 scenarios x 6 attack
# percentages, at the SAME topology as our own method (N_Vehicles=200,
# N_RSUs=64, N_Controllers=4). Each run simultaneously produces:
#   - comparison_veremi_summary.csv  (appended across runs — VeReMi MCC)
#   - comparison_veremi_pairs.csv    (overwritten each run — copied out below,
#                                      used later by knn_bagging_detector.py)
#   - PEM_RUN_SUMMARY/<scenario>_seed999.csv (our own method's MCC, same run)
#
# NOTE: comparison_veremi_summary.csv/pairs.csv are bare relative paths (not
# --output_root aware) — do NOT run this in parallel with itself or with the
# MBSM sweep against the same cwd; run this script and sweep_comparison_mbsm.sh
# in two SEPARATE terminals only (they write different filenames, so those two
# are safe to run concurrently with each other).

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/comparison_sweep/veremi"
mkdir -p "$OUT/pairs" "$OUT/pem_our_method"

cd "$NS3_DIR"

PCTS="0 20 40 60 80 100"

for SC in 4 5 6 7 8 9 10 11 12 13; do
  for PCT in $PCTS; do
    echo "=== VeReMi scenario=$SC pct=$PCT ==="
    ISO="$OUT/pem_our_method/sc${SC}_p${PCT}"
    mkdir -p "$ISO"
    ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=$SC --attack_percentage=$PCT --RngRun=999 --comparison_detector=1 --output_root=$ISO" \
      > "$OUT/log_sc${SC}_p${PCT}.log" 2>&1

    # comparison_veremi_pairs.csv is truncated fresh each run (bare relative
    # path) — copy it out immediately before the next run overwrites it.
    if [ -f "comparison_veremi_pairs.csv" ]; then
      cp "comparison_veremi_pairs.csv" "$OUT/pairs/pairs_sc${SC}_p${PCT}.csv"
    fi
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

# Final accumulated summary (all 78 rows: 13 scenarios x 6 pcts)
cp "$NS3_DIR/comparison_veremi_summary.csv" "$OUT/comparison_veremi_summary_ALL.csv"
echo ""
echo "=== VeReMi sweep complete ==="
echo "Summary : $OUT/comparison_veremi_summary_ALL.csv"
echo "Pairs   : $OUT/pairs/pairs_sc<N>_p<PCT>.csv"
echo "Ours    : $OUT/pem_our_method/sc<N>_p<PCT>/PEM_RUN_SUMMARY/"
