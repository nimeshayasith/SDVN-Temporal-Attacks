#!/bin/bash
# Resumes sweep_comparison_mbsm.sh from scenario=6 pct=40 onward
# (scenarios 1-5 complete, scenario 6 pct=0/20 already done).
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
OUT="$HOME/comparison_sweep/mbsm"
mkdir -p "$OUT/pem_our_method"

cd "$NS3_DIR"

for PCT in 40 60 80 100; do
  echo "=== MBSM scenario=6 pct=$PCT ==="
  ISO="$OUT/pem_our_method/sc6_p${PCT}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=6 --attack_percentage=$PCT --RngRun=999 --comparison_detector=2 --output_root=$ISO" \
    > "$OUT/log_sc6_p${PCT}.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

for SC in 7 8 9 10 11 12 13; do
  for PCT in 0 20 40 60 80 100; do
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
echo "=== MBSM resume complete ==="
