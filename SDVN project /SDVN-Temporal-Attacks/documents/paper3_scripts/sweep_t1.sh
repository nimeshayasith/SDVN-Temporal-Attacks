#!/bin/bash
# sweep_t1.sh
# T1 (Paper 3, TETA-GUARD): Joint Concurrent Multi-Family Attack.
# All three attack families (TTW+BSHH+ME) active simultaneously via
# attack_scenario=13 -- verified still present and correctly wired in
# routing.cc (every "if (attack_scenario == N || attack_scenario == 13)"
# gate across all 12 per-scenario blocks fires together under 13). This
# was intentionally dropped from the Elsevier ablation scripts (A1/A2/etc
# test isolated scenarios per the PDF's own methodology) but the mechanism
# itself was never removed from routing.cc -- reused here for its actual
# intended purpose: the genuinely-new concurrent-threat experiment neither
# Elsevier paper evaluates.
#
# X variable: joint penetration L in {0,0.2,0.4,0.6,0.8,1.0} -- 6 equal
# steps, mapped to --attack_percentage (same rinj-style flag A1/A2/A12 use
# for isolated-family injection rate, applied here uniformly across all
# three concurrently-active families since attack_scenario=13 activates
# all family blocks at once).
#
# Four arms per L: TETA-GUARD (default, comparison_detector=0) + B1 (VeReMi,
# comparison_detector=1) + B2 (Mekonen KNN+Bagging, comparison_detector=1's
# CSV output post-processed by existing_methods/knn_bagging_detector.py --
# NOT a separate NS-3 flag, requires the Python step after each B1-flavoured
# run) + B3 (TopoSleuth/MBSM, comparison_detector=2).
#
# 5 seeds per point (RngRun=1..5) per the project's standard statistics
# requirement -- NOT yet reflected below (single seed placeholder); expand
# the RngRun loop before the real (non-test) run.
#
# NOT YET RUN -- ablation sweeps (A1-A14) are using the machine. Run only
# after they complete, or pass SIMTIME=60 for a quick correctness check on
# an idle core.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/t1"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for L in 0.0 0.2 0.4 0.6 0.8 1.0; do
  echo "=== T1 L=${L} -- TETA-GUARD (comparison_detector=0) ==="
  ISO="$OUT/tetaguard_L${L}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=$(python3 -c "print(int(${L}*100))") --RngRun=1 --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

  echo "=== T1 L=${L} -- B1 (VeReMi, comparison_detector=1) ==="
  ISO="$OUT/b1_veremi_L${L}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=$(python3 -c "print(int(${L}*100))") --RngRun=1 --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  # B2 (Mekonen KNN+Bagging) reuses this same run's comparison_veremi_pairs.csv --
  # post-process separately: python3 existing_methods/knn_bagging_detector.py <that csv>
  cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

  echo "=== T1 L=${L} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
  ISO="$OUT/b3_mbsm_L${L}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=$(python3 -c "print(int(${L}*100))") --RngRun=1 --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== T1 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_L*/comparison_veremi_pairs.csv for B2 ==="
