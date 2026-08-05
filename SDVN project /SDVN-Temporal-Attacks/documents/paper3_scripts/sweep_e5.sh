#!/bin/bash
# sweep_e5.sh
# E5 (SOTA benchmark, RQ6): Per-Variant Comparison Table.
# Single default operating point: L=0.20 (--attack_percentage=20),
# vmax=60 (routing.cc default), N_Vehicles=200 -- run across ALL 12
# isolated attack scenarios INDIVIDUALLY (disaggregated, NOT
# attack_scenario=13 -- per spec, this table exists specifically to show
# per-variant behavior, unlike E1-E4's joint/aggregate sweeps), 5 seeds,
# 4 methods each (TETA-GUARD + B1/B2/B3) "under identical simulation
# conditions" per the spec's own phrasing.
#
# RSU_FOR_SC pattern matches A12/A14/T2/T3's own per-scenario RSU
# assignment (S1/S3-family-no-RSU scenarios get N_RSUs=0, S2/S4-family
# get N_RSUs=64).
#
# TGN checkpoint: sc1-12 (single-scenario runs throughout, same as T2/T3
# -- not the sc13-only checkpoint since attack_scenario=13 is never used
# here).
#
# NOT YET RUN -- do not run without explicit permission. Pass SIMTIME=60
# for a quick correctness check on an idle core first.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc1_12_capped_RETRAIN.bin"
OUT="$HOME/ablation_sweep/e5"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [1]=0 [2]=64 [3]=0 [4]=64 [5]=0 [6]=64 [7]=0 [8]=64 [9]=0 [10]=64 [11]=0 [12]=64 )

for SC in 1 2 3 4 5 6 7 8 9 10 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for SEED in 1 2 3 4 5; do
    echo "=== E5 sc=${SC} seed=${SEED} -- TETA-GUARD (comparison_detector=0) ==="
    ISO="$OUT/tetaguard_sc${SC}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=20 --RngRun=${SEED} --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

    echo "=== E5 sc=${SC} seed=${SEED} -- B1 (VeReMi, comparison_detector=1) ==="
    ISO="$OUT/b1_veremi_sc${SC}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=20 --RngRun=${SEED} --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
    cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

    echo "=== E5 sc=${SC} seed=${SEED} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
    ISO="$OUT/b3_mbsm_sc${SC}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=20 --RngRun=${SEED} --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== E5 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_sc*_seed*/comparison_veremi_pairs.csv for B2 ==="
