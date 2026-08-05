#!/bin/bash
# sweep_e1.sh
# E1 (SOTA benchmark, RQ1): Joint Attack Penetration & Intensity.
# X variable: joint penetration L in {0,0.2,0.4,0.6,0.8,1.0} -- mapped to
# --attack_percentage uniformly, attack_scenario=13 (all 3 families
# concurrently, same mechanism basis as T1). Per the spec, alpha_atk(L)=L
# AND rinj(L)=L are both set equal to L, so a single --attack_percentage
# flag suffices (it already drives both the attacker-density fraction and
# the per-attacker injection rate inside routing.cc's scenario=13 blocks --
# same flag T1 uses for the same reason).
#
# Controller compromise is co-modeled: p_C=L, via --compromised_controllers
# rounded to the nearest integer out of N_Controllers=4 (0,1,1,2,3,4 for
# L=0,0.2,0.4,0.6,0.8,1.0) -- WITHOUT --no_reassign=1 (failover stays live,
# same as T2, since E1 is measuring detection+system behavior under
# escalating joint stress, not isolating a disabled-mitigation regime).
#
# Four arms per L: TETA-GUARD (comparison_detector=0) + B1 (VeReMi,
# comparison_detector=1, also feeds B2/KNN+Bagging via post-processing) +
# B3 (MBSM/TopoSleuth, comparison_detector=2). B1's csv is copied out per
# L for the separate KNN+Bagging post-process step (existing_methods/
# knn_bagging_detector.py), same pattern as sweep_t1.sh.
#
# TGN checkpoint: attack_scenario=13 throughout -> sc13-only checkpoint,
# same reasoning as sweep_t1.sh.
#
# 5 seeds per point (RngRun=1..5) per project statistics requirement.
#
# NOT YET RUN -- do not run without explicit permission. Pass SIMTIME=60
# for a quick correctness check on an idle core first.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc13_only_3seed_pooled.bin"
OUT="$HOME/ablation_sweep/e1"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A NC_FOR_L=( ["0.0"]=0 ["0.2"]=1 ["0.4"]=1 ["0.6"]=2 ["0.8"]=3 ["1.0"]=4 )

for L in 0.0 0.2 0.4 0.6 0.8 1.0; do
  PCT=$(python3 -c "print(int(${L}*100))")
  NC=${NC_FOR_L[$L]}
  for SEED in 1 2 3 4 5; do
    echo "=== E1 L=${L} seed=${SEED} -- TETA-GUARD (comparison_detector=0) ==="
    ISO="$OUT/tetaguard_L${L}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=${PCT} --compromised_controllers=${NC} --RngRun=${SEED} --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

    echo "=== E1 L=${L} seed=${SEED} -- B1 (VeReMi, comparison_detector=1) ==="
    ISO="$OUT/b1_veremi_L${L}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=${PCT} --compromised_controllers=${NC} --RngRun=${SEED} --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
    cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

    echo "=== E1 L=${L} seed=${SEED} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
    ISO="$OUT/b3_mbsm_L${L}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=${PCT} --compromised_controllers=${NC} --RngRun=${SEED} --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== E1 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_L*_seed*/comparison_veremi_pairs.csv for B2 ==="
