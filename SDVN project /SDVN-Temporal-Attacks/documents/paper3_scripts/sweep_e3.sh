#!/bin/bash
# sweep_e3.sh
# E3 (SOTA benchmark, RQ3): Network Scalability.
# X variable: N_Vehicles in {100,200,300,400}, N_RSUs=64 and
# N_Controllers=4 held FIXED across all N (per spec), alpha_atk=0.20 fixed
# so absolute attacker count scales with N (not attacker density) --
# tests the O(|W|) pipeline-cost claim as the network grows.
# attack_scenario=13 (joint, same basis as E1/E2/T1), maxspeed=60
# (routing.cc default, also A4's density-sweep speed) -- these N values
# are the EXACT same 4 points already used by A4's own density sweep
# (routing.cc:157625-157672, "lambda in {0.01,...,0.05} maps to
# N_Vehicles in {100,200,300,400,500}", each with its own genuinely-
# simulated trace at that N: mobility_urban_60_{100,200,300,400}veh
# density traces) -- no new mobility data needed, mechanism reused as-is
# with N_RSUs/N_Controllers held constant here (A4 itself may vary RSU
# count with N; E3 deliberately does not, per its own spec of isolating
# vehicle-count scaling with a fixed committee/RSU footprint).
#
# Four arms per N: TETA-GUARD + B1(VeReMi) + B3(MBSM). TGN checkpoint:
# sc13-only (attack_scenario=13 throughout).
#
# 5 seeds per point (RngRun=1..5).
#
# NOT YET RUN -- do not run without explicit permission. Pass SIMTIME=60
# for a quick correctness check on an idle core first.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc13_only_3seed_pooled.bin"
OUT="$HOME/ablation_sweep/e3"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for N in 100 200 300 400; do
  for SEED in 1 2 3 4 5; do
    echo "=== E3 N=${N} seed=${SEED} -- TETA-GUARD (comparison_detector=0) ==="
    ISO="$OUT/tetaguard_N${N}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=64 --N_Controllers=4 --maxspeed=60 --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

    echo "=== E3 N=${N} seed=${SEED} -- B1 (VeReMi, comparison_detector=1) ==="
    ISO="$OUT/b1_veremi_N${N}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=64 --N_Controllers=4 --maxspeed=60 --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
    cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

    echo "=== E3 N=${N} seed=${SEED} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
    ISO="$OUT/b3_mbsm_N${N}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=64 --N_Controllers=4 --maxspeed=60 --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== E3 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_N*_seed*/comparison_veremi_pairs.csv for B2 ==="
