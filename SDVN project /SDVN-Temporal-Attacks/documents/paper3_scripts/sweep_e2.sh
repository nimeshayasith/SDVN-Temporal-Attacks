#!/bin/bash
# sweep_e2.sh
# E2 (SOTA benchmark, RQ2): Vehicular Mobility Sweep.
# X variable: vmax in {10,60,100,140} km/h. Fixed alpha_atk=0.20,
# rinj=0.20 (--attack_percentage=20), attack_scenario=13 (joint, all 3
# families), mobility_scenario=0 (urban) -- routing.cc's own mobility
# trace-selection switch (around line 157560-157680) has case(10)/case(100)/
# case(140) EXPLICITLY commented "PDF Experiment 2 vmax sweep" and each
# points at a dedicated 200-vehicle Colombo urban trace
# (mobility_urban_{10,100,140}_200veh.tcl); case(60) is routing.cc's own
# default maxspeed and resolves to mobility_urban_60_200veh.tcl for
# N_Vehicles in [150,296). This confirms the mechanism was pre-built
# specifically for this experiment -- no new C++ needed, just drive
# --maxspeed and keep --N_Vehicles=200 so every point hits the intended
# 200-vehicle trace (verified: N_Vehicles>=100 required for the 100/140
# cases, which have no smaller-N fallback).
#
# vType speedFactor/speedDev are baked into the .tcl trace files
# themselves (SUMO-generated, not routing.cc CLI flags) -- not
# independently controllable here; the 4 dedicated traces already encode
# the paper's speedFactor=1.0/speedDev=0.0 intent structurally (fixed
# vmax per trace file, not a distribution).
#
# Four arms per vmax: TETA-GUARD + B1(VeReMi) + B3(MBSM), same pattern as
# sweep_e1.sh. TGN checkpoint: sc13-only (attack_scenario=13 throughout).
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
OUT="$HOME/ablation_sweep/e2"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for VMAX in 10 60 100 140; do
  for SEED in 1 2 3 4 5; do
    echo "=== E2 vmax=${VMAX} seed=${SEED} -- TETA-GUARD (comparison_detector=0) ==="
    ISO="$OUT/tetaguard_v${VMAX}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=${VMAX} --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

    echo "=== E2 vmax=${VMAX} seed=${SEED} -- B1 (VeReMi, comparison_detector=1) ==="
    ISO="$OUT/b1_veremi_v${VMAX}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=${VMAX} --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
    cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

    echo "=== E2 vmax=${VMAX} seed=${SEED} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
    ISO="$OUT/b3_mbsm_v${VMAX}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=${VMAX} --attack_scenario=13 --attack_percentage=20 --RngRun=${SEED} --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== E2 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_v*_seed*/comparison_veremi_pairs.csv for B2 ==="
