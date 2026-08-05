#!/bin/bash
# sweep_e4.sh
# E4 (SOTA benchmark, RQ5): Attack Aggressiveness Index Psi.
# Psi = fm * floor(Tburst/Tb): total false-evidence volume per attacker
# per contiguous injection episode. 4 log-spaced operating points:
#   (fm,Tburst,Psi) = (1,10s,100), (2,30s,600), (4,60s,2400), (8,120s,9600)
# via --psi_fm and --psi_tburst (routing.cc:156611-156621, confirmed wired
# g_psi_fm/g_psi_tburst_s globals).
#
# SCOPE CORRECTION vs. the original plan (which assumed attack_scenario=13
# like E1-E3): traced the actual g_psi_fm/g_psi_tburst_s call site
# (routing.cc:160069-160195) and confirmed it fires ONLY inside the TTW-S1
# scheduling block (ttw_s1_total_pairs / assignedPairs / TTW_ReplayAttack
# repeat-injection loop) -- NOT generalized to attack_scenario=13 or any
# other scenario. This is a separate, TTW-S1-specific mechanism from the
# rinj/AttackScheduleRepeatedInjection generalization used by E1-E3/A1/A2/
# A12 (routing.cc:11111-11174, which IS scenario-agnostic but answers a
# different question -- per-interval injection rate, not burst-structured
# false-evidence multiplicity). Running E4 at scenario=13 would silently
# no-op the Psi mechanism entirely (g_psi_fm's only read site never
# executes outside TTW-S1). Corrected: E4 runs attack_scenario=1 (TTW-S1,
# malicious vehicle, no RSU) exclusively, matching where Psi is actually
# implemented.
#
# alpha_atk=0.20 fixed (--attack_percentage=20, controls attacker
# fraction/pairing pool per TTW-S1's existing mechanism); rinj=1.0 within
# the burst is inherent to Psi's own fm/Tburst structure (every repeat
# slot in the burst window is used, no probabilistic skipping) so no
# separate --attack_percentage=100 override is applied here -- Psi's
# burst repeats are additive on top of the base pct=20 injection pattern,
# per the psi_fm cmd.AddValue's own "additive on top of the [rinj
# mechanism]" description (routing.cc:1991).
#
# TTW-S1 has no RSU in its own attack model -- N_RSUs=0 throughout,
# consistent with A1/A2/A12's own TTW-S1/S2 scoping pattern. TGN
# checkpoint: sc1-12 (single-scenario TTW-S1 run, not scenario=13).
#
# Three arms per (fm,Tburst): TETA-GUARD + B1(VeReMi) + B3(MBSM), same
# pattern as E1-E3.
#
# 5 seeds per point (RngRun=1..5).
#
# NOT YET RUN -- do not run without explicit permission. Pass SIMTIME=60
# for a quick correctness check on an idle core first.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc1_12_capped_RETRAIN.bin"
OUT="$HOME/ablation_sweep/e4"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A TBURST_FOR_FM=( [1]=10 [2]=30 [4]=60 [8]=120 )

for FM in 1 2 4 8; do
  TBURST=${TBURST_FOR_FM[$FM]}
  for SEED in 1 2 3 4 5; do
    echo "=== E4 fm=${FM} Tburst=${TBURST}s seed=${SEED} -- TETA-GUARD (comparison_detector=0) ==="
    ISO="$OUT/tetaguard_fm${FM}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=20 --psi_fm=${FM} --psi_tburst=${TBURST} --RngRun=${SEED} --comparison_detector=0 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

    echo "=== E4 fm=${FM} Tburst=${TBURST}s seed=${SEED} -- B1 (VeReMi, comparison_detector=1) ==="
    ISO="$OUT/b1_veremi_fm${FM}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=20 --psi_fm=${FM} --psi_tburst=${TBURST} --RngRun=${SEED} --comparison_detector=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
    cp "$NS3_DIR/comparison_veremi_pairs.csv" "$ISO/comparison_veremi_pairs.csv" 2>/dev/null || true

    echo "=== E4 fm=${FM} Tburst=${TBURST}s seed=${SEED} -- B3 (TopoSleuth/MBSM, comparison_detector=2) ==="
    ISO="$OUT/b3_mbsm_fm${FM}_seed${SEED}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=20 --psi_fm=${FM} --psi_tburst=${TBURST} --RngRun=${SEED} --comparison_detector=2 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== E4 sweep complete -- run existing_methods/knn_bagging_detector.py on each b1_veremi_fm*_seed*/comparison_veremi_pairs.csv for B2 ==="
