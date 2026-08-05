#!/bin/bash
# sweep_a3.sh
# A3 (Table 4.2): Static GCN (No Temporal Memory), via --static_gcn=1. X
# variable: observation window length Tobs in {60,120,180,240,300}s -- 5
# equal 60s steps (updated 2026-08-04, was 3 unequal points
# {50s,150s,300s}). Design note: Static GCN replaces GRU but must still
# receive the same node features x_v -- the GRU hidden state h_v(t-) is
# replaced with a zero vector at every step (stateless); the pipeline is
# not broken, message passing still runs (--static_gcn=1 already
# implements exactly this). Applicable PEMs: M1, M3 (TTW/BSHH only -- no
# ME), M9 -- so scoped to a TTW/BSHH representative scenario.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Uses attack_scenario=1
# (TTW-S1), matching this script's own pre-existing "sc1_tobsXX" folder
# naming, which was already the intended scenario even before this fix.
#
# TWO-ARM COMPARISON (added 2026-08-05, found via review): this script
# previously only ran --static_gcn=1 (single arm), with nothing to contrast
# it against. Table 4.2's own A3 description says it "Tests the isolated
# contribution of temporal memory to attack detection" relative to "the full
# TGN" -- that comparison is structurally impossible without a baseline
# (temporal GRU, flag omitted) arm swept across the same Tobs range. Same
# missing-arm bug already found and fixed for A4's --no_mobility_adapt=1.
# Output now splits into tobs${T}_static/ and tobs${T}_baseline/ per Tobs.
#
# SIMTIME override: pass SIMTIME_OVERRIDE=60 to force every point to a fixed
# 60s smoke-test run (ignoring the Tobs+WARMUP formula) for fast validation
# before committing to the real Tobs-scaled sweep.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a3"
mkdir -p "$OUT"
cd "$NS3_DIR"

WARMUP=10
for TOBS in 60 120 180 240 300; do
  SIMT=${SIMTIME_OVERRIDE:-$((TOBS + WARMUP))}

  echo "=== a3 scenario=1 Tobs=${TOBS} -- static (--static_gcn=1) ==="
  ISO="$OUT/tobs${TOBS}_static"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMT} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=60 --RngRun=1 --static_gcn=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "${ISO}/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

  echo "=== a3 scenario=1 Tobs=${TOBS} -- baseline (full temporal GRU) ==="
  ISO="$OUT/tobs${TOBS}_baseline"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMT} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=1 --attack_percentage=60 --RngRun=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "${ISO}/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a3 sweep complete ==="
