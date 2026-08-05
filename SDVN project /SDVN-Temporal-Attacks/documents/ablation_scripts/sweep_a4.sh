#!/bin/bash
# sweep_a4.sh
# A4 (Table 4.2): vehicle density lambda in {0.01, 0.02, 0.03, 0.04, 0.05}
# veh/m -- 5 equal steps (updated 2026-08-04, was 3 unequal points
# {0.01,0.02,0.04}). Maps to N_Vehicles in {100, 200, 300, 400, 500} --
# clean round numbers per explicit instruction, not the raw lambda*9674
# fractional values (which would be ~97/~194/~290/~387/~484). Each N uses
# its own genuinely-simulated SUMO trace at the same 60 km/h default speed
# (mobility_urban_60_{100,200,300,400,500}veh_density.tcl), not the same
# trace subsampled/reused at different N. The 300/500 traces were newly
# generated 2026-08-04 (randomTrips.py -> duarouter -> sumo ->
# traceExporter.py) since only 100/200/400 existed before -- see
# routing.cc's case(60) trace-selection comment for the exact recipe.
#
# --no_mobility_adapt=1 is A4's own on/off flag (fixes rho_max/W to static
# constants instead of calibrating from real density) — included so this
# sweep directly answers A4's stated question: "is mobility-adaptive
# threshold computation necessary as density varies, or does a fixed
# operational point suffice?"
#
# TWO-ARM COMPARISON (added 2026-08-04, found via review): answering A4's own
# question requires BOTH arms swept across the same density range -- adaptive
# threshold ON (baseline, flag omitted) vs fixed/OFF (--no_mobility_adapt=1).
# A single-arm sweep (fixed-only, the previous version of this script) cannot
# demonstrate necessity -- there is nothing to contrast the fixed-threshold
# numbers against. Output now splits into n${N}_adaptive/ and
# n${N}_fixed/ per N so plot_ablations.py's a4() can plot both series.
#
# N=400/500 are genuinely heavier (larger PBFT consensus, more events) — no
# internal timeout here; let it run as long as it needs.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale.
#
# SCENARIO FIX (2026-08-05): M4 (PIR) is ME-specific, but the PDF's Table 4.2
# A4 row does not name a specific ME variant -- attack_scenario=9 (ME-S1) was
# a local implementation choice, not a PDF requirement. It was wrong: the
# PDF's own Table 4.10 discussion (Ch.4) states ME-S1/ME-S2 attacks are
# structurally intercepted by the Stage-0 location-binding quorum check
# (Eqs. 3.29-3.32, "eliminating vehicle-origin and RSU-origin ME vectors at
# the pre-detection filter layer") before ever reaching Stage-1, where
# rho_max/delta_max (what --no_mobility_adapt freezes) actually operate --
# confirmed even at the PDF's own full 300s/2361-event corpus, ruling out
# "just run longer" as a fix. Only ME-S3/ME-S4 (controller-origin, no
# network-layer packet for the crypto filter to intercept) reach Stage-1.
# Switched to attack_scenario=11 (ME-S3, no RSU -- matches this sweep's
# existing N_RSUs=0) so mean_pir can actually reflect the adaptive/fixed
# threshold difference this ablation is meant to test.
#
# BEACONING FIX (2026-08-05): --enable_neighborhood_beaconing=1 added to both
# arms. Without it, g_rsu_beacon_log (PemComputeLambdaHat's only data source)
# stays empty for the whole run, so lambda_hat=0 always -> the "adaptive"
# rho_max/delta_max floor to their hard minimums (2 and 1) regardless of
# N_Vehicles -- the adaptive arm was never actually adaptive. PDF Eq. 3.8's
# own text requires this: "lambda_hat(t) is... updated dynamically from
# RSU-observed beacon rates at each time step" -- PemNeighborhoodDiscoveryTick
# is the (opt-in, off-by-default) mechanism that supplies exactly that feed,
# and its own comment confirms it never touches PemEmitEvent/PemEvaluateEvent
# or any scored counter, so enabling it does not risk the TTW/BSHH/ME
# regression previously found with the old, unrelated PemPeriodicBeaconTick
# dead code. Note per PDF Eq. 3.10's own worked examples (urban and highway),
# delta_max is expected to equal 1 "across all realistic SDVN conditions" --
# so only rho_max (Eq. 3.8, scales linearly with lambda_hat) is expected to
# actually separate between arms; delta_max/ME-S2 staying flat is not a bug.
#
# SIMTIME: pass SIMTIME=60 env var for fast test runs; defaults to the full
# 310s otherwise.

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a4"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for N in 100 200 300 400 500; do
  echo "=== a4 N_Vehicles=$N (lambda proxy) -- adaptive (baseline) ==="
  ISO="$OUT/n${N}_adaptive"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=0 --N_Controllers=4 --attack_scenario=11 --attack_percentage=60 --RngRun=1 --enable_neighborhood_beaconing=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=${ISO} > "${ISO}/run.log" 2>&1
  rm -rf "${ISO}/PCAP_FILES" "${ISO}/XML"

  echo "=== a4 N_Vehicles=$N (lambda proxy) -- fixed (--no_mobility_adapt=1) ==="
  ISO="$OUT/n${N}_fixed"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=0 --N_Controllers=4 --attack_scenario=11 --attack_percentage=60 --RngRun=1 --no_mobility_adapt=1 --enable_neighborhood_beaconing=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=${ISO} > "${ISO}/run.log" 2>&1
  rm -rf "${ISO}/PCAP_FILES" "${ISO}/XML"
done

echo "=== a4 sweep complete ==="
