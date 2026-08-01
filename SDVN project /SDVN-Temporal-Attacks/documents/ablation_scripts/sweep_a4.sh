#!/bin/bash
# sweep_a4.sh
# A4 (Table 4.2): vehicle density lambda in {0.01, 0.02, 0.04} veh/m.
# Maps to N_Vehicles in {100, 200, 400} per routing.cc's own
# kNetworkRoadLengthEstimateM=9674m calibration (N=200 <-> lambda~=0.0207,
# the paper's reference point). Each N uses its own genuinely-simulated
# SUMO trace at the same 60 km/h default speed (mobility_urban_60_100veh_
# density.tcl / _200veh.tcl / _60_400veh_density.tcl), not the same trace
# subsampled/reused at different N.
#
# --no_mobility_adapt=1 is A4's own on/off flag (fixes rho_max/W to static
# constants instead of calibrating from real density) — included so this
# sweep directly answers A4's stated question: "is mobility-adaptive
# threshold computation necessary as density varies, or does a fixed
# operational point suffice?"
#
# N=400 is genuinely heavier (larger PBFT consensus, more events) — no
# internal timeout here; let it run as long as it needs.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. M4 (PIR) is ME-specific, so
# this uses attack_scenario=9 (ME-S1) as the representative scenario.

set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a4"
mkdir -p "$OUT"
cd "$NS3_DIR"

for N in 100 200 400; do
  echo "=== a4 N_Vehicles=$N (lambda proxy) ==="
  ISO="$OUT/n${N}"
  mkdir -p "$ISO"
  "$BIN" --simTime=310 --N_Vehicles=${N} --N_RSUs=0 --N_Controllers=4 --attack_scenario=9 --attack_percentage=60 --RngRun=1 --no_mobility_adapt=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=${ISO} > /dev/null 2>&1
  rm -rf "${ISO}/PCAP_FILES" "${ISO}/XML"
done

echo "=== a4 sweep complete ==="
