#!/bin/bash
# sweep_t2.sh
# T2 (Paper 3, TETA-GUARD): Controller Compromise Rate Sweep.
# x = compromised controllers nC in {0,1,2,3,4} out of N_Controllers=4 --
# SAME flag as A14 (--compromised_controllers=nC) but WITHOUT
# --no_reassign=1 -- this is the deliberate opposite configuration from
# A14 (which now correctly runs WITH --no_reassign=1 to measure
# degradation-when-disabled per the Elsevier PDF's own A14 text). T2 is a
# genuinely different question: "does the failover mechanism maintain
# topology integrity as the controller pool is progressively compromised?"
# -- this requires TrustReassignController to actually run and its own
# arg-max backup search to genuinely starve as nC climbs.
#
# y = TDRR, T_trust, T_reassign (already-existing PEM_RUN_SUMMARY columns
# tdrr_pct, t_trust_ms, t_reassign_ms -- no new instrumentation needed).
#
# SCENARIO SCOPE FIX (2026-08-05): previously used attack_scenario=13
# (joint concurrent, all 12 scenarios at once) on the theory that this
# exercises "every controller-origin detection path... simultaneously."
# Corrected: controller compromise is only meaningful for the 6
# controller-origin scenarios (TTW-S3/S4, BSHH-S3/S4, ME-S3/S4 = attack
# scenarios 3,4,7,8,11,12) -- vehicle/RSU-origin scenarios (1,2,5,6,9,10)
# cannot be affected by controller compromise at all, so folding them into
# a joint run only adds unrelated noise to the controller-specific signal
# T2 is meant to isolate. Matches the same controller-origin scoping
# already used by A12/A14. Now loops the 6 controller-origin scenarios
# individually instead of using scenario=13.
#
# TGN CHECKPOINT FIX (2026-08-05): since this no longer uses
# attack_scenario=13, it needs the sc1-12 checkpoint
# (tgn_weights_sc1_12_capped_RETRAIN.bin), not the sc13-only one --
# matches sweep_t3.sh's checkpoint choice, for the same reason (all
# scenarios here are in the 1-12 range).
#
# NOT YET RUN -- ablation sweeps (A1-A14) are using the machine.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc1_12_capped_RETRAIN.bin"
OUT="$HOME/ablation_sweep/t2"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [3]=0 [4]=64 [7]=0 [8]=64 [11]=0 [12]=64 )

for SC in 3 4 7 8 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for NC in 0 1 2 3 4; do
    echo "=== T2 scenario=${SC} compromised_controllers=${NC} (reassignment ACTIVE, unlike A14) ==="
    ISO="$OUT/sc${SC}_nc${NC}"
    mkdir -p "$ISO"
    "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --compromised_controllers=${NC} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== T2 sweep complete ==="
