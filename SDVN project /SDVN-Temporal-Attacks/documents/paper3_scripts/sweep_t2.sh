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
# Attack type fixed to "all-attacks" per the instructions -- uses
# attack_scenario=13 (joint concurrent, same mechanism as T1) so every
# controller-origin detection path across all three families is exercised
# simultaneously while the controller pool degrades.
#
# NOT YET RUN -- ablation sweeps (A1-A14) are using the machine.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/t2"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for NC in 0 1 2 3 4; do
  echo "=== T2 compromised_controllers=${NC} (reassignment ACTIVE, unlike A14) ==="
  ISO="$OUT/nc${NC}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --attack_percentage=60 --RngRun=1 --compromised_controllers=${NC} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== T2 sweep complete ==="
