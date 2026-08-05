#!/bin/bash
# sweep_a14.sh
# A14 (Table 4.2): No Controller Reassignment Mechanism.
#
# CORRECTED SCOPE (2026-08-04, verified against Temporal_echo_project (31).pdf
# p.119-120): A14's actual specification is "Remove the controller
# reassignment pipeline (Eqs. 3.44-3.45)... When a controller's trust score
# drops below tau_min^C=0.30 the flagged controller remains active rather
# than being replaced." This means --no_reassign=1 must be ACTIVE for this
# ablation -- the whole point is to measure degradation with reassignment
# permanently disabled, not to watch TrustReassignController's own backup
# pool exhaust (that is Paper 3/T2's experiment, a distinct study which
# legitimately sweeps nC WITHOUT --no_reassign=1 and targets t_reassign_ms).
# The PDF: "A12 tests whether controller-origin attacks are detected; A14
# tests whether the reassignment RESPONSE is necessary once detection has
# occurred. Quantifies topology recovery degradation and reassignment
# latency when the mechanism is absent." Applicable PEMs: M1 (controller-
# origin), M2, M3 (TTW-MC/BSHH-MC), M4 (ME-MC), M12 (T_reassign)+.
#
# A previous "fix" here (now reverted) removed --no_reassign=1 on the
# mistaken theory that A14 was about backup-pool exhaustion -- that
# reasoning applies to Paper 3's T2, not to this Elsevier ablation. Restored
# --no_reassign=1 so the reassignment pipeline is genuinely disabled and
# M1-M4 topology/detection-quality degradation is what varies with nC, per
# the PDF's own wording.
#
# X variable: nC in {0,1,2,3,4} out of N_Controllers=4 -- 5 equal steps,
# full range (extended from the PDF's own un-extended {1,2,3} per project
# convention of always including 0 and n endpoints, matching A12's
# expansion). nC=0 is the genuine no-compromise baseline. nC=4 pre-flags
# to_preflag=3, verified safe against controller_Node.GetN()=4. Covers all
# 6 controller-origin scenarios (3,4,7,8,11,12), matching A12.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a14"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [3]=0 [4]=64 [7]=0 [8]=64 [11]=0 [12]=64 )

for SC in 3 4 7 8 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 0 1 2 3 4; do
    echo "=== a14 scenario=${SC} x=${X} ==="
    ISO="$OUT/sc${SC}_x${X}"
    mkdir -p "$ISO"
    # --no_reassign=1: reassignment pipeline (Eqs. 3.44-3.45) disabled per
    # A14's actual spec -- see header comment. nC's pre-flagging still
    # happens (raising trust-based detection/quarantine signal density) but
    # no backup controller is ever installed, so M1-M4 topology/detection
    # degradation is what should vary with nC here.
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --compromised_controllers=${X} --no_reassign=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a14 sweep complete ==="
