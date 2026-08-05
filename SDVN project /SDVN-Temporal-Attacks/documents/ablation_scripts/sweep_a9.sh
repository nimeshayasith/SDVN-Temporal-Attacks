#!/bin/bash
# sweep_a9.sh
# A9 (Table 4.2): Equal-Weight PBFT (No Trust Weighting), via
# --equal_weight_pbft=1. X variable: Byzantine peers in active consensus
# set, fb in {0,1,2,3} -- 4 points, complete for this parameter (updated
# 2026-08-04, was {0,1,2}).
#
# CORRECTION (2026-08-04, verified against routing.cc): the real PBFT
# consensus gate in PemApplyMitigation (PemPbftConsensusGate, f =
# (n_peers-1)/3) draws peer_ids from ALL RSU_Nodes for these RSU-present
# scenarios (n_peers=64 here), NOT from TrustSelectActivePeers()'s
# TRUST_NP=8 active-peer subset -- that n_p=8 mechanism is a separate trust-
# promotion path (lines ~4899/5310) unrelated to this vote-counting loop.
# The real safety bound is therefore f=(64-1)/3=21, not 2 as an earlier
# version of this comment claimed. fb in {0,1,2,3} sits far below that real
# bound, so a flat t_trust_ms (TPBFT) across all four points is the
# CORRECT, expected result for this sweep -- 0-3 Byzantine votes out of 64
# barely move the sum_approve_tau/sum_active_tau ratio, not a bug or a
# sign the ablation isn't working. Kept at 4 points (not expanded toward
# 21) since the PDF's own X-variable for A9 is fb in {0,1,2} plus one
# failure-mode point beyond the ORIGINAL (mistaken) n_p=8 assumption, not
# a full sweep to the true 21-peer bound. Applicable PEMs: M1, M2, M12 --
# general, no single-family restriction.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. PBFT consensus needs RSU
# peers to exist for "Byzantine peer count" to mean anything, so this uses
# the RSU-present representative per family (S2=TTW-S2, S6=BSHH-S2,
# S10=ME-S2) rather than the RSU-less S1/S5/S9 used for the pure-detection
# ablations (A1/A2/A8).
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a9"
mkdir -p "$OUT"
cd "$NS3_DIR"

for SC in 2 6 10; do
  for BYZ in 0 1 2 3; do
    echo "=== a9 scenario=${SC} x=${BYZ} ==="
    ISO="$OUT/sc${SC}_x${BYZ}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --equal_weight_pbft=1 --byzantine_peer_count=${BYZ} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a9 sweep complete ==="
