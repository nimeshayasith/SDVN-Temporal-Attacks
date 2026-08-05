#!/bin/bash
# sweep_a6.sh
# A6 (Table 4.2): No Threshold Aggregate Signature (BSHH Defence).
#
# CORRECTED DESIGN (2026-08-04, found via smoke-test review): the checklist's
# own FSR description -- "Expect FSR(f_c) = 0 for f_c < t and jumps at
# f_c = t -- this is what you are testing" -- only makes sense with the REAL
# threshold-signature check ACTIVE. The previous version of this script
# passed --no_threshold_sig=1 unconditionally, which BYPASSES
# PemVerifyThresholdSig entirely (routing.cc ~line 160752:
# "g_abl.no_threshold_sig ? true : PemVerifyThresholdSig(...)") -- making
# forgery succeed unconditionally at every fc>=1 regardless of collusion
# size, producing a flat, uninformative FSR=1 for all fc (confirmed
# empirically: fc=1..4 all showed fsr_attempts=1, fsr_success=1, no step
# function at all). --no_threshold_sig=1 REMOVED here so the real threshold
# check runs and the collusion-size sweep actually stresses it.
#
# RANGE FIX: PemVerifyThresholdSig's threshold is t = n_p/2+1 where
# n_p=kBshhS1FsrPeerBasis=8 (the same fixed 5-RSU+3-OBU Fabric committee
# size used elsewhere, routing.cc ~line 160750) -> t=5. The checklist's own
# suggested range {0,1,2,3,4} never reaches t=5, so even with the flag
# fixed it could never show the jump. Extended to {1,3,5,7,9} -- 5 equal
# steps of 2, symmetric around and including t=5 exactly, so the step
# function is actually observable in the swept data.
#
# fc=0 is no longer included (the flag fix means the "no forced collusion"
# baseline is uninteresting once threshold-sig is genuinely active --
# fc=0 trivially cannot form any claim to threshold-check at all). Starting
# at fc=1 (well below t=5) instead preserves a clean "below threshold"
# baseline while keeping 5 equal steps.
#
# Implemented via the --bshh_s1_fc=N flag (2026-07-29), which forces N
# distinct, genuinely-mutual-range attackers in BSHH-S1's round-0 pairing
# to all target one shared victim identity instead of each getting its own
# distinct victim (Eq. 3.5's Va != Vb / tau_r_Va ~= tau_r_Vb existential
# test).
#
# Scoped to scenario 5 (BSHH-S1) only: fc/Eq. 3.5 (duplicate liveness
# assertion from >=2 distinct physical senders) is BSHH-S1's own signature
# specifically -- BSHH-S2/S3/S4 use different signatures (timestamp
# regression / missing-beacon / RSU-variant) that --bshh_s1_fc has no wired
# effect on, so sweeping it across scenarios 6/7/8 wouldn't vary anything
# meaningful there.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a6"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

for FC in 1 3 5 7 9; do
  echo "=== a6 scenario=5 bshh_s1_fc=${FC} (threshold-sig ACTIVE, t=5) ==="
  ISO="$OUT/fc${FC}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --attack_percentage=60 --RngRun=1 --bshh_s1_fc=${FC} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a6 sweep complete ==="
