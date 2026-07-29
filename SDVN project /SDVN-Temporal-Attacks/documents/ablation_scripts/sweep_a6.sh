#!/bin/bash
# sweep_a6.sh
# A6 (Table 4.2): No Threshold Aggregate Signature (BSHH Defence), via
# --no_threshold_sig=1. X variable: colluding Byzantine vehicles fc in
# {1, 2, f=2} that simultaneously claim the SAME victim identity within one
# observation window (Eq. 3.5's Va != Vb / tau_r_Va ~= tau_r_Vb existential
# test). Implemented via the new --bshh_s1_fc=N flag (2026-07-29), which
# forces N distinct, genuinely-mutual-range attackers in BSHH-S1's round-0
# pairing to all target one shared victim identity instead of each getting
# its own distinct victim -- previously this script instead looped over
# scenarios 5/6/7/8 with a fixed attacker count, never actually varying fc
# at all, which didn't match the PDF's stated X-variable.
#
# Scoped to scenario 5 (BSHH-S1) only: fc/Eq. 3.5 (duplicate liveness
# assertion from >=2 distinct physical senders) is BSHH-S1's own signature
# specifically -- BSHH-S2/S3/S4 use different signatures (timestamp
# regression / missing-beacon / RSU-variant) that --bshh_s1_fc has no wired
# effect on, so sweeping it across scenarios 6/7/8 wouldn't vary anything
# meaningful there.
#
# The third PDF value "f=2" is a formula-derived Byzantine quorum bound
# (f = floor((n_p-1)/3) with n_p=8 PBFT peers per A9's context = 2) --
# numerically identical to the literal "2" test point already covered, so
# re-running fc=2 a second time under the same RngRun=1 would just
# duplicate the first result. Two distinct runs (fc=1, fc=2) cover both
# real X-values.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_170m_dim192_pw0.3191_seed5.bin"
OUT="$HOME/ablation_sweep/a6"
mkdir -p "$OUT"
cd "$NS3_DIR"

for FC in 1 2; do
  echo "=== a6 scenario=5 bshh_s1_fc=${FC} ==="
  ISO="$OUT/fc${FC}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=300 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=5 --attack_percentage=60 --RngRun=1 --no_threshold_sig=1 --bshh_s1_fc=${FC} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a6 sweep complete ==="
