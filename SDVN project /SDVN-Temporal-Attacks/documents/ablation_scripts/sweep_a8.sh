#!/bin/bash
# sweep_a8.sh
# A8 (Table 4.2): No Smart Contract Mitigation (Detection Only), via
# --mitigation_delay_intervals=k (post-alert enforcement delay, k in
# {0,2,4,6,8,10} beacon intervals -- 6 equal steps, updated 2026-08-04, was
# 4 unequal points {0,1,5,10}) plus --no_blockchain=1 (the true "never
# enforced" endpoint the PDF's title describes). Applicable PEMs: M2, M3,
# M4, M6 -- general, no single-family restriction.
#
# DESIGN FIX (2026-08-04, PemApplyMitigation, routing.cc): the smart
# contract has two roles -- forensic logging (PBFT consensus + threshold-
# sig/quorum verification, alert recorded) AND FlowMod/LKH/quarantine
# enforcement. --mitigation_delay_intervals=k now keeps the forensic role
# fully ACTIVE (PBFT consensus still runs to completion, TPBFT still
# measured, the FS-MITIGATE gate result is still logged) and withholds only
# the enforcement half (Tier 1/2 FlowMod DROP, BlacklistBeacon, ME
# reroute/isolation, LKH session-key revocation, REAUTH/quarantine) for k
# beacon intervals after the first alert per attacker. Previously the k
# grace-window check ran BEFORE the PBFT block and skipped it entirely,
# silently disabling forensic logging too during the grace window --
# contradicting this ablation's own "Detection Only" title. --no_blockchain
# is untouched (still the genuine total-removal endpoint, PBFT and
# enforcement both skipped, since the PDF's own title for that flag is
# "no smart contract" full stop, not "no enforcement").
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Runs one representative
# isolated scenario per family (S1=TTW-S1, S5=BSHH-S1, S9=ME-S1) at each k
# value plus the no_blockchain endpoint.
#
# METRIC FIX (2026-08-04, found via smoke-test review): plot_ablations.py's
# a8() previously read pdr_post_mitigation_pct, which averages PDR over the
# ENTIRE remaining run once the first alert fires (often 40+ seconds even
# at 60s smoke scale) -- a mere k*0.1s grace window's damage gets diluted
# into invisibility inside that much longer average, confirmed empirically
# flat at 100.0/0.0 for every k AND no_blockchain. Added a new dedicated
# CSV column, pdr_during_grace_pct (PemComputeRealRoutingPdr +
# PemInEnforcementGraceWindow, routing.cc), scoped ONLY to the k-interval
# window itself -- -1.0 sentinel when k=0 (no window) or no attack has
# fired yet, so it's distinguishable from a genuine 0%.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a8"
mkdir -p "$OUT"
cd "$NS3_DIR"

for SC in 1 5 9; do
  for K in 0 2 4 6 8 10; do
    echo "=== a8 scenario=${SC} x=${K} ==="
    ISO="$OUT/sc${SC}_x${K}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=${K} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done

  echo "=== a8 scenario=${SC} no_blockchain (Detection Only, true endpoint) ==="
  ISO="$OUT/sc${SC}_no_blockchain"
  mkdir -p "$ISO"
  "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_blockchain=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a8 sweep complete ==="
