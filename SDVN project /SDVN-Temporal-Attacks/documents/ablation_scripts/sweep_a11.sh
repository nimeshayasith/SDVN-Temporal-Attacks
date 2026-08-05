#!/bin/bash
# sweep_a11.sh
# A11 (Table 4.2): Naive Flat Re-Keying (No LKH Hierarchy), via --no_lkh=1.
# X variable: network size n in {50,100,150,200,250,300} vehicles -- 6
# equal 50-veh steps (updated 2026-08-04, was 4 points {50,100,150,200}).
# N=300 hits the exact new density trace (mobility_urban_60_300veh_density,
# generated 2026-08-04 for A4); N=250 has no dedicated trace and falls back
# to the 200veh bucket (routing.cc's case(60) 150<=N<350 bracket) -- the
# same approximate-reuse behaviour N=150 already relies on, not a new gap.
# Applicable PEMs: M12 (Trevoke), M5 (TFlowMod) -- general, no
# single-family restriction; this tests LKH revocation cost scaling, not
# attack-family detection.
#
# METRIC FIX (2026-08-04, found via smoke-test review): plot_ablations.py's
# a11() previously read t_revoke_ms, which is detection-to-first-successful-
# revocation LATENCY (pem_tau_lkh_complete - pem_first_alert_time) -- a
# scheduling artifact dependent on exactly when the first alert happens to
# land, NOT the LKH tree operation's own cost. That produced a non-
# monotonic 1990/1710/1185/1488/1691/1838ms sequence across n=50..300 that
# looked like noise but was actually just measuring the wrong thing. Added
# a new dedicated column, lkh_crypto_mean_ms (mean of
# g_pem_lkh_crypto_stats, the real CryptoMeasureLKH/TimedLkhRevoke wall-
# clock cost, previously stdout-only) -- confirmed this shows a clean,
# monotonically increasing O(log n)-consistent trend (0.027->0.19ms across
# the same n=50..300 range), exactly what A11 is meant to demonstrate.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13 -- see
# sweep_a1.sh's comment for the full rationale. Uses attack_scenario=2
# (TTW-S2, RSU-present) as the representative -- revocation needs an actual
# attack/alert to trigger, and RSU infrastructure needs to be present for
# LKH group re-keying to have peers to re-key.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a11"
mkdir -p "$OUT"
cd "$NS3_DIR"

for N in 50 100 150 200 250 300; do
  echo "=== a11 N_Vehicles=$N ==="
  ISO="$OUT/n${N}"
  mkdir -p "$ISO"
  "$BIN" --simTime=310 --N_Vehicles=${N} --N_RSUs=64 --N_Controllers=4 --attack_scenario=2 --attack_percentage=60 --RngRun=1 --no_lkh=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=${ISO} > /dev/null 2>&1
  rm -rf "${ISO}/PCAP_FILES" "${ISO}/XML"
done

echo "=== a11 sweep complete ==="
