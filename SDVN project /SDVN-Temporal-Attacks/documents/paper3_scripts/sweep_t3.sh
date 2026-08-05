#!/bin/bash
# sweep_t3.sh
# T3 (Paper 3, TETA-GUARD): System-Level Ablation -- three SYSTEM variants,
# not component variants (that's the Elsevier papers' job, A1-A14).
#
# FULL: no flags, complete TETA-GUARD (LW+TGN detection, full PQC +
#   location-binding + blockchain forensic+enforcement).
#
# DETECT-ONLY: LW+TGN detection stays fully active (default, no --no_lw/
#   --no_tgn). Enforcement (FlowMod/LKH revoke/failover/trust-update writes)
#   is withheld for the ENTIRE run via --mitigation_delay_intervals=99999
#   (99999 * T_b=0.1s = 9999.9s, exceeds any realistic simTime) -- reuses
#   the SAME A8 grace-window mechanism (PemInEnforcementGraceWindow /
#   PemApplyMitigation's forensic-active/enforcement-withheld gate,
#   routing.cc:4384) already verified to keep PBFT consensus + threshold-sig
#   verification + ledger logging running to completion while withholding
#   only the enforcement half -- here used as a PERMANENT withhold rather
#   than A8's k-interval sweep. T_revoke/T_reassign will be N/A (no
#   enforcement ever fires) per the spec -- read as -1/sentinel in the CSV,
#   report as N/A in the table, not as a missing-data bug.
#
# CRYPTO-ONLY: --no_lw=1 --no_tgn=1 (both detection engines off). PQC
#   (hybrid KEM), location-binding quorum, threshold aggregate signatures,
#   and blockchain (forensic+enforcement) all stay at their defaults
#   (active). Per the spec, behavioral/insider attacks that bypass crypto
#   checks are expected to show low MCC here -- this is the intended,
#   demonstrated result, not a bug to chase.
#
# Runs across all 12 isolated attack scenarios (not attack_scenario=13 --
# T3's own spec says "across all 12 attack scenarios", matching the
# Elsevier per-scenario methodology, unlike T1/T2 which are deliberately
# concurrent/joint).
#
# TGN CHECKPOINT FIX (2026-08-05): switched from tgn_weights_WBPTT50.bin to
# tgn_weights_sc1_12_capped_RETRAIN.bin -- both are sc1-12 models (WBPTT50
# confirmed trained on the same training_data_sc1_12_capped_170m.csv from
# its own training log, so the ablations that already used WBPTT50 were not
# mismatched), but this script uses the newer, explicitly-designated
# checkpoint for Paper 3's own experiments per project decision, distinct
# from the Elsevier ablations which already used WBPTT50 correctly.
#
# NOT YET RUN -- ablation sweeps (A1-A14) are using the machine.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_weights_sc1_12_capped_RETRAIN.bin"
OUT="$HOME/ablation_sweep/t3"
SIMTIME="${SIMTIME:-310}"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [1]=0 [2]=64 [3]=0 [4]=64 [5]=0 [6]=64 [7]=0 [8]=64 [9]=0 [10]=64 [11]=0 [12]=64 )

for SC in 1 2 3 4 5 6 7 8 9 10 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}

  echo "=== T3 FULL sc=${SC} ==="
  ISO="$OUT/full_sc${SC}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

  echo "=== T3 DETECT-ONLY sc=${SC} ==="
  ISO="$OUT/detectonly_sc${SC}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --mitigation_delay_intervals=99999 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"

  echo "=== T3 CRYPTO-ONLY sc=${SC} ==="
  ISO="$OUT/cryptoonly_sc${SC}"
  mkdir -p "$ISO"
  "$BIN" --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --RngRun=1 --no_lw=1 --no_tgn=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > "$ISO/run.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== T3 sweep complete ==="
