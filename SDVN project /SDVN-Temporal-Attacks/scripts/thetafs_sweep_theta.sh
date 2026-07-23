#!/bin/bash
# Usage: bash thetafs_sweep_theta.sh <THETA>
# Re-verifies theta_FS against the new dim=192 canonical model, matching the
# original calibration methodology exactly: N_Vehicles=200 N_RSUs=64
# N_Controllers=4 simTime=60 RngRun=999 (unseen seed), all 12 individual
# scenarios + combined scenario 13, worst-case MCC selection.
#
# --no_lw=1 ablation: LW disabled so theta_FS's effect on TGN's OWN decision
# is visible (not masked by LW's OR-combination). Bug found and fixed in
# tgn_core.cc before this version of the script: TGN's own tp/fn/mcc were
# being written to "tgn_summary.csv" (TGN_SUMMARY folder now), a bare
# relative path — PEM_RUN_SUMMARY only reflects LW's alert_raised, which is
# always 0 under --no_lw=1, so reading it here always gave tp=0/mcc=0
# regardless of theta or TGN's actual (correct) per-event detections.
THETA=$1
ISO="$HOME/theta_fs_sweep_dim192/theta_${THETA}"
mkdir -p "$ISO"
RESULTS="$HOME/theta_fs_sweep_dim192/results_theta_${THETA}.csv"
echo "attack_scenario,theta,tgn_tp,tgn_fp,tgn_fn,tgn_mcc" > "$RESULTS"

cd ~/ns-allinone-3.35/ns-3.35

declare -A NAMES=(
  [1]="01_TTW_S1_Malicious_Vehicle" [2]="02_TTW_S2_Malicious_RSU"
  [3]="03_TTW_S3_Malicious_Controller_No_RSU" [4]="04_TTW_S4_Malicious_Controller_With_RSU"
  [5]="05_BSHH_S1_Malicious_Vehicle" [6]="06_BSHH_S2_Malicious_RSU"
  [7]="07_BSHH_S3_Malicious_Controller_No_RSU" [8]="08_BSHH_S4_Malicious_Controller_With_RSU"
  [9]="09_ME_S1_Malicious_Vehicles" [10]="10_ME_S2_Malicious_RSU"
  [11]="11_ME_S3_Malicious_Controller_No_RSU" [12]="12_ME_S4_Malicious_Controller_With_RSU"
  [13]="13_COMBINED_All_Scenarios"
)

for SC in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  echo "=== theta=$THETA scenario=$SC ==="
  ./waf --run "scratch/routing --simTime=60 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=60 --attack_scenario=$SC --RngRun=999 --lw_threshold=0.05 --no_lw=1 --tgn_theta=$THETA --output_root=$ISO --tgn_weights=/home/sdvn_echo_topology/tgn_weights_dim192_final.bin --tgn_dim=192 --tgn_layers=2 --tgn_l_link=43.0" > "$HOME/theta_fs_sweep_dim192/log_theta${THETA}_sc${SC}.log" 2>&1

  SUM="$ISO/TGN_SUMMARY/${NAMES[$SC]}_seed999.csv"
  if [ -f "$SUM" ]; then
    # attack_name (column 2) can contain an internal comma (e.g. "TTW-S3:
    # Malicious Controller, No RSU"), which breaks naive `awk -F,` column
    # indexing for every column after it — collapse the quoted field to a
    # single token first so column numbers stay fixed regardless of content.
    ROW=$(tail -1 "$SUM" | sed -E 's/"[^"]*"/NAME/')
    TP=$(echo "$ROW" | awk -F, '{print $3}')
    FP=$(echo "$ROW" | awk -F, '{print $5}')
    FN=$(echo "$ROW" | awk -F, '{print $6}')
    MCC=$(echo "$ROW" | awk -F, '{print $7}')
    echo "$SC,$THETA,$TP,$FP,$FN,$MCC" >> "$RESULTS"
    echo "  -> tgn_tp=$TP tgn_fp=$FP tgn_fn=$FN tgn_mcc=$MCC"
  else
    echo "  -> WARNING: no TGN_SUMMARY for scenario=$SC theta=$THETA"
    echo "$SC,$THETA,MISSING,,," >> "$RESULTS"
  fi
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo ""
echo "=== theta=$THETA complete: $RESULTS ==="
cat "$RESULTS"
