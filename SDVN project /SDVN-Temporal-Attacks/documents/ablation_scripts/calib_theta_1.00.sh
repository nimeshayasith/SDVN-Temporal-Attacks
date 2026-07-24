#!/bin/bash
# calib_theta_1.00.sh
# theta_fs recalibration sweep point: --tgn_theta=1.00, --no_lw=1 (isolates
# TGN exactly like A2), attack_percentage=50, across all 13 scenarios
# (1-12 individual + 13 combined). Run alongside the other 5 theta-value
# scripts, then aggregate all 6 x 13 TGN_SUMMARY mcc values to find the
# theta_fs that maximizes worst-case/average MCC across every scenario --
# not just scenario 13 -- matching the code's own stated calibration intent
# ("worst-case MCC across scenarios").
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_dim192_final.bin"
OUT="$HOME/theta_calib/theta_1.00"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [1]=0 [2]=64 [3]=0 [4]=64 [5]=0 [6]=64 [7]=0 [8]=64 [9]=0 [10]=64 [11]=0 [12]=64 [13]=64 )

for SC in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  NRSU=${RSU_FOR_SC[$SC]}
  echo "=== theta=1.00 scenario=${SC} ==="
  ISO="$OUT/sc${SC}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=50 --RngRun=999 --no_lw=1 --tgn_theta=1.00 --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== theta=1.00 sweep complete ==="
