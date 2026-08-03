#!/bin/bash
# sweep_a12_baseline.sh
# A12 baseline (divergence detector ENABLED) -- the missing comparison arm.
# sweep_a12.sh only ever ran --no_divergence_detector=1; without a paired
# baseline where the detector is genuinely active, A12 cannot show the
# ablation's effect at all (divergence_tp/recall would be 0 in both arms
# by construction). This runs the exact same 6 controller-origin scenarios
# x 3 rinj values WITHOUT the ablation flag, so PemControllerDivergenceGate
# actually runs (confirmed = (delta > thresh), not forced false).
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a12"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [3]=0 [4]=64 [7]=0 [8]=64 [11]=0 [12]=64 )

for SC in 3 4 7 8 11 12; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 0.01 0.05 0.10; do
    echo "=== a12 BASELINE scenario=${SC} rinj=${X} ==="
    ISO="$OUT/baseline_sc${SC}_rinj${X}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --attack_percentage=60 --rinj=${X} --RngRun=1 --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a12 baseline sweep complete ==="
