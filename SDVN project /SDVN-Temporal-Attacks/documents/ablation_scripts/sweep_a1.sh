#!/bin/bash
# sweep_a1.sh
# A1 (Table 4.2): LW Detection Stage Only (--no_tgn=1). X variable: attack
# injection rate rinj in {1%, 5%, 10%}. Applicable PEMs span M3 (TTW/BSHH)
# AND M4 (ME) -- the PDF does not restrict this to a single attack family.
#
# UPDATED (dropped combined mode): no longer uses attack_scenario=13. The
# PDF's own methodology (Experiment 5, Table 4.6) evaluates "each of the 12
# attack scenarios independently" -- there is no PDF text anywhere
# specifying concurrent multi-family execution for the ablation study; that
# was an implementation choice from an earlier session, not a PDF
# requirement. This now runs one representative isolated scenario per
# family (S1=TTW-S1, S5=BSHH-S1, S9=ME-S1) at each rinj value; per-family
# MCC is obtained by pooling each family's own isolated-run TGN_EVENTS.csv,
# the same approach already used for the Table 4.6 per-variant comparison.
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
BIN="$NS3_DIR/build/scratch/routing"
export LD_LIBRARY_PATH="$NS3_DIR/build/lib"
TGN="$HOME/tgn_l_wbptt_sweep/tgn_weights_WBPTT50.bin"
OUT="$HOME/ablation_sweep/a1"
mkdir -p "$OUT"
cd "$NS3_DIR"

declare -A RSU_FOR_SC=( [1]=0 [5]=0 [9]=0 )

for SC in 1 5 9; do
  NRSU=${RSU_FOR_SC[$SC]}
  for X in 0.01 0.05 0.10; do
    echo "=== a1 scenario=${SC} rinj=${X} ==="
    ISO="$OUT/sc${SC}_rinj${X}"
    mkdir -p "$ISO"
    "$BIN" --simTime=310 --N_Vehicles=200 --N_RSUs=${NRSU} --N_Controllers=4 --attack_scenario=${SC} --RngRun=1 --no_tgn=1 --attack_percentage=60 --rinj=${X} --skip_npfads=true --skip_logs=1 --tgn_weights=$TGN --tgn_theta=0.26 --output_root=$ISO > /dev/null 2>&1
    rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
  done
done

echo "=== a1 sweep complete ==="
