#!/bin/bash
# sweep_a1.sh
# A1 (Table 4.2): LW Detection Stage Only (--no_tgn=1). X variable: attack
# injection rate rinj in {1%, 5%, 10%}. Applicable PEMs are M3 (TTW/BSHH) AND
# M4 (ME) together -- the PDF does not restrict this to a single attack
# family -- so this uses attack_scenario=13 (combined, all 12 variants
# concurrently) instead of separately re-running sc1/sc5/sc9. One combined
# run also natively yields per-family breakdown via pem_run_summary.csv's
# f1_ttw/f1_bshh/f1_me/f1_macro columns, so no coverage is lost versus the
# old 3-scenario approach -- it's a superset (concurrent multi-family attack
# load, not three isolated single-family instances).
set -e
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
TGN="$HOME/tgn_weights_dim192_final.bin"
OUT="$HOME/ablation_sweep/a1"
mkdir -p "$OUT"
cd "$NS3_DIR"

for X in 1 5 10; do
  echo "=== a1 scenario=13 x=${X} ==="
  ISO="$OUT/sc13_x${X}"
  mkdir -p "$ISO"
  ./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=13 --RngRun=999 --no_tgn=1 --attack_percentage=${X} --tgn_weights=$TGN --output_root=$ISO" > "$ISO.log" 2>&1
  rm -rf "$ISO/PCAP_FILES" "$ISO/XML"
done

echo "=== a1 sweep complete ==="
