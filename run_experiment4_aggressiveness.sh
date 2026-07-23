#!/bin/bash
# Experiment 4 (RQ5, Eq. 4.28/4.29): Attack Aggressiveness Index Psi.
# (fm, Tburst, Psi) in {(1,10s,100), (2,30s,600), (4,60s,2400), (8,120s,9600)}.
# alpha_atk=0.20, r_inj=1.0 within the burst window (default TTW-S1 attacker
# fraction via attack_percentage=20; r_inj is not independently controllable
# -- see Experiment 1 script's caveat).
#
# IMPORTANT SCOPE NOTE: psi_fm/psi_tburst are currently wired into TTW-S1
# ONLY (an additive repeat-injection layer on top of its existing single-shot
# replay -- see routing.cc's g_psi_fm/g_psi_tburst_s declaration comment).
# BSHH/ME and the other TTW variants do not yet respond to these flags, so
# this script forces --attack_scenario=1 (TTW-S1) rather than 13 (combined)
# to get a real, non-vacuous Psi response. Extending Psi to the other 11
# scenarios is future work.
#
# Usage: bash run_experiment4_aggressiveness.sh [simTime]

set -e
SIMTIME=${1:-310}
NS3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/EXPERIMENT4_AGGRESSIVENESS"
mkdir -p "$OUT_DIR"
cd "$NS3_DIR"

# (fm, Tburst, Psi) operating points
declare -a FM=(1 2 4 8)
declare -a TBURST=(10 30 60 120)
declare -a PSI=(100 600 2400 9600)

for i in 0 1 2 3; do
    fm=${FM[$i]}; tb=${TBURST[$i]}; psi=${PSI[$i]}
    echo "=== Experiment 4: fm=${fm} Tburst=${tb}s (Psi=${psi}) ==="
    rm -f pem_run_summary.csv
    ./waf --run "scratch/routing --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 \
        --N_Controllers=4 --maxspeed=60 --attack_scenario=1 --attack_percentage=20 \
        --psi_fm=${fm} --psi_tburst=${tb} --RngRun=1" > "$OUT_DIR/log_psi${psi}.txt" 2>&1
    CSV=$(ls -t "$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY/"*.csv 2>/dev/null | head -1)
    cp "$CSV" "$OUT_DIR/summary_psi${psi}.csv"
done

python3 - "$OUT_DIR" <<'PYEOF'
import csv, sys, os
out_dir = sys.argv[1]
cols = ["mcc","auroc","tdet_ms","mean_t_stale_ms","pdr_under_attack_pct",
        "pdr_post_mitigation_pct","t_pipeline_mean_ms","total_events"]
rows = ["fm,Tburst_s,Psi," + ",".join(cols)]
pts = [(1,10,100), (2,30,600), (4,60,2400), (8,120,9600)]
for fm, tb, psi in pts:
    p = os.path.join(out_dir, f"summary_psi{psi}.csv")
    with open(p) as f:
        r = list(csv.DictReader(f))
    if not r:
        continue
    rows.append(f"{fm},{tb},{psi}," + ",".join(r[0][c] for c in cols))
out_csv = os.path.join(out_dir, "experiment4_summary.csv")
with open(out_csv, "w") as f:
    f.write("\n".join(rows) + "\n")
print(f"=== Experiment 4 summary written to {out_csv} ===")
print("\n".join(rows))
PYEOF

echo "=== Experiment 4 complete. Results in $OUT_DIR ==="
