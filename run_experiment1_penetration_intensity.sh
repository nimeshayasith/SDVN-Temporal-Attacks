#!/bin/bash
# Experiment 1 (RQ2, Eq. 4.24/4.25): Joint Attack Penetration and Intensity.
#
# L in {0, 0.20, 0.40, 0.60, 0.80, 1.00} sets both dimensions simultaneously:
#   alpha_atk(L) = L  (fraction of vehicles malicious)
#   r_inj(L)     = L  (per-attacker injection rate)
#
# Known gap: this codebase's attack functions run on FIXED one-shot
# timelines (e.g. TTW-S1's hello/break/replay at t=10/15/20), not a
# continuously configurable per-beacon-interval injection rate. There is no
# r_inj parameter to sweep independently. This script sweeps attack_percentage
# (alpha_atk) only, which also proportionally drives controller-compromise
# probability (see routing.cc's ttw_malicious_controllers[] thresholds) --
# it does NOT reproduce the r_inj half of Eq. 4.24, so Lambda(L) (Eq. 4.25)
# will not scale quadratically as the paper describes. Treat results as an
# attack-penetration sweep only until r_inj is implemented (see Experiment 4
# script's Psi/burst work for the closest existing analogue).
#
# Usage: bash run_experiment1_penetration_intensity.sh [attack_scenario] [simTime]

set -e
SCENARIO=${1:-13}
SIMTIME=${2:-310}
NS3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/EXPERIMENT1_PENETRATION_INTENSITY"
mkdir -p "$OUT_DIR"
cd "$NS3_DIR"

for L in 0 20 40 60 80 100; do
    echo "=== Experiment 1: L=${L}% (alpha_atk=r_inj proxy) ==="
    rm -f pem_run_summary.csv
    ./waf --run "scratch/routing --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 \
        --N_Controllers=4 --maxspeed=60 --attack_scenario=${SCENARIO} \
        --attack_percentage=${L} --RngRun=1" > "$OUT_DIR/log_L${L}.txt" 2>&1
    CSV=$(ls -t "$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY/"*.csv 2>/dev/null | head -1)
    cp "$CSV" "$OUT_DIR/summary_L${L}.csv"
done

python3 - "$OUT_DIR" <<'PYEOF'
import csv, sys, os
out_dir = sys.argv[1]
cols = ["mcc","auroc","tdet_ms","pdr_under_attack_pct","pdr_post_mitigation_pct",
        "t_pipeline_mean_ms","omega_lw_pct"]
rows = ["L," + ",".join(cols)]
for L in (0, 20, 40, 60, 80, 100):
    p = os.path.join(out_dir, f"summary_L{L}.csv")
    with open(p) as f:
        r = list(csv.DictReader(f))
    if not r:
        continue
    rows.append(f"{L}," + ",".join(r[0][c] for c in cols))
out_csv = os.path.join(out_dir, "experiment1_summary.csv")
with open(out_csv, "w") as f:
    f.write("\n".join(rows) + "\n")
print(f"=== Experiment 1 summary written to {out_csv} ===")
print("\n".join(rows))
PYEOF

echo "=== Experiment 1 complete. Results in $OUT_DIR ==="
