#!/bin/bash
# Experiment 3 (RQ4, Eq. 4.27): Network Scalability.
# N in {100, 200, 300, 400} vehicles; RSU=64 and N_Controllers=4 held fixed
# so scaling effects are attributable to vehicle-side detection workload,
# not infrastructure growth. attack_percentage=20 held constant so absolute
# attacker count scales proportionally with N.
#
# This is the per-run-metrics companion to M8's own N-sweep
# (run_m8_scalability.sh already computes rho_det(N) from tdet_ms across
# N in {50,100,150,200}); this script instead runs the paper's own
# N in {100,200,300,400} points and reports the FULL PEM row per point
# (M1-M6), not just the M8 ratio, matching Experiment 3's "Applicable PEMs:
# M1, M2, M3, M4, M5, M6, M8" scope.
#
# Usage: bash run_experiment3_scalability.sh [attack_scenario] [simTime]

set -e
SCENARIO=${1:-13}
SIMTIME=${2:-310}
NS3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/EXPERIMENT3_SCALABILITY"
mkdir -p "$OUT_DIR"
cd "$NS3_DIR"

for N in 100 200 300 400; do
    echo "=== Experiment 3: N=${N} vehicles ==="
    rm -f pem_run_summary.csv
    ./waf --run "scratch/routing --simTime=${SIMTIME} --N_Vehicles=${N} --N_RSUs=64 \
        --N_Controllers=4 --maxspeed=60 --attack_scenario=${SCENARIO} \
        --attack_percentage=20 --RngRun=1" > "$OUT_DIR/log_N${N}.txt" 2>&1
    CSV=$(ls -t "$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY/"*.csv 2>/dev/null | head -1)
    cp "$CSV" "$OUT_DIR/summary_N${N}.csv"
done

python3 - "$OUT_DIR" <<'PYEOF'
import csv, sys, os
out_dir = sys.argv[1]
cols = ["mcc","auroc","tdet_ms","mean_t_stale_ms","mean_pir",
        "pdr_under_attack_pct","pdr_post_mitigation_pct","t_pipeline_mean_ms"]
rows = ["N_vehicles," + ",".join(cols)]
tdet0 = None
for N in (100, 200, 300, 400):
    p = os.path.join(out_dir, f"summary_N{N}.csv")
    with open(p) as f:
        r = list(csv.DictReader(f))
    if not r:
        continue
    rows.append(f"{N}," + ",".join(r[0][c] for c in cols))
    if N == 100:
        tdet0 = float(r[0]["tdet_ms"]) if float(r[0]["tdet_ms"]) > 0 else None
out_csv = os.path.join(out_dir, "experiment3_summary.csv")
with open(out_csv, "w") as f:
    f.write("\n".join(rows) + "\n")
print(f"=== Experiment 3 summary written to {out_csv} ===")
print("\n".join(rows))
PYEOF

echo "=== Experiment 3 complete. Results in $OUT_DIR ==="
echo "(For rho_det(N) ratios specifically, also see run_m8_scalability.sh)"
