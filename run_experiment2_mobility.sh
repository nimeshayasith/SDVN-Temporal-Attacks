#!/bin/bash
# Experiment 2 (RQ3, Eq. 4.26): Vehicular Mobility.
# vmax in {10, 60, 100, 140} km/h. Default penetration (attack_percentage=20).
#
# Note (SUMO mismatch caveat, Section 4.3.9): the paper requires
# speedFactor=1.0/speedDev=0.0 in the SUMO vType and matching edge speeds in
# .net.xml so vehicles travel at EXACTLY vmax with no randomisation. This
# repo drives mobility from pre-generated NS-3 trace CSVs (mobility_scenario
# selects urban/rural/highway traces per maxspeed), not a live SUMO run, so
# whether the underlying trace was actually regenerated per exact vmax value
# (rather than reusing the nearest available trace) should be verified
# against what trace files exist for each of the 4 speeds before trusting
# these results quantitatively.
#
# Usage: bash run_experiment2_mobility.sh [attack_scenario] [simTime]

set -e
SCENARIO=${1:-13}
SIMTIME=${2:-310}
NS3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/EXPERIMENT2_MOBILITY"
mkdir -p "$OUT_DIR"
cd "$NS3_DIR"

for VMAX in 10 60 100 140; do
    echo "=== Experiment 2: vmax=${VMAX} km/h ==="
    rm -f pem_run_summary.csv
    ./waf --run "scratch/routing --simTime=${SIMTIME} --N_Vehicles=200 --N_RSUs=64 \
        --N_Controllers=4 --maxspeed=${VMAX} --attack_scenario=${SCENARIO} \
        --attack_percentage=20 --RngRun=1" > "$OUT_DIR/log_v${VMAX}.txt" 2>&1
    CSV=$(ls -t "$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY/"*.csv 2>/dev/null | head -1)
    cp "$CSV" "$OUT_DIR/summary_v${VMAX}.csv"
done

python3 - "$OUT_DIR" <<'PYEOF'
import csv, sys, os
out_dir = sys.argv[1]
cols = ["mcc","auroc","tdet_ms","mean_t_stale_ms","pdr_under_attack_pct",
        "pdr_post_mitigation_pct","t_pipeline_mean_ms"]
rows = ["vmax_kmh," + ",".join(cols)]
for V in (10, 60, 100, 140):
    p = os.path.join(out_dir, f"summary_v{V}.csv")
    with open(p) as f:
        r = list(csv.DictReader(f))
    if not r:
        continue
    rows.append(f"{V}," + ",".join(r[0][c] for c in cols))
out_csv = os.path.join(out_dir, "experiment2_summary.csv")
with open(out_csv, "w") as f:
    f.write("\n".join(rows) + "\n")
print(f"=== Experiment 2 summary written to {out_csv} ===")
print("\n".join(rows))
PYEOF

echo "=== Experiment 2 complete. Results in $OUT_DIR ==="
