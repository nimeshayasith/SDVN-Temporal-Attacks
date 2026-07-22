#!/bin/bash
# M8 (Eq. 4.12/4.13): Scalability Metric — cross-run comparison.
#
# M8 sweeps two orthogonal axes that are simulation-wide configuration
# (N_Vehicles, N_Controllers), not per-event data, so unlike M2/M5/M6 it
# cannot be computed within a single run — it genuinely requires launching
# several separate simulations and comparing their CSV outputs. This
# mirrors what M2's TDRR was before it got automated in-run: a metric whose
# definition (Eq. 4.12/4.13) is inherently a ratio between independent runs.
#
# rho_det(N)   = Tdet(N)   / Tdet(N0=50),        N  in {50,100,150,200}
# rho_PBFT(np) = TPBFT(np) / TPBFT(np0=4),        np in {4,8,12}
#
# Usage: bash run_m8_scalability.sh [attack_scenario] [simTime]
#   attack_scenario defaults to 1 (TTW-S1); simTime defaults to 60.

set -e
SCENARIO=${1:-1}
SIMTIME=${2:-60}
NS3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/M8_SCALABILITY"
mkdir -p "$OUT_DIR"

cd "$NS3_DIR"

run_one () {
    local N_VEH=$1
    local N_CTRL=$2
    local TAG=$3
    rm -f pem_run_summary.csv
    ./waf --run "scratch/routing --simTime=${SIMTIME} --N_Vehicles=${N_VEH} --N_RSUs=0 \
        --N_Controllers=${N_CTRL} --attack_scenario=${SCENARIO} --RngRun=1" > "$OUT_DIR/log_${TAG}.txt" 2>&1
    # Locate the scenario CSV written by PemWriteRunSummaryCsv (BuildScenarioCsvPath)
    local CSV
    CSV=$(ls -t "$NS3_DIR/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY/"*.csv 2>/dev/null | head -1)
    cp "$CSV" "$OUT_DIR/summary_${TAG}.csv"
    echo "$OUT_DIR/summary_${TAG}.csv"
}

echo "=== M8 vehicle-count (N) scaling sweep: rho_det(N) ==="
declare -a N_CSVS
for N in 50 100 150 200; do
    echo "-- N_Vehicles=$N --"
    N_CSVS[$N]=$(run_one "$N" 4 "N${N}")
done

echo "=== M8 peer-count (np) scaling sweep: rho_PBFT(np) ==="
declare -a NP_CSVS
for NP in 4 8 12; do
    echo "-- N_Controllers=$NP --"
    NP_CSVS[$NP]=$(run_one 100 "$NP" "np${NP}")
done

python3 - "$OUT_DIR" <<'PYEOF'
import csv, sys, os

out_dir = sys.argv[1]

def read_val(path, col):
    with open(path) as f:
        r = list(csv.DictReader(f))
    if not r:
        return 0.0
    return float(r[0][col])

n_vals = {}
for N in (50, 100, 150, 200):
    p = os.path.join(out_dir, f"summary_N{N}.csv")
    n_vals[N] = read_val(p, "tdet_ms")

np_vals = {}
for NP in (4, 8, 12):
    p = os.path.join(out_dir, f"summary_np{NP}.csv")
    np_vals[NP] = read_val(p, "t_pbft_mean_ms")

tdet0 = n_vals[50]
np0 = np_vals[4]

rows = []
rows.append("axis,param,value_ms,rho,expected")
for N in (50, 100, 150, 200):
    rho = (n_vals[N] / tdet0) if tdet0 > 0 else 0.0
    rows.append(f"N,{N},{n_vals[N]:.4f},{rho:.4f},~1.0")
for NP in (4, 8, 12):
    rho = (np_vals[NP] / np0) if np0 > 0 else 0.0
    expected = (NP / 4.0) ** 2
    rows.append(f"np,{NP},{np_vals[NP]:.4f},{rho:.4f},{expected:.4f}")

out_csv = os.path.join(out_dir, "m8_scalability_summary.csv")
with open(out_csv, "w") as f:
    f.write("\n".join(rows) + "\n")

print(f"\n=== M8 scalability summary written to {out_csv} ===")
print("\n".join(rows))
PYEOF

echo "=== M8 sweep complete. Results in $OUT_DIR ==="
