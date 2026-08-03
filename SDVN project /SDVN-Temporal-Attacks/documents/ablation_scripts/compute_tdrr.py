#!/usr/bin/env python3
"""
compute_tdrr.py — genuine Eq. 4.2 Topology Divergence Reduction Ratio (TDRR).

Q48 fix: routing.cc's own in-run "tdrr_pct" column is NOT this metric (see
its declaration comment) -- it splits attack-labeled vs post-injection-benign
events WITHIN one protected run, whereas the PDF defines TDRR as the mean
divergence delta_bar over the SAME scenario+seed under two SEPARATE
conditions: detection disabled (unprotected) vs detection enabled (mitigated).
A single simulation process can only run with one --detection_enabled state,
so this genuinely requires two paired runs, read here from their own
mean_topology_divergence_postdetection column (unsplit, already correct per run).

Usage:
    python3 compute_tdrr.py <unprotected_run_dir> <mitigated_run_dir> [scenario_id]

Each <run_dir> is a routing.cc --output_root directory containing
PEM_RUN_SUMMARY/<NN>_*.csv. The two dirs MUST be the same attack_scenario and
same --RngRun seed, differing only in --detection_enabled (0 for unprotected,
1 for mitigated) -- this script checks and refuses to proceed if either the
scenario or seed differ, since Eq. 4.2 is only meaningful for a matched pair.
"""
import sys
import os
import glob
import csv


def read_run_summary(run_dir, scenario_id=None):
    pattern = os.path.join(run_dir, "PEM_RUN_SUMMARY", "*.csv") if scenario_id is None \
        else os.path.join(run_dir, "PEM_RUN_SUMMARY", f"{scenario_id:02d}_*.csv")
    matches = [m for m in glob.glob(pattern) if "COMBINED" not in os.path.basename(m)]
    if not matches:
        raise FileNotFoundError(f"No PEM_RUN_SUMMARY CSV found under {run_dir}")
    with open(matches[0], newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"{matches[0]} has no data rows")
    return rows[-1]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    unprotected_dir = sys.argv[1]
    mitigated_dir = sys.argv[2]
    scenario_id = int(sys.argv[3]) if len(sys.argv) > 3 else None

    unprotected_row = read_run_summary(unprotected_dir, scenario_id)
    mitigated_row = read_run_summary(mitigated_dir, scenario_id)

    if unprotected_row["attack_scenario"] != mitigated_row["attack_scenario"]:
        print(f"[ERROR] scenario mismatch: unprotected={unprotected_row['attack_scenario']} "
              f"mitigated={mitigated_row['attack_scenario']} -- TDRR requires the SAME scenario.")
        sys.exit(1)
    if unprotected_row["run_id"] != mitigated_row["run_id"]:
        print(f"[ERROR] seed mismatch: unprotected run_id={unprotected_row['run_id']} "
              f"mitigated run_id={mitigated_row['run_id']} -- TDRR requires the SAME seed.")
        sys.exit(1)
    if unprotected_row.get("detection_enabled") != "0":
        print(f"[WARN] unprotected_dir's detection_enabled={unprotected_row.get('detection_enabled')} "
              f"(expected 0) -- is this really the unprotected run?")
    if mitigated_row.get("detection_enabled") != "1":
        print(f"[WARN] mitigated_dir's detection_enabled={mitigated_row.get('detection_enabled')} "
              f"(expected 1) -- is this really the mitigated run?")

    delta_unprotected = float(unprotected_row["mean_topology_divergence_postdetection"])
    delta_mitigated = float(mitigated_row["mean_topology_divergence_postdetection"])

    if delta_unprotected <= 0.0:
        print(f"[ERROR] delta_bar_unprotected={delta_unprotected} <= 0 -- TDRR undefined "
              "(no divergence in the unprotected run to reduce).")
        sys.exit(1)

    tdrr_pct = 100.0 * (delta_unprotected - delta_mitigated) / delta_unprotected

    print(f"scenario={unprotected_row['attack_scenario']}  seed={unprotected_row['run_id']}")
    print(f"delta_bar_unprotected = {delta_unprotected:.6f}")
    print(f"delta_bar_mitigated   = {delta_mitigated:.6f}")
    print(f"TDRR (Eq. 4.2)        = {tdrr_pct:.3f}%")


if __name__ == "__main__":
    main()
