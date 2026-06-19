#!/usr/bin/env python3
"""
pem_to_alerts.py  —  NS-3 PEM → tgn_alerts.json bridge

Reads routing.cc's PEM_RUN_SUMMARY CSV (already on disk after any simulation run)
and writes tgn_alerts.json so submitToFabric.js can submit to the blockchain.

This bypasses the TGN detector and crypto pipeline — the PEM anomaly score
(AUROC) is used directly as ŷ (y_hat).  This is the correct approach during
development: TGN and Dilithium2 signing are future additions; the blockchain
layer can be tested independently using routing.cc outputs.

Usage:
    python3 pem_to_alerts.py                           # uses latest CSV in outputs/
    python3 pem_to_alerts.py --scenario 1              # TTW-S1 specifically
    python3 pem_to_alerts.py --csv path/to/file.csv    # explicit CSV file
    python3 pem_to_alerts.py --out my_alerts.json      # custom output path
"""

import csv
import json
import os
import sys
import time
import argparse
import glob

# ─── Paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR  = os.path.join(SCRIPT_DIR, "outputs", "PEM_RUN_SUMMARY")
DEFAULT_OUT  = os.path.join(SCRIPT_DIR, "tgn_alerts.json")

# ─── Scenario metadata ────────────────────────────────────────────────────────

# Maps scenario ID → (alpha string, S_trig bitmask positions, attacker node)
SCENARIO_META = {
    0:  ("BASELINE",                  [],        "V_none"),
    1:  ("TTW_S1_MAL_VEH_NO_RSU",    [0, 1],    "V0"),
    2:  ("TTW_S2_MAL_RSU",           [1, 2],    "RSU0"),
    3:  ("TTW_S3_MAL_CTRL_NO_RSU",   [2],       "CTRL"),
    4:  ("TTW_S4_MAL_CTRL_WITH_RSU", [1, 2],    "CTRL"),
    5:  ("BSHH_S1_MAL_VEH_NO_RSU",   [3, 4],    "V0"),
    6:  ("BSHH_S2_MAL_RSU",          [3, 4, 5], "RSU0"),
    7:  ("BSHH_S3_MAL_CTRL_NO_RSU",  [4, 5],    "CTRL"),
    8:  ("BSHH_S4_MAL_CTRL_WITH_RSU",[3, 5],    "CTRL"),
    9:  ("ME_S1_MAL_VEHICLES",        [6, 8],    "V0"),
    10: ("ME_S2_MAL_RSU",             [6, 7],    "RSU0"),
    11: ("ME_S3_MAL_CTRL_NO_RSU",    [7, 8],    "CTRL"),
    12: ("ME_S4_MAL_CTRL_WITH_RSU",  [6, 7, 8], "CTRL"),
}

SCENARIO_FILENAMES = {
    0:  "00_Baseline_No_Attack",
    1:  "01_TTW_S1_Malicious_Vehicle",
    2:  "02_TTW_S2_Malicious_RSU",
    3:  "03_TTW_S3_Malicious_Controller_No_RSU",
    4:  "04_TTW_S4_Malicious_Controller_With_RSU",
    5:  "05_BSHH_S1_Malicious_Vehicle",
    6:  "06_BSHH_S2_Malicious_RSU",
    7:  "07_BSHH_S3_Malicious_Controller_No_RSU",
    8:  "08_BSHH_S4_Malicious_Controller_With_RSU",
    9:  "09_ME_S1_Malicious_Vehicles",
    10: "10_ME_S2_Malicious_RSU",
    11: "11_ME_S3_Malicious_Controller_No_RSU",
    12: "12_ME_S4_Malicious_Controller_With_RSU",
}

# ─── Core conversion ──────────────────────────────────────────────────────────

def csv_to_alerts(csv_path):
    """Read a PEM_RUN_SUMMARY CSV and return a list of alert dicts."""
    alerts = []
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            scenario  = int(row.get("attack_scenario", 0))
            tp        = int(row.get("tp", 0))
            fp        = int(row.get("fp", 0))
            fn        = int(row.get("fn", 0))
            mcc       = float(row.get("mcc", 0.0))
            auroc     = float(row.get("auroc", 0.0))
            tdet_ms   = float(row.get("tdet_ms", 0.0))

            # Skip baseline rows and rows with no detections
            if scenario == 0:
                continue
            if tp == 0 and fp == 0:
                # Nothing detected — either mitigation inactive or no attack fired
                print(f"  [skip] run_id={row['run_id']}  tp=0  fp=0 — no detection events")
                continue

            meta  = SCENARIO_META.get(scenario, ("UNKNOWN", [], "V0"))
            alpha, s_trig, v_id = meta

            # y_hat: use auroc as anomaly score proxy.
            # auroc in [0,1] — values >= 0.5 indicate attack detected.
            # If auroc is invalid (e.g. -0.55 from a partial run), use mcc instead.
            y_hat = auroc if auroc >= 0.0 else max(0.0, mcc)
            # Clamp to [0,1]
            y_hat = min(1.0, max(0.0, y_hat))

            alert = {
                "v_id":           v_id,
                "alpha":          alpha,
                "y_hat":          round(y_hat, 4),
                "t_alert":        int(time.time() * 1000),
                "interval_ts_ms": int(time.time() * 1000),
                "S_trig":         s_trig,
                "from_lw_path":   False,
                "mcc":            round(mcc, 4),
                "tdet_ms":        round(tdet_ms, 2),
                "tp":             tp,
                "fp":             fp,
                "fn":             fn,
            }
            alerts.append(alert)
            print(f"  [alert] scenario={scenario}  α={alpha}  v_id={v_id}  "
                  f"ŷ={y_hat:.4f}  mcc={mcc:.3f}  tdet={tdet_ms:.1f}ms  tp={tp}  fp={fp}")
    return alerts


def find_csv(scenario_id=None):
    """Locate the best CSV to read: explicit scenario or latest written file."""
    if scenario_id is not None:
        fname = SCENARIO_FILENAMES.get(scenario_id)
        if fname:
            path = os.path.join(OUTPUTS_DIR, fname + ".csv")
            if os.path.exists(path):
                return path
            print(f"[WARN] CSV not found for scenario {scenario_id}: {path}")

    # Fall back to most recently modified CSV in outputs dir
    csvs = glob.glob(os.path.join(OUTPUTS_DIR, "*.csv"))
    if not csvs:
        return None
    # Exclude baseline
    attack_csvs = [c for c in csvs if "Baseline" not in c]
    if attack_csvs:
        return max(attack_csvs, key=os.path.getmtime)
    return max(csvs, key=os.path.getmtime)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", "-s", type=int, default=None,
                        help="Attack scenario ID (1-12). Default: latest CSV in outputs/")
    parser.add_argument("--csv", "-c", default=None,
                        help="Explicit path to PEM_RUN_SUMMARY CSV")
    parser.add_argument("--out", "-o", default=DEFAULT_OUT,
                        help=f"Output JSON file (default: {DEFAULT_OUT})")
    args = parser.parse_args()

    # Resolve input CSV
    if args.csv:
        csv_path = args.csv
    else:
        csv_path = find_csv(args.scenario)

    if not csv_path or not os.path.exists(csv_path):
        print("[ERROR] No PEM_RUN_SUMMARY CSV found.")
        print(f"  Run the NS-3 simulation first:")
        print(f"  cd ~/ns-allinone-3.35/ns-3.35")
        print(f"  ./waf --run 'scratch/routing --simTime=30 --N_Vehicles=2 --attack_scenario=1'")
        sys.exit(1)

    print(f"[PEM→Alerts] Reading: {csv_path}")
    alerts = csv_to_alerts(csv_path)

    if not alerts:
        print("[WARN] No alert rows found in CSV. Check that the simulation ran with an attack scenario.")
        print("       Writing empty tgn_alerts.json — blockchain submit will do nothing.")
        alerts = []

    with open(args.out, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"\n[PEM→Alerts] Wrote {len(alerts)} alert(s) → {args.out}")
    if alerts:
        print(f"             Ready for: node blockchain/client/submitToFabric.js --alerts {args.out}")


if __name__ == "__main__":
    main()
