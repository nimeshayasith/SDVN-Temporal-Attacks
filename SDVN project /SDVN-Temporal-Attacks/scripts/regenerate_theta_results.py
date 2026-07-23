#!/usr/bin/env python3
"""Rebuild results_theta_<T>.csv from the raw per-scenario TGN_SUMMARY CSVs,
using proper CSV parsing (handles the comma embedded inside the quoted
attack_name field that broke the sweep script's naive awk -F, extraction)."""
import csv
import glob
import os

HOME = os.path.expanduser("~")
NAMES = {
    1: "01_TTW_S1_Malicious_Vehicle", 2: "02_TTW_S2_Malicious_RSU",
    3: "03_TTW_S3_Malicious_Controller_No_RSU", 4: "04_TTW_S4_Malicious_Controller_With_RSU",
    5: "05_BSHH_S1_Malicious_Vehicle", 6: "06_BSHH_S2_Malicious_RSU",
    7: "07_BSHH_S3_Malicious_Controller_No_RSU", 8: "08_BSHH_S4_Malicious_Controller_With_RSU",
    9: "09_ME_S1_Malicious_Vehicles", 10: "10_ME_S2_Malicious_RSU",
    11: "11_ME_S3_Malicious_Controller_No_RSU", 12: "12_ME_S4_Malicious_Controller_With_RSU",
    13: "13_COMBINED_All_Scenarios",
}

base = os.path.join(HOME, "theta_fs_sweep_dim192")
for theta_dir in sorted(glob.glob(os.path.join(base, "theta_*"))):
    theta = os.path.basename(theta_dir).replace("theta_", "")
    out_path = os.path.join(base, f"results_theta_{theta}.csv")
    rows = []
    for sc, name in NAMES.items():
        sum_path = os.path.join(theta_dir, "TGN_SUMMARY", f"{name}_seed999.csv")
        if not os.path.isfile(sum_path):
            rows.append((sc, theta, "MISSING", "", "", ""))
            continue
        with open(sum_path, newline="") as f:
            reader = csv.DictReader(f)
            row = next(reader, None)
        if row is None:
            rows.append((sc, theta, "MISSING", "", "", ""))
            continue
        rows.append((sc, theta, row["tp"], row["fp"], row["fn"], row["mcc"]))
    with open(out_path, "w") as f:
        f.write("attack_scenario,theta,tgn_tp,tgn_fp,tgn_fn,tgn_mcc\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    print(f"wrote {out_path} ({sum(1 for r in rows if r[2] != 'MISSING')}/13 scenarios present)")
