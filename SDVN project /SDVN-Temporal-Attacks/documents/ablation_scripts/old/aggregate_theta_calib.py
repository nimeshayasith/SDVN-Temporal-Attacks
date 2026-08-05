#!/usr/bin/env python3
"""
aggregate_theta_calib.py
-------------------------
Reads all theta_calib/theta_<X>/sc<N>/TGN_SUMMARY/*.csv files (11 theta
values x 13 scenarios = 143 runs) and computes, per theta value:
  - worst-case MCC (min across the 13 scenarios)
  - average MCC (mean across the 13 scenarios)
  - per-scenario MCC breakdown

Recommends the theta that maximizes worst-case MCC (matching the code's own
stated calibration intent: "worst-case MCC across scenarios"), with average
MCC as a tiebreaker/secondary view.
"""
import os, csv, glob

HOME = os.path.expanduser("~")
CALIB_ROOT = os.path.join(HOME, "theta_calib")

THETAS = ["0.90", "0.91", "0.92", "0.93", "0.94", "0.95",
          "0.96", "0.97", "0.98", "0.99", "1.00"]
SCENARIOS = list(range(1, 14))

def read_mcc(theta, sc):
    pattern = os.path.join(CALIB_ROOT, f"theta_{theta}", f"sc{sc}", "TGN_SUMMARY", "*.csv")
    matches = glob.glob(pattern)
    if not matches:
        return None
    with open(matches[0], newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return None
    try:
        return float(rows[-1]["mcc"])
    except (KeyError, ValueError):
        return None

def main():
    results = {}  # theta -> {sc: mcc}
    for theta in THETAS:
        results[theta] = {}
        for sc in SCENARIOS:
            mcc = read_mcc(theta, sc)
            results[theta][sc] = mcc

    print(f"{'theta':>6} | {'worst-case':>10} | {'average':>8} | per-scenario mcc")
    print("-" * 100)

    summary = []
    for theta in THETAS:
        vals = [v for v in results[theta].values() if v is not None]
        missing = [sc for sc, v in results[theta].items() if v is None]
        if not vals:
            print(f"{theta:>6} | NO DATA")
            continue
        worst = min(vals)
        avg = sum(vals) / len(vals)
        summary.append((theta, worst, avg, len(missing)))
        breakdown = " ".join(f"sc{sc}={results[theta][sc]:.3f}" if results[theta][sc] is not None else f"sc{sc}=MISSING"
                              for sc in SCENARIOS)
        print(f"{theta:>6} | {worst:>10.4f} | {avg:>8.4f} | {breakdown}")
        if missing:
            print(f"       ! missing scenarios: {missing}")

    if not summary:
        print("\nNo data found at all -- check theta_calib/ directory.")
        return

    print("\n" + "=" * 60)
    best_worstcase = max(summary, key=lambda r: r[1])
    best_avg = max(summary, key=lambda r: r[2])
    print(f"Best by WORST-CASE MCC (recommended): theta={best_worstcase[0]}  "
          f"worst-case={best_worstcase[1]:.4f}  avg={best_worstcase[2]:.4f}")
    print(f"Best by AVERAGE MCC:                  theta={best_avg[0]}  "
          f"worst-case={best_avg[1]:.4f}  avg={best_avg[2]:.4f}")

if __name__ == "__main__":
    main()
