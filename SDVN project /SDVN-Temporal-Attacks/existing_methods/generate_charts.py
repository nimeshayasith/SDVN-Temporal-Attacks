#!/usr/bin/env python3
"""
generate_charts.py
------------------
Reads results from run_comparison_study.sh and produces ONE combined chart
PER SCENARIO (13 total: scenarios 1-12 individual + 13 combined), each
showing all 4 methods (Ours, VeReMi, MBSM, kNN+Bagging) on the same axes
across attack_percentage {0,20,40,60,80,100}.

Metric plotted: MCC (primary detection-quality metric). AUROC and
detection-latency (Tdet) variants are also generated per scenario.
"""

import os, sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── Paths ──────────────────────────────────────────────────────────────────
BASE   = os.path.dirname(os.path.abspath(__file__))
RESDIR = os.path.join(BASE, "results")

VEREMI_CSV  = os.path.join(RESDIR, "veremi_raw", "combined_summary.csv")
MBSM_CSV    = os.path.join(RESDIR, "mbsm_raw",   "combined_summary.csv")
KNN_CSV     = os.path.join(RESDIR, "knn_raw",    "knn_all_scenarios_summary.csv")
OURS_LW_TGN_CSV = os.path.join(RESDIR, "ours_raw", "combined_summary_lw_tgn.csv")

CHART_DIR = os.path.join(RESDIR, "charts", "per_scenario")
os.makedirs(CHART_DIR, exist_ok=True)

# ── Scenario metadata ───────────────────────────────────────────────────────
SCENARIO_NAMES = {
    1:  "TTW-S1 (Mal. Vehicle, No RSU)",
    2:  "TTW-S2 (Mal. RSU)",
    3:  "TTW-S3 (Mal. Controller, No RSU)",
    4:  "TTW-S4 (Mal. Controller, RSU)",
    5:  "BSHH-S1 (Mal. Vehicle, No RSU)",
    6:  "BSHH-S2 (Mal. RSU)",
    7:  "BSHH-S3 (Mal. Controller, No RSU)",
    8:  "BSHH-S4 (Mal. Controller, RSU)",
    9:  "ME-S1 (Mal. Vehicle, No RSU)",
    10: "ME-S2 (Mal. RSU)",
    11: "ME-S3 (Mal. Controller, No RSU)",
    12: "ME-S4 (Mal. Controller, RSU)",
    13: "COMBINED (All 12 Scenarios)",
}

ATTACK_PCTS = [0, 20, 40, 60, 80, 100]

METRICS = {
    "mcc":     ("MCC",                    -1.05, 1.05),
    "auroc":   ("AUROC",                   0.45, 1.05),
    "tdet_ms": ("Detection Latency (ms)", -10.0, 110.0),
}

METHODS = ["Ours", "VeReMi", "MBSM", "kNN+Bagging"]
METHOD_STYLE = {
    "Ours":        {"color": "#d62728", "marker": "o", "linestyle": "-",  "linewidth": 2.2, "zorder": 6},
    "VeReMi":      {"color": "#1f77b4", "marker": "s", "linestyle": "--", "linewidth": 1.6, "zorder": 3},
    "MBSM":        {"color": "#2ca02c", "marker": "^", "linestyle": "-.", "linewidth": 1.6, "zorder": 3},
    "kNN+Bagging": {"color": "#9467bd", "marker": "D", "linestyle": ":",  "linewidth": 1.6, "zorder": 3},
}

# PDF Table 4.4, M1 (MCC): design components are "LW signature scoring
# (Eq. 3.12); FS binary scorer (Eq. 3.25)" -- M1's confusion matrix is meant
# to come from the COMBINED alert decision (LW OR TGN fires), not either
# stage in isolation. TGN_SUMMARY's comb_mcc column implements exactly this
# (.tgn_src/tgn_core.cc: `comb_alert = e.alert_raised || tgn_alert`) and is
# what "Ours" reports for mcc here (previously split into separate "Ours
# (LW)"/"Ours (TGN)" lines, which understated the full dual-mode system's
# combined detection quality vs. the PDF's own M1 definition). No combined
# equivalent is computed for auroc/tdet_ms in the C++ code, so those two
# metrics still use LW's own values (lw_auroc/lw_tdet_ms) as the reported
# figure for "Ours" -- out of scope of this fix, which is specifically MCC.
OURS_COL_MAP = {
    "Ours": {"mcc": "comb_mcc", "auroc": "lw_auroc", "tdet_ms": "lw_tdet_ms"},
}

# ── Load data ───────────────────────────────────────────────────────────────
def load_csv(path, label):
    if not os.path.exists(path):
        print(f"[WARN] {label} CSV not found: {path}")
        return pd.DataFrame()
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    print(f"[OK]  Loaded {label}: {len(df)} rows, cols: {list(df.columns)}")
    return df

df_ours   = load_csv(OURS_LW_TGN_CSV, "Ours (comb_mcc)")
df_veremi = load_csv(VEREMI_CSV, "VeReMi")
df_mbsm   = load_csv(MBSM_CSV,   "MBSM")
df_knn    = load_csv(KNN_CSV,    "kNN+Bagging")

DFS = {
    "Ours": df_ours,
    "VeReMi": df_veremi, "MBSM": df_mbsm, "kNN+Bagging": df_knn,
}

# normalise column names across methods (each CSV uses slightly different
# naming for the same concept)
for name, df in DFS.items():
    if df.empty:
        continue
    if "pdr_under_attack_pct" not in df.columns and "pdr_attack" in df.columns:
        df.rename(columns={"pdr_attack": "pdr_under_attack_pct"}, inplace=True)
    if "tdet_ms" in df.columns:
        df["tdet_ms"] = pd.to_numeric(df["tdet_ms"], errors="coerce")
    if "attack_scenario" in df.columns:
        df["attack_scenario"] = pd.to_numeric(df["attack_scenario"], errors="coerce")
    if "attack_percentage" in df.columns:
        df["attack_percentage"] = pd.to_numeric(df["attack_percentage"], errors="coerce")

def get_series(method_name, scenario, metric_key):
    """Return (attack_pcts, values) for one method x scenario x metric."""
    df = DFS[method_name]
    if df.empty or "attack_scenario" not in df.columns:
        return ATTACK_PCTS, [np.nan] * len(ATTACK_PCTS)
    # Ours (LW)/Ours (TGN) share one dataframe -- resolve to the right column.
    col = OURS_COL_MAP[method_name][metric_key] if method_name in OURS_COL_MAP else metric_key
    sub = df[df["attack_scenario"] == scenario]
    vals = []
    for pct in ATTACK_PCTS:
        row = sub[sub["attack_percentage"] == pct]
        if row.empty or col not in row.columns:
            vals.append(np.nan)
        else:
            vals.append(float(row[col].iloc[-1]))
    return ATTACK_PCTS, vals

# ── Plotting ─────────────────────────────────────────────────────────────────
def save_fig(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved -> {os.path.relpath(path, BASE)}")

def plot_scenario(scenario, metric_key):
    metric_label, ylim_lo, ylim_hi = METRICS[metric_key]
    fig, ax = plt.subplots(figsize=(8, 5.5))

    any_data = False
    for method in METHODS:
        xs, ys = get_series(method, scenario, metric_key)
        if all(np.isnan(v) for v in ys):
            continue
        any_data = True
        style = METHOD_STYLE[method]
        ax.plot(xs, ys, label=method, markersize=7, **style)

    ax.set_xlabel("Attack Percentage (%)", fontsize=11)
    ax.set_ylabel(metric_label, fontsize=11)
    ax.set_title(f"Scenario {scenario}: {SCENARIO_NAMES[scenario]} — {metric_label}",
                 fontsize=12, fontweight="bold")
    ax.set_xticks(ATTACK_PCTS)
    ax.set_ylim(ylim_lo, ylim_hi)
    ax.grid(True, linestyle="--", alpha=0.4)
    if any_data:
        ax.legend(fontsize=9, loc="best")
    else:
        ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                 ha="center", va="center", fontsize=12, color="gray")

    fname = f"scenario{scenario:02d}_{metric_key}.png"
    save_fig(fig, os.path.join(CHART_DIR, fname))

print("\n== Per-scenario combined charts (13 scenarios x 3 metrics) ==")
for scenario in range(1, 14):
    for metric_key in METRICS:
        plot_scenario(scenario, metric_key)

# ── One MCC-only summary grid: 13 scenarios in a 4x4 grid, one figure ──────
print("\n== Grand MCC overview (all 13 scenarios in one figure) ==")
fig, axes = plt.subplots(4, 4, figsize=(20, 18))
axes_flat = axes.flatten()
metric_key = "mcc"
metric_label, ylim_lo, ylim_hi = METRICS[metric_key]
for idx, scenario in enumerate(range(1, 14)):
    ax = axes_flat[idx]
    any_data = False
    for method in METHODS:
        xs, ys = get_series(method, scenario, metric_key)
        if all(np.isnan(v) for v in ys):
            continue
        any_data = True
        style = METHOD_STYLE[method]
        ax.plot(xs, ys, label=method, markersize=4, linewidth=1.3,
                 color=style["color"], marker=style["marker"],
                 linestyle=style["linestyle"])
    ax.set_title(f"Sc.{scenario}: {SCENARIO_NAMES[scenario].split('(')[0].strip()}",
                 fontsize=9, fontweight="bold")
    ax.set_xticks(ATTACK_PCTS)
    ax.tick_params(labelsize=7)
    ax.set_ylim(ylim_lo, ylim_hi)
    ax.grid(True, linestyle="--", alpha=0.35)
    if idx == 0:
        ax.legend(fontsize=7, loc="best")
# hide the 3 unused subplots (16 slots, 13 scenarios)
for idx in range(13, 16):
    axes_flat[idx].axis("off")
fig.suptitle("All 13 Scenarios — MCC vs Attack Percentage — All 4 Methods",
             fontsize=15, fontweight="bold")
save_fig(fig, os.path.join(RESDIR, "charts", "grand_overview_mcc.png"))

print("\nAll charts generated.")
print(f"  Per-scenario (13 x 3 metrics): {CHART_DIR}")
print(f"  Grand MCC overview:            {os.path.join(RESDIR, 'charts', 'grand_overview_mcc.png')}")
