#!/usr/bin/env python3
"""
generate_charts.py
------------------
Reads results from run_all_existing_methods.sh and produces:
  results/charts/veremi/   – per-metric charts for VeReMi+KNN method
  results/charts/mbsm/     – per-metric charts for MBSM method
  results/charts/combined/ – all methods on the same axes per attack family

Metrics plotted vs attack_percentage (0, 25, 50, 75, 100):
  MCC, AUROC, Tdet (ms), PDR (%)

Attack families:
  TTW  → scenarios 1(S1) 2(S2) 3(S3) 4(S4)
  BSHH → scenarios 5(S1) 6(S2) 7(S3) 8(S4)
  ME   → scenarios 9(S1) 10(S2) 11(S3) 12(S4)

S3/S4 (malicious controller) = undetectable by existing methods → MCC=0, AUROC=0.5
"""

import os, sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ── Paths ──────────────────────────────────────────────────────────────────
BASE   = os.path.dirname(os.path.abspath(__file__))
RESDIR = os.path.join(BASE, "results")

VEREMI_CSV = os.path.join(RESDIR, "veremi_raw", "temporal_veremi_compare_pem_summary.csv")
MBSM_CSV   = os.path.join(RESDIR, "mbsm_raw",   "temporal_mbsm_compare_summary.csv")
KNN_CSV    = os.path.join(RESDIR, "knn_raw",    "temporal_compare_knn_summary.csv")

CHART_VEREMI   = os.path.join(RESDIR, "charts", "veremi")
CHART_MBSM     = os.path.join(RESDIR, "charts", "mbsm")
CHART_KNN      = os.path.join(RESDIR, "charts", "knn")
CHART_COMBINED = os.path.join(RESDIR, "charts", "combined")

for d in [CHART_VEREMI, CHART_MBSM, CHART_KNN, CHART_COMBINED]:
    os.makedirs(d, exist_ok=True)

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
}

FAMILIES = {
    "TTW":  [1, 2, 3, 4],
    "BSHH": [5, 6, 7, 8],
    "ME":   [9, 10, 11, 12],
}

S_LABELS = {1: "S1", 2: "S2", 3: "S3", 4: "S4",
            5: "S1", 6: "S2", 7: "S3", 8: "S4",
            9: "S1", 10:"S2", 11:"S3",12:"S4"}

METRICS = {
    "mcc":      ("MCC",                    0.0, 1.0),
    "auroc":    ("AUROC",                  0.0, 1.0),
    "tdet_ms":  ("Detection Latency (ms)", -10.0, 110.0),
}

COLORS = {
    "S1": "#1f77b4",   # blue  – malicious vehicles
    "S2": "#ff7f0e",   # orange – malicious RSU
    "S3": "#d62728",   # red   – malicious controller, no RSU
    "S4": "#9467bd",   # purple – malicious controller, RSU
}
LINESTYLES = {"S1": "-", "S2": "--", "S3": "-.", "S4": ":"}
MARKERS    = {"S1": "o", "S2": "s", "S3": "^", "S4": "D"}

ATTACK_PCTS = [0, 25, 50, 75, 100]

# ── Load data ───────────────────────────────────────────────────────────────
def load_csv(path, label):
    if not os.path.exists(path):
        print(f"[WARN] {label} CSV not found: {path}")
        return pd.DataFrame()
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    print(f"[OK]  Loaded {label}: {len(df)} rows, cols: {list(df.columns)}")
    return df

df_veremi = load_csv(VEREMI_CSV, "VeReMi/KNN")
df_mbsm   = load_csv(MBSM_CSV,   "MBSM")
df_knn    = load_csv(KNN_CSV,    "KNN+Bagging")

# normalise PDR column name for mbsm (uses acr_pct instead of accuracy_pct)
for df in [df_veremi, df_mbsm, df_knn]:
    if "pdr_under_attack_pct" not in df.columns and "pdr_attack" in df.columns:
        df.rename(columns={"pdr_attack": "pdr_under_attack_pct"}, inplace=True)
    # tdet: keep -1 (undetected) as-is so it shows on the chart
    if "tdet_ms" in df.columns:
        df["tdet_ms"] = pd.to_numeric(df["tdet_ms"], errors="coerce")

def get_series(df, scenario, metric):
    """Return (attack_pcts, values) for one scenario × metric."""
    if df.empty:
        return ATTACK_PCTS, [np.nan] * len(ATTACK_PCTS)
    sub = df[df["attack_scenario"] == scenario].copy()
    sub["attack_percentage"] = pd.to_numeric(sub["attack_percentage"], errors="coerce")
    vals = []
    for pct in ATTACK_PCTS:
        row = sub[sub["attack_percentage"] == pct]
        if row.empty or metric not in row.columns:
            vals.append(np.nan)
        else:
            vals.append(float(row[metric].iloc[-1]))   # last row if duplicates
    return ATTACK_PCTS, vals

# ── Plotting helpers ─────────────────────────────────────────────────────────
def save_fig(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {os.path.relpath(path, BASE)}")

def style_ax(ax, metric_key, ylim_lo, ylim_hi, title):
    ax.set_xlabel("Attack Percentage (%)", fontsize=11)
    ax.set_ylabel(METRICS[metric_key][0], fontsize=11)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.set_xticks(ATTACK_PCTS)
    ax.xaxis.set_tick_params(labelsize=9)
    if metric_key == "tdet_ms":
        ax.set_ylim(ylim_lo, ylim_hi)
    elif ylim_hi is not None:
        ax.set_ylim(ylim_lo, ylim_hi * 1.05)
    else:
        ax.set_ylim(bottom=ylim_lo)
    if metric_key == "tdet_ms":
        ax.set_yticks([0, 25, 50, 75, 100])
        # check if any plotted data sits at -1 and annotate it
        has_neg = any(
            line.get_ydata() is not None and
            any(abs(float(v) - (-1)) < 0.1 for v in line.get_ydata()
                if v is not None and not (isinstance(v, float) and np.isnan(v)))
            for line in ax.get_lines()
        )
        if has_neg:
            ax.axhline(y=-1, color="gray", linestyle=":", linewidth=1.0, alpha=0.6)
            ax.text(ATTACK_PCTS[0], -1, " Not Detected (−1)", fontsize=7,
                    color="gray", va="bottom", ha="left")
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(fontsize=8, loc="best")

# ═══════════════════════════════════════════════════════════════════════════
# 1. Per-method charts: one PNG per (method, attack family, metric)
# ═══════════════════════════════════════════════════════════════════════════
def plot_method_family(df, method_name, method_dir, family, scenarios, metric_key):
    metric_label, ylim_lo, ylim_hi = METRICS[metric_key]
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for scen in scenarios:
        sl = S_LABELS[scen]
        xs, ys = get_series(df, scen, metric_key)
        label = f"{sl} – {SCENARIO_NAMES[scen].split('(')[1].rstrip(')')}"
        ax.plot(xs, ys,
                color=COLORS[sl], linestyle=LINESTYLES[sl],
                marker=MARKERS[sl], markersize=5, linewidth=1.6,
                label=label)

    style_ax(ax, metric_key, ylim_lo, ylim_hi,
             f"{method_name}: {family} — {metric_label} vs Attack Percentage")
    fname = f"{method_name.lower().replace('/', '_')}_{family}_{metric_key}.png"
    save_fig(fig, os.path.join(method_dir, fname))

for method_name, df, method_dir in [
    ("VeReMi+KNN", df_veremi, CHART_VEREMI),
    ("MBSM",       df_mbsm,   CHART_MBSM),
    ("KNN+Bagging",df_knn,    CHART_KNN),
]:
    print(f"\n── {method_name} charts ──")
    for family, scenarios in FAMILIES.items():
        for metric_key in METRICS:
            plot_method_family(df, method_name, method_dir,
                               family, scenarios, metric_key)

# ═══════════════════════════════════════════════════════════════════════════
# 2. Combined charts: all methods on same axes, one PNG per (family, metric)
#    Subplots: 2 rows (S1/S2 detectable, S3/S4 undetectable) × 1 col
# ═══════════════════════════════════════════════════════════════════════════
METHODS_DATA = [
    ("VeReMi+KNN", df_veremi, "solid"),
    ("MBSM",       df_mbsm,   "dashed"),
    ("KNN+Bagging",df_knn,    "dotted"),
]

METHOD_COLORS = {
    "VeReMi+KNN":  {"S1": "#1f77b4", "S2": "#ff7f0e", "S3": "#d62728", "S4": "#9467bd"},
    "MBSM":        {"S1": "#17becf", "S2": "#bcbd22", "S3": "#e377c2", "S4": "#8c564b"},
    "KNN+Bagging": {"S1": "#2ca02c", "S2": "#8c6d31", "S3": "#e7ba52", "S4": "#393b79"},
}

print("\n── Combined charts ──")
for family, scenarios in FAMILIES.items():
    detectable    = [s for s in scenarios if S_LABELS[s] in ("S1", "S2")]
    undetectable  = [s for s in scenarios if S_LABELS[s] in ("S3", "S4")]

    for metric_key in METRICS:
        metric_label, ylim_lo, ylim_hi = METRICS[metric_key]

        fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=False)

        for ax_idx, (ax, subset, subtitle) in enumerate(zip(
            axes,
            [detectable, undetectable],
            ["Detectable scenarios (S1 Mal.Vehicle, S2 Mal.RSU)",
             "Undetectable scenarios (S3 Mal.Controller no RSU, S4 Mal.Controller RSU)"]
        )):
            for method_name, df, ls_base in METHODS_DATA:
                ls = "-" if ls_base == "solid" else "--"
                for scen in subset:
                    sl = S_LABELS[scen]
                    xs, ys = get_series(df, scen, metric_key)
                    col = METHOD_COLORS[method_name][sl]
                    lbl = f"{method_name} {sl}"
                    ax.plot(xs, ys,
                            color=col, linestyle=ls,
                            marker=MARKERS[sl], markersize=5, linewidth=1.6,
                            label=lbl)

            ax.set_xlabel("Attack Percentage (%)", fontsize=10)
            ax.set_ylabel(metric_label, fontsize=10)
            ax.set_title(f"{family} — {subtitle}", fontsize=10, fontweight="bold")
            ax.set_xticks(ATTACK_PCTS)
            ax.xaxis.set_tick_params(labelsize=8, rotation=45)
            if ylim_hi is not None:
                ax.set_ylim(ylim_lo, ylim_hi * 1.05)
            ax.grid(True, linestyle="--", alpha=0.4)
            ax.legend(fontsize=7, loc="best", ncol=2)

        fig.suptitle(
            f"Existing Methods Comparison — {family} Attacks — {metric_label}",
            fontsize=13, fontweight="bold", y=1.02
        )
        fname = f"combined_{family}_{metric_key}.png"
        save_fig(fig, os.path.join(CHART_COMBINED, fname))

# ═══════════════════════════════════════════════════════════════════════════
# 3. Grand overview: 4 metrics × 3 families in one large figure per method
# ═══════════════════════════════════════════════════════════════════════════
print("\n── Grand overview charts ──")
for method_name, df, method_dir in [
    ("VeReMi+KNN", df_veremi, CHART_VEREMI),
    ("MBSM",       df_mbsm,   CHART_MBSM),
    ("KNN+Bagging",df_knn,    CHART_KNN),
]:
    fig, axes = plt.subplots(4, 3, figsize=(18, 20))
    for col_idx, (family, scenarios) in enumerate(FAMILIES.items()):
        for row_idx, metric_key in enumerate(METRICS):
            ax = axes[row_idx][col_idx]
            metric_label, ylim_lo, ylim_hi = METRICS[metric_key]
            for scen in scenarios:
                sl = S_LABELS[scen]
                xs, ys = get_series(df, scen, metric_key)
                ax.plot(xs, ys,
                        color=COLORS[sl], linestyle=LINESTYLES[sl],
                        marker=MARKERS[sl], markersize=4, linewidth=1.4,
                        label=sl)
            ax.set_xlabel("Attack %", fontsize=8)
            ax.set_ylabel(metric_label, fontsize=8)
            ax.set_title(f"{family} — {metric_label}", fontsize=9, fontweight="bold")
            ax.set_xticks(ATTACK_PCTS)
            ax.tick_params(labelsize=7)
            if ylim_hi is not None:
                ax.set_ylim(ylim_lo, ylim_hi * 1.05)
            ax.grid(True, linestyle="--", alpha=0.35)
            ax.legend(fontsize=7, loc="best")

    fig.suptitle(f"{method_name} — All Metrics × All Attack Families",
                 fontsize=14, fontweight="bold")
    save_fig(fig, os.path.join(method_dir, f"{method_name.lower().replace('+','_')}_overview.png"))

# ── Also one combined grand overview ─────────────────────────────────────
fig, axes = plt.subplots(4, 3, figsize=(18, 20))
for col_idx, (family, scenarios) in enumerate(FAMILIES.items()):
    for row_idx, metric_key in enumerate(METRICS):
        ax = axes[row_idx][col_idx]
        metric_label, ylim_lo, ylim_hi = METRICS[metric_key]
        for method_name, df, ls_base in METHODS_DATA:
            ls = "-" if ls_base == "solid" else "--"
            for scen in scenarios:
                sl = S_LABELS[scen]
                xs, ys = get_series(df, scen, metric_key)
                col = METHOD_COLORS[method_name][sl]
                ax.plot(xs, ys, color=col, linestyle=ls,
                        marker=MARKERS[sl], markersize=4, linewidth=1.4,
                        label=f"{method_name[:5]}-{sl}")
        ax.set_xlabel("Attack %", fontsize=8)
        ax.set_ylabel(metric_label, fontsize=8)
        ax.set_title(f"{family} — {metric_label}", fontsize=9, fontweight="bold")
        ax.set_xticks(ATTACK_PCTS)
        ax.tick_params(labelsize=7)
        if ylim_hi is not None:
            ax.set_ylim(ylim_lo, ylim_hi * 1.05)
        ax.grid(True, linestyle="--", alpha=0.35)
        ax.legend(fontsize=6, loc="best", ncol=2)

fig.suptitle("All Existing Methods — All Metrics × All Attack Families",
             fontsize=14, fontweight="bold")
save_fig(fig, os.path.join(CHART_COMBINED, "combined_grand_overview.png"))

print("\n✓ All charts generated.")
print(f"  Per-method VeReMi:       {CHART_VEREMI}")
print(f"  Per-method MBSM:         {CHART_MBSM}")
print(f"  Per-method KNN+Bagging:  {CHART_KNN}")
print(f"  Combined:                {CHART_COMBINED}")
