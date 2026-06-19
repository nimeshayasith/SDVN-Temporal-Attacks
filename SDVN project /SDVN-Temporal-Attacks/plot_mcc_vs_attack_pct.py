#!/usr/bin/env python3
"""
plot_mcc_vs_attack_pct.py
─────────────────────────
Generate three sets of graphs for the Temporal-Echo Topology Attack paper:

  Figure 1 — MCC vs Attack Percentage
  Figure 2 — Detection Latency (T_det) vs Attack Percentage
  Figure 3 — PDR (Packet Delivery Ratio) vs Attack Percentage

Each figure has three subplots, one per attack family:
  TTW (scenarios 1-4)  |  BSHH (scenarios 5-8)  |  ME (scenarios 9-12)

Lines per subplot:
  ─ MBSM_Detect  (Trabelsi 2022)       — solid markers
  ─ VREM_Detect  (Mekonen 2025)        — dashed markers
  ─ KNN+Bagging  (Mekonen 2025, ML)    — dotted markers  [if CSV available]

Each point = mean across seeds; shaded band = ±1 std.

Usage:
  python3 plot_mcc_vs_attack_pct.py \\
      --mbsm   results/temporal_mbsm_compare_summary_all.csv \\
      --veremi results/temporal_veremi_compare_pem_summary_all.csv \\
      --knn    results/knn/temporal_compare_knn_results.csv \\
      --out-dir plots/

Requirements:
  pip install pandas matplotlib numpy
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
except ImportError:
    sys.exit("ERROR: matplotlib not installed — pip install matplotlib")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
FAMILY = {
    "TTW":  [1, 2, 3, 4],
    "BSHH": [5, 6, 7, 8],
    "ME":   [9, 10, 11, 12],
}

SCENARIO_NAMES = {
    0:  "Baseline",
    1:  "TTW-S1 (Veh)",    2:  "TTW-S2 (RSU)",
    3:  "TTW-S3 (Ctrl)",   4:  "TTW-S4 (Ctrl+RSU)",
    5:  "BSHH-S1 (Veh)",   6:  "BSHH-S2 (RSU)",
    7:  "BSHH-S3 (Ctrl)",  8:  "BSHH-S4 (Ctrl+RSU)",
    9:  "ME-S1 (Veh)",     10: "ME-S2 (RSU)",
    11: "ME-S3 (Ctrl)",    12: "ME-S4 (Ctrl+RSU)",
}

DETECTOR_STYLE = {
    "MBSM":  dict(color="#e15759", linestyle="-",  marker="o", linewidth=2.0, markersize=6),
    "VeReMi":dict(color="#4e79a7", linestyle="--", marker="s", linewidth=2.0, markersize=6),
    "KNN":   dict(color="#59a14f", linestyle=":",  marker="^", linewidth=2.0, markersize=6),
}

SCENARIO_LINE_STYLES = [
    dict(color="#1f77b4", linestyle="-"),
    dict(color="#ff7f0e", linestyle="--"),
    dict(color="#2ca02c", linestyle="-."),
    dict(color="#d62728", linestyle=":"),
]

plt.rcParams.update({
    "font.family":    "DejaVu Sans",
    "font.size":      11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize":10,
    "ytick.labelsize":10,
    "legend.fontsize": 9,
    "figure.dpi":     130,
})


# ─────────────────────────────────────────────────────────────────────────────
# Data loading helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_mbsm(path: str) -> pd.DataFrame | None:
    """Load temporal_mbsm_compare_summary_all.csv."""
    if not path or not os.path.isfile(path):
        print(f"  [MBSM] CSV not found: {path} — skipping")
        return None
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    # Rename to unified column names
    col_map = {
        "attack_scenario":      "scenario",
        "attack_percentage":    "attack_pct",
        "mcc":                  "mcc",
        "tdet_ms":              "tdet_ms",
        "pdr_under_attack_pct": "pdr_attack",
    }
    df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
    df["detector"] = "MBSM"
    return df[["scenario", "attack_pct", "detector", "mcc", "tdet_ms", "pdr_attack"]]


def load_veremi(path: str) -> pd.DataFrame | None:
    """Load temporal_veremi_compare_pem_summary_all.csv."""
    if not path or not os.path.isfile(path):
        print(f"  [VeReMi] CSV not found: {path} — skipping")
        return None
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    col_map = {
        "attack_scenario":      "scenario",
        "attack_percentage":    "attack_pct",
        "mcc":                  "mcc",
        "tdet_ms":              "tdet_ms",
        "pdr_under_attack_pct": "pdr_attack",
    }
    df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
    df["detector"] = "VeReMi"
    return df[["scenario", "attack_pct", "detector", "mcc", "tdet_ms", "pdr_attack"]]


def load_knn(path: str) -> pd.DataFrame | None:
    """Load temporal_compare_knn_results.csv (KNN+Bagging holdout per scenario)."""
    if not path or not os.path.isfile(path):
        print(f"  [KNN] CSV not found: {path} — skipping KNN lines")
        return None
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    # KNN results have attack_type not attack_percentage — we treat them as
    # scenario-level results (no per-attack-% sweep from KNN directly).
    # We add attack_pct = "N/A" and tdet_ms = -1 for display purposes.
    if "attack_type" in df.columns:
        df = df.rename(columns={"attack_type": "scenario"})
    # Keep only KNN+Bagging rows
    if "classifier" in df.columns:
        df = df[df["classifier"] == "KNN+Bagging"]
    df["detector"]   = "KNN"
    df["attack_pct"] = None   # no per-% sweep for KNN
    df["tdet_ms"]    = df.get("tdet_ms", -1.0)
    df["pdr_attack"] = None
    return df[["scenario", "attack_pct", "detector", "mcc", "tdet_ms", "pdr_attack"]]


def aggregate(df: pd.DataFrame, metric: str) -> pd.DataFrame:
    """
    Group by (scenario, attack_pct, detector) and compute mean ± std.
    Returns a DataFrame with columns: scenario, attack_pct, detector,
    mean, std.
    """
    df = df[df[metric].notna() & (df[metric] >= -1e6)].copy()
    if metric == "tdet_ms":
        # Only rows where detection actually happened (tdet >= 0)
        df = df[df[metric] >= 0]
    grp = (df.groupby(["scenario", "attack_pct", "detector"])[metric]
             .agg(["mean", "std"])
             .reset_index())
    grp["std"] = grp["std"].fillna(0.0)
    return grp


# ─────────────────────────────────────────────────────────────────────────────
# Plot helpers
# ─────────────────────────────────────────────────────────────────────────────

def plot_family_panel(ax, agg_df: pd.DataFrame, scenarios: list[int],
                      detectors: list[str], metric: str,
                      family_name: str, y_label: str,
                      y_lim: tuple | None = None):
    """
    Draw one subplot: one line per (scenario × detector) combination.
    x-axis = attack_pct  y-axis = metric mean   band = ±std
    """
    ax.set_title(f"{family_name} Attacks")
    ax.set_xlabel("Attack Percentage (%)")
    ax.set_ylabel(y_label)
    if y_lim:
        ax.set_ylim(y_lim)
    ax.grid(True, linestyle="--", alpha=0.4)

    plotted = False
    for det_idx, det in enumerate(detectors):
        det_style = DETECTOR_STYLE.get(det, {})
        for sc_idx, sc in enumerate(scenarios):
            sub = agg_df[
                (agg_df["scenario"] == sc) &
                (agg_df["detector"] == det)
            ].sort_values("attack_pct")

            if sub.empty:
                continue

            sc_color_style = SCENARIO_LINE_STYLES[sc_idx % len(SCENARIO_LINE_STYLES)]

            # Override colour with scenario colour; keep linestyle from detector
            color    = sc_color_style["color"]
            ls       = det_style.get("linestyle", "-")
            marker   = det_style.get("marker", "o")
            lw       = det_style.get("linewidth", 1.8)
            ms       = det_style.get("markersize", 5)

            x   = sub["attack_pct"].values.astype(float)
            y   = sub["mean"].values
            err = sub["std"].values

            line, = ax.plot(x, y, color=color, linestyle=ls, marker=marker,
                            linewidth=lw, markersize=ms,
                            label=f"{det}: {SCENARIO_NAMES.get(sc, sc)}")
            ax.fill_between(x, y - err, y + err,
                            color=color, alpha=0.12, linewidth=0)
            plotted = True

    if plotted:
        ax.legend(loc="best", fontsize=8, framealpha=0.7)


def plot_family_grouped(ax, agg_df: pd.DataFrame, scenarios: list[int],
                        detectors: list[str], metric: str,
                        family_name: str, y_label: str,
                        y_lim: tuple | None = None):
    """
    Alternative: one line per detector, averaged across scenarios in the family.
    Cleaner when many scenarios exist.
    """
    ax.set_title(f"{family_name} Attacks (family average)")
    ax.set_xlabel("Attack Percentage (%)")
    ax.set_ylabel(y_label)
    if y_lim:
        ax.set_ylim(y_lim)
    ax.grid(True, linestyle="--", alpha=0.4)

    plotted = False
    for det in detectors:
        sub = agg_df[
            (agg_df["scenario"].isin(scenarios)) &
            (agg_df["detector"] == det)
        ]
        if sub.empty:
            continue

        # Average family mean across scenarios at each attack_pct
        fam_mean = (sub.groupby("attack_pct")["mean"]
                       .mean().reset_index().sort_values("attack_pct"))
        fam_std  = (sub.groupby("attack_pct")["mean"]
                       .std().fillna(0.0).reset_index().rename(columns={"mean": "std"})
                       .sort_values("attack_pct"))

        x    = fam_mean["attack_pct"].values.astype(float)
        y    = fam_mean["mean"].values
        err  = fam_std["std"].values
        sty  = DETECTOR_STYLE.get(det, {})

        line, = ax.plot(x, y,
                        color=sty.get("color", "black"),
                        linestyle=sty.get("linestyle", "-"),
                        marker=sty.get("marker", "o"),
                        linewidth=sty.get("linewidth", 2.0),
                        markersize=sty.get("markersize", 6),
                        label=det)
        ax.fill_between(x, y - err, y + err,
                        color=sty.get("color", "black"),
                        alpha=0.15, linewidth=0)
        plotted = True

    if plotted:
        ax.legend(loc="best", fontsize=9, framealpha=0.8)


# ─────────────────────────────────────────────────────────────────────────────
# Three main figures
# ─────────────────────────────────────────────────────────────────────────────

def make_figure(agg_df: pd.DataFrame, metric: str, y_label: str,
                title: str, fname: str, out_dir: str,
                y_lim: tuple | None = None,
                per_scenario: bool = False):
    """
    Three-subplot figure (one per attack family), saved to out_dir/fname.
    """
    detectors = agg_df["detector"].unique().tolist()
    families  = list(FAMILY.keys())

    fig, axes = plt.subplots(1, 3, figsize=(17, 5), sharey=True)
    fig.suptitle(title, fontsize=14, fontweight="bold")

    for ax, fam_name in zip(axes, families):
        scens = FAMILY[fam_name]
        if per_scenario:
            plot_family_panel(ax, agg_df, scens, detectors, metric,
                              fam_name, y_label, y_lim)
        else:
            plot_family_grouped(ax, agg_df, scens, detectors, metric,
                                fam_name, y_label, y_lim)

    # Shared legend at figure level (detectors)
    legend_handles = [
        Line2D([0], [0],
               color=DETECTOR_STYLE[d]["color"],
               linestyle=DETECTOR_STYLE[d]["linestyle"],
               marker=DETECTOR_STYLE[d]["marker"],
               linewidth=2.0, markersize=7,
               label=d)
        for d in detectors if d in DETECTOR_STYLE
    ]
    if legend_handles:
        fig.legend(handles=legend_handles,
                   loc="lower center", ncol=len(legend_handles),
                   fontsize=10, framealpha=0.9,
                   bbox_to_anchor=(0.5, -0.05))

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    out_path = os.path.join(out_dir, fname)
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {out_path}")


def make_per_scenario_figure(agg_df: pd.DataFrame, metric: str, y_label: str,
                              title: str, fname: str, out_dir: str,
                              y_lim: tuple | None = None):
    """
    Same three-subfamily layout but with individual scenario lines
    (more detail, noisier legend).
    """
    make_figure(agg_df, metric, y_label, title, fname, out_dir, y_lim,
                per_scenario=True)


def make_heatmap(agg_df: pd.DataFrame, metric: str, detector: str,
                 fname: str, out_dir: str, title: str):
    """
    Heatmap: rows = attack scenario (1-12), columns = attack_pct (0-100).
    Cell value = mean metric.  Good for a quick overview.
    """
    sub = agg_df[agg_df["detector"] == detector].copy()
    if sub.empty:
        return

    sub = sub[sub["scenario"].between(1, 12)]
    pivot = sub.pivot_table(index="scenario", columns="attack_pct",
                             values="mean", aggfunc="mean")
    pivot = pivot.sort_index()
    pivot.index = [SCENARIO_NAMES.get(s, str(s)) for s in pivot.index]

    fig, ax = plt.subplots(figsize=(12, 6))
    im = ax.imshow(pivot.values, aspect="auto", cmap="RdYlGn",
                   vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels([f"{int(c)}%" for c in pivot.columns], fontsize=9)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index, fontsize=9)
    ax.set_xlabel("Attack Percentage (%)")
    ax.set_title(f"{title} — {detector}", fontsize=13, fontweight="bold")
    plt.colorbar(im, ax=ax, label=metric)

    for r in range(len(pivot.index)):
        for c in range(len(pivot.columns)):
            val = pivot.values[r, c]
            if not np.isnan(val):
                ax.text(c, r, f"{val:.2f}", ha="center", va="center",
                        fontsize=7,
                        color="black" if 0.3 < val < 0.8 else "white")

    plt.tight_layout()
    out_path = os.path.join(out_dir, fname)
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Plot MCC / T_det / PDR vs attack percentage for Temporal-Echo study"
    )
    parser.add_argument("--mbsm",   default=None,
                        help="Path to temporal_mbsm_compare_summary_all.csv")
    parser.add_argument("--veremi", default=None,
                        help="Path to temporal_veremi_compare_pem_summary_all.csv")
    parser.add_argument("--knn",    default=None,
                        help="Path to temporal_compare_knn_results.csv (optional)")
    parser.add_argument("--out-dir", default="plots",
                        help="Output directory for PNG graphs (default: plots/)")
    parser.add_argument("--per-scenario", action="store_true",
                        help="Also produce per-scenario line plots (one line per scenario)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # ── Load data ──────────────────────────────────────────────────────────
    frames = []
    df_mbsm   = load_mbsm(args.mbsm)
    df_veremi = load_veremi(args.veremi)
    df_knn    = load_knn(args.knn)

    if df_mbsm   is not None: frames.append(df_mbsm)
    if df_veremi is not None: frames.append(df_veremi)
    # KNN has no per-attack-% sweep — we still include it in scenario-level plots
    # but skip it for the attack-% line plots.

    if not frames:
        sys.exit("ERROR: No input CSVs found. Provide at least one of --mbsm or --veremi.")

    combined = pd.concat(frames, ignore_index=True)

    # Filter out baseline (scenario=0) from attack-% sweep plots
    sweep_df = combined[combined["scenario"] > 0].copy()

    # ── Aggregate ──────────────────────────────────────────────────────────
    agg_mcc = aggregate(sweep_df, "mcc")
    agg_tdet = aggregate(sweep_df[sweep_df["tdet_ms"] >= 0], "tdet_ms") \
               if "tdet_ms" in sweep_df.columns else pd.DataFrame()
    agg_pdr  = aggregate(sweep_df[sweep_df["pdr_attack"].notna()], "pdr_attack") \
               if "pdr_attack" in sweep_df.columns else pd.DataFrame()

    # ── Detectors present ─────────────────────────────────────────────────
    detectors = sweep_df["detector"].unique().tolist()
    print(f"\nDetectors found: {detectors}")
    print(f"Scenarios found: {sorted(sweep_df['scenario'].unique().tolist())}")
    print(f"Attack% range  : {sorted(sweep_df['attack_pct'].dropna().unique().tolist())}")
    print()

    # ══ Figure 1 — MCC vs Attack Percentage ═══════════════════════════════
    print("Generating MCC vs Attack Percentage graphs …")
    make_figure(
        agg_mcc, "mean",
        y_label="Matthews Correlation Coefficient (MCC)",
        title="MCC vs Attack Percentage — Temporal-Echo Topology Attacks",
        fname="mcc_vs_attack_pct_grouped.png",
        out_dir=args.out_dir,
        y_lim=(-0.05, 1.05),
    )
    if args.per_scenario:
        make_per_scenario_figure(
            agg_mcc, "mean",
            y_label="MCC",
            title="MCC vs Attack Percentage (per scenario)",
            fname="mcc_vs_attack_pct_per_scenario.png",
            out_dir=args.out_dir,
            y_lim=(-0.05, 1.05),
        )

    # Heatmaps — one per detector
    for det in detectors:
        make_heatmap(
            agg_mcc, "mcc (mean)", det,
            fname=f"mcc_heatmap_{det.lower()}.png",
            out_dir=args.out_dir,
            title="MCC",
        )

    # ══ Figure 2 — T_det vs Attack Percentage ═════════════════════════════
    if not agg_tdet.empty:
        print("Generating T_det vs Attack Percentage graphs …")
        make_figure(
            agg_tdet, "mean",
            y_label="Detection Latency T_det (ms)",
            title="Detection Latency vs Attack Percentage — Temporal-Echo Topology Attacks",
            fname="tdet_vs_attack_pct_grouped.png",
            out_dir=args.out_dir,
        )
        if args.per_scenario:
            make_per_scenario_figure(
                agg_tdet, "mean",
                y_label="T_det (ms)",
                title="T_det vs Attack Percentage (per scenario)",
                fname="tdet_vs_attack_pct_per_scenario.png",
                out_dir=args.out_dir,
            )
    else:
        print("  [T_det] No positive detection latency data — skipping T_det graphs")

    # ══ Figure 3 — PDR vs Attack Percentage ═══════════════════════════════
    if not agg_pdr.empty:
        print("Generating PDR vs Attack Percentage graphs …")
        make_figure(
            agg_pdr, "mean",
            y_label="Packet Delivery Ratio (%)",
            title="PDR vs Attack Percentage — Temporal-Echo Topology Attacks",
            fname="pdr_vs_attack_pct_grouped.png",
            out_dir=args.out_dir,
            y_lim=(0, 105),
        )
        if args.per_scenario:
            make_per_scenario_figure(
                agg_pdr, "mean",
                y_label="PDR (%)",
                title="PDR vs Attack Percentage (per scenario)",
                fname="pdr_vs_attack_pct_per_scenario.png",
                out_dir=args.out_dir,
                y_lim=(0, 105),
            )
    else:
        print("  [PDR] No PDR data available — skipping PDR graphs")

    # ══ KNN scenario-level MCC bar chart ══════════════════════════════════
    if df_knn is not None and not df_knn.empty:
        print("Generating KNN+Bagging per-scenario MCC bar chart …")
        knn_sub = df_knn[df_knn["scenario"].between(1, 12)].copy()
        if not knn_sub.empty:
            fig, ax = plt.subplots(figsize=(13, 5))
            sc_list = sorted(knn_sub["scenario"].unique())
            x = np.arange(len(sc_list))
            mcc_vals = [knn_sub.loc[knn_sub["scenario"] == s, "mcc"].mean()
                        for s in sc_list]
            colours = ["#e15759" if v < 0.05 else "#59a14f" for v in mcc_vals]
            ax.bar(x, mcc_vals, color=colours, edgecolor="white", linewidth=0.8)
            ax.set_xticks(x)
            ax.set_xticklabels([SCENARIO_NAMES.get(s, str(s)) for s in sc_list],
                               rotation=35, ha="right", fontsize=9)
            ax.set_ylabel("MCC (holdout)")
            ax.set_ylim(-0.05, 1.05)
            ax.set_title("KNN+Bagging MCC per Temporal-Echo Scenario",
                         fontsize=13, fontweight="bold")
            ax.axhline(0.0, color="black", linewidth=0.8, linestyle="--")
            ax.grid(axis="y", linestyle="--", alpha=0.4)
            legend_patches = [
                Patch(facecolor="#e15759", label="MCC ≈ 0 (undetectable — control-plane attack)"),
                Patch(facecolor="#59a14f", label="MCC > 0 (detectable — data-plane anomaly present)"),
            ]
            ax.legend(handles=legend_patches, fontsize=9, loc="upper right")
            plt.tight_layout()
            out_path = os.path.join(args.out_dir, "knn_mcc_per_scenario.png")
            fig.savefig(out_path, bbox_inches="tight")
            plt.close(fig)
            print(f"  Saved: {out_path}")

    # ══ Combined 3-detector comparison at scenario level ══════════════════
    # One bar per scenario, grouped by detector — good for supervisor meeting slides
    if df_knn is not None and len(frames) >= 1:
        print("Generating 3-detector MCC comparison bar chart …")
        det_dfs = {}
        if df_mbsm is not None:
            det_dfs["MBSM"] = (df_mbsm[df_mbsm["scenario"] > 0]
                               .groupby("scenario")["mcc"].mean())
        if df_veremi is not None:
            det_dfs["VeReMi"] = (df_veremi[df_veremi["scenario"] > 0]
                                 .groupby("scenario")["mcc"].mean())
        if df_knn is not None:
            det_dfs["KNN"] = (df_knn[df_knn["scenario"] > 0]
                              .groupby("scenario")["mcc"].mean())

        sc_list = sorted(set.union(*[set(v.index) for v in det_dfs.values()]))
        sc_list = [s for s in sc_list if 1 <= s <= 12]
        n_sc = len(sc_list)
        n_det = len(det_dfs)
        if n_sc > 0 and n_det > 0:
            width = 0.25
            x = np.arange(n_sc)
            fig, ax = plt.subplots(figsize=(14, 5))
            for i, (det_name, mcc_series) in enumerate(det_dfs.items()):
                vals = [mcc_series.get(s, 0.0) for s in sc_list]
                offset = (i - (n_det - 1) / 2) * width
                sty = DETECTOR_STYLE.get(det_name, {})
                ax.bar(x + offset, vals, width=width * 0.9,
                       color=sty.get("color", f"C{i}"),
                       label=det_name, edgecolor="white", linewidth=0.6)

            ax.set_xticks(x)
            ax.set_xticklabels([SCENARIO_NAMES.get(s, str(s)) for s in sc_list],
                               rotation=35, ha="right", fontsize=9)
            ax.set_ylabel("MCC (mean across attack-% sweep)")
            ax.set_ylim(-0.05, 1.05)
            ax.set_title("Detector MCC Comparison — All Temporal-Echo Scenarios",
                         fontsize=13, fontweight="bold")
            ax.axhline(0.0, color="black", linewidth=0.8, linestyle="--")
            ax.legend(fontsize=10, loc="upper right")
            ax.grid(axis="y", linestyle="--", alpha=0.4)
            plt.tight_layout()
            out_path = os.path.join(args.out_dir, "detector_comparison_mcc.png")
            fig.savefig(out_path, bbox_inches="tight")
            plt.close(fig)
            print(f"  Saved: {out_path}")

    print(f"\nAll graphs saved to: {os.path.abspath(args.out_dir)}")


if __name__ == "__main__":
    main()
