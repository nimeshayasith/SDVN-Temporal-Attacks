#!/usr/bin/env python3
"""
plot_temporal_results.py
─────────────────────────
Generate performance plots comparing three detection mechanisms against
Temporal-Echo topology attacks in SDVNs:

  1. MBSM_Detect  — Trabelsi et al., Electronics 2022
  2. VREM_Detect  — Mekonen et al., PLOS ONE 2025
  3. KNN+Bagging  — Mekonen et al., PLOS ONE 2025 (ML ensemble)

Plots produced (saved to --out-dir, default: plots/):
  mbsm_panel.png            MCC + AUROC vs attack % (all 12 scenarios)
  mbsm_mcc.png              MCC vs attack % (individual)
  mbsm_auroc.png            AUROC vs attack % (individual)
  mbsm_pdr.png              PDR vs attack % (individual)
  veremi_panel.png          MCC + AUROC vs attack % (all 12 scenarios)
  veremi_mcc.png
  veremi_auroc.png
  veremi_pdr.png
  knn_all_classifiers.png   MCC per scenario, all 4 classifiers (grouped bar)
  knn_knnbagging.png        MCC per scenario, KNN+Bagging only (coloured bar)
  comparison_s2_s6.png      S2 & S6: MBSM vs VeReMi vs KNN on same axes

Usage:
  python3 plot_temporal_results.py \\
      --mbsm   results/mbsm/mbsm_summary_all.csv \\
      --veremi results/veremi/veremi_summary_all.csv \\
      --knn    results/knn_holdout_all_scenarios.csv \\
      --out-dir plots/
"""

import argparse
import os
import sys
import pandas as pd

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

except ImportError:
    print("ERROR: matplotlib not installed.  pip install matplotlib")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Global style
# ─────────────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':     'DejaVu Sans',
    'font.size':       11,
    'axes.titlesize':  13,
    'axes.labelsize':  12,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 9,
    'figure.dpi':      120,
})

# ─────────────────────────────────────────────────────────────────────────────
# Scenario metadata
# ─────────────────────────────────────────────────────────────────────────────
SCENARIO_NAMES = {
    1:  "TTW-S1",   2:  "TTW-S2",   3:  "TTW-S3",   4:  "TTW-S4",
    5:  "BSHH-S1",  6:  "BSHH-S2",  7:  "BSHH-S3",  8:  "BSHH-S4",
    9:  "ME-S1",    10: "ME-S2",    11: "ME-S3",    12: "ME-S4",
}

# S2 = red  (TTW-S2, Malicious RSU — detectable)
# S6 = blue (BSHH-S2, Malicious RSU — detectable)
# Others: distinct muted colours; solid lines for detectable, dashed for rest
COLORS = {
    1:  '#888888',   # TTW-S1   mid-gray
    2:  '#e41a1c',   # TTW-S2   RED       ← detectable
    3:  '#aaaaaa',   # TTW-S3   light-gray
    4:  '#cccccc',   # TTW-S4   lighter-gray
    5:  '#4daf4a',   # BSHH-S1  green
    6:  '#377eb8',   # BSHH-S2  BLUE      ← detectable
    7:  '#984ea3',   # BSHH-S3  purple
    8:  '#ff7f00',   # BSHH-S4  orange
    9:  '#a65628',   # ME-S1    brown
    10: '#f781bf',   # ME-S2    pink
    11: '#444444',   # ME-S3    dark-gray
    12: '#e6ab02',   # ME-S4    gold
}

MARKERS = {
    1: 'o',  2: 's',  3: '^',  4: 'v',
    5: 'D',  6: 'P',  7: 'X',  8: '*',
    9: 'h', 10: 'p', 11: 'x', 12: '8',
}

LINESTYLES = {sc: ('--' if sc not in {2, 6} else '-') for sc in range(1, 13)}

DETECTABLE = {2, 6}

# KNN classifier colours (for grouped bar chart)
CLF_COLORS = {
    'DT+Bagging':  '#4daf4a',
    'RF+Bagging':  '#e41a1c',
    'KNN+Bagging': '#377eb8',
    'MLP+Bagging': '#ff7f00',
}
CLF_HATCHES = {
    'DT+Bagging':  '',
    'RF+Bagging':  '//',
    'KNN+Bagging': 'xx',
    'MLP+Bagging': '..',
}
CLF_ORDER = ['DT+Bagging', 'RF+Bagging', 'KNN+Bagging', 'MLP+Bagging']


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────
def _load_csv(path, label):
    if path is None or not os.path.isfile(path):
        print(f"  [WARN] {label} CSV not found: {path}")
        return None
    try:
        df = pd.read_csv(path)
        print(f"  Loaded {label}: {len(df)} rows  ({path})")
        return df
    except Exception as e:
        print(f"  [ERROR] Could not read {label} CSV: {e}")
        return None


def load_rule_based(path, label):
    """Load MBSM or VeReMi summary CSV produced by the .cc comparison files."""
    df = _load_csv(path, label)
    if df is None:
        return None
    # Normalise column name: both files use 'attack_scenario'
    for alt in ('attack_type', 'scenario'):
        if 'attack_scenario' not in df.columns and alt in df.columns:
            df = df.rename(columns={alt: 'attack_scenario'})
    df['attack_scenario']  = pd.to_numeric(df['attack_scenario'],  errors='coerce')
    df['attack_percentage'] = pd.to_numeric(df['attack_percentage'], errors='coerce')
    df['mcc']              = pd.to_numeric(df['mcc'],               errors='coerce').fillna(0.0)
    df['auroc']            = pd.to_numeric(df['auroc'],             errors='coerce').fillna(0.5)
    for col in ('pdr_under_attack_pct', 'pdr_baseline_pct',
                'te2e_under_attack_ms', 'te2e_baseline_ms', 'tdet_ms'):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df[df['attack_scenario'].between(1, 12)].copy()
    return df


def load_knn(path):
    """Load KNN holdout CSV produced by temporal_veremi_compare_knn.py."""
    df = _load_csv(path, 'KNN holdout')
    if df is None:
        return None
    for alt in ('attack_scenario',):
        if 'attack_type' not in df.columns and alt in df.columns:
            df = df.rename(columns={alt: 'attack_type'})
    df['attack_type'] = pd.to_numeric(df['attack_type'], errors='coerce')
    df['mcc']         = pd.to_numeric(df['mcc'],         errors='coerce').fillna(0.0)
    df['auroc']       = pd.to_numeric(df['auroc'],       errors='coerce').fillna(0.5)
    df = df[df['attack_type'].between(1, 12)].copy()
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Legend helpers
# ─────────────────────────────────────────────────────────────────────────────
def _legend_handles(present_scenarios=None):
    """Return Line2D legend handles for all 12 (or a subset of) scenarios."""
    scs = present_scenarios if present_scenarios else list(range(1, 13))
    return [
        Line2D([0], [0],
               color=COLORS[sc],
               marker=MARKERS[sc],
               linestyle=LINESTYLES[sc],
               linewidth=2 if sc in DETECTABLE else 1.5,
               markersize=7 if sc in DETECTABLE else 5,
               label=f"{SCENARIO_NAMES[sc]}{'  ★' if sc in DETECTABLE else ''}")
        for sc in scs
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Core single-axis plot helper
# ─────────────────────────────────────────────────────────────────────────────
def _draw_metric(ax, df, metric, scenarios, ylabel, ylim, xticks=None):
    """Draw one metric vs attack_percentage on ax, one line per scenario."""
    for sc in scenarios:
        sc_df = df[df['attack_scenario'] == sc].sort_values('attack_percentage')
        if sc_df.empty or metric not in sc_df.columns:
            continue
        x = sc_df['attack_percentage'].values
        y = sc_df[metric].values
        ax.plot(x, y,
                color=COLORS.get(sc, '#555555'),
                marker=MARKERS.get(sc, 'o'),
                linestyle=LINESTYLES.get(sc, '--'),
                linewidth=2.5 if sc in DETECTABLE else 1.5,
                markersize=7  if sc in DETECTABLE else 4,
                zorder=3      if sc in DETECTABLE else 2)

    ax.set_xlabel('Attack Percentage (%)', fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xlim([-3, 103])
    ax.set_ylim(ylim)
    ax.set_xticks(xticks if xticks else range(0, 101, 10))
    ax.grid(True, linestyle='--', alpha=0.45)
    ax.tick_params(axis='both', which='major', labelsize=10)


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based detector: panel (MCC + AUROC side-by-side) + individual plots
# ─────────────────────────────────────────────────────────────────────────────
def plot_rule_based(df, detector_label, prefix, out_dir):
    scenarios = sorted(df['attack_scenario'].dropna().unique().astype(int))
    scenarios = [s for s in scenarios if 1 <= s <= 12]
    handles   = _legend_handles(scenarios)

    # ── Panel: MCC and AUROC side by side ─────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(15, 5.5))
    fig.suptitle(f'{detector_label}\nDetection Performance vs Attack Percentage (%)',
                 fontsize=14, fontweight='bold', y=1.02)

    _draw_metric(axes[0], df, 'mcc',
                 scenarios,
                 ylabel='Matthews Correlation Coefficient (MCC)',
                 ylim=(-0.05, 1.08))
    axes[0].set_title('MCC vs Attack Percentage', fontsize=12)
    axes[0].set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])

    _draw_metric(axes[1], df, 'auroc',
                 scenarios,
                 ylabel='Area Under ROC Curve (AUROC)',
                 ylim=(0.44, 1.08))
    axes[1].set_title('AUROC vs Attack Percentage', fontsize=12)
    axes[1].set_yticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])

    fig.legend(handles=handles,
               loc='lower center', ncol=6, fontsize=9,
               bbox_to_anchor=(0.5, -0.14), framealpha=0.95,
               title='Attack Scenario  (★ = detectable by this mechanism)')
    fig.tight_layout()
    _save(fig, out_dir, f'{prefix}_panel.png')

    # ── Individual plots ───────────────────────────────────────────────────
    metric_specs = [
        ('mcc',   'Matthews Correlation Coefficient (MCC)',  (-0.05, 1.08),
         [0.0, 0.2, 0.4, 0.6, 0.8, 1.0], 'MCC vs Attack Percentage'),
        ('auroc', 'Area Under ROC Curve (AUROC)',            (0.44,  1.08),
         [0.5, 0.6, 0.7, 0.8, 0.9, 1.0], 'AUROC vs Attack Percentage'),
    ]

    # PDR if available
    if 'pdr_under_attack_pct' in df.columns:
        metric_specs.append((
            'pdr_under_attack_pct',
            'Packet Delivery Ratio Under Attack (%)',
            (-2, 105),
            [0, 20, 40, 60, 80, 100],
            'PDR vs Attack Percentage',
        ))

    for metric, ylabel, ylim, yticks, title in metric_specs:
        fig2, ax2 = plt.subplots(figsize=(9, 5.5))
        _draw_metric(ax2, df, metric, scenarios, ylabel, ylim)
        ax2.set_yticks(yticks)
        ax2.set_title(f'{detector_label}\n{title}', fontsize=12, fontweight='bold')
        ax2.legend(handles=handles, loc='best', ncol=2, fontsize=8,
                   framealpha=0.95,
                   title='Scenario  (★ = detectable)')
        fig2.tight_layout()
        suffix = metric.split('_')[0]   # mcc / auroc / pdr
        _save(fig2, out_dir, f'{prefix}_{suffix}.png')


# ─────────────────────────────────────────────────────────────────────────────
# KNN+Bagging: line plots (MCC vs attack percentage)
#
# The KNN CSV has one MCC value per scenario (trained on all attack percentages
# combined).  Non-detectable scenarios (S1,S3,S4,S5,S7-S12) produce no label=1
# pairs → not in CSV → MCC=0.  Detectable scenarios (S2,S6) → MCC=1.
# We show these as flat horizontal lines across the 0-100 % x-axis so the plot
# matches the MBSM / VeReMi line-plot format exactly.
# ─────────────────────────────────────────────────────────────────────────────
def _knn_scenario_mccs(df, clf_name):
    """Return dict {scenario: mcc} for all 12 scenarios for one classifier."""
    clf_df = df[df['classifier'] == clf_name]
    result = {}
    for sc in range(1, 13):
        row = clf_df[clf_df['attack_type'] == sc]
        result[sc] = float(row['mcc'].iloc[0]) if not row.empty else 0.0
    return result


def _knn_scenario_aurocs(df, clf_name):
    clf_df = df[df['classifier'] == clf_name]
    result = {}
    for sc in range(1, 13):
        row = clf_df[clf_df['attack_type'] == sc]
        result[sc] = float(row['auroc'].iloc[0]) if not row.empty else 0.5
    return result


def _draw_knn_lines(ax, scenario_vals, ylabel, ylim, yticks, marker_every=2):
    """Plot 12 flat lines (one per scenario) across attack_percentage 0-100."""
    attack_pcts = list(range(0, 101, 10))
    for sc in range(1, 13):
        val = scenario_vals.get(sc, 0.0)
        y   = [val] * len(attack_pcts)
        ax.plot(attack_pcts, y,
                color=COLORS.get(sc, '#555555'),
                marker=MARKERS.get(sc, 'o'),
                linestyle=LINESTYLES.get(sc, '--'),
                linewidth=2.5 if sc in DETECTABLE else 1.5,
                markersize=7  if sc in DETECTABLE else 4,
                markevery=marker_every,
                zorder=3 if sc in DETECTABLE else 2)
    ax.set_xlabel('Attack Percentage (%)', fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xlim([-3, 103])
    ax.set_ylim(ylim)
    ax.set_xticks(range(0, 101, 10))
    ax.set_yticks(yticks)
    ax.grid(True, linestyle='--', alpha=0.45)
    ax.tick_params(axis='both', which='major', labelsize=10)


def plot_knn(df, out_dir):
    ALL_SCENARIOS = list(range(1, 13))
    handles       = _legend_handles(ALL_SCENARIOS)
    present_clfs  = [c for c in CLF_ORDER if c in df['classifier'].values]

    # ── Panel: MCC + AUROC (KNN+Bagging only) ─────────────────────────────
    if 'KNN+Bagging' in df['classifier'].values:
        mcc_vals  = _knn_scenario_mccs(df,  'KNN+Bagging')
        auroc_vals = _knn_scenario_aurocs(df, 'KNN+Bagging')

        fig, axes = plt.subplots(1, 2, figsize=(15, 5.5))
        fig.suptitle(
            'KNN+Bagging (Mekonen et al., PLOS ONE 2025)\n'
            'Detection Performance vs Attack Percentage (%)',
            fontsize=14, fontweight='bold', y=1.02,
        )
        _draw_knn_lines(axes[0], mcc_vals,
                        'Matthews Correlation Coefficient (MCC)',
                        (-0.05, 1.08), [0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
        axes[0].set_title('MCC vs Attack Percentage', fontsize=12)

        _draw_knn_lines(axes[1], auroc_vals,
                        'Area Under ROC Curve (AUROC)',
                        (0.44, 1.08), [0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
        axes[1].set_title('AUROC vs Attack Percentage', fontsize=12)

        fig.legend(handles=handles, loc='lower center', ncol=6, fontsize=9,
                   bbox_to_anchor=(0.5, -0.14), framealpha=0.95,
                   title='Attack Scenario  (★ = detectable by KNN+Bagging)')
        fig.tight_layout()
        _save(fig, out_dir, 'knn_panel.png')

        # Individual MCC line plot
        fig2, ax2 = plt.subplots(figsize=(9, 5.5))
        _draw_knn_lines(ax2, mcc_vals,
                        'Matthews Correlation Coefficient (MCC)',
                        (-0.05, 1.08), [0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
        ax2.set_title('KNN+Bagging\nMCC vs Attack Percentage (%)',
                      fontsize=12, fontweight='bold')
        ax2.legend(handles=handles, loc='best', ncol=2, fontsize=8,
                   framealpha=0.95, title='Scenario  (★ = detectable)')
        fig2.tight_layout()
        _save(fig2, out_dir, 'knn_mcc.png')

        # Individual AUROC line plot
        fig3, ax3 = plt.subplots(figsize=(9, 5.5))
        _draw_knn_lines(ax3, auroc_vals,
                        'Area Under ROC Curve (AUROC)',
                        (0.44, 1.08), [0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
        ax3.set_title('KNN+Bagging\nAUROC vs Attack Percentage (%)',
                      fontsize=12, fontweight='bold')
        ax3.legend(handles=handles, loc='best', ncol=2, fontsize=8,
                   framealpha=0.95, title='Scenario  (★ = detectable)')
        fig3.tight_layout()
        _save(fig3, out_dir, 'knn_auroc.png')

    # ── All 4 classifiers: one subplot each ───────────────────────────────
    if len(present_clfs) > 1:
        fig4, axes4 = plt.subplots(2, 2, figsize=(16, 11))
        fig4.suptitle(
            'KNN+Bagging Ensemble — All 4 Classifiers\n'
            'MCC vs Attack Percentage (%)',
            fontsize=14, fontweight='bold',
        )
        clf_ax_map = list(zip(present_clfs, axes4.flatten()))
        for clf, ax in clf_ax_map:
            mcc_v = _knn_scenario_mccs(df, clf)
            _draw_knn_lines(ax, mcc_v,
                            'MCC',
                            (-0.05, 1.08), [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
                            marker_every=5)
            ax.set_title(clf, fontsize=12, fontweight='bold')
        # Hide unused subplots
        for ax in axes4.flatten()[len(present_clfs):]:
            ax.set_visible(False)
        fig4.legend(handles=handles, loc='lower center', ncol=6, fontsize=9,
                    bbox_to_anchor=(0.5, -0.04), framealpha=0.95,
                    title='Attack Scenario  (★ = detectable)')
        fig4.tight_layout()
        _save(fig4, out_dir, 'knn_all_classifiers.png')

    # ── S2 vs S6 line plot (detectable only, all 4 classifiers) ───────────
    fig5, ax5 = plt.subplots(figsize=(10, 5.5))
    clf_line_styles = ['-', '--', '-.', ':']
    for clf, ls in zip(present_clfs, clf_line_styles):
        mcc_v = _knn_scenario_mccs(df, clf)
        attack_pcts = list(range(0, 101, 10))
        for sc in DETECTABLE:
            val = mcc_v.get(sc, 0.0)
            ax5.plot(attack_pcts, [val] * len(attack_pcts),
                     color=COLORS[sc],
                     linestyle=ls,
                     marker=MARKERS[sc],
                     linewidth=2.5, markersize=7, markevery=2,
                     label=f'{SCENARIO_NAMES[sc]} — {clf}')

    ax5.set_xlabel('Attack Percentage (%)', fontsize=12)
    ax5.set_ylabel('Matthews Correlation Coefficient (MCC)', fontsize=12)
    ax5.set_title('KNN+Bagging — MCC vs Attack Percentage\n'
                  'Detectable Scenarios: TTW-S2 (red) and BSHH-S2 (blue)',
                  fontsize=12, fontweight='bold')
    ax5.set_xlim([-3, 103])
    ax5.set_ylim([-0.05, 1.08])
    ax5.set_xticks(range(0, 101, 10))
    ax5.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax5.grid(True, linestyle='--', alpha=0.45)
    ax5.legend(fontsize=9, ncol=2, framealpha=0.95)
    fig5.tight_layout()
    _save(fig5, out_dir, 'knn_knnbagging.png')


# ─────────────────────────────────────────────────────────────────────────────
# Comparison: S2 and S6 — all three detectors on same axes
# ─────────────────────────────────────────────────────────────────────────────
def plot_comparison_s2_s6(mbsm_df, veremi_df, knn_df, out_dir):
    """
    For S2 (TTW-S2) and S6 (BSHH-S2): overlay MCC from all three detectors.
    Rule-based detectors → line vs attack_percentage.
    KNN → horizontal dashed line (trained on all percentages combined).
    """
    det_configs = [
        ('MBSM_Detect (Trabelsi 2022)',  mbsm_df,   '#e41a1c', '-',  's', 2.5),
        ('VREM_Detect (Mekonen 2025)',   veremi_df, '#377eb8', '--', 'o', 2.5),
    ]
    knn_color = '#4daf4a'

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), sharey=True)
    fig.suptitle(
        'Detection Capability Comparison: S2 (TTW-S2) and S6 (BSHH-S2)\n'
        'Only scenarios where a BSM-layer anomaly (stale position) exists',
        fontsize=13, fontweight='bold',
    )

    for ax, sc in zip(axes, [2, 6]):
        for det_label, df, col, ls, mk, lw in det_configs:
            if df is None:
                continue
            sc_df = df[df['attack_scenario'] == sc].sort_values('attack_percentage')
            if sc_df.empty:
                continue
            ax.plot(sc_df['attack_percentage'], sc_df['mcc'],
                    color=col, linestyle=ls, marker=mk,
                    linewidth=lw, markersize=7, label=det_label)

        if knn_df is not None:
            knn_row = knn_df[
                (knn_df['attack_type'] == sc) &
                (knn_df['classifier'] == 'KNN+Bagging')
            ]
            if not knn_row.empty:
                knn_mcc = float(knn_row['mcc'].iloc[0])
                ax.axhline(knn_mcc,
                           color=knn_color, linestyle=':', linewidth=2.5,
                           label=f'KNN+Bagging  (MCC = {knn_mcc:.2f})')

        ax.set_xlabel('Attack Percentage (%)', fontsize=12)
        ax.set_ylabel('Matthews Correlation Coefficient (MCC)', fontsize=12)
        ax.set_title(f'{SCENARIO_NAMES[sc]} — MCC vs Attack Percentage', fontsize=12)
        ax.set_xlim([-3, 103])
        ax.set_ylim([-0.05, 1.10])
        ax.set_xticks(range(0, 101, 10))
        ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
        ax.grid(True, linestyle='--', alpha=0.45)
        ax.legend(fontsize=10, framealpha=0.95, loc='best')

    fig.tight_layout()
    _save(fig, out_dir, 'comparison_s2_s6.png')


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────
def _save(fig, out_dir, filename):
    path = os.path.join(out_dir, filename)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Generate Temporal-Echo detection performance plots'
    )
    parser.add_argument(
        '--mbsm',
        default='results/mbsm/mbsm_summary_all.csv',
        help='MBSM summary CSV  (default: results/mbsm/mbsm_summary_all.csv)',
    )
    parser.add_argument(
        '--veremi',
        default='results/veremi/veremi_summary_all.csv',
        help='VeReMi summary CSV  (default: results/veremi/veremi_summary_all.csv)',
    )
    parser.add_argument(
        '--knn',
        default='results/knn_holdout_all_scenarios.csv',
        help='KNN holdout CSV  (default: results/knn_holdout_all_scenarios.csv)',
    )
    parser.add_argument(
        '--out-dir',
        default='plots',
        help='Output directory for PNG files  (default: plots/)',
    )
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print(f"\nLoading data...")
    mbsm_df   = load_rule_based(args.mbsm,   'MBSM')
    veremi_df = load_rule_based(args.veremi,  'VeReMi')
    knn_df    = load_knn(args.knn)

    any_loaded = any(df is not None for df in [mbsm_df, veremi_df, knn_df])
    if not any_loaded:
        print("\nERROR: No CSV files found. Run the simulation first:")
        print("  bash run_temporal_attack_study.sh")
        sys.exit(1)

    print(f"\nGenerating plots → {args.out_dir}/")

    if mbsm_df is not None:
        print("\n  [1/4] MBSM_Detect plots...")
        plot_rule_based(
            mbsm_df,
            'MBSM_Detect (Trabelsi et al., Electronics 2022)',
            'mbsm', args.out_dir,
        )

    if veremi_df is not None:
        print("\n  [2/4] VREM_Detect plots...")
        plot_rule_based(
            veremi_df,
            'VREM_Detect (Mekonen et al., PLOS ONE 2025)',
            'veremi', args.out_dir,
        )

    if knn_df is not None:
        print("\n  [3/4] KNN+Bagging plots...")
        plot_knn(knn_df, args.out_dir)

    if mbsm_df is not None or veremi_df is not None:
        print("\n  [4/4] S2 / S6 comparison plot...")
        plot_comparison_s2_s6(mbsm_df, veremi_df, knn_df, args.out_dir)

    print(f"\nDone.  All plots saved to: {args.out_dir}/")
    generated = [f for f in sorted(os.listdir(args.out_dir)) if f.endswith('.png')]
    for f in generated:
        print(f"  {f}")


if __name__ == '__main__':
    main()
