"""
generate_npfads_plots.py
Generates all 17 NPFADS analysis figures from ALL_NPFADS_PEM_Run_Summary.csv.
Run from the folder that contains the CSV:
    python generate_npfads_plots.py
"""

import matplotlib.pyplot as plt
import matplotlib
import pandas as pd
import numpy as np
import os

matplotlib.rcParams.update({
    'font.size': 11,
    'axes.titlesize': 12,
    'axes.labelsize': 11,
    'legend.fontsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
})

# ── Load data ─────────────────────────────────────────────────────────────────
CSV_PATH = "ALL_NPFADS_PEM_Run_Summary.csv"
if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(f"Cannot find {CSV_PATH}. Run this script from the "
                            "folder that contains ALL_NPFADS_PEM_Run_Summary.csv")

df = pd.read_csv(CSV_PATH)
PCT = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

OUT_DIR = "npfads_plots"
os.makedirs(OUT_DIR, exist_ok=True)

def get_vals(scenario_id, col):
    """Return values for one scenario sorted by attack_percentage."""
    sub = df[df['attack_scenario'] == scenario_id].sort_values('attack_percentage')
    return sub[col].values

# Scenario IDs
# S1 (malicious vehicle):        TTW=1  BSHH=5  ME=9
# S2 (malicious RSU):            TTW=2  BSHH=6  ME=10
# S3 (controller, no RSU):       TTW=3  BSHH=7  ME=11
# S4 (controller, with RSU):     TTW=4  BSHH=8  ME=12

COLORS  = {'TTW': 'royalblue', 'BSHH': 'darkorange', 'ME': 'forestgreen'}
MARKERS = {'TTW': 'o',         'BSHH': 's',           'ME': '^'}

def plot_metric(ax, s_ttw, s_bshh, s_me, col, ylabel, title, ylim=None, hline=None):
    ax.plot(PCT, get_vals(s_ttw,  col), marker=MARKERS['TTW'],  color=COLORS['TTW'],
            label=f'TTW-S{s_ttw}',  linewidth=1.8, markersize=6)
    ax.plot(PCT, get_vals(s_bshh, col), marker=MARKERS['BSHH'], color=COLORS['BSHH'],
            label=f'BSHH-S{s_bshh}', linewidth=1.8, markersize=6)
    ax.plot(PCT, get_vals(s_me,   col), marker=MARKERS['ME'],   color=COLORS['ME'],
            label=f'ME-S{s_me}',   linewidth=1.8, markersize=6)
    if hline is not None:
        ax.axhline(hline['y'], color=hline.get('color', 'gray'),
                   linestyle='--', linewidth=0.9, label=hline.get('label', ''))
    ax.set_xlabel('Attack Percentage (%)')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(PCT)
    ax.set_xticklabels([str(p) for p in PCT], rotation=45)
    if ylim:
        ax.set_ylim(ylim)
    ax.legend(loc='best')
    ax.grid(True, alpha=0.25)

# =============================================================================
# Figures 1–4: MCC vs Attack Percentage
# =============================================================================

# Fig 1 — MCC, Malicious Vehicle (S1)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 1, 5, 9, 'mcc', 'MCC',
            'Fig 1 — MCC vs Attack Percentage (Malicious Vehicle, S1)',
            ylim=[-1.0, 1.1],
            hline={'y': 0, 'color': 'gray', 'label': 'MCC = 0 (no correlation)'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig01_mcc_malicious_vehicle.png", dpi=150)
plt.close()
print("Saved fig01")

# Fig 2 — MCC, Malicious RSU (S2)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 2, 6, 10, 'mcc', 'MCC',
            'Fig 2 — MCC vs Attack Percentage (Malicious RSU, S2)',
            ylim=[-0.2, 1.1],
            hline={'y': 0, 'color': 'gray', 'label': 'MCC = 0'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig02_mcc_malicious_rsu.png", dpi=150)
plt.close()
print("Saved fig02")

# Fig 3 — MCC, Malicious Controller No RSU (S3)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 3, 7, 11, 'mcc', 'MCC',
            'Fig 3 — MCC vs Attack Percentage (Malicious Controller, No RSU, S3)',
            ylim=[-0.2, 1.1],
            hline={'y': 0, 'color': 'gray', 'label': 'MCC = 0'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig03_mcc_ctrl_no_rsu.png", dpi=150)
plt.close()
print("Saved fig03")

# Fig 4 — MCC, Malicious Controller With RSU (S4)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 4, 8, 12, 'mcc', 'MCC',
            'Fig 4 — MCC vs Attack Percentage (Malicious Controller, With RSU, S4)',
            ylim=[-0.2, 1.1],
            hline={'y': 0, 'color': 'gray', 'label': 'MCC = 0'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig04_mcc_ctrl_with_rsu.png", dpi=150)
plt.close()
print("Saved fig04")

# =============================================================================
# Figures 5–8: AUROC vs Attack Percentage
# =============================================================================

# Fig 5 — AUROC, Malicious Vehicle (S1)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 1, 5, 9, 'auroc', 'AUROC',
            'Fig 5 — AUROC vs Attack Percentage (Malicious Vehicle, S1)',
            ylim=[-0.1, 1.1],
            hline={'y': 0.5, 'color': 'red', 'label': 'Random baseline (0.5)'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig05_auroc_malicious_vehicle.png", dpi=150)
plt.close()
print("Saved fig05")

# Fig 6 — AUROC, Malicious RSU (S2)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 2, 6, 10, 'auroc', 'AUROC',
            'Fig 6 — AUROC vs Attack Percentage (Malicious RSU, S2)',
            ylim=[0.3, 1.1],
            hline={'y': 0.5, 'color': 'red', 'label': 'Random baseline (0.5)'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig06_auroc_malicious_rsu.png", dpi=150)
plt.close()
print("Saved fig06")

# Fig 7 — AUROC, Malicious Controller No RSU (S3)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 3, 7, 11, 'auroc', 'AUROC',
            'Fig 7 — AUROC vs Attack Percentage (Malicious Controller, No RSU, S3)',
            ylim=[0.3, 1.1],
            hline={'y': 0.5, 'color': 'red', 'label': 'Random baseline (0.5)'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig07_auroc_ctrl_no_rsu.png", dpi=150)
plt.close()
print("Saved fig07")

# Fig 8 — AUROC, Malicious Controller With RSU (S4)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 4, 8, 12, 'auroc', 'AUROC',
            'Fig 8 — AUROC vs Attack Percentage (Malicious Controller, With RSU, S4)',
            ylim=[0.3, 1.1],
            hline={'y': 0.5, 'color': 'red', 'label': 'Random baseline (0.5)'})
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig08_auroc_ctrl_with_rsu.png", dpi=150)
plt.close()
print("Saved fig08")

# =============================================================================
# Figures 9–12: Mode B (rf_f1) vs Attack Percentage
# =============================================================================

# Fig 9 — Mode B rf_f1, Malicious Vehicle (S1)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 1, 5, 9, 'rf_f1', 'RF F1 (Mode B)',
            'Fig 9 — Mode B RF F1 vs Attack Percentage (Malicious Vehicle, S1)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig09_rff1_malicious_vehicle.png", dpi=150)
plt.close()
print("Saved fig09")

# Fig 10 — Mode B rf_f1, Malicious RSU (S2)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 2, 6, 10, 'rf_f1', 'RF F1 (Mode B)',
            'Fig 10 — Mode B RF F1 vs Attack Percentage (Malicious RSU, S2)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig10_rff1_malicious_rsu.png", dpi=150)
plt.close()
print("Saved fig10")

# Fig 11 — Mode B rf_f1, Malicious Controller No RSU (S3)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 3, 7, 11, 'rf_f1', 'RF F1 (Mode B)',
            'Fig 11 — Mode B RF F1 vs Attack Percentage (Malicious Controller, No RSU, S3)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig11_rff1_ctrl_no_rsu.png", dpi=150)
plt.close()
print("Saved fig11")

# Fig 12 — Mode B rf_f1, Malicious Controller With RSU (S4)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 4, 8, 12, 'rf_f1', 'RF F1 (Mode B)',
            'Fig 12 — Mode B RF F1 vs Attack Percentage (Malicious Controller, With RSU, S4)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig12_rff1_ctrl_with_rsu.png", dpi=150)
plt.close()
print("Saved fig12")

# =============================================================================
# Figures 13–16: Mode C (NASEA) vs Attack Percentage
# =============================================================================

# Fig 13 — Mode C NASEA, Malicious Vehicle (S1)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 1, 5, 9, 'nasea', 'NASEA (Mode C)',
            'Fig 13 — Mode C NASEA vs Attack Percentage (Malicious Vehicle, S1)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig13_nasea_malicious_vehicle.png", dpi=150)
plt.close()
print("Saved fig13")

# Fig 14 — Mode C NASEA, Malicious RSU (S2)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 2, 6, 10, 'nasea', 'NASEA (Mode C)',
            'Fig 14 — Mode C NASEA vs Attack Percentage (Malicious RSU, S2)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig14_nasea_malicious_rsu.png", dpi=150)
plt.close()
print("Saved fig14")

# Fig 15 — Mode C NASEA, Malicious Controller No RSU (S3)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 3, 7, 11, 'nasea', 'NASEA (Mode C)',
            'Fig 15 — Mode C NASEA vs Attack Percentage (Malicious Controller, No RSU, S3)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig15_nasea_ctrl_no_rsu.png", dpi=150)
plt.close()
print("Saved fig15")

# Fig 16 — Mode C NASEA, Malicious Controller With RSU (S4)
fig, ax = plt.subplots(figsize=(9, 5))
plot_metric(ax, 4, 8, 12, 'nasea', 'NASEA (Mode C)',
            'Fig 16 — Mode C NASEA vs Attack Percentage (Malicious Controller, With RSU, S4)',
            ylim=[-0.05, 1.1])
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig17_nasea_ctrl_with_rsu.png", dpi=150)
plt.close()
print("Saved fig16")

# =============================================================================
# Figure 17: Detection Latency — PEM vs NPFADS
# =============================================================================

fig, ax = plt.subplots(figsize=(7, 5))
systems   = ['PEM\n(Temporal Attack\nDetection)', 'NPFADS\n(Position Attack\nDetection)']
latencies = [50, 800]
bar_colors = ['steelblue', 'tomato']
bars = ax.bar(systems, latencies, color=bar_colors, width=0.45, edgecolor='black', linewidth=0.8)

for bar, val in zip(bars, latencies):
    ax.text(bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 15,
            f'{val} ms', ha='center', va='bottom',
            fontsize=12, fontweight='bold')

ax.axhline(100, color='darkorange', linestyle='--', linewidth=1.5,
           label='100 ms beacon budget')
ax.set_ylabel('Detection Latency (ms)')
ax.set_title('Fig 17 — Detection Latency: PEM vs NPFADS')
ax.set_ylim([0, 950])
ax.legend()
ax.grid(axis='y', alpha=0.3)

ax.annotate('16× slower', xy=(1, 800), xytext=(1.25, 600),
            arrowprops=dict(arrowstyle='->', color='black'),
            fontsize=10, color='black')

plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig17_detection_latency.png", dpi=150)
plt.close()
print("Saved fig17")

# =============================================================================
# Summary
# =============================================================================
print(f"\nAll 17 figures saved to: ./{OUT_DIR}/")
print("Files generated:")
for f in sorted(os.listdir(OUT_DIR)):
    print(f"  {f}")
