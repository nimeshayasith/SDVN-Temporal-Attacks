#!/usr/bin/env python3
"""
generate_ablation_charts.py
----------------------------
Reads every ablation sweep's output (~/ablation_sweep/<config>/...) and
produces one chart per config (metric vs. its PDF Table 4.2 X-variable),
plus a combined summary CSV.

Handles missing/partial data gracefully (e.g. an in-progress sweep) —
missing points are simply omitted from the line, not treated as an error.
"""
import os, re, glob, csv, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HOME = os.path.expanduser("~")
SWEEP_ROOT = os.path.join(HOME, "ablation_sweep")
OUT_DIR = os.path.join(HOME, "ablation_charts")
os.makedirs(OUT_DIR, exist_ok=True)

# Fixed categorical order (colorblind-safe, from the dataviz reference palette).
# Assigned per-chart by sorted-key order below (never reused for a DIFFERENT
# scenario within the SAME chart — a static scenario->color dict would collide
# whenever a chart spans multiple scenario families, e.g. a1 spans sc1+sc5+sc9).
CATEGORICAL_PALETTE = [
    "#4C6EF5",  # blue
    "#F76707",  # orange
    "#2F9E44",  # green
    "#AE3EC9",  # purple
    "#E64980",  # pink
]
DEFAULT_COLOR = "#4C6EF5"
# Secondary encoding (linestyle) so perfectly-overlapping lines — common here,
# e.g. multiple scenarios all hitting mcc=1.0 — stay visually distinguishable
# even when color alone can't separate them.
LINESTYLES = ["-", "--", ":", "-."]

SCEN_LABEL = {
    "sc1": "TTW-S1", "sc2": "TTW-S2", "sc3": "TTW-S3",
    "sc5": "BSHH-S1", "sc6": "BSHH-S2", "sc7": "BSHH-S3", "sc8": "BSHH-S4",
    "sc9": "ME-S1",
    "veh": "Vehicle-origin (S1)", "rsu": "RSU-origin (S2)", "ctrl": "Controller-origin (S3)",
}

CONFIG_META = {
    "a1":  {"title": "A1 — LW-Only (rinj sweep)",              "xlabel": "Injection rate rinj (%)", "xtype": float},
    "a2":  {"title": "A2 — FS/TGN-Only (rinj sweep)",           "xlabel": "Injection rate rinj (%)", "xtype": float},
    "a3":  {"title": "A3 — Static GCN (Tobs sweep)",            "xlabel": "Observation window Tobs (s)", "xtype": float},
    "a4":  {"title": "A4 — Vehicle Density (N_Vehicles proxy)", "xlabel": "N_Vehicles (proxy for lambda)", "xtype": int},
    "a5":  {"title": "A5 — No Crypto Pre-Filter (attacker origin)", "xlabel": "Attacker origin", "xtype": str},
    "a6":  {"title": "A6 — No Threshold Aggregate Signature (fc sweep)", "xlabel": "Colluding vehicles f_c", "xtype": int},
    "a7":  {"title": "A7 — ME Echo Distance Ratio",             "xlabel": "Echo distance ratio (x r_comm)", "xtype": float},
    "a8":  {"title": "A8 — Mitigation Delay Intervals",         "xlabel": "Post-alert grace (beacon intervals k)", "xtype": float},
    "a9":  {"title": "A9 — Byzantine PBFT Peers",                "xlabel": "Byzantine peers f_b", "xtype": float},
    "a10": {"title": "A10 — Detector False-Positive Rate",       "xlabel": "Synthetic FP rate p_FP", "xtype": float},
    "a11": {"title": "A11 — Network Size (LKH vs flat rekey)",   "xlabel": "N_Vehicles (network size n)", "xtype": float},
    "a12": {"title": "A12 — Controller-Origin Injection Rate",   "xlabel": "Injection rate rinj (%)", "xtype": float},
    "a13": {"title": "A13 — KEM Handshake Rate",                 "xlabel": "Handshake rate r_hs (vehicles/s)", "xtype": float},
    "a14": {"title": "A14 — Compromised Controllers",            "xlabel": "Compromised controllers n_C", "xtype": float},
}

def find_tgn_summary(run_dir):
    matches = glob.glob(os.path.join(run_dir, "TGN_SUMMARY", "*.csv"))
    return matches[0] if matches else None

# PDF Table 4.4, M1 (MCC): design components listed as "LW signature scoring
# (Eq. 3.12); FS binary scorer (Eq. 3.25)" -- i.e. M1's confusion matrix is
# meant to come from the COMBINED alert decision (LW OR TGN fires), not
# either stage read in isolation. TGN_SUMMARY's comb_tp/tn/fp/fn/comb_mcc
# columns implement exactly this (.tgn_src/tgn_core.cc: `comb_alert =
# e.alert_raised || tgn_alert`) -- confirmed live/non-dead via direct data
# inspection (comb_tp=189, comb_mcc=1.000 for a real run), contrary to an
# earlier, now-superseded calibration-doc note that called it dead code
# (that note was checking a different, non-compiled copy of tgn_core.cc).
# comb_mcc self-corrects for A1/A2 automatically: A1 (--no_tgn=1) never
# raises tgn_alert, so comb_alert reduces to pure LW; A2 (--no_lw=1) forces
# e.alert_raised false, so comb_alert reduces to pure TGN. One column,
# uniformly, for every config -- no more per-config special-casing needed.
def read_comb_mcc(csv_path):
    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return None
    row = rows[-1]
    try:
        return float(row["comb_mcc"])
    except (KeyError, ValueError):
        return None

def parse_dirname(cid, name):
    """Returns (scenario_key_or_None, x_value_str)."""
    # a1/a2 pattern: sc<N>_x<val>
    m = re.match(r"sc(\d+)_x([\d.]+)$", name)
    if m:
        return f"sc{m.group(1)}", m.group(2)
    # a3 pattern: sc1_tobs<val>
    m = re.match(r"sc1_tobs(\d+)$", name)
    if m:
        return "sc1", m.group(1)
    # a4 pattern: n<val>
    m = re.match(r"n(\d+)$", name)
    if m and cid == "a4":
        return None, m.group(1)
    # a11 pattern: n<val>
    if m and cid == "a11":
        return None, m.group(1)
    # a5 pattern: <origin>_sc<N>
    m = re.match(r"(veh|rsu|ctrl)_sc\d+$", name)
    if m:
        return m.group(1), m.group(1)
    # a6 pattern: fc<N> (colluding-vehicle count, --bshh_s1_fc sweep on sc5)
    m = re.match(r"fc(\d+)$", name)
    if m and cid == "a6":
        return "sc5", m.group(1)
    # generic: x<val>
    m = re.match(r"x([\d.]+)$", name)
    if m:
        return None, m.group(1)
    return None, None

def plot_config(cid, meta):
    cdir = os.path.join(SWEEP_ROOT, cid)
    if not os.path.isdir(cdir):
        print(f"[SKIP] {cid}: no sweep directory found")
        return None

    series = {}  # scenario_key -> list of (x, comb_mcc)
    for sub in sorted(os.listdir(cdir)):
        subpath = os.path.join(cdir, sub)
        if not os.path.isdir(subpath):
            continue
        scen_key, xval = parse_dirname(cid, sub)
        if xval is None:
            continue
        try:
            xnum = meta["xtype"](xval) if meta["xtype"] != str else xval
        except ValueError:
            xnum = xval
        key = scen_key if scen_key else "single"

        summary = find_tgn_summary(subpath)
        if not summary:
            print(f"[WARN] {cid}/{sub}: no TGN_SUMMARY found, skipping")
            continue
        mcc = read_comb_mcc(summary)
        if mcc is None:
            print(f"[WARN] {cid}/{sub}: could not parse comb_mcc, skipping")
            continue
        series.setdefault(key, []).append((xnum, mcc))

    if not series:
        print(f"[SKIP] {cid}: no data points found yet")
        return None

    fig, ax = plt.subplots(figsize=(7, 4.5))
    is_categorical = meta["xtype"] == str
    for i, key in enumerate(sorted(series.keys())):
        pts = series[key]
        if not is_categorical:
            pts = sorted(pts, key=lambda p: p[0])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        color = CATEGORICAL_PALETTE[i % len(CATEGORICAL_PALETTE)]
        ls = LINESTYLES[i % len(LINESTYLES)]
        label = SCEN_LABEL.get(key, key)
        ax.plot(xs, ys, color=color, linestyle=ls, linewidth=2.2, marker="o", markersize=7,
                label=label if key != "single" else None)

    ax.set_xlabel(meta["xlabel"], fontsize=11)
    ax.set_ylabel("MCC", fontsize=11)
    ax.set_title(meta["title"], fontsize=12, fontweight="bold")
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, linestyle="--", alpha=0.35, linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=9, loc="best", frameon=False)

    fig.tight_layout()
    outpath = os.path.join(OUT_DIR, f"{cid}_mcc_vs_x.png")
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] {cid}: {sum(len(v) for v in series.values())} points -> {outpath}")
    return series

def plot_a6():
    """A6 supplementary chart: M11 FSR(f_c) (Eq. 4.18), separate from the
    M1/comb_mcc chart plot_config() already produces for a6 via the
    standard path. Reads the new fc<N> directory structure (sweep_a6.sh,
    rewritten 2026-07-29 to actually sweep --bshh_s1_fc against sc5/
    BSHH-S1) -- was previously sc5/sc6/sc7/sc8, stale since that rewrite."""
    cdir = os.path.join(SWEEP_ROOT, "a6")
    if not os.path.isdir(cdir):
        print("[SKIP] a6 (FSR): no sweep directory found")
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    any_data = False
    fc_dirs = [s for s in sorted(os.listdir(cdir)) if re.match(r"fc(\d+)$", s)]
    pts = []
    for sub in fc_dirs:
        subpath = os.path.join(cdir, sub)
        if not os.path.isdir(subpath):
            continue
        fsr_files = glob.glob(os.path.join(subpath, "M11_FSR_SWEEP", "*.csv"))
        if not fsr_files:
            print(f"[WARN] a6 (FSR)/{sub}: no M11_FSR_SWEEP found")
            continue
        with open(fsr_files[0], newline="") as f:
            rows = list(csv.DictReader(f))
        for r in rows:
            try:
                pts.append((int(r["f_c"]), float(r["fsr_fc"])))
            except (KeyError, ValueError):
                continue
    pts = sorted(set(pts), key=lambda p: p[0])
    if pts:
        any_data = True
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color=CATEGORICAL_PALETTE[0], linestyle="-", linewidth=2.2,
                marker="o", markersize=7, label="BSHH-S1")
    if not any_data:
        print("[SKIP] a6 (FSR): no data points found yet")
        plt.close(fig)
        return
    ax.set_xlabel("Colluding signers f_c", fontsize=11)
    ax.set_ylabel("FSR(f_c) — forgery success rate", fontsize=11)
    ax.set_title("A6 — BSHH Threshold Signature (f_c auto-sweep, Eq. 4.18)", fontsize=12, fontweight="bold")
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, linestyle="--", alpha=0.35, linewidth=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=9, loc="best", frameon=False)
    fig.tight_layout()
    outpath = os.path.join(OUT_DIR, "a6_fsr_vs_fc.png")
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] a6 -> {outpath}")

def write_summary_csv(all_series):
    outpath = os.path.join(OUT_DIR, "ablation_summary.csv")
    with open(outpath, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "scenario", "x_value", "mcc"])
        for cid, series in all_series.items():
            if series is None:
                continue
            for key, pts in series.items():
                for x, mcc in pts:
                    w.writerow([cid, key, x, f"{mcc:.4f}"])
    print(f"\n[OK] summary CSV -> {outpath}")

if __name__ == "__main__":
    all_series = {}
    for cid, meta in CONFIG_META.items():
        all_series[cid] = plot_config(cid, meta)
    plot_a6()
    write_summary_csv(all_series)
    print(f"\nAll charts written to: {OUT_DIR}")
