#!/usr/bin/env python3
"""
tgn_compare.py — RQ3 Baseline Comparison for Temporal-Echo Attack Detection
============================================================================

Answers RQ3: "Does a TGN that explicitly models sequential beacon-based
topology snapshots under vehicular mobility achieve significantly higher
detection performance (F1, MCC, AUROC) than rule-based, static-GCN, and
DMSTG-AD baselines for all three attack variants?"

Four detectors evaluated on the same tgn_events.csv data:

  1. Rule-based (LW path)  — 9 PEM signatures already scored in the CSV
                              (pem_score / pem_alert columns from routing.cc)
  2. Static-GCN            — 2-layer GCN without GRU temporal memory.
                              Each event classified independently from its
                              feature vector; no node state across events.
  3. DMSTG-AD (approx)     — LSTM + GCN over a sliding window of raw events
                              (no mobility-aware phi, no edge freshness decay,
                              no sliding-window beacon_count). Approximates
                              [Dong et al.] designed for wired SDN. See §2.2.2.
  4. Proposed TGN (FS-DETECT) — GRU temporal memory + L=2 message passing
                              + edge freshness decay. Trained by tgn_train.py.

Usage:
    # Step 1 — Generate CSV (heuristic TGN mode, no trained weights needed yet):
    #   ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1"
    #   (repeat for all scenarios; cat tgn_events.csv files)

    # Step 2 — Train TGN weights:
    #   python3 tgn_train.py all_events.csv --output tgn_weights.bin

    # Step 3 — Compare all four detectors:
    python3 tgn_compare.py all_events.csv --tgn_weights tgn_weights.bin

    # Or without trained weights (TGN uses heuristic scoring):
    python3 tgn_compare.py all_events.csv

Output files:
    tgn_compare_results.csv   — per-scenario + combined F1/MCC/AUROC for all 4 detectors
    tgn_compare_plots/        — bar charts, ROC curves, per-family comparison figures
"""

import argparse
import copy
import math
import os
import struct
import sys
from collections import defaultdict

import numpy as np

try:
    import pandas as pd
except ImportError:
    sys.exit("[ERROR] pandas not installed.  pip install pandas")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
except ImportError:
    sys.exit("[ERROR] PyTorch not installed.  pip install torch")

try:
    from sklearn.metrics import (
        matthews_corrcoef, roc_auc_score, f1_score,
        precision_score, recall_score, confusion_matrix
    )
except ImportError:
    sys.exit("[ERROR] scikit-learn not installed.  pip install scikit-learn")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[WARN] matplotlib not installed — skipping plots (pip install matplotlib)")

# ---------------------------------------------------------------------------
# Constants — must match tgn_train.py and tgn_detector.cc
# ---------------------------------------------------------------------------
BEACON_INTERVAL = 0.1   # T_b (seconds) — IEEE 802.11p = 100 ms
WMAX            = 50    # default; auto-set to ceil(L_link/T_b) in run_comparison

SCENARIO_NAMES = {
    0:  "Baseline",
    1:  "TTW-S1", 2:  "TTW-S2",  3:  "TTW-S3",  4:  "TTW-S4",
    5:  "BSHH-S1", 6: "BSHH-S2", 7:  "BSHH-S3", 8:  "BSHH-S4",
    9:  "ME-S1",  10: "ME-S2",   11: "ME-S3",   12: "ME-S4",
}

FAMILIES = {
    "TTW":  [1, 2, 3, 4],
    "BSHH": [5, 6, 7, 8],
    "ME":   [9, 10, 11, 12],
}

# ---------------------------------------------------------------------------
# 1.  Feature extraction (identical to tgn_train.py)
# ---------------------------------------------------------------------------

def extract_features(df: pd.DataFrame, gamma: float = 310.0,
                     wmax: int = WMAX) -> np.ndarray:
    """7 features: [id_v, tau_s, beacon_count, seq_gap, reporter_count, identity_mismatch, phi]
    Matches tgn_train.py and tgn_detector.cc exactly (Eq 3.19 + phi from Eq 3.21).
    """
    N     = len(df)
    feats = np.zeros((N, 7), dtype=np.float32)
    last_ts, reporters, bwin, last_recv = {}, defaultdict(set), defaultdict(list), {}

    for i, row in enumerate(df.itertuples(index=False)):
        nid   = int(row.claimed_sender_id)
        tau_s = float(row.claimed_ts_s)
        recv  = float(row.recv_time_s)
        lkey  = f"{int(row.link_src_id)}_{int(row.link_dst_id)}"
        phys  = int(row.physical_sender_id)

        id_v_norm = float(nid % 1000) / 1000.0   # Eq 3.19: id_v

        win = bwin[nid]; win.append(recv)
        if len(win) > wmax: win.pop(0)
        beacon_count = float(len(win))

        seq_gap = 0.0
        if nid in last_ts and tau_s < last_ts[nid]:
            seq_gap = last_ts[nid] - tau_s
        last_ts[nid] = tau_s

        reporters[lkey].add(phys)
        reporter_count = float(len(reporters[lkey]))
        identity_mismatch = 1.0 if phys != nid else 0.0

        prev = last_recv.get(nid, recv)
        phi  = math.log(1.0 + max(0.0, recv - prev) / BEACON_INTERVAL)
        last_recv[nid] = recv

        feats[i] = [id_v_norm, tau_s, beacon_count, seq_gap,
                    reporter_count, identity_mismatch, phi]

    return feats


# ---------------------------------------------------------------------------
# 2.  Baseline 1 — Rule-based (LW/PEM) — scores already in CSV
# ---------------------------------------------------------------------------

def evaluate_rulebased(df: pd.DataFrame, theta: float = 0.12) -> np.ndarray:
    """
    Use pre-computed PEM scores from tgn_detector.cc output.
    Threshold theta matches PEM_SCORE_THRESHOLD in routing.cc (0.12).
    """
    return df["pem_score"].values.astype(np.float32)


# ---------------------------------------------------------------------------
# 3.  Baseline 2 — Static-GCN (no temporal memory)
# ---------------------------------------------------------------------------

class StaticGCN(nn.Module):
    """
    2-layer GCN applied independently to each event's feature vector.
    No node memory, no GRU — pure static per-event classification.
    Equivalent to ignoring the temporal dimension of the TGN.
    """
    def __init__(self, in_dim: int = 6, hidden: int = 32, layers: int = 2):
        super().__init__()
        dims = [in_dim] + [hidden] * layers
        self.layers_ = nn.ModuleList()
        for i in range(layers):
            self.layers_.append(nn.Linear(dims[i], dims[i + 1]))
        self.readout = nn.Linear(hidden, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        for layer in self.layers_:
            x = torch.relu(layer(x))
        return self.readout(x).squeeze(-1)   # (N,) logits


def train_static_gcn(
    tr_f: torch.Tensor, tr_l: torch.Tensor,
    va_f: torch.Tensor, va_l: np.ndarray,
    args: argparse.Namespace,
    device: torch.device,
) -> StaticGCN:
    model = StaticGCN(in_dim=7, hidden=args.dim, layers=2).to(device)
    n_pos = float(tr_l.sum().item()); n_neg = float(len(tr_l)) - n_pos
    crit  = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([n_neg / max(n_pos, 1.0)], device=device))
    opt   = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    sch   = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

    best_mcc, best_state = -1.0, None
    for epoch in range(1, args.epochs + 1):
        model.train(); opt.zero_grad()
        loss = crit(model(tr_f), tr_l)
        loss.backward(); nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); sch.step()

        if epoch % max(1, args.epochs // 5) == 0 or epoch == args.epochs:
            model.eval()
            with torch.no_grad():
                va_scores = torch.sigmoid(model(va_f)).cpu().numpy()
            preds = (va_scores >= args.theta).astype(int)
            mcc = matthews_corrcoef(va_l, preds) if va_l.sum() > 0 else 0.0
            if mcc > best_mcc:
                best_mcc = mcc
                best_state = copy.deepcopy(model.state_dict())

    if best_state:
        model.load_state_dict(best_state)
    return model


# ---------------------------------------------------------------------------
# 4.  Baseline 3 — DMSTG-AD approximation
#     Dong et al., wired SDN temporal GNN — without mobility-aware features.
#     Key differences from proposed TGN (per §2.2.2):
#       - No time-elapsed encoding phi (no beacon-interval normalization)
#       - No edge freshness decay A_uv (ignores link staleness)
#       - Fixed-size LSTM window over raw events (not per-node GRU memory)
#       - No sliding-window beacon_count (static node appearance assumption)
# ---------------------------------------------------------------------------

class DMSTGADApprox(nn.Module):
    """
    DMSTG-AD approximation for SDVN: LSTM over a fixed window of raw events
    (no phi, no edge freshness, no per-node beacon_count window).
    Represents a temporal GNN designed for wired SDN applied naively to SDVN.
    """
    WINDOW = 8   # fixed event window — mimics DMSTG-AD's snapshot size

    def __init__(self, in_dim: int = 4, hidden: int = 32):
        super().__init__()
        # Uses only 4 features (no phi, no beacon_count — wired-SDN approximation)
        # in_dim = [tau_s, seq_gap, reporter_count, identity_mismatch]
        self.lstm    = nn.LSTM(in_dim, hidden, batch_first=True)
        self.linear1 = nn.Linear(hidden, hidden)
        self.readout = nn.Linear(hidden, 1)

    def forward(self, x_win: torch.Tensor) -> torch.Tensor:
        """x_win: (B, W, 4) → logits (B,)"""
        _, (h, _) = self.lstm(x_win)
        h = h.squeeze(0)                      # (B, hidden)
        h = torch.relu(self.linear1(h))
        return self.readout(h).squeeze(-1)    # (B,) logits


def make_windows(feats_4: np.ndarray, labels: np.ndarray,
                 W: int = DMSTGADApprox.WINDOW):
    """
    Build sliding-window tensors for DMSTG-AD training.
    feats_4: (N, 4) — tau_s, seq_gap, reporter_count, identity_mismatch (no phi, no c_vW)
    Returns X (M, W, 4) and y (M,) for the last event in each window.
    """
    if len(feats_4) <= W:
        return None, None
    X = np.stack([feats_4[i:i + W] for i in range(len(feats_4) - W)],
                 axis=0).astype(np.float32)
    y = labels[W:].astype(np.float32)
    return X, y


def train_dmstgad(
    tr_f4: np.ndarray, tr_l: np.ndarray,
    va_f4: np.ndarray, va_l_full: np.ndarray,
    args:  argparse.Namespace,
    device: torch.device,
) -> DMSTGADApprox:
    W = DMSTGADApprox.WINDOW
    Xtr, ytr = make_windows(tr_f4, tr_l, W)
    Xva, yva = make_windows(va_f4, va_l_full, W)

    if Xtr is None or Xva is None:
        return DMSTGADApprox(hidden=args.dim).to(device)   # too few events

    Xtr_t = torch.tensor(Xtr, device=device)
    ytr_t = torch.tensor(ytr, device=device)
    Xva_t = torch.tensor(Xva, device=device)

    model = DMSTGADApprox(in_dim=4, hidden=args.dim).to(device)
    n_pos = float(ytr.sum()); n_neg = float(len(ytr)) - n_pos
    crit  = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([n_neg / max(n_pos, 1.0)], device=device))
    opt   = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    sch   = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

    best_mcc, best_state = -1.0, None
    for epoch in range(1, args.epochs + 1):
        model.train(); opt.zero_grad()
        loss = crit(model(Xtr_t), ytr_t)
        loss.backward(); nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); sch.step()

        if epoch % max(1, args.epochs // 5) == 0 or epoch == args.epochs:
            model.eval()
            with torch.no_grad():
                va_scores = torch.sigmoid(model(Xva_t)).cpu().numpy()
            preds = (va_scores >= args.theta).astype(int)
            mcc   = matthews_corrcoef(yva, preds) if yva.sum() > 0 else 0.0
            if mcc > best_mcc:
                best_mcc = mcc
                best_state = copy.deepcopy(model.state_dict())

    if best_state:
        model.load_state_dict(best_state)
    return model, yva   # return yva for aligned evaluation


# ---------------------------------------------------------------------------
# 5.  Proposed TGN — load trained weights or use heuristic
# ---------------------------------------------------------------------------

class ProposedTGN(nn.Module):
    """Proposed TGN — same architecture as tgn_train.py TGNModel."""
    def __init__(self, dim: int = 32, layers: int = 2):
        super().__init__()
        self.dim = dim; self.layers = layers
        gs = dim + 7   # [id_v, tau_s, c_vW, seq_gap, rho, id_mis, phi]
        self.Wz = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wz)
        self.Uz = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Uz)
        self.bz = nn.Parameter(torch.zeros(dim))
        self.Wr = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wr)
        self.Ur = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Ur)
        self.br = nn.Parameter(torch.zeros(dim))
        self.Wn = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wn)
        self.Un = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Un)
        self.bn = nn.Parameter(torch.zeros(dim))
        self.W_layers = nn.ParameterList(
            [nn.Parameter(torch.empty(dim, dim)) for _ in range(layers)])
        self.b_layers = nn.ParameterList(
            [nn.Parameter(torch.zeros(dim)) for _ in range(layers)])
        for W in self.W_layers: nn.init.xavier_uniform_(W)
        self.w_score = nn.Parameter(0.01 * torch.randn(dim))

    def gru_step(self, h, feat):
        gru_in = torch.cat([h, feat])
        z = torch.sigmoid(self.Wz @ gru_in + self.Uz @ h + self.bz)
        r = torch.sigmoid(self.Wr @ gru_in + self.Ur @ h + self.br)
        n = torch.tanh(  self.Wn @ gru_in + self.Un @ (r * h) + self.bn)
        return (1.0 - z) * h + z * n

    def mp_step(self, h_node, h_ldst, h_lsrc, Auv):
        h = (h_node + Auv * h_ldst) / (1.0 + Auv) + 0.1 * h_lsrc
        for l in range(self.layers):
            h = torch.relu(self.W_layers[l] @ h + self.b_layers[l])
        return h

    def forward_sequence(self, feats, nids, lsrcs, ldsts, fresh):
        device = feats.device
        mem = {}
        logits = []
        for i in range(feats.shape[0]):
            nid  = int(nids[i]); lsrc = int(lsrcs[i]); ldst = int(ldsts[i])
            Auv  = float(fresh[i])
            for v in (nid, lsrc, ldst):
                if v not in mem: mem[v] = torch.zeros(self.dim, device=device)
            h_new   = self.gru_step(mem[nid], feats[i])
            h_final = self.mp_step(h_new, mem[ldst], mem[lsrc], Auv)
            logits.append(torch.dot(self.w_score, h_final))
            mem[nid] = h_new.detach()
        return torch.stack(logits)


def load_tgn_weights(model: ProposedTGN, path: str) -> bool:
    if not os.path.exists(path):
        print(f"[TGN] Weight file '{path}' not found — using heuristic scoring")
        return False
    dim, layers = model.dim, model.layers
    gs = dim + 7

    def f64(t): return t.detach().cpu().numpy().astype(np.float64).tobytes()

    try:
        with open(path, "rb") as fp:
            d, l = struct.unpack("ii", fp.read(8))
            assert d == dim and l == layers, \
                f"Weight file dim={d},layers={l} != model dim={dim},layers={layers}"

            def rm(r, c):
                raw = fp.read(r * c * 8)
                arr = np.frombuffer(raw, dtype=np.float64).reshape(r, c).copy()
                return torch.tensor(arr, dtype=torch.float32)

            def rv(n):
                raw = fp.read(n * 8)
                arr = np.frombuffer(raw, dtype=np.float64).copy()
                return torch.tensor(arr, dtype=torch.float32)

            for W, U, b in [(model.Wz, model.Uz, model.bz),
                            (model.Wr, model.Ur, model.br),
                            (model.Wn, model.Un, model.bn)]:
                W.data.copy_(rm(dim, gs))
                U.data.copy_(rm(dim, dim))
                b.data.copy_(rv(dim))
            for ll in range(layers):
                model.W_layers[ll].data.copy_(rm(dim, dim))
                model.b_layers[ll].data.copy_(rv(dim))
            model.w_score.data.copy_(rv(dim))

        print(f"[TGN] Weights loaded from '{path}'")
        return True
    except Exception as ex:
        print(f"[TGN][WARN] Could not load weights: {ex}")
        return False


def train_tgn(
    tr_f, tr_n, tr_ls, tr_ld, tr_fr, tr_l,
    va_f, va_n, va_ls, va_ld, va_fr, va_l,
    args, device,
) -> ProposedTGN:
    model = ProposedTGN(dim=args.dim, layers=args.layers).to(device)
    n_pos = float(tr_l.sum()); n_neg = float(len(tr_l)) - n_pos
    crit  = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([n_neg / max(n_pos, 1.0)], device=device))
    opt   = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    sch   = optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

    best_mcc, best_state = -1.0, None
    for epoch in range(1, args.epochs + 1):
        model.train(); opt.zero_grad()
        logits = model.forward_sequence(tr_f, tr_n, tr_ls, tr_ld, tr_fr)
        loss   = crit(logits, tr_l)
        loss.backward(); nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step(); sch.step()

        if epoch % max(1, args.epochs // 5) == 0 or epoch == args.epochs:
            model.eval()
            with torch.no_grad():
                va_scores = torch.sigmoid(
                    model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)).cpu().numpy()
            preds = (va_scores >= args.theta).astype(int)
            mcc   = matthews_corrcoef(va_l, preds) if va_l.sum() > 0 else 0.0
            if mcc > best_mcc:
                best_mcc = mcc; best_state = copy.deepcopy(model.state_dict())

    if best_state: model.load_state_dict(best_state)
    return model


# ---------------------------------------------------------------------------
# 6.  Metrics
# ---------------------------------------------------------------------------

def metrics(labels: np.ndarray, scores: np.ndarray, theta: float) -> dict:
    preds = (scores >= theta).astype(int)
    tp = int(((preds == 1) & (labels == 1)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    mcc  = matthews_corrcoef(labels, preds) \
           if labels.sum() > 0 and (labels == 0).sum() > 0 else 0.0
    f1   = f1_score(labels, preds, zero_division=0)
    prec = precision_score(labels, preds, zero_division=0)
    rec  = recall_score(labels, preds, zero_division=0)
    try:
        auc = roc_auc_score(labels, scores)
    except ValueError:
        auc = 0.5
    return dict(tp=tp, tn=tn, fp=fp, fn=fn,
                mcc=mcc, f1=f1, precision=prec, recall=rec, auroc=auc)


# ---------------------------------------------------------------------------
# 7.  Plotting
# ---------------------------------------------------------------------------

DETECTOR_COLORS = {
    "Rule-based (LW)":     "#2196F3",
    "Static-GCN":          "#FF9800",
    "DMSTG-AD":            "#9C27B0",
    "TGN-NoMobility (A4)": "#F44336",   # A4 ablation — red to highlight gap vs full TGN
    "Proposed TGN":        "#4CAF50",
}

METRIC_LABELS = {"mcc": "MCC", "f1": "F1 Score", "auroc": "AUROC"}


def plot_comparison(results: list[dict], out_dir: str) -> None:
    """
    results: list of {detector, scenario, mcc, f1, auroc, ...}
    """
    if not HAS_MPL:
        return
    os.makedirs(out_dir, exist_ok=True)

    df = pd.DataFrame(results)
    detectors = ["Rule-based (LW)", "Static-GCN", "DMSTG-AD",
                 "TGN-NoMobility (A4)", "Proposed TGN"]
    scenarios  = sorted(df["scenario"].unique())
    snames     = [SCENARIO_NAMES.get(s, str(s)) for s in scenarios]

    # --- 1. Per-scenario bar charts for MCC, F1, AUROC -----------------------
    for metric, ylabel in METRIC_LABELS.items():
        fig, ax = plt.subplots(figsize=(14, 5))
        x    = np.arange(len(scenarios))
        w    = 0.15
        offset_center = (len(detectors) - 1) / 2.0
        for i, det in enumerate(detectors):
            vals = [float(df[(df["detector"] == det) &
                             (df["scenario"] == s)][metric].iloc[0])
                    if len(df[(df["detector"] == det) &
                              (df["scenario"] == s)]) > 0 else 0.0
                    for s in scenarios]
            ax.bar(x + (i - offset_center) * w, vals, w,
                   label=det, color=DETECTOR_COLORS[det], alpha=0.85,
                   edgecolor="white", linewidth=0.5)

        ax.set_xticks(x); ax.set_xticklabels(snames, rotation=45, ha="right")
        ax.set_xlabel("Attack Scenario")
        ax.set_ylabel(ylabel)
        ax.set_title(f"RQ3 — {ylabel}: Proposed TGN vs Baselines (All Scenarios)")
        ax.set_ylim(0, 1.08)
        ax.axhline(0.85, color="gray", linestyle="--", linewidth=0.8,
                   label="MCC≥0.85 target" if metric == "mcc" else None)
        ax.legend(loc="upper right", fontsize=8, framealpha=0.8)
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()
        path = os.path.join(out_dir, f"tgn_compare_{metric}.png")
        plt.savefig(path, dpi=150); plt.close()
        print(f"[Plot] Saved {path}")

    # --- 2. Per-family summary (TTW / BSHH / ME) ------------------------------
    family_rows = []
    for fam, scens in FAMILIES.items():
        fam_df = df[df["scenario"].isin(scens)]
        for det in detectors:
            sub = fam_df[fam_df["detector"] == det]
            if len(sub) == 0: continue
            family_rows.append({
                "family": fam, "detector": det,
                "mcc":   sub["mcc"].mean(),
                "f1":    sub["f1"].mean(),
                "auroc": sub["auroc"].mean(),
            })
    fdf = pd.DataFrame(family_rows)

    for metric, ylabel in METRIC_LABELS.items():
        fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
        for ax, fam in zip(axes, ["TTW", "BSHH", "ME"]):
            sub = fdf[fdf["family"] == fam]
            x   = np.arange(len(detectors))
            vals = [float(sub[sub["detector"] == d][metric].iloc[0])
                    if len(sub[sub["detector"] == d]) > 0 else 0.0
                    for d in detectors]
            bars = ax.bar(x, vals, color=[DETECTOR_COLORS[d] for d in detectors],
                          alpha=0.85, edgecolor="white")
            ax.set_xticks(x)
            ax.set_xticklabels(["LW", "S-GCN", "DMSTG", "NoMob", "TGN"], fontsize=9)
            ax.set_title(f"{fam} Family")
            ax.set_ylim(0, 1.08)
            ax.axhline(0.85, color="gray", linestyle="--", linewidth=0.8)
            ax.grid(axis="y", alpha=0.3)
            if ax == axes[0]: ax.set_ylabel(ylabel)

        handles = [mpatches.Patch(color=DETECTOR_COLORS[d], label=d) for d in detectors]
        fig.legend(handles=handles, loc="upper center",
                   ncol=4, fontsize=9, bbox_to_anchor=(0.5, 1.02))
        fig.suptitle(f"RQ3 — {ylabel} by Attack Family", y=1.05)
        plt.tight_layout()
        path = os.path.join(out_dir, f"tgn_compare_{metric}_by_family.png")
        plt.savefig(path, dpi=150, bbox_inches="tight"); plt.close()
        print(f"[Plot] Saved {path}")

    # --- 3. Combined ROC-style summary (MCC vs scenario, line plot) -----------
    fig, ax = plt.subplots(figsize=(12, 4))
    for det in detectors:
        sub   = df[df["detector"] == det].sort_values("scenario")
        scens = sub["scenario"].values
        mccs  = sub["mcc"].values
        ax.plot(snames, mccs, marker="o", label=det,
                color=DETECTOR_COLORS[det], linewidth=2, markersize=5)

    ax.axhline(0.85, color="gray", linestyle="--", linewidth=0.8,
               label="MCC≥0.85 target")
    ax.set_xlabel("Attack Scenario")
    ax.set_ylabel("MCC")
    ax.set_title("RQ3 — MCC Across All Scenarios: Proposed TGN vs Baselines")
    ax.set_ylim(-0.05, 1.08)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    path = os.path.join(out_dir, "tgn_compare_mcc_line.png")
    plt.savefig(path, dpi=150); plt.close()
    print(f"[Plot] Saved {path}")


# ---------------------------------------------------------------------------
# 8.  Main comparison loop
# ---------------------------------------------------------------------------

def run_comparison(df: pd.DataFrame, args: argparse.Namespace) -> list[dict]:
    """Train and evaluate all 4 detectors; return list of result dicts."""

    df = df.sort_values("recv_time_s").reset_index(drop=True)

    # γ and W_max from l_link  — Eq 9.3 / Eq 9.2
    l_link = getattr(args, "l_link", 43.0)
    gamma  = (l_link / 2.0) / (BEACON_INTERVAL * math.log(2.0))
    wmax   = int(math.ceil(l_link / BEACON_INTERVAL))

    feats_7 = extract_features(df, gamma=gamma, wmax=wmax)      # (N, 7) all features
    # DMSTG-AD uses 4 features: [tau_s, seq_gap, reporter_count, identity_mismatch]
    # Indices after adding id_v at [0]: tau_s=[1], seq_gap=[3], reporter=[4], id_mis=[5]
    feats_4 = feats_7[:, [1, 3, 4, 5]].copy()                  # (N, 4) DMSTG-AD subset
    labels  = df["is_attack"].values.astype(np.float32)
    nids    = df["claimed_sender_id"].values.astype(np.int64)
    lsrcs   = df["link_src_id"].values.astype(np.int64)
    ldsts   = df["link_dst_id"].values.astype(np.int64)
    fresh   = df["edge_freshness"].values.astype(np.float32)
    pem_sc  = df["pem_score"].values.astype(np.float32)
    scens   = df["attack_scenario"].values.astype(int)

    N     = len(df)
    n_tr  = int(0.70 * N)
    n_va  = int(0.15 * N)
    n_te  = N - n_tr - n_va

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def tt(arr, dtype=torch.float32):
        return torch.tensor(arr, dtype=dtype, device=device)

    # Tensors for TGN / Static-GCN
    tr_f6 = tt(feats_7[:n_tr]);     va_f6 = tt(feats_7[n_tr:n_tr+n_va])
    te_f6 = tt(feats_7[n_tr+n_va:])
    tr_l  = tt(labels[:n_tr]);      va_l  = labels[n_tr:n_tr+n_va]
    te_l  = labels[n_tr+n_va:]
    tr_n  = tt(nids[:n_tr],  torch.int64)
    tr_ls = tt(lsrcs[:n_tr], torch.int64)
    tr_ld = tt(ldsts[:n_tr], torch.int64)
    tr_fr = tt(fresh[:n_tr])
    va_n  = tt(nids[n_tr:n_tr+n_va],  torch.int64)
    va_ls = tt(lsrcs[n_tr:n_tr+n_va], torch.int64)
    va_ld = tt(ldsts[n_tr:n_tr+n_va], torch.int64)
    va_fr = tt(fresh[n_tr:n_tr+n_va])
    te_n  = tt(nids[n_tr+n_va:],  torch.int64)
    te_ls = tt(lsrcs[n_tr+n_va:], torch.int64)
    te_ld = tt(ldsts[n_tr+n_va:], torch.int64)
    te_fr = tt(fresh[n_tr+n_va:])
    te_scens = scens[n_tr+n_va:]
    te_pem   = pem_sc[n_tr+n_va:]

    print("\n[Compare] Training Static-GCN...")
    gcn = train_static_gcn(tr_f6, tr_l, va_f6, va_l, args, device)

    print("[Compare] Training DMSTG-AD approximation...")
    dmstg_result = train_dmstgad(
        feats_4[:n_tr],     labels[:n_tr],
        feats_4[n_tr:n_tr+n_va], va_l,
        args, device)
    if isinstance(dmstg_result, tuple):
        dmstg_model, dmstg_va_y = dmstg_result
    else:
        dmstg_model = dmstg_result
        dmstg_va_y  = va_l

    print("[Compare] Loading/training Proposed TGN (mobility-calibrated)...")
    tgn = ProposedTGN(dim=args.dim, layers=args.layers).to(device)
    weights_loaded = False
    if args.tgn_weights:
        weights_loaded = load_tgn_weights(tgn, args.tgn_weights)
    if not weights_loaded:
        print("[Compare] Training TGN from scratch (no weight file provided)...")
        tgn = train_tgn(
            tr_f6, tr_n, tr_ls, tr_ld, tr_fr, tr_l,
            va_f6, va_n, va_ls, va_ld, va_fr, va_l,
            args, device)

    # ── A4 (NoMobility) ablation — Table 4.3  ────────────────────────────────
    # TGN with fixed W_max=50 and fixed gamma=1.0 (no l_link calibration).
    # Demonstrates the contribution of mobility-adaptive W_max and gamma (§9.2-9.3).
    print("[Compare] Training A4-NoMobility TGN (fixed W=50, gamma=1.0)...")
    feats_nm = extract_features(df, gamma=1.0, wmax=50)   # no mobility calibration
    tr_fnm = tt(feats_nm[:n_tr]); va_fnm = tt(feats_nm[n_tr:n_tr+n_va])
    te_fnm = tt(feats_nm[n_tr+n_va:])
    tgn_nm = train_tgn(
        tr_fnm, tr_n, tr_ls, tr_ld, tr_fr, tr_l,
        va_fnm, va_n, va_ls, va_ld, va_fr, va_l,
        args, device)

    # ── Test-set scores ───────────────────────────────────────────────────────
    gcn.eval()
    with torch.no_grad():
        gcn_scores = torch.sigmoid(gcn(te_f6)).cpu().numpy()

    # DMSTG-AD test set: need aligned windows
    W = DMSTGADApprox.WINDOW
    te_f4 = feats_7[n_tr+n_va:, [1, 3, 4, 5]]   # same 4-feature DMSTG-AD subset
    dmstg_labels = te_l
    dmstg_scores = np.full(len(te_l), 0.0, dtype=np.float32)
    if len(te_f4) > W:
        Xte, yte_dmstg = make_windows(te_f4, te_l, W)
        if Xte is not None:
            dmstg_model.eval()
            with torch.no_grad():
                ds = torch.sigmoid(
                    dmstg_model(torch.tensor(Xte, device=device))).cpu().numpy()
            # Align: first W events have no window → score 0
            dmstg_scores[W:] = ds
            dmstg_labels = te_l   # full length; first W rows scored 0 (benign)

    tgn.eval()
    with torch.no_grad():
        tgn_scores = torch.sigmoid(
            tgn.forward_sequence(te_f6, te_n, te_ls, te_ld, te_fr)).cpu().numpy()

    tgn_nm.eval()
    with torch.no_grad():
        tgn_nm_scores = torch.sigmoid(
            tgn_nm.forward_sequence(te_fnm, te_n, te_ls, te_ld, te_fr)).cpu().numpy()

    # ── Per-scenario evaluation ───────────────────────────────────────────────
    results = []
    eval_scenarios = list(sorted(set(te_scens)))

    for sc in eval_scenarios:
        mask = (te_scens == sc)
        if mask.sum() == 0: continue

        for det_name, scores in [
            ("Rule-based (LW)",      te_pem[mask]),
            ("Static-GCN",           gcn_scores[mask]),
            ("DMSTG-AD",             dmstg_scores[mask]),
            ("TGN-NoMobility (A4)",  tgn_nm_scores[mask]),
            ("Proposed TGN",         tgn_scores[mask]),
        ]:
            lbl = te_l[mask]
            m   = metrics(lbl, scores, args.theta)
            row = {"detector": det_name, "scenario": int(sc),
                   "scenario_name": SCENARIO_NAMES.get(sc, str(sc)),
                   "n_events": int(mask.sum()),
                   "n_attack": int(lbl.sum()), **m}
            results.append(row)

    # ── Combined (all scenarios) ───────────────────────────────────────────────
    for det_name, scores in [
        ("Rule-based (LW)",     te_pem),
        ("Static-GCN",          gcn_scores),
        ("DMSTG-AD",            dmstg_scores),
        ("TGN-NoMobility (A4)", tgn_nm_scores),
        ("Proposed TGN",        tgn_scores),
    ]:
        m   = metrics(te_l, scores, args.theta)
        row = {"detector": det_name, "scenario": -1,
               "scenario_name": "ALL COMBINED",
               "n_events": len(te_l), "n_attack": int(te_l.sum()), **m}
        results.append(row)

    return results


# ---------------------------------------------------------------------------
# 9.  Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="RQ3 baseline comparison: Proposed TGN vs LW / Static-GCN / DMSTG-AD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("csv",          nargs="?", default="tgn_events.csv",
                    help="Input tgn_events.csv (default: tgn_events.csv)")
    ap.add_argument("--tgn_weights", default="",
                    help="Path to tgn_weights.bin (from tgn_train.py). "
                         "Omit to train TGN from scratch.")
    ap.add_argument("--dim",         type=int,   default=32)
    ap.add_argument("--layers",      type=int,   default=2)
    ap.add_argument("--epochs",      type=int,   default=40,
                    help="Training epochs for Static-GCN, DMSTG-AD, TGN (default: 40)")
    ap.add_argument("--lr",          type=float, default=1e-3)
    ap.add_argument("--theta",       type=float, default=0.40,
                    help="Decision threshold for TGN/GCN/DMSTG (default: 0.40). "
                         "LW uses PEM_SCORE_THRESHOLD=0.12 from routing.cc.")
    ap.add_argument("--lw_theta",    type=float, default=0.12,
                    help="Rule-based (LW/PEM) threshold (default: 0.12)")
    ap.add_argument("--l_link",      type=float, default=43.0,
                    help="Expected link lifetime L_link (s) for gamma/W_max calibration. "
                         "Urban≈43s, Highway≈9s (default: 43.0)")
    ap.add_argument("--out_dir",     default="tgn_compare_plots",
                    help="Directory for output plots (default: tgn_compare_plots)")
    ap.add_argument("--scenario",    type=int,   default=-1,
                    help="Filter to one scenario (-1 = all)")
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(
            f"[ERROR] '{args.csv}' not found.\n"
            f"  Generate it with:\n"
            f"    ./waf --run \"scratch/tgn_detector --simTime=60 "
            f"--N_Vehicles=6 --attack_scenario=1\"\n"
            f"  Run for all 12 scenarios and concatenate."
        )

    df = pd.read_csv(args.csv)
    df = df[df["sim_time_s"] != "sim_time_s"].reset_index(drop=True)
    for col in ["sim_time_s", "attack_scenario", "physical_sender_id",
                "claimed_sender_id", "link_src_id", "link_dst_id",
                "claimed_ts_s", "recv_time_s", "edge_freshness",
                "seq_gap", "reporter_count", "identity_mismatch",
                "pem_score", "pem_alert", "is_attack"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["is_attack", "claimed_sender_id", "pem_score"])
    df = df[df["event_type"] != "BEACON"].reset_index(drop=True)

    print(f"[Compare] {len(df)} non-beacon events loaded from '{args.csv}'")
    print(f"           Attack: {int(df['is_attack'].sum())}  "
          f"Benign: {int((df['is_attack'] == 0).sum())}")

    if args.scenario >= 0:
        df = df[df["attack_scenario"] == args.scenario].reset_index(drop=True)
        print(f"[Compare] Filtered to scenario {args.scenario}: {len(df)} events")

    if len(df) < 30:
        sys.exit("[ERROR] Too few events. Run more scenarios or longer simTime.")

    results = run_comparison(df, args)

    # ── Print summary table ───────────────────────────────────────────────────
    print("\n" + "="*82)
    print(f"{'Detector':<20} {'Scenario':<12} {'MCC':>6} {'F1':>6} {'AUROC':>6} "
          f"{'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4}")
    print("-"*82)
    for r in results:
        sname = r["scenario_name"] if r["scenario"] >= 0 else "ALL"
        print(f"{r['detector']:<20} {sname:<12} {r['mcc']:>6.3f} {r['f1']:>6.3f} "
              f"{r['auroc']:>6.3f} {r['tp']:>4} {r['tn']:>4} {r['fp']:>4} {r['fn']:>4}")
    print("="*82)

    # ── Save CSV ──────────────────────────────────────────────────────────────
    out_csv = "tgn_compare_results.csv"
    pd.DataFrame(results).to_csv(out_csv, index=False)
    print(f"\n[Compare] Results saved to '{out_csv}'")

    # ── Plots ─────────────────────────────────────────────────────────────────
    plot_rows = [r for r in results if r["scenario"] >= 0]
    plot_comparison(plot_rows, args.out_dir)
    print(f"[Compare] Plots saved to '{args.out_dir}/'")


if __name__ == "__main__":
    main()
