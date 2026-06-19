#!/usr/bin/env python3
"""
tgn_train.py — Train TGN weights on tgn_events.csv; export binary checkpoint
               for tgn_detector.cc (TGNDetector::LoadWeights).

Paper reference:
  Section 3.4.3 + Algorithm 2 (FS-DETECT) — Eqs 3.18-3.23, 3.34.

Workflow:
  Step 1 — Generate training data (heuristic/random-weight mode):
    ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1"
    # Repeat for all 12 attack scenarios; concatenate the tgn_events.csv files.

  Step 2 — Train:
    python3 tgn_train.py tgn_events.csv --epochs 50 --output tgn_weights.bin

  Step 3 — Run detector with trained weights:
    ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 \\
                 --attack_scenario=1 --tgn_weights=tgn_weights.bin"

Binary weight format (all values float64, row-major — must match LoadWeights()):
  int32  dim
  int32  layers
  Wz (dim x gs)  Uz (dim x dim)  bz (dim)
  Wr (dim x gs)  Ur (dim x dim)  br (dim)
  Wn (dim x gs)  Un (dim x dim)  bn (dim)
  for l in 0..layers-1:
      W_layers[l] (dim x dim)  b_layers[l] (dim)
  w_score (dim)
  where gs = dim + 7   (id_v, tau_s, c_vW, seq_gap, rho_v, id_mis, phi)
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
    import torch
    import torch.nn as nn
    import torch.optim as optim
except ImportError:
    sys.exit("[ERROR] PyTorch not installed.  pip install torch")

try:
    import pandas as pd
except ImportError:
    sys.exit("[ERROR] pandas not installed.  pip install pandas")

try:
    from sklearn.metrics import matthews_corrcoef, roc_auc_score
except ImportError:
    sys.exit("[ERROR] scikit-learn not installed.  pip install scikit-learn")

# ---------------------------------------------------------------------------
# Constants — must match tgn_detector.cc Section 1
# ---------------------------------------------------------------------------
BEACON_INTERVAL = 0.1   # T_b (seconds) — IEEE 802.11p = 100 ms
WMAX            = 430   # urban default: ceil(L_link/T_b) = ceil(43/0.1) = 430
# Highway: WMAX = ceil(9/0.1) = 90.  Overridden at runtime via --l_link argument.
# This constant is also used as the fallback when tgn_train.py is imported as a
# module (not run as __main__), so it must be correct for the primary scenario.

# ---------------------------------------------------------------------------
# 1.  Feature extraction  (mirrors C++ TGN_ExtractFeatures + TGN_EdgeFreshness)
# ---------------------------------------------------------------------------

def extract_features(df: "pd.DataFrame", gamma: float = 310.0,
                     wmax: int = WMAX) -> np.ndarray:
    """
    Compute the 7-element feature vector for every row in df (already time-sorted).

    Feature mapping to paper notation (Eq 3.19 + phi from Eq 3.21):
      [id_v, tau_s, beacon_count, seq_gap, reporter_count, identity_mismatch, phi]
       = [id_v, tau_s^(v), c_v^W, delta_s_v, rho_v, id_mis, log(1+delta_t/T_b)]

    id_v is node_id % 1000 / 1000  (scalar approximation of learnable embedding).
    """
    N     = len(df)
    feats = np.zeros((N, 7), dtype=np.float32)

    last_ts   = {}             # node_id -> previous claimed_ts_s
    reporters = defaultdict(set)
    bwin      = defaultdict(list)
    last_recv = {}             # node_id -> previous recv_time_s

    for i, row in enumerate(df.itertuples(index=False)):
        nid  = int(row.claimed_sender_id)
        tau_s = float(row.claimed_ts_s)
        recv  = float(row.recv_time_s)
        lkey  = f"{int(row.link_src_id)}_{int(row.link_dst_id)}"
        phys  = int(row.physical_sender_id)

        # id_v (Eq 3.19) — normalised node ID (scalar proxy for learnable embedding)
        id_v_norm = float(nid % 1000) / 1000.0

        # beacon_count (c_v^W) — sliding window; W_max = ceil(L_link / T_b) (Eq 9.2)
        win = bwin[nid]
        win.append(recv)
        if len(win) > wmax:
            win.pop(0)
        beacon_count = float(len(win))

        # seq_gap (delta_s_v) — TTW-S2: claimed timestamp regression
        seq_gap = 0.0
        if nid in last_ts and tau_s < last_ts[nid]:
            seq_gap = last_ts[nid] - tau_s
        last_ts[nid] = tau_s

        # reporter_count (rho_v) — ME-S1: distinct reporters per link
        reporters[lkey].add(phys)
        reporter_count = float(len(reporters[lkey]))

        # identity_mismatch — BSHH primary signal
        identity_mismatch = 1.0 if phys != nid else 0.0

        # phi — time-elapsed encoding (Eq 3.21); T_b = 0.1 s
        prev_recv  = last_recv.get(nid, recv)
        delta_t    = max(0.0, recv - prev_recv)
        phi        = math.log(1.0 + delta_t / BEACON_INTERVAL)
        last_recv[nid] = recv

        feats[i] = [id_v_norm, tau_s, beacon_count, seq_gap, reporter_count,
                    identity_mismatch, phi]

    return feats


# ---------------------------------------------------------------------------
# 2.  TGN model in PyTorch
#     Architecture mirrors tgn_detector.cc so exported weights load correctly.
# ---------------------------------------------------------------------------

class TGNModel(nn.Module):
    """
    Temporal Graph Network — implements Eqs 3.21-3.23, 3.34.

    The GRU gate and message-passing parameter shapes exactly match those
    expected by TGNDetector::LoadWeights(), so export_weights() is lossless.
    """

    def __init__(self, dim: int = 32, layers: int = 2):
        super().__init__()
        self.dim    = dim
        self.layers = layers
        gs = dim + 7   # GRU input = hidden (dim) + [id_v, tau_s, c_vW, seq_gap, rho, id_mis, phi]

        # GRU gates  (Eq 3.21)
        #   W*: (dim, gs),  U*: (dim, dim),  b*: (dim,)
        self.Wz = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wz)
        self.Uz = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Uz)
        self.bz = nn.Parameter(torch.zeros(dim))

        self.Wr = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wr)
        self.Ur = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Ur)
        self.br = nn.Parameter(torch.zeros(dim))

        self.Wn = nn.Parameter(torch.empty(dim, gs));  nn.init.xavier_uniform_(self.Wn)
        self.Un = nn.Parameter(torch.empty(dim, dim)); nn.init.xavier_uniform_(self.Un)
        self.bn = nn.Parameter(torch.zeros(dim))

        # Message-passing layers  (Eq 3.22)
        #   W: (dim, dim),  b: (dim,)
        self.W_layers = nn.ParameterList(
            [nn.Parameter(torch.empty(dim, dim)) for _ in range(layers)])
        self.b_layers = nn.ParameterList(
            [nn.Parameter(torch.zeros(dim)) for _ in range(layers)])
        for W in self.W_layers:
            nn.init.xavier_uniform_(W)

        # Score readout  (Eq 3.23)
        self.w_score = nn.Parameter(0.01 * torch.randn(dim))

        # Variant classification head (Section 4.7)
        # α̂_v = softmax(Wcls · h_v^(L) + b_cls),  α ∈ {TTW=0, BSHH=1, ME=2}
        # Trained jointly with binary scorer via multi-class cross-entropy loss.
        self.Wcls  = nn.Parameter(torch.empty(3, dim)); nn.init.xavier_uniform_(self.Wcls)
        self.b_cls = nn.Parameter(torch.zeros(3))

    # ── GRU step (Eq 3.21) ───────────────────────────────────────────────────
    def gru_step(self, h: torch.Tensor, feat: torch.Tensor) -> torch.Tensor:
        """
        h:    (dim,)  current memory h_v(t-)
        feat: (6,)    raw feature vector [tau_s, c_vW, seq_gap, rho, id_mis, phi]
        returns new_h: (dim,)  updated memory m_v(t)
        """
        gru_in = torch.cat([h, feat])                             # (gs,)
        z = torch.sigmoid(self.Wz @ gru_in + self.Uz @ h + self.bz)   # update gate
        r = torch.sigmoid(self.Wr @ gru_in + self.Ur @ h + self.br)   # reset gate
        n = torch.tanh(  self.Wn @ gru_in + self.Un @ (r * h) + self.bn)  # candidate
        return (1.0 - z) * h + z * n

    # ── Message passing (Eq 3.22) ─────────────────────────────────────────────
    def mp_step(self,
                h_node: torch.Tensor,
                h_ldst: torch.Tensor,
                h_lsrc: torch.Tensor,
                Auv:    float) -> torch.Tensor:
        """
        Mini message-passing over the event's 3-node subgraph:
          active = {claimed_sender_id, link_src_id, link_dst_id}
          edge:    claimed_sender_id <-> link_dst_id  with weight Auv (Eq 3.20)
        Aggregation: MEAN{h_u * A_uv : u in N(v)} per Eq 3.22.
        link_src has no in-edge so it contributes only as a small context signal.
        """
        # Aggregated neighbourhood of reporting node = weighted mean of ldst
        h_agg = (h_node + Auv * h_ldst) / (1.0 + Auv)
        h_agg = h_agg + 0.1 * h_lsrc   # weak lsrc context (no direct edge)

        for l in range(self.layers):
            h_agg = torch.relu(self.W_layers[l] @ h_agg + self.b_layers[l])
        return h_agg

    # ── Sequential forward (1-step truncated BPTT) ───────────────────────────
    def forward_sequence(
        self,
        feats:  torch.Tensor,   # (N, 6)
        nids:   torch.Tensor,   # (N,)  int64  claimed_sender_id
        lsrcs:  torch.Tensor,   # (N,)  int64  link_src_id
        ldsts:  torch.Tensor,   # (N,)  int64  link_dst_id
        fresh:  torch.Tensor,   # (N,)  float  edge freshness A_uv (Eq 3.20)
    ) -> torch.Tensor:
        """
        Process N events in reception-time order.
        Returns raw logits (N,) before sigmoid — use BCEWithLogitsLoss for training.
        Node memories are detached between events (1-step TBPTT) as in the
        TGN paper (Rossi et al., 2020) to handle long sequences efficiently.
        New nodes are zero-initialized (Eq 3.34).
        """
        device = feats.device
        mem: dict[int, torch.Tensor] = {}   # node_id -> (dim,) detached tensor

        logits     = []
        cls_logits = []
        for i in range(feats.shape[0]):
            nid  = int(nids[i].item())
            lsrc = int(lsrcs[i].item())
            ldst = int(ldsts[i].item())
            Auv  = float(fresh[i].item())

            # Zero-init new nodes (Eq 3.34)
            for v in (nid, lsrc, ldst):
                if v not in mem:
                    mem[v] = torch.zeros(self.dim, device=device)

            # GRU memory update for the reporting node
            h_new = self.gru_step(mem[nid], feats[i])

            # Message passing over 3-node subgraph
            h_final = self.mp_step(h_new, mem[ldst], mem[lsrc], Auv)

            # Binary score logit (sigmoid applied by loss/caller)  — Eq 3.23
            logits.append(torch.dot(self.w_score, h_final))

            # Variant classification logit  — Section 4.7
            cls_logits.append(self.Wcls @ h_final + self.b_cls)

            # Detach and store (prevents gradient accumulation across events)
            mem[nid] = h_new.detach()

        return torch.stack(logits), torch.stack(cls_logits)   # (N,), (N, 3)


# ---------------------------------------------------------------------------
# 3.  Binary weight export  (bit-compatible with TGNDetector::LoadWeights())
# ---------------------------------------------------------------------------

def export_weights(model: TGNModel, path: str) -> None:
    """
    Write weights to a binary file in the exact order and dtype that
    TGNDetector::LoadWeights() reads them.
    All tensors are converted to float64 (double) in row-major order.
    """
    dim    = model.dim
    layers = model.layers

    def f64(t: torch.Tensor) -> bytes:
        return t.detach().cpu().to(torch.float64).numpy().tobytes()

    with open(path, "wb") as fp:
        fp.write(struct.pack("ii", dim, layers))
        for W, U, b in [(model.Wz, model.Uz, model.bz),
                        (model.Wr, model.Ur, model.br),
                        (model.Wn, model.Un, model.bn)]:
            fp.write(f64(W)); fp.write(f64(U)); fp.write(f64(b))
        for l in range(layers):
            fp.write(f64(model.W_layers[l])); fp.write(f64(model.b_layers[l]))
        fp.write(f64(model.w_score))
        fp.write(f64(model.Wcls))
        fp.write(f64(model.b_cls))

    size = os.path.getsize(path)
    print(f"[TGN] Weights saved to '{path}'  ({size} bytes, dim={dim} layers={layers})")


# ---------------------------------------------------------------------------
# 4.  Metric helpers
# ---------------------------------------------------------------------------

def compute_metrics(labels: np.ndarray, scores: np.ndarray, theta: float):
    preds = (scores >= theta).astype(int)
    tp = int(((preds == 1) & (labels == 1)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    mcc = 0.0
    if labels.sum() > 0 and (labels == 0).sum() > 0:
        mcc = matthews_corrcoef(labels, preds)
    try:
        auc = roc_auc_score(labels, scores)
    except ValueError:
        auc = 0.5
    return tp, tn, fp, fn, mcc, auc


# ---------------------------------------------------------------------------
# 5.  Training loop
# ---------------------------------------------------------------------------

def train(df: "pd.DataFrame", args: argparse.Namespace) -> TGNModel:
    # Sort strictly by reception time — preserves temporal ordering for GRU
    df = df.sort_values("recv_time_s").reset_index(drop=True)

    feats  = extract_features(df, gamma=args.gamma,
                              wmax=getattr(args, "wmax", WMAX))   # (N, 7)
    labels = df["is_attack"].values.astype(np.float32)
    nids   = df["claimed_sender_id"].values.astype(np.int64)
    lsrcs  = df["link_src_id"].values.astype(np.int64)
    ldsts  = df["link_dst_id"].values.astype(np.int64)
    fresh  = df["edge_freshness"].values.astype(np.float32)    # from CSV

    # Variant class labels for Section 4.7 classification head.
    # -1 = benign (excluded from CE loss), 0 = TTW, 1 = BSHH, 2 = ME
    sc = df["attack_scenario"].values.astype(np.int64) if "attack_scenario" in df.columns \
         else np.zeros(len(df), dtype=np.int64)
    variant_label = np.where((sc >= 1)  & (sc <= 4),  0,
                    np.where((sc >= 5)  & (sc <= 8),  1,
                    np.where((sc >= 9)  & (sc <= 12), 2, -1))).astype(np.int64)

    N    = len(df)
    n_tr = int(0.70 * N)
    n_va = int(0.15 * N)

    slices = {
        "train": (0,        n_tr),
        "val":   (n_tr,     n_tr + n_va),
        "test":  (n_tr + n_va, N),
    }

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[TGN] Device: {device}")
    for split, (a, b) in slices.items():
        n_a = int(labels[a:b].sum())
        print(f"       {split:5s}: {b-a:5d} events  ({n_a} attack, {b-a-n_a} benign)")

    model = TGNModel(dim=args.dim, layers=args.layers).to(device)

    # Class-weight balancing for BCE (Section 4 — imbalanced attack/benign events)
    n_pos  = float(labels[:n_tr].sum())
    n_neg  = float(n_tr - n_pos)
    pos_wt = torch.tensor([n_neg / max(n_pos, 1.0)], device=device)
    crit   = nn.BCEWithLogitsLoss(pos_weight=pos_wt)

    optim_ = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    sched  = optim.lr_scheduler.CosineAnnealingLR(optim_, T_max=args.epochs)

    def tt(arr, dtype=torch.float32):
        return torch.tensor(arr, dtype=dtype, device=device)

    a, b = slices["train"]
    tr_f, tr_l = tt(feats[a:b]), tt(labels[a:b])
    tr_n   = tt(nids[a:b],          torch.int64)
    tr_ls  = tt(lsrcs[a:b],         torch.int64)
    tr_ld  = tt(ldsts[a:b],         torch.int64)
    tr_fr  = tt(fresh[a:b])
    tr_var = tt(variant_label[a:b], torch.int64)

    a, b = slices["val"]
    va_f  = tt(feats[a:b])
    va_n  = tt(nids[a:b],  torch.int64)
    va_ls = tt(lsrcs[a:b], torch.int64)
    va_ld = tt(ldsts[a:b], torch.int64)
    va_fr = tt(fresh[a:b])
    va_l  = labels[slices["val"][0]:slices["val"][1]]

    best_mcc, best_epoch, best_state = -1.0, 0, None
    log_every = max(1, args.epochs // 10)

    print(f"\n[TGN] Training: dim={args.dim} layers={args.layers} "
          f"epochs={args.epochs} lr={args.lr} theta={args.theta}\n")

    for epoch in range(1, args.epochs + 1):
        model.train()
        optim_.zero_grad()

        logits, cls_logits = model.forward_sequence(tr_f, tr_n, tr_ls, tr_ld, tr_fr)
        bce_loss = crit(logits, tr_l)

        # Joint multi-class CE loss for attack events only (Section 4.7)
        cls_mask = tr_var >= 0
        if cls_mask.any():
            ce_loss = nn.CrossEntropyLoss()(cls_logits[cls_mask], tr_var[cls_mask])
            loss = bce_loss + 0.3 * ce_loss
        else:
            loss = bce_loss
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optim_.step()
        sched.step()

        if epoch % log_every == 0 or epoch == args.epochs:
            model.eval()
            with torch.no_grad():
                va_logits, _ = model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)
                va_scores = torch.sigmoid(va_logits).cpu().numpy()

            tp, tn, fp, fn, mcc, auc = compute_metrics(va_l, va_scores, args.theta)
            print(f"  Epoch {epoch:4d}/{args.epochs}  loss={loss.item():.4f}"
                  f"  val_MCC={mcc:.3f}  val_AUROC={auc:.3f}"
                  f"  TP={tp} TN={tn} FP={fp} FN={fn}")

            if mcc > best_mcc:
                best_mcc   = mcc
                best_epoch = epoch
                best_state = copy.deepcopy(model.state_dict())

    if best_state is not None:
        model.load_state_dict(best_state)
        print(f"\n[TGN] Best checkpoint: epoch={best_epoch}  val_MCC={best_mcc:.3f}")

    # ── Optimal threshold selection by MCC on validation set ─────────────────
    # Paper Section 7: "θ_FS selected by maximising MCC on held-out validation data"
    model.eval()
    with torch.no_grad():
        opt_va_scores = torch.sigmoid(
            model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)[0]).cpu().numpy()

    if args.theta < 0:   # auto-select
        best_theta, best_theta_mcc = 0.40, -1.0
        for th in np.arange(0.05, 0.96, 0.01):
            preds = (opt_va_scores >= th).astype(int)
            if preds.sum() == 0 or preds.sum() == len(preds):
                continue
            try:
                m = matthews_corrcoef(va_l, preds)
            except Exception:
                m = 0.0
            if m > best_theta_mcc:
                best_theta_mcc = m
                best_theta = float(th)
        args.theta = best_theta
        print(f"[TGN] Optimal theta_FS = {args.theta:.2f}  (val_MCC={best_theta_mcc:.3f})")
    else:
        print(f"[TGN] Using fixed theta_FS = {args.theta:.2f}")

    # Test evaluation
    a, b = slices["test"]
    te_f  = tt(feats[a:b])
    te_n  = tt(nids[a:b],  torch.int64)
    te_ls = tt(lsrcs[a:b], torch.int64)
    te_ld = tt(ldsts[a:b], torch.int64)
    te_fr = tt(fresh[a:b])
    te_l  = labels[a:b]

    model.eval()
    with torch.no_grad():
        te_scores = torch.sigmoid(
            model.forward_sequence(te_f, te_n, te_ls, te_ld, te_fr)[0]).cpu().numpy()

    tp, tn, fp, fn, mcc, auc = compute_metrics(te_l, te_scores, args.theta)
    print(f"\n[TGN] Test  MCC={mcc:.3f}  AUROC={auc:.3f}  "
          f"TP={tp} TN={tn} FP={fp} FN={fn}")

    return model


# ---------------------------------------------------------------------------
# 6.  Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Train TGN on tgn_events.csv and export binary weights for tgn_detector.cc."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example workflow:\n"
            "  # Generate data for all scenarios first:\n"
            "  for s in 1 2 3 4 5 6 7 8 9 10 11 12; do\n"
            "    ./waf --run \"scratch/tgn_detector --simTime=60 "
            "--N_Vehicles=6 --attack_scenario=$s\"\n"
            "    cat tgn_events.csv >> all_events.csv\n"
            "  done\n"
            "  # (Remove duplicate CSV headers if concatenating manually)\n\n"
            "  # Train on all scenarios:\n"
            "  python3 tgn_train.py all_events.csv --epochs 50 --output tgn_weights.bin\n\n"
            "  # Deploy:\n"
            "  ./waf --run \"scratch/tgn_detector --simTime=60 --N_Vehicles=6 \\\n"
            "               --attack_scenario=1 --tgn_weights=tgn_weights.bin\"\n"
        ),
    )
    ap.add_argument("csv",        nargs="?", default="tgn_events.csv",
                    help="Input events CSV (default: tgn_events.csv)")
    ap.add_argument("--dim",      type=int,   default=32,
                    help="Embedding dim — must match --tgn_dim in tgn_detector (default: 32)")
    ap.add_argument("--layers",   type=int,   default=2,
                    help="Message-passing rounds — must match --tgn_layers (default: 2)")
    ap.add_argument("--epochs",   type=int,   default=50,
                    help="Training epochs (default: 50)")
    ap.add_argument("--lr",       type=float, default=1e-3,
                    help="Adam learning rate (default: 0.001)")
    ap.add_argument("--l_link",   type=float, default=43.0,
                    help="Expected link lifetime L_link (s). Urban≈43s, Highway≈9s. "
                         "Used to calibrate gamma and W_max. (default: 43.0)")
    ap.add_argument("--gamma",    type=float, default=-1.0,
                    help="Edge freshness decay gamma. -1 = auto from --l_link via "
                         "gamma=(L_link/2)/(T_b*ln2) Eq 9.3 (default: auto)")
    ap.add_argument("--theta",    type=float, default=-1.0,
                    help="Alert threshold theta_FS. -1 = auto-select by max-MCC on "
                         "validation set (paper Section 7, default: auto)")
    ap.add_argument("--scenario", type=int,   default=-1,
                    help="Filter to one attack_scenario; -1 = all (default: -1)")
    ap.add_argument("--output",   default="tgn_weights.bin",
                    help="Output binary file (default: tgn_weights.bin)")
    args = ap.parse_args()

    # γ calibration: γ = (L_link/2) / (T_b · ln2)  — Eq 9.3
    if args.gamma < 0:
        args.gamma = (args.l_link / 2.0) / (BEACON_INTERVAL * math.log(2.0))
    # W_max = ⌈L_link / T_b⌉  — Eq 9.2
    args.wmax = int(math.ceil(args.l_link / BEACON_INTERVAL))
    print(f"[TGN] L_link={args.l_link}s  gamma={args.gamma:.1f}  W_max={args.wmax}")

    if not os.path.exists(args.csv):
        sys.exit(
            f"[ERROR] '{args.csv}' not found.\n"
            f"  Run tgn_detector first to generate tgn_events.csv, e.g.:\n"
            f"    ./waf --run \"scratch/tgn_detector --simTime=60 "
            f"--N_Vehicles=6 --attack_scenario=1\""
        )

    df = pd.read_csv(args.csv)

    # Remove duplicate header rows (artefact when cat-ing multiple CSV files)
    df = df[df["sim_time_s"] != "sim_time_s"].reset_index(drop=True)
    # Coerce numeric columns after string-header removal
    num_cols = ["sim_time_s", "attack_scenario", "physical_sender_id",
                "claimed_sender_id", "link_src_id", "link_dst_id",
                "claimed_ts_s", "recv_time_s", "rx_delay_s",
                "edge_freshness", "seq_gap", "reporter_count",
                "identity_mismatch", "pem_score", "pem_alert",
                "tgn_score", "tgn_alert", "is_attack"]
    for col in num_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["is_attack", "claimed_sender_id"]).reset_index(drop=True)

    print(f"[TGN] Loaded {len(df)} rows from '{args.csv}'")
    print(f"      Attack events: {int(df['is_attack'].sum())}  "
          f"Benign events: {int((df['is_attack'] == 0).sum())}")

    if args.scenario >= 0:
        df = df[df["attack_scenario"] == args.scenario].reset_index(drop=True)
        print(f"[TGN] Filtered to scenario {args.scenario}: {len(df)} rows")

    # Drop pure beacon events — TGN focuses on topology/heartbeat anomalies
    df = df[df["event_type"] != "BEACON"].reset_index(drop=True)
    print(f"[TGN] After BEACON filter: {len(df)} rows")

    if len(df) < 20:
        sys.exit(
            "[ERROR] Too few events to train (need >= 20 non-beacon rows).\n"
            "  Generate data for more scenarios or longer simTime."
        )

    if "attack_scenario" in df.columns:
        print("\n[TGN] Events per attack_scenario:")
        for sc, grp in df.groupby("attack_scenario"):
            n_a = int(grp["is_attack"].sum())
            print(f"        scenario {int(sc):2d}: {len(grp):5d} events "
                  f"({n_a} attack, {len(grp)-n_a} benign)")

    model = train(df, args)
    export_weights(model, args.output)

    print(f"\n[TGN] Complete.  Deploy with:")
    print(f"  ./waf --run \"scratch/tgn_detector --simTime=60 --N_Vehicles=6 \\")
    print(f"               --attack_scenario=1 --tgn_weights={args.output} \\")
    print(f"               --tgn_theta={args.theta:.2f} --tgn_l_link={args.l_link}\"")
    if args.dim != 32 or args.layers != 2:
        print(f"  # Also pass: --tgn_dim={args.dim} --tgn_layers={args.layers}")


if __name__ == "__main__":
    main()
