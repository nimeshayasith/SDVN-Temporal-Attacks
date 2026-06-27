#!/usr/bin/env python3
"""
tgn_train.py — Train TGN weights on tgn_events.csv; export binary checkpoint
               for tgn_detector.cc (TGNDetector::LoadWeights).

Paper reference:
  Section 3.4.3 + Algorithm 2 (FS-DETECT) — Eqs 3.18-3.23, 3.34.

Workflow:
  Step 1 — Generate training data (routing.cc includes tgn_core.cc):
    ./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --attack_scenario=1"
    # Repeat for all 12 attack scenarios; concatenate the tgn_events.csv files.
    # Or use: bash generate_training_data.sh  (does all scenarios automatically)

  Step 2 — Train:
    python3 tgn_train.py tgn_events.csv --epochs 50 --output tgn_weights.bin

  Step 3 — Run detector with trained weights:
    ./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 \\
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
  Wcls (3 x dim)
  b_cls (3)
  where gs = dim + 6   (tau_dev, c_vW, seq_gap, rho_v, id_mis, phi)  — Eq 3.20, Table 4.7
"""

import argparse
import copy
import math
import os
import struct
import sys

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

def extract_features(df: "pd.DataFrame") -> np.ndarray:
    """
    Compute the 6-element feature vector for every row in df (already time-sorted).

    Feature mapping to paper notation (Eq 3.20 + phi from Eq 3.21):
      [tau_deviation, beacon_count, seq_gap, reporter_count, identity_mismatch, phi]
       = [(recv−τ_s)/T_b, c_v^W, delta_s_v, rho_v, iota_v, log(1+delta_t/T_b)]

    id_v (node_id % 1000 / 1000) is deliberately excluded: it causes the model to
    learn attacker identity → attack rather than temporal patterns, and the controller
    sentinel id_v=0.999 is uniquely discriminative but not a behavioral signal.

    tau_deviation = clip((recv_time_s − claimed_ts_s) / T_b, −50, 50).
    A fresh packet yields tau_deviation ≈ 0; a TTW replay yields a large positive
    value because claimed_ts_s is old while recv_time_s is current.

    beacon_count, seq_gap, reporter_count, identity_mismatch are read directly from
    the pre-computed CSV columns written by C++ TGN_ExtractFeatures.  Recomputing
    them in Python would produce wrong values for:
      beacon_count    — BEACON events absent from CSV (window severely undercounted)
      seq_gap         — last_ts carries across run boundaries in concatenated CSV files
      reporter_count  — RSU-path uses claimed_sender_id; reporter_id not in CSV
      identity_mismatch — RSU events and controller sentinel 9999 must give 0.0
    Only tau_deviation and phi are recomputed because they depend on recv_time_s and
    are not stored in the CSV.
    """
    N     = len(df)
    feats = np.zeros((N, 6), dtype=np.float32)

    last_recv    = {}          # node_id -> previous recv_time_s (for phi only)
    prev_scenario = None       # reset last_recv at each scenario boundary

    for i, row in enumerate(df.itertuples(index=False)):
        scen = getattr(row, "attack_scenario", -1)
        if scen != prev_scenario:
            last_recv = {}
            prev_scenario = scen

        nid  = int(row.claimed_sender_id)
        recv  = float(row.recv_time_s)

        # tau_deviation — normalised temporal gap (recv − τ_s) / T_b, clamped [−50, 50].
        # Replaces absolute tau_s: prevents the model from learning absolute timestamp
        # values and instead captures the staleness signal directly.
        tau_deviation = float(np.clip(
            (recv - float(row.claimed_ts_s)) / BEACON_INTERVAL, -50.0, 50.0))

        # beacon_count (c_v^W) — read from pre-computed CSV column.
        # C++ g_tgn_beacon_windows is updated by BOTH BEACON events (via the Issue 9 fix
        # in TGN_ProcessAllEvents) and TOPO_UPDATE events (via TGN_ExtractFeatures).
        # BEACON rows are absent from the CSV (BEACON events don't produce a CSV row),
        # so recomputing the sliding window here from CSV rows alone would miss all
        # BEACON contributions and produce beacon_count ≈ 5-10 vs C++'s ≈ 430.
        beacon_count = float(row.beacon_count)

        # seq_gap (delta_s_v) — read from pre-computed CSV column.
        # Recomputing from last_ts would be wrong for concatenated multi-run CSVs:
        # after sorting by recv_time_s, run N's attack event (tau_s=0.0) may follow
        # run N-1's attack event (tau_s=0.0), making last_ts[nid]=0.0 so the computed
        # seq_gap=0.0 instead of the correct 5.0.  C++ computes per-run with a fresh
        # g_tgn_last_sender_ts.clear() at the start of each TGN_ProcessAllEvents.
        seq_gap = float(row.seq_gap)

        # reporter_count (rho_v) — read from pre-computed CSV column.
        # C++ TGN_ExtractFeatures uses RSU-aware logic: no-RSU path tracks reporter_id
        # (not physical_sender_id); RSU path tracks claimed_sender_id.  reporter_id is
        # not present in the CSV, so recomputing from physical_sender_id here would
        # produce wrong values for RSU and controller scenarios.
        reporter_count = float(row.reporter_count)

        # identity_mismatch — read from pre-computed CSV column.
        # C++ suppresses to 0.0 for RSU events (physical_is_rsu=true) and for the
        # controller sentinel (physical_sender_id==9999).  Recomputing as
        # (phys != nid) here would give 1.0 for those cases, producing features that
        # don't match what the C++ inference path computes — causing train/infer mismatch
        # for all "With RSU" and "Malicious Controller" scenarios.
        identity_mismatch = float(row.identity_mismatch)

        # phi — time-elapsed encoding (Eq 3.21); T_b = 0.1 s
        # Not stored in CSV; must be recomputed from consecutive recv times.
        prev_recv  = last_recv.get(nid, recv)
        delta_t    = max(0.0, recv - prev_recv)
        phi        = math.log(1.0 + delta_t / BEACON_INTERVAL)
        last_recv[nid] = recv

        feats[i] = [tau_deviation, beacon_count, seq_gap, reporter_count,
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
        gs = dim + 6   # GRU input = hidden (dim) + [tau_dev, c_vW, seq_gap, rho, id_mis, phi]  (Eq 3.20)

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
        # Scalar bias: initialised to −2.0 so sigmoid(logit) ≈ 0.12 at start.
        # With h_final ≥ 0 (ReLU mp_step), dot(w_score, h_final) drifts positive
        # for all events without this bias, giving TN=0 at every threshold.
        self.b_score = nn.Parameter(torch.tensor(-0.85))

        # Variant classification head (Section 4.7)
        # α̂_v = softmax(Wcls · h_v^(L) + b_cls),  α ∈ {TTW=0, BSHH=1, ME=2}
        # Trained jointly with binary scorer via multi-class cross-entropy loss.
        self.Wcls  = nn.Parameter(torch.empty(3, dim)); nn.init.xavier_uniform_(self.Wcls)
        self.b_cls = nn.Parameter(torch.zeros(3))

    # ── GRU step (Eq 3.21) ───────────────────────────────────────────────────
    def gru_step(self, h: torch.Tensor, feat: torch.Tensor) -> torch.Tensor:
        """
        h:    (dim,)  current memory h_v(t-)
        feat: (6,)    feature vector [tau_dev, c_vW, seq_gap, rho, id_mis, phi]  (Eq 3.20)
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
                Auv:    float) -> torch.Tensor:
        """
        Mirrors C++ MessagePassingRound over 3-node subgraph {node_id, link_src, link_dst}.

        Adjacency (built in ProcessEvent):
          adj[node_id][link_dst] = Auv  (symmetric, no self-loops)
          adj[link_dst][node_id] = Auv
          link_src has no adj entries → passes through unchanged, not used for scoring.

        Each round l:
          hn_new = ReLU(W_l @ (Auv * hd) + b_l)   # node_id aggregates from link_dst
          hd_new = ReLU(W_l @ (Auv * hn) + b_l)   # link_dst aggregates from node_id

        For L=2 rounds, node_id embedding becomes:
          relu(W1 @ (Auv * relu(W0 @ (Auv * h_node) + b0)) + b1)
        which matches the C++ 2-round message passing path.
        """
        hn, hd = h_node, h_ldst
        for l in range(self.layers):
            hn_new = torch.relu(self.W_layers[l] @ (Auv * hd) + self.b_layers[l])
            hd_new = torch.relu(self.W_layers[l] @ (Auv * hn) + self.b_layers[l])
            hn, hd = hn_new, hd_new
        return hn

    # ── Sequential forward (per-node window-based TBPTT, W=100) ─────────────
    TBPTT_WINDOW = 100   # detach each node's memory after W events for that node

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
        Returns raw logits (N,) and classification logits (N, 3) before
        sigmoid/softmax — use BCEWithLogitsLoss + CrossEntropyLoss for training.
        New nodes are zero-initialized (Eq 3.34).

        Per-node TBPTT: each node's GRU memory is detached after every
        TBPTT_WINDOW events for THAT node. With 200 vehicles a global window
        counter would give ~0.5 events per node per window (≈ 1-step TBPTT);
        per-node counting guarantees each node accumulates exactly W gradient
        steps through its own temporal trajectory before detachment.
        """
        device = feats.device
        mem:        dict[int, torch.Tensor] = {}   # node_id -> (dim,) tensor
        node_count: dict[int, int]          = {}   # node_id -> events seen so far

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
                    mem[v]        = torch.zeros(self.dim, device=device)
                    node_count[v] = 0

            # GRU memory update for the reporting node (gradient flows within window)
            h_new = self.gru_step(mem[nid], feats[i])

            # Message passing over 3-node subgraph
            h_final = self.mp_step(h_new, mem[ldst], Auv)

            # Binary score logit (sigmoid applied by loss/caller)  — Eq 3.23
            logits.append(torch.dot(self.w_score, h_final) + self.b_score)

            # Variant classification logit  — Section 4.7
            cls_logits.append(self.Wcls @ h_final + self.b_cls)

            # Per-node window boundary: detach only this node's memory after W events.
            node_count[nid] += 1
            if node_count[nid] % self.TBPTT_WINDOW == 0:
                mem[nid] = h_new.detach()
            else:
                mem[nid] = h_new

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
        fp.write(struct.pack("d", float(model.b_score.item())))
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
    # Stratified temporal 70/15/15 split:
    # Attack and benign events within each scenario are split independently so that
    # the last 30% of EACH class (by recv_time_s) reaches val/test.
    # Without this, benign events (t≈10) always land in the train 70% while attack
    # events (t≈20) fill val/test — leaving 8 of 12 scenarios with zero benign in test.
    df = df.sort_values(["attack_scenario", "recv_time_s"]).reset_index(drop=True)

    train_idx, val_idx, test_idx = [], [], []
    for scen_id in sorted(df["attack_scenario"].unique()):
        scen_mask = df["attack_scenario"] == scen_id
        for label in [0, 1]:   # benign then attack
            idx = df.index[scen_mask & (df["is_attack"] == label)].tolist()
            n = len(idx)
            if n == 0:
                continue
            n_tr_s = max(1, int(0.70 * n))
            n_va_s = max(0, round(0.15 * n))   # round so n>=4 contributes >=1 val event
            train_idx.extend(idx[:n_tr_s])
            val_idx.extend(  idx[n_tr_s : n_tr_s + n_va_s])
            test_idx.extend( idx[n_tr_s + n_va_s:])

    # Re-sort each split by recv_time_s so the GRU sees events in time order
    train_idx = sorted(train_idx, key=lambda i: df.loc[i, "recv_time_s"])
    val_idx   = sorted(val_idx,   key=lambda i: df.loc[i, "recv_time_s"])
    test_idx  = sorted(test_idx,  key=lambda i: df.loc[i, "recv_time_s"])

    # Reorder df so slice-based indexing [0:n_tr], [n_tr:n_tr+n_va], etc. works
    all_idx = train_idx + val_idx + test_idx
    df = df.loc[all_idx].reset_index(drop=True)

    feats  = extract_features(df)   # (N, 6)
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

    n_tr = len(train_idx)
    n_va = len(val_idx)
    N    = len(all_idx)

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

    # Auto-restart: reinitialise model if val_bestMCC stays below target
    # OR the class separation gap is too narrow for a robust threshold.
    # Each restart uses a fresh random initialisation. Max 5 attempts.
    MAX_RESTARTS   = 5
    TARGET_VAL_MCC = 0.975  # stop when this is reached; 0.98 is unattainable on small datasets
    MIN_GAP_WIDTH  = 0.010  # min score gap between classes for stable theta

    model             = None
    # Global-best trackers: preserved across all restart attempts
    global_best_mcc   = -1.0
    global_best_auc   = -1.0
    global_best_epoch = 0
    global_best_state = None

    # Per-attempt trackers: reset each attempt
    best_criterion    = -1.0
    best_criterion_auc = -1.0
    best_epoch        = 0
    best_state        = None

    for attempt in range(1, MAX_RESTARTS + 1):
        if attempt > 1:
            print(f"\n[TGN] Restart {attempt-1}/{MAX_RESTARTS-1} "
                  f"— val_bestMCC={best_criterion:.3f} < target={TARGET_VAL_MCC}. "
                  f"Re-initialising model.")

        model  = TGNModel(dim=args.dim, layers=args.layers).to(device)
        # Dynamic pos_weight = n_benign / n_attack (actual class ratio).
        # Using the real ratio (instead of a fixed 2.0) adapts to whatever imbalance
        # the generated dataset has — balanced data gets pos_weight≈1, skewed data
        # gets a larger weight that exactly compensates the imbalance.
        n_atk_tr = int(tr_l.sum().item())
        n_ben_tr = int((tr_l == 0).sum().item())
        pw_val   = float(n_ben_tr) / max(1, n_atk_tr)
        pos_wt   = torch.tensor([pw_val], device=device)
        print(f"       pos_weight = {pw_val:.2f}  ({n_ben_tr} benign / {n_atk_tr} attack in train)")
        crit   = nn.BCEWithLogitsLoss(pos_weight=pos_wt)
        optim_ = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
        sched  = optim.lr_scheduler.CosineAnnealingLR(optim_, T_max=args.epochs)

        best_criterion     = -1.0
        best_criterion_auc = -1.0
        best_epoch         = 0
        best_state         = None

        log_every = max(1, args.epochs // 10)

        print(f"\n[TGN] Training attempt {attempt}/{MAX_RESTARTS}: "
              f"dim={args.dim} layers={args.layers} "
              f"epochs={args.epochs} lr={args.lr} theta={args.theta}\n")

        for epoch in range(1, args.epochs + 1):
            model.train()
            optim_.zero_grad()

            logits, cls_logits = model.forward_sequence(tr_f, tr_n, tr_ls, tr_ld, tr_fr)
            bce_loss = crit(logits, tr_l)

            # Margin loss: force mean(score_attack) - mean(score_benign) >= MARGIN.
            # This directly targets gap_width=0 (overlapping distributions).
            # When scores overlap, the gradient pulls attack scores up and benign
            # scores down simultaneously — something BCE alone cannot do because
            # it only cares about individual labels, not relative separation.
            MARGIN        = 0.35   # minimum required separation between class means
            MARGIN_LAMBDA = 0.50   # weight relative to BCE
            atk_mask = (tr_l == 1)
            ben_mask = (tr_l == 0)
            if atk_mask.any() and ben_mask.any():
                atk_mean    = torch.sigmoid(logits[atk_mask]).mean()
                ben_mean    = torch.sigmoid(logits[ben_mask]).mean()
                margin_loss = torch.clamp(MARGIN - (atk_mean - ben_mean), min=0.0)
            else:
                margin_loss = torch.tensor(0.0, device=device)

            # Joint multi-class CE loss for attack events only (Section 4.7)
            cls_mask = tr_var >= 0
            if cls_mask.any():
                ce_loss = nn.CrossEntropyLoss()(cls_logits[cls_mask], tr_var[cls_mask])
                loss = bce_loss + 0.3 * ce_loss + MARGIN_LAMBDA * margin_loss
            else:
                loss = bce_loss + MARGIN_LAMBDA * margin_loss
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim_.step()
            sched.step()

            if epoch % log_every == 0 or epoch == args.epochs:
                model.eval()
                with torch.no_grad():
                    va_logits, _ = model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)
                    va_scores = torch.sigmoid(va_logits).cpu().numpy()

                # Use 0.5 for display; early stopping uses best MCC over full theta sweep.
                monitor_theta = 0.5 if args.theta < 0 else args.theta
                tp, tn, fp, fn, mcc, auc = compute_metrics(va_l, va_scores, monitor_theta)

                # Find best val_MCC across all thresholds (the criterion we actually care about)
                best_mcc_this_epoch = -1.0
                best_th_this_epoch  = monitor_theta
                for th in np.arange(0.001, 0.999, 0.001):
                    preds_th = (va_scores >= th).astype(int)
                    if preds_th.sum() == 0 or preds_th.sum() == len(preds_th):
                        continue
                    try:
                        m_th = matthews_corrcoef(va_l, preds_th)
                    except Exception:
                        m_th = 0.0
                    if m_th > best_mcc_this_epoch:
                        best_mcc_this_epoch = m_th
                        best_th_this_epoch  = th

                gap_str = ""
                if atk_mask.any() and ben_mask.any():
                    # logits still valid from the training step above (not recomputed)
                    tr_sigs_d = torch.sigmoid(logits.detach())
                    gap_str = (f"  gap={float(tr_sigs_d[atk_mask].mean()) - float(tr_sigs_d[ben_mask].mean()):.3f}"
                               f"  mrgn={float(margin_loss.detach()):.3f}")
                print(f"  Epoch {epoch:4d}/{args.epochs}  loss={loss.item():.4f}"
                      f"  bce={bce_loss.item():.4f}{gap_str}"
                      f"  val_MCC@0.5={mcc:.3f}  val_bestMCC={best_mcc_this_epoch:.3f}"
                      f"  (θ={best_th_this_epoch:.3f})  val_AUROC={auc:.3f}"
                      f"  TP={tp} TN={tn} FP={fp} FN={fn}")

                # Primary key: best val_MCC; secondary key: val_AUROC (tiebreaker for equal MCC)
                is_better = (best_mcc_this_epoch > best_criterion or
                             (best_mcc_this_epoch >= best_criterion - 1e-6 and auc > best_criterion_auc))
                if is_better:
                    best_criterion     = best_mcc_this_epoch
                    best_criterion_auc = auc
                    best_epoch         = epoch
                    best_state         = copy.deepcopy(model.state_dict())
                    # Propagate to global-best tracker across all restarts
                    if best_mcc_this_epoch > global_best_mcc or \
                       (best_mcc_this_epoch >= global_best_mcc - 1e-6 and auc > global_best_auc):
                        global_best_mcc   = best_mcc_this_epoch
                        global_best_auc   = auc
                        global_best_epoch = epoch
                        global_best_state = best_state  # already deep-copied above

        if best_state is not None:
            model.load_state_dict(best_state)
            print(f"\n[TGN] Best checkpoint: epoch={best_epoch}  val_bestMCC={best_criterion:.3f}  val_AUROC={best_criterion_auc:.3f}")

        # Compute gap width at best checkpoint for restart decision
        model.eval()
        with torch.no_grad():
            rs_scores = torch.sigmoid(
                model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)[0]).cpu().numpy()
        atk_rs = rs_scores[va_l == 1]
        ben_rs = rs_scores[va_l == 0]
        gap_width_rs = 0.0
        if len(atk_rs) > 0 and len(ben_rs) > 0:
            min_atk = float(atk_rs.min())
            max_ben = float(ben_rs.max())
            if min_atk > max_ben:
                gap_width_rs = min_atk - max_ben

        # Stop condition: MCC target alone is sufficient — gap_width is used only
        # for threshold selection quality, not as a gate on saving the best model.
        mcc_ok = best_criterion >= TARGET_VAL_MCC
        gap_ok = gap_width_rs >= MIN_GAP_WIDTH
        print(f"[TGN] Restart check: val_bestMCC={best_criterion:.3f} (>={TARGET_VAL_MCC}? {mcc_ok})  "
              f"gap_width={gap_width_rs:.4f} (>={MIN_GAP_WIDTH}? {gap_ok})")

        if mcc_ok:   # stop as soon as MCC target is met, regardless of gap
            if attempt > 1:
                print(f"[TGN] MCC target met on attempt {attempt}.")
            break
        if attempt == MAX_RESTARTS:
            print(f"[TGN] Max restarts ({MAX_RESTARTS}) reached. "
                  f"Proceeding with global best (val_bestMCC={global_best_mcc:.3f}).")

    # Restore the globally best weights found across all restart attempts.
    # Without this, model holds the weights from the final attempt only —
    # which may be worse than an earlier attempt (e.g. attempt 2 with MCC=1.0).
    if global_best_state is not None:
        model.load_state_dict(global_best_state)
        print(f"[TGN] Global best restored: epoch={global_best_epoch}  "
              f"val_bestMCC={global_best_mcc:.3f}  val_AUROC={global_best_auc:.3f}")

    # ── Optimal threshold selection by MCC on validation set ─────────────────
    # Paper Section 7: "θ_FS selected by maximising MCC on held-out validation data"
    model.eval()
    with torch.no_grad():
        opt_va_scores = torch.sigmoid(
            model.forward_sequence(va_f, va_n, va_ls, va_ld, va_fr)[0]).cpu().numpy()

    if args.theta < 0:   # auto-select
        # ── Step 1: plateau search (stability check / fallback) ───────────────
        best_theta_mcc = -1.0
        plateau_thetas = []
        for th in np.arange(0.001, 0.999, 0.001):
            preds = (opt_va_scores >= th).astype(int)
            if preds.sum() == 0 or preds.sum() == len(preds):
                continue
            try:
                m = matthews_corrcoef(va_l, preds)
            except Exception:
                m = 0.0
            if m > best_theta_mcc + 1e-6:
                best_theta_mcc = m
                plateau_thetas = [float(th)]
            elif abs(m - best_theta_mcc) <= 1e-6:
                plateau_thetas.append(float(th))
        theta_plateau = float(np.median(plateau_thetas)) if plateau_thetas else 0.40

        # ── Step 2: gap midpoint (primary estimator, scale-independent) ──────
        attack_va   = opt_va_scores[va_l == 1]
        benign_va   = opt_va_scores[va_l == 0]
        gap_available = False
        theta_gap     = theta_plateau
        if len(attack_va) > 0 and len(benign_va) > 0:
            min_attack = float(attack_va.min())
            max_benign = float(benign_va.max())
            if min_attack > max_benign:
                theta_gap     = (min_attack + max_benign) / 2.0
                gap_available = True

        # ── Step 3: sanity check — both methods must agree within tolerance ──
        TOLERANCE = 0.15
        agreement = gap_available and abs(theta_gap - theta_plateau) < TOLERANCE

        # ── Step 4: choose final theta ────────────────────────────────────────
        if agreement:
            best_theta = theta_gap
            method     = "gap_midpoint"
        elif gap_available:
            best_theta = theta_gap
            method     = "gap_midpoint [WARN: plateau disagrees > tol, check data]"
        else:
            best_theta = theta_plateau
            method     = "plateau_mid [no val separation gap]"

        args.theta = best_theta
        gap_str = (f"  gap=[{max_benign:.3f}–{min_attack:.3f}]"
                   if gap_available else "  gap=N/A")
        print(f"[TGN] Optimal theta_FS = {args.theta:.3f}  "
              f"(val_MCC={best_theta_mcc:.3f}"
              f"  theta_plateau={theta_plateau:.3f}"
              f"{gap_str}"
              f"  method={method})")
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
            "  # Easiest: use the bundled script (handles all scenarios + training):\n"
            "  bash generate_training_data.sh\n\n"
            "  # Or manually (note: first run uses 'cat', rest use 'tail -n +2'):\n"
            "  FIRST=1\n"
            "  for s in 0 1 2 3 4 5 6 7 8 9 10 11 12; do\n"
            "    ./waf --run \"scratch/routing --simTime=60 "
            "--N_Vehicles=6 --attack_scenario=$s\"\n"
            "    if [ $FIRST -eq 1 ]; then cat tgn_events.csv > all_events.csv; FIRST=0\n"
            "    else tail -n +2 tgn_events.csv >> all_events.csv; fi\n"
            "  done\n\n"
            "  # Train on all scenarios:\n"
            "  python3 tgn_train.py all_events.csv --epochs 50 --output tgn_weights.bin\n\n"
            "  # Deploy:\n"
            "  ./waf --run \"scratch/routing --simTime=60 --N_Vehicles=6 \\\n"
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
            f"  Generate training data first:\n"
            f"    bash generate_training_data.sh\n"
            f"  Or manually:\n"
            f"    ./waf --run \"scratch/routing --simTime=60 "
            f"--N_Vehicles=6 --attack_scenario=1\""
        )

    df = pd.read_csv(args.csv)

    # Remove duplicate header rows (artefact when cat-ing multiple CSV files)
    df = df[df["sim_time_s"] != "sim_time_s"].reset_index(drop=True)
    # Coerce numeric columns after string-header removal
    num_cols = ["sim_time_s", "attack_scenario", "physical_sender_id",
                "claimed_sender_id", "link_src_id", "link_dst_id",
                "claimed_ts_s", "recv_time_s", "rx_delay_s",
                "edge_freshness", "beacon_count", "seq_gap", "reporter_count",
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

    print(f"\n[TGN] Complete.  Deploy with (use the SAME simTime/N_Vehicles/mobility_scenario")
    print(f"                 as the data generation runs to avoid train/eval mismatch):")
    print(f"  ./waf --run \"scratch/routing --simTime=<N> --N_Vehicles=<N> \\")
    print(f"               --mobility_scenario=<N> --maxspeed=<N> \\")
    print(f"               --attack_scenario=1 --tgn_weights={args.output} \\")
    print(f"               --tgn_theta={args.theta:.2f} --tgn_l_link={args.l_link}\"")
    if args.dim != 32 or args.layers != 2:
        print(f"  # Also pass: --tgn_dim={args.dim} --tgn_layers={args.layers}")


if __name__ == "__main__":
    main()
