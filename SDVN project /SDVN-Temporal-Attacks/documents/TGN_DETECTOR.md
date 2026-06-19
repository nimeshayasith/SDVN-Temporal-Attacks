# Temporal Graph Neural Network Detector — TETA-Guard Layer 4 (FS Path)

**Files:** `tgn_detector.cc` · `tgn_train.py` · `tgn_compare.py`
**Paper reference:** Section 3.4.3, Eqs. 3.18–3.23, 3.34, Algorithm 2 (FS-DETECT)

---

## Overview

The Full-Stack (FS) detector models the SDVN topology as a sequence of graph snapshots (one per 100 ms beacon interval), using a Temporal Graph Neural Network for anomaly detection. Unlike static GNNs, it explicitly models high-mobility vehicular dynamics where nodes appear and disappear at beacon intervals.

```
routing.cc (RoutingMain)
    │  fills pem_all_events in memory
    ▼
TGN_ApplyCryptoFilter()          ← Algorithm 3, Eqs. 3.14–3.17
    │  drops stale/replay/revoked events
    │  writes crypto_filter_log.txt
    ▼
TGN_ProcessAllEvents()           ← Algorithm 2 FS-DETECT, Eqs. 3.18–3.23
    │  writes tgn_events.csv
    │  writes tgn_detection_log_s{N}.txt
    ▼
TGN_WriteAlertsJson()            ← Eq. 3.36 AlertObject
    │  writes tgn_alerts.json
    ▼
submit_alerts.py → Hyperledger Fabric
```

---

## Architecture

### Graph Snapshot — Eq. 3.18
```
G_t = (V_t, E_t, X_t, A_t)

V_t  — active vehicles and RSUs at time t
E_t  — reported topology links
X_t  ∈ R^(|V_t|×d)  — node feature matrix  (d = 32)
A_t  ∈ R^(|V_t|×|V_t|) — freshness-weighted adjacency matrix
```

### Node Feature Vector — Eq. 3.19
```
x_v = [id_v, τs(v), c^W_v, Δs_v, ρ_v] ∈ R^d
```

| Feature | Meaning | Attack Signal |
|---------|---------|---------------|
| `id_v` | Learnable node identity embedding | — |
| `τs(v)` | Timestamp of last received beacon | Recency |
| `c^W_v` | Beacon count in sliding window W | Low count → BSHH-S3 liveness anomaly |
| `Δs_v` | Sequence number gap between beacons | Non-zero → TTW-S2 inversion |
| `ρ_v` | Reporter count for adjacent links | Inflated → ME-S1 echo injection |

### Freshness-Aware Edge Weighting — Eq. 3.20
```
A_uv(t) = exp(−(τr(t) − τs(uv)) / (γ · T_b))
```
- Fresh reports → weight ~1
- Stale TTW-replayed edges → weight ~0
- γ calibrated so A_uv ≈ 0.5 at L_link/2: `γ = (L_link/2) / (T_b · ln2)` — Eq. 9.3
- Urban default: γ = 310 (L_link = 43 s)
- Highway: γ ≈ 32 (L_link = 4.5 s, recalibrate via `--tgn_l_link=4.5`)

### Temporal Memory Update — Eq. 3.21
```
m_v(t) = GRU(h_v(t⁻), x_v(t), φ(Δt_v))
φ(Δt_v) = log(1 + Δt_v / T_b)
```
- GRU fuses prior embedding, current features, and time-elapsed encoding
- φ amplifies nodes silent for unusually long intervals (BSHH-S3 detection)
- Normal gap (Δt_v = T_b) encodes as log 2 ≈ 0.69

### Neighbourhood Aggregation — Eq. 3.22
```
h_v^(l+1) = σ(W^(l) · MEAN{h_u^(l) ⊙ A_uv(t) : u ∈ N(v,t)} + b^(l))
```
- L = 2 rounds of message passing
- Each neighbour's embedding scaled element-wise by A_uv(t)
- Stale TTW-replayed neighbours contribute proportionally less

### Anomaly Score — Eq. 3.23
```
ŷ_v(t) = σ(w⊤ h_v^(L)(t))    ŷ_v(t) ∈ (0, 1)
```
- Alert raised when `ŷ_v(t) > θ_FS`
- θ_FS selected by maximising MCC on held-out validation data
- Default: `θ_FS = 0.40`

### New Node Initialisation — Eq. 3.34
```
h_{V_new}(t⁻) = 0 ∈ R^d
```
Zero initialisation prevents spurious prior embeddings for newly appeared vehicles.

---

## Mobility-Aware Design (§3.4.7)

Three design decisions motivated by SDVN high-mobility dynamics:

### 1. Sliding Window W_max — Eq. 9.2
```
W_max = ⌈L_link / T_b⌉
```
Default 50 = ⌈5s / 0.1s⌉. Recalibrated at runtime via `--tgn_l_link`.

### 2. Decay Rate γ — Eq. 9.3
```
γ = (L_link / 2) / (T_b · ln2)
```
Ensures A_uv = 0.5 exactly halfway through expected link lifetime — no manual threshold tuning.

### 3. Online Per-Event Mode
Events processed in ascending `reception_timestamp` order, one at a time. **Not** end-of-interval batch. This is necessary because attackers inject mid-interval — a batch model adds up to T_b = 100 ms of blind time before it sees the attack. Online mode ensures GRU memory (Eq. 3.21) and anomaly score (Eq. 3.23) are computed immediately on receipt.

---

## Crypto Pre-Filter Integration (Algorithm 3)

`TGN_ApplyCryptoFilter()` runs before `TGN_ProcessAllEvents()`:

| Condition | Equation | Events Dropped |
|-----------|----------|----------------|
| Timestamp freshness `\|τr−τs\| ≤ 110 ms` | Eq. 3.15 | BSHH replays (old stored heartbeat) |
| Nonce novelty `(reporter,sender,τs)` not seen | Eq. 3.16 | Intra-session duplicates |
| Key revocation after first alert | Eq. 3.17 | Post-detection attacker events |
| Controller-origin bypass (`sender==9999`) | — | Insider events → pass to TGN |

---

## Algorithm 2 — FS-DETECT

Runs at each trusted node (RSU or designated OBU):

1. **Feature extraction** — `EXTRACT_FEATURES` constructs X_t from RSU-local beacon observations only (no controller data)
2. **Crypto pre-filter** — Algorithm 3 applied to event stream
3. **Temporal memory update** — GRU fuses prior embedding, current features, time-elapsed encoding (Eq. 3.21)
4. **L rounds neighbourhood aggregation** — freshness-weighted (Eqs. 3.20, 3.22)
5. **Anomaly scoring** — Eq. 3.23, threshold θ_FS
6. **Alert submission** — directly to Hyperledger Fabric via `SUBMIT_TO_FABRIC`, bypassing controller

---

## How TGN Captures Each Attack

| Attack | TGN Detection Mechanism |
|--------|-------------------------|
| TTW | Stale edges get near-zero A_uv weight; Δs_v encodes sequence inversions; memory gap φ amplified |
| BSHH | Nodes silent during spoofing receive large φ(Δt_v) in memory update; GRU flags anomalous silence |
| ME | ρ_v (reporter count) inflated by echo injection; cross-observer patterns via multi-hop aggregation |

---

## Heuristic Fallback Mode

> **When no `tgn_weights.bin` is provided**, the detector prints a prominent `stderr` warning and falls back to `HeuristicScore()` — a manually-tuned weighted sum. The GRU memory and message-passing equations (3.21–3.22) run but use random Xavier-initialised weights, producing meaningless scores that are overridden by the heuristic readout.

To enable the real TGN:
```bash
# Step 1 — Generate training data (automated)
bash generate_training_data.sh

# Step 2 — Train
python3 tgn_train.py training_data/all_events.csv --epochs 50 --output tgn_weights.bin

# Step 3 — Run with weights
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 \
    --attack_scenario=1 --tgn_weights=tgn_weights.bin"
```

---

## Training (`tgn_train.py`)

**Preferred:** use `generate_training_data.sh` which handles all scenarios and seeds automatically.

```bash
# Automated (recommended)
bash generate_training_data.sh --epochs 50 --output tgn_weights.bin

# Manual — generate training data then train
for SCENARIO in 0 1 2 3 4 5 6 7 8 9 10 11 12; do
    N_RSU=0; case $SCENARIO in 2|4|6|8|10|12) N_RSU=1;; esac
    ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 \
        --N_RSUs=${N_RSU} --attack_scenario=${SCENARIO} --RngRun=1"
    [ "$SCENARIO" -eq 0 ] && cp tgn_events.csv all_events.csv \
                          || tail -n +2 tgn_events.csv >> all_events.csv
done

# Train
python3 tgn_train.py all_events.csv --epochs 50 --output tgn_weights.bin
python3 tgn_train.py all_events.csv --epochs 100 --lr 0.001 --dim 32 --layers 2 --output tgn_weights.bin
```

Training setup:
- 70/15/15 train/validation/test split
- Binary cross-entropy loss with class-weight balancing
- MCC-optimised θ_FS threshold on validation set
- L = 2 message-passing rounds

---

## Baseline Comparison (`tgn_compare.py`)

Compares TGN (FS-DETECT) against three baselines for RQ3:

```bash
python3 tgn_compare.py --scenario 1 --n_runs 5
```

| Baseline | Description | Features |
|----------|-------------|---------|
| LW | Lightweight 9-signature weighted score (Eq. 3.11) | Rule-based |
| Static-GCN | GCN without temporal memory (no GRU) | 7 features |
| DMSTG-AD | LSTM over fixed snapshot window | **7 features** (fair ablation) |
| **Proposed TGN** | Full FS-DETECT with GRU + freshness weighting | 7 features |

**Fair ablation design:** DMSTG-AD was previously given only 4 features (missing `phi` and `c_vW`), disadvantaging it beyond its intended architectural difference. It now uses all 7 features, isolating the contribution of the TGN's GRU temporal memory and freshness-weighted aggregation.

---

## Output Files

| File | Contents |
|------|----------|
| `tgn_events.csv` | Per-event scores: 20 columns including features, PEM scores, TGN score, is_attack |
| `tgn_detection_log_s{N}.txt` | Per-event step-by-step log: feature extraction → GRU → message passing → verdict |
| `tgn_attack{N}.txt` | Human-readable summary for scenario N |
| `tgn_summary.csv` | tp/tn/fp/fn, MCC, AUROC, tdet_ms, precision, recall, θ_FS, dim, layers |
| `tgn_alerts.json` | AlertObject array → `submit_alerts.py` → Fabric SubmitAlert |
| `crypto_filter_log.txt` | Per-event crypto filter decisions (stale/replay/revoked/pass) |

---

## Build and Run

```bash
# Copy to NS-3 scratch directory (Ubuntu VMware)
cp tgn_detector.cc ~/ns-allinone-3.35/ns-3.35/scratch/

# Build
cd ~/ns-allinone-3.35/ns-3.35
./waf build

# Run TGN detector (scenario 1 — TTW-S1)
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"

# Run with pre-trained weights
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1 --tgn_weights=tgn_weights.bin"

# Recalibrate for highway mobility (L_link ≈ 4.5 s)
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1 --tgn_l_link=4.5"

# Baseline: no attack
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=0"
```

### Runtime Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `--tgn_l_link` | 43.0 | Link lifetime (s) for γ and W_max calibration |
| `--tgn_theta` | 0.40 | Anomaly threshold θ_FS |
| `--tgn_weights` | — | Path to pre-trained weights binary |
| `--simTime` | 240 | Simulation duration (s) |
| `--N_Vehicles` | 80 | Number of vehicle nodes |
| `--N_RSUs` | 0 | Number of RSU nodes |
| `--attack_scenario` | 0 | 0=baseline, 1–12=attack variants |
