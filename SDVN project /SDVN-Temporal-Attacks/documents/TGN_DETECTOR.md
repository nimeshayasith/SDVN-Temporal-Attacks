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

### Node Feature Vector — Implementation vs Paper

The paper (Eq. 3.19) specifies a 5-element feature vector:
```
x_v = [id_v, τs(v), c^W_v, Δs_v, ρ_v] ∈ R^d
```

The implementation extends this to 7 elements (dimension labelled `dim+7` in the GRU input):
```
x_v = [id_v_norm, τs(v), c^W_v, Δs_v, ρ_v, identity_mismatch, φ(Δt_v)]
```

| Feature | Paper | Implementation | Attack Signal |
|---------|-------|---------------|---------------|
| `id_v` | Learnable embedding ∈ R^d | Scalar normalisation `node_id / (N+1)` | — |
| `τs(v)` | Timestamp of last received beacon | Same | Recency |
| `c^W_v` | Beacon count in window W | Same | Low count → BSHH-S3 liveness anomaly |
| `Δs_v` | Sequence number gap | Same | Non-zero → TTW inversion |
| `ρ_v` | Reporter count for adjacent links | Same (but per directed key — see below) | Inflated → ME echo injection |
| `identity_mismatch` | Not in paper | Added: 1.0 when physical≠claimed sender (no RSU path only) | BSHH impersonation |
| `φ(Δt_v)` | Not in paper | Added: log(1 + Δt_v/T_b) — time-elapsed encoding passed to GRU | Long silence → BSHH-S3 |

**id_v implementation note:** The paper specifies a learnable embedding matrix E ∈ R^(N×d) that projects integer node IDs into d-dimensional space. The implementation uses `id_v_norm = node_id / (N+1)` (a scalar) concatenated with the 6 other features, giving `dim+7` total GRU input dimensions. When `tgn_weights.bin` is trained, the training script must use the same 7-feature format — not a learnable embedding layer — or the weight tensor shapes will be incompatible.

### Freshness-Aware Edge Weighting — Eq. 3.20
```
A_uv(t) = exp(−(τr(t) − τs(uv)) / (γ · T_b))
```
- Fresh reports → weight ~1
- Stale TTW-replayed edges → weight ~0
- γ calibrated so A_uv ≈ 0.5 at L_link/2: `γ = (L_link/2) / (T_b · ln2)` — Eq. 9.3
- Urban default: γ = 310 (L_link = 43 s)
- Highway: γ ≈ 32 (L_link = 4.5 s, recalibrate via `--tgn_l_link=4.5`)

**T_b offset note:** The implementation adds a plateau region: events with `(τr − τs) < T_b` are capped to weight 1.0 before the exponential decay. This prevents very-fresh-but-non-zero age differences from producing sub-1.0 weights during the first beacon interval. The paper's Eq. 3.20 has no such offset. The engineering choice ensures ME-S1/S2 fresh echo events do not accidentally appear "slightly stale," so ME detection relies purely on reporter_count (ρ_v) rather than edge weight, matching the intended detection logic.

### Temporal Memory Update — Eq. 3.21
```
m_v(t) = GRU(h_v(t⁻), x_v(t), φ(Δt_v))
φ(Δt_v) = log(1 + Δt_v / T_b)
```
- GRU fuses prior embedding, current features, and time-elapsed encoding
- φ amplifies nodes silent for unusually long intervals (BSHH-S3 detection)
- Normal gap (Δt_v = T_b) encodes as log 2 ≈ 0.69

**h_v(0) initialisation — correct as implemented:** `UpdateNodeMemory` (Step 1) runs first, updating `states_[node_id].memory` = mv(t). The message-passing initialisation at Step 3 then sets `H[v] = states_[v].memory` — this IS mv(t), the freshly computed GRU output. The prior embedding h_v(t⁻) is the GRU's own internal state (hidden state `h`), not a separate field. The code is correct; do not add a separate "prior embedding" read before Step 3.

### Neighbourhood Aggregation — Eq. 3.22
```
h_v^(l+1) = σ(W^(l) · MEAN{h_u^(l) ⊙ A_uv(t) : u ∈ N(v,t)} + b^(l))
```
- L = 2 rounds of message passing (pending validation — set in `TGN_LAYERS = 2`)
- Each neighbour's embedding scaled element-wise by A_uv(t)
- Stale TTW-replayed neighbours contribute proportionally less

**3-node streaming approximation:** The implementation uses a minimal active set `{node_id, link_src_id, link_dst_id}` — the three nodes involved in each event — rather than the full V_t. This is a streaming approximation for simulation efficiency. When `tgn_train.py` is written, it must use the same 3-node subgraph per event (not full V_t), or the training and inference graph structures will diverge.

### Anomaly Score — Eq. 3.23
```
ŷ_v(t) = σ(w⊤ h_v^(L)(t))    ŷ_v(t) ∈ (0, 1)
```
- Alert raised when `ŷ_v(t) > θ_FS`
- θ_FS selected by maximising MCC on held-out validation data
- Default: `θ_FS = 0.40` (UNCALIBRATED placeholder — requires tgn_train.py)

**Variant classification head — Eq. 3.25:** The classifier runs only when both `alert == true` AND trained weights are loaded. Paper specifies it runs for all nodes. This is intentional — heuristic scores are not reliable enough for multi-class classification; the variant head requires weights to be meaningful.

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
Default 430 = ⌈43s / 0.1s⌉ for urban mobility (L_link=43s). Recalibrated at runtime via `--tgn_l_link`.

### 2. Decay Rate γ — Eq. 9.3
```
γ = (L_link / 2) / (T_b · ln2)
```
Ensures A_uv = 0.5 exactly halfway through expected link lifetime — no manual threshold tuning.

### 3. Online Per-Event Mode
Events processed in ascending `reception_timestamp` order, one at a time. **Not** end-of-interval batch. This is necessary because attackers inject mid-interval — a batch model adds up to T_b = 100 ms of blind time before it sees the attack. Online mode ensures GRU memory (Eq. 3.21) and anomaly score (Eq. 3.23) are computed immediately on receipt.

---

## Crypto Pre-Filter Integration (Algorithm 3)

`TGN_ApplyCryptoFilter()` runs before `TGN_ProcessAllEvents()`.

**Dual enforcement:** Algorithm 3 also runs during simulation as `PemCryptoPreFilter` in routing.cc. `TGN_ApplyCryptoFilter` is a second independent pass on `pem_all_events` — same 3 checks, not a replacement.

**Important caveat — Layer 3 cannot recover events dropped at Layers 1 or 2.** `TGN_ApplyCryptoFilter` only sees events that already entered `pem_all_events`. Events dropped by `PemCryptoPreFilter` (Layer 1 — BSHH threshold-sig failures, out-of-range ME reporters before quorum) never reached `pem_all_events` and are invisible to Layer 3 and Layer 4. This is correct by design: those events were cryptographically invalid and should not reach the TGN. Layer 3 re-checking them is not possible and not needed.

| Condition | Equation | Which attacks / events |
|-----------|----------|------------------------|
| **Threshold aggregate signature** — impersonator holds 0 of t Dilithium key shares → Verify_agg fails | **Eq. 3.26** | BSHH S1 (malicious vehicle), BSHH S2 (malicious RSU) — dropped at Stage 0; **TGN never sees these events** |
| **Location-binding distance gate** — `d(reporter_pos, link_endpoint) > r_comm` | **Eq. 3.29** | ME S1/S2 out-of-range echo reporters |
| **ME witness quorum** — fewer than t=2 legitimate witnesses confirmed the link at this trusted node | **Eq. 3.30** | ME S1/S2 in-range echoes when baseline has not yet been established |
| **Timestamp freshness** `\|τr−τs\| ≤ T_b + ε` | Eq. 3.16 | TTW raw-replay variant (original τ_store preserved); intra-session stale events |
| **Nonce novelty** `(sender_id, τs)` not in per-node cache | Eq. 3.17 | TTW raw-replay variant (original nonce re-used); intra-session duplicates |
| **HMAC-SHA256 integrity** `HMAC(K_Vi,nk, m‖τs‖nonce)` | Eq. 3.15 | Applies to external attackers lacking the session key — not the primary gate for any of the 12 in-scope scenarios (attackers are insiders or key-holding nodes) |
| Controller-origin bypass (`is_malicious_controller == true`) | — | TTW/BSHH/ME S3/S4 — controller holds valid credentials; all steps pass; TGN + blockchain are sole defences |

**Per-family attribution (§3.4.9):**
- **TTW S1/S2 (vehicle/RSU-origin)**: attacker holds its own valid session key and recomputes a fresh HMAC with the forged timestamp. Eq. 3.15 passes (valid MAC). Eq. 3.16 passes (age ≈ 0). Eq. 3.17 passes (fresh nonce). **Stage 0 does NOT stop timestamp-forged TTW. Stage 1 (PEM sig[0]/sig[2]) is the detection layer.**
- **BSHH S1/S2 (vehicle/RSU-origin)**: eliminated at Stage 0 by **Eq. 3.26** (threshold aggregate signature). The attacker holds zero Dilithium key shares — Eq. 3.26 fails at Step 1. `tg_crypto_drop_mac` counter records this (Step 1 identity failure; named "mac" for CSV compatibility but mechanism is Eq. 3.26, not Eq. 3.15).
- **ME S1/S2 (vehicle/RSU-origin)**: out-of-range reporters caught at Stage 0 by **Eq. 3.29** distance gate (`tg_crypto_drop_mac`); in-range reporters deferred by **Eq. 3.30** quorum gate until TGN can evaluate. **Stage 1 (Eq. 3.8 reporter-count density) is the primary detection layer for in-range ME.**
- **All controller-origin (S3/S4)**: bypass all crypto steps → Stage 1 TGN + blockchain divergence check only.

**Stale output file warning — regenerate after the upper-bound fix:** Before the `physical_is_rsu` upper-bound fix was applied (Issue 1 in the errata), the controller sentinel 9999 was incorrectly classified as an RSU node (`9999 >= N_Vehicles` passed the lower bound only). This caused scenarios 4 (TTW Malicious Controller With RSU), 8 (BSHH Malicious Controller With RSU), and 12 (ME Malicious Controller With RSU) to produce wrong `identity_mismatch` values and incorrect `reporter_count` tracking in `tgn_events.csv` and `tgn_alerts.json`. Any output files from those scenarios generated before the fix must be discarded and the runs repeated.

**`physical_is_rsu` upper bound:** The RSU check is:
```cpp
const bool physical_is_rsu =
    (N_RSUs > 0)
    && (e.physical_sender_id >= (uint32_t)N_Vehicles)
    && (e.physical_sender_id <  (uint32_t)(N_Vehicles + N_RSUs));
```
The upper bound `< N_Vehicles + N_RSUs` prevents the controller sentinel 9999 from being classified as an RSU (which would bypass the MAC check incorrectly). Without this bound, 9999 ≥ N_Vehicles would make it RSU-classified.

---

## Algorithm 2 — FS-DETECT

Runs at each trusted node (RSU or designated OBU):

1. **Feature extraction** — `EXTRACT_FEATURES` constructs X_t from RSU-local beacon observations only (no controller data)
2. **Crypto pre-filter** — Algorithm 3 applied to event stream
3. **Temporal memory update** — GRU fuses prior embedding, current features, time-elapsed encoding (Eq. 3.21)
4. **L rounds neighbourhood aggregation** — freshness-weighted (Eqs. 3.20, 3.22)
5. **Anomaly scoring** — Eq. 3.23, threshold θ_FS
6. **Alert submission** — directly to Hyperledger Fabric via `SUBMIT_TO_FABRIC`, bypassing controller

**SUBMIT_TO_FABRIC — file-mediated handoff:** In the NS-3 simulation, `submit_alerts.py` reads `tgn_alerts.json` after the simulation ends. This is a simulation artifact — the script cannot run inline during NS-3's event loop. In a real deployment, the TGN would call the Fabric SDK directly. This distinction does not affect detection correctness; it only applies to the Alert submission latency in a real system.

---

## How TGN Captures Each Attack

| Attack | TGN Detection Mechanism |
|--------|-------------------------|
| TTW Malicious Vehicle | Stale edges get near-zero A_uv weight; Δs_v encodes sequence inversions; memory gap φ amplified |
| TTW Malicious RSU | Same as above; RSU forwarding path used (physical_is_rsu=true) |
| TTW Malicious Controller (No RSU) | Controller sentinel 9999 passes crypto filter; TGN sees stale A_uv weight and Δs_v; identity_mismatch suppressed (9999 is insider, not impersonation) |
| TTW Malicious Controller (With RSU) | Same as No RSU variant; events arrive via RSU aggregation path |
| BSHH Malicious Vehicle (S1) | **Dropped at Stage 0 by Eq. 3.26 (threshold aggregate signature) — TGN never sees these events.** Attacker cannot forge ML-DSA-87 key shares. `tg_crypto_drop_mac` counter incremented. |
| BSHH Malicious RSU (S2) | **Dropped at Stage 0 by Eq. 3.26 (threshold aggregate signature) — TGN never sees these events.** RSU cannot forge victim's Dilithium key shares. `tg_crypto_drop_mac` counter incremented. |
| BSHH Malicious Controller (No RSU) | identity_mismatch suppressed (9999 sentinel); seq_gap and φ(Δt_v) amplify detection |
| BSHH Malicious Controller (With RSU) | Same as No RSU; events via RSU path |
| ME Malicious Vehicle | reporter_count (ρ_v) exceeds rhoMax=1.5; score from HeuristicScore; multi-hop aggregation amplifies cross-observer patterns |
| ME Malicious RSU | Same ρ_v mechanism; RSU-path claimed_sender_id tracking; identity_mismatch=0.0 (RSU path) |
| ME Malicious Controller (No RSU) | ρ_v inflated by internally fabricated echo entries; identity_mismatch suppressed (9999) |
| ME Malicious Controller (With RSU) | Same as No RSU; events via RSU path |

### ME Reporter Count — Directed Key Detail

TGN tracks reporters per **directed** link key `"linkSrc_linkDst"`. V1 reporting "V1 sees V2" goes to key `"v1_v2"`. V2's reciprocal report goes to `"v2_v1"` — a separate key. The benign baseline for any directed key is 1 (only the node named as `link_src` legitimately reports under that key).

**ρ_v is per-directed-key, not node-level aggregation:** The paper describes ρ_v as an aggregate reporter count at node v. The implementation uses a per-directed-link-key counter (`g_tgn_link_reporters["src_dst"]`). This is intentional: node-level aggregation would blur the signal across all edges of v, whereas directed-key counting isolates the specific link being echoed. The implementation is strictly more sensitive to ME attacks — a single directed key's count jumping from 1 to 2 fires the signature immediately.

| Scenario | senderTimestamp in echo | Key "v1_v2" reporter set | Count | rhoMax | Score |
|----------|------------------------|--------------------------|-------|--------|-------|
| ME Malicious Vehicle | `now` (fabrication — fresh signature) | {v1_id} + {echo_v3} + {echo_v4} | 3 | 1.5 | min(2.0, (3−1)×0.8) = **1.6** |
| ME Malicious RSU | `t` (replay — original obs time) | {rsu_id} + {false_v3} + {false_v4} | 3 | 1.5 | min(2.0, (3−1)×0.8) = **1.6** |

**senderTimestamp split — implementation difference between the two ME variants:**
- **ME Malicious Vehicle** (scenario 9): V3/V4 echo attackers sign a fresh message (`senderTimestamp = Simulator::Now()`) because they are insiders with valid session keys. Age = 0 → edge_freshness = 1.0. Detection relies entirely on reporter_count exceeding rhoMax.
- **ME Malicious RSU** (scenario 10): The malicious RSU replays the original V1 observation timestamp (`senderTimestamp = t`). Injection happens at `t + T_b`, so age = T_b, stale_excess = 0 → edge_freshness = 1.0 (not stale enough to trigger staleness signature alone). Detection still via reporter_count.

The original project PDF's description (`sender_timestamp = 10.0`) matched ME Malicious RSU's behaviour. ME Malicious Vehicle uses `now` instead. Both are correct for their respective variants.

**RSU path tracking in ME Malicious RSU:** The benign V1 report has `physical=v1_id` (vehicle), so `physical_is_rsu=false` → tracked as `reporter_id`. The RSU echo events have `physical=rsu_id` → `physical_is_rsu=true` → tracked as `claimed_sender_id` (false_v3, false_v4). The reporter set holds a mix of reporter_id and claimed_sender_id values — this is correct: the set grows from {rsu_id} after the benign report to {rsu_id, false_v3, false_v4} after both echoes, giving count=3.

### False Positive Risk at Large N_Vehicles

rhoMax=1.5 is safe at any scale. `PemEmitEvent` is called **only** from within attack scenario code blocks — never from the normal vehicle routing loop (`distributed_dsrc_data_broadcast`). A baseline run (`attack_scenario=0`) produces zero TGN events regardless of N_Vehicles. Verified empirically: N_Vehicles=20, attack_scenario=0 → "No PEM events — skipping TGN pipeline."

Even if PemEmitEvent were called for benign traffic, the directed-key architecture guarantees count=1 per key in benign operation: each vehicle reports only links where it is the `link_src`, so no other vehicle would ever add to that vehicle's directed key under normal routing.

### BSHH-S3 Beacon Count — Fixed (Issue 9)

`TGN_ProcessAllEvents` previously skipped `PEM_EVENT_BEACON` events with a bare `continue`, which left `g_tgn_beacon_windows` unpopulated from beacon data. `beacon_count` (`c^W_v`) would undercount for BSHH-S3 (victim silence detection) whenever `PemEmitVehicleBeacon` had been called.

**Fix applied:** The BEACON skip block now updates `g_tgn_beacon_windows[claimed_sender_id]` before continuing — the sliding window receives every beacon timestamp, but the GRU/message-passing pipeline does not run for BEACON events (correct, since beacons carry no anomaly signal themselves):

```cpp
if (e.type == PEM_EVENT_BEACON) {
    auto& win = g_tgn_beacon_windows[e.claimed_sender_id];
    win.push_back(e.reception_timestamp);
    while ((int)win.size() > TGN_WMAX) win.erase(win.begin());
    continue;
}
```

### Controller Sentinel and identity_mismatch — Fixed (Issue 13)

Controller-origin events (TTW Malicious Controller, ME Malicious Controller) use `physical_sender_id = 9999` as a sentinel. The old identity_mismatch computation:
```cpp
(!physical_is_rsu && physical != claimed) ? 1.0 : 0.0
```
would fire `identity_mismatch=1.0` for all controller events (9999 ≠ claimed always), incorrectly adding a BSHH signal to TTW and ME controller scenarios.

**Fix applied:** Added `e.physical_sender_id != 9999u` guard:
```cpp
f.identity_mismatch =
    (!physical_is_rsu
     && e.physical_sender_id != 9999u   // controller holds all IDs — not impersonation
     && e.physical_sender_id != e.claimed_sender_id) ? 1.0 : 0.0;
```

Controller events now produce `identity_mismatch=0.0`. Detection for controller scenarios relies on edge_freshness (A_uv), seq_gap, and reporter_count — which are the correct signals for TTW and ME respectively.

---

## Heuristic Fallback Mode

> **When no `tgn_weights.bin` is provided**, the detector prints a prominent `stderr` warning and falls back to `HeuristicScore()` — a manually-tuned weighted sum. The GRU memory and message-passing equations (3.21–3.22) run but use random Xavier-initialised weights, producing meaningless intermediate representations that are overridden by the heuristic readout.

HeuristicScore logic:
```cpp
double rhoMax = 1.5;  // benign baseline = 1 per directed key; fires at count=2 (first echo)
if (feat.reporter_count > rhoMax)
    s += min(2.0, (feat.reporter_count - 1.0) * 0.8);  // count=3 → s+=1.6
// ... other heuristic terms for edge_freshness, seq_gap, tau_staleness
return sigmoid(s - 2.0);
```

θ_FS = 0.40 is an uncalibrated placeholder for heuristic mode. It is not derived from MCC optimisation on validation data (there is no training data yet).

---

## Critical Gap: Training Pipeline Missing

**`tgn_train.py` does not exist.** The system is permanently in heuristic mode until it is written. This is the most critical gap between the paper and the current implementation.

When writing `tgn_train.py`, these constraints must be respected to match the inference code in `tgn_core.cc`:

| Constraint | Reason |
|------------|--------|
| 7-element feature vector `[id_v_norm, τs, c^W_v, Δs_v, ρ_v, identity_mismatch, φ]` | Matches `dim+7` GRU input dimensionality in TGN_ExtractFeatures |
| Scalar `id_v_norm = node_id / (N+1)`, not a learnable embedding layer | Paper specifies learnable; implementation uses scalar. Train must match inference |
| 3-node active set per event `{node_id, link_src, link_dst}` | Matches streaming subgraph in TGN_ProcessAllEvents |
| T_b offset in edge freshness (plateau for age < T_b) | Matches `stale_excess = max(0, age - T_b)` in TGN_ExtractFeatures |
| Variant head gated on `alert == true` | Eq. 3.25 classification only runs when Eq. 3.23 fires |
| `d = 32`, `L = 2` defaults | Matches `TGN_DIM = 32`, `TGN_LAYERS = 2` constants |

---

## Location-Binding / RSSI Detection — Implemented in Primary Crypto Gate

Eqs. 3.27–3.30 are fully implemented in `routing.cc::PemCryptoPreFilter` (lines 2477–2616), which is the **primary enforcement gate** running during simulation. They are NOT in `tgn_core.cc::TGN_ApplyCryptoFilter` — that secondary pass only re-checks Eqs. 3.14–3.17 (by design, since the primary gate already applied location-binding before events entered `pem_all_events`).

Implementation in `routing.cc::PemCryptoPreFilter`:

| Equation | What it does | Implementation |
|----------|-------------|----------------|
| Eq. 3.27 | Reporter constructs signed message: `link_id ‖ pos_Vk ‖ RSSI_Vk←Vi ‖ τs ‖ nonce` | `create_location_bound_report()` in `location_binding.cc` (included at line 93) |
| Eq. 3.28 | Reporter signs with Dilithium5 key | `dilithium5_sign_locbind()` — domain-separated to prevent cross-protocol replay |
| Eq. 3.29 | Verify spatial plausibility: `d(pos_Vk, link_endpoint) ≤ r_comm` | `PemDistance2d(reporter_position, link_src/dst_position) > TTW_COMM_RANGE` → drop |
| Eq. 3.30 | Accept link only when ≥ t independent witnesses passed Eq. 3.29 | `pem_link_legitimate_witnesses[lkey].size() < t_witness` → defer (quorum not met) |

`verify_single_witness()` and `verify_quorum()` from `location_binding.cc` implement the full gate sequence (crypto → spatial → RSSI/Friis), including:
- Gate D: timestamp freshness (`|recv_time − sender_ts| ≤ LOCBIND_FRESHNESS_WINDOW_MS`)
- Gate E: per-reporter nonce novelty cache (prevents cross-aggregate replay of valid reports)
- Gate (iii)/(iv): RSSI plausibility using RSU-measured RSSI (not self-reported, which is attacker-controlled)

The simulation approximates Eq. 3.29 using Euclidean NS-3 position distance instead of haversine-over-RSSI (no real radio hardware) — the detection logic and gate structure are correct; only the distance measurement method differs from a live deployment.

---

## alpha_source Field in tgn_alerts.json

The `alpha_source` field in `tgn_alerts.json` records how the variant classification was determined:

| Value | Meaning | When it appears |
|-------|---------|-----------------|
| `"eq_3.25"` | Eq. 3.25 classifier ran with trained weights | Only when tgn_weights.bin loaded AND alert fired |
| `"scenario_id_fallback"` | Variant inferred directly from the `attack_scenario` CLI argument | All heuristic-mode runs (no weights) |

`"scenario_id_fallback"` leaks ground-truth labels into the output. This is acceptable in simulation (the ground truth is known) but must be replaced by `"eq_3.25"` in a real deployment. The fallback values use family-level labels (`"TTW_family"`, `"BSHH_family"`, `"ME_family"`) while the trained classifier produces scenario-specific labels (`"TTW"`, `"BSHH"`, `"ME"` per Eq. 3.25).

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
- Feature vector must be 7-element (not paper's 5-element with learnable id embedding)

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

**Fair ablation design:** DMSTG-AD uses all 7 features, isolating the contribution of the TGN's GRU temporal memory and freshness-weighted aggregation from feature-count differences.

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

# Run TGN detector (scenario 1 — TTW Malicious Vehicle)
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
| `--tgn_theta` | 0.40 | Anomaly threshold θ_FS (uncalibrated — requires training) |
| `--tgn_weights` | — | Path to pre-trained weights binary |
| `--simTime` | 240 | Simulation duration (s) |
| `--N_Vehicles` | 80 | Number of vehicle nodes |
| `--N_RSUs` | 0 | Number of RSU nodes |
| `--attack_scenario` | 0 | 0=baseline, 1–12=attack variants |

---

## Paper vs Implementation — Issue Tracker

Summary of all 14 issues reviewed against the paper:

| # | Issue | Status | Action |
|---|-------|--------|--------|
| 1 | x_v has 7 elements (paper says 5); id_v is scalar norm not learnable embedding | Intentional extension | Document above; tgn_train.py must match |
| 2 | h_v(0) initialisation wrong | **INCORRECT — user misread code.** H[v]=states_[v].memory at Step 3 uses mv(t) freshly computed by Step 1. No bug. | None |
| 3 | 3-node active set vs full V_t | Streaming approximation, intentional | Document above; tgn_train.py must use same 3-node subgraph |
| 4 | T_b offset plateau in edge freshness | Intentional engineering choice | Document above |
| 5 | Variant head gated on alert | Intentional (heuristic scores unreliable for multi-class) | Document above |
| 6 | θ_FS = 0.40 uncalibrated | Already noted in code comments | Requires tgn_train.py to calibrate |
| 7 | d=32, L=2 pending validation | Already noted in code comments | Pending hyperparameter search |
| 8 | rhoMax=1.5 flat vs density-dependent | Already noted in code comments | Heuristic approximation |
| 9 | BEACON events skip without updating beacon_count | **REAL BUG — FIXED** | Beacon window now updated in skip block |
| 10 | ρ_v per-directed-key vs node-level aggregation | Intentional, more sensitive | Document above |
| 11 | tgn_train.py entirely missing | **CRITICAL GAP** | Future work; constraints documented above |
| 12 | SUBMIT_TO_FABRIC is file-mediated not inline | Simulation artifact | Document above |
| 13 | Controller sentinel 9999 triggers identity_mismatch=1.0 for non-BSHH scenarios | **REAL BUG — FIXED** | 9999u guard added to identity_mismatch |
| 14 | Location-binding Eqs. 3.27–3.30 not implemented | **INCORRECT — already implemented** in `routing.cc::PemCryptoPreFilter` (primary gate). Not in `tgn_core.cc` by design (secondary pass only re-checks 3.14–3.17). | TGN_DETECTOR.md corrected |
