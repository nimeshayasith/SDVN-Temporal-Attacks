# TGN Implementation Guide
## Temporal Graph Network for Temporal-Echo Attack Detection in SDVNs

**Project:** TGN and Blockchain-Based Framework — Countering Temporal-Echo Topology Poisoning Attacks in SDVNs  
**Paper sections:** §3.4.3, Algorithm 2 (FS-DETECT), Algorithm 3 (LW-MITIGATE)  
**Key equations:** Eqs 3.15–3.17, 3.20–3.25, 3.32, 3.36

---

## Table of Contents

1. [What is a TGN and Why Do We Need One?](#1-what-is-a-tgn-and-why-do-we-need-one)
2. [Where TGN Fits in the 5-Layer Pipeline](#2-where-tgn-fits-in-the-5-layer-pipeline)
3. [File Map — Everything TGN Touches](#3-file-map--everything-tgn-touches)
4. [Layer 3: Secondary Crypto Gate (TGN_ApplyCryptoFilter)](#4-layer-3-secondary-crypto-gate-tgn_applycryptofilter)
5. [Layer 4: TGN Inference — Algorithm 2 (FS-DETECT)](#5-layer-4-tgn-inference--algorithm-2-fs-detect)
6. [Global State Maps — The Memory Outside the GRU](#6-global-state-maps--the-memory-outside-the-gru)
7. [Feature Extraction (Eq 3.20 + identity_mismatch)](#7-feature-extraction-eq-320--identity_mismatch)
8. [Step 1: GRU Memory Update (Eq 3.22)](#8-step-1-gru-memory-update-eq-322)
9. [Step 2: Edge Freshness Weight (Eq 3.21)](#9-step-2-edge-freshness-weight-eq-321)
10. [Step 3: Neighborhood Aggregation (Eq 3.23)](#10-step-3-neighborhood-aggregation-eq-323)
11. [Step 4: Anomaly Score — Trained vs Heuristic (Eq 3.24)](#11-step-4-anomaly-score--trained-vs-heuristic-eq-324)
12. [Step 5: Variant Classification (Eq 3.25)](#12-step-5-variant-classification-eq-325)
13. [alpha_source — Classifier Output vs Ground Truth Fallback](#13-alpha_source--classifier-output-vs-ground-truth-fallback)
14. [TGN_RunPipeline() — The Complete Sequence](#14-tgn_runpipeline--the-complete-sequence)
15. [Output Files Reference](#15-output-files-reference)
16. [Command-Line Parameters](#16-command-line-parameters)
17. [Constants, Calibration, and Their Derivations](#17-constants-calibration-and-their-derivations)
18. [What Each Attack Family Looks Like to TGN](#18-what-each-attack-family-looks-like-to-tgn)
19. [RSU vs No-RSU: How Feature Extraction Differs](#19-rsu-vs-no-rsu-how-feature-extraction-differs)
20. [Training Pipeline — tgn_train.py](#20-training-pipeline--tgn_trainpy)
21. [Binary Weight File Format](#21-binary-weight-file-format)
22. [End-to-End Workflow: From Simulation to Trained Detector](#22-end-to-end-workflow-from-simulation-to-trained-detector)
23. [Reading and Interpreting the Output Files](#23-reading-and-interpreting-the-output-files)
24. [Common Issues and Fixes](#24-common-issues-and-fixes)

---

## 1. What is a TGN and Why Do We Need One?

### The problem the LW detector cannot solve

The 9-signature LW (Lightweight) detector (Layer 2) catches attacks with clear structural signatures — for example, a heartbeat arriving with a mismatched sender identity (BSHH-S1) or a topology report from more than one unexpected reporter (ME-S1). But two attack families partially evade it:

- **TTW (Topology Time-Warp):** The attacker is a legitimate key-holder (a real vehicle or RSU that has gone malicious). It re-signs the forged packet with its own valid key and sets the timestamp to "now". The packet passes all three crypto checks (MAC valid, timestamp fresh, nonce new) and arrives at the controller looking completely legitimate. The only signal is temporal: the link being reported has been physically dead since t=15, but the controller's table entry keeps getting refreshed as if the link were still alive.

- **Controller-origin attacks (S3/S4/S7/S8/S11/S12):** The malicious controller uses `physical_sender_id = 9999` as a sentinel. The crypto filter explicitly bypasses all three checks for this sentinel (the controller holds all keys, generates valid MACs, fresh timestamps, and novel nonces). The sole defence against controller-origin attacks is the TGN.

A graph neural network is the right tool because attacks manifest as *patterns across time and topology*, not as single-packet anomalies. The TGN keeps a per-node memory of everything it has seen, weights recent observations by how fresh the underlying link is, and propagates information across neighbouring nodes. It can learn: "V0 has been reporting that it sees V1 every 100ms for the last 10 seconds, but V1's beacon window shows V1 hasn't appeared in 15 seconds — this link is temporally inconsistent."

### Why "Temporal" GNN specifically

Standard GNNs treat graphs as static snapshots. A vehicular network changes every 100ms (IEEE 802.11p beacon interval). The **Temporal GNN** adds:

1. A **GRU (Gated Recurrent Unit)** that maintains a per-node memory vector updated every time a new event involving that node arrives. The memory captures the node's history.
2. An **edge freshness weight** that decays exponentially with how stale the reported link observation is.
3. **Sequential processing** in reception-time order, so the model builds up temporal context before scoring each event.

This combination — temporal memory + fresh-weighted graph structure — is what allows the TGN to detect link-lifetime violations that no single-event rule can catch.

---

## 2. Where TGN Fits in the 5-Layer Pipeline

> **⚠ This section (and §5, §6, §14 below) describe the batch-replay path
> (`TGN_ProcessAllEvents`), which runs post-simulation after
> `Simulator::Destroy()`. That is NOT the path that actually executes.**
> `routing.cc` calls `TGN_Init()` before `Simulator::Run()`, which sets
> `g_tgn_online_mode = true`. From that point on, every PEM event is scored
> immediately by `TGN_ProcessEventInline()` (tgn_core.cc §11a) as it's
> recorded — during the simulation, not after it. `TGN_RunPipeline()` still
> runs after `Simulator::Destroy()`, but when `g_tgn_online_mode` is true it
> detects that events were already processed inline and skips
> re-initialisation/re-processing — it only runs the (now-passthrough, see
> §4 note below) secondary crypto audit and writes the output files. The
> diagram and step sequence below are still useful as a description of the
> algorithm's *logic* (feature extraction → GRU → message passing → score),
> but read "runs once per event as it arrives" wherever this section says
> "runs once, post-simulation, over the full batch."

```
LAYER 1 — CRYPTO PRE-FILTER  (routing.cc::PemCryptoPreFilter)
           Runs DURING simulation for every event.
           Drops events that fail MAC/freshness/nonce checks.
           → pem_event_log.csv, pem_run_summary.csv, crypto_drop_log.csv
           │
           ▼  (surviving events accumulated in pem_all_events[])
LAYER 2 — LW DETECTOR  (routing.cc::PemEvaluateEvent)
           9-signature weighted scoring (Eqs 3.12-3.14).
           → pem_event_log.csv, pem_run_summary.csv
           │
           ▼  (Simulator::Destroy() — simulation ends)
           ▼  (TGN_RunPipeline() called — post-simulation batch)
LAYER 3 — SECONDARY CRYPTO GATE  (.tgn_src/tgn_core.cc::TGN_ApplyCryptoFilter)
           Re-applies Eqs 3.15-3.17 on pem_all_events[].
           Removes events the trained TGN should never see.
           → crypto_filter_log.txt
           │
           ▼  (filtered[] passed to TGN_ProcessAllEvents)
LAYER 4 — TGN INFERENCE  (.tgn_src/tgn_core.cc::TGN_ProcessAllEvents)
           Algorithm 2 (FS-DETECT): GRU + message passing + anomaly score.
           → tgn_events.csv, tgn_alerts.json, tgn_detection_log_s{N}.txt,
             tgn_attack{N}.txt, tgn_summary.csv
           │
           ▼  (tgn_alerts.json written to disk)
LAYER 5 — BLOCKCHAIN  (Hyperledger Fabric — SEPARATE process)
           submit_alerts.py reads tgn_alerts.json → Fabric smart contract.
           Not compiled into routing.cc.
```

**Key architectural fact:** Layers 3 and 4 are both inside `.tgn_src/tgn_core.cc`, which is `#include`d into `routing.cc` at line 1389. Layer 1 runs during simulation. **Layer 4 (TGN inference) also runs during simulation now**, via the online/inline path described in the warning above — only Layer 3 (the crypto audit) and output-file writing still happen after `Simulator::Destroy()`.

---

## 3. File Map — Everything TGN Touches

| File | Role |
|------|------|
| `.tgn_src/tgn_core.cc` | C++ implementation — Layers 3 and 4. Included at routing.cc line 1389. |
| `tgn/tgn_train.py` | PyTorch training script. Reads `tgn_events.csv`, exports `tgn_weights.bin`. |
| `tgn/tgn_weights.bin` | Binary weight checkpoint (72K, float64, row-major). Loaded at runtime. |
| `tgn/tgn_compare.py` | Comparison detector evaluation (baseline comparisons). |
| `tgn/deploy_to_ns3.sh` | Deployment helper — copies files, builds, runs, copies results back. |
| `generate_training_data.sh` | Runs all 12 attack scenarios × N seeds, concatenates `tgn_events.csv`. |
| `routing.cc` | Main simulation file. Declares `pem_all_events[]`, includes tgn_core.cc, calls `TGN_RunPipeline()` at line 148799. |
| **Output files** | See [Section 15](#15-output-files-reference). |

### Integration points in routing.cc

| Line | What happens |
|------|-------------|
| 1378 | `pem_all_events[]` vector declared (feeds Layer 3 and 4) |
| 1389 | `#include ".tgn_src/tgn_core.cc"` |
| 1596 | `PemEmitEvent()` forward declaration |
| 2673 | `PemEmitEvent()` full definition |
| 2709 | `PemCryptoPreFilter()` called inside `PemEmitEvent()` (Layer 1) |
| 144694–144710 | `--tgn_weights`, `--tgn_theta`, `--tgn_l_link`, `--tgn_dim`, `--tgn_layers` registered |
| 148799 | `TGN_RunPipeline()` called after `Simulator::Destroy()` |

---

## 4. Layer 3: Secondary Crypto Gate (TGN_ApplyCryptoFilter)

> **⚠ Also stale:** `TGN_ApplyCryptoFilter()` no longer re-derives or drops
> anything (Finding-14 fix in tgn_core.cc §6). The primary gate
> (`routing.cc::PemCryptoPreFilter` → `TetaGuardCryptoFilter()`) already
> performs the real Eq. 3.15/3.16/3.17 checks (genuine HMAC-SHA256, not the
> `physical==claimed` proxy described below) plus the Eq. 3.26–3.30
> threshold-sig/location-binding checks before an event ever reaches
> `pem_all_events`. `TGN_ApplyCryptoFilter()` is now a thin passthrough that
> returns its input unchanged and just writes an explanatory
> `crypto_filter_log.txt` — it does not, and cannot, drop `DROP-MAC` /
> `DROP-STALE` / `DROP-NONCE` events the way the rest of this section
> describes. The "why a second gate" rationale, the three-check walkthrough,
> and the example `crypto_filter_log.txt` output below all describe the
> **old** secondary-pass design and no longer reflect what the code does.

### Why a second crypto gate?

Layer 1 (`PemCryptoPreFilter`) runs during simulation and drops events at the moment they arrive. The TGN runs post-simulation on the full `pem_all_events[]` batch. The secondary gate re-applies the same three Algorithm 3 checks to this batch so that:
- The TGN sees only events that would survive authentication in a real online deployment.
- Events dropped here are logged with a reason (`DROP-MAC`, `DROP-STALE`, `DROP-NONCE`), giving visibility into what a real deployment would reject before the GRU even runs.

This gate is **not** redundant — it operates on a different view of the event stream (the post-simulation batch vs the real-time stream).

### The three checks

#### Step 1 — HMAC/MAC integrity (Eq 3.15)

```
mac_valid = physical_is_rsu  OR  (physical_sender == claimed_sender)
```

If `mac_valid` is false → `DROP-MAC`.

The RSU range guard is:
```
physical_is_rsu = (N_RSUs > 0)
               AND (physical_sender_id >= N_Vehicles)
               AND (physical_sender_id <  N_Vehicles + N_RSUs)
```

**Why both bounds matter:** Without the upper bound, the controller sentinel `9999` satisfies `9999 >= N_Vehicles` whenever `N_RSUs > 0`. This would incorrectly classify all controller-origin events in "With RSU" scenarios as RSU-forwarded (trusted), bypassing the MAC check. The upper bound `< N_Vehicles + N_RSUs` excludes the sentinel.

#### Step 2 — Timestamp freshness (Eq 3.16)

```
|τ_r − τ_s| ≤ T_b + ε = 110 ms
```

If this fails → `DROP-STALE`.

This catches BSHH old-replays where the attacker uses a heartbeat from `t=0` when the current time is `t=10`. The 10-second gap far exceeds 110ms.

#### Step 3 — Nonce novelty (Eq 3.17)

```
nonce = (reporter_id, claimed_sender_id, sender_timestamp) — must be unique
```

If the same nonce was seen before → `DROP-NONCE`.

#### Special cases

| Case | Handling |
|------|---------|
| `PEM_EVENT_BEACON` | Always passes — beacons are not signed data packets |
| `physical_sender_id == 9999` | All checks bypassed — controller sentinel |

### What each attack family survives or fails

| Attack | Step 1 (MAC) | Step 2 (Fresh) | Step 3 (Nonce) | TGN needed? |
|--------|-------------|---------------|----------------|------------|
| TTW (malicious vehicle/RSU) | **PASSES** — re-signs with own valid key | **PASSES** — timestamp set to now | **PASSES** — fresh nonce | **YES — TGN is sole detector** |
| BSHH non-RSU-path | **FAILS** — attacker signs under victim identity | — | — | Not needed (caught here) |
| BSHH old-replay | May fail Step 1 or **FAILS** Step 2 | **FAILS** — old timestamp | — | Not needed for old replays |
| ME echo (own identity) | **PASSES** — signs with own key | **PASSES** — fresh timestamp | **PASSES** — fresh nonce | **YES — TGN detects via reporter inflation** |
| Controller-origin (9999) | **BYPASSED** | **BYPASSED** | **BYPASSED** | **YES — TGN is sole detector** |

### Output: crypto_filter_log.txt

Written by `TGN_ApplyCryptoFilter()`. Example:
```
== TGN Secondary Crypto Filter (Algorithm 3, §3.4.2) ==
  Step 1  Eq 3.15 — HMAC/MAC integrity check
  Step 2  Eq 3.16 — timestamp freshness: |τr-τs| ≤ 110.0 ms
  Step 3  Eq 3.17 — nonce novelty: (reporter, sender, τs) unique
  Controller bypass: physical_sender==9999 → all steps skipped
  RSU path: physical_sender>=N_Vehicles → Step 1 skipped (RSU trust)

[DROP-MAC]    t=10.0050  physical=1  claimed=0  (Eq 3.15 — BSHH)
[DROP-STALE]  t=10.0050  |τr-τs|=10000.0ms  sender=0  (Eq 3.16 — old replay)

== Summary ==
  In=150  Pass=143  Ctrl_bypass=3  MAC_fail=2  Stale=2  Nonce=0  Out=143
```

---

## 5. Layer 4: TGN Inference — Algorithm 2 (FS-DETECT)

`TGN_ProcessAllEvents()` iterates the filtered event list in reception-time order. For each non-beacon event, it runs 5 steps:

```
Event e (topology update or heartbeat)
  │
  ├─ TGN_ExtractFeatures(e)         → NodeFeatures feat  (Section 7)
  ├─ TGN_EdgeFreshness(recv, τ_s)   → A_uv ∈ (0, 1]     (Section 9)
  │
  └─ g_tgn->ProcessEvent(feat, link_src, link_dst, recv_time):
       ① UpdateNodeMemory(feat, recv_time)               GRU Eq 3.22  (Section 8)
       ② Build adjacency adj from A_uv                   Eq 3.21      (Section 9)
       ③ MessagePassingRound × L=2                       Eq 3.23      (Section 10)
       ④ score = σ(w_score · h_v^(L))  or HeuristicScore Eq 3.24     (Section 11)
       ⑤ if alert AND weights loaded: softmax variant    Eq 3.25      (Section 12)
       → returns score ∈ (0, 1)
  │
  ├─ tgn_alert = (score > θ_FS)
  ├─ accumulate TP/TN/FP/FN
  └─ TGN_WriteEventRow() → tgn_events.csv
```

**Beacon events** are handled separately: they update the beacon sliding window (`g_tgn_beacon_windows`) without running the GRU or message passing. This is critical for accurate `beacon_count` (c_v^W) — BEACON events don't produce a CSV row, but their timestamps must enter the window or the count will undercount by a factor of ~10.

---

## 6. Global State Maps — The Memory Outside the GRU

> **⚠ Correction:** this section previously said these maps are "cleared at
> the start of `TGN_ProcessAllEvents()` and never shared across simulation
> runs" — true only of the batch path. The live online/inline path
> (`TGN_ProcessEventInline`, see §2 warning) used to share one flat instance
> of these maps across *every* trusted node processed in the same run, since
> inline events from different observers (e.g. an RSU and the controller
> sentinel in S4/S8/S12) interleave in real time rather than being processed
> one node's slice at a time. That was a real cross-contamination bug — one
> trusted node's `seq_gap`/`reporter_count`/beacon-window state leaked into
> another's. **Fixed:** all three maps now carry an outer
> `trusted_node_id` key, so each observer gets an isolated local view in
> both the batch and online paths, matching §3.1.3's requirement that
> detection run independently per trusted node.

Three global maps accumulate state across the event sequence, scoped per trusted node:

```cpp
// Outer key = trusted_node_id (the observer running FS-DETECT: an RSU,
// an OBU peer, or the controller sentinel 9999). Inner key as before.
static std::map<uint32_t, std::map<uint32_t, double>>                g_tgn_last_sender_ts;
// [trusted_node_id][claimed_sender_id] → most recent sender_timestamp seen
// Purpose: detect seq_gap (backward timestamp regression for TTW-S2)

static std::map<uint32_t, std::map<std::string, std::set<uint32_t>>> g_tgn_link_reporters;
// [trusted_node_id]["link_src_id_link_dst_id"]  (DIRECTED)
// value = set of reporter IDs (vehicle or claimed sender, depends on RSU mode)
// Purpose: reporter_count (ρ_v) for ME detection

static std::map<uint32_t, std::map<uint32_t, std::vector<double>>>   g_tgn_beacon_windows;
// [trusted_node_id][claimed_sender_id]
// value = sliding window of reception timestamps, max size W_max
// Purpose: beacon_count (c_v^W, Eq 3.32) for silent-vehicle BSHH detection
```

### Why the link key is DIRECTED

`lkey = std::to_string(link_src_id) + "_" + std::to_string(link_dst_id)`

V1 reporting "V1 sees V2" uses key `"1_2"`. V2 reporting "V2 sees V1" uses key `"2_1"`. These are separate keys. On key `"1_2"`, the only legitimate reporter is V1 (count = 1). When V3 echoes `"V1 sees V2"`, it uses the same key `"1_2"` with reporter V3 → count becomes 2, exceeding `rhoMax=1.5`. This is how ME detection works: counting distinct reporters for the same directed link.

If the key were undirected (`"1_2"` and `"2_1"` merged), V1's benign report and V2's benign report would both contribute, pushing the baseline to 2 and requiring a higher threshold to detect echoes.

---

## 7. Feature Extraction (Eq 3.20 + identity_mismatch)

**Current implementation — updated, this section used to describe a stale 7-feature/`id_v_norm` scheme that no longer exists in the code.** The thesis Eq 3.20 defines 5 formal components, and `TGN_ExtractFeatures()` now matches exactly — `id_v` is deliberately excluded (identity-overfitting risk):
`x_v = [τ_dev^(v) | c_v^W | Δs_v | ρ_v | ι_v]`

φ is not part of x_v — it's appended inside the GRU cell (Eq 3.22), for a `dim+6` GRU input:

| Index | Name | Paper symbol | Source | Purpose |
|-------|------|-------------|--------|---------|
| 0 | `tau_dev` | τ_dev^(v) | `clip((recv_time − sender_ts) / T_b, −50, 50)` | Normalised reception/sender timestamp deviation (Eq 3.20) — fresh≈0, BSHH replay→large positive |
| 1 | `beacon_count` | c_v^W | `g_tgn_beacon_windows[trusted_node_id][node].size()` | Activity level in W_max window (Eq 3.32) |
| 2 | `seq_gap` | Δs_v | `prev_sender_ts - e.sender_timestamp` if regressive | Backward timestamp jump (TTW-S2 signal) |
| 3 | `reporter_count` | ρ_v | `g_tgn_link_reporters[trusted_node_id][lkey].size()` | Distinct reporters for this link (ME signal) |
| 4 | `identity_mismatch` | ι_v | `(physical ≠ claimed) ? 1.0 : 0.0` | BSHH signal (engineering extension) |
| — | `φ` (GRU-internal, not in x_v) | φ | `log(1 + Δt / T_b)` | Time elapsed since last event for this node |

**Note the `[trusted_node_id]` outer key on `g_tgn_beacon_windows`/`g_tgn_link_reporters`** — these maps are scoped per trusted node (the observer running FS-DETECT) so that concurrent trusted nodes (e.g. an RSU and the controller sentinel, interleaved during the live online/inline path — see §2 warning above) don't share state. See §6 below.

### identity_mismatch — the exact condition

```cpp
f.identity_mismatch =
    (!physical_is_rsu                           // not RSU forwarding
     && e.physical_sender_id != 9999u          // not controller sentinel
     && e.physical_sender_id != e.claimed_sender_id)  // actual mismatch
    ? 1.0 : 0.0;
```

Three independent guards are all required:
- **`!physical_is_rsu`**: RSU forwarding V1's data under V1's ID is legitimate — set to 0 to avoid false BSHH positives on all S2/S4/S6/S8/S10/S12 scenarios.
- **`!= 9999u`**: The controller sentinel always differs from `claimed_sender_id`, but this is NOT impersonation — it means the controller is internally fabricating an entry. Without this guard, all controller-origin attacks (S3/S4/S7/S8/S11/S12) would trigger `identity_mismatch=1.0` and be misclassified as BSHH.
- **`!= claimed_sender_id`**: The actual mismatch check for BSHH-S1 (V2 impersonating V1).

---

## 8. Step 1: GRU Memory Update (Eq 3.22)

The GRU maintains a per-node memory vector `m_v(t) ∈ ℝ^d` (dimension d=32). On each event involving node v:

**Input:**
```
gru_in = [m_v(t⁻) ‖ τ_dev, c_v^W, Δs_v, ρ_v, id_mis, φ]     — no id_v (Eq 3.20 excludes it)
       = concat(memory_vector_dim32, feature_vector_dim5, phi_dim1)
       → total input size = 38   (gru_input_size = dim + 6, TGNWeights::gru_input_size)
```

**Three gates:**
```
z = σ(Wz·gru_in + Uz·h + bz)           update gate — how much of new candidate to keep
r = σ(Wr·gru_in + Ur·h + br)           reset gate  — how much of old memory to use
n = tanh(Wn·gru_in + Un·(r⊙h) + bn)   candidate   — new information
```

**Output:**
```
m_v(t) = (1 - z) ⊙ m_v(t⁻) + z ⊙ n
```

Where `⊙` is element-wise (Hadamard) product.

**Weight matrix dimensions (d=32):**
- `Wz`, `Wr`, `Wn`: (32 × 38) — input projection
- `Uz`, `Ur`, `Un`: (32 × 32) — recurrent projection
- `bz`, `br`, `bn`: (32,) — biases

**Temporal encoding φ:**  
`φ = log(1 + Δt / T_b)` where `Δt = max(0, recv_time - last_event_time)`.  
This gives φ=0 for back-to-back events, φ=log(2)≈0.69 for events one `T_b`=100ms apart, growing logarithmically for longer gaps. It tells the GRU how long it has been since it last saw this node — useful for detecting nodes that have been silent (BSHH-S3).

**Zero-initialisation:** New nodes (first contact) start with `m_v = 0` and `last_event_time = recv_time`. This is Algorithm 2 (FS-DETECT) step 0, Eq 3.34.

---

## 9. Step 2: Edge Freshness Weight (Eq 3.21)

```
A_uv(t) = exp(-(max(0, age - T_b)) / (γ · T_b))
```

Where `age = recv_time - sender_timestamp` (how old is the observation in the packet).

- If `age ≤ T_b` (observation is fresh, within one beacon interval): A_uv = 1.0
- If `age > T_b` (stale): A_uv decays exponentially below 1.0

**Derivation of γ:**
```
γ = L_link / (2 · T_b · ln2)
```
Designed so that A_uv = 0.5 when the observation age equals `L_link/2` (half the expected link lifetime). For urban L_link ≈ 43s, T_b = 0.1s:
```
γ = 43 / (2 × 0.1 × 0.6931) ≈ 310
```

**Why A_uv matters for TTW:** A TTW attacker reports a link that physically broke at t=15 by forging the timestamp to t=now. The forged timestamp makes `age` appear fresh → A_uv ≈ 1.0. But the GRU's memory for that node has been accumulating stale observations since t=10, and the staleness term in `HeuristicScore` picks this up via `last_event_time - τ_s`. In trained mode, the GRU has learned to detect this inconsistency through the sequence of past memory states.

**Per-event adjacency structure:**
```
adj[node_id][link_dst] = A_uv  (symmetric)
adj[link_dst][node_id] = A_uv
```
`link_src` has no adjacency entries in this construction — it passes through message passing unchanged. This is intentional: `node_id` (the reporting node) is the anomalous entity; `link_dst` is the claimed neighbor; `link_src` is the link origin.

---

## 10. Step 3: Neighborhood Aggregation (Eq 3.23)

### The 3-node induced subgraph

Every event creates a fixed 3-node active set:
```
active = {reporting_node (node_id), link_src, link_dst}
```

Initial embeddings are taken from each node's current GRU memory:
```
H^(0)[v] = states_[v].memory    for each v ∈ active
```

### The aggregation formula

For each round `l ∈ {0, 1}` (L=2 rounds total), for each node `v ∈ active`:

```
Case 1 — no neighbors:
    H^(l+1)[v] = H^(l)[v]     (passthrough — no transform applied)

Case 2 — has neighbors:
    agg = mean{ A_uv × H^(l)[u] : u ∈ N(v) ∩ active }
    H^(l+1)[v] = ReLU(W_l · agg + b_l)
```

Full formula: `h_v^(l) = ReLU(W_l · (Σ_u A_uv · h_u^(l-1) / |N(v)|) + b_l)`

### Worked example for one event (L=2)

Say `event = {node_id=V0, link_src=V0, link_dst=V1}`.  
Active = {V0, V1} (V0 appears twice — deduplicated by set).

Adjacency: `adj[V0][V1] = A_uv`, `adj[V1][V0] = A_uv`.

**Round l=0:**
- V0: neighbors in active = {V1}. `agg = A_uv × H^(0)[V1]`. cnt=1, no division. `H^(1)[V0] = ReLU(W_0 · agg + b_0)`
- V1: neighbors in active = {V0}. `agg = A_uv × H^(0)[V0]`. `H^(1)[V1] = ReLU(W_0 · agg + b_0)`

**Round l=1:**
- V0: neighbors still = {V1}. `H^(2)[V0] = ReLU(W_1 · (A_uv × H^(1)[V1]) + b_1)`
- V1: similarly.

After both rounds, `states_[V0].embedding = H^(2)[V0]` and `states_[V1].embedding = H^(2)[V1]`.

**Weight matrix dimensions (d=32):**
- `W_layers[l]`: (32 × 32)  — one per round
- `b_layers[l]`: (32,)

### What message passing achieves

After L=2 rounds, `h_v^(L)` for the reporting node contains information from:
- Round 0: direct neighbor (link_dst) — 1-hop context
- Round 1: neighbor's neighbor (which is link_src through V1) — 2-hop context

The GRU memory of all three nodes influences the final embedding. An echo attacker (ME) sitting far from the real link endpoints will contribute different memory patterns than the legitimate reporter, and trained weights can detect this inconsistency.

---

## 11. Step 4: Anomaly Score — Trained vs Heuristic (Eq 3.24)

### Trained mode (weights loaded)

```
ŷ_v = σ(w_score · h_v^(L))
```

`w_score` is a learned (32,) vector. The dot product `w_score · h_v^(L)` is a scalar projection of the node's embedding, passed through sigmoid to get `ŷ_v ∈ (0,1)`. Alert fires if `ŷ_v > θ_FS`.

### Heuristic mode (no weights — current operating mode)

When `tgn_weights.bin` is not provided, random Xavier-initialised weights are used for the GRU and message passing (embedding update is computed but not meaningful), and scoring falls back to `HeuristicScore()`:

```
s = 0

# TTW staleness — link still reported beyond expected lifetime
staleness = last_event_time[v] - τ_s    (if τ_s > 0)
s += clamp((staleness - T_b) / T_b, 0, 2)

# TTW-S2 — backward timestamp regression
s += min(1, seq_gap / 5)

# BSHH — identity mismatch (0 for RSU-path events and controller sentinel)
s += identity_mismatch × 1.5

# ME — reporter density excess
rhoMax = 1.5
if reporter_count > rhoMax:
    s += min(2, (reporter_count - 1) × 0.8)   # baseline=1, not 2

# Edge staleness contribution
s += 2 × (1 - edge_freshness)

ŷ_v = σ(s - 2.0)   # centred at 2.0; benign events score ≈ σ(-2) ≈ 0.12
```

**Important:** In heuristic mode the GRU runs (memory updates happen) but the GRU weights are random — the memory vectors carry no learned information. The heuristic score is computed purely from the extracted features, not from the embedding. This is why the system works in heuristic mode — the feature signals are directly interpretable without needing trained weights.

**What each term catches:**
- Staleness: TTW family (link remains reported past its physical expiry)
- seq_gap: TTW-S2 specifically (RSU uses an older stored timestamp that went backwards)
- identity_mismatch: BSHH-S1 and BSHH-S3 (physical sender ≠ claimed sender)
- reporter_count: ME family (echo reports inflate the reporter set)
- edge_freshness: contributes to TTW via stale edge weight; also fires when sender timestamps are old relative to reception time

---

## 12. Step 5: Variant Classification (Eq 3.25)

**Only runs when:** `score > θ_FS` AND `weights_.loaded == true`.  
In heuristic mode (no weights): this step is completely skipped.

```
logits = W_cls · h_v^(L) + b_cls        (3,) raw scores for TTW, BSHH, ME
α̂_v = softmax(logits)                   numerically stable softmax
predicted_variant = argmax(α̂_v)         0=TTW, 1=BSHH, 2=ME
```

**Weight dimensions:**
- `Wcls`: (3 × 32)
- `b_cls`: (3,)

The predicted variant label `"TTW"`, `"BSHH"`, or `"ME"` is stored in `alert_variants_[node_id]` and retrieved by `TGN_WriteAlertsJson()` when building `tgn_alerts.json`.

---

## 13. alpha_source — Classifier Output vs Ground Truth Fallback

Every alert entry in `tgn_alerts.json` includes an `alpha_source` field that indicates how the variant label was derived.

| alpha_source | Meaning | When used |
|---|---|---|
| `"eq_3.25"` | Real softmax classifier prediction (Eq 3.25) | Only when weights are loaded AND an alert fires |
| `"scenario_id_fallback"` | Derived from `--attack_scenario` CLI argument (ground truth leak) | Always in heuristic mode |

### Critical warnings about `scenario_id_fallback`

When `alpha_source = "scenario_id_fallback"`:

1. **It is NOT a classifier prediction.** The attack family (TTW/BSHH/ME) is read from the `attack_scenario` command-line argument — which is ground truth, not something the model inferred.
2. **Never compute variant-classification accuracy using this.** MCC, precision, recall, and F1 for variant classification would be trivially 100% — meaningless.
3. **Never submit `scenario_id_fallback` alpha to the blockchain trust scoring** as evidence of classifier quality.
4. **The alpha values are deliberately different** in heuristic mode: `"TTW_family"`, `"BSHH_family"`, `"ME_family"` (with `_family` suffix) vs `"TTW"`, `"BSHH"`, `"ME"` in trained mode. This prevents accidentally treating them as equivalent.

```json
// Trained mode — real classifier:
{ "alpha": "TTW",        "alpha_source": "eq_3.25",              "y_hat": 0.87 }

// Heuristic mode — ground truth leak:
{ "alpha": "TTW_family", "alpha_source": "scenario_id_fallback", "y_hat": 0.73 }
```

---

## 14. TGN_RunPipeline() — The Complete Sequence

> **⚠ Stale — describes the pre-online-mode sequence.** `TGN_RunPipeline()`
> is still called once after `Simulator::Destroy()`, but steps ①–④ and ⑥–⑦
> below (calibration, weight loading, crypto filter, `TGN_ProcessAllEvents`)
> now only execute when `g_tgn_online_mode` is **false** — i.e. when
> `TGN_Init()` was never called before `Simulator::Run()`. The current
> `routing.cc` always calls `TGN_Init()` up front, so in practice
> `TGN_RunPipeline()` takes the online branch: it skips straight to building
> `E_t^trusted` from the events already scored by `TGN_ProcessEventInline()`
> during the simulation, runs the (passthrough — see §4 note) crypto audit,
> and writes the output files (⑧–⑩ below still apply). See §2's warning for
> the live pipeline.

Called once at routing.cc line 148799, after `Simulator::Destroy()`.

```
TGN_RunPipeline()
  │
  ├─ Guard: if pem_all_events.empty() → return
  │
  ├─ ① Calibrate from --tgn_l_link:
  │      γ = L_link / (2 · T_b · ln2)          Eq 3.21 decay constant
  │      W_max = floor(L_link / T_b)            Eq 3.32 beacon window size
  │      Copies to g_tgn_params.{gamma, wmax}
  │
  ├─ ② Set θ_FS from --tgn_theta → g_tgn_params.theta_fs
  │      Set dim from --tgn_dim, layers from --tgn_layers
  │
  ├─ ③ Create TGNDetector(g_tgn_params)
  │      → initialises weights (Xavier random, weights_.loaded=false)
  │
  ├─ ④ if --tgn_weights given:
  │        LoadWeights(path) → reads binary file, sets weights_.loaded=true
  │      else:
  │        Print heuristic-mode warning banner
  │
  ├─ ⑤ TGN_InitOutputFiles()
  │        Opens tgn_events.csv (with header)
  │        Opens tgn_detection_log_s{N}.txt (or tgn_detection_log.txt for baseline)
  │        Opens tgn_attack{N}.txt (or tgn_baseline.txt)
  │
  ├─ ⑥ TGN_ApplyCryptoFilter(pem_all_events) → filtered[]    [LAYER 3]
  │        Writes crypto_filter_log.txt
  │
  ├─ ⑦ swap pem_all_events ← filtered[]
  │      TGN_ProcessAllEvents()                               [LAYER 4]
  │        Clears g_tgn_last_sender_ts, g_tgn_link_reporters, g_tgn_beacon_windows
  │        Sorts events by reception_timestamp
  │        Loops: ExtractFeatures → ProcessEvent → WriteEventRow
  │      restore pem_all_events ← saved original
  │
  ├─ ⑧ TGN_WriteAlertsJson() → tgn_alerts.json
  │
  ├─ ⑨ TGN_WriteSummary() → tgn_summary.csv + tgn_attack{N}.txt
  │
  └─ ⑩ Cleanup:
         Close tgn_detection_log_s{N}.txt (writes blockchain handoff footer)
         delete g_tgn → nullptr
         Close tgn_events.csv
         Close tgn_attack{N}.txt
```

**Note on the swap (step ⑦):** `TGN_ProcessAllEvents()` reads from `pem_all_events` (the global). Rather than passing `filtered[]` as a parameter (which would require changing the function signature), the implementation temporarily replaces `pem_all_events` with `filtered`, runs processing, then restores the original. This is an intentional design choice to avoid touching `TGN_ProcessAllEvents()`'s interface.

---

## 15. Output Files Reference

| File | Written by | When | Contents |
|------|-----------|------|---------|
| `crypto_filter_log.txt` | `TGN_ApplyCryptoFilter()` | Layer 3 | Per-drop log (MAC/STALE/NONCE) + summary counts |
| `tgn_events.csv` | `TGN_WriteEventRow()` | Layer 4, per event | Full per-event record (see columns below) |
| `tgn_detection_log_s{N}.txt` | `TGN_ProcessAllEvents()` | Layer 4, per event | Human-readable step-by-step Eqs 3.20–3.25 trace |
| `tgn_alerts.json` | `TGN_WriteAlertsJson()` | End of pipeline | Confirmed alerts for blockchain submission |
| `tgn_attack{N}.txt` | `TGN_WriteSummary()` | End of pipeline | Summary: TP/TN/FP/FN, MCC, AUROC, Tdet |
| `tgn_summary.csv` | `TGN_WriteSummary()` | End of pipeline | Machine-readable summary (one row) |

Where `{N}` = `attack_scenario` value (e.g., `tgn_detection_log_s1.txt` for TTW-S1). Baseline runs use `tgn_detection_log.txt` and `tgn_baseline.txt`.

### tgn_events.csv columns

```
sim_time_s, attack_scenario, event_type,
physical_sender_id, claimed_sender_id, link_src_id, link_dst_id,
claimed_ts_s, recv_time_s, rx_delay_s, edge_freshness,
beacon_count, seq_gap, reporter_count, identity_mismatch, pem_signatures,
pem_score, pem_alert,
tgn_score, tgn_alert, is_attack
```

**Critical:** Use `is_attack` (last column) as the training label, **never** `tgn_alert`. `is_attack` is ground truth from the simulation. `tgn_alert` is the current model's prediction — in heuristic mode it is wrong for ME/TTW-RSU events, and training on wrong labels would make the model reinforce its own errors.

### tgn_alerts.json structure (Eq 3.36)

```json
[
  {
    "v_id":         "0",
    "alpha":        "TTW_family",
    "alpha_source": "scenario_id_fallback",
    "y_hat":        0.731,
    "S_trig":       [0, 2],
    "t_alert":      20050
  }
]
```

Fields: `v_id` = claimed_sender_id, `alpha` = variant family, `y_hat` = TGN score, `S_trig` = LW signature indices that fired (0–8), `t_alert` = alert time in milliseconds.

### tgn_summary.csv columns

```
attack_scenario, attack_name, tp, tn, fp, fn,
mcc, acr_pct, precision, recall,
tdet_ms, auroc, theta_fs, dim, layers, n_rsu, gamma, wmax
```

Good results expected (from paper):
- `mcc` > 0.85
- `auroc` > 0.90
- `tdet_ms` < 100 ms

---

## 16. Command-Line Parameters

Five TGN-specific parameters are registered in routing.cc at lines 144694–144710:

| Parameter | Default | Role |
|-----------|---------|------|
| `--tgn_weights=<path>` | `""` (empty) | Path to trained `tgn_weights.bin`. Empty = heuristic mode. |
| `--tgn_theta=<float>` | `0.40` | Alert threshold θ_FS. UNCALIBRATED — select by MCC on validation data after training. |
| `--tgn_l_link=<float>` | `43.0` | Expected link lifetime L_link (seconds). Used to compute γ and W_max. Urban≈43s, Highway≈9s. |
| `--tgn_dim=<int>` | `32` | GRU hidden dimension d. Must match the dim used during training. |
| `--tgn_layers=<int>` | `2` | Message-passing rounds L. Must match training. |

**Important:** `--tgn_theta` controls the alert threshold, not γ or W_max. Those two are computed solely from `--tgn_l_link`. The parameters play different roles:
- `--tgn_l_link` → γ (edge decay) and W_max (beacon window) — determine what "stale" means
- `--tgn_theta` → when a score becomes an alert — calibrate to maximise MCC on validation data

### Examples

```bash
# Heuristic mode (no weights):
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --attack_scenario=1"

# Trained mode:
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 \
             --attack_scenario=1 --tgn_weights=tgn/tgn_weights.bin \
             --tgn_theta=0.52 --tgn_l_link=43.0"

# Highway scenario (shorter link lifetime):
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 \
             --attack_scenario=1 --tgn_weights=tgn/tgn_weights.bin \
             --tgn_l_link=9.0 --tgn_theta=0.45"

# Controller-origin attacks (need N_Controllers and N_RSUs for S4/S8/S12):
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 \
             --attack_scenario=4"
```

---

## 17. Constants, Calibration, and Their Derivations

### T_b — Beacon interval (100 ms)

IEEE 802.11p mandates a 100ms broadcast period. This is the fundamental timing unit.

```cpp
static const double TGN_BEACON_INTERVAL = 0.1;   // T_b (seconds)
```

### γ — Edge freshness decay constant

```
γ = L_link / (2 · T_b · ln2)
```

Derived from the design condition: A_uv = 0.5 when the link observation is `L_link/2` seconds old.

Proof: `0.5 = exp(-(L_link/2) / (γ·T_b))` → `ln(0.5) = -(L_link/2)/(γ·T_b)` → `γ = L_link/(2·T_b·ln2)`.

| Scenario | L_link | γ |
|---------|--------|---|
| Urban | 43 s | 310 |
| Highway | 9 s | 65 |
| Rural | ~25 s | ~180 |

**Note:** L_link and therefore γ are marked TBD in the thesis. The 43s / γ=310 values are urban-scenario placeholders, not final calibrated values. After collecting real trace data, run the calibration:
```
γ = empirical_mean_link_lifetime / (2 · 0.1 · 0.6931)
```

### W_max — Beacon sliding window size (Eq 3.32)

```
W_max = floor(L_link / T_b)
```

For urban: `W_max = floor(43 / 0.1) = 430` beacons.

This is the expected number of beacons received from a node across its full link lifetime. `beacon_count` for a legitimate node approaches W_max over time. A node that just appeared (e.g., a hijacker impersonating a departed vehicle) will have `beacon_count` much lower than W_max.

### θ_FS — Alert threshold

```cpp
static const double TGN_THETA_FS = 0.40;   // UNCALIBRATED PLACEHOLDER
```

In heuristic mode, `σ(s - 2.0)` gives scores around:
- Benign events: s ≈ 0 → `σ(-2)` ≈ 0.12
- TTW attack (staleness=1.5T_b, seq_gap=0, id_mis=0, count=1): s ≈ 0.5 + 0 + 0 + 0 = 0.5 → `σ(-1.5)` ≈ 0.18
- BSHH attack (id_mis=1.0): s += 1.5 → s ≈ 1.5 → `σ(-0.5)` ≈ 0.38
- ME after first echo (count=2): s += 0.8 → s ≈ 0.8 → `σ(-1.2)` ≈ 0.23

The default threshold of 0.40 is intentionally set to catch BSHH (≈0.38) but may require tuning downward to 0.20–0.25 for better TTW and ME sensitivity in heuristic mode. **After training, select θ_FS by maximising MCC on validation data** — use `tgn_train.py --theta -1` for automatic selection.

---

## 18. What Each Attack Family Looks Like to TGN

### TTW — Topology Time-Warp

**What happens:**
- t=10: V0 sends legitimate `<V0 sees V1, t=10>` to controller. TGN records this — `g_tgn_last_sender_ts[V0] = 10.0`, `g_tgn_link_reporters["0_1"] = {V0}`, `beacon_count` grows.
- t=15: Link breaks. V1 stops beaconing.
- t=20: V0 sends forged `<V0 sees V1, t=20>` (fresh timestamp). TGN receives this — `sender_timestamp=20.0` is fresh (within 110ms of reception), but `g_tgn_last_sender_ts[V0]` was 10.0 → no seq_gap (20 > 10, no regression). Key signal: `staleness = last_event_time[V0] - τ_s` where `last_event_time[V0]` was updated to t=10 by the legitimate packet, but `τ_s=20.0` by the forged one. In trained mode the GRU memory for V0 carries the history of the link being alive at t=10 then quiet until t=20 — the pattern of memory states is what trained weights learn to flag.

**Heuristic detection:** Primarily via `staleness` term and `edge_freshness`. The forged packet has fresh τ_s (A_uv≈1.0) but the GRU `last_event_time` is from 10s ago → staleness contributes.

**TGN signal:** Temporal inconsistency in the GRU memory trajectory. Trained mode catches this more reliably than heuristic.

**Crypto filter behaviour:** TTW passes ALL three crypto checks (MAC valid, timestamp fresh, nonce new). TGN is the only layer that can detect it.

### BSHH — Beacon State Heartbeat Hijack

**What happens:**
- t=5: V1 sends legitimate heartbeat `<claimed=V1, physical=V1, t=5>`.
- t=10: V2 replays `<claimed=V1, physical=V2, t=0>` (old heartbeat).

**Crypto filter:** `physical=V2 ≠ claimed=V1` AND `physical_is_rsu=false` → `DROP-MAC`. Also `|recv_time - τ_s| = |10 - 0| = 10s >> 110ms` → `DROP-STALE`.

**Most BSHH attacks are caught at Layer 3.** What reaches the TGN is:
- BSHH-S2 (malicious RSU): RSU is trusted (`physical_is_rsu=true`), so MAC check is skipped. RSU can replay with freshened timestamps (bypasses Step 2). TGN catches via `seq_gap` (timestamp went backwards for V1's sequence) and `identity_mismatch=0` (suppressed for RSU path — caught by staleness instead).
- BSHH-S3/S4 (malicious controller): bypassed via sentinel `9999`. TGN must detect via `seq_gap`.

**TGN signal:** `identity_mismatch=1.0` (non-RSU path), `seq_gap > 0` (backward timestamp), `beacon_count` drops (victim went silent after moving away).

### ME — Multipath Echo

**What happens:**
- t=10: V1 reports `<V1 sees V2, t=10>`. V3 and V4 also send `<V1 sees V2, t=10>` under their own identities.

**Crypto filter:** V3 signs with V3's own key (`physical_is_rsu=false, physical==claimed`) → MAC valid. Fresh timestamp → Step 2 passes. Fresh nonce → Step 3 passes. **ME is NOT stopped by the crypto filter.** TGN is the sole detector.

**TGN signal:** `g_tgn_link_reporters["1_2"]` accumulates `{V1, V3, V4}`. After V3's echo: `reporter_count=2 > rhoMax=1.5`. Score grows with each additional echo.

**Important subtlety:** RSU-path ME (ME-S2): the RSU sends echo reports attributed to fake `claimed_sender_id` values. `reporter_count` tracks `claimed_sender_id` in RSU mode (not `reporter_id`), so the inflation is still detected.

### Controller-origin (S3, S4, S7, S8, S11, S12)

All crypto checks are bypassed (`physical_sender_id=9999` sentinel). The TGN must be the sole detector. The signals depend on the attack family:
- TTW-S3/S4: temporal inconsistency in GRU memory, staleness term
- BSHH-S3/S4: seq_gap (backward timestamp for the victim identity), `identity_mismatch=0` (sentinel suppresses it — caught by other signals)
- ME-S3/S4: `reporter_count` inflation in `g_tgn_link_reporters`

---

## 19. RSU vs No-RSU: How Feature Extraction Differs

The RSU presence affects two features and their interpretation:

| Feature | No RSU (physical_is_rsu=false) | With RSU (physical_is_rsu=true) |
|---------|-------------------------------|--------------------------------|
| `reporter_count` key | `reporter_id` (vehicle that physically transmitted) | `claimed_sender_id` (who the message claims to be from) |
| `identity_mismatch` | `1.0` if physical ≠ claimed | Always `0.0` |
| `rhoMax` (heuristic) | `max(2, N_Vehicles/4) × 1.5` | `1.5` |

**Why the reporter_count tracking changes:**
- Without RSU: the attacker (V3) echoes a link report under V3's own identity. We track distinct physical reporters (`reporter_id`) to detect V3 joining V1 as a co-reporter of the V1→V2 link.
- With RSU: a malicious RSU sends echo reports claiming to be from fabricated vehicles (e.g., `claimed_sender_id=V5`, `V6`). The physical sender is always the RSU. Tracking `reporter_id` (the RSU) would give count=1 always. We track `claimed_sender_id` instead to count how many distinct identities the RSU has attributed the link to.

**Why identity_mismatch is suppressed for RSU:**
RSU legitimately forwards V1's data with `claimed_sender_id=V1` and `physical_sender_id=RSU_ID`. This is not impersonation — it is aggregation. Suppressing `identity_mismatch` for RSU-path events prevents false BSHH alerts on all S2/S4/S6/S8/S10/S12 scenarios. BSHH-S2/S4 is instead caught by `seq_gap` (the RSU uses old timestamps) and `staleness`.

---

## 20. Training Pipeline — tgn_train.py

### Overview

`tgn_train.py` trains a PyTorch model whose architecture exactly mirrors `TGNDetector` in `tgn_core.cc`. After training, it exports weights to a binary file (`tgn_weights.bin`) that `TGNDetector::LoadWeights()` reads directly. The weight format is strictly bit-compatible — no conversion layer is needed.

### PyTorch model architecture

```python
class TGNModel(nn.Module):
    # GRU gates (Eq 3.22): gs = dim + 6   (5 features per Eq 3.20, no id_v, + phi)
    Wz, Wr, Wn  — shape (dim, gs)  input projections
    Uz, Ur, Un  — shape (dim, dim) recurrent projections
    bz, br, bn  — shape (dim,)     biases

    # Message-passing layers (Eq 3.23): L layers
    W_layers[l] — shape (dim, dim)
    b_layers[l] — shape (dim,)

    # Detection head (Eq 3.24)
    w_score     — shape (dim,)

    # Classification head (Eq 3.25)
    Wcls        — shape (3, dim)   TTW/BSHH/ME logits
    b_cls       — shape (3,)
```

### Why features are read from CSV, not recomputed

Four of the five Eq. 3.20 features are pre-computed by C++ and read directly from `tgn_events.csv`:

| Feature | Why not recomputed in Python |
|---------|------------------------------|
| `beacon_count` | BEACON events don't appear in the CSV (they don't generate a row). Recomputing the sliding window from CSV rows alone misses all BEACON contributions, giving count ≈ 5-10 instead of the correct ≈430. |
| `seq_gap` | After concatenating multi-run CSVs, the last_ts from run N-1 would carry into run N. C++ clears `g_tgn_last_sender_ts` at the start of each run; Python can't replicate this from the CSV alone. |
| `reporter_count` | RSU-path mode tracks `claimed_sender_id`, not `reporter_id`. The `reporter_id` column is not always in the CSV; recomputing from `physical_sender_id` would give wrong values for RSU and controller scenarios. |
| `identity_mismatch` | RSU events and controller sentinel must give `0.0`. Recomputing as `(physical != claimed)` would give `1.0` for all of these, causing train/infer mismatch for 6 of 12 scenarios. |

Only `φ` (temporal encoding) is recomputed in Python, because it depends on consecutive `recv_time_s` values and is not stored in the CSV.

### Training loss

```
loss = BCE(logits, is_attack_label)           — binary attack detection (primary)
     + 0.3 × CrossEntropy(cls_logits, variant) — variant classification (auxiliary)
```

The variant cross-entropy loss is computed only for attack events (benign events have label=-1, excluded from CE loss). This jointly trains the detection head (`w_score`) and classification head (`Wcls`) in one pass.

Class-weight balancing (`pos_weight = n_neg / n_pos`) is applied to BCE to handle the imbalanced attack/benign event ratio.

### Data split

```
70% train | 15% validation | 15% test
Split is temporal (not random) — first 70% chronologically goes to train.
```

Temporal splitting is critical: random splitting would leak future information into training (an event at t=20s would see features like `beacon_count` that depend on earlier events, which may be in the test set). By splitting chronologically, the model is evaluated on events it has never seen temporally.

### Optimal threshold selection

After training, θ_FS is selected by scanning `[0.05, 0.95]` in steps of 0.01 and choosing the threshold that maximises MCC on the validation set:
```
θ* = argmax_θ MCC(val_labels, (val_scores >= θ))
```

The optimal θ is printed and included in the deployment command at the end of training output:
```
./waf --run "scratch/routing ... --tgn_theta=0.52 ..."
```

---

## 21. Binary Weight File Format

`tgn_weights.bin` is a raw binary file. All values are `float64` (C++ `double`), stored in row-major order. The layout must exactly match `TGNDetector::LoadWeights()`.

```
Bytes  Content
──────────────────────────────────────────────────────
4      int32  dim        (e.g., 32)
4      int32  layers     (e.g., 2)

Then for each GRU gate (z, r, n) in order:
  dim*gs*8  W (dim×gs)  float64 row-major   gs = dim + 6
  dim*dim*8 U (dim×dim) float64 row-major
  dim*8     b (dim,)    float64

Then for each message-passing layer l in [0, layers-1]:
  dim*dim*8 W_layers[l] (dim×dim) float64 row-major
  dim*8     b_layers[l] (dim,)    float64

dim*8     w_score (dim,)   float64
3*dim*8   Wcls (3×dim)     float64 row-major
3*8       b_cls (3,)       float64
```

For `dim=32, layers=2, gs=39`:
```
Total = 4+4 + 3×(32×39 + 32×32 + 32)×8 + 2×(32×32 + 32)×8 + 32×8 + 3×32×8 + 3×8
      ≈ 8 + 3×(1248+1024+32)×8 + 2×(1024+32)×8 + 256 + 768 + 24
      ≈ 8 + 55296 + 16896 + 1048
      ≈ 73,248 bytes ≈ 72K
```

This matches the observed `tgn_weights.bin` size of ~72K.

---

## 22. End-to-End Workflow: From Simulation to Trained Detector

### Step 1 — Generate training data

```bash
cd ~/ns-allinone-3.35/ns-3.35

# Option A: Automated (all 12 scenarios, 3 seeds each)
bash "scratch/SDVN project /SDVN-Temporal-Attacks/generate_training_data.sh"

# Option B: Manual (one scenario at a time)
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --attack_scenario=0"
cat tgn_events.csv > all_events.csv

for SCENARIO in 1 2 3 4 5 6 7 8 9 10 11 12; do
    ./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --attack_scenario=${SCENARIO}"
    tail -n +2 tgn_events.csv >> all_events.csv
done
```

Recommended: at least 3 simulation runs (`--RngRun=1`, `--RngRun=2`, `--RngRun=3`) per scenario to get diverse vehicle positions and mobility patterns.

### Step 2 — Train

```bash
cd ~/ns-allinone-3.35/ns-3.35/scratch

python3 "SDVN project /SDVN-Temporal-Attacks/tgn/tgn_train.py" \
    all_events.csv \
    --epochs 50 \
    --dim 32 \
    --layers 2 \
    --l_link 43.0 \
    --theta -1 \            # auto-select θ by MCC
    --output tgn_weights.bin
```

Training output includes:
```
[TGN] Device: cpu
       train:  3640 events  (480 attack, 3160 benign)
       val:     780 events  (102 attack,  678 benign)
       test:    780 events  ...
[TGN] Training: dim=32 layers=2 epochs=50 lr=0.001 theta=-1
  Epoch   5/50  loss=0.3821  val_MCC=0.712  val_AUROC=0.891  TP=87 TN=651 FP=27 FN=15
  ...
  Epoch  50/50  loss=0.1234  val_MCC=0.934  val_AUROC=0.976  TP=98 TN=673 FP=5 FN=4
[TGN] Best checkpoint: epoch=47  val_MCC=0.936
[TGN] Optimal theta_FS = 0.52  (val_MCC=0.936)
[TGN] Test  MCC=0.921  AUROC=0.968  TP=97 TN=668 FP=10 FN=5
[TGN] Weights saved to 'tgn_weights.bin'  (73248 bytes, dim=32 layers=2)

Next deploy command:
  ./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 \
               --attack_scenario=1 --tgn_weights=tgn_weights.bin \
               --tgn_theta=0.52 --tgn_l_link=43.0"
```

### Step 3 — Run with trained weights

```bash
cd ~/ns-allinone-3.35/ns-3.35

./waf --run "scratch/routing \
    --simTime=60 \
    --N_Vehicles=6 \
    --N_RSUs=0 \
    --attack_scenario=1 \
    --tgn_weights=tgn_weights.bin \
    --tgn_theta=0.52 \
    --tgn_l_link=43.0"
```

### Step 4 — Check results

```bash
# Detection metrics
cat tgn_summary.csv

# Human-readable per-event trace
cat tgn_detection_log_s1.txt | head -80

# Alerts for blockchain
cat tgn_alerts.json

# Crypto filter drops
cat crypto_filter_log.txt
```

### Step 5 — Submit to blockchain (optional)

```bash
cd "scratch/SDVN project /SDVN-Temporal-Attacks"
python3 submit_alerts.py tgn_alerts.json
```

### Step 6 — Run 5 experiments for report statistics

```bash
#!/bin/bash
# run_5_tgn_experiments.sh
SCENARIO=${1:-1}
N_VEH=${2:-6}
N_RSU=${3:-0}
WEIGHTS=${4:-tgn_weights.bin}
THETA=${5:-0.52}

cd ~/ns-allinone-3.35/ns-3.35
mkdir -p results/tgn_scenario_${SCENARIO}

for SEED in 1 2 3 4 5; do
    echo "=== Run $SEED / 5 (scenario=$SCENARIO) ==="
    rm -f tgn_events.csv tgn_summary.csv tgn_alerts.json tgn_detection_log_s*.txt tgn_attack*.txt

    ./waf --run "scratch/routing \
        --simTime=60 \
        --N_Vehicles=${N_VEH} \
        --N_RSUs=${N_RSU} \
        --attack_scenario=${SCENARIO} \
        --tgn_weights=${WEIGHTS} \
        --tgn_theta=${THETA} \
        --RngRun=${SEED}"

    cp tgn_summary.csv results/tgn_scenario_${SCENARIO}/run_${SEED}_tgn_summary.csv
done

echo "Done. Results in results/tgn_scenario_${SCENARIO}/"
```

---

## 23. Reading and Interpreting the Output Files

### tgn_detection_log_s{N}.txt — step-by-step trace

Each event produces a block like:

```
────────────────────────────────────────────
[t=20.0050]  TOPO_UPDATE  *** ATTACK ***
  Physical: V0  Claimed: V0  Link: V0<->V1

  ① Eq 3.20 — Feature Vector x_v (+ identity_mismatch extension)
    id_v=0.000  τ_s=20.005  c_v^W=101  Δs_v=0.000  ρ_v=1  id_mis=0.000

  ② Eq 3.21 — Edge Freshness A_uv = 0.9998  (1=fresh, 0=stale)

  ③ Eq 3.22/3.23 — GRU Memory + Message Passing (L=2)

  ④ Eq 3.12 — LW Signature Detector (9 signatures)
    Sig[0] TTW-S1: TRIGGERED  w=0.15
    Sig[1] TTW-S2: not fired  w=0.15
    ...
    s(e)=0.150  LW alert=YES  sigs: TTW-S1

  ⑤ Eq 3.24 — TGN Score ŷ_v = 0.731  θ_FS=0.40  alert=RAISED
  ⑥ Eq 3.25 — Variant α̂_v = TTW
```

The block shows all 5 algorithm steps for that event. Use this file to debug why an event was or wasn't flagged.

### tgn_summary.csv — key metrics

```csv
attack_scenario,attack_name,tp,tn,fp,fn,mcc,acr_pct,precision,recall,tdet_ms,auroc,theta_fs,dim,layers,n_rsu,gamma,wmax
1,"TTW-S1: Malicious Vehicle, No RSU",3,97,0,0,1.000,100.000,1.000,1.000,48.200,1.000,0.400,32,2,0,310.000,430
```

Interpreting:
- `tp=3, fp=0, fn=0` → perfect detection, no false positives, no missed attacks
- `mcc=1.000` → perfect MCC (maximum is 1.0)
- `tdet_ms=48.2` → 48.2ms from first attack event to first alert (within 100ms budget)
- `auroc=1.000` → perfect area under ROC curve

### tgn_alerts.json — what goes to blockchain

Each alert has an `alpha_source` field. In the results, always verify:
- If `alpha_source = "eq_3.25"` → the variant comes from the model classifier. Usable for classification metrics.
- If `alpha_source = "scenario_id_fallback"` → heuristic mode was used. Do not report variant classification accuracy from these.

### crypto_filter_log.txt — what the secondary gate dropped

```
== Summary ==
  In=150  Pass=143  Ctrl_bypass=3  MAC_fail=2  Stale=2  Nonce=0  Out=143
```

- `In`: total events in `pem_all_events[]`
- `Ctrl_bypass`: controller-origin events (sentinel 9999) — passed through for TGN to handle
- `MAC_fail`: BSHH-S1 attack packets caught here (before TGN)
- `Stale`: old replay heartbeats caught here
- `Out`: events that reached the TGN

---

## 24. Common Issues and Fixes

### TGN runs in heuristic mode even with --tgn_weights specified

**Check:** Is the path relative or absolute?
```bash
# Wrong (relative path from wrong directory):
./waf --run "scratch/routing --tgn_weights=tgn_weights.bin"

# Correct (path relative to where waf runs — ns-3.35/ root):
./waf --run "scratch/routing --tgn_weights=scratch/tgn/tgn_weights.bin"
# Or use absolute path:
./waf --run "scratch/routing --tgn_weights=/home/yourname/.../tgn_weights.bin"
```

Look for this in the output: `[TGN] Weight file '...' not found — using heuristic scoring.`

### tgn_events.csv is empty after simulation

The file is opened in `TGN_InitOutputFiles()` (called inside `TGN_RunPipeline()`). If the simulation was interrupted before `Simulator::Destroy()`, `TGN_RunPipeline()` was never called. Let the simulation complete:
```bash
./waf --run "scratch/routing --simTime=25 --N_Vehicles=2 --attack_scenario=1"
# Use shorter simTime for testing rather than Ctrl+C
```

### tgn_summary.csv shows mcc=0

Possible causes:
1. `pem_all_events[]` was empty — check if any events were generated
2. The attack schedule happened after `simTime` — check that attack timing constants (e.g., `TTW_REPLAY_TIME=20.0`) are within `simTime`
3. θ_FS is too high — lower it: `--tgn_theta=0.2` to test heuristic-mode sensitivity

### Training error: "Too few events to train"

Need at least 20 non-beacon events. Generate more data:
- Increase `simTime`: `--simTime=120`
- Increase vehicles: `--N_Vehicles=10`
- Concatenate multiple scenarios before training

### Train/infer mismatch (good val_MCC during training, poor tgn_summary.csv after)

Most likely cause: the training data was generated with different parameters than the evaluation run. Must match:
- `--simTime` (affects event density)
- `--N_Vehicles` (affects RSU detection paths and `rhoMax`)
- `--N_RSUs` (changes RSU/no-RSU mode — completely different feature behaviour)
- `--mobility_scenario` and `--maxspeed` (affect link lifetimes → affects L_link calibration)
- `--tgn_l_link` (must be the same value used during training in `--l_link`)

### Weight dim/layers mismatch error

`LoadWeights()` reads `dim` and `layers` from the binary file header. If `--tgn_dim` or `--tgn_layers` differ from what was used during training, the weight matrix dimensions won't match. The file header is authoritative — the loaded `dim` and `layers` override the command-line values:
```
Loaded: dim=32 layers=2 (from file header)
```
Always use the same `--dim` and `--layers` in `tgn_train.py` as you intend to use with `--tgn_dim` and `--tgn_layers` at runtime. Or just accept the file header values (the code reads them automatically).

### beacon_count is very low (≈5-10 instead of ≈400+)

This means BEACON events from `pem_all_events[]` are not being processed. Check that `PemEmitVehicleBeacon()` is being called during simulation. The BEACON branch in `TGN_ProcessAllEvents()` updates `g_tgn_beacon_windows` but does not write a CSV row — that's by design.

If running with `--simTime=30` and `--N_Vehicles=2`, `beacon_count` starts from 0 and grows to `min(30/0.1, W_max) = 300` for a node active throughout. A much lower count suggests beacons aren't being emitted.

### alpha_source is always scenario_id_fallback in tgn_alerts.json

This means the model is in heuristic mode (weights not loaded) OR the score never exceeded θ_FS while weights were loaded. The Eq 3.25 variant classification (Step 5) only runs when `score > θ_FS AND weights_.loaded`.

Check:
```bash
grep "alpha_source" tgn_alerts.json      # should show "eq_3.25" after training
grep "TGN.*loaded from" tgn_summary.csv  # won't appear, check terminal output
```
Terminal should show `[TGN] Weights loaded from 'tgn_weights.bin' (dim=32 layers=2)`.

---

*Last updated: Department of EIE, University of Ruhuna — FYP implementation guide for `.tgn_src/tgn_core.cc` and `tgn/tgn_train.py`*
