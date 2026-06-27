# Full Implementation Reference
## A Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection in SDVNs

**Department of EIE — University of Ruhuna — Final Year Project**  
**Supervisor:** Dr. Nilmantha Wijesekara | **Co-supervisor:** Dr. Prabath Weerasingha

---

## Table of Contents

1. [What the System Does](#1-what-the-system-does)
2. [Network Topology](#2-network-topology)
3. [The Three Attack Families](#3-the-three-attack-fa
4. [The 12 Attack Scenarios](#4-the-12-attack-scenarios)
5. [Full System Flow Diagram](#5-full-system-flow-diagram)
6. [Layer 0 — NS-3 Simulation](#6-layer-0--ns-3-simulation)
7. [Layer 1 — PEM](#7-layer-1--pem)
8. [Layer 2 — Cryptographic Pre-Filter](#8-layer-2--cryptographic-pre-filter)
9. [Layer 3 — TGN](#9-layer-3--tgn)
10. [Feature Vector — Every Element Explained](#10-feature-vector--every-element-explained)
11. [TGN Internal Computations Step by Step](#11-tgn-internal-computations-step-by-step)
12. [Training Pipeline](#12-training-pipeline)
13. [Layer 4 — Blockchain](#13-layer-4--blockchain)
14. [How Each Attack Is Detected](#14-how-each-attack-is-detected)
15. [Output Files Reference](#15-output-files-reference)
16. [Key Numbers Quick Reference](#16-key-numbers-quick-reference)
17. [Glossary of All Special Terms](#17-glossary-of-all-special-terms)

---

## 1. What the System Does

An **SDVN (Software-Defined Vehicular Network)** is a road network where vehicles
communicate wirelessly and a centralised **SDN controller** makes routing decisions
for all of them. Because the controller trusts the topology information it receives,
attackers can feed it false information to make it install wrong routes.

This project implements a **four-layer detection and mitigation pipeline**:

```
Layer 0:  NS-3 simulation    ->  generates realistic traffic with and without attacks
Layer 1:  PEM                ->  9 lightweight rule-based signatures, runs in real time
Layer 2:  Crypto pre-filter  ->  drops obviously stale or replayed packets by math
Layer 3:  TGN                ->  neural network that learns temporal attack patterns
Layer 4:  Blockchain         ->  stores confirmed alerts immutably via PBFT consensus
```

---

## 2. Network Topology

```
+--------------------------------------------------------------------+
|                         ROAD (simulated)                           |
|                                                                    |
|  [V0] <--DSRC 802.11p--> [V1] <--DSRC--> [V2] <- - [V3] [V4]   |
|   |                         |                                      |
|   +---------- DSRC ---------+                                      |
|                             | (V2R)                                |
|                          [RSU_0]                                   |
|                             |  CSMA Ethernet (10.1.1.0/24)        |
|                             +-----------> [SDN Controller]         |
|                                          [Management Server]       |
+--------------------------------------------------------------------+
```

### Node types

| Node | Count | Radio | Purpose |
|------|-------|-------|---------|
| Vehicle | 0-200 | DSRC 802.11p (5.9 GHz) | Move, broadcast beacons, are targets and attackers |
| RSU | 0-2 | DSRC + CSMA Ethernet | Relay vehicle beacons to controller over wired LAN |
| SDN Controller | 1 | CSMA Ethernet | Builds topology table, makes routing decisions |
| Management Server | 1 | CSMA Ethernet | Legacy architecture; not used in attack scenarios |

### Communication paths

| Path | Technology | Used for |
|------|-----------|---------|
| V2V (Vehicle to Vehicle) | DSRC 802.11p broadcast | Topology beacons, heartbeats, HELLO exchanges |
| V2R (Vehicle to RSU) | DSRC 802.11p broadcast | Same beacons, RSU receives from range |
| R2C (RSU to Controller) | CSMA Ethernet UDP port 7777 | RSU forwards aggregated topology |
| V2C (Vehicle to Controller) | LTE uplink | Disabled in attack scenarios |

### DSRC channels (5.9 GHz band)

| Channel | Frequency | Type | Purpose |
|---------|-----------|------|---------|
| 172 | 5.860 GHz | SCH | Service data |
| 174 | 5.870 GHz | SCH | Service data |
| 176 | 5.880 GHz | SCH | Service data |
| **178** | **5.890 GHz** | **CCH** | **Safety beacons and heartbeats** |
| 180 | 5.900 GHz | SCH | Service data |
| 182 | 5.910 GHz | SCH | Service data |
| 184 | 5.920 GHz | SCH | Service data |

- Communication range: **300 m**  
- Beacon interval: **T_b = 100 ms** (IEEE 802.11p)

---

## 3. The Three Attack Families

### TTW — Topology Time-Warp

**What the attacker does:** Stores a legitimate topology packet when a link is real,
waits for the link to physically break (the vehicle drives away), then replays it with
a forged current timestamp. The controller believes the broken link is still active.

```
t=10s  V0 and V1 are 150m apart -> link exists
       V0 -> controller: "I see V1, ts=10s"  [LEGITIMATE]
       V0 secretly stores this packet

t=15s  V1 drives away -> physical link breaks (>300m)

t=20s  V0 replays: "I see V1, ts=20s"   [FORGED: ts was rewritten to current time]
       Controller: "Link V0<->V1 is still active at t=20s, route through it"
       Reality: every packet routed through V0->V1 is dropped
```

### BSHH — Beacon State Heartbeat Hijack

**What the attacker does:** Stores a heartbeat from another vehicle (V1), then replays
it impersonating V1's identity. The controller believes V1 is alive when it is not.

```
t=5s   V1 sends: "I am alive, sender=V1, ts=5s"  [LEGITIMATE]
       V2 (malicious) overhears and stores old: "sender=V1, ts=0s"

t=10s  V2 -> controller: "sender=V1, ts=0s"       [FORGED: V2 impersonates V1]
       Controller now has conflicting heartbeats for V1:
         ts=5s (real) vs ts=0s (stale replay from V2)
       Controller uses wrong liveness -> faulty routing
```

### ME — Multipath Echo

**What the attacker does:** A real link V1<->V2 exists. Malicious nodes V3 and V4 claim
they also observed this link. Controller infers phantom paths V1->V3->V2 and V1->V4->V2
that do not physically exist.

```
t=10s  V1 -> controller: "I see V2"  [LEGITIMATE]
       V2 -> controller: "I see V1"  [LEGITIMATE]
       V3 -> controller: "I see V2"  [FORGED - V3 never contacted V2]
       V4 -> controller: "I see V2"  [FORGED]

Controller infers:
  Path V1->V2         (REAL)
  Path V1->V3->V2     (PHANTOM)
  Path V1->V4->V2     (PHANTOM)
  Path V1->V3->V4->V2 (PHANTOM)

Packets sent via phantom paths are dropped
```

---

## 4. The 12 Attack Scenarios

| ID | Family | Attacker | RSU? | physical_sender_id |
|----|--------|----------|------|-------------------|
| 0  | None (baseline) | — | No | — |
| 1  | TTW-S1 | Malicious vehicle | No | Vehicle ID (e.g. 0) |
| 2  | TTW-S2 | Malicious RSU | Yes | RSU node ID |
| 3  | TTW-S3 | Malicious controller | No | **9999** |
| 4  | TTW-S4 | Malicious controller | Yes | **9999** |
| 5  | BSHH-S1 | Malicious vehicle | No | Vehicle ID |
| 6  | BSHH-S2 | Malicious RSU | Yes | RSU node ID |
| 7  | BSHH-S3 | Malicious controller | No | **9999** |
| 8  | BSHH-S4 | Malicious controller | Yes | **9999** |
| 9  | ME-S1 | Malicious vehicles (V3, V4) | No | Vehicle IDs 3, 4 |
| 10 | ME-S2 | Malicious RSU | Yes | RSU node ID |
| 11 | ME-S3 | Malicious controller | No | **9999** |
| 12 | ME-S4 | Malicious controller | Yes | **9999** |

**Why 9999?** When the controller itself is the attacker, no external packet is sent —
the manipulation happens inside the controller's own memory tables. The code uses
`physical_sender_id = 9999` as a sentinel. The **cryptographic pre-filter bypasses
all events with sender=9999** because a malicious insider already holds valid credentials.

---

## 5. Full System Flow Diagram

```
+-----------------------------------------------------------------------------+
|                    NS-3 SIMULATION  (routing.cc)                            |
|                                                                             |
|   Vehicles broadcast beacons every 100ms on DSRC Channel 178               |
|   Attack injected at scheduled simulation time (e.g. t=20s)                |
|   Every event (beacon / topology update / heartbeat) -> pem_all_events[]   |
|                                                                             |
|   +---------------------------------------------------------------+        |
|   |              PEM  (runs inline during simulation)             |        |
|   |                                                               |        |
|   |   For each event:                                             |        |
|   |     9 signatures checked (O(1) each)                         |        |
|   |     score = sum of triggered_weight[i]   (Eq. 3.12)          |        |
|   |     + temporal pressure from recent window                    |        |
|   |     alert if score >= 0.075                                   |        |
|   |                                                               |        |
|   |   Writes: pem_event_log.csv, pem_run_summary.csv             |        |
|   +---------------------------------------------------------------+        |
+-----------------------------------------------------------------------------+
                                 |
                                 |  pem_all_events[] passed to TGN pipeline
                                 v
+-----------------------------------------------------------------------------+
|              CRYPTO PRE-FILTER  (Algorithm 3 - LW-MITIGATE)                |
|                                                                             |
|  Rule 1  Eq.3.15 Freshness:  |recv_time - sender_ts| <= 110ms             |
|          DROP if stale  (catches BSHH-S1/S2 old heartbeat replays)         |
|                                                                             |
|  Rule 2  Eq.3.16 Nonce:  (reporter, claimed_sender, ts) not seen before   |
|          DROP if duplicate  (catches exact packet replays)                  |
|                                                                             |
|  Rule 3  Eq.3.17 Revocation:  after first alert, attacker is revoked       |
|          DROP all future events from that physical_sender                   |
|                                                                             |
|  BYPASS: physical_sender == 9999  ->  always pass through                  |
|          (controller insider has valid keys; TGN is only defence here)      |
|                                                                             |
|  Writes: crypto_filter_log.txt                                              |
+-----------------------------------------------------------------------------+
                                 |
                                 |  filtered events -> TGN_ProcessAllEvents()
                                 v
+-----------------------------------------------------------------------------+
|                 TGN  (Temporal Graph Neural Network)                        |
|                                                                             |
|  For each event e (in reception-time order):                                |
|                                                                             |
|  Step 1  Extract features -> NodeFeatures struct                            |
|           f = [tau_deviation, beacon_count, seq_gap,                        |
|                reporter_count, identity_mismatch, phi]                      |
|                                                                             |
|  Step 2  Compute edge freshness  A_uv  (Eq. 3.20)                         |
|           A_uv = exp(-max(0, age - T_b) / (gamma * T_b))                   |
|                                                                             |
|  Step 3  GRU memory update  (Eq. 3.21)                                     |
|           gru_input = [h_v(t-) || tau_dev, c_vW, seq_gap,                  |
|                        rho_v, id_mis, phi]   (38 elements)                  |
|           h_v(t) = GRU(gru_input)                                           |
|                                                                             |
|  Step 4  Message passing x L=2 rounds  (Eq. 3.22)                         |
|           over 3-node subgraph {reporter, link_src, link_dst}               |
|           h_v^(l+1) = ReLU(W^(l) * MEAN{h_u * A_uv} + b^(l))             |
|                                                                             |
|  Step 5  Anomaly score  (Eq. 3.23)                                         |
|           y_hat_v = sigmoid(w^T * h_v^(L) + b_score)                       |
|                                                                             |
|  Step 6  Alert if y_hat_v >= theta_FS = 0.40                               |
|           -> write to tgn_alerts.json                                       |
|                                                                             |
|  Writes: tgn_events.csv, tgn_summary.csv, tgn_alerts.json                  |
+-----------------------------------------------------------------------------+
                                 |
                                 |  tgn_alerts.json
                                 v
+-----------------------------------------------------------------------------+
|                  BLOCKCHAIN  (Hyperledger Fabric)                           |
|                                                                             |
|  Node.js client reads tgn_alerts.json                                       |
|  Submits each alert via PBFT consensus                                      |
|  Chaincode (temporalecho.go) stores alert immutably                         |
|  trust.go decrements trust score for flagged node                           |
+-----------------------------------------------------------------------------+
```

---

## 6. Layer 0 — NS-3 Simulation

**File:** `routing.cc` (140,000+ lines)  
**Role:** Generates all events. Every subsequent layer reads from what this produces.

### Attack timing example (TTW-S1)

```
t = 10.0s  ->  HELLO beacons exchanged V0 <-> V1
t = 10.0s  ->  V0 -> controller: <V0 sees V1, ts=10>   [LEGITIMATE]
t = 10.2s  ->  V0 stores old packet: <V0 sees V1, ts=10>
t = 15.0s  ->  V1 moves away; physical link V0<->V1 breaks
t = 20.0s  ->  V0 forges ts: <V0 sees V1, ts=20>
t = 20.0s  ->  V0 -> controller: forged packet  [ATTACK INJECTED]
               pem_attack_injection_time = 20.0
               pem_attack_active = true
t = 20.05s ->  PEM detection check fires (50ms delay)
```

### Key in-RAM data structures (plain C++ structs, not radio packets)

```cpp
// What the controller BELIEVES about the topology
std::map<std::string, TopologyPacket> ttw_controller_table;
// key = "srcId_seenId"  e.g. "0_1" = "node 0 claims to see node 1"

struct TopologyPacket {
    uint32_t src_id;     // who is reporting
    uint32_t seen_id;    // who they claim to see
    double   timestamp;  // claimed observation time
    bool     is_forged;  // true if the attacker tampered this
};

// Liveness table for BSHH
std::map<uint32_t, HeartbeatPacket> bshh_controller_liveness_table;

struct HeartbeatPacket {
    uint32_t claimed_sender_id;  // whose identity the heartbeat claims
    uint32_t physical_sender_id; // who actually transmitted it
    double   timestamp;          // time of original heartbeat
    bool     is_replayed;        // true = stored replay
};

// Echo reports for ME
std::vector<MEEchoReport> me_echo_reports;

struct MEEchoReport {
    uint32_t link_src;       // V1 (real link endpoint)
    uint32_t link_dst;       // V2 (real link endpoint)
    uint32_t false_reporter; // V3 or V4 (fake witness)
    double   timestamp;
    bool     is_echo;        // always true for forged echo
};
```

### Radio packet types (NS-3 Tags — travel over the air)

| Tag class | What it carries | Used for |
|-----------|----------------|---------|
| CustomDataTag1 | Node ID, position (x,y,z), velocity, acceleration, neighbour list, timestamp | Topology beacon (V2V, V2R) |
| CustomHeartbeatTag | claimed_sender_id, timestamp, is_replayed | Liveness heartbeat (BSHH) |
| CustomMetaDataUnicastTag0 | Aggregated topology from RSU | RSU -> Controller over CSMA |

### The universal event struct (PemEvent)

Every event in the system is captured as a `PemEvent`:

```cpp
struct PemEvent {
    PemEventType type;             // BEACON / TOPOLOGY_UPDATE / HEARTBEAT
    uint32_t physical_sender_id;  // who actually sent the packet over the air
    uint32_t claimed_sender_id;   // who the packet claims it came from
    uint32_t reporter_id;         // who forwarded it to the controller
    uint32_t link_src_id;         // topology link endpoint A
    uint32_t link_dst_id;         // topology link endpoint B
    double   sender_timestamp;    // tau_s: timestamp inside the packet
    double   reception_timestamp; // tau_r: when it arrived at the detector
    bool     attack_label;        // ground truth: true = forged event
    bool     triggered[9];        // which PEM signatures fired
    double   score;               // PEM weighted score (Eq. 3.12)
    bool     alert_raised;        // true if score >= PEM_SCORE_THRESHOLD
    double   detection_latency_ms;// tau_r - pem_attack_injection_time
};
```

---

## 7. Layer 1 — PEM

**What "PEM score" means:** PEM stands for Performance Evaluation Metrics in the codebase
and also names the lightweight real-time detection layer. The **PEM score** is the
**weighted detection score s(e)** from Eq. 3.12. It is a simple rule-based number —
**not** a neural network output.

```
s(e) = sum over i=0..8 of  w_i * 1[sig_i(e) fired]     (Eq. 3.12)

w_i      = PEM_WEIGHTS[i] = 1/9 for all i
threshold = PEM_SCORE_THRESHOLD = 0.075

Alert fires when s(e) >= 0.075
```

### Important: PEM alert decision is a logical OR of the 9 signatures

```
Weight per signature:  1/9 = 0.111
Alert threshold:       0.075

0.111 > 0.075  ->  any single signature firing already exceeds the threshold
```

The **binary alert_raised flag** is based on s(e) alone (the 9-signature sum). Because
0.111 > 0.075, one fired signature always suffices — co-firing raises the numeric score
but does not change whether the alert fires. The report must not describe this as
"graduated combined evidence" for the alert decision.

### Temporal pressure term

PEM also computes a **total reported score** that adds exponentially-decayed pressure
from recent events:

```
temporalPressure = sum over past events e'  in 200ms window:
                     score(e') * exp(-age(e') / tau_decay)

tau_decay = PEM_DECAY_TAU_S = 200ms
cap       = 30% of full weighted score

Total reported score = s(e) + min(temporalPressure * 0.05, 0.30)
```

This total score appears in pem_event_log.csv and informs the detection latency metric.
The temporal pressure is **not** part of the alert_raised decision — that uses s(e)
alone. Therefore the "single signature suffices" property holds for the alert decision
even when temporal pressure is non-zero.

### The 9 PEM signatures

| Index | What it checks | Caught attack |
|-------|---------------|---------------|
| 0 (TTW-S1) | `|recv_time - sender_ts| > T_b + epsilon = 110ms` | TTW (all variants) |
| 1 (TTW-S2) | Current sender_ts < previous sender_ts from same node | TTW-S2 (sequence regression) |
| 2 (TTW-S3) | Same link reported by two reporters with timestamp gap > T_b | TTW-S3 (cross-reporter) |
| 3 (BSHH-S1) | Two heartbeats with same claimed_sender but different physical_sender | BSHH (identity hijack) |
| 4 (BSHH-S2) | heartbeat_ts < last known ts for this identity | BSHH (stale replay) |
| 5 (BSHH-S3) | Heartbeat arrived for identity with no prior beacon in window | BSHH (ghost liveness) |
| 6 (ME-S1) | reporter_count > density bound (Eq. 3.8): `(1+mu) * 2 * r_comm * lambda_hat` | ME (all variants) |
| 7 (ME-S2) | Path count for a link increased by more than Delta_max in one update | ME-S2 (path explosion) |
| 8 (ME-S3) | Reporter's position is outside 300m range of both link endpoints | ME-S3 (impossible witness) |

---

## 8. Layer 2 — Cryptographic Pre-Filter

**File:** `tgn_detector.cc` — function `TGN_ApplyCryptoFilter()`  
**Paper:** Algorithm 3 — LW-MITIGATE, Section 4.4

Runs after the simulation, before the TGN. Discards events eliminable by cryptographic
rules alone.

### Rule 1 — Eq. 3.15 Freshness Check

```
PASS condition:  |tau_r - tau_s| <= T_b + epsilon = 110ms

tau_r = reception_timestamp  (when packet arrived at detector)
tau_s = sender_timestamp     (claimed time inside packet)
T_b   = 100ms                (beacon interval)
epsilon = 10ms               (propagation tolerance)

DROP if |tau_r - tau_s| > 110ms  (packet is too stale to be legitimate)
```

- Catches **BSHH-S1 and BSHH-S2**: stored heartbeat has tau_s from seconds ago
- Does NOT catch TTW: attacker forges tau_s = current time so |tau_r - tau_s| ≈ 0

### Rule 2 — Eq. 3.16 Nonce Novelty

```
PASS condition:  triplet (reporter_id, claimed_sender_id, tau_s) not seen before

DROP if same triplet already appeared  (exact replay)
```

Proxy for real cryptographic nonces. The same (reporter, sender, timestamp) triplet
cannot appear twice.

### Rule 3 — Eq. 3.17 Key Revocation

```
After the first TGN alert fires:
  - Attacker's physical_sender_id added to revoked set
  - All future events from revoked senders -> DROP
```

Mirrors LKH (Logical Key Hierarchy) revocation.

### Controller bypass

```
If physical_sender_id == 9999  ->  BYPASS all three rules (pass through unconditionally)
```

Controller insiders have valid signing keys. TGN is the only defence for scenarios 3,4,7,8,11,12.

### BSHH scenario split

| Scenario | Attacker | Filter outcome | Who detects it |
|----------|----------|----------------|----------------|
| BSHH-S5 (scenario 5) | Malicious vehicle | |tau_r - tau_s| >> 110ms -> **dropped by Rule 1** | Crypto pre-filter |
| BSHH-S6 (scenario 6) | Malicious RSU | |tau_r - tau_s| >> 110ms -> **dropped by Rule 1** | Crypto pre-filter |
| BSHH-S7 (scenario 7) | Malicious controller | 9999 -> **bypasses all rules** | TGN |
| BSHH-S8 (scenario 8) | Malicious controller + RSU | 9999 -> **bypasses all rules** | TGN |

**Output:** `crypto_filter_log.txt` — one line per dropped event with rule number and reason.

---

## 9. Layer 3 — TGN

**Files:** `tgn_detector.cc` (C++ inference), `tgn_train.py` (Python training)  
**Paper:** Section 3.4.3, Algorithm 2 (FS-DETECT), Equations 3.18-3.23, 3.34

The TGN models the vehicular network as a graph evolving through time. Each vehicle is
a node. Each topology event updates the node's memory via a GRU. Suspicious nodes score
near 1.0; normal nodes score near 0.0.

### Graph snapshot (Eq. 3.18)

```
G_t = (V_t, E_t, X_t, A_t)

V_t = vehicle nodes active at time t
E_t = reported links at time t
X_t = node feature matrix (5 features per node)
A_t = adjacency matrix weighted by edge freshness A_uv
```

### Edge freshness weight (Eq. 3.20)

```
A_uv(t) = exp( -max(0, age - T_b) / (gamma * T_b) )

age   = recv_time - tau_s       (how old the packet is)
T_b   = 0.1s                    (beacon interval = grace period)
gamma = 310 (urban), ~65 (highway)

Interpretation:
  age < T_b:    max(0, age-T_b) = 0  ->  A_uv = 1.0   (fully fresh)
  age = T_b:    stale_excess = 0     ->  A_uv = 1.0   (right at deadline, still fresh)
  age = 10s:    stale_excess = 9.9s  ->  A_uv = exp(-9.9/31) ≈ 0.726
  age = 30s:    stale_excess = 29.9s ->  A_uv = exp(-29.9/31) ≈ 0.382
```

**When the attacker does NOT update tau_s** (leaves the old timestamp), the stale
packet has large age so A_uv is low — the phantom link contributes little during message
passing. **When the attacker DOES update tau_s to the current time** (standard TTW as shown
in Section 3), age ≈ 0 so A_uv ≈ 1.0 (fully fresh-looking). In that case tau_deviation also
reads ≈ 0. The TGN then relies on seq_gap (the controller's replayed entry has a timestamp
that didn't monotonically increase) and the GRU's accumulated memory of the attack sequence.

---

## 10. Feature Vector — Every Element Explained

The TGN receives a 6-element vector for each event. In the paper these are x_v (Eq. 3.19,
Table 4.7) plus phi from Eq. 3.21:

```
gru_input = [ h_v(t-)  ||  tau_dev, beacon_count, seq_gap, reporter_count, id_mis, phi ]
             <--32 d-->     <------------------------  6  --------------------------->
             = 38 elements total  (called gs = dim + 6)
```

---

### Feature 1: tau_deviation (tau_dev)

**Paper notation:** First element of x_v (Table 4.7)  
**Formula:** `clip( (recv_time - tau_s) / T_b,  -50,  +50 )`  
**Units:** Number of beacon intervals  
**Computed in:** C++ `UpdateNodeMemory()`, Python `extract_features()`

What it measures: How stale the packet's claimed timestamp is, normalised by the beacon
interval.

```
tau_dev ≈ 0    -> packet arrived within one T_b of its timestamp -> looks fresh (benign)
tau_dev = 50   -> packet's tau_s is 50 x 100ms = 5 seconds old  -> strongly stale (TTW)
tau_dev = -50  -> packet claims a future timestamp               -> anomalous
```

Why NOT raw tau_s: Absolute timestamps don't generalise across simulation runs.
tau_deviation is scale-free.

---

### Feature 2: beacon_count (c_v^W)

**Paper notation:** c_v^W (second element of x_v)  
**Formula:** Count of events from `claimed_sender_id` in last W_max=430 window entries  
**Units:** Integer count  
**Computed in:** C++ `TGN_ExtractFeatures()` via `g_beacon_windows[]`

What it measures: How active this node has been recently. A well-established node has
been sending beacons for the past 43 seconds (one link lifetime = 430 beacons).

**Why read from CSV, not recomputed in Python:** C++ updates the window with BOTH BEACON
events AND TOPOLOGY_UPDATE events. BEACON events produce no CSV row. Python recomputing
from CSV alone would miss all BEACON contributions and produce counts of 5-10 instead of 430.

---

### Feature 3: seq_gap (delta_s_v)

**Paper notation:** delta_s_v (third element of x_v)  
**Formula:** `max(0, last_tau_s[node] - current_tau_s)`  
**Units:** Seconds  
**Computed in:** C++ `TGN_ExtractFeatures()` via `g_last_sender_ts[]`

What it measures: Whether the sender's timestamp went backwards vs the previous event
from the same node.

```
seq_gap = 0      -> timestamps are monotonically increasing -> normal
seq_gap = 5.0    -> current tau_s is 5s earlier than the previous one -> TTW-S2 replay
```

**Why read from CSV, not recomputed in Python:** In a concatenated multi-run CSV, a run N
attack event (tau_s=0) may follow a run N-1 attack event (tau_s=0) after sorting, giving
seq_gap=0 instead of the correct value. C++ computes this fresh each run.

---

### Feature 4: reporter_count (rho_v)

**Paper notation:** rho_v (fourth element of x_v)  
**Formula:** Number of distinct nodes that have claimed to observe link (link_src, link_dst)  
**Units:** Integer count  
**Computed in:** C++ `TGN_ExtractFeatures()` via `g_link_reporters[]`

What it measures: How many distinct nodes reported the same link. The expected count from
honest reporting is bounded by Eq. 3.8:

```
Expected max reporters = (1 + mu) * 2 * r_comm * lambda_hat
```

A count much higher than this bound signals fake witnesses.

**RSU-path and controller-sentinel special case:** When `physical_sender_id >= N_Vehicles`
(which covers both RSU node IDs and the 9999 controller sentinel), tracking `reporter_id`
would collapse everything to one node. Instead the code tracks `claimed_sender_id`. A
malicious RSU injecting V3 and V4 as false witnesses produces claimed_sender=V3 then V4,
raising the count to 2. Controller-sentinel events (9999) follow the same path: the
controller fabricates entries attributed to multiple claimed senders (V3, V4), raising
the count correctly.

---

### Feature 5: identity_mismatch (iota_v)

**Paper notation:** iota_v (fifth element of x_v)  
**Formula:** `1.0 if (physical_sender_id != claimed_sender_id) AND not RSU-path AND physical_sender_id != 9999, else 0.0`  
**Units:** Binary (0.0 or 1.0)  
**Computed in:** C++ `TGN_ExtractFeatures()`

```
identity_mismatch = 0.0  -> sender is who they say they are -> normal
identity_mismatch = 1.0  -> V2 transmits packet claiming to be from V1 -> BSHH signal
```

**RSU suppression:** When the RSU legitimately forwards a vehicle's data,
`physical_sender_id = RSU` and `claimed_sender_id = V_x`. This is NOT impersonation.
The code suppresses `identity_mismatch` to 0.0 for RSU-path events.

**Controller sentinel suppression:** When `physical_sender_id = 9999`, also suppressed
to 0.0 because no real transmitter exists.

---

### Feature 6: phi

**Paper notation:** phi(delta_t_v) from Eq. 3.21  
**Formula:** `log(1 + delta_t / T_b)` where `delta_t = recv_time - last_event_time_for_node`  
**Units:** Dimensionless (log-scaled)  
**Computed in:** C++ `UpdateNodeMemory()`, Python `extract_features()`

What it measures: How long the node was silent before this event.

```
delta_t = T_b = 0.1s   -> phi = log(2) ≈ 0.693   -> steady rhythm (one event per interval)
delta_t = 0            -> phi = 0                 -> back-to-back events
delta_t = 10s          -> phi = log(101) ≈ 4.615  -> node was silent for 10 seconds
```

**Why log-scaled:** Compresses range [0, many seconds] into a manageable numeric range.  
**Why recomputed in Python:** phi depends on consecutive event times for the same node.
Iteration order changes after sorting, so it cannot be stored in CSV.

---

### What is NOT in the feature vector

| Excluded | Reason |
|----------|--------|
| Raw node ID (id_v) | Model would memorise "node 3 is always attacker" instead of learning temporal patterns. Excluded per Table 4.7. |
| Raw tau_s (absolute timestamp) | Does not generalise across runs. Replaced by tau_deviation. |
| PEM score | Separate parallel detector output. Including it would make TGN learn to follow PEM rather than learning from raw temporal features. |

---

## 11. TGN Internal Computations Step by Step

### Step 0 — Zero-initialise new nodes (Eq. 3.34)

```
First time a node appears:
  h_v(t-) = zero vector of dimension 32

This is the cold-start state. GRU updates it as events arrive.
```

### Step 1 — GRU temporal memory update (Eq. 3.21)

```
Inputs:
  h      = h_v(t-)     (current memory, 32-dimensional)
  phi    = log(1 + delta_t / T_b)

Build GRU input (38 elements):
  gru_input = [h || tau_dev, beacon_count, seq_gap, reporter_count, id_mis, phi]

GRU gates:
  z = sigmoid( Wz * gru_input + Uz * h + bz )    <- update gate
  r = sigmoid( Wr * gru_input + Ur * h + br )    <- reset gate
  n = tanh(    Wn * gru_input + Un * (r . h) + bn ) <- candidate

New memory:
  h_v(t) = (1 - z) . h  +  z . n

Weight matrix sizes:
  Wz, Wr, Wn:  each (32 x 38)  -- how features influence gates
  Uz, Ur, Un:  each (32 x 32)  -- how prior memory influences gates
  bz, br, bn:  each (32,)       -- biases
```

The update gate z decides how much new information to incorporate. A node that suddenly
shows anomalous features gets z ≈ 1, and its memory shifts dramatically.

### Step 2 — Message passing (Eq. 3.22)

```
Active subgraph: {reporter_node, link_src, link_dst}

Adjacency:
  adj[reporter_node][link_dst] = A_uv  (from Step 0 of ProcessEvent)
  adj[link_dst][reporter_node] = A_uv  (symmetric)

For each round l = 0, 1:
  For each active node v:
    aggregate = MEAN{ h_u^(l) * A_uv : u in neighbours(v) }
    h_v^(l+1) = ReLU( W^(l) * aggregate + b^(l) )

Layer weights:
  W^(0), W^(1):  each (32 x 32)
  b^(0), b^(1):  each (32,)
```

After 2 rounds, reporter_node's embedding h_v^(2) has absorbed link-neighbour information
weighted by freshness. When the attacker does not update the timestamp, A_uv is low for the
phantom link and message passing discounts the false topology evidence. When the timestamp is
forged to current time, A_uv ≈ 1.0 and the detection relies instead on seq_gap and the
GRU's accumulated memory across the attack event sequence.

### Step 3 — Anomaly score (Eq. 3.23)

```
y_hat_v(t) = sigmoid( w^T * h_v^(2) + b_score )

w       = 32-dimensional scoring vector (learned)
b_score = scalar bias (initialised to -0.85 so default score ≈ 0.3)

Alert fires if y_hat_v(t) >= theta_FS = 0.40
```

### Step 4 — Variant classification head (Section 4.7)

```
logits  = Wcls * h_v^(2) + b_cls    (shape: 3)
variant = argmax(logits)             -> 0=TTW, 1=BSHH, 2=ME

Wcls:  (3 x 32)
b_cls: (3,)
```

Trained jointly with the binary scorer using cross-entropy loss weighted at 0.3.

### Weight file byte layout (tgn_weights.bin)

All values are float64 (8 bytes each), row-major order:

```
[4 bytes int32: dim=32]
[4 bytes int32: layers=2]
Wz   (32 x 38 = 1216 float64 values = 9728 bytes)
Uz   (32 x 32 = 1024 float64 values = 8192 bytes)
bz   (32 float64 = 256 bytes)
Wr   (32 x 38)    Ur   (32 x 32)    br   (32,)
Wn   (32 x 38)    Un   (32 x 32)    bn   (32,)
W_layers[0]  (32 x 32)    b_layers[0]  (32,)
W_layers[1]  (32 x 32)    b_layers[1]  (32,)
w_score  (32 float64 values)
b_score  (1 float64 scalar)
Wcls     (3 x 32 = 96 float64 values = 768 bytes)
b_cls    (3 float64 values = 24 bytes)
```

**Critical:** C++ and Python must both use `gs = dim + 6 = 38`. If C++ used `gs = dim + 7`
while Python used `gs = dim + 6`, then `Wz` would load as a (32x39) matrix from a file
storing (32x38) — every subsequent matrix reads 32 doubles at the wrong offset. All
weights are silently corrupted. This was the root cause of TTW tgn_alert=0.

---

## 12. Training Pipeline

### Step 1 — Generate training data

```bash
bash generate_training_data.sh \
  --sim_time 30       \
  --n_vehicles 200    \
  --seeds "1 2 3"     \
  --outdir training_data_v2/
```

Runs all 13 scenarios (0=baseline, 1-12=attacks) and concatenates their
`tgn_events.csv` files into one `all_events.csv`.

### Step 2 — What all_events.csv contains

| Column | What it contains |
|--------|-----------------|
| sim_time_s | Simulation time of the event |
| recv_time_s | tau_r: when the detector received it |
| claimed_ts_s | tau_s: timestamp inside the packet |
| claimed_sender_id | Who the packet claims it came from |
| physical_sender_id | Who actually sent it (9999 for controller) |
| reporter_id | Who forwarded it to the controller |
| link_src_id | Link endpoint A |
| link_dst_id | Link endpoint B |
| beacon_count | Pre-computed c_v^W (C++ sliding window) |
| seq_gap | Pre-computed delta_s_v (timestamp regression) |
| reporter_count | Pre-computed rho_v (distinct reporters) |
| identity_mismatch | Pre-computed iota_v (0 or 1) |
| edge_freshness | Pre-computed A_uv value |
| is_attack | Ground truth: 1=forged, 0=benign |
| attack_scenario | 0-12 |
| pem_score | PEM weighted score (NOT used as TGN feature) |
| pem_alert | PEM alert 0 or 1 |
| tgn_score | Filled during inference (empty during training generation) |
| tgn_alert | Filled during inference |

### Step 3 — Train/val/test split

**Stratified 70/15/15** per scenario per class:

```
For each attack_scenario in 0..12:
  For each class (0=benign, 1=attack):
    Sort events by recv_time_s
    First 70%  -> train
    Next  15%  -> val
    Final 15%  -> test
```

**Why not a naive time-based split?** Attack events happen late in simulation time
(e.g. t=20s), benign events start from t=0. A naive 70/30 time split would put ALL
attack events into test and ALL benign into train — the model would never see attacks
during training.

### Step 4 — Loss function

```
total_loss = BCE_loss + 0.3 * CE_loss + 0.5 * margin_loss

BCE_loss    = BCEWithLogitsLoss(pos_weight = n_benign / n_attack)
              Penalises false negatives proportionally to class imbalance.

CE_loss     = CrossEntropyLoss (attack events only)
              Trains the variant classification head (TTW/BSHH/ME).

margin_loss = max(0, MARGIN - (mean_score(attacks) - mean_score(benign)))
              MARGIN = 0.35
              Forces the class score distributions apart.
              When gap < 0.35, gradient simultaneously pulls attack scores UP
              and benign scores DOWN.
              BCE alone cannot do this — it only cares about individual labels,
              not relative position between the two distributions.
```

**Why dynamic pos_weight instead of fixed 2.0:**  
`pos_weight = n_benign / n_attack` uses the actual ratio. If you have 300 benign and
100 attack events, the correct weight is 3.0. A fixed 2.0 underweights attack events
whenever you have more benign data than expected.

### Step 5 — Restart logic

```
MAX_RESTARTS   = 5
TARGET_VAL_MCC = 0.975

Each attempt:
  1. Reinitialise model with random weights
  2. Train for --epochs epochs
  3. Track global_best_state across ALL attempts
  4. If val_bestMCC >= 0.975: stop early

After all attempts:
  Restore global_best_state (the best weights across all 5 attempts)
```

The global-best tracker outside the loop is critical: without it, if attempt 2 reaches
MCC=1.0 but attempt 3 starts (because stop condition wasn't met) and gets MCC=0.9, the
final model would use attempt 3's worse weights.

### Step 6 — Threshold selection

```
Sweep theta in [0.001, 0.999] on validation set
Choose theta that maximises MCC

Secondary check: gap midpoint between min(attack_scores) and max(benign_scores)
Both methods must agree within TOLERANCE = 0.15

Final theta_FS saved to tgn_weights.bin and used during inference
```

### Step 7 — Deploy

```bash
./waf --run "scratch/tgn_detector \
  --simTime=60 --N_Vehicles=200 \
  --attack_scenario=1            \
  --tgn_weights=tgn_weights.bin  \
  --tgn_theta=0.40               \
  --tgn_l_link=43"
```

---

## 13. Layer 4 — Blockchain

### Flow

```
tgn_alerts.json
     |
     v
submitToFabric.js  (Node.js client)
     |  connects to Hyperledger Fabric peer
     |  submits transaction via PBFT consensus
     v
temporalecho.go  (Go chaincode)
     |  stores alert: {node_id, attack_type, score, timestamp} immutably
     v
trust.go  (Go chaincode)
     |  decrements trust score for flagged node_id
     |  node blocklisted when trust < threshold
     v
eventListener.js  (Node.js)
     |  listens for ledger events
     |  alerts dashboard / other nodes
```

### What tgn_alerts.json contains

```json
[
  {
    "node_id": 0,
    "attack_type": "TTW",
    "score": 0.873,
    "timestamp_s": 20.05,
    "detection_latency_ms": 50.2,
    "scenario": 1
  }
]
```

**Why blockchain?** The SDN controller could itself be compromised (scenarios 3,4,7,8,11,12).
If alert records were stored only on the controller, a malicious controller could delete or
modify them. Blockchain storage is tamper-evident: once a block is committed, it cannot be
changed without invalidating the entire subsequent chain.

---

## 14. How Each Attack Is Detected

### TTW (Scenarios 1-4)

| Detection layer | Mechanism |
|----------------|-----------|
| PEM signature 0 | |recv_time - tau_s| > 110ms fires if attacker didn't update the timestamp |
| PEM signature 1 | tau_s < prev_tau_s fires for TTW-S2 (sequence regression) |
| PEM signature 2 | Cross-reporter timestamp gap fires for TTW-S3 |
| Crypto pre-filter | Drops if |tau_r - tau_s| > 110ms AND attacker left timestamp unforged |
| TGN | **If timestamp not forged:** tau_deviation large + low A_uv both catch the stale packet. **If timestamp forged to current time:** tau_deviation ≈ 0 and A_uv ≈ 1.0 (normal-looking); TGN detects via seq_gap and GRU memory of the attack sequence |
| TTW-S3/S4 | Controller bypass (9999) means TGN is primary detector; seq_gap fires because the controller's internal replay has a timestamp that went backwards |

### BSHH (Scenarios 5-8)

| Detection layer | Mechanism |
|----------------|-----------|
| PEM signature 3 | Two heartbeats with same claimed_sender but different physical_sender |
| PEM signature 4 | Heartbeat timestamp went backwards for this identity |
| PEM signature 5 | Heartbeat from identity with no prior beacon in window |
| Crypto pre-filter | BSHH-S5 and S6: |tau_r - tau_s| >> 110ms -> dropped by Eq.3.15 |
| TGN | BSHH-S7 and S8 bypass crypto (9999); identity_mismatch=1.0 is primary TGN signal |

### ME (Scenarios 9-12)

| Detection layer | Mechanism |
|----------------|-----------|
| PEM signature 6 | reporter_count > density bound (Eq. 3.8) |
| PEM signature 7 | Path count for link jumped by more than Delta_max |
| PEM signature 8 | Reporter physically outside 300m range of link endpoints |
| TGN | reporter_count feature is primary signal; for controller scenarios GRU learns sudden topology inflation pattern |

---

## 15. Output Files Reference

| File | Written by | Contents |
|------|-----------|---------|
| pem_event_log.csv | PEM (routing.cc) | Per-event: sim_time, event_type, physical_sender, claimed_sender, triggered_sigs, score, alert_raised, detection_latency_ms |
| pem_run_summary.csv | PEM (routing.cc) | Per-run: tp, tn, fp, fn, mcc, auroc, tdet_ms, pdr_under_attack_pct, pdr_post_mitigation_pct, te2e_ms |
| crypto_filter_log.txt | Crypto pre-filter | Per-dropped-event: timestamp, sender IDs, rule number, reason |
| tgn_events.csv | TGN (tgn_detector.cc) | Per-event: 6 features + edge_freshness + tgn_score + tgn_alert + variant |
| tgn_summary.csv | TGN (tgn_detector.cc) | Per-run: tp, tn, fp, fn, mcc, auroc, tdet_ms |
| tgn_alerts.json | TGN (tgn_detector.cc) | Alert objects submitted to blockchain |
| tgn_weights.bin | tgn_train.py | Binary weight checkpoint (float64, see Section 11 for layout) |
| routing-animation.xml | NS-3 (routing.cc) | NetAnim visualisation |
| channel_delivery_analysis.csv | NS-3 (routing.cc) | Per-channel tx_count, rx_count, avg_fanout |
| optimization_link_lifetime_data.csv | NS-3 (routing.cc) | Link lifetime data for ML optimisation |

### Detection quality targets

```
MCC   > 0.85
AUROC > 0.90
Tdet  < 100ms  (within the 100ms beacon budget)
PDR post-mitigation significantly higher than PDR under attack
```

---

## 16. Key Numbers Quick Reference

| Parameter | Value | Formula / Source |
|-----------|-------|-----------------|
| Beacon interval T_b | 100 ms | IEEE 802.11p |
| DSRC range r_comm | 300 m | TTW_COMM_RANGE |
| PEM weight per signature | 1/9 = 0.111 | Uniform, 9 signatures |
| PEM alert threshold | 0.075 | PEM_SCORE_THRESHOLD |
| PEM temporal decay | 200 ms | PEM_DECAY_TAU_S |
| Crypto freshness window | 110 ms | T_b + epsilon (Eq. 3.15) |
| GRU embedding dimension d | 32 | TGN_DIM |
| GRU input size gs | 38 | d + 6 = 32 + 5 features + phi |
| Message-passing rounds L | 2 | TGN_LAYERS |
| TGN alert threshold | 0.40 | TGN_THETA_FS (auto-tuned on val) |
| gamma (edge decay, urban) | 310 | (L_link/2) / (T_b * ln2) = (43/2)/(0.1*0.693) |
| W_max (beacon window, urban) | 430 | ceil(L_link / T_b) = ceil(43/0.1) |
| L_link urban | 43 s | Expected link lifetime, urban |
| gamma (highway) | ~65 | (9/2) / (0.1 * 0.693) = 4.5/0.0693 ≈ 64.9 |
| W_max (highway) | 90 | ceil(9/0.1) |
| Margin loss MARGIN | 0.35 | Minimum required score gap between class means |
| Margin loss lambda | 0.50 | Weight of margin term relative to BCE |
| Variant CE weight | 0.30 | Weight of classification term relative to BCE |
| Train/val/test split | 70/15/15 | Stratified per scenario per class |
| Max training restarts | 5 | MAX_RESTARTS |
| Target val MCC to stop | 0.975 | TARGET_VAL_MCC |
| Blockchain consensus | PBFT | Hyperledger Fabric |

**Note on gamma vs W_max:** Both use L_link as input but serve completely different purposes.
gamma controls how fast A_uv (edge freshness) decays in message passing.
W_max controls how many beacons fit in the sliding window for counting beacon_count.
They are derived from different formulas with different denominators (T_b*ln2 vs T_b).

---

## 17. Glossary of All Special Terms

| Term | What it means |
|------|--------------|
| **PEM score** | The weighted detection score s(e) from Eq. 3.12. A simple rule-based number = sum of weights of fired signatures. NOT a neural network output. Alert fires at >= 0.075. |
| **PEM** | Performance Evaluation Metrics — codebase name for the lightweight rule-based detection layer. Also names PemEvent struct and output files. |
| **TGN score** | Output of sigmoid(w^T * h_v^(L) + b_score) — the neural network's anomaly score in (0,1). Alert fires at >= theta_FS = 0.40. |
| **theta_LW** | PEM alert threshold = 0.075. LW = lightweight. |
| **theta_FS** | TGN alert threshold = 0.40. FS = FS-DETECT (Algorithm 2). Auto-tuned on validation set. |
| **tau_s** | Sender timestamp — the timestamp inside the packet (what the sender claims). Column `claimed_ts_s` in CSV. |
| **tau_r** | Reception timestamp — when the packet actually arrived at the detector. Column `recv_time_s` in CSV. |
| **tau_deviation** | clip((tau_r - tau_s) / T_b, -50, 50). How stale the packet is, in beacon intervals. First TGN feature. |
| **c_v^W** | beacon_count — events from node v in the last W_max=430 window entries. Second TGN feature. |
| **delta_s_v** | seq_gap — how much the sender's timestamp went backwards compared to the previous event from same node. Third TGN feature. |
| **rho_v** | reporter_count — number of distinct nodes that claimed to observe the same link. Fourth TGN feature. |
| **iota_v** | identity_mismatch — 1.0 if physical sender != claimed sender (BSHH signal), else 0.0. Fifth TGN feature. |
| **phi** | Time-elapsed encoding log(1 + delta_t/T_b). How long node was silent before this event. Sixth TGN input. |
| **A_uv** | Edge freshness weight = exp(-max(0, age-T_b) / (gamma*T_b)). How fresh the link evidence is. 1.0=fresh, approaches 0 for stale. |
| **gamma** | Edge decay constant for A_uv. Urban: 310. Highway: ~65. Formula: (L_link/2)/(T_b*ln2). |
| **W_max** | Beacon sliding window capacity. Urban: 430. Highway: 90. Formula: ceil(L_link/T_b). |
| **L_link** | Expected link lifetime in seconds. Urban: 43s. Highway: 9s. Calibration parameter. |
| **T_b** | Beacon interval = 100ms (IEEE 802.11p). |
| **gs** | GRU input size = dim + 6 = 32 + 6 = 38. |
| **dim** | GRU embedding dimension = 32 (d in the paper). |
| **MCC** | Matthews Correlation Coefficient. Range [-1, +1]. 1.0 = perfect. 0.0 = random. |
| **AUROC** | Area Under ROC Curve. 1.0 = perfect. 0.5 = random. |
| **Tdet** | Detection latency = first_alert_time - attack_injection_time (milliseconds). |
| **PDR** | Packet Delivery Ratio — fraction of packets reaching their destination. |
| **Te2e** | End-to-end latency in milliseconds. |
| **TTW** | Topology Time-Warp attack. |
| **BSHH** | Beacon State Heartbeat Hijack attack. |
| **ME** | Multipath Echo attack. |
| **V2V** | Vehicle-to-Vehicle (DSRC direct). |
| **V2R** | Vehicle-to-RSU (DSRC). |
| **R2C** | RSU-to-Controller (CSMA Ethernet). |
| **DSRC** | Dedicated Short-Range Communication. IEEE 802.11p standard, 5.9 GHz band. |
| **CCH** | Control Channel — DSRC Channel 178 (5.890 GHz). All safety beacons and heartbeats. |
| **SCH** | Service Channel — the other 6 DSRC channels. |
| **RSU** | Road-Side Unit. Fixed infrastructure node that relays vehicle beacons to controller. |
| **SDVN** | Software-Defined Vehicular Network. SDN controller centralises routing decisions. |
| **SDN controller** | Builds the topology table and installs routing entries. Primary attack target. |
| **physical_sender_id** | NS-3 node ID that actually transmitted the packet over the air. |
| **claimed_sender_id** | Node ID that the packet claims to be from (may differ in BSHH). |
| **9999 sentinel** | Special value for physical_sender_id in controller-origin events (scenarios 3,4,7,8,11,12). Bypasses all crypto filter rules. |
| **pem_all_events** | C++ std::vector<PemEvent> — accumulator of all events during a simulation run. Passed to TGN pipeline after simulation ends. |
| **GRU** | Gated Recurrent Unit. Recurrent neural network cell for temporal memory. Three gates: update (z), reset (r), candidate (n). |
| **margin loss** | Loss term max(0, 0.35 - (mean_attack_score - mean_benign_score)). Forces class score distributions apart. Fixes gap_width=0. |
| **gap_width** | Distance between min(attack scores) and max(benign scores). If > 0, a perfect threshold exists. If = 0, classes overlap. |
| **pos_weight** | BCEWithLogitsLoss parameter = n_benign/n_attack. Makes missed attacks cost pos_weight times more than false alarms. |
| **PBFT** | Practical Byzantine Fault Tolerance. Consensus algorithm used by Hyperledger Fabric. |
| **LKH** | Logical Key Hierarchy. Key management scheme for node revocation (Eq. 3.17). |
| **TBPTT** | Truncated Backpropagation Through Time. Gradients propagated through at most 100 consecutive events per node before detaching. Prevents exploding gradients. |
| **Xavier initialisation** | Weight init: W ~ Uniform(-sqrt(6/(rows+cols)), +sqrt(6/(rows+cols))). Keeps gradient variance stable. |
| **SUMO** | Simulation of Urban MObility. External traffic simulator generating vehicle movement traces used by NS-3. |
| **NetAnim** | NS-3 network animation visualiser. Reads routing-animation.xml. |
| **waf** | NS-3 build system. Always run from ~/ns-allinone-3.35/ns-3.35/. |
| **detection_enabled** | Boolean flag in routing.cc. When false, PEM logs scores but never raises alerts — used to measure unmitigated damage for PDR comparison. |
| **pem_attack_injection_time** | Simulation timestamp when the forged packet was first sent. Used to compute Tdet. |
| **stale_excess** | max(0, age - T_b) — the age of a packet beyond the one-beacon-interval grace period. Used inside A_uv formula. |
