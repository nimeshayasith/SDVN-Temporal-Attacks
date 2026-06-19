# Link Latency Attack (LLA) — Code and Output Explanation

**File:** `attack_link_latency.cc`  
**Based on:** Soltani et al., *Security Analysis of SDN Topology Discovery Mechanism and Defense Proposal*, CNSM 2021  
**Simulator:** NS-3.35 (standalone scratch file)  
**Scenario IDs:** 0 (baseline), 16 (Full LLA), 17 (Relay only), 18 (Basic LFA), 19 (Gradual LFA)

---

## 1. Overview

This standalone NS-3.35 simulation models four **Link Latency Attack (LLA)** variants against an SDN network's topology discovery mechanism. The attacks target **TopoGuard+**, a well-known SDN topology defence. A second defence, **MLLG (Multi-Layer Link Guard)**, is implemented alongside TopoGuard+ to demonstrate how its additional checks close the gaps that TopoGuard+ alone cannot cover.

All LLDP events are transmitted as real NS-3 UDP packets carrying a custom NS-3 Tag (`LldpTag`), following the same tag-based packet architecture used in `routing.cc`. This makes every LLDP event visible as a packet arrow in NetAnim and ensures the controller processes events on reception — not by direct function call.

---

## 2. Background: How TopoGuard+ Works

TopoGuard+ uses the **Link Latency Inspector (LLI)** to validate every LLDP topology advertisement:

```
Tl = TLLDP − Tp1 − Tp2           (Eq. 1: Link Latency)
Th = Q3 + 3 × (Q3 − Q1)          (Eq. 2: Adaptive threshold — IQR fence on Tl history)

ALARM if Tl > Th
```

Where:
- `TLLDP` = total time for the LLDP probe to travel from controller → switch1 → (path) → switch2 → controller
- `Tp1`, `Tp2` = probe RTTs to switch1 and switch2 respectively (measured separately)
- `Tl` = the residual link latency (should match the physical inter-switch link delay)
- `Th` = adaptive upper threshold computed from the IQR of the last 20 `Tl` observations

**Legitimate baseline:**
- `TLLDP_LEGIT = 6 ms` (ctrl→s1: 0.5ms + s1→s2: 5ms + s2→ctrl: 0.5ms)
- `Tp = 1 ms` each
- `Tl = 6 − 1 − 1 = 4 ms`
- `Th = 4 ms` (all history = 4ms → IQR=0 → `Th = 4 + 3×0 = 4 ms`)

---

## 3. Network Topology

```
                    ┌──── h1 (compromised host at s1)
ctrl ─── s1 ─── s2 ─── s3 ─── h2 (compromised host at s3)
  └──────────────────────────────────────┘  (OOB relay path h1→h2: 10ms)
```

| Link | Delay |
|---|---|
| ctrl ↔ s1, s2, s3 | 0.5 ms (control plane) |
| s1 ↔ s2, s2 ↔ s3 | 5 ms (data plane) |
| s1 ↔ h1, s3 ↔ h2 | 5 ms (host–switch) |
| h1 ↔ h2 (OOB relay) | 10 ms |

**Note:** There is **no physical link** between s1 and s3. Any LLDP claiming s1↔s3 is fabricated.

---

## 4. Attack Scenarios

### Scenario 16 — Full LLA (Overload + Relay)

**Goal:** Convince the controller that a direct link exists between s1 and s3.

**Phase 1 — Overload (t=5s):**  
h1 and h2 launch an ARP flood against s1 and s3, inflating their probe RTTs from 1ms to 130ms.  
Effect on legitimate LLDP: `Tl = 6 − 130 − 130 = −254 ms` (deeply negative).  
Since `Tl (−254) < Th (4)`, TopoGuard+ does NOT alarm → **TG FAILS**.  
MLLG detects via `NEG_TL` (Tl < 0) and `HIGH_TP` (Tp=130ms > 50ms threshold).

**Phase 2 — Relay (t=11s, every 5s):**  
h2 relays a forged LLDP claiming s1↔s3. With overload active:  
`Tl_relay = 21 − 130 − 130 = −239 ms < Th` → **TG FAILS**.  
MLLG fires `NEG_TL|HIGH_TP` on every relay → fake link detected.

**Outcome:** TopoGuard+ bypassed throughout. MLLG detects every relay injection (FN=0).

---

### Scenario 17 — Relay Only (No Overload)

**Goal:** Test whether a relay alone (without overload) can evade TopoGuard+.

**What happens:**  
No overload → `Tp = 1ms` (normal). Relay `TLLDP = 21ms`.  
`Tl_relay = 21 − 1 − 1 = 19 ms > Th=4 ms` → **TG ALARMS** on first 4 relays. ✓

However, the relay's `Tl=19ms` values enter the IQR history (depth=20). After 5 relay injections, exactly 25% of the window (5/20) contains 19ms values, causing `Q3` to jump from 4ms to 19ms. The IQR formula gives `Th = 19 + 3×(19−4) = 64 ms`. From the 5th relay onward: `Tl=19 < Th=64` → **TG FAILS**.

**MLLG:** Fires `HIGH_TL` (Tl=19ms > 8ms) on **every** relay event — immune to threshold drift.  
**Outcome:** MLLG achieves perfect MCC=1.000. This shows MLLG's fixed-threshold checks are more robust than TopoGuard+'s adaptive IQR for persistent relay attacks.

---

### Scenario 18 — Basic LFA (Direct Data-Plane Injection)

**Goal:** h1 directly injects an LLDP into the data plane claiming s1↔s3.

**Attack path:**  
`ctrl→s1` (0.5ms) + `s1→h1` (5ms) + `h1→s3` (10ms) + `s3→ctrl` (0.5ms) = `TLLDP=16ms`  
`Tl = 16 − 1 − 1 = 14 ms > Th=4 ms` → **TG ALARMS immediately**.  
MLLG also fires `HIGH_TL` (14ms > 8ms).

**Outcome:** Both defences detect with MCC=1.000. Fake link: NOT accepted.  
This scenario shows why the attacker needs overload (scenario 16) or gradual inflation (scenario 19) — a direct injection is trivially detected.

---

### Scenario 19 — Gradual LFA (Threshold Inflation + Relay)

**Goal:** Slowly inflate `Th` over multiple injection batches so the final relay passes undetected.

**Phase 1 — Gradual injection (t=10s to t=30s, 5 batches of 3):**

| Batch | Time | Injected Tl | Th before | Th after |
|---|---|---|---|---|
| 1 | t=10s | 5 ms | 4 ms | 4 ms |
| 2 | t=15s | 6 ms | 4 ms | 8 ms |
| 3 | t=20s | 7 ms | 8 ms | 12 ms |
| 4 | t=25s | 8 ms | 12 ms | 16 ms |
| 5 | t=30s | 9 ms | 16 ms | 20 ms |

Each batch's second event causes a TH_DRIFT (Th increase > 2ms) → MLLG fires.

**Phase 2 — Relay (t=35s):**  
`Tl_relay = 19 ms < Th=20 ms` → **TG PASSES** (attack succeeds at TopoGuard+ level).  
MLLG fires `HIGH_TL` (19ms > 8ms) → relay is still caught by MLLG.

**Outcome:** TopoGuard+ successfully bypassed. MLLG detects via `HIGH_TL` and `TH_DRIFT`.

---

## 5. Packet Tag Architecture — `LldpTag`

### Why NS-3 Tags?

Following the architecture of `routing.cc` (which uses `CustomDataTag1`, `CustomMetaDataUnicastTag0`, etc.), every LLDP event in this simulation is encoded as an NS-3 `LldpTag` attached to a real `Ptr<Packet>`. The packet is sent from the appropriate source node (switch or compromised host) to the controller via the P2P network. The controller's receive callback then extracts the tag and runs the TopoGuard+/MLLG algorithms — exactly as a real SDN controller would process incoming LLDP messages.

### `LldpTag` Definition (34 bytes)

```cpp
class LldpTag : public Tag {
    // Serialized layout (34 bytes total):
    uint32_t m_sw1Idx;     // 4 bytes — index of switch 1 (0=s1, 1=s2, 2=s3)
    uint32_t m_sw2Idx;     // 4 bytes — index of switch 2
    double   m_tlldpMs;    // 8 bytes — measured TLLDP (ms)
    double   m_tp1Ms;      // 8 bytes — probe RTT to sw1 (ms)
    double   m_tp2Ms;      // 8 bytes — probe RTT to sw2 (ms)
    uint8_t  m_isAttack;   // 1 byte  — 0=legitimate, 1=forged LLDP
    uint8_t  m_eventType;  // 1 byte  — 0=LEGIT, 1=RELAY_FAKE, 2=BASIC_LFA, 3=GRADUAL_INJECT
};
```

**NS-3 Tag interface methods implemented:**
- `GetTypeId()` — registers `"LldpTag"` with the NS-3 type system
- `GetSerializedSize()` — returns 34
- `Serialize(TagBuffer)` — writes all fields using `WriteU32`, `WriteDouble`, `WriteU8`
- `Deserialize(TagBuffer)` — reads all fields in the same order
- `Print(ostream)` — human-readable debug output

### Packet Flow

```
Source node (switch or host)  [LLA_SendLldpPacket()]
    │
    │  sock = Socket::CreateSocket(src_node, UdpSocketFactory)
    │  sock->Connect(InetSocketAddress(ctrl_ip, LLDP_PORT=6633))
    │  pkt = Create<Packet>(0)
    │  pkt->AddPacketTag(LldpTag{sw1, sw2, tlldp, tp1, tp2, isAttack, evType})
    │  sock->Send(pkt); sock->Close()
    │
    ▼  [travels through P2P links + IP routing]
    │
Controller  [LLA_CtrlReceive() — bound on port 6633]
    │
    │  pkt = sock->Recv()
    │  pkt->PeekPacketTag(LldpTag tag)
    │  r = RunLLI(tag.GetTlldpMs(), tag.GetTp1Ms(), tag.GetTp2Ms(), tag.GetIsAttack())
    │  AccountPEM(r)
    │  LogEvent(...)
    ▼
Detection result + PEM accounting
```

### Controller Socket Setup (in `LLA_SetupNetworkForAnim`)

```cpp
g_ctrl_recv_socket = Socket::CreateSocket(
    g_Controller_Nodes.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
g_ctrl_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), LLDP_PORT));
g_ctrl_recv_socket->SetRecvCallback(MakeCallback(&LLA_CtrlReceive));
```

### Sender Nodes per Event Type

| Event | Sender Node | Reason |
|---|---|---|
| `LLDP_LEGIT` | `g_Switch_Nodes.Get(sw1_idx)` | Switch initiates legitimate LLDP probe |
| `LLDP_RELAY_FAKE` | `g_Host_Nodes.Get(1)` (h2) | h2 is at s3 — final hop of the OOB relay |
| `LLDP_BASIC_LFA` | `g_Host_Nodes.Get(0)` (h1) | h1 injects directly from s1 into data plane |
| `LLDP_GRADUAL_INJECT` | `g_Host_Nodes.Get(0)` (h1) | h1 injects incremental Tl values |

### How Malicious Timestamps Are Created — New Packets, Not Modified Packets

**The attacker does NOT intercept and modify existing LLDP packets.** Instead, for every attack event the attacker calls `LLA_SendLldpPacket(...)` which creates a **brand new NS-3 packet** with a **fabricated `m_tlldpMs` value** chosen by the attacker:

```cpp
Ptr<Packet> pkt = Create<Packet>(0);    // brand new empty packet
LldpTag tag;
tag.SetTlldpMs(tlldp_ms);              // ← attacker-controlled fake TLLDP value
tag.SetTp1Ms  (tp1_ms);
tag.SetTp2Ms  (tp2_ms);
tag.SetIsAttack(1);
pkt->AddPacketTag(tag);
sock->Send(pkt);                        // inject into network
```

The `m_tlldpMs` field in the tag is not a physically measured time — it is a value the attacker chooses to make `Tl = TLLDP − Tp1 − Tp2` land where the attack requires:

| Scenario | What the attacker puts in `m_tlldpMs` | Why |
|---|---|---|
| **16** — Full LLA | `TLLDP_RELAY_FAKE_MS = 21 ms` (hardcoded) | Models the physical OOB relay path delay; with overload Tp=130ms, `Tl = 21−130−130 = −239ms < Th` → TG passes |
| **17** — Relay only | `TLLDP_RELAY_FAKE_MS = 21 ms` (same) | Without overload, `Tl = 21−1−1 = 19ms`; initially exceeds Th=4ms but Th adapts as history fills |
| **18** — Basic LFA | `TLLDP_BASIC_FAKE_MS = 16 ms` (hardcoded) | Models direct host→switch path delay; `Tl = 16−1−1 = 14ms > Th=4ms` → immediately detected |
| **19** — Gradual LFA | `tlldp_syn = fake_tl_ms + Tp1 + Tp2` (reverse-calculated) | Attacker **chooses desired Tl first**, then back-calculates TLLDP: `tlldp_syn = target_tl + 1 + 1`; each batch inflates Th step by step |

The Scenario 19 reverse-calculation (line 638 in the source) is the clearest demonstration of timestamp fabrication:

```cpp
// LLA_GradualLFA_Inject(double fake_tl_ms)
double tlldp_syn = fake_tl_ms + tp1 + tp2;
// e.g. for batch 3: fake_tl_ms=7ms → tlldp_syn = 7 + 1 + 1 = 9ms
// Controller computes: Tl = 9 − 1 − 1 = 7ms  ← exactly what attacker wanted
```

The controller has no way to verify whether the `TLLDP` value in the tag reflects a real physical measurement. It reads the field, computes `Tl`, and updates its topology accordingly — trusting the packet entirely.

---

## 6. TopoGuard+ LLI Implementation — `RunLLI`

```cpp
LLI_Result RunLLI(double tlldp_ms, double tp1_ms, double tp2_ms, bool is_attack) {
    r.tl_ms = tlldp_ms - tp1_ms - tp2_ms;          // Eq. 1

    RecordTlSample(r.tl_ms);                        // add to sliding history (depth=20)
    r.th_ms = ComputeThreshold(g_tl_history);       // Eq. 2: Q3 + 3*(Q3-Q1)

    r.topoguard_alarm = (r.tl_ms > r.th_ms);        // TopoGuard+ alarm

    r.mllg_neg_tl  = (r.tl_ms < 0.0);              // MLLG check 1
    r.mllg_high_tp = (tp1 > 50ms || tp2 > 50ms);   // MLLG check 2
    r.mllg_high_tl = (r.tl_ms > 8.0);              // MLLG check 3
    r.mllg_th_drift = (r.th_ms - g_prev_th > 2.0); // MLLG check 4
    r.mllg_alarm = any of the above;
}
```

**Tl history:** Pre-populated with 20 samples of `TL_LEGIT_BASELINE_MS = 4ms`.  
**`TL_HISTORY_DEPTH = 20`:** Sliding window; oldest sample removed when new one added.

### MLLG Four Checks

| Check | Threshold | Catches |
|---|---|---|
| `NEG_TL` | Tl < 0 | Scenario 16 (overloaded probes make Tl negative) |
| `HIGH_TP` | Tp > 50 ms | Scenario 16 (ARP flood inflates Tp to 130ms) |
| `HIGH_TL` | Tl > 8 ms | Scenarios 17, 18, 19 relay (Tl=19ms exceeds fixed bound) |
| `TH_DRIFT` | Th increase > 2ms per event | Scenario 19 gradual inflation (each batch step) |

---

## 7. Key Constants

| Constant | Value | Meaning |
|---|---|---|
| `TLLDP_LEGIT_MS` | 6.0 ms | Legitimate s1↔s2 LLDP time |
| `TLLDP_RELAY_FAKE_MS` | 21.0 ms | Relay s1↔s3 (via OOB) LLDP time |
| `TLLDP_BASIC_FAKE_MS` | 16.0 ms | Basic LFA injection time |
| `PROBE_RTT_NORMAL_MS` | 1.0 ms | Normal probe RTT |
| `PROBE_RTT_OVERLOADED_MS` | 130.0 ms | Overloaded probe RTT (ARP flood) |
| `TL_LEGIT_BASELINE_MS` | 4.0 ms | `= TLLDP_LEGIT − 2×Tp_normal` |
| `MLLG_TP_THRESHOLD_MS` | 50.0 ms | HIGH_TP alarm threshold |
| `MLLG_TL_HIGH_MS` | 8.0 ms | HIGH_TL alarm threshold |
| `MLLG_TH_DRIFT_MS` | 2.0 ms | TH_DRIFT alarm per event |
| `TL_HISTORY_DEPTH` | 20 | IQR window size |
| `LLDP_PORT` | 6633 | UDP port for LLDP→controller packets |

---

## 8. Output Files

| File | Description |
|---|---|
| `lla_attack16.txt` | Detailed event log for scenario 16 |
| `lla_attack17.txt` | Detailed event log for scenario 17 |
| `lla_attack18.txt` | Detailed event log for scenario 18 |
| `lla_attack19.txt` | Detailed event log for scenario 19 |
| `lla_baseline.txt` | Event log for baseline (scenario 0) |
| `lla_events.csv` | Per-event CSV log |
| `lla_pem_summary.csv` | Per-run PEM metrics (one row per detector per scenario) |
| `lla_anim_scenario{N}.xml` | NetAnim XML (ctrl=blue, switches=grey, hosts=orange) |

**`lla_events.csv` columns:**
`sim_time_s, event_type, sw1_id, sw2_id, tl_ms, th_ms, tp1_ms, tp2_ms, topoguard_alarm, mllg_alarm, mllg_reason, is_attack_event`

**`lla_pem_summary.csv` columns:**
`attack_scenario, detector, tp, tn, fp, fn, mcc, tdet_ms, fake_link_accepted, fake_link_accept_time`

---

## 9. Simulation Results

### Run commands
```bash
./waf --run "scratch/attack_link_latency --attack_scenario=16"
./waf --run "scratch/attack_link_latency --attack_scenario=17"
./waf --run "scratch/attack_link_latency --attack_scenario=18"
./waf --run "scratch/attack_link_latency --attack_scenario=19"
```

### Scenario 16 — Full LLA

| Detector | TP | TN | FP | FN | MCC | Tdet | Fake link |
|---|---|---|---|---|---|---|---|
| TopoGuard+ | 1 | 22 | 2 | 9 | 0.027 | 45005 ms | YES |
| MLLG | 10 | 4 | 20 | 0 | 0.236 | 5.5 ms | YES |

- TG FN=9: 9 relay injections pass because Tl is negative (< Th which is also negative/inflated).
- TG FP=2: After overload ends, Th is corrupted to −194ms; legit Tl=4ms > −194ms → false alarm.
- MLLG FP=20: Legitimate LLDP during overload has Tp=130ms > 50ms → MLLG correctly flags it as suspicious. These count as FP because the IS_ATTACK label is false (they are genuine LLDP, not injected relay packets).
- MLLG FN=0: Every single relay injection is caught. ✅

### Scenario 17 — Relay Only

| Detector | TP | TN | FP | FN | MCC | Tdet | Fake link |
|---|---|---|---|---|---|---|---|
| TopoGuard+ | 4 | 24 | 0 | 6 | 0.566 | 5.5 ms | YES |
| MLLG | 10 | 24 | 0 | 0 | **1.000** | 5.5 ms | YES |

- TG TP=4: First 4 relays detected (Tl=19 > Th=4). After 5th relay, Th jumps to 64ms → TG fails.
- MLLG: Perfect detection on every relay via HIGH_TL. Zero false positives.

### Scenario 18 — Basic LFA

| Detector | TP | TN | FP | FN | MCC | Tdet | Fake link |
|---|---|---|---|---|---|---|---|
| TopoGuard+ | 1 | 24 | 0 | 0 | **1.000** | 5.5 ms | NO |
| MLLG | 1 | 24 | 0 | 0 | **1.000** | 5.5 ms | NO |

Both defences detect immediately. Fake link rejected. ✅

### Scenario 19 — Gradual LFA

| Detector | TP | TN | FP | FN | MCC | Tdet | Fake link |
|---|---|---|---|---|---|---|---|
| TopoGuard+ | 4 | 24 | 0 | 12 | 0.408 | 5.5 ms | YES |
| MLLG | 7 | 24 | 0 | 9 | 0.564 | 5105 ms | YES |

- TG TP=4: First inject of each of batch 1 and partial batch 2 trigger TG before Th inflates. After Th=8ms, subsequent injects (Tl=6,7,8,9ms) pass TG.
- MLLG TP=7: TH_DRIFT fires at each batch step (4 detections) + HIGH_TL fires at batch 5 (2) + relay (1) = 7 TP.
- MLLG Tdet=5105ms: First detection at t=15.106s (TH_DRIFT). Attack start at t=10s. Latency=5.106s=5106ms. ✅

---

## 10. NetAnim Visualization

Open `lla_anim_scenario{N}.xml` in NetAnim to see:
- **Blue node** = controller
- **Grey nodes** = switches (s1, s2, s3)
- **Orange nodes** = hosts (h1 compromised at s1, h2 compromised at s3)
- **Packet arrows** = LldpTag UDP packets travelling from source to controller (visible because `EnablePacketMetadata(true)` is set and real NS-3 packets are sent via `LLA_SendLldpPacket`)

---

## 11. Key Design Decisions

| Decision | Rationale |
|---|---|
| Real NS-3 Tags (`LldpTag`) instead of direct `RunLLI()` calls | Matches `routing.cc` architecture; supervisor requirement; detection happens on reception at the controller, not at the sender |
| Detection moved to `LLA_CtrlReceive` callback | More realistic — the controller processes packets when they arrive; models real SDN LLDP processing |
| `RunLLI` takes explicit `tp1_ms, tp2_ms` parameters | Tag carries pre-encoded Tp values; callback is self-contained and does not need global `g_overload_active` state |
| All Tl values (including attack values) added to IQR history | Models a real adaptive TopoGuard+ that cannot distinguish legitimate from forged LLDP before running LLI; explains why scenario 19 (gradual) and scenario 17 (persistent relay) eventually corrupt Th |
| `g_fake_link_accepted` set when `is_attack && !topoguard_alarm` | Measures TopoGuard+ evasion specifically — demonstrates the paper's thesis that TopoGuard+ alone is insufficient |
| `TL_HISTORY_DEPTH = 20` | Paper's original window size; mathematically explains the IQR phase transition in scenarios 16 and 17 |

---

*Department of EIE, University of Ruhuna — FYP: Temporal-Echo Topology Poisoning in SDVNs*
