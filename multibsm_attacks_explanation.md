# Multi-BSM Position Falsification Attack — Code and Output Explanation

**File:** `multibsm_attacks.cc`  
**Based on:** Trabelsi et al., *Electronics* 2022, 11, 3282  
**Simulator:** NS-3.35 (standalone scratch file)  
**Scenario IDs:** 13 (Type 1), 14 (Type 2), 15 (Type 3), 0 (Baseline)

---

## 1. Overview

This standalone NS-3.35 simulation models three **BSM (Basic Safety Message) position falsification attacks** in a Software-Defined Vehicular Network (SDVN). An attacker vehicle manipulates its reported GPS position in the BSMs it broadcasts, attempting to deceive the Road-Side Unit (RSU) and, through it, the SDN controller. The simulation uses **real NS-3 UDP packet forwarding with NS-3 Tag objects**, matching the tag-based architecture used in `routing.cc`.

### Attack Families

| Scenario ID | Attack Type | Mechanism |
|---|---|---|
| 0 | Baseline | No attack — all BSMs report true GPS positions |
| 13 | Type 1 — Fixed Position | Attacker always reports a hardcoded coordinate `(1000, 2000)` regardless of true position |
| 14 | Type 2 — Random Position | Attacker injects a fresh uniformly-random coordinate in every BSM |
| 15 | Type 3 — Stealthy (Delayed) | Attacker behaves legitimately for 20 s, then freezes its reported position at the last real coordinate while continuing to move and report non-zero speed |

---

## 2. Network Topology

```
Vehicle_0 (attacker) ──┐
Vehicle_1              ├── P2P links ──► RSU_0 ──► (detection + PEM)
Vehicle_2              │
  ...                  │
Vehicle_5 ─────────────┘
```

- **P2P star topology**: each vehicle connects to the RSU via a dedicated Point-to-Point link (`1 Gbps`, `1 ms` delay).
- **Internet stack** installed on all nodes (`InternetStackHelper`).
- **IP addressing**: vehicle *i* gets `10.1.(i+1).1/30`; RSU gets `10.1.(i+1).2/30` on each link. Global routing (`Ipv4GlobalRoutingHelper::PopulateRoutingTables()`) ensures all vehicles can reach the RSU at `g_rsu_ip_anim`.
- **BSM Port:** `7777` (UDP).

---

## 3. Packet Tag Architecture — `BsmTag`

### Why NS-3 Tags?

In `routing.cc`, all DSRC communications use NS-3 Tag subclasses (`CustomDataTag1`, `CustomHeartbeatTag`, etc.) attached to `Ptr<Packet>` objects and transmitted over real simulated radio links. This simulation follows the same pattern: every BSM is encoded as a real NS-3 UDP packet carrying a **`BsmTag`**, sent over the P2P network, and received by the RSU via a socket callback.

### `BsmTag` Definition (45 bytes)

```cpp
class BsmTag : public Tag {
    // Serialized layout (45 bytes total):
    uint32_t m_vehicleId;    // 4 bytes — NS-3 global node ID of sender
    double   m_posX;         // 8 bytes — reported X position (m)
    double   m_posY;         // 8 bytes — reported Y position (m)
    double   m_speed;        // 8 bytes — reported speed (m/s)
    double   m_direction;    // 8 bytes — reported heading (rad)
    double   m_timestamp;    // 8 bytes — simulation time of transmission (s)
    uint8_t  m_isFalsified;  // 1 byte  — 0=legitimate, 1=forged
};
```

**Key NS-3 Tag methods implemented:**
- `GetTypeId()` — registers `"BsmTag"` with the NS-3 type system
- `GetSerializedSize()` — returns 45 (fixed)
- `Serialize(TagBuffer)` — writes all fields to the wire buffer
- `Deserialize(TagBuffer)` — reads all fields from the wire buffer
- `Print(ostream)` — human-readable debug output

### Packet Flow

```
Vehicle (MBSM_SendBsm)
    │
    │  Socket::CreateSocket(vehicle_node, UdpSocketFactory)
    │  sock->Connect(InetSocketAddress(g_rsu_ip_anim, BSM_PORT=7777))
    │  pkt->AddPacketTag(BsmTag{...})
    │  sock->Send(pkt)
    │
    ▼  [travels through P2P link + IP routing]
    │
RSU (MBSM_RSUSocketReceive — bound on port 7777)
    │
    │  pkt = sock->Recv()
    │  pkt->PeekPacketTag(BsmTag tag)
    │  → reconstruct BsmRecord from tag fields
    │  → call MBSM_RSUReceive(bsm)
    ▼
Detection + PEM accounting
```

### Socket Setup (in `MBSM_SetupNetworkForAnim`)

```cpp
// RSU receive socket — listens for all incoming BsmTag packets
g_rsu_recv_socket = Socket::CreateSocket(
    RSU_Nodes.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
g_rsu_recv_socket->SetRecvCallback(MakeCallback(&MBSM_RSUSocketReceive));
```

---

## 4. BSM Tick Scheduler — `MBSM_BsmTick`

Each vehicle has a periodic callback (`MBSM_BsmTick`) that fires every `BSM_INTERVAL_S = 0.05 s` (20 Hz). On each tick:

1. `GetKinematics(node, px, py, spd, dir)` reads the node's current mobility model position and velocity.
2. An DSRC range check (`InRSURange(px, py)`) determines whether the vehicle is within `DSRC_RANGE_M = 250 m` of the RSU.
3. If in range, the appropriate send function is called:
   - **Attacker node** → `MBSM_SendType1/2/3` (depending on scenario)
   - **Legitimate node** → `MBSM_SendLegit`
4. `MBSM_SendBsm(veh_idx, posX, posY, speed, dir, is_falsified)` creates and sends the `BsmTag` UDP packet.
5. The next tick is scheduled with `Simulator::Schedule(Seconds(BSM_INTERVAL_S), &MBSM_BsmTick, ...)`.

---

## 5. Attack Send Functions

### Type 1 — Fixed Position (`MBSM_SendType1`)
```
Reported:  pos = (T1_FIXED_X=1000, T1_FIXED_Y=2000) — never changes
           speed = real speed (from mobility model)
Range check: uses REAL position (attacker can be in range even with fake pos)
is_falsified: true
```

### Type 2 — Random Position (`MBSM_SendType2`)
```
Reported:  pos = (rand_x, rand_y) — new uniform random in [0, SIM_AREA_MAX] each BSM
           speed = real speed
is_falsified: true
```

### Type 3 — Stealthy (`MBSM_SendType3`)
```
Phase 1 (now < T3_legit_duration=20s):
    Reported pos = real GPS  →  is_falsified = false
    g_t3_freeze_x/y updated every tick

Phase 2 (now >= 20s):
    Reported pos = (g_t3_freeze_x, g_t3_freeze_y)  →  is_falsified = true
    Speed still reports real non-zero value → CONTRADICTION detected
```

### Legitimate (`MBSM_SendLegit`)
```
Reported: pos = real GPS, speed = real speed
is_falsified: false
```

---

## 6. Detection — `MBSM_Detect`

The RSU runs physics-based detection on every received BSM. Two triggers:

### Trigger A — Frozen Position + Non-Zero Speed
```
Condition: speed_reported > 0.1 m/s
       AND |pos_reported - pos_last_reported| < FREEZE_DIST_THRESHOLD_M (0.5 m)
       AND time since last BSM >= 2 * BSM_INTERVAL_S

Catches: Type 1 (fixed pos never moves), Type 3 Phase 2 (frozen pos + moving)
```

### Trigger B — Impossible Displacement
```
Condition: |Δpos_reported| > speed_reported * Δt * DISPLACEMENT_FACTOR (1.5)

Catches: Type 2 (random pos creates impossible jumps)
```

A detected anomaly sets `anomaly_raised = true` and returns to `MBSM_RSUReceive` for PEM accounting.

---

## 7. PEM Accounting

After detection, `MBSM_RSUReceive` updates four counters:

```
is_attack=true,  detected=true  → pem_tp++  (True Positive)
is_attack=true,  detected=false → pem_fn++  (False Negative — missed attack)
is_attack=false, detected=true  → pem_fp++  (False Positive — false alarm)
is_attack=false, detected=false → pem_tn++  (True Negative — correct pass)
```

**MCC (Matthews Correlation Coefficient):**
```
MCC = (TP×TN − FP×FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
```

**Detection Latency (Tdet):** time from `pem_attack_start_time` to `pem_first_alert_time`.

---

## 8. Output Files

| File | Description |
|---|---|
| `multibsm_attack13.txt` | Step-by-step human-readable event log for scenario 13 |
| `multibsm_attack14.txt` | Step-by-step event log for scenario 14 |
| `multibsm_attack15.txt` | Step-by-step event log for scenario 15 |
| `multibsm_baseline.txt` | Log for baseline (scenario 0) |
| `multibsm_events.csv` | Per-BSM event log: `sim_time_s, vehicle_id, reported_pos_x, reported_pos_y, speed_ms, direction_rad, is_attack, alert_raised` |
| `multibsm_pem_summary.csv` | Per-run summary: `attack_scenario, tp, tn, fp, fn, mcc, acr_pct, precision, recall, tdet_ms` |
| `multibsm_anim_scenario{N}.xml` | NetAnim visualization (node colors: attacker=red, legitimate=green, RSU=amber) |

---

## 9. Simulation Results

### Run command
```bash
./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=13"
./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=14"
./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=15"
```

### Results Summary

| Scenario | TP | TN | FP | FN | MCC | ACR | Tdet |
|---|---|---|---|---|---|---|---|
| 13 — Fixed position | 712 | 1575 | 0 | 1 | **0.999** | 99.956% | 51 ms |
| 14 — Random position | 708 | 1575 | 0 | 5 | **0.995** | 99.781% | 51 ms |
| 15 — Stealthy freeze | 315 | 1973 | 0 | 0 | **1.000** | 100.000% | 1 ms |

### Interpretation

**Scenario 13 (Fixed):** The RSU detects 712 out of 713 falsified BSMs. One miss (FN=1) occurs at the very first falsified packet before the position history is established. After that, the frozen-position trigger fires on every subsequent BSM. MCC=0.999 confirms near-perfect detection.

**Scenario 14 (Random):** 5 misses (FN=5) occur when the randomly-generated fake position happens to be close enough to the previous fake position that the displacement check doesn't fire. Since the position is uniform-random in a 500×500m grid, most fake positions produce impossible jumps — only ~0.7% slip through. MCC=0.995.

**Scenario 15 (Stealthy):** Perfect detection (MCC=1.000). The freeze trigger fires at the very first BSM in Phase 2 (t=20s, Tdet=1ms): the attacker reports a non-zero speed (12 m/s) but a frozen position — immediate physical contradiction. The legitimate phase produces zero false positives.

**Zero false positives in all scenarios**: Legitimate vehicles with real mobility data never trigger either detection rule.

---

## 10. NetAnim Visualization

Open `multibsm_anim_scenario13.xml` (or 14/15) in NetAnim to see:
- **Red node** = attacker (V0) sending forged BSMs
- **Green nodes** = legitimate vehicles sending real BSMs
- **Amber node** = RSU receiving and processing all BSMs
- **Packet arrows** = real UDP packets carrying `BsmTag` over P2P links (visible because `EnablePacketMetadata(true)` is set)

---

## 11. Key Design Decisions

| Decision | Rationale |
|---|---|
| Real NS-3 Tags (`BsmTag`) instead of direct function calls | Matches `routing.cc` architecture; supervisor requirement; packets visible in NetAnim |
| P2P star topology instead of DSRC 802.11p | Standalone file — no WAVE module dependency; P2P correctly models V2R communication for attack analysis |
| `InRSURange()` check before sending | Ensures only vehicles within DSRC_RANGE=250m can reach the RSU, preserving physical realism |
| Pre-populated Tl history in Trigger A | RSU needs a minimum of 2 historical BSMs from a vehicle before it can detect freezing; first BSM always stored, not checked |
| Phase 1 legitimate behaviour (Type 3) | Demonstrates why the stealthy attack is harder to detect with non-physics-based methods; by the time Phase 2 starts, the RSU has built a trusted history |

---

*Department of EIE, University of Ruhuna — FYP: Temporal-Echo Topology Poisoning in SDVNs*
