# CLAUDE.md — SDVN Temporal-Echo Topology Attack Implementation Guide

**Project:** A Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection: Countering Temporal-Echo Topology Poisoning Attacks in SDVNs
**Team:** Final Year Project — Department of EIE, University of Ruhuna
**Supervisor:** Dr. Nilmantha Wijesekara | Co-supervisor: Dr. Prabath Weerasingha
**Simulator:** NS-3.35 on Linux (Ubuntu)
**Main file:** `routing.cc` (place inside `ns-3.35/scratch/`)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository & File Structure](#2-repository--file-structure)
3. [Environment Setup (Linux + NS-3.35)](#3-environment-setup-linux--ns-335)
4. [Build & Run Instructions](#4-build--run-instructions)
5. [Code Architecture Summary](#5-code-architecture-summary)
6. [Attack Scenario Numbering System](#6-attack-scenario-numbering-system)
7. [Currently Implemented: TTW-S1 (attack_scenario = 4)](#7-currently-implemented-ttw-s1-attack_scenario--4)
8. [Performance Evaluation Metrics (PEM)](#8-performance-evaluation-metrics-pem)
9. [TTW Attack — All 4 Variants](#9-ttw-attack--all-4-variants)
10. [BSHH Attack — All 4 Variants](#10-bshh-attack--all-4-variants)
11. [ME Attack — All 4 Variants](#11-me-attack--all-4-variants)
12. [Implementation Workflow (One Attack at a Time)](#12-implementation-workflow-one-attack-at-a-time)
13. [Output Files Reference](#13-output-files-reference)
14. [Running Multiple Runs for Report Statistics](#14-running-multiple-runs-for-report-statistics)
15. [Common Errors & Fixes](#15-common-errors--fixes)
16. [DSRC/WAVE Communication and the 7 Channels](#16-dsrcwave-communication-and-the-7-channels)
17. [Two-Layer Architecture: Radio Tags vs Controller Structs](#17-two-layer-architecture-radio-tags-vs-controller-structs)
18. [Vehicle Mobility and SUMO Trace Files](#18-vehicle-mobility-and-sumo-trace-files)
19. [Full Communication Stack Reference](#19-full-communication-stack-reference)
20. [Data Transmission Functions Reference](#20-data-transmission-functions-reference)
21. [SimpleUdpApplication — How It Works](#21-simpleudpapplication--how-it-works)
22. [Node Roles and Architecture Modes](#22-node-roles-and-architecture-modes)
23. [Agent-Based Data Upload — send_LTE_data_agent and RSU_dataunicast_agent](#23-agent-based-data-upload--send_lte_data_agent-and-rsu_dataunicast_agent)

---

## 1. Project Overview

This project studies how an SDVN (Software-Defined Vehicular Network) controller can be misled when attackers reuse valid control-plane information at the wrong time, with the wrong identity, or through duplicated topology evidence.

### Three Attack Families

| Family | Full Name | Core Manipulation |
|--------|-----------|-------------------|
| **TTW** | Topology Time-Warp | Replay legitimate topology packets with forged/future timestamps after a link has physically broken |
| **BSHH** | Beacon State Heartbeat Hijack | Replay old heartbeat messages impersonating another vehicle's identity to falsify liveness state |
| **ME** | Multipath Echo | Duplicate/echo a real link observation through false reporters so the controller infers non-existent paths |

### Four Attacker Placement Scenarios (per attack)

| Scenario | Attacker Position | RSU Present? |
|----------|------------------|--------------|
| S1 | Malicious Vehicle | No |
| S2 | Malicious RSU | Yes |
| S3 | Malicious Controller | No |
| S4 | Malicious Controller | Yes |

**Total: 3 families × 4 placements = 12 attack variants**

### What the Framework Detects

The PEM (Performance Evaluation Metrics) layer — already implemented in `routing.cc` — computes:
- **MCC** (Matthews Correlation Coefficient)
- **AUROC** (Area Under ROC Curve)
- **Tdet** (Detection Latency in ms)
- **PDR** (Packet Delivery Ratio)
- **Te2e** (End-to-End Latency in ms)

---

## 2. Repository & File Structure

```
ns-3.35/
└── scratch/
    └── routing.cc           ← Main simulation file (140 000+ lines)

Project root/
├── CLAUDE.md                ← This file
├── README.md                ← High-level project guide
├── PEM_implementation_guide.md  ← PEM metrics explanation
├── routing.cc               ← Source (copy to scratch/)
├── Temporal_echo_project.pdf    ← Project proposal (primary reference)
├── Temporal_Echo_Reference_Papers.pdf
├── Kyber__Saber_V2Xsensors2506938v2.pdf
├── Top_Trust_adjou2022.pdf
├── Top_Selluth_s4159802643048z_1.pdf
└── A_certificateless_aggregate_signature_scheme_for_V.pdf
```

**Output files generated after simulation runs:**

| File | Contents |
|------|----------|
| `ttw_attack_scenario4.txt` | Human-readable TTW S1 attack log |
| `pem_event_log.csv` | Per-event detection log (all signatures, scores, alerts) |
| `pem_run_summary.csv` | Per-run summary (TP, TN, FP, FN, MCC, AUROC, Tdet) |
| `routing-animation.xml` | NetAnim visualization file |
| `optimization_link_lifetime_data.csv` | Link-lifetime data for optimization |

---

## 3. Environment Setup (Linux + NS-3.35)

### Step 1 — Verify NS-3.35 installation

```bash
cd ~/ns-3.35
./waf --version
# Expected output: Waf: Entering directory `...ns-3.35/build`
# or use ./ns3 if you have the newer build system
```

### Step 2 — Check required NS-3 modules are enabled

```bash
./waf --check-profile
```

The following modules must be present (check `src/` directory):
- `wave`
- `wifi`
- `lte`
- `aodv`
- `internet`
- `applications`
- `mobility`
- `netanim`
- `csma`
- `point-to-point`

If any module is missing, re-configure:

```bash
./waf configure --enable-examples --enable-tests
```

### Step 3 — Copy routing.cc into scratch

```bash
cp /path/to/routing.cc ~/ns-3.35/scratch/routing.cc
```

### Step 4 — Fix known compile issues before first build

Open `routing.cc` and fix these BEFORE compiling:

**Issue A — Stray text after namespace declaration**

Find and fix:
```cpp
// WRONG (causes compile error):
using namespace ns3;hjhjhj

// CORRECT:
using namespace ns3;
```

**Issue B — Hardcoded paths**

Search for `/home/nimesha/` and replace with your actual home directory:
```bash
grep -n "/home/nimesha/" scratch/routing.cc
# Replace each occurrence with your path, e.g. /home/yourname/
```

### Step 5 — Build

```bash
cd ~/ns-3.35
./waf build 2>&1 | tee build_log.txt
```

If errors appear, check `build_log.txt`. Common fixes are in [Section 15](#15-common-errors--fixes).

---

## 4. Build & Run Instructions

### Standard build

```bash
cd ~/ns-3.35
./waf build
```

### Run the currently implemented TTW-S1 attack (attack_scenario = 4)

```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=4"
```

### Run with more vehicles (realistic scenario)

```bash
./waf --run "scratch/routing --simTime=60 --N_Vehicles=10 --N_RSUs=0 --attack_scenario=4"
```

### Run with RSU infrastructure (for RSU-based attack variants)

```bash
./waf --run "scratch/routing --simTime=60 --N_Vehicles=10 --N_RSUs=2 --attack_scenario=6"
```

### Run baseline (no attack)

```bash
./waf --run "scratch/routing --simTime=60 --N_Vehicles=10 --N_RSUs=0 --attack_scenario=0"
```

### Command-line parameter reference

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `simTime` | 240 | Simulation duration (seconds) |
| `N_Vehicles` | 80 | Number of vehicle nodes |
| `N_RSUs` | 0 | Number of RSU nodes |
| `attack_scenario` | 0 | Attack ID (0 = none, see Section 6) |
| `malicious_vehicle_id` | 0 | Node ID of malicious vehicle |
| `victim_neighbor_id` | 1 | Node ID of victim vehicle |
| `routing_algorithm` | 4 | 0=ECMP, 2=QRSDN, 3=RLMR, 4=Proposed RL, 5=DCMR |
| `lambda` | 30 | Vehicle arrival rate |
| `maxspeed` | 80 | Max vehicle speed (km/h) |

### View results

```bash
cat ttw_attack_scenario4.txt          # Human-readable attack log
cat pem_run_summary.csv               # Detection metrics summary
cat pem_event_log.csv                 # Per-event log
# Open routing-animation.xml in NetAnim for visual replay
```

---

## 5. Code Architecture Summary

### Key global data structures in `routing.cc`

```cpp
// ── Topology table — what the controller BELIEVES ───────────────────────────
std::map<std::string, TopologyPacket> ttw_controller_table;
// key = "srcId_seenId"   value = most recent TopologyPacket

// ── Stored attacker packet (for replay attacks) ──────────────────────────────
TopologyPacket ttw_stored_packet;
bool           ttw_packet_stored = false;

// ── PEM state ────────────────────────────────────────────────────────────────
uint64_t pem_true_positive, pem_true_negative;
uint64_t pem_false_positive, pem_false_negative;
double   pem_attack_injection_time;   // when attack was injected
double   pem_first_alert_time;        // when first alert fired
bool     pem_attack_active;
bool     pem_mitigation_active;
```

### All Three Attack Struct Types

There are three structs for in-memory attack data (defined at lines ~164–247 in `routing.cc`). These are **not** NS-3 Tags — they are plain C++ structs that live only in RAM inside the controller or attacker node logic.

```cpp
// ── TTW and ME topology records ──────────────────────────────────────────────
struct TopologyPacket {
    uint32_t src_id;      // node reporting the link
    uint32_t seen_id;     // neighbor being reported
    double   timestamp;   // simulation time when link was observed
    bool     is_forged;   // true = attacker tampered this
};

// ── BSHH liveness records ────────────────────────────────────────────────────
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity this heartbeat claims
    uint32_t physical_sender_id;  // who actually transmitted it
    double   timestamp;           // time when heartbeat was originally generated
    bool     is_replayed;         // true = this is a stored replay
};

// ── ME echo injection records ─────────────────────────────────────────────────
struct MEEchoReport {
    uint32_t link_src;         // V1 (real link endpoint)
    uint32_t link_dst;         // V2 (real link endpoint)
    uint32_t false_reporter;   // V3 or V4 (fake witness)
    double   timestamp;
    bool     is_echo;          // always true for forged echo
};
```

All three structs are stored and still used — do not remove them.

### Attack control variables

```cpp
uint32_t attack_scenario      = 0;   // which attack to run
uint32_t malicious_vehicle_id = 0;   // V0 = attacker by default
uint32_t victim_neighbor_id   = 1;   // V1 = victim by default
bool is_malicious_controller  = false;
bool has_RSU_infrastructure   = false;
```

### Attack timing constants (TTW)

```cpp
static const double TTW_HELLO_TIME  = 10.0;  // t=10: HELLO exchange
static const double TTW_LINK_BREAK  = 15.0;  // t=15: physical link breaks
static const double TTW_REPLAY_TIME = 20.0;  // t=20: attacker replays forged packet
static const double TTW_COMM_RANGE  = 300.0; // 300m DSRC range
```

### PEM signature weights

```cpp
// 9 signatures: TTW(3) + BSHH(3) + ME(3)
static const double PEM_WEIGHTS[9] = {
    0.15, 0.15, 0.10,   // TTW-S1, TTW-S2, TTW-S3
    0.15, 0.10, 0.10,   // BSHH-S1, BSHH-S2, BSHH-S3
    0.10, 0.075, 0.075  // ME-S1, ME-S2, ME-S3
};
static const double PEM_SCORE_THRESHOLD = 0.12;
```

---

## 6. Attack Scenario Numbering System

Use these integer IDs for `attack_scenario` on the command line and in code.
**Add this enum near the attack parameters block in `routing.cc`:**

```cpp
// ── Attack Scenario ID Enum ───────────────────────────────────────────────────
// Add this after the existing attack parameter declarations
enum AttackScenarioId {
    ATTACK_NONE          = 0,

    // TTW family
    TTW_S1_MAL_VEH_NO_RSU     = 1,   // malicious vehicle, no RSU  ← IMPLEMENTED
    TTW_S2_MAL_RSU            = 2,   // malicious RSU
    TTW_S3_MAL_CTRL_NO_RSU    = 3,   // malicious controller, no RSU
    TTW_S4_MAL_CTRL_WITH_RSU  = 4,   // malicious controller, with RSU

    // BSHH family
    BSHH_S1_MAL_VEH_NO_RSU    = 5,   // malicious vehicle, no RSU
    BSHH_S2_MAL_RSU           = 6,   // malicious RSU
    BSHH_S3_MAL_CTRL_NO_RSU   = 7,   // malicious controller, no RSU
    BSHH_S4_MAL_CTRL_WITH_RSU = 8,   // malicious controller, with RSU

    // ME family
    ME_S1_MAL_VEH_NO_RSU      = 9,   // malicious vehicles, no RSU
    ME_S2_MAL_RSU             = 10,  // malicious RSU
    ME_S3_MAL_CTRL_NO_RSU     = 11,  // malicious controller, no RSU
    ME_S4_MAL_CTRL_WITH_RSU   = 12   // malicious controller, with RSU
};
```

> **Note:** The existing code uses `attack_scenario == 4` for what is logically TTW-S1. After you add the enum, remap it: the existing block should check `attack_scenario == TTW_S1_MAL_VEH_NO_RSU` (value = 1). Remap by changing the default at the top or by passing `--attack_scenario=1` on the command line.

---

## 7. Currently Implemented: TTW-S1 (attack_scenario = 4)

> **Current code label:** `attack_scenario == 4`
> **Logical name:** TTW-S1 — Malicious Vehicle, No RSU
> **Status:** ✅ FULLY IMPLEMENTED AND PEM-INSTRUMENTED

### What is already implemented

| Function | Role |
|----------|------|
| `TTW_InitLog()` | Opens `ttw_attack_scenario4.txt` and writes header |
| `TTW_SendHelloBeacon(sender, receiver)` | Step 1 — V2V HELLO exchange at t=10 |
| `TTW_SendTopologyUpdate(vehicle, seen_id, obs_time)` | Step 2 — legitimate topology update to controller |
| `TTW_StorePacket(src_id, dst_id, obs_time)` | Step 3 — attacker stores old valid packet |
| `TTW_ReplayAttack(attacker, victim, src_id, dst_id, forged_time)` | Steps 4+5+6 — forge timestamp, send to controller, log faulty routing |
| `TTW_RunReplayDetection(src_id, dst_id, linkDistance)` | PEM detection — runs 50ms after attack injection |

### Attack timeline

```
t = 10.0s  →  ① V2V HELLO exchange between V0 and V1
t = 10.0s  →  ② Legitimate topology updates sent to controller
               Controller table: <V0 sees V1, t=10> ACCEPTED
t = 10.2s  →  ③ V0 (attacker) stores old packet: <V0 sees V1, t=10>
t = 15.0s  →  Physical link between V0 and V1 breaks (V1 moves away)
t = 20.0s  →  ④ V0 forges timestamp: <V0 sees V1, t=20> MALICIOUS
t = 20.0s  →  ⑤ Forged packet sent to controller → ACCEPTED (controller deceived)
t = 20.0s  →  ⑥ Controller installs faulty route via ghost link V0↔V1
t = 20.05s →  PEM detection check fires (50ms delay)
               Score computed → alert raised → entry removed from controller table
```

### How to test it right now

```bash
cd ~/ns-3.35
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=4"
cat ttw_attack_scenario4.txt
cat pem_run_summary.csv
```

Expected `pem_run_summary.csv` values:
- `tp >= 1`, `fp = 0`, `mcc` close to 1.0, `auroc` close to 1.0
- `tdet_ms` around 50 ms (well within the 100 ms budget)

---

## 8. Performance Evaluation Metrics (PEM)

### PEM is already implemented. Every new attack must hook into it.

### The 9 detection signatures

```
Index  Name      Meaning
  0    TTW-S1    Reception timestamp minus sender timestamp > beacon interval + epsilon
  1    TTW-S2    Newer reception but older sender timestamp than a previous event (replay contradiction)
  2    TTW-S3    Same link reported by different reporters with timestamp gap > beacon interval
  3    BSHH-S1   Two heartbeats claim same identity but come from different physical senders
  4    BSHH-S2   Heartbeat sender_timestamp < previous heartbeat from same identity (out-of-order)
  5    BSHH-S3   Heartbeat arrived but no matching beacon seen for same identity in the window
  6    ME-S1     Reporter count for a link exceeds expected density: ρ > (1+μ)·2R·λ̂
  7    ME-S2     Path count for a link increases by more than Δmax in one update
  8    ME-S3     Reporter position is outside communication range of the reported link endpoints
```

### How to emit a PEM event for your new attack

**For a topology update (TTW or ME):**
```cpp
PemEmitEvent(
    PEM_EVENT_TOPOLOGY_UPDATE,
    physical_sender_id,    // who actually sent it
    claimed_sender_id,     // who the packet claims it came from
    reporter_id,           // who is forwarding to the controller
    link_src_id,           // link endpoint A
    link_dst_id,           // link endpoint B
    sender_timestamp,      // timestamp in the packet
    Simulator::Now().GetSeconds(),  // reception time
    reporterPosition,
    linkSrcPosition,
    linkDstPosition,
    true                   // true = this is an attack event
);
```

**For a heartbeat (BSHH):**
```cpp
PemEmitHeartbeatEvent(
    physical_sender_id,   // who physically sent it
    claimed_sender_id,    // whose identity is claimed (may differ for hijack)
    sender_timestamp,     // the timestamp inside the heartbeat
    true                  // attack label
);
```

**For a beacon (normal, benign):**
```cpp
PemEmitVehicleBeacon(sender_id, receiver_id);
// attack_label is always false for beacons
```

### Marking attack start and mitigation

```cpp
// At the moment the attack packet is injected:
pem_attack_injection_time = Simulator::Now().GetSeconds();
pem_attack_active = true;
pem_mitigation_active = false;

// PemRecordObservation handles first_alert_time automatically
// when alertRaised = true for an actualAttack = true event.
```

### CSV outputs

After a complete simulation run, check these files:

- **`pem_event_log.csv`** — one row per PEM event. Columns: `sim_time_s`, `event_type`, `physical_sender_id`, `claimed_sender_id`, `triggered_signatures`, `score`, `alert_raised`, `phase`, `detection_latency_ms`
- **`pem_run_summary.csv`** — one row per run. Columns: `tp`, `tn`, `fp`, `fn`, `mcc`, `auroc`, `tdet_ms`, `pdr_under_attack_pct`, `pdr_post_mitigation_pct`, `te2e_under_attack_ms`, `te2e_post_mitigation_ms`

---

## 9. TTW Attack — All 4 Variants

### Understanding TTW

> A malicious node stores a legitimate topology packet `<V_src sees V_dst, t=T_old>` when the link is real, then replays it with a forged current timestamp after the link has broken, making the controller believe the link is still active.

---

### TTW-S1 — Malicious Vehicle, No RSU ✅ DONE

**Scenario:** `attack_scenario = 1` (or current `= 4`)
**Attacker:** Vehicle V0 | **Victim neighbor:** Vehicle V1 | **RSU:** None

**Attack flow:**
```
t=10  V1→V0: HELLO beacon (V2V)
t=10  V0 → Controller: <V0 sees V1, t=10>   (legitimate)
t=10  V0 stores old packet: <V0 sees V1, t=10>
t=15  V1 moves away → physical link V0↔V1 breaks
t=20  V0 forges: <V0 sees V1, t=20>
t=20  V0 → Controller: <V0 sees V1, t=20>   (FORGED)
      Controller believes link V0↔V1 is still ACTIVE ← ATTACK SUCCESS
```

**Already implemented.** See Section 7 for full details.

---

### TTW-S2 — Malicious RSU ✅ TO IMPLEMENT NEXT

**Scenario:** `attack_scenario = 2`
**Attacker:** RSU_0 | **Victims:** V1, V2 | **RSU:** Yes (1 RSU)

**Required globals to add near attack parameters:**
```cpp
// TTW-S2 specific
static const double TTWS2_HELLO_TIME   = 10.0;
static const double TTWS2_LINK_BREAK   = 15.0;
static const double TTWS2_REPLAY_TIME  = 20.0;
TopologyPacket ttws2_stored_packet;
bool           ttws2_packet_stored = false;
std::ofstream  ttws2_log;
```

**Attack flow:**
```
t=10  V1→V2: HELLO (V2V exchange)
t=10  V1 → RSU: <V1 sees V2, t=10>   (legitimate)
t=10  V2 → RSU: <V2 sees V1, t=10>   (legitimate)
t=10  RSU (normal) → Controller: [V1 sees V2 t=10, V2 sees V1 t=10]
t=10  RSU (malicious) stores: <V1 sees V2, t=10>
t=15  Physical link V1↔V2 breaks
t=20  RSU forges: <V1 sees V2, t=20>
t=20  RSU → Controller: <V1 sees V2, t=20>  (FORGED)
      Controller believes link V1↔V2 is still ACTIVE ← ATTACK SUCCESS
```

**Functions to add:**
```cpp
void TTWS2_InitLog();
void TTWS2_VehiclesToRSU(Ptr<Node> v1, Ptr<Node> v2, Ptr<Node> rsu, double obs_time);
  // V1 and V2 send legitimate updates to RSU
  // RSU aggregates and forwards to controller (normal)
  // RSU ALSO stores the V1-sees-V2 packet internally
void TTWS2_RSUForwardAggregated(Ptr<Node> rsu, double obs_time);
  // RSU → Controller: legitimate aggregated update
void TTWS2_StorePacket(uint32_t v1_id, uint32_t v2_id, double obs_time);
  // Malicious RSU stores a copy
void TTWS2_ReplayAttack(Ptr<Node> rsu, uint32_t v1_id, uint32_t v2_id, double forged_time);
  // RSU injects forged <V1 sees V2, forged_time> into controller table
  // Sets pem_attack_injection_time, calls PemEmitEvent with attack_label=true
```

**Scheduling in `main()` (inside `if (attack_scenario == TTW_S2_MAL_RSU)` block):**
```cpp
Simulator::Schedule(Seconds(TTWS2_HELLO_TIME),
    &TTWS2_VehiclesToRSU, v1_node, v2_node, rsu_node, TTWS2_HELLO_TIME);
Simulator::Schedule(Seconds(TTWS2_HELLO_TIME + 0.1),
    &TTWS2_RSUForwardAggregated, rsu_node, TTWS2_HELLO_TIME);
Simulator::Schedule(Seconds(TTWS2_HELLO_TIME + 0.2),
    &TTWS2_StorePacket, v1_id, v2_id, TTWS2_HELLO_TIME);
Simulator::Schedule(Seconds(TTWS2_REPLAY_TIME),
    &TTWS2_ReplayAttack, rsu_node, v1_id, v2_id, TTWS2_REPLAY_TIME);
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2"
```

---

### TTW-S3 — Malicious Controller, No RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 3`
**Attacker:** Controller node (internal) | **RSU:** None

**Key difference from S1/S2:** The manipulation happens *inside the controller*. Vehicles send legitimate updates. The controller itself replays an old entry as if it were fresh.

**Required globals:**
```cpp
static const double TTWS3_HELLO_TIME   = 10.0;
static const double TTWS3_LINK_BREAK   = 15.0;
static const double TTWS3_INTERNAL_REPLAY = 20.0;
TopologyPacket ttws3_stored_packet;
bool           ttws3_packet_stored = false;
std::ofstream  ttws3_log;
```

**Attack flow:**
```
t=10  V1→V2: HELLO (legitimate)
t=10  V1 → Controller: <V1 sees V2, t=10>  (legitimate, accepted normally)
t=10  V2 → Controller: <V2 sees V1, t=10>  (legitimate, accepted normally)
t=10  Controller (malicious) stores: <V1 sees V2, t=10>
t=15  Physical link V1↔V2 breaks (V2 moves away)
      Controller would naturally time out the link — but it does NOT
t=20  Controller internally reprocesses: <V1 sees V2, t=20> (forged timestamp)
      Controller overwrites its own table with stale entry, link "stays active"
      ← ATTACK SUCCESS: no external packet needed
```

**Functions to add:**
```cpp
void TTWS3_InitLog();
void TTWS3_ReceiveLegitimateUpdates(uint32_t v1_id, uint32_t v2_id, double obs_time);
  // Simulate both vehicles sending legitimate updates
  // Controller stores them normally
  // Controller ALSO keeps a private copy of <V1 sees V2, t=obs_time>
void TTWS3_StorePacketInternal(uint32_t v1_id, uint32_t v2_id, double obs_time);
  // Controller saves the old packet for internal replay
void TTWS3_InternalReplay(uint32_t v1_id, uint32_t v2_id, double forged_time);
  // Controller rewrites its table: <V1 sees V2, forged_time>
  // Sets pem_attack_injection_time
  // Calls PemEmitEvent with:
  //   physical_sender_id = 0 (controller itself, use a sentinel)
  //   claimed_sender_id  = v1_id (impersonating V1)
  //   attack_label       = true
```

**Scheduling in `main()`:**
```cpp
Simulator::Schedule(Seconds(TTWS3_HELLO_TIME),
    &TTWS3_ReceiveLegitimateUpdates, v1_id, v2_id, TTWS3_HELLO_TIME);
Simulator::Schedule(Seconds(TTWS3_HELLO_TIME + 0.1),
    &TTWS3_StorePacketInternal, v1_id, v2_id, TTWS3_HELLO_TIME);
Simulator::Schedule(Seconds(TTWS3_INTERNAL_REPLAY),
    &TTWS3_InternalReplay, v1_id, v2_id, TTWS3_INTERNAL_REPLAY);
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=3"
```

---

### TTW-S4 — Malicious Controller, With RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 4` (after remapping; currently this slot holds TTW-S1)
**Attacker:** Controller node (internal) | **RSU:** Yes (1+ RSUs)

**Difference from S3:** Vehicles report to RSU, RSU aggregates and forwards to controller. The controller then internally replays the RSU-aggregated entry with a forged timestamp.

**Attack flow:**
```
t=10  V1→V2: HELLO (legitimate)
t=10  V1 → RSU: <V1 sees V2, t=10>
t=10  V2 → RSU: <V2 sees V1, t=10>
t=10  RSU → Controller: [V1 sees V2 t=10, V2 sees V1 t=10]  (legitimate aggregate)
t=10  Controller (malicious) stores: <V1 sees V2, t=10>  ← from RSU aggregate
t=15  Physical link V1↔V2 breaks
t=20  Controller internally replays: <V1 sees V2, t=20>  (forged timestamp)
      Controller's own routing table poisoned
      ← ATTACK SUCCESS
```

**This is nearly identical to TTW-S3** but with RSU in the data path. Re-use `TTWS3_*` functions and add an RSU aggregation step before the controller stores the packet.

**Run command:**
```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=4"
```

---

## 10. BSHH Attack — All 4 Variants

### Understanding BSHH

> A malicious node stores a legitimate heartbeat from vehicle V_x (which proves "V_x is alive") and replays it later — either to peer vehicles or directly to the controller — impersonating V_x's identity. This creates false liveness: the controller thinks V_x is still alive and nearby even when it is not.

### Heartbeat data structures — already in `routing.cc`

These structs and globals are **already defined** (lines ~164–247). Do not add them again:

```cpp
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity this heartbeat claims
    uint32_t physical_sender_id;  // who actually transmitted it
    double   timestamp;           // time when heartbeat was originally generated
    bool     is_replayed;         // true = this is a stored replay
};

HeartbeatPacket bshh_stored_heartbeat;
bool            bshh_heartbeat_stored = false;
std::map<uint32_t, HeartbeatPacket> bshh_controller_liveness_table;
std::ofstream   bshh_log;
```

The `bshh_controller_liveness_table` is also updated automatically by the `Rx()` callback whenever a `CustomHeartbeatTag` packet is received over DSRC (see Section 17).

---

### BSHH-S1 — Malicious Vehicle, No RSU ✅ TO IMPLEMENT AFTER ALL TTW VARIANTS

**Scenario:** `attack_scenario = 5`
**Attacker:** V2 (malicious vehicle) | **Victim:** V1 | **RSU:** None

**Attack flow:**
```
t=5   V1→V2: Heartbeat("I am alive", t=5)  (normal exchange)
t=5   V2→V1: Heartbeat("I am alive", t=5)
t=5   V1 → Controller: Heartbeat(Sender=V1, t=5)  (legitimate)
t=5   V2 → Controller: Heartbeat(Sender=V2, t=5)  (legitimate)

t=0   [V2 had previously stored]: Heartbeat(Sender=V1, t=0)  ← OLD packet

t=10  V2 → V1: Heartbeat(Sender=V1, t=0)   ← REPLAY: V2 impersonates V1 sending old data
      V1 receives this, believes it is valid, forwards it:
t=10  V1 → Controller: Heartbeat(Sender=V1, t=0)  ← Controller gets stale liveness

t=10  V2 → Controller: Heartbeat(Sender=V1, t=0)  ← V2 ALSO impersonates V1 directly
      Controller now has CONFLICTING heartbeats for V1:
        - one claiming V1 was alive at t=5  (real)
        - one claiming V1 was alive at t=0  (stale, forged)
      Controller uses stale/wrong liveness → faulty routing
      ← ATTACK SUCCESS
```

**Functions to add:**
```cpp
void BSHH_S1_InitLog();

void BSHH_S1_LegitimateExchange(uint32_t v1_id, uint32_t v2_id, double t);
  // Models the t=5 legitimate exchange
  // V1 → Controller: Heartbeat(Sender=V1, t=5)
  // V2 → Controller: Heartbeat(Sender=V2, t=5)
  // Calls PemEmitHeartbeatEvent(v1_id, v1_id, t, false) for both
  // Also updates bshh_controller_liveness_table

void BSHH_S1_StoreOldHeartbeat(uint32_t victim_id, double stored_time);
  // V2 stores Heartbeat(Sender=V1, t=stored_time) for later replay

void BSHH_S1_ReplayAttack(uint32_t attacker_id, uint32_t victim_id, double stored_time);
  // V2 sends Heartbeat(claimed=V1, t=stored_time) to V1 AND to controller
  // V1 forwards it to controller (V1 is deceived)
  // Sets pem_attack_injection_time
  // Calls PemEmitHeartbeatEvent(attacker_id, victim_id, stored_time, true)
  //   physical_sender = V2, claimed_sender = V1 ← triggers BSHH-S1 signature
  //   timestamp = 0 < most recent known timestamp → triggers BSHH-S2 signature
```

**Scheduling in `main()`:**
```cpp
static const double BSHH_S1_EXCHANGE_TIME = 5.0;
static const double BSHH_S1_OLD_HB_TIME   = 0.0;   // the "old" t=0 heartbeat
static const double BSHH_S1_REPLAY_TIME   = 10.0;

Simulator::Schedule(Seconds(BSHH_S1_EXCHANGE_TIME),
    &BSHH_S1_LegitimateExchange, v1_id, v2_id, BSHH_S1_EXCHANGE_TIME);
Simulator::Schedule(Seconds(BSHH_S1_EXCHANGE_TIME + 0.1),
    &BSHH_S1_StoreOldHeartbeat, v1_id, BSHH_S1_OLD_HB_TIME);
Simulator::Schedule(Seconds(BSHH_S1_REPLAY_TIME),
    &BSHH_S1_ReplayAttack, v2_id, v1_id, BSHH_S1_OLD_HB_TIME);
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=5"
```

---

### BSHH-S2 — Malicious RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 6`
**Attacker:** RSU_0 | **Victim:** V1 | **RSU:** Yes

**Attack flow:**
```
t=5   V1→V2: Heartbeat("alive", t=5) (normal V2V)
t=5   V1 → RSU: Heartbeat(Sender=V1, t=5)
t=5   V2 → RSU: Heartbeat(Sender=V2, t=5)
t=5   RSU → Controller: [V1(t=5), V2(t=5)]  (legitimate aggregated)
      RSU stores: Heartbeat(Sender=V1, t=0)  ← old one kept from earlier

t=10  RSU → Controller: Heartbeat(Sender=V1, t=0)  (REPLAYED old HB, impersonating V1)
      Conflicting timestamps for V1 at controller → faulty liveness
      ← ATTACK SUCCESS
```

**Key difference from S1:** RSU is the replayer, not a vehicle. The RSU sends the old heartbeat directly to the controller using V1's identity — no V2V interaction needed.

**Functions to add:**
```cpp
void BSHH_S2_InitLog();
void BSHH_S2_LegitimateExchange(Ptr<Node> v1, Ptr<Node> v2, Ptr<Node> rsu, double t);
void BSHH_S2_StoreOldHeartbeat(uint32_t victim_id, double stored_time);
void BSHH_S2_ReplayAttack(Ptr<Node> rsu, uint32_t victim_id, double stored_time);
  // RSU → Controller: Heartbeat(Sender=V1, t=stored_time)
  // physical_sender = RSU node id, claimed_sender = v1_id
  // Calls PemEmitHeartbeatEvent(rsu_id, v1_id, stored_time, true)
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=6"
```

---

### BSHH-S3 — Malicious Controller, No RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 7`
**Attacker:** Controller (internal) | **RSU:** None

**Attack flow:**
```
t=5   V1→V2: Heartbeat, both send to controller legitimately
      Controller stores legitimately:
        bshh_controller_liveness_table[V1] = Heartbeat(V1, t=5)
        bshh_controller_liveness_table[V2] = Heartbeat(V2, t=5)

      Controller ALSO keeps stale copies:
        Heartbeat(Sender=V1, t=0)   ← saved from an earlier exchange
        Heartbeat(Sender=V2, t=0)

t=10  Controller internally reprocesses old heartbeats AS IF they are current:
        bshh_controller_liveness_table[V1] ← Heartbeat(V1, t=0)  ← OVERWRITES fresh
        bshh_controller_liveness_table[V2] ← Heartbeat(V2, t=0)
      Controller now believes V1 and V2 are at old positions/state
      ← ATTACK SUCCESS (no external packet required)
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=7"
```

---

### BSHH-S4 — Malicious Controller, With RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 8`
**Attacker:** Controller (internal) | **RSU:** Yes

**Same logic as S3** but vehicles report through RSU, which aggregates. The controller stores old heartbeats from RSU aggregated reports and replays them internally.

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=8"
```

---

## 11. ME Attack — All 4 Variants

### Understanding ME

> A real link V1↔V2 exists. Malicious nodes (vehicles, RSU, or controller) create *duplicate* topology observations of this same link, attributed to different reporters (V3, V4). The controller aggregates all reports and wrongly infers that multiple paths exist: V1→V3→V2, V1→V4→V2, V1→V3→V4→V2. These paths are phantom — they do not exist physically.

### ME data structures — already in `routing.cc`

These are **already defined** (lines ~164–247). Do not add them again:

```cpp
struct MEEchoReport {
    uint32_t link_src;         // V1 (real link endpoint)
    uint32_t link_dst;         // V2 (real link endpoint)
    uint32_t false_reporter;   // V3 or V4 (fake witness)
    double   timestamp;
    bool     is_echo;          // always true for forged echo
};

std::vector<MEEchoReport> me_echo_reports;
std::ofstream me_log;
```

---

### ME-S1 — Malicious Vehicles, No RSU ✅ TO IMPLEMENT AFTER BSHH

**Scenario:** `attack_scenario = 9`
**Attackers:** V3 and V4 (malicious vehicles) | **Victims:** V1, V2 (legitimate link) | **RSU:** None

**Attack flow:**
```
Normal topology:   V1 ↔ V2  (real link)
                   V3, V4 are in overhearing range

t=10  V1→V2: HELLO exchange  (normal)
      V3 and V4 overhear this HELLO

t=10  V1 → Controller: <V1 sees V2, t=10>  (legitimate, real reporter)
t=10  V2 → Controller: <V2 sees V1, t=10>  (legitimate, real reporter)

Now the attack — V3 and V4 echo the same link:
t=10  V3 → Controller: <V1 sees V2, t=10> (ECHO — V3 reports V1↔V2 as if it observed it)
t=10  V4 → Controller: <V1 sees V2, t=10> (ECHO — V4 reports V1↔V2 as if it observed it)

Controller aggregates all 4 reports and infers:
  Path 1: V1 → V2          (REAL)
  Path 2: V1 → V3 → V2     (PHANTOM — V3 never had a direct link to V1 or V2)
  Path 3: V1 → V4 → V2     (PHANTOM)
  Path 4: V1 → V3 → V4 → V2  (PHANTOM)

Controller installs routes via phantom paths → packets dropped
← ATTACK SUCCESS
```

**Functions to add:**
```cpp
void ME_S1_InitLog();

void ME_S1_LegitimateDiscovery(uint32_t v1_id, uint32_t v2_id, double t);
  // V1 → Controller: <V1 sees V2, t>  (normal, attack_label=false)
  // V2 → Controller: <V2 sees V1, t>  (normal, attack_label=false)
  // Calls PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE, v1_id, v1_id, v1_id,
  //                    v1_id, v2_id, t, now, ..., false)

void ME_S1_EchoAttack(uint32_t echo_v3, uint32_t echo_v4,
                      uint32_t link_src, uint32_t link_dst, double t);
  // V3 → Controller: <V1 sees V2, t>  (echo, attack_label=true)
  //   physical_sender=v3, claimed_sender=v3, reporter=v3, link=(v1,v2)
  //   This triggers ME-S1 (reporter count exceeds density bound)
  //   This may trigger ME-S3 (V3 is outside comm range of V1↔V2)
  // V4 → Controller: <V1 sees V2, t>  (echo, attack_label=true)
  //   Same as V3's echo
  // Sets pem_attack_injection_time

  // For each echo call PemEmitEvent with attack_label=true:
  // PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE,
  //              echo_v3, echo_v3, echo_v3,
  //              link_src, link_dst, t, now,
  //              v3_position, v1_position, v2_position, true);
```

**Scheduling in `main()`:**
```cpp
static const double ME_S1_DISCOVERY_TIME = 10.0;
// Use IDs: v1_id=1, v2_id=2, v3_id=3, v4_id=4

Simulator::Schedule(Seconds(ME_S1_DISCOVERY_TIME),
    &ME_S1_LegitimateDiscovery, v1_id, v2_id, ME_S1_DISCOVERY_TIME);
Simulator::Schedule(Seconds(ME_S1_DISCOVERY_TIME + 0.1),
    &ME_S1_EchoAttack, v3_id, v4_id, v1_id, v2_id, ME_S1_DISCOVERY_TIME);
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=9"
```

---

### ME-S2 — Malicious RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 10`
**Attacker:** RSU_0 | **RSU:** Yes

**Attack flow:**
```
t=10  V1↔V2 HELLO exchange (normal)
t=10  V1 → RSU: <V1 sees V2, t=10>  (legitimate)
t=10  V2 → RSU: <V2 sees V1, t=10>  (legitimate)
t=10  RSU (legit part) → Controller: [V1↔V2 (t=10)]

RSU ALSO injects echo reports into its aggregated message:
t=10  RSU (malicious) → Controller:
       + <V1 sees V2, t=10> reported by V3  ← INJECTED (V3 did not observe this)
       + <V1 sees V2, t=10> reported by V4  ← INJECTED
Controller infers phantom paths V1→V3→V2 and V1→V4→V2
← ATTACK SUCCESS
```

**Key function pattern:**
```cpp
void ME_S2_InjectEchoReports(Ptr<Node> rsu,
                              uint32_t v1_id, uint32_t v2_id,
                              uint32_t false_v3, uint32_t false_v4,
                              double t);
// RSU sends forged echo reports to controller
// For each false reporter (V3, V4):
// PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE,
//              rsu_id,           // physically sent by RSU
//              false_v3,         // claimed to be from V3
//              rsu_id,           // RSU is the reporter
//              v1_id, v2_id,     // the real link being echoed
//              t, now, ..., true);
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=10"
```

---

### ME-S3 — Malicious Controller, No RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 11`
**Attacker:** Controller (internal) | **RSU:** None

**Attack flow:**
```
t=10  V1→V2 HELLO; V1 → Controller: <V1 sees V2, t=10> (legitimate)
      V2 → Controller: <V2 sees V1, t=10> (legitimate)
      V3 → Controller: own topology (no relation to V1↔V2)

Controller (malicious) internally fabricates echo entries:
  + <V1 sees V2, t=10> "as reported by V3"  ← FORGED internally
  + <V1 sees V2, t=10> "as reported by V4"  ← FORGED internally

Controller adds these to its own topology database
Controller now infers phantom paths V1→V3→V2, V1→V4→V2
← ATTACK SUCCESS (no external packet required)
```

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=11"
```

---

### ME-S4 — Malicious Controller, With RSU ✅ TO IMPLEMENT

**Scenario:** `attack_scenario = 12`
**Attacker:** Controller (internal) | **RSU:** Yes

**Same as ME-S3** but topology arrives via RSU aggregation. The controller still adds phantom echo entries internally.

**Run command:**
```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=12"
```

---

## 12. Implementation Workflow (One Attack at a Time)

Follow this workflow for **each new attack variant**. Never implement two variants simultaneously.

```
Step 1 — Read the attack description
   Read the relevant section in Temporal_echo_project.pdf for the specific variant.
   Write down: attacker node, victim node, RSU present?, what packet is forged,
   what the controller wrongly believes.

Step 2 — Add globals
   Near the existing TTW globals, add the struct / stored packet variable /
   liveness table / log file for the new variant.
   DO NOT change any existing code yet.

Step 3 — Add helper functions
   Write the attack functions using the same pattern as TTW_InitLog,
   TTW_SendTopologyUpdate, TTW_ReplayAttack.
   Each function must:
     a) write to the attack log file
     b) update the controller table (ttw_controller_table or equivalent)
     c) call PemEmitEvent or PemEmitHeartbeatEvent with attack_label=true
        at the moment of attack injection
     d) set pem_attack_injection_time = Simulator::Now().GetSeconds()
     e) set pem_attack_active = true

Step 4 — Add scheduling block in main()
   Find the existing attack_scenario block in main() and add a new
   else-if branch:
     else if (attack_scenario == <NEW_SCENARIO_ID>) {
         // set is_malicious_controller / has_RSU_infrastructure
         // schedule all helper functions with Simulator::Schedule(...)
         // color nodes in NetAnim
     }

Step 5 — Compile
   ./waf build 2>&1 | grep -E "error:|warning:"
   Fix ALL errors before proceeding.

Step 6 — Run with minimal parameters
   ./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=0 \
     --attack_scenario=<ID>"

Step 7 — Verify the log file
   cat <attack_log_file>.txt
   Confirm each step appears in the correct order with correct timestamps.

Step 8 — Verify PEM output
   cat pem_event_log.csv
   Check: attack events have attack_label=1, score > 0.12, alert_raised=1
   cat pem_run_summary.csv
   Check: tp >= 1, tdet_ms < 100

Step 9 — Run 5 times for statistics
   See Section 14 for the 5-run script.

Step 10 — Commit and move to next variant
   git add routing.cc
   git commit -m "Implement <ATTACK_VARIANT_NAME>"
```

---

## 13. Output Files Reference

| File | When created | Key columns |
|------|-------------|-------------|
| `ttw_attack_scenario4.txt` | TTW-S1 run | Step-by-step human-readable log |
| `bshh_s1_attack_log.txt` | BSHH-S1 run | (name this yourself in your InitLog) |
| `me_s1_attack_log.txt` | ME-S1 run | (name this yourself) |
| `pem_event_log.csv` | Every run | sim_time, event_type, triggered_signatures, score, alert_raised, phase |
| `pem_run_summary.csv` | End of every run | tp, tn, fp, fn, mcc, auroc, tdet_ms, pdr pcts, te2e ms |
| `channel_delivery_analysis.csv` | End of every run | channel_number, frequency_mhz, power_dbm, tx_count, rx_end_count, avg_fanout |
| `routing-animation.xml` | Every run | NetAnim visualization |
| `optimization_link_lifetime_data.csv` | Routing runs | Link lifetime data for ML optimization |

### Reading `pem_run_summary.csv` for your report

```
run_id  attack_scenario  tp  tn  fp  fn   mcc    auroc   tdet_ms  pdr_under_attack  pdr_post_mitigation
1       1                3   97  0   0    1.000  1.000   48.2     82.1              96.3
2       1                3   98  0   0    1.000  1.000   51.0     79.4              95.8
...
```

Good detection result criteria (from project proposal):
- `mcc` > 0.85
- `auroc` > 0.90
- `tdet_ms` < 100 ms (within the 100 ms beacon budget)
- `pdr_post_mitigation` significantly higher than `pdr_under_attack`

---

## 14. Running Multiple Runs for Report Statistics

The project requires **5 independent runs** per scenario, each with a different random seed. Use this bash script:

```bash
#!/bin/bash
# run_5_experiments.sh
# Usage: bash run_5_experiments.sh <attack_scenario_id> <N_Vehicles> <N_RSUs>

SCENARIO=$1
N_VEH=${2:-4}
N_RSU=${3:-0}

cd ~/ns-3.35
mkdir -p results/scenario_${SCENARIO}

for SEED in 1 2 3 4 5; do
    echo "=== Run $SEED / 5 (scenario=$SCENARIO) ==="

    # Clean old outputs
    rm -f pem_event_log.csv pem_run_summary.csv *.txt routing-animation.xml

    # Run simulation
    ./waf --run "scratch/routing \
        --simTime=60 \
        --N_Vehicles=${N_VEH} \
        --N_RSUs=${N_RSU} \
        --attack_scenario=${SCENARIO} \
        --RngRun=${SEED}"

    # Save outputs
    cp pem_run_summary.csv results/scenario_${SCENARIO}/run_${SEED}_summary.csv
    cp pem_event_log.csv   results/scenario_${SCENARIO}/run_${SEED}_events.csv
done

echo "=== All 5 runs complete. Results in results/scenario_${SCENARIO}/ ==="
```

Make it executable and run:
```bash
chmod +x run_5_experiments.sh
bash run_5_experiments.sh 1 4 0    # TTW-S1, 4 vehicles, no RSU
bash run_5_experiments.sh 5 4 0    # BSHH-S1, 4 vehicles, no RSU
bash run_5_experiments.sh 9 6 0    # ME-S1, 6 vehicles, no RSU
```

### Computing mean ± std with Python

```python
# compute_stats.py
import pandas as pd
import glob
import sys

scenario_id = sys.argv[1]
files = glob.glob(f"results/scenario_{scenario_id}/run_*_summary.csv")
df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

cols = ['mcc', 'auroc', 'tdet_ms',
        'pdr_under_attack_pct', 'pdr_post_mitigation_pct',
        'te2e_under_attack_ms', 'te2e_post_mitigation_ms']

print(f"\n=== Scenario {scenario_id} Statistics (n={len(df)}) ===")
for col in cols:
    if col in df.columns:
        print(f"  {col:35s}: {df[col].mean():.3f} ± {df[col].std():.3f}")
```

Run:
```bash
python3 compute_stats.py 1
```

---

## 15. Common Errors & Fixes

### Error: `error: 'hjhjhj' was not declared`
**Cause:** Stray text after `using namespace ns3;`
**Fix:**
```bash
sed -i 's/using namespace ns3;hjhjhj/using namespace ns3;/' scratch/routing.cc
```

### Error: `error: 'Vehicle_Nodes' was not declared`
**Cause:** Using `Vehicle_Nodes` before it is declared, or in a function outside its scope
**Fix:** Make sure `Vehicle_Nodes` is declared as a global. It should already be in the file:
```cpp
extern NodeContainer Vehicle_Nodes;
```
If it is missing in your new function's file scope, add `extern NodeContainer Vehicle_Nodes;` at the top of your new function block.

### Error: `No such file or directory` for CSV files
**Cause:** Optimization CSV files are not present before functions try to read them
**Fix:** Run a baseline (no-attack) simulation first to generate the CSV files:
```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --attack_scenario=0"
```

### Error: `Segmentation fault` during attack scenario
**Cause:** Accessing a node by ID that exceeds the total number of nodes
**Fix:** Always guard node access:
```cpp
if (node_id < Vehicle_Nodes.GetN()) {
    Ptr<Node> node = Vehicle_Nodes.Get(node_id);
    // ...
}
```

### Warning: `pem_run_summary.csv` is empty after run
**Cause:** Simulation was stopped early (Ctrl+C) before `PemWriteRunSummaryCsv()` was called
**Fix:** Let the simulation run to `simTime` naturally. Use shorter `simTime` for testing:
```bash
./waf --run "scratch/routing --simTime=25 --N_Vehicles=2 --attack_scenario=4"
```

### Error: `MCC = 0` in summary
**Cause:** No attack events were recorded (PemRecordObservation was never called with `actualAttack=true`)
**Fix:** Verify that:
1. `pem_attack_injection_time` is being set in your `ReplayAttack` function
2. `PemEmitEvent(..., true)` is called with `attack_label=true`
3. The scheduling times in `main()` are within `simTime`

### NetAnim shows no arrows
**Cause:** The visual UDP packets were not scheduled, or `AnimationInterface` is not set up
**Fix:** Follow the pattern in the existing `attack_scenario == 4` block in `main()` which schedules visual packets and sets node colors via `AnimationInterface`.

### BSHH detection score = 0 even for attack events
**Cause:** PEM only triggers BSHH signatures on `PEM_EVENT_HEARTBEAT` events
**Fix:** For BSHH, always use `PemEmitHeartbeatEvent(...)` not `PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE, ...)`.

### ME detection score = 0 even for attack events
**Cause:** ME signatures (6, 7, 8) require a populated `pem_link_report_history` and `pem_previous_path_counts`
**Fix:** Ensure the legitimate discovery `PemEmitEvent` calls happen BEFORE the echo attack calls, so the history is populated when the echo arrives.

---

## Quick Reference: Scenario IDs

```
0  = No attack (baseline)
1  = TTW-S1: Malicious Vehicle, No RSU        ✅ IMPLEMENTED
2  = TTW-S2: Malicious RSU                    → implement next
3  = TTW-S3: Malicious Controller, No RSU     → after S2
4  = TTW-S4: Malicious Controller, With RSU   → after S3
5  = BSHH-S1: Malicious Vehicle, No RSU       → after all TTW
6  = BSHH-S2: Malicious RSU                   → after BSHH-S1
7  = BSHH-S3: Malicious Controller, No RSU    → after BSHH-S2
8  = BSHH-S4: Malicious Controller, With RSU  → after BSHH-S3
9  = ME-S1: Malicious Vehicles, No RSU        → after all BSHH
10 = ME-S2: Malicious RSU                     → after ME-S1
11 = ME-S3: Malicious Controller, No RSU      → after ME-S2
12 = ME-S4: Malicious Controller, With RSU    → after ME-S3
```

---

## 16. DSRC/WAVE Communication and the 7 Channels

### What is DSRC?

**DSRC (Dedicated Short-Range Communication)** is a wireless communication technology designed specifically for vehicles. It operates at **5.9 GHz** using the IEEE 802.11p standard (a variant of Wi-Fi adapted for high-speed vehicular use). The full system is called **WAVE (Wireless Access in Vehicular Environments)** and is standardized by IEEE 1609.

Key properties used in this project:
- Range: ~300 m (defined as `TTW_COMM_RANGE = 300.0` in `routing.cc`)
- Ethertype: `0x88dc` (WAVE Short Message Protocol — WSMP)
- Broadcast: `Mac48Address::GetBroadcast()`
- No association / no handshake — vehicles broadcast directly

DSRC is used for:
- **V2V** (Vehicle-to-Vehicle): topology beacons, heartbeat liveness messages
- **V2R** (Vehicle-to-RSU): topology reports forwarded to the RSU
- The RSU then sends these to the controller over CSMA (wired Ethernet), NOT over DSRC

### The 7 DSRC/WAVE Channels (5.9 GHz band)

The DSRC spectrum is divided into 7 channels, each 10 MHz wide:

| Channel | Frequency | Type | TX Power (mobility_scenario=1) | Purpose |
|---------|-----------|------|-------------------------------|---------|
| **172** | 5.860 GHz | SCH | **23.0 dBm** (shortest reach) | Service Channel — application data |
| **174** | 5.870 GHz | SCH | **26.5 dBm** | Service Channel |
| **176** | 5.880 GHz | SCH | **30.0 dBm** | Service Channel |
| **178** | 5.890 GHz | **CCH** | **33.5 dBm** (mid-range) | **Control Channel — safety beacons, heartbeats** |
| **180** | 5.900 GHz | SCH | **37.0 dBm** | Service Channel |
| **182** | 5.910 GHz | SCH | **40.5 dBm** | Service Channel |
| **184** | 5.920 GHz | SCH | **44.0 dBm** (longest reach) | Service Channel |

Channel 178 is the **CCH (Control Channel)** — all safety-critical messages (beacons, heartbeats) go here. The other six are **SCH (Service Channels)** for application-level data.

**Power in other scenarios:** Urban (mobility_scenario=0) uses 41 dBm on all channels. Highway (mobility_scenario=2) uses 44 dBm on all channels. Only `mobility_scenario=1` (rural/non-urban) assigns the per-channel gradient above.

### Why Different Powers per Channel (mobility_scenario = 1)

The 23–44 dBm gradient is intentional, not random:

- **Lower power (23 dBm on Ch 172)** → shorter effective range (~150–200 m) → some broadcasts reach only nearby nodes → **packet delivery ratio drops**
- **Higher power (44 dBm on Ch 184)** → longer effective range (~450–500 m) → broadcasts reach most nodes in area → **packet delivery ratio rises**

This creates a measurable **per-channel PDR gradient** across the 7 channels. Under normal operation, each channel's delivery ratio follows this gradient predictably. When an attacker replays old packets:

- A replayed packet will arrive on a channel whose power profile does **not** match the attacker node's known transmission profile at that distance
- The attacker may transmit on the wrong channel or with wrong fanout statistics
- PEM uses this per-channel delivery anomaly as an additional attack detection feature

### Channel Analysis Output File

`channel_delivery_analysis.csv` is written at the end of every simulation run. Columns:

| Column | Meaning |
|--------|---------|
| `channel_number` | DSRC channel (172–184) |
| `frequency_mhz` | Center frequency (5860–5920 MHz) |
| `power_dbm` | TX power configured for mobility_scenario=1 |
| `tx_count` | Total PhyTxBegin events on this channel (packets transmitted) |
| `rx_end_count` | Total PhyRxEnd events on this channel (reception attempts) |
| `avg_fanout` | rx_end_count / tx_count — how many nodes received each broadcast on average |

**Interpreting avg_fanout:**
- `avg_fanout` close to 1.0 → only 1 node received each broadcast (very low power, short range)
- `avg_fanout` equal to `N_Vehicles - 1` → every vehicle received every broadcast (max range)
- Under attack: fanout spikes on specific channels when the attacker echoes packets to extra nodes

**How to read the CSV:**
```bash
cat channel_delivery_analysis.csv
# Expected for mobility_scenario=1 with N_Vehicles=6:
# channel_number,frequency_mhz,power_dbm,tx_count,rx_end_count,avg_fanout
# 172,5860,23.0,240,192,0.80   ← low power, low fanout
# 174,5870,26.5,240,264,1.10
# 176,5880,30.0,240,360,1.50
# 178,5890,33.5,240,480,2.00   ← CCH: mid fanout
# 180,5900,37.0,240,600,2.50
# 182,5910,40.5,240,720,3.00
# 184,5920,44.0,240,960,4.00   ← high power, high fanout
```

### How the 7 Channels Appear in `routing.cc`

The file defines a dedicated Custom Tag class for each channel, each with 26 neighbour-count variants (for different topology sizes). This is why the file is 140,000+ lines:

```
CustomMetaDataUnicastTagN172   → channel 172
CustomMetaDataUnicastTagN01    → channel 174  (N01–N7 naming for channels 2–7)
CustomMetaDataUnicastTagN02    → channel 176
CustomMetaDataUnicastTagN03    → channel 178 (CCH)
CustomMetaDataUnicastTagN04    → channel 180
CustomMetaDataUnicastTagN05    → channel 182
CustomMetaDataUnicastTagN06    → channel 184
```

Each of those 7 classes has 26 variants for different `max` neighbour counts → **7 × 26 = 182 tag classes** for multi-channel unicast metadata alone.

### How Attack Helpers Use DSRC

Both `AttackSendDSRCBeacon()` and `AttackSendHeartbeat()` send real 802.11p frames:

```cpp
// Get the WifiNetDevice (DSRC radio) for a node
Ptr<WifiNetDevice> wdi = AttackGetDSRCDevice(physical_sender_node);

// Create packet, attach tag, broadcast
Ptr<Packet> pkt = Create<Packet>(0);
pkt->AddPacketTag(tag);
wdi->Send(pkt, Mac48Address::GetBroadcast(), 0x88dc);  // 0x88dc = WSMP ethertype
```

The `Rx()` callback at line ~121761 fires on every received DSRC packet and uses `PeekPacketTag()` to identify the packet type.

---

## 17. Two-Layer Architecture: Radio Tags vs Controller Structs

This is the most important architectural concept in `routing.cc`. There are **two completely separate layers**:

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1 — RADIO (NS-3 Tags flying over the air)               │
│                                                                 │
│  CustomDataTag1          → topology beacon (position, velocity, │
│                            neighbour IDs, timestamp)            │
│  CustomHeartbeatTag      → liveness heartbeat (claimed sender,  │
│                            timestamp, is_replayed)              │
│  CustomMetaDataUnicastTag0  → RSU→Controller CSMA metadata      │
│  CustomMetaDataUnicastTagN172  → channel-172 unicast data       │
│  ... (182+ more tag classes for 7 channels × 26 neighbour sizes)│
│                                                                 │
│  These are NS-3 Tag subclasses with Serialize/Deserialize.      │
│  They travel inside Ptr<Packet> objects over WifiNetDevice      │
│  (DSRC) or SimpleUdpApplication (CSMA).                        │
└─────────────────────────────────────────────────────────────────┘
                          ↓ Rx() callback reads tags and writes ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2 — CONTROLLER MEMORY (Plain C++ structs in RAM)        │
│                                                                 │
│  TopologyPacket  → stored in ttw_controller_table              │
│                    key = "srcId_seenId"                         │
│  HeartbeatPacket → stored in bshh_controller_liveness_table    │
│                    key = vehicle_id                             │
│  MEEchoReport    → stored in me_echo_reports vector            │
│                                                                 │
│  These are plain structs. They never go over the air.          │
│  Attack replay functions write directly into these tables to   │
│  simulate what the controller's memory would contain after     │
│  accepting a forged packet.                                     │
└─────────────────────────────────────────────────────────────────┘
```

### The Two Message Types in BSHH

BSHH uses two distinct message types:

| Message | NS-3 Tag | In-Memory Struct | Purpose |
|---------|----------|-----------------|---------|
| **Topology Beacon** | `CustomDataTag1` | `TopologyPacket` | Neighbour discovery — who is near whom, position, velocity |
| **Heartbeat** | `CustomHeartbeatTag` | `HeartbeatPacket` | Liveness check — "I am alive at time T" |

Before `CustomHeartbeatTag` was added, heartbeats were only in-memory struct updates with no real DSRC radio event. Now both message types generate real 802.11p packets that travel over the simulated radio and are received by the `Rx()` callback.

### `CustomHeartbeatTag` — 13-byte fixed NS-3 Tag

Added at line ~1121 in `routing.cc`. Carries liveness info over DSRC:

```cpp
class CustomHeartbeatTag : public Tag {
    // Serialized layout (13 bytes total):
    uint32_t m_claimedSenderId;   // 4 bytes — whose identity this claims
    double   m_timestamp;          // 8 bytes — time of original heartbeat
    bool     m_isReplayed;         // 1 byte  — 0=legit, 1=forged replay
};
```

The `Rx()` callback (line ~122266) reads this tag and updates `bshh_controller_liveness_table`:

```cpp
CustomHeartbeatTag hb_tag;
if (pkt->PeekPacketTag(hb_tag)) {
    HeartbeatPacket hb = {hb_tag.GetClaimedSenderId(),
                          (uint32_t)destination_node_id,
                          hb_tag.GetTimestamp(),
                          hb_tag.GetIsReplayed()};
    bshh_controller_liveness_table[hb_tag.GetClaimedSenderId()] = hb;
}
```

### `CustomDataTag1` — Variable-size topology beacon NS-3 Tag

Defined at line ~2757. Carries full topology state over DSRC:
- Node ID, position (x, y, z), velocity, acceleration
- Neighbour IDs list (up to `max1` neighbours)
- Timestamp

Used by `AttackSendDSRCBeacon()` to send topology beacon packets in all BSHH and TTW functions.

---

## 18. Vehicle Mobility and SUMO Trace Files

### What is SUMO?

**SUMO (Simulation of Urban MObility)** is an open-source traffic simulator. It generates realistic vehicle movement traces — position and velocity of every vehicle at every timestep — which NS-3 then replays to move nodes during simulation.

The trace files are pre-generated CSV files placed at `/home/nimesha/` (or your home directory). The simulation reads them to drive `MobilityModel` updates for each vehicle node.

### The `mobility_scenario` Parameter

The global `mobility_scenario` (line 111, default = 0) selects which trace file to load:

| Value | Environment | Trace file pattern |
|-------|-------------|-------------------|
| `0` | Urban | `centralized_mobility_<speed>.csv` |
| `1` | Rural / Non-urban | `centralized_mobility_rural_<speed>.csv` |
| `2` | Highway | `centralized_mobility_highway_<speed>.csv` |

The `<speed>` part comes from the `maxspeed` command-line parameter (default 80 km/h).

### Why This Matters for Attacks

Vehicle positions affect:
- Whether two vehicles are within 300 m DSRC range (link exists or not)
- The link break time in TTW attacks (when V1 moves out of V0's range)
- ME-S3 detection: `PemEmitEvent` checks whether the echo reporter is within comm range of the reported link — this uses positions from the mobility model

For quick testing with small `simTime`, always use `N_Vehicles=2` to `N_Vehicles=6` to avoid the overhead of loading large traces.

---

## 19. Full Communication Stack Reference

The SDVN has four communication paths. Understanding which path each message uses is essential for attack implementation.

```
┌──────────┐  802.11p DSRC (5.9 GHz)    ┌──────────┐
│ Vehicle  │ ──────────────────────────► │ Vehicle  │   V2V
│   (Vx)   │   CustomDataTag1 (beacon)   │   (Vy)   │
│          │   CustomHeartbeatTag (HB)   │          │
└──────────┘                             └──────────┘

┌──────────┐  802.11p DSRC (5.9 GHz)    ┌──────────┐
│ Vehicle  │ ──────────────────────────► │   RSU    │   V2R
│   (Vx)   │   CustomDataTag1 (beacon)   │  (RSU_0) │
└──────────┘                             └──────────┘
                                               │
                                    CSMA Ethernet (10.1.1.0/24)
                                    UDP port 7777
                                    CustomMetaDataUnicastTag0
                                               │
                                               ▼
                                        ┌──────────┐
                                        │Controller│   R2C
                                        └──────────┘

┌──────────┐  LTE Cellular (uplink)     ┌──────────┐
│ Vehicle  │ ──────────────────────────► │Controller│   V2C (LTE)
│   (Vx)   │  send_LTE_metadata_uplink_ │          │   ⚠ DISABLED
└──────────┘  alone()  [commented out]  └──────────┘
```

### V2V — Vehicle to Vehicle (DSRC 802.11p)

- Radio: `WifiNetDevice` obtained via `AttackGetDSRCDevice(node)`
- Send: `wdi->Send(pkt, Mac48Address::GetBroadcast(), 0x88dc)`
- Receive: `Rx()` callback fires on the receiving node
- Range: 300 m
- Used for: topology beacons (`CustomDataTag1`), heartbeats (`CustomHeartbeatTag`), HELLO exchanges

### V2R — Vehicle to RSU (DSRC 802.11p)

Same radio as V2V. RSU nodes have a `WifiNetDevice` for DSRC. Vehicles broadcast and the RSU receives via the same `Rx()` callback.

### RSU→Controller (CSMA Ethernet)

RSU and Controller are on the same wired LAN (`10.1.1.0/24`). The RSU sends UDP packets to the controller on port 7777.

**Helper functions added to `routing.cc` (around line 1195):**

```cpp
// Gets the controller's CSMA IP address
static Ipv4Address AttackGetControllerIP() {
    Ptr<Ipv4> ipv4 = controller_Node.Get(0)->GetObject<Ipv4>();
    uint32_t iface_idx = (N_Vehicles > 0) ? 1 : 0;
    return ipv4->GetAddress(iface_idx, 0).GetLocal();
}

// Sends a CSMA UDP packet from RSU to controller
// Parameter: rsu_global_id — the global NS-3 node ID (RSU_Nodes.Get(0)->GetId())
static void AttackSendRSUToController(uint32_t rsu_global_id) {
    Ptr<Node> rsu_node = nullptr;
    for (uint32_t i = 0; i < RSU_Nodes.GetN(); i++) {
        if (RSU_Nodes.Get(i)->GetId() == rsu_global_id) { rsu_node = RSU_Nodes.Get(i); break; }
    }
    if (!rsu_node) return;
    Ptr<SimpleUdpApplication> udp_app =
        DynamicCast<SimpleUdpApplication>(rsu_node->GetApplication(0));
    if (!udp_app) return;
    Ptr<Packet> pkt = Create<Packet>(0);
    CustomMetaDataUnicastTag0 tag;
    tag.SetNodeId(rsu_node->GetId());
    tag.SetTimestamp(Simulator::Now());
    pkt->AddPacketTag(tag);
    Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                        udp_app, pkt, AttackGetControllerIP(), (uint16_t)7777);
}
```

**Every BSHH and TTW RSU-forwarding function calls `AttackSendRSUToController(rsu_id)` to generate a real CSMA packet.**
**Pass the global node ID** (`RSU_Nodes.Get(0)->GetId()`), not the container index — the function does an internal lookup. The controller's `HandleReadOne()` at line ~97345 receives it.

> **Interface index note:** When `N_Vehicles > 0`, the controller's CSMA interface is index 1 (index 0 is the loopback). When no vehicles are present, it is index 0. `AttackGetControllerIP()` handles this automatically.

### V2C LTE Cellular — Status: DISABLED

The LTE hardware is fully configured in `routing.cc` (lines 141344–142307):
- `LteHelper`, `EpcHelper`
- `enbdevices` (base stations), `uedevices` (vehicle UEs)
- `send_LTE_metadata_uplink_alone()` function at line ~114279 — complete and working

However, the **scheduling calls** for LTE uplink are inside a `/* */` block comment (lines 142738–142818). This means LTE transmissions are intentionally disabled for attack scenario runs. The DSRC + CSMA path is used exclusively.

**Do not re-enable LTE scheduling** unless explicitly needed — it would add interference to the attack timing and PEM scoring.

---

## 20. Data Transmission Functions Reference

There are five data transmission functions in `routing.cc`. Only one is active during attack simulations. The others are legacy code from earlier architecture designs.

### Active Function — `distributed_dsrc_data_broadcast` (line 124271)

**Status:** ✅ Active — called every 100ms in the `paper == 0` loop in `main()`

```cpp
void distributed_dsrc_data_broadcast(Ptr<NetDevice> nd, Ptr<Node> node, uint32_t node_index)
```

- **Tag:** `CustomDataTag` — node ID, position, velocity, acceleration, timestamp
- **Send:** 802.11p broadcast on Ch178 (`Mac48Address::GetBroadcast()`, `0x88dc`)
- **Timestamp array:** `dsrc_packet_initial_timestamp[nid]` — recorded only when `paper == 0`
- **Scheduled by:** the periodic loop in `main()`:
  ```cpp
  for (double t=0.40; t<simTime-1; t=t+data_transmission_period) {
      for (uint32_t i=0; i<wifidevices.GetN(); i++) {
          Simulator::Schedule(Seconds(t+0.0001*i),
              distributed_dsrc_data_broadcast, wifidevices.Get(i), dsrc_Nodes.Get(i), i);
      }
  }
  ```
  Period = 100ms, start = t=0.40s, stagger = 0.1ms per vehicle to avoid collisions.

---

### Dead Code Functions — Not Used in Attack Scenarios

#### `centralized_dsrc_data_broadcast` (line 123212) ❌ Commented out

**Status:** Dead code — both scheduling calls are inside `/* */` block comments

```cpp
void centralized_dsrc_data_broadcast(Ptr<NetDevice> nd, Ptr<Node> node, uint32_t node_index)
```

- **Tag:** `CustomDataTag` — same fields as distributed version
- **Send:** Same 802.11p broadcast on Ch178
- **Differences from distributed:**
  - Sets `routing_time = false` (not needed in distributed mode)
  - Uses `packet_initial_timestamp[nid]` (unconditional, different array name)
  - No `paper == 0` guard
- **Was for:** Centralized architecture (`architecture == 0`) where a management server collected all vehicle data
- **Replaced by:** `distributed_dsrc_data_broadcast`

#### `centralized_dsrc_data_unicast` (line 123422) ❌ Dead code

```cpp
void centralized_dsrc_data_unicast(Ptr<NetDevice> source_nd, Ptr<Node> source_node,
                                    uint32_t node_index, uint32_t destination)
```

- **Tag:** `CustomDataUnicastTag_Routing` — adds sender ID and destination ID for hop-by-hop routing
- **Send:** 802.11p **unicast** to a specific next-hop MAC address (not broadcast)
- **Routing:** calls `find_next_hop()` to look up the routing table before sending
- **Called by:** `send_centralized_packets()` (also dead code)

#### `send_centralized_packets` (line 123577) ❌ Dead code

Orchestrator for centralized unicast delivery:
1. Runs Dijkstra (`calculate_dijkstra_solution`) to build routing tables
2. Schedules `centralized_dsrc_data_unicast` for each source→destination pair
- Not scheduled in `main()` for any attack scenario

#### `send_hybrid_packets` (line 123510) ❌ Not used in attack scenarios

Orchestrator for hybrid architecture:
1. Runs `calculate_dijkstra_stable_solution` (Dijkstra variant for stable paths)
2. Uses a triangular wave pattern for transmission timing based on `data_gathering_cycle_number`
3. Schedules `hybrid_data_unicast` for each source
- `hybrid_data_unicast` decides per-hop: if both sender and next-hop are RSUs → CSMA Ethernet; otherwise → DSRC unicast

### Architecture Map

```
Architecture        Broadcast Function                  Unicast Orchestrator       Status
───────────────────────────────────────────────────────────────────────────────────────────
Distributed         distributed_dsrc_data_broadcast     routing_dsrc_data_unicast  ✅ ACTIVE
(paper == 0)        Ch178, every 100ms per vehicle      multi-channel, flow-based

Centralized         centralized_dsrc_data_broadcast     send_centralized_packets   ❌ commented
(architecture == 0) Ch178, same period                  → centralized_dsrc_         out
                                                        data_unicast (Dijkstra)

Hybrid              dsrc_metadata_broadcast             send_hybrid_packets        ❌ not used
(architecture == 2) one-shot at t=0.4                   → hybrid_data_unicast       in attacks
                                                        (DSRC or CSMA per hop)
```

**Key rule:** For all 12 attack scenarios in this project, `paper == 0` is always true, so only `distributed_dsrc_data_broadcast` fires. The centralized and hybrid functions are preserved for reference but do not execute.

---

## 21. SimpleUdpApplication — How It Works

### What it is

`SimpleUdpApplication` is a **custom NS-3 Application class** (line 97389), written specifically for this project. It is the **wired network socket layer** that lives on RSU and Controller nodes, enabling them to send and receive packets over the CSMA Ethernet network (IP/UDP on `10.1.1.0/24`).

> **Important:** Vehicles use `WifiNetDevice::Send()` (DSRC radio) directly and do NOT use `SimpleUdpApplication`. Only RSUs and the Controller have it installed.

### Installation in `main()`

```cpp
// One SimpleUdpApplication instance per RSU node (line 141452)
for (uint32_t u = 0; u < RSU_Nodes.GetN(); u++) {
    Ptr<SimpleUdpApplication> udp_app = Create<SimpleUdpApplication>();
    RSU_Nodes.Get(u)->AddApplication(udp_app);
    RSU_apps.Add(udp_app);
}
RSU_apps.Start(Seconds(0.00));
RSU_apps.Stop(Seconds(simTime));
```

### Internal Structure — 3 Components

#### 1. `StartApplication()` — opens sockets at simulation start

```
Port 7777  →  m_recv_socket1  →  HandleReadOne()   ← topology/routing/status data
Port 9999  →  m_recv_socket2  →  HandleReadTwo()   ← secondary channel
Send       →  m_send_socket   →  SendPacket()      ← outgoing CSMA packets
```

Both receive sockets listen on `0.0.0.0` (any interface) with `SetAllowBroadcast(true)`.

#### 2. `SendPacket(packet, destIP, port)` — sends over CSMA Ethernet

```cpp
void SimpleUdpApplication::SendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t port)
{
    m_send_socket->Connect(InetSocketAddress(destination, port));
    m_send_socket->Send(packet);
}
```

Always called with port 7777. Usage pattern:
```cpp
Ptr<SimpleUdpApplication> udp_app =
    DynamicCast<SimpleUdpApplication>(RSU_apps.Get(rsu_index));
Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                    udp_app, packet, controllerIP, (uint16_t)7777);
```

#### 3. `HandleReadOne()` — the Controller receive handler (port 7777)

When a packet arrives at the Controller, this function identifies the tag type and updates controller state. It handles all these tag types:

| Tag type | What the controller does |
|---|---|
| `CustomDataUnicastTag_Routing` | Hop-by-hop forward: find next-hop via `find_next_hop()`, relay via DSRC or CSMA |
| `CustomDeltavaluesDownlinkUnicastTag` | Update `delta_at_nodes_inst` — routing split ratios sent down to vehicles |
| `CustomStatusDataUplinkTag1` | Update `routing_data_at_controller_inst` — vehicle position/velocity/acceleration |
| `CustomFlowDataUplinkTag1` | Update flow demand table — source, destination, flow size, QoS |
| `CustomDataTag` | Log basic beacon delivery delay |
| `CustomMetaDataUnicastTag0` | Update `con_data_inst` — records CSMA/LTE packet delay for that node |
| `CustomMetaDataUnicastTag1`+ | Similar metadata for other unicast tag variants |

### Full Data Flow with udp_app

```
Vehicle (DSRC) ──802.11p──► RSU: Rx() callback fires
                                │
                                │  RSU builds Ptr<Packet> with tag attached
                                │  Gets udp_app: RSU_apps.Get(rsu_index)
                                │
                                ▼
                    udp_app->SendPacket(pkt, controllerIP, 7777)
                                │
                    CSMA Ethernet  10.1.1.x/24  UDP
                                │
                                ▼
                    Controller: HandleReadOne() fires on port 7777
                    PeekPacketTag() → identifies tag type
                    Updates controller tables
```

### How Attack Functions Use udp_app

The attack helper `AttackSendRSUToController(rsu_global_id)` uses the same mechanism to send forged packets from a malicious RSU to the controller. **Always pass the global node ID** (`RSU_Nodes.Get(0)->GetId()`), not the container index:

```cpp
// rsu_global_id = RSU_Nodes.Get(0)->GetId()  — global NS-3 node ID
static void AttackSendRSUToController(uint32_t rsu_global_id) {
    Ptr<Node> rsu_node = nullptr;
    for (uint32_t i = 0; i < RSU_Nodes.GetN(); i++) {
        if (RSU_Nodes.Get(i)->GetId() == rsu_global_id) { rsu_node = RSU_Nodes.Get(i); break; }
    }
    if (!rsu_node) return;
    Ptr<SimpleUdpApplication> udp_app =
        DynamicCast<SimpleUdpApplication>(rsu_node->GetApplication(0));
    if (!udp_app) return;
    Ptr<Packet> pkt = Create<Packet>(0);
    CustomMetaDataUnicastTag0 tag;
    tag.SetNodeId(rsu_node->GetId());
    tag.SetTimestamp(Simulator::Now());
    pkt->AddPacketTag(tag);
    Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                        udp_app, pkt, AttackGetControllerIP(), (uint16_t)7777);
}
```

The controller receives this exactly as it would a legitimate RSU packet — `HandleReadOne()` fires and processes the tag without knowing it is forged.

### Getting the Controller IP

```cpp
static Ipv4Address AttackGetControllerIP() {
    Ptr<Ipv4> ipv4 = controller_Node.Get(0)->GetObject<Ipv4>();
    uint32_t iface_idx = (N_Vehicles > 0) ? 1 : 0;
    return ipv4->GetAddress(iface_idx, 0).GetLocal();
}
```

When `N_Vehicles > 0`, the controller's CSMA interface is index 1 (index 0 is loopback). When no vehicles are present, it is index 0.

---

## 22. Node Roles and Architecture Modes

### The Two Server Nodes

Two separate server nodes are created in `main()` (lines 141164–141165):

```cpp
controller_Node.Create(1);   // SDN Controller — routing decisions, attack target
management_Node.Create(1);   // Management/Data Server — collects raw vehicle data
```

Both sit on the same CSMA Ethernet LAN (`10.1.1.0/24`) alongside all RSU nodes.
They have different roles and are used in different architecture modes.

### Control Variables

```cpp
int architecture = 0;   // 0=centralized, 1=distributed, 2=hybrid  (line 112)
int paper        = 1;   // 0=proposed RL algorithm, 1=comparison baseline  (line 114)
```

### Three Architecture Modes

#### Architecture 0 — Centralized (`architecture = 0`)

```
[Vehicle] ──DSRC──► [Vehicle] ──UDP/LTE──► [management_Node]
                                                   │
                                           collects all vehicle data
                                           runs Dijkstra centrally
                                           sends routes back down
```

- Vehicles send data directly to the **management server** — not the controller
- `management_Node` is the destination
- `centralized_dsrc_data_broadcast` + `send_centralized_packets` were built for this path
- **These functions are now commented out — this mode is not used in attack scenarios**

#### Architecture 1 + `paper = 0` — Distributed Proposed Algorithm

```
[Vehicle] ──DSRC broadcast──► [All nearby Vehicles + RSU]
                               each node makes its OWN routing
                               decision locally using RL algorithm
```

- No central server involved in routing
- `distributed_dsrc_data_broadcast` fires every 100ms
- `paper = 0` loop in `main()` schedules this

#### Architecture 0 + `paper = 1` — Comparison Baselines (QRSDN, RLMR, DCMR)

```
[Vehicle] ──DSRC──► [RSU] ──CSMA/UDP──► [controller_Node]
                                               │
                                       computes routes centrally
                                       sends delta values back down
                                       to vehicles
```

- Vehicles send topology data → RSU → **controller_Node**
- Controller runs the comparison algorithm and pushes split ratios (`delta` values) back
- `SimpleUdpApplication` is the socket layer for RSU ↔ Controller communication

### What Runs During Attack Scenarios

For all 12 attack scenarios (`attack_scenario = 1–12`), the active data path is:

```
[Vehicle] ──DSRC (AttackSendDSRCBeacon / AttackSendHeartbeat)──► [Vehicles / RSU]
                                │
[RSU] ──CSMA/UDP (AttackSendRSUToController)──► [controller_Node]
                                                        │
                                           ttw_controller_table  ← POISONED
                                           bshh_controller_liveness_table  ← POISONED
```

### Node Role Summary

| Node | Role | Used in Attack Scenarios? |
|---|---|---|
| `Vehicle_Nodes` | Move around, send DSRC beacons | ✅ Yes — attacker and victim |
| `RSU_Nodes` | Relay V2R packets to controller | ✅ Yes — in S2/S4 variants |
| `controller_Node` | SDN controller, routing decisions — **the attack target** | ✅ Yes |
| `management_Node` | Data collection server for centralized studies | ❌ No |

> **Key point:** `management_Node` is only relevant in the old centralized architecture studies that preceded the attack work. For all 12 attack scenarios in this project, only `controller_Node` is targeted and only `controller_Node` runs `HandleReadOne()` to process incoming topology/heartbeat data.

---

## 23. Agent-Based Data Upload — send_LTE_data_agent and RSU_dataunicast_agent

### The `X_nodes[]` Selection Gate

Both functions are guarded by `X_nodes[nid] == 1` (line 97444). This global boolean array marks which nodes are **selected agents** — nodes chosen by the RL optimization layer to upload their full topology knowledge to the management server. Initialized to `1` for all nodes at line 114392; can be updated by the controller via `CustomDeltavaluesDownlinkUnicastTag`.

### `send_LTE_data_agent` (line 124900)

**Sender:** Vehicle node | **Transport:** LTE uplink UDP | **Destination:** `controller_Node` port 7777

```cpp
void send_LTE_data_agent(Ptr<SimpleUdpApplication> udp_app,
                          Ptr<Node> node_source,
                          Ptr<Node> destination_node,   // controller_Node
                          uint32_t node_index)
```

**What it does:**
1. Guards on `X_nodes[nid] == 1`
2. Gets own position, velocity, acceleration from mobility model
3. Calls `add_received_data_at_nodes()` to include self in `data_at_nodes_inst`
4. Extracts the full topology snapshot — every node this vehicle has observed via DSRC beacons (positions, velocities, neighbour sets)
5. Selects a `CustomMetaDataUnicastTagN01x` tag variant by neighbour count (switch on 1..max) and packs the snapshot
6. Sends: `udp_app->SendPacket(packet1, controller_IP, 7777)` via `GetAddress((N_Vehicles > 0 ? 1 : 0), 0)` — controller's CSMA interface

**Scheduled by** `begin_sending_LTE_data_agent()`, staggered 25 µs per agent.

> **Change (routing.cc line 124999):** IP selection changed from hardcoded `GetAddress(2,0)` (management LTE interface) to `GetAddress((N_Vehicles > 0 ? 1 : 0), 0)` (controller CSMA interface). Matches logic in `AttackGetControllerIP()`.

### `RSU_dataunicast_agent` (line 132992)

**Sender:** RSU node | **Transport:** CSMA Ethernet UDP | **Destination:** `controller_Node` port 7777

Identical logic to `send_LTE_data_agent` — same guard, same topology extraction, same `CustomMetaDataUnicastTagN01x` packing — except:
- Uses CSMA Ethernet not LTE
- Destination IP: `GetAddress(1,0)` when `N_Vehicles > 0`, else `GetAddress(0,0)` — already correct for `controller_Node`
- Stagger: 50 µs per agent (via `begin_sending_RSU_data_agent()`)

### Scheduling in main() — What Replaced What

| Old call (line) | New call | Destination |
|---|---|---|
| `send_LTE_routing_data_alone` (142796) | `send_LTE_data_agent` | `controller_Node` |
| `RSU_routing_statusdataunicast_alone` (142857) | `RSU_dataunicast_agent` | `controller_Node` |

`send_LTE_routing_data_alone` (line 124369) — old function, sent basic routing metrics only. Replaced by `send_LTE_data_agent` which sends the full topology snapshot.

### Quick Comparison

| | `send_LTE_data_agent` | `RSU_dataunicast_agent` |
|---|---|---|
| Sender | Vehicle | RSU |
| Transport | LTE UDP | CSMA Ethernet UDP |
| Destination | `controller_Node` | `controller_Node` |
| Dest IP | `GetAddress((N_Vehicles>0?1:0), 0)` | `GetAddress(1,0)` |
| Stagger | 25 µs/agent | 50 µs/agent |
| Tag family | `CustomMetaDataUnicastTagN01x` | Same |
| Active in runs? | ✅ Yes (all runs) | ✅ Yes (when N_RSUs > 0) |

---

*Last updated: implementation guide for routing.cc, ns-3.35, FYP — Department of EIE, University of Ruhuna*
