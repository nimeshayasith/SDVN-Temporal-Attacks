# SDVN Temporal-Echo Attack Implementation — Team Notes

**Project:** A Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection:
Countering Temporal-Echo Topology Poisoning Attacks in SDVNs
**Department:** EIE, University of Ruhuna
**Supervisors:** Dr. Nilmantha Wijesekara | Dr. Prabath Weerasingha
**Main file:** `routing.cc` (place inside `ns-3.35/scratch/` on Linux)
**Simulator:** NS-3.35 on Ubuntu Linux

> **Purpose of this document:** A complete explanation for team members who were not involved
> in this coding session. After reading, you will understand what was already in the code,
> what was added, why every change was made, and exactly how to run and test all 12 scenarios.

---

## Table of Contents

1. [What is This Project?](#1-what-is-this-project)
2. [What Was Already There Before We Started](#2-what-was-already-there-before-we-started)
3. [What Was Added — Summary of All Changes](#3-what-was-added--summary-of-all-changes)
4. [Understanding the Three Attack Families](#4-understanding-the-three-attack-families)
5. [Attack Scenario ID Map (Quick Reference)](#5-attack-scenario-id-map-quick-reference)
6. [Detailed Attack Flows — All 12 Scenarios](#6-detailed-attack-flows--all-12-scenarios)
7. [How Detection Works (PEM)](#7-how-detection-works-pem)
8. [Data Structures Added to routing.cc](#8-data-structures-added-to-routingcc)
9. [Build and Setup on Linux](#9-build-and-setup-on-linux)
10. [All Run Commands](#10-all-run-commands)
11. [Understanding the Output Files](#11-understanding-the-output-files)
12. [Running 5-Experiment Statistics for the Report](#12-running-5-experiment-statistics-for-the-report)
13. [NetAnim Visualization Color Guide](#13-netanim-visualization-color-guide)
14. [Common Errors and Fixes](#14-common-errors-and-fixes)
15. [Running Attacks Without Detection (attack-only mode)](#15-running-attacks-without-detection-attack-only-mode)
16. [Per-Scenario NetAnim XML Files](#16-per-scenario-netanim-xml-files)
17. [PEM Accuracy Improvements (ME-S1 and ME-S3)](#17-pem-accuracy-improvements-me-s1-and-me-s3)
18. [RSU and RSU Network Explained](#18-rsu-and-rsu-network-explained)
19. [Questions and Answers — Conceptual Session (2026-05-01)](#19-questions-and-answers--conceptual-session-2026-05-01)
20. [Questions and Answers — Conceptual Session (2026-05-02)](#20-questions-and-answers--conceptual-session-2026-05-02)
21. [Per-Channel TX Power and Channel Delivery Analysis](#21-per-channel-tx-power-and-channel-delivery-analysis)
22. [Data Transmission Functions and UDP Application (2026-05-02)](#22-data-transmission-functions-and-udp-application-2026-05-02)
23. [Node Roles, Architecture Modes, and centralized_dsrc_data_broadcast](#23-node-roles-architecture-modes-and-centralized_dsrc_data_broadcast)
24. [Agent-Based Data Upload Functions — send_LTE_data_agent and RSU_dataunicast_agent](#24-agent-based-data-upload-functions--send_lte_data_agent-and-rsu_dataunicast_agent)
25. [Build Fix Notes — Forward Declarations and Helper Placement (2026-05-02)](#25-build-fix-notes--forward-declarations-and-helper-placement-2026-05-02)
26. [Observed Run Note — Scenario Outputs and Logs (2026-05-07)](#26-observed-run-note--scenario-outputs-and-logs-2026-05-07)

---

## 1. What is This Project?

### The system being simulated

An **SDVN (Software-Defined Vehicular Network)** is a road network where vehicles (V),
Road-Side Units (RSUs), and a central SDN Controller communicate wirelessly.
The controller collects **topology updates** — messages saying "V0 can see V1 right now,
at time T" — and uses this to decide routing: which path to use to send packets from A to B.

```
  [Vehicle V0] ←—— DSRC 300m ——→ [Vehicle V1]
        |                               |
        └──── sends topology update ────┘
                         |
                         ▼
                 [SDN Controller]  ← makes ALL routing decisions
                         |
                 [RSU] (optional) ← can relay/aggregate updates
```

The DSRC (Dedicated Short-Range Communication) range is **300 metres**.
If two vehicles are farther apart than 300m, they cannot communicate directly.

### The problem: temporal-echo attacks

An attacker who is part of this network (a compromised vehicle, RSU, or controller) can
**poison the controller's view of the topology** by replaying old or forged control messages.
The controller then believes a link exists (or a vehicle is alive) when it no longer is.
It installs routes over these "ghost" links — packets are sent but never arrive.

### Our goal

Implement all 12 attack variants in NS-3.35 and measure how well the
**PEM (Performance Evaluation Metrics)** detection layer catches each one:
MCC, AUROC, detection latency (Tdet), and Packet Delivery Ratio (PDR).

---

## 2. What Was Already There Before We Started

Before this round of work, `routing.cc` already contained:

| Already Done | Description |
|---|---|
| Full SDVN simulation framework | Vehicle mobility, WAVE/DSRC radio, routing algorithms |
| `TopologyPacket` struct | Data structure for a topology update: `{src_id, seen_id, timestamp, is_forged}` |
| `ttw_controller_table` | The `std::map` that IS the controller's topology belief — everything in here the controller treats as truth |
| **TTW-S1 attack (was scenario 4)** | One working attack: malicious vehicle replaying a forged timestamp |
| Full PEM layer | 9 detection signatures, MCC/AUROC computation, CSV output |
| `PemEmitEvent()` | Feeds a topology event into the detector |
| `PemEmitHeartbeatEvent()` | Feeds a heartbeat event into the detector |
| `PemEmitVehicleBeacon()` | Registers a legitimate beacon (for baseline detection history) |
| CSV output functions | Auto-writes per-scenario files in `PEM_RUN_SUMMARY/` and `PEM_EVENT_LOG/` |

**What was missing:** The remaining 11 attack scenarios existed only as written descriptions
in the project proposal PDF — none were coded. This session implemented all of them.

---

## 3. What Was Added — Summary of All Changes

All changes are inside `routing.cc`. No other file was modified.
Here is every change, in order, with the reason for each decision.

---

### Change 1 — Remapped TTW-S1 from scenario 4 to scenario 1

**What changed:** Every `if (attack_scenario == 4)` that belonged to TTW-S1 was changed to
`if (attack_scenario == 1)`. There were four such places in the file:
- Mobility setup block
- First animation block (controller node repositioning)
- Second animation block (node colours)
- Scheduling header block (the console printout)

**Why this was necessary:** The original code used `attack_scenario = 4` for TTW-S1 by
accident — probably because it was the 4th scenario implemented during development.
Our project plan defines 12 scenarios numbered 1–12 across three families. TTW-S1 is
logically scenario 1. Slot 4 needed to be freed for TTW-S4 (malicious controller + RSU).
Without this remap, the numbering would have a gap and TTW-S4 would have no slot.

---

### Change 2 — Added the `AttackScenarioId` enum

**What was added** (around line 185, after the TTW-S1 globals):

```cpp
enum AttackScenarioId {
    ATTACK_NONE               = 0,
    TTW_S1_MAL_VEH_NO_RSU    = 1,
    TTW_S2_MAL_RSU            = 2,
    TTW_S3_MAL_CTRL_NO_RSU    = 3,
    TTW_S4_MAL_CTRL_WITH_RSU  = 4,
    BSHH_S1_MAL_VEH_NO_RSU   = 5,
    BSHH_S2_MAL_RSU           = 6,
    BSHH_S3_MAL_CTRL_NO_RSU   = 7,
    BSHH_S4_MAL_CTRL_WITH_RSU = 8,
    ME_S1_MAL_VEH_NO_RSU      = 9,
    ME_S2_MAL_RSU             = 10,
    ME_S3_MAL_CTRL_NO_RSU     = 11,
    ME_S4_MAL_CTRL_WITH_RSU   = 12
};
```

**Why:** Without an enum, the scenario integers are magic numbers. The enum makes it
immediately clear in code that `attack_scenario == 6` means "BSHH-S2 = malicious RSU"
without needing to cross-reference a document. It also prevents typos.

---

### Change 3 — Added TTW-S2 / S3 / S4 global variables

**What was added** (after the TTW-S1 globals block):

```cpp
// One block per variant, e.g. for TTW-S2:
static const double TTWS2_HELLO_TIME  = 10.0;  // t=10: vehicles exchange HELLO
static const double TTWS2_LINK_BREAK  = 15.0;  // t=15: physical link breaks
static const double TTWS2_REPLAY_TIME = 20.0;  // t=20: RSU replays forged packet
TopologyPacket ttws2_stored_packet;             // the old packet the RSU saved
bool           ttws2_packet_stored = false;     // guard: only replay if stored
std::ofstream  ttws2_log;                       // log file for this variant
```

Same pattern for S3 and S4 (with `TTWS3_INTERNAL_REPLAY` instead of `TTWS3_LINK_BREAK`
because internal controller attacks have no separate "link break" event — the controller
simply refuses to expire the entry).

**Why separate variables per variant:** Each simulation run executes exactly one scenario.
Separate variables prevent state leakage between variants and make it safe to have all
scenario code in one file. Separate log files (`ttw_s2_attack_log.txt`, etc.) make
per-run results immediately identifiable.

---

### Change 4 — Added `HeartbeatPacket` struct and BSHH globals

**What was added:**

```cpp
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity this heartbeat CLAIMS to be from
    uint32_t physical_sender_id;  // who ACTUALLY transmitted it (differs in an attack)
    double   timestamp;           // when the heartbeat was originally generated
    bool     is_replayed;         // true = this is a stored replay, not a fresh heartbeat
};

HeartbeatPacket bshh_stored_heartbeat;
bool            bshh_heartbeat_stored = false;
std::map<uint32_t, HeartbeatPacket> bshh_controller_liveness_table;
// key = vehicle_id, value = most recent heartbeat accepted for that vehicle
std::ofstream   bshh_log;
```

**Why a new struct was needed:** TTW attacks replay topology (link state) packets.
BSHH attacks replay heartbeat (liveness) packets — a completely different message type.
Heartbeats carry two identity fields: `claimed_sender_id` (whose name is on the packet)
versus `physical_sender_id` (who actually sent the radio signal). In a normal network
these are always the same. In a BSHH attack, V2 physically sends a packet claiming
to be V1 — so they differ. The `HeartbeatPacket` struct captures this distinction.

The `bshh_controller_liveness_table` represents what the controller currently believes
about the aliveness of each vehicle. When the attacker overwrites an entry with stale
data, the controller makes wrong routing decisions.

---

### Change 5 — Added `MEEchoReport` struct and ME globals

**What was added:**

```cpp
struct MEEchoReport {
    uint32_t link_src;          // V0 — one end of the real physical link
    uint32_t link_dst;          // V1 — other end of the real physical link
    uint32_t false_reporter;    // V2 or V3 — the attacker claiming to have observed it
    double   timestamp;
    bool     is_echo;           // always true: this is a forged echo entry
};

std::vector<MEEchoReport> me_echo_reports;  // all echo entries injected this run
std::ofstream me_log;
```

**Why a new struct was needed:** ME attacks neither fake a broken link (TTW) nor fake
vehicle liveness (BSHH). They take a *real, active* link V0↔V1 and make the controller
believe additional reporters (V2, V3) also independently observed that link. The
`MEEchoReport` captures the difference between the real link and the fake reporter —
something neither `TopologyPacket` nor `HeartbeatPacket` can express cleanly.

---

### Change 6 — Added `extern` declarations for RSU_Nodes and controller_Node

**What was added** (after the existing `extern NodeContainer Vehicle_Nodes;`):

```cpp
extern NodeContainer RSU_Nodes;
extern NodeContainer controller_Node;
```

**Why:** New attack functions for TTW-S2/S4, BSHH-S2/S4, ME-S2/S4 need to access the
RSU node's NS3 global node ID (`RSU_Nodes.Get(0)->GetId()`) and the controller node
for NetAnim colour coding. These containers are declared and filled inside `main()`,
which appears later in the file. The `extern` keyword lets functions defined before
`main()` use them without causing a compile error.

---

### Change 7 — Added all 11 new attack function sets

**What was added:** Approximately 1,000 lines of C++ functions inserted before `main()`.
Each attack variant follows this function pattern:

```
<VARIANT>_InitLog()               Opens log file, writes the attack timeline header.
<VARIANT>_LegitimateExchange()    Simulates the normal benign communication step.
                                  Calls PemEmitEvent(..., false) — not an attack event.
<VARIANT>_StorePacket/Heartbeat() Attacker saves the legitimate packet for later replay.
<VARIANT>_ReplayAttack()          Injects the forged packet into ttw_controller_table
                                  (or bshh_controller_liveness_table for BSHH).
                                  Sets pem_attack_injection_time = now.
                                  Sets pem_attack_active = true.
                                  Calls PemEmitEvent(..., true) — the attack label.
```

For controller-internal attacks (S3/S4 variants of all three families), there is
no external packet — the controller tampers with its own state:

```
<VARIANT>_ReceiveLegitimateUpdates()  Normal vehicles send to controller (benign PEM calls).
<VARIANT>_StorePacketInternal()       Controller secretly keeps the old packet.
<VARIANT>_InternalReplay()            Controller overwrites its own table with stale data.
                                      physical_sender_id = 9999u (see sentinel note below).
```

For ME attacks, the pattern is:
```
<VARIANT>_LegitimateDiscovery()   Real link V0↔V1 is reported normally (benign PEM calls).
<VARIANT>_EchoAttack()            Fake reporters echo the same link (attack PEM calls).
```

**Key design decision — controller sentinel value `9999u`:**
For internal controller attacks (S3 and S4 of all three families), the controller
fabricates entries in its own table. There is no external physical sender.
The `PemEmitEvent()` function requires a `physical_sender_id` argument. We use
`9999u` as a sentinel meaning "the controller itself fabricated this."
This ensures the PEM detector's BSHH-S1 signature still fires correctly, because
`physical_sender = 9999` is never equal to any real vehicle's claimed identity.
This value was chosen because it is far outside any realistic node ID range
(NS-3 assigns IDs starting from 0 sequentially).

**Key design decision — no lambda functions:**
NS-3.35's `Simulator::Schedule()` requires plain function pointers — it does not safely
support C++ lambda captures. All detection-runner logic (e.g., `TTWS2_RunDetection`,
`TTWS3_RunDetection`) was written as named `static void` functions defined *immediately
before* the attack functions that call them. This avoids both lambda issues and
C++ forward-declaration problems.

---

### Change 8 — Added mobility setup for new scenario groups

**What was added** (in `main()`, in the mobility configuration section):

```cpp
else if (attack_scenario == 2 || attack_scenario == 3 || attack_scenario == 4) {
    // TTW-S2/S3/S4:
    // V0 at (0,0), stationary — the victim
    // V1 starts near (0,0) and moves at 20 m/s — so it is within range at t=10,
    //   passes 300m (link break) at t=15, and is clearly gone by t=20
    // Other vehicles placed at y=400 (out of range, irrelevant to attack)
}
else if (attack_scenario >= 5 && attack_scenario <= 8) {
    // BSHH-S1..S4:
    // All vehicles spaced 150m apart along the x-axis.
    // At 150m spacing, every vehicle is within the 300m DSRC range of its neighbours.
    // All vehicles can exchange heartbeats with each other.
}
else if (attack_scenario >= 9 && attack_scenario <= 12) {
    // ME-S1..S4:
    // V0 at (0,0), V1 at (100,0) — the REAL link (100m apart, well within 300m)
    // V2 at (700,0), V3 at (850,0) — the echo ATTACKERS
    // V2 and V3 are >300m from V0/V1 — physically impossible to have observed the link
    // This intentional distance mismatch triggers PEM signature ME-S3:
    //   "reporter position is outside comm range of the reported link endpoints"
}
```

**Why mobility matters:** Each attack family has different physical requirements.
TTW needs a link that physically breaks (V1 must drive out of range).
BSHH needs all vehicles within range (to legitimately exchange heartbeats first).
ME needs the echo reporters to be outside comm range (to trigger the position anomaly).
Without correct initial positions and velocities, the PEM detection scores may not
match what the project proposal specifies.

---

### Change 10 — Added `--detection_enabled` command-line flag

**What was added** (in `main()`, `CommandLine` block):

```cpp
cmd.AddValue("detection_enabled",
             "1=run attack WITH PEM detection+mitigation (default), "
             "0=run attack ONLY, PEM logs but never mitigates",
             detection_enabled);
```

And the corresponding global (declared near other PEM globals):

```cpp
bool detection_enabled = true;   // default: detection ON
```

The flag gates the alert inside `PemEvaluateEvent`:

```cpp
event.alert_raised = detection_enabled && (score > PEM_SCORE_THRESHOLD);
```

**Why:** To compare the network performance with and without the detection layer.
When `detection_enabled = 0`, the attack fires and the ghost link stays in the controller
table (no mitigation). PDR stays low for the whole simulation — this gives you the
worst-case PDR for the report comparison table:

| Run mode | What you measure |
|---|---|
| `--detection_enabled=1` (default) | PDR recovery after detection; Tdet |
| `--detection_enabled=0` | Worst-case PDR; attack effect without any defence |

---

### Change 11 — Added per-scenario named XML files to `XML/` folder

**What was added** (in `main()`, immediately before `Simulator::Run()`):

```cpp
std::system("mkdir -p /home/nimesha/ns-allinone-3.35/ns-3.35/XML");
static const char* scenario_xml_names[] = {
    "00_Baseline_No_Attack",
    "01_TTW_S1_Malicious_Vehicle",
    "02_TTW_S2_Malicious_RSU",
    ...
    "12_ME_S4_Malicious_Controller_With_RSU"
};
uint32_t safe_scenario = (attack_scenario <= 12) ? attack_scenario : 0;
std::string anim_xml_path = std::string("/home/nimesha/ns-allinone-3.35/ns-3.35/XML/")
                            + scenario_xml_names[safe_scenario] + ".xml";
AnimationInterface anim(anim_xml_path);
```

**Why:** Previously every run overwrote the same `routing-animation.xml` file.
Running all 12 scenarios in sequence would keep only the last one.
Now each scenario writes its own named file — 13 files total (scenarios 0–12) — into a
dedicated `XML/` folder, making it easy to open any scenario's animation without re-running.

---

### Change 12 — Improved ME-S1 local density check and added ME-S3 RSSI condition

These are PEM accuracy improvements. See Section 17 for full details.

**Summary of what changed:**
- ME-S1 (signature 6): replaced global vehicle count estimate with local density
  (only vehicles whose beacon was received within 300m of the specific link are counted).
  Prevents false negatives in small simulations.
- ME-S3 (signature 8): added RSSI (signal strength) check alongside the position check,
  matching the full project proposal formula: `d > r_comm OR RSSI < RSSI_min`.
- `PEM_EVENT_LOG/<scenario_name>.csv`: added `rssi_reporter_dbm` as the 22nd column,
  recording the synthetic signal strength for every topology-update event.

---

### Change 9 — Added 11 scheduling blocks in main()

**What was added** (immediately before the `// RUN SIMULATION` comment, at the end of
`main()`): 11 `if (attack_scenario == N)` blocks, one per new scenario (2 through 12).

Each block does five things:

1. **Prerequisite check** — For RSU-required scenarios (2, 4, 6, 8, 10, 12):
   ```cpp
   if (N_RSUs < 1 || RSU_Nodes.GetN() < 1) {
       std::cout << "[ERROR] Scenario N requires --N_RSUs=1. Aborting.\n";
       return 1;
   }
   ```

2. **Console summary** — Prints who is attacking whom and the timeline so the user
   can verify the correct scenario is running without opening a log file.

3. **InitLog call** — Opens the variant-specific log file (e.g., `ttw_s2_attack_log.txt`).

4. **Simulator::Schedule calls** — Queues each attack phase at the correct simulated time:
   ```cpp
   Simulator::Schedule(Seconds(10.0), &TTWS2_VehiclesToRSU, v1_id, v2_id, rsu_id, 10.0);
   Simulator::Schedule(Seconds(10.1), &TTWS2_RSUForwardAggregated, rsu_id, v1_id, v2_id, 10.0);
   Simulator::Schedule(Seconds(10.2), &TTWS2_StorePacket, v1_id, v2_id, 10.0);
   Simulator::Schedule(Seconds(20.0), &TTWS2_ReplayAttack, rsu_id, v1_id, v2_id, 20.0);
   ```
   NS-3 is fully event-driven — nothing happens unless explicitly scheduled.
   The small offsets (0.1s, 0.2s) ensure steps happen in the correct order.

5. **NetAnim colours** — Tags each node with a colour and label so the visual replay
   in NetAnim immediately shows who is attacking whom (see colour guide in Section 13).

---

## 4. Understanding the Three Attack Families

### TTW — Topology Time-Warp

**What gets attacked:** The controller's topology table (`ttw_controller_table`).

**The core trick:** A link V0↔V1 is real at time T=10. At T=15 the link breaks
(V1 drives away). The attacker later injects a packet saying "V0 sees V1 at T=20"
— claiming the link is *still active* after it has physically broken.
The controller believes this and keeps the ghost route installed.

The **forgery is the timestamp**. The content of the packet (V0 once saw V1) was true
at T=10, so it looks authentic. Only the timestamp is wrong.

**The four placements:**

| | Where the forgery happens |
|---|---|
| S1 | A malicious **vehicle** (V0) does the replay over V2V |
| S2 | A malicious **RSU** does the replay (it sits between vehicles and controller) |
| S3 | The **controller itself** is compromised and replays its own stale table entry internally |
| S4 | Same as S3 but the topology arrived via RSU aggregation before being stored |

---

### BSHH — Beacon State Heartbeat Hijack

**What gets attacked:** The controller's vehicle liveness table (`bshh_controller_liveness_table`).

**The core trick:** Vehicles periodically send heartbeats: "I am V0, I am alive at T."
An attacker stores an old heartbeat from V0 (alive at T=0) and replays it later.
The controller now has two conflicting liveness entries for V0:
- The real one: V0 alive at T=5
- The replayed stale one: V0 alive at T=0

This makes the controller think V0 is at an old position or still present when it has left.

**Key difference from TTW:** TTW poisons topology (link presence). BSHH poisons
identity/liveness (vehicle presence). Different PEM signatures detect each.

**The four placements:** Same S1/S2/S3/S4 pattern as TTW.

---

### ME — Multipath Echo

**What gets attacked:** The controller's path inference (it counts reporters to infer routes).

**The core trick:** V0 and V1 have a real link. Normally V0 and V1 are the only reporters
of this link. The attacker makes additional nodes (V2, V3) also report the same link —
as if V2 and V3 independently observed V0 and V1 communicating. The controller sees
four reporters for one link and infers intermediate nodes exist:

```
Real topology:     V0 ——— V1
Phantom topology:  V0 — V2 — V1
                   V0 — V3 — V1
                   V0 — V2 — V3 — V1
```

Packets routed via phantom paths arrive at V2/V3, who have no real route to V1, and drop.

**Key difference from TTW and BSHH:** ME does not replay *old* packets. It duplicates a
*current* observation through false witnesses. Detection relies on density (too many
reporters) and position (V2 is 700m from V0/V1 — impossible to have observed the link).

---

## 5. Attack Scenario ID Map (Quick Reference)

| ID | Name | Attacker | RSU Required? |
|----|------|----------|--------------|
| 0 | Baseline | None | No |
| 1 | TTW-S1 | Malicious vehicle (V0) | No |
| 2 | TTW-S2 | Malicious RSU | **Yes** |
| 3 | TTW-S3 | Malicious controller | No |
| 4 | TTW-S4 | Malicious controller | **Yes** |
| 5 | BSHH-S1 | Malicious vehicle (V1) | No |
| 6 | BSHH-S2 | Malicious RSU | **Yes** |
| 7 | BSHH-S3 | Malicious controller | No |
| 8 | BSHH-S4 | Malicious controller | **Yes** |
| 9 | ME-S1 | Malicious vehicles V2 + V3 | No |
| 10 | ME-S2 | Malicious RSU | **Yes** |
| 11 | ME-S3 | Malicious controller | No |
| 12 | ME-S4 | Malicious controller | **Yes** |

**Rule:** Any scenario with an even number ≥ 2 and any scenario 4 requires `--N_RSUs=1`.
More precisely: scenarios 2, 4, 6, 8, 10, 12 require RSU.

---

## 6. Detailed Attack Flows — All 12 Scenarios

### Scenario 0 — Baseline (no attack)

No attack code runs. PEM records all events as benign (TN = true negatives).
Use this as the comparison baseline PDR and latency for the report.

---

### Scenario 1 — TTW-S1 (Malicious Vehicle, No RSU)

```
Nodes: V0 = attacker, V1 = victim. No RSU.
Node positions: V0 at (0,0) stationary. V1 starts near V0, moves at 20 m/s.

t=10.0s  V0 ←—HELLO——→ V1   V2V DSRC exchange (both within 300m)
t=10.0s  V0 → Controller : <V0 sees V1, timestamp=10>   LEGITIMATE, accepted
t=10.0s  V1 → Controller : <V1 sees V0, timestamp=10>   LEGITIMATE, accepted
t=10.2s  V0 stores internally : <V0 sees V1, timestamp=10>
t=15.0s  V1 reaches 300m from V0 — physical link BREAKS
t=20.0s  V0 forges timestamp : <V0 sees V1, timestamp=20>   MALICIOUS
t=20.0s  V0 → Controller : forged packet
         Controller updates table: V0↔V1 ACTIVE at t=20  ← GHOST LINK (ATTACK SUCCESS)
t=20.05s PEM detection fires (50 ms after injection)
         Signature 0: timestamp anomaly detected
         Score > 0.12 → ALERT → ghost entry removed from table
```

Log file: `ttw_attack_scenario4.txt` (name kept for backward compatibility with existing test scripts)

---

### Scenario 2 — TTW-S2 (Malicious RSU)

```
Nodes: V0, V1 = victims. RSU_0 = attacker. RSU required.

t=10.0s  V0 ←—HELLO——→ V1   V2V exchange
t=10.0s  V0 → RSU_0 : <V0 sees V1, t=10>   normal vehicle-to-RSU update
t=10.0s  V1 → RSU_0 : <V1 sees V0, t=10>   normal vehicle-to-RSU update
t=10.1s  RSU_0 (normal) → Controller : aggregated [V0↔V1, t=10]   LEGITIMATE
t=10.2s  RSU_0 (malicious) stores : <V0 sees V1, t=10>   ← saves for replay
t=15.0s  Physical link V0↔V1 BREAKS (V1 drives away)
t=20.0s  RSU_0 forges : <V0 sees V1, timestamp=20>
t=20.0s  RSU_0 → Controller : forged packet
         Controller: V0↔V1 ACTIVE  ← GHOST LINK (ATTACK SUCCESS)
t=20.05s PEM: TTWS2_RunDetection fires, signature 0 + 1, alert raised
```

Log file: `ttw_s2_attack_log.txt`

---

### Scenario 3 — TTW-S3 (Malicious Controller, No RSU)

```
Nodes: V0, V1 = victims. Controller = attacker. No RSU.
No external packet is ever forged — the controller manipulates itself.

t=10.0s  V0 → Controller : <V0 sees V1, t=10>   LEGITIMATE
t=10.0s  V1 → Controller : <V1 sees V0, t=10>   LEGITIMATE
         Controller accepts these and also secretly saves: <V0 sees V1, t=10>
t=10.1s  Controller stores stale copy internally.
t=15.0s  Physical link BREAKS.
         A normal controller would expire the t=10 entry after the timeout.
         The malicious controller does NOT expire it.
t=20.0s  Controller internally overwrites its table:
           ttw_controller_table["0_1"] = {src=0, seen=1, timestamp=20, is_forged=true}
           physical_sender_id = 9999 (sentinel: controller itself)
         Controller believes V0↔V1 ACTIVE  ← ATTACK SUCCESS (no packet sent)
         PEM fires inline at t=20.
```

Log file: `ttw_s3_attack_log.txt`

---

### Scenario 4 — TTW-S4 (Malicious Controller, With RSU)

```
Nodes: V0, V1 = victims. RSU_0 = legitimate relay. Controller = attacker.
RSU required. Data path: V → RSU → Controller.

t=10.0s  V0, V1 → RSU_0 : their topology updates (normal V2RSU)
t=10.0s  RSU_0 → Controller : aggregated update [V0↔V1, t=10]   LEGITIMATE
         Controller saves stale copy: <V0 sees V1, t=10>
t=15.0s  Physical link BREAKS.
t=20.0s  Controller internal replay: <V0 sees V1, timestamp=20>   FORGED
         Same outcome as Scenario 3.  ← ATTACK SUCCESS
```

Log file: `ttw_s4_attack_log.txt`

---

### Scenario 5 — BSHH-S1 (Malicious Vehicle, No RSU)

```
Nodes: V0 = victim. V1 = attacker. No RSU.

Background: At t=0, a heartbeat exchange happened.
  V1 secretly saved: Heartbeat(claimed=V0, physical=V0, t=0)

t=5.0s   V0 ←→ V1 : mutual heartbeat exchange (normal V2V)
t=5.0s   V0 → Controller : Heartbeat(sender=V0, t=5)   LEGITIMATE
t=5.0s   V1 → Controller : Heartbeat(sender=V1, t=5)   LEGITIMATE
         Controller liveness table: V0 last alive at t=5, V1 last alive at t=5.

t=5.1s   V1 formally stores the old heartbeat for replay: Heartbeat(claimed=V0, t=0)

t=10.0s  V1 → Controller : Heartbeat(claimed_sender=V0, physical_sender=V1, t=0)
           V1 impersonates V0 sending an OLD heartbeat directly to the controller.
         Controller now has conflicting entries for V0:
           real entry   : V0 alive at t=5
           stale replay : V0 alive at t=0  (sent by V1, not V0)
         Controller is confused about V0's actual state  ← ATTACK SUCCESS

PEM fires:
  BSHH-S1 (signature 3): physical_sender(V1) ≠ claimed_sender(V0)
  BSHH-S2 (signature 4): sender_timestamp(0) < previous known timestamp(5) — out of order
```

Log file: `bshh_s1_attack_log.txt`

---

### Scenario 6 — BSHH-S2 (Malicious RSU)

```
Nodes: V0 = victim. V1 = normal vehicle. RSU_0 = attacker. RSU required.

t=5.0s   V0, V1 → RSU_0 : heartbeats (normal V2RSU)
t=5.0s   RSU_0 → Controller : aggregated heartbeats [V0(t=5), V1(t=5)]   LEGITIMATE
t=5.1s   RSU_0 stores old heartbeat : Heartbeat(claimed=V0, t=0)

t=10.0s  RSU_0 → Controller : Heartbeat(claimed_sender=V0, physical_sender=RSU_0, t=0)
           RSU impersonates V0 sending a stale heartbeat directly to controller.
         Controller liveness for V0 becomes stale  ← ATTACK SUCCESS
```

Log file: `bshh_s2_attack_log.txt`

---

### Scenario 7 — BSHH-S3 (Malicious Controller, No RSU)

```
Nodes: V0, V1 = victims. Controller = attacker. No RSU.

t=5.0s   V0 → Controller : Heartbeat(V0, t=5)   LEGITIMATE
t=5.0s   V1 → Controller : Heartbeat(V1, t=5)   LEGITIMATE
t=5.1s   Controller secretly saves stale copies:
           Heartbeat(claimed=V0, physical=9999, t=0)
           Heartbeat(claimed=V1, physical=9999, t=0)

t=10.0s  Controller internally replaces its liveness table:
           bshh_controller_liveness_table[0] ← stale V0 at t=0
           bshh_controller_liveness_table[1] ← stale V1 at t=0
         Controller now believes V0 and V1 were last alive at t=0, not t=5.
         Routes are calculated using old vehicle state  ← ATTACK SUCCESS
```

Log file: `bshh_s3_attack_log.txt`

---

### Scenario 8 — BSHH-S4 (Malicious Controller, With RSU)

Same as Scenario 7. The only difference is that heartbeats arrive via RSU aggregation
(V → RSU → Controller) rather than directly (V → Controller).
The internal stale replay at t=10 is identical to S3.

Log file: `bshh_s4_attack_log.txt`

---

### Scenario 9 — ME-S1 (Malicious Vehicles, No RSU)

```
Nodes: V0↔V1 = real link. V2, V3 = echo attackers. No RSU.
Positions: V0=(0,0), V1=(100,0), V2=(700,0), V3=(850,0)
NOTE: V2 and V3 are more than 300m from V0/V1 — outside DSRC range.
      They physically cannot have observed the V0↔V1 link.

t=10.0s  V0 ←—HELLO——→ V1   real 100m link, normal exchange
t=10.0s  V0 → Controller : <V0 sees V1, t=10>   LEGITIMATE
t=10.0s  V1 → Controller : <V1 sees V0, t=10>   LEGITIMATE

t=10.1s  V2 → Controller : <V0 sees V1, t=10>   ECHO (V2 never observed this link)
t=10.1s  V3 → Controller : <V0 sees V1, t=10>   ECHO (V3 never observed this link)

Controller has 4 reporters for the V0↔V1 link. Infers:
  Path 1: V0 → V1          REAL
  Path 2: V0 → V2 → V1     PHANTOM (V2 is 700m from V0)
  Path 3: V0 → V3 → V1     PHANTOM (V3 is 850m from V0)
  Path 4: V0 → V2 → V3 → V1  PHANTOM
Packets routed on phantom paths are dropped  ← ATTACK SUCCESS

PEM fires:
  ME-S1 (signature 6): 4 reporters > expected density bound (≈ 2)
  ME-S3 (signature 8): V2 position (700m) and V3 position (850m) are both
                        outside the 300m comm range of the V0↔V1 link
```

Log file: `me_s1_attack_log.txt`

---

### Scenario 10 — ME-S2 (Malicious RSU)

```
Nodes: V0↔V1 = real link. RSU_0 = attacker. RSU required.

t=10.0s  V0, V1 → RSU_0 : their legitimate topology updates
t=10.0s  RSU_0 (normal) → Controller : aggregated [V0↔V1, t=10]   LEGITIMATE
t=10.1s  RSU_0 (malicious) injects additional entries into a second controller message:
           <V0 sees V1, reported by phantom V2, t=10>   FORGED
           <V0 sees V1, reported by phantom V3, t=10>   FORGED
         physical_sender = RSU_0, claimed_sender = V2 (or V3) for each forged entry
         Controller infers phantom paths via V2 and V3  ← ATTACK SUCCESS
```

Log file: `me_s2_attack_log.txt`

---

### Scenario 11 — ME-S3 (Malicious Controller, No RSU)

```
Nodes: V0↔V1 = real link. V2 = normal vehicle. Controller = attacker. No RSU.

t=10.0s  V0, V1, V2 → Controller : their own legitimate topology updates
t=10.1s  Controller (malicious) internally fabricates and adds to its database:
           <V0 sees V1, reporter = phantom V2, t=10>   FORGED
           <V0 sees V1, reporter = phantom V3, t=10>   FORGED
           physical_sender_id = 9999 (controller itself fabricated these)
         Controller infers phantom paths  ← ATTACK SUCCESS
         No external packet was ever sent.
```

Log file: `me_s3_attack_log.txt`

---

### Scenario 12 — ME-S4 (Malicious Controller, With RSU)

Same as Scenario 11. V0/V1 first report to RSU_0, which aggregates and forwards to the
controller. The controller then fabricates phantom echo entries internally, identical to S3.

Log file: `me_s4_attack_log.txt`

---

## 7. How Detection Works (PEM)

The PEM layer runs automatically — you do not need to trigger it manually.
Every time an attack function calls `PemEmitEvent()` or `PemEmitHeartbeatEvent()`,
PEM evaluates all 9 signatures against that event.

### The 9 detection signatures

| Index | Family | Name | What it checks |
|---|---|---|---|
| 0 | TTW | S1 | `reception_time − sender_timestamp > beacon_interval + epsilon` (timestamp too far in the past) |
| 1 | TTW | S2 | A newer reception but older sender timestamp than a previous event for the same link (replay contradiction) |
| 2 | TTW | S3 | Same link reported by different reporters with timestamp gap > beacon interval |
| 3 | BSHH | S1 | physical_sender_id ≠ claimed_sender_id (someone is impersonating another node) |
| 4 | BSHH | S2 | sender_timestamp < previous_timestamp for same identity (out-of-order — old packet) |
| 5 | BSHH | S3 | Heartbeat arrived but no matching beacon was seen for same identity in the recent window |
| 6 | ME | S1 | Reporter count for a link exceeds the expected density bound: `ρ > (1+0.3)·2R·λ̂` |
| 7 | ME | S2 | Path count for a link increased by more than `Δmax = 1.0` in one update |
| 8 | ME | S3 | Reporter's position is outside the DSRC communication range of the reported link's endpoints |

### Weighted score and alert threshold

```
PEM_WEIGHTS    = [0.15, 0.15, 0.10,   // TTW
                  0.15, 0.10, 0.10,   // BSHH
                  0.10, 0.075, 0.075] // ME
                  (sum = 1.0)

PEM_SCORE_THRESHOLD = 0.12
```

If `total_score ≥ 0.12`, an alert is raised:
- The ghost entry is removed from the controller table
- The event is recorded as a true positive (TP)
- Detection latency is computed: `Tdet = alert_time − pem_attack_injection_time` (ms)

### What PEM writes at end of simulation

`PemWriteRunSummaryCsv()` is called at `simTime − 0.001` seconds and writes one row to
`PEM_RUN_SUMMARY/<scenario_name>.csv` with:
`run_id, attack_scenario, detection_enabled, tp, tn, fp, fn, mcc, auroc, tdet_ms,
pdr_under_attack_pct, pdr_post_mitigation_pct, te2e_under_attack_ms, te2e_post_mitigation_ms`
(15 columns total). The `detection_enabled` column (0 or 1) makes it immediately clear
in your results table which rows came from attack-only runs versus full detection runs.

### Detection vs identification

PEM provides two levels of information:

| Level | What it tells you | How |
|---|---|---|
| **Detection** | Binary: was an attack happening? | `alert_raised = 1` |
| **Family identification** | Which family: TTW / BSHH / ME? | Which signature group fired (0-2 = TTW, 3-5 = BSHH, 6-8 = ME) |
| **Scenario identification** | Which placement: S1/S2/S3/S4? | Requires the full-stack GNN (out of scope for PEM alone) |

PEM can tell you "a TTW attack is happening" but cannot distinguish S1 from S2.
That fine-grained identification is the job of the GNN layer that sits on top of PEM.
For the FYP, PEM's family-level identification is sufficient for the detection metrics.

---

## 8. Data Structures Added to routing.cc

### Existing before our changes

```cpp
// The core topology structure
struct TopologyPacket {
    uint32_t src_id;      // node reporting the link
    uint32_t seen_id;     // neighbour being reported
    double   timestamp;   // simulation time when link was observed
    bool     is_forged;   // set true by attacker functions
};

// THE controller topology table — what the controller "believes"
// key = "src_id_seen_id"  e.g. "0_1" means V0 sees V1
// Attacker inserts forged entries here to poison routing
std::map<std::string, TopologyPacket> ttw_controller_table;
```

### New: HeartbeatPacket (for BSHH family)

```cpp
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity the heartbeat CLAIMS
    uint32_t physical_sender_id;  // who ACTUALLY transmitted it
    double   timestamp;           // when generated
    bool     is_replayed;         // true = stored replay, not a fresh heartbeat
};

// THE controller liveness table — what the controller believes about vehicle aliveness
// key = vehicle_id
std::map<uint32_t, HeartbeatPacket> bshh_controller_liveness_table;
```

### New: MEEchoReport (for ME family)

```cpp
struct MEEchoReport {
    uint32_t link_src;          // V0 — one end of the real link
    uint32_t link_dst;          // V1 — other end of the real link
    uint32_t false_reporter;    // V2 or V3 — attacker claiming to have observed it
    double   timestamp;
    bool     is_echo;           // always true for forged entries
};

// All echo reports injected during this simulation run
std::vector<MEEchoReport> me_echo_reports;
```

---

## 9. Build and Setup on Linux

### Step 1 — Copy routing.cc to NS-3 scratch directory

```bash
cp routing.cc ~/ns-3.35/scratch/routing.cc
```

### Step 2 — Fix the stray text after namespace declaration (if present)

```bash
grep -n "using namespace ns3;" ~/ns-3.35/scratch/routing.cc
# If you see "using namespace ns3;hjhjhj" → fix it:
sed -i 's/using namespace ns3;hjhjhj/using namespace ns3;/' ~/ns-3.35/scratch/routing.cc
```

### Step 3 — Build

```bash
cd ~/ns-3.35
./waf build 2>&1 | tee build_log.txt
# Check for errors:
grep "error:" build_log.txt
```

### Step 4 — Run baseline first (generates CSV files needed internally)

```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=0"
```

---

## 10. All Run Commands

All commands assume you are in `~/ns-3.35/`. Copy and paste directly.

### Baseline

```bash
./waf --run "scratch/routing --simTime=60 --N_Vehicles=10 --N_RSUs=0 --attack_scenario=0"
```

### TTW family

```bash
# TTW-S1: Malicious Vehicle
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=1"

# TTW-S2: Malicious RSU
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=1 --attack_scenario=2"

# TTW-S3: Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=3"

# TTW-S4: Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=1 --attack_scenario=4"
```

### BSHH family

```bash
# BSHH-S1: Malicious Vehicle
./waf --run "scratch/routing --simTime=20 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=5"

# BSHH-S2: Malicious RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=2 --N_RSUs=1 --attack_scenario=6"

# BSHH-S3: Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=7"

# BSHH-S4: Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=2 --N_RSUs=1 --attack_scenario=8"
```

### ME family

```bash
# ME-S1: Malicious Vehicles  (4 vehicles: V0,V1=real link; V2,V3=attackers)
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=9"

# ME-S2: Malicious RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=10"

# ME-S3: Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=11"

# ME-S4: Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=12"
```

### Attack-only mode (no detection/mitigation)

Add `--detection_enabled=0` to any attack run command.
The ghost link is never removed — the attack stays active for the full simulation.
Use this to measure worst-case PDR impact.

```bash
# Example: TTW-S2, attack fires but PEM never mitigates
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2 --detection_enabled=0"

# Example: ME-S1, attack fires but PEM never mitigates
./waf --run "scratch/routing --simTime=20 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=9 --detection_enabled=0"
```

### Attack + detection mode (default)

`--detection_enabled=1` is the default; you do not need to write it explicitly.
These two commands are equivalent:

```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=1"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=1 --detection_enabled=1"
```

### Read results immediately after any run

```bash
# Step-by-step attack log for each scenario
cat ttw_attack_scenario4.txt   # TTW-S1 (historical filename, kept for compatibility)
cat ttw_s2_attack_log.txt      # TTW-S2
cat ttw_s3_attack_log.txt      # TTW-S3
cat ttw_s4_attack_log.txt      # TTW-S4
cat bshh_s1_attack_log.txt     # BSHH-S1
cat bshh_s2_attack_log.txt     # BSHH-S2
cat bshh_s3_attack_log.txt     # BSHH-S3
cat bshh_s4_attack_log.txt     # BSHH-S4
cat me_s1_attack_log.txt       # ME-S1
cat me_s2_attack_log.txt       # ME-S2
cat me_s3_attack_log.txt       # ME-S3
cat me_s4_attack_log.txt       # ME-S4

cat PEM_RUN_SUMMARY/05_BSHH_S1_Malicious_Vehicle.csv   # Detection metrics for BSHH-S1
cat PEM_EVENT_LOG/05_BSHH_S1_Malicious_Vehicle.csv     # Per-event PEM log for BSHH-S1
cat CHANNEL_DELIVERY_ANALYSIS/05_BSHH_S1_Malicious_Vehicle.csv  # Per-channel analysis

# NetAnim XML files — in named files under XML/ folder
ls ~/ns-allinone-3.35/ns-3.35/XML/
# Opens the correct file in NetAnim for the scenario you just ran
```

---

## 11. Understanding the Output Files

### Attack log file (e.g., `ttw_s2_attack_log.txt`)

Human-readable step-by-step trace. Each scenario writes its own file, for example:

- `ttw_s2_attack_log.txt`
- `bshh_s1_attack_log.txt`
- `me_s1_attack_log.txt`

Example excerpt from TTW-S2:

```
[t=10.000]  STEP ①  V2V HELLO + topology updates to RSU_4
  V0 -> RSU : <V0 sees V1, t=10>
  V1 -> RSU : <V1 sees V0, t=10>

[t=10.200]  STEP ③  MALICIOUS RSU STORES PACKET
  old_packet : <V0 sees V1, t=10>
  Awaiting replay at t=20

[t=20.000]  STEP ④  FORGING TIMESTAMP
  Original : <V0 sees V1, t=10>
  Forged   : <V0 sees V1, t=20>  MALICIOUS

[t=20.000]  STEP ⑥  FAULTY ROUTING DECISION
  Controller believes V0<->V1 ACTIVE at t=20
  Physical reality : link BROKEN
  Consequence : packets routed via ghost link will be DROPPED

[t=20.050]  DETECTION + MITIGATION
  Ghost link V0<->V1 removed
  Score: 0.30
  Latency: 50.0 ms
```

### `pem_event_log.csv` — per-event detection log (22 columns)

| Column | Meaning |
|---|---|
| `sim_time_s` | When the event occurred |
| `event_type` | 0=beacon, 1=topology update, 2=heartbeat |
| `physical_sender_id` | Who actually sent it (9999 = controller internal fabrication) |
| `claimed_sender_id` | Who the packet claims to be from |
| `reporter_id` | Who forwarded it to the controller |
| `link_src_id` | Source node of the reported link |
| `link_dst_id` | Destination node of the reported link |
| `sender_timestamp` | Timestamp inside the packet |
| `reception_time_s` | When the controller received it |
| `reporter_x`, `reporter_y` | Reporter node position |
| `link_src_x`, `link_src_y` | Link source position |
| `link_dst_x`, `link_dst_y` | Link destination position |
| `triggered_signatures` | 9-character bitmask, one char per signature (e.g., `100000010` = sigs 0 and 7 fired) |
| `score` | Weighted sum of triggered signature weights |
| `alert_raised` | 1 = alert raised (detection enabled AND score ≥ 0.12), 0 = passed |
| `actual_attack` | 1 = this event was injected by an attack function, 0 = benign |
| `phase` | `pre_attack`, `under_attack`, or `post_mitigation` |
| `detection_latency_ms` | ms from attack injection to this alert (−1 if no alert) |
| `rssi_reporter_dbm` | Synthetic RSSI of reporter to link (log-distance path-loss model). Used in ME-S3 check. |

> **Note on `rssi_reporter_dbm`:** This column always appears. For non-ME events (TTW, BSHH, baseline)
> it holds the placeholder value `PEM_SIGNAL_PLACEHOLDER` (−999). The real computation runs
> only for topology-update events where ME-S3 signature evaluation is relevant.

### `pem_run_summary.csv` — the table for your report (15 columns)

| Column | Position | Target value | Meaning |
|---|---|---|---|
| `run_id` | 1 | — | Sequential run number |
| `attack_scenario` | 2 | — | 0–12 |
| `detection_enabled` | 3 | — | 1 = detection+mitigation on, 0 = attack-only mode |
| `tp` | 4 | ≥ 1 | True positives: attacks correctly detected |
| `tn` | 5 | high | True negatives: benign events correctly passed |
| `fp` | 6 | 0 ideally | False positives: benign events wrongly flagged |
| `fn` | 7 | 0 ideally | False negatives: attack events missed |
| `mcc` | 8 | > 0.85 | Matthews Correlation Coefficient (−1 worst, +1 perfect) |
| `auroc` | 9 | > 0.90 | Area Under ROC Curve (0.5 = random, 1.0 = perfect) |
| `tdet_ms` | 10 | < 100 ms | Detection latency (must be within one beacon interval) |
| `pdr_under_attack_pct` | 11 | — | PDR while attack is active (lower = attack more effective) |
| `pdr_post_mitigation_pct` | 12 | near baseline | PDR after PEM removes ghost entry |
| `te2e_under_attack_ms` | 13 | — | End-to-end latency under attack |
| `te2e_post_mitigation_ms` | 14 | near baseline | End-to-end latency after mitigation |

A good result row (detection enabled):
```
run_id,attack_scenario,detection_enabled,tp,tn,fp,fn,mcc,auroc,tdet_ms,pdr_under_attack_pct,pdr_post_mitigation_pct,...
1,2,1,3,97,0,0,1.000,1.000,50.1,79.2,95.8,...
```

An attack-only run row (no detection):
```
1,2,0,0,0,0,3,0.000,0.500,-1.0,38.5,38.5,...
```
`mcc = 0` and `tdet_ms = -1` because no alert ever fired. PDR stays low for the entire run
because the ghost link was never removed.

---

## 12. Running 5-Experiment Statistics for the Report

The report requires 5 independent runs per scenario with different random seeds.

### Shell script — save as `run_5_experiments.sh`

The script now accepts an optional 4th argument for `detection_enabled` (default 1).
Run all 5 seeds twice — once with detection, once without — to get both PDR columns for
the report comparison table.

```bash
#!/bin/bash
# Usage: bash run_5_experiments.sh <scenario_id> <N_Vehicles> <N_RSUs> [detection_enabled]
# Examples:
#   bash run_5_experiments.sh 2 4 1        # attack + detection (default)
#   bash run_5_experiments.sh 2 4 1 0      # attack only (no mitigation)
SCENARIO=$1
N_VEH=${2:-4}
N_RSU=${3:-0}
DET=${4:-1}                        # detection_enabled flag (1=default, 0=attack-only)

cd ~/ns-3.35

OUTDIR="results/scenario_${SCENARIO}_det${DET}"
mkdir -p "${OUTDIR}"

for SEED in 1 2 3 4 5; do
    echo "=== Run $SEED / 5 (scenario=$SCENARIO, detection=$DET) ==="
    rm -f PEM_EVENT_LOG/*.csv PEM_RUN_SUMMARY/*.csv CHANNEL_DELIVERY_ANALYSIS/*.csv *.txt

    ./waf --run "scratch/routing \
        --simTime=60 --N_Vehicles=${N_VEH} --N_RSUs=${N_RSU} \
        --attack_scenario=${SCENARIO} \
        --detection_enabled=${DET} \
        --RngRun=${SEED}"

    cp PEM_RUN_SUMMARY/*.csv "${OUTDIR}/run_${SEED}_summary.csv"
    cp PEM_EVENT_LOG/*.csv   "${OUTDIR}/run_${SEED}_events.csv"
done
echo "Done. Results in ${OUTDIR}/"
```

### Run commands for all 12 scenarios — with detection

```bash
chmod +x run_5_experiments.sh

bash run_5_experiments.sh  1  2 0 1    # TTW-S1  + detection
bash run_5_experiments.sh  2  2 1 1    # TTW-S2  + detection
bash run_5_experiments.sh  3  2 0 1    # TTW-S3  + detection
bash run_5_experiments.sh  4  2 1 1    # TTW-S4  + detection
bash run_5_experiments.sh  5  2 0 1    # BSHH-S1 + detection
bash run_5_experiments.sh  6  2 1 1    # BSHH-S2 + detection
bash run_5_experiments.sh  7  2 0 1    # BSHH-S3 + detection
bash run_5_experiments.sh  8  2 1 1    # BSHH-S4 + detection
bash run_5_experiments.sh  9  4 0 1    # ME-S1   + detection
bash run_5_experiments.sh 10  4 1 1    # ME-S2   + detection
bash run_5_experiments.sh 11  4 0 1    # ME-S3   + detection
bash run_5_experiments.sh 12  4 1 1    # ME-S4   + detection
```

### Run commands for all 12 scenarios — attack only (no detection)

```bash
bash run_5_experiments.sh  1  2 0 0    # TTW-S1  attack only
bash run_5_experiments.sh  2  2 1 0    # TTW-S2  attack only
bash run_5_experiments.sh  3  2 0 0    # TTW-S3  attack only
bash run_5_experiments.sh  4  2 1 0    # TTW-S4  attack only
bash run_5_experiments.sh  5  2 0 0    # BSHH-S1 attack only
bash run_5_experiments.sh  6  2 1 0    # BSHH-S2 attack only
bash run_5_experiments.sh  7  2 0 0    # BSHH-S3 attack only
bash run_5_experiments.sh  8  2 1 0    # BSHH-S4 attack only
bash run_5_experiments.sh  9  4 0 0    # ME-S1   attack only
bash run_5_experiments.sh 10  4 1 0    # ME-S2   attack only
bash run_5_experiments.sh 11  4 0 0    # ME-S3   attack only
bash run_5_experiments.sh 12  4 1 0    # ME-S4   attack only
```

### Compute mean ± std — save as `compute_stats.py`

```python
import pandas as pd, glob, sys

scenario_id = sys.argv[1]
det = sys.argv[2] if len(sys.argv) > 2 else "1"   # default: detection runs

files = glob.glob(f"results/scenario_{scenario_id}_det{det}/run_*_summary.csv")
if not files:
    print(f"No files found for scenario {scenario_id} det={det}")
    sys.exit(1)

df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

cols = ['mcc', 'auroc', 'tdet_ms',
        'pdr_under_attack_pct', 'pdr_post_mitigation_pct',
        'te2e_under_attack_ms', 'te2e_post_mitigation_ms']

label = "with detection" if det == "1" else "attack-only (no detection)"
print(f"\n=== Scenario {scenario_id} — {label} (n={len(df)}) ===")
for col in cols:
    if col in df.columns:
        print(f"  {col:35s}: {df[col].mean():.3f} ± {df[col].std():.3f}")
```

```bash
python3 compute_stats.py 1 1   # TTW-S1, with detection
python3 compute_stats.py 1 0   # TTW-S1, attack-only (PDR impact without defence)
python3 compute_stats.py 9 1   # ME-S1,  with detection
python3 compute_stats.py 9 0   # ME-S1,  attack-only
```

---

## 13. NetAnim Visualization Color Guide

Each simulation run now writes its own named XML file to the `XML/` folder instead of
overwriting a single `routing-animation.xml`. See Section 16 for the full file list and
how to open them.

Open the relevant XML file in the NetAnim application:

| Colour | Node role |
|---|---|
| RED (255, 0, 0) — large | Malicious attacker node (vehicle, RSU, or controller) |
| BLUE (0, 150–200, 255) | Victim node |
| GREEN (0, 255, 100) | Normal / uninvolved vehicle |
| ORANGE (255, 200, 0) | RSU that is in the data path but NOT malicious (S4 variants) |
| PURPLE (255, 0, 255) | Controller when it is NOT the attacker |
| RED (255, 0, 0) — large | Controller when it IS the attacker (S3/S4 variants) |

Node labels visible in NetAnim:

| Label | Meaning |
|---|---|
| `V1-Victim`, `V2-Victim` | Nodes being targeted by the attack |
| `V2-Attacker` | The malicious vehicle |
| `RSU-Attacker` | Malicious RSU (scenarios 2, 6, 10) |
| `RSU-In-Path` | Legitimate RSU relay, not attacking (scenarios 4, 8, 12) |
| `Controller-Attacker` | Malicious controller (scenarios 3, 4, 7, 8, 11, 12) |
| `V1-Real`, `V2-Real` | The endpoints of the real physical link (ME attacks) |
| `V3-Echo`, `V4-Echo` | Malicious echo reporters (ME attacks) |

---

## 14. Common Errors and Fixes

### Error: `[ERROR] TTW-S2 requires --N_RSUs=1. Aborting.`

Scenarios 2, 4, 6, 8, 10, 12 all require at least one RSU. Add `--N_RSUs=1` to the command.

```bash
# Wrong:
./waf --run "scratch/routing --attack_scenario=2"
# Correct:
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2"
```

### Error: `pem_run_summary.csv` is empty or missing

The simulation was stopped early (Ctrl+C) before `PemWriteRunSummaryCsv()` ran at
`simTime − 0.001`. Let it finish. For quick tests use `--simTime=25`.

### Error: `MCC = 0` in the summary

No attack event reached PEM with `attack_label = true`. Check:
1. Is `attack_scenario` the right number?
2. Is `simTime` long enough? TTW injects at t=20 → needs `simTime > 20`. BSHH/ME inject at t=10 → needs `simTime > 10`.
3. For RSU scenarios: did you pass `--N_RSUs=1`?

### Error: `No such file or directory` for optimization CSV files

Run the baseline simulation first to generate them:
```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --attack_scenario=0"
```

### Error: `Segmentation fault`

Usually a node index is out of bounds. The most common cause: `N_Vehicles` is too small
for the scenario (e.g., ME needs 4 vehicles: V0, V1 = real link; V2, V3 = echo reporters). Use
`--N_Vehicles=4` for all families (TTW, BSHH, ME). TTW-S1 can use as few as 2.

### NetAnim shows no arrows or movement

The `routing-animation.xml` file may be from a previous run. Always clear old output files
before a new run, or the new run appends and the timestamps become confusing:
```bash
rm -f routing-animation.xml *.txt
rm -f PEM_EVENT_LOG/*.csv PEM_RUN_SUMMARY/*.csv CHANNEL_DELIVERY_ANALYSIS/*.csv
./waf --run "scratch/routing ..."
```

---

## 15. Running Attacks Without Detection (attack-only mode)

### Why you need attack-only runs

The project report needs to show two things side by side:
1. How badly the attack degrades PDR without any defence.
2. How well the detection+mitigation restores PDR.

To compare these you need two sets of runs for each scenario:

```
Normal run (detection_enabled=1):
  → PDR drops during attack → PEM fires alert → ghost link removed → PDR recovers
  → Report shows: pdr_under_attack vs pdr_post_mitigation (both in one run)

Attack-only run (detection_enabled=0):
  → PDR drops during attack → ghost link STAYS → PDR stays low for entire simulation
  → Report shows: worst-case PDR without any defence mechanism
```

### What `--detection_enabled=0` actually does in routing.cc

Only one line of code is affected:

```cpp
// In PemEvaluateEvent(), at the point where the alert decision is made:
event.alert_raised = detection_enabled && (score > PEM_SCORE_THRESHOLD);
```

When `detection_enabled = false`:
- PEM still computes scores and writes to `PEM_EVENT_LOG/<scenario_name>.csv` (the log is always written)
- `alert_raised` is always 0 — no alert fires
- No ghost entry is ever removed from `ttw_controller_table` or `bshh_controller_liveness_table`
- The summary CSV records `tp = 0`, `mcc = 0`, `tdet_ms = -1` for the run in `PEM_RUN_SUMMARY/<scenario_name>.csv`

### Run commands comparison

```bash
# TTW-S2 — with detection (ghost link removed at t≈20.05s, PDR recovers)
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2 --detection_enabled=1"

# TTW-S2 — attack only (ghost link stays, PDR never recovers)
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2 --detection_enabled=0"

# Compare the pdr_post_mitigation_pct column between the two runs
# The gap between them quantifies the benefit of the detection layer
```

### What to expect in `PEM_RUN_SUMMARY/<scenario_name>.csv`

```
# With detection (detection_enabled=1):
run_id,attack_scenario,detection_enabled,tp,tn,fp,fn,mcc,auroc,tdet_ms,...
1,2,1,3,97,0,0,1.000,1.000,50.2,78.4,95.1,...

# Attack only (detection_enabled=0):
1,2,0,0,0,0,3,0.000,0.500,-1.0,38.5,38.5,...
```

The `pdr_post_mitigation_pct` in the attack-only row equals `pdr_under_attack_pct`
because there is no mitigation — PDR stays at the attack-degraded level.

---

## 16. Per-Scenario NetAnim XML Files

### What changed

Previously every run wrote `routing-animation.xml` in the NS-3 working directory,
overwriting the previous run's file. Now each run writes a named file inside
`/home/nimesha/ns-allinone-3.35/ns-3.35/XML/`:

```
XML/
├── 00_Baseline_No_Attack.xml
├── 01_TTW_S1_Malicious_Vehicle.xml
├── 02_TTW_S2_Malicious_RSU.xml
├── 03_TTW_S3_Malicious_Controller_No_RSU.xml
├── 04_TTW_S4_Malicious_Controller_With_RSU.xml
├── 05_BSHH_S1_Malicious_Vehicle.xml
├── 06_BSHH_S2_Malicious_RSU.xml
├── 07_BSHH_S3_Malicious_Controller_No_RSU.xml
├── 08_BSHH_S4_Malicious_Controller_With_RSU.xml
├── 09_ME_S1_Malicious_Vehicles.xml
├── 10_ME_S2_Malicious_RSU.xml
├── 11_ME_S3_Malicious_Controller_No_RSU.xml
└── 12_ME_S4_Malicious_Controller_With_RSU.xml
```

### How to list and open them

```bash
# List all XML files
ls ~/ns-allinone-3.35/ns-3.35/XML/

# Check file sizes (non-zero = simulation wrote data)
ls -lh ~/ns-allinone-3.35/ns-3.35/XML/

# Open a specific scenario in NetAnim (Linux)
# Replace the path with the actual NetAnim binary location on your machine
netanim ~/ns-allinone-3.35/ns-3.35/XML/02_TTW_S2_Malicious_RSU.xml

# Or from within the NetAnim GUI: File → Open → navigate to XML/ folder
```

### The XML folder is created automatically

The code runs `std::system("mkdir -p /home/nimesha/ns-allinone-3.35/ns-3.35/XML")` at
simulation startup. If the folder already exists the `mkdir -p` command does nothing —
no error. The folder does NOT need to be created manually.

### What you see in NetAnim for each scenario

When you open an XML file in NetAnim and press Play:
- **Red nodes** — the attacker(s). Large red = high-priority attacker.
- **Blue nodes** — victim vehicles (the ones being targeted).
- **Green nodes** — uninvolved bystander vehicles.
- **Orange nodes** — legitimate RSU relay (present in S4 variants but not malicious).
- **Purple or red node far from vehicles** — the SDN controller.
- **Arrows between nodes** — simulated packet transmissions (HELLO, topology updates, forged packets).

The attack forgery step is visible as an arrow from the attacker to the controller
at t=20s for TTW, t=10s for BSHH/ME.

---

## 17. PEM Accuracy Improvements (ME-S1 and ME-S3)

These changes were made to fix two issues where PEM was not detecting ME attacks
reliably in small simulations. No new attack scenarios were added — only the
detection logic for existing ME signatures was improved.

### Problem 1: ME-S1 was not firing in small simulations

**Signature 6 (ME-S1):** Fires when the number of reporters for a link exceeds the
expected density bound: `reporters > (1 + tolerance) × expected_reporters`.

**Old code:** Used a global vehicle density estimate: divided total active vehicles by the
road length to get λ̂, then computed expected reporters as `2 × r_comm × λ̂`.
With 6 vehicles spread over a long road, λ̂ was very small, making the bound too large.
Example: 6 vehicles, λ̂ = 0.01, rhoMax ≈ 7.8 → 4 reporters never exceeded 7.8 → signature never fired.

**New code:** Uses local density. Instead of counting all vehicles, it counts only the
vehicles whose recent beacon was received within `r_comm = 300m` of the specific link's
endpoints:

```cpp
std::set<uint32_t> vehiclesNearLink;
for (each recent beacon event w in PEM window) {
    double dToSrc = distance(w.position, link_src_position);
    double dToDst = distance(w.position, link_dst_position);
    if (min(dToSrc, dToDst) <= TTW_COMM_RANGE)
        vehiclesNearLink.insert(w.claimed_sender_id);
}
double localRhoMax = (1.0 + PEM_ME_TOLERANCE_MU) * vehiclesNearLink.size();
double effectiveRhoMax = max(localRhoMax, 2.0);   // floor: never less than 2
if (reporters.size() > effectiveRhoMax) triggered[6] = true;
```

**Why this works for ME scenarios:** In ME-S1, V2 and V3 (the echo attackers) are placed
at (700,0) and (850,0) — more than 300m from the real link at (0,0)↔(100,0). Their
beacons do NOT appear in `vehiclesNearLink`. Only V0 and V1 do. So `vehiclesNearLink = 2`,
`effectiveRhoMax = 2.6`, and 4 reporters fires the signature.

---

### Problem 2: ME-S3 RSSI check was missing

**Signature 8 (ME-S3):** The project proposal formula is:

```
Trigger if: d(reporter, link) > r_comm  OR  RSSI(reporter → link) < RSSI_min
```

**Old code:** Only checked the distance condition (`d > r_comm`). The RSSI condition was not implemented.

**New code:** Both conditions are evaluated. A synthetic RSSI is computed from the
log-distance path-loss model:

```cpp
const double safeDistance = max(nearestDistance, 1.0);   // prevent log(0)
const double syntheticRSSI = PEM_RSSI_REF_DBM
    - 10.0 * PEM_PATH_LOSS_EXP * log10(safeDistance);
event.rssi_reporter_dbm = syntheticRSSI;

const bool positionOutOfRange = (nearestDistance > TTW_COMM_RANGE);
const bool rssiTooWeak        = (syntheticRSSI < PEM_RSSI_MIN_DBM);
if (positionOutOfRange || rssiTooWeak) triggered[8] = true;
```

**The three path-loss constants (defined as globals):**

| Constant | Value | Meaning |
|---|---|---|
| `PEM_RSSI_REF_DBM` | −40.0 dBm | Reference RSSI at 1m |
| `PEM_PATH_LOSS_EXP` | 2.75 | Path-loss exponent (urban DSRC typical value) |
| `PEM_RSSI_MIN_DBM` | −108.1 dBm | Threshold = −40 − 10×2.75×log10(300) = −40 − 68.1 |

**Why `log10(300)` is precomputed as a literal (2.4771):** C++ does not allow `std::log10`
inside a `static const double` initializer at file scope. Using the literal
`10.0 * 2.75 * 2.4771 = 68.12` makes the constant compile cleanly:
`PEM_RSSI_MIN_DBM = −40.0 − 68.12 = −108.1 dBm`.

**Why both conditions together:** The distance check and the RSSI check are theoretically
equivalent (path-loss is monotone in distance). Using both provides defence against edge
cases such as GPS spoofing: an attacker might forge its position to appear inside 300m,
but the signal strength (derived from physics, not the packet's claimed position) still
reveals the true distance.

---

## Appendix — Complete Scenario Reference Card

```
ID  FAMILY   ATTACKER                   RSU?  simTime  N_Vehicles  N_RSUs
────────────────────────────────────────────────────────────────────────────
 0  None     —                          No      60         10          0
 1  TTW-S1   Malicious vehicle V0       No      30          2          0
 2  TTW-S2   Malicious RSU              YES     30          2          1
 3  TTW-S3   Malicious controller       No      30          2          0
 4  TTW-S4   Malicious controller       YES     30          2          1
 5  BSHH-S1  Malicious vehicle V1       No      20          2          0
 6  BSHH-S2  Malicious RSU              YES     20          2          1
 7  BSHH-S3  Malicious controller       No      20          2          0
 8  BSHH-S4  Malicious controller       YES     20          2          1
 9  ME-S1    Malicious vehicles V2+V3   No      20          4          0
10  ME-S2    Malicious RSU              YES     20          4          1
11  ME-S3    Malicious controller       No      20          4          0
12  ME-S4    Malicious controller       YES     20          4          1
────────────────────────────────────────────────────────────────────────────

KEY CONSTANTS IN routing.cc:
  DSRC range           : 300 m     (TTW_COMM_RANGE)
  Beacon interval      : 100 ms    (PEM_BEACON_INTERVAL_S = 0.1)
  Detection budget     : 100 ms    (PEM_BEACON_BUDGET_MS)
  PEM score threshold  : 0.12      (PEM_SCORE_THRESHOLD)
  Controller sentinel  : 9999u     (physical_sender_id for internal attacks)
  RSSI reference       : −40.0 dBm (PEM_RSSI_REF_DBM, at 1m)
  Path-loss exponent   : 2.75      (PEM_PATH_LOSS_EXP, urban DSRC)
  RSSI minimum         : −108.1 dBm (PEM_RSSI_MIN_DBM, threshold at 300m edge)

ATTACK INJECTION TIMES:
  TTW  : attack injects at t=20s (after link breaks at t=15s)
  BSHH : attack injects at t=10s (after exchange at t=5s)
  ME   : attack injects at t=10.1s (0.1s after real discovery at t=10s)

NEW FLAG:
  --detection_enabled=1  (default) attack + PEM detection + mitigation
  --detection_enabled=0            attack only — ghost link stays, PDR impact visible

OUTPUT FILE LOCATIONS:
  PEM_EVENT_LOG/<scenario_name>.csv         : 22 columns (incl. rssi_reporter_dbm)
  PEM_RUN_SUMMARY/<scenario_name>.csv       : 15 columns (incl. detection_enabled as col 3)
  CHANNEL_DELIVERY_ANALYSIS/<scenario_name>.csv : 6 columns — per-channel tx/rx/fanout analysis
  XML/<scenario_name>.xml                   : per-scenario NetAnim animation (in XML/ folder)
  *_attack_log.txt                          : per-scenario human-readable attack log

PEM TARGET METRICS (project proposal):
  MCC    > 0.85
  AUROC  > 0.90
  Tdet   < 100 ms
  PDR post-mitigation should recover to near-baseline
────────────────────────────────────────────────────────────────────────────
```

---

---

## 18. RSU and RSU Network Explained

### What is an RSU?

An RSU (Road-Side Unit) is a **fixed infrastructure node** placed beside the road —
at intersections, on lamp posts, or along highways. Unlike vehicles, RSUs do not move.
They stay at a fixed GPS coordinate for the entire simulation.

---

### Role in the SDVN Architecture

```
  [Vehicle V0] ←── DSRC 300m ──→ [RSU_0] ←── Wired Ethernet ──→ [SDN Controller]
  [Vehicle V1] ←── DSRC 300m ──→ [RSU_0]
  [Vehicle V2] ←── DSRC 300m ──→ [RSU_0]
```

RSUs sit between vehicles (wireless DSRC side) and the controller (wired backhaul side).

| Task | What the RSU does |
|---|---|
| **Relay** | Receives DSRC beacons from vehicles within 300 m, forwards to controller |
| **Aggregate** | Bundles multiple vehicle reports into one message — reduces controller load |
| **Coverage extension** | Vehicles out of V2V range can still reach the controller via RSU |
| **Attack role (S2)** | Malicious RSU intercepts, stores, and replays forged packets to controller |
| **Relay role (S4)** | Legitimate RSU passes data to controller; the controller itself is the attacker |

---

### How RSUs Are Set Up in routing.cc

```cpp
// Declaration (line ~96898)
NodeContainer RSU_Nodes;
RSU_Nodes.Create(N_RSUs);        // controlled by --N_RSUs flag on command line

// RSUs share the same 802.11p DSRC channel as vehicles
dsrc_Nodes.Add(Vehicle_Nodes);
dsrc_Nodes.Add(RSU_Nodes);       // RSUs get a WifiNetDevice through dsrc_Nodes

// RSUs use ConstantPositionMobilityModel — they never move
// Vehicles use WaypointMobilityModel — they move along road paths
```

---

### RSU Coverage in a Real Deployment

```
Road:  ─────────────────────────────────────────────────────────────────
               [RSU_0]           [RSU_1]           [RSU_2]
               |←300m→|         |←300m→|         |←300m→|

Vehicles moving along the road hand off from one RSU coverage zone to the next.
Each RSU covers a 300 m radius (DSRC range = TTW_COMM_RANGE = 300 m).
```

In this project, `--N_RSUs=1` is used for all RSU-required attack scenarios. A single
RSU is sufficient because the attack vehicles (V0, V1) are placed within 300 m of
RSU_Nodes.Get(0) at simulation start.

---

### What the RSU Does in Each Attack Family

#### TTW-S2 — Malicious RSU

```
t=10  V0 → RSU_0 : <V0 sees V1, t=10>    (legitimate DSRC beacon, RSU receives)
t=10  V1 → RSU_0 : <V1 sees V0, t=10>    (legitimate DSRC beacon, RSU receives)
t=10  RSU_0 → Controller : aggregate [V0↔V1, t=10]    LEGITIMATE forward

      RSU_0 secretly stores: <V0 sees V1, t=10>  ← for later replay

t=15  Physical link V0↔V1 breaks (V1 drives away beyond 300 m)
t=20  RSU_0 forges timestamp and sends:
      RSU_0 → Controller : <V0 sees V1, t=20>    FORGED
      Controller believes V0↔V1 is still ACTIVE  ← ATTACK SUCCESS
```

#### TTW-S4 — Legitimate RSU, Malicious Controller

```
t=10  V0, V1 → RSU_0 : legitimate DSRC beacons
t=10  RSU_0 → Controller : aggregate [V0↔V1, t=10]    LEGITIMATE (RSU is innocent)
      Controller secretly saves: <V0 sees V1, t=10>

t=15  Physical link breaks
t=20  Controller INTERNALLY replays: <V0 sees V1, t=20>    FORGED (no external packet)
      RSU did nothing wrong — the controller is the attacker in S4 variants
```

The same S2 vs S4 pattern applies to BSHH and ME families.

---

### RSU-Required Scenarios and Run Commands

Scenarios 2, 4, 6, 8, 10, 12 all require `--N_RSUs=1`. The code aborts with an error
if you forget it:

```bash
# Wrong — will print [ERROR] and abort:
./waf --run "scratch/routing --attack_scenario=2"

# Correct:
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2"
```

The guard inside each RSU scenario block in main():

```cpp
if (N_RSUs < 1 || RSU_Nodes.GetN() < 1) {
    std::cout << "[ERROR] This scenario requires --N_RSUs=1. Aborting.\n";
    return 1;
}
```

---

### Vehicle vs RSU — Quick Comparison

| Property | Vehicle | RSU |
|---|---|---|
| Moves? | Yes | **No** (fixed position) |
| Has DSRC radio (802.11p)? | Yes | Yes |
| Has wired link to controller? | No | **Yes** (Ethernet backhaul) |
| Mobility model | `WaypointMobilityModel` | `ConstantPositionMobilityModel` |
| Container | `Vehicle_Nodes` | `RSU_Nodes` |
| Role in S1/S3 attacks | Attacker or victim | Not present (`--N_RSUs=0`) |
| Role in S2 attacks | Victim | **Attacker** |
| Role in S4 attacks | Victim | **Legitimate relay** (controller is attacker) |
| Global NS-3 node ID | Assigned first (lower IDs) | Assigned after vehicles (higher IDs) |

---

## 19. Questions and Answers — Conceptual Session (2026-05-01)

This section records every question that was raised about the implementation,
the root cause of each issue, and exactly how it was resolved. Anyone reading this
can understand both what was wrong and why the fix works.

---

### Q1 — What are the custom data tags in routing.cc? Why are there so many?

**Question:** The file defines dozens of classes like `CustomDataTag1`, `CustomDataTag2`,
`CustomMetaDataUnicastTag0`–`CustomMetaDataUnicastTag25`. What are they and why are there
so many nearly identical classes?

**Answer:**

In NS-3, a `Tag` is a metadata object attached to a `Packet`. Unlike a `Header`, it does
not add bytes to the simulated packet size. Tags are used to pass cross-layer information
(e.g., the sender's GPS position) alongside a packet without affecting measured overhead.

Every NS-3 Tag class must implement `GetSerializedSize()`, which must return a
**compile-time constant** — it cannot vary at runtime. This is the core constraint.

The project needs to send arrays of neighbour IDs alongside beacons, and the array length
varies (a vehicle with 3 neighbours needs a different-sized array than one with 7). Since
the size must be constant, a separate class is required for each possible array length.

There are three groups:

| Group | Classes | Attached to | Why many? |
|---|---|---|---|
| `CustomDataTag` + `CustomDataTag1`–`20` | 21 | DSRC V2V broadcast beacons | One per possible neighbour count 0–20 |
| `CustomDataUnicastTag_Routing` | 1 | Unicast routing packets | Array sized to compile-time constant `max1` — only one needed |
| `CustomMetaDataUnicastTag0`–`25` | 26 | LTE uplink metadata to controller | One per possible neighbour count 0–25 |

**Total: 48 Tag classes. All exist for the same reason: NS-3 fixed-size serialization constraint.**

---

### Q2 — What is DSRC?

**Question:** What does DSRC stand for and how does it work in this project?

**Answer:**

DSRC = **Dedicated Short-Range Communication**. Standard: IEEE 802.11p (also called WAVE).

| Property | Value |
|---|---|
| Frequency | 5.9 GHz |
| Range | Up to 300–1000 m (project uses 300 m) |
| Latency | ~1–10 ms |
| Purpose | Vehicle-to-vehicle (V2V) and vehicle-to-infrastructure (V2I) safety messages |
| Key advantage | No base station needed — vehicles communicate directly |

In routing.cc, every vehicle broadcasts a DSRC beacon every 100 ms. The beacon carries
the vehicle's position, velocity, acceleration, and its list of current neighbours.
Any vehicle or RSU within 300 m picks it up via the `Rx()` callback. This is how the
SDN controller learns the topology: vehicles overhear each other's DSRC beacons and
report "I can see V1 right now" up through the control channel.

The `CustomDataTag` family (see Q1) carries the payload of these DSRC beacon packets.

---

### Q3 — Did the attack functions use the custom data tags?

**Question:** The attack scenarios (TTW, BSHH, ME) are supposed to model V2V communication.
Did the attack code use the `CustomDataTag` mechanism to send real DSRC packets?

**Answer: No.**

The attack functions did not send any real NS-3 packets at all. They simulated V2V
communication by directly writing to data structures and log files:

```cpp
// What the attack "HELLO exchange" actually did:
ttw_log << "V0 <--HELLO--> V1\n";                    // just a log line
ttw_controller_table["0_1"] = {0, 1, 10.0, false};   // direct table write
```

No `Packet` object was created, no socket was used, no `CustomDataTag` was attached.
The communication existed only as text in a log file.

---

### Q4 — Is this a mistake?

**Question:** Since the baseline scenario uses real NS-3 DSRC packets but the attack
scenarios only pretend to send packets, was the implementation wrong?

**Root cause:** Yes — it was a simplification that created an inconsistency:

| | Baseline (scenario 0) | Attack scenarios (1–12) |
|---|---|---|
| V2V HELLO | Real NS-3 DSRC packet via `WifiNetDevice::Send()` | Log text only |
| `Rx()` callback fires? | Yes — neighbour tables updated | No |
| NetAnim shows real arrows? | Yes | Only manual animation arrows |
| Consistent with NS-3 simulation? | Yes | No |

For measuring PEM detection metrics (MCC, AUROC, Tdet) the simplification still gives
correct numbers — the PEM logic does not care how a packet arrived, only what it contains.
But for a complete NS-3 simulation where V2V communication is physically modelled, it was
incomplete.

---

### Q5 — How was it fixed?

**Fix implemented:** Two helper functions were added to routing.cc, and all 12 "legitimate
exchange" functions were updated to call them.

**Helper 1 — `AttackGetDSRCDevice(Ptr<Node>)`:**
Iterates a node's device list and returns its `WifiNetDevice` (the 802.11p DSRC interface).
This is needed because the `wifidevices` container is local to `main()` and cannot be
accessed from the attack functions.

```cpp
static Ptr<WifiNetDevice> AttackGetDSRCDevice(Ptr<Node> node) {
    for (uint32_t i = 0; i < node->GetNDevices(); i++) {
        Ptr<WifiNetDevice> w = DynamicCast<WifiNetDevice>(node->GetDevice(i));
        if (w) return w;
    }
    return nullptr;
}
```

**Helper 2 — `AttackSendDSRCBeacon(sender_node, neighbor_node)`:**
Creates a real NS-3 `Packet`, attaches a `CustomDataTag1` with the sender's current
position/velocity from the mobility model, and sends via `WifiNetDevice::Send()` using
MAC broadcast address and WAVE ethertype `0x88dc` — exactly the same mechanism as the
baseline `dsrc_data_broadcast()`.

```cpp
static void AttackSendDSRCBeacon(Ptr<Node> sender_node, Ptr<Node> neighbor_node) {
    Ptr<WifiNetDevice> wdi = AttackGetDSRCDevice(sender_node);
    if (!wdi) return;
    // ... get position/velocity from mobility model ...
    Ptr<Packet> pkt = Create<Packet>(0);
    CustomDataTag1 tag;
    // ... attach tag with sender ID, neighbour ID, position, velocity ...
    pkt->AddPacketTag(tag);
    wdi->Send(pkt, Mac48Address::GetBroadcast(), 0x88dc);  // real DSRC send
}
```

**12 functions modified** (2 DSRC calls added at the end of each):

| Scenario | Function modified |
|---|---|
| 1 TTW-S1 | `TTW_SendHelloBeacon()` |
| 2 TTW-S2 | `TTWS2_VehiclesToRSU()` |
| 3 TTW-S3 | `TTWS3_ReceiveLegitimateUpdates()` |
| 4 TTW-S4 | `TTWS4_VehiclesToRSU()` |
| 5 BSHH-S1 | `BSHH_S1_LegitimateExchange()` |
| 6 BSHH-S2 | `BSHH_S2_LegitimateExchange()` |
| 7 BSHH-S3 | `BSHH_S3_LegitimateExchange()` |
| 8 BSHH-S4 | `BSHH_S4_VehiclesToRSU()` |
| 9 ME-S1 | `ME_S1_LegitimateDiscovery()` |
| 10 ME-S2 | `ME_S2_LegitimateDiscovery()` |
| 11 ME-S3 | `ME_S3_LegitimateDiscovery()` |
| 12 ME-S4 | `ME_S4_VehiclesViaRSU()` |

**What was NOT changed:** The replay/echo/internal-replay attack injection functions
(`TTW_ReplayAttack`, `BSHH_S1_ReplayAttack`, `ME_S1_EchoAttack`, etc.) were left as
direct table writes. These model control-plane forgeries — there is no physical DSRC
radio event for a timestamp forgery or internal controller table manipulation, so direct
writes are correct for those steps.

**What changed in the simulation after the fix:**
- The NS-3 `Rx()` receive callback (line ~121642) now fires when attack beacons arrive
- `add_neighbor_info()` and `add_received_data_at_nodes()` are called — neighbour tables updated
- NetAnim XML files now show real packet arrows between vehicles at the HELLO/heartbeat step
- PEM detection metrics (MCC, AUROC, Tdet) are unaffected — `Rx()` does not touch
  `ttw_controller_table` or `bshh_controller_liveness_table`

**Commit:** `d81f3d0` — "Add real DSRC 802.11p packet sends to all 12 attack legitimate-exchange steps"

---

---

## 20. Questions and Answers — Conceptual Session (2026-05-02)

This section records every conceptual question raised in the 2026-05-02 session and
the detailed answers. All topics relate to the DSRC channel system, mobility traces,
message types, and the per-channel power analysis feature that was added.

---

### Q6 — What are the 7 DSRC/WAVE channels? Why are there so many tag classes?

**Question:** In routing.cc there are tag classes like `CustomMetaDataUnicastTagN172`
and groups `N01`–`N7`. Is this related to the 7 channels?

**Answer: Yes.**

The DSRC/WAVE standard divides the 5.9 GHz band into **7 channels** of 10 MHz each:

| Channel | Frequency | Type | Purpose |
|---------|-----------|------|---------|
| 172 | 5.860 GHz | SCH | Service Channel — application data |
| 174 | 5.870 GHz | SCH | Service Channel |
| 176 | 5.880 GHz | SCH | Service Channel |
| **178** | **5.890 GHz** | **CCH** | **Control Channel — safety beacons, heartbeats** |
| 180 | 5.900 GHz | SCH | Service Channel |
| 182 | 5.910 GHz | SCH | Service Channel |
| 184 | 5.920 GHz | SCH | Service Channel |

Channel 178 (CCH) is where all safety messages go. The others are service channels.

In routing.cc the code creates one `YansWifiPhyHelper` per channel (Phy, Phy_172, …, Phy_184),
one `WifiHelper` per channel, and installs separate device containers (`wifidevices`,
`wifidevices_172`, …, `wifidevices_184`).

The `CustomMetaDataUnicastTagN172` tag class is named after channel 172. There are 7
groups of tag classes (one per channel), each with 26 neighbour-count variants (for different
topology sizes). **7 × 26 = 182 tag classes** — this is why the file is 140,000+ lines.

The channel is chosen dynamically at runtime based on the number of pending data subflows
(lines ~123791–123809): more pending subflows → use CCH 178; fewer → use lower channels.

Attack helpers (`AttackSendDSRCBeacon`, `AttackSendHeartbeat`) always broadcast on the
**primary CCH 178** device (the first WifiNetDevice returned by `AttackGetDSRCDevice()`).
Ethertype `0x88dc` = WAVE Short Message Protocol (WSMP).

---

### Q7 — What is a mobility trace file and what does mobility_scenario mean?

**Question:** What is a "mobility trace file"? What does `mobility_scenario` = 1 mean?

**Answer:**

**Mobility trace file:** A pre-generated CSV file produced by
**SUMO (Simulation of Urban MObility)**, an open-source traffic simulator. It contains
the position (x, y) and velocity of every vehicle at every timestep. NS-3 reads this file
and moves each vehicle node to the correct position during simulation — it does not
compute vehicle movement itself.

The files are at `/home/nimesha/` (the hardcoded path in routing.cc):

| `mobility_scenario` value | Environment | Trace file |
|---------------------------|-------------|------------|
| `0` (default) | Urban | `centralized_mobility_<maxspeed>.csv` |
| `1` | Rural / Non-urban | `centralized_mobility_rural_<maxspeed>.csv` |
| `2` | Highway | `centralized_mobility_highway_<maxspeed>.csv` |

`<maxspeed>` comes from the `--maxspeed` command-line parameter (default 80 km/h).

**Why it matters for attacks:**
- Vehicle positions determine whether two nodes are within 300 m DSRC range
- A link break in TTW attacks happens when V1 drives beyond 300 m from V0 — this timing
  depends on speed from the mobility trace
- ME-S3 signature checks whether the echo reporter is within 300 m of the reported link —
  this uses the reporter's current position from the mobility model

**`mobility_scenario = 1` was chosen** for the channel power analysis because rural
environments have sparse vehicle density. In sparse conditions, lower-powered channels
(23–30 dBm) reach fewer receivers, creating a stronger per-channel PDR gradient that
is easier to measure as an attack detection feature.

---

### Q8 — What is the two-layer architecture (Tags vs Structs)?

**Question:** There are both NS-3 Tag classes and plain C++ structs for the same concepts
(topology, heartbeats, echo reports). Why two representations?

**Answer:**

These are two completely different layers serving different purposes:

```
LAYER 1 — RADIO (NS-3 Tags, travel over the simulated wireless medium)
──────────────────────────────────────────────────────────────────────
CustomDataTag1          → topology beacon (position, velocity, neighbour IDs, timestamp)
CustomHeartbeatTag      → liveness heartbeat (claimed sender, timestamp, is_replayed)
CustomMetaDataUnicastTag0  → RSU→Controller CSMA metadata packet

These are NS-3 Tag subclasses. They Serialize/Deserialize and travel inside
Ptr<Packet> objects over WifiNetDevice (DSRC 802.11p) or SimpleUdpApplication (CSMA).
The Rx() callback at line ~121436 reads them via PeekPacketTag().

LAYER 2 — CONTROLLER MEMORY (plain C++ structs in RAM)
──────────────────────────────────────────────────────
TopologyPacket   → stored in ttw_controller_table
HeartbeatPacket  → stored in bshh_controller_liveness_table
MEEchoReport     → stored in me_echo_reports vector

These never go over the air. Attack replay functions write directly into these
tables to simulate what the controller would believe after accepting a forged packet.
```

**Why separate?** The radio layer models physical transmission. The memory layer models
the controller's belief state. An attacker who forges a topology update does two things
simultaneously: sends a real (or fake) DSRC packet AND writes a forged entry into the
controller's belief table. NS-3 handles the radio automatically; the struct write represents
the control-plane consequence.

---

### Q9 — What is CustomHeartbeatTag and why was it added?

**Question:** Where is `CustomHeartbeatTag` defined and what does it do?

**Answer:**

`CustomHeartbeatTag` is a 13-byte NS-3 Tag class added at line ~1121 of routing.cc.
It carries BSHH heartbeat liveness information over the DSRC radio:

```cpp
class CustomHeartbeatTag : public Tag {
    // 13 bytes total:
    uint32_t m_claimedSenderId;  // 4 bytes — whose identity this heartbeat claims
    double   m_timestamp;         // 8 bytes — when the heartbeat was originally generated
    bool     m_isReplayed;        // 1 byte  — 0 = legitimate, 1 = forged replay
};
```

**Why it was needed:** Before this was added, BSHH heartbeats existed only as in-memory
struct writes — the attacker simply wrote directly into `bshh_controller_liveness_table`.
No real NS-3 packet was created, so:
- `Rx()` never fired for heartbeats
- NetAnim showed no heartbeat arrows
- The radio channel was never actually used for heartbeat traffic
- Channel delivery statistics for heartbeats were not counted

Adding `CustomHeartbeatTag` makes heartbeats real 802.11p DSRC packets. The `Rx()`
callback (line ~122266) was extended to read this tag and update the liveness table:

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

The helper `AttackSendHeartbeat(node, claimed_id, timestamp, is_replayed)` was also added
to send these packets from any node over the CCH 178 radio.

---

### Q10 — How does RSU→Controller communication work?

**Question:** How does an RSU send data to the SDN Controller? Is it wireless or wired?

**Answer: Wired (CSMA Ethernet), not wireless.**

The RSU and Controller are on the same simulated wired LAN:

```
Vehicle → (DSRC 802.11p wireless, 300 m) → RSU
RSU     → (CSMA Ethernet, 10.1.1.0/24)  → Controller
```

The controller listens on UDP port 7777 via `HandleReadOne()` (line ~97345).

Two helper functions were added to routing.cc (around line 1195) to generate real CSMA
packets from RSU attack functions:

```cpp
// Gets the controller's wired IP address
static Ipv4Address AttackGetControllerIP() {
    Ptr<Ipv4> ipv4 = controller_Node.Get(0)->GetObject<Ipv4>();
    uint32_t iface_idx = (N_Vehicles > 0) ? 1 : 0;  // 0=loopback, 1=CSMA
    return ipv4->GetAddress(iface_idx, 0).GetLocal();
}

// Sends a real UDP packet from RSU to Controller over CSMA
static void AttackSendRSUToController(uint32_t rsu_index) {
    Ptr<SimpleUdpApplication> udp_app =
        DynamicCast<SimpleUdpApplication>(RSU_Nodes.Get(rsu_index)->GetApplication(0));
    Ptr<Packet> pkt = Create<Packet>(0);
    CustomMetaDataUnicastTag0 tag;
    tag.SetNodeId(RSU_Nodes.Get(rsu_index)->GetId());
    tag.SetTimestamp(Simulator::Now());
    pkt->AddPacketTag(tag);
    Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                        udp_app, pkt, AttackGetControllerIP(), (uint16_t)7777);
}
```

All 8 RSU forwarding functions (TTW-S2, TTW-S4, BSHH-S2, BSHH-S4, ME-S2, ME-S4 and
their legitimate-exchange variants) call `AttackSendRSUToController()` so each RSU
aggregation step generates a real CSMA packet.

> **Interface index note:** The controller has device 0 = loopback, device 1 = CSMA
> (when vehicles are present). `AttackGetControllerIP()` handles this automatically.

---

### Q11 — Does the project use LTE cellular (V2C) communication?

**Question:** Is there LTE vehicle-to-controller communication in this project?

**Answer: The hardware is configured but the scheduling is disabled.**

The LTE setup (lines 141344–142307) is fully written:
- `LteHelper`, `EpcHelper` objects exist
- `enbdevices` (LTE base stations) and `uedevices` (vehicle UEs) are installed
- `send_LTE_metadata_uplink_alone()` function exists at line ~114279 and works

BUT the scheduler calls are inside a `/* */` block comment (lines 142738–142818), so LTE
transmissions never happen during any simulation run. This is intentional — re-enabling
LTE would add interference to attack timing and PEM scoring that we do not want.

**Do not uncomment the LTE scheduling block** unless you are specifically studying LTE
V2C behaviour.

---

## 21. Per-Channel TX Power and Channel Delivery Analysis

### Why different TX powers per channel?

For `mobility_scenario = 1` (rural/non-urban), each of the 7 DSRC channels is now
assigned a **different TX power**. The values are linearly spaced from 23 dBm (minimum)
to 44 dBm (maximum), step 3.5 dBm:

| Channel | Phy variable | TX Power | Approx. effective range |
|---------|-------------|----------|------------------------|
| 172 | `Phy_172` | **23.0 dBm** | ~150–200 m (shortest) |
| 174 | `Phy_174` | **26.5 dBm** | ~200–250 m |
| 176 | `Phy_176` | **30.0 dBm** | ~250–300 m |
| 178 (CCH) | `Phy` | **33.5 dBm** | ~300–350 m (mid) |
| 180 | `Phy_180` | **37.0 dBm** | ~350–400 m |
| 182 | `Phy_182` | **40.5 dBm** | ~400–450 m |
| 184 | `Phy_184` | **44.0 dBm** | ~450–500 m (longest) |

Other scenarios still use their original uniform power:
- `mobility_scenario = 0` (urban): all channels = 41 dBm
- `mobility_scenario = 2` (highway): all channels = 44 dBm

### Why this helps attack detection

The per-channel PDR gradient creates a **channel power signature** for every node:
a legitimate node at distance D from a receiver will show predictable delivery ratios
across the 7 channels (high delivery on high-power channels, low delivery on low-power ones).

When an attacker replays an old packet, they may:
- Transmit on the wrong channel (power does not match the expected range)
- Show anomalous fanout statistics (too many or too few receivers) for their claimed position

PEM can use the deviation from the expected per-channel signature as an additional
attack detection feature alongside the existing timestamp and reporter-density checks.

### What `channel_delivery_analysis.csv` contains

This file is written at the end of every simulation run (scheduled at `simTime − 1ms`).

```
channel_number,frequency_mhz,power_dbm,tx_count,rx_end_count,avg_fanout
172,5860,23.0,240,192,0.80
174,5870,26.5,240,264,1.10
176,5880,30.0,240,360,1.50
178,5890,33.5,240,480,2.00
180,5900,37.0,240,600,2.50
182,5910,40.5,240,720,3.00
184,5920,44.0,240,960,4.00
```

| Column | Source | Meaning |
|--------|--------|---------|
| `channel_number` | fixed | DSRC channel (172–184) |
| `frequency_mhz` | fixed | Center frequency (5860–5920 MHz) |
| `power_dbm` | fixed | Configured TX power for mobility_scenario=1 |
| `tx_count` | `PhyTxBegin` trace | Total packet transmissions started on this channel |
| `rx_end_count` | `PhyRxEnd` trace | Total reception attempts ended on this channel |
| `avg_fanout` | computed | `rx_end_count / tx_count` — average receivers per broadcast |

**How to read `avg_fanout`:**
- `avg_fanout = 1.0` → each broadcast was heard by exactly one other node (very short range)
- `avg_fanout = 4.0` → each broadcast was heard by 4 other nodes (long range with 6 vehicles)
- Under attack: fanout spikes on channels used by the attacker to echo packets to extra nodes

### Trace mechanism used

Per-channel Phy traces are connected in `main()` immediately after `wifi.Install()`:

```cpp
auto connect_ch = [](NetDeviceContainer& devs, uint32_t ci) {
    for (uint32_t i = 0; i < devs.GetN(); i++) {
        Ptr<WifiNetDevice> wd = DynamicCast<WifiNetDevice>(devs.Get(i));
        if (!wd || !wd->GetPhy()) continue;
        wd->GetPhy()->TraceConnectWithoutContext("PhyTxBegin",
            MakeBoundCallback(&ChannelPhyTxBegin, ci));
        wd->GetPhy()->TraceConnectWithoutContext("PhyRxEnd",
            MakeBoundCallback(&ChannelPhyRxEnd, ci));
    }
};
connect_ch(wifidevices_172, 0u); // Ch 172 — idx 0
connect_ch(wifidevices_174, 1u); // Ch 174 — idx 1
connect_ch(wifidevices_176, 2u); // Ch 176 — idx 2
connect_ch(wifidevices,     3u); // Ch 178 CCH — idx 3
connect_ch(wifidevices_180, 4u); // Ch 180 — idx 4
connect_ch(wifidevices_182, 5u); // Ch 182 — idx 5
connect_ch(wifidevices_184, 6u); // Ch 184 — idx 6
```

`MakeBoundCallback` pre-binds the channel index `ci` so the same callback function
handles all channels with a single counter array lookup.

### Run command for channel analysis

```bash
# Run with mobility_scenario=1 to activate per-channel powers
./waf --run "scratch/routing --simTime=30 --N_Vehicles=6 --N_RSUs=0 \
  --attack_scenario=5 --mobility_scenario=1"

# Read results
cat CHANNEL_DELIVERY_ANALYSIS/05_BSHH_S1_Malicious_Vehicle.csv
cat PEM_RUN_SUMMARY/05_BSHH_S1_Malicious_Vehicle.csv
```

Compare `avg_fanout` across channels — you should see a clear increasing trend from
channel 172 (lowest power, fewest receivers) to channel 184 (highest power, most receivers).

---

---

## 22. Data Transmission Functions and UDP Application (2026-05-02)

### Q12: There are several broadcast/unicast functions — which one actually runs?

Only **`distributed_dsrc_data_broadcast`** (line 124271) runs during attack simulations.
The other functions are legacy code from earlier architecture designs and are either
commented out or not scheduled in `main()` for attack scenarios.

| Function | Line | Status | Architecture |
|---|---|---|---|
| `distributed_dsrc_data_broadcast` | 124271 | ✅ **ACTIVE** | Distributed (`paper == 0`) |
| `centralized_dsrc_data_broadcast` | 123212 | ❌ Commented out | Centralized (`architecture == 0`) |
| `centralized_dsrc_data_unicast` | 123422 | ❌ Commented out | Centralized |
| `send_centralized_packets` | 123577 | ❌ Not scheduled | Centralized — Dijkstra orchestrator |
| `send_hybrid_packets` | 123510 | ❌ Not scheduled | Hybrid (`architecture == 2`) |

---

### Q13: What is the difference between `centralized_dsrc_data_broadcast` and `distributed_dsrc_data_broadcast`?

They are nearly identical — both create a `CustomDataTag` packet and send it as an
802.11p broadcast on Ch178 (`0x88dc`). The only three differences are:

| Aspect | `centralized_dsrc_data_broadcast` | `distributed_dsrc_data_broadcast` |
|---|---|---|
| `routing_time` flag | Sets `routing_time = false` | Does NOT set it |
| Timestamp array | `packet_initial_timestamp[nid]` (always) | `dsrc_packet_initial_timestamp[nid]` (only if `paper == 0`) |
| Scheduling status | ❌ Commented out — never runs | ✅ Active — runs every 100ms |

The `centralized` version was written for the original centralized architecture.
When the code evolved to the distributed design, a new version was written with
the correct timestamp array and the `paper == 0` guard. The old version was left
in place but commented out rather than deleted.

---

### Q14: What are `send_centralized_packets` and `send_hybrid_packets`?

Both are **orchestrator functions** — they set up routing and then schedule the
individual unicast transmission functions.

**`send_centralized_packets` (line 123577):**
1. Calls `initialize_all_routing_tables()` and `generate_adjacency_matrix()`
2. Runs `calculate_dijkstra_solution(i)` for every node — builds optimal paths
3. Schedules `centralized_dsrc_data_unicast` for each source→destination pair
4. Unicast uses `CustomDataUnicastTag_Routing` tag (includes destination ID and
   hop-by-hop routing info, unlike the broadcast `CustomDataTag`)

**`send_hybrid_packets` (line 123510):**
1. Runs `calculate_dijkstra_stable_solution` (stable-path Dijkstra variant)
2. Uses a **triangular wave** for transmission gap `tg` based on
   `data_gathering_cycle_number` — staggers transmissions to reduce collisions
3. Schedules `hybrid_data_unicast` for each source
4. `hybrid_data_unicast` decides per-hop at runtime:
   - If both sender and next-hop are RSUs → use CSMA Ethernet
   - Otherwise → use DSRC unicast

Neither function is scheduled for any of the 12 attack scenarios.

---

### Q15: What is `SimpleUdpApplication` and how does `udp_app` work?

`SimpleUdpApplication` is a **custom NS-3 Application class** (line 97389) written
specifically for this project. It provides the **wired IP/UDP socket layer** for RSU
and Controller nodes on the CSMA Ethernet network (`10.1.1.0/24`).

> Vehicles use `WifiNetDevice::Send()` (DSRC radio) directly — they do **NOT** use
> `SimpleUdpApplication`. Only RSUs and the Controller have it installed.

#### How it is installed

```cpp
// In main() — one instance per RSU (line 141452)
for (uint32_t u = 0; u < RSU_Nodes.GetN(); u++) {
    Ptr<SimpleUdpApplication> udp_app = Create<SimpleUdpApplication>();
    RSU_Nodes.Get(u)->AddApplication(udp_app);
    RSU_apps.Add(udp_app);
}
RSU_apps.Start(Seconds(0.00));
RSU_apps.Stop(Seconds(simTime));
```

#### Three internal components

**1. `StartApplication()` — opens sockets when simulation starts**

Opens two receive sockets and one send socket:
```
Port 7777  →  m_recv_socket1  →  HandleReadOne()   ← topology / routing / status data
Port 9999  →  m_recv_socket2  →  HandleReadTwo()   ← secondary channel
Send       →  m_send_socket   →  SendPacket()      ← outgoing CSMA packets
```

**2. `SendPacket(packet, destIP, port)` — sends over CSMA Ethernet (line 114276)**

```cpp
void SimpleUdpApplication::SendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t port)
{
    m_send_socket->Connect(InetSocketAddress(destination, port));
    m_send_socket->Send(packet);
}
```

This is always called with port 7777. The packet must already have an NS-3 Tag
attached before `SendPacket` is called. Typical usage:

```cpp
Ptr<SimpleUdpApplication> udp_app =
    DynamicCast<SimpleUdpApplication>(RSU_apps.Get(rsu_index));
Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                    udp_app, packet, controllerIP, (uint16_t)7777);
```

**3. `HandleReadOne()` — the big receiver at the Controller (port 7777)**

Reads whatever tag is inside the arriving packet and updates the controller's tables:

| Tag type received | Controller action |
|---|---|
| `CustomDataUnicastTag_Routing` | Find next hop, forward via DSRC or CSMA |
| `CustomDeltavaluesDownlinkUnicastTag` | Update `delta_at_nodes_inst` — routing split ratios |
| `CustomStatusDataUplinkTag1` | Update vehicle position/velocity/acceleration |
| `CustomFlowDataUplinkTag1` | Update flow demand: source, destination, size, QoS |
| `CustomDataTag` | Log basic beacon delivery delay |
| `CustomMetaDataUnicastTag0` | Update `con_data_inst` — record CSMA/LTE packet delay |

#### Full data flow

```
Vehicle (DSRC 802.11p) ──► RSU: Rx() callback fires
                               │
                               │  Build Ptr<Packet>, attach Tag
                               │  udp_app = RSU_apps.Get(u)
                               │
                               ▼
               udp_app->SendPacket(pkt, controllerIP, 7777)
                               │
                   CSMA Ethernet  10.1.1.x/24  UDP
                               │
                               ▼
           Controller: HandleReadOne() fires on port 7777
           PeekPacketTag() → identifies tag → updates tables
```

#### How attack functions use it

`AttackSendRSUToController()` (the attack helper) uses exactly the same mechanism
to inject a forged packet from a malicious RSU to the controller:

```cpp
static void AttackSendRSUToController(uint32_t rsu_index) {
    Ptr<SimpleUdpApplication> udp_app =
        DynamicCast<SimpleUdpApplication>(RSU_Nodes.Get(rsu_index)->GetApplication(0));
    Ptr<Packet> pkt = Create<Packet>(0);
    CustomMetaDataUnicastTag0 tag;
    tag.SetNodeId(RSU_Nodes.Get(rsu_index)->GetId());
    tag.SetTimestamp(Simulator::Now());
    pkt->AddPacketTag(tag);
    Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                        udp_app, pkt, AttackGetControllerIP(), (uint16_t)7777);
}
```

The controller cannot distinguish this from a legitimate RSU packet — `HandleReadOne()`
fires and processes the tag in exactly the same way.

---

---

## 23. Node Roles, Architecture Modes, and centralized_dsrc_data_broadcast

### Q16: What is `centralized_dsrc_data_broadcast` — is it for the management server or the controller?

It was written for the **management server** (`management_Node`), not the controller.
To understand why, you need to know there are two completely separate server nodes
and three architecture modes in this project.

---

### The Two Server Nodes

Two server nodes are created in `main()` at lines 141164–141165:

```cpp
controller_Node.Create(1);   // SDN Controller — routing decisions
management_Node.Create(1);   // Management/Data Server — raw data collection
```

Both are on the same CSMA Ethernet LAN (`10.1.1.0/24`) alongside all RSU nodes.
They serve **different purposes** and are used in **different architecture modes**.

---

### The `architecture` and `paper` Control Variables

Two global integers (lines 112 and 114) control which data path is active:

```cpp
int architecture = 0;   // 0=centralized, 1=distributed, 2=hybrid
int paper        = 1;   // 0=proposed RL algorithm (this paper), 1=comparison baseline
```

---

### Three Architecture Modes Explained

#### Mode A — Centralized (`architecture = 0`)

```
Vehicle ──DSRC──► Vehicle ──UDP/LTE──► management_Node
                                              │
                                     collects ALL vehicle data
                                     runs Dijkstra centrally
                                     pushes routes back to vehicles
```

- **Destination:** `management_Node` (the data collection server)
- **Broadcast function used:** `centralized_dsrc_data_broadcast` → was the first broadcast step
- **Unicast function used:** `send_centralized_packets` → ran Dijkstra then unicast delivery
- **Status:** ❌ Both scheduling calls are inside `/* */` block comments — not active

This was the original design for the centralized comparison study (QRSDN, RLMR baselines
where a central server computes all routes). It was replaced by Mode B and Mode C.

---

#### Mode B — Distributed + Proposed RL Algorithm (`architecture = 1`, `paper = 0`)

```
Vehicle ──DSRC broadcast──► All nearby Vehicles + RSU
                             each node makes its OWN routing
                             decision locally using RL
```

- **Destination:** No central server — each vehicle decides locally
- **Broadcast function used:** `distributed_dsrc_data_broadcast` — fires every 100ms
- **Scheduling:** `if (paper == 0)` loop in `main()` at line 142932
- **Status:** ✅ Active when `paper = 0`

---

#### Mode C — Controller-Based Comparison (`architecture = 0`, `paper = 1`)

```
Vehicle ──DSRC──► RSU ──CSMA/UDP──► controller_Node
                                           │
                                  runs comparison algorithm
                                  (QRSDN, RLMR, DCMR, ECMP)
                                  sends delta routing values
                                  back down to vehicles
```

- **Destination:** `controller_Node` (the SDN controller)
- **Socket layer:** `SimpleUdpApplication` on RSU nodes
- **Status:** Active for comparison baseline runs

---

### What Runs During All 12 Attack Scenarios

For attack scenarios (`attack_scenario = 1–12`), the path is the **Controller path**:

```
Vehicle ──DSRC (AttackSendDSRCBeacon / AttackSendHeartbeat)──► Vehicles / RSU
                       │
RSU ──CSMA/UDP (AttackSendRSUToController)──► controller_Node
                                                     │
                                        ttw_controller_table  ← POISONED by TTW
                                        bshh_controller_liveness_table  ← POISONED by BSHH
                                        me_echo_reports  ← POISONED by ME
```

**`management_Node` plays no role in any attack scenario.**

---

### Node Role Summary for This Project

| Node | Purpose | Active in attack scenarios? |
|---|---|---|
| `Vehicle_Nodes` | Move, send DSRC beacons | ✅ Yes — attacker and victim nodes |
| `RSU_Nodes` | Relay V2R packets to controller | ✅ Yes — in S2/S4 variants |
| `controller_Node` | SDN controller — **the attack target** | ✅ Yes — its tables get poisoned |
| `management_Node` | Data collection for centralized studies | ❌ No |

---

### Why `centralized_dsrc_data_broadcast` Is in the File

The function was written when the project was studying the centralized architecture
(Mode A). When the focus shifted to the proposed RL algorithm and attack detection,
the centralized scheduling calls were commented out. The function was kept for
comparison reference and documentation purposes. It has zero runtime cost since
it is never scheduled.

---

---

## 24. Agent-Based Data Upload Functions — send_LTE_data_agent and RSU_dataunicast_agent

## 25. Build Fix Notes — Forward Declarations and Helper Placement (2026-05-02)

This section documents the build fix that was made after `./waf build` failed in
`AttackSendDSRCBeacon()` and `AttackSendRSUToController()`.

### What failed

The compiler reported that these names were not declared:

- `CustomDataTag1`
- `CustomMetaDataUnicastTag0`
- `SimpleUdpApplication`

At first glance this looked like the classes were missing, but they were already present
later in `routing.cc`.

### Real cause

The problem was **declaration order inside one very large source file**.

These helper functions were defined early in the file:

- `AttackSendDSRCBeacon(...)`
- `AttackSendRSUToController(...)`

But the classes they use are defined much later:

- `CustomDataTag1`
- `CustomMetaDataUnicastTag0`
- `SimpleUdpApplication`

In C++, a class must be known before code can create an object of that class or call one
of its member functions through a typed pointer. Because the helper function bodies came
too early, the compiler stopped with "not declared in this scope" errors.

### What was changed

The fix was intentionally small:

1. The early function bodies were replaced with **forward declarations only**:
   - `static void AttackSendDSRCBeacon(Ptr<Node> sender_node, Ptr<Node> neighbor_node);`
   - `static void AttackSendRSUToController(uint32_t rsu_index);`
2. The real implementations were moved to a later location in the file, after
   `SimpleUdpApplication::SendPacket(...)`, where all required classes are already known.
3. While moving `AttackSendRSUToController(...)`, the scheduled send call was verified and
   kept in the correct form:

```cpp
Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
                    udp_app, pkt, dest_ip, static_cast<uint16_t>(7777));
```

### Why this fix is safe

This change does **not** alter the attack logic, timing, packet contents, or scenario
selection. It only changes where the compiler sees the helper function bodies.

Behavior remains the same:

- `AttackSendDSRCBeacon(...)` still creates a DSRC packet, attaches `CustomDataTag1`,
  and broadcasts it on the Wi-Fi device.
- `AttackSendRSUToController(...)` still creates a packet, attaches
  `CustomMetaDataUnicastTag0`, and schedules `SimpleUdpApplication::SendPacket(...)`
  to send the packet to the controller on UDP port `7777`.

### Result

After this change, the target built successfully with:

```bash
./waf build --targets=routing -j1
```

This confirms the failure was a compile-order issue, not a missing-feature issue.

### Background — What is an "agent" here?

The project has an RL (Reinforcement Learning) optimization layer where certain nodes
are designated as **selected agents** — nodes chosen by the algorithm to upload their
full local topology knowledge to the management server for centralized learning.

The selection is tracked by the global boolean array `X_nodes[]` (line 97444):
- `X_nodes[i] = 1` → node i is a selected agent → should upload
- `X_nodes[i] = 0` → node i is not selected → stays silent

`X_nodes` is initialized to `1` for all nodes (line 114392). During RL runs it can be
updated via `CustomDeltavaluesDownlinkUnicastTag` messages from the controller.

---

### `send_LTE_data_agent` (line 124900)

**Purpose:** Selected **vehicle** agent uploads full topology snapshot to `controller_Node` via LTE/UDP port 7777.

**Signature:**
```cpp
void send_LTE_data_agent(Ptr<SimpleUdpApplication> udp_app,
                          Ptr<Node> node_source,
                          Ptr<Node> destination_node,   // controller_Node
                          uint32_t node_index)
```

**Steps:**
1. Guard: `if (X_nodes[nid] == 1)`
2. Gets position, velocity, acceleration from mobility model
3. Calls `add_received_data_at_nodes()` → adds self to `data_at_nodes_inst`
4. Extracts full topology from `data_at_nodes_inst[nid]` — all observed neighbours
5. Packs into `CustomMetaDataUnicastTagN01x` (switch on neighbour count 1..max)
6. Sends: `udp_app->SendPacket(packet1, controller_IP, 7777)`

**Destination IP (line 124999):** `ipv4->GetAddress((N_Vehicles > 0 ? 1 : 0), 0)` — controller's CSMA interface.

> **Changed from:** `GetAddress(2,0)` (management_Node LTE interface — wrong for controller_Node which has no LTE).

**Scheduled from main() (line 142796):** replaced `send_LTE_routing_data_alone` — old function (line 124369) sent only basic routing metrics. New function sends full topology snapshot.

---

### `RSU_dataunicast_agent` (line 132992)

**Purpose:** Same as `send_LTE_data_agent` but sender is an **RSU** over CSMA Ethernet.

**Signature:**
```cpp
void RSU_dataunicast_agent(Ptr<SimpleUdpApplication> udp_app,
                            Ptr<Node> source_node,
                            Ptr<Node> destination_node)   // controller_Node
```

**Same steps as vehicle version.** Key differences:
- Transport: CSMA Ethernet (not LTE)
- Dest IP: `GetAddress(1,0)` when `N_Vehicles > 0`, else `GetAddress(0,0)` — already correct for `controller_Node` ✅

**Scheduled from main() (line 142857):** replaced `RSU_routing_statusdataunicast_alone` + `management_Node` → `RSU_dataunicast_agent` + `controller_Node`.

---

### Comparison

| Aspect | `send_LTE_data_agent` | `RSU_dataunicast_agent` |
|---|---|---|
| Sender | Vehicle | RSU |
| Transport | LTE UDP | CSMA Ethernet UDP |
| Destination | `controller_Node` | `controller_Node` |
| Dest IP | `GetAddress((N_Vehicles>0?1:0), 0)` | `GetAddress(1,0)` |
| Stagger | 25 µs/agent | 50 µs/agent |
| Tag family | `CustomMetaDataUnicastTagN01x` | Same |
| Selection gate | `X_nodes[nid] == 1` | `X_nodes[nid] == 1` |
| Active | ✅ All runs | ✅ When N_RSUs > 0 |

### Old vs New Scheduling (main())

| Line | Old function | New function | Old destination | New destination |
|---|---|---|---|---|
| 142796 | `send_LTE_routing_data_alone` | `send_LTE_data_agent` | `management_Node` | `controller_Node` |
| 142857 | `RSU_routing_statusdataunicast_alone` | `RSU_dataunicast_agent` | `management_Node` | `controller_Node` |
This topology snapshot feeds the centralized RL/optimization algorithm that computes
new routing decisions and sends `delta` values back down to nodes.

> **For attack scenarios:** These agent upload functions are **NOT called** in any
> of the 12 attack scenarios. They are only active in the agent-based learning runs
> (`paper == 1`, separate scheduling path). All attack detection runs use the
> `controller_Node` path, not `management_Node`.

## 26. Observed Run Note — Scenario Outputs and Logs (2026-05-07)

**Commands observed:**

```bash
./waf --run "scratch/routing --simTime=20 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=9"
./waf --run "scratch/routing --simTime=30 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=2"
```

**What happened during these runs:**

- The `attack_scenario=9` run entered `ME-S1` and printed the scenario banner normally.
- It wrote the NetAnim file:
  - `XML/09_ME_S1_Malicious_Vehicles.xml`
- It opened the scenario log file:
  - `me_s1_attack_log.txt`
- Earlier completed runs had already populated the per-scenario CSV folders with files such as:
  - `PEM_EVENT_LOG/01_TTW_S1_Malicious_Vehicle.csv`
  - `PEM_EVENT_LOG/02_TTW_S2_Malicious_RSU.csv`
  - `PEM_EVENT_LOG/05_BSHH_S1_Malicious_Vehicle.csv`
  - `PEM_RUN_SUMMARY/01_TTW_S1_Malicious_Vehicle.csv`
  - `PEM_RUN_SUMMARY/02_TTW_S2_Malicious_RSU.csv`
  - `PEM_RUN_SUMMARY/05_BSHH_S1_Malicious_Vehicle.csv`
  - `CHANNEL_DELIVERY_ANALYSIS/01_TTW_S1_Malicious_Vehicle.csv`
  - `CHANNEL_DELIVERY_ANALYSIS/02_TTW_S2_Malicious_RSU.csv`
  - `CHANNEL_DELIVERY_ANALYSIS/05_BSHH_S1_Malicious_Vehicle.csv`
- The console output showed normal DSRC broadcast / receive activity after the banner, which is expected for these simulations.

**Interpretation:**

The important change is that each scenario now has its own output set instead of all runs sharing one `pem_event_log.csv`, one `pem_run_summary.csv`, and one `channel_delivery_analysis.csv`. That makes it much easier to compare attack families and keep the logs aligned with the XML files.

**Useful generated files from these runs:**

- `XML/09_ME_S1_Malicious_Vehicles.xml`
- `me_s1_attack_log.txt`
- `PEM_EVENT_LOG/<scenario_name>.csv`
- `PEM_RUN_SUMMARY/<scenario_name>.csv`
- `CHANNEL_DELIVERY_ANALYSIS/<scenario_name>.csv`

---

*Written by Nimesha Yasith | FYP — Department of EIE, University of Ruhuna | 2026-04-30*
*Updated 2026-04-30: added --detection_enabled flag, per-scenario XML files, ME-S1/S3 PEM improvements, updated CSV column layouts.*
*Updated 2026-05-01: added Section 18 — RSU and RSU Network explanation; Section 19 — Q&A session documenting custom data tags, DSRC, V2V implementation gap, and fix.*
*Updated 2026-05-02: added Section 20 — Q&A session (7 DSRC channels, mobility traces, two-layer architecture, CustomHeartbeatTag, RSU→Controller CSMA, LTE V2C status); Section 21 — per-channel TX power 23–44 dBm for mobility_scenario=1, channel_delivery_analysis.csv output; Section 22 — data transmission functions comparison (centralized vs distributed broadcast, send_centralized_packets, send_hybrid_packets), SimpleUdpApplication internals (3 sockets, HandleReadOne tag dispatch, attack usage); Section 23 — node roles (controller_Node vs management_Node), three architecture modes (centralized/distributed/hybrid), which mode runs in attack scenarios.*
*Updated 2026-05-07: revised output layout to per-scenario CSV folders (`PEM_EVENT_LOG/`, `PEM_RUN_SUMMARY/`, `CHANNEL_DELIVERY_ANALYSIS/`), and updated Section 26 to record the scenario outputs/logs observed during the `ME-S1` and `TTW-S2` runs.*
