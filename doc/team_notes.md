# Team Notes — Complete Project Understanding
> **For:** Team members who are new to the codebase  
> **File explained:** `routing.cc` (the main simulation file)  
> **After reading this:** You will understand what the project does, what was broken, what was fixed, and how the whole detection system works.

---

## Part 1 — What Is This Project?

### Step-by-Step: How the Network Works (Normal Case)

```
Step 1: Vehicles drive on a road, broadcasting their location every 0.1 seconds (beacon)

Step 2: Nearby vehicles hear each other's beacons and report:
        "I can see Vehicle B right now"  →  sent to RSU or directly to Controller

Step 3: Controller receives all reports and builds a TOPOLOGY MAP:
        [ V0 ↔ V1 ]  [ V1 ↔ V2 ]  [ V2 ↔ V3 ]

Step 4: Controller uses this map to route data:
        "Send packet from V0 to V3 via: V0 → V1 → V2 → V3"

Step 5: Packets travel along the chosen path and reach the destination ✅
```

### The Security Problem — Step by Step

```
Step 1: Attacker captures a VALID old topology packet
        (e.g., "V0 sees V1, observed at t=10s")

Step 2: V0 and V1 move apart — the real link breaks at t=15s
        Controller is NOT told about the break

Step 3: Attacker changes the timestamp: 10s → 20s  (FORGED)

Step 4: Attacker sends the forged packet to the Controller
        Controller sees: "V0 sees V1, observed at t=20s"  — looks fresh!

Step 5: Controller updates its map — believes V0↔V1 is still active

Step 6: Controller routes packets through V0→V1 — but V1 is gone!
        All packets are DROPPED ❌
```

### Three Attack Families

| # | Full Name | Short Name | Core Technique |
|---|---|---|---|
| 1 | Topology Time-Warp | **TTW** | Replay old topology packet with forged timestamp |
| 2 | Beacon State Heartbeat Hijack | **BSHH** | Replay old heartbeat pretending vehicle is still alive |
| 3 | Multipath Echo | **ME** | Inject duplicate link reports to create phantom paths |

---

## Part 2 — The 5 Compile Errors That Were Fixed

> Before fixes, the code would **not compile at all**. These must be fixed first.

### Error Summary Table

| Error # | Variable / Item | Problem | Fix Applied |
|---|---|---|---|
| 1 | `attack_scenario` | Declared twice — `uint32_t` AND `int` | Kept one `uint32_t` at line 139 |
| 2 | `malicious_vehicle_id` | Declared twice | Kept one at line 142 |
| 3 | `victim_neighbor_id` | Declared twice | Kept one at line 145 |
| 4 | `using namespace ns3` | Placed too late — types used before namespace | Moved to line 50 |
| 5 | `TopologyPacket` + `StoredPacket` | Two structs for same concept | Merged into one struct at lines 164–169 |

---

### Error 1 — Duplicate Variable

**Before (broken):**
```cpp
uint32_t attack_scenario = 0;   // line 100
// ...hundreds of lines later...
int attack_scenario = 4;        // ← ILLEGAL: declared again
```

**After (fixed, line 139):**
```cpp
// ERROR 1 FIX: Keep ONE declaration only
uint32_t attack_scenario = 0;   // change via: --attack_scenario=4
```

---

### Error 2 & 3 — Same Pattern

**After fix (lines 142, 145):**
```cpp
uint32_t malicious_vehicle_id = 0;   // V0 is the attacker
uint32_t victim_neighbor_id   = 1;   // V1 is the victim
```

---

### Error 4 — Namespace Too Late

**Step-by-step explanation:**
```
1. NS-3 puts all its tools (Seconds, Vector, Simulator...) inside namespace ns3
2. To use them without typing ns3:: every time, you write: using namespace ns3;
3. PROBLEM: attack constants used Seconds() BEFORE the namespace line
4. FIX: Move "using namespace ns3;" to line 50 — before everything else
```

**Before → After:**
```cpp
// BEFORE: namespace declared too late
// ... (attack constants here using Seconds()) ...
using namespace ns3;   // too late — compiler already gave up

// AFTER: namespace at the very top
using namespace std;
using namespace ns3;   // line 50 — now covers the whole file
// ... (attack constants here — now Seconds() works) ...
```

---

### Error 5 — Duplicate Struct

**Before (broken):**
```cpp
struct StoredPacket {          // defined in one place
    double originalTimestamp;
    uint32_t sourceId;
    uint32_t neighborId;
};

struct TopologyPacket {        // defined AGAIN in another place
    uint32_t src_id;
    uint32_t seen_id;
    double timestamp;
};
```

**After (fixed, lines 164–169):**
```cpp
struct TopologyPacket {
    uint32_t src_id;       // who sent the update
    uint32_t seen_id;      // who they reported seeing
    double   timestamp;    // when they saw them
    bool     is_forged;    // true = attacker tampered this
};
```

---

## Part 3 — The TTW Attack (What Currently Runs)

### Scenario Setup

| Role | Vehicle | Behaviour |
|---|---|---|
| Attacker | V0 (Vehicle 0) | Malicious — stores and replays packets |
| Victim | V1 (Vehicle 1) | Innocent — drives away at t=15s |
| Controller | Central node | Receives topology updates, makes routing decisions |
| RSU | None | Not used in this scenario |

---

### Attack Timeline — Step by Step

| Time | Step | What Happens | Code Function |
|---|---|---|---|
| t = 0s | Start | Vehicles start moving | `main()` |
| t = 10s | ① HELLO | V0 and V1 are close. They exchange HELLO beacons | `TTW_SendHelloBeacon()` |
| t = 10s | ② UPDATE | V0 sends legitimate topology update to Controller | `TTW_SendTopologyUpdate()` |
| t = 10s | ③ STORE | V0 secretly saves a copy of the packet | `TTW_StorePacket()` |
| t = 15s | BREAK | V0 and V1 drive apart. Physical link breaks. Controller not told. | (mobility model) |
| t = 20s | ④ FORGE | V0 changes timestamp on stored packet: 10.0 → 20.0 | `TTW_ReplayAttack()` |
| t = 20s | ⑤ SEND | V0 sends forged packet. Controller accepts it as fresh. | `TTW_ReplayAttack()` |
| t = 20s | ⑥ DAMAGE | Controller believes ghost link V0↔V1 is active. Packets lost. | `TTW_ReplayAttack()` |
| t = 20.05s | DETECT | PEM detector checks the event 50ms later | `TTW_RunReplayDetection()` |

---

### What the Log File Shows

After running, open `ttw_attack_scenario4.txt`. You should see:

```
[t=10.000]  STEP ①  HELLO
  V0 pos=(x, y)   V1 pos=(x, y)
  dist=XXm  DELIVERED — neighbor discovered

[t=10.000]  STEP ②  TOPOLOGY UPDATE (legitimate)
  V0 → Controller
  Packet: <V0 sees V1, t=10.000>
  Result: ACCEPTED — link V0↔V1 marked ACTIVE

[t=10.000]  STEP ③  ATTACKER STORES PACKET
  Stored: <V0 sees V1, t=10.000>
  Awaiting replay at t=20

[t=20.000]  STEP ④  FORGING TIMESTAMP
  Original: t=10.000   →   Forged: t=20.000  MALICIOUS

[t=20.000]  STEP ⑤  FORGED PACKET → CONTROLLER
  Controller ACCEPTED — cannot detect forgery

[t=20.000]  STEP ⑥  FAULTY ROUTING DECISION
  Ghost link V0↔V1 active in controller table
  Physical reality: BROKEN

[t=20.050]  DETECTION + MITIGATION
  Alert raised!  Score: 0.30  Latency: 50ms
  Forged entry removed from controller table
```

---

## Part 4 — The Detection System (PEM Layer)

### What PEM Stands For

**P**erformance **E**valuation **M**etrics

It is the detection system layered on top of the attack simulation. It watches every packet event and scores it for suspiciousness.

---

### The 9 Detection Signatures

Every incoming event is checked against 9 binary questions. If the answer is "suspicious" → that signature is **triggered**.

#### TTW Group — Timestamp / Replay Anomalies

| Index | Name | Plain English Question | Triggers When |
|---|---|---|---|
| S0 | TTW-S1 | Did this packet arrive too late? | `reception_time − sender_time > beacon_interval + tolerance` |
| S1 | TTW-S2 | Does the time order contradict itself? | Newer reception but older sender timestamp than a previous event |
| S2 | TTW-S3 | Do different nodes disagree on when they saw this link? | Two reporters have timestamps more than one beacon interval apart |

#### BSHH Group — Identity / Heartbeat Anomalies

| Index | Name | Plain English Question | Triggers When |
|---|---|---|---|
| S3 | BSHH-S1 | Are two physical vehicles claiming the same identity? | Different physical sender IDs claim same vehicle ID in window |
| S4 | BSHH-S2 | Did the heartbeat timestamp go backward? | Current heartbeat timestamp < previous heartbeat timestamp |
| S5 | BSHH-S3 | Heartbeat without proof of presence? | No beacon from this vehicle seen in the sliding window |

#### ME Group — Topology / Density Anomalies

| Index | Name | Plain English Question | Triggers When |
|---|---|---|---|
| S6 | ME-S1 | Too many reporters for this link? | Reporter count > `(1 + mu) × 2 × range × density` |
| S7 | ME-S2 | Did path count jump suddenly? | Path count increased by more than `PEM_ME_DELTA_MAX = 1` |
| S8 | ME-S3 | Reporter too far away to have seen this link? | Reporter distance > `TTW_COMM_RANGE = 300m` from both endpoints |

---

## Part 5 — Scoring System

### Problem with Old Code

**Before (broken logic):**
```cpp
// Every signature adds exactly the same amount — NO justification
score += (1.0 / 9.0);   // = 0.111 each
```

**Why this is wrong:**

| Signature | Evidence Type | Equal weight makes sense? |
|---|---|---|
| S1 (TTW-S2) | Direct timestamp contradiction | Should be HIGH weight |
| S0 (TTW-S1) | Packet arrived late | Should be HIGH weight |
| S8 (ME-S3) | Reporter position hint | Should be LOW weight |
| S7 (ME-S2) | Path count change | Should be LOW weight |

Treating a **direct timestamp contradiction** the same as a **geometric hint** is academically unjustifiable.

---

### Step-by-Step: New Weighted Scoring

**Step 1 — New constants added (lines 195–203):**
```cpp
static const double PEM_WEIGHTS[9] = {
    0.15, 0.15, 0.10,   // TTW-S0, TTW-S1, TTW-S2  ← highest (direct evidence)
    0.15, 0.10, 0.10,   // BSHH-S3, BSHH-S4, BSHH-S5 ← medium
    0.10, 0.075, 0.075  // ME-S6, ME-S7, ME-S8      ← lowest (circumstantial)
};
// Total: 0.15+0.15+0.10 + 0.15+0.10+0.10 + 0.10+0.075+0.075 = 1.000 ✅
```

**Step 2 — New score loop (lines 824–831):**
```cpp
double score = 0.0;
for (uint32_t i = 0; i < 9; ++i)
{
    if (event.triggered[i])
    {
        score += PEM_WEIGHTS[i];   // each adds its own weight
    }
}
```

**Step 3 — Example for TTW replay event:**

| Signature | Triggered? | Weight Added |
|---|---|---|
| S0 (TTW-S1) | ✅ Yes — packet arrived 10s late | +0.15 |
| S1 (TTW-S2) | ✅ Yes — timestamp contradiction | +0.15 |
| S2 (TTW-S3) | ❌ No | +0.00 |
| S3–S8 | ❌ No | +0.00 |
| **Total score** | | **0.30** |
| Alert threshold | | 0.12 |
| **Alert raised?** | | **✅ YES (0.30 > 0.12)** |

---

### Temporal Pressure — Why and How

#### The Concept

> **"Temporal Echo"** means: suspicious activity happening repeatedly and recently should make the system MORE alarmed.

#### The Wrong Way (Bug in the original proposal)

```cpp
// ❌ WRONG — do not use this
double timeDiff = now - pem_event_window.back().reception_timestamp;
decayFactor = exp(-timeDiff / 0.400);
score *= decayFactor;   // BUG: if timeDiff=10s → decayFactor ≈ 0 → attack missed!
```

**Why it fails:**

| Situation | timeDiff | decayFactor | Result |
|---|---|---|---|
| Events every 0.1s | 0.1s | 0.78 | Score reduced a little |
| 10s quiet then attack | 10.0s | ≈0.000 | **Score → zero → attack MISSED ❌** |

#### The Correct Way (What was implemented)

**Step-by-step logic:**

```
Step 1: Compute weighted score from current event's signatures
        score = sum of PEM_WEIGHTS[i] for triggered signatures

Step 2: Look back at all past events in the sliding window (last 0.4 seconds)
        For each past event that had a suspicious score:
            age = now − past_event.reception_timestamp
            contribution = past_event.score × exp(−age / 0.200)
            temporalPressure += contribution

        → Recent past events contribute FULLY
        → Older past events FADE naturally

Step 3: Scale and cap the pressure
        temporalPressure = min(temporalPressure × 0.05, 0.30)
        → History can add AT MOST 0.30 to the score
        → Prevents false alarms from history alone

Step 4: Final score = weighted_score + temporalPressure
        event.score = score

Step 5: Check against threshold
        alert_raised = (score > 0.12)
```

**Code (lines 833–855):**
```cpp
double temporalPressure = 0.0;
const double now = event.reception_timestamp;

for (each past event in pem_event_window)
{
    if (past_event.score > 0.0)
    {
        double age = now - past_event.reception_timestamp;
        temporalPressure += past_event.score * exp(-age / PEM_DECAY_TAU_S);
    }
}

temporalPressure = min(temporalPressure * 0.05, 0.30);
score += temporalPressure;
```

**Behaviour comparison:**

| Scenario | Temporal Pressure Effect | Result |
|---|---|---|
| Single isolated attack event | `temporalPressure ≈ 0` (empty window) | Full weighted score — **not suppressed** ✅ |
| Burst of echoes (ME attack) | `temporalPressure` builds up | Score increases → **detects faster** ✅ |
| Normal traffic | All past scores ≈ 0 → no pressure | No false alarm boost ✅ |

---

## Part 6 — All New Constants Explained

| Constant | Value | Meaning |
|---|---|---|
| `PEM_BEACON_BUDGET_MS` | 100.0 ms | Detection must happen within 100ms (one beacon cycle) |
| `PEM_BEACON_INTERVAL_S` | 0.100 s | Vehicles beacon every 0.1 seconds |
| `PEM_PROPAGATION_EPSILON_S` | 0.020 s | Tolerance for radio delay |
| `PEM_HEARTBEAT_WINDOW_S` | 0.400 s | How far back the sliding window looks |
| `PEM_SCORE_THRESHOLD` | 0.12 | Score above this → alert fires |
| `PEM_ME_TOLERANCE_MU` | 0.30 | 30% tolerance margin for density check |
| `PEM_ME_DELTA_MAX` | 1.0 | Max allowed path count jump |
| `PEM_WEIGHTS[9]` | see above | Signature weights, sum = 1.0 |
| `PEM_DECAY_TAU_S` | 0.200 s | Time constant for temporal pressure decay |

---

## Part 7 — Detection Metrics for the Paper

### The Confusion Matrix

Every time the detector makes a decision:

| | Detector says: **ATTACK** | Detector says: **NORMAL** |
|---|---|---|
| **Reality: ATTACK** | ✅ True Positive (TP) | ❌ False Negative (FN) — missed |
| **Reality: NORMAL** | ❌ False Positive (FP) — false alarm | ✅ True Negative (TN) |

**Goal:** Maximize TP and TN. Minimize FP and FN.

---

### Metric Definitions

| Metric | Formula | Interpretation | Target |
|---|---|---|---|
| **MCC** | `(TP×TN − FP×FN) / sqrt(...)` | +1 = perfect, 0 = random, -1 = wrong | > 0.5 |
| **AUROC** | Concordant pairs / all pairs | 1.0 = perfect separation, 0.5 = random | > 0.85 |
| **Tdet** | `first_alert_time − attack_injection_time` (ms) | How fast the attack was caught | < 100 ms |
| **PDR** | Delivered packets / sent packets (%) | Higher is better | Compare baseline vs attack |
| **Te2e** | Avg packet travel time (ms) | Lower is better | Compare baseline vs attack |

---

### Phase Labels in CSV

| Phase | Meaning | Expected PDR | Expected Te2e |
|---|---|---|---|
| `baseline` | Before attack injection | High (≥ 90%) | Low |
| `under_attack` | After attack, before detection | **Drops** | **Rises** |
| `post_mitigation` | After alert raised | Recovers | Recovers |

---

## Part 8 — Output Files After Running

| File | When Created | What to Check |
|---|---|---|
| `ttw_attack_scenario4.txt` | Always when `attack_scenario=4` | All 6 steps present, detection + mitigation logged |
| `pem_event_log.csv` | Always when `attack_scenario=4` | Row at t≈20.050: `alert_raised=1`, `phase=under_attack` |
| `pem_run_summary.csv` | End of each run | `tp≥1`, `fp=0`, `mcc>0.5`, `tdet_ms≈50` |

### `pem_event_log.csv` Key Columns

| Column | Meaning |
|---|---|
| `sim_time_s` | When the event happened |
| `attack_label` | 0 = normal event, 1 = attack event |
| `triggered_signatures` | e.g. `TTW-S1\|TTW-S2` |
| `score` | Suspicion score (0 to ~1.3) |
| `alert_raised` | 1 if alert fired |
| `phase` | baseline / under_attack / post_mitigation |
| `detection_latency_ms` | Time to detect (-1 if no alert) |

---

## Part 9 — How to Run

### Step-by-Step: First Time Setup

```
Step 1: Copy routing.cc into:
        /home/nimesha/ns-allinone-3.35/ns-3.35/scratch/

Step 2: Open terminal and navigate to ns-3 folder:
        cd /home/nimesha/ns-allinone-3.35/ns-3.35/

Step 3: Build the simulation:
        ./waf build

Step 4: Run one of the commands below
```

### Run Commands

| Goal | Command |
|---|---|
| **Baseline** (no attack) | `./waf --run "scratch/routing --simTime=30 --attack_scenario=0"` |
| **Attack only** (no detection) | `./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=1"` |
| **Attack + Detection** ← main | `./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=4"` |
| **Run 1 of 5** (for paper) | `./waf --run "scratch/routing --attack_scenario=4 --RngRun=1"` |
| **Run 2 of 5** | `./waf --run "scratch/routing --attack_scenario=4 --RngRun=2"` |
| **Run 3 of 5** | `./waf --run "scratch/routing --attack_scenario=4 --RngRun=3"` |
| **Run 4 of 5** | `./waf --run "scratch/routing --attack_scenario=4 --RngRun=4"` |
| **Run 5 of 5** | `./waf --run "scratch/routing --attack_scenario=4 --RngRun=5"` |

After 5 runs → open `pem_run_summary.csv` → compute **mean ± std** for MCC, AUROC, Tdet.

---

## Part 10 — Complete Change Log

### Bug Fixes

| # | Line(s) | What Changed | Why |
|---|---|---|---|
| Fix 1 | 139 | Removed duplicate `attack_scenario` | Compile error — declared twice |
| Fix 2 | 142 | Removed duplicate `malicious_vehicle_id` | Compile error — declared twice |
| Fix 3 | 145 | Removed duplicate `victim_neighbor_id` | Compile error — declared twice |
| Fix 4 | 49–50 | Moved `using namespace ns3` to top | Compile error — types used before namespace |
| Fix 5 | 164–169 | Merged two structs into one `TopologyPacket` | Type mismatch — two definitions of same concept |

### New Additions

| Category | Lines | What Was Added | Purpose |
|---|---|---|---|
| Attack timing | 154–156 | `TTW_HELLO_TIME`, `TTW_LINK_BREAK`, `TTW_REPLAY_TIME` | Clear timeline constants |
| Attack state | 172–183 | `ttw_stored_packet`, `ttw_controller_table`, `ttw_log` | Store attacker's data and log |
| PEM constants | 185–193 | 8 threshold/parameter constants | Configure the detector |
| Weights | 195–203 | `PEM_WEIGHTS[9]` | Weighted signature scoring |
| Decay tau | 207 | `PEM_DECAY_TAU_S = 0.200` | Temporal pressure time constant |
| Event type | 209–214 | `PemEventType` enum | Label beacon/topology/heartbeat |
| Event struct | 216–235 | `PemEvent` struct (16 fields) | Store all info about one event |
| Counters | 237–256 | TP/TN/FP/FN, score, timing, phase flags | Track detection state |
| Math functions | 272–389 | MCC, AUROC, latency, phase label | Compute metrics |
| CSV output | 556–671 | Event CSV + summary CSV writers | Export results to file |
| 9-sig detector | 690–877 | `PemEvaluateEvent()` | Core detection logic |
| Weighted loop | 824–831 | Replaced `1/9` with `PEM_WEIGHTS[i]` | Fix equal-weight problem |
| Temporal pressure | 833–855 | History-based decay loop | Make score time-aware |
| Event emitters | 879–955 | `PemEmitEvent`, beacon/heartbeat helpers | Connect events to detector |
| TTW functions | 956–1212 | 6 TTW attack functions | Implement the attack scenario |

---

## Quick Reference Card

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ATTACK SCENARIO VALUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --attack_scenario=0   →  No attack (baseline only)
  --attack_scenario=1   →  Attack, no detection
  --attack_scenario=4   →  Attack + PEM detection ← USE THIS

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  KEY THRESHOLDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PEM_SCORE_THRESHOLD = 0.12   →  score > 0.12 = alert
  PEM_DECAY_TAU_S     = 0.200  →  200ms temporal decay
  TTW attack:  S0(0.15) + S1(0.15) = 0.30 > 0.12 ✅

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OUTPUT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ttw_attack_scenario4.txt  →  Human-readable attack log
  pem_event_log.csv         →  Every event with score
  pem_run_summary.csv       →  TP/TN/FP/FN/MCC/AUROC/Tdet

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PAPER TARGET METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MCC    > 0.5
  AUROC  > 0.85
  Tdet   < 100 ms  (expected ≈ 50 ms)
  Run simulation 5× with RngRun=1..5 for mean ± std
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
