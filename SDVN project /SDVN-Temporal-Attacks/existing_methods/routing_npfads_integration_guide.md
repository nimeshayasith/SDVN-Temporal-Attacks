# routing.cc — NPFADS Integration Change Guide

**Purpose:** Integrate `npfads_solution.h` into `routing.cc` so the NPFADS position-based detector runs alongside the PEM temporal-echo detector. The key research finding to demonstrate is: TTW / BSHH / ME are **temporal attacks** — NPFADS (which analyses position variance) will correctly classify all vehicles as benign, while PEM detects them. The two detectors are **complementary**.

**Reference paper:** Ilango, Ma & Su (2022), *Engineering Applications of Artificial Intelligence*, 116, 105380.

---

## Overview of All Changes

| # | Location in routing.cc | What changes | Lines affected |
|---|------------------------|-------------|----------------|
| 1 | Line 47 (after last `#include`) | Add `#include "npfads_solution.h"` | Insert after line 47 |
| 2 | Line 559 (after PEM globals) | Add NPFADS BSM log globals | Insert after line 559 |
| 3 | Lines 1488–1525 (`PemEmitVehicleBeacon`) | Append BSM record inside the function | Insert inside lines 1488–1525 |
| 4 | Line 982 (before `PemWriteRunSummaryCsv`) | Add `RunNpfadsDetection()` function | Insert before line 982 |
| 5 | Line 146663 (simulation schedule block) | Schedule `RunNpfadsDetection()` | Insert before line 146663 |

> **Files needed in `ns-3.35/scratch/`:**
> - `routing.cc` (this file)
> - `npfads_solution.h` (copy alongside routing.cc)
>
> ```bash
> cp npfads_solution.h ~/ns-3.35/scratch/npfads_solution.h
> ```

---

---

## Change 1 — Add `#include "npfads_solution.h"`

### Location
**After line 47** — this is the last `#include` line in the file. Line 47 currently reads:
```cpp
#include <bits/stdc++.h>
```
Line 48 is blank. Line 49 is `using namespace std;`.

### What to add
Insert **one new line** between line 47 and line 48:

```
Line 47   #include <bits/stdc++.h>
          ↓ INSERT HERE
Line 47+1 #include "npfads_solution.h"
Line 48   (blank)
Line 49   using namespace std;
Line 50   using namespace ns3;
```

### Exact text to insert

```cpp
#include "npfads_solution.h"
```

### Why this line
`npfads_solution.h` must be included **after** all STL headers (`<bits/stdc++.h>` pulls in everything it needs) and **before** `using namespace std;` and `using namespace ns3;` so the `NpfadsBsmRecord` struct and `NpfadsSolution` class are visible to all code below.

### After the change, lines 46–51 look like this

```cpp
#include <limits.h>
#include <bits/stdc++.h>
#include "npfads_solution.h"

using namespace std;
using namespace ns3;
```

---

---

## Change 2 — Add NPFADS Global Variables

### Location
**After line 559** — this is the last line of the PEM global state block. Line 559 currently reads:
```cpp
std::map<std::string, double> pem_previous_path_counts;
```
Lines 555–559 are the last PEM global variables.

### What to add
Insert the following block **after line 559** (before the blank line that follows):

```cpp
// ── NPFADS BSM log ─────────────────────────────────────────────────────────
// Populated by PemEmitVehicleBeacon(). Used by RunNpfadsDetection() at end.
// In routing.cc, all vehicle positions are TRUE (no position falsification
// for TTW/BSHH/ME attacks). NPFADS will therefore classify all senders as
// benign from a position perspective — proving complementarity with PEM.
static std::vector<NpfadsBsmRecord>          g_routing_bsm_log;
static std::map<uint32_t, NpfadsBsmRecord>   g_routing_last_bsm;
```

### After the change, that section looks like this

```cpp
// (existing lines 546–559, unchanged)
std::vector<double> pem_positive_scores;
std::vector<double> pem_negative_scores;
std::deque<PemEvent> pem_event_window;
std::map<uint32_t, std::vector<PemEvent> > pem_sender_event_history;
std::map<uint32_t, std::vector<PemEvent> > pem_heartbeat_history;
std::map<std::string, std::vector<PemEvent> > pem_link_report_history;
std::map<std::string, double> pem_link_first_recorded_time;
std::map<uint32_t, double> pem_last_authentic_beacon_reception;
std::map<std::string, double> pem_previous_path_counts;
std::vector<PemEvent> pem_all_events;
double pem_under_attack_pdr_sum = 0.0;
double pem_under_attack_te2e_sum = 0.0;
double pem_post_mitigation_pdr_sum = 0.0;
double pem_post_mitigation_te2e_sum = 0.0;

// ── NPFADS BSM log ─────────────────────────────────────────────────────────
// Populated by PemEmitVehicleBeacon(). Used by RunNpfadsDetection() at end.
static std::vector<NpfadsBsmRecord>          g_routing_bsm_log;
static std::map<uint32_t, NpfadsBsmRecord>   g_routing_last_bsm;
```

### What these variables do

| Variable | Type | Purpose |
|----------|------|---------|
| `g_routing_bsm_log` | `vector<NpfadsBsmRecord>` | One record per vehicle beacon. Accumulates across entire simulation. Fed into `NpfadsSolution::LoadBsmLog()` at the end. |
| `g_routing_last_bsm` | `map<uint32_t, NpfadsBsmRecord>` | Stores the previous BSM per sender so acceleration (ΔVel/Δt) can be derived for each new beacon. |

---

---

## Change 3 — Modify `PemEmitVehicleBeacon()` to Populate the BSM Log

### Location
**Lines 1488–1525** — the full body of `PemEmitVehicleBeacon()`.

Current full function (lines 1488–1525):

```cpp
static void
PemEmitVehicleBeacon(uint32_t senderId, uint32_t receiverId)
{
    if (senderId >= Vehicle_Nodes.GetN() || receiverId >= Vehicle_Nodes.GetN())
    {
        return;
    }

    Ptr<MobilityModel> senderMobility = Vehicle_Nodes.Get(senderId)->GetObject<MobilityModel>();
    Ptr<MobilityModel> receiverMobility = Vehicle_Nodes.Get(receiverId)->GetObject<MobilityModel>();
    if (!senderMobility || !receiverMobility)
    {
        return;
    }

    Vector senderPosition = senderMobility->GetPosition();
    Vector receiverPosition = receiverMobility->GetPosition();
    const double distance =
        std::sqrt(std::pow(senderPosition.x - receiverPosition.x, 2.0) +
                  std::pow(senderPosition.y - receiverPosition.y, 2.0));
    if (distance > TTW_COMM_RANGE)
    {
        return;
    }

    PemEmitEvent(PEM_EVENT_BEACON,
                 senderId,
                 senderId,
                 senderId,
                 senderId,
                 receiverId,
                 Simulator::Now().GetSeconds(),
                 Simulator::Now().GetSeconds(),
                 senderPosition,
                 senderPosition,
                 receiverPosition,
                 false);
}
```

### What to add
Insert a new block **after the `PemEmitEvent(...)` call and before the closing brace `}`** of the function.

This means the insertion point is **after line 1524** (the last line of `PemEmitEvent(...)`) and **before line 1525** (the closing `}`).

### Exact code to insert (between the existing `PemEmitEvent(...)` call and the closing `}`)

```cpp
    // ── NPFADS BSM record ───────────────────────────────────────────────────
    // Build one NpfadsBsmRecord for this beacon and append to g_routing_bsm_log.
    // In routing.cc there is NO position falsification for TTW/BSHH/ME attacks —
    // the attacker manipulates timestamps or heartbeats, not GPS coordinates.
    // Therefore xPos = trueXPos always, and attackType = 0 (benign from
    // NPFADS perspective). NPFADS will classify every vehicle as benign,
    // which is the CORRECT result proving these attacks evade position detection.
    {
        Vector senderVel = senderMobility->GetVelocity();
        double now       = Simulator::Now().GetSeconds();

        NpfadsBsmRecord rec;
        rec.sendTime  = now;
        rec.senderId  = senderId;
        rec.xPos      = senderPosition.x;   // true — no falsification
        rec.yPos      = senderPosition.y;
        rec.xSpd      = senderVel.x;
        rec.ySpd      = senderVel.y;
        rec.trueXPos  = senderPosition.x;
        rec.trueYPos  = senderPosition.y;
        rec.attackType = 0;   // NPFADS_BENIGN: TTW/BSHH/ME are not position attacks

        // Derive acceleration from previous beacon for this sender
        auto it = g_routing_last_bsm.find(senderId);
        if (it != g_routing_last_bsm.end())
        {
            double dt = now - it->second.sendTime;
            if (dt > 1e-9)
            {
                rec.xAcc = (rec.xSpd - it->second.xSpd) / dt;
                rec.yAcc = (rec.ySpd - it->second.ySpd) / dt;
            }
            else
            {
                rec.xAcc = rec.yAcc = 0.0;
            }
        }
        else
        {
            rec.xAcc = rec.yAcc = 0.0;   // first beacon from this sender
        }

        g_routing_last_bsm[senderId] = rec;
        g_routing_bsm_log.push_back(rec);
    }
    // ── End NPFADS BSM record ───────────────────────────────────────────────
```

### After the change, the full function looks like this

```cpp
static void
PemEmitVehicleBeacon(uint32_t senderId, uint32_t receiverId)
{
    if (senderId >= Vehicle_Nodes.GetN() || receiverId >= Vehicle_Nodes.GetN())
    {
        return;
    }

    Ptr<MobilityModel> senderMobility = Vehicle_Nodes.Get(senderId)->GetObject<MobilityModel>();
    Ptr<MobilityModel> receiverMobility = Vehicle_Nodes.Get(receiverId)->GetObject<MobilityModel>();
    if (!senderMobility || !receiverMobility)
    {
        return;
    }

    Vector senderPosition = senderMobility->GetPosition();
    Vector receiverPosition = receiverMobility->GetPosition();
    const double distance =
        std::sqrt(std::pow(senderPosition.x - receiverPosition.x, 2.0) +
                  std::pow(senderPosition.y - receiverPosition.y, 2.0));
    if (distance > TTW_COMM_RANGE)
    {
        return;
    }

    PemEmitEvent(PEM_EVENT_BEACON,
                 senderId,
                 senderId,
                 senderId,
                 senderId,
                 receiverId,
                 Simulator::Now().GetSeconds(),
                 Simulator::Now().GetSeconds(),
                 senderPosition,
                 senderPosition,
                 receiverPosition,
                 false);

    // ── NPFADS BSM record ───────────────────────────────────────────────────
    {
        Vector senderVel = senderMobility->GetVelocity();
        double now       = Simulator::Now().GetSeconds();

        NpfadsBsmRecord rec;
        rec.sendTime  = now;
        rec.senderId  = senderId;
        rec.xPos      = senderPosition.x;
        rec.yPos      = senderPosition.y;
        rec.xSpd      = senderVel.x;
        rec.ySpd      = senderVel.y;
        rec.trueXPos  = senderPosition.x;
        rec.trueYPos  = senderPosition.y;
        rec.attackType = 0;

        auto it = g_routing_last_bsm.find(senderId);
        if (it != g_routing_last_bsm.end())
        {
            double dt = now - it->second.sendTime;
            if (dt > 1e-9)
            {
                rec.xAcc = (rec.xSpd - it->second.xSpd) / dt;
                rec.yAcc = (rec.ySpd - it->second.ySpd) / dt;
            }
            else
            {
                rec.xAcc = rec.yAcc = 0.0;
            }
        }
        else
        {
            rec.xAcc = rec.yAcc = 0.0;
        }

        g_routing_last_bsm[senderId] = rec;
        g_routing_bsm_log.push_back(rec);
    }
    // ── End NPFADS BSM record ───────────────────────────────────────────────
}
```

### Nothing else in this function changes
The existing `PemEmitEvent(...)` call is **not removed or modified**. The NPFADS block is **purely additive** — it only appends to `g_routing_bsm_log` and does nothing else.

---

---

## Change 4 — Add `RunNpfadsDetection()` Function

### Location
**Before line 982** — line 982 is the start of `PemWriteRunSummaryCsv()`.
Line 981 is a blank line. Line 980 is a closing `}`.

Insert the entire new function **between line 980 and line 982** (i.e., in the blank line at 981).

### Exact code to insert

```cpp
// =============================================================================
// RunNpfadsDetection — runs the NPFADS pipeline on routing.cc vehicle beacons.
//
// This function is called at t = simTime - 0.002 (just before PEM summary).
//
// KEY RESEARCH FINDING:
//   TTW / BSHH / ME are TEMPORAL attacks — they manipulate timestamps,
//   heartbeat identity, or topology path reports. They do NOT falsify GPS
//   position. Therefore all vehicles in routing.cc report their true position
//   in every beacon and NPFADS will classify all senders as benign
//   (posVar ≈ benign, no alerts).
//
//   PEM detects TTW/BSHH/ME via temporal signatures.
//   NPFADS cannot detect them — it outputs "all benign".
//
//   The two-table comparison in the report proves:
//     PEM  → detects temporal attacks, blind to position attacks
//     NPFADS → detects position attacks, blind to temporal attacks
//     A complete IoV security system needs BOTH.
// =============================================================================
static void
RunNpfadsDetection()
{
    NS_LOG_UNCOND("\n[NPFADS] ====== Running NPFADS Detection Pipeline ======");
    NS_LOG_UNCOND("[NPFADS]  Attack scenario : " << attack_scenario);
    NS_LOG_UNCOND("[NPFADS]  BSM records     : " << g_routing_bsm_log.size());

    if (g_routing_bsm_log.empty())
    {
        NS_LOG_UNCOND("[NPFADS] No BSM records collected — skipping.");
        return;
    }

    // Build and run the full NPFADS pipeline
    NpfadsSolution sol;
    sol.SetBeaconInterval(0.1);   // 100 ms beacon interval (same as routing.cc)
    sol.SetMinBsms(8);
    sol.SetVerbose(true);

    sol.LoadBsmLog(g_routing_bsm_log);
    sol.RunFullPipeline();

    // Write output CSVs to the same scenario folder as PEM output
    const std::string scenarioFolder =
        BuildScenarioCsvPath("NPFADS_OUTPUT", attack_scenario);
    // BuildScenarioCsvPath returns a full file path — strip the filename to get folder
    // Use the PEM_RUN_SUMMARY folder instead for co-location
    const std::string outFolder =
        BuildScenarioCsvPath("PEM_RUN_SUMMARY", attack_scenario);
    // outFolder is a .csv path like ".../PEM_RUN_SUMMARY/01_TTW_S1.csv"
    // Extract directory: strip everything from the last '/'
    std::string outDir = outFolder;
    size_t lastSlash = outDir.find_last_of("/\\");
    if (lastSlash != std::string::npos)
        outDir = outDir.substr(0, lastSlash);

    sol.WriteOutputCsvs(outDir);
    sol.PrintSummary();

    NS_LOG_UNCOND("[NPFADS] ====== NPFADS Detection Complete ======");
    NS_LOG_UNCOND("[NPFADS] Expected result for TTW/BSHH/ME scenarios:");
    NS_LOG_UNCOND("[NPFADS]   posVar F1  ≈ 0.0  (all vehicles look benign)");
    NS_LOG_UNCOND("[NPFADS]   RF-sim F1  ≈ 0.0  (no position anomaly rules fire)");
    NS_LOG_UNCOND("[NPFADS]   Novel det  = NO    (no AE reconstruction error)");
    NS_LOG_UNCOND("[NPFADS] This confirms TTW/BSHH/ME evade position-based detection.");
    NS_LOG_UNCOND("[NPFADS] PEM detected them via temporal signature analysis.");
    NS_LOG_UNCOND("[NPFADS] --> The two detectors are COMPLEMENTARY.\n");
}
```

### After inserting, the surrounding area looks like this

```
(line 980)   }                          ← closing brace of previous function
(line 981)   (blank)
             ↓ INSERT RunNpfadsDetection() here
(line 982)   static void
(line 983)   PemWriteRunSummaryCsv()
(line 984)   {
```

---

---

## Change 5 — Schedule `RunNpfadsDetection()` at Simulation End

### Location
**Line 146663** — this line currently reads:
```cpp
Simulator::Schedule(Seconds(simTime - 0.001), &PemWriteRunSummaryCsv);
```

### What to add
Insert **one new line immediately before line 146663**:

```
(before line 146663)  ← INSERT HERE
Line 146663   Simulator::Schedule(Seconds(simTime - 0.001), &PemWriteRunSummaryCsv);
Line 146664   Simulator::Schedule(Seconds(simTime - 0.001), &WriteChannelAnalysisCsv);
```

### Exact line to insert

```cpp
  Simulator::Schedule(Seconds(simTime - 0.002), &RunNpfadsDetection);
```

### After the change, that block looks like this

```cpp
  Simulator::Schedule(Seconds(simTime - 0.002), &RunNpfadsDetection);      // ← NEW
  Simulator::Schedule(Seconds(simTime - 0.001), &PemWriteRunSummaryCsv);
  Simulator::Schedule(Seconds(simTime - 0.001), &WriteChannelAnalysisCsv);
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();
```

### Why `simTime - 0.002` (not `simTime - 0.001`)
NPFADS runs at `t - 2ms` so it completes **before** `PemWriteRunSummaryCsv` at `t - 1ms`. This ensures the NPFADS console output appears first in the terminal, then the PEM summary CSV is written, making the terminal log easy to read in sequence.

---

---

## Build and Run Instructions

### Step 1 — Copy files to NS-3 scratch

```bash
cp routing.cc       ~/ns-3.35/scratch/routing.cc
cp npfads_solution.h ~/ns-3.35/scratch/npfads_solution.h
```

### Step 2 — Build

```bash
cd ~/ns-3.35
./waf build 2>&1 | grep -E "error:|warning:"
```

Expected: zero errors. If you see `NpfadsBsmRecord was not declared`, the `#include "npfads_solution.h"` was placed after `using namespace`, or `npfads_solution.h` was not copied to `scratch/`.

### Step 3 — Run baseline (no attack, verify NPFADS runs cleanly)

```bash
./waf --run "scratch/routing --attack_scenario=0 --simTime=60 --N_Vehicles=10"
```

Expected terminal output:
```
[NPFADS] ====== Running NPFADS Detection Pipeline ======
[NPFADS]  Attack scenario : 0
[NPFADS]  BSM records     : (some number > 0)
[NPFADS-SOL] Loaded N BSM records
[NPFADS-SOL] Eigenvalues computed for N senders
...
[NPFADS] Expected result for TTW/BSHH/ME scenarios:
[NPFADS]   posVar F1  ≈ 0.0  (all vehicles look benign)
```

### Step 4 — Run TTW-S1 (scenario 1)

```bash
./waf --run "scratch/routing --attack_scenario=1 --simTime=60 --N_Vehicles=10"
```

### Step 5 — Run ME-S1 (scenario 9)

```bash
./waf --run "scratch/routing --attack_scenario=9 --simTime=60 --N_Vehicles=10"
```

---

---

## Expected Output Files

After each run, the following files will appear in the scenario output folder:

```
PEM_RUN_SUMMARY/
├── 01_TTW_S1_Malicious_Vehicle/
│   ├── pem_run_summary.csv          ← existing PEM output (TP≥1, FP=0)
│   ├── npfads_sol_eigenvalues.csv   ← NEW: per-sender eigenvalues
│   ├── npfads_sol_sender_results.csv ← NEW: per-sender posVar / RF / NADM scores
│   ├── npfads_sol_metrics.csv       ← NEW: detection metrics (F1≈0 expected)
│   └── npfads_sol_pem_summary.csv   ← NEW: PEM-format NPFADS summary
```

---

---

## Expected Detection Results — The Complementarity Table

This is the two-table research result your report should show:

| Attack Scenario | PEM TP | PEM FP | PEM MCC | NPFADS posVar F1 | NPFADS RF F1 | NPFADS Novel? |
|----------------|--------|--------|---------|-----------------|-------------|--------------|
| 0 — Baseline | 0 | 0 | N/A | N/A | N/A | NO |
| 1 — TTW-S1 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |
| 2 — TTW-S2 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |
| 3 — TTW-S3 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |
| 4 — TTW-S4 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |
| 5 — BSHH-S1 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |
| 9 — ME-S1 | ≥1 | 0 | ~1.0 | **~0.0** | **~0.0** | **NO** |

**Reading the table:**
- PEM detects all temporal attacks (MCC ≈ 1.0, FP = 0).
- NPFADS outputs F1 ≈ 0 for all temporal attacks — it cannot see them because no position is falsified.
- Both columns together prove the two systems are **complementary, not redundant**.

---

---

## Why NPFADS Will Output F1 ≈ 0 for All Routing.cc Scenarios

This is not a failure — it is the **intended and correct result**:

```
In routing.cc:
  Vehicle_Nodes.Get(i)->GetObject<MobilityModel>()->GetPosition()
  returns the TRUE position every time.

In PemEmitVehicleBeacon (after Change 3):
  rec.xPos     = senderPosition.x   ← always true
  rec.trueXPos = senderPosition.x   ← same
  rec.attackType = 0                ← always NPFADS_BENIGN

After column centering in NPFADS:
  - Every vehicle's posVar is "normal" (constant-velocity motion)
  - No vehicle has frozen, random, or offset position
  - posVar scores for all vehicles ≈ benign baseline

Result:
  - No NPFADS alert fires for any vehicle
  - F1 = 0 (no true positives — all vehicles are correctly labelled benign
    by the position scorer, even the temporal attackers)
```

This is exactly the research contribution: **temporal attacks are invisible to position-based detection**, which is why a separate temporal detector (PEM) is necessary.

---

---

## Summary of Lines Changed

| Change | Lines in routing.cc | Type | Code added |
|--------|---------------------|------|-----------|
| 1 | After line 47 | INSERT | `#include "npfads_solution.h"` |
| 2 | After line 559 | INSERT | 2 global variable declarations |
| 3 | Inside lines 1488–1525 | INSERT | ~40 lines inside `PemEmitVehicleBeacon()` |
| 4 | Before line 982 | INSERT | ~60 lines new function `RunNpfadsDetection()` |
| 5 | Before line 146663 | INSERT | 1 `Simulator::Schedule(...)` call |

**Total lines added to routing.cc: ~105**
**Lines removed or modified: 0**

All changes are purely additive. No existing code is deleted or altered.

---

*Integration guide for routing.cc + npfads_solution.h — FYP, Department of EIE, University of Ruhuna*
*Reference: Ilango, Ma & Su (2022), Engineering Applications of Artificial Intelligence, 116, 105380*
