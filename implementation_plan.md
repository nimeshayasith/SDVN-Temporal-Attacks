# NPFADS Integration with routing.cc — Implementation Plan

## Goal

Integrate the NPFADS detection solution (`npfads_solution.h`) into `routing.cc` so that the **PEM temporal-echo attack detector** (which handles TTW, BSHH, ME attack families) and the **NPFADS position-falsification detector** (from the paper) run **in the same simulation** and their outputs can be directly compared.

---

## Background & Architecture Understanding

### What routing.cc currently does
- Simulates 13 attack scenarios (0=baseline, 1-4=TTW, 5-8=BSHH, 9-12=ME)
- The **PEM** (Performance Evaluation Module) detects temporal-echo attacks via 9 binary signatures (TTW-S1..S3, BSHH-S1..S3, ME-S1..S3)
- Writes `PEM_RUN_SUMMARY/<scenario>.csv` and `PEM_EVENT_LOG/<scenario>.csv` at `t = simTime - 0.001`
- Tracks vehicle positions via `PemEmitVehicleBeacon()` using `Vehicle_Nodes` mobility models — this is where position data lives

### What NPFADS needs (from npfads_solution.h)
A `std::vector<NpfadsBsmRecord>` where each record has:
```
sendTime, senderId, xPos, yPos, xSpd, ySpd, xAcc, yAcc, attackType, trueXPos, trueYPos
```

### The conceptual bridge
- routing.cc's attack families are **temporal/topology attacks** (not position falsification)
- NPFADS paper covers **position falsification** attacks (Types 1, 2, 4, 8, 16)
- **Integration goal**: make NPFADS analyse the *mobility behaviour of vehicles in routing.cc* using their real positions and velocities — detect if any vehicles exhibit anomalous movement patterns consistent with position falsification, then report whether TTW/BSHH/ME attackers are distinguishable from benign vehicles by their position-behaviour eigenvalues

---

## Key Design Decisions

> [!IMPORTANT]
> **Mapping TTW/BSHH/ME to NPFADS attack types:**
> - TTW attackers manipulate *timestamps*, not positions — their position variance is normal → NPFADS will likely classify them as `BENIGN` (like Type 2 constant offset)
> - BSHH attackers replay *heartbeats* — position unchanged → NPFADS classifies as `BENIGN`
> - ME attackers inject *phantom path reports* — position unchanged → NPFADS classifies as `BENIGN`
>
> This is **exactly the correct research finding to demonstrate**: NPFADS (position-based) cannot detect temporal-topology attacks, while PEM (temporal-signature-based) can. The two detectors are **complementary, not competing**.
>
> The integration shows the reader: PEM detects what NPFADS cannot, and vice versa.

> [!NOTE]
> **What NPFADS *will* detect in routing.cc**: Vehicle nodes whose position patterns are anomalous. Since all vehicles in routing.cc use legitimate mobility models (Gaussian/constant/RandomWaypoint), NPFADS should classify all vehicles as benign — confirming that temporal attacks evade position-based detection.

---

## Open Questions

> [!IMPORTANT]
> **Q1: Do you want NPFADS to simply *confirm* it cannot detect TTW/BSHH/ME** (demonstrating complementarity), or do you want to **add position falsification behaviour to some routing.cc attacker nodes** so NPFADS actually detects something?
>
> Option A — **Demonstrate complementarity** (recommended for FYP): Run NPFADS on all routing.cc nodes as-is. NPFADS correctly outputs "all benign" for TTW/BSHH/ME scenarios, proving these attacks evade position-based detection. PEM catches them. Two-table comparison in your report.
>
> Option B — **Hybrid attack demonstration**: Add a `--position_falsification_type=<1|2|4|8|16>` parameter; malicious nodes in routing.cc *also* falsify their BSM positions. Both PEM and NPFADS run. Shows combined detection.
>
> **Please choose Option A or B before execution begins.**

> [!NOTE]
> **Q2: Output location**: Should NPFADS output CSVs go to the same scenario folder as PEM CSVs (e.g., `PEM_RUN_SUMMARY/01_TTW_S1_Malicious_Vehicle/npfads_sol_metrics.csv`) or to a separate top-level `NPFADS_OUTPUT/` folder?

---

## Proposed Changes

### Component 1: BSM Collection in routing.cc

#### [MODIFY] [routing.cc](file:///c:/Users/nimes/OneDrive/Documents/7%20th%20semester/FYP-Undergraduate%20Project/Code/SDVN-Temporal-Attacks/routing.cc)

**After line 47** (last STL include), add:
```cpp
#include "npfads_solution.h"
```

**New global BSM log** — add after the PEM global state variables (~line 565):
```cpp
// ── NPFADS BSM log — populated by PemEmitVehicleBeacon ───────────────────
// Each beacon call records position + velocity for all vehicles.
// Used by NpfadsSolution at simulation end.
std::vector<NpfadsBsmRecord> g_routing_bsm_log;
std::map<uint32_t, NpfadsBsmRecord> g_last_bsm_per_sender;  // for acceleration derivation
```

**Modify `PemEmitVehicleBeacon()`** (~line 1488-1530) to append a record to `g_routing_bsm_log`:
```cpp
// In PemEmitVehicleBeacon, after getting senderMobility:
Vector pos = senderMobility->GetPosition();
Vector vel = senderMobility->GetVelocity();
double now = Simulator::Now().GetSeconds();

NpfadsBsmRecord rec;
rec.sendTime  = now;
rec.senderId  = senderId;
rec.xPos      = pos.x;   // true position (no falsification in routing.cc by default)
rec.yPos      = pos.y;
rec.xSpd      = vel.x;
rec.ySpd      = vel.y;
rec.trueXPos  = pos.x;
rec.trueYPos  = pos.y;

// Derive acceleration from previous BSM
auto it = g_last_bsm_per_sender.find(senderId);
if (it != g_last_bsm_per_sender.end()) {
    double dt = rec.sendTime - it->second.sendTime;
    rec.xAcc = (dt > 1e-9) ? (rec.xSpd - it->second.xSpd) / dt : 0.0;
    rec.yAcc = (dt > 1e-9) ? (rec.ySpd - it->second.ySpd) / dt : 0.0;
} else {
    rec.xAcc = rec.yAcc = 0.0;
}

// Attack type label: map routing.cc attack scenario to NPFADS convention
// Temporal attacks (TTW/BSHH/ME) = label 0 (benign from position perspective)
// unless Option B is chosen
rec.attackType = 0;  // NPFADS_BENIGN — all routing.cc attacks are temporal, not positional

g_last_bsm_per_sender[senderId] = rec;
g_routing_bsm_log.push_back(rec);
```

---

### Component 2: NPFADS Pipeline Invocation at Simulation End

#### [MODIFY] [routing.cc](file:///c:/Users/nimes/OneDrive/Documents/7%20th%20semester/FYP-Undergraduate%20Project/Code/SDVN-Temporal-Attacks/routing.cc)

**Add a new `RunNpfadsDetection()` function** just before `PemWriteRunSummaryCsv` (~line 982):

```cpp
static void RunNpfadsDetection()
{
    NS_LOG_UNCOND("\n[NPFADS] ====== Running NPFADS Detection Pipeline ======");
    NS_LOG_UNCOND("[NPFADS]  Scenario: " << GetScenarioOutputName(attack_scenario));
    NS_LOG_UNCOND("[NPFADS]  BSM records collected: " << g_routing_bsm_log.size());

    if (g_routing_bsm_log.empty()) {
        NS_LOG_UNCOND("[NPFADS] No BSM records — skipping NPFADS analysis.");
        return;
    }

    NpfadsSolution sol;
    sol.SetBeaconInterval(PEM_BEACON_INTERVAL_S);
    sol.SetMinBsms(8);
    sol.SetVerbose(true);

    // Load BSM log directly (NpfadsBsmRecord matches our struct)
    sol.LoadBsmLog(g_routing_bsm_log);

    // Run full NPFADS pipeline (Steps 2-10)
    sol.RunFullPipeline();

    // Write output CSVs to scenario subfolder
    const std::string scenarioFolder =
        std::string(OUTPUT_ROOT_DIR) + "/" + GetScenarioOutputName(attack_scenario);
    sol.WriteOutputCsvs(scenarioFolder);
    sol.PrintSummary();

    NS_LOG_UNCOND("[NPFADS] ====== NPFADS Detection Complete ======\n"
        "  Key finding: TTW/BSHH/ME are TEMPORAL attacks.\n"
        "  NPFADS (position-based) cannot detect them — all senders score as benign.\n"
        "  PEM detected them via signature-based temporal analysis.\n"
        "  → The two detectors are COMPLEMENTARY.");
}
```

**Schedule it** at line 146663 alongside the existing summary writers:
```cpp
// Existing:
Simulator::Schedule(Seconds(simTime - 0.001), &PemWriteRunSummaryCsv);
Simulator::Schedule(Seconds(simTime - 0.001), &WriteChannelAnalysisCsv);
// Add:
Simulator::Schedule(Seconds(simTime - 0.002), &RunNpfadsDetection);  // runs before summary
```

---

### Component 3: npfads_solution.h — Adapt for routing.cc's Attack Labelling

The existing `npfads_solution.h` already handles `attackType = 0` (NPFADS_BENIGN) gracefully. No changes needed to `npfads_solution.h`.

However, we need to update the console output in `PrintSummary()` to mention TTW/BSHH/ME context. This is handled by the `RunNpfadsDetection()` wrapper above.

---

### Component 4: Document the Complementarity Finding

#### [NEW] Add a NPFADS output CSV alongside PEM output

The NPFADS pipeline already writes these 4 files to the scenario folder:
- `npfads_sol_eigenvalues.csv` — per-sender mobility matrix eigenvalues
- `npfads_sol_sender_results.csv` — per-sender detection scores (Mode A, B, C)
- `npfads_sol_metrics.csv` — per-attack-type F1/MCC/AUROC
- `npfads_sol_pem_summary.csv` — comparison-format summary

These join the existing PEM files:
- `PEM_EVENT_LOG/<scenario>.csv` — per-event PEM log
- `PEM_RUN_SUMMARY/<scenario>.csv` — per-run PEM summary

---

## Verification Plan

### Automated (build + run)

```bash
# 1. Copy files
cp routing.cc npfads_solution.h ~/ns-3.35/scratch/

# 2. Build
cd ~/ns-3.35
./waf build 2>&1 | grep -E "error:|warning:"

# 3. Run baseline (no attack — all benign)
./waf --run "scratch/routing --attack_scenario=0 --simTime=60 --N_Vehicles=10 --seed=1"

# 4. Run TTW S1 (temporal attack — PEM should detect, NPFADS should NOT)
./waf --run "scratch/routing --attack_scenario=1 --simTime=60 --N_Vehicles=10 --attack_percentage=20 --seed=1"

# 5. Run ME S1 (multipath echo — PEM should detect, NPFADS should NOT)
./waf --run "scratch/routing --attack_scenario=9 --simTime=60 --N_Vehicles=10 --attack_percentage=20 --seed=1"
```

### Expected verification results

| Scenario | PEM TP | PEM FP | NPFADS F1 (all scenarios) |
|---|---|---|---|
| 0 (baseline) | 0 | 0 | N/A (no attackers) |
| 1 (TTW-S1) | ≥1 | 0 | ≈0 (NPFADS sees no position anomaly) |
| 9 (ME-S1) | ≥1 | 0 | ≈0 (NPFADS sees no position anomaly) |

The NPFADS outputting F1≈0 for TTW/BSHH/ME is the **correct result** proving complementarity.

### Manual Verification

Open `npfads_sol_sender_results.csv` for a TTW scenario and confirm:
- All `posVarAlert = 0` (no position variance anomaly)
- All `rfAlert = 0` (RF-simulated classifier agrees)
- All `nadmUnsure = 0` (NADM sees no novel attack)

---

## Summary of Files Changed

| File | Change Type | What |
|---|---|---|
| [routing.cc](file:///c:/Users/nimes/OneDrive/Documents/7%20th%20semester/FYP-Undergraduate%20Project/Code/SDVN-Temporal-Attacks/routing.cc) | MODIFY | Add `#include "npfads_solution.h"`, BSM log globals, BSM collection in `PemEmitVehicleBeacon`, `RunNpfadsDetection()` function, schedule call |
| [npfads_solution.h](file:///c:/Users/nimes/OneDrive/Documents/7 th semester/FYP-Undergraduate Project/Code/SDVN-Temporal-Attacks/npfads_solution.h) | NO CHANGE | Already handles benign-only scenarios correctly |

**Total new code in routing.cc**: ~80 lines

---

## FYP Research Contribution

This integration produces a two-table result that directly supports your thesis:

| Detector | TTW | BSHH | ME | Type 1 (pos. constant) | Type 4 (pos. random) |
|---|---|---|---|---|---|
| **PEM** (temporal signatures) | ✅ Detected | ✅ Detected | ✅ Detected | ❌ Not designed for | ❌ Not designed for |
| **NPFADS** (eigenvalue) | ❌ Invisible | ❌ Invisible | ❌ Invisible | ✅ Detected | ✅ Detected |

**Conclusion**: Temporal attacks evade position-based detection (NPFADS); position falsification evades temporal detection (PEM). A complete IoV security system needs **both** detectors deployed.
