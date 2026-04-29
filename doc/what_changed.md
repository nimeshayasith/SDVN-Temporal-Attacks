# What Changed — SDVN Temporal-Echo Attack Implementation

This document describes every change made to `routing.cc` and the addition of `sdvn-temporal-attacks.cc` for the SDVN Temporal-Echo Topology Attack simulation project.

---

## Files Changed

| File | Type of Change |
|---|---|
| `routing.cc` | Major additions: attack variables, PEM layer, TTW functions |
| `sdvn-temporal-attacks.cc` | New file: standalone NS-3 simulation |
| `doc/PEM_implementation_guide.md` | New file: PEM documentation |

---

## 1. `routing.cc` — Global Variable Fixes

### Error 1 Fix — `attack_scenario` declared twice
**Before (broken):**
```cpp
uint32_t attack_scenario = 0;   // somewhere in globals
// ...later in file:
int attack_scenario = 4;        // REDECLARATION — compile error
```

**After (fixed, line 139):**
```cpp
// ERROR 1 FIX: was declared twice (uint32_t=0 AND int=4). Keep ONE declaration.
//              Default = 0 (no attack). Pass --attack_scenario=4 on command line.
uint32_t attack_scenario = 0;
```

### Error 2 Fix — `malicious_vehicle_id` declared twice
**Before (broken):**
```cpp
uint32_t malicious_vehicle_id = 0;
// ...later:
uint32_t malicious_vehicle_id = 5;   // REDECLARATION
```

**After (fixed, line 142):**
```cpp
// ERROR 2 FIX: was declared twice. Keep ONE declaration.
uint32_t malicious_vehicle_id = 0;   // V0 = attacker
```

### Error 3 Fix — `victim_neighbor_id` declared twice
**Before (broken):**
```cpp
uint32_t victim_neighbor_id = 1;
// ...later:
uint32_t victim_neighbor_id = 2;   // REDECLARATION
```

**After (fixed, line 145):**
```cpp
// ERROR 3 FIX: was declared twice. Keep ONE declaration.
uint32_t victim_neighbor_id = 1;     // V1 = victim
```

---

## 2. `routing.cc` — Attack Timing Constants (Error 4 Fix)

**Before:** The timing constants used `Seconds()` from `ns3` namespace but the `using namespace ns3` declaration was placed too late in the file, causing a compile error.

**After (lines 154–156):**
```cpp
// ERROR 4 FIX: uncommented now that namespace is declared earlier
static const double TTW_HELLO_TIME  = 10.0;   // t=10: HELLO exchange
static const double TTW_LINK_BREAK  = 15.0;   // t=15: physical link breaks
static const double TTW_REPLAY_TIME = 20.0;   // t=20: attacker replays
```

---

## 3. `routing.cc` — Topology Packet Struct Merge (Error 5 Fix)

**Before:** Two different structs existed:
- `StoredPacket` — used in one part of the file
- `TopologyPacket` — defined again separately in the implementation section

**After (lines 164–169):** Merged into one unified struct:
```cpp
struct TopologyPacket {
    uint32_t src_id;         // node sending the update
    uint32_t seen_id;        // neighbor being reported
    double   timestamp;      // simulation time when link was observed
    bool     is_forged;      // true = attacker tampered this packet
};
```

All global usage now references `TopologyPacket` consistently.

---

## 4. `routing.cc` — New Attack State Variables (lines 172–180)

```cpp
// Attacker's stored copy of old packet  ← step ③ in diagram
TopologyPacket ttw_stored_packet;
bool           ttw_packet_stored = false;

// Controller's belief about the network topology
std::map<std::string, TopologyPacket> ttw_controller_table;

// DSRC communication range
static const double TTW_COMM_RANGE = 300.0;

// Log file for attack events
std::ofstream ttw_log;
```

---

## 5. `routing.cc` — New PEM (Performance Evaluation Metrics) Layer (lines 182–938)

This is the largest addition. The entire PEM instrumentation block was added.

### PEM Constants (lines 186–193)
```cpp
static const double PEM_BEACON_BUDGET_MS        = 100.0;
static const double PEM_BEACON_INTERVAL_S       = 0.100;
static const double PEM_PROPAGATION_EPSILON_S   = 0.020;
static const double PEM_HEARTBEAT_WINDOW_S      = 0.400;
static const double PEM_SCORE_THRESHOLD         = 0.12;
static const double PEM_ME_TOLERANCE_MU         = 0.30;
static const double PEM_ME_DELTA_MAX            = 1.0;
static const double PEM_SIGNAL_PLACEHOLDER      = -9999.0;
```

### New Enum (lines 195–200)
```cpp
enum PemEventType {
    PEM_EVENT_BEACON         = 0,
    PEM_EVENT_TOPOLOGY_UPDATE = 1,
    PEM_EVENT_HEARTBEAT      = 2
};
```

### New Struct: `PemEvent` (lines 202–221)
Added 16-field struct to record every observable network event for detection scoring.

### New Counters (lines 223–256)
```cpp
uint64_t pem_true_positive  = 0;
uint64_t pem_true_negative  = 0;
uint64_t pem_false_positive = 0;
uint64_t pem_false_negative = 0;
double   pem_last_mcc       = 0.0;
double   pem_last_auroc     = 0.5;
// ... plus score, timing, phase flags, history maps
```

### New Helper Functions Added

| Function | Lines | Purpose |
|---|---|---|
| `PemSafeSqrt()` | 258–262 | Safe square root (clamps negatives to 0) |
| `PemComputeMcc()` | 264–281 | Matthews Correlation Coefficient |
| `PemComputeAuroc()` | 283–310 | Area Under ROC Curve |
| `PemRecordObservation()` | 312–351 | Update TP/TN/FP/FN counters |
| `PemGetDetectionLatencyMs()` | 353–361 | Compute Tdet in milliseconds |
| `PemGetPhaseLabel()` | 363–375 | Return baseline/under_attack/post_mitigation |
| `PemEventTypeToString()` | 410–424 | Enum to string |
| `PemGetLinkKey()` | 426–432 | Canonical link key "a_b" |
| `PemTrimSlidingWindow()` | 434–442 | Remove old events from window |
| `PemEstimateLambdaHat()` | 444–462 | Vehicle density estimate |
| `PemCountPathsDfs()` | 464–502 | DFS path counter (cap 8) |
| `PemComputePathCount()` | 504–524 | Count paths between two nodes |
| `PemTriggeredSignatureString()` | 526–554 | Build human-readable signature |
| `PemWriteCsvHeaderIfNeeded()` | 556–578 | Write CSV header once |
| `PemWriteEventCsv()` | 580–613 | Write one event row to CSV |
| `PemWriteRunSummaryCsv()` | 615–657 | Write full-run summary row |
| `PemCaptureRoutingPhaseMetrics()` | 659–674 | Snapshot PDR/Te2e by phase |
| `PemEvaluateEvent()` | 676–833 | 9-signature detection scorer |
| `PemEmitEvent()` | 835–868 | Dispatch one event through scorer |
| `PemEmitHeartbeatEvent()` | 870–890 | Helper for heartbeat events |
| `PemEmitVehicleBeacon()` | 892–929 | Helper for beacon events |
| `PemEmitVehicleHeartbeat()` | 931–938 | Helper for vehicle heartbeat |

---

## 6. `routing.cc` — New TTW Attack Functions (lines 941–1198)

### `TTW_InitLog()` (line 947)
Opens `ttw_attack_scenario4.txt` log file and writes attack timeline header.

### `TTW_SendHelloBeacon()` (line 966)
Simulates the V2V HELLO exchange at `t=10s`. Logs position, distance, and delivery result.

### `TTW_SendTopologyUpdate()` (line 993)
Sends a legitimate topology update to the controller table. Now also calls `PemEmitEvent()` so the PEM layer records this as a normal (non-attack) observation.

### `TTW_StorePacket()` (line 1051)
Attacker (V0) captures and stores a valid topology packet at `t=10s` before the link breaks.

### `TTW_ReplayAttack()` (line 1073)
The core attack function:
- Builds a forged `TopologyPacket` with a new timestamp
- Injects it into `ttw_controller_table`
- Sets `pem_attack_injection_time` and `pem_attack_active = true`
- Schedules `TTW_RunReplayDetection()` 50ms later

### `TTW_RunReplayDetection()` (line 1148)
Runs the PEM detector after the attack:
- Emits a `PEM_EVENT_TOPOLOGY_UPDATE` with `attackLabel = true`
- If alert is raised, erases the forged entry from `ttw_controller_table`
- Logs detection score and latency

---

## 7. `sdvn-temporal-attacks.cc` — New Standalone File

This is a complete independent NS-3 simulation file implementing all three attack families.

### Attack Types Defined
```cpp
enum AttackType {
    NO_ATTACK   = 0,
    TTW_ATTACK  = 1,   // Topology Time-Warp Attack
    BSHH_ATTACK = 2,   // Beacon State Heartbeat Hijack Attack
    ME_ATTACK   = 3    // Multipath Echo Attack
};
```

### New NS-3 Tag Classes
| Class | Purpose |
|---|---|
| `TopologyUpdateTag` | Carries source/neighbor IDs, timestamp, malicious/forged flags in NS-3 packets |
| `HeartbeatTag` | Carries sender ID, timestamp, replay flag, original timestamp |

### New Application Classes
| Class | Purpose |
|---|---|
| `VehicleApplication` | Sends beacons, discovers neighbors, sends topology updates |
| `RSUApplication` | Receives packets, optionally performs TTW/BSHH/ME attacks |
| `ControllerApplication` | Receives topology + heartbeat updates, detects inconsistencies |

### Simulation Main Setup
- Creates 4 vehicles + 1 RSU + 1 controller node
- Configures 802.11p WiFi with OCBMODE
- Uses `ConstantVelocityMobilityModel` for vehicles
- Schedules link break at `t=15s` and replay at `t=20s`
- Writes logs to `simulation.log`, `topology_log.csv`, `attack_log.csv`

---

## Summary Table of All Changes

| Change | Location | Reason |
|---|---|---|
| Removed duplicate `attack_scenario` | routing.cc:139 | Fix compile error (Error 1) |
| Removed duplicate `malicious_vehicle_id` | routing.cc:142 | Fix compile error (Error 2) |
| Removed duplicate `victim_neighbor_id` | routing.cc:145 | Fix compile error (Error 3) |
| Moved `using namespace ns3` earlier | routing.cc:49–50 | Fix `Seconds()` usage (Error 4) |
| Merged `StoredPacket`+`TopologyPacket` | routing.cc:164–169 | Fix duplicate struct (Error 5) |
| Added attack timing constants | routing.cc:154–156 | TTW timeline reference |
| Added `ttw_controller_table` + `ttw_log` | routing.cc:172–183 | Attack state storage |
| Added full PEM layer (constants, structs, functions) | routing.cc:185–938 | Detection metrics |
| Added TTW attack functions (6 functions) | routing.cc:941–1198 | Attack simulation |
| Created `sdvn-temporal-attacks.cc` | New file | Standalone simulation |
