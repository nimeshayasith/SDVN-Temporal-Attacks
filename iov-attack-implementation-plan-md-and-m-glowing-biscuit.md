# Plan: npfads_attacks.cc — IoV Position Falsification Attack Simulator

## Context

All 12 SDVN attack scenarios (TTW, BSHH, ME) are already implemented in `routing.cc`. This plan adds a **separate, standalone** NS-3 simulation file `npfads_attacks.cc` based on the IoV position falsification attack model from Ilango et al. (2022). It is independent of `routing.cc` and targets a different threat model: insider vehicles falsifying their BSM position fields. The file will:
- Simulate all 5 VeReMi attack variants (Type 1/2/4/8/16)
- Log every BSM with ground truth labels to CSV
- Compute per-sender mobility matrix eigenvalues (as per paper's preprocessing pipeline)
- Output precision / recall / F1 per attack variant using a simple anomaly classifier

---

## Critical Files

| File | Role |
|------|------|
| **`npfads_attacks.cc`** | New file — place in `ns-3.35/scratch/` |
| `routing.cc` | Reference only — do NOT modify |
| `IoV_Attack_Implementation_Plan.md` | Source of truth for attack parameters and preprocessing spec |

---

## Architecture Overview

```
npfads_attacks.cc (standalone scratch program)

Simulator::Schedule callbacks (every 100 ms per vehicle)
        │
        ▼
GenerateBSM(node, attack_type)
  ├── reads true pos/vel from MobilityModel
  ├── computes XAcc/YAcc from delta vs previous BSM
  ├── IF attacker: FalsifyPosition_TypeN(...)
  └── appends BSMRecord to bsm_log[]

After Simulator::Run() returns
        │
        ▼
PostProcess()
  ├── group bsm_log by senderId
  ├── per sender:
  │     build M_i (n×7), centralize columns
  │     compute A = M_i^T × M_i  (7×7)
  │     Jacobi eigenvalue decomposition of A  → λ₁…λ₇ (sorted descending)
  │     write row to npfads_eigenvalues.csv
  └── ComputeMetrics() → npfads_metrics.csv
```

---

## Section 1 — Includes and Namespace

```cpp
// NS-3 core + mobility only (no WAVE radio needed — BSMs are generated directly)
#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/random-variable-stream.h"
#include <fstream>  <vector>  <map>  <cmath>  <algorithm>  <numeric>
#include <iomanip>  <sstream>  <string>
using namespace ns3;
```

No DSRC radio stack is needed: BSMs are logged as data records, not over-the-air packets. This matches the paper's offline preprocessing pipeline.

---

## Section 2 — Constants

```cpp
// Attack type IDs (match VeReMi ground-truth labels)
static const int BENIGN   = 0;
static const int TYPE_1   = 1;   // Constant position
static const int TYPE_2   = 2;   // Constant offset
static const int TYPE_4   = 4;   // Random position
static const int TYPE_8   = 8;   // Random offset
static const int TYPE_16  = 16;  // Eventual stop

// Playground bounds (VeReMi defaults)
static const double X_MIN = 0.0,    X_MAX = 10000.0;
static const double Y_MIN = 0.0,    Y_MAX = 10000.0;

// Type 1 fixed position
static const double TYPE1_XPOS = 5560.0, TYPE1_YPOS = 5820.0;

// Type 2 constant offset
static const double TYPE2_DX = 250.0,  TYPE2_DY = -150.0;

// Type 8 random offset bound
static const double TYPE8_BOUND = 300.0;

// Type 16 stop probability increment per update
static const double TYPE16_PROB_INCREMENT = 0.025;
```

---

## Section 3 — Data Structures

```cpp
struct BSMRecord {
    double   sendTime;
    uint32_t senderId;
    double   xPos, yPos;        // FALSIFIED (what receiver sees)
    double   xSpd, ySpd;        // true velocity
    double   xAcc, yAcc;        // derived from delta speed / delta time
    int      attackType;         // ground truth: BENIGN / TYPE_N
    double   trueXPos, trueYPos; // for ground truth logging
};

struct AttackerState {           // per-node, used by Type 16 only
    double stopProb   = 0.0;
    double frozenXPos = 0.0;
    double frozenYPos = 0.0;
};
```

Globals:
```cpp
std::vector<BSMRecord>                   g_bsmLog;
std::map<uint32_t, BSMRecord>            g_lastBSM;      // previous BSM per sender (for acceleration)
std::map<uint32_t, AttackerState>        g_attackerState;
std::map<uint32_t, int>                  g_nodeAttackType; // 0=benign, else TYPE_N
Ptr<UniformRandomVariable>               g_rng;
```

---

## Section 4 — Command-line Parameters

Parsed with `CommandLine` in `main()`:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `--simTime` | 120.0 | Simulation duration (s) |
| `--N_Vehicles` | 20 | Total vehicle count |
| `--N_Attackers` | 4 | Attacker count (first N_Attackers nodes) |
| `--attack_type` | 1 | Attack type for ALL attackers (0=benign, 1,2,4,8,16,31=all-mixed) |
| `--beacon_interval` | 0.1 | BSM generation period (s) |
| `--seed` | 42 | Random seed |
| `--output_dir` | "." | Directory for output CSV files |

When `attack_type=31`: attackers are assigned attack types round-robin (Type 1, 2, 4, 8, 16, 1, 2, …).

---

## Section 5 — Position Falsification Functions

```cpp
// Returns falsified position vector
Vector FalsifyPosition(uint32_t nodeId, int attackType, Vector truePos);
```

Logic per type:
- **Type 1**: return Vector(5560.0, 5820.0, truePos.z)
- **Type 2**: return Vector(truePos.x + 250.0, truePos.y - 150.0, truePos.z)
- **Type 4**: return Vector(g_rng->GetValue(X_MIN, X_MAX), g_rng->GetValue(Y_MIN, Y_MAX), truePos.z)
- **Type 8**: return Vector(truePos.x + g_rng->GetValue(-300,300), truePos.y + g_rng->GetValue(-300,300), truePos.z)
- **Type 16**: use/update `g_attackerState[nodeId].stopProb`:
  - draw r ~ Uniform(0,1)
  - if r < stopProb: return frozen position; else: update frozen position to truePos, return truePos
  - always increment stopProb += 0.025 after update

---

## Section 6 — BSM Generation Callback

```cpp
void GenerateBSM(uint32_t nodeId, NodeContainer* nodes, double beaconInterval);
```

Steps:
1. Get `Ptr<Node> n = nodes->Get(nodeId)` and `Ptr<MobilityModel> mob = n->GetObject<MobilityModel>()`
2. Read `truePos = mob->GetPosition()`, `vel = mob->GetVelocity()`
3. Compute acceleration from delta(velocity) / delta(time) vs `g_lastBSM[nodeId]`; zero on first call
4. Determine `attackType = g_nodeAttackType[nodeId]`
5. `falsifiedPos = FalsifyPosition(nodeId, attackType, truePos)` (returns truePos if benign)
6. Construct `BSMRecord r = {now, nodeId, falsifiedPos.x, falsifiedPos.y, vel.x, vel.y, accX, accY, attackType, truePos.x, truePos.y}`
7. `g_bsmLog.push_back(r); g_lastBSM[nodeId] = r`
8. `Simulator::Schedule(Seconds(beaconInterval), &GenerateBSM, nodeId, nodes, beaconInterval)` (reschedule self)

---

## Section 7 — Matrix Utilities (for eigenvalue computation)

```cpp
// 7×7 matrix operations
using Mat7 = std::array<std::array<double,7>,7>;

// Transpose multiply: A = M^T × M  (M is n×7)
Mat7 TransposeMultiply(const std::vector<std::array<double,7>>& M);

// Center columns: subtract column mean from each element
void CenterColumns(std::vector<std::array<double,7>>& M);

// Jacobi eigenvalue decomposition of symmetric 7×7 matrix
// Returns eigenvalues in descending order
std::array<double,7> JacobiEigenvalues(Mat7 A, int maxIter = 1000, double tol = 1e-10);
```

Jacobi algorithm: iteratively zero off-diagonal elements via Givens rotations on the 7×7 `A` matrix until convergence. Extract diagonal as eigenvalues. This is well-established and accurate for small symmetric matrices.

---

## Section 8 — Post-processing

```cpp
void PostProcess(double simTime, const std::string& outputDir);
```

Sub-steps:

### 8a — Group BSMs by sender
```cpp
std::map<uint32_t, std::vector<BSMRecord>> bySender;
for (auto& r : g_bsmLog) bySender[r.senderId].push_back(r);
```

### 8b — Write npfads_bsm_log.csv
Header: `sendTime,senderId,xPos,yPos,xSpd,ySpd,xAcc,yAcc,attackType,trueXPos,trueYPos`  
One row per BSMRecord. Written during simulation (flush at end) OR after `Simulator::Run()`.

### 8c — Build mobility matrix and compute eigenvalues per sender
For each senderId with ≥ 8 BSMs (minimum for meaningful matrix):
1. Build `std::vector<array<double,7>> M` — each row = `{sendTime, xPos, yPos, xSpd, ySpd, xAcc, yAcc}`
2. `CenterColumns(M)`
3. `Mat7 A = TransposeMultiply(M)` (7×7)
4. `auto eigs = JacobiEigenvalues(A)` (sorted descending)
5. Determine ground truth label: any BSM from this sender has `attackType != BENIGN`?

### 8d — Write npfads_eigenvalues.csv
Header: `senderId,lambda1,lambda2,lambda3,lambda4,lambda5,lambda6,lambda7,attackType,n_bsms`

### 8e — Simple anomaly classifier and metrics per attack type
Anomaly score: `score = eigs[0] / (sum(eigs) + 1e-12)` — ratio of dominant eigenvalue. Higher score = more anomalous (Type 1/4/8/16 have near-zero position variance → very high first eigenvalue ratio; Type 2 is hardest).

Threshold is set per-run as the midpoint between mean-benign-score and mean-attack-score (since this is simulation, not deployed system — we just demonstrate separability).

For each unique attackType present:
- TP = attack senders above threshold
- FN = attack senders below threshold
- FP = benign senders above threshold
- TN = benign senders below threshold
- Compute precision, recall, F1

### 8f — Write npfads_metrics.csv
Header: `attack_type,n_attackers,n_benign,TP,FP,FN,TN,precision,recall,f1,threshold`

---

## Section 9 — main()

```cpp
int main(int argc, char* argv[]) {
    // 1. Parse CommandLine
    // 2. SeedManager::SetSeed(seed)
    // 3. g_rng = CreateObject<UniformRandomVariable>()
    // 4. nodes.Create(N_Vehicles)
    // 5. MobilityHelper: RandomWaypointMobilityModel in [X_MIN..X_MAX] × [Y_MIN..Y_MAX]
    //    speed = Uniform(10, 30) m/s,  pause = 0
    // 6. Assign attack types: nodes 0..N_Attackers-1 get attack_type (or round-robin if =31)
    // 7. Schedule GenerateBSM for each node at t=beacon_interval, 2*beacon_interval, ... up to simTime
    //    (use a loop: for t in range(beacon_interval, simTime-beacon_interval, beacon_interval))
    //    OR let GenerateBSM reschedule itself (self-rescheduling approach)
    // 8. Simulator::Run()
    // 9. Simulator::Destroy()
    // 10. PostProcess(simTime, outputDir)
    // 11. return 0
}
```

---

## Section 10 — Output Files

| File | When written | Contents |
|------|-------------|---------|
| `npfads_bsm_log.csv` | After simulation | All BSMs: sendTime, senderId, falsified pos, vel, acc, type, true pos |
| `npfads_eigenvalues.csv` | Post-processing | Per-sender: 7 eigenvalues + attackType + n_bsms |
| `npfads_metrics.csv` | Post-processing | Per attack type: precision, recall, F1, threshold, confusion matrix |

---

## Section 11 — Build and Run Commands

```bash
cp npfads_attacks.cc ~/ns-3.35/scratch/npfads_attacks.cc
cd ~/ns-3.35
./waf build 2>&1 | grep -E "error:|warning:"

# Run single attack type
./waf --run "scratch/npfads_attacks --simTime=120 --N_Vehicles=20 --N_Attackers=4 --attack_type=1"

# Run all attack types in one simulation
./waf --run "scratch/npfads_attacks --simTime=120 --N_Vehicles=25 --N_Attackers=10 --attack_type=31"

# Run with longer window for better eigenvalue quality
./waf --run "scratch/npfads_attacks --simTime=300 --N_Vehicles=20 --N_Attackers=4 --attack_type=2"

# Baseline (benign only)
./waf --run "scratch/npfads_attacks --simTime=120 --N_Vehicles=20 --N_Attackers=0 --attack_type=0"
```

---

## Section 12 — Verification Checklist

1. **Compile clean**: `./waf build` — zero errors
2. **BSM log sanity**: `cat npfads_bsm_log.csv | head -5` — check Type 1 attackers always show xPos=5560, yPos=5820
3. **Type 2 check**: attacker rows show xPos = trueXPos + 250 (within rounding)
4. **Type 4 check**: positions are outside any fixed range (uncorrelated with trueXPos)
5. **Type 16 check**: early rows show true position; later rows show frozen position more often
6. **Eigenvalue file**: `cat npfads_eigenvalues.csv` — benign senders should have more spread eigenvalues; Type 1 attackers should have near-zero λ₂…λ₇ (position columns are constant → near-zero variance)
7. **Metrics**: Type 4, 8, 1 should show F1 > 0.90; Type 2 should show F1 < other types (matches paper finding)
8. **n_bsms column**: should be approximately `simTime / beacon_interval` (±1) per sender

---

## Notes

- The Jacobi 7×7 implementation is ~80 lines; the entire file is ~550–650 lines
- No external libraries needed beyond NS-3 core + mobility
- This is intentionally independent of `routing.cc` — different threat model, different paper
- The simple anomaly classifier is only for demonstrating separability; the full NPFADS detector (Random Forest + AutoEncoder) would be trained in Python on the `npfads_eigenvalues.csv` output
