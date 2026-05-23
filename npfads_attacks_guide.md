# npfads_attacks.cc — Implementation Guide

> **Based on:** *"A misbehavior detection system to detect novel position falsification attacks in the Internet of Vehicles"*
> Ilango, Ma & Su (2022), *Engineering Applications of Artificial Intelligence 116, 105380*
>
> **File:** `npfads_attacks.cc` — standalone NS-3.35 scratch simulation
> **Purpose:** Simulate all five VeReMi position falsification attack variants over a real 802.11p DSRC radio channel, log ground-truth feature vectors, compute per-sender mobility matrix eigenvalues, and evaluate detection performance (precision / recall / F1).

---

## Table of Contents

1. [What This Simulation Does](#1-what-this-simulation-does)
2. [Attack Model — Insider Position Falsification](#2-attack-model--insider-position-falsification)
3. [The Five Attack Types](#3-the-five-attack-types)
   - 3.1 Type 1 — Constant Position Attack
   - 3.2 Type 2 — Constant Offset Attack
   - 3.3 Type 4 — Random Position Attack
   - 3.4 Type 8 — Random Offset Attack
   - 3.5 Type 16 — Eventual Stop Attack
4. [NS-3 Architecture](#4-ns-3-architecture)
   - 4.1 NPFADSBSMTag — the DSRC packet
   - 4.2 GenerateBSM — sender side
   - 4.3 OnBSMReceived — receiver side
   - 4.4 Data flow end to end
5. [Preprocessing Pipeline — Mobility Matrix Eigenvalues](#5-preprocessing-pipeline--mobility-matrix-eigenvalues)
6. [Anomaly Scoring and Detection Metrics](#6-anomaly-scoring-and-detection-metrics)
7. [Build and Run](#7-build-and-run)
8. [Output Files](#8-output-files)
9. [Verification Checklist](#9-verification-checklist)
10. [Known Limitations and Notes](#10-known-limitations-and-notes)

---

## 1. What This Simulation Does

In a real Internet of Vehicles (IoV) network, every vehicle broadcasts a **Basic Safety Message (BSM)** every 100 ms over DSRC/802.11p. A BSM contains the vehicle's claimed position, speed, and acceleration. A **misbehaving insider vehicle** can falsify the position field of its own BSM while the underlying mobility model continues to move the vehicle normally. Neighboring vehicles and infrastructure units receive the falsified BSM and may make incorrect routing or safety decisions.

This simulation:

1. Creates `N_Vehicles` vehicle nodes with realistic random waypoint mobility.
2. Designates the first `N_Attackers` nodes as misbehaving insiders — each assigned one of the five VeReMi attack types.
3. Every 100 ms each node broadcasts a BSM over a real 802.11p radio channel. Attackers send a falsified position; their true mobility is unaffected.
4. Receiver nodes log every received BSM through an NS-3 `Rx` callback.
5. After the simulation, per-sender mobility matrices are built from the logged feature vectors and decomposed into eigenvalues.
6. A simple anomaly detector scores each sender and computes precision, recall, and F1 per attack type.

---

## 2. Attack Model — Insider Position Falsification

### What is an insider attacker?

Unlike an external jammer or eavesdropper, an **insider attacker** is a legitimately registered vehicle that holds a valid certificate. It participates normally in the network but falsifies one or more fields of its BSM. Because the certificate is valid, cryptographic authentication alone cannot detect the attack — the signature is correct, but the content is false.

### What is falsified?

Only the **position field** (`xPos`, `yPos`) is falsified. The paper specifies:

- Velocity (`xSpd`, `ySpd`) is always reported truthfully.
- Acceleration is derived by receivers from consecutive velocity observations — it is not transmitted.
- The vehicle continues to move normally according to its mobility model; only what it _reports_ changes.

### Why position falsification matters

The controller and neighboring vehicles use reported positions to:
- Build topology maps and routing tables.
- Estimate relative positions for collision avoidance.
- Decide which RSU or base station to associate with.

A falsified position can poison all three, creating phantom routes, false proximity alerts, or incorrect handover decisions.

### Attacker node assignment

Nodes `0` through `N_Attackers - 1` are attackers. All remaining nodes are benign. The attack type is uniform across all attackers (or round-robin when `--attack_type=31`).

```
Node IDs:   0   1   2   3   |   4   5   6  ...  N-1
Role:    ATK ATK ATK ATK  |  Benign Benign ...
```

---

## 3. The Five Attack Types

### 3.1 Type 1 — Constant Position Attack

**Paper name:** Constant Attack

**Concept:** The attacker always broadcasts the same fixed coordinates regardless of where it actually is. Its reported position never changes — it appears frozen at a single point on the map.

**Fixed coordinates used (from VeReMi dataset defaults):**
```
xPos = 5560.0 m
yPos = 5820.0 m
```

**Why it is detectable:** After column centering, the xPos and yPos columns in the mobility matrix have zero variance. The corresponding diagonal entries of `A = M^T × M` are zero, making the eigenvalue contribution of the position columns negligible. The anomaly score (deviation from benign position variance) is very high.

**Implementation steps in `FalsifyPosition`:**
1. Receive `truePos` from the vehicle's `MobilityModel`.
2. Ignore `truePos.x` and `truePos.y` entirely.
3. Return `Vector(5560.0, 5820.0, truePos.z)`.

**What to expect in `npfads_bsm_log.csv`:**
- Every row with `attackType=1` has `xPos=5560.000000` and `yPos=5820.000000`.
- `trueXPos` and `trueYPos` change every row — the vehicle is physically moving.

---

### 3.2 Type 2 — Constant Offset Attack

**Paper name:** Constant Offset Attack

**Concept:** The attacker adds a fixed constant offset to its true position every beacon. The reported trajectory looks exactly like the real trajectory — same shape, same speed — just shifted by a constant vector. This is the **hardest attack to detect** because the pattern of movement is preserved.

**Offset used:**
```
Δx = +250.0 m
Δy = −150.0 m
```

**Why it is hard to detect:** When column centering is applied to the mobility matrix, the column mean of xPos absorbs the constant offset. After centering, the xPos and yPos columns of an attacker look statistically identical to those of a benign vehicle — only the mean differs, and the mean is removed by centering. The anomaly score for Type 2 is expected to be near zero.

**Implementation steps in `FalsifyPosition`:**
1. Receive `truePos` from the vehicle's `MobilityModel`.
2. Return `Vector(truePos.x + 250.0, truePos.y - 150.0, truePos.z)`.

**What to expect in `npfads_bsm_log.csv`:**
- Every row with `attackType=2` satisfies `xPos - trueXPos ≈ 250.0` and `yPos - trueYPos ≈ -150.0`.
- The offset is exactly constant — no random component.

---

### 3.3 Type 4 — Random Position Attack

**Paper name:** Random Attack

**Concept:** The attacker broadcasts a completely random position sampled uniformly across the entire playground on every beacon cycle. Each BSM reports a different, uncorrelated position with no relationship to the vehicle's true location or previous reports.

**Position bounds (VeReMi playground defaults):**
```
xPos ~ Uniform(0, 10000) m
yPos ~ Uniform(0, 10000) m
```

**Why it is detectable:** The position columns in the mobility matrix have enormous variance — far larger than any physically mobile vehicle could produce. The diagonal entries `A[1][1]` and `A[2][2]` are inflated by orders of magnitude, producing a very high anomaly score.

**Implementation steps in `FalsifyPosition`:**
1. Draw `rx ~ Uniform(0, 10000)` from the NS-3 `UniformRandomVariable`.
2. Draw `ry ~ Uniform(0, 10000)` independently.
3. Return `Vector(rx, ry, truePos.z)`.

**What to expect in `npfads_bsm_log.csv`:**
- Rows with `attackType=4` show `xPos` and `yPos` values scattered across [0, 10000] with no correlation to `trueXPos` / `trueYPos`.

---

### 3.4 Type 8 — Random Offset Attack

**Paper name:** Random Offset Attack

**Concept:** The attacker adds a different random offset on every beacon. Unlike Type 4, the falsified position stays in the neighbourhood of the true position (within ±300 m), so it looks slightly more plausible. However the jitter per beacon is far larger than legitimate position noise.

**Offset bound:**
```
Δx ~ Uniform(−300, +300) m   (independent each beacon)
Δy ~ Uniform(−300, +300) m
```

**Why it is detectable:** The per-beacon random offset introduces variance in xPos and yPos that is larger than what a moving vehicle naturally produces. The anomaly score is elevated compared to benign nodes, though less extreme than Type 4.

**Implementation steps in `FalsifyPosition`:**
1. Draw `dx ~ Uniform(-300, +300)`.
2. Draw `dy ~ Uniform(-300, +300)` independently.
3. Return `Vector(truePos.x + dx, truePos.y + dy, truePos.z)`.

**What to expect in `npfads_bsm_log.csv`:**
- For rows with `attackType=8`: `|xPos - trueXPos| <= 300` and `|yPos - trueYPos| <= 300` always.
- The offset is different on each row (random, not constant like Type 2).

---

### 3.5 Type 16 — Eventual Stop Attack

**Paper name:** Eventual Stop Attack

**Concept:** The attacker starts by broadcasting its true position normally. Over time, a "stop probability" (`stopProb`) increases by `+0.025` after every beacon. Once triggered, the attacker freezes its reported position at the last seen location — it appears to stop moving even as the vehicle continues to drive away. The longer the attack runs, the more likely the freeze is sustained.

**Parameters:**
```
stopProb starts at 0.0
stopProb += 0.025 after every BSM  (capped at 1.0)
After 40 BSMs (= 4 seconds at 100 ms interval): stopProb = 1.0 (always frozen)
```

**Attack state machine per attacker node:**

```
Beacon N:   draw r ~ Uniform(0, 1)
            if r < stopProb  →  broadcast frozenPos  (attack active)
            else             →  update frozenPos = truePos, broadcast truePos
            stopProb += 0.025
```

**Why it is detectable:** In the later portion of the simulation, the attacker's reported position becomes constant while its true position continues to change. The xPos and yPos columns in the mobility matrix flatten out, reducing their variance toward zero — similar to Type 1 but only in the tail of the time window.

**Implementation steps in `FalsifyPosition`:**
1. On first call for this node: initialise `frozenXPos = truePos.x`, `frozenYPos = truePos.y`, `stopProb = 0.0`.
2. Draw `r ~ Uniform(0, 1)`.
3. If `r < stopProb`: return `Vector(frozenXPos, frozenYPos, truePos.z)` — position is frozen.
4. Else: update `frozenXPos = truePos.x`, `frozenYPos = truePos.y`, return `truePos` — position advances.
5. Unconditionally: `stopProb = min(stopProb + 0.025, 1.0)`.

**What to expect in `npfads_bsm_log.csv`:**
- Early rows with `attackType=16`: `xPos ≈ trueXPos`, `yPos ≈ trueYPos` (not yet frozen).
- Later rows: `xPos` and `yPos` stay constant across many rows while `trueXPos`, `trueYPos` keep changing.
- The fraction of frozen rows grows monotonically with time: ~50% overall in a 60 s run, approaching 100% after t ≈ 4 s per attacker.

---

## 4. NS-3 Architecture

This simulation uses real NS-3 802.11p radio — packets physically travel over a simulated DSRC channel and are received by nodes within 300 m range via a registered `Rx` callback. There is no shortcut logging at the sender.

### 4.1 NPFADSBSMTag — the DSRC packet

`NPFADSBSMTag` is an NS-3 `Tag` subclass (48 bytes serialized) that models a Basic Safety Message travelling over the 802.11p air interface.

| Field | Type | Description |
|---|---|---|
| `m_nodeId` | `uint32_t` | Sender's node ID |
| `m_sendTime` | `double` | Simulation time at transmission |
| `m_xPos` | `double` | **Reported** (possibly falsified) x position |
| `m_yPos` | `double` | **Reported** (possibly falsified) y position |
| `m_xSpd` | `double` | True x velocity (never falsified) |
| `m_ySpd` | `double` | True y velocity (never falsified) |
| `m_attackType` | `uint32_t` | Ground-truth label (simulation-only; 0 = benign) |

**Note:** Acceleration is NOT in the tag. It is derived by each receiver from consecutive velocity observations. This matches what a real detector would do.

**Serialized layout:**

```
[  nodeId 4B  ][ sendTime 8B ][ xPos 8B ][ yPos 8B ][ xSpd 8B ][ ySpd 8B ][ attackType 4B ]
                                                                          total = 48 bytes
```

---

### 4.2 GenerateBSM — sender side

`GenerateBSM(nodeId)` is a self-rescheduling NS-3 callback. It fires every `beacon_interval` seconds (default 100 ms) for each vehicle.

**Sender steps:**
```
1. Read truePos and vel from the node's MobilityModel.
2. Call FalsifyPosition(nodeId, attackType, truePos)
       → returns reportedPos (falsified for attackers, same as truePos for benign nodes)
3. Build NPFADSBSMTag:
       SetNodeId(nodeId)
       SetSendTime(now)
       SetPosition(reportedPos.x, reportedPos.y)   ← falsified
       SetVelocity(vel.x, vel.y)                   ← always true
       SetAttackType(attackType)                   ← ground-truth label
4. Attach tag to a zero-byte Ptr<Packet>.
5. Broadcast: wdev->Send(pkt, Mac48Address::GetBroadcast(), 0x88dc)
       (ethertype 0x88dc = WAVE Short Message Protocol)
6. Reschedule: Simulator::Schedule(Seconds(beacon_interval), &GenerateBSM, nodeId)
```

The sender does **not** write to `g_bsmLog`. All logging is done by the receiver.

---

### 4.3 OnBSMReceived — receiver side

`OnBSMReceived` is installed on every vehicle's DSRC net device via `SetReceiveCallback`. It fires whenever a node within 300 m range receives a broadcast packet.

**Receiver steps:**
```
1. PeekPacketTag<NPFADSBSMTag>(tag)  — returns false if not a BSM, drop silently.
2. Extract senderId and sendTime from tag.
3. Deduplication check: if (senderId, sendTime) already in g_loggedBSMs, return.
       Insert (senderId, sendTime) into g_loggedBSMs.
       → This ensures the same BSM logged by multiple receivers is counted only once.
4. Compute acceleration:
       dt   = sendTime − g_lastBSM[senderId].sendTime
       xAcc = (tag.GetXSpd() − g_lastBSM[senderId].xSpd) / dt
       yAcc = (tag.GetYSpd() − g_lastBSM[senderId].ySpd) / dt
       (zero on first BSM from this sender)
5. Look up sender's true position from its MobilityModel:
       mob = g_nodes.Get(senderId)->GetObject<MobilityModel>()
       truePos = mob->GetPosition()
       (simulation-only privilege — real detector cannot know this)
6. Build BSMRecord and append to g_bsmLog.
7. Update g_lastBSM[senderId] for next acceleration computation.
```

---

### 4.4 Data flow end to end

```
Every 100 ms per vehicle:

GenerateBSM(nodeId)
    │  reads MobilityModel (truePos, vel)
    │  calls FalsifyPosition → reportedPos
    │  builds NPFADSBSMTag
    │
    └──► wdev->Send()
              │
         802.11p DSRC radio (300 m range, OcbWifiMac, 33.5 dBm)
              │
         ◄─── OnBSMReceived fires on each node within range
                    │  deduplicates (senderId, sendTime)
                    │  derives xAcc, yAcc from velocity delta
                    │  fetches sender's true position
                    │
                    └──► g_bsmLog.push_back(BSMRecord)
                         g_lastBSM[senderId] = record

After Simulator::Run():

PostProcess()
    │  groups g_bsmLog by senderId
    │  per sender: build M (n×7), center columns, compute A = M^T×M
    │  JacobiEigenvalues(A) → λ₁…λ₇
    │  anomaly score = |log1p(posVar) − benign_mean_log1p(posVar)|
    │  F1-optimal threshold sweep per attack type
    │
    ├──► npfads_bsm_log.csv
    ├──► npfads_eigenvalues.csv
    └──► npfads_metrics.csv
```

---

## 5. Preprocessing Pipeline — Mobility Matrix Eigenvalues

This follows the paper's Section 3.2 preprocessing pipeline exactly.

### Step 1 — Build the mobility matrix M

For each sender that has at least 8 logged BSMs, build an `n × 7` matrix where row `k` is:

```
M[k] = [ sendTime,  xPos,  yPos,  xSpd,  ySpd,  xAcc,  yAcc ]
```

- `xPos`, `yPos` are the **reported** (possibly falsified) values.
- `xSpd`, `ySpd` are true velocity values from the tag.
- `xAcc`, `yAcc` are derived by the receiver: `Δvel / Δtime`.

### Step 2 — Column centering

Subtract the column mean from every entry:

```
M̄[k][c] = M[k][c] − mean_over_k(M[k][c])
```

**Key effect on Type 2 attacks:** The constant offset (+250, −150) is exactly the column mean of xPos and yPos. After centering, these columns look identical to a benign vehicle's columns — making Type 2 the hardest to detect, as noted in the paper.

### Step 3 — Compute A = M^T × M (7×7)

Instead of the paper's `M × M^T` (n×n, expensive), we compute `M^T × M` (7×7). The non-zero eigenvalues are identical by the relation between the two formulations. This reduces computation from O(n²) to O(49).

The diagonal entry `A[i][i]` is the sum of squares of column `i` after centering — it represents the **variance** of that feature across all BSMs from this sender.

Critical entries:
- `A[1][1]` = variance of xPos column
- `A[2][2]` = variance of yPos column
- `posVar = A[1][1] + A[2][2]` is computed before calling JacobiEigenvalues (which modifies A in place via Givens rotations).

### Step 4 — Jacobi eigenvalue decomposition

A symmetric 7×7 Jacobi iteration zeroes off-diagonal elements via successive Givens rotations until convergence. Returns eigenvalues `λ₁ ≥ λ₂ ≥ … ≥ λ₇` sorted descending.

Convergence uses a relative tolerance: `absTol = relTol × initOffNorm` so that large position values (on the order of 10,000 m) do not cause premature termination.

### Expected eigenvalue patterns by attack type

| Attack type | `posVar` relative to benign | Interpretation |
|---|---|---|
| Benign | Moderate (vehicle moves normally) | Baseline |
| Type 1 | ≈ 0 | Constant position → zero variance in position columns |
| Type 2 | ≈ benign | Offset removed by centering → indistinguishable |
| Type 4 | >> benign | Random positions → enormous variance |
| Type 8 | > benign | Bounded random → inflated but not extreme |
| Type 16 | → 0 over time | Frozen position → variance collapses in later window |

---

## 6. Anomaly Scoring and Detection Metrics

### Anomaly score

```
score(sender_i) = |log1p(posVar_i) − mean_benign_log1p(posVar)|
```

- `log1p` compresses the range and handles `posVar = 0` without −∞.
- The absolute value means **both** near-zero posVar (Types 1, 16) and huge posVar (Types 4, 8) score high.
- Benign senders score near 0 by construction.
- Type 2 scores near 0 — correctly reflecting the paper's finding.

### F1-optimal threshold

Rather than a fixed threshold, we sweep all unique score values and pick the threshold that maximises F1 for each attack type independently:

```
for each threshold t in sorted(scores):
    TP = attackers with score > t
    FP = benign with score > t
    FN = attackers with score ≤ t
    TN = benign with score ≤ t
    F1 = 2·TP / (2·TP + FP + FN)
pick t* = argmax F1
```

### Expected detection performance

| Type | Expected F1 | Reason |
|---|---|---|
| 1 | > 0.90 | posVar ≈ 0 is very distinct from benign |
| 2 | ~0.2–0.5 | posVar ≈ benign after centering — hardest |
| 4 | > 0.90 | Enormous posVar immediately distinguishable |
| 8 | > 0.80 | Bounded random still inflates posVar noticeably |
| 16 | > 0.80 | Frozen position reduces posVar significantly |

---

## 7. Build and Run

### Build

```bash
cp npfads_attacks.cc ~/ns-3.35/scratch/npfads_attacks.cc
cd ~/ns-3.35
./waf build 2>&1 | grep -E "error:|warning:"
```

### Run — single attack type

```bash
# Type 1: constant position
./waf --run "scratch/npfads_attacks --simTime=60 --N_Vehicles=20 --N_Attackers=4 --attack_type=1 --seed=1"

# Type 2: constant offset (hardest to detect)
./waf --run "scratch/npfads_attacks --simTime=60 --N_Vehicles=20 --N_Attackers=4 --attack_type=2 --seed=1"

# Type 4: fully random
./waf --run "scratch/npfads_attacks --simTime=60 --N_Vehicles=20 --N_Attackers=4 --attack_type=4 --seed=1"

# Type 8: bounded random offset
./waf --run "scratch/npfads_attacks --simTime=60 --N_Vehicles=20 --N_Attackers=4 --attack_type=8 --seed=1"

# Type 16: eventual stop
./waf --run "scratch/npfads_attacks --simTime=60 --N_Vehicles=20 --N_Attackers=4 --attack_type=16 --seed=1"
```

### Run — all types in one simulation (round-robin assignment)

```bash
./waf --run "scratch/npfads_attacks --simTime=120 --N_Vehicles=25 --N_Attackers=10 --attack_type=31 --seed=42"
```

`--attack_type=31` assigns types 1→2→4→8→16→1→… across attackers.

### Command-line parameters

| Parameter | Default | Meaning |
|---|---|---|
| `--simTime` | 120.0 | Simulation duration (seconds) |
| `--N_Vehicles` | 20 | Total vehicle count |
| `--N_Attackers` | 4 | Attacker count (nodes 0 to N−1) |
| `--attack_type` | 1 | Attack type: 0=benign, 1, 2, 4, 8, 16, 31=mixed |
| `--beacon_interval` | 0.1 | BSM interval in seconds |
| `--seed` | 42 | RNG seed for reproducibility |
| `--output_dir` | "." | Directory for CSV output files |

### NetAnim visualisation

`npfads-animation.xml` is written automatically. Open it in NetAnim:

```bash
cd ~/ns-3.35/netanim
./NetAnim
# File → Open → npfads-animation.xml
```

Node colours:
- **Red** = attacker (labelled `ATK-T1`, `ATK-T2`, etc.)
- **Blue** = benign vehicle (labelled `V0`, `V1`, etc.)

Packet animations show BSM broadcasts as they propagate within 300 m range.

---

## 8. Output Files

### `npfads_bsm_log.csv`

One row per received BSM. Written after `Simulator::Run()`.

| Column | Description |
|---|---|
| `sendTime` | Simulation time of transmission (s) |
| `senderId` | NS-3 node ID of the sender |
| `xPos` | Reported x position — **falsified** for attackers |
| `yPos` | Reported y position — **falsified** for attackers |
| `xSpd` | True x velocity |
| `ySpd` | True y velocity |
| `xAcc` | Derived x acceleration (ΔV/Δt at receiver) |
| `yAcc` | Derived y acceleration |
| `attackType` | Ground-truth label: 0=benign, 1/2/4/8/16 |
| `trueXPos` | Actual x position from MobilityModel |
| `trueYPos` | Actual y position from MobilityModel |

### `npfads_eigenvalues.csv`

One row per sender with at least 8 BSMs.

| Column | Description |
|---|---|
| `senderId` | NS-3 node ID |
| `lambda1`…`lambda7` | Eigenvalues of M^T×M, sorted descending |
| `attackType` | Ground-truth label |
| `n_bsms` | Number of BSMs used to build the matrix |

### `npfads_metrics.csv`

One row per attack type present in the run.

| Column | Description |
|---|---|
| `attack_type` | 1 / 2 / 4 / 8 / 16 |
| `n_attackers` | Number of attacker senders in the analysis |
| `n_benign` | Number of benign senders in the analysis |
| `TP, FP, FN, TN` | Confusion matrix at optimal threshold |
| `precision` | TP / (TP + FP) |
| `recall` | TP / (TP + FN) |
| `f1` | 2 × precision × recall / (precision + recall) |
| `opt_threshold` | Anomaly score threshold that maximised F1 |

### `npfads-animation.xml`

NetAnim trace file. Shows node positions, movement, and DSRC packet propagation over time.

---

## 9. Verification Checklist

After each run, verify the following using the BSM log.

### Check 1 — Attackers appear in the log

```bash
awk -F',' 'NR>1 && $9!=0 { types[$9]++ }
END { for(t in types) print "attackType=" t " rows=" types[t] }' npfads_bsm_log.csv
```

If all counts are 0, no attacker BSMs were received — the network is too sparse (see Section 10).

### Check 2 — Type 1 position is always exactly (5560, 5820)

```bash
awk -F',' 'NR>1 && $9==1 {
    if ($3 != 5560.000000 || $4 != 5820.000000)
        print "FAIL row " NR ": xPos=" $3 " yPos=" $4
    else ok++
} END { print "Type1 ok=" ok " rows" }' npfads_bsm_log.csv
```

Expected: zero FAIL lines.

### Check 3 — Type 2 offset is exactly +250 / −150 every row

```bash
awk -F',' 'NR>1 && $9==2 {
    dx = $3 - $10;  dy = $4 - $11
    if (dx < 249.9 || dx > 250.1 || dy < -150.1 || dy > -149.9)
        print "FAIL row " NR ": dx=" dx " dy=" dy
    else ok++
} END { print "Type2 ok=" ok " rows" }' npfads_bsm_log.csv
```

Expected: zero FAIL lines.

### Check 4 — Type 8 offset is within ±300 m every row

```bash
awk -F',' 'NR>1 && $9==8 {
    dx = $3 - $10;  dy = $4 - $11
    if (dx < -300.1 || dx > 300.1 || dy < -300.1 || dy > 300.1)
        print "FAIL row " NR ": dx=" dx " dy=" dy
    else ok++
} END { print "Type8 ok=" ok " rows" }' npfads_bsm_log.csv
```

Expected: zero FAIL lines.

### Check 5 — Type 16 shows increasing freeze rate over time

```bash
awk -F',' 'NR>1 && $9==16 {
    frozen = (($3-$10)^2 + ($4-$11)^2 > 1) ? 1 : 0
    total++; if(frozen) nfrozen++
} END { print "Type16: total=" total " frozen=" nfrozen " (" int(100*nfrozen/total) "%)" }' \
npfads_bsm_log.csv
```

Expected: frozen percentage > 0 and increases as `simTime` increases. In a 60 s run, expect ~40–60 % frozen overall.

### Check 6 — Eigenvalue patterns match expected

```bash
# Average lambda1 for benign vs attackers
awk -F',' 'NR>1 { if($10==0) {sb+=$2;nb++} else {sa+=$2;na++} }
END { print "Benign avg λ1=" sb/nb "\nAttacker avg λ1=" sa/na }' \
npfads_eigenvalues.csv
```

Expected: attackers (Types 1, 4, 8, 16) have `avg λ1` noticeably different from benign. Type 2 attackers will have `avg λ1` similar to benign.

### Check 7 — Detection metrics are plausible

```bash
cat npfads_metrics.csv
```

Expected F1 values:

| Type | Expected F1 range |
|---|---|
| 1 | > 0.90 |
| 2 | 0.20 – 0.60 |
| 4 | > 0.90 |
| 8 | > 0.80 |
| 16 | > 0.80 |

---

## 10. Known Limitations and Notes

### Sparse network — BSMs not received

The playground is 10,000 m × 10,000 m and the DSRC range is 300 m. With the default 20 vehicles, average node density is 0.0002 nodes/m², meaning vehicles are frequently out of range of each other.

**Symptom:** All attacker rows in `npfads_bsm_log.csv` are missing, or `n_bsms` in the eigenvalue file is below `MIN_BSMS = 8`.

**Fix:** Increase vehicle density for testing:

```bash
./waf --run "scratch/npfads_attacks --simTime=120 --N_Vehicles=50 --N_Attackers=10 --attack_type=31"
```

Or reduce playground bounds by changing `X_MAX` and `Y_MAX` constants in the source from `10000.0` to `2000.0`.

### Type 2 has intentionally low F1

This is the expected result per the paper. Column centering removes the constant offset, making Type 2 statistically identical to benign after preprocessing. A real-world detector would need additional features (e.g., cross-vehicle consistency checks) to detect Type 2.

### `m_attackType` in the tag is a simulation-only field

In a deployed system, an attacker would never include its attack label in the BSM. The field is present in `NPFADSBSMTag` solely for CSV ground-truth labelling. It does not affect any detection logic — the anomaly scorer uses only eigenvalues derived from the position/velocity/acceleration columns.

### Acceleration is derived, not transmitted

The acceleration columns in `BSMRecord` (`xAcc`, `yAcc`) are computed at the receiver from consecutive velocity observations. The first BSM from any sender always has `xAcc = yAcc = 0` because there is no previous observation to delta against.

### Round-robin assignment with `attack_type=31`

When `--attack_type=31`, attacker nodes are assigned types in order: `1, 2, 4, 8, 16, 1, 2, 4, 8, 16, …`. This means with `N_Attackers=5` you get exactly one attacker of each type, which is useful for comparing all five types in a single simulation run.

---

*Guide covers `npfads_attacks.cc` as of 2026-05-23 — Department of EIE, University of Ruhuna*
