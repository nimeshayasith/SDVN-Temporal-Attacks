# IoV Position Falsification Attack — Complete Implementation Plan

> **Based on:** *"A misbehavior detection system to detect novel position falsification attacks in the Internet of Vehicles"* — Ilango, Ma & Su (2022), *Engineering Applications of Artificial Intelligence 116 (2022) 105380*

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Communication Layers — How They Work](#2-communication-layers)
   - 2.1 Vehicle-to-Vehicle (V2V)
   - 2.2 Vehicle-to-RSU (V2I)
   - 2.3 RSU to Fog Node / Controller
   - 2.4 Fog Node to Cloud Server
3. [Data Structures — Basic Safety Message (BSM)](#3-data-structures--basic-safety-message-bsm)
4. [Position Falsification Attack Types](#4-position-falsification-attack-types)
5. [Step-by-Step Attack Implementation](#5-step-by-step-attack-implementation)
   - 5.1 Type 1 — Constant Attack
   - 5.2 Type 2 — Constant Offset Attack
   - 5.3 Type 4 — Random Attack
   - 5.4 Type 8 — Random Offset Attack
   - 5.5 Type 16 — Eventual Stop Attack
6. [Dataset — VeReMi Pre-processing Pipeline](#6-dataset--veremi-pre-processing-pipeline)
7. [Detection Mechanism — NPFADS](#7-detection-mechanism--npfads)
   - 7.1 MDS (Misbehavior Detection System)
   - 7.2 NADM (Novel Attack Detection Module)
   - 7.3 AutoEncoder (AE)
   - 7.4 Random Forest (RF)
   - 7.5 Threshold Setting — Hypotheses H1, H2, H3
8. [End-to-End Detection Flow — Step by Step](#8-end-to-end-detection-flow--step-by-step)
9. [Performance Metrics](#9-performance-metrics)
10. [Implementation Checklist](#10-implementation-checklist)

---

## 1. System Architecture Overview

The Internet of Vehicles (IoV) system in this paper consists of **four tiers**:

```
[ Vehicles with OBU ]
        |  DSRC (up to 1 km)
        v
[ Road Side Units / RSU (gNodeB) ]
        |  5G (FR1: 410 MHz–7125 MHz, up to 30 km)
        v
[ Fog Node (AMF + Fog Server) ]
        |  5G Core / Backhaul
        v
[ Cloud Server ]
```

| Component | Role |
|---|---|
| **OBU** (OnBoard Unit) | Installed in every vehicle; runs local MDS; holds OBU-BSMD |
| **RSU** (Road Side Unit) | Implemented as gNodeBs; relays BSMs to fog nodes |
| **Fog Node** | Runs MDS + NADM over aggregated BSMs every 100 s; holds FN-BSMD + MVD |
| **Cloud Server** | Retrains MDS and NADM when novel attacks are discovered; distributes updates |
| **CA** (Certificate Authority) | Registers vehicles and issues credentials |

---

## 2. Communication Layers

### 2.1 Vehicle-to-Vehicle (V2V) Communication

**Protocol:** DSRC (Dedicated Short-Range Communications)  
**Data Rate:** 6 Mbps  
**Range:** Up to 1,000 m  
**Message Type:** Basic Safety Message (BSM)  
**Frequency:** Several times per second (periodic broadcast)

#### Step-by-Step V2V Flow

```
Step 1 — Registration
  Vehicle registers with the Certificate Authority (CA).
  CA issues digital credentials (public/private key pair).

Step 2 — Network Join
  Vehicle joins the IoV network using CA-issued credentials.
  OBU initialises two local databases:
    - OBU-BSMD  : stores BSMs received from nearby vehicles
    - Local MVD  : copy of the Misbehaving Vehicles Database

Step 3 — BSM Construction (Sender)
  OBU reads from onboard sensors:
    - GPS position  → XPos, YPos, ZPos
    - Speedometer   → XSpd, YSpd, ZSpd
    - Accelerometer → XAcc, YAcc (derived)
  OBU constructs BSM fields:
    { SendTime, XPos, YPos, XSpd, YSpd, XAcc, YAcc, RSSI }
  OBU digitally signs the BSM using its private key.

Step 4 — BSM Broadcast (Sender)
  Signed BSM is broadcast over DSRC to all vehicles within 1 km radius.
  Broadcast occurs multiple times per second.

Step 5 — BSM Reception (Receiver OBU)
  Receiving OBU gets the BSM.
  
  ── Entity-Centric Check ──────────────────────────────────────
  OBU checks its local MVD:
    IF sender is blacklisted → DISCARD BSM immediately. Stop.
    IF sender is NOT blacklisted → proceed.
  ─────────────────────────────────────────────────────────────

  BSM is added to OBU-BSMD.

  ── Data-Centric Check (MDS at OBU) ──────────────────────────
  OBU runs MDS (Random Forest) on the mobility matrix built
  from OBU-BSMD for this sender.
    IF MDS flags sender as misbehaving → DISCARD BSM.
    IF MDS clears sender → ACCEPT BSM.
  (Data-centric decision always overrules entity-centric.)
  ─────────────────────────────────────────────────────────────

Step 6 — MVD & MDS Update
  If fog node pushes an updated MVD or MDS to the vehicle via RSU,
  the OBU downloads and replaces its local copies immediately.

Step 7 — Database Expiry
  If no BSM is received from a vehicle for 100 s,
  its records are deleted from OBU-BSMD
  (assumption: sender is out of DSRC range).
```

---

### 2.2 Vehicle-to-RSU (V2I) Communication

**Protocol:** 5G FR1 bands (410 MHz – 7125 MHz)  
**Coverage:** 2 km – 30 km per RSU (gNodeB)  
**Downlink Data Rate:** Up to 1,400 Mbps  

#### Step-by-Step V2I Flow

```
Step 1 — Uplink (Vehicle → RSU)
  Every BSM broadcast by a vehicle is also received by the
  nearest RSU (gNodeB) in range.
  
  The RSU does NOT perform any detection itself.
  Its sole role is to relay the BSM upward to the fog node.

Step 2 — Relay (RSU → Fog Node)
  RSU immediately forwards every received BSM to the
  associated fog node over the 5G core network.
  The fog node adds the BSM to FN-BSMD.

Step 3 — Downlink (RSU → Vehicle)
  RSU acts as a downlink bridge for:
    - Updated MVD     (new blacklisted vehicles)
    - Updated MDS     (retrained model weights)
    - Updated NADM    (retrained novel attack detector)
  
  These updates originate from the fog node or cloud server
  and are pushed through the RSU to all vehicles in range.
```

---

### 2.3 RSU to Fog Node / Controller Communication

**Network:** 5G Core (backhaul)  
**Trigger:** On every BSM received from any vehicle

#### Step-by-Step RSU → Fog Node Flow

```
Step 1 — BSM Aggregation at Fog Node
  Fog node continuously receives BSMs from all RSUs in its scope.
  Each BSM is appended to FN-BSMD (Fog Node BSM Database).

Step 2 — Periodic MDS Execution (every 100 seconds)
  Fog node runs the MDS (Random Forest) over the entire FN-BSMD.
  For each unique vehicle (sender ID) in FN-BSMD:
    a. Build mobility matrix Mi from all BSMs of that sender.
    b. Centralise Mi (subtract column means).
    c. Compute MS_i = Mi × Mi^T.
    d. Compute 7 eigenvalues of MS_i.
    e. Feed eigenvalues into the Random Forest MDS.
    f. IF MDS labels vehicle as misbehaving:
         → Add vehicle ID to MVD.
         → Broadcast updated MVD to all fog nodes immediately.
         → Push MVD update to vehicles via RSU.

Step 3 — NADM Execution (every 100 seconds, parallel to MDS)
  Fog node also runs the NADM on FN-BSMD:
    a. Pass FN-BSMD through AutoEncoder.
    b. Samples with MSE ≥ τ_AE are marked malicious.
    c. Malicious samples are fed to the RF in NADM.
    d. Compute UC_FN-BSMD (Unsure Classification Rate).
    e. IF UC_FN-BSMD > UC_known:
         → Novel attack detected.
         → Extract samples where S(X) < τ_i.
         → Send extracted samples to cloud server for retraining.

Step 4 — MVD Synchronisation Across Fog Nodes
  When any fog node updates MVD:
    All other fog nodes immediately download the updated MVD.
  This ensures network-wide awareness of misbehaving vehicles.

Step 5 — Database Expiry (same as OBU)
  If no BSM from a vehicle for 100 s → delete from FN-BSMD.
```

---

### 2.4 Fog Node to Cloud Server Communication

**Network:** 5G Core interconnect between fog nodes and cloud

```
Step 1 — Novel Attack Samples Upload
  When NADM detects a novel attack,
  extracted novel-class samples are sent to the cloud server.

Step 2 — Retraining at Cloud Server
  Cloud server receives novel attack samples.
  Assigns new class label to extracted samples.
  Adds samples to the known attacks dataset.
  Retrains:
    - MDS (Random Forest) with updated known attacks.
    - NADM (AutoEncoder + Random Forest) with updated dataset.
  Stores updated models.

Step 3 — Distribution of Updated Models
  Fog nodes periodically poll the cloud server for updates.
  On detecting an update:
    a. Fog node downloads updated MDS and NADM.
    b. Fog node sends updated MDS to vehicles via RSU.
    c. Vehicles update their OBU-side MDS.
  
  Result: All vehicles and fog nodes are immunised
          to the newly learned attack class.
```

---

## 3. Data Structures — Basic Safety Message (BSM)

### 3.1 Raw BSM Fields (from VeReMi dataset)

| Field | Description |
|---|---|
| `rcvTime` | Reception timestamp at receiver |
| `sendTime` | Claimed transmission time by sender |
| `sender` | Claimed sender vehicle ID |
| `messageID` | Simulation-wide unique message ID |
| `XPos` | Claimed X position |
| `YPos` | Claimed Y position |
| `ZPos` | Claimed Z position (zero variance → removed) |
| `XSpd` | X-axis speed |
| `YSpd` | Y-axis speed |
| `ZSpd` | Z-axis speed (zero variance → removed) |
| `RSSI` | Received Signal Strength Indicator |
| `pos_noise` | Position noise vector (zero variance → removed) |
| `spd_noise` | Speed noise vector (zero variance → removed) |
| `type` | Attack type label (ground truth) |

### 3.2 Pre-processed BSM Fields (after feature engineering)

| Field | Description |
|---|---|
| `SendTime` | Transmission time |
| `XPos` | X position |
| `YPos` | Y position |
| `XSpd` | X-axis speed |
| `YSpd` | Y-axis speed |
| `XAcc` | X-axis acceleration (derived: ΔXSpd / Δt) |
| `YAcc` | Y-axis acceleration (derived: ΔYSpd / Δt) |

> **Removed fields:** `ZPos`, `ZSpd`, `pos_noise`, `spd_noise` (zero variance), `RSSI` (environment-dependent), `type`, `rcvTime`, `messageID` (not useful for detection).

### 3.3 Mobility Matrix Construction

For each unique sender vehicle `i`, build mobility matrix **M_i**:

```
M_i = [ n rows × 7 columns ]

Row n = [ SendTime_n, XPos_n, YPos_n, XSpd_n, YSpd_n, XAcc_n, YAcc_n ]

Steps:
  1. Collect all pre-processed BSMs for sender i → n rows.
  2. Centralise M_i: subtract column mean from each column.
     (Ensures eigenvalues are real, not complex.)
  3. Compute square matrix: MS_i = M_i × M_i^T   (shape: n×n)
  4. Compute eigenvalues of MS_i.
  5. Take the 7 eigenvalues → feature vector for sender i.
  6. Append ground truth attack label → labelled sample.
```

---

## 4. Position Falsification Attack Types

| ID | Name | Description | Attacker Behaviour |
|---|---|---|---|
| **Type 1** | Constant | Always broadcasts a fixed position | XPos = 5560, YPos = 5820 (regardless of true position) |
| **Type 2** | Constant Offset | Adds a fixed offset to true position | ΔX = +250, ΔY = −150 (always added to actual GPS) |
| **Type 4** | Random | Broadcasts fully random positions | XPos, YPos = uniformly random across the simulation playground |
| **Type 8** | Random Offset | Adds a constrained random offset | ΔX, ΔY = uniformly random from [−300, +300] |
| **Type 16** | Eventual Stop | Gradually starts broadcasting a fixed position | Stop probability increases by 0.025 after each position update |

### Why Type 2 is the hardest to detect

Type 2 (Constant Offset) adds a small, consistent delta to the true position. The vehicle still moves realistically — it just appears shifted. Because the movement pattern is preserved, the eigenvalues of Type 2 attack samples closely resemble benign eigenvalues, making it the most difficult attack to detect accurately (lowest F1 scores across all models).

### Why Type 16 interferes with Type 1 detection

Type 16 (Eventual Stop) initially broadcasts the correct position and then progressively freezes at a fixed point — which is behaviorally similar to Type 1 (Constant). This similarity causes Type 1 detection accuracy to degrade slightly when Type 16 detection capability is added (as seen at Time Instant 4 in the paper).

---

## 5. Step-by-Step Attack Implementation

### 5.1 Type 1 — Constant Attack

```
[Attacker vehicle setup]
  - Vehicle holds valid CA credentials (insider attacker).
  - Vehicle's OBU is compromised to override GPS output.

[Per BSM broadcast cycle]
  Step 1: True GPS position is read from sensors → (X_true, Y_true).
  Step 2: OBU OVERRIDES position fields:
            XPos ← 5560
            YPos ← 5820
            (True position is discarded.)
  Step 3: Speed and acceleration remain from real sensors
          (or may also be falsified — only position is guaranteed fake).
  Step 4: BSM is digitally signed with valid credentials.
  Step 5: Falsified BSM is broadcast over DSRC.

[Effect on receivers]
  Receivers believe attacker is always at (5560, 5820).
  Safety applications (e.g., blind-spot warning) are misled.
  The eigenvalue pattern of this sender will be highly abnormal
  (no variation in position columns → near-zero eigenvalues for position).
```

### 5.2 Type 2 — Constant Offset Attack

```
[Attacker vehicle setup]
  - Same as Type 1: insider, valid credentials.
  - OBU is programmed to apply a fixed offset.

[Per BSM broadcast cycle]
  Step 1: True GPS position read → (X_true, Y_true).
  Step 2: OBU APPLIES OFFSET:
            XPos ← X_true + 250
            YPos ← Y_true + (−150)
  Step 3: Speed and acceleration are broadcast normally.
  Step 4: BSM is digitally signed and broadcast.

[Effect on receivers]
  Vehicle appears to be 250 m east and 150 m south of true position.
  Movement pattern is still realistic (vehicle appears to move normally).
  Eigenvalues are close to benign → hardest attack to detect.
```

### 5.3 Type 4 — Random Attack

```
[Attacker vehicle setup]
  - OBU generates random positions within simulation bounds.

[Per BSM broadcast cycle]
  Step 1: OBU calls random number generator:
            XPos ← uniform_random(X_min, X_max)  [playground bounds]
            YPos ← uniform_random(Y_min, Y_max)
  Step 2: Speed and acceleration may or may not be falsified.
  Step 3: BSM is signed and broadcast.

[Effect on receivers]
  Receiver sees erratic, physically impossible position jumps.
  Eigenvalues of the mobility matrix will be highly irregular.
  Easy to detect because the movement is physically implausible.
```

### 5.4 Type 8 — Random Offset Attack

```
[Attacker vehicle setup]
  - Similar to Type 2 but offset is randomised each cycle.

[Per BSM broadcast cycle]
  Step 1: True GPS position read → (X_true, Y_true).
  Step 2: OBU generates random bounded offsets:
            ΔX ← uniform_random(−300, +300)
            ΔY ← uniform_random(−300, +300)
  Step 3: Apply offset:
            XPos ← X_true + ΔX
            YPos ← Y_true + ΔY
  Step 4: BSM is signed and broadcast.

[Effect on receivers]
  Position appears to jitter randomly around the true location.
  The jitter range (±300 m) is large enough to cause safety misclassification.
  More detectable than Type 2 because the eigenvalue variance is higher.
```

### 5.5 Type 16 — Eventual Stop Attack

```
[Attacker vehicle setup]
  - OBU maintains a "stop probability" counter, initially 0.

[Per BSM broadcast cycle]
  Step 1: Check current stop probability P_stop.
  Step 2: Draw random number r ← uniform_random(0, 1).
  Step 3: IF r < P_stop:
              XPos ← X_frozen  (last frozen position)
              YPos ← Y_frozen
            ELSE:
              XPos ← X_true (normal GPS)
              YPos ← Y_true
              X_frozen ← X_true  (update frozen position)
              Y_frozen ← Y_true
  Step 4: Increment P_stop ← P_stop + 0.025 after each update.
  Step 5: BSM is signed and broadcast.

[Effect on receivers]
  Attacker initially appears normal (no offset).
  Over time, broadcasts appear to "freeze" in place more often.
  Looks similar to Type 1 eventually → causes interference in detection.
```

---

## 6. Dataset — VeReMi Pre-processing Pipeline

```
[Input]  VeReMi simulation logs
            - Reception logs  (one per vehicle, per simulation run)
            - Ground truth file (transmission time, sender, attack type,
                                 actual position/speed vectors)

Step 1: Parse reception logs
  - Split each entry into GPS messages and BSM messages.
  - DISCARD GPS entries entirely.

Step 2: Aggregate BSMs
  - Combine all BSM messages from a single simulation run.
  - Remove duplicate records of the same BSM message ID.

Step 3: Vector field splitting
  - Split Pos vector → XPos, YPos, ZPos
  - Split Speed vector → XSpd, YSpd, ZSpd

Step 4: Remove zero-variance and irrelevant features
  Remove: ZPos, ZSpd, pos_noise, spd_noise  (zero variance)
  Remove: RSSI  (environment-dependent, model should not rely on it)
  Remove: type, rcvTime, messageID  (not position-behaviour signals)

Step 5: Derive acceleration features
  For each pair of consecutive BSMs from the same sender:
    XAcc = (XSpd_n − XSpd_{n−1}) / (SendTime_n − SendTime_{n−1})
    YAcc = (YSpd_n − YSpd_{n−1}) / (SendTime_n − SendTime_{n−1})

Step 6: Build mobility matrix per sender (see Section 3.3)

Step 7: Compute eigenvalues (7 eigenvalues per sender per window)

Step 8: Append ground truth label from ground truth file

Step 9: Split dataset
  - Separate: Attack samples vs Benign samples
  - Within attacks: Known attacks (Type 1, Type 2)
                    Unknown/Novel attacks (Type 4, Type 8, Type 16)
  - Split each subset: 80% training / 20% testing
```

---

## 7. Detection Mechanism — NPFADS

NPFADS has two modules:

```
NPFADS
├── MDS (Misbehavior Detection System)
│     └── Random Forest classifier
│           - Trained on: Benign + Known attack samples
│           - Goal: Classify incoming BSMs as benign or attack
│           - Deployed at: OBU (per vehicle) + Fog Node
│
└── NADM (Novel Attack Detection Module)
      ├── AutoEncoder (AE)
      │     - Trained on: Benign samples ONLY
      │     - Goal: Separate benign from malicious via reconstruction error
      │
      └── Random Forest (RF)
            - Trained on: Known attack samples
            - Goal: Detect when a malicious sample belongs to an UNKNOWN class
```

---

### 7.1 MDS — Misbehavior Detection System

**Model:** Random Forest (RF)  
**Hyperparameter optimisation:** Random Search with Cross-Validation (scikit-learn)  
**Training data:** Benign samples + Known attack samples  
**Output:** Binary label — `Benign (0)` or `Attack (1)`

#### MDS at OBU vs MDS at Fog Node

| Aspect | OBU | Fog Node |
|---|---|---|
| Trigger | Every time a BSM is received | Every 100 seconds |
| Data volume | Small (few BSMs per sender in range) | Large (all BSMs from all vehicles in scope) |
| Accuracy | Slightly lower (less context) | Higher (more BSMs → better mobility pattern) |
| Response time | Immediate (per-BSM) | Delayed (batch, every 100 s) |

---

### 7.2 NADM — Novel Attack Detection Module

The NADM works by comparing the **Unsure Classification Rate** of incoming data against a baseline for known attacks.

**Key intuition:** When the RF is given a sample from a class it has never seen, it will still predict the nearest known class — but with *lower confidence* (lower probability score S(X)). The NADM exploits this low-confidence signal.

---

### 7.3 AutoEncoder (AE) — First Stage of NADM

**Purpose:** Filter out benign samples; pass only suspected malicious samples to RF.  
**Training data:** Benign samples ONLY  
**Architecture:**

```
Input Layer   →  7 neurons   (7 eigenvalue features)
Encoder
  Hidden Dense Layer 1  →  4 neurons
  Hidden Dense Layer 2  →  3 neurons
  Bottleneck Layer      →  2 neurons
Decoder (mirror of encoder)
  Hidden Dense Layer 3  →  3 neurons
  Hidden Dense Layer 4  →  4 neurons
Output Layer  →  7 neurons   (reconstructed input)
```

**Training:**
- Optimiser: Adam
- Epochs: 20 (with early stopping: stop if validation loss unchanged for 3 consecutive epochs)
- Batch size: 64
- Loss function: Mean Squared Error (MSE)

**Inference:**

```
For each input sample X:
  1. Encode X → compressed latent representation
  2. Decode → reconstructed X_hat
  3. Compute MSE(X, X_hat)
  4. IF MSE(X, X_hat) < τ_AE  → classify as BENIGN
     IF MSE(X, X_hat) ≥ τ_AE  → classify as MALICIOUS
                                  → pass to RF in NADM

τ_AE is set by feeding both benign and known attack testing
samples through the trained AE and finding the MSE threshold
that best separates the two classes.
```

---

### 7.4 Random Forest (RF) — Second Stage of NADM

**Purpose:** Among malicious samples, distinguish known attacks from novel (unknown) attacks.  
**Training data:** Known attack samples (Type 1, Type 2 initially)  
**Output per sample X:** `C(X)` = predicted class, `S(X)` = probability of that prediction

**Key insight:**

```
Known attack sample  → S(X) is typically HIGH (close to 1.0)
Novel attack sample  → S(X) is typically LOW  (uncertain; RF guesses nearest known class)
```

---

### 7.5 Threshold Setting — Hypotheses H1, H2, H3

For each known class `i`, a detection threshold `τ_i` is set using one of three hypotheses.

#### Hypothesis H1 — Maximise CCR first, then minimise MCR

```
Step 1: Compute CCR_i(τ) and MCR_i(τ) for τ ∈ [0, 1] with step 0.001.
Step 2: Find S_τ = set of all τ values where CCR_i(τ) is maximum.
Step 3: Among S_τ, set τ_i = the τ that minimises MCR_i(τ).
        (Ties broken by taking the largest such τ.)
```

#### Hypothesis H2 — Minimise MCR first, then maximise CCR

```
Step 1: Compute CCR_i(τ) and MCR_i(τ) for τ ∈ [0, 1] step 0.001.
Step 2: Find S_τ = set of all τ values where MCR_i(τ) is minimum.
Step 3: Among S_τ, set τ_i = the τ that maximises CCR_i(τ).
        (Ties broken by taking the largest such τ.)
```

#### Hypothesis H3 — Require CCR > 0.9, then minimise MCR ✅ (SELECTED)

```
Step 1: Compute CCR_i(τ) and MCR_i(τ) for τ ∈ [0, 1] step 0.001.
Step 2: Find S_τ = set of all τ values where CCR_i(τ) > 0.90.
Step 3: Among S_τ, set τ_i = the τ that minimises MCR_i(τ).
```

#### Why H3 was selected

| Hypothesis | τ₁ | τ₂ | UC_known | UC_FN-BSMD | Novel Attack Detected? | NASEA |
|---|---|---|---|---|---|---|
| H1 | 0.539 | 0.589 | 0.00093 | 0.00219 | Yes | 0.00225 |
| H2 | 0.049 | 0.469 | 0 | 0 | **No** | — |
| H3 | 0.989 | 0.999 | 0.09617 | 0.99944 | **Yes** | **0.99944** |

H3 sets a **higher threshold**, which means more samples fall below it (more are flagged as "unsure"). This trades some known-class precision for a dramatically higher **Novel Attack Sample Extraction Ability (NASEA = 99.9%)**, enabling the system to extract nearly all novel attack samples for retraining.

---

### 7.6 NASEA — Novel Attack Sample Extraction Ability

```
NASEA = (Number of samples where S(X) < τ_i) / (Total novel attack samples)

Higher NASEA → more novel samples extracted → better retraining → better future detection.
```

---

## 8. End-to-End Detection Flow — Step by Step

### Phase 1 — System Initialisation (Time Instant 1)

```
1.  Pre-process VeReMi dataset.
2.  Build eigenvalue dataset.
3.  Split: Benign | Known attacks (Type 1, Type 2) | Novel (Type 4, 8, 16)
4.  Train MDS (RF) on Benign + Type 1 + Type 2 samples.
5.  Train AE in NADM on Benign samples only.
6.  Train RF in NADM on Type 1 + Type 2 samples.
7.  Set τ_AE using benign/known attack test samples.
8.  Set τ_1 = 0.989 and τ_2 = 0.999 using Hypothesis H3.
9.  Compute UC_known = 0.09617.
10. Deploy MDS to all OBUs and fog nodes.
11. Deploy NADM to all fog nodes.
```

### Phase 2 — Ongoing Protection (Steady State)

```
Every BSM received at OBU:
  1. Check MVD → blacklisted? DISCARD.
  2. Add to OBU-BSMD.
  3. Build Mi, compute eigenvalues.
  4. MDS (RF) predicts: Attack or Benign.
  5. If Attack → flag sender.

Every 100 seconds at Fog Node:
  1. MDS runs over entire FN-BSMD → flag misbehaving vehicles → update MVD.
  2. NADM runs:
     a. AE filters FN-BSMD → marks malicious samples.
     b. RF predicts C(X) and S(X) for each malicious sample.
     c. Compute UC_FN-BSMD.
     d. Compare: UC_FN-BSMD > UC_known?
        YES → novel attack detected.
        NO  → no novel attack; continue.
```

### Phase 3 — Novel Attack Detected (Time Instants 2, 3, 4)

```
On novel attack detection:
  1. Extract all samples where S(X) < τ_i.
  2. Assign new class label (e.g., "Type 4") to extracted samples.
  3. Send samples to cloud server.

At cloud server:
  4. Add new class samples to known attacks dataset.
  5. Retrain MDS (RF) with updated dataset.
  6. Retrain NADM (AE + RF) with updated dataset.
  7. Recompute τ_i for all classes (including new class) using H3.
  8. Recompute UC_known.
  9. Push updated MDS, NADM to fog nodes.

At fog nodes:
  10. Distribute updated MDS to vehicles via RSU.
  11. Update fog-side MDS and NADM.

At vehicles:
  12. OBU downloads and replaces its local MDS.
  13. System is now immunised to the new attack class.
```

---

## 9. Performance Metrics

All metrics are computed at both OBU-level and Fog Node-level:

```
Accuracy  = (TP + TN) / (TP + FP + FN + TN)
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1 Score  = 2 × (Precision × Recall) / (Precision + Recall)
```

**Supplementary metrics:**
- **ROC Curve & AUC** — measures class separability (AUC = 1.0 for Type 1, 4, 8)
- **PR Curve & AUC** — measures precision-recall tradeoff (especially meaningful for imbalanced classes)
- **CCR_i(τ)** — Correct Classification Rate for class i at threshold τ
- **MCR_i(τ)** — Misclassification Rate for class i at threshold τ
- **UC_known** — Unsure Classification Rate for known attacks (baseline)
- **UC_FN-BSMD** — Unsure Classification Rate in fog node BSM data (compared against UC_known)
- **NASEA** — Novel Attack Sample Extraction Ability

### Key Results from Paper

| Model | Overall Precision | Recall | F1 |
|---|---|---|---|
| Sharma & Liu (2021) Ensemble | 0.887 | 0.576 | 0.70 |
| So et al. (2019) WBSM | 0.959 | 0.837 | 0.89 |
| **NPFADS — MDS at OBU** | **0.98** | **0.85** | **0.91** |
| **NPFADS — MDS at Fog Node** | **0.96** | **0.92** | **0.94** |
| Sharma & Jaekel (2022) KNN* | 0.981 | 0.985 | 0.98 |

> *Sharma & Jaekel excluded benign samples during evaluation, making direct comparison unfair.

---

## 10. Implementation Checklist

### Environment & Libraries

- [ ] Python 3.x
- [ ] `scikit-learn` — Random Forest, Random Search CV
- [ ] `tensorflow` / `keras` or `pytorch` — AutoEncoder
- [ ] `numpy`, `pandas` — data handling & matrix operations
- [ ] `matplotlib` / `seaborn` — ROC and PR curve plotting
- [ ] VeReMi Dataset — download and extract

### Data Pipeline

- [ ] Parse VeReMi reception logs (JSON/CSV)
- [ ] Filter BSM messages; discard GPS entries
- [ ] Aggregate and deduplicate BSMs per simulation run
- [ ] Split position/speed vectors into individual fields
- [ ] Remove zero-variance features (ZPos, ZSpd, pos_noise, spd_noise)
- [ ] Remove RSSI, rcvTime, type, messageID
- [ ] Derive XAcc and YAcc from consecutive BSMs
- [ ] Build mobility matrix M_i per sender
- [ ] Centralise columns of M_i
- [ ] Compute M_i × M_i^T → eigenvalues (7 per sender)
- [ ] Append ground truth labels
- [ ] Split into benign / known-attack / novel-attack subsets
- [ ] Split each into train/test (80/20)

### MDS Implementation

- [ ] Train Random Forest on Benign + Known (Type 1, Type 2) train sets
- [ ] Tune hyperparameters with Random Search + 5-fold CV
- [ ] Evaluate on test set: Accuracy, Precision, Recall, F1
- [ ] Plot ROC curves and compute AUC
- [ ] Plot PR curves and compute AUC

### NADM — AutoEncoder

- [ ] Build AE architecture (7→4→3→2→3→4→7)
- [ ] Train on Benign samples only (Adam, batch=64, max 20 epochs, early stopping patience=3)
- [ ] Compute MSE on benign test samples
- [ ] Compute MSE on known attack test samples
- [ ] Set τ_AE at the MSE value that best separates the two classes
- [ ] Validate AE: confirm low MSE for benign, high for attacks

### NADM — RF Threshold Setting

- [ ] Train RF on known attack samples (Type 1, Type 2)
- [ ] For each known class i, iterate τ from 0 to 1 in steps of 0.001
- [ ] Compute CCR_i(τ) and MCR_i(τ) at each step
- [ ] Apply Hypothesis H3: find τ_i (CCR > 0.9, minimum MCR)
- [ ] Compute UC_known using Eq. 5

### Novel Attack Detection

- [ ] Introduce novel attack samples (Type 4) into FN-BSMD
- [ ] Pass FN-BSMD through AE → mark malicious samples
- [ ] Pass malicious samples through RF → get C(X) and S(X)
- [ ] Compute UC_FN-BSMD
- [ ] Compare UC_FN-BSMD > UC_known → confirm novel detection
- [ ] Extract samples where S(X) < τ_i → NASEA calculation
- [ ] Assign new class label; retrain MDS and NADM
- [ ] Recompute τ_i for all classes including new class
- [ ] Repeat for Type 8 and Type 16 at subsequent time instants

### Evaluation

- [ ] Compare NPFADS with Sharma & Liu (2021), So et al. (2019), Sharma & Jaekel (2022)
- [ ] Report per-class metrics for all 5 attack types
- [ ] Report binary (Attack vs Benign) overall metrics
- [ ] Verify detection time (~20 µs per sample)
- [ ] Confirm no degradation in known-attack detection after adding novel classes

---

*End of Implementation Plan*

> **Reference:** Ilango, H.S., Ma, M., Su, R. (2022). A misbehavior detection system to detect novel position falsification attacks in the Internet of Vehicles. *Engineering Applications of Artificial Intelligence*, 116, 105380. https://doi.org/10.1016/j.engappai.2022.105380
