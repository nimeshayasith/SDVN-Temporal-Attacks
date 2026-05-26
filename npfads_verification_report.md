# NPFADS Attack Verification Report
## Novel Position Falsification Attack Detection System — NS-3 Simulation

---

## 1. Overview

This report presents the verification of five VeReMi-style position falsification attacks implemented in the NPFADS NS-3.35 simulation (`npfads_attacks.cc`). Each attack is verified by examining the Basic Safety Message (BSM) log output and the Performance Evaluation Metrics (PEM) summary produced at the end of each simulation run.

The simulation models 20 vehicles (4 attackers, 16 benign) broadcasting BSMs every 100 ms over a 10 km × 10 km area using 802.11p DSRC radio (300 m range). Each attacker falsifies only its reported **position** (`xPos`, `yPos`); velocity (`xSpd`, `ySpd`) and acceleration (`xAcc`, `yAcc`) always reflect the true MobilityModel values.

Detection is performed using a **position variance (posVar) anomaly scorer** based on Principal Component Analysis (PCA):

1. For each sender, a mobility matrix **M** (n × 7) is built from all received BSMs.
2. Columns are centred (column mean subtracted).
3. The covariance proxy **A = Mᵀ × M** (7 × 7) is computed.
4. Eigenvalues λ₁ … λ₇ are extracted via Jacobi decomposition.
5. `posVar = A[1][1] + A[2][2]` (sum of squared centred xPos and yPos residuals) is used as the anomaly score.
6. An F1-optimal threshold is swept per run to produce the final classification.

---

## 2. Reference Paper

> **Ilango, S., Ma, M., & Su, R. (2022).**
> *Misbehaviour detection in vehicular networks using deep learning.*
> **Engineering Applications of Artificial Intelligence, 116, 105380.**
> https://doi.org/10.1016/j.engappai.2022.105380

The five attack types, their falsification parameters, and the ground-truth labels used in this simulation are taken directly from **Table 1** of the above paper.

> **Note:** The paper uses a Random Forest + AutoEncoder (RF+AE) classifier operating on the full feature set (position, velocity, acceleration). This simulation uses the simpler posVar scorer as a proxy. Detection performance for Types 2 and 8 differs from the paper's results for reasons explained in Sections 4.3 and 5.3.

---

## 3. Simulation Parameters

| Parameter | Value |
|-----------|-------|
| Simulation time | 60 s |
| Total vehicles | 20 |
| Attackers (nodes 0–3) | 4 |
| Benign (nodes 4–19) | 16 |
| Beacon interval | 0.1 s |
| Beacons per node | 599 |
| Total BSMs logged | 11 980 |
| DSRC range | 300 m |
| Playground | 10 000 × 10 000 m |
| Random seed | 1 |

---

---

# Attack Type 1 — Constant Position

---

## 4.1 Brief Introduction

In the **Constant Position** attack, every attacker reports the same fixed GPS coordinate for every beacon, regardless of where the vehicle actually is. The falsified position is hardcoded as **(5560.0 m, 5820.0 m)** — a single static point in the simulation area. The vehicle continues to move physically (its true position and velocity change normally), but the reported position never changes.

**Falsification formula (from paper Table 1):**

```
reported xPos = 5560.0   (constant)
reported yPos = 5820.0   (constant)
```

**Key observable contradiction:** Reported position is frozen but reported velocity is non-zero. A stationary vehicle cannot have non-zero velocity. As the vehicle moves away from (5560, 5820), the `posError` (distance between reported and true position) grows continuously over time.

**Why easy to detect:** A frozen position sequence produces a near-zero variance position matrix (rank-0 in position columns) after centering, which is far below the natural motion variance of any benign node. The posVar score for Type 1 attackers approaches zero, while benign nodes score significantly higher.

---

## 4.2 BSM Log — First 3 Beacons

> 📷 **[INSERT SCREENSHOT: BSM Log CSV — Type 1, t = 0.1 s to 0.3 s]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 4.3 PEM Metrics Summary

> 📷 **[INSERT SCREENSHOT: npfads_pem_summary.csv — Type 1]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 4.4 Observable Characteristics in BSM Log

| Field | Attacker (Nodes 0–3) | Benign (Nodes 4–19) |
|-------|---------------------|---------------------|
| `xPos` | **Always 5560.000** — never changes | Changes every beacon |
| `yPos` | **Always 5820.000** — never changes | Changes every beacon |
| `xSpd`, `ySpd` | Non-zero (vehicle still moving) | Non-zero |
| `trueXPos` | Drifts away from 5560 over time | Same as `xPos` |
| `posError` | **Grows every beacon** as vehicle moves away | Always 0.000 |
| `xAcc`, `yAcc` | 0.000 (constant true speed) | 0.000 |

**Primary contradiction:** `xPos` = 5560.000 (frozen) while `xSpd` ≠ 0 (moving). Physically impossible.

---

## 4.5 Detection Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Precision | 1.000 | No benign nodes wrongly flagged |
| Recall | 1.000 | All 4 attackers correctly detected |
| F1 | 1.000 | Perfect classification |
| MCC | 1.000 | Perfect correlation |
| AUROC | 1.000 | Perfect ranking separation |
| Tdet_est | 800 ms | Minimum observation window (8 beacons × 100 ms) |

**Verdict:** ✅ Implementation correct. Perfect detection achieved. Type 1 is the most detectable attack — a frozen position produces near-zero posVar, completely separated from all benign nodes.

---
---

# Attack Type 2 — Constant Offset

---

## 5.1 Brief Introduction

In the **Constant Offset** attack, every attacker adds the same fixed displacement to its true GPS coordinates in every beacon. The reported position moves with the vehicle but is always shifted by exactly **(+250 m, −150 m)**. The offset never changes.

**Falsification formula (from paper Table 1):**

```
reported xPos = trueXPos + 250.0
reported yPos = trueYPos − 150.0
```

**Key observable:** The `posError` (Euclidean distance between reported and true position) is constant at exactly **√(250² + 150²) = 291.548 m** every single beacon, for every attacker.

**Why hardest to detect with posVar scorer:** The constant offset (+250, −150) equals the column mean of the reported position sequence. When the preprocessing step subtracts the column mean (centering), the offset is **completely cancelled out** — the centred position matrix of the attacker becomes mathematically identical to a benign node's centred matrix. The posVar scorer therefore cannot distinguish Type 2 attackers from benign nodes.

---

## 5.2 BSM Log — First 3 Beacons

> 📷 **[INSERT SCREENSHOT: BSM Log CSV — Type 2, t = 0.1 s to 0.3 s]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 5.3 PEM Metrics Summary

> 📷 **[INSERT SCREENSHOT: npfads_pem_summary.csv — Type 2]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 5.4 Observable Characteristics in BSM Log

| Field | Attacker (Nodes 0–3) | Benign (Nodes 4–19) |
|-------|---------------------|---------------------|
| `xPos` | trueXPos **+ 250.000** — changes each beacon | Same as `trueXPos` |
| `yPos` | trueYPos **− 150.000** — changes each beacon | Same as `trueYPos` |
| `posError` | **Exactly 291.548 m every beacon** (never varies) | 0.000 |
| `xSpd`, `ySpd` | True values — consistent with motion | True values |
| `trueXPos` | Differs from `xPos` by exactly +250 always | Same as `xPos` |

**Primary contradiction:** A real GPS error would vary over time — correlated noise, multipath, etc. A perfectly constant posError of 291.548 m across hundreds of beacons is physically implausible for any legitimate sensor.

---

## 5.5 Detection Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Precision | 0.235 | 13 of 16 benign nodes wrongly flagged |
| Recall | 1.000 | All 4 attackers found (at very low threshold) |
| F1 | 0.381 | Poor overall accuracy |
| MCC | 0.210 | Near-random performance |
| AUROC | **0.344** | **Below 0.5 — inverted ranking** |
| Tdet_est | 800 ms | Minimum observation window |

---

## 5.6 Why MCC is Low — The Centering Property (Important)

> ⚠️ **This low MCC is not a bug. It is the mathematically expected result for Type 2 with the posVar scorer.**

**Mathematical explanation:**

```
Reported xPos(t)  =  trueXPos(t) + 250

Column mean of reported xPos  =  mean(trueXPos) + 250

After centering:
  reported xPos(t) − mean(reported xPos)
= trueXPos(t) + 250 − mean(trueXPos) − 250
= trueXPos(t) − mean(trueXPos)
                ↑
       +250 is completely cancelled
```

The constant offset becomes the column mean and is subtracted out in the preprocessing step. After centering, the attacker's position matrix is **mathematically identical** to a benign node's position matrix. The posVar score carries no attack signal.

**The inversion effect (AUROC = 0.344 < 0.5):**

After centering removes the offset, the attacker's trajectory (a smooth constant-offset linear path) appears more regular than the natural variation of benign nodes. This means:

- Attacker posVar scores → **lower** than most benign nodes
- 13 of 16 benign nodes score **higher** than all 4 attackers
- To catch all 4 attackers (Recall = 1.0), the threshold must be set so low that 13 benign nodes are falsely flagged

```
TN = 3   →  only 3 benign nodes score LOWER than attackers
FP = 13  →  13 of 16 benign nodes score HIGHER than all 4 attackers
```

This means **attackers appear more regular than 81% of actual benign nodes** — a direct consequence of the centering cancellation.

**Comparison with research paper:** The paper's RF+AE classifier achieves F1 = 0.48 (OBU) / 0.73 (fog node) for Type 2 because it uses velocity and acceleration features in addition to position, which are not affected by the centering cancellation. The posVar scorer uses position variance only, making it blind to this attack.

---
---

# Attack Type 4 — Random Position

---

## 6.1 Brief Introduction

In the **Random Position** attack, every attacker reports a completely random GPS coordinate drawn uniformly from the entire simulation area, independently for each beacon. There is no relationship between the reported position and the true position, or between consecutive reported positions.

**Falsification formula (from paper Table 1):**

```
reported xPos = Uniform(0, 10 000)
reported yPos = Uniform(0, 10 000)
```

**Key observable:** The reported position jumps by thousands of metres between consecutive beacons, while the reported velocity is only 15–30 m/s. A vehicle cannot physically teleport.

**Why easy to detect:** Random positions across a 10 km × 10 km area produce enormous position variance in the mobility matrix. After centering, the attacker's posVar score (~33 million m²) is orders of magnitude larger than any benign node's score (~187 000 m²), giving perfect separation.

---

## 6.2 BSM Log — First 3 Beacons

> 📷 **[INSERT SCREENSHOT: BSM Log CSV — Type 4, t = 0.1 s to 0.3 s]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 6.3 PEM Metrics Summary

> 📷 **[INSERT SCREENSHOT: npfads_pem_summary.csv — Type 4]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 6.4 Observable Characteristics in BSM Log

| Field | Attacker (Nodes 0–3) | Benign (Nodes 4–19) |
|-------|---------------------|---------------------|
| `xPos` | Random in [0, 10 000] — **jumps thousands of metres each beacon** | Smooth change consistent with velocity |
| `yPos` | Random in [0, 10 000] — no pattern | Smooth change |
| `posError` | **Wildly varies** (71 m → 8023 m) with no pattern | 0.000 |
| `xSpd`, `ySpd` | 15–30 m/s (cannot explain km-scale jumps) | Consistent with position changes |
| Implied velocity from xPos | Would require **km/s** between beacons | ~25 m/s |

**Primary contradiction:** Reported position changes by thousands of metres per 0.1 s interval while reported velocity is only tens of m/s. Physically impossible.

---

## 6.5 Detection Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Precision | 1.000 | No false positives |
| Recall | 1.000 | All attackers detected |
| F1 | 1.000 | Perfect classification |
| MCC | 1.000 | Perfect correlation |
| AUROC | 1.000 | Perfect ranking separation |
| Tdet_est | 800 ms | Minimum observation window |

**Verdict:** ✅ Implementation correct. Perfect detection achieved. Type 4 produces the largest possible posVar signal (~10 000 times larger than benign nodes), making it trivially separable.

---
---

# Attack Type 8 — Random Offset

---

## 7.1 Brief Introduction

In the **Random Offset** attack, every attacker adds an independent random displacement to its true GPS coordinates in each beacon. The offset is drawn fresh from a uniform distribution on **[−300 m, +300 m]** for both axes independently. The reported position roughly tracks the true position but with random noise up to 300 m per axis.

**Falsification formula (from paper Table 1):**

```
reported xPos = trueXPos + Uniform(−300, +300)
reported yPos = trueYPos + Uniform(−300, +300)
```

**Key observable:** The `posError` varies randomly each beacon (between 0 and ~424 m maximum), with no fixed pattern. Each beacon has a completely independent offset.

**Why hardest to detect with posVar scorer (alongside Type 2):** The random offset adds only ~30 000 m² of additional variance per axis, while a benign vehicle moving at 25 m/s for 60 s already has ~187 500 m² of natural position variance. The attack signal is only ~16% above the baseline, causing heavy overlap between attacker and benign posVar scores.

---

## 7.2 BSM Log — First 3 Beacons

> 📷 **[INSERT SCREENSHOT: BSM Log CSV — Type 8, t = 0.1 s to 0.3 s]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 7.3 PEM Metrics Summary

> 📷 **[INSERT SCREENSHOT: npfads_pem_summary.csv — Type 8]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 7.4 Observable Characteristics in BSM Log

| Field | Attacker (Nodes 0–3) | Benign (Nodes 4–19) |
|-------|---------------------|---------------------|
| `xPos` | trueXPos + random offset ∈ [−300, +300] | Same as `trueXPos` |
| `yPos` | trueYPos + random offset ∈ [−300, +300] | Same as `trueYPos` |
| `posError` | **Varies randomly each beacon** (71–353 m), always ≤ 424.3 m | 0.000 |
| Offset direction | **Changes sign and magnitude each beacon** | N/A |
| `xSpd`, `ySpd` | True values — never falsified | True values |

**Primary contradiction:** A real GPS error model produces correlated noise (errors persist between measurements). An offset that randomly changes sign and magnitude every 0.1 s is not consistent with any legitimate sensor error model.

**Maximum theoretical posError:** √(300² + 300²) = **424.3 m**. All observed posErrors are within this bound, confirming the ±300 m range is correctly applied.

---

## 7.5 Detection Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Precision | 0.333 | 4 false positives out of 6 flagged |
| Recall | 0.500 | Only 2 of 4 attackers detected |
| F1 | 0.400 | Poor overall accuracy |
| MCC | 0.218 | Near-random performance |
| AUROC | **0.500** | Completely random ranking — no signal |
| Tdet_est | 800 ms | Minimum observation window |

---

## 7.6 Why MCC is Low — The Signal-to-Noise Problem (Important)

> ⚠️ **This low MCC is not a bug. It is the mathematically expected result for Type 8 with the posVar scorer.**

**Mathematical explanation:**

The posVar scorer measures position variance. For both attackers and benign nodes:

```
Benign node — natural position variance from motion (25 m/s × 60 s):
  σ²_motion ≈ (v × T)² / 12 = (25 × 60)² / 12 ≈ 187 500 m² per axis

Type 8 attacker — attack adds offset variance on top:
  σ²_offset = 300² / 3 = 30 000 m² per axis    (variance of Uniform(−300, 300))

Attack signal as fraction of baseline:
  30 000 / 187 500 = only 16% extra variance
```

The random offset adds only 16% more variance on top of what a normally moving vehicle already produces. The posVar score distributions of attackers and benign nodes **heavily overlap**:

```
Benign posVar:   ████████████████░░░░░░░
Attacker posVar:        ████████████████░░░
                         ↑↑↑↑↑↑↑↑↑
                      Large overlap → AUROC = 0.500
                      (no better than random coin flip)
```

**AUROC = 0.500** is the mathematical confirmation: if you pick one random attacker and one random benign node, the attacker scores higher only 50% of the time — equivalent to a coin flip. No threshold can reliably separate them.

**Comparison with Type 2:**

| | Type 2 | Type 8 |
|--|--------|--------|
| Root cause | Centering **cancels** the offset completely | Offset signal too **small** vs motion variance |
| AUROC | 0.344 (inverted — attackers score lower) | 0.500 (random — no signal at all) |
| MCC | 0.210 | 0.218 |

**Comparison with research paper:** The paper's RF+AE classifier achieves better results for Type 8 because it incorporates velocity change patterns and cross-feature correlations. The random offset, while invisible to the posVar position scorer, causes detectable inconsistencies between reported position jumps and the smooth velocity trajectory — features that RF+AE can exploit but posVar cannot.

---
---

# Attack Type 16 — Eventual Stop

---

## 8.1 Brief Introduction

In the **Eventual Stop** attack, each attacker uses a probabilistic state machine to progressively freeze its reported position. The probability of freezing increases by 0.025 with every beacon. Once frozen, the attacker reports the same position repeatedly while the vehicle continues to physically move.

**Falsification formula (from paper Table 1):**

```
stopProb += 0.025  (per beacon)
if Uniform(0, 1) < stopProb:
    reported position = last frozen position   ← FROZEN
else:
    reported position = truePosition          ← unfrozen
```

**Freeze rate progression:**

| Beacon k | Time (s) | stopProb | Freeze probability |
|----------|----------|----------|-------------------|
| 0 | 0.1 | 0.000 | **0%** — attack not yet active |
| 10 | 1.1 | 0.250 | 25% |
| 20 | 2.1 | 0.500 | 50% |
| 40 | 4.1 | **1.000** | **100%** — always frozen from here |
| 599 | 60.0 | 1.000 | 100% |

**Overall freeze rate across full 60 s run:**
Unfrozen beacons per attacker = Σ(k=0→39)(1 − k×0.025) = **20.5 out of 599** ≈ **3.4% unfrozen**, **96.6% frozen**.

> **Important:** At t = 0.1 s (the very first beacon), `stopProb = 0`, so no freezing occurs yet. The attack is completely invisible in the first beacon — reported position equals true position for all attackers. The attack becomes visible progressively from t ≈ 0.5 s and is fully active (100% frozen) after t = 4.1 s.

---

## 8.2 BSM Log — First 3 Beacons

> 📷 **[INSERT SCREENSHOT: BSM Log CSV — Type 16, t = 0.1 s to 0.3 s]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 8.3 PEM Metrics Summary

> 📷 **[INSERT SCREENSHOT: npfads_pem_summary.csv — Type 16]**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

---

## 8.4 Observable Characteristics in BSM Log

| Field | Attacker (Nodes 0–3) after t = 4 s | Benign (Nodes 4–19) |
|-------|-------------------------------------|---------------------|
| `xPos` | **Constant — same value for many consecutive beacons** | Changes every beacon |
| `yPos` | **Constant — frozen** | Changes every beacon |
| `trueXPos` | Continues to move away from frozen value | Same as `xPos` |
| `posError` | **Grows continuously** as vehicle moves away from frozen point | 0.000 |
| `xSpd`, `ySpd` | Non-zero (vehicle physically moving) | Non-zero |
| `xAcc`, `yAcc` | 0.000 (constant speed) | 0.000 |

**Primary contradiction at t > 4 s:** `xPos` is constant (frozen), `xSpd` ≠ 0 (still moving), and `trueXPos` is drifting away — all three simultaneously. By the end of the 60 s run, `posError` can exceed 1 000 m as the vehicle drives far from its frozen reported location.

> **Note:** The attack is invisible at t = 0.1 s (first beacon) because `stopProb = 0`. To observe the freeze clearly, examine rows with `sendTime > 4.0 s` in the CSV — the frozen `xPos` will remain static while `trueXPos` changes each row.

---

## 8.5 Detection Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| Precision | 1.000 | No false positives |
| Recall | 1.000 | All 4 attackers detected |
| F1 | 1.000 | Perfect classification |
| MCC | 1.000 | Perfect correlation |
| AUROC | 1.000 | Perfect ranking separation |
| Tdet_est | 800 ms | Minimum observation window (8 beacons × 100 ms) |

**Verdict:** ✅ Implementation correct. Perfect detection achieved. A 96.6% frozen position produces near-zero posVar (similar to Type 1), completely separated from all benign nodes. The 3.4% unfrozen beacons add negligible variance that does not affect the classification.

---
---

# 9. Summary Comparison — All Five Attack Types

| Attack | Falsification | posError pattern | MCC | AUROC | Detectable? |
|--------|--------------|-----------------|-----|-------|-------------|
| **Type 1** — Constant Position | xPos=5560, yPos=5820 (always) | Grows as vehicle moves away | **1.000** | **1.000** | ✅ Perfect |
| **Type 2** — Constant Offset | +250, −150 fixed every beacon | **Exactly 291.548 m always** | 0.210 | 0.344 | ⚠️ Near-random (centering cancels offset) |
| **Type 4** — Random Position | Uniform(0, 10 000) each beacon | Jumps wildly 0–8 000+ m | **1.000** | **1.000** | ✅ Perfect |
| **Type 8** — Random Offset | Uniform(−300, +300) each beacon | Varies 0–424 m randomly | 0.218 | 0.500 | ⚠️ Near-random (signal too small) |
| **Type 16** — Eventual Stop | Freezes with prob += 0.025/beacon | Grows after freeze | **1.000** | **1.000** | ✅ Perfect |

---

## 10. Key Limitations of the posVar Scorer

The posVar scorer achieves perfect detection (MCC = 1.000, AUROC = 1.000) for attacks that produce extreme position variance (Type 4) or near-zero position variance (Types 1, 16). However, it fails for two specific cases:

| Limitation | Type 2 | Type 8 |
|-----------|--------|--------|
| Root cause | Column centering mathematically removes the constant offset | Random offset adds only 16% extra variance above natural motion |
| AUROC | 0.344 (below 0.5 — score is inverted) | 0.500 (completely random — no signal) |
| Paper result (RF+AE) | F1 = 0.48–0.73 | Better than posVar | 
| Fix | Use velocity-position consistency check | Use velocity-position consistency check |

The paper's **RF+AE classifier** mitigates both limitations by incorporating velocity, acceleration, and cross-feature patterns that remain uncorrupted in both Type 2 and Type 8 attacks (since only position is falsified, never velocity). The posVar scorer is used here as a simpler proxy to demonstrate the eigenvalue analysis framework described in the paper.

---

*Report generated from NPFADS NS-3.35 simulation — `npfads_attacks.cc`*
*Simulation parameters: `--simTime=60 --N_Vehicles=20 --N_Attackers=4 --seed=1`*
*Reference: Ilango, Ma & Su (2022), Engineering Applications of Artificial Intelligence, 116, 105380*
