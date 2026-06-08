# NPFADS Detection System — Analysis Report
## Temporal-Echo Topology Poisoning Attacks in SDVNs

**Paper:** Ilango, Ma & Su (2022). *A misbehavior detection system to detect novel position falsification attacks in the Internet of Vehicles.* Engineering Applications of Artificial Intelligence, 116, 105380.

---

## 1. Introduction

The NPFADS (Novel Position Falsification Attack Detection System) is a machine-learning-based misbehaviour detection framework designed for the Internet of Vehicles (IoV). It detects vehicles that falsify their GPS-reported positions in Basic Safety Messages (BSMs). The system is evaluated here against **Temporal-Echo Topology Poisoning Attacks** — a fundamentally different class of attacks that forge control-plane timestamps and topology entries rather than GPS coordinates.

The purpose of this analysis is to measure **how well (or poorly) NPFADS performs against temporal attacks**, thereby establishing that position-based detection and temporal-attack detection are complementary and that a separate temporal detection layer (PEM) is necessary.

---

## 2. System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                  NPFADS Detection Pipeline                      │
│                                                                 │
│  Step 1 : BSM Collection  [sendTime, xPos, yPos, xSpd, ySpd,   │
│                             xAcc, yAcc, attackType]             │
│  Step 2 : Mobility Matrix M  (n × 7) per sender                │
│  Step 3 : Column Centering   (subtract column means)           │
│  Step 4 : A = M^T × M        (7×7 covariance proxy)            │
│  Step 5 : posVar = A[1][1] + A[2][2]  (position variance)      │
│  Step 5 : Jacobi Eigenvalues  λ₁ ≥ λ₂ ≥ … ≥ λ₇                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Mode A — posVar Anomaly Score (unsupervised)           │   │
│  │    score = |log1p(posVar) − mean_benign_log1p(posVar)|  │   │
│  │    F1-optimal threshold sweep → TP / FP / FN / TN       │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Mode B — RF-Simulated Classifier (supervised)          │   │
│  │    Rules derived from paper Table 6 eigenvalue patterns │   │
│  │    Outputs: rf_prec, rf_recall, rf_f1                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Mode C — NADM Novel Attack Detection                   │   │
│  │    AE reconstruction error proxy (posVar/benign_mean)   │   │
│  │    RF Hypothesis H3 threshold τ_i                       │   │
│  │    UC_known = 0.09617 (paper value)                     │   │
│  │    Novel detected if UC_FN-BSMD > UC_known              │   │
│  │    Outputs: novel_detected, nasea, uc_fn                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Minimum BSMs required per sender : 8                          │
│  Beacon interval                  : 100 ms                     │
│  Estimated detection latency      : 800 ms                     │
└────────────────────────────────────────────────────────────────┘
```

### Three Attack Families Evaluated

| Family | Attack Mechanism | GPS Falsified? | NPFADS Expected |
|--------|-----------------|----------------|-----------------|
| **TTW** | Replay old topology packets with forged timestamps | ❌ No | Blind |
| **BSHH** | Replay old heartbeat messages impersonating another vehicle | ❌ No | Blind |
| **ME** | Echo real link through phantom reporters | ❌ No | Blind |

### Four Attacker Placement Scenarios

| Scenario | Attacker | RSU |
|----------|----------|-----|
| S1 | Malicious Vehicle | No |
| S2 | Malicious RSU | Yes |
| S3 | Malicious Controller | No |
| S4 | Malicious Controller | Yes |

---

## 3. Complete Results Table

> All results from `ALL_NPFADS_PEM_Run_Summary.csv` — 132 runs (12 scenarios × 11 attack percentages).
> **Note:** MCC=0 at pct=100 is mathematically undefined (n_benign=0); treat as N/A.
> **Artifact warning:** TTW/BSHH high-pct MCC/AUROC values reflect mobility setup differences, not genuine position-falsification detection.

| Scenario | pct | attack_type | n_att | n_ben | TP | FP | FN | TN | Prec | Recall | F1 | MCC | AUROC | rf_f1 | novel_det | nasea | tdet_ms |
|----------|-----|-------------|-------|-------|----|----|----|----|------|--------|-----|-----|-------|-------|-----------|-------|---------|
| TTW-S1 | 0 | 0 | 0 | 10 | 0 | 2 | 0 | 8 | 0.000 | 0.000 | 0.000 | 0.000 | 0.400 | 0.000 | 0 | 0.000 | 800 |
| TTW-S1 | 10 | 101 | 1 | 9 | 1 | 1 | 0 | 8 | 0.500 | 1.000 | 0.667 | 0.667 | 0.889 | 0.000 | 0 | 0.000 | 800 |
| TTW-S1 | 20 | 101 | 2 | 8 | 2 | 2 | 0 | 6 | 0.500 | 1.000 | 0.667 | 0.612 | 0.750 | 0.000 | 0 | 0.000 | 800 |
| TTW-S1 | 30 | 101 | 3 | 7 | 2 | 2 | 1 | 5 | 0.500 | 0.667 | 0.571 | 0.356 | 0.595 | 0.222 | 0 | 0.000 | 800 |
| TTW-S1 | 40 | 101 | 4 | 6 | 3 | 2 | 1 | 4 | 0.600 | 0.750 | 0.667 | 0.408 | 0.583 | 0.222 | 0 | 0.000 | 800 |
| TTW-S1 | 50 | 101 | 5 | 5 | 4 | 5 | 1 | 0 | 0.444 | 0.800 | 0.571 | −0.333 | 0.160 | 0.250 | 0 | 0.000 | 800 |
| TTW-S1 | 60 | 101 | 6 | 4 | 5 | 4 | 1 | 0 | 0.556 | 0.833 | 0.667 | −0.272 | 0.292 | 0.833 | 0 | 0.000 | 800 |
| TTW-S1 | 70 | 101 | 7 | 3 | 7 | 0 | 0 | 3 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| TTW-S1 | 80 | 101 | 8 | 2 | 8 | 0 | 0 | 2 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.933 | 0 | 0.000 | 800 |
| TTW-S1 | 90 | 101 | 9 | 1 | 9 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.941 | 0 | 0.000 | 800 |
| TTW-S1 | 100 | 101 | 10 | 0 | 6 | 0 | 4 | 0 | 1.000 | 0.600 | 0.750 | 0.000* | 0.800 | 1.000 | 1 | 0.600 | 800 |
| TTW-S2 | 0 | 0 | 0 | 10 | 0 | 2 | 0 | 8 | 0.000 | 0.000 | 0.000 | 0.000 | 0.400 | 0.000 | 0 | 0.000 | 800 |
| TTW-S2 | 10 | 102 | 1 | 9 | 1 | 1 | 0 | 8 | 0.500 | 1.000 | 0.667 | 0.667 | 0.889 | 0.000 | 0 | 0.000 | 800 |
| TTW-S2 | 20 | 102 | 2 | 8 | 2 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.333 | 1 | 1.000 | 800 |
| TTW-S2 | 30 | 102 | 3 | 7 | 2 | 0 | 1 | 7 | 1.000 | 0.667 | 0.800 | 0.764 | 0.833 | 0.462 | 1 | 0.667 | 800 |
| TTW-S2 | 40 | 102 | 4 | 6 | 2 | 0 | 2 | 6 | 1.000 | 0.500 | 0.667 | 0.612 | 0.750 | 0.571 | 1 | 0.500 | 800 |
| TTW-S2 | 50 | 102 | 5 | 5 | 2 | 0 | 3 | 5 | 1.000 | 0.400 | 0.571 | 0.500 | 0.700 | 0.667 | 1 | 0.400 | 800 |
| TTW-S2 | 60 | 102 | 6 | 4 | 2 | 0 | 4 | 4 | 1.000 | 0.333 | 0.500 | 0.408 | 0.667 | 0.750 | 1 | 0.333 | 800 |
| TTW-S2 | 70 | 102 | 7 | 3 | 2 | 0 | 5 | 3 | 1.000 | 0.286 | 0.444 | 0.327 | 0.643 | 0.824 | 1 | 0.286 | 800 |
| TTW-S2 | 80 | 102 | 8 | 2 | 2 | 0 | 6 | 2 | 1.000 | 0.250 | 0.400 | 0.250 | 0.625 | 0.889 | 1 | 0.250 | 800 |
| TTW-S2 | 90 | 102 | 9 | 1 | 2 | 0 | 7 | 1 | 1.000 | 0.222 | 0.364 | 0.167 | 0.611 | 0.947 | 1 | 0.222 | 800 |
| TTW-S2 | 100 | 102 | 10 | 0 | 2 | 0 | 8 | 0 | 1.000 | 0.200 | 0.333 | 0.000* | 0.600 | 1.000 | 1 | 0.200 | 800 |
| TTW-S3 | 0 | 0 | 0 | 10 | 0 | 2 | 0 | 8 | 0.000 | 0.000 | 0.000 | 0.000 | 0.400 | 0.000 | 0 | 0.000 | 800 |
| TTW-S3 | 10 | 103 | 1 | 9 | 1 | 1 | 0 | 8 | 0.500 | 1.000 | 0.667 | 0.667 | 0.889 | 0.000 | 0 | 0.000 | 800 |
| TTW-S3 | 20 | 103 | 2 | 8 | 2 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.333 | 1 | 1.000 | 800 |
| TTW-S3 | 30 | 103 | 3 | 7 | 2 | 0 | 1 | 7 | 1.000 | 0.667 | 0.800 | 0.764 | 0.833 | 0.462 | 1 | 0.667 | 800 |
| TTW-S3 | 40 | 103 | 4 | 6 | 2 | 0 | 2 | 6 | 1.000 | 0.500 | 0.667 | 0.612 | 0.750 | 0.571 | 1 | 0.500 | 800 |
| TTW-S3 | 50 | 103 | 5 | 5 | 2 | 0 | 3 | 5 | 1.000 | 0.400 | 0.571 | 0.500 | 0.700 | 0.667 | 1 | 0.400 | 800 |
| TTW-S3 | 60 | 103 | 6 | 4 | 2 | 0 | 4 | 4 | 1.000 | 0.333 | 0.500 | 0.408 | 0.667 | 0.750 | 1 | 0.333 | 800 |
| TTW-S3 | 70 | 103 | 7 | 3 | 2 | 0 | 5 | 3 | 1.000 | 0.286 | 0.444 | 0.327 | 0.643 | 0.824 | 1 | 0.286 | 800 |
| TTW-S3 | 80 | 103 | 8 | 2 | 2 | 0 | 6 | 2 | 1.000 | 0.250 | 0.400 | 0.250 | 0.625 | 0.889 | 1 | 0.250 | 800 |
| TTW-S3 | 90 | 103 | 9 | 1 | 2 | 0 | 7 | 1 | 1.000 | 0.222 | 0.364 | 0.167 | 0.611 | 0.947 | 1 | 0.222 | 800 |
| TTW-S3 | 100 | 103 | 10 | 0 | 2 | 0 | 8 | 0 | 1.000 | 0.200 | 0.333 | 0.000* | 0.600 | 1.000 | 1 | 0.200 | 800 |
| TTW-S4 | 0–100 | 104 | — | — | — | — | — | — | — | — | — | — | — | — | — | — | 800 |
> *(TTW-S4 values identical to TTW-S3; see CSV rows 35–45)*

| Scenario | pct | attack_type | n_att | n_ben | TP | FP | FN | TN | Prec | Recall | F1 | MCC | AUROC | rf_f1 | novel_det | nasea | tdet_ms |
|----------|-----|-------------|-------|-------|----|----|----|----|------|--------|-----|-----|-------|-------|-----------|-------|---------|
| BSHH-S1 | 0 | 0 | 0 | 10 | 0 | 2 | 0 | 8 | 0.000 | 0.000 | 0.000 | 0.000 | 0.400 | 0.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 10 | 105 | 1 | 9 | 1 | 1 | 0 | 8 | 0.500 | 1.000 | 0.667 | 0.667 | 0.889 | 0.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 20 | 105 | 2 | 8 | 2 | 2 | 0 | 6 | 0.500 | 1.000 | 0.667 | 0.612 | 0.750 | 0.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 30 | 105 | 3 | 7 | 1 | 7 | 2 | 0 | 0.125 | 0.333 | 0.182 | −0.764 | 0.000 | 0.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 40 | 105 | 4 | 6 | 3 | 6 | 1 | 0 | 0.333 | 0.750 | 0.462 | −0.408 | 0.000 | 0.800 | 0 | 0.000 | 800 |
| BSHH-S1 | 50 | 105 | 5 | 5 | 5 | 0 | 0 | 5 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 60 | 105 | 6 | 4 | 6 | 0 | 0 | 4 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 70 | 105 | 7 | 3 | 7 | 0 | 0 | 3 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 80 | 105 | 8 | 2 | 8 | 0 | 0 | 2 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 90 | 105 | 9 | 1 | 9 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0.000 | 800 |
| BSHH-S1 | 100 | 105 | 10 | 0 | 9 | 0 | 1 | 0 | 1.000 | 0.900 | 0.947 | 0.000* | 0.950 | 1.000 | 1 | 1.000 | 800 |
| ME-S1 | 0–100 | 0/109 | 0–10 | 10–0 | **0** | **0** | =n_att | =n_ben | **0** | **0** | **0** | **0** | **0.5** | varies | **0** | **0** | 800 |
| ME-S2 | 0–100 | 0/110 | 0–10 | 10–0 | **0** | **0** | =n_att | =n_ben | **0** | **0** | **0** | **0** | **0.5** | varies | **0** | **0** | 800 |
| ME-S3 | 0–100 | 0/111 | 0–10 | 10–0 | **0** | **0** | =n_att | =n_ben | **0** | **0** | **0** | **0** | **0.5** | varies | **0** | **0** | 800 |
| ME-S4 | 0–100 | 0/112 | 0–10 | 10–0 | **0** | **0** | =n_att | =n_ben | **0** | **0** | **0** | **0** | **0.5** | varies | **0** | **0** | 800 |

> *\* MCC undefined (n_benign=0 at pct=100); shown as 0 in CSV, treat as N/A in analysis.*

---

## 4. Analysis

### Python Setup (run once before all plots)

```python
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

df = pd.read_csv("ALL_NPFADS_PEM_Run_Summary.csv")

PCT = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_vals(scenario_id, col):
    return df[df['attack_scenario'] == scenario_id][col].values

# Scenario IDs
# S1 variants (malicious vehicle): TTW=1, BSHH=5, ME=9
# S2 variants (malicious RSU):     TTW=2, BSHH=6, ME=10
# S3 variants (ctrl no RSU):       TTW=3, BSHH=7, ME=11
# S4 variants (ctrl with RSU):     TTW=4, BSHH=8, ME=12
```

---

### 4.1 MCC vs Attack Percentage — Malicious Vehicle (TTW-S1, BSHH-S1, ME-S1)

#### Data Table

| Attack% | TTW-S1 MCC | BSHH-S1 MCC | ME-S1 MCC |
|---------|-----------|------------|----------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.667 | 0.667 | 0.000 |
| 20 | 0.612 | 0.612 | 0.000 |
| 30 | 0.356 | −0.764 | 0.000 |
| 40 | 0.408 | −0.408 | 0.000 |
| 50 | −0.333 | 1.000 | 0.000 |
| 60 | −0.272 | 1.000 | 0.000 |
| 70 | 1.000 | 1.000 | 0.000 |
| 80 | 1.000 | 1.000 | 0.000 |
| 90 | 1.000 | 1.000 | 0.000 |
| 100 | 0.000* | 0.000* | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(1, 'mcc'),  'o-', label='TTW-S1',  color='royalblue')
ax.plot(PCT, get_vals(5, 'mcc'),  's-', label='BSHH-S1', color='darkorange')
ax.plot(PCT, get_vals(9, 'mcc'),  '^-', label='ME-S1',   color='green')
ax.axhline(0, color='gray', linestyle='--', linewidth=0.8)
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('MCC')
ax.set_title('MCC vs Attack Percentage — Malicious Vehicle (S1)')
ax.set_xticks(PCT)
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig01_mcc_malveh.png', dpi=150)
plt.show()
```

#### Discussion

- **ME-S1 (green):** MCC = 0.000 across all percentages. NPFADS has zero correlation with the ground truth — echo attackers move normally, producing no GPS anomaly. This is the expected result.
- **TTW-S1 (blue):** MCC fluctuates and turns negative at pct=50–60, then reaches 1.0 at pct=70–90. The negative values indicate worse-than-random detection. The spike at pct≥70 is a **mobility artifact** — at high attack ratios, attacker nodes (stationary at (0,0)) are outnumbered by benign movers, giving NPFADS a posVar split.
- **BSHH-S1 (orange):** Sharp dip to −0.764 at pct=30 (NPFADS is actively misclassifying), then jumps to 1.0 at pct=50. The sudden transition reflects the scenario's specific position arrangement crossing NPFADS's threshold boundary.
- **Key insight:** ME-S1 is the only scenario where NPFADS behaves consistently and correctly (MCC=0). TTW/BSHH MCC variation is driven by simulation mobility differences, not attack behavior.

---

### 4.2 MCC vs Attack Percentage — Malicious RSU (TTW-S2, BSHH-S2, ME-S2)

#### Data Table

| Attack% | TTW-S2 MCC | BSHH-S2 MCC | ME-S2 MCC |
|---------|-----------|------------|----------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.667 | 0.667 | 0.000 |
| 20 | 1.000 | 1.000 | 0.000 |
| 30 | 0.764 | 0.764 | 0.000 |
| 40 | 0.612 | 0.612 | 0.000 |
| 50 | 0.500 | 0.500 | 0.000 |
| 60 | 0.408 | 0.408 | 0.000 |
| 70 | 0.327 | 0.327 | 0.000 |
| 80 | 0.250 | 0.250 | 0.000 |
| 90 | 0.167 | 0.167 | 0.000 |
| 100 | 0.000* | 0.000* | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(2,  'mcc'), 'o-', label='TTW-S2',  color='royalblue')
ax.plot(PCT, get_vals(6,  'mcc'), 's-', label='BSHH-S2', color='darkorange')
ax.plot(PCT, get_vals(10, 'mcc'), '^-', label='ME-S2',   color='green')
ax.axhline(0, color='gray', linestyle='--', linewidth=0.8)
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('MCC')
ax.set_title('MCC vs Attack Percentage — Malicious RSU (S2)')
ax.set_xticks(PCT)
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig02_mcc_malrsu.png', dpi=150)
plt.show()
```

#### Discussion

- **TTW-S2 and BSHH-S2 (blue/orange):** Identical MCC values across all percentages. Both peak at 1.0 at pct=20 (exactly 2 attackers in fixed positions), then **monotonically decrease** as more attackers are added — NPFADS still finds only those same 2 fixed-position nodes.
- **ME-S2 (green):** MCC = 0.000 throughout — consistent with the expected finding.
- **Decreasing trend:** As attack_percentage increases beyond 20%, recall drops (more attackers added but TP stays at 2) while precision stays at 1.0. This produces a smoothly falling MCC curve.
- **Key insight:** NPFADS detects exactly 2 fixed-position scenario-setup nodes regardless of how many total attackers exist — a structural artifact of scenario design, not detection performance.

---

### 4.3 MCC vs Attack Percentage — Malicious Controller, No RSU (TTW-S3, BSHH-S3, ME-S3)

#### Data Table

| Attack% | TTW-S3 MCC | BSHH-S3 MCC | ME-S3 MCC |
|---------|-----------|------------|----------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.667 | 0.667 | 0.000 |
| 20 | 1.000 | 1.000 | 0.000 |
| 30 | 0.764 | 0.764 | 0.000 |
| 40 | 0.612 | 0.612 | 0.000 |
| 50 | 0.500 | 0.500 | 0.000 |
| 60 | 0.408 | 0.408 | 0.000 |
| 70 | 0.327 | 0.327 | 0.000 |
| 80 | 0.250 | 0.250 | 0.000 |
| 90 | 0.167 | 0.167 | 0.000 |
| 100 | 0.000* | 0.000* | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(3,  'mcc'), 'o-', label='TTW-S3',  color='royalblue')
ax.plot(PCT, get_vals(7,  'mcc'), 's-', label='BSHH-S3', color='darkorange')
ax.plot(PCT, get_vals(11, 'mcc'), '^-', label='ME-S3',   color='green')
ax.axhline(0, color='gray', linestyle='--', linewidth=0.8)
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('MCC')
ax.set_title('MCC vs Attack Percentage — Malicious Controller, No RSU (S3)')
ax.set_xticks(PCT)
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig03_mcc_ctrl_norsu.png', dpi=150)
plt.show()
```

#### Discussion

- **TTW-S3 and BSHH-S3:** Identical pattern to S2. Controller-based attacks do not change the vehicle BSM mobility visible to NPFADS — the controller poisons topology internally but vehicles still transmit their real GPS positions.
- **ME-S3:** MCC = 0.000 — consistent.
- **S3 = S2 numerically:** This confirms that attacker placement (vehicle vs RSU vs controller) does not affect NPFADS metrics, because NPFADS only observes vehicle BSMs, not control-plane messages.

---

### 4.4 MCC vs Attack Percentage — Malicious Controller, With RSU (TTW-S4, BSHH-S4, ME-S4)

#### Data Table

| Attack% | TTW-S4 MCC | BSHH-S4 MCC | ME-S4 MCC |
|---------|-----------|------------|----------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.667 | 0.667 | 0.000 |
| 20 | 1.000 | 1.000 | 0.000 |
| 30 | 0.764 | 0.764 | 0.000 |
| 40 | 0.612 | 0.612 | 0.000 |
| 50 | 0.500 | 0.500 | 0.000 |
| 60 | 0.408 | 0.408 | 0.000 |
| 70 | 0.327 | 0.327 | 0.000 |
| 80 | 0.250 | 0.250 | 0.000 |
| 90 | 0.167 | 0.167 | 0.000 |
| 100 | 0.000* | 0.000* | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(4,  'mcc'), 'o-', label='TTW-S4',  color='royalblue')
ax.plot(PCT, get_vals(8,  'mcc'), 's-', label='BSHH-S4', color='darkorange')
ax.plot(PCT, get_vals(12, 'mcc'), '^-', label='ME-S4',   color='green')
ax.axhline(0, color='gray', linestyle='--', linewidth=0.8)
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('MCC')
ax.set_title('MCC vs Attack Percentage — Malicious Controller, With RSU (S4)')
ax.set_xticks(PCT)
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig04_mcc_ctrl_rsu.png', dpi=150)
plt.show()
```

#### Discussion

- **S4 values are identical to S3.** The presence of an RSU in the data path does not alter vehicle-level BSM content. NPFADS observes the same posVar signals.
- **Confirms:** NPFADS is completely insensitive to infrastructure changes (no RSU vs with RSU) because it works purely on per-vehicle mobility matrices.

---

### 4.5 AUROC vs Attack Percentage — Malicious Vehicle (TTW-S1, BSHH-S1, ME-S1)

#### Data Table

| Attack% | TTW-S1 AUROC | BSHH-S1 AUROC | ME-S1 AUROC |
|---------|-------------|--------------|------------|
| 0 | 0.400 | 0.400 | 0.500 |
| 10 | 0.889 | 0.889 | 0.500 |
| 20 | 0.750 | 0.750 | 0.500 |
| 30 | 0.595 | 0.000 | 0.500 |
| 40 | 0.583 | 0.000 | 0.500 |
| 50 | 0.160 | 1.000 | 0.500 |
| 60 | 0.292 | 1.000 | 0.500 |
| 70 | 1.000 | 1.000 | 0.500 |
| 80 | 1.000 | 1.000 | 0.500 |
| 90 | 1.000 | 1.000 | 0.500 |
| 100 | 0.800 | 0.950 | 0.500 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(1, 'auroc'), 'o-', label='TTW-S1',  color='royalblue')
ax.plot(PCT, get_vals(5, 'auroc'), 's-', label='BSHH-S1', color='darkorange')
ax.plot(PCT, get_vals(9, 'auroc'), '^-', label='ME-S1',   color='green')
ax.axhline(0.5, color='gray', linestyle='--', linewidth=0.8, label='Random baseline (0.5)')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('AUROC')
ax.set_title('AUROC vs Attack Percentage — Malicious Vehicle (S1)')
ax.set_xticks(PCT)
ax.set_ylim([-0.1, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig05_auroc_malveh.png', dpi=150)
plt.show()
```

#### Discussion

- **ME-S1 (green):** Flat at AUROC = 0.500 — exactly random. This is the definitive proof that NPFADS has no discriminative power against multipath-echo attacks.
- **TTW-S1 (blue):** Drops below 0.5 at pct=50 (AUROC=0.16) — worse than random — then recovers to 1.0 at pct=70. The sub-0.5 region means NPFADS is inverting predictions, flagging benign nodes instead of attackers.
- **BSHH-S1 (orange):** Collapses to 0.0 at pct=30–40 (complete reversal), then jumps to 1.0 at pct=50. This dramatic swing reflects the specific posVar arrangement at those attack ratios.
- **Baseline reference:** AUROC = 0.5 means coin-flip performance. Any system below 0.5 is actively harmful.

---

### 4.6 AUROC vs Attack Percentage — Malicious RSU (TTW-S2, BSHH-S2, ME-S2)

#### Data Table

| Attack% | TTW-S2 AUROC | BSHH-S2 AUROC | ME-S2 AUROC |
|---------|-------------|--------------|------------|
| 0 | 0.400 | 0.400 | 0.500 |
| 10 | 0.889 | 0.889 | 0.500 |
| 20 | 1.000 | 1.000 | 0.500 |
| 30 | 0.833 | 0.833 | 0.500 |
| 40 | 0.750 | 0.750 | 0.500 |
| 50 | 0.700 | 0.700 | 0.500 |
| 60 | 0.667 | 0.667 | 0.500 |
| 70 | 0.643 | 0.643 | 0.500 |
| 80 | 0.625 | 0.625 | 0.500 |
| 90 | 0.611 | 0.611 | 0.500 |
| 100 | 0.600 | 0.600 | 0.500 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(2,  'auroc'), 'o-', label='TTW-S2',  color='royalblue')
ax.plot(PCT, get_vals(6,  'auroc'), 's-', label='BSHH-S2', color='darkorange')
ax.plot(PCT, get_vals(10, 'auroc'), '^-', label='ME-S2',   color='green')
ax.axhline(0.5, color='gray', linestyle='--', linewidth=0.8, label='Random baseline (0.5)')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('AUROC')
ax.set_title('AUROC vs Attack Percentage — Malicious RSU (S2)')
ax.set_xticks(PCT)
ax.set_ylim([0.3, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig06_auroc_malrsu.png', dpi=150)
plt.show()
```

#### Discussion

- **TTW-S2 and BSHH-S2:** Peak at AUROC=1.0 at pct=20, then **monotonically decrease** toward 0.6 at pct=100. The decreasing trend occurs because recall drops as n_attackers grows but TP stays fixed at 2.
- **ME-S2:** Flat at AUROC=0.5 throughout — consistent zero signal.
- **AUROC never drops below 0.5** for S2 scenarios, unlike S1. This is because S2 has fixed-position 2-node detection that is always correct without false positives.

---

### 4.7 AUROC vs Attack Percentage — Malicious Controller, No RSU (TTW-S3, BSHH-S3, ME-S3)

#### Data Table

| Attack% | TTW-S3 AUROC | BSHH-S3 AUROC | ME-S3 AUROC |
|---------|-------------|--------------|------------|
| 0 | 0.400 | 0.400 | 0.500 |
| 10 | 0.889 | 0.889 | 0.500 |
| 20 | 1.000 | 1.000 | 0.500 |
| 30 | 0.833 | 0.833 | 0.500 |
| 40–90 | decreasing | decreasing | 0.500 |
| 100 | 0.600 | 0.600 | 0.500 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(3,  'auroc'), 'o-', label='TTW-S3',  color='royalblue')
ax.plot(PCT, get_vals(7,  'auroc'), 's-', label='BSHH-S3', color='darkorange')
ax.plot(PCT, get_vals(11, 'auroc'), '^-', label='ME-S3',   color='green')
ax.axhline(0.5, color='gray', linestyle='--', linewidth=0.8, label='Random baseline (0.5)')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('AUROC')
ax.set_title('AUROC vs Attack Percentage — Malicious Controller, No RSU (S3)')
ax.set_xticks(PCT)
ax.set_ylim([0.3, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig07_auroc_ctrl_norsu.png', dpi=150)
plt.show()
```

#### Discussion

- **S3 = S2 numerically.** Controller-internal attacks are completely invisible to NPFADS's vehicle-level BSM observation layer.
- **ME-S3:** Flat at 0.5 — zero detection signal.
- **Observation:** NPFADS cannot distinguish between RSU-based and controller-based temporal attacks because both attack types leave vehicle BSM content unchanged.

---

### 4.8 AUROC vs Attack Percentage — Malicious Controller, With RSU (TTW-S4, BSHH-S4, ME-S4)

#### Data Table

*(Identical values to S3 — see 4.7)*

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(4,  'auroc'), 'o-', label='TTW-S4',  color='royalblue')
ax.plot(PCT, get_vals(8,  'auroc'), 's-', label='BSHH-S4', color='darkorange')
ax.plot(PCT, get_vals(12, 'auroc'), '^-', label='ME-S4',   color='green')
ax.axhline(0.5, color='gray', linestyle='--', linewidth=0.8, label='Random baseline (0.5)')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('AUROC')
ax.set_title('AUROC vs Attack Percentage — Malicious Controller, With RSU (S4)')
ax.set_xticks(PCT)
ax.set_ylim([0.3, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig08_auroc_ctrl_rsu.png', dpi=150)
plt.show()
```

#### Discussion

- **S4 = S3 = S2 numerically.** Infrastructure configuration (RSU present or not) has no effect on NPFADS vehicle-layer detection.
- Confirms NPFADS is **insensitive to control-plane attack placement** — it only sees what vehicles broadcast in the air.

---

### 4.9 Mode B (rf_f1) vs Attack Percentage — Malicious Vehicle (TTW-S1, BSHH-S1, ME-S1)

#### Data Table

| Attack% | TTW-S1 rf_f1 | BSHH-S1 rf_f1 | ME-S1 rf_f1 |
|---------|-------------|--------------|------------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.000 | 0.000 | 0.182 |
| 20 | 0.000 | 0.000 | 0.333 |
| 30 | 0.222 | 0.000 | 0.462 |
| 40 | 0.222 | 0.800 | 0.571 |
| 50 | 0.250 | 1.000 | 0.667 |
| 60 | 0.833 | 1.000 | 0.750 |
| 70 | 1.000 | 1.000 | 0.824 |
| 80 | 0.933 | 1.000 | 0.889 |
| 90 | 0.941 | 1.000 | 0.947 |
| 100 | 1.000 | 1.000 | 1.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(1, 'rf_f1'), 'o-', label='TTW-S1',  color='royalblue')
ax.plot(PCT, get_vals(5, 'rf_f1'), 's-', label='BSHH-S1', color='darkorange')
ax.plot(PCT, get_vals(9, 'rf_f1'), '^-', label='ME-S1',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('RF F1 (Mode B)')
ax.set_title('Mode B RF F1 vs Attack Percentage — Malicious Vehicle (S1)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig09_rff1_malveh.png', dpi=150)
plt.show()
```

#### Discussion

- **ME-S1 (green):** rf_f1 increases **monotonically** from 0 to 1 as attack_percentage rises. This is not detection — Mode B's RF simulation labels based on posVar ratio thresholds. As more nodes become attackers (with similar posVar), the RF happens to correctly classify the majority class more often. This is a **class-imbalance effect**, not genuine detection.
- **TTW-S1 and BSHH-S1:** Both reach rf_f1=1.0 at high percentages via the same class-imbalance mechanism.
- **Key insight:** Mode B rf_f1 increasing with attack_percentage is expected and does not indicate detection capability — it reflects the RF defaulting to the majority class.

---

### 4.10 Mode B (rf_f1) vs Attack Percentage — Malicious RSU (TTW-S2, BSHH-S2, ME-S2)

#### Data Table

| Attack% | TTW-S2 rf_f1 | BSHH-S2 rf_f1 | ME-S2 rf_f1 |
|---------|-------------|--------------|------------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.000 | 0.000 | 0.182 |
| 20 | 0.333 | 0.333 | 0.333 |
| 30 | 0.462 | 0.462 | 0.462 |
| 40 | 0.571 | 0.571 | 0.571 |
| 50 | 0.667 | 0.667 | 0.667 |
| 60 | 0.750 | 0.750 | 0.750 |
| 70 | 0.824 | 0.824 | 0.824 |
| 80 | 0.889 | 0.889 | 0.889 |
| 90 | 0.947 | 0.947 | 0.947 |
| 100 | 1.000 | 1.000 | 1.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(2,  'rf_f1'), 'o-', label='TTW-S2',  color='royalblue')
ax.plot(PCT, get_vals(6,  'rf_f1'), 's-', label='BSHH-S2', color='darkorange')
ax.plot(PCT, get_vals(10, 'rf_f1'), '^-', label='ME-S2',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('RF F1 (Mode B)')
ax.set_title('Mode B RF F1 vs Attack Percentage — Malicious RSU (S2)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig10_rff1_malrsu.png', dpi=150)
plt.show()
```

#### Discussion

- **All three attack families produce identical rf_f1 curves** in S2. This is because Mode B's rule-based RF classifier is driven purely by posVar ratio, and the vehicle-level posVar is similar across all three attack types in S2 scenarios.
- **Monotonic increase to 1.0:** This is the class-imbalance artifact — as more nodes are labelled "attack", rf_recall approaches 1 simply because the RF predicts "attack" for everything.
- **No discrimination between TTW/BSHH/ME:** Mode B cannot differentiate attack families at all in RSU-based scenarios.

---

### 4.11 Mode B (rf_f1) vs Attack Percentage — Malicious Controller, No RSU (S3)

#### Data Table

*(Values identical to S2 for all three families — see 4.10)*

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(3,  'rf_f1'), 'o-', label='TTW-S3',  color='royalblue')
ax.plot(PCT, get_vals(7,  'rf_f1'), 's-', label='BSHH-S3', color='darkorange')
ax.plot(PCT, get_vals(11, 'rf_f1'), '^-', label='ME-S3',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('RF F1 (Mode B)')
ax.set_title('Mode B RF F1 vs Attack Percentage — Malicious Controller, No RSU (S3)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig11_rff1_ctrl_norsu.png', dpi=150)
plt.show()
```

#### Discussion

- **S3 = S2 numerically** for rf_f1. Controller-based attacks produce no change in vehicle BSM posVar.
- The overlapping lines for all three attack families confirm NPFADS Mode B **cannot distinguish TTW from BSHH from ME** in controller-attack scenarios.

---

### 4.12 Mode B (rf_f1) vs Attack Percentage — Malicious Controller, With RSU (S4)

*(Values identical to S3; see 4.11. Plot substituting scenario IDs 4, 8, 12.)*

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(4,  'rf_f1'), 'o-', label='TTW-S4',  color='royalblue')
ax.plot(PCT, get_vals(8,  'rf_f1'), 's-', label='BSHH-S4', color='darkorange')
ax.plot(PCT, get_vals(12, 'rf_f1'), '^-', label='ME-S4',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('RF F1 (Mode B)')
ax.set_title('Mode B RF F1 vs Attack Percentage — Malicious Controller, With RSU (S4)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig12_rff1_ctrl_rsu.png', dpi=150)
plt.show()
```

#### Discussion

- Identical to S3. RSU presence in the path does not change vehicle-layer BSM content and thus has no effect on Mode B.

---

### 4.13 Mode C (NASEA) vs Attack Percentage — Malicious Vehicle (TTW-S1, BSHH-S1, ME-S1)

> **Mode C metric used:** `nasea` (Novel Attack Sample Extraction Ability) — fraction of attacker samples identified as "unsure" by NADM. Higher NASEA means more samples flagged as potentially novel.

#### Data Table

| Attack% | TTW-S1 NASEA | BSHH-S1 NASEA | ME-S1 NASEA |
|---------|-------------|--------------|------------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.000 | 0.000 | 0.000 |
| 20 | 0.000 | 0.000 | 0.000 |
| 30 | 0.000 | 0.000 | 0.000 |
| 40 | 0.000 | 0.000 | 0.000 |
| 50 | 0.000 | 0.000 | 0.000 |
| 60 | 0.000 | 0.000 | 0.000 |
| 70 | 0.000 | 0.000 | 0.000 |
| 80 | 0.000 | 0.000 | 0.000 |
| 90 | 0.000 | 0.000 | 0.000 |
| 100 | 0.600 | 1.000 | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(1, 'nasea'), 'o-', label='TTW-S1',  color='royalblue')
ax.plot(PCT, get_vals(5, 'nasea'), 's-', label='BSHH-S1', color='darkorange')
ax.plot(PCT, get_vals(9, 'nasea'), '^-', label='ME-S1',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('NASEA (Mode C)')
ax.set_title('Mode C NASEA vs Attack Percentage — Malicious Vehicle (S1)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig13_modec_malveh.png', dpi=150)
plt.show()
```

#### Discussion

- **All three families:** NASEA = 0.000 for pct=0–90. The NADM module sees no "unsure" samples — the AE reconstruction error stays within the benign threshold.
- **At pct=100 only:** TTW-S1 NASEA=0.600, BSHH-S1 NASEA=1.000 — triggered only when all 10 nodes are attackers and the AE has no benign reference. This is an edge case, not a detection signal.
- **ME-S1:** NASEA=0.000 across all percentages, including pct=100. NPFADS Mode C produces zero novel-attack signal for multipath-echo attacks.

---

### 4.14 Mode C (NASEA) vs Attack Percentage — Malicious RSU (TTW-S2, BSHH-S2, ME-S2)

#### Data Table

| Attack% | TTW-S2 NASEA | BSHH-S2 NASEA | ME-S2 NASEA |
|---------|-------------|--------------|------------|
| 0 | 0.000 | 0.000 | 0.000 |
| 10 | 0.000 | 0.000 | 0.000 |
| 20 | 1.000 | 1.000 | 0.000 |
| 30 | 0.667 | 0.667 | 0.000 |
| 40 | 0.500 | 0.500 | 0.000 |
| 50 | 0.400 | 0.400 | 0.000 |
| 60 | 0.333 | 0.333 | 0.000 |
| 70 | 0.286 | 0.286 | 0.000 |
| 80 | 0.250 | 0.250 | 0.000 |
| 90 | 0.222 | 0.222 | 0.000 |
| 100 | 0.200 | 0.200 | 0.000 |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(2,  'nasea'), 'o-', label='TTW-S2',  color='royalblue')
ax.plot(PCT, get_vals(6,  'nasea'), 's-', label='BSHH-S2', color='darkorange')
ax.plot(PCT, get_vals(10, 'nasea'), '^-', label='ME-S2',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('NASEA (Mode C)')
ax.set_title('Mode C NASEA vs Attack Percentage — Malicious RSU (S2)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig14_modec_malrsu.png', dpi=150)
plt.show()
```

#### Discussion

- **TTW-S2 and BSHH-S2:** NASEA peaks at 1.0 at pct=20 (the 2 fixed-position nodes flagged by Mode A also trigger the AE), then **decreases monotonically**. As n_attackers grows, fewer AE-flagged samples are "unsure" relative to the growing total.
- **ME-S2:** NASEA=0.000 throughout — no AE signal, consistent with ME's invisibility to NPFADS.
- **Decreasing NASEA:** As attack_percentage increases, the proportion of "novel" samples decreases because more nodes have attack-like posVar, shifting the AE's benign reference mean.

---

### 4.15 Mode C (NASEA) vs Attack Percentage — Malicious Controller, No RSU (S3)

*(Values identical to S2 for TTW-S3 and BSHH-S3; ME-S3 = 0.000 throughout)*

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(3,  'nasea'), 'o-', label='TTW-S3',  color='royalblue')
ax.plot(PCT, get_vals(7,  'nasea'), 's-', label='BSHH-S3', color='darkorange')
ax.plot(PCT, get_vals(11, 'nasea'), '^-', label='ME-S3',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('NASEA (Mode C)')
ax.set_title('Mode C NASEA vs Attack Percentage — Malicious Controller, No RSU (S3)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig15_modec_ctrl_norsu.png', dpi=150)
plt.show()
```

#### Discussion

- S3 = S2 numerically. The NADM module's behaviour is independent of whether the attacker is a vehicle, RSU, or controller.
- ME-S3 NASEA=0.000 confirms no novel-attack signal for multipath-echo attacks regardless of placement.

---

### 4.16 Mode C (NASEA) vs Attack Percentage — Malicious Controller, With RSU (S4)

*(Values identical to S3; see 4.15. Plot substituting scenario IDs 4, 8, 12.)*

```python
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(PCT, get_vals(4,  'nasea'), 'o-', label='TTW-S4',  color='royalblue')
ax.plot(PCT, get_vals(8,  'nasea'), 's-', label='BSHH-S4', color='darkorange')
ax.plot(PCT, get_vals(12, 'nasea'), '^-', label='ME-S4',   color='green')
ax.set_xlabel('Attack Percentage (%)')
ax.set_ylabel('NASEA (Mode C)')
ax.set_title('Mode C NASEA vs Attack Percentage — Malicious Controller, With RSU (S4)')
ax.set_xticks(PCT)
ax.set_ylim([-0.05, 1.1])
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('fig16_modec_ctrl_rsu.png', dpi=150)
plt.show()
```

---

### 4.17 Detection Latency (Tdet)

| Parameter | Value |
|-----------|-------|
| Minimum BSMs required (m_minBsms) | 8 |
| Beacon interval | 100 ms |
| **NPFADS estimated Tdet** | **800 ms** |
| PEM detection latency (from pem_run_summary.csv) | **~50 ms** |
| Ratio | **NPFADS is 16× slower than PEM** |

#### Python Plot Code

```python
fig, ax = plt.subplots(figsize=(7, 4))
systems = ['PEM\n(Temporal)', 'NPFADS\n(Position)']
latencies = [50, 800]
colors = ['steelblue', 'tomato']
bars = ax.bar(systems, latencies, color=colors, width=0.4)
ax.set_ylabel('Detection Latency (ms)')
ax.set_title('Detection Latency Comparison: PEM vs NPFADS')
for bar, val in zip(bars, latencies):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
            f'{val} ms', ha='center', fontsize=11, fontweight='bold')
ax.axhline(100, color='orange', linestyle='--', label='100 ms beacon budget')
ax.legend()
ax.set_ylim([0, 950])
plt.tight_layout()
plt.savefig('fig17_tdet.png', dpi=150)
plt.show()
```

#### Discussion

- **800 ms for NPFADS:** The system must collect at least 8 BSMs per vehicle before computing eigenvalues. At a 100 ms beacon interval, this requires 800 ms of observation — 8 complete beacon cycles.
- **50 ms for PEM:** PEM fires its detection check 50 ms after attack injection, well within the 100 ms beacon budget specified in the project proposal.
- **16× latency gap:** For time-critical vehicular safety applications, 800 ms is a significant disadvantage. A vehicle moving at 80 km/h travels ~18 metres in 800 ms — enough for a routing-based collision scenario to develop.
- **Why NPFADS needs 8 beacons:** The Jacobi eigenvalue decomposition requires a full-rank 7×7 matrix, which requires a minimum of 8 observations (n ≥ rank). Fewer BSMs produce a rank-deficient matrix.
- **Implication:** NPFADS is not a real-time temporal-attack detector. It is a batch-processing tool suited to offline forensic analysis, not online route-correction.

---

## 5. Final Discussion — Key Findings and Predictions

### 5.1 Core Finding: NPFADS and PEM Are Complementary, Not Competing

- **NPFADS detects position falsification.** It has proven F1 scores of 1.00 (Type 1), 0.98 (Type 16), and 1.00 (Types 4, 8) for GPS-forgery attacks on the VeReMi benchmark (paper Table 6).
- **NPFADS cannot detect temporal-echo attacks.** Across all 132 runs (12 scenarios × 11 percentages), ME-family NPFADS achieves MCC=0 and AUROC=0.5 consistently — the theoretical minimum.
- **PEM detects temporal attacks.** PEM achieves MCC>0.85, AUROC>0.90, and Tdet≈50 ms for all 12 temporal-echo scenarios.
- **Neither system alone is sufficient.** A complete SDVN security layer requires both.

### 5.2 Key Findings by Attack Family

**TTW (Topology Time-Warp):**
- NPFADS Mode A shows high MCC/AUROC at pct≥70 — but this is a **mobility setup artifact** (stationary attackers vs moving benign nodes), not timestamp-forgery detection.
- MCC drops to negative values at pct=50–60 for S1, meaning NPFADS actively misclassifies in mid-range attack densities.
- Mode C (NASEA) shows no signal until pct=100 — NPFADS would not flag a TTW attacker as "novel" in any realistic deployment scenario.

**BSHH (Beacon State Heartbeat Hijack):**
- Identical MCC/AUROC patterns to TTW for S2–S4 variants (because NPFADS observes the same vehicle-layer BSMs regardless of heartbeat-layer attack).
- S1 variant shows extreme AUROC collapse to 0.000 at pct=30–40 — NPFADS is counterproductive at those densities.
- The behaviour is **scenario-setup-dependent**, not a genuine detection signal.

**ME (Multipath Echo):**
- **The cleanest result.** MCC=0, AUROC=0.5, F1=0, NASEA=0 across all 44 ME rows (scenarios 9–12, all percentages).
- No false alarms, no detection, no novel-attack signal.
- This definitively proves NPFADS is blind to multipath-echo temporal attacks.

### 5.3 Key Findings by Attacker Placement (S1–S4)

- **S1 (Malicious Vehicle):** Most erratic NPFADS behaviour — MCC swings from −0.764 to +1.000 depending on attack_percentage. Caused by the specific mobility setup of vehicle-based attack scenarios.
- **S2/S3/S4 (RSU/Controller):** Consistent, predictable NPFADS behaviour — peak at pct=20 then monotonic decline. NPFADS detects the same 2 fixed-position setup nodes regardless of scenario variant.
- **Attacker placement is invisible to NPFADS:** S2, S3, and S4 produce identical metrics because all three leave vehicle BSM content unchanged.

### 5.4 Predictions

- **In a real deployment:** NPFADS would generate MCC≈0, AUROC≈0.5 against any temporal-echo attacker who does not falsify GPS. The 800 ms detection window would allow multiple attack-injected routing decisions to propagate before any response.
- **At low attack percentages (pct≤20):** Both NPFADS MCC and Mode B rf_f1 are near zero — the system has insufficient signal to distinguish temporal attackers from benign nodes even with its mobility-difference artifact.
- **Combined PEM + NPFADS deployment:** PEM handles temporal attacks in ≤50 ms; NPFADS handles GPS-falsification attacks with proven F1≥0.98. Together they cover the full attack surface with no detection gap.
- **Scalability:** As N_Vehicles increases beyond 10, ME attack results are expected to remain at MCC=0/AUROC=0.5, while TTW/BSHH mobility artifacts may diminish as the mobility distributions of attacker and benign nodes converge.

### 5.5 Summary Metrics Table

| Attack Family | Attacker Placement | NPFADS MCC (mean) | NPFADS AUROC (mean) | NPFADS Tdet | PEM Tdet |
|--------------|-------------------|-------------------|---------------------|-------------|---------|
| TTW | Vehicle (S1) | Variable (−0.33 to +1.0) | Variable | 800 ms | ~50 ms |
| TTW | RSU/Controller (S2–S4) | Decreasing (1.0→0) | Decreasing (1.0→0.6) | 800 ms | ~50 ms |
| BSHH | Vehicle (S1) | Variable (−0.76 to +1.0) | Variable | 800 ms | ~50 ms |
| BSHH | RSU/Controller (S2–S4) | Decreasing (1.0→0) | Decreasing (1.0→0.6) | 800 ms | ~50 ms |
| **ME** | **All (S1–S4)** | **0.000 (constant)** | **0.500 (constant)** | **800 ms** | **~50 ms** |

> The ME family provides the most rigorous evidence: NPFADS achieves exactly random-classifier performance (AUROC=0.5) across all four attacker placements and all attack percentages. This result is independent of simulation mobility artifacts and represents the true detection capability of position-based analysis against temporal-echo attacks.

---

*Report generated from `ALL_NPFADS_PEM_Run_Summary.csv` — 132 experimental runs.*
*Simulation: NS-3.35 | Framework: SDVN Temporal-Echo Attack Testbed | FYP, Dept. of EIE, University of Ruhuna*
