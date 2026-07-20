# TGN Decision Threshold (θ) Calibration — Controlled Sweep Results

**Model:** `tgn_weights_sim60_ap60_3seeds.bin` (dim=128, layers=2)
**Method:** Live NS-3 deployment runs (not offline test-set reconstruction), `simTime=60`, `N_Vehicles=200`, fixed **unseen** seed `RngRun=999` (not used in training/validation/test data generation — genuinely out-of-sample), same seed held constant across all θ values within each scenario so differences are attributable to θ alone.
**θ values tested:** 0.65, 0.75, 0.85, 0.90, 0.941, 1.0
**Note:** the PDF specifies only the *methodology* (sweep thresholds, select by validation MCC) — it does not mandate a specific numeric θ. All values below are empirically derived, not PDF-prescribed constants.

---

## Per-scenario MCC by θ

| Scenario | θ=0.65 | θ=0.75 | θ=0.85 | θ=0.90 | θ=0.941 | θ=1.0 | **Best θ (MCC)** |
|---|---|---|---|---|---|---|---|
| 1 — TTW-S1 | 0.870 | **0.923** | 0.898 | 0.871 | 0.816 | 0.000 | **0.75 (0.923)** |
| 2 — TTW-S2 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | **0.65–0.941 (tie, 1.000)** |
| 3 — TTW-S3 | — | — | — | — | — | — | *not run in this batch* |
| 4 — TTW-S4 | 1.000 | 1.000 | 1.000 | 1.000 | 0.969 | 0.000 | **0.65–0.90 (tie, 1.000)** |
| 5 — BSHH-S1 | 0.705 | 0.705 | 0.896 | 0.896 | **0.932** | 0.000 | **0.941 (0.932)** |
| 6 — BSHH-S2 | 0.174 | 0.202 | 0.690 | **0.910** | 0.862 | 0.000 | **0.90 (0.910)** |
| 7 — BSHH-S3 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | **0.65–0.941 (tie, 1.000)** |
| 8 — BSHH-S4 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | **0.65–0.941 (tie, 1.000)** |
| 9 — ME-S1 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | *degenerate — 0 attack events at this seed/duration, θ-insensitive* |
| 10 — ME-S2 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | *degenerate — 0 events at all, θ-insensitive* |
| 11 — ME-S3 | **1.000** | 0.872 | 0.872 | 0.775 | 0.697 | 0.000 | **0.65 (1.000)** |
| 12 — ME-S4 | **0.775** | 0.775 | 0.697 | 0.632 | 0.632 | 0.000 | **0.65–0.75 (tie, 0.775)** |
| 13 — Combined (all 12) | 0.692 | 0.735 | 0.762 | 0.781 | **0.788** | 0.000 | **0.941 (0.788)** — TGN-alone `[beh]`; `[comb]` LW-OR-TGN reaches 0.811 at 0.941 |

`θ=1.0` is a degenerate edge case everywhere (nothing can ever score ≥1.0 from a sigmoid in practice) — included per request, uniformly collapses TP→0, MCC→0 across every scenario. Not a usable deployment value.

---

## Global θ across the 12 individual scenarios only

Criterion: **worst-case MCC** (the scenario that performs worst at a given θ) — the right criterion for real deployment, since the detector never knows in advance which attack family it's facing (see prior discussion this session on why per-scenario θ selection is not deployable). Scenarios 9 and 10 excluded from this calculation — both are structurally degenerate (0 or near-0 events at this seed/duration) and contribute no signal regardless of θ. Scenario 3 excluded — not run in this controlled batch.

| θ | Worst-case MCC | Worst scenario | Average MCC (9 scenarios) |
|---|---|---|---|
| 0.65 | 0.174 | BSHH-S2 | 0.836 |
| 0.75 | 0.202 | BSHH-S2 | 0.831 |
| **0.85** | **0.690** | BSHH-S2 | 0.895 |
| 0.90 | 0.632 | ME-S4 | **0.898** |
| 0.941 | 0.632 | ME-S4 | 0.879 |

**Best by worst-case: θ = 0.85** (worst-case MCC 0.690, more than 3x better than θ=0.65/0.75's worst-case of ~0.17–0.20). θ=0.90 has a marginally higher average (0.898 vs 0.895) but a meaningfully worse worst-case (0.632 vs 0.690) — worst-case is the more important property for deployment robustness, so 0.85 is the better choice overall.

---

## Global θ across all 12 individual scenarios + combined scenario 13

Adding scenario 13's `[beh]` MCC column into the same worst-case comparison:

| θ | Worst-case MCC (incl. S13) | Worst scenario |
|---|---|---|
| 0.65 | 0.174 | BSHH-S2 |
| 0.75 | 0.202 | BSHH-S2 |
| **0.85** | **0.690** | BSHH-S2 |
| 0.90 | 0.632 | ME-S4 |
| 0.941 | 0.632 | ME-S4 |

Including scenario 13 does not change the bottleneck or the ranking — BSHH-S2 (individual) / ME-S4 (individual) remain the binding constraints at every θ, and scenario 13 itself never scores below either of them at any tested θ. **θ = 0.85 remains the best choice** with or without the combined scenario included.

---

## Recommended optimized θ: **0.85**

This is the same value already in use as the deployment default. Justification, consolidated:

1. **Best worst-case MCC** (0.690) among all tested values, both with and without scenario 13 included — more than 3x better than θ=0.65/0.75, and clearly ahead of θ=0.90/0.941 (0.632).
2. **Near-best average MCC** (0.895, within 0.003 of the peak at θ=0.90) — the small average-case cost of choosing 0.85 over 0.90 is far outweighed by the worst-case robustness gain.
3. **Confirmed on genuinely unseen data** — this sweep used `RngRun=999`, never part of training/validation/test generation, with the same seed held fixed across all θ values for a clean, controlled comparison. This is a stronger evidence base than the earlier offline test-set sweep (which was reconstructed from the training CSV's own held-out split and gave a conflicting recommendation of θ≈0.65 — that result should be treated as superseded by this live, controlled, out-of-sample sweep).
4. **BSHH-S2 remains the persistent bottleneck** at every θ tested — consistent with this session's extensive prior investigation (sophisticated credential-bypass sub-mode, a confirmed architectural limitation rather than a threshold-tunable issue; see prior findings on `identity_mismatch`/`tau_dev` feature indistinguishability for that specific attack sub-mode).

## Known gaps in this analysis (for follow-up, not blocking)

- **Scenario 3 (TTW-S3) was not included in this controlled batch** — should be re-run at the same `RngRun=999` across the same θ grid to close this gap.
- **Scenarios 9 (ME-S1) and 10 (ME-S2) produced 0–4 total events** at this seed/duration — consistent with the previously-documented architectural gap (crypto pre-filter interception eliminating vehicle/RSU-origin ME events before they reach the detector). These scenarios contribute no signal to θ selection at this configuration and would need a longer `simTime` or different seed to meaningfully evaluate.
