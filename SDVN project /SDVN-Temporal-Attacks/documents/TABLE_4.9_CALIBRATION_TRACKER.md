# Table 4.9 Calibration Tracker

Master tracker mirroring **Table 4.9** ("Empirically calibrated parameters,
post NS-3/SUMO and TGN training") in `Temporal_echo_project (30).pdf`
(pages 123-129), **same section order (A-G) and same row order** as the PDF.
Update this file each time a parameter's calibration run completes — one row
at a time, evidence attached, so the whole table stays an accurate live
record of what's actually been measured vs. what's still a PDF placeholder.

**Status legend:** ✅ calibrated (evidence below) · 🟡 in progress (sweep
running) · ⬜ not started · ➖ already fixed by design in the PDF (concrete
value given, not marked TBD — no calibration sweep needed)

---

## A. Detection Threshold Parameters

### 1. LW alert threshold (θ_LW)

**PDF default:** not set, determined post-training. **PDF calibration
method:** grid search over [0,1] in steps of 0.05 on the validation split,
select value maximizing **F1 score**.

**Status: 🟡 in progress.** 21-value grid (0.00 → 1.00, step 0.05) running
via `--lw_threshold` flag (added this session — was previously a hardcoded
`PEM_SCORE_THRESHOLD` constant, `routing.cc:2100`), on `attack_scenario=13`
(combined), `N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 RngRun=1`,
selecting by `f1_macro` per the PDF's spec. Script: `/tmp/lw_threshold_sweep_f1.sh`.

**Calibrated value:** *(fill in once sweep completes — top-5 by f1_macro
printed at end of script)*

---

### 2. FS anomaly score threshold (θ_FS)

**PDF default:** not set, determined post-training. **PDF calibration
method:** sweep sigmoid output thresholds on the validation set, select value
maximizing **MCC** under class imbalance.

**Status: ✅ DONE.** Corresponds to the `--tgn_theta` flag.

**Calibrated value: θ_FS = 0.85**

**Evidence** (full detail in `theta_calibration_results.md`):
- Method: live NS-3 deployment sweep (not offline test-set reconstruction),
  `tgn_weights_sim60_ap60_3seeds.bin` (dim=128, layers=2), `simTime=60`,
  `N_Vehicles=200`, unseen seed `RngRun=999` (not used in
  train/val/test generation), held fixed across all θ values tested.
- θ values tested: 0.65, 0.75, 0.85, 0.90, 0.941, 1.0 — across all 12
  individual attack scenarios + combined scenario 13.
- Selection criterion: **worst-case MCC** across scenarios (the right
  criterion for deployment — the detector doesn't know in advance which
  attack family it's facing), scenarios 9/10 excluded as structurally
  degenerate (0 attack events at this seed/duration).
- Result: θ=0.85 gives worst-case MCC **0.690** (bottleneck: BSHH-S2), more
  than 3x better than θ=0.65/0.75 (worst-case ~0.17-0.20), and better
  worst-case than θ=0.90/0.941 (0.632) despite θ=0.90 having a marginally
  higher *average* MCC (0.898 vs 0.895 — a 0.003 difference not worth the
  worse worst-case).
- Confirmed unchanged whether or not combined scenario 13 is included in the
  comparison.
- BSHH-S2 is the persistent bottleneck at every θ tested — this is a
  separately-documented architectural limitation (sophisticated
  credential-bypass sub-mode), not something a threshold change can fix; see
  `SESSION_SUMMARY_handoff.md` §7.

**No further action needed on θ_FS** — do not re-sweep without new evidence
(e.g. a retrained model, since θ_FS is model-dependent).

---

### 3. TGN edge-weight decay rate (γ)

**PDF default:** set so `A_uv(t) ≈ 0.5` at report age `L_link/2`
(formula-derived per speed). Per **Table 3.2** (TGN training
hyperparameters): `L_link = 43s (urban) / 9s (highway)` →
`γ = auto: L_link/(2·T_b·ln2)` → urban γ≈310, highway γ≈65. **PDF
calibration method:** verify on NS-3 traces that TTW-replayed edges receive
near-zero weight; tune if detection accuracy drops below target.

**Correction to a prior internal doc:** `TGN_IMPLEMENTATION_GUIDE.md` §17
additionally lists a "rural ≈25s / γ≈180" row — this value does **not**
appear anywhere in the PDF (searched the full 170-page text for "rural":
zero matches). The PDF only defines urban and highway; "rural" appears to be
a locally-extrapolated value from earlier development work, not a
PDF-sourced constant. Also note the PDF's own text (§4.1) states highway
conditions are "analysed within the mobility model... but lie outside the
current NS-3/SUMO evaluation scope" — so even the highway value (γ≈65) is a
table default, not something the PDF's own evaluation actually ran.

**Status: ⚠️ verification attempted — PDF's stated check does not hold
(documented finding, not a tunable-parameter gap).**

Checked directly against real training data
(`training_data/sim60_ap60_3seeds_events.csv`, γ=310 urban default, all 1052
TTW attack-labeled events):

```
edge_freshness (A_uv) for TTW attack rows:
  min=0.9923  max=1.0000  mean=0.9967  median=0.9949
  count <0.1: 0        count >0.9: 1052 (all of them)
```

**The PDF's verification requirement — "TTW-replayed edges receive
near-zero weight" — fails as literally stated, for any γ.** `A_uv(t) =
exp(-(τ_r-τ_s)/(γ·T_b))` measures timestamp *recency*
(`tgn_core.cc:433`). TTW's attack model works by forging
`sender_timestamp = now()` — the attack's entire mechanism is to make the
replayed packet appear freshly sent, so `τ_r - τ_s ≈ 0` and `A_uv ≈ 1`
regardless of γ. Decreasing γ to force this toward zero would also push
every *benign* edge toward zero (rx_delay is ~0 for nearly all events, not
just TTW), destroying the signal entirely rather than isolating the attack.
This is a mismatch between what A_uv physically measures and what the PDF's
verification prose assumes it measures — not a value of γ that can resolve
it.

Detection is **not** actually broken by this (TTW-S1 still scores MCC=1.0
overall) — the mechanism that catches TTW is the per-node GRU temporal
memory discontinuity (`tgn_core.cc:605` comment), not the edge-freshness
weight. γ=310 (formula-derived, `A_uv≈0.5` at `L_link/2`) remains in active
use as the default since nothing in this check suggests it should change;
this section exists to honestly record that the PDF's specific verification
method for γ doesn't apply to this attack model, rather than silently
skipping it or claiming a false pass.

Still open: highway/rural γ values (γ≈65, γ≈180) remain analytical
estimates, unverified against real highway/rural trace data — blocked on
generating that data first, see `TGN_HYPERPARAMETER_CALIBRATION.md` §4
item 3.

---

## B. LW Signature Weights (w1-w9, Eq. 3.12)

**PDF default (all 9):** `1/9 ≈ 0.111` (uniform, calibration-neutral
baseline) — matches `PEM_WEIGHTS[]` in `routing.cc` currently. **PDF
calibration method (all 9):** recalibrate proportionally to each signature's
observed FP rate on **real-network data**, maintaining `Σw_k = 1, w_k ≥ 0`.

**Status: ⬜ not started (all 9).** The PDF's own prose (§3.4.2, quoted in
this session's earlier discussion) explicitly ties this recalibration to
*real-network* deployment where non-zero FP rates are expected — the current
NS-3/SUMO simulation observes a **zero FP rate across all nine signatures**
(MCC=1.0, AUROC=1.0), so there is no FP-rate signal yet to recalibrate
against. This is a documented, PDF-anticipated future-work item, not a gap
in the current simulation phase.

| # | Weight | Signature | Status |
|---|---|---|---|
| 1 | w1 | TTW-S1: topology state persistence anomaly (Eq. 3.2) | ⬜ not started |
| 2 | w2 | TTW-S2: timestamp-topology age inconsistency (Eq. 3.3) | ⬜ not started |
| 3 | w3 | TTW-S3: cross-reporter inconsistency (Eq. 3.4) | ⬜ not started |
| 4 | w4 | BSHH-S1: duplicate liveness assertion (Eq. 3.5) | ⬜ not started |
| 5 | w5 | BSHH-S2: timestamp regression / replay (Eq. 3.6) | ⬜ not started |
| 6 | w6 | BSHH-S3: liveness-beacon inconsistency (Eq. 3.7) | ⬜ not started |
| 7 | w7 | ME-S1: reporter count excess (Eq. 3.8) | ⬜ not started |
| 8 | w8 | ME-S2: path diversity inflation (Eq. 3.9) | ⬜ not started |
| 9 | w9 | ME-S3: reporter range/signal inconsistency (Eq. 3.11) | ⬜ not started |

---

## C. Sliding Window & Observation Window Parameters

### LW detector max window size (W_max)

**PDF default:** `⌈L_link/T_b⌉` intervals; urban≈430, highway≈90. **PDF
calibration method:** increase until no TTW-S2 cross-interval misses;
decrease until TTW-S3 false positives from departed vehicles disappear.

**Status: ⬜ not started.**

### BSHH-S3 liveness observation window (W_BSHH)

**PDF default:** `W > 2·W_ho` (formula-derived). **PDF calibration method:**
confirm `W > W_ho` prevents handover false positives; validate BSHH-S3 still
fires before the stale heartbeat expires.

**Status: ⬜ not started.**

---

## D. Physical and Signal Consistency Parameters

### Max propagation tolerance / freshness bound (ε, Eq. 3.16)

**PDF default:** not set, conceptually ≈ one-way propagation delay. **PDF
calibration method:** measure 95th-percentile one-way latency from NS-3
simulation logs; set ε equal to this value.

**Status: ⬜ not started.** Current live value is `PEM_PROPAGATION_EPSILON_S
= 0.020` (20ms, `routing.cc:2097`) — a placeholder kept in sync with
`teta_guard_types.h`'s `PROPAGATION_TOL_MS`, not yet derived from a measured
95th-percentile latency distribution.

### Detection formula range (r_comm)

**Status: ➖ already fixed by design.** PDF value: 300m design bound /
282.2m NS-3 Ch.178 effective range (COST-231 Hata propagation @ 44dBm) — both
values already in active use (300m for ME-S1 ρ_max / ME-S3 range check
analytical formulas; 282.2m for NS-3-trace-derived results). No sweep needed.

### Minimum RSSI threshold (RSSI_min, Eq. 3.31)

**Status: ➖ already fixed by design.** PDF value: -85 dBm default,
derived from the NS-3 propagation model at r_comm. No sweep needed.

### Inter-lane density margin (µ, ME-S1, Eq. 3.8)

**PDF default:** 0.20 (recommended default). **PDF calibration method:**
increase if urban runs produce false positives on legitimate multi-lane
observers; decrease to improve sparse-traffic sensitivity.

**Status: ⬜ not started.** `PEM_ME_TOLERANCE_MU = 0.20` (`routing.cc:2099`)
is in active use at the PDF's recommended default; no FP-driven tuning done
yet (consistent with the zero-FP-rate simulation phase noted in §B above).

---

## E. Trust Management Parameters

**Status: ➖ all already fixed by design.** Every parameter in this section
already has a concrete PDF "Empirical Value" (not TBD) — these are
Hyperledger Fabric chaincode constants already deployed at their listed
values, not simulation-side hyperparameters requiring a sweep:

| Parameter | Symbol | Value |
|---|---|---|
| Controller trust penalty per confirmed divergence | ∆C⁻ | 0.20 |
| Node admission / consensus-participation floor | τ_min | 0.10 |
| Ground-truth / bootstrap-completion threshold | τ_min^gt | 0.50 |
| Bootstrap phase duration | R_min | 8 rounds |
| Controller reassignment trust threshold | τ_min^C | 0.30 |
| OBU minimum dwell time before eligibility | T_min^dwell | 3000 ms |
| OBU minimum hardware capacity | — | 2048 MB RAM |
| RSU peer quarantine monitoring window | T_quar | 30,000 ms |
| Periodic peer re-selection interval | T_prs | T_b = 100 ms |

---

## F. TGN Model Hyperparameters

### TBPTT window size per node (W_BPTT)

**PDF default:** 100 (per-node event counter, detach after W_BPTT events).
**PDF calibration method:** sweep {50, 100, 200} events per node on
validation MCC.

**Status: ⬜ not started.**

### GRU total input dimension (d_in)

**Status: ➖ already fixed by design.** PDF value: 38 (=32+5+1), fixed by
architecture after the feature-vector revision (tau_dev replacing absolute
tau_s). No sweep — this is a structural constant, not a tunable
hyperparameter.

### Score-separation margin weight (λ_m, Eq. 3.27 term iii)

**Status: ➖ already fixed by design.** PDF value: 0.50, fixed unless
term (iii) is found to dominate gradient magnitude (a diagnostic condition,
not a routine sweep).

### Score-separation margin threshold (m, Eq. 3.27 term iii)

**Status: ➖ already fixed by design.** PDF value: 0.35, fixed unless score
collapse or non-convergence is observed.

### Training restart convergence target (MCC_target)

**Status: ➖ already fixed by design.** PDF value: 0.975, max 5 restart
attempts. Matches `tgn_train.py`'s `TARGET_VAL_MCC=0.975` default exactly.
Note: this session added a `--max_restarts` override (default still 5,
unchanged from PDF) purely to speed up *hyperparameter sweep* runs that
don't need the full 5-attempt search each time — see
`TGN_HYPERPARAMETER_CALIBRATION.md` §1. The PDF-specified default of 5
remains untouched for final/deployed model training.

### Message-passing rounds (L, Eq. 3.24)

**PDF default:** 2 (Table 4.1). **PDF calibration method:** test
L ∈ {1,2,3}; select by validation MCC.

**Status: ⬜ not started.** Planned as `TGN_HYPERPARAMETER_CALIBRATION.md`
§4 item 1 (layers sensitivity), pending completion of the dim/pos_weight
sweeps currently running.

### Node feature embedding dimension (d, Eq. 3.20)

**PDF default:** not specified. **PDF calibration method:** evaluate
d ∈ {32,64,128}; select by validation MCC; match GRU hidden-state size to d.

**Status: 🟡 in progress.** Running as `TGN_HYPERPARAMETER_CALIBRATION.md`
§3b (dim ∈ {64,192} × 6 seeds each, vs. existing dim=128 × 6-seed anchor).
Note the PDF's grid is {32,64,128} — the current sweep uses {64,128,192}
instead (dim=32 not yet tested in the current sim60_ap60_3seeds dataset;
dim=192 added because dim=128 was already the established anchor from prior
sessions). Flag for follow-up: add a dim=32 arm if strict PDF-grid
compliance is required for the final report.

**Calibrated value:** *(fill in once §3b completes)*

### GRU hidden-state size (h_GRU, Eq. 3.23)

**Status: ➖ tied to d by design.** PDF: "match to d by default; tune
separately only if temporal memory update over-fits relative to embedding
dimension" — a diagnostic condition, not a routine sweep. Will inherit
whatever `d` is chosen above unless over-fitting is separately observed.

### Optimiser learning rate (η)

**PDF default:** not specified; start at 1e-3, reduce on plateau, cosine
annealing for stability. **Status: ⬜ not started.** Current default
`--lr 0.001` (matches PDF's starting point) with `CosineAnnealingLR`
scheduling already implemented (`tgn_train.py`) — the PDF's suggested
schedule is already in place; no separate rate-*value* sweep has been run
yet.

### Class imbalance weight (benign vs. attack ratio, w_class)

**PDF default:** binary cross-entropy with class-weight balancing
(qualitative). **PDF calibration method:** compute from the training split
as `w_attack = total/(2·n_attack)`, recompute after each split.

**Status: 🟡 in progress, with a methodology note.** This corresponds to
the `--pos_weight_override` flag / `TGN_HYPERPARAMETER_CALIBRATION.md` §3a
sweep (pos_weight ∈ {4,4.5,5,5.5,6,6.5,7}). **Important distinction:** the
PDF's formula computes a single *dynamic* ratio from the actual train-split
imbalance (this is `tgn_train.py`'s default behavior when
`--pos_weight_override` is *not* passed — logged as `[dynamic ratio]` vs.
`[override]` in training output). The current sweep instead tests fixed
*override* values independently of that ratio, to see whether deviating from
the exact empirical ratio trades recall/precision favorably — this is a
superset investigation of the PDF's method, not a replacement for it. Once
the sweep's winning override value is found, compare it against the
dynamic-ratio baseline (already run, unseeded) to confirm the override
actually beats the PDF-prescribed formula before adopting it as final.

**Calibrated value:** *(fill in once §3a completes)*

### Train / validation / test split

**Status: ➖ already fixed by design.** PDF value: 70/15/15, already the
active default in `tgn_train.py`. No sweep needed — PDF only requires
confirming no class leakage across splits, especially for time-ordered
scenarios (not yet explicitly audited, but no evidence of leakage found in
any run's train/val/test event counts to date).

---

## G. Consensus and Quorum Parameters

### Threshold aggregate signature majority (t, Eq. 3.28, Eq. 3.32)

**PDF default:** `t ≥ ⌊n/2⌋ + 1` (strict majority). **PDF calibration
method:** confirm n from SUMO density traces; recompute t; verify no
single-vehicle or sub-quorum collusion forges a valid aggregate report.

**Status: ⬜ not started.**

### Vehicles per RSU reporting (n)

**PDF default:** varies with λ and r_comm. **PDF calibration method:**
extract min/max/mean from SUMO mobility traces.

**Status: ⬜ not started.**

*(Table 4.9 continues beyond this point in the PDF — remaining rows to be
added here if/when work on them begins.)*

---

## Summary — what's actually actionable right now

| Status | Count | Items |
|---|---|---|
| ✅ Done | 1 | θ_FS = 0.85 |
| 🟡 In progress | 3 | θ_LW (sweep running), dim d (sweep running), class imbalance weight (sweep running) |
| ⚠️ Checked, PDF check doesn't hold | 1 | γ (urban value unchanged; TTW-replayed edges do NOT reach near-zero weight, structurally can't for any γ — documented finding) |
| ⬜ Not started | ~15 | w1-w9, W_max, W_BSHH, ε, µ, W_BPTT, L (layers), η, t, n |
| ➖ Fixed, no sweep needed | ~13 | r_comm, RSSI_min, all of §E (trust mgmt), d_in, λ_m, m, MCC_target, h_GRU, train/val/test split |

Cross-reference: detailed run commands and per-run evidence for the three
🟡 items live in `TGN_HYPERPARAMETER_CALIBRATION.md` (dim, class-imbalance
weight) and this file's §A.1 (θ_LW).
