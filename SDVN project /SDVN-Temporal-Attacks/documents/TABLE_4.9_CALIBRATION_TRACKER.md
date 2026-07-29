# Table 4.9 Calibration Tracker

Master tracker mirroring **Table 4.9** ("Empirically calibrated parameters,
post NS-3/SUMO and TGN training") in `Temporal_echo_project (31).pdf`
(printed pages 124-131), **same section order (A-H) and same row order** as
the PDF. Table 4.9 continues into **§H (Blockchain and Trust Update
Parameters)** beyond the A-G sections originally transcribed here — only
the "Anchor checkpoint interval" row of §H has been added so far (below);
the remaining §H rows (δ_thresh(t), Δ+, Δ-, τ0, K, T_exec, τ_RSU,0, orderer
batch timeout/size, channel endorsement policy) are not yet in this tracker.
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

**Status: ✅ DONE.** Full 21-point grid (0.00 → 1.00, step 0.05) completed
via `--lw_threshold` flag (`routing.cc:2154`, `PEM_SCORE_THRESHOLD` — was a
hardcoded constant, now runtime-overridable), on `attack_scenario=13`
(combined), `N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 RngRun=1`,
with the TGN half of the pipeline held fixed at the already-calibrated
θ_FS=0.85 (`--tgn_weights=tgn_weights_sim60_ap60_3seeds.bin --tgn_theta=0.85
--tgn_l_link=43.0 --tgn_dim=128 --tgn_layers=2`) so only θ_LW varied. Full
results: `/tmp/lw_sweep_results.csv`, per-run logs `/tmp/lw_sweep_*.log`.

**Methodology correction found during this run:** the PDF's spec says
"select by F1 score," and the earlier (incomplete) sweep attempt used the
`f1_macro` CSV column for this — but that column is the **TGN variant
classifier's** F1 (TTW vs BSHH vs ME), a fixed property of the trained
model that does not respond to θ_LW at all (it printed the identical value,
0.808012, at all 21 grid points — confirmed not a live signal). The
correct metric is the **binary detection F1** (attack alerted vs not),
`F1 = 2·tp / (2·tp + fp + fn)`, computed directly from the tp/fp/fn columns
since no ready-made column exists for it.

**Results (binary detection F1, correctly computed):**

| θ | tp | fp | fn | mcc | f1 (binary) |
|---|---|---|---|---|---|
| 0.00–0.10 | 351 | 2 | 49 | **0.9217** | **0.9323** |
| 0.15–0.20 | 92 | 3 | 308 | 0.4352 | 0.3717 |
| 0.25 | 18 | 0 | 382 | 0.1936 | 0.0861 |
| 0.30–0.35 | 14 | 0 | 386 | 0.1706 | 0.0676 |
| 0.40–1.00 | 0 | 0 | 400 | 0.0000 | 0.0000 |

θ ∈ [0.00, 0.10] is a flat plateau (identical tp/fp/fn/mcc/f1 across all
three grid points); detection collapses sharply from θ=0.15 onward and is
dead (tp=0) by θ=0.40.

**Calibrated value: θ_LW = 0.05** — plateau-midpoint method (same method
already used for θ_FS, see §A.2), selected as the midpoint of the winning
[0.00, 0.10] plateau rather than an edge value, for robustness to small
future shifts in the score distribution.

**No code change required** — the code's existing hardcoded default
(`PEM_SCORE_THRESHOLD = 0.075`, `routing.cc:2154`) already falls inside
this same optimal plateau. This sweep converts that from an untested guess
into an evidence-backed value; the constant itself does not need editing.

**Per-scenario worst-case re-verification (2026-07-23):** the combined-run
result above averages across all 12 families, which could mask one family
doing badly at θ=0.05 while others compensate — same concern that drove
θ_FS's own worst-case-across-scenarios methodology (§A.2). Re-swept
θ ∈ {0.00, 0.05, 0.10, 0.15} against **each of the 12 individual
scenarios**, same config, RngRun=1:

| Scenario | tp/fp/fn @ θ=0.00-0.10 | mcc @ 0.00-0.10 | @ θ=0.15 |
|---|---|---|---|
| 1 TTW-S1 | 63/0/0 | 1.000 | unchanged (63/0/0) |
| 2 TTW-S2 | 51/0/0 | 1.000 | unchanged (51/0/0) |
| 3 TTW-S3 | 17/0/0 | 1.000 | unchanged (17/0/0) |
| 4 TTW-S4 | 17/0/0 | 1.000 | unchanged (17/0/0) |
| 5 BSHH-S1 | 55/0/0 | 1.000 | **collapses**: 0/3/55, mcc=-0.060 |
| 6 BSHH-S2 | 50/0/0 | 1.000 | **collapses**: 0/2/50, mcc=-0.017 |
| 7 BSHH-S3 | 32/0/0 | 1.000 | **collapses**: 0/0/32, mcc=0 |
| 8 BSHH-S4 | 32/0/0 | 1.000 | **collapses**: 0/0/32, mcc=0 |
| 9 ME-S1 | 1/0/0 | 1.000 | **collapses**: 0/0/1, mcc=0 |
| 10 ME-S2 | 0/0/0 | (degenerate — 0 attack events this seed/duration, unrelated to θ) | unchanged |
| 11 ME-S3 | 17/0/3 | 0.697 (fn=3 pre-existing, threshold-independent, unrelated to θ) | unchanged |
| 12 TTW-S4/ME-S4* | 19/0/1 | 0.872 (fn=1 pre-existing, unrelated to θ) | **collapses**: 0/0/20, mcc=0 |

\* scenario 12 = ME-S4 per the enum in this codebase.

**Conclusion: θ ∈ [0.00, 0.10] is worst-case-safe across all 12/12
individual scenarios** — none degrade in this range, matching the combined
run. **θ=0.15 is a hard cliff** for 6 of the 12 families (5,6,7,8,9,12),
several dropping to zero true positives and two (5, 6) even flipping to
*negative* MCC. This is strong evidence θ=0.05 has real margin, not just a
lucky combined-average pick. Scenarios 10 and 11 have pre-existing,
threshold-independent gaps (structurally degenerate / fn=3) — flagged as
separate open issues, not θ_LW calibration problems.

**SUPERSEDED (2026-07-29) — re-calibrated for the 170m-patch w1-w9
weights.** The θ_LW=0.05 result above was calibrated against the *old*
w1-w9 weights (pre-170m-patch). Once w1-w9 were re-measured under the new
ρ_max/δ_thresh formulas (§B below), θ_LW needed its own fresh sweep
against the new weighted-score distribution — same rule this project has
applied to every parameter whose input formula changed (θ_FS after each
model swap, etc.).

**Methodology**: full-range grid sweep `{0.00,...,1.00}` step 0.05
(coarse) + targeted fine sweep, `--no_tgn=1` (isolates LW's own decision
— without it, TGN's much stronger post-retrain performance completely
masked θ_LW's effect: every coarse point gave an identical combined MCC
regardless of θ_LW), `simTime=60`, `N_Vehicles=200`, `N_RSUs=64`(RSU
scenarios)/`0`, `attack_percentage=40`, `RngRun=999`, individual
scenarios 1-12 only (**scenario 13 dropped** — costs 30-65+ minutes per
point for zero scoring benefit, since its output is a single blended
tp/tn/fp/fn with no per-family breakdown; see §B below for the full
reasoning). MCC computed directly from `PEM_EVENT_LOG`'s per-event
`attack_label`/`alert_raised` (not `TGN_SUMMARY`'s `mcc`/`comb_mcc` —
both broken under `--no_tgn=1`; see §3i of
`TGN_HYPERPARAMETER_CALIBRATION.md` for the full explanation). Selection
criterion **switched to maximize average MCC** (not worst-case) for
θ_LW/µ specifically, per explicit instruction — tiebreak: highest θ
among ties, not lowest.

**Coarse result**: flat plateau avg_mcc=0.5605 at θ∈{0.00,0.05,0.10}
(worst-case bottleneck sc5/BSHH-S1, mcc=-0.105), sharp drop to 0.3266 at
0.15-0.20, continuing to decay with a small secondary bump at 0.40-0.45
(avg=0.0608).

**Fine sweep caught a real methodological trap**: (0.10,0.15) initially
showed θ=0.12 at avg=0.6128 — apparently better than the whole coarse
plateau — but this was an artifact: at θ=0.12, sc7 (BSHH-S3) and sc8
(BSHH-S4) both collapsed to zero true positives (`tp=0` despite 14,000+
real attack events, every one missed) — a genuine detection failure, not
"no signal to measure" like ME-S1/S2's exclusion. Their MCC became
undefined and got silently dropped from the average (n=8 instead of the
correct n=10), hiding a total collapse and making θ=0.12 look like an
improvement. Caught by comparing the reported `n=` scenario count
between fine-sweep points and confirmed via same-seed re-run
(reproducible, not noise).

**Result: θ_LW = 0.11** — the honest, fully-10-scenario plateau value.
θ=0.12 explicitly rejected. **Code updated**: `PEM_SCORE_THRESHOLD`
(`routing.cc`) changed from 0.075 to **0.11**, rebuilt.

---

### 2. FS anomaly score threshold (θ_FS)

**PDF default:** not set, determined post-training. **PDF calibration
method:** sweep sigmoid output thresholds on the validation set, select value
maximizing **MCC** under class imbalance.

**Status: ✅ DONE (re-calibrated).** Corresponds to the `--tgn_theta` flag.

**Calibrated value: θ_FS = 0.92** (supersedes both the θ_FS=0.95 and θ_FS=0.85 picks below)

**Evidence** (2026-07-24 fine re-sweep, dim=192 canonical model, all 13 scenarios):
- Method: live NS-3 deployment sweep, `tgn_weights_dim192_final.bin`
  (dim=192), `simTime=30`, `N_Vehicles=200`, `N_RSUs=64`/`0` per scenario,
  `attack_percentage=50`, unseen seed `RngRun=999`, `--no_lw=1` ablation
  (same isolation rationale as the 2026-07-23 round below). **All 13
  scenarios included this time** — the 2026-07-23 round's "Scenario 3 not
  run" gap is closed.
- θ values tested: 0.90, 0.91, 0.92, ..., 0.99, 1.00 (11 points, 0.01
  granularity — finer than the 0.05-step 2026-07-23 grid, specifically to
  check whether a tighter optimum existed between 0.90 and 0.95 that the
  coarser grid could have missed).
- Selection criterion: **worst-case MCC**, excluding ME-S1/S2 (scenarios
  9/10 — re-confirmed this round: sc10 had 0 total attack events, sc9 had 2,
  at *every* θ tested, Stage-0 crypto pre-filter interception, θ-insensitive).
- Result: **θ=0.91 and θ=0.92 tied for best worst-case MCC (0.613,
  bottleneck: ME-S3/scenario 11)**. Tiebreak on average MCC across the 11
  included scenarios: θ=0.92 → 0.7169 vs θ=0.91 → 0.7075 — θ=0.92 wins.
  This **improves on 2026-07-23's θ=0.95 pick** (worst-case MCC 0.554, also
  bottlenecked at ME-S3) by ~10.6% relative — the coarser grid (0.90, 0.941,
  1.0 tested; 0.91-0.94 and 0.96-0.99 never evaluated) missed this tighter
  optimum sitting just below 0.95.
- ME-S3 (scenario 11) is the persistent bottleneck across the 0.85-era,
  0.95-era, and this round's analysis — worth flagging as a candidate for
  the same kind of architectural investigation BSHH-S2 received below,
  rather than expecting further threshold tuning alone to close it further.
- Full per-θ, per-scenario breakdown: `theta_calibration_results.md`'s
  "2026-07-24 Re-calibration" section; raw data under `~/theta_calib/`;
  aggregation script `documents/ablation_scripts/aggregate_theta_calib.py`.
- Applied in code: `tgn_core.cc`'s `TGN_THETA_FS` constant, 0.95 → 0.92.

**No further action needed on θ_FS** at this model — do not re-sweep without
new evidence (e.g. a retrained model, since θ_FS is model-dependent).

---

**[SUPERSEDED] 2026-07-23 re-sweep — θ_FS = 0.95**

**Evidence** (2026-07-23 re-sweep, dim=192 canonical model):
- Method: live NS-3 deployment sweep, `tgn_weights_dim192_final.bin`
  (dim=192, layers=2), `simTime=60`, `N_Vehicles=200`, `N_RSUs=64`,
  unseen seed `RngRun=999`, **`--no_lw=1` ablation** — LW disabled so
  θ_FS's effect on TGN's own decision is visible. The original 0.85 pick
  was measured with LW enabled, where LW's `alert_raised || tgn_alert`
  OR-combination masks TGN's standalone sensitivity to θ (LW alone already
  saturates detection in most scenarios post this session's LW fixes).
- θ values tested: 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 1.0 — across
  all 12 individual attack scenarios + combined scenario 13.
- Selection criterion: **worst-case MCC** across scenarios, excluding
  ME-S1/S2 (scenarios 9/10, mcc=0 at every θ — confirmed to be a crypto-layer
  drop artifact upstream of TGN, not θ-sensitive) and scenario 13/combined.
- Result: θ=0.95 gives worst-case MCC **0.529** (bottleneck: ME-S3,
  scenario 11) and mean MCC **0.846** — best of all values tested.
  θ=0.65-0.80 are all bottlenecked by BSHH-S2 (worst-case 0.287-0.301);
  θ=0.85/0.90 improve BSHH-S2 to 0.416/0.366 (non-monotonic, FP-count noise)
  but are still the binding constraint; only at θ=0.95 does BSHH-S2 clear
  to 0.836 and the bottleneck shifts to ME-S3.
- θ=1.0 is a **degenerate boundary case**, not a real calibration candidate:
  the alert check is `tgn_score > theta` (strict), and no observed score
  ever equals exactly 1.0, so every scenario collapses to tp=0/mcc=0 at
  θ=1.0. Excluded from the comparison.
- Two script bugs were found and fixed while producing this sweep (see
  `feedback_bugs.md`-style note): (1) `tgn_summary.csv` was opened as a bare
  relative path in `tgn_core.cc`, clobbered by every sequential
  scenario/parallel terminal — fixed via `BuildScenarioCsvPath` →
  `TGN_SUMMARY/<scenario>_seed999.csv`, matching the `TGN_EVENTS` fix
  pattern already in the code; (2) the sweep script's `awk -F,` column
  extraction broke on scenarios whose `attack_name` field contains an
  internal comma (`"...Controller, No RSU"`), silently reading `fn` into the
  `mcc` slot for scenarios 3/4/7/8/11/12 — fixed with an `NAME`-collapsing
  `sed` pre-pass before the `awk` split.
- Original 0.85 pick (below) remains documented for provenance/audit trail
  but is superseded — that sweep also had the awk field-shift bug affecting
  scenarios 3/4/7/8/11/12's reported values, in addition to being measured
  under LW-enabled OR-masking.
- **This 0.95 pick is itself now superseded by the 2026-07-24 fine re-sweep
  above (θ=0.92)** — kept here for provenance/audit trail.

---

**[SUPERSEDED] Original calibration — θ_FS = 0.85** (kept for audit trail only)

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
baseline). **PDF calibration method (all 9):** recalibrate proportionally to
each signature's observed FP rate (precision) on real event data,
maintaining `Σw_k = 1, w_k ≥ 0`.

**Status: ✅ DONE (8 of 9 on real evidence, 1 on placeholder) — this section
was stale, code has already moved past it.** `PEM_WEIGHTS[]`
(`routing.cc:2287-2291`) is **no longer uniform** — it was recalibrated
proportional to each signature's Laplace-smoothed precision `(TP+1)/(TP+FP+2)`,
computed across 13,823 PEM_EVENT_LOG rows from 52 scenario runs, normalized
to sum to 1. This happened *after* the Eq. 3.8 density-formula fix (2D disk
→ 1D road-segment model per the document), which was a prerequisite —
before that fix ME-S1 (`triggered[6]`) almost never fired, so there was no
real evidence to calibrate against for that signature.

| # | Weight | Signature | Value | Precision (evidence) | Status |
|---|---|---|---|---|---|
| 1 | w1 | TTW-S1: topology state persistence anomaly (Eq. 3.2) | 0.1121 | 0.893 | ✅ calibrated |
| 2 | w2 | TTW-S2: timestamp-topology age inconsistency (Eq. 3.3) | 0.1236 | 0.985 | ✅ calibrated |
| 3 | w3 | TTW-S3: cross-reporter inconsistency (Eq. 3.4) | 0.1253 | 0.998 | ✅ calibrated |
| 4 | w4 | BSHH-S1: duplicate liveness assertion (Eq. 3.5) | 0.1229 | 0.979 | ✅ calibrated |
| 5 | w5 | BSHH-S2: timestamp regression / replay (Eq. 3.6) | 0.0796 | 0.634 | ✅ calibrated (known bottleneck — lowest precision of the 9) |
| 6 | w6 | BSHH-S3: liveness-beacon inconsistency (Eq. 3.7) | 0.0627 | — (structural, see below) | ✅ accepted as final — Laplace-smoothed neutral prior, not real precision evidence, for a documented structural reason (not just "hasn't happened yet") |
| 7 | w7 | ME-S1: reporter count excess (Eq. 3.8) | 0.1253 | 0.999 | ✅ calibrated |
| 8 | w8 | ME-S2: path diversity inflation (Eq. 3.9) | 0.1237 | 0.986 | ✅ calibrated |
| 9 | w9 | ME-S3: reporter range/signal inconsistency (Eq. 3.11) | 0.1248 | 0.995 | ✅ calibrated |

**w6 — resolved as a documented structural finding (2026-07-23), not left
as an unexplained gap.** Investigated why this signature never fires
(traced through, not just re-asserted from the old code comment):

- Confirmed at N=200 (full-scale) and N=2 (minimal) that BSHH-S3
  genuinely never triggers `event.triggered[5]`, only `BSHH-S1` fires.
- Traced sig[5]'s condition (`!beaconSeen`, Eq. 3.7): fires only if the
  claimed identity has no corroborating beacon within the liveness window.
  Tried silencing the claimed vehicle (`--silence_vehicle_id`) — no
  effect, because `PemBshh3PresenceTick()` (a separate periodic mechanism)
  stamps `g_pem_last_beacon_time` for any vehicle with *any* witness
  (RSU or peer) in range, independent of that vehicle's own silence
  state.
- Root cause: **a genuine timing conflict in the attack model itself.**
  BSHH-S3's replay margin is 2s (`TTW_S1_REPLAY_MARGIN_S`) — the attacker
  deliberately replays fast, to convincingly impersonate *recent*
  liveness. `W_BSHH` (the liveness window this same session already
  calibrated and validated, §C above) is ~7.2s. Since 2s « 7.2s, the
  presence tick's most recent stamp is always still within the window by
  replay time — `beaconSeen` can never go false, for any vehicle count,
  silencing, or isolation attempt, as long as the attack's own realistic
  2s timing is preserved.
- **Forcing a firing would cost something real either way**: stretching
  the replay margin far beyond 7.2s makes the attack scenario less
  realistic (a slower, less convincing impersonation than the paper's own
  design intends); shrinking `W_BSHH` below 2s would undo this session's
  own validated calibration of that exact parameter and likely reintroduce
  the handover false positives it was calibrated to prevent. Neither
  trade is worth it just to populate one weight.
- **Decision:** keep `w6 = 0.0627` (the Laplace-smoothed neutral prior,
  same formula as an unobserved signature, normalized against the other 8
  observed weights) as the final value. This is defensible specifically
  *because* the reason it's unobserved is now a documented, understood
  structural property of the attack model — not an unexplored gap that
  happened to never come up.

**SUPERSEDED (2026-07-29) — re-measured for the 170m-patch.** The
table above was calibrated against the pre-patch ρ_max/δ_thresh/ME
link-reality formulas (300m-based). Once those moved to
`g_me_detect_range`(170m), the underlying signature-firing behavior
they drive changed, so the precision evidence needed re-measuring —
same methodology (Laplace-smoothed `(TP+1)/(TP+FP+2)`, normalized to
sum to 1), against `simTime=60`, `N_Vehicles=200`, `N_RSUs=64`(RSU)/`0`,
`attack_percentage=40`, `RngRun=999`, `--no_blockchain=1`, individual
scenarios 1-12 (**scenario 13 excluded from this and all future
LW-side measurement passes** — see note below).

| # | Weight | Signature | Old value | **New value** | Note |
|---|---|---|---|---|---|
| 1 | w1 | TTW-S1 | 0.1121 | **0.1132** | stable |
| 2 | w2 | TTW-S2 | 0.1236 | **0.1217** | stable |
| 3 | w3 | TTW-S3 | 0.1253 | **0.1201** | stable |
| 4 | w4 | BSHH-S1 | 0.1229 | **0.1103** | stable |
| 5 | w5 | BSHH-S2 | 0.0796 | **0.1117** | **rose substantially** — no longer the bottleneck |
| 6 | w6 | BSHH-S3 | 0.0627 | **0.0609** | still the Laplace-smoothed neutral prior; structural non-firer finding above still applies unchanged |
| 7 | w7 | ME-S1 | 0.1253 | **0.1206** | stable |
| 8 | w8 | ME-S2 | 0.1237 | **0.1203** | stable |
| 9 | w9 | ME-S3 | 0.1248 | **0.1212** | stable |

BSHH-S2's rise (0.0796→0.1117, was the second-lowest/"known bottleneck",
now solidly mid-pack) is consistent with the 170m formulas producing
more geometrically-accurate detection conditions. The ME family also
converged much tighter (0.1203-0.1212 vs. the old 0.1237-0.1253 spread)
— all three ME signatures now share the same detection range, reducing
inter-signature precision variance. **Code updated**: `PEM_WEIGHTS[9]`
(`routing.cc`) changed to the new values, rebuilt.

**Scenario 13 exclusion note**: live-measured this session to cost
30-65+ minutes per run (all 12 attack families running concurrently
inherits TTW-S1's own unavoidable Stage-0-bypass-by-construction cost —
see `CALIBRATION_VALUES.md` — multiplied across every family) vs.
single-digit minutes for any individual scenario, while contributing
zero usable evidence: its `PEM_EVENT_LOG` mixes all 12 attack types'
events together with no per-family attribution, so precision can't be
attributed back to any single signature from it anyway. Dropped from
this measurement and all downstream θ_LW/µ sweeps this session.

---

## C. Sliding Window & Observation Window Parameters

### LW detector max window size (W_max)

**PDF default:** `⌈L_link/T_b⌉` intervals; urban≈430, highway≈90. **PDF
calibration method:** increase until no TTW-S2 cross-interval misses;
decrease until TTW-S3 false positives from departed vehicles disappear.

**Status: ⚠️ verified-safe across a wide range, true crossover NOT located
(documented limitation, not a silent gap).** Added `--pem_w_max=<events>`
runtime override (`routing.cc`, `g_pem_w_max_events`/`g_pem_w_max_override`)
to make this sweepable — previously only settable via the mobility-adaptive
auto-formula or a compile-time constant.

Swept `--pem_w_max ∈ {5, 10, 15, 20, 25, 30, 36, 50, 75, 100, 150, 200, 300,
430, 600}` against TTW-S2 (scenario 2) and TTW-S3 (scenario 3),
`N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 RngRun=1`, θ_LW=0.05.

**Label correction:** the grid point `36` was mislabeled "(default)" when
this was first written. `36` is only `g_pem_w_max_events`'s *compile-time
fallback*, used solely if `--no_mobility_adapt` is passed. None of these
sweep runs passed that flag, so the actual live default under this exact
config (urban, `mobility_scenario=0`) is the mobility-adaptive formula:
`W_max = ceil(ttw_link_lifetime_bound / T_b) = ceil((2×300/14) / 0.1) =
ceil(42.857/0.1) = 429` — not 36, and not the `TGN_WMAX≈430` figure
elsewhere in this doc either, which is a *different* variable belonging to
the TGN model's own window, not this LW-detector one (similar formula,
separate system — do not conflate the two). 429 sits inside the tested
range (between the 300 and 430 grid points), so this doesn't change the
sweep's flat-result conclusion, but the earlier "default" label was wrong
and is corrected here.

**Result: completely flat** — identical tp/fp/fn/mcc (scenario 2: tp=51
fp=0 fn=0 mcc=1; scenario 3: tp=17 fp=0 fn=0 mcc=1) at every single value
across the full 120x range tested. Neither of the PDF's two failure modes
(TTW-S2 cross-interval misses at low W_max, TTW-S3 false positives from
departed vehicles at high W_max) appeared anywhere in this range.

**Why it came back flat, not why it's broken:** scenario 2 produces only 51
attack-relevant events and scenario 3 only 17, even at this vehicle/RSU
scale — nowhere near large enough to fill and evict even the smallest
W_max=5 tested. The PDF's calibration method requires the window to
actually fill up and start evicting events before either failure mode can
manifest; at this event volume that threshold is never reached, so this
sweep proves "no regression across a wide range," not "here is the actual
crossover point" — those are different claims, and only the first one is
supported by this evidence.

**Decision (2026-07-23): accept as verified-safe, do not chase the
crossover further right now.** Current default (mobility-adaptive
auto-formula, `g_pem_w_max_events` recomputed from
`ttw_link_lifetime_bound / PEM_BEACON_INTERVAL_S`) is kept, with this sweep
as evidence that it introduces no detectable regression across a wide
range at this scale. Finding the genuine PDF-described crossover would
require a harder stress config (substantially longer `simTime`, e.g. 300s+,
and/or higher attack-replay frequency, to actually accumulate enough
events to fill and evict the window) — explicitly deferred, not attempted
in this pass.

### BSHH-S3 liveness observation window (W_BSHH)

**PDF default:** `W > 2·W_ho` (formula-derived). **PDF calibration method:**
confirm `W > W_ho` prevents handover false positives; validate BSHH-S3 still
fires before the stale heartbeat expires.

**Status: ✅ DONE (validated, not swept — this is a formula-locked value,
not a free scalar).** `g_pem_bshh3_liveness_window_s`
(`routing.cc:2179`) is computed as `W = 2 × r_overlap / v_max(t)` and
recalibrated every `PEM_BSHH3_RECAL_PERIOD_S=1.0`s during the run
(`PemRecalibrateBshh3Window`) — it satisfies `W = 2·W_ho > W_ho` by
construction, always, so there is no separate value to sweep; the PDF's own
calibration method for this parameter is a validation, not a search.

**Evidence (2026-07-23):** BSHH-S3 (scenario 7) and BSHH-S4 (scenario 8),
`N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 RngRun=1
lw_threshold=0.05`. Confirmed startup value from the run log:
`[PEM] BSHH-S3 liveness W=7.2s  RSSI_min=-85 dBm  W_max=429 events`
(also independently confirms the W_max=429 figure derived by hand in §C
above — cross-check passes).

| Scenario | tp | fp | fn | mcc |
|---|---|---|---|---|
| 7 BSHH-S3 | 32 | 0 | 0 | 1.000 |
| 8 BSHH-S4 | 32 | 0 | 0 | 1.000 |

Zero false positives (satisfies "no handover FPs") and 100% of attacks
caught (satisfies "still fires" — nothing missed). One caveat: `tdet_ms=0`
in both run summaries — this is very likely a reporting artifact (field not
populated for this event type) rather than a genuine "detected in 0ms"
measurement, and is *not* being used here as evidence of timing margin
relative to stale-heartbeat expiry — only the fp=0/fn=0 result is being
relied on.

---

## D. Physical and Signal Consistency Parameters

### Max propagation tolerance / freshness bound (ε, Eq. 3.16)

**PDF default:** not set, conceptually ≈ one-way propagation delay. **PDF
calibration method:** measure 95th-percentile one-way latency from NS-3
simulation logs; set ε equal to this value.

**Status: ✅ DONE (code changed and verified, 2026-07-23).** Computed
95th-percentile `rx_delay_s` (`= recv_time_s - claimed_ts_s`, the one-way
latency the PDF's method calls for) over 5,662 **benign** events (`is_attack
== 0`) in `training_data/sim60_ap60_3seeds_events.csv` (all 13 scenarios ×
3 seeds):

| Percentile | rx_delay (s) |
|---|---|
| p50 | 0.031 |
| p90 | 0.100 |
| **p95** | **0.101** |
| p99 | 0.115 |
| max | 0.120 |

**Finding that motivated the change:** the prior placeholder
`PEM_PROPAGATION_EPSILON_S = 0.020` gave an effective detection threshold
`T_b + ε = 0.100 + 0.020 = 0.120s` — and the real observed benign maximum
is **exactly 0.120s**. That left essentially zero margin; no false
positives had actually been observed in any run to date, but that looked
like favorable seed luck rather than a real safety margin, which is
precisely the situation the PDF's calibration method exists to fix.

**Calibrated value: ε = 0.101s** (was 0.020s). Applied to both
`PEM_PROPAGATION_EPSILON_S` (`routing.cc:2155`) and the paired
`PROPAGATION_TOL_MS` constant (`crypto/teta_guard_types.h:49`, kept in sync
per the existing Gap-15-fix requirement — both represent the same physical
epsilon). Rebuilt and re-verified on TTW-S1 (scenario 1) and TTW-S3
(scenario 3) — the two families most directly gated by this ε-based
freshness check (Eq. 3.2/3.16) — at `N_Vehicles=200 N_RSUs=64
N_Controllers=4 simTime=60 RngRun=1 lw_threshold=0.05`:

| Scenario | tp | fp | mcc | vs. pre-change baseline |
|---|---|---|---|---|
| 1 TTW-S1 | 63 | 0 | 1.000 | unchanged |
| 3 TTW-S3 | 17 | 0 | 1.000 | unchanged |

No regression — the wider ε doesn't cost any detection sensitivity at this
scale/config, while giving real margin against benign propagation jitter
instead of sitting exactly at the observed edge.

### Detection formula range (r_comm)

**Status: ⚠️ CORRECTED (2026-07-23) — one half of the PDF's dual value is
stale relative to actual code behavior; the other half is correct.**
**SUPERSEDED IN PART (2026-07-27) — see update below; the "used throughout
every detection formula" claim is no longer accurate for ME-S1's ρ_max.**

- **300m design bound: confirmed correct and in active use — for TTW's own
  placement/HELLO-geometry/link-break logic and BSHH-S3's `r_overlap`
  fallback.** `TTW_COMM_RANGE = 300.0` and `g_rcomm = 300.0`
  (`routing.cc:1866,2227`). Matches the PDF exactly for these uses.
- **UPDATE (2026-07-27, supervisor's detection-equation patch): NOT
  "used throughout every detection formula" anymore.** A new
  `g_me_detect_range = 170.0` m constant now supersedes `TTW_COMM_RANGE`
  specifically for ME-S1's `ρ_max` (Eq. 3.8), the δ_thresh formula, and
  ME's link-reality checks (`link12`/`link34`/`srcDstLinked`/
  `v3v4_linked`). ME-S3's own range check and TTW's link-break/repair
  checks still use the unchanged 300m `TTW_COMM_RANGE`/`g_rcomm` — this
  patch only touched the specific formulas named above, not every
  detection-side use of a communication-range constant. See
  `CALIBRATION_VALUES.md` §1/§4 and `TGN_HYPERPARAMETER_CALIBRATION.md`
  §3g-3h for the full scoping rationale and downstream TGN
  retrain/recalibration this required.
- **282.2m "NS-3 Ch.178 effective range": does NOT match actual simulated
  behavior.** The PDF derives this from COST-231 Hata @ 44dBm on Ch178 —
  but per `CALIBRATION_VALUES.md` §1-2 (an existing finding from an
  earlier session, not previously cross-referenced into this master
  tracker), **live beaconing was deliberately restricted to 3 channels
  (Ch172/174/176 @ 33dBm each), explicitly excluding Ch178.** The
  real, load-tested effective range on the channels actually used for
  beaconing is **100m**, confirmed across 3 independent test
  configurations (isolated 3-channel, full-scale N=200/RSU=64 loaded,
  and single-channel-concentrated contention) — not 282.2m. Ch178 in
  isolation does measure ~180m-scale, and COST-231 Hata at 44dBm alone
  would give something in the 282m range, but that number describes a
  channel that isn't in the live send path at all, so it doesn't
  describe what the simulation actually produces.

**Corrected empirical value for the PDF: 300m (analytical design bound,
governs TTW placement/link-break + BSHH-S3 r_overlap, unchanged) / 170m
(detection-equation-only value for ME-S1 ρ_max, δ_thresh, and ME's
link-reality checks, as of 2026-07-27) / 100m (real NS-3 trace-derived
effective range on the 3 channels actually used for beaconing — not
282.2m). Three genuinely distinct constants for three genuinely distinct
purposes.** See `CALIBRATION_VALUES.md` §1 for the full measurement
methodology and evidence (bug fixes to
`ThresholdPreambleDetectionModel::MinimumRssi` and an ambient-broadcast
contamination source that were needed to get a clean measurement).

### Minimum RSSI threshold (RSSI_min, Eq. 3.31)

**Status: ➖ already fixed by design.** PDF value: -85 dBm default,
derived from the NS-3 propagation model at r_comm. No sweep needed.

### Inter-lane density margin (µ, ME-S1, Eq. 3.8)

**PDF default:** 0.20 (recommended default). **PDF calibration method:**
increase if urban runs produce false positives on legitimate multi-lane
observers; decrease to improve sparse-traffic sensitivity.

**Status: ⚠️ verified-safe across a wide range, no differentiating signal
found (documented limitation, not a silent gap) — same pattern as W_max
above.** Added `--pem_me_mu=<value>` runtime override
(`routing.cc`, `PEM_ME_TOLERANCE_MU`, was a compile-time constant) to make
this sweepable.

**Prerequisite finding before the sweep was even meaningful:** ME-S1/ME-S2
at default settings only let 3/42 and 10/62 attack packets reach the LW
layer at all — the rest are dropped at crypto Stage-0
(`crypto_drop_mac`/`crypto_drop_quorum`/etc.), well before ever reaching
the µ-gated `rho_max` check. Sweeping µ against that starved signal would
have been meaningless. Re-ran with `--no_crypto=1` (ablation A6, bypasses
Stage-0 entirely) to get full attack signal through to the check being
calibrated.

**Swept `--pem_me_mu ∈ {0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50}`**
against ME-S1 (scenario 9) and ME-S2 (scenario 10), `--no_crypto=1`,
`N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 RngRun=1
lw_threshold=0.05`:

| Scenario | Result across entire µ range | 
|---|---|
| 9 ME-S1 | **completely flat**: tp=40 fp=0 fn=0 mcc=1.000 at every value 0.05–0.50 |
| 10 ME-S2 | **completely flat**: tp=6 fp=4 fn=4 mcc=0.378 at every value 0.05–0.50 |

**ME-S1 (the actual µ-gated scenario): perfect and unaffected by µ anywhere
in this range** — no FP signal to justify raising µ, no sensitivity gap to
justify lowering it. **ME-S2's fp=4/fn=4 is unrelated to µ** — event-log
inspection shows its detections actually route through the **ME-S3**
signature (sig[8], RSSI-range check), not ME-S1's µ-gated `rho_max` (sig[6])
at all; the false negative sits right at the RSSI_min=-85 boundary
(RSSI=-89.1 missed vs. RSSI=-86 caught), which looks like a distinct
RSSI-boundary sensitivity issue in ME-S3, not a µ problem. Flagged as a
separate open item, not investigated further here (out of scope for this
calibration pass).

**Decision: keep µ = 0.20 (PDF default), no code change.** No evidence in
this range justifies moving it in either direction; the scenario that
could show a real signal (ME-S1) is already perfect across the whole
tested range.

**RECONFIRMED (2026-07-29) against the 170m-patch ρ_max formula.**
Since µ's own multiplier sits directly inside ρ_max = `(1+µ)·2·r_comm·λ̂(t)`,
and `r_comm` in that formula moved from 300m to `g_me_detect_range`(170m)
this session, the old finding above (measured against the pre-patch
formula) needed independent re-verification, not just an assumption
that "flat before" implies "flat after."

Re-swept the full range `{0.00,...,1.00}` step 0.05 (21 points, finer
than the original 8-point sweep), directly against ME-S1 (sc9) and
ME-S2 (sc10) — not excluded this time, scored directly — with
`--no_tgn=1 --no_blockchain=1 --no_crypto=1 --no_lbs=1` (same
Stage-0-bypass rationale as the original sweep, plus stripping TGN,
blockchain, and ME-S3's own signature to isolate ME-S1's ρ_max as
cleanly as possible), `simTime=60`, `attack_percentage=40`, `RngRun=999`.

**Result: still completely flat.** sc9 (ME-S1) shows identical
MCC=0.894 (`tp=16125, tn=4, fp=0, fn=1`) at all 21 values from 0.00 to
1.00 — zero differentiation, even finer-grained and under stricter
isolation than the original sweep. sc10 (ME-S2) shows undefined MCC
throughout (`tp=0` always) — expected, its own signature (path-count,
sig[7]) was never µ-gated.

**Decision unchanged: µ = 0.20.** Independently reconfirmed against the
new formula — this isn't a stale finding being carried forward
unverified, it was re-measured from scratch and gives the identical
verdict. No code change (`PEM_ME_TOLERANCE_MU` was already 0.20).

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

**Status: ✅ DONE.** Swept `{50, 100, 150, 200}` × 3 seeds at the dim=192
anchor (added `--tbptt_window` CLI override to `tgn_train.py` to make this
testable).

| W_BPTT | mean Test MCC (3 seeds) |
|---|---|
| 50 | 0.889 |
| **100** | **0.897** |
| 150 | 0.897 (byte-identical to 100) |
| 200 | 0.897 (byte-identical to 100) |

**Calibrated value: W_BPTT = 100 (PDF default, confirmed).** 50 is
measurably worse (real drop from over-truncating gradients); 100/150/200
are byte-identical, meaning no node in this dataset ever accumulates
enough events to hit the 100-window truncation boundary in the first
place — so there's no evidence a larger window would ever help, and no
reason to move off the PDF's own default.

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

**Status: ✅ DONE.** `TGN_HYPERPARAMETER_CALIBRATION.md` §3d: L ∈ {1,3}
tested at dim=192/pos_weight=6/ce_weight=0.3, 3 seeds each, against the
L=2 anchor (6 seeds, mean MCC 0.8965). **Calibrated: L = 2** — not a close
call, both alternatives collapsed (L=1 mean MCC 0.169, L=3 mean MCC 0.331),
more than 0.55 MCC below the anchor.

### Node feature embedding dimension (d, Eq. 3.20)

**PDF default:** not specified. **PDF calibration method:** evaluate
d ∈ {32,64,128}; select by validation MCC; match GRU hidden-state size to d.

**Status: ✅ DONE.** `TGN_HYPERPARAMETER_CALIBRATION.md` §3c: dim ∈ {64,192}
× 6 seeds each, vs. existing dim=128 × 6-seed anchor (pos_weight=6 fixed).
Note the PDF's grid is {32,64,128} — the actual sweep used {64,128,192}
instead (dim=32 not tested; dim=192 added because dim=128 was already the
established anchor from prior sessions) — flagged for follow-up if strict
PDF-grid compliance is required for the final report, but not blocking.

**Calibrated value: d = 192** — mean Test MCC 0.8965 (n=6) vs. dim=128's
0.8957 (n=6) and dim=64's 0.8820 (n=6). Narrow win on mean, decisive win on
stability (std 0.0036 vs. dim=128's 0.0088, ~2.4x tighter). This is the new
anchor for all subsequent TGN sweeps (layers, ce_weight both re-run against
dim=192, not the original dim=128 plan — see §3d).

### GRU hidden-state size (h_GRU, Eq. 3.23)

**Status: ➖ tied to d by design.** PDF: "match to d by default; tune
separately only if temporal memory update over-fits relative to embedding
dimension" — a diagnostic condition, not a routine sweep. Will inherit
whatever `d` is chosen above unless over-fitting is separately observed.

### Optimiser learning rate (η)

**PDF default:** not specified; start at 1e-3, reduce on plateau, cosine
annealing for stability.

**Status: ✅ DONE.** Swept `{0.0005, 0.001, 0.002}` × 3 seeds at the
dim=192 anchor (`--lr` already existed, no code change needed).

| η | mean Test MCC (3 seeds) | std |
|---|---|---|
| 0.0005 | 0.875 | 0.0098 |
| **0.001** | **0.897** | **0.0022** |
| 0.002 | 0.902 | 0.0095 |

**Calibrated value: η = 0.001 (PDF's own starting point, confirmed).**
0.002 has a marginally higher mean (+0.005), but that's within the
~0.007-0.011 seed-to-seed noise band seen throughout every sweep this
session, and 0.001's variance is over 4x tighter (0.0022 vs 0.0095) — per
this project's "ties broken by lower std" rule (§3), 0.001 wins. Matches
the PDF's own stated starting point exactly, with `CosineAnnealingLR`
scheduling already implemented (`tgn_train.py`) as the PDF's suggested
schedule.

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

**Status: ✅ DONE.** `TGN_HYPERPARAMETER_CALIBRATION.md` §3c: pos_weight ∈
{4, 4.5, 5, 5.5, 6, 6.5, 7} at dim=128 (3 seeds each for the new points, 6
seeds reused for the pre-existing 4/6 points), later reconfirmed valid at
the updated dim=192 anchor.

**Calibrated value: pos_weight = 6** — highest mean Test MCC (0.8957, n=6)
with the strongest evidence base; pos_weight=5.5 was close (0.8940) but
only had n=3, not enough to overturn the n=6 anchor. Per the methodology
note above, this is the fixed-override value that beat the PDF's own
dynamic-ratio formula in this sweep — adopted as final per the stated
comparison rule.

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

**Status: ✅ DONE (validated, not swept — formula-locked like W_max/W_BSHH,
not a free scalar).** `t = floor(n/2)+1` is already implemented exactly as
the PDF default (`VERIFY_QUORUM`, Algorithm 4 lines 52-66 / Eqs. 3.29-3.32),
with `n = |R(eij,t)|` computed live as the actual claimed witness-set size
per link at report time — architecturally SUMO-density-derived by
construction (not a fixed/placeholder count), satisfying the PDF's "confirm
n from SUMO density traces" requirement without a separate step.

**Evidence for the second half of the PDF's method** ("verify no
single-vehicle or sub-quorum collusion forges a valid aggregate report"),
pulled from data already collected this session (`qrr_echo_attempts/pass/
blocked/qrr` columns, `N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60
RngRun=1`):

| Scenario | attempts | pass (forged, admitted) | blocked | qrr |
|---|---|---|---|---|
| 9 ME-S1 | 20 | **0** | 20 | **1.000** |
| 10 ME-S2 | 8 | **0** | 8 | **1.000** |

Zero of 28 total sub-quorum collusion attempts were admitted across both ME
scenarios that exercise this echo/quorum path (BSHH's attack model doesn't
route through VERIFY_QUORUM at all — `qrr_echo_attempts=0` for BSHH-S3/S4,
architecturally not applicable rather than untested). qrr=1.000 confirms
the quorum gate is working exactly as designed at this scale.

### Vehicles per RSU reporting (n)

**PDF default:** varies with λ and r_comm. **PDF calibration method:**
extract min/max/mean from SUMO mobility traces.

**Status: ✅ DONE (measured, 2026-07-23).** Added opt-in instrumentation
(`--measure_vehicles_per_rsu=1`, `PemMeasureVehiclesPerRsu()`,
`routing.cc`) that logs live per-RSU vehicle counts (within `g_rcomm`)
every 1s to a new `VEHICLES_PER_RSU` CSV — zero overhead/behavior change
when the flag is off (default). Uses the actual fixed RSU grid layout and
real SUMO vehicle trajectories, not a re-derived approximation.

**Measured (baseline/no-attack, `N_Vehicles=200 N_RSUs=64 N_Controllers=4
simTime=60 RngRun=1`, 3,776 samples = 64 RSUs × 59 one-second snapshots):**

| Statistic | n |
|---|---|
| min | 0 |
| max | 42 |
| mean | 11.67 |
| median | 8.0 |

This directly satisfies the PDF's calibration method ("extract min/max/mean
from SUMO mobility traces") — n varies widely by RSU/time (0 at sparsely
covered RSUs up to 42 at the busiest), consistent with the PDF's own
description that n "varies with λ and r_comm" rather than being a fixed
constant. Cross-reference against the `t = floor(n/2)+1` formula validated
above: at the mean (n≈12), t=7; at the max observed (n=42), t=22; the n=0
edge case has no witnesses to form a quorum from at all (architecturally a
non-event, not a quorum failure).

*(Remaining §G rows and all of §H beyond "Anchor checkpoint interval" below
are transcribed as work begins on them.)*

---

## H. Blockchain and Trust Update Parameters

### Anchor checkpoint interval (⌊T_min/T_b⌋ blocks)

**PDF default:** formula-derived from minimum dwell time `T_min` and beacon
interval `T_b`. **PDF calibration method:** measure synchronisation latency
of newly promoted Tier-2 peers in simulation; confirm all peers reach
consistent ledger state before joining consensus round.

**Status: ✅ DONE — bug fixed, deployed to the live network, and load-tested
(2026-07-23, revised from an earlier "not load-tested" assessment — see
below).**

**The bug:** `AnchorIntervalBlocksUrban`/`AnchorIntervalBlocksHighway`
(`blockchain/chaincode/temporalecho/anchor.go`) held `215`/`45` — which
numerically match `L_link/(2·T_b)` (43000/200=215, 9000/200=45, the same
formula shape as the TGN `γ_init` derivation) — **not**
`⌊T_min/T_b⌋ = ⌊3000/100⌋ = 30` as this row's own PDF spec requires and as
the code's own comment always claimed ("AnchorIntervalBlocksUrban is
⌊Tmin/Tb⌋"). Confirmed via `TrustMinDwellMs = 3000` (`trust.go`) — the real
`T_min`, unrelated to either 215 or 45. Since `T_min` is a single global
OBU-eligibility constant that doesn't vary by mobility scenario (unlike
`L_link`, which does), there was never a legitimate basis for an
urban/highway split on this parameter under the PDF's own formula — the
215/45 split is itself evidence the wrong quantity was used, not a
deliberate calibration choice. Also found: `AnchorIntervalBlocksHighway`
was never actually referenced anywhere in the codebase (dead constant;
only `AnchorIntervalBlocksUrban` is used, at `anchor.go:85`), so the
urban/highway distinction was non-functional before this fix too.

**Fix applied:** both constants set to `30` (`⌊3000/100⌋`), matching the
PDF formula exactly. Kept as two separate named constants rather than
collapsing to one, to avoid a larger structural change than the bug fix
itself requires. `go build ./...` compiles clean.

**Correction: a live Fabric network was actually already running.** The
earlier "no live network available" assessment was wrong — checked more
thoroughly and found the project's own 4-orderer SmartBFT network + 5 RSU
peers already up (4-5 days uptime), with an older chaincode version
(2.2/sequence 4) deployed. This unblocked real load testing.

**Deployment:** packaged, installed on all 5 RSU peers, approved, and
committed the fix as version 2.3/sequence 5 via the project's own
`deploy_chaincode.sh` (bumped from the stale 2.1/3 the script had on disk).
Confirmed live via `peer lifecycle chaincode querycommitted`.

**Load test:** wrote `blockchain/client/loadtest_anchor_checkpoint.js`,
submitting 30 `CreateAnchorCheckpoint` calls back-to-back against the real
network (denser than the real ~3s natural cadence at 30 blocks × 100ms
beacon interval). **Result: 30/30 succeeded, zero MVCC conflicts, zero
rejections** — the genuine safety signal this row's PDF calibration method
is asking for (no contention under load significantly denser than
real-world usage).

**Important interpretation caveat, found and resolved via a differentiator
test:** the raw submit-transaction latencies were 8.6-20 seconds per call —
alarming at face value, but a pure read-only query
(`GetLatestAnchorCheckpoint`, which never touches consensus/ordering)
returned in **5-19 *milliseconds*** against the same network. This proves
the 8-20s figures reflect the SDK's `NETWORK_SCOPE_ANYFORTX` commit-event-
wait strategy (client-side network-wide commit notification, present for
every submitted transaction regardless of chaincode function or checkpoint
frequency), not genuine orderer/consensus throughput — the underlying
ledger itself commits and responds in milliseconds. So the raw latency
numbers do **not** answer "does the orderer's 20ms batch timeout / 50-tx
budget get exceeded" directly (that would need block-level timing
instrumentation, not client round-trip time) — but the zero-conflict,
zero-rejection result across a denser-than-real load is itself sufficient
evidence that the frequency increase doesn't destabilize the network.

---

### Tier-2 ledger window size (K = ⌈T_dwell/T_b⌉)

**PDF default:** varies per OBU dwell time `T_dwell`. **PDF calibration
method:** extract per-vehicle dwell times from SUMO traces; set K to cover
at least one full anchor checkpoint interval to prevent ledger gaps during
handover.

**Status: ⚠️ measured (2026-07-23), not implemented — purely informational,
same category as "n" above.** No existing ledger-window/retention mechanism
exists anywhere in the chaincode for this to correct (unlike the anchor
checkpoint interval, which had a real, if buggy, implementation) — per
your decision, only the measurement was added
(`--measure_vehicle_dwell=1`, `PemMeasureVehicleDwellTimes()`,
`routing.cc`), chaincode integration deferred to a separate task.

**Methodology correction found mid-measurement:** the first version of this
instrumentation tracked dwell against "in range of *any* RSU" and produced
0 completed intervals (200/200 vehicles censored) — because `r_comm=300m`
exceeds the 8×8 grid's ~273×264m spacing, adjacent RSU coverage circles
overlap with no gaps, so every vehicle is continuously covered by *some*
RSU for the entire run. That's not the quantity `K` needs — what matters is
how long a vehicle stays associated with **one serving RSU** before handing
over to an adjacent one (matching the existing `W_ho`/`T_min^dwell`
handover concepts elsewhere in this table). Corrected to track the nearest
RSU as the "serving" RSU and re-ran.

**Measured (baseline/no-attack, same config as `n`, 204 completed
handover-bounded dwell intervals + 200 right-censored at simTime end):**

| Statistic | T_dwell (s) | K = ⌈T_dwell/T_b⌉ |
|---|---|---|
| min | 0.20 | 2 |
| p5 | — | 12 |
| p10 | — | 19 |
| p25 | — | 49 |
| median (p50) | 16.30 | 164 |
| p75 | — | 268 |
| p90 | — | 412 |
| p95 | — | 508 |
| mean | 17.99 | 179.9 |
| max | 59.80 | 598 |

**Real finding, not just a number to report:** 17.2% of completed intervals
(35/204) give `K < 30` — shorter than one full anchor-checkpoint-interval
(§H's `AnchorIntervalBlocks = 30`, fixed above). Taking `K = ⌈T_dwell/T_b⌉`
*literally* per-vehicle would violate this row's own stated safety
requirement for those fast-handover vehicles — their ledger window
wouldn't reliably contain even one checkpoint, exactly the "ledger gaps
during handover" failure mode the PDF is calibrating against.

**Recommended formula for future implementation:
`K = max(⌈T_dwell/T_b⌉, AnchorIntervalBlocks)` = `max(⌈T_dwell/T_b⌉, 30)`** —
a floor at one anchor-checkpoint-interval, so short-dwelling vehicles still
get a guaranteed-safe window while longer-dwelling vehicles get a window
sized to their actual visit. Not applied to any code since K isn't
implemented yet — recorded here as the calibration finding for whoever
designs that implementation next.

---

### Smart contract execution latency (T_exec)

**PDF default:** 50-200ms (Hyperledger Fabric literature). **PDF
calibration method:** measured per-event chaincode execution time; ensures
`T_det + T_exec ≤ 100ms` safety budget.

**Status: ✅ DONE (2026-07-23) — real data captured, plus two genuine
performance bugs found and fixed along the way.** No live Fabric network
exists in this environment (same constraint as the anchor checkpoint item),
so this measures the in-simulation FlowMod/BlacklistBeacon enforcement code
path's real wall-clock time (`g_pem_exec_flowmod_*`, `routing.cc`) — the
same established proxy methodology already used for M5/T_pipeline
project-wide, not literal Fabric chaincode latency.

**Why this took real investigation, not just a run:** the enforcement
timer only fires after a multi-gate chain succeeds (alert-fresh-or-
divergence-confirmed → not-already-revoked → PBFT quorum → threshold-
signature/witness-quorum). The threshold-signature check
(`VERIFY_THRESHOLD_SIG`) deliberately cycles an assumed-fault-count `f_c`
sweep variable (Eq. 4.18 methodology) from 1 upward across successive
calls, and needs `f_c ≥ t_req = ⌊N_Vehicles/2⌋+1 = 101` (at N=200) before it
can ever pass — meaning **100+ FSR-eligible mitigation calls must
accumulate within a single run** before this path is exercised even once.
Every run this session (single-scenario, moderate attack density) produced
far fewer calls (e.g. 16 for BSHH-S3 alone), so `t_exec_flowmod` stayed at
0 across every prior dataset — not a bug, just never-exercised.

**Bug #1 found and fixed en route — ME-S4 event-volume multiplication:**
reusing a high-attack-density combined run (scenario 13,
`attack_percentage=80`) to accumulate enough calls exposed a severe
performance stall recurring at `t≈10.1s` in every attempt. Traced to
`ME_S4_InjectPhantomPaths` (routing.cc) being called inside a
`for (c = 0; c < n_mal_ctrl4; c++)` loop — the same phantom-pair
re-injection-per-controller bug already fixed for its sibling
`ME_S3_InjectPhantomPaths`, but never applied here. Fixed identically
(inject once, `attacker_idx=0`, matching ME-S3's established fix).
Confirmed real but **not** the actual stall cause — the same stall
recurred after this fix.

**Bug #2 found and fixed — the actual stall cause, an O(n²)/combinatorial
DFS blowup in `PemComputeReporterInferredPathCount`** (used by ME-S2's
sig[7] path-diversity check). Isolated via systematic checkpoint
instrumentation (bracketing crypto pre-filter → LW signature scoring →
TGN, then each of the 9 individual signature checks) to precisely this
function. It builds a graph from every historical reporter ever logged
against a link (`ns.link_report_history[linkKey]`, trimmed by age but
never by count) and exhaustively DFS-enumerates all simple paths between
the link endpoints. A prior fix (`kPathCountCap=4096`, already in the
code, confirmed via its own comment as "confirmed root cause of ME-S3's
exponential wall-clock blowup" from an earlier session) caps the *output*
path count — but not the *work*: with a dense, mutually-in-range graph,
DFS explores enormous numbers of dead-end branches (never reaching the
destination, never incrementing the capped counter) before that cap is
even reached. Per the existing comment, ~13 mutually-connected nodes was
already enough to explore billions of path attempts despite the cap.
**Fix:** added an earlier cap directly on graph *input size*
(`kMaxNodesForExactPathCount=12`, chosen to stay safely under the
documented ~13-node explosion point while comfortably covering every
attack scenario's actual reporter counts, which are single-digit) —
above that, the function returns the same "count exceeds cap" sentinel
immediately, skipping the expensive graph build and DFS entirely.

**Verification:** the same combined-scenario/attack_percentage=80 config
that previously never completed (18+ CPU-minutes stuck at `t≈10.1s`, no
matter how long it ran) now completes the full 60s simulated run in
~5 minutes wall-clock. Detection quality unaffected:
`tp=958 fp=4 fn=85 mcc=0.942` (this extreme config was never previously
run to completion, so there's no pre-fix baseline to regression-test
against directly, but the mcc is consistent with every other high-quality
result observed this session — the cap has no visible detection-accuracy
cost at realistic reporter counts, exactly as its own design reasoning
predicts).

**Calibrated value: T_exec mean = 0.0037ms, max = 0.0091ms**
(`N_Vehicles=200 N_RSUs=64 N_Controllers=4 simTime=60 attack_scenario=13
attack_percentage=80 RngRun=1`). Both comfortably inside the PDF's
`T_det + T_exec ≤ 100ms` budget — this in-sim proxy stage is not a
bottleneck. Real Fabric chaincode latency (the PDF's literal 50-200ms
literature figure) remains unmeasured against an actual deployed network,
same caveat as the anchor checkpoint interval item above.

---

## Summary — what's actually actionable right now

| Status | Count | Items |
|---|---|---|
| ✅ Done, evidence-backed | 14 | θ_FS = 0.92 (fine re-sweep {0.90..1.00} against dim=192 model, no_lw ablation, all 13 scenarios — supersedes earlier 0.95 and 0.85 picks), θ_LW = 0.05 (worst-case verified across 12/12 individual scenarios), w1-w5/w7-w9 (8 of 9 signature weights, precision-weighted from real evidence), dim d = 192, pos_weight/w_class (class imbalance weight) = 6, L/layers (message-passing rounds) = 2, W_BPTT = 100 (confirmed, larger values byte-identical), η = 0.001 (confirmed, lowest variance), W_BSHH (formula-locked, validated: fp=0/fn=0 on BSHH-S3 and S4), ε = 0.101s (code changed + verified, was 0.020s), t (quorum majority threshold, formula-locked, validated: qrr=1.000, 0/28 collusion attempts admitted), n (vehicles per RSU: measured min=0/max=42/mean=11.67/median=8.0 from real SUMO traces, new opt-in instrumentation added), T_exec (mean=0.0037ms/max=0.0091ms, measured after fixing 2 real performance bugs found en route), Anchor checkpoint interval (215/45 -> 30/30 bug fix deployed live as chaincode v2.3/seq5, load-tested: 30/30 checkpoints succeeded, zero MVCC conflicts) |
| ✅ Done, resolved via documented finding (not raw evidence) | 4 | γ (PDF's own verification method structurally doesn't apply to this attack model, for any value); W_max, µ (both swept across wide ranges, zero differentiating signal found — kept at defaults with real evidence that nothing better shows up); w6 (BSHH-S3 signature weight — traced to a genuine timing conflict in the attack model itself: 2s replay margin vs. the already-validated ~7.2s W_BSHH window means this signature structurally cannot fire without either making the attack less realistic or regressing an already-validated calibration; kept at its Laplace-smoothed neutral-prior value, now for a documented structural reason rather than "hasn't come up yet") |
| 🔍 Measured, not implemented (informational only) | 1 | K = ⌈T_dwell/T_b⌉ (§H) — measured from real SUMO traces (min=2, median=164, max=598 handover-bounded intervals); found 17.2% of vehicles would get K<30 (unsafe per this row's own requirement) if computed literally — recommended formula `K = max(⌈T_dwell/T_b⌉, 30)` documented for future chaincode implementation, no ledger-window mechanism exists yet to apply it to |
| ⬜ Not yet examined at all | ~7 | §H rows beyond what was investigated this session: δ_thresh(t), Δ+, Δ-, τ0, τ_RSU,0, orderer batch timeout/size, channel endorsement policy — the PDF itself already gives concrete "Empirical Value" entries for all of these (not TBD), so no calibration sweep is owed here per the PDF's own table, but they have NOT been individually cross-checked against the actual chaincode implementation the way Anchor checkpoint interval was (where that cross-check found a real bug) — worth the same scrutiny if pursued |

**Every row the PDF itself marks "TBD" now has a final, defensible
resolution** — either real evidence (14 rows) or a documented structural/
methodological finding explaining why real evidence isn't obtainable
without a worse trade-off (4 rows: γ, W_max, µ, w6). K is a special case:
not a PDF "TBD" row in the strict sense (the PDF gives its own formula as
the "Empirical Value"), measured anyway per its stated calibration method,
but the mechanism it should control doesn't exist in code yet. The only
genuinely unaudited territory left is the batch of §H rows the PDF already
answers with concrete values and that this session never individually
cross-checked against the chaincode.
| 🔍 New finding, flagged not investigated | 1 | ME-S2's fp=4/fn=4 at scenario 10 traced to an RSSI-boundary sensitivity in the ME-S3 signature (sig[8]), unrelated to µ — discovered during the µ sweep, out of scope for this calibration pass |
| ⚠️ PDF value corrected (not a sweep — a factual mismatch found and fixed in documentation) | 1 | r_comm — the 300m design bound is correct for TTW placement/link-break logic and BSHH-S3's r_overlap (unchanged); the PDF's second stated value ("282.2m NS-3 Ch.178 effective") does not match actual code behavior (Ch178 is excluded from the live beacon-send path; real effective range on the 3 channels actually used is 100m, per an existing `CALIBRATION_VALUES.md` finding never previously cross-checked into this table); a 2026-07-27 detection-equation patch additionally split off a fourth value, `g_me_detect_range=170m`, used only by ME-S1 ρ_max/δ_thresh/ME link-reality checks — corrected empirical value: 300m (TTW/BSHH-S3) / 170m (ME detection-equation subset) / 100m (real achievable DSRC range) |
| ➖ Fixed, no sweep needed | ~12 | RSSI_min, all of §E (trust mgmt), d_in, λ_m, m, MCC_target, h_GRU, train/val/test split |
| ➖ Out of scope (explicit decision) | 1 | L_link/gamma for highway/rural — urban-only project scope, not evaluated |

Cross-reference: detailed run commands and per-run evidence for dim,
pos_weight, layers, and ce_weight all live in
`TGN_HYPERPARAMETER_CALIBRATION.md` §3c/§3d; θ_LW per-scenario evidence is
in this file's §A.1; W_max evidence is in §C above.
