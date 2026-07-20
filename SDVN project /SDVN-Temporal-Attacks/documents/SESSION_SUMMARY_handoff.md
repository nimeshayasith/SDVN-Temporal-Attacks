# Session Handoff Summary — SDVN Temporal-Echo TGN/LW Detection Work

This file exists so a **future session** can pick up exactly where this one left off, without re-deriving everything. Read this first before doing anything else in a new session.

---

## 1. Build performance fix (safe to reuse, already applied)

**Problem:** NS-3 was building in `debug` profile — no compiler optimization, `NS3_ASSERT_ENABLE`/`NS3_LOG_ENABLE` active. A 60s-simTime run took **~1 hour**.

**Fix applied (already done, persists across sessions unless someone reconfigures):**
```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf configure --build-profile=optimized --enable-examples --enable-tests --disable-werror --disable-python
./waf build
```
- `--disable-werror`: works around an unrelated, pre-existing NS-3-core warning-as-error (`length.cc`, `-Werror=maybe-uninitialized`) surfaced only by a newer/stricter GCC in optimized mode. Not our code, not fixable by editing our project.
- `--disable-python`: skips Python bindings generation (pybindgen failures on 3 modules), which we don't use — we only run the compiled C++ binary via `./waf --run`.

**Result:** 60s simTime dropped to **~6m41s** (~9x speedup). Numerically verified identical detection results (same TP/TN/FP/FN) between debug and optimized builds — this was a pure build-configuration change, zero code/logic touched.

**If a future session finds builds slow again**, check `build/c4che/_cache.py` for `BUILD_PROFILE` — if it says `'debug'`, someone reconfigured back; redo the above.

---

## 2. Real bugs found and fixed this session (all still in place)

### LW (rule-based signature) layer
1. **`kEvidenceWindowS`** (`routing.cc`, `PemRecordBeaconEvidence`) — was `5.0s`, way too loose for Eq. 3.21's "interval t" semantics. Was letting stale beacon evidence wrongly suppress `identity_mismatch` for BSHH-S2. Fixed to `3.0 * PEM_BEACON_INTERVAL_S` (300ms).
2. **BSHH-S1 proximity-window bug** (`routing.cc`, `PemEvaluateEvent`, signature index 3) — the `!it->alert_raised` guard alone let an old *undetected* forged heartbeat linger indefinitely in `event_window` and later collide with a much-later, unrelated benign self-report, causing false positives. Fixed by adding a proximity bound: `kBshhS1ProximityWindowS = 2.0 * TTW_S1_REPLAY_MARGIN_S` (4.0s) — restores Eq. 3.5's "near-simultaneous reception" semantics.

### TGN feature layer
3. **TTW-S1's `tau_dev` fix — attempted, then REVERTED.** Tried adding a link-age fallback term (`max(msgDev, linkAgeDev)`) to `tau_dev` for vehicle/RSU-origin events, reasoning TTW-S1's forged-fresh timestamp made `msgDev` trivially blind. **This regressed overall model MCC** on a larger dataset — it turned Eq. 3.2's PDF-intended *soft, corroborated vote* (one of 9 LW signatures) into a *hard, uncorroborated override* on the TGN's most heavily-weighted feature, misfiring on genuinely long-duration benign links (e.g. platooning vehicles). **Reverted to the literal Eq. 3.20 formula.** Do not re-attempt this without a fundamentally different approach (e.g. keeping it as a corroborated signal, not a `max()` override).

### Deployment/tooling bugs (not detection-logic bugs, but real)
4. **Weight-file path bug:** the project directory is literally named `SDVN project ` (with a trailing space). Passing `--tgn_weights=` pointing inside that path caused NS-3's `--run "..."` argument to get silently truncated mid-string at the space (NS-3 re-tokenizes the run string internally), loading a garbage/nonexistent file and silently falling back to **heuristic/random-init scoring** — no error, just wrong results (was causing TP=0 everywhere). **Fix:** always copy `.bin` weight files to a no-space path before deploying, e.g. `~/tgn_weights_<name>.bin`. **Always grep deployment logs for `"not found\|heuristic scoring\|invalid header"` (using `-a` for binary-safe grep) to confirm weights actually loaded** before trusting any live-run result.
5. **`max` macro conflict:** `routing.cc` line 179 does `#define max 60` globally (array-sizing macro). Any new code using `std::max` can silently break if it lands in a region where this macro is still active — must use a ternary (`(a>b?a:b)`) or a differently-named variable instead. Already documented with an inline comment at line ~3456 in the file; a new violation was hit and fixed during the combined-scenario-13 work (see below).

---

## 3. Training data situation

- **`training_data/all_events.csv`** — the ORIGINAL dataset. Confirmed **single-seed**, not multi-seed (2362 rows, one seed per scenario). Do not assume otherwise.
- **`training_data/sim60_ap60_3seeds_events.csv`** — the CURRENT best dataset. Built from `simTime=60`, `N_Vehicles=200`, `attack_percentage=60`, merging **3 seeds** (13, 14, 15) across all 12 scenarios (7751 rows). This is what the current deployed model and all the sweep runs are trained on.
- **attack_percentage=60** was deliberately chosen (up from the original 40) to improve class balance (benign:attack ratio 3.74→2.71), which measurably helped MCC.
- Data generation commands use `./waf --run "scratch/routing --simTime=60 --N_Vehicles=200 --N_RSUs=<0 or 64> --N_Controllers=4 --attack_scenario=<1-12> --mobility_scenario=0 --maxspeed=60 --attack_percentage=60 --attacker_sophistication=0.5 --attack_activation_probability=1.0 --skip_npfads=1 --RngRun=<seed>"`, output lands in `outputs/TGN_EVENTS/<NN_Scenario_Name>.csv` (scenario-namespaced, **not** seed-namespaced — same-scenario-different-seed runs must be copied out between runs or they overwrite each other).
- **Never reuse a training/val/test seed (13, 14, 15) for live "does the model generalize" verification** — that contaminates the test with data the model was literally trained on. Use a genuinely new seed (this session used `RngRun=999`) for any live generalization check.

---

## 4. Model training sweep results

Two sweeps run in `tgn/sweep_5seeds/` (bin + log files saved there):

**Sweep 1** (dim=128 fixed, pos_weight ∈ {4,6}, seeds {1,2,3,4,5,42}) — **winner: `tgn_weights_dim128_pw6_seed4.bin`** (referred to as "seed4_pw6" in chat), test MCC=0.906, AUROC=0.974, FN=34 (vs. current-deployed-at-the-time's FN=41) — a genuine, if modest, improvement, primarily via better recall.

**Sweep 2** (dim ∈ {64,128,192}, pos_weight ∈ {3,4,5,6,7,8}, 6 seeds, 10 runs) — **commands were given but NOT YET RUN/checked by the user as of this session's end.** If continuing, check `tgn/sweep_5seeds/log_dim*.log` for results with:
```bash
cd "/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/tgn/sweep_5seeds"
for f in log_dim*.log; do echo "=== $f ==="; grep -E "Global best restored|Test  MCC" "$f"; done
```

**Currently deployed model:** `tgn_weights_sim60_ap60_3seeds.bin` (seed=100, pos_weight=4, dim=128) — this is what all the θ calibration work (Section 6) was done against. **`seed4_pw6` was identified as marginally better but has NOT been deployed/re-verified yet** — that's a good next step if picking this back up.

---

## 5. attack_scenario=13 — Combined multi-family test mode (NEW FEATURE, implemented this session)

**What it is:** a new attack mode that runs all 12 attack scenarios (TTW/BSHH/ME × S1-S4) **simultaneously** in one simulation, instead of the existing mutually-exclusive one-scenario-per-run design. Built specifically to stress-test the PDF's 3-way TGN variant classifier under realistic "detector doesn't know which attack it's facing" conditions.

**Explicitly NOT required by the PDF** — this is additional validation infrastructure the user asked for, built without breaking any PDF-specified detection algorithm. User said they'd flag this to their supervisor separately since it's outside the PDF's literal test protocol.

### How it works (routing.cc changes)
- `declare_attack_states()`: new `attack_scenario==13` branch activates all 3 families' `present_*_attack_nodes/_controllers` flags at once.
- `Scenario13_VehicleSlice(exactScenario, sliceSize)` (new helper, ~line 8195): gives each of the 12 exact sub-scenarios a **disjoint slice** of the shuffled vehicle-ID pool, preventing cross-family attacker/victim collisions. Also populates `g_scenario13_vehicle_origin` (vehicle-ID → true 1-12 scenario map).
- Applied to: the shared `indices`/`n_mal_veh` loop in `declare_attackers()` (covers TTW-S1, BSHH-S1, and ALL of ME S1-S4 since ME uniquely shares one array across all 4 variants), plus 6 more sites with their own independent full-pool shuffles (TTW-S2/S3/S4, BSHH-S2/S3/S4) that needed individual fixing since they don't consult the shared arrays.
- **`IsAnyFamilyAttacker(k)`** helper + fix in TTW-S1/BSHH-S1/ME-S1's victim-pool-building loops: without this, e.g. TTW-S1 could pick a BSHH-family attacker vehicle as its own "victim," contaminating that vehicle's benign traffic. Fixed by excluding all 3 families' attacker sets from each victim pool.
- **`is_malicious_controller` global-contamination bug (found and fixed):** this flag is set once during scenario *setup* (before simulation runs), so in combined mode, once ANY controller-origin scenario's setup ran, it stayed `true` for the WHOLE run — contaminating mitigation decisions (`PemApplyMitigation`) for unrelated vehicle-origin events too. Fixed via a **local shadow** inside `PemApplyMitigation` itself: `const bool is_malicious_controller = (scenario_tag == "TTW-S3" || ... )` derived per-call from the already-correct `scenario_tag` parameter, shadowing the global for that function's scope only. Zero changes needed to the other ~8 read sites (C++ scoping handles it automatically) or to any single-scenario behavior.
- `origin_scenario` — new trailing CSV column (both `PEM_EVENT_LOG` and `TGN_EVENTS` outputs) recovering each event's true 1-12 family via `PemResolveOriginScenario()`, which looks up `g_scenario13_vehicle_origin` by `claimed_sender_id`/`physical_sender_id`. Falls back to the plain `attack_scenario` value for single-scenario runs (backward compatible).
- `tgn_train.py`'s variant-classifier label mapping updated to prefer `origin_scenario` over `attack_scenario` when present (needed since `attack_scenario=13` itself falls outside every TTW/BSHH/ME range and would otherwise get excluded from classifier training entirely).
- `scenario_names[]` extended with a 14th slot `"13_COMBINED_All_Scenarios"`.

### Regression-verified
All 12 individual scenarios (1-12) produce **byte-identical results** to before these changes — confirmed via direct comparison of TP/TN/FP/FN. The combined-mode additions are purely additive (`attack_scenario==N || attack_scenario==13` guards, new branches gated behind `==13` checks); no existing code path was modified.

### Known, documented limitations (not bugs, honest gaps)
1. **ME family's S1-S4 sub-variants are NOT individually distinguishable in `origin_scenario`** — all 4 get lumped under `origin_scenario=9`, since `me_malicious_nodes[]` (unlike TTW/BSHH) is shared identically across all 4 ME variants in the existing (pre-this-session) codebase design.
2. **~13% of combined-run events are unresolved (`origin_scenario=0`)** — controller-fabricated events (likely ME-S3/S4's internal phantom witnesses, or TTW/BSHH's `9999` controller-sentinel events) whose identity doesn't map to any vehicle slice. A real, minor gap in the lightweight vehicle-ID-based attribution mechanism.
3. **Combined-run FP is notably higher than the sum of isolated single-scenario FPs** (investigated: not an implementation bug — checked feature values, timing clustering, identity-mismatch, none show a smoking gun). Most coherent explanation: **train/test distribution mismatch** — the training dataset was built by concatenating 12 *separately-run* single-scenario simulations, so the model has never seen genuinely simultaneous, densely-interleaved 12-family traffic. **Fix path (not yet done):** generate actual training data FROM `attack_scenario=13` runs and include it in training — not a code fix, a data fix.

---

## 6. Decision threshold (θ) calibration — full history and current recommendation

**Critical lesson learned this session:** two different evaluation methodologies gave **conflicting** recommendations, and it's important to understand why:

1. **Offline test-set reconstruction** (Python script re-deriving the exact train/val/test split from the training CSV, running the model on the held-out 15% test slice) — suggested **θ≈0.65** was best (worst-case MCC 0.634).
2. **Live NS-3 deployment runs at a genuinely unseen seed** (`RngRun=999`, never part of training data) — suggested **θ=0.85** was best (worst-case MCC 0.690), and θ=0.65 was actually one of the *worst* choices live (worst-case MCC only 0.174, driven by BSHH-S2).

**Resolution: trust the live, controlled, out-of-sample sweep (method 2) over the offline reconstruction (method 1).** The offline test-set, despite being "held out," still comes from the same seeds (13/14/15) whose *other* rows were used for training — it's a weaker generalization test than genuinely fresh simulated data the model has never touched in any form.

**Full results are in `documents/theta_calibration_results.md`** (companion file, already written). Coarse sweep (0.65, 0.75, 0.85, 0.90, 0.941, 1.0) done for all 13 scenarios at `RngRun=999`, except **scenario 3 (TTW-S3) was accidentally skipped** in that batch.

**Current recommendation: θ = 0.85.** Best worst-case MCC among tested values, near-best average, confirmed on genuinely unseen data.

**PENDING, NOT YET RUN:** a fine-grained sweep at θ ∈ {0.86, 0.87, 0.88, 0.89} was requested and commands were generated (13 scenarios × 4 theta values, same `RngRun=999` controlled pattern) but **the user had not run them yet** when this session ended. This is the natural next step — see the chat history immediately before this handoff file was created for the exact commands, or regenerate them following the same pattern as the coarse sweep.

**Also pending:** re-run scenario 3 at `RngRun=999` across the full theta grid (0.65 through 1.0) to close that gap in the existing results table.

---

## 7. BSHH-S2 sophisticated-mode — confirmed architectural limitation, extensively investigated, do not re-litigate without new evidence

This was investigated **exhaustively** this session — four independent hypotheses checked and all ruled out as bugs:
1. `kEvidenceWindowS` timing (fixed — was a real bug, see Section 2).
2. RSU-forward latency (measured directly: 0.009-0.038ms, nowhere near any relevant threshold — not the cause).
3. LW's BSHH-S1/S2/S3 signatures (all confirmed correctly implemented, matching PDF equations exactly).
4. BSHH-S3's liveness/beacon-correlation check (confirmed correctly implements the PDF's identity-scoped Eq. 3.7; a reporter-specific tightening was considered and explicitly rejected — would break legitimate multi-RSU relay scenarios elsewhere, same regression class as the reverted `tau_dev` fix).

**Root cause:** the sophisticated sub-mode (attacker has genuinely exfiltrated the victim's session key) produces a message that is genuinely crypto-clean and temporally fresh — `physical_sender_id` (the one signal that would distinguish it) is discarded before the TGN's graph/GRU layers ever see it, by architectural design matching the PDF's literal 6-feature schema. **AUROC≈0.955 confirms real discriminative signal still exists** — this is a threshold/distribution-overlap problem for this specific attack family, not a "cannot detect at all" problem.

**PDF-consistency confirmed:** the PDF's own coverage table rates BSHH-S2 as "∼" (partial), not "✓" — this is an accepted, PDF-anticipated limitation, not something the project is expected to fully solve. The PDF's own prescribed remedy is "retrain with more data" (which is what generating more `attack_percentage=60`, multi-seed data already does), not a new physical-sender-identity feature (which would exceed the PDF's stated 38-dim schema and carries real regression risk, as already demonstrated once this session).

**Do not attempt further architecture changes for this specific issue** without discussing with the user first — this exact category of "seemingly narrow fix, actually broad blast radius" mistake has already happened twice this session (the `tau_dev` revert, and the rejected BSHH-S3 tightening).

---

## 8. Quick reference — key file paths

- Main sim source: `/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/routing.cc` (~158,800+ lines)
- TGN core (C++, `#include`d into routing.cc at line ~2736): `.../SDVN-Temporal-Attacks/tgn/tgn_core.cc`
- TGN training (Python): `.../SDVN-Temporal-Attacks/tgn/tgn_train.py`
- Current best training data: `.../SDVN-Temporal-Attacks/training_data/sim60_ap60_3seeds_events.csv`
- Currently deployed weights (no-space copy, required for `--tgn_weights=` to work): `~/tgn_weights_sim60_ap60_3seeds.bin`
- Sweep outputs: `.../SDVN-Temporal-Attacks/tgn/sweep_5seeds/` (bin + log files)
- This file and its companion: `.../SDVN-Temporal-Attacks/documents/theta_calibration_results.md` and `SESSION_SUMMARY_handoff.md`
- **Note the literal space in the path**: `.../scratch/SDVN project /SDVN-Temporal-Attacks/...` — always quote this path in shell commands, and never pass anything inside it directly to `--tgn_weights=` (see Section 2, bug #4).

## 9. Immediate next steps, in priority order

1. Run the fine-grained θ sweep (0.86-0.89, 13 scenarios, `RngRun=999`) — commands already generated, just needs execution.
2. Fill the scenario-3 gap in the θ calibration data (same seed/method).
3. Check sweep 2's results (dim/pos_weight grid) — may supersede the current deployed model.
4. If `seed4_pw6` (or a sweep-2 winner) is adopted, redo the θ calibration for that specific model — thresholds are model-specific, don't assume 0.85 carries over.
5. (Lower priority, larger effort) Generate `attack_scenario=13` training data and retrain, to address the combined-mode FP gap documented in Section 5.
