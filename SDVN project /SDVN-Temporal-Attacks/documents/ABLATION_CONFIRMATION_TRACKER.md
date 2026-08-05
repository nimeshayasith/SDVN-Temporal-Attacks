# Ablation Confirmation Tracker

Tracks, per ablation (A1–A14), whether the current IV range/script/flag configuration has been (a) verified correct per the checklist and PDF, and (b) empirically confirmed to produce real, sensible, non-degenerate results — not just "the script runs without crashing."

Two different things are tracked separately and must not be conflated:
- **Script/IV-range correctness** — does the sweep script pass the right flags over the right range, per the corrected checklist?
- **Empirical confirmation** — has real CSV/log data actually been pulled and checked to behave the way the PDF/ablation's own hypothesis predicts?

An ablation is only marked ✅ CONFIRMED when both are true and the underlying data has been personally verified in this investigation (not inferred from script inspection alone, and not carried over from a stale/pre-fix binary run).

---

## ✅ CONFIRMED

### A3 — Static GCN (No Temporal Memory), `--static_gcn=1`

**IV:** `T_obs ∈ {60,120,180,240,300}` s — 5 equal 60s steps (updated from PDF's raw 3-point `{50s,150s,300s}`). Scenario: sc1 (TTW-S1).

**Bug found and fixed:** `sweep_a3.sh` originally only ran `--static_gcn=1` — a single arm with no baseline to contrast it against, structurally unable to demonstrate the "isolated contribution of temporal memory" Table 4.2 says this ablation tests. Added the missing baseline arm (full temporal GRU, flag omitted), same pattern as A4's fix.

**What was checked (60s validation, Tobs=60 point, both arms):** `PEM_RUN_SUMMARY`'s combined tp/tn/mcc came out bit-identical between arms (`tp=1160, tn=940, mcc=1.0, auroc=1.0`) — same "wrong column" trap as A2: `--static_gcn` only calls `TGN_SetStaticGCN`, touching the FS/TGN pipeline exclusively, never the LW rule-based detector, and TTW-S1's timestamp-mismatch signature is caught by LW alone with 100% accuracy regardless of TGN, masking the entire ablation at the combined-metric level.

**Why acceptable:** reading `TGN_SUMMARY.csv` (TGN-only accuracy) instead reveals the real, striking, PDF-consistent result — static GCN (no temporal memory): `tp=0, fn=1160, mcc=0.000` (complete detection failure); full temporal GRU: `tp=1073, fn=87, mcc=0.893, recall=0.925`. This is exactly what the ablation should show: TTW is a fundamentally temporal attack (a replayed/forged timestamp is only anomalous relative to beacon history), so a single-snapshot static GCN has no basis to ever flag it, while the GRU's temporal memory recovers strong detection.

**What to know:** always read `TGN_SUMMARY.csv`'s own tp/fn/mcc for A3, never `PEM_RUN_SUMMARY`'s combined columns — same caution as A2. Full 5-point × 2-arm sweep not yet launched; held pending explicit go-ahead (60s validation only, per standing instruction not to run 310s sweeps without confirmation).

### A8 — No Smart Contract Enforcement, `--mitigation_delay_intervals=k` / `--no_blockchain=1`

Three real bugs found and fixed:
1. Grace-window PDR sampling was nested inside the `!pem_attack_active` branch, making it logically impossible to ever populate during the very withheld-enforcement period A8 is designed to measure. Hoisted to an independent measurement dimension.
2. `PemInEnforcementGraceWindow` never returned true for `--no_blockchain=1` (guard required `mitigation_delay_intervals>0`, never set for that flag). Fixed to treat `no_blockchain` as a permanent, unbounded grace window.
3. `PEM_ROUTING_EDGE_FRESHNESS_S=0.2s` (borrowed from an unrelated crypto-layer freshness bound, Eq. 3.16, never specified by the PDF for this purpose) made the topology census see 0 qualifying entries on ~97.6% of ticks. Replaced with `ttw_link_lifetime_bound` (`L_link = 2·r_comm/v_max`), a PDF-grounded constant already used elsewhere in the codebase for the identical "how long is a topology observation still valid" question.
4. A fourth, family-specific gap found via the full sweep review: `PemComputeRealRoutingPdr()` (the grace-window census function) iterated exclusively over `ttw_controller_table` (TTW/ME's topology-adjacency structure), never touching `bshh_controller_liveness_table` — what BSHH-S1 actually poisons — so `attempted` stayed 0 for BSHH runs regardless of k/no_blockchain (`pdr_during_grace_pct=-1` for every condition despite `tp=373` real detections). Fixed by adding a dedicated BSHH liveness census branch reusing the exact delivery semantics already validated by the working per-event heartbeat PDR path (a claim is "delivered" iff the physical sender's live position is within `kEffectiveReceptionRadius` of the claimed identity's live position), not the TTW BFS-over-adjacency path (`HeartbeatPacket` has no route endpoints to run BFS over).

**What was checked:** two-point validation (TTW, k=10 vs no_blockchain) passed with real, distinct, directionally-sensible values (68.43% vs 31.62%). Full 21-run sweep review (2026-08-05) confirmed sc1 (TTW-S1) and sc9 (ME-S1) correct — sc1 matches the two-point validation exactly across k∈{0,2,4,6,8,10}+no_blockchain (k=0→-1 as expected, k=2..10≈68-70%, no_blockchain≈31.6%); sc9 correctly shows -1 everywhere since tp=0 (zero detections ever fire — the already-confirmed 100% Stage-0 crypto-layer blocking for ME-S1). After the BSHH census fix, the full BSHH k-sweep (k∈{0,2,4,6,8,10}+no_blockchain, 60s) shows real, monotonic, sensible values: k=0→-1 (correct), k=2→97.28%, k=4→98.64%, k=6→99.09%, k=8→99.32%, k=10→99.46%, no_blockchain→98.73% (sits between k=6/k=8, directionally consistent with permanent withhold accumulating slightly more exposure than a bounded window — same pattern as TTW).

**Why acceptable:** all four bugs were genuine logic gaps (nesting, missing guard case, wrong constant, missing per-family code path), not disagreements with the ablation's design — the underlying grace-window mechanism now measures exactly what A8 is meant to measure, across all three attack families, with real and directionally-sensible numbers.

**What to know:** confirmed at 60s validation scale only; full 310s × {TTW,BSHH,ME} × {k∈0..10, no_blockchain} sweep not yet launched. Temporary `[A8-TTW-DIAG]`/`[A8-GRACE-DIAG]`/`[A8-ATTEMPTED-DIAG]` diagnostics still present in code, not yet removed.

### A4 — Fixed δ_thresh (No Mobility-Adaptive Threshold), `--no_mobility_adapt=1`

Three real, independent bugs found and fixed:

1. **`mean_pir` metric-definition bug.** The M4 PIR reporter-set insert (`pem_link_reporters[linkKey].insert(reporterId)`) ran unconditionally at the very top of `PemEmitEvent`, before Stage-0/Stage-1 detection ever ran — counting every *attempted* report regardless of whether it survived crypto/signature filtering, rather than the controller's actual surviving belief (`|P_controller|`, per the struct's own comment). Since the attack-injection schedule is deterministic and identical between arms, this made `mean_pir` structurally incapable of reflecting any detection-threshold change. Fixed by moving the insert to after `PemEvaluateEvent(event)`, gated on `!event.alert_raised` (and implicitly on having survived Stage-0, since a Stage-0 rejection returns before this point).

2. **Wrong representative scenario.** `sweep_a4.sh` used `attack_scenario=9` (ME-S1) as ME's representative scenario — a local implementation choice, not a PDF requirement (Table 4.2's A4 row names no specific ME variant). This was wrong: the PDF's own Table 4.10 discussion states ME-S1/S2 attacks are structurally intercepted by the Stage-0 location-binding quorum check (Eqs. 3.29-3.32) before ever reaching Stage-1, where ρ_max/δ_max (what `--no_mobility_adapt` freezes) actually operate — confirmed even at the PDF's own full 300s/2361-event corpus, ruling out "run longer" as a fix. Switched to `attack_scenario=11` (ME-S3, controller-origin, no network-layer packet for Stage-0 to intercept) — confirmed working: `tp=28` (N=100) attack events genuinely reach Stage-1, `crypto_drop_quorum=0`.

3. **λ̂ input signal never populated.** `PemComputeLambdaHat` reads only from `g_rsu_beacon_log`, which is populated exclusively by `PemNeighborhoodDiscoveryTick` — gated behind `--enable_neighborhood_beaconing=1`, default off, never passed by any ablation script. Without it, λ̂=0 always, so the "adaptive" ρ_max/δ_max silently floored to their hard minimums (2 and 1) for every N — the adaptive arm was never actually adaptive across the entire N range. PDF Eq. 3.8's own text requires exactly this feed ("λ̂(t) is... updated dynamically from RSU-observed beacon rates at each time step"). Added `--enable_neighborhood_beaconing=1` to both arms; confirmed safe (per the tick function's own comment, it never touches `PemEmitEvent`/`PemEvaluateEvent` or any scored counter, unlike the earlier, unrelated `PemPeriodicBeaconTick` regression).

**What was checked — full 5-point (N∈{100,200,300,400,500} × adaptive/fixed, 60s) validation:**

```
N     lambda_hat   rho_max(adaptive)   rho_max(fixed)
100   0.023        9                   4
200   0.028        11                  4
300   0.038        15                  4
400   0.067        27                  4
500   0.097        39                  4
```

λ̂ and ρ_max scale smoothly and monotonically with density across the entire tested range — confirms the adaptive mechanism is genuinely operational end-to-end, not just at two endpoints.

**Why acceptable despite `mean_pir`/`mcc` being identical between arms at every single N:** this is a separate, legitimate finding, not a symptom of remaining brokenness. ME-S3 injects only ~2 fake reporters per attack round — never enough to exceed even the *fixed* ρ_max=4, let alone the much larger adaptive values — so detection is carried entirely by the growth-rate/δ_max branch throughout the whole range, which the PDF's own Eq. 3.10 worked examples predict should stay pinned at 1 "across all realistic SDVN conditions" regardless of density. That is exactly what was observed at all 5 points, confirming the mechanism behaves PDF-consistently even though the downstream PIR/MCC metric doesn't separate.

**What to know:** confirmed at 60s validation scale across the full prescribed N range; full 5-point×2-arm×310s sweep not yet launched (held pending review of other in-flight ablations). Temporary `[A4-DIAG]` print still present in code (`PemComputeRhoMaxForLink`), not yet removed.

### A5 — No HMAC + Timestamp + Nonce Pre-Filter, `--no_crypto=1`

**IV:** attacker origin ∈ {vehicle, RSU, controller} — a categorical 3-point sweep per PDF Table 4.2 (not a numeric range). Mapped onto `attack_scenario=1/2/3` (TTW-S1/S2/S3) as the three origin representatives — PDF names no specific attack family for A5 either, so this is an implementation choice, same unconstrained-choice situation as A4's original ME pick, but a defensible one here since A5 tests the crypto pre-filter generically rather than a family-specific mechanism.

**No code bug found** — unlike A4/A8/A9, this was purely a stale-data concern, not a logic defect. `--no_crypto=1` was independently confirmed to bypass `PemCryptoPreFilter` entirely, matching Eqs. 3.15-3.17.

**What was checked:** the existing `veh_sc1`/`rsu_sc2`/`ctrl_sc3` results (dated Aug 2) predate this session's confirmed fixes (notably the `PEM_ROUTING_EDGE_FRESHNESS_S→ttw_link_lifetime_bound` swap, which directly affects the M6 PDR census A5 also depends on). A 60s spot-check on `veh_sc1` confirmed the concern was real: `pdr_under_attack_pct` swung from 95.03% (stale) to 19.27% (current binary) — though the exact attribution between the code fix and the 60s-vs-310s duration difference wasn't fully isolated. Full 60s structural-sanity check across all three origins on the current binary:

```
              tp    fn   fp   mcc     pdr_under_attack_pct  fra  frr  crypto_drop_mac/stale/nonce
veh_sc1      1387    0    0   1.000   19.27%                 -    -   0/0/0
rsu_sc2       402   18    0   0.968   25.71%                 1    0   0/0/0
ctrl_sc3       53    0    0   1.000   24.50%                 1    0   0/0/0
```

**Why acceptable:** none of the failure signatures checked for appear — no `tp=0` despite known attacks, no FP explosion, no MCC collapse, no `pdr=-1`, no missing T_det/FRA/FRR. `crypto_drop_mac/stale/nonce=0` across all three confirms the bypass is genuinely active (nothing gets dropped at Stage-0, as expected when it's disabled). RSU shows a small, non-degenerate miss rate (`fn=18`, `mcc=0.968`) rather than a suspiciously perfect or zero result — real, non-trivial variation, not a masked failure. `pdr_under_attack_pct` is consistent (19-26%) across all three attacker origins, not wildly divergent.

**What to know:** confirmed structurally operational at 60s across all three origins on the current binary. Full production sweep (`veh_sc1`/`rsu_sc2`/`ctrl_sc3` at 310s) not yet launched — held pending explicit go-ahead.

### A7 — No Location-Binding + Quorum (ME Defence), `--no_lbs=1`, `--echo_dist_ratio=X`

**IV:** echo reporter distance from claimed link, `d ∈ {1.0, 1.5, 2.0, 2.5, 3.0}×r_comm` — 5 equal steps extended from the PDF's raw 3-point `{1.0, 1.5, 3.0}×r_comm`. Scenarios: all 4 ME variants (sc9=ME-S1, sc10=ME-S2, sc11=ME-S3, sc12=ME-S4). **Applicable PEMs per PDF: M4 (PIR), M1 (ME scenarios), M11 (QRR)† — not raw `tp`/`mcc`**, an initial wrong-column read (same class as A2/A3/A12) corrected during this review.

**No code bug found** — mechanism-level fixes for A7 were already made in an earlier session (documented in the code's own `A7 fix, parts 1-3` comments): the location-binding gate (Eq. 3.29-3.31) and quorum check (Eq. 3.32) previously ran unconditionally in `teta_guard_filter.h` regardless of `--no_lbs`, silently blocking ~99% of ME-S1/S2 traffic even with the ablation "on"; both are now correctly gated, and QRR bookkeeping was relocated to the crypto-layer gate that's actually exercised under the ablation.

**What was checked:** full 5-point × 4-scenario sweep at 60s on the current binary, reading `mean_pir`/`qrr_echo_attempts`/`qrr_echo_pass`/`qrr_echo_blocked`/`qrr`:

```
sc9 (ME-S1, vehicle-origin):  qrr_attempts=120  qrr_pass=120  qrr_blocked=0  qrr=0.0   mean_pir=2.5-3.0
sc10 (ME-S2, RSU-origin):     qrr N/A — events never reach the QRR measurement stage
sc11 (ME-S3, controller):     qrr N/A — events never reach the QRR measurement stage
sc12 (ME-S4, controller+RSU): qrr N/A — events never reach the QRR measurement stage
```

**Why acceptable:** `qrr=0.0` for sc9 is exactly the correct signature of a fully-disabled quorum defense (`qrr_pass==qrr_attempts`, `qrr_blocked=0` — every forged echo now admitted), and `mean_pir≈3` independently confirms the surviving forged echoes are actually contributing to the phantom-path belief — the ablation is affecting the intended ME defense, not merely changing a counter. sc10/11/12 showing `qrr_attempts=0` was investigated at the code level (not just inferred) and resolved as **QRR not applicable, not untracked**: the real `pem_qrr_echo_attempts++` counter (teta_guard_filter.h:747) is not scenario-scoped in code — it only requires having survived the *earlier*, un-ablated location-binding entry gate. sc10 (RSU-origin) is legitimately stopped earlier by that separate, still-active base HMAC/identity check (Eq. 3.15) before ever reaching the QRR measurement point — a malicious RSU doesn't possess the impersonated vehicle's session key (same root cause already confirmed for sc10's `tp=0` in the A10 review). sc11/sc12 (controller-origin) have no external packet entering the crypto-filter path at all, so QRR is architecturally inapplicable there — not a measurement failure, consistent with the PDF's own `M11 (QRR)†` dagger footnote. sc9 is the only origin where the forged claim is signed using a legitimate vehicle identity/session key, so it legitimately reaches the location-binding/quorum stage — exactly where `--no_lbs=1` should have an observable effect, and does.

| Item | Finding |
|---|---|
| `--no_lbs=1` mechanism | Correctly bypasses location-binding + quorum |
| `--echo_dist_ratio` | Correctly changes echo-attacker placement |
| PIR response | Changes/accumulates as expected |
| QRR, sc9 | 0.0; all attempts pass |
| QRR, sc10 | Correctly not applicable — blocked earlier by HMAC |
| QRR, sc11/sc12 | Correctly not applicable — no crypto-layer packet path |
| Instrumentation gap | None |
| Scenario-specific QRR scope bug | None |
| `tp`/`mcc` flatness | Not the A7 target signal |

**What to know:** confirmed at 60s across all 4 scenarios and the full 5-point range, reading the correct PIR/QRR columns (not `tp`/`mcc`, which stay flat for an unrelated, separately-explainable reason — redundant detection from the still-active LW ME-S1/S3 signatures). Full 310s production sweep not yet launched — held pending explicit go-ahead.

### A6 — No Threshold Aggregate Signature (BSHH Defence), `--bshh_s1_fc=N`

**IV:** colluding Byzantine vehicles `fc ∈ {1,3,5,7,9}` — 5 equal steps of 2, symmetric around and including the real threshold `t=5` (`t=⌊n/2⌋+1`, `n=8`, matching PDF Eq. 3.28 and the codebase's own calibrated per-RSU-zone vehicle count). Scenario: sc5 (BSHH-S1) only — the only scenario where `--bshh_s1_fc` has a wired effect.

**Bug already found and fixed (documented in `sweep_a6.sh`'s own header):** `--no_threshold_sig=1` was previously always-on, unconditionally bypassing `PemVerifyThresholdSig` and making forgery succeed at every `fc≥1` regardless of collusion size (flat `fsr=1`, no step function — confirmed as the literal "before" data via an old stale smoke test, `~/ablation_sweep_smoke60/a6`, which reproduced exactly this flat-1 pattern). Fixed by removing the flag so the real threshold check runs.

**What was checked:** full 60s validation across `fc∈{0,1,3,5,7,9}` on the current binary (sweep had been interrupted mid-run previously — only `fc1`, stale, had completed).

```
fc     fsr_attempts   fsr_success   fsr
0      0              0             0
1      1              0             0
3      1              0             0
5      1              1             1   <- jump at t=5
7      1              1             1
9      1              1             1
```

**Why acceptable:** this is exactly the predicted step function — `FSR(fc)=0` for `fc<t` and jumps to `1` at `fc=t=5`, staying at 1 above threshold. Clean, real, non-degenerate result; `tp/fp/fn/mcc` also sane throughout (`mcc=1.0`, `fp=0` at every point).

**What to know:** confirmed at 60s scale with the corrected script. Full 5-point 310s sweep not yet launched — held pending explicit go-ahead.

### A10 — Immediate Removal (No Quarantine Pipeline), `--no_quarantine=1`, `--detector_fp_rate=X`

**IV:** injected detector false-positive rate `X ∈ {0.0, 0.01, 0.02, 0.03, 0.04, 0.05}` (0-5%) — 6 equal 1% steps matching the corrected checklist range. Scenarios: sc2 (TTW-S2), sc6 (BSHH-S2), sc10 (ME-S2) — RSU-present representatives per family, since quarantine/removal is a controller/RSU-layer mechanism.

**No code bug found** — same category as A5, purely a stale/incomplete-data situation. Existing canonical data (Aug 2) only had 3 of 6 x points (`{0.0,0.02,0.05}`) and predated this session's fixes, plus some leftover unscoped folders from an earlier combined-mode script version.

**What was checked:** full 6-point sweep across all 3 scenarios at 60s on the current binary:

```
sc2 (TTW-S2)   x=0.0  0.01  0.02  0.03  0.04  0.05
  fp             0    10    18    27    32    40
  mcc          0.982 0.960 0.943 0.924 0.914 0.898

sc6 (BSHH-S2)  x=0.0  0.01  0.02  0.03  0.04  0.05
  fp             0    11    23    32    39    48
  mcc          1.000 0.988 0.976 0.966 0.959 0.949

sc10 (ME-S2)   x=0.0  0.01  0.02  0.03  0.04  0.05
  tp             0     0     0     0     0     0
  fp             0     0     1     2     3     3
  mcc            1     1     0     0     0     0
```

**Why acceptable:** sc2/sc6 show exactly the expected mechanism — with quarantine buffering removed, injected false positives translate directly into real `fp` counts and monotonically degrade `mcc`, a clean "immediate removal amplifies FP harm" signal. sc10's `tp=0` throughout is the same already-confirmed ME-S2 Stage-0 MAC-blocking behavior (independent of `--no_quarantine`, which doesn't touch Stage-0 any more than A7's `--no_lbs` did); its `mcc` collapsing to `0` once `fp>0` is the correct degenerate-case value (same MCC design already confirmed during the A1 review: the CSV-write-time override to `1.0` only applies when `fp==0 && fn==0`, not merely `tp+fn==0`). Notably, `--detector_fp_rate` visibly produces real `fp` in sc10 even though `tp` never leaves 0 — confirming the injection mechanism is genuinely independent of whether real attacks reach detection, not silently no-op'd by the Stage-0 block.

**Considered and confirmed acceptable (no code change):** sc10's `mcc=0` at `x≥0.02` was briefly questioned (fp comes from *injected* detector noise on benign traffic, not from misjudging real attackers, since ME-S2 is Stage-0-blocked) — but this is the same underlying situation as A1's already-accepted `rinj=0 → mcc=0` case: whenever the detection-stage confusion matrix never sees real attack ground truth (either because none were injected, or because they were filtered upstream before reaching this stage), `mcc=0` is the mathematically honest result once any `fp>0` occurs — it reflects a detector with zero true-positive evidence producing wrong positive predictions, not a broken metric. Both cases confirmed acceptable on the same reasoning; no epsilon/override change made.

**What to know:** confirmed at 60s across all 3 scenarios and the full 6-point range on the current binary. Full 310s production sweep not yet launched — held pending explicit go-ahead.

### A1 — LW Detection Stage Only, `--no_tgn=1`

**IV:** `r_inj ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}` — 6 equal steps across the full injection range, matching the corrected checklist range. Scenarios: sc1 (TTW-S1), sc5 (BSHH-S1), sc9 (ME-S1).

**What was checked:** `mcc`, `tp`, `fp`, `fn`, `tn` per scenario per rinj point.

**Result:**
```
sc1 (TTW-S1): rinj=0.0 -> mcc=0 (tp=0,fp=5,fn=0,tn=935)   rinj=0.2..1.0 -> mcc=1, tp scales 9916->49966, fp=fn=0
sc5 (BSHH-S1): rinj=0.0 -> mcc=1 (tp=0,fp=0,fn=0,tn=285)  rinj=0.2..1.0 -> mcc=1, tp scales 6933->35114, fp=fn=0
sc9 (ME-S1):   ALL rinj -> mcc=1 (tp=0,fp=0,fn=0,tn=2), including rinj=1.0
```

**Why this is acceptable:**
- **sc1's `mcc=0` at rinj=0 is correct, not a bug.** The 5 false positives are real detector mistakes against a genuinely attack-free baseline — reporting `mcc=0` (rather than an artificially forced `1.0`) honestly reflects that the detector isn't flawless, even with no attacks present. Traced to the code's own deliberate special-case logic (`routing.cc:6986-6990`): `mcc` is only force-set to `1.0` when `fp==0 && fn==0` exactly; a nonzero `fp` correctly falls through to the raw MCC formula's `0.0` degenerate-denominator default. This is intentional — the code does not paper over real false positives.
- **sc5's `mcc=1` at rinj=0 (`fp=0,fn=0`) is the same special case, correctly triggered** — a genuinely clean, error-free baseline.
- **sc9's `mcc=1` at every rinj, including 100%, is expected — not a broken pipeline.** ME-S1's forged echo reports are caught and dropped at the Stage-0 crypto pre-filter (HMAC/timestamp/nonce) before ever reaching the LW/TGN anomaly-scoring pipeline — confirmed ~84-100% Stage-0 blocking rate for ME-S1/S2 is already documented in the code's own comment at the same site. With crypto genuinely neutralizing the attack before scoring ever happens, there is structurally nothing for the scorer to get right or wrong, and `mcc=1` correctly represents that outcome rather than "perfect anomaly detection."

**What to know:** don't be misled by `tn=2` (a tiny sample count) into assuming sc9 is a data-starved/broken run — it's small because almost nothing reaches the scoring stage at all when crypto pre-filtering is this effective, which is itself the expected result for this attack family under A1's LW-only configuration.

**Considered but rejected:** adding a blanket `+ε` to the raw MCC formula's numerator/denominator to force `mcc=1` whenever there are no ground-truth positives (`tp+fn=0`). Rejected because the denominator's degenerate `0` triggers purely from `tp+fn=0`, **regardless of `fp`** — a uniform epsilon fix would also silently convert sc1's real `fp=5` case to `mcc=1`, undoing the deliberate design distinction already in the code. The existing `fp==0 && fn==0`-guarded special case already implements exactly the intended behavior; no code change was needed here.

---

### A2 — TGN (Full-Stack) Detection Stage Only, `--no_lw=1`

**IV:** `r_inj ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}` — 6 equal steps, matching the corrected checklist range. Scenarios: sc1 (TTW-S1), sc5 (BSHH-S1), sc9 (ME-S1).

**Important gotcha — wrong metric caught mid-investigation:** `--no_lw=1` forces `event.alert_raised=false` (`routing.cc:9191-9198`), which feeds `PEM_RUN_SUMMARY.csv`'s generic `tp/fp/fn/tn/mcc` columns — that is specifically the **LW path's own bookkeeping**, deliberately zeroed out by design when LW is disabled. Reading that column for A2 makes it look like TGN caught 0% of every attack (`tp=0`, `fn=`full attack count) — which is **not** what's happening; it's just the wrong column. TGN's own outcome lives in a separate `TGN_SUMMARY/*.csv` file (columns `tp,tn,fp,fn,mcc,recall,...`), unaffected by `--no_lw`.

**What was checked (from `TGN_SUMMARY`, not `PEM_RUN_SUMMARY`):**
```
sc1 (TTW-S1): rinj=0.0 -> mcc=0.000 (tp=0,fp=3,fn=0,tn=609)
              rinj=0.2..1.0 -> mcc=0.919-0.929, recall=0.993-0.998, tp scales 9844->49881, small real fp(7-19)/fn(73-87)
sc5 (BSHH-S1): rinj=0.0 -> mcc=1.000 (clean baseline, tp=0,fp=0,fn=0,tn=285)
               rinj=0.2..1.0 -> mcc=0.974-0.986, recall=1.000, tp scales 6933->35116, small real fp(8-14), fn=0
sc9 (ME-S1):   mcc=1.000 throughout (tp=0,fp=0,fn=0,tn=2), including rinj=1.0
```

**Why this is acceptable:** genuinely realistic detector performance — `mcc` in the 0.92-0.99 range (not artificially saturated at a suspicious flat 1.0 the way the wrong-column reading suggested), sensible `tp` scaling proportional to injection rate, small nonzero `fp`/`fn` counts reflecting real (if minor) imperfection, near-perfect but not literally-perfect recall. sc1's `mcc=0` at rinj=0 is the same legitimate "few real false positives at a genuinely attack-free baseline" pattern already validated for A1 — not forced to `1.0` because the special case correctly requires `fp==0`. sc9's flat `mcc=1` is the same Stage-0 crypto pre-filter blocking explanation as A1 (upstream of both LW and TGN, so unaffected by which detector is disabled).

**What to know:** always read `TGN_SUMMARY`'s own `tp/fp/fn/tn/mcc` columns for any ablation that disables/isolates a specific detection stage (A1/A2 and similar) — `PEM_RUN_SUMMARY`'s generic columns reflect whichever stage's `event.alert_raised` was left active, and can look like a total failure for the *other* stage when it's actually just not the column being measured.

---

### A11 — No LKH (Naive Flat Re-Keying), `--no_lkh=1`

**IV:** `n ∈ {50, 100, 150, 200, 250, 300}` vehicles — 6 equal 50-step points, matching the corrected checklist range (previously only `{50,100,150,200}`, 4 points).

**What was checked:** `lkh_crypto_mean_ms` (the real `CryptoMeasureLKH`/`TimedLkhRevoke` wall-clock cost per revocation operation — not `t_revoke_ms`, which is a scheduling-artifact latency measure unrelated to the LKH tree operation's own cost).

**Result (post-fix binary, verified column-by-name not `$NF`):**
```
N=50  -> 123 LKH calls, mean=0.039ms
N=100 -> 242 LKH calls, mean=0.068ms
N=150 -> 468 LKH calls, mean=0.149ms
N=200 -> 635 LKH calls, mean=0.197ms
N=250 -> 759 LKH calls, mean=0.222ms
N=300 -> 905 LKH calls, mean=0.229ms
```

**Why this is acceptable:** clean, monotonically increasing trend across the full corrected 6-point range, with substantial per-point sample sizes (123–905 calls — not single-sample flukes). The diminishing rate of increase at higher N is consistent with O(log n) LKH tree-depth scaling, exactly what this ablation is meant to demonstrate (naive flat re-keying removed, LKH's own real per-operation cost measured directly).

**What to know:** an earlier "confirmed" claim for A11 in this investigation turned out to be wrong — the dataset it was based on predated the `lkh_crypto_mean_ms` CSV column entirely (confirmed by checking the CSV schema directly: the column literally didn't exist in that file) and was missing N=250/300 outright. The result above is from a genuinely fresh rerun on the current binary, with the column verified by name via `csv.DictReader`, not a blind trailing-field guess.

---

### A13 — Single KEM (ML-KEM-1024 Only, No HQC-5), `--single_kem=1`

**IV:** `r_hs ∈ {10, 55, 100, 145, 190}` handshakes/s — 5 equal 45-step points, matching the corrected checklist range (previously unequal `{10,50,100,200}`).

**What was checked:** `n_handshakes_timed`, `avg_handshake_ms`, `over_budget_pct` from `KEM_HANDSHAKE_SUMMARY`.

**Result:**
```
r_hs=10  -> n_handshakes=199, avg=0.252ms, over_budget=0%
r_hs=55  -> n_handshakes=199, avg=0.244ms, over_budget=0%
r_hs=100 -> n_handshakes=199, avg=0.271ms, over_budget=0%
r_hs=145 -> n_handshakes=199, avg=0.244ms, over_budget=0%
r_hs=190 -> n_handshakes=199, avg=0.233ms, over_budget=0%
```

**Why this is acceptable, despite the flat numbers:** the flat `n_handshakes≈199` (≈N_Vehicles) across every rate is confirmed **by design**, not a bug — `--kem_handshake_rate=r_hs` only controls the *inter-arrival spacing* between one-time per-vehicle handshakes at startup, not a sustained arrival process over the whole run (confirmed directly from the code comment at the flag's declaration: "only inter-arrival spacing changes"). So a constant handshake count at every rate is the correct, expected behavior of the mechanism as implemented.

**What to know — this is a legitimate but underwhelming finding, not a broken ablation:** at every tested rate (up to 190/s, i.e., ~5.3ms spacing between successive handshakes), the real per-handshake crypto cost (~0.23–0.27ms) never comes close to producing measurable contention or exceeding any latency budget — so `avg_handshake_ms` and `over_budget_pct` are flat because the system genuinely handles all tested rates with negligible overhead, not because the measurement is broken. If the eventual writeup wants to demonstrate a *breaking point* for single-KEM handshake overhead, the tested rate range would need to go well beyond 190/s — that's a scope decision for the writeup, not a defect in the current implementation. As specified by the checklist's own range, A13 is complete and correctly executed.

### A9 — Equal-Weight PBFT (No Trust Weighting), `--equal_weight_pbft=1`, `--byzantine_peer_count=N`

**IV:** Byzantine peers in the active consensus set, `fb ∈ {0,1,2,3}` — complete per the corrected checklist range (real safety bound is `f=(64-1)/3=21` for RSU-present scenarios, but the PDF's own X-variable stays at `{0,1,2}` plus one failure-mode point, not a sweep to the true bound). Scenarios: sc2 (TTW-S2), sc6 (BSHH-S2), sc10 (ME-S2) — RSU-present representatives, since Byzantine peer count is meaningless without RSU infrastructure.

**Real bug found and fixed:** PBFT voting committee was scaling with `RSU_Nodes.GetN()` (up to 64) instead of the fixed 5 RSU + 3 OBU (or 8 OBU) Fabric deployment pool. Fixed in `routing.cc` (committee capped to the real pool). Root-cause diagnosis (temporary `[A9-DIAG]` print, later replaced by permanent `pem_pbft_attempt_count`/`pem_pbft_abort_count`/`pbft_pass_rate` CSV columns) confirmed the underlying consensus math is correct.

**What was checked:** the canonical `~/ablation_sweep/a9/` sweep folder is invalid (missing `byz=3` entirely, and its CSVs predate the `pbft_pass_rate` column existing at all — `None`, not just stale). A separate, complete 60s validation run (`~/ablation_sweep/a9_test60/`, dated Aug 4 21:56) has all 4 byz points across all 3 scenarios with the real columns present:

```
             byz=0   byz=1    byz=2    byz=3
sc2 (TTW-S2)  100%   88.98%   75.12%   0%
sc6 (BSHH-S2) 100%   94.92%   80.34%   0%
sc10 (ME-S2)   -1     -1       -1      -1   (pbft_attempt_count=0 at every point)
```

**Why acceptable:** sc2 and sc6 both show a clean, monotonic degradation in `pbft_pass_rate` as Byzantine votes rise, with a real, dramatic finding at `byz=3` — consensus pass rate collapses completely to 0% (every attempt aborted), showing exactly where the trust-weighting safety margin breaks. sc10 correctly shows `pbft_attempt_count=0`/`pbft_pass_rate=-1` (sentinel, not broken) at every byz — consistent with the already-established finding that ME-S2 attacks never generate an alert in the first place (Stage-0 MAC-blocked, per A7/A10's identical finding), so PBFT mitigation never has anything to vote on.

**What to know:** use `~/ablation_sweep/a9_test60/`, not the canonical `~/ablation_sweep/a9/` folder (invalid — missing column, missing byz=3). Confirmed at 60s across all 3 scenarios and the full 4-point range. Full 310s production sweep not yet launched — held pending explicit go-ahead.

### A12 — No Topology Divergence Detector (Controller-Origin Blind), `--no_divergence_detector=1`

**IV:** controller-origin injection rate `rinj ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}` — 6 equal steps, matching A1/A2's rinj-range fix (was 3 unequal points `{0.01,0.05,0.10}`). Scenarios: all 6 controller-origin variants (sc3=TTW-S3, sc4=TTW-S4, sc7=BSHH-S3, sc8=BSHH-S4, sc11=ME-S3, sc12=ME-S4).

**No code bug found** — the canonical `~/ablation_sweep/a12/` folder was simply never run with the corrected rinj range at all (every existing folder used the old `{0.01,0.05,0.10}` naming/values, Aug 2, predating the fix entirely). This needed a full run from scratch, not a bug fix.

**Metric-reading correction:** `PEM_RUN_SUMMARY`'s combined `tp`/`mcc` stayed flat (`mcc=1.0`) across every rinj, which initially looked like the ablation had no effect — same wrong-column trap as A2/A3. The PDF's actual applicable PEMs for A12 are the dedicated `divergence_tp`/`divergence_fn`/`divergence_recall` columns (isolated divergence-mechanism outcome), separate from `combined_tp`/`combined_recall` (LW/TGN OR divergence — the paper's own documented 3-way reporting split, routing.cc:2774-2782).

**What was checked:** full 6-point × 6-scenario sweep (36 runs) at 60s on the current binary:

```
              rinj=0.0   0.2   0.4   0.6   0.8   1.0
sc3  divergence_recall:   1     0     0     0     0     0
sc4  divergence_recall:   1     0     0     0     0     0
sc7  divergence_recall:   1     0     0     0     0     0
sc8  divergence_recall:   1     0     0     0     0     0
sc11 divergence_recall:   1     0     0     0     0     0
sc12 divergence_recall:   1     0     0     0     0     0
combined_recall: ~1.0 at every point across all 6 scenarios (sc11 shows tiny real misses, 0.9999 at higher rinj)
```

**Why acceptable:** `divergence_recall=0` at every rinj>0, uniformly across all 6 scenarios, is exactly the correct, deterministic signature of the ablation — traced to code: `confirmed = (!g_abl.no_divergence_detector) && (delta > thresh)` (routing.cc:5329) hard-forces the divergence gate's confirmation to false whenever the flag is set, regardless of the actual delta/threshold comparison. `combined_recall≈1.0` staying high is not a masking bug — it reflects that these controller-origin attacks are also caught by the independent LW/TGN detector, exactly the redundant-defense architecture the paper's own 3-way reporting split (`pem_true_positive` / `pem_divergence_true_positive` / `pem_combined_true_positive`) is designed to reveal: ablating one defense layer in isolation doesn't blind the whole system when another independent layer covers the same ground.

**Family-specific nuance worth preserving:** the combined `mcc` (`PEM_RUN_SUMMARY`'s `tp`/`fn`/`mcc`, reflecting the same LW/TGN-OR-divergence combined outcome) is a *flawless* `1.0` at every rinj for all 4 TTW/BSHH controller-origin scenarios (sc3/4/7/8) — full redundant coverage, no real misses. **ME's controller-origin variants (sc11/sc12) show real, non-trivial gaps**: `mcc` drops to 0.71-0.89 with genuine `fn>0` (1-2 real misses per run), and sc11 specifically shows a real degrading trend as rinj rises (`mcc: 0.816→0.707`, `fn: 1→2`). This means the divergence detector is not merely redundant for ME's controller-origin family the way it is for TTW/BSHH — disabling it produces a measurable, if partial, real detection gap. Consistent with the broader pattern seen across nearly every ablation this session (ME behaves differently from TTW/BSHH throughout), not a red flag on its own, but a genuine result worth reporting distinctly rather than treating "combined_recall stays high" as uniform across all 6 scenarios.

**What to know:** confirmed at 60s across all 6 controller-origin scenarios and the full 6-point range, reading `divergence_recall`/`divergence_fn`, not the combined `tp`/`mcc`. Full 310s production sweep not yet launched — held pending explicit go-ahead. (One infrastructure note, not an ablation issue: several runs in this validation batch were initially lost to `/tmp` filling up from accumulated earlier-session scratch data — cleaned up and reruns completed successfully.)

---

## 🔴 STALE — SCRIPT/DESIGN CORRECTED, RERUN PENDING REVIEW

A14 — stale canonical output (pre-dating the corrected IV ranges/flags found earlier in this investigation) and/or genuine design issues found and fixed (A3/A4/A5/A6/A7/A8/A9/A10/A12 moved to CONFIRMED above; see those entries for what changed):
- **A14**: restored `--no_reassign=1` (was incorrectly removed) and confirmed `nC∈{0,1,2,3,4}` range; plot metric switched from `t_reassign_ms` (structurally flat under `--no_reassign=1` by construction) to `mean_topology_divergence`/`mcc`/`pdr_post_mitigation_pct` (M1-M4 style, matching the PDF's actual applicable-PEMs list for this ablation).

---

## Open, unrelated issue (not an ablation bug)

**LTE eNB SRS-periodicity crash**: found during A4's 5-seed sweep — `N=300`, 2 of 5 seeds crashed with `"too many UEs (321) for current SRS periodicity 320"` (`lte-enb-rrc.cc:2979`), an uncaught NS-3 fatal error. Seed-dependent at fixed N, suggesting RNG-driven mobility/attach-timing sensitivity near a hard capacity boundary. Affects any sweep with enough vehicles regardless of attack logic (potentially A11's N=300 point too — not yet re-checked for this specific crash). Not yet investigated/fixed.
