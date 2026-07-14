# Session Handoff — PEM Metrics, Ablations, and Detection-Accuracy Fixes

**Context:** TETA-Guard SDVN implementation, `routing.cc` (156K+ lines), FYP — Dept. of EIE, University of Ruhuna.
**Build:** `cd /home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35 && ./waf build`
**IMPORTANT build gotcha:** waf sometimes reports "finished successfully" in <1s without actually recompiling (stale cache). Always force a clean rebuild before trusting a build result or running a smoke test:
```bash
rm -f /home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/build/scratch/routing.cc.*.o /home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/build/scratch/routing
cd /home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35 && ./waf build 2>&1 | tail -20
```
A genuine rebuild takes ~14-15s and shows `[N/2019] Compiling scratch/routing.cc` + `[N/2019] Linking build/scratch/routing`. If it finishes in under 1s with no "Compiling" line, it did NOT actually recompile — force it again.

**Note on reference material:** There is no accessible up-to-date paper/PDF in this repo. The `documents/Temporal_echo_project.pdf` was a stale early-draft progress report (explicitly says "no implementation, no NS-3, no GNN training" — contradicted by this entire codebase) and has been `git rm`'d (staged, not committed). All equations/architecture facts cited below (Eq. 3.11, 3.47/3.48, Table 3.4, the LW/FS/divergence 3-way split, etc.) came from the user directly quoting their own (external) source material during this session, cross-checked against the actual code — not from a file Claude can read. If the next session needs to re-verify against the paper, ask the user to paste the relevant section; do not assume a PDF in this repo is current.

---

## 1. What this session covered (chronological)

### 1.1 Full PEM metrics implementation (M1–M12)
All 12 paper metrics are implemented and exported to `pem_run_summary.csv`. Confirmed complete: M1 (MCC), M2 (TDRR/topology divergence), M3 (T_stale), M4 (PIR), M5 (T_pipeline), M6 (PDR/T_e2e), M7 (Ω comm overhead), M8 (scalability — left as post-processing per spec), M9 (F1 variant classification), M10 (FRA/FRR crypto pre-filter), M11 (FSR/QRR), M12 (trust/revocation/reassignment timing).

### 1.2 Full ablation implementation (A1–A14)
All 14 ablation toggles exist as CLI flags on `AblationFlags` (routing.cc ~2048). Confirmed complete via earlier audit.

### 1.3 100m calibrated range / 3-channel consistency fix
**Problem found:** `g_rcomm`/`TTW_COMM_RANGE` = 300m is the *protocol design* constant (used in Eq. 3.11 and all formal detection math — must never change). `kEffectiveReceptionRadius` = 100m (routing.cc ~1845) is the *empirically calibrated* real range under the actual Cost231 propagation model + 3 live 33dBm channels. Scenario construction was using the wrong one (300m) to pick "legitimate" vehicle pairs, causing benign events near the 100–300m boundary to spuriously trigger ME-S3 (ground-truth leak into false positives).

**Fixed:**
- `TtwFindNaturalBreakPairs`/`TtwEvaluateNaturalBreak` (TTW/BSHH scenario pair-selection) now use `kEffectiveReceptionRadius`, not `TTW_COMM_RANGE`.
- `MeSelectMutualRangePairNearRsu` (ME-S2/S4) already used 100m — confirmed correct, untouched.
- Live DSRC beacon/heartbeat TX (`AttackGetAllDSRCDevices`, used by `AttackSendDSRCBeacon`/`AttackSendHeartbeat`) restricted to the 3 calibrated 33dBm SCH channels (Ch172/174/176) — matches the channel set the 100m figure was actually measured under.
- Two scenario-agnostic ambient functions (`PemEmitVehicleBeacon`, `PemEmitNeighborObservation`) and the one genuinely-live ambient broadcast loop (`centralized_dsrc_data_broadcast`, routing.cc ~133621) were also switched from 300m to 100m and restricted to the 3 channels — these run regardless of `attack_scenario`, so they needed the same fix independently of the scenario-specific ones.

**Result:** confirmed via direct log tracing that the TTW-S4/ME-S4 false-positive class caused by this range mismatch is gone (`fp=0` across all 12 scenarios + baseline in the last full sweep).

### 1.4 ME-S3 controller-origin signature-misapplication fix (Phase 2)
**Problem found:** ME-S3 (`sig[8]`, Eq. 3.11 GPS/RSSI plausibility check) was firing unconditionally on controller-origin events (TTW-S3/S4, ME-S3/S4, `ME_Single3` modes 3/4) for two different underlying reasons:
- TTW-S3/S4: `reporterId=9999` (sentinel, no real vehicle) → RSSI lookup can never find real evidence → defaults to "too weak" → always triggers.
- ME-S3/S4/`ME_Single3` modes 3/4: `reporterId=false_v3` (a real vehicle) but `reporterPosition=ctrlPos` (the controller's own fixed location, a completely different entity) → `positionOutOfRange` is essentially always true.

**Why not just fix the position lookup to use the real vehicle's true position:** would be a ground-truth leak — in the real threat model the controller fabricates the entire report itself, so it could equally forge a *plausible* claimed position; using the simulator's omniscient real position gives the detector unrealistic information a real attacker's forgery could avoid.

**Verified NOT a bug (control group):** ME-S1 (`echo_v3`'s own real position) and ME-S2 (RSU's own real position) both have self-consistent `reporterId`==`reporterPosition` entity — legitimate, untouched.

**Fixed:** added `bool has_physical_reporter = true` to `PemEvent` (routing.cc ~2226) and a 13th trailing parameter to `PemEmitEvent` (default `true`), gated the ME-S3 check (`positionOutOfRange || rssiTooWeak`) on `event.has_physical_reporter`. Set `false` explicitly at all 7 confirmed controller-origin call sites: `TTWS3_RunDetection`, `TTWS4_RunDetection`, `ME_Single3_EchoAttack` (modes 3/4 only, via `echoHasPhysicalReporter = !(mode==3||mode==4)`), `ME_S3_InjectPhantomPaths` (×2 calls), `ME_S4_InjectPhantomPaths` (×2 calls).

### 1.5 Controller-divergence-mechanism independence (Phase 1)
**Problem found:** `PemControllerDivergenceGate` (Eq. 3.47/3.48, delta-divergence check) was nested inside `if (pem_last_alert) {...}` at all 7 controller-origin call sites — meaning it could only ever run *after* the LW/TGN score had already crossed threshold on its own. Per the source material quoted this session, the divergence mechanism is supposed to be the **primary, independent** detector for controller-origin attacks — the code's own comment (pre-existing) explicitly said the opposite ("this only gates the trust/mitigation-side consequence... PEM's own TP/FP/MCC/AUROC scoring is unaffected either way"), confirming a genuine implementation/spec mismatch.

**Fixed:** restructured all 7 call sites so the gate evaluates unconditionally; added `pem_divergence_true_positive`/`pem_divergence_false_negative` counters (tracked separately, ground truth is always "attack" at these call sites so no FP/TN tracked); mitigation now gates on `lwTgnAlert || divergenceConfirmed`. New CSV columns: `divergence_tp, divergence_fn, divergence_recall`.

### 1.6 Delta-threshold calibration bug (Phase 0 — found *because* of Phase 1)
**Problem found (confirmed with real numbers):** once Phase 1 let the gate run independently, it never actually confirmed anything — `delta_t=1` vs `delta_thresh=1639` at N=200 vehicles. Root cause, `PemComputeDeltaThreshold()` (routing.cc ~4003, before this fix):
1. `tau_prop_s = ⌈log2(N)⌉ × T_b` (a multi-hop network-diameter delay, ~8×T_b at N=200) — the paper's own worked example uses `tau_prop ≈ T_b/10` (a small propagation margin), an ~80× difference.
2. `lambdaHat = distinctVehicles.size() / (2×TTW_COMM_RANGE)`, then multiplied by `2×TTW_COMM_RANGE` again later in the same formula — **mathematically self-cancelling**, reducing the whole formula to `raw ≈ (1+tau_prop_s/Tb) × distinctVehicles.size()`, i.e. scaling linearly with total network population instead of a bounded local density.

**Fixed:** `tau_prop_s = PEM_BEACON_INTERVAL_S / 10.0` (matches paper exactly); replaced the self-cancelling `lambdaHat` with a genuine density using a new `kNetworkRoadLengthEstimateM = 2×(2460+2377)` (the known Colombo OSM map's perimeter, routing.cc ~152837 cites the same map dimensions for RSU grid placement) as an honest, documented proxy for "total road network length" — no exact per-segment SUMO road length is tracked in this NS-3 simulation.

**Validated:** at N=200, this gives `λ̂ ≈ 200/9674 ≈ 0.0207/m` (remarkably close to the paper's reference `λ=0.02/m`), reproducing `raw≈13.66 → delta_thresh=14`, matching the paper's stated worked-example result almost exactly. Confirmed live: `delta_thresh` dropped from 1639 to 13 in a real run, and ME-S3/S4 now correctly show `CONFIRMED DIVERGENCE` once delta accumulates past ~13 (verified in real log output — delta climbs 4→7→9→11→13→15... crossing the threshold organically as phantom reporters accumulate).

### 1.7 Combined detection metric (LW/TGN OR divergence)
Added `pem_combined_true_positive`/`pem_combined_false_negative` counters (same 7 call sites, same ground-truth-always-attack scope as divergence counters) and `combined_tp, combined_fn, combined_recall` CSV columns — the paper's 3rd reporting configuration (LW/TGN only; divergence only; combined), so suppressing ME-S3's inapplicable contribution (1.4 above) doesn't make the system look artificially worse in isolation when divergence is independently covering the same ground.

### 1.8 ME-S4 `tn=0` bug
**Root cause:** ME-S2/S4 hardcoded `RSU_Nodes.Get(0)` regardless of whether that specific RSU had a real local neighborhood for the given run/seed — forcing every one of that scenario's few benign events into the pre-existing `no_vehicle_within_effective_reception_range` exclusion bucket (a legitimate, already-working mechanism — see 1.10), leaving nothing to count as `tn`.
**Fixed:** new `SelectRsuWithViableNeighborhood(pool, atTime)` helper (routing.cc, near `MeSelectMutualRangePairNearRsu`) — picks whichever RSU actually has the most vehicles within `kEffectiveReceptionRadius`. Applied to ME-S2 and ME-S4's RSU selection.

### 1.9 ME-S1/ME-S3 pair-selection (mutual range, no RSU anchor)
**Root cause hypothesis (partially correct):** ME-S1/S3's "real link" `v1/v2` was picked as `pool[0]/pool[1]` with zero distance verification (unlike ME-S2/S4, anchored to a real RSU position). Added `SelectMutualRangePair(pool, atTime)` helper (no-RSU counterpart of `MeSelectMutualRangePairNearRsu`) — verifies the pair is genuinely within `kEffectiveReceptionRadius` of each other before use. Applied to ME-S1 and ME-S3's general (non-`ME_Single3`) paths.
**Caveat:** when actually tested on the specific failing case, the picked pair (`V45<->V46` internal indices 40/41) turned out to already be genuinely close (~5m) even before this fix — so this fix, while real and correct, was **not** the actual cause of the observed `fn=36` for ME-S3. Don't assume it alone explains any given run's numbers; the real cause was 1.10 below. Keep this fix (it's still correct and needed for cases where the pool really is spread out), just don't over-credit it.

### 1.10 ME-S3's real root cause: missing `PemEmitVehicleBeacon` call (the fix that actually matters)
**Root cause (fully confirmed, precise):** `g_rsu_beacon_log` (feeds ME-S1's Eq. 3.8 density threshold) is only populated by two paths: (a) real `PEM_EVENT_BEACON`-type receptions via `Rx()` → `PemEvaluateEvent` (subject to real 802.11p contention/collisions — unreliable at scale), and (b) direct, deterministic `PemEmitVehicleBeacon(...)` calls (simulation-level, always succeeds if the pair is within `kEffectiveReceptionRadius`, regardless of real radio contention).
- `ME_S1_LegitimateDiscovery` **already** calls `PemEmitVehicleBeacon` for both its pairs — this is why ME-S1 has always shown perfect `fn=0`.
- `ME_S4_VehiclesViaRSU_Continue` **already** calls it too (added previously as "Issue 4/3 fix", found this session while investigating — was initially missed because the function's real body is in a `_Continue` continuation scheduled 20ms later, not the entry function).
- `ME_S3_LegitimateDiscovery` was **missing** it entirely — relying purely on real, contention-prone radio reception for its only density evidence, at a network scale (200 vehicles) where that reception is unreliable. This is the actual, complete explanation for ME-S1 (perfect) vs ME-S4 (good, `tp=28/40`) vs ME-S3 (bad, `tp=4/40`) before this fix.

**Fixed:** added `PemEmitVehicleBeacon(v1_id, v2_id)` and (if `s3ld_link34`) `PemEmitVehicleBeacon(v3_id, v4_id)` to `ME_S3_LegitimateDiscovery`, matching ME-S1's exact pattern.

**STATUS: fix implemented and build-clean, but NOT YET RE-VERIFIED by a fresh run.** This is the single most important open verification item for the next session — see Section 2.

### 1.11 Scenario-validity exclusion mechanisms — confirmed working as designed, NOT bugs
Two pre-existing (predate this session) mechanisms, both verified correct via direct `SCENARIO_VALIDITY` CSV inspection:
- `no_vehicle_within_effective_reception_range` (excluded from confusion matrix) — correctly fires when an RSU/reporter genuinely has no viable local neighborhood for that run/seed (a scenario-construction limitation, not a detector failure).
- `no_real_reception_at_reporter` (deliberately NOT excluded) — genuine real-world channel contention on an otherwise-valid benign event; kept in the confusion matrix on purpose (reverted from exclusion in an earlier session after disproving that theory for a prior fp=16 case).

Do not "fix" either of these — they are validated, intentional design.

### 1.12 Vehicle-to-controller LTE fallback (Part A of a 2-part request — DONE, pending final regression confirmation)
**User request:** when no RSU is present, or a vehicle is not within any RSU's real 100m range right now, vehicles should communicate directly with **all 4 controllers** via LTE (the existing, previously-dormant hardware — `send_LTE_data_agent`, per CLAUDE.md Section 19/23).

**Implemented:** new function `VehicleControllerLteFallbackTick()` (routing.cc, placed right after `send_LTE_data_agent`'s definition to avoid needing a forward declaration). Runs every `PEM_BEACON_INTERVAL_S`, for every vehicle: checks real-time distance to every RSU; if none is within `kEffectiveReceptionRadius` (or `N_RSUs==0`), sends `send_LTE_data_agent` to **every** controller in `controller_Node` (confirmed `controller_Node.Create(N_Controllers)` — genuinely 4 separate nodes, not 1). Uses the correct `app_veh_base = N_Controllers + 1` offset into the `apps` container (the old, now-dead LTE scheduling code assumed a hardcoded `+2` offset from a pre-multi-controller architecture — do not copy that old offset pattern anywhere else in the file). Scheduled once at `t=0.5` in `main()`, right after the `apps` container is populated (`architecture==1` branch, since `architecture` defaults to 0... wait — actually the vehicles get apps via the `architecture != 1` branch which adds `LTE_Nodes` = `controller_Node + management_Node + Vehicle_Nodes`; confirm this branch is what's active by checking `architecture`'s runtime value if anything looks off).

**Verified so far:**
- Build is clean (genuine forced recompile confirmed).
- Smoke test (`N_Vehicles=10, N_RSUs=0, simTime=15`): no crash, but `simTime=15` was too short for TTW-S1's own attack timeline to complete (unrelated false alarm — CLAUDE.md's documented minimum for TTW-S1 is `simTime=30`).
- Smoke test (`N_Vehicles=200, N_RSUs=0, simTime=40`, real-network scale): clean exit, TTW-S1 attack sequence fires correctly (real HELLO beacon delivery logs at correct distances), and 315,984 `lte total packet size is ...` lines appeared — arithmetically consistent with 200 vehicles × 4 controllers × ~400 ticks over 40s.

**NOT YET DONE:** the full 12-scenario + baseline regression sweep was requested (to check for the exact interference CLAUDE.md's original "don't re-enable LTE" warning anticipated, especially in TTW-S1/BSHH-S1 which currently score `mcc=1`) — **results were never returned**; the user's next message pivoted to this handoff-doc request instead. **This sweep must be run and checked before trusting Part A is safe.**

### 1.13 Multi-neighbor beacon content (Part B of the 2-part request — NOT STARTED)
**User request:** each vehicle's beacon should carry its full currently-observed neighbor list (not just one neighbor), since `CustomDataTag1` already supports up to `max1` neighbor IDs (`nid_arr[max1+1]`) but `AttackSendDSRCBeacon` only ever populates `nid_arr[0]`.
**Status:** NOT implemented. Requires: (a) a way to track each vehicle's actual real-time observed-neighbor set, (b) modifying `AttackSendDSRCBeacon` (or adding a variant) to populate the full array from that set. Scoping/design not yet started — do this only after Part A's regression sweep is confirmed clean.

---

## 2. Immediate next steps (in order)

1. **Run the full 12-scenario + baseline regression sweep** (real-network scale, `N_Vehicles=200`, `simTime=40`, RSU counts per scenario: 0 for S1/S3/family-`-1`/`-3` variants i.e. scenarios 1,3,5,7,9,11; 64 for scenarios 2,4,6,8,10,12) to check:
   - Part A (LTE fallback) introduced no regression — especially TTW-S1/BSHH-S1 should stay at `mcc=1`.
   - ME-S3's `PemEmitVehicleBeacon` fix (1.10) actually closes the gap — expect `tp` well above the old `4/40` and `mcc` well above the old `0.1`, ideally approaching ME-S1/S4-like numbers.
   - No other scenario regressed.

   Clean + run commands:
   ```bash
   cd "/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY"
   rm -f *.csv
   cd /home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35
   for s in 0 1 3 5 7 9 11; do ./waf --run "scratch/routing --simTime=40 --N_Vehicles=200 --N_RSUs=0 --N_Controllers=4 --attack_scenario=$s"; done
   for s in 2 4 6 8 10 12; do ./waf --run "scratch/routing --simTime=40 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=$s"; done
   ```
   Then check:
   ```bash
   cd "/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/outputs/PEM_RUN_SUMMARY"
   for f in *.csv; do
     echo "--- $f ---"
     awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i=="tp")tp=i; else if($i=="tn")tn=i; else if($i=="fp")fp=i; else if($i=="fn")fn=i; else if($i=="mcc")mcc=i; else if($i=="divergence_tp")dtp=i; else if($i=="divergence_fn")dfn=i; else if($i=="combined_tp")ctp=i; else if($i=="combined_fn")cfn=i}
              NR>1{print "tp="$tp" tn="$tn" fp="$fp" fn="$fn" mcc="$mcc" | div_tp="$dtp" div_fn="$dfn" | comb_tp="$ctp" comb_fn="$cfn}' "$f"
   done
   ```

2. **If Part A regresses anything:** likely culprit is LTE traffic interfering with PEM event timing/scoring (the exact risk CLAUDE.md flagged). Consider gating the fallback tick more conservatively (e.g., only firing when genuinely useful, or moving its start time later past initial HELLO/discovery windows) rather than reverting outright — discuss with the user first.

3. **If ME-S3 still underperforms after 1.10's fix:** re-open the investigation — check whether `PemEmitVehicleBeacon`'s own internal range gate (`kEffectiveReceptionRadius`) is being satisfied for whatever pair got selected that run, and whether the neighborhood-tick warmup (`PEM_NEIGHBORHOOD_WARMUP_S = 10.0`, exactly coinciding with attack start — routing.cc ~7390) is still a contributing factor even with the deterministic beacon now added.

4. **Once Part A is confirmed clean, implement Part B** (multi-neighbor beacon content) — scope it as its own small task, don't bundle with anything else.

5. **Update the persistent memory files** (`/home/sdvn_echo_topology/.claude/projects/.../memory/`) — this session's `project_state.md` memory is now stale (still describes the pre-Phase-0/1/2 state). Should be refreshed to reflect the current, much-more-detailed picture once the above verification lands. This was not done during this session — flag it for the next one.

6. **Un-deleted PDF:** the stale `documents/Temporal_echo_project.pdf` removal is `git rm`'d but **not committed**. Confirm with the user whether to commit that deletion or leave it staged.

---

## 3. Things NOT to re-litigate (already settled this session, don't re-investigate from scratch)

- `g_rcomm`/`TTW_COMM_RANGE` = 300m is correct and must not change — it's the formal Eq. 3.11 design constant, separate from the empirically-calibrated 100m.
- ME-S1 and ME-S2's ME-S3 signature evaluation is legitimate (self-consistent reporter identity/position) — do not add `has_physical_reporter=false` there.
- The two scenario-validity exclusion categories (Section 1.11) are working as designed.
- `PemComputeDeltaThreshold`'s new formula (Section 1.6) was cross-validated against the paper's own worked example numbers (λ=0.02/m, τ_prop≈Tb/10 → raw=13.2 → thresh=14) and against a live run (thresh dropped 1639→13) — don't second-guess the formula itself without new contradicting evidence.
- `SelectMutualRangePair` (1.9) is real and correct but was NOT the actual cause of ME-S3's main detection problem — don't attribute ME-S3 improvements solely to it; the real fix is 1.10.

---

## 4. Prompt for the next session

Paste this as the first message in the new chat:

```
Continue work on the TETA-Guard SDVN project (routing.cc, ns-3.35). Read the handoff doc first:
"/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/documents/SESSION_HANDOFF_PEM_DETECTION_FIXES.md"

Then do this, in order:
1. Run the full 12-scenario + baseline regression sweep exactly as specified in Section 2, item 1 of the handoff doc (commands are given there verbatim). Report the tp/tn/fp/fn/mcc/divergence/combined table.
2. Confirm two things specifically: (a) TTW-S1 and BSHH-S1 are still mcc=1 (checking that the new vehicle-to-controller LTE fallback tick didn't introduce interference), and (b) ME-S3 (scenario 11) now shows tp well above the old 4/40 and mcc well above the old 0.1 (checking that the PemEmitVehicleBeacon fix actually closed the gap).
3. If anything regressed, investigate using the same file:line-cited, verify-before-concluding approach used throughout the handoff doc — don't guess, trace actual event logs and SCENARIO_VALIDITY output the way the doc's Section 1 entries do.
4. Once confirmed clean, implement Part B from the handoff doc (Section 1.13): give each vehicle's DSRC beacon its full real-time neighbor list, not just one hardcoded neighbor, using CustomDataTag1's existing multi-neighbor array (nid_arr[max1+1]).
5. Do not re-investigate anything listed in the handoff doc's Section 3 ("things not to re-litigate") without new contradicting evidence.

Remember: force a real rebuild (delete build/scratch/routing.cc.*.o and build/scratch/routing before ./waf build) before trusting any build result or smoke test — waf sometimes reports success without actually recompiling.
```
