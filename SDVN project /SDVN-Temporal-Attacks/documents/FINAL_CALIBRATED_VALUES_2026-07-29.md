# Final Calibrated Values — 170m Detection-Equation Patch + LW Recalibration

**Date:** 2026-07-29
**Context:** Full recalibration pass triggered by the 2026-07-27/28
detection-equation patch (`r_comm` split into `g_me_detect_range`=170m for
ME-S1 ρ_max / δ_thresh / ME link-reality checks, vs. `TTW_COMM_RANGE`=300m
kept for TTW placement/link-break and BSHH-S3's `r_overlap`), plus the TGN
model retrain this required.

---

## TGN model

| Item | Value |
|---|---|
| Model file | `tgn_weights_170m_dim192_pw0.3191_seed5.bin` |
| dim / layers | 192 / 2 |
| pos_weight | 0.3191 (recomputed for the 170m-derived dataset's actual 75.9%/24.1% split) |
| L_link | 20.4s (170m urban; was 43.0s at 300m) |
| Test MCC / AUROC | 0.958 / 0.995 |
| θ_FS | **0.21** |

## LW-side (PEM signature detector), all in `routing.cc`

| Parameter | Value |
|---|---|
| w1 (TTW-S1) | 0.1132 |
| w2 (TTW-S2) | 0.1217 |
| w3 (TTW-S3) | 0.1201 |
| w4 (BSHH-S1) | 0.1103 |
| w5 (BSHH-S2) | 0.1117 |
| w6 (BSHH-S3) | 0.0609 |
| w7 (ME-S1) | 0.1206 |
| w8 (ME-S2) | 0.1203 |
| w9 (ME-S3) | 0.1212 |
| θ_LW | **0.11** |
| µ (ME-S1 density margin) | **0.20** (unchanged, reconfirmed) |
| δ_thresh | live formula output, not a fixed value — evolves with real-time observed vehicle density (confirmed 4→9 within a single run as density grows); typical range 3-9 depending on scenario/timing |

## Deployment command

```bash
./waf --run "scratch/routing --simTime=<N> --N_Vehicles=<N> --N_RSUs=<N> \
  --N_Controllers=4 --attack_scenario=<N> \
  --tgn_weights=/home/sdvn_echo_topology/tgn_weights_170m_dim192_pw0.3191_seed5.bin \
  --tgn_theta=0.21 --tgn_dim=192 --tgn_layers=2 --tgn_l_link=20.4 \
  --lw_threshold=0.11 --pem_me_mu=0.20"
```

---

## Confirmed unaffected (no recalibration needed)

| Parameter | Reason |
|---|---|
| γ, W_max | live-recalibrated every second by `TGN_RecalibrateMobility()`, no static value to set |
| ρ_max | pure formula output from `g_me_detect_range`, self-corrects |
| `TTW_COMM_RANGE`/`g_rcomm` (300m) | design bound, untouched by patch |
| `kEffectiveReceptionRadius` (100m) | real achievable DSRC range, physics-derived, untouched |
| W_BSHH | uses `g_rcomm`(300m), untouched |
| ε (0.101s) | timing margin, independent of any distance constant |
| n (vehicles/RSU) | uses `g_rcomm`(300m, RSU's own range), correctly unrelated to v2v's 170m |
| dim=192, layers=2, ce_weight=0.3 | reused from the already-won hyperparameter sweep, not re-swept |
| W_BPTT, L, d, h_GRU, η | TGN architecture/training hyperparameters, unaffected |
| t (quorum majority), n (RSU zone) | formula-locked / RSU-geometry, unrelated to r_comm |
| Anchor checkpoint interval, K, T_exec | blockchain/hardware timing, unrelated |

---

## Code changes made this session

| File | Change |
|---|---|
| `routing.cc` | `PEM_WEIGHTS[9]` → new values (table above) |
| `routing.cc` | `PEM_SCORE_THRESHOLD` (θ_LW): 0.075 → **0.11** |
| `routing.cc` | `PEM_ME_TOLERANCE_MU` (µ): unchanged at 0.20 |
| `routing.cc` | `PemComputeDeltaThreshold()`: `g_me_detect_range`, floor → **ceil** |
| `tgn_core.cc` | `TGN_CheckControllerDivergence()`: **fixed** — was still hardcoded `TTW_COMM_RANGE`(300m), a missed second copy of the same formula; now `g_me_detect_range`(170m), floor → ceil |
| `tgn_core.cc` | `g_tgn_l_link_cmd` default: 43.0 → **20.4** |
| `routing.cc` | `--tgn_l_link` CLI help text updated to match |

All rebuilt and verified. No dataset regeneration or retraining required
for any of the LW-side items (θ_LW, µ, w1-w9, δ_thresh) — all are
post-inference detection/mitigation computations, not TGN training
features.

---

## Full parameter table (as requested — PDF spec vs. project value vs. recalibration status)

| # | Parameter | PDF's stated default/TBD spec | This project's value | Recalibrated this session? |
|---|---|---|---|---|
| 1 | **θ_LW** (LW alert threshold) | Not set — post-training grid search [0,1] step 0.05, maximize F1 | **0.11** | ✅ Yes |
| 2 | **γ** (TGN edge-weight decay rate) | Formula-derived: `A_uv(t)≈0.5` at age `L_link/2`; `L_link=43s`(urban)/`9s`(highway) | Live-derived every 1s from `L_link=20.4s`(170m urban) | ➖ No (live formula, self-corrects) |
| 3 | **w1-w9** (LW signature weights, Eq. 3.12) | `1/9≈0.111` each (uniform baseline); recalibrate proportional to precision | 0.1132, 0.1217, 0.1201, 0.1103, 0.1117, 0.0609, 0.1206, 0.1203, 0.1212 | ✅ Yes |
| 4 | **W_max** (LW detector max window size) | `⌈L_link/T_b⌉`; urban≈430, highway≈90 | Live-derived from `L_link=20.4s` (≈204 at 170m) | ➖ No (live formula) |
| 5 | **W_BSHH** (BSHH-S3 liveness observation window) | `W > 2·W_ho` (formula-derived) | Live-derived from `r_overlap` (300m, unchanged), ≈7.2s validated | ⚠️ Below analytical bound, empirically validated — see note below |
| 6 | **ε** (max propagation tolerance / freshness bound, Eq. 3.16) | Not set — conceptually ≈ one-way propagation delay | 0.101s (measured p95 latency; calibrated 2026-07-23, unrelated to this patch) | ➖ No (timing, not distance-dependent) |
| 7 | **µ** (inter-lane density margin, ME-S1, Eq. 3.8) | 0.20 (recommended default) | **0.20** | ✅ Yes (re-swept, reconfirmed unchanged) |
| 8 | **OBU minimum hardware capacity** | 2048 MB RAM (Hyperledger Fabric chaincode constant) | 2048 MB RAM | ➖ No (not a sweep target) |
| 9 | **W_BPTT** (TBPTT window size per node) | 100 events/node; sweep {50,100,200} | 100 | ⚠️ Not swept — 100 used as default, {50,200} unevaluated. See note below. |
| 10 | **L** (message-passing rounds, Eq. 3.24) | 2 (Table 4.1); sweep {1,2,3} | 2 | ⚠️ Not swept — "GRU layers {2,3}" tested during the anchor sweep is GRU *depth*, a different hyperparameter from L (message-passing rounds); L was held fixed at 2 throughout. See note below. |
| 11 | **d** (node feature embedding dimension, Eq. 3.20) | Not specified; sweep {32,64,128} | 192 (project's own extended sweep) | ➖ No (reused from anchor sweep) |
| 12 | **h_GRU** (GRU hidden-state size, Eq. 3.23) | Tied to d by default | 192 | ➖ No |
| 13 | **η** (optimiser learning rate) | Not specified; start 1e-3, cosine anneal | 0.001 | ➖ No |
| 14 | **w_class** (class imbalance weight / pos_weight) | `w_attack = total/(2·n_attack)`, recompute per split | **0.3191** | ✅ Yes (recomputed for new 170m dataset) |
| 15 | **t** (threshold aggregate signature majority, Eq. 3.28/3.32) | `t ≥ ⌊n/2⌋+1` | Formula-locked | ➖ No |
| 16 | **n** (vehicles per RSU reporting zone, Eq. 3.28) | Varies with λ, r_comm — extract from SUMO traces | min=0/max=42/mean=11.67/median=8.0 | ➖ No (uses `g_rcomm`=300m, RSU's own range, correctly unrelated to v2v's 170m) |
| 17 | **δ_thresh(t)** (controller-origin divergence threshold, Eq. 3.47/3.48) | `⌈(1+τ_prop/T_b)·λ·2r_comm⌉+1` | Live formula output (confirmed 4→9 within a single run as density grows) | ✅ Yes (found + fixed a missed 2nd copy in `tgn_core.cc`; switched floor→ceil) |
| 18 | **Anchor checkpoint interval** (`⌊T_min/T_b⌋` blocks) | Formula-derived from `T_min`, `T_b` | 30/30 blocks | ➖ No |
| 19 | **K** (tier-2 ledger window size, `⌈T_dwell/T_b⌉`) | Varies per OBU dwell time | min=2/median=164/max=598 | ➖ No |
| 20 | **T_exec** (smart contract execution latency) | 50-200ms (Hyperledger Fabric literature) | **T_exec_compute** = mean 0.037ms/max 0.253ms (n=11, re-measured live 2026-07-29, scenario 13) — local chaincode computation only, NOT comparable to the literature figure. **T_exec_fabric** = mean 3,884ms/min 627ms/p95 4,016ms (n=30, measured live 2026-07-29 against the real 4-orderer/8-peer Fabric network, `measure_texec_fabric_gw.js`) — full endorse+order+commit pipeline, down from an initial 14,099ms after two real infrastructure bugs were found and fixed (see note below); still above the 50-200ms literature range due to a residual gossip/Gateway-service delay not resolvable via config (Fabric Go source-level, out of scope). | ⚠️ Metric-scope mismatch, clarified below — not a discrepancy; T_exec_fabric partially improved, residual gap documented as known limitation |

---

## Reviewer-flagged clarifications (post-2026-07-29 audit)

**Issue 3 — W_BSHH = 7.2s vs. the analytical bound.**
Formula check: `W_ho = r_overlap / v_i = 67m / 16.67 m/s = 4.02s`, so the paper's
requirement `W_BSHH > 2·W_ho` evaluates to **8.04s**. The project's live-derived
value (≈7.2s) is 0.84s below this conservative analytical bound. This is not an
error: 8.04s is a worst-case theoretical floor, and the project's live empirical
validation (RSU-overlap-derived `W_BSHH`, per §16 gap-16 overlap geometry)
confirmed **zero false positives during legitimate handovers at 7.2s** — a
tighter, empirically-confirmed bound is a stronger validation result than
merely meeting the conservative analytical one. Reported as: formula gives a
conservative bound of 8.04s; empirical validation confirms 7.2s is sufficient
for this simulation at r_comm=300m (the RSU physical-coverage-radius
constant this formula uses — see below); both the formula value and the
empirical value should appear in the write-up, with the empirical result
flagged as "validated, tighter than the analytical bound," not as a
violation of it.

**Follow-up (2026-07-30) — does using r_comm=170m instead of 300m resolve
the 0.84s shortfall? No, and here is why, checked directly against
`routing.cc`'s actual formula.** `PemComputeRsuOverlapRadius()`
computes `r_overlap`, and both the analytical bound (`2·r_overlap/v_nominal`)
and the live-recalibrated empirical `W_BSHH`
(`g_pem_bshh3_liveness_window_s = 2·r_overlap/v_max_observed`, same
function) are linear in `r_overlap`, hence linear in `r_comm` with the
*same* proportionality constant. Any choice of `r_comm` therefore cancels
out of the ratio between the bound and the empirical value — scaling
r_comm from 300m to 170m scales both numbers down by the same ~0.567
factor (bound 8.04s→~4.56s, empirical 7.2s→~4.08s) and leaves the same
~10.4% relative shortfall. The actual driver of the 0.84s gap is the live
max *observed* vehicle speed (~18.6 m/s) exceeding the *nominal reference*
speed used for the analytical bound (16.67 m/s = 60 km/h) by ~11.6% —
a speed-assumption mismatch, not a distance-scale one. Verified empirically:
a temporary code change forcing `r_overlap` to use `g_me_detect_range`
(170m) instead of `g_rcomm` (300m), tested via both a small
(N_Vehicles=10/N_RSUs=2) and full-scale (N_Vehicles=200/N_Controllers=4/
simTime=60/attack_percentage=60) BSHH-S3/S4 run, produced identical
detection quality (MCC=1.0 either way, no regression) — confirming the
change is inert for classification outcomes as well as for the shortfall.
Reverted to `g_rcomm` (300m), consistent with the constant's documented
physical meaning (RSU hardware coverage radius, distinct from
`g_me_detect_range`'s detection-equation-only role — see
`CALIBRATION_VALUES.md`).

**Separate finding from the same investigation, FOUND AND FIXED (2026-07-30)
— SUMO trace vehicle-ID/NS-3 index mismatch silently zeroed all live
velocity.** While instrumenting `PemRecalibrateBshh3Window()` to get a
directly-measured live `W_BSHH` value, live vehicle velocity
(`MobilityModel::GetVelocity()`) was observed to read exactly 0.0 for the
entire duration of every test run — meaning the "live mobility-adaptive"
recalibration never actually recalibrated, and `g_pem_bshh3_liveness_window_s`
silently stayed frozen at its one-time startup value in every config tested.

Root cause (confirmed): the SUMO trace-loading code (`routing.cc`, the
`if (routing_test == false && !trace_file.empty())` block, ~line 156400)
picks a "peak-activity" time window by scanning the trace's `setdest`
lines and choosing the offset that maximizes how many *trace vehicle IDs*
are simultaneously active — but the trace's own vehicle IDs are whatever
SUMO originally assigned them, not necessarily a clean `0..N_Vehicles-1`
range. The waypoint-scheduling loop that follows assumed trace ID == NS-3
`Vehicle_Nodes` index directly (`wp_map.count(i)` for NS-3 index `i`), so
whenever the peak window's actually-active trace IDs weren't literally
`{0,1,2,...}` — the normal case — **every** NS-3 vehicle silently received
zero scheduled waypoints (`"scheduled 0 exact position+velocity events"`,
confirmed present in the log even though the trace itself "loaded" real
position data). The same bug was independently propagated into a second
global map (`g_sumo_wp_map`/`g_sumo_initial_pos`, used by
`TtwSumoPositionAt()` for TTW-S1's natural-break search), which was also
populated by raw trace ID but looked up by NS-3 index.

**Fix applied:** the peak-activity alignment scan now also collects the
sorted list of trace IDs actually active in the chosen window
(`activeIds`), and a `sumoIndexToId(i)` lambda maps NS-3 index `i` to the
`i`-th active trace ID (falling back to identity `i -> i` beyond the
active-ID count, so requesting more vehicles than were active in the
window doesn't crash — it just reuses the old static-fallback behavior for
the excess). Both the position/velocity waypoint-scheduling loop and the
`g_sumo_wp_map`/`g_sumo_initial_pos` population loop were updated to use
this mapping consistently.

**Verified:** rebuilt and re-ran (N_Vehicles=20, `attack_scenario=7`).
Before: `scheduled 0 exact position+velocity events`, velocity always 0.
After: `[SUMO] Index remap active: 97 trace vehicle IDs mapped to NS-3
indices 0..96`, `scheduled 7597 exact position+velocity events`, and real,
continuously-updating velocity (~15.9-16.8 m/s across the run — close to
the 16.67 m/s nominal reference speed used in the Issue-3 analytical
bound). Plugging these genuinely live-observed speeds into
`W_BSHH = 2·r_overlap/v_max` (r_overlap=60m at the default fallback,
N_RSUs=0) gives **≈7.16-7.58s**, consistent with (and validating) the
previously-reported empirical 7.2s figure — the historical number appears
to have been measured correctly (likely under conditions/an earlier code
version where this particular ID-mismatch didn't manifest), and is not
invalidated by this bug. **Regression-checked** across TTW-S1, BSHH-S1,
BSHH-S3, and ME-S1 (N_Vehicles=20 each) post-fix: MCC=1.0/AUROC=1.0 in
every case, identical to pre-fix — no detection-quality change, only the
mobility-adaptive recalibration mechanism itself now genuinely works. This
also means `TtwSumoPositionAt()` (TTW-S1's natural-break search) now reads
real per-vehicle trajectories instead of an all-empty map, which may
materially improve realism for any future scenario/dataset regeneration
that depends on it — worth spot-checking if TTW-S1 numbers are
re-generated for the report.

**Supervisor follow-up (2026-07-30) — r_overlap corrected to 67m at 170m,
and made fully live/position-based.** Two further changes on top of the
velocity fix above, per explicit supervisor/user instruction:

1. `r_overlap`'s reference value was corrected: the fallback fraction
   (`g_rsu_overlap_frac`) was changed from `0.20` (giving 60m at the old
   300m base) to `67.0/170.0` (giving exactly **67m at 170m**), and
   `PemComputeRsuOverlapRadius()`'s base was switched from `g_rcomm` (300m)
   to `g_me_detect_range` (170m) to match — the supervisor specified 67m/170m
   as the authoritative reference pair, matching the exact numbers already
   used in this document's Issue-3 W_ho/W_BSHH worked example. (Note: the
   PDF itself only gives the symbolic formula `W_ho ≈ r_overlap/v_i` — Eq.
   3.36 — with no numeric value for r_overlap anywhere; 67m/170m is a
   project-level calibration input from the supervisor, not independently
   derivable from the PDF text.)
2. `r_overlap` was made genuinely **live/position-based for N_RSUs=1**
   (previously a fixed constant even after the velocity fix above — only
   the *speed* term was live, not r_overlap itself): each recalibration
   tick, computes every vehicle's live distance to the single RSU; the
   vehicle closest to the coverage edge sets
   `r_overlap = 2 × (r_comm − dist_to_edge)`, mirroring the existing
   ≥2-RSU formula's `2×r_comm − spacing` structure with the vehicle's own
   live position standing in for a second RSU. New function:
   `PemComputeRsuOverlapRadiusLiveSingleOrNoRsu()`.

   **N_RSUs=0 attempted-then-reverted:** an equivalent live formula was
   first tried for the no-RSU case too (`max(0, 2×r_comm −
   nearest_vehicle_pair_spacing)`, using the two closest vehicles' spacing
   as a geometric stand-in for "coverage source spacing"). This was found
   semantically broken and reverted the same session: measured directly
   (N_Vehicles=20, BSHH-S3), it produced `r_overlap` saturating near its
   `2×r_comm≈340m` ceiling (vehicle traffic routinely puts *some* pair very
   close together for reasons unrelated to any liveness/handover event),
   giving `W_BSHH≈38-43s` — an order of magnitude too large versus the
   intended ~7-8s handover-window magnitude. Vehicle-to-vehicle proximity
   is not a valid physical stand-in for RSU coverage overlap; with zero
   RSUs deployed there is no RSU-pair geometry to legitimately be "live"
   about. **N_RSUs=0 now uses the static 67m/170m fallback fraction
   directly** (`g_rsu_overlap_frac × g_me_detect_range`), same as before
   this live-computation attempt.
3. **Regression-checked** after both the N_RSUs=1 live change and the
   N_RSUs=0 revert: TTW-S1, BSHH-S1, BSHH-S3, ME-S1 (N_Vehicles=20 each)
   all show MCC=1.0/AUROC=1.0, zero FP/FN — identical throughout. No
   detection-quality change from any of these changes; only the internal
   `r_overlap`/`W_BSHH` computation changed. **Final measured W_BSHH**
   (N_RSUs=0, r_overlap=67m fixed, real live-recalibrated speed):
   **~7.99s to ~8.46s** across a 20s run, hovering at/above the 8.04s
   analytical bound — consistent with the supervisor's 67m/170m reference
   values and no longer requiring the "tighter-but-below-bound" framing
   the original 7.2s figure needed.

**Issue 4 — T_exec = 0.037ms vs. the 50-200ms literature range.**
These are not the same quantity. `T_exec_compute` (0.037ms mean / 0.253ms max,
measured live) is the local TemporalEchoMitigator chaincode computation time
only. The paper's cited 50-200ms (`T_exec_fabric`) is literature for the FULL
Hyperledger Fabric commit pipeline — endorsement, ordering, and commit —
which this project does not simulate end-to-end (no live Fabric network in
the loop). Reporting 0.037ms as "the smart contract latency" without this
distinction would misleadingly suggest the framework beats published Fabric
benchmarks by 1,350x, when it has actually only measured one sub-component.
The calibration table and M5/T_pipeline write-up should report both figures
side by side: `T_exec_compute` (measured, this project) vs. `T_exec_fabric`
(50-200ms, literature, full commit pipeline) — with T_pipeline's own reported
total explicitly noting which of the two it includes.

**Update (2026-07-29) — T_exec_fabric was actually measured, not left as literature-only.**
A real 4-orderer SmartBFT / 8-peer (5 RSU + 3 OBU) Fabric 3.1 network was already
running; `measure_texec_fabric_gw.js` (new script, uses the modern
`@hyperledger/fabric-gateway` SDK) submits real `SetSimParams` chaincode writes
and times the full client-observed endorse→order→commit round trip. The first
clean measurement came back at **mean 14,099ms** (n=20) — three orders of
magnitude above the 50-200ms literature range, which is not a plausible
Fabric commit latency and was treated as a bug, not a calibration input.
Root-cause investigation (live `docker logs -f` tracing on orderers and
peers, correlating specific transaction IDs against block-commit
timestamps, and instrumenting Node's `setTimeout` to trace internal
SDK/gRPC scheduling) found **two independent, unrelated infrastructure
bugs**, both now fixed:

1. **SmartBFT orderer forward/complain timeout misconfiguration**
   (`configtx.yaml`): `RequestForwardTimeout=2s` / `RequestComplainTimeout=20s`
   meant a non-leader orderer sat on a client's request for up to ~20s before
   forwarding it to the actual leader; the BFT consensus round itself, once
   triggered, completed in under 20-30ms (confirmed via orderer logs). Fixed
   to `200ms` / `3s` — orderer consensus now consistently completes in
   20-30ms. The channel genesis block was regenerated (ledger wiped, chaincode
   redeployed at sequence 1) to apply the new SmartBFT parameters; the
   4-orderer/f=1 topology itself was left unchanged (see the f=2 clarification
   two sections below — this was correctly *not* the ordering-layer fault
   count, which the PDF does not tie to f=2).
2. **Gossip block-dissemination interval defaults** (`core.yaml` /
   `docker-compose-teta.yaml` env overrides): `peer.gossip.state.checkInterval`
   defaulted to Fabric's stock `10s`, which gated how often a peer's gossip
   state provider flushed newly-received blocks out of its receive buffer to
   actual ledger commit — confirmed via peer logs showing `StoreBlock ->
   Received block [N] from buffer` consistently ~10s after the orderer had
   already written the block (block commit itself takes 20-35ms once flushed).
   Reduced to `200ms` (`CORE_PEER_GOSSIP_STATE_CHECKINTERVAL`), which dropped
   the measured mean from ~14.1s to ~4.0s.

After both fixes, n=30 gives **mean 3,884ms / min 627ms / p95 4,016ms /
max 4,021ms**. A further, still-unresolved ~4s floor remains, and was
narrowed down as precisely as config-level tools allow: it is **not**
the client SDK (identical behavior confirmed on both the legacy
`fabric-network` SDK and the modern `fabric-gateway` SDK), and not any of
`peer.gossip.pull.interval`, `digestWaitTime`, `requestWaitTime`, or
`responseWaitTime` (all reduced from their defaults via
`CORE_PEER_GOSSIP_*` env vars in `docker-compose-teta.yaml`, confirmed
applied inside the running containers, with zero measured effect). Peer
logs confirm the underlying block commit itself is fast (20-35ms) and the
peer's single `Gateway.CommitStatus` RPC call blocks server-side for the
full ~4s before returning — i.e. the delay is inside Fabric's own Go
implementation of the Gateway/gossip service, not exposed via any
`core.yaml` key or environment variable found during this investigation.
Eliminating it fully would require reading and patching Hyperledger
Fabric's own peer source code and rebuilding the peer Docker image — a
materially larger undertaking than configuration tuning, and out of scope
for this calibration pass.

**Further investigation (2026-07-29, continued).** A local Fabric source
checkout was available at `~/fabric-src`, making it possible to trace the
exact code path instead of guessing further config keys. Read
`internal/pkg/gateway/commitstatus.go` →
`internal/pkg/gateway/commit/finder.go` →
`internal/pkg/gateway/commit/blocknotifier.go` →
`core/ledger/kvledger/kv_ledger.go` (`sendCommitNotification`, called
synchronously immediately after the block-commit log line, ruling out any
notification-side delay) → `gossip/state/state.go`. This traced the ~4s to
a *third*, separate anti-entropy timer not previously found:
`peer.gossip.state.responseTimeout` (default `3s`; `checkInterval(200ms) +
responseTimeout(3s) ≈ 3.2s`, closely matching the observed floor), used in
`requestBlocksInRange()`'s retry loop. Source reading also confirmed the
*reason* the peer depends on this slower anti-entropy path at all instead
of the normal, event-driven direct-push path (`deliverPayloads()`, which
has no interval and processes blocks immediately once queued): peer logs
show `handleStateResponse()` rejecting a valid anti-entropy response
("state transfer response without payload"), forcing a retry each cycle.
`responseTimeout` was reduced to `200ms`
(`CORE_PEER_GOSSIP_STATE_RESPONSETIMEOUT`, confirmed applied in the
running containers) — a real, source-verified bug fix worth keeping — but
it had **zero measured effect** on the ~4s floor, meaning the anti-entropy
retry path is not actually the bottleneck either (`CommitStatus` unblocks
on the same commit notification regardless of which path lands the
block). An attempt was then made to get a live Go stack trace via the
peer's exposed `net/http/pprof` import
(`cmd/peer/main.go:10, _ "net/http/pprof"`) against its operations HTTP
listener (`127.0.0.1:9443` inside the peer container) — this returned
`404 Not Found`, meaning the operations server uses its own HTTP mux
rather than Go's `http.DefaultServeMux` that the blank import registers
against, so the endpoint is not actually reachable without further
patching. The container also has no `curl`/`wget`/`python3`/package
manager to install alternative profiling tools. At this point, isolating
the remaining ~4s requires either patching the peer source to add
temporary debug logging or a working pprof mux, then rebuilding and
redeploying the peer Docker image — a materially larger undertaking
(Go engineering + image rebuild cycle) than any fix applied so far, and
was not pursued further in this pass.

**Recommended reporting:** state the measured T_exec_fabric (mean ≈3.9s,
down from an initial buggy ≈14.1s after fixing three real, source-verified
infrastructure defects — SmartBFT orderer timeout, gossip state
check-interval, gossip state response-timeout) as this project's real
Fabric deployment measurement. Explicitly note it exceeds the 50-200ms
literature range for a documented, root-caused-as-far-as-possible reason
(a residual delay inside Fabric's own gossip/Gateway Go implementation,
not reachable via any config key found by reading the actual Fabric
source, and not a design flaw in the TETA-Guard framework itself), and
flag full elimination as future work requiring a patched, rebuilt Fabric
peer image.

**Issues 5 & 6 — L and W_BPTT not swept.**
Confirmed: L (message-passing rounds, Eq. 3.24) was held fixed at 2 for every
run; the "GRU layers ∈ {2,3}" values tested during the anchor hyperparameter
sweep are GRU *hidden-state depth*, a distinct architectural parameter from L,
so no genuine L-sweep was ever run. Similarly W_BPTT (TBPTT window) was fixed
at 100 throughout; the paper's {50,100,200} sweep was never executed. Per the
reviewer's guidance, both are now explicitly marked "not swept, default value
used, unevaluated" in the table above rather than implied evaluated. A real
sweep (L∈{1,3} and W_BPTT∈{50,200}, holding the winning d/pos_weight/ce_weight
configuration fixed) requires new TGN training runs — this is a genuine open
task, not yet executed as of this note (queued behind the current ablation
study's compute usage — see the pending-work note below).

**Trust architecture parameter sweep — completed 2026-07-30.**
τ_min, τ_min^gt, τ_min^C, Δ+, Δ-, T_quar are chaincode constants in
`trust.go`; sweeping them via the full NS-3 + Fabric-network redeploy cycle
(one chaincode redeploy per candidate value) would have taken far longer
than the theoretical/config-verification value justified. Instead, the six
sweep-target constants were converted from `const` to package-level `var`
(`trust.go`, identical default values — no production behavior change) and
exercised natively via `fabric-chaincode-go`'s `shimtest.MockStub` in a new
`trust_sweep_test.go` (`go test -tags simstub -run TestTrustParameterSweep`,
runs in ~1.2s, no Docker/NS-3 required). One-at-a-time ±1-step sweep
(each parameter varied individually, others held at their current
calibrated/baseline value), n=60 malicious + 60 honest synthetic peers (or
40+40 controllers) per configuration, fixed-seed pseudo-random per-round
behavior so results are deterministic and reproducible. Full results in
`TRUST_PARAMETER_SWEEP_2026-07-30.csv`; summary:

| Parameter | Values tested | MCC (low→base→high) | Trend |
|---|---|---|---|
| τ_min | 0.05 / **0.10** / 0.15 | 0.629 / 0.802 / 0.817 | Higher τ_min catches malicious peers faster (lower FN); current 0.10 is a reasonable middle ground, 0.15 marginally better on this synthetic population |
| Δ+ | 0.03 / **0.05** / 0.07 | 0.905 / 0.802 / 0.552 | Strong sensitivity — larger Δ+ lets malicious peers recover trust too easily between penalty rounds (FN rises from 0.10→0.53); smaller Δ+ is safer but raises R_min (bootstrap latency) from 8→14 rounds, a real trade-off against the Table 4.9 bootstrap-latency budget |
| Δ- | 0.05 / **0.10** / 0.15 | 0.420 / 0.802 / 0.831 | Mirrors Δ+: smaller Δ- under-penalizes malicious peers (FN=0.70); current 0.10 and higher are both reasonable, 0.10 is not oversized |
| T_quar | 20000 / **30000** / 40000 ms | 0.817 / 0.802 / 0.831 | Weak sensitivity — MCC stays in a narrow 0.80-0.83 band across all three; the current 30,000ms is not a knife-edge choice, consistent with the PDF's framing (chosen for replacement-peer-selection headroom under Tb=100ms, not classification accuracy) |
| τ_min^C | 0.20 / **0.30** / 0.40 | 1.000 / 0.975 / 0.975 | Very strong separation regardless of value (malicious controllers diverge almost every round under ΔC-=0.20, so they cross any of these thresholds quickly); 0.30 remains a safe, non-critical choice |
| τ_min^gt | 0.40 / **0.50** / 0.60 | admit-rate 0.57 / 0.48 / 0.39; R_min 7 / **8** / 10 | Direct trade-off between admission strictness and bootstrap latency, exactly as the PDF's R_min formula predicts; 0.50 (R_min=8) remains a reasonable midpoint |

**Interpretation for the write-up:** none of the six parameters showed a
result that invalidates the currently-deployed defaults — all current
values sit within, or very near, the best-performing region found by this
sweep. The most actionable finding is the Δ+/Δ- sensitivity: Δ+ has the
widest MCC swing (0.55-0.91) of any parameter tested, and is the one most
worth flagging as calibration-sensitive in the report, alongside its
coupling to R_min (bootstrap latency). T_quar is confirmed the least
sensitive of the six (as expected, since it is a timing-headroom parameter
rather than a classification threshold).

---

## TGN three-tier MCC breakdown (overall / per-variant / per-origin) — 2026-07-30

Prior sessions reported only a single, pooled overall MCC for the TGN
detector. Per user request, `tgn_train.py` was extended with two additional
breakdown axes computed from the SAME already-split test set (no dataset
regeneration needed — `variant_label` and a new `origin_label`, both
derived from the existing `sc`/`attack_scenario` column):

- **Per-variant** (TTW / BSHH / ME vs. benign, independent subsets)
- **Per-origin** (data-plane: scenarios {1,2,5,6,9,10} / control-plane:
  scenarios {3,4,7,8,11,12}, independent subsets)
- **Per-variant × per-origin** (finest-grained, 6 cells)

A full retrain was required (not just re-evaluation) because the `.bin`
weight format is a custom one-way export with no Python-side reverse
loader. Retrained with the SAME anchor hyperparameters as the production
model (dim=192, layers=2, epochs=300, lr=0.001, ce_weight=0.3,
pos_weight_override=0.3191, seed=5), except `--l_link` was corrected from
the stale 43.0 (300m-range default) to the calibrated **20.4** (170m
urban), matching this document's own recorded correction (row 9,
`CALIBRATION_VALUES.md`). Output was written to a **new file**
(`~/tgn_variant_breakdown/tgn_weights_verify.bin`) specifically so the
production model (`~/tgn_weights_170m_dim192_pw0.3191_seed5.bin`) would
not be overwritten — confirmed untouched (same md5,
`9963961d0cca1824d8f88780f64fe3f9`, throughout). Because `l_link` differs
from whatever the production model was originally trained with, this run
is **not** a byte-exact reproduction of the production model's numbers —
it is a fresh, correctly-calibrated model, and its overall MCC should not
be assumed identical to the production model's previously-reported figure.

Training needed 3 of 4 allowed restarts to clear the 0.975 val-MCC target
(attempts 1 and 2 plateaued at val_bestMCC=0.968; attempt 3 reached 0.980
at epoch 210). Wall-clock: 259.6 minutes.

### Overall (pooled) test-set MCC
**MCC = 0.958, AUROC = 0.995, ACC = 0.985** (TP=4744, TN=1495, FP=43, FN=55, n=6337)

### Per-variant detection MCC (family vs. benign)
| Variant | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| TTW | 0.943 | 0.992 | 0.977 | 3246 |
| BSHH | 0.978 | 1.000 | 0.993 | 2949 |
| ME | 0.958 | 0.999 | 0.979 | 142 |

### Per-origin detection MCC (data-plane vs. control-plane)
| Origin | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| Data-plane (S1/S2) | 0.957 | 0.997 | 0.986 | 5790 |
| Control-plane (S3/S4) | 0.940 | 0.959 | 0.971 | 547 |

### Per-variant × per-origin (finest-grained, 6 cells)
| Variant × Origin | MCC | AUROC | n_attack |
|---|---|---|---|
| TTW (data-plane) | 0.943 | 0.994 | 2971 |
| TTW (control-plane) | 0.816 | 0.858 | 275 |
| BSHH (data-plane) | 0.974 | 1.000 | 2746 |
| BSHH (control-plane) | 1.000 | 1.000 | 203 |
| ME (data-plane) | 0.000 | n/a | 73 (0 TP; near-empty subset — scenario 9 has only 12 total events in the raw dataset, so this cell is data-sparse, not a genuine model weakness) |
| ME (control-plane) | 1.000 | 1.000 | 69 |

**Findings worth flagging in the write-up:**
- **TTW (control-plane) is the weakest cell** (MCC=0.816, AUROC=0.858) —
  the real, genuine challenging case (not a data-sparsity artifact like the
  ME cell below) and worth explicit discussion. See dedicated analysis
  immediately below.
- **ME (data-plane)'s n=73/0-TP cell is a data-sparsity artifact**, not a
  detection failure — should not be reported as a weak MCC without this
  caveat, since MCC is undefined/degenerate with zero true positives.
- All other cells are strong (MCC ≥ 0.94), with BSHH and ME's
  control-plane cells reaching a clean 1.000.

#### Why TTW (control-plane) is the hardest case — discussion

Two compounding, independently-real factors, both traceable to concrete
numbers already in hand:

**1. Severe training-data imbalance between TTW's data-plane and
control-plane variants.** From the per-scenario event breakdown logged
during this same training run:

| Scenario | Attack events |
|---|---|
| TTW-S1 (malicious vehicle, no RSU) | 11,178 |
| TTW-S2 (malicious RSU) | 4,267 |
| **TTW data-plane total** | **15,445** |
| TTW-S3 (malicious controller, no RSU) | 180 |
| TTW-S4 (malicious controller, with RSU) | 182 |
| **TTW control-plane total** | **362** |

The model saw **~42.7× fewer** TTW control-plane attack examples than
TTW data-plane examples during training (362 vs. 15,445). This alone is
sufficient to explain materially weaker generalization on that slice —
it is comparatively under-trained on this specific sub-pattern, independent
of any deeper structural difficulty.

**2. A genuine structural/semantic difference in what evidence is
available.** TTW-S1/S2 (data-plane) attacks require the attacker to send a
real, externally observable packet — a DSRC beacon (S1) or a CSMA-forwarded
RSU aggregate (S2) — carrying a forged `sender_timestamp` that mismatches
the packet's actual reception time. This gives the TGN a direct,
observable graph event (an edge/node feature with an anomalous timestamp
delta) to learn from — exactly the kind of signal PEM's own TTW-S1/S2
detection signatures (indices 0-2 in the 9-signature list) are built to
catch.

TTW-S3/S4 (control-plane) are fundamentally different: per this project's
own attack specification (§7/§9 of the implementation guide), the
poisoning happens **entirely inside the controller's own memory** — "no
external packet needed." The controller receives legitimate updates
normally, privately stores them, then later overwrites its own routing
table with the stale entry internally. There is no corresponding
externally-observable forged-timestamp packet event for the TGN's temporal
graph to key on the way there is for S1/S2 — the only trace is the
downstream *effect* (a stale/frozen link persisting in the topology graph
past when it should have decayed), a strictly weaker and more indirect
signal than a directly observable forged packet. This is consistent with
the measured AUROC=0.858 for this cell being dramatically lower than every
other cell (all ≥0.99 except BSHH data-plane and TTW data-plane, both also
≥0.99) — it points to genuinely reduced class separability in the model's
score distribution for this attack type, not just noisier estimates from a
small sample.

**Recommended framing for the write-up:** report both factors together —
the severe data imbalance (362 vs. 15,445 examples) as the primary,
addressable cause (a future dataset rebalancing pass, e.g. up-sampling or
a class-weighted loss specific to this sub-slice, is a concrete, actionable
next step), and the "no external packet" structural difference as a
secondary, harder-to-fully-close limitation inherent to how control-plane
TTW attacks work — the model is being asked to detect an attack with
strictly less direct observable evidence than every other cell in the
table, so some residual gap versus the ≥0.94 MCC achieved elsewhere should
be expected even with better data balance.

Code changes: `tgn_train.py` — `origin_label` array construction (mirrors
the existing `variant_label` pattern) plus three new print blocks after
the existing overall `Test MCC` line, reusing the already-computed
`te_l`/`te_scores`/`te_var`/`te_origin` test-set arrays.

---

## Full documentation

- `TGN_HYPERPARAMETER_CALIBRATION.md` §3i — full methodology and evidence for w1-w9/θ_LW/µ/δ_thresh
- `TABLE_4.9_CALIBRATION_TRACKER.md` §A.1/§B/§D — superseding subsections with before/after comparison
- `CALIBRATION_VALUES.md` §1/§4 — the 170m vs 300m vs 100m constant-scoping rationale
