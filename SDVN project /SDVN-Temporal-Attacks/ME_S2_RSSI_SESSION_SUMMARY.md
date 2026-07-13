# ME-S2/ME-S4 Real-RSSI Independence — Session Summary & Next Steps

**Purpose of this file:** a complete record of a multi-session investigation into making the
ME-S3 (location-binding/RSSI) signature's signal-plausibility check (Eq. 3.31 condition iii)
genuinely independent of the position-claim check (condition ii), as originally requested by
the supervisor. Kept so the next session can resume without re-deriving any of this.

---

## 1. The original problem

Eq. 3.31 defines three independent physical consistency checks for a location-binding report:

1. Cryptographic signature validity.
2. Spatial plausibility — is the claimed GPS position within `r_comm` of the reported link?
3. Signal plausibility — does the physically-measured RSSI at the receiver confirm proximity?

**Bug found:** the codebase computed RSSI for check (3) using the *same* COST-231
distance formula used for check (2) — meaning the two checks were perfectly correlated
(an attacker who forges a plausible position automatically "passes" the RSSI check too).
This defeats the purpose of having two independent checks.

**Fix (confirmed working):** ME-S3's signal-plausibility check (routing.cc, inside
`PemEvaluateEvent`) now uses the **real PHY-measured RSSI** from `Rx()`'s genuine
`MonitorSnifferRx` `signalNoise.signal` parameter, captured into a global map
`g_real_rssi_dbm` keyed by `(senderId, receiverId) -> (rssi, timestamp)`. This is a real,
independent physical measurement — an attacker cannot manipulate what signal strength
actually arrives at a receiver regardless of what position it claims.

This part of the fix is done and correct. Everything below is about fixing the cascade of
pre-existing bugs this change exposed (previously invisible because the old synthetic RSSI
never depended on whether a real reception ever happened).

---

## 2. The cascade of bugs this exposed and fixed

Once detection started depending on *real* receptions, several previously-invisible gaps in
the ME-S2 (`ME_S2_LegitimateDiscovery`)/ME-S4 (`ME_S4_VehiclesViaRSU`) attack-injection
functions surfaced, one at a time:

1. **RSUs never physically received anything at all.** The "legitimate discovery" code only
   ever sent real V2V beacons (`AttackSendDSRCBeacon`) between the vehicle pair — never a
   real vehicle→RSU transmission. Fixed by adding real `AttackSendDSRCBeacon(vehicle, rsuNode)`
   calls for V1, V2, and the phantom pair (`false_v3`/`false_v4`).

2. **PHY/MAC collisions from too-tight scheduling.** Multiple beacons fired within the same
   burst destructively interfered with each other. Measured the real beacon airtime via
   end-to-end PHY tracing (`TxBegin`→`TxEnd` timestamps, nanosecond precision): **152µs**.
   Fixed by spacing sends `200µs` apart (152µs measured airtime + ~48µs guard) instead of the
   original arbitrary 50µs.

3. **Vehicle-selection didn't check RSU proximity at all.** The "malicious RSU" was picked by
   container index (kept as-is, per explicit decision — index-based selection is intentional
   and correct), but the *vehicle pair* used for the "real link" was picked by index too, with
   no relation to where the RSU physically is. Added `MeSelectMutualRangePairNearRsu`/
   `MeSortVehiclesByDistanceToRsu` to pick vehicles by real proximity to the RSU instead.

4. **Empirically calibrated effective reception radius.** Rather than assume the nominal
   `g_rcomm=300m` design constant reflects real reception distance, built a dedicated
   calibration mode (`--calibrate_range=1`) that sweeps a TX/RX pair from 10m-300m in 10m
   steps and measures real packet-reception ratio (PRR). After fixing two calibration-harness
   bugs (residual mobility-model velocity causing drift during a "constant distance" dwell;
   a ~120ms PHY settling transient right after `SetPosition()`), the clean result was:
   **100% PRR from 10-260m, collapsing to 17.65% at 270m, 0% by 280m** — closely matching the
   analytical `R(P)` formula's independent ~282m estimate for this channel/power. Adopted
   **`kEffectiveReceptionRadius = 260.0`** (a separate constant from `g_rcomm`, used *only* for
   scenario-construction vehicle selection — never for any PEM detection threshold, which
   stays a deliberate, unrelated design parameter).

5. **A real bug in the vehicle-selection fallback.** `MeSelectMutualRangePairNearRsu`'s
   last-resort fallback (when no mutual-range pair exists among in-range candidates) used to
   return the nearest-by-distance pair from the **entire unfiltered pool**, with no range check
   at all — silently returning a genuinely out-of-range pair. Fixed: prefer the RSU-in-range
   subset when it has ≥2 candidates; only fall back to the fully unfiltered pool (with an
   explicit warning) when fewer than 2 vehicles are within range at all.

6. **Redundant retransmission for real, measured channel contention.** A controlled
   baseline-vs-attack comparison (global `PhyRxDrop` reason tally, all traffic, both with and
   without any attack running) showed this network's real per-transmission contention rate
   (`BUSY_DECODING_PREAMBLE`/`TXING`/`RXING` — "receiver already busy") is **~14%** and is
   **statistically identical** whether or not an attack is running (32.78% vs 32.782% overall
   success rate including far-away nodes; ~14% specifically for genuine contention). This is a
   real, always-present property of a 264-node shared-channel network, not a scenario defect.
   Added a second retry attempt (1ms after the original) per beacon send, since a single
   ~14%-probability contention event is unlikely to hit both attempts — this mirrors real
   802.11p reliability (periodic re-broadcast), and does not weaken detection of genuine
   attackers at all (a fabricated ME witness never transmits anything real regardless of retry
   count).

7. **Correctly excluding (not deleting) physically-impossible scenario instances from the
   confusion matrix.** When an RSU genuinely has zero vehicles within `kEffectiveReceptionRadius`
   at all (a scenario-construction limitation for that specific run/seed's vehicle layout, not a
   detection failure), the "benign" observation constructed for it is not a valid classification
   instance — the claimed link cannot physically exist. Implemented:
   - `g_scenario_invalid_neighborhood_rsus`: set of RSU ids where `MeSelectMutualRangePairNearRsu`
     hit the last-resort fallback (logged explicitly: `[ME-S2][WARNING] No valid local
     neighborhood found for RSU=<id> nearest_vehicle_distance=<d>m effective_range=260m`).
   - Events reported through such an RSU are excluded from **both** confusion-matrix mechanisms
     found in the codebase (there are two, and both had to be gated — the per-event counters in
     `PemRecordObservation`, and a **separate, node-level** tracking mechanism
     `pem_false_positive_nodes`/`pem_detected_attacker_nodes` that `PemWriteRunSummaryCsv`'s
     reported `tp`/`fp`/`tn`/`fn` columns actually derive from — the first attempt at this fix
     only gated the first mechanism and had zero visible effect until this was found).
   - Excluded events are written to a new `outputs/SCENARIO_VALIDITY/<scenario>.csv` report
     (not silently dropped), documenting exactly what was excluded and why.
   - **Confirmed working** on the test network (20 vehicles/10 RSUs): went from `fp=4` to
     `fp=0, mcc=1.0, auroc=1.0`, with the 8 genuinely-invalid events cleanly reported in
     `SCENARIO_VALIDITY`.

8. **All temporary diagnostic instrumentation removed** after each finding was confirmed
   (`DEBUG-SEND`, `DEBUG-RX`, `FP-CLASSIFY`, `DEBUG-RSSI-MISS`, `TRACE-PHY` (TxBegin/TxEnd/
   TxDrop/RxBegin/RxEnd/RxDrop), `SELECT-DEBUG`, `GlobalChannel*` congestion tally). Confirmed
   via a clean `grep` sweep and successful rebuild that none remain. The **calibration mode**
   (`--calibrate_range=1`) and its `CALIB-TX`/`CALIB-RX` prints were deliberately **kept** —
   useful, reusable, opt-in tooling, not temporary debug noise.

---

## 3. Current state (as of end of this session)

**Test network (20 vehicles, 10 RSUs, `--test_network=1`), scenario 10 (ME-S2):**
```
tp=2, tn=2, fp=0, fn=0, mcc=1.0, auroc=1.0
```
8 events correctly excluded (2 RSUs with zero vehicles in real range) — see
`SCENARIO_VALIDITY/10_ME_S2_Malicious_RSU.csv`. **This is a clean, fully-resolved result.**

**Full-scale network (200 vehicles, 64 RSUs), scenario 10 (ME-S2):**
```
tp=13, tn=18, fp=20, fn=0, mcc=0.432, auroc=1.0
```
12 events correctly excluded (4 RSUs with zero vehicles in real range) — the
invalid-neighborhood exclusion mechanism itself is confirmed working correctly at this scale
too. **But `fp=20` remains** from RSUs that DO have valid vehicles in range yet still
experience real reception failure — this is the open problem for next session.

---

## 4. The open problem: `fp=20` at full scale

### Diagnosis performed this session

- Confirmed (via `PemWriteEventCsv`/`pem_event_log.csv`, no custom instrumentation needed) that
  these are genuine confusion-matrix false positives per the paper's own strict definition
  (`FP = benign event + alert_raised=true`), not a counting-methodology artifact. Verified the
  evaluation chain directly in code: `PEM signatures → weighted score → alert_raised (score >
  threshold) → compared against attack_label → tp/tn/fp/fn`. No shortcuts anywhere.
- Confirmed via end-to-end PHY tracing that **both** the original send and the 1ms-later retry
  for a specific pair (V134↔V139 via RSU_206, ground-truth distance 0m) succeed at reaching
  other nearby vehicles but never reach the specific reporter RSU at all, in **any** of 4
  separate attempts (2 vehicles × 2 attempts each) — ruling out random bad luck; this is some
  kind of structurally-recurring collision or exclusion, not an isolated fluke.
- Reasoned (not yet independently re-confirmed after the fix below) that a **fixed** 1ms retry
  offset may not be enough separation, since NS-3 is fully deterministic and the entire
  200-vehicle fleet's periodic broadcast cycle (when active) lands very close to `t=10.0s`
  exactly (`0.4 + 96×0.1 = 10.0`) — a fixed retry offset may just land in a different point of
  the *same* generally-busy window, not a genuinely quieter one.

### The stronger fix attempted (and why it had zero effect)

The most defensible fix — per explicit methodological pushback received this session — is
**not** to keep tuning the attack-scenario's scheduling (defensible only if real vehicles would
actually behave that way; hard to justify adding an arbitrary +50ms retry *just* for this one
attack scenario). Instead: **improve the detector's temporal evidence model** so it draws on
*any* real reception between two nodes (not just the one scripted attack-instant attempt) —
exactly how a real deployed system would use its most recent known reception rather than
require one exact instant to succeed.

Implemented: extended `g_real_rssi_dbm` capture (previously only listening to the
attack-specific `CustomDataTag1` tag) to **also** capture from the regular periodic
`CustomDataTag` beacon traffic (`distributed_dsrc_data_broadcast`, nominally every 100ms
starting at `t=0.4s` — by `t=10.0s` there would be ~96 real opportunities for any genuinely
in-range pair to have exchanged a real beacon).

**Result: zero effect on `fp` (still exactly 20).** Root cause: traced every scheduling site
for `distributed_dsrc_data_broadcast`/`dsrc_data_broadcast` and confirmed **under this
project's default configuration (`paper=1`, `architecture=0` — what every test command in this
session used), there is no active periodic DSRC beacon exchange between vehicles/RSUs at all.**

- The scheduling loop that would call `distributed_dsrc_data_broadcast` is gated behind
  `if (paper == 0)` (routing.cc ~line 152917) — never true under the default `paper=1`.
- A second candidate block (~line 153013 onward) is entirely inside a `/* ... */` comment —
  doesn't even compile.
- Per this project's own architecture docs, `paper=1`/`architecture=0` ("Comparison
  Baselines") routes vehicle data to the controller via LTE/CSMA agents
  (`send_LTE_data_agent`/`RSU_dataunicast_agent`), not real DSRC broadcast.

So under this configuration, **the only real over-the-air DSRC beacon exchanges that exist at
all are the attack-scripted ones.** There is no ambient traffic pool to draw temporal evidence
from — the fix is conceptually correct but has no substrate to act on in this configuration.

### Decision (this session, explicit): defer to next session

The user wants `fp` reduced to 0 at full scale (matching the test-network result), but agreed
to treat this as a separate, dedicated next-session task rather than rushing a fix now.

### Options for next session, roughly in order of how defensible/scoped they are

1. **Investigate enabling real periodic DSRC beaconing as a standing feature.** This is the
   "real fix" per the temporal-evidence argument above, but it changes simulation behavior
   broadly (every scenario, not just ME-S2) — needs careful evaluation of side effects on the
   other 11 scenarios' already-passing results before considering it. Start by understanding
   exactly what `paper=0` changes elsewhere (routing algorithm selection, other broadcast
   paths, etc.) before flipping it, since it's a global mode switch, not a narrow toggle.

2. **A narrower, ME-S2/S4-scoped version of (1):** instead of enabling the *global*
   `distributed_dsrc_data_broadcast` mechanism, add a small, dedicated, always-on periodic
   "ambient beacon" specifically between the ME-S2/S4 real-link vehicle pair and their
   candidate RSUs, independent of `paper`'s value — narrower blast radius, but needs its own
   justification for why only ME-S2/S4 get this and not the other attack families (arguably
   fine, since only ME-S2/S4 depend on RSU-relay real-RSSI evidence at all).

3. **Increase retry count/spacing further** (e.g. 3+ attempts, wider spacing) as a fallback if
   (1)/(2) turn out to be too invasive — but per this session's own methodological finding,
   this is scenario-scheduling tuning, not a detector improvement, and is harder to defend in
   the paper ("we delayed the beacon by Xms so the channel was quieter" vs. "the detector
   tolerates transient loss via temporal evidence"). Should be the last resort, not the first.

4. **Re-verify the "is this genuinely unfixable at 0% collision" assumption** with fresh
   end-to-end PHY tracing (the instrumentation was removed this session, but the pattern —
   `TraceBeaconTxBegin`/`TxEnd`/`RxBegin`/`RxEnd`/`RxDrop`, `Packet::GetUid()` as the
   correlation key — is fully documented above and easy to re-add temporarily) before
   committing to any specific fix, per this session's established practice of diagnosing before
   implementing.

### What NOT to do

- Do not re-litigate whether the real-RSSI approach itself is correct — it is, confirmed
  multiple times, and is the entire point of this work.
- Do not touch `g_rcomm` (300m) — it's a separate, deliberate protocol/design parameter used by
  PEM's detection signatures (Eq. 3.11/3.29-3.32) and must not be conflated with
  `kEffectiveReceptionRadius` (260m, scenario-construction only).
- Do not silently suppress/delete `fp` counts — if a genuine reason to exclude events is found,
  follow the same pattern as §2.7 above (explicit flag, separate report, documented reason).
- Do not add scenario-specific timing hacks (arbitrary retry delays "because it makes the
  number better") without first checking whether the change reflects real protocol behavior a
  vehicle would actually exhibit.

---

## 5. Key file locations (routing.cc)

- `g_real_rssi_dbm`, `PemGetRealRssi`, `PemResolveVehicleGlobalId` — near line ~2440-2500.
- `kEffectiveReceptionRadius`, `MeSortVehiclesByDistanceToRsu`,
  `MeSelectMutualRangePairNearRsu` — near line ~7200-7400.
- `g_scenario_invalid_neighborhood_rsus`, `g_pem_excluded_invalid_neighborhood` — declared near
  `pem_all_events` (~line 2316-2330); used/populated in `PemEvaluateEvent` (~line 5860-5900) and
  `MeSelectMutualRangePairNearRsu`'s fallback (~line 7370-7400).
- `PemWriteScenarioValidityReport` — just before `PemWriteRunSummaryCsv` (~line 4705-4730).
- `ME_S2_LegitimateDiscovery`/`ME_S2_LegitimateDiscovery_Continue` — ~line 10700+.
- `ME_S4_VehiclesViaRSU`/`ME_S4_VehiclesViaRSU_Continue` — ~line 11280+.
- `CalibrationRun`/`CalibrationSetDistance`/`CalibrationWriteResults` — near
  `MeSortVehiclesByDistanceToRsu` (~line 7080-7150); triggered via `--calibrate_range=1`.
- Real-RSSI capture in `Rx()` — two sites: the `CustomDataTag1` handler (attack beacons,
  ~line 131250+) and the `CustomDataTag` handler (periodic beacons, currently inactive under
  `paper=1` — ~line 131233+, the fix from §2's "attempted, zero effect" step).

## 6. Useful commands

```bash
# Fast test-network sweep (all 12 scenarios, ~seconds each)
cd ~/ns-3.35
for S in 1 2 3 4 5 6 7 8 9 10 11 12; do
  echo "=== Scenario $S ==="
  ./waf --run "scratch/routing --test_network=1 --simTime=30 --N_Vehicles=20 --N_RSUs=10 --N_Controllers=4 --attack_scenario=$S"
done

# Full-scale ME-S2 (slow, ~minutes)
./waf --run "scratch/routing --simTime=40 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=10"

# Check results
D="scratch/SDVN project /SDVN-Temporal-Attacks/outputs"
tail -1 "$D/PEM_RUN_SUMMARY/10_ME_S2_Malicious_RSU.csv"
cat "$D/SCENARIO_VALIDITY/10_ME_S2_Malicious_RSU.csv"

# Re-run the range calibration if needed (takes ~1 minute)
./waf --run "scratch/routing --calibrate_range=1 --N_Vehicles=2 --N_RSUs=0 --simTime=35"
cat outputs/CALIBRATION/range_calibration.csv   # written relative to CWD (~/ns-3.35), not the project outputs/ dir
```
