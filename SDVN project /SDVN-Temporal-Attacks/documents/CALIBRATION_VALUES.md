# Calibration Values — Reference

This file tracks every calibrated constant/parameter established through empirical measurement or paper cross-checking during the TGN/LW detection fix work, so they aren't re-derived or second-guessed later. Update this file whenever a new calibration value is confirmed.

---

## 1. Effective communication range (scenario construction / ambient reception)

- **`kEffectiveReceptionRadius = 100.0` m** (`routing.cc:1845`) — revised down from the original 260 m.
- **Distinct from `g_rcomm` / `TTW_COMM_RANGE = 300.0` m** — that is the protocol/design communication-range parameter used throughout PEM's detection signatures (Eq. 3.11, 3.29–3.32) and must **not** change. `kEffectiveReceptionRadius` is only used for (a) scenario-construction vehicle selection (`MeSelectMutualRangePairNearRsu`, `TtwFindNaturalBreakPairs`, etc.) and (b) the ambient reception gates (`PemEmitVehicleBeacon`, `PemEmitNeighborObservation`), so attack scenarios are only built from vehicle placements that are physically realizable under the real Cost231 propagation + WifiPhy error-rate model.
- **Why 100 m, not 260 m or 300 m:** live beaconing is restricted to 3 same-power SCH channels (see §2), which top out at ~100–110 m under realistic contention. Re-measured after fixing two real bugs:
  1. `ThresholdPreambleDetectionModel::MinimumRssi` was silently defaulting to ~-82 dBm (stricter than `RxSensitivity`'s -105 dBm), artificially capping range at 30–40 m. Now explicitly set to -110 dBm on all 7 channels.
  2. The ambient `centralized_dsrc_data_broadcast` loop was unconditionally active during calibration sweeps, contaminating even the original 260 m measurement. Now disabled during `--calibrate_range=1`/`--calibrate_range_loaded=1`.
- **Measurements (last 100%-PRR point):**
  - Isolated, 3-channel design (Ch172/174/176, 33 dBm each): **100 m**
  - Ch178 alone, isolated: 180 m (not used — the 3 channels actually used for beaconing top out at 100 m, so 100 m is the design-relevant ceiling)
  - Full-scale realistic load (`--calibrate_range_loaded=1`, N_Vehicles=200, N_RSUs=64), tested with real 3-channel spread AND with contention concentrated on a single channel: **both converge to the same 100 m/110 m cliff** — robust across 3 independent test configurations.

## 2. DSRC channel restriction (beacon transmission)

- Beacons broadcast on exactly **3 same-power channels: Ch172/174/176** (5860/5870/5880 MHz, 33 dBm each), via `AttackGetAllDSRCDevices()` (`routing.cc:7826`).
- **Ch178 (CCH, 44 dBm) and Ch180–184 are deliberately excluded** from this send path. Original 7-channel design (6 retries × 7 channels = 42 tx attempts/beacon) was the dominant *source* of channel contention it was meant to work around. Restricting to 3 same-power channels, single-shot, cuts per-beacon airtime 42→3 (14×) and removes the range-mismatch problem (mixing a 44 dBm/282 m channel with 23–44 dBm/short-range channels made cross-channel evidence physically incomparable).
- `--calib_channel_mhz=<freq>` can isolate a single one of the 3 for calibration testing only; default 0 = all 3, matching normal attack-scenario behavior.

### Cost231 isolated-model ranges (for reference, not what's actually used for beaconing)

| Channel | Freq (MHz) | Power | Isolated range |
|---|---|---|---|
| Ch172 | 5860 | 33 dBm | 133 m |
| Ch174 | 5870 | 33 dBm | 133 m |
| Ch176 | 5880 | 33 dBm | 133 m |
| Ch178 (CCH) | 5890 | 44 dBm | 282 m |
| Ch180 | 5900 | 23 dBm | 67 m |
| Ch182 | 5910 | 23 dBm | 67 m |
| Ch184 | 5920 | 40 dBm | 214 m |

Real, load-tested range for the 3 channels actually used: **100 m** (see §1).

## 3. Controller revocation threshold

- **`g_ctrl_revoke_confirm_count = 5`** (default; `routing.cc`, runtime-overridable via `--ctrl_revoke_confirm_count=<N>`).
- Number of **independent confirmed** controller-divergence events (`PemControllerDivergenceGate` returning `confirmed=true`) required before a malicious controller is actually revoked (flagged + zone reassigned via `TrustReassignController`). Counts confirmations only — unconfirmed attempts (`divergence_fn`) do not advance the streak.
- Applies uniformly to all 6 controller-origin scenarios: TTW-S3, TTW-S4, BSHH-S3, BSHH-S4, ME-S3, ME-S4 (one shared global, not per-scenario).
- Not a compile-time constant on purpose — meant to be swept post-training on the real system.

## 4. Attacker density scaling (attack_percentage vs. N_Vehicles)

- **Paper's own Experiment 3 (Network Scalability, RQ4)** varies `N ∈ {100, 200, 300, 400}` while holding attacker fraction **α_atk = 0.20 constant** — i.e. the absolute attacker count scales proportionally with N (40 attackers at N=200, not a fixed small count).
- **Confirmed root cause of "ME-S1/S3/S4 undetected at N=200"**: `sig[6]` (ME-S1, Eq. 3.8) uses a density-adaptive threshold `rhoMax = floor((1+0.20) × 2 × r_comm × λ̂(t))` (`PemComputeRhoMaxForLink`, `routing.cc:4884`) — NOT a fixed threshold. At N=200, ambient vehicle density `λ̂(t)` is high enough that `rhoMax` comfortably exceeds a ~20-phantom-reporter attack (an implicit α_atk ≈ 0.10, not the paper's 0.20). This is **Eq. 3.8 working as designed**, not a bug — confirmed by re-running at small scale (N=20, `--test_network=1`): same code, same formula, reporter_count still climbs correctly, and 9/10 attack rows get flagged once the attacker-to-density ratio is realistic.
- **Fix is scenario configuration, not code**: for the 200-vehicle real-network config, use `--attack_percentage=40` (not the default 20) to reach the paper's own validated α_atk=0.20 operating point at this scale.
- ⚠️ **Pending verification** (as of this writing): confirming that `--attack_percentage=40` actually yields ~40 phantom reporters in the ME-S3 scenario log (earlier observation at `--attack_percentage=20` showed only ~20 phantom reporters selected, not the expected ~40 — the exact selection/split ratio needs re-checking once the verification run's output is reviewed). Update this section once confirmed.
- **PEM_ME_TOLERANCE_MU = 0.20** — the `µ` margin in Eq. 3.8's `rhoMax` formula (`(1+µ)·2·r_comm·λ̂(t)`).

## 5. TGN training configuration (best model so far)

- Best model selected via 5-seed sweep `{1, 2, 3, 42, 100}` — winner: **seed 42** (val MCC 0.703, tied with seeds 1 & 100, but highest val AUROC of the three at 0.792).
- `--dim=32 --layers=2 --l_link=43.0 --epochs=200 --lr=0.001`
- Auto-selected threshold: **`theta_fs = 0.321`** (plateau-midpoint method, max-MCC on validation).
- `gamma` auto-derived from `l_link`: **310.2**; `W_max` auto-derived: **430** (urban, `l_link=43s`). For highway mobility, `l_link=9` → different gamma/W_max.
- Test results (this model, this dataset — see note below): MCC=0.548, AUROC=0.811, ACC=0.845, TP=10 TN=72 FP=1 FN=14.
- Variant classifier (TTW/BSHH/ME): ACC=0.546, F1_macro=0.297 (weak — small/imbalanced per-family sample sizes, especially ME).
- **Note**: this trained checkpoint (`tgn_weights_seed42.bin`) was trained on data generated *before* the reporter_count/tau_dev/identity_mismatch/self-report fixes below. It must be retrained once the fixed dataset is regenerated.

## 6. Trust/blockchain layer constants (Table 3.4, unchanged — confirmed correct, not recalibrated this session)

| Constant | Value | Meaning |
|---|---|---|
| `TRUST_DELTA_PLUS` | 0.05 | Δ+ correct-participation increment |
| `TRUST_DELTA_MINUS` | 0.10 | Δ- failure/inconsistent evidence |
| `TRUST_TAU_MIN` | 0.10 | τ_min eligibility floor (Eq. 3.42) |
| `TRUST_TAU_MIN_CTRL` | 0.30 | τ_min^C controller reassignment threshold (Eq. 3.44) |
| `TRUST_TAU_GT_MIN` | 0.50 | τ_min^gt bootstrap qualification threshold |
| `TRUST_R_MIN` | 8 | R_min bootstrap consensus rounds |
| `TRUST_TAU_TIER1_INIT` | 1.00 | RSU authority-vetted initial trust |
| `TRUST_TAU_TIER2_INIT` | 0.10 | OBU/vehicle initial trust |
| `TRUST_DELTA_C` | 0.20 | Δ_C controller trust decrement per confirmed divergence (Eq. 3.41) |
| `TRUST_TQUAR_S` | 30.0 s | T_quar quarantine window |
| `TRUST_TMIN_DWELL_S` | 3.0 s | T_min minimum RSU-coverage dwell time |

## 7. Attacker sophistication model

- **`g_attacker_sophistication_prob = 0.5`** default (routing.cc:2195) — probability that a malicious RSU/vehicle in S1/S2-type scenarios rolls "sophisticated" (key-exfiltration, forges nonce/key/position so Stage-0 crypto genuinely passes) vs. "basic" (dropped at Stage-0 MAC check). Overridable via `--attacker_sophistication=<0|1|p>`; exactly `0` or `1` forces deterministic basic/sophisticated.

## 8. Known open items (not yet fixed/calibrated)

- ME-S3/S4 phantom-reporter count at N=200 needs re-verification against `--attack_percentage=40` (see §4).
- Whether the same α_atk=0.20 scaling should apply uniformly to TTW/BSHH families too, or whether it's ME-specific (only ME's detection signature, Eq. 3.8, is density-adaptive) — TTW/BSHH's own signatures (Eq. 3.2–3.7) don't use a `λ̂(t)`-scaled threshold, so this scaling question is likely ME-specific, but worth confirming against the paper's Experiment 3 methodology if TTW/BSHH results also look scale-sensitive.
- **θ_LW (LW alert threshold, `PEM_SCORE_THRESHOLD`) sweep is incomplete**: only 12/21 grid points (θ=0.00–0.45) were run and saved (`/tmp/lw_thresh_*_summary.csv`); θ=0.50–1.00 were never run. Best MCC in the observed range is θ=0.10 (mcc=0.799, fp=17), better than the code's current hardcoded default θ=0.075 — but the PDF's own selection criterion is f1_macro, not MCC, and the full grid was never finished. See `TABLE_4.9_CALIBRATION_TRACKER.md` §A.1 for the partial results table.

## 9. LW signature weights (w1–w9) — now calibrated, tracker was stale

`PEM_WEIGHTS[9]` (`routing.cc:2287`) is **already recalibrated** — precision-weighted (Laplace-smoothed `(TP+1)/(TP+FP+2)`) across 13,823 real PEM events / 52 scenario runs, not the uniform 1/9 baseline. This was done *after* the Eq. 3.8 density-formula fix (2D disk → 1D road-segment model), which was a prerequisite for ME-S1 evidence to exist at all. 8 of 9 weights rest on real fired-signature evidence; w6 (BSHH-S3) is still a smoothed-prior placeholder because that signature has never fired in any run. Full per-signature precision table now lives in `TABLE_4.9_CALIBRATION_TRACKER.md` §B (previously said "⬜ not started" — corrected in this pass).
