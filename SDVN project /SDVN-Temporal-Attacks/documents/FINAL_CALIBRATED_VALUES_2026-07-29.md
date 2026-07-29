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
| 5 | **W_BSHH** (BSHH-S3 liveness observation window) | `W > 2·W_ho` (formula-derived) | Live-derived from `r_overlap` (300m, unchanged), ≈7.2s validated | ➖ No (uses unchanged 300m constant) |
| 6 | **ε** (max propagation tolerance / freshness bound, Eq. 3.16) | Not set — conceptually ≈ one-way propagation delay | 0.101s (measured p95 latency; calibrated 2026-07-23, unrelated to this patch) | ➖ No (timing, not distance-dependent) |
| 7 | **µ** (inter-lane density margin, ME-S1, Eq. 3.8) | 0.20 (recommended default) | **0.20** | ✅ Yes (re-swept, reconfirmed unchanged) |
| 8 | **OBU minimum hardware capacity** | 2048 MB RAM (Hyperledger Fabric chaincode constant) | 2048 MB RAM | ➖ No (not a sweep target) |
| 9 | **W_BPTT** (TBPTT window size per node) | 100 events/node | 100 | ➖ No |
| 10 | **L** (message-passing rounds, Eq. 3.24) | 2 (Table 4.1); sweep {1,2,3} | 2 | ➖ No (reused from anchor sweep) |
| 11 | **d** (node feature embedding dimension, Eq. 3.20) | Not specified; sweep {32,64,128} | 192 (project's own extended sweep) | ➖ No (reused from anchor sweep) |
| 12 | **h_GRU** (GRU hidden-state size, Eq. 3.23) | Tied to d by default | 192 | ➖ No |
| 13 | **η** (optimiser learning rate) | Not specified; start 1e-3, cosine anneal | 0.001 | ➖ No |
| 14 | **w_class** (class imbalance weight / pos_weight) | `w_attack = total/(2·n_attack)`, recompute per split | **0.3191** | ✅ Yes (recomputed for new 170m dataset) |
| 15 | **t** (threshold aggregate signature majority, Eq. 3.28/3.32) | `t ≥ ⌊n/2⌋+1` | Formula-locked | ➖ No |
| 16 | **n** (vehicles per RSU reporting zone, Eq. 3.28) | Varies with λ, r_comm — extract from SUMO traces | min=0/max=42/mean=11.67/median=8.0 | ➖ No (uses `g_rcomm`=300m, RSU's own range, correctly unrelated to v2v's 170m) |
| 17 | **δ_thresh(t)** (controller-origin divergence threshold, Eq. 3.47/3.48) | `⌈(1+τ_prop/T_b)·λ·2r_comm⌉+1` | Live formula output (confirmed 4→9 within a single run as density grows) | ✅ Yes (found + fixed a missed 2nd copy in `tgn_core.cc`; switched floor→ceil) |
| 18 | **Anchor checkpoint interval** (`⌊T_min/T_b⌋` blocks) | Formula-derived from `T_min`, `T_b` | 30/30 blocks | ➖ No |
| 19 | **K** (tier-2 ledger window size, `⌈T_dwell/T_b⌉`) | Varies per OBU dwell time | min=2/median=164/max=598 | ➖ No |
| 20 | **T_exec** (smart contract execution latency) | 50-200ms (Hyperledger Fabric literature) | mean=0.037ms/max=0.253ms (n=11, re-measured live 2026-07-29, scenario 13; earlier figure was mean=0.0037ms/max=0.0091ms — normal run-to-run wall-clock variance, both figures are sub-millisecond and orders of magnitude below the 100ms safety budget) | ➖ No (re-verified live, confirmed unaffected) |

---

## Full documentation

- `TGN_HYPERPARAMETER_CALIBRATION.md` §3i — full methodology and evidence for w1-w9/θ_LW/µ/δ_thresh
- `TABLE_4.9_CALIBRATION_TRACKER.md` §A.1/§B/§D — superseding subsections with before/after comparison
- `CALIBRATION_VALUES.md` §1/§4 — the 170m vs 300m vs 100m constant-scoping rationale
