# Latest Trained Models — 2026-08-03

Three TGN models trained this session, after the three pre-retrain fixes were applied:
Q25 (W_max discrepancy, LW/TGN now both 204), Q37 (genuine mini-batching via chunked
detach-all-at-boundary, `--batch_size 256`), Q3 (FS warmup timestamp guard, mirrors
LW's `PEM_WARMUP_S` gate).

Shared hyperparameters across all three runs:
```
--dim 192 --lr 0.001 --l_link 20.4 --ce_weight 0.3 --seed 5 --max_restarts 3
--epochs 300 --layers 2 --tbptt_window 50 --batch_size 256
```
`--pos_weight_override` differs per dataset (see below) — always computed fresh as
`benign_count / attack_count` on the actual final training file, never reused blindly.

---

## 1. Main 12-scenario model

- **Weights:** `/home/sdvn_echo_topology/tgn_weights_sc1_12_capped_RETRAIN.bin`
- **Dataset:** `training_data_sc1_12_capped_170m.csv` — 42,151 rows (170m-capped, scenarios 1–12 per the PDF's attack grid)
  - attack=31,954 / benign=10,197 (75.81% attack, ratio 3.134:1)
- **pos_weight_override:** 0.3191
- **Training time:** 142.9 min (8,575.7s)
- **Max restarts allowed:** 3 (`--max_restarts 3`) — **Attempts taken: 1/4** (succeeded on the first attempt, val_bestMCC ≥ 0.975, no restarts needed)

### Results
- val_bestMCC = **0.991** (epoch 150), val_AUROC = 1.000
- Optimal θ_FS = 0.218
- **Test: MCC=0.981, AUROC=1.000, ACC=0.993** (TP=4792 TN=1500 FP=38 FN=7)

| Family | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| TTW | 0.972 | 1.000 | 0.989 | 3246 |
| BSHH | 0.993 | 1.000 | 0.998 | 2949 |
| ME | 0.958 | 1.000 | 0.979 | 142 |

| Origin | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| Data-plane (S1/S2) | 0.979 | 1.000 | 0.993 | 5790 |
| Control-plane (S3/S4) | 0.981 | 1.000 | 0.991 | 547 |

Test variant classifier (TTW/BSHH/ME): ACC=0.846, F1_macro=0.800, n=6337

---

## 2. Scenario-13 (combined, all 12 families concurrently), seed1-only

- **Weights:** `/home/sdvn_echo_topology/tgn_weights_sc13_only.bin`
- **Dataset:** `training_data_sc13_only.csv` — 8,788 rows, sourced from `attack_scenario=13, attack_percentage=100, RngRun=1` only
  - Natural ratio was 98.57% attack / 1.43% benign (68.9:1) — subsampled attack down to match the main dataset's 3.134:1 ratio
  - Final: attack=6,662 / benign=2,126 (75.81% attack)
- **pos_weight_override:** 0.3191 (computed fresh, landed on the same value since the ratio was deliberately matched)
- **Training time:** 66.9 min (4,014.3s)
- **Max restarts allowed:** 3 (`--max_restarts 3`) — **Attempts taken: 4/4** (initial attempt + all 3 restarts used; never reached val_bestMCC ≥ 0.975 in any of the 4, so the global best across all attempts was kept)

### Results
- val_bestMCC = **0.946** (epoch 90), val_AUROC = 0.997
- Optimal θ_FS = 0.822
- **Test: MCC=0.829, AUROC=0.952, ACC=0.939** (TP=994 TN=244 FP=75 FN=6)

| Family | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| TTW | 0.879 | 0.967 | 0.964 | 680 |
| BSHH | 0.754 | 0.948 | 0.881 | 547 |
| ME | 0.000 | n/a | 0.772 | 23 |

Control-plane (S3/S4) test slices were empty — dataset too small to hold out any control-plane rows for test.

Test variant classifier: ACC=0.715, F1_macro=0.477, n=1250

---

## 3. Scenario-13 (combined), pooled across 3 seeds

- **Weights:** `/home/sdvn_echo_topology/tgn_weights_sc13_only_3seed_pooled.bin`
- **Dataset:** `training_data_sc13_only_3seed_pooled.csv` — 24,000 rows, pooled from `attack_scenario=13, attack_percentage=100` at RngRun=1, 2, 3 (independent SUMO/mobility realizations — genuinely additive, unlike the 0/20/40/60/80 percentage sweep which mostly duplicates the same baseline benign traffic within a seed)
  - Pooled raw totals: attack=439,196 / benign=6,355 across all 3 seeds
  - Subsampled to match the main dataset's ratio: kept all-but-549 of the available benign (5,806 used), attack subsampled from 439,196 down to 18,194
  - Final: attack=18,194 / benign=5,806 (75.81% attack, ratio 3.1337:1 — matches target to 4 decimal places)
- **pos_weight_override:** 0.3191 (computed fresh)
- **Training time:** 51.8 min (3,108.0s) — fastest of the three despite the largest sc13 dataset, since GPU was contention-free (other two runs had already finished)
- **Max restarts allowed:** 3 (`--max_restarts 3`) — **Attempts taken: 1/4** (succeeded on the first attempt, val_bestMCC ≥ 0.975, no restarts needed)

### Results
- val_bestMCC = **0.992** (epoch 120), val_AUROC = 1.000
- Optimal θ_FS = 0.652
- **Test: MCC=0.806, AUROC=0.935, ACC=0.931** (TP=2709 TN=642 FP=229 FN=21)

| Family | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| TTW | 0.854 | 0.961 | 0.957 | 1874 |
| BSHH | 0.716 | 0.919 | 0.863 | 1457 |
| ME | 0.000 | n/a | 0.767 | 82 |

| Origin | MCC | AUROC | ACC | n_attack |
|---|---|---|---|---|
| Data-plane (S1/S2) | 0.806 | 0.935 | 0.931 | 3410 |
| Control-plane (S3/S4) | 0.174 | 0.902 | 0.670 | 3 |

Test variant classifier: ACC=0.733, F1_macro=0.500, n=3413

---

## Summary comparison

| Model | Dataset size | val_bestMCC | Test MCC | Test AUROC | Attempts taken (of max) |
|---|---|---|---|---|---|
| Main 12-scenario | 42,151 | 0.991 | **0.981** | 1.000 | 1/4 (succeeded immediately) |
| sc13 seed1-only | 8,788 | 0.946 | 0.829 | 0.952 | 4/4 (never hit threshold, kept global best) |
| sc13 3-seed pooled | 24,000 | **0.992** | 0.806 | 0.935 | 1/4 (succeeded immediately) |

"Attempts taken" = 1 initial training pass + up to `--max_restarts 3` additional restart passes if val_bestMCC never reaches the 0.975 exit threshold, so 4 is the max possible for all three runs.

**Notes:**
- Pooling scenario-13 to 3 seeds pushed validation performance up (val_bestMCC 0.946→0.992, and hit the ≥0.975 restart-exit threshold on the first attempt, unlike the seed1-only run which never did) but test MCC dipped slightly (0.829→0.806). Likely explanation: the larger, more topologically-diverse pool is easier to fit well on validation, while the larger/more-varied test split draws from more distinct mobility realizations, making it a harder, more representative generalization test — not necessarily a worse model in an absolute sense.
- Both scenario-13 models substantially trail the main 12-scenario model. Scenario 13 is a much more chaotic, out-of-PDF-scope setting (all 3 attack families firing concurrently, shared vehicle pool across families — see caveat below) and ME detection is essentially non-functional in both sc13 models (MCC=0.000, too few test samples: 23 and 82 respectively) vs. a strong 0.958 in the main model.
- **Known caveat (confirmed by code inspection, `declare_attackers()` in `routing.cc:10694`, `attack_scenario==13` branch):** TTW, BSHH, and ME attacker pools for scenario 13 are each an *independent* random draw from the *same* full vehicle pool (`0..N_Vehicles-1`) — there is no cross-family exclusion. A vehicle can be selected as an attacker for more than one family simultaneously. Ground truth is labeled per-event (`is_attack`, `origin_scenario`), not per-vehicle, so event-level labels aren't corrupted — but per-family detection metrics (the TTW/BSHH/ME breakdowns above) can be confounded by shared attacker identity/behavior across families. This is documented in-code as an intentional design choice ("a real concurrent multi-family attack would genuinely have this overlap too"), not a bug, but it means the per-family sc13 numbers above should be read with that caveat in mind.
