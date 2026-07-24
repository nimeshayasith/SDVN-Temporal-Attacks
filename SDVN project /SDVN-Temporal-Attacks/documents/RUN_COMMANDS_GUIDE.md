# RUN_COMMANDS_GUIDE.md — Normal Runs vs. Ablation Study Runs

This file is the practical companion to `CLAUDE.md`: it separates **what you run
for a normal/default result** (no extra flags needed) from **what you must pass
for each ablation config (A1–A14)**. All commands assume you are in
`~/ns-allinone-3.35/ns-3.35` and that no other `waf`/`routing` process is
currently running (`ps aux | grep -iE "waf|routing.*RngRun"` should be empty
before any build or run).

---

## 1. Normal Runs (Default System — No Ablation Flags)

The full system (TGN + LW signatures + crypto pre-filter + blockchain
mitigation + PBFT weighted-trust consensus + LKH revocation + divergence gate
+ threshold signatures + controller reassignment) is what you get with **no
ablation flags at all**. Every `g_abl.*` field defaults to `0`/disabled, so
omitting them is the correct way to run "our full proposed system."

### 1.1 Single scenario, single run

```bash
./waf --run "scratch/routing \
  --simTime=60 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --attack_scenario=1 --attack_percentage=50 --RngRun=1"
```

- `attack_scenario` — 0=none (baseline), 1-12=attack variants (see CLAUDE.md §6), 13=combined
- `attack_percentage` — 0-100, percentage of vehicles behaving as attackers (TTW/BSHH only; ME's two echo attackers are fixed identities and are not gated by this)
- `RngRun` — seed; use a different integer per repeated run for statistics

### 1.2 Baseline (no attack)

```bash
./waf --run "scratch/routing --simTime=60 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --attack_scenario=0"
```

### 1.3 5-run statistics batch (per scenario)

```bash
bash documents/ablation_scripts/../../run_5_experiments.sh 1 200 64   # example — adjust script name/path to what exists in your tree
```

Or manually loop `--RngRun=1..5`, saving `pem_run_summary.csv` /
`pem_event_log.csv` per seed (see CLAUDE.md §14 for the full script).

### 1.4 Comparison-detector runs (VeReMi / MBSM baselines, alongside ours)

```bash
# 1 = VeReMi/VREM_Detect, 2 = Multi-BSM/MBSM — both ALSO produce our own
# PEM_RUN_SUMMARY in the same run, so one run gives you both methods' numbers
# for that (scenario, pct) point.
./waf --run "scratch/routing \
  --simTime=60 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --attack_scenario=2 --attack_percentage=50 --RngRun=999 \
  --comparison_detector=1 --output_root=$HOME/comparison_sweep/veremi/sc2_p50"
```

Baseline detectors (VeReMi/MBSM/KNN+Bagging) only produce non-trivial
detections on scenarios **2, 6, 13** — the only scenarios where
`comparison_detector.h`'s stale-BSM-injection mechanism fires. They are
structurally blind (mcc=0, by design, not a bug) on every other scenario,
including all of ME (9-12), because ME attacks echo real links through fake
reporters rather than replaying stale beacons.

### 1.5 KNN+Bagging (offline, on collected pairs CSVs)

```bash
python3 "existing_methods/knn_bagging_detector.py" \
  "$HOME/comparison_sweep/veremi/pairs/pairs_sc2_p50.csv" --holdout-only
```

### 1.6 Default parameter reference (unchanged from CLAUDE.md §4)

| Parameter | Default | Meaning |
|---|---|---|
| `simTime` | 240 | Simulation duration (s) |
| `N_Vehicles` | 80 | Vehicle node count |
| `N_RSUs` | 0 | RSU node count |
| `N_Controllers` | 4 | SDN controller count |
| `attack_scenario` | 0 | Attack ID |
| `attack_percentage` | — | % of vehicles attacking (TTW/BSHH) |
| `routing_algorithm` | 4 | 0=ECMP, 2=QRSDN, 3=RLMR, 4=Proposed RL, 5=DCMR |
| `maxspeed` | 80 | km/h |
| `lambda` | 30 | Vehicle arrival rate |

**This project's standard fairness baseline for all comparisons is
`--N_Vehicles=200 --N_RSUs=64 --N_Controllers=4`** on the same real SUMO
topology — use it for every scenario except the no-RSU family (1,3,5,7,9,11),
where `--N_RSUs=0` is correct by definition (no malicious-RSU actor exists in
those scenarios).

---

## 2. Ablation Study Runs (A1–A14) — Flags REQUIRED

Every ablation config needs at least one explicit flag beyond the normal run
command. Defaults for all `g_abl.*` fields are `0` (= full system, unchanged
behavior), so **the flag is what turns the ablation ON**.

> Naming note: the code's own comments record that A1/A2, A5/A6, A7/A8 were
> initially mislabeled against the PDF's Table 4.2 numbering and have since
> been corrected in the `cmd.AddValue` help text. The mapping below is the
> corrected, current mapping.

### A1 — LW-Only (disable TGN inference)

```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --attack_scenario=1 --attack_percentage=${rinj} --RngRun=999 \
  --no_tgn=1 --output_root=$OUT/a1/sc1_x${rinj}"
```
X-variable: injection rate `attack_percentage` (rinj).

### A2 — FS/TGN-Only (disable LW rule-based signatures)

```bash
--no_lw=1
```
X-variable: injection rate `attack_percentage`.

### A3 — Static GCN (freeze GRU memory / no temporal encoding)

```bash
--static_gcn=1 --simTime=${tobs}
```
X-variable: observation window `Tobs` (via `simTime`).

### A4 — Vehicle Density (fix rho_max/W to static constants)

```bash
--no_mobility_adapt=1 --N_Vehicles=${N}   # N in {100, 200, 400}, proxy for lambda in {0.01, 0.02, 0.04} veh/m
```
Requires the matching density-specific SUMO trace to exist for each N (see
`mobility_urban_60_{100,400}veh_density.tcl`). X-variable: `N_Vehicles`.

### A5 — No Crypto Pre-Filter (bypass Stage-0 HMAC/nonce)

```bash
--no_crypto=1
```
X-variable: attacker origin (grouping by scenario family: veh/rsu/ctrl).

### A6 — No Threshold Signature (BSHH aggregate sig → majority-count heuristic)

```bash
--no_threshold_sig=1
```
X-variable: colluding signers `f_c` — auto-swept internally via
`M11_FSR_SWEEP`, no separate CLI sweep loop needed.

### A7 — No Location-Binding + Quorum (ME-S3 geometric/RSSI check suppressed)

```bash
--no_lbs=1
# OR to sweep the echo-distance ratio directly instead of just on/off:
--echo_dist_ratio=${ratio}   # ratio in {1.0, 1.5, 3.0} × r_comm
```
X-variable: ME echo-reporter distance ratio.

### A8 — No Smart Contract Mitigation / Mitigation Delay

```bash
--no_blockchain=1
# OR sweep the post-alert grace interval:
--mitigation_delay_intervals=${k}   # k in {0, 1, 5, 10} beacon intervals
```
X-variable: post-alert grace interval `k`.

### A9 — Byzantine PBFT Peers (equal-weight voting)

```bash
--equal_weight_pbft=1 --byzantine_peer_count=${fb}   # fb in {0, 1, 2}
```
X-variable: Byzantine peer count `f_b`. **Both flags together** are required
for A9's full comparison (equal-weight alone won't sweep `f_b`).

### A10 — Detector False-Positive Rate

```bash
--detector_fp_rate=${pfp} --no_quarantine=${0_or_1}   # pfp in {0.0, 0.02, 0.05}
```
X-variable: synthetic FP rate `p_FP`. Run once with `--no_quarantine=0` and
once with `=1` per `p_FP` point for A10's quarantine-vs-immediate comparison.

### A11 — Network Size / LKH vs Flat Rekey

```bash
--no_lkh=1 --N_Vehicles=${n}
```
X-variable: network size `n` (`N_Vehicles`).

### A12 — Controller-Origin Injection Rate / Divergence Detector

```bash
--no_divergence_detector=1 --attack_percentage=${rinj}
```
Use with a controller-origin scenario (3,4,7,8,11,12). X-variable: injection
rate `rinj`.

### A13 — KEM Handshake Rate

```bash
--single_kem=1 --kem_handshake_rate=${rhs}   # rhs in {10, 50, 100, 200} veh/s
```
X-variable: handshake arrival rate `r_hs`.

### A14 — Compromised Controllers

```bash
--no_reassign=1
# OR sweep how many controllers are pre-flagged as compromised:
--compromised_controllers=${nC}   # nC in {1, 2, 3} out of N_Controllers=4
```
Use with a controller-origin scenario (3,4,7,8,11,12). X-variable:
compromised controllers `n_C`.
Note: controller registration into `TrustReassignController`'s candidate pool
(`g_ctrl_table`/`g_trust_table`) for `controller_Node.Get(1)..Get(N-1)` is now
**unconditional / part of the default system** (per the PDF's Eq. 3.43/3.44
design, which searches the whole pool, not a fixed 2-node pair) — only the
*pre-flagging* of `(nC-1)` controllers as already compromised is
ablation-gated behind `--compromised_controllers`.

---

## 3. Quick Flag Reference Table

| Config | Flag(s) | X-variable | Notes |
|---|---|---|---|
| A1 | `--no_tgn=1` | `attack_percentage` | |
| A2 | `--no_lw=1` | `attack_percentage` | |
| A3 | `--static_gcn=1` | `simTime` (Tobs) | |
| A4 | `--no_mobility_adapt=1` | `N_Vehicles` (100/200/400) | needs density-specific trace |
| A5 | `--no_crypto=1` | attacker origin | veh/rsu/ctrl grouping |
| A6 | `--no_threshold_sig=1` | `f_c` | auto-swept via `M11_FSR_SWEEP` |
| A7 | `--no_lbs=1` or `--echo_dist_ratio=X` | echo distance ratio | |
| A8 | `--no_blockchain=1` or `--mitigation_delay_intervals=k` | grace interval `k` | |
| A9 | `--equal_weight_pbft=1 --byzantine_peer_count=fb` | `f_b` | both flags together |
| A10 | `--detector_fp_rate=pFP --no_quarantine={0,1}` | `p_FP` | run both quarantine states |
| A11 | `--no_lkh=1` | `N_Vehicles` (n) | |
| A12 | `--no_divergence_detector=1` | `attack_percentage` | controller-origin scenarios only |
| A13 | `--single_kem=1 --kem_handshake_rate=rhs` | `r_hs` | |
| A14 | `--no_reassign=1` or `--compromised_controllers=nC` | `n_C` | controller-origin scenarios only |

**Every ablation sweep must use `--output_root=<isolated path>` per data
point** to avoid CSV clobbering across parallel/sequential runs (see
`documents/ablation_scripts/sweep_a*.sh` for the working pattern).

---

## 4. Where Results Land

| Run type | Output |
|---|---|
| Normal run | `pem_run_summary.csv`, `pem_event_log.csv` in the working dir (or under `--output_root` if set) |
| Comparison-detector run | Same + `comparison_veremi_summary.csv` / `comparison_mbsm_summary.csv` / `comparison_veremi_pairs.csv` |
| Ablation sweep | `~/ablation_sweep/<config>/<point>/PEM_RUN_SUMMARY/*.csv` (via `--output_root`) |
| Ablation charts | `~/ablation_charts/<config>_mcc_vs_x.png` + `ablation_summary.csv` (via `documents/ablation_scripts/generate_ablation_charts.py`) |
| 4-method combined charts | `~/combined_charts/scenario<NN>_combined_mcc.png` (via `existing_methods/scripts/generate_combined_charts.py`) |

---

*Companion to `documents/CLAUDE.md`. Keep this file's flag table in sync if new `cmd.AddValue` ablation flags are added to `routing.cc`.*
