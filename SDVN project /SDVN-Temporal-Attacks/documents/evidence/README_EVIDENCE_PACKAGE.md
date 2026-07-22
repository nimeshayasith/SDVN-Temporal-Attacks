# Full System Implementation Evidence Package

Prepared for supervisor review — "Full system implementation evidence with
correct timing and correct coding without bypassing modeling."

This package contains **two separate, complete evidence sets** from two real,
unmodified NS-3 simulation runs — nothing here is mocked, hand-typed, or
precomputed. Each lives in its own subfolder so neither overwrites the other.

```
scenario_1/   -- attack_scenario=1 (TTW-S1), N_Vehicles=200, N_RSUs=0,
                 attack_percentage=80, simTime=30s, untrained/default TGN
scenario_13/  -- attack_scenario=13 (COMBINED, all 12 attacks concurrently),
                 N_Vehicles=200, N_RSUs=64, N_Controllers=4,
                 attack_percentage=80, simTime=60s, TRAINED TGN model
                 (tgn_weights_sim60_ap60_3seeds.bin, theta_FS=0.85, dim=128,
                 layers=2, L_link=43.0)
```

Both were produced by the same script, `functional_verification.py`, which
auto-creates a `scenario_<N>/` subfolder per run (based on `--scenario`) so
re-running against a different attack scenario never clobbers a prior run's
evidence.

## The 5 deliverables, per scenario

| # | Requirement | scenario_1 result | scenario_13 result |
|---|---|---|---|
| 1 | Equation & algorithm presence audit | **56/56 PASS** (49 auto-detected, 7 curated manual review) | **56/56 PASS** (same — this check is scenario-independent, it audits the whole codebase) |
| 2 | Functional verification (live confirmation) | 12/56 citations observed printing live | **18/56** citations observed printing live (combined mode exercises far more code paths — all 12 families run concurrently) |
| 3 | Manual timing verification | Pipeline mean 29.88ms / max 31.51ms vs 100ms budget — 0/129 over budget | Pipeline mean 24.76ms / max 50.85ms vs 100ms budget — **0/587 over budget**, even running all 12 attacks concurrently at full 264-node scale |
| 4 | Video clip | NetAnim XML from the scenario_1 run (`outputs/XML/01_TTW_S1_Malicious_Vehicle.xml`) — see `HOW_TO_RECORD_VIDEO_CLIP.md` | NetAnim XML from the scenario_13 run (`outputs/XML/13_COMBINED_All_Scenarios.xml`) |
| 5 | PEM data point | `scenario_1/pem_datapoint_scenario1_30s.csv`: TP=129,TN=660,FP=0,FN=0, **MCC=1.0, AUROC=1.0** | `scenario_13/pem_datapoint_scenario13_60s.csv`: TP=1364,TN=3048,FP=6,FN=96, **MCC=0.949, AUROC=0.966** |

## scenario_13's additional detector-level breakdown (trained TGN model)

Printed directly by the running simulation (`scenario_13/ns3_run_raw_stdout.log`,
grep for `TGN DETECTION SUMMARY`):

```
TGN neural detector:      TP=1352 TN=1687 FP=176 FN=108   MCC=0.828  AUROC=0.968
  [ctrl] (controller-origin, TTW/BSHH/ME-S3/S4): TP=1023 FN=6
  [beh]  (vehicle/RSU-origin, S1/S2):            TP=329  TN=1687 FP=176 FN=102
Combined pipeline (LW-signature OR TGN-score):
                           TP=1432 TN=1681 FP=182 FN=28    MCC=0.877  AUROC=0.968
ACR: 91.454%
Divergence-only catches: 70 (controller-origin attacks TGN missed but the
                             blockchain divergence audit independently caught)
```

Three independent detection layers (LW signature detector, TGN neural
detector, blockchain divergence audit) all contribute, and the combined
pipeline outperforms any single layer alone — direct evidence the layered
defense design (Fig. 3.1) functions as intended, not just each layer in
isolation.

## Folder contents

Each `scenario_<N>/` folder contains:
- `equation_algorithm_audit_log.txt` — deliverable 1
- `functional_verification_log.txt` — deliverable 2
- `ns3_run_raw_stdout.log` — the full raw captured simulation output (proof of a real run)
- `pem_datapoint_scenario<N>_<simtime>s.csv` — deliverable 5

Shared (scenario-independent) files at the top level:
- `functional_verification.py` — the Python script itself
- `TIMING_VERIFICATION.md` — deliverable 3 (manual timing analysis, currently documents the scenario_1 run in detail; see the two tables above for scenario_13's numbers)
- `HOW_TO_RECORD_VIDEO_CLIP.md` — deliverable 4 instructions

## Re-running this yourself

```bash
cd "/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/documents/evidence"

# Scenario 1 (untrained model, fast)
python3 functional_verification.py --scenario 1 --simtime 30 --vehicles 200 --rsus 0 --attack_percentage 80

# Scenario 13 (combined, trained model, theta=0.85 -- takes longer, all 12 attacks concurrently)
python3 functional_verification.py --scenario 13 --simtime 60 --vehicles 200 --rsus 64 --controllers 4 --attack_percentage 80 \
  --tgn_weights=/home/sdvn_echo_topology/tgn_weights_sim60_ap60_3seeds.bin \
  --tgn_theta=0.85 --tgn_l_link=43.0 --tgn_dim=128 --tgn_layers=2
```

Each run auto-creates/overwrites its own `scenario_<N>/` subfolder only —
running scenario 1 again never touches scenario 13's evidence and vice versa.
Use `--skip-run` to re-generate the audit logs from an existing
`scenario_<N>/ns3_run_raw_stdout.log` without re-running the simulation.
