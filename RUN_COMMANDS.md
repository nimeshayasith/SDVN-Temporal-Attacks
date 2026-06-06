# Full Run Commands — TETA-Guard Framework

**Environment:** Ubuntu (VMware), NS-3.35, Python 3.8+, Go 1.21+, Node.js 18+, OpenSSL

---

## Quick Reference

```
Layer 1 — NS-3 Simulation     →  routing.cc  (./waf --run)
Layer 2 — Crypto Filter       →  crypto_pipeline  (standalone binary)
Layer 4 — TGN Detector        →  tgn_detector.cc  (./waf --run)
Layer 5 — Blockchain          →  submit_alerts.py  (python3)
Training                      →  tgn_train.py  (python3)
```

---

## Step 0 — Environment Setup (once)

```bash
# Set NS-3 home (adjust path to match your installation)
export NS3_HOME=~/ns-allinone-3.35/ns-3.35

# Copy simulation files to NS-3 scratch
cp routing.cc        $NS3_HOME/scratch/
cp tgn_detector.cc   $NS3_HOME/scratch/

# Install Python dependencies
pip3 install torch torch-geometric pandas numpy matplotlib scikit-learn

# Install Node.js blockchain client dependencies
cd blockchain/client && npm install && cd ../..

# Install OpenSSL (for crypto pipeline)
sudo apt-get install libssl-dev
```

---

## Step 1 — Build NS-3

```bash
cd $NS3_HOME
./waf build 2>&1 | tee build_log.txt

# Check for errors
grep -E "^.*error:" build_log.txt | head -20
```

---

## Step 2 — Run NS-3 Simulation (`routing.cc`)

### Baseline (no attack)
```bash
cd $NS3_HOME
./waf --run "scratch/routing \
    --simTime=60 \
    --N_Vehicles=6 \
    --N_RSUs=0 \
    --attack_scenario=0"
```

### TTW Attacks
```bash
# TTW-S1 — Malicious Vehicle, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"

# TTW-S2 — Malicious RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=2"

# TTW-S3 — Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=3"

# TTW-S4 — Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=4"
```

### BSHH Attacks
```bash
# BSHH-S1 — Malicious Vehicle, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=5"

# BSHH-S2 — Malicious RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=6"

# BSHH-S3 — Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=7"

# BSHH-S4 — Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=8"
```

### ME Attacks
```bash
# ME-S1 — Malicious Vehicles, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=9"

# ME-S2 — Malicious RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=10"

# ME-S3 — Malicious Controller, No RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=11"

# ME-S4 — Malicious Controller, With RSU
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=12"
```

### All Attack Scenario IDs
```
0  = Baseline (no attack)
1  = TTW-S1   4  = TTW-S4
2  = TTW-S2   5  = BSHH-S1
3  = TTW-S3   6  = BSHH-S2
               7  = BSHH-S3
               8  = BSHH-S4
               9  = ME-S1
              10  = ME-S2
              11  = ME-S3
              12  = ME-S4
```

### Key Parameters
```bash
--simTime=60               # simulation duration (s)
--N_Vehicles=6             # number of vehicle nodes
--N_RSUs=1                 # number of RSU nodes (required for S2/S4 variants)
--attack_scenario=1        # attack ID (0–12)
--attack_percentage=20     # % of vehicles that are malicious (default 20)
--detection_enabled=1      # 1=detect+mitigate, 0=attack only (measure damage)
--ttw_link_lifetime_bound=3.52  # L_link for TTW (Eq. 3.29), seconds
--routing_algorithm=4      # 0=ECMP, 2=QRSDN, 3=RLMR, 4=Proposed RL, 5=DCMR
--RngRun=1                 # random seed for reproducibility
```

### 5 Runs for Report Statistics
```bash
#!/bin/bash
SCENARIO=$1
N_VEH=${2:-6}
N_RSU=${3:-0}
mkdir -p results/scenario_${SCENARIO}

for SEED in 1 2 3 4 5; do
    rm -f pem_event_log*.csv pem_run_summary*.csv *.txt routing-animation.xml
    ./waf --run "scratch/routing \
        --simTime=60 --N_Vehicles=${N_VEH} --N_RSUs=${N_RSU} \
        --attack_scenario=${SCENARIO} --RngRun=${SEED}"
    cp pem_run_summary_s${SCENARIO}.csv results/scenario_${SCENARIO}/run_${SEED}_summary.csv
    cp pem_event_log_s${SCENARIO}.csv   results/scenario_${SCENARIO}/run_${SEED}_events.csv
done

# Usage:
# bash run_5.sh 1 6 0    # TTW-S1
# bash run_5.sh 9 6 0    # ME-S1
```

### View Simulation Output
```bash
cat pem_run_summary_s1.csv    # detection metrics (MCC, AUROC, Tdet)
cat pem_event_log_s1.csv      # per-event log
cat ttw_attack_scenario4.txt  # human-readable TTW-S1 attack trace
```

---

## Step 2.5 — Handoff: routing.cc output → crypto pipeline input

> **This step is required before running the crypto pipeline.**
> routing.cc writes output files to `OUTPUT_ROOT_DIR/PEM_EVENT_LOG/` (defined as
> `/home/lasindu/ns-allinone-3.35/ns-3.35` in the source). The crypto pipeline
> expects `pem_event_log.csv` in the current working directory. Copy the file first:

```bash
# After Step 2, locate the generated PEM log:
ls $NS3_HOME/PEM_EVENT_LOG/          # files named by scenario, e.g. 01_TTW_S1_...csv

# Copy to working directory with the name crypto_pipeline expects:
SCENARIO=1
cp "$NS3_HOME/PEM_EVENT_LOG/$(ls $NS3_HOME/PEM_EVENT_LOG/ | grep "^0${SCENARIO}_\|^${SCENARIO}_" | head -1)" \
   pem_event_log_s${SCENARIO}.csv

# Or copy all scenarios at once:
for f in $NS3_HOME/PEM_EVENT_LOG/*.csv; do
    cp "$f" "$(basename $f)"
done

# Alternatively, if OUTPUT_ROOT_DIR was left as default "." in the build,
# the files are already in the current directory — no copy needed.
```

---

## Step 3 — Run Crypto Pipeline (`crypto_pipeline.cc`)

```bash
# Build (once, requires OpenSSL)
cd $NS3_HOME/scratch   # or wherever routing.cc is
g++ -std=c++17 -O2 crypto_pipeline.cc -lssl -lcrypto -lm -o crypto_pipeline

# Run (after Step 2.5 copies the PEM log to current directory)
./crypto_pipeline pem_event_log_s1.csv tgn_alerts.json

# Or with default filenames (if file is named pem_event_log.csv)
./crypto_pipeline
# reads: pem_event_log.csv  tgn_alerts.json

# View output
cat crypto_verified_events.csv    # events passed to TGN
cat crypto_drop_log.csv           # dropped events with reasons
cat crypto_layer_log.txt          # step-by-step trace
```

---

## Step 4 — Run TGN Detector (`tgn_detector.cc`)

The TGN detector includes `routing.cc` and runs the full pipeline in one command.

```bash
cd $NS3_HOME

# TTW-S1
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"

# BSHH-S2
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=6"

# ME-S1
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=9"

# Baseline
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --attack_scenario=0"

# Highway mobility (recalibrate γ and W_max)
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --attack_scenario=1 --tgn_l_link=4.5"

# With pre-trained weights
./waf --run "scratch/tgn_detector \
    --simTime=60 --N_Vehicles=6 --attack_scenario=1 --tgn_weights=tgn_weights.bin"
```

TGN-specific parameters:
```bash
--tgn_l_link=43.0      # link lifetime (s) for γ + W_max calibration
--tgn_theta=0.40       # anomaly threshold θ_FS
--tgn_weights=path     # pre-trained weights binary
```

View TGN output:
```bash
cat tgn_summary.csv               # MCC, AUROC, Tdet, precision, recall
cat tgn_events.csv                # per-event features + scores
cat tgn_detection_log_s1.txt      # step-by-step detection trace
cat tgn_alerts.json               # alerts for blockchain
cat crypto_filter_log.txt         # crypto pre-filter decisions
```

---

## Step 5 — TGN Training (`tgn_train.py`)

**Preferred: use `generate_training_data.sh`** — handles all 13 scenarios × N seeds, correct N_RSUs per scenario, and calls `tgn_train.py` automatically.

```bash
# Automated (recommended) — from the project root directory
bash generate_training_data.sh

# With options
bash generate_training_data.sh \
    --ns3_home ~/ns-allinone-3.35/ns-3.35 \
    --sim_time 60 \
    --n_vehicles 6 \
    --seeds "1 2 3" \
    --epochs 50 \
    --output tgn_weights.bin

# Skip training (data collection only)
bash generate_training_data.sh --skip_training
python3 tgn_train.py training_data/all_events.csv --epochs 200 --output tgn_weights.bin
```

> **Note:** Until `tgn_weights.bin` exists, `tgn_detector.cc` runs in **heuristic mode** and prints a prominent warning. The heuristic is structurally similar to the LW detector — not the trained GNN claimed in the paper.

```bash
# Verify you are in real GNN mode (no warning should appear):
./waf --run "scratch/tgn_detector --attack_scenario=1 --tgn_weights=tgn_weights.bin" 2>&1 | \
    grep -c "WARNING.*HEURISTIC"
# Expected output: 0  (no warning = real GNN active)
```

---

## Step 6 — Baseline Comparison (`tgn_compare.py`)

```bash
# Compare TGN vs LW vs Static-GCN vs DMSTG-AD (RQ3)
python3 tgn_compare.py --scenario 1 --n_runs 5
python3 tgn_compare.py --scenario 9 --n_runs 5   # ME-S1

# All scenarios
for S in 1 2 3 4 5 6 7 8 9 10 11 12; do
    python3 tgn_compare.py --scenario $S --n_runs 5
done
```

---

## Step 7 — Blockchain Layer

### Start Hyperledger Fabric Network
```bash
cd blockchain

# Install Fabric binaries (once)
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7

# Full setup
cd scripts
chmod +x bootstrap.sh create_channel.sh deploy_chaincode.sh
bash bootstrap.sh

# Or manually:
cd ../network
docker-compose -f docker-compose-teta.yaml up -d
cd ../scripts
bash create_channel.sh
bash deploy_chaincode.sh

# Verify
docker ps
peer chaincode list --installed -C teta-channel
```

### Submit TGN Alerts to Blockchain
```bash
# After Step 4 generates tgn_alerts.json:

# Simple submission (peer CLI)
python3 submit_alerts.py

# Custom alert file
python3 submit_alerts.py --alerts tgn_alerts.json

# With beacon evidence (enables Eq. 3.1 divergence check)
python3 submit_alerts.py \
    --alerts tgn_alerts.json \
    --evidence beacon_evidence.json

# Dry run
python3 submit_alerts.py --alerts tgn_alerts.json --dry-run

# Full SDK path (Node.js) with controller topology divergence check
cd blockchain/client
node submitToFabric.js \
    --alerts tgn_alerts.json \
    --evidence beacon_evidence.json \
    --ctrl_topo ctrl_topo.json
```

### Monitor Events
```bash
node blockchain/client/eventListener.js
# Listens for AttackDetected events on teta-channel in real time
```

### Stop Fabric Network
```bash
cd blockchain/network
docker-compose -f docker-compose-teta.yaml down -v
```

---

## Step 8 — Statistics from Results

```python
# compute_stats.py — run after Step 2 with 5 seeds
import pandas as pd, glob, sys

scenario_id = sys.argv[1]
files = glob.glob(f"results/scenario_{scenario_id}/run_*_summary.csv")
df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

cols = ['mcc','auroc','tdet_ms',
        'pdr_under_attack_pct','pdr_post_mitigation_pct',
        'te2e_under_attack_ms','te2e_post_mitigation_ms']

print(f"\n=== Scenario {scenario_id} (n={len(df)}) ===")
for col in cols:
    if col in df.columns:
        print(f"  {col:35s}: {df[col].mean():.3f} ± {df[col].std():.3f}")
```

```bash
python3 compute_stats.py 1    # TTW-S1
python3 compute_stats.py 9    # ME-S1
```

---

## Automated Integration Test

Use `run_integration_test.sh` to verify the full pipeline in one command:

```bash
# Full test (requires Fabric network running)
bash run_integration_test.sh --scenario 1

# Without live Fabric (dry-run mode — no Docker needed)
bash run_integration_test.sh --scenario 1 --dry_run

# With pre-trained TGN weights
bash run_integration_test.sh --scenario 1 --tgn_weights tgn_weights.bin

# Skip individual steps
bash run_integration_test.sh --scenario 1 --skip_crypto --dry_run
```

The script runs all 4 steps, checks each output file, and reports PASS/FAIL.

---

## Complete End-to-End Run (Single Scenario — Manual)

```bash
cd $NS3_HOME

# 1. Run NS-3 simulation
./waf --run "scratch/routing --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"

# 2. Handoff: copy PEM log to working directory (see Step 2.5 above)
cp PEM_EVENT_LOG/01_TTW_S1_Malicious_Vehicle.csv pem_event_log_s1.csv

# 3. Run crypto pipeline
./crypto_pipeline pem_event_log_s1.csv tgn_alerts.json

# 4. Run TGN detector (re-runs simulation + crypto filter + GNN scoring)
./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --N_RSUs=0 \
    --attack_scenario=1 --tgn_weights=tgn_weights.bin"

# 5. Start Fabric (if not running)
cd blockchain/network && docker-compose -f docker-compose-teta.yaml up -d && cd $NS3_HOME

# 6. Submit alerts — eventListener.js will execute FlowMod HTTP POST to Ryu
python3 submit_alerts.py --alerts tgn_alerts.json

# 7. View all outputs
echo "=== PEM Summary ===" && cat pem_run_summary_s1.csv
echo "=== TGN Summary ===" && cat tgn_summary.csv
echo "=== Crypto Filter ===" && cat crypto_filter_log.txt
echo "=== Blockchain Log ===" && cat blockchain_submission_log.txt
```

---

## Output Files Reference

| File | Generated By | Contents |
|------|-------------|----------|
| `pem_event_log_s{N}.csv` | routing.cc | Per-event PEM log (22 columns) |
| `pem_run_summary_s{N}.csv` | routing.cc | tp/tn/fp/fn, MCC, AUROC, Tdet |
| `ttw_attack_scenario4.txt` | routing.cc | Human-readable TTW-S1 trace |
| `bshh_s1_attack_log.txt` | routing.cc | Human-readable BSHH-S1 trace |
| `me_s1_attack_log.txt` | routing.cc | Human-readable ME-S1 trace |
| `channel_delivery_analysis.csv` | routing.cc | 7-channel DSRC fanout analysis |
| `routing-animation.xml` | routing.cc | NetAnim visualization |
| `crypto_verified_events.csv` | crypto_pipeline | Events passing crypto filter |
| `crypto_drop_log.csv` | crypto_pipeline | Dropped events with reasons |
| `crypto_layer_log.txt` | crypto_pipeline | Per-packet 4-step trace |
| `tgn_events.csv` | tgn_detector | Per-event TGN features + scores |
| `tgn_summary.csv` | tgn_detector | MCC, AUROC, Tdet, θ_FS |
| `tgn_detection_log_s{N}.txt` | tgn_detector | Step-by-step detection trace |
| `tgn_alerts.json` | tgn_detector | AlertObject array for blockchain |
| `crypto_filter_log.txt` | tgn_detector | Crypto pre-filter decisions |
| `blockchain_submission_log.txt` | submit_alerts.py | Per-alert blockchain submission |
