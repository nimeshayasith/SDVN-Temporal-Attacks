# How to Run — Attack Only vs Attack + Detection

This document explains exactly how to run the two main scenarios you will switch between during your project work.

---

## The Two Modes You Need

| Mode | What It Does | When to Use It |
|---|---|---|
| **Attack Only** | Runs the TTW attack, produces `ttw_attack_scenario4.txt`, no detection scoring | Testing / verifying the attack works correctly |
| **Attack + Detection** | Runs the attack AND the PEM detector, produces `pem_event_log.csv` + `pem_run_summary.csv` | Evaluating detection performance for your FYP results |

The difference is controlled by **one command-line argument**: `--attack_scenario`

---

## Prerequisites

Both modes use the same file: `routing.cc`
It must be placed inside the ns-3 scratch directory:

```
<your-ns3-folder>/scratch/routing.cc
```

Your ns-3 folder (based on your project README):
```
/home/nimesha/ns-allinone-3.35/ns-3.35/
```

---

## Mode 1 — Attack Only (No Detection)

Use this when you just want to watch the TTW attack happen — see the forged packet, the ghost link, and the controller being deceived.

### What happens:
- Attack timeline runs (t=10, t=15, t=20)
- `ttw_attack_scenario4.txt` is written
- PEM detector is NOT triggered (attack_scenario ≠ 4, so PEM code path is bypassed)
- No `pem_event_log.csv` or `pem_run_summary.csv` produced

### Command (ns-3.35 style — `waf`):

```bash
cd /home/nimesha/ns-allinone-3.35/ns-3.35/

./waf --run "scratch/routing \
  --simTime=30 \
  --N_Vehicles=2 \
  --N_RSUs=0 \
  --attack_scenario=1 \
  --malicious_vehicle_id=0 \
  --victim_neighbor_id=1 \
  --routing_algorithm=4"
```

### Command (newer ns-3 style — `ns3`):

```bash
cd /home/nimesha/ns-allinone-3.35/ns-3.35/

./ns3 run "scratch/routing \
  --simTime=30 \
  --N_Vehicles=2 \
  --N_RSUs=0 \
  --attack_scenario=1 \
  --malicious_vehicle_id=0 \
  --victim_neighbor_id=1 \
  --routing_algorithm=4"
```

> **Note:** `attack_scenario=1` triggers the attack. Any value **other than 0** that has a corresponding branch in `main()` will run attack logic. Check your `main()` switch to confirm which value maps to TTW.

### Expected output files after Mode 1:
```
ttw_attack_scenario4.txt     ← attack timeline log
NetAnim XML output            ← if AnimationInterface is enabled
routing result CSVs           ← normal routing metrics
```

---

## Mode 2 — Attack + Detection (Full PEM Evaluation)

Use this when you want to measure whether the detector catches the attack, compute MCC/AUROC/Tdet, and generate the CSV output for your FYP report.

### What happens:
- Attack timeline runs (t=10, t=15, t=20)
- `ttw_attack_scenario4.txt` is written
- PEM detector runs 50 ms after the attack (t=20.050)
- `pem_event_log.csv` is written (one row per network event)
- `pem_run_summary.csv` is written near the end of the run at `t = simTime - 0.001`
- If alert is raised → ghost link is removed from controller table (mitigation)

### Command (ns-3.35 style — `waf`):

```bash
cd /home/nimesha/ns-allinone-3.35/ns-3.35/

./waf --run "scratch/routing \
  --simTime=30 \
  --N_Vehicles=2 \
  --N_RSUs=0 \
  --attack_scenario=4 \
  --malicious_vehicle_id=0 \
  --victim_neighbor_id=1 \
  --routing_algorithm=4"
```

### Command (newer ns-3 style — `ns3`):

```bash
cd /home/nimesha/ns-allinone-3.35/ns-3.35/

./ns3 run "scratch/routing \
  --simTime=30 \
  --N_Vehicles=2 \
  --N_RSUs=0 \
  --attack_scenario=4 \
  --malicious_vehicle_id=0 \
  --victim_neighbor_id=1 \
  --routing_algorithm=4"
```

> **Key difference:** `--attack_scenario=4` is the value wired to the TTW attack + PEM detection path in `routing.cc`. This is the number that activates `TTW_InitLog()`, `TTW_SendHelloBeacon()`, `TTW_StorePacket()`, `TTW_ReplayAttack()`, and `TTW_RunReplayDetection()`.

### Expected output files after Mode 2:
```
ttw_attack_scenario4.txt     ← attack timeline log (same as Mode 1)
pem_event_log.csv             ← one row per event (beacon, topology update, heartbeat)
pem_run_summary.csv           ← one row with TP, TN, FP, FN, MCC, AUROC, Tdet
scratch/routing-animation.xml ← NetAnim XML output
routing result CSVs           ← normal routing metrics with phase column
```

### Viewing NetAnim

From the NetAnim build folder:

```bash
cd /home/nimesha/ns-allinone-3.35/netanim-3.108/
./NetAnim ../ns-3.35/scratch/routing-animation.xml
```

---

## Running No Attack (Baseline Only)

Use this to measure your network's normal performance before any attack.
The PEM layer will record all events as normal (attack_label = 0) — no alerts raised.

```bash
./waf --run "scratch/routing \
  --simTime=30 \
  --N_Vehicles=10 \
  --N_RSUs=2 \
  --attack_scenario=0 \
  --routing_algorithm=4"
```

> `--attack_scenario=0` = no attack, normal simulation only.

---

## Running Five Independent Runs (For Your FYP Report)

Your project requires **mean ± std** over **5 runs**. Use different RNG seeds for each run:

```bash
# Run 1
./waf --run "scratch/routing --attack_scenario=4 --RngRun=1 --simTime=30"

# Run 2
./waf --run "scratch/routing --attack_scenario=4 --RngRun=2 --simTime=30"

# Run 3
./waf --run "scratch/routing --attack_scenario=4 --RngRun=3 --simTime=30"

# Run 4
./waf --run "scratch/routing --attack_scenario=4 --RngRun=4 --simTime=30"

# Run 5
./waf --run "scratch/routing --attack_scenario=4 --RngRun=5 --simTime=30"
```

Each run appends one row to `pem_run_summary.csv`.
After 5 runs, open the CSV and compute mean ± std for: MCC, AUROC, Tdet, PDR, Te2e.

> If you want a clean single-run CSV, delete old `pem_event_log.csv` / `pem_run_summary.csv` first or move them aside. The current code appends summary rows across runs.

---

## Quick Reference — Key Parameters

| Parameter | What it controls | Attack-Only value | Detection value |
|---|---|---|---|
| `--attack_scenario` | Which scenario branch runs | `1` (or any non-4 attack branch) | `4` |
| `--N_Vehicles` | Number of vehicles | `2` minimum | `2` minimum |
| `--N_RSUs` | Number of RSUs | `0` for vehicle attacker | `0` for vehicle attacker |
| `--simTime` | Simulation duration (s) | `30` | `30` |
| `--malicious_vehicle_id` | Which vehicle is attacker | `0` | `0` |
| `--victim_neighbor_id` | Which vehicle is victim | `1` | `1` |
| `--routing_algorithm` | Routing algorithm | `4` (Proposed RL) | `4` (Proposed RL) |
| `--RngRun` | Random seed for multiple runs | `1` | `1`–`5` |

---

## What to Check After Each Run

### After Mode 1 (Attack Only)

Open `ttw_attack_scenario4.txt` and verify:

```
✅ STEP ①  HELLO — shows vehicles were in range at t=10
✅ STEP ②  TOPOLOGY UPDATE — accepted by controller
✅ STEP ③  ATTACKER STORES PACKET
✅ STEP ④  FORGING TIMESTAMP
✅ STEP ⑤  FORGED PACKET -> CONTROLLER
✅ STEP ⑥  FAULTY ROUTING DECISION
```

### After Mode 2 (Attack + Detection)

Open `pem_run_summary.csv` and verify:

```
✅ tp ≥ 1       (at least one true positive)
✅ fp = 0       (no false alarms during baseline)
✅ mcc > 0.5    (good detection correlation)
✅ auroc > 0.85 (good score separation)
✅ tdet_ms ≈ 50 (detected within 50 ms)
```

Open `pem_event_log.csv` and verify:

```
✅ Rows before t=20:   phase=baseline, attack_label=0, alert_raised=0
✅ Row at t≈20.050:    attack_label=1, alert_raised=1
✅ Detection + mitigation also appears in ttw_attack_scenario4.txt
```

> Important: let the simulation finish normally. If you stop it early with `Ctrl+C`, `pem_run_summary.csv` may not get its final row because the summary writer is scheduled just before `t = simTime`.

---

## The One Line That Switches Between Modes

Inside `routing.cc` in `main()`, look for the block:

```cpp
if (attack_scenario == 4)
{
    // This branch runs the TTW attack AND wires PEM detection
    TTW_InitLog();
    Simulator::Schedule(Seconds(TTW_HELLO_TIME),  &TTW_SendHelloBeacon, ...);
    Simulator::Schedule(Seconds(TTW_HELLO_TIME),  &TTW_SendTopologyUpdate, ...);
    Simulator::Schedule(Seconds(TTW_HELLO_TIME),  &TTW_StorePacket, ...);
    Simulator::Schedule(Seconds(TTW_REPLAY_TIME), &TTW_ReplayAttack, ...);
    // TTW_ReplayAttack internally schedules TTW_RunReplayDetection (PEM)
}
```

- Pass `--attack_scenario=4` → **this block runs → attack + detection**
- Pass `--attack_scenario=0` → **this block is skipped → no attack, no detection**
- Pass any other value → **other attack branches, no PEM wiring**

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `pem_event_log.csv` not created | `attack_scenario` ≠ 4 | Use `--attack_scenario=4` |
| `ttw_attack_scenario4.txt` empty | `TTW_InitLog()` not called | Check `attack_scenario == 4` branch in `main()` |
| `NetAnim: command not found` | Binary is not on your `PATH` | Run `./NetAnim ../ns-3.35/scratch/routing-animation.xml` from `netanim-3.108/` |
| NetAnim cannot find XML | Wrong file location | Open `scratch/routing-animation.xml` from the ns-3 root |
| Compilation fails near `std::max(...)` | Legacy `#define max 40` macro collides with PEM helpers | Already fixed in current `routing.cc` |
| `pem_run_summary.csv` has 0 new rows | Simulation was interrupted before final summary write | Let the run reach `t = simTime` without `Ctrl+C` |
| Detection latency = -1 | Alert was never raised | Check score threshold `PEM_SCORE_THRESHOLD = 0.12` |
