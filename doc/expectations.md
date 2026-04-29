# Expectations — What the Simulation Should Produce

This document defines the expected outputs, behaviors, and metric targets for the SDVN Temporal-Echo Topology Attack simulation.

---

## Overview of Expected Simulation Flow

The simulation models a Software-Defined Vehicular Network (SDVN) where a malicious RSU or vehicle performs temporal replay attacks to corrupt the SDN controller's view of the network topology.

### Timeline of Events (Attack Scenario 4 — TTW)

```
t =  0 s   Vehicles start moving. Beacons begin.
t = 10 s   ① V2V HELLO exchange: V0 and V1 are neighbors
t = 10 s   ② V0 sends legitimate topology update to controller
t = 10 s   ③ V0 (attacker) stores a copy of the packet
t = 15 s   Physical link V0 ↔ V1 breaks (vehicles move apart)
t = 20 s   ④ V0 forges a new timestamp on the stored packet
t = 20 s   ⑤ V0 sends forged packet → controller is deceived
t = 20 s   ⑥ Controller believes ghost link V0↔V1 is still ACTIVE
t = 20.05s PEM detector runs — should catch the attack within 50 ms
t = end    Simulation writes CSV results and log files
```

---

## Expected Detection Results

### Detection Latency (Tdet)

| Metric | Expected Value |
|---|---|
| Attack injection time | `20.000 s` |
| First alert time | `≈ 20.050 s` |
| Detection latency | `≈ 50 ms` |
| Budget threshold (Tb) | `100 ms` |
| Within budget | **YES** (`50 ms < 100 ms`) |

The detector is scheduled `50 ms` after the attack is injected:
```cpp
Simulator::Schedule(MilliSeconds(50), &TTW_RunReplayDetection, src_id, dst_id, dist);
```

### MCC (Matthews Correlation Coefficient)

| Scenario | Expected MCC |
|---|---|
| Perfect detection | `+1.0` |
| Random guessing | `≈ 0.0` |
| **Target for your project** | `> 0.5` (good detection) |

### AUROC (Area Under ROC Curve)

| Scenario | Expected AUROC |
|---|---|
| Perfect separation | `1.0` |
| Random | `0.5` |
| **Target for your project** | `> 0.85` |

---

## Expected Network Performance Results

### Packet Delivery Ratio (PDR)

| Phase | Expected PDR |
|---|---|
| Baseline (before attack) | `≥ 90%` |
| Under attack | Drops significantly (packets routed via ghost link are dropped) |
| Post-mitigation | Recovers toward baseline |

### End-to-End Latency (Te2e)

| Phase | Expected Te2e |
|---|---|
| Baseline | Low (typical routing latency) |
| Under attack | **Increases** — packets hit dead routes |
| Post-mitigation | **Decreases** — correct routes restored |

---

## Expected Log Files

After simulation, the following output files should exist:

### `ttw_attack_scenario4.txt`
Human-readable attack log.

**Expected structure:**
```
========================================================
  TTW Attack Scenario 4 — Malicious Vehicle, No RSUs   
========================================================

  t=10  ①  V2V HELLO exchange
  t=10  ②  Topology updates to controller
  t=10  ③  Attacker stores old packet
  t=15      Link breaks physically
  t=20  ④  Attacker forges timestamp
  t=20  ⑤  Forged packet sent to controller
  t=20  ⑥  Controller issues faulty routing

[t=10.000]  STEP ①  HELLO
  V0 pos=(x0, y0)
  V1 pos=(x1, y1)
  dist=XXX m  DELIVERED — neighbor discovered

[t=10.000]  STEP ②  TOPOLOGY UPDATE (legitimate)
  V0 -> Controller
  Packet : <V0 sees V1, t=10.000>
  Result : ACCEPTED — link V0<->V1 marked ACTIVE

[t=10.000]  STEP ③  ATTACKER STORES PACKET
  old_packet : <V0 sees V1, t=10.000>
  Status     : Stored — awaiting replay at t=20

[t=20.000]  STEP ④  FORGING TIMESTAMP
  Original : <V0 sees V1, t=10.000>
  Forged   : <V0 sees V1, t=20.000>  MALICIOUS
  Physical link distance : XXX m  BROKEN

[t=20.000]  STEP ⑤  FORGED PACKET -> CONTROLLER
  Controller ACCEPTED (cannot detect forgery)

[t=20.000]  STEP ⑥  FAULTY ROUTING DECISION
  Controller believes V0<->V1 ACTIVE at t=20.000
  Physical reality : link BROKEN
  Consequence : packets routed via ghost link will be DROPPED

[t=20.050]  DETECTION + MITIGATION
  Alert raised for ghost link V0<->V1
  Link distance: XXX m
  Detector score: 0.XX
  Detection latency: 50.0 ms
  Action: forged topology entry removed from controller table
```

---

### `pem_event_log.csv`
One row per network event observed.

**Expected columns:**
```
sim_time_s, event_type, physical_sender_id, claimed_sender_id,
reporter_id, link_src_id, link_dst_id, sender_timestamp_s,
reception_timestamp_s, attack_label, triggered_signatures,
score, alert_raised, phase, detection_latency_ms,
reporter_x, reporter_y, link_src_x, link_src_y, link_dst_x, link_dst_y
```

**Expected key rows:**
- Rows before t=20: `attack_label=0`, `score≈0`, `alert_raised=0`, `phase=baseline`
- Row at t≈20.050: `attack_label=1`, `score>0.12`, `alert_raised=1`, `phase=under_attack`
- Rows after alert: `phase=post_mitigation`

---

### `pem_run_summary.csv`
One row per simulation run.

**Expected columns:**
```
run_id, attack_scenario, tp, tn, fp, fn, mcc, auroc, tdet_ms,
pdr_under_attack_pct, pdr_post_mitigation_pct,
te2e_under_attack_ms, te2e_post_mitigation_ms, total_events
```

**Expected values (single run):**
```
tp ≥ 1   (at least the replay event is detected)
tn ≥ 1   (at least some baseline events correctly not flagged)
fp = 0   (no false alarms in the baseline)
fn = 0   (no missed attacks)
mcc > 0.5
auroc > 0.85
tdet_ms ≈ 50
```

---

### `simulation.log` (from sdvn-temporal-attacks.cc)
Human-readable event log from the standalone simulation.

**Expected entries (TTW scenario):**
```
0.500s - V0 sent BEACON
1.000s - V1 sent BEACON
...
10.000s - RSU0 configured for TTW ATTACK
...
20.000s - RSU0 STORED topology update for replay
...
20.000s - RSU0 REPLAYED with FORGED TIMESTAMP: V0->V1 original_t=10.000 forged_t=20.000
```

---

### `topology_log.csv` (from sdvn-temporal-attacks.cc)
Records all topology updates.

**Expected columns:**
```
sim_time, source, destination, timestamp, status
```

**Expected entries:**
- Before attack: `LEGITIMATE` rows
- After attack: `FORGED` rows at `t=20s`

---

### `attack_log.csv` (from sdvn-temporal-attacks.cc)
Records every malicious action.

**Expected entries:**
```
20.000, TTW, Replay attack started
20.000, TTW, Replayed V0->V1 with forged timestamp
```

---

## Expected Detection Signatures (9-Signature System)

The PEM evaluator checks 9 binary signatures for each event. For the TTW replay event, the **expected triggered signatures** are:

| Index | Signature | Expected for TTW replay |
|---|---|---|
| 0 | `TTW-S1` — reception delay > beacon interval + epsilon | **YES** — replayed old packet arrives late |
| 1 | `TTW-S2` — newer reception but older sender timestamp | **YES** — forged packet has contradicting timestamps |
| 2 | `TTW-S3` — same link reported with different timestamps by different reporters | Possible |
| 3 | `BSHH-S1` — conflicting heartbeats | No (TTW attack only) |
| 4 | `BSHH-S2` — out-of-order heartbeat | No |
| 5 | `BSHH-S3` — heartbeat without beacon | No |
| 6 | `ME-S1` — reporters exceed density-based limit | No |
| 7 | `ME-S2` — path count sudden jump | No |
| 8 | `ME-S3` — reporter outside communication range | Possible |

**Expected composite score for TTW replay:**
```
score = (number of triggered signatures) / 9
      ≥ 2/9 = 0.222  →  exceeds PEM_SCORE_THRESHOLD = 0.12
      → alert_raised = true
```

---

## Expected Research Results (Five-Run Summary)

The project requires five independent NS-3/SUMO runs. The expected final report values are:

| Metric | Expected Mean | Expected Std Dev |
|---|---|---|
| MCC | `≥ 0.80` | `≤ 0.10` |
| AUROC | `≥ 0.90` | `≤ 0.05` |
| Tdet (ms) | `≈ 50` | `≤ 5` |
| PDR baseline | `≥ 90%` | `≤ 5%` |
| PDR under attack | Drops visibly | — |
| PDR post-mitigation | Recovers toward baseline | — |
| Te2e baseline | Low | — |
| Te2e under attack | Increases | — |
| Te2e post-mitigation | Decreases | — |

---

## What a Successful Run Looks Like

A successful simulation run should show these outcomes in order:

1. ✅ Vehicles exchange HELLO beacons at `t=10s`
2. ✅ Legitimate topology update accepted by controller
3. ✅ Attacker stores old packet
4. ✅ Physical link breaks at `t=15s`
5. ✅ Forged packet injected at `t=20s`
6. ✅ PEM detector fires at `t=20.050s`
7. ✅ `alert_raised = 1` in `pem_event_log.csv`
8. ✅ Forged entry erased from `ttw_controller_table`
9. ✅ `tdet_ms ≈ 50` in `pem_run_summary.csv`
10. ✅ Phase changes: `baseline` → `under_attack` → `post_mitigation`
