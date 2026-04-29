# Performance Evaluation Metrics Guide

This document explains what was added to `routing.cc`, why it was added, how the current Temporal Echo attack detection flow works, and how to check both attack-detection performance and network-routing performance.

## Purpose

The goal of the update was to extend the existing routing metrics code so the simulation can also report the performance evaluation metrics (PEMs) required by your Temporal Echo project:

- `MCC`
- `AUROC`
- `Detection Latency (Tdet, ms)`
- `Packet Delivery Ratio (PDR)`
- `End-to-End Latency (Te2e, ms)`

The current implementation is connected to the existing TTW attack scenario already present in `routing.cc`, especially `attack_scenario == 4`.

## What Was Added

The PEM update added four main parts to `routing.cc`.

### 1. PEM state variables

A new block of variables was added near the TTW attack globals:

- `pem_true_positive`
- `pem_true_negative`
- `pem_false_positive`
- `pem_false_negative`
- `pem_last_detection_score`
- `pem_last_auroc`
- `pem_last_mcc`
- `pem_attack_injection_time`
- `pem_first_alert_time`
- `pem_attack_active`
- `pem_mitigation_active`

These variables store the current detection status of the simulation.

### 2. PEM helper functions

Several helper functions were added:

- `PemSafeSqrt(double value)`
- `PemComputeMcc()`
- `PemComputeAuroc()`
- `PemRecordObservation(bool actualAttack, double score, bool alertRaised)`
- `PemGetDetectionLatencyMs()`
- `PemGetPhaseLabel()`

These functions calculate the metrics from the stored state.

### 3. Detection hook for TTW replay

A new function was added:

- `TTW_RunReplayDetection(uint32_t src_id, uint32_t dst_id, double linkDistance)`

This function is called shortly after the replay attack is injected. It acts as the current lightweight detector for the existing TTW scenario.

### 4. Periodic CSV export update

The existing periodic routing CSV writer was extended so it now exports the PEM values together with routing metrics.

The updated function is:

- `write_csv_results_routing()`

## Step-by-Step: What Happens During the Attack

This section explains the current logic step by step.

### Step 1. Normal topology update is accepted

Before the attack, vehicles send normal topology information to the controller.

Function involved:

- `TTW_SendTopologyUpdate(...)`

What happens:

- the controller stores a normal topology packet
- this is treated as a benign observation
- `PemRecordObservation(false, 0.0, false)` is called

Meaning:

- `actualAttack = false`
- `score = 0.0`
- `alertRaised = false`

So this contributes to the normal-class statistics, usually increasing `TN`.

### Step 2. The attacker stores an old valid packet

Function involved:

- `TTW_StorePacket(...)`

What happens:

- the attacker stores a previously valid topology packet
- this packet will later be replayed with false timing

This step prepares the attack but does not yet trigger detection.

### Step 3. The replay attack is injected

Function involved:

- `TTW_ReplayAttack(...)`

What happens:

- a forged packet is created
- the forged topology is inserted into the controller table
- the attack injection time is stored in:

`pem_attack_injection_time`

- attack phase flags are updated:

`pem_attack_active = true`

`pem_mitigation_active = false`

Meaning:

This marks the moment from which detection latency starts.

### Step 4. Detection is triggered after a short delay

At the end of `TTW_ReplayAttack(...)`, the code schedules:

```cpp
Simulator::Schedule(MilliSeconds(50), &TTW_RunReplayDetection, src_id, dst_id, dist);
```

Meaning:

- the detector is run `50 ms` after the attack injection
- this allows the simulation to compute a measurable `Tdet`

### Step 5. The TTW detector checks the ghost link

Function involved:

- `TTW_RunReplayDetection(...)`

What happens:

- it checks whether the physical link distance is larger than communication range
- it builds a simple detection score from the link inconsistency
- it raises an alert if the score is above threshold

Current threshold:

```cpp
static const double PEM_ALERT_THRESHOLD = 1.0;
```

Current budget target from the project:

```cpp
static const double PEM_BEACON_BUDGET_MS = 100.0;
```

### Step 6. Detection statistics are updated

Inside `TTW_RunReplayDetection(...)`, the code calls:

```cpp
PemRecordObservation(true, score, alertRaised);
```

Meaning:

- `actualAttack = true`
- the replay is treated as an attack sample
- if an alert is raised, `TP` increases
- if no alert is raised, `FN` increases

If this is the first alert, the code stores:

- `pem_first_alert_time`

and changes the system phase to:

- `post_mitigation`

### Step 7. Detection latency is computed

Function involved:

- `PemGetDetectionLatencyMs()`

Formula:

```text
Tdet = 1000 × (first_alert_time - attack_injection_time)
```

This returns milliseconds.

If the attack starts at `20.000 s` and the alert is raised at `20.050 s`, then:

```text
Tdet = 50 ms
```

Since the project compares this against `Tb = 100 ms`, this case satisfies the requirement:

```text
50 ms < 100 ms
```

## How the Metrics Are Calculated

## MCC

`MCC` means Matthews Correlation Coefficient.

It uses all four confusion-matrix values:

- `TP`
- `TN`
- `FP`
- `FN`

Formula used in the code:

```text
MCC = (TP × TN - FP × FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
```

Why it is useful:

- it is robust when classes are imbalanced
- this is important because normal events are usually much more frequent than attack events

Interpretation:

- `+1` means perfect detection
- `0` means no useful detection ability
- `-1` means completely wrong classification

## AUROC

`AUROC` means Area Under the Receiver Operating Characteristic.

In this code:

- attack scores are stored in `pem_positive_scores`
- benign scores are stored in `pem_negative_scores`

The code compares all positive scores against all negative scores and estimates how often attack scores are ranked higher than benign scores.

Interpretation:

- `1.0` means perfect separation
- `0.5` means random guessing
- below `0.5` means the scoring direction is poor

Important note:

The current AUROC implementation is suitable for this lightweight detector and early experimentation. It is not yet a full ML evaluation pipeline.

## Detection Latency

`Detection Latency` is the time between attack injection and first alert.

Formula:

```text
Tdet = first_alert_time - attack_injection_time
```

Then it is converted to milliseconds.

This is compared with:

```text
Tb = 100 ms
```

The CSV also writes whether the budget was satisfied in the `within_budget` column.

## Packet Delivery Ratio

`PDR` means the fraction of packets that were successfully delivered.

The routing metrics code already had packet delivery calculations. The PEM update reuses that periodic mechanism and exports the value together with detection metrics.

Interpretation:

- high `PDR` is good
- low `PDR` under attack means the attack hurts routing
- improved `PDR` after mitigation means the defense helps recover the network

## End-to-End Latency

`Te2e` is the average packet delivery time from sender to receiver.

The routing code already computes packet delay using:

- packet initial timestamps
- packet final timestamps

The PEM export now writes:

- `current_te2e_ms`
- `avg_te2e_ms`

Interpretation:

- low latency is good
- higher latency under attack indicates routing disruption
- reduced latency after mitigation shows recovery

## How Network Performance Is Checked

Network performance in this update is observed mainly through:

- `PDR`
- `Te2e`

These are written periodically to the routing results CSV.

The CSV also includes the phase label:

- `baseline`
- `under_attack`
- `post_mitigation`

This helps you compare network behavior across the three stages.

### Baseline

Before attack injection:

- `phase = baseline`
- use this as the normal reference

### Under attack

After attack injection but before mitigation:

- `phase = under_attack`
- check whether `PDR` drops
- check whether `Te2e` increases

### Post mitigation

After alert detection and mitigation:

- `phase = post_mitigation`
- check whether `PDR` improves again
- check whether `Te2e` decreases toward normal

## What Is Written to CSV

The updated routing CSV now includes columns like:

- `cycle`
- `sim_time_s`
- `phase`
- `current_te2e_ms`
- `avg_te2e_ms`
- `current_pdr_pct`
- `avg_pdr_pct`
- `current_jitter_ms`
- `avg_jitter_ms`
- `current_load_balance_pct`
- `avg_load_balance_pct`
- `tp`
- `tn`
- `fp`
- `fn`
- `mcc`
- `auroc`
- `detection_score`
- `alert_raised`
- `attack_injection_time_s`
- `first_alert_time_s`
- `detection_latency_ms`
- `threshold_budget_ms`
- `within_budget`

This means one periodic output file can now be used for both:

- attack-detection evaluation
- routing-performance evaluation

## How to Prove the Implementation Works

There are three levels of proof.

### 1. Code path proof

Check these connections in `routing.cc`:

- normal update calls `PemRecordObservation(false, 0.0, false)`
- replay attack stores `pem_attack_injection_time`
- replay attack schedules `TTW_RunReplayDetection(...)`
- detection calls `PemRecordObservation(true, score, alertRaised)`
- periodic metrics writer exports PEM values

If all of these are connected, the logic path exists.

### 2. Runtime proof

Run the simulation with the TTW attack scenario and inspect:

- `ttw_attack_scenario4.txt`
- the routing CSV output file

Expected behavior:

- attack injected around `20.000 s`
- alert raised around `20.050 s`
- `detection_latency_ms` around `50`
- `within_budget = 1`
- `phase` moves from `under_attack` to `post_mitigation`

### 3. Experimental proof for the report

The project states:

```text
All metrics are reported as mean ± standard deviation over five independent NS-3/SUMO simulation runs.
```

So for the report:

1. run the simulation five times
2. collect the CSV outputs
3. compute mean and standard deviation for:

- `MCC`
- `AUROC`
- `Detection Latency`
- `PDR`
- `Te2e`

## Important Limitation of the Current Version

The current detector is a lightweight TTW-specific detector for the already implemented attack scenario.

That means:

- it is suitable for scenario `attack_scenario == 4`
- it demonstrates how to compute the PEMs in the simulator
- it is not yet a full detector for all TTW, BSHH, and ME variants
- it is not yet a GNN-based detector

So this implementation should be understood as:

- a working PEM instrumentation layer
- a working example detection path
- a strong base for future extension

## Suggested Next Steps

To make this stronger for your final project, the next useful tasks are:

1. create a separate PEM-only CSV file for cleaner analysis
2. add explicit console logs for TP, TN, FP, FN, MCC, AUROC, and `Tdet`
3. add a post-processing script to calculate `mean ± std` over five runs
4. generalize the detector to other attack families:

- `TTW`
- `BSHH`
- `ME`

5. later replace the lightweight detector score with the score produced by your real ML or GNN detector

## Beginner Summary

In simple words, the update works like this:

1. the simulation runs normally
2. a replay attack is injected
3. the code stores the exact attack start time
4. the detector checks whether the replay created an impossible ghost link
5. if yes, it raises an alert
6. the code measures how fast the alert was raised
7. the code updates `TP`, `TN`, `FP`, `FN`
8. from those values, it computes `MCC` and `AUROC`
9. at the same time, it keeps exporting routing performance like `PDR` and `Te2e`
10. all values are written to CSV so you can later analyze and report them

## Final Note

This document explains the current implementation that was added to `routing.cc`. It is a practical first version for measuring PEMs inside your existing ns-3 attack scenario, not the final full research-grade detector for every attack family.
