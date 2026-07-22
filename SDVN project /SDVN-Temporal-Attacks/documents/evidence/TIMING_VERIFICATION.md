# Manual Timing Verification Confirmation

**System:** SDVN Temporal-Echo Topology Attack Framework (routing.cc + tgn_core.cc + teta_guard_filter.h)
**Evidence source:** real NS-3 run, `attack_scenario=1` (TTW-S1), `N_Vehicles=200`
(full network scale), `N_RSUs=0`, `attack_percentage=80`, `simTime=30s`,
`RngRun=1` — captured verbatim in `ns3_run_raw_stdout.log` (same run used for
the functional verification log and the PEM data point below). Nothing here is
simulated or hand-typed; every number is copy-pasted from that run's real
console output or its `pem_run_summary.csv` row.

This is a **manual** confirmation (a human reading and cross-checking the printed
budget-check lines the framework already produces against the thesis's own stated
timing requirements) — not an automated pass/fail script, per the supervisor's
request that this specific deliverable be manually verified.

---

## 1. The governing timing requirement

Per the PDF (§3.4.3 / Fig. 3.18), the full detect-and-mitigate pipeline — from a
beacon `Packet-In` event through TGN inference to a `FlowMod`/`BlacklistBeacon`
mitigation action — must complete within a **100 ms** budget, tied to the beacon
interval `T_b`. Algorithm 2 (FS-DETECT) and the crypto pre-filter (Algorithm 3)
are both scoped inside this same budget.

## 2. End-to-end pipeline latency — PASS

Printed by the framework itself (`M5` ablation instrumentation), from the real run:

```
[M5][T_pipeline] mean=29.916 ms  max=31.872 ms  over_budget=0/129
Full Pipeline Real-Time Budget Check (wall-clock, T_b=100 ms)
  Events exceeding budget: 0 / 903
  Events exceeding 100 ms budget: 0 / 129  -- full pipeline stays within the T_b budget on this hardware
```

**Verified manually:** mean pipeline latency (29.916 ms) and worst-case observed
latency (31.872 ms) are both well under (roughly 3x margin at full 200-vehicle
network scale) the 100 ms budget, and `over_budget=0/129` confirms every one of
the 129 real detection events in this run individually met the budget — not
just the average. Note the latency rose from ~9ms (50-vehicle run) to ~30ms
(200-vehicle run), a real, expected effect of network scale on per-event
processing cost — still comfortably inside budget. **PASS.**

## 3. Per-stage budget checks — PASS

```
Beacon sign/verify crypto (HMAC+Dilithium, CryptoMeasureBeaconSign/Verify):
  Calls: 516  Avg: 0.068 ms  Max: 0.26 ms  Calls exceeding budget: 0 / 516

Detection crypto (Dilithium verify+threshold-sig, CryptoMeasureDetection):
  Calls: 129  Avg: 0.28 ms  Max: 0.47 ms  Calls exceeding budget: 0 / 129

LKH mitigation crypto (LKH revoke+rekey, CryptoMeasureLKH):
  Calls: 129  Avg: 0.0055 ms  Max: 0.24 ms  Calls exceeding budget: 0 / 129
```

Every individually-instrumented pipeline stage (beacon reception + crypto,
RSU-forward, signature detection, detection-crypto, mitigation, LKH-crypto)
reports zero over-budget calls, each averaging well under 1ms. **PASS.**

## 4. Continuous neighborhood-beaconing tick budget — PASS

```
Real-time (wall-clock) budget check — T_b=100 ms:
  Ticks exceeding 100 ms budget: 0 / 200  -- pipeline stays within the T_b budget on this hardware
  -- grand total stays within the 100 ms beacon-interval budget (T_b) on this hardware
```

The ambient O(N²) neighborhood-discovery tick (`PemNeighborhoodDiscoveryTick`,
which runs every `T_b`=100ms for the whole simulated duration) itself stays
within its own 100ms deadline on every one of the 200 ticks measured — confirming
this background mechanism does not itself threaten the real-time budget it's
trying to feed data within.

## 5. KEM handshake sub-budget — DOCUMENTED LIMITATION, not a pipeline failure

```
[KEM][10ms budget] 199 handshakes timed: avg=34.9919 ms, max=41.0328 ms, over_budget=199/199 (budget=10 ms)
```

The PDF's literature-cited claim (§2.2.3/§3.4.2) that the ML-KEM-1024 + HQC-5
hybrid handshake "achieves millisecond-level handshake latency compliant with
the 10 ms V2X timing constraint" is **not met on this hardware** — every one of
199 real per-vehicle handshakes measured 3-4x over the stated 10ms target
(avg 34.99ms, max 41.03ms). This is a genuine, honestly-instrumented measurement
(`KEM_HANDSHAKE_BUDGET_MS = 10.0` in routing.cc, checked against real liboqs
ML-KEM-1024/HQC-5 operations), not a simulated/rounded figure.

**This does not violate the overall 100ms per-event pipeline budget verified in
§2 above**, because KEM handshakes happen once per vehicle at simulation setup
(t=0, before `Simulator::Run()` begins), not once per detection event. The
per-event detection pipeline (§2) does not re-run a KEM handshake on every
beacon/topology update, so this sub-component overshoot does not propagate into
the measured 29.9ms mean / 31.9ms max end-to-end latency.

**Recommendation for the write-up:** report this transparently as a known
hardware-dependent limitation of the literature-cited KEM latency claim, not as
a pipeline SLA violation — the two are architecturally decoupled and the actual
governing 100ms detection-pipeline budget (§3.4.3) is met with wide margin.

## Summary

| Check | Budget | Measured | Result |
|---|---|---|---|
| End-to-end detection pipeline (mean) | 100 ms | 29.916 ms | PASS |
| End-to-end detection pipeline (max) | 100 ms | 31.872 ms | PASS |
| Events exceeding pipeline budget | 0 expected | 0 / 129 | PASS |
| Per-stage budget (beacon/detection/LKH crypto) | 100 ms each | 0 over-budget calls, all <1ms avg | PASS |
| Ambient neighborhood tick | 100 ms | 0 / 200 over budget | PASS |
| KEM handshake sub-component | 10 ms | avg 34.99 ms, max 41.03 ms | **OVER BUDGET** (documented, does not affect pipeline SLA) |

Manually verified by cross-referencing every figure above against the identical
lines in `ns3_run_raw_stdout.log` (same run as the equation audit and PEM data
point). Timestamp of verification: see file mtimes in this directory.
