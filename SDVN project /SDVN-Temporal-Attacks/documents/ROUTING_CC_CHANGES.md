# Changes to routing.cc — TETA-Guard Implementation

All changes were made to `routing.cc` (146,760 lines total).
Companion change to `teta_guard_types.h` — Saber buffer sizes corrected.

**Change categories:**
- §3.4.1 formal model + T/E matrix wiring
- Mobility equation labels (Eqs. 3.2–3.33)
- Eq. 3.33 density formula fix
- ME weight recalibration warning
- TTWS2_ActivateReplay signature fix
- PemWriteCsvHeaderIfNeeded design decision documented

---

## Change 1 — §3.4.1 Formal Attack Triple (Lines 250–281)

**Location:** After the attack parameter declarations, before the `TopologyPacket` struct.

**What was there before:** Nothing — these declarations did not exist.

**What was added:**
```cpp
// Lines 250–268: §3.4.1 comment block
// §3.4.1 — TEMPORAL-ECHO ATTACK FORMALIZATION
//
// Formal attack triple (paper §3.4.1):
//   A = (G_t, T, E)
//   T[i][j] = forged timestamp for link eij
//   E[i][j] = 1 if link eij is echoed by a false reporter
//
// Topology divergence metric (Eq. 3.1):
//   delta(G_t^C, G_t^R) = |E_t^C  △  E_t^R|  > 0

// Line 272: T matrix — forged timestamps per link
std::map<std::string, double> attack_T_matrix;

// Line 276: E matrix — echo injection flags per link
std::set<std::string> attack_E_matrix;

// Line 281: Live divergence counter δ = |E_t^C △ E_t^R|
uint32_t topology_divergence_delta = 0;
```

---

## Change 2 — Mobility Equation Labels near `ttw_link_lifetime_bound` (Lines 167–180)

**Location:** Line 168 — `double ttw_link_lifetime_bound = 3.52;`

**What was there before:**
```cpp
double link_lifetime_threshold = 0.400;
double ttw_link_lifetime_bound = 3.52;
```

**What was added** (comment block inserted before line 168):
```cpp
double link_lifetime_threshold = 0.400;
// §3.4.7 Mobility-Induced Attack Amplification — Eq. 3.29–3.32
// Eq. 3.29:  L_link = 2 * r_comm / v_rel
//   Default: r_comm=300m, v_rel=80km/h * 2 = 160km/h = 44.4m/s → L_link ≈ 13.5s
//   The 3.52s default is calibrated for highway (v_rel=170km/h)
// Eq. 3.30:  N_beacon = L_link / T_b  (beacon intervals per link lifetime)
// Eq. 3.31:  tau_conv = 2 * T_b       (topology convergence delay)
// Eq. 3.32:  W_ho = r_comm / (v_max * T_b)  (RSU handover window)
double ttw_link_lifetime_bound = 3.52;
```

---

## Change 3 — Eq. 3.33 Density Formula in `PemComputeRhoMaxForLink` (Lines 856–896)

**Location:** `PemComputeRhoMaxForLink()` function, around line 856.

**What was there before:**
```cpp
// Used 2D disk area model: λ·π·rcomm²
const double observationArea =
    3.14159265358979323846 * std::pow(TTW_COMM_RANGE, 2.0);

// ...vehicle counting loop...

// Equation ME-S1: rhoMax(lambda, rcomm) = floor(lambda * pi * rcomm^2).
const double lambdaHat =
    observationArea > 0.0
        ? static_cast<double>(vehiclesNearLink.size()) / observationArea
        : 0.0;
uint32_t rhoMax =
    static_cast<uint32_t>(std::floor(lambdaHat * observationArea));
```

**What it is now (Eq. 3.33 — 1D road-segment model):**
```cpp
// Eq. 3.33: E[|R*(e_ij, t)|] = 2 * r_comm * lambda(t)
// lambda(t) is vehicles per metre along the road segment.
const double corridorLength = 2.0 * TTW_COMM_RANGE;   // metres

// ...vehicle counting loop (unchanged)...

// lambda_hat = observed vehicles / corridor length  (vehicles / m)
// rhoMax = E[|R*(e_ij, t)|] = 2 * r_comm * lambda_hat  (Eq. 3.33)
const double lambdaHat =
    corridorLength > 0.0
        ? static_cast<double>(vehiclesNearLink.size()) / corridorLength
        : 0.0;
uint32_t rhoMax =
    static_cast<uint32_t>(std::floor(2.0 * TTW_COMM_RANGE * lambdaHat));
```

---

## Change 4 — Equation Labels on 9 Signatures (Lines 1223–1375)

**Location:** `PemEvaluateEvent()` function — the triggered[0]…triggered[8] blocks.

**What was there before:** Plain descriptive comments without equation numbers.

**What was added:** Equation number prefix added to each signature's comment:

| Line | Before | After |
|------|--------|-------|
| 1223 | `// TTW-S1: the controller is still...` | `// Eq. 3.2 — TTW-S1: the controller is still...` |
| 1237 | `// TTW-S2: a topology timestamp...` | `// Eq. 3.3 — TTW-S2: a topology timestamp...` |
| 1252 | `// TTW-S3: two distinct reporters...` | `// Eq. 3.4 — TTW-S3: two distinct reporters...` |
| 1261 | `// ME-S1: \|R(eij,t)\| > rhoMax...` | `// Eq. 3.8 — ME-S1: \|R(e_ij,t)\| > E[\|R*(e_ij,t)\|]...` |
| 1277 | (no comment) | `// Eq. 3.5 — BSHH-S1: two heartbeats claim same identity...` |
| 1293 | (no comment) | `// Eq. 3.6 — BSHH-S2: heartbeat sender_timestamp is less than...` |
| 1314 | `// BSHH-S3 only fires when...` | `// Eq. 3.7 — BSHH-S3: heartbeat arrived but no beacon...` |
| 1325 | `// ME-S2: sudden inflation of reporter-inferred paths...` | `// Eq. 3.9 — ME-S2: sudden inflation of reporter-inferred paths...` |
| 1348 | `// ME-S3 (Reporter-Range AND Signal Inconsistency)...` | `// Eq. 3.10 — ME-S3: reporter position is outside...` |
| 1371 | `// ── STEP 1+2: Weighted signature scoring` | `// Eq. 3.11 — weighted detection score: s(e) = Σ w_i · 1[sig_i(e)=1]` |
| 1373 | (no complexity note) | `// Time complexity: O(9) per event — Eq. 3.12. Window scan: O(\|W\|) — Eq. 3.13.` |

---

## Change 5 — T Matrix and δ Wired into TTW Replay Functions

### TTW-S1 `TTW_ReplayAttack` — STEP 5 (Lines 2092–2097)

**What was there before:**
```cpp
// STEP 5: Send to controller
std::string key = std::to_string(src_id) + "_" + std::to_string(dst_id);
ttw_controller_table[key] = forged;
```

**What it is now:**
```cpp
// STEP 5: Send to controller — record in §3.4.1 T matrix and increment δ
std::string key = std::to_string(src_id) + "_" + std::to_string(dst_id);
attack_T_matrix[key] = forged_time;   // T[i][j] = forged timestamp (Eq. 3.1)
ttw_controller_table[key] = forged;
topology_divergence_delta++;          // δ = |E_t^C △ E_t^R| grows by 1
```

### TTW-S1 Mitigation in `TTW_RunReplayDetection` (Lines 2200–2201)

**What was there before:**
```cpp
ttw_controller_table.erase(key);
```

**What it is now:**
```cpp
ttw_controller_table.erase(key);
attack_T_matrix.erase(key);                          // remove from T matrix
if (topology_divergence_delta > 0) topology_divergence_delta--;  // δ restored
```

### TTW-S2/S3/S4 Replay Functions (same pattern applied to each)

**What was there before** (all three variants):
```cpp
ttw_controller_table[key] = forged;
```

**What it is now** (all three variants):
```cpp
ttw_controller_table[key] = forged;
attack_T_matrix[key] = forged_time;
topology_divergence_delta++;
```

Same δ decrement pattern applied to S3 and S4 mitigation erasures.

---

## Change 6 — E Matrix Wired into ME Echo Functions

### ME-S1 `ME_S1_EchoAttack` — emit_v3 / emit_v4 blocks (Lines 3649–3660)

**What was there before:**
```cpp
ttw_controller_table[k3] = {echo_v3, link_dst, t, true};
// (no E matrix or δ tracking)
```

**What it is now:**
```cpp
ttw_controller_table[k3] = {echo_v3, link_dst, t, true};
attack_E_matrix.insert(k3);       // E[i][j]=1: link echoed by false reporter V3
topology_divergence_delta++;      // δ += 1 (Eq. 3.1)
```

Same two lines added after each `ttw_controller_table[k4]` assignment for V4.

### ME-S2 `ME_S2_InjectEchoReports` (same pattern)

**Before:**
```cpp
ttw_controller_table[k3] = {false_v3, v2_id, t, true};
ttw_controller_table[k4] = {false_v4, v2_id, t, true};
```

**After:**
```cpp
ttw_controller_table[k3] = {false_v3, v2_id, t, true};
ttw_controller_table[k4] = {false_v4, v2_id, t, true};
attack_E_matrix.insert(k3); attack_E_matrix.insert(k4);
topology_divergence_delta += 2;
```

Same pattern applied identically to `ME_S3_InjectPhantomPaths` and `ME_S4_InjectPhantomPaths`.

---

## Change 7 — Eq. 3.32 W_ho Handover Window (Lines 142879–142885)

**Location:** Immediately after `cmd.Parse(argc, argv)` in `main()`.

**What was there before:**
```cpp
cmd.Parse (argc, argv);

// ── TTW mobility derived from cmd params — computed once after Parse ─────
```

**What was added** (inserted between Parse and TTW mobility block):
```cpp
cmd.Parse (argc, argv);

// ── §3.4.7 Eq. 3.32 — RSU handover window (beacon slots) ─────────────────
// W_ho = r_comm / (v_max · T_b)
// For default maxspeed=80 km/h: W_ho = 300 / (22.22 * 0.1) ≈ 135 slots
const double v_max_ms     = static_cast<double>(maxspeed) / 3.6;
const double w_ho_handover_window =
    (v_max_ms > 0.0 && PEM_BEACON_INTERVAL_S > 0.0)
        ? TTW_COMM_RANGE / (v_max_ms * PEM_BEACON_INTERVAL_S)
        : 135.0;
NS_LOG_INFO("[Mobility] W_ho = " << w_ho_handover_window << " beacon slots");
```

---

## Change 14 — ME Signature Weight Recalibration Warning (near PEM_WEIGHTS)

**Location:** Above the `PEM_WEIGHTS[9]` array declaration (~line 518).

**What was there before:**
```cpp
// TTW (S0,S1,S2): timestamp/topology persistence evidence, highest weight
// BSHH (S3,S4,S5): identity/heartbeat anomaly, mid weight
// ME (S6,S7,S8): topology-density anomaly, lower weight
static const double PEM_WEIGHTS[9] = { ... };
```

**What was added:** A detailed warning explaining that ME weights [6..8] were tuned against the old broken 2D disk formula and may produce elevated false-positive rates after the Eq. 3.33 fix, with exact recalibration steps.

---

## Change 15 — `TTWS2_ActivateReplay` Signature Fix (~line 2291)

**What was there before:**
```cpp
static void TTWS2_ActivateReplay(uint32_t rsu_ns3_id, uint32_t /*v1_ns3_id*/, uint32_t /*v2_ns3_id*/)
```

**What it is now:**
```cpp
// Vehicle pairs come from ttw_s2_all_pairs (registered in main()).
static void TTWS2_ActivateReplay(uint32_t rsu_ns3_id)
```

Call site updated from `(..., 0u, 0u)` to `(...)`. The dummy parameters were misleading — the function never used them; vehicle pairs were always loaded from `ttw_s2_all_pairs`.

---

## Change 16 — `PemWriteCsvHeaderIfNeeded` Design Decision (~line 978)

**What was there before:** Commented-out idempotency logic (append mode) with no explanation of why it was replaced.

**What was added:** Full design decision comment explaining:
- Why always-truncate was chosen over multi-run append
- When the original append design was appropriate
- How to restore it if needed for streaming dashboards

---

## Summary of All Changes

| # | File | Line Range | Type | What Changed |
|---|------|------------|------|--------------|
| 1 | routing.cc | 250–281 | Added | §3.4.1 attack triple structs + divergence counter |
| 2 | routing.cc | 167–180 | Added | Eq. 3.29–3.32 comment block |
| 3 | routing.cc | 856–896 | Modified | 2D disk → 1D road-segment density (Eq. 3.33) |
| 4 | routing.cc | 1223–1375 | Modified | Eq. 3.2–3.13 labels added to all 9 signatures + scoring |
| 5 | routing.cc | 2092–2097 | Modified | T matrix + δ++ wired to TTW-S1 replay injection |
| 6 | routing.cc | 2200–2201 | Modified | T matrix erase + δ-- wired to TTW-S1 mitigation |
| 7 | routing.cc | ~2387, 2546, 2700 | Modified | T matrix + δ++ in TTW-S2/S3/S4 replay |
| 8 | routing.cc | ~2455, 2614 | Modified | T matrix erase + δ-- in TTW-S3/S4 mitigation |
| 9 | routing.cc | 3649–3660 | Modified | E matrix + δ++ wired to ME-S1 echo injection |
| 10 | routing.cc | ~3851–3854 | Modified | E matrix + δ+=2 in ME-S2 |
| 11 | routing.cc | ~4013–4016 | Modified | E matrix + δ+=2 in ME-S3 |
| 12 | routing.cc | ~4163–4167 | Modified | E matrix + δ+=2 in ME-S4 |
| 13 | routing.cc | 142879–142885 | Added | Eq. 3.32 W_ho handover window computation |
| 14 | routing.cc | ~518 | Modified | ME weight recalibration warning (Eq. 3.33 impact) |
| 15 | routing.cc | ~2291 | Modified | TTWS2_ActivateReplay: removed 2 unused parameters |
| 16 | routing.cc | ~978 | Modified | PemWriteCsvHeaderIfNeeded: design decision documented |
| 17 | teta_guard_types.h | ~49–68 | Modified | Added SABER_* size constants; fixed KemExchangeState Saber fields to use correct sizes |
