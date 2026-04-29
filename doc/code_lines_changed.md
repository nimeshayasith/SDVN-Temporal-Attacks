# Code Lines Changed — Line-by-Line Reference

This document lists every specific line range changed or added in `routing.cc` and describes what each block does. Use this as a quick code reference alongside the source file.

---

## `routing.cc` — Line-by-Line Change Map

### Lines 1–50 — Includes & Namespace

```
Lines 1–47    Unchanged: NS-3 module includes + STL includes
Line 49       using namespace std;
Line 50       using namespace ns3;
```

> **Why this matters:** `using namespace ns3` must appear before any NS-3 types or functions are used at file scope. Moving it earlier (Error 4 fix) allows the attack timing constants on lines 154–156 to compile.

---

### Lines 54–80 — Simulation `#define` Macros

```
Lines 55–80   Unchanged: #define max, max1 ... max25
```

No changes.

---

### Lines 82–130 — Core Simulation Parameters

```
Lines 83–130  Unchanged: lambda, flow_size, N_RSUs, N_Vehicles, routing_algorithm,
              experiment_number, simTime, optimization parameters, mu1/mu2/mu3, etc.
```

No changes to existing parameters.

---

### Lines 132–156 — ATTACK PARAMETERS BLOCK ← **CHANGED**

```
Line 132   // ─── ATTACK PARAMETERS ───
Line 134   // ERROR 1+2+3 FIX: each variable declared EXACTLY ONCE, one type only

Line 137   // ERROR 1 FIX comment
Line 139   uint32_t attack_scenario = 0;           ← single declaration (was declared twice)

Line 141   // ERROR 2 FIX comment
Line 142   uint32_t malicious_vehicle_id = 0;       ← single declaration (was declared twice)

Line 144   // ERROR 3 FIX comment
Line 145   uint32_t victim_neighbor_id = 1;         ← single declaration (was declared twice)

Line 147   bool is_malicious_controller  = false;   ← unchanged (was fine)
Line 148   bool has_RSU_infrastructure   = false;   ← unchanged (was fine)

Line 151   // ERROR 4 FIX comment
Line 154   static const double TTW_HELLO_TIME  = 10.0;
Line 155   static const double TTW_LINK_BREAK  = 15.0;
Line 156   static const double TTW_REPLAY_TIME = 20.0;
```

---

### Lines 158–183 — TTW Packet Struct & State Variables ← **NEW**

```
Line 163   // ERROR 5 FIX: merged StoredPacket + TopologyPacket → ONE struct
Line 164   struct TopologyPacket {
Line 165       uint32_t src_id;
Line 166       uint32_t seen_id;
Line 167       double   timestamp;
Line 168       bool     is_forged;
Line 169   };

Line 172   TopologyPacket ttw_stored_packet;         ← attacker's stored copy
Line 173   bool           ttw_packet_stored = false;

Line 177   std::map<std::string, TopologyPacket> ttw_controller_table;   ← controller belief table

Line 180   static const double TTW_COMM_RANGE = 300.0;   ← DSRC range in meters

Line 182   std::ofstream ttw_log;                    ← attack event log file
```

---

### Lines 185–193 — PEM Constants ← **NEW**

```
Line 186   static const double PEM_BEACON_BUDGET_MS      = 100.0;   ← detection budget Tb
Line 187   static const double PEM_BEACON_INTERVAL_S     = 0.100;   ← beacon period
Line 188   static const double PEM_PROPAGATION_EPSILON_S = 0.020;   ← propagation tolerance
Line 189   static const double PEM_HEARTBEAT_WINDOW_S    = 0.400;   ← sliding window width
Line 190   static const double PEM_SCORE_THRESHOLD       = 0.12;    ← alert threshold
Line 191   static const double PEM_ME_TOLERANCE_MU       = 0.30;    ← ME density tolerance
Line 192   static const double PEM_ME_DELTA_MAX          = 1.0;     ← ME path jump limit
Line 193   static const double PEM_SIGNAL_PLACEHOLDER    = -9999.0; ← missing data marker
```

---

### Lines 195–221 — PEM Event Enum & Struct ← **NEW**

```
Line 195   enum PemEventType {
Line 197       PEM_EVENT_BEACON         = 0,
Line 198       PEM_EVENT_TOPOLOGY_UPDATE = 1,
Line 199       PEM_EVENT_HEARTBEAT      = 2
Line 200   };

Line 202   struct PemEvent {
Line 204       double sim_time;
Line 205       PemEventType type;
Line 206       uint32_t physical_sender_id;
Line 207       uint32_t claimed_sender_id;
Line 208       uint32_t reporter_id;
Line 209       uint32_t link_src_id;
Line 210       uint32_t link_dst_id;
Line 211       double sender_timestamp;
Line 212       double reception_timestamp;
Line 213       Vector reporter_position;
Line 214       Vector link_src_position;
Line 215       Vector link_dst_position;
Line 216       bool attack_label;
Line 217       bool triggered[9];         ← 9 detection signatures
Line 218       double score;
Line 219       bool alert_raised;
Line 220       double detection_latency_ms;
Line 221   };
```

---

### Lines 223–256 — PEM Global State Variables ← **NEW**

```
Line 223   uint64_t pem_true_positive  = 0;
Line 224   uint64_t pem_true_negative  = 0;
Line 225   uint64_t pem_false_positive = 0;
Line 226   uint64_t pem_false_negative = 0;

Line 228   double pem_last_detection_score = 0.0;
Line 229   double pem_last_auroc           = 0.5;
Line 230   double pem_last_mcc             = 0.0;
Line 231   double pem_attack_injection_time = -1.0;
Line 232   double pem_first_alert_time      = -1.0;

Line 234   bool pem_last_alert         = false;
Line 235   bool pem_attack_active      = false;
Line 236   bool pem_mitigation_active  = false;

Line 238   std::vector<double> pem_positive_scores;    ← attack-class scores for AUROC
Line 239   std::vector<double> pem_negative_scores;    ← normal-class scores for AUROC
Line 240   std::deque<PemEvent> pem_event_window;      ← sliding window
Line 241   std::map<uint32_t, std::vector<PemEvent>> pem_sender_event_history;
Line 242   std::map<uint32_t, std::vector<PemEvent>> pem_heartbeat_history;
Line 243   std::map<std::string, std::vector<PemEvent>> pem_link_report_history;
Line 244   std::map<std::string, double> pem_previous_path_counts;
Line 245   std::vector<PemEvent> pem_all_events;
Line 246   double pem_under_attack_pdr_sum         = 0.0;
Line 247   double pem_under_attack_te2e_sum        = 0.0;
Line 248   double pem_post_mitigation_pdr_sum      = 0.0;
Line 249   double pem_post_mitigation_te2e_sum     = 0.0;
Line 250   uint64_t pem_under_attack_snapshots     = 0;
Line 251   uint64_t pem_post_mitigation_snapshots  = 0;
Line 252   bool pem_event_csv_header_written    = false;
Line 253   bool pem_summary_csv_header_written  = false;
Line 254   extern double current_packet_delivery_ratio;   ← from routing section
Line 255   extern double current_latency_routing;         ← from routing section
Line 256   extern NodeContainer Vehicle_Nodes;            ← from main setup
```

---

### Lines 258–262 — `PemSafeSqrt` ← **NEW**

```
Line 258   static double PemSafeSqrt(double value) {
Line 261       return std::sqrt(std::max(0.0, value));
Line 262   }
```

Prevents `sqrt()` from receiving negative numbers due to floating-point rounding.

---

### Lines 264–281 — `PemComputeMcc` ← **NEW**

```
Line 264   static double PemComputeMcc() {
Line 267–270   Cast TP, TN, FP, FN to double
Line 272       numerator = (tp * tn) - (fp * fn)
Line 273–274   denominator = PemSafeSqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
Line 276–279   Return 0.0 if denominator <= 0
Line 280       return numerator / denominator;
Line 281   }
```

---

### Lines 283–310 — `PemComputeAuroc` ← **NEW**

```
Line 283   static double PemComputeAuroc() {
Line 286       if either score list is empty: return 0.5
Line 291       double concordant = 0.0;
Line 292–304   For every (positive, negative) score pair:
                   if posScore > negScore: concordant += 1.0
                   if equal within 1e-12: concordant += 0.5
Line 307–309   return concordant / (n_positive * n_negative)
Line 310   }
```

---

### Lines 312–351 — `PemRecordObservation` ← **NEW**

```
Line 312   static void PemRecordObservation(bool actualAttack, double score, bool alertRaised) {
Line 315       pem_last_detection_score = score;
Line 316       pem_last_alert = alertRaised;

Line 318       if (actualAttack):
Line 320           pem_positive_scores.push_back(score);
Line 321–329       if alertRaised: pem_true_positive++
                       set pem_first_alert_time, pem_mitigation_active=true
Line 332–334       else: pem_false_negative++
Line 336–347   else (normal event):
                   pem_negative_scores.push_back(score)
                   if alertRaised: pem_false_positive++
                   else: pem_true_negative++

Line 349       pem_last_mcc   = PemComputeMcc();
Line 350       pem_last_auroc = PemComputeAuroc();
Line 351   }
```

---

### Lines 353–361 — `PemGetDetectionLatencyMs` ← **NEW**

```
Line 353   static double PemGetDetectionLatencyMs() {
Line 356       if attack_injection_time < 0 OR first_alert_time < 0: return -1.0
Line 360       return 1000.0 * (pem_first_alert_time - pem_attack_injection_time);
Line 361   }
```

---

### Lines 363–375 — `PemGetPhaseLabel` ← **NEW**

```
Line 363   static std::string PemGetPhaseLabel() {
Line 366       if pem_mitigation_active: return "post_mitigation"
Line 370       if pem_attack_active:    return "under_attack"
Line 373       return "baseline"
Line 375   }
```

---

### Lines 377–407 — Forward Declarations ← **NEW**

```
Lines 377–407   Forward declarations for all PEM functions so the compiler 
                can resolve calls before definitions appear later in file.
```

---

### Lines 410–432 — `PemEventTypeToString`, `PemGetLinkKey` ← **NEW**

```
Lines 410–424   PemEventTypeToString: switch enum to "beacon"/"topology_update"/"heartbeat"
Lines 426–432   PemGetLinkKey: min(a,b)_max(a,b) canonical link key
```

---

### Lines 434–502 — Window Trimming & Path Counting ← **NEW**

```
Lines 434–442   PemTrimSlidingWindow: drops events older than PEM_HEARTBEAT_WINDOW_S
Lines 444–462   PemEstimateLambdaHat: counts unique active vehicles / (2 * comm_range)
Lines 464–502   PemCountPathsDfs: DFS up to depth 5, capped at 8 paths
Lines 504–524   PemComputePathCount: builds adjacency graph from controller table, calls DFS
```

---

### Lines 526–613 — String & CSV Output Functions ← **NEW**

```
Lines 526–554   PemTriggeredSignatureString: "TTW-S1|TTW-S2|..." or "none"
Lines 556–578   PemWriteCsvHeaderIfNeeded: writes header only if file is empty
Lines 580–613   PemWriteEventCsv: appends one full event row to pem_event_log.csv
                  Columns: sim_time, event_type, ids, timestamps, attack_label,
                           triggered_signatures, score, alert_raised, phase,
                           detection_latency_ms, positions
```

---

### Lines 615–674 — Summary CSV & Phase Metrics ← **NEW**

```
Lines 615–657   PemWriteRunSummaryCsv: appends full-run summary row to pem_run_summary.csv
                  Includes: run_id, attack_scenario, TP/TN/FP/FN, MCC, AUROC, Tdet,
                             PDR under attack, PDR post-mitigation, Te2e metrics
Lines 659–674   PemCaptureRoutingPhaseMetrics: snapshots current_pdr + current_te2e
                  into the correct phase accumulator (under_attack or post_mitigation)
```

---

### Lines 676–833 — `PemEvaluateEvent` — 9 Detection Signatures ← **NEW (core detector)**

This is the main detection function. It evaluates every incoming event against 9 binary signatures:

```
Line 679   Fill event.triggered[0..8] = false

Line 682   Signature 0 (TTW-S1): reception_timestamp - sender_timestamp
                > PEM_BEACON_INTERVAL_S + PEM_PROPAGATION_EPSILON_S
                → packet arrived later than a fresh beacon could

Line 694   Signature 1 (TTW-S2): found older event from same sender where
                reception was earlier but sender_timestamp was LATER
                → contradicts normal time ordering (replay pattern)

Line 708   Signature 2 (TTW-S3): same link reported with timestamps differing
                by more than one beacon interval from another reporter

Line 727   Signature 6 (ME-S1): number of distinct reporters for a link
                exceeds (1 + mu) * 2 * range * lambda_hat
                → too many reporters — Multipath Echo pattern

Line 736   Signature 3 (BSHH-S1): another node claimed same heartbeat ID
                in current window → identity conflict

Line 751   Signature 4 (BSHH-S2): current heartbeat's sender_timestamp < previous one
                → out-of-order timestamp → replay

Line 762   Signature 5 (BSHH-S3): no beacon from this sender seen in window
                → heartbeat without proof of physical presence

Line 783   Signature 7 (ME-S2): path count jumped by > PEM_ME_DELTA_MAX
                → sudden multipath inflation

Line 792   Signature 8 (ME-S3): reporter's position > comm_range from both link endpoints
                → physically impossible to observe the link

Line 805   score = (count of triggered) / 9.0
Line 814   event.alert_raised = (score > PEM_SCORE_THRESHOLD)   [threshold = 0.12]

Line 816   PemRecordObservation(event.attack_label, event.score, event.alert_raised)
Line 817   event.detection_latency_ms = alert ? PemGetDetectionLatencyMs() : -1.0

Lines 820–832  Push event into all relevant history structures
Line 832        PemWriteEventCsv(event)
```

---

### Lines 835–938 — PEM Event Emitters ← **NEW**

```
Lines 835–868   PemEmitEvent: builds a PemEvent struct from raw parameters,
                  then calls PemEvaluateEvent to score and log it

Lines 870–890   PemEmitHeartbeatEvent: convenience wrapper for heartbeat events
                  (sets reporter = physical sender, both endpoints = claimed sender)

Lines 892–929   PemEmitVehicleBeacon: reads vehicle positions from mobility model,
                  skips if distance > comm_range, then calls PemEmitEvent with
                  attack_label = false (beacon events are always legitimate)

Lines 931–938   PemEmitVehicleHeartbeat: thin wrapper calling PemEmitHeartbeatEvent
```

---

### Lines 941–1198 — TTW Attack Functions ← **NEW**

```
Lines 941–963   TTW_InitLog(): opens ttw_attack_scenario4.txt, writes header with timeline

Lines 965–990   TTW_SendHelloBeacon(sender, receiver):
                  - reads positions of both nodes via mobility model
                  - computes Euclidean distance
                  - checks if dist <= TTW_COMM_RANGE
                  - logs STEP ① to both NS_LOG and ttw_log

Lines 992–1048  TTW_SendTopologyUpdate(vehicle, seen_id, obs_time):
                  - creates TopologyPacket{src, seen, time, false}
                  - checks if already a newer entry in ttw_controller_table
                  - if accepted: logs STEP ② to ttw_log
                  - NEW: calls PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE, ..., attack_label=false)
                    at lines 1036–1047

Lines 1050–1070 TTW_StorePacket(src_id, dst_id, obs_time):
                  - copies packet into ttw_stored_packet
                  - sets ttw_packet_stored = true
                  - logs STEP ③ to ttw_log

Lines 1072–1146 TTW_ReplayAttack(attacker, victim, src_id, dst_id, forged_time):
                  - checks ttw_packet_stored guard
                  - reads attacker/victim positions
                  - builds forged TopologyPacket{src, dst, forged_time, true}
                  - logs STEP ④ (forging)
                  - injects into ttw_controller_table[key] = forged    (STEP ⑤)
                  - NEW line 1114: pem_attack_injection_time = now
                  - NEW line 1115: pem_attack_active = true
                  - logs STEP ⑥ (faulty routing consequence)
                  - dumps final topology table
                  - NEW line 1145: Simulator::Schedule(MilliSeconds(50), &TTW_RunReplayDetection, ...)

Lines 1148–1198 TTW_RunReplayDetection(src_id, dst_id, linkDistance):
                  - reads current positions of src and dst vehicles
                  - calls PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE,
                      src_id, src_id, src_id, src_id, dst_id,
                      ttw_stored_packet.timestamp,     ← original (old) timestamp
                      Simulator::Now().GetSeconds(),   ← reception time = now
                      positions...,
                      attack_label = true)             ← this IS an attack event
                  - if pem_last_alert == true (alert was raised):
                      ttw_controller_table.erase(key)  ← mitigate: remove ghost link
                      logs: detection score, detection latency, mitigation action
```

---

## `sdvn-temporal-attacks.cc` — Key Line Reference

| Lines | What |
|---|---|
| 1–5 | File header comment |
| 7–20 | NS-3 includes |
| 22–23 | `using namespace ns3/std` |
| 28–33 | `enum AttackType` |
| 36–57 | Global simulation parameters |
| 61–128 | `class TopologyUpdateTag` (Tag serialization) |
| 131–192 | `class HeartbeatTag` (Tag serialization) |
| 197–215 | `struct StoredPacket` (replay buffer) |
| 219–229 | Statistics counters |
| 233–259 | Helper functions: `LogEvent`, `LogTopologyUpdate`, `LogAttack`, `InRange` |
| 263–423 | `class VehicleApplication` (beacon + neighbor discovery) |
| 427–764 | `class RSUApplication` (attack logic: TTW, BSHH, ME) |
| 603–638 | `PerformTTWAttack()` — forged timestamp replay |
| 641–692 | `PerformBSHHAttack()` — old heartbeat replay |
| 694–764 | `PerformMEAttack()` — echo injection (V3/V4 falsely report V1/V2) |
| 768–1050 | `class ControllerApplication` (topology processing, inconsistency detection) |
| 1052–1234 | `main()` — node creation, WiFi setup, mobility, app installation, simulation run |

---

## Quick Reference: The Most Critical Line Changes

| Line | Change | Why |
|---|---|---|
| 139 | `uint32_t attack_scenario = 0;` | Removed duplicate → fixed Error 1 |
| 142 | `uint32_t malicious_vehicle_id = 0;` | Removed duplicate → fixed Error 2 |
| 145 | `uint32_t victim_neighbor_id = 1;` | Removed duplicate → fixed Error 3 |
| 49–50 | `using namespace std; using namespace ns3;` | Moved earlier → fixed Error 4 |
| 164–169 | `struct TopologyPacket { ... }` | Merged two structs → fixed Error 5 |
| 1036–1047 | `PemEmitEvent(PEM_EVENT_TOPOLOGY_UPDATE, ..., false)` | PEM hook for normal updates |
| 1114–1116 | `pem_attack_injection_time = now; pem_attack_active = true;` | PEM attack start marker |
| 1145 | `Simulator::Schedule(MilliSeconds(50), &TTW_RunReplayDetection, ...)` | 50ms detection delay |
| 1171–1182 | `PemEmitEvent(..., attack_label = true)` | PEM hook for attack detection |
| 1184–1196 | `if (pem_last_alert) { ttw_controller_table.erase(key); }` | Mitigation action |
