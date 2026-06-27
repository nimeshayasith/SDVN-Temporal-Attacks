# SDVN Temporal-Echo Topology Attack Detection — Full System Flow

**Project:** Temporal GNN (TGN) and Blockchain-Based Framework — Countering Temporal-Echo Topology Poisoning Attacks in SDVNs  
**Simulator:** NS-3.35 | **Blockchain:** Hyperledger Fabric | **ML:** Temporal GNN (PyTorch → C++)

---

## Full System Architecture

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                     NS-3.35 SIMULATION LAYER  (routing.cc)                         ║
║                                                                                      ║
║   ┌──────────────────┐   DSRC 802.11p (5.9 GHz, 7 channels)  ┌────────────────┐   ║
║   │  Vehicle Nodes   │ ◄──────────────────────────────────── ►│   RSU Nodes    │   ║
║   │   (200 nodes)    │   CustomDataTag1    (topology beacon)   │  (64 nodes)    │   ║
║   │                  │   CustomHeartbeatTag(liveness HB)       │                │   ║
║   │  V2V range: 300m │                                         │  CSMA Ethernet │   ║
║   └────────┬─────────┘                                         └───────┬────────┘   ║
║            │                                                            │            ║
║            │              V2V / V2R  (DSRC 802.11p)                   │            ║
║            └────────────────────────────────────────────────────────────┘            ║
║                                          │   UDP port 7777                           ║
║                                          │   SimpleUdpApplication                   ║
║                                          ▼                                           ║
║                              ┌───────────────────────┐                              ║
║                              │   Controller Nodes    │  (4 controllers)             ║
║                              │   SDN Routing Engine  │                              ║
║                              │   ttw_controller_table│                              ║
║                              │   bshh_liveness_table │                              ║
║                              └───────────────────────┘                              ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                          ATTACK INJECTION LAYER                                      ║
║                                                                                      ║
║   ┌──────────────────────────────────────────────────────────────────────────────┐  ║
║   │                        12 Attack Scenarios                                   │  ║
║   │                                                                              │  ║
║   │  TTW — Topology Time-Warp                                                    │  ║
║   │  S1 (scenario 1):  TTW_ReplayAttack()           malicious vehicle, no RSU   │  ║
║   │  S2 (scenario 2):  TTWS2_ReplayAttack()         malicious RSU               │  ║
║   │  S3 (scenario 3):  TTWS3_InternalReplay()       malicious controller, no RSU│  ║
║   │  S4 (scenario 4):  TTWS4_InternalReplay()       malicious controller + RSU  │  ║
║   │                                                                              │  ║
║   │  BSHH — Beacon State Heartbeat Hijack                                        │  ║
║   │  S5 (scenario 5):  BSHH_S1_ReplayOldHeartbeatToVictim()    mal. vehicle     │  ║
║   │                    BSHH_S1_AttackerHijacksOldHeartbeatToController()         │  ║
║   │  S6 (scenario 6):  BSHH_S2_ReplayAttack()       malicious RSU               │  ║
║   │  S7 (scenario 7):  BSHH_S3_InternalReplay()     malicious controller, no RSU│  ║
║   │  S8 (scenario 8):  BSHH_S4_InternalReplay()     malicious controller + RSU  │  ║
║   │                                                                              │  ║
║   │  ME — Multipath Echo                                                         │  ║
║   │  S9  (scenario 9):  ME_S1_EchoAttack()          malicious vehicles, no RSU  │  ║
║   │  S10 (scenario 10): ME_S2_InjectEchoReports()   malicious RSU               │  ║
║   │  S11 (scenario 11): ME_S3_InjectPhantomPaths()  malicious controller, no RSU│  ║
║   │  S12 (scenario 12): ME_S4_InjectPhantomPaths()  malicious controller + RSU  │  ║
║   └──────────────────────────────────┬───────────────────────────────────────────┘  ║
║                                      │  PemEmitEvent() / PemEmitHeartbeatEvent()    ║
╠══════════════════════════════════════╪══════════════════════════════════════════════╣
║                    LAYER 1 — CRYPTO PRE-FILTER  (separate from the LW detector)      ║
║                    (#included in routing.cc from .crypto_src/ — compiled in)         ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │                      PemCryptoPreFilter()   ← crypto auth gate               │   ║
║   │                   Algorithm 3 — LW-MITIGATE  (Eqs 3.15–3.17, 3.26–3.30)   │   ║
║   │              Drops forged/replayed packets BEFORE they reach the LW detector│   ║
║   │                                                                             │   ║
║   │  Step 1 — Integrity / identity check                                        │   ║
║   │  ┌─────────────────────┐   ┌─────────────────────┐                         │   ║
║   │  │   hmac_filter.cc    │   │    dilithium.cc      │                         │   ║
║   │  │   HMAC-SHA256       │   │    ML-DSA-87         │                         │   ║
║   │  │   integrity (3.15)  │   │    Post-Quantum Sig  │  Eq 3.26: threshold     │   ║
║   │  └─────────────────────┘   └─────────────────────┘  aggregate sig check    │   ║
║   │                                                                             │   ║
║   │  ┌──────────────────────────────┐  ┌─────────────────────┐                  │   ║
║   │  │          kem.cc              │  │  location_binding.cc │                  │   ║
║   │  │  Kyber-1024 + FireSaber      │  │  Haversine distance  │  Eq 3.27–3.29:  │   ║
║   │  │  Hybrid-KEM session key      │  │  location verify     │  range check    │   ║
║   │  │  K=KDF(ss_kyber ⊕ ss_saber) │  └─────────────────────┘                  │   ║
║   │  │  (liboqs≥0.10: FireSaber     │                                           │   ║
║   │  │   maps to ML-KEM-1024)       │                                           │   ║
║   │  └──────────────────────────────┘                                           │   ║
║   │                                                                             │   ║
║   │  ┌─────────────────────┐                                                   │   ║
║   │  │    lkh_mgmt.cc      │                                                   │   ║
║   │  │  LKH Group Key Mgmt │  Eq 3.30: quorum / witness check                 │   ║
║   │  └─────────────────────┘                                                   │   ║
║   │                                                                             │   ║
║   │  Step 2 — Freshness check     (Eq 3.16)  age > T_b + ε → DROP             │   ║
║   │  Step 3 — Nonce novelty check (Eq 3.17)  replayed nonce → DROP             │   ║
║   │                                                                             │   ║
║   │  Packets failing any check → silently dropped (pem_crypto_drop_* counters) │   ║
║   │  Controller-origin attacks (S3/S4/S7/S8/S11/S12) bypass crypto filter      │   ║
║   │  (is_malicious_controller = true → filter returns true immediately)         │   ║
║   └──────────────────────────────────┬──────────────────────────────────────────┘   ║
║                                      │  surviving events → pem_all_events[]         ║
╠══════════════════════════════════════╪══════════════════════════════════════════════╣
║                    LAYER 2 — LW DETECTOR  (9-Signature Weighted PEM Scoring)         ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │                         pem_all_events[]   (line 1378, routing.cc)          │   ║
║   │                                                                             │   ║
║   │  9 Weighted Signatures:                                                     │   ║
║   │  ┌──────────────────────────────────────────────────────────────────────┐  │   ║
║   │  │  TTW-S1  (w=1/9)  timestamp gap > beacon interval + ε                 │  │   ║
║   │  │  TTW-S2  (w=1/9)  newer reception but older sender timestamp           │  │   ║
║   │  │  TTW-S3  (w=1/9)  same link, different reporters, timestamp gap        │  │   ║
║   │  │  BSHH-S1 (w=1/9)  two heartbeats claim same identity, diff sender      │  │   ║
║   │  │  BSHH-S2 (w=1/9)  heartbeat timestamp < previous (out-of-order)        │  │   ║
║   │  │  BSHH-S3 (w=1/9)  heartbeat with no matching beacon in window          │  │   ║
║   │  │  ME-S1   (w=1/9)  reporter count > expected density bound              │  │   ║
║   │  │  ME-S2   (w=1/9)  path count increases by > Δmax in one update         │  │   ║
║   │  │  ME-S3   (w=1/9)  reporter outside comm range of reported link          │  │   ║
║   │  └──────────────────────────────────────────────────────────────────────┘  │   ║
║   │                                                                             │   ║
║   │  Score = Σ (1/9) × signature[i]         Alert if Score > 0.075            │   ║
║   │                                                                             │   ║
║   │  Parallel detector: topology_divergence_delta (Eq 3.1, line 1022)         │   ║
║   │  → catches controller-origin attacks (S3/S4/S7/S8/S11/S12)               │   ║
║   │                                                                             │   ║
║   │  Output files:                                                              │   ║
║   │    pem_event_log.csv      — per-event scores and alert flags               │   ║
║   │    pem_run_summary.csv    — MCC, AUROC, Tdet, PDR, Te2e per run           │   ║
║   └──────────────────────────────────┬──────────────────────────────────────────┘   ║
║                                      │                                               ║
╠══════════════════════════════════════╪══════════════════════════════════════════════╣
║           LAYER 3 — SECONDARY CRYPTO GATE  (.tgn_src/tgn_core.cc § 3.4.2)           ║
║           TGN_ApplyCryptoFilter(pem_all_events) → filtered[]                         ║
║           (separate from PemCryptoPreFilter — this re-checks AFTER simulation ends)  ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │              TGN_ApplyCryptoFilter()  — Algorithm 3, §3.4.2                 │   ║
║   │                                                                             │   ║
║   │  Passes beacons through without checking (type == PEM_EVENT_BEACON)        │   ║
║   │  Controller bypass: physical_sender_id == 9999 → skips all 3 checks        │   ║
║   │  (controllers hold all keys and generate valid MACs and fresh nonces)       │   ║
║   │                                                                             │   ║
║   │  RSU range guard: physical_is_rsu = (physical_sender_id >= N_Vehicles)     │   ║
║   │    AND (physical_sender_id < N_Vehicles+N_RSUs)                            │   ║
║   │    Upper bound required: without it, sentinel 9999 satisfies               │   ║
║   │    (9999 >= N_Vehicles) and wrongly bypasses MAC check in With-RSU         │   ║
║   │    controller variants (TTW/BSHH/ME -ctrl-RSU)                             │   ║
║   │                                                                             │   ║
║   │  Step 1 — HMAC/MAC integrity (Eq 3.15)                                     │   ║
║   │    mac_valid = physical_is_rsu OR (physical_sender == claimed_sender)       │   ║
║   │    DROP-MAC: identity mismatch → BSHH replay caught here                   │   ║
║   │                                                                             │   ║
║   │  Step 2 — Timestamp freshness (Eq 3.16)                                    │   ║
║   │    |τ_r − τ_s| ≤ T_b + ε = 110 ms                                         │   ║
║   │    DROP-STALE: old BSHH replays (τ_s = t=0 heartbeat) caught here          │   ║
║   │                                                                             │   ║
║   │  Step 3 — Nonce novelty (Eq 3.17)                                          │   ║
║   │    nonce = (reporter_id, claimed_sender_id, sender_timestamp) — must unique │   ║
║   │    DROP-NONCE: duplicate nonce = replay attack caught here                  │   ║
║   │                                                                             │   ║
║   │  Output file:                                                               │   ║
║   │    crypto_filter_log.txt  — per-drop reason (MAC/STALE/NONCE) + summary    │   ║
║   └──────────────────────────────────┬──────────────────────────────────────────┘   ║
║                                      │  filtered[]                                   ║
╠══════════════════════════════════════╪══════════════════════════════════════════════╣
║                    LAYER 4 — TGN DETECTION  (.tgn_src/tgn_core.cc)                  ║
║                    (included in routing.cc at line 1389)                             ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │          TGN_ProcessAllEvents()  — Algorithm 2 (FS-DETECT)                  │   ║
║   │                                                                             │   ║
║   │  Global state maps (populated per-event before scoring):                   │   ║
║   │    g_tgn_last_sender_ts[node]       → seq_gap (timestamp regression)       │   ║
║   │    g_tgn_link_reporters[link_key]   → reporter count set (ME signal)        │   ║
║   │    g_tgn_beacon_windows[node]       → beacon_count sliding window           │   ║
║   │    link_key is DIRECTED: "link_src_link_dst"                                │   ║
║   │                                                                             │   ║
║   │  Feature vector x_v (Eq 3.20) — 7 features per event:                     │   ║
║   │  [id_v | tau_s | beacon_count | seq_gap | reporter_count |                 │   ║
║   │   identity_mismatch | phi=log(1+Δt/T_b)]                                   │   ║
║   │                                                                             │   ║
║   │  reporter_count / identity_mismatch RSU/no-RSU split:                      │   ║
║   │    physical_is_rsu = (physical_sender_id >= N_Vehicles)                    │   ║
║   │                    AND (physical_sender_id < N_Vehicles+N_RSUs)            │   ║
║   │    No-RSU: reporter_count tracks reporter_id (vehicle reporters for link)  │   ║
║   │            identity_mismatch = 1.0 if physical ≠ claimed AND               │   ║
║   │                                physical_sender ≠ 9999 (sentinel guard)     │   ║
║   │    RSU path: reporter_count tracks claimed_sender_id (ME-S2 RSU injection) │   ║
║   │             identity_mismatch = 0.0 (RSU forwarding is trusted)            │   ║
║   │                                                                             │   ║
║   │  Step 1 — GRU memory update (Eq 3.22)                                      │   ║
║   │           UpdateNodeMemory():  h_new = GRU(h_prev, [h_prev ‖ x_v])        │   ║
║   │           dim=32, input_size=39 (32 hidden + 7 features)                   │   ║
║   │                                                                             │   ║
║   │  Step 2 — Edge freshness A_uv (Eq 3.21)                                    │   ║
║   │           A_uv = exp(-stale_excess / (γ · T_b))   γ=310 (urban)           │   ║
║   │                                                                             │   ║
║   │  Step 3 — Neighborhood aggregation L=2 rounds (Eq 3.23)                    │   ║
║   │           Per-event 3-node induced subgraph: active = {reporting_node,      │   ║
║   │           link_src, link_dst}                                               │   ║
║   │           For each round l ∈ {0,1}:                                        │   ║
║   │             For each node v ∈ active:                                       │   ║
║   │               if N(v) empty: H^(l+1)[v] = H^(l)[v]  (passthrough)         │   ║
║   │               else: agg = mean{ A_uv × H^(l)[u] : u ∈ N(v) ∩ active }    │   ║
║   │                     H^(l+1)[v] = ReLU(W_l · agg + b_l)                    │   ║
║   │           → 2 rounds × 3 nodes = 6 independent per-node updates            │   ║
║   │                                                                             │   ║
║   │  Step 4 — Anomaly score (Eq 3.24)  [trained mode]                          │   ║
║   │           ŷ_v = σ(w_score · h_v^(L))    Alert if ŷ_v > θ_FS              │   ║
║   │                                                                             │   ║
║   │           [heuristic mode — current operating mode, no weights loaded]     │   ║
║   │           HeuristicScore(feat, edge_freshness):                            │   ║
║   │             s += clamp(staleness − T_b, 0, 2T_b) / T_b   (TTW staleness) │   ║
║   │             s += min(1, seq_gap / 5)                       (TTW regression)│   ║
║   │             s += identity_mismatch × 1.5                   (BSHH signal)  │   ║
║   │             s += min(2, (reporter_count−1) × 0.8)  if count > 1.5         │   ║
║   │                                                            (ME density)    │   ║
║   │             s += edge_freshness heuristic component        (stale edge)    │   ║
║   │                                                                             │   ║
║   │  Step 5 — Variant classification (Eq 3.25) [only when alert fires         │   ║
║   │           AND weights loaded — skipped in heuristic mode]                  │   ║
║   │           α̂_v = softmax(W_cls · h_v^(L) + b_cls)                          │   ║
║   │           → TTW=0 / BSHH=1 / ME=2                                         │   ║
║   │           In heuristic mode: alpha_source = scenario_id_fallback           │   ║
║   │           (NOT a classifier prediction — derived from attack_scenario)     │   ║
║   │                                                                             │   ║
║   │  TGN_RunPipeline() sequence (line 148799, after Simulator::Destroy()):     │   ║
║   │    ① γ/W_max calibration from --tgn_l_link                                 │   ║
║   │    ② Load tgn_weights.bin or init Xavier (heuristic fallback)              │   ║
║   │    ③ TGN_InitOutputFiles()                                                 │   ║
║   │    ④ TGN_ApplyCryptoFilter(pem_all_events) → filtered[]   (Layer 3)       │   ║
║   │    ⑤ TGN_ProcessAllEvents() on filtered[]                (this layer)     │   ║
║   │    ⑥ TGN_WriteAlertsJson() + TGN_WriteSummary()                           │   ║
║   │    ⑦ cleanup: close files, delete g_tgn, clear global state maps           │   ║
║   │                                                                             │   ║
║   │  Output files:                                                              │   ║
║   │    tgn_events.csv              — per-event TGN scores, alerts, is_attack   │   ║
║   │    tgn_alerts.json             — confirmed alerts → blockchain              │   ║
║   │    tgn_detection_log_s{N}.txt  — human-readable detection log per scenario │   ║
║   │    tgn_attack{N}.txt           — per-scenario attack+detection summary      │   ║
║   │    tgn_summary.csv             — MCC, AUROC, tdet_ms, dim, layers per run  │   ║
║   └──────────────────────────────────┬──────────────────────────────────────────┘   ║
║                                      │  tgn_alerts.json                             ║
╠══════════════════════════════════════╪══════════════════════════════════════════════╣
║                    LAYER 5 — BLOCKCHAIN  (Hyperledger Fabric)                        ║
║                    NOTE: runs SEPARATELY from routing.cc — not compiled in           ║
║                    Reads tgn_alerts.json + beacon_evidence.csv written to disk       ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │                      submitToFabric.js  (Node.js, separate process)         │   ║
║   │                                                                             │   ║
║   │  Reads tgn_alerts.json + beacon_evidence.csv                               │   ║
║   │  Signs with Dilithium2 (post-quantum signature)                            │   ║
║   │  Submits transactions to Hyperledger Fabric peer                           │   ║
║   └──────────────────────────────────┬──────────────────────────────────────────┘   ║
║                                      │                                               ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │           Smart Contract — temporalecho.go  (Chaincode main entry)          │   ║
║   │                                                                             │   ║
║   │  Submission functions:                                                      │   ║
║   │    SubmitBeaconEvidence()        — RSU beacon observation records           │   ║
║   │    SubmitDetectionEvent()        — PEM/TGN alert submission                 │   ║
║   │    SubmitControllerTopology()    — controller topology snapshot             │   ║
║   │    SubmitAlert()                 — consolidated attack alert                │   ║
║   │    SubmitLWDetectionResult()     — lightweight detection result             │   ║
║   │    SubmitIndividualSigEvidence() — per-node threshold sig evidence          │   ║
║   │    SubmitWitnessRecord()         — witness observation record               │   ║
║   │    SubmitVehicleMAC()            — vehicle MAC address registration         │   ║
║   │                                                                             │   ║
║   │  Mitigation functions:                                                      │   ║
║   │    Mitigate()                    — trigger mitigation action                │   ║
║   │    runMitigation()               — internal mitigation execution            │   ║
║   │    ClearReauth()                 — clear re-authentication flag             │   ║
║   │                                                                             │   ║
║   │  Query functions:                                                           │   ║
║   │    QueryMitigationHistory()      — retrieve mitigation log                 │   ║
║   │    QueryDetectionEventsByVehicle()— query per-vehicle events               │   ║
║   │    QueryBeaconEvidenceByInterval()— query beacon evidence                  │   ║
║   │    GetPendingFlowMod()           — get pending flow rule                   │   ║
║   │    GetAllPendingFlowMods()       — get all pending flow rules               │   ║
║   │    GetDivergenceDelta()          — get controller divergence value          │   ║
║   │    GetLatestControllerReassignment() — get last controller swap            │   ║
║   │    AcknowledgeFlowMod()          — confirm flow rule installed              │   ║
║   └──────────────┬───────────────────┬───────────────────┬──────────────────────┘  ║
║                  │                   │                   │                          ║
║        ┌─────────▼──────┐  ┌─────────▼──────┐  ┌────────▼───────────────────────┐ ║
║        │   trust.go     │  │  flowmod.go    │  │  anchor.go                     │ ║
║        │                │  │                │  │                                │ ║
║        │ updateTrust()  │  │ pushFlowMod    │  │ CreateAnchorCheckpoint()       │ ║
║        │ updateCtrlTrust│  │   Drop()       │  │ GetLatestAnchorCheckpoint()    │ ║
║        │ RegisterRSUPeer│  │ pushReroute    │  │ SyncFromAnchorCheckpoint()     │ ║
║        │ RegisterOBUPeer│  │   FlowMod()    │  │                                │ ║
║        │ SetRSUZone()   │  │ pushFlowMod    │  │ Immutable ledger checkpoints   │ ║
║        │ UpdateTrustRoun│  │   Override()   │  │ for peer re-synchronisation    │ ║
║        │ ZeroTrust()    │  │ writePending   │  └────────────────────────────────┘ ║
║        │ DemotePeerTo   │  │   FlowMod()    │                                     ║
║        │   Client()     │  │ Acknowledge    │  ┌─────────────────────────────────┐ ║
║        │ SelectPeers()  │  │   FlowMod()    │  │  divergence.go                  │ ║
║        │ CheckPBFT      │  │ lookupVehicle  │  │                                 │ ║
║        │   Consensus()  │  │   MAC()        │  │ checkControllerDivergence()     │ ║
║        │ CheckController│  └────────────────┘  │ computeDivergence()             │ ║
║        │   TrustAndRe   │                      │ buildLinkSet()                  │ ║
║        │   assign()     │                      │ aggregateEvidenceLinkSet()      │ ║
║        │ GetTrustScore()│                      │ symmetricDifference()           │ ║
║        └────────────────┘                      │ On-chain Eq 3.1 verification    │ ║
║                                                └─────────────────────────────────┘ ║
║        ┌─────────────────────────────────────────────────────────────────────────┐ ║
║        │  verification.go                                                        │ ║
║        │                                                                         │ ║
║        │  verifyThresholdSig()   — threshold aggregate signature check          │ ║
║        │  verifyQuorum()         — PBFT quorum weight verification              │ ║
║        │  haversineDistanceM()   — location distance verification               │ ║
║        │  resolveDualPath()      — conflict resolution between alert paths      │ ║
║        │  loadSimParams()        — load simulation parameters from ledger       │ ║
║        └─────────────────────────────────────────────────────────────────────────┘ ║
║        ┌─────────────────────────────────────────────────────────────────────────┐ ║
║        │  structs.go  — all shared data structures                              │ ║
║        │                                                                         │ ║
║        │  VehicleObservation     BeaconEvidenceRecord   DetectionEvent          │ ║
║        │  TopologyLink           ControllerTopologyClaim MitigationLogEntry     │ ║
║        │  TrustRecord            ControllerTrustRecord   AlertObject            │ ║
║        │  IndividualSigEvidence  WitnessRecord           AnchorCheckpoint       │ ║
║        │  BlacklistBeacon        ControllerRevokedBeacon RSUZoneReassignment    │ ║
║        └─────────────────────────────────────────────────────────────────────────┘ ║
║                                      │  on-chain events emitted                     ║
║   ┌──────────────────────────────────▼──────────────────────────────────────────┐   ║
║   │                       eventListener.js                                      │   ║
║   │                                                                             │   ║
║   │  startEventListener()            — polls Fabric for on-chain events         │   ║
║   │  handleAttackDetected()          — triggers flow modification               │   ║
║   │  handleKeyRevocation()           — revokes compromised node keys            │   ║
║   │  handleControllerOriginAttack()  — removes malicious controller             │   ║
║   │  handleControllerRemoved()       — reassigns controller role                │   ║
║   │  handleAnchorCheckpoint()        — syncs anchor state                       │   ║
║   │  replayPendingFlowMods()         — re-applies unacknowledged flow rules     │   ║
║   │  executeFlowMod()                — installs OpenFlow drop/reroute rule      │   ║
║   │                                    via Ryu REST API (100ms latency budget)  │   ║
║   └─────────────────────────────────────────────────────────────────────────────┘   ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                    OFFLINE TRAINING PIPELINE                                         ║
║                                                                                      ║
║   NS-3 simulation runs (all 12 scenarios × N seeds)                                 ║
║         │  tgn_events.csv written per run by TGN_WriteEventRow()                   ║
║         ▼                                                                            ║
║   generate_training_data_tmux.sh                                                     ║
║         │  concatenates all scenario files → training_data/all_events.csv           ║
║         │  saves per-scenario copies: scenario{N}_seed{S}_events.csv               ║
║         ▼                                                                            ║
║   tgn/tgn_train.py                                                                   ║
║         │                                                                            ║
║         │  1. Load all_events.csv                                                   ║
║         │  2. Drop BEACON rows — keep TOPO_UPDATE + HEARTBEAT only                 ║
║         │  3. Sort strictly by recv_time_s (no shuffling)                           ║
║         │  4. Split 70% train / 15% val / 15% test  (temporal order)               ║
║         │  5. Train TGNModel (PyTorch):                                             ║
║         │       Loss = BCEWithLogitsLoss + 0.3 × CrossEntropyLoss                  ║
║         │       pos_weight = n_neg/n_pos  (class imbalance handling)               ║
║         │       Optimizer: Adam  lr=0.001  weight_decay=1e-4                       ║
║         │       Scheduler: CosineAnnealingLR over 50 epochs                        ║
║         │       Gradient clipping: max norm 1.0                                     ║
║         │       1-step truncated BPTT (detach between events)                      ║
║         │       Best checkpoint saved by validation MCC                             ║
║         │  6. Auto-select theta_FS: sweep 0.05–0.95, maximise MCC on val set      ║
║         │  7. export_weights() → float64, row-major binary                         ║
║         ▼                                                                            ║
║   tgn/tgn_weights.bin  (72K)                                                        ║
║         │                                                                            ║
║         └──────────────────────────────────────────────────────────────────────►   ║
║                                              loaded into routing.cc via              ║
║                                              --tgn_weights flag                      ║
║                                              TGN_RunPipeline() at line 148799       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## Data Flow Summary

```
Vehicle/RSU DSRC packets
        │
        ▼
routing.cc receives events
        │
        ├── Attack functions inject → PemEmitEvent() → pem_all_events[]
        │
        ▼
LAYER 1: PemCryptoPreFilter()  ← crypto auth gate (NOT the LW detector)
  hmac_filter.cc      — HMAC-SHA256 integrity                (Eq 3.15)
  dilithium.cc        — ML-DSA-87 threshold sig check        (Eq 3.26)
  location_binding.cc — Haversine range check                (Eq 3.27–3.29)
  lkh_mgmt.cc        — quorum/witness check                  (Eq 3.30)
  kem.cc             — Kyber-1024 + FireSaber Hybrid-KEM
                        K = KDF(ss_kyber ⊕ ss_saber)
                        (liboqs ≥ 0.10: FireSaber → ML-KEM-1024)
  Failures → silent DROP
        │
        ▼
LAYER 2: LW detector — 9-signature PEM scorer (separate from Layer 1 crypto gate)
  Score = Σ weight[i] × signature[i]   threshold 0.12
  topology_divergence_delta (Eq 3.1)   parallel controller-origin detector
  → pem_event_log.csv
  → pem_run_summary.csv
        │
        ▼
LAYER 3: Secondary crypto gate (TGN_ApplyCryptoFilter, tgn_core.cc §3.4.2)
  MAC check (Eq 3.15) → freshness check (Eq 3.16) → nonce check (Eq 3.17)
  controller sentinel bypass (physical_sender==9999), RSU range guard
  → crypto_filter_log.txt
        │
        ▼
LAYER 4: TGN inference (tgn_core.cc, included in routing.cc line 1389)
  Global state: g_tgn_last_sender_ts / g_tgn_link_reporters / g_tgn_beacon_windows
  GRU update → edge freshness → neighborhood aggregation (mean, L=2 rounds, 3 nodes)
  → anomaly score (heuristic or σ(w·h)) → variant label (softmax or scenario fallback)
  → tgn_events.csv, tgn_alerts.json, tgn_detection_log_s{N}.txt,
    tgn_attack{N}.txt, tgn_summary.csv
        │
        ▼
LAYER 5: Blockchain (Hyperledger Fabric) — SEPARATE process, not in routing.cc
  Reads output files: tgn_alerts.json + beacon_evidence.csv
  submitToFabric.js → temporalecho.go smart contract
        │
        ├── trust.go        → trust score updated on ledger (PBFT consensus)
        ├── flowmod.go      → pending flow rule written to ledger
        ├── anchor.go       → checkpoint saved to ledger
        ├── divergence.go   → controller divergence verified on-chain (Eq 3.1)
        ├── verification.go → threshold sig + quorum + location verified
        └── structs.go      → shared data structures
        │
        ▼
  eventListener.js → executeFlowMod() → Ryu OpenFlow REST API
        │
        ▼
  DROP / REROUTE rule installed at SDN controller (100ms latency budget)
```

---

## File-to-Layer Mapping

| File | Layer | Role |
|------|-------|------|
| `routing.cc` | Layers 1–4 | Main simulation — crypto, LW detector, secondary crypto gate, and TGN compile inside this file (blockchain Layer 5 is a separate process) |
| `.tgn_src/tgn_core.cc` | Layers 3–4 | Secondary crypto gate (TGN_ApplyCryptoFilter) + TGN inference engine (included at line 1389) |
| `.crypto_src/hmac_filter.cc` | Layer 1 | HMAC-SHA256 integrity check (Eq 3.15) |
| `.crypto_src/dilithium.cc` | Layer 1 | ML-DSA-87 post-quantum digital signatures |
| `.crypto_src/kem.cc` | Layer 1 | Kyber-1024 + FireSaber Hybrid-KEM (K = KDF(ss_kyber ⊕ ss_saber)) |
| `.crypto_src/lkh_mgmt.cc` | Layer 1 | LKH group key management + quorum check |
| `.crypto_src/location_binding.cc` | Layer 1 | Location-based range binding (Eq 3.27–3.29) |
| `.crypto_src/teta_guard_types.h` | Layer 1 | Shared type definitions for crypto layer |
| `tgn/tgn_train.py` | Training | Python training + weight export (PyTorch) |
| `tgn/tgn_weights.bin` | Layer 4 | Trained weights loaded at runtime (72K, float64) |
| `blockchain/chaincode/temporalecho/temporalecho.go` | Layer 5 | Smart contract main entry point (**separate process — not in routing.cc**) |
| `blockchain/chaincode/temporalecho/trust.go` | Layer 5 | Trust scoring and peer management on ledger |
| `blockchain/chaincode/temporalecho/flowmod.go` | Layer 5 | SDN flow rule management on ledger |
| `blockchain/chaincode/temporalecho/anchor.go` | Layer 5 | Anchor peer management + checkpoints |
| `blockchain/chaincode/temporalecho/divergence.go` | Layer 5 | On-chain controller divergence verification |
| `blockchain/chaincode/temporalecho/verification.go` | Layer 5 | Threshold sig + quorum + location verification |
| `blockchain/chaincode/temporalecho/verification_liboqs.go` | Layer 5 | liboqs-backed PQ signature verification (build tag: liboqs) |
| `blockchain/chaincode/temporalecho/verification_stub.go` | Layer 5 | Stub implementation when liboqs is not available |
| `blockchain/chaincode/temporalecho/structs.go` | Layer 5 | All shared chaincode data structures |
| `blockchain/client/submitToFabric.js` | Layer 5 | Alert submission to Hyperledger Fabric |
| `blockchain/client/eventListener.js` | Layer 5 | On-chain event handler + OpenFlow rule installer |

---

## Key Integration Points in routing.cc

| Line | What happens |
|------|-------------|
| 88–93 | `.crypto_src/` files included (hmac, dilithium, kem, lkh, location_binding) |
| 1022 | `topology_divergence_delta` declared (Eq 3.1 parallel detector) |
| 1378 | `pem_all_events[]` vector declared |
| 1389 | `.tgn_src/tgn_core.cc` included |
| 1596 | `PemEmitEvent()` forward declared |
| 2550 | `PemCryptoPreFilter()` defined |
| 2673 | `PemEmitEvent()` defined (full implementation) |
| 2709 | `PemCryptoPreFilter()` called inside `PemEmitEvent()` |
| 144694–144710 | `--tgn_weights`, `--tgn_theta`, `--tgn_l_link`, `--tgn_dim`, `--tgn_layers` registered |
| 148799 | `TGN_RunPipeline()` called after `Simulator::Destroy()` |

---

*All five layers and the training pipeline connect through `routing.cc`. The simulation generates labelled events (Layer 1 crypto pre-filter), PEM scores them with 9 signatures (Layer 2 LW detector), TGN_ApplyCryptoFilter re-checks MAC/freshness/nonce post-simulation (Layer 3 secondary crypto gate), TGN classifies them with GRU + neighborhood aggregation (Layer 4), and the blockchain enforces mitigation (Layer 5 — separate process) — one closed end-to-end loop.*
