# SDVN Temporal-Echo Detection Framework — Complete System Flow
**Project:** A Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection in SDVNs
**University of Ruhuna — Department of EIE — Final Year Project**

---

## HOW TO READ THIS DIAGRAM

```
Everything inside the routing.cc binary box runs in ONE process with ONE command:
  ./waf --run "scratch/routing --attack_scenario=1 --tgn_weights=tgn/tgn_weights.bin"

The Blockchain layer runs in a SEPARATE process after routing.cc finishes.
The Training Pipeline runs OFFLINE before deployment.
```

---

```
╔══════════════════════════════════════════════════════════════════════════════════════════════╗
║          OFFLINE TRAINING PIPELINE  (run once before deployment)                            ║
║                                                                                              ║
║  Step 1 — Generate labelled events from all 13 scenarios (0=baseline, 1-12=attacks)         ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  generate_training_data.sh                                                          │    ║
║  │    Runs ./waf --run scratch/routing for each scenario × seed combination            │    ║
║  │    Collects tgn_events.csv from each run                                            │    ║
║  │    Concatenates → training_data/all_events.csv                                      │    ║
║  └───────────────────────────────────┬─────────────────────────────────────────────────┘    ║
║                                      │ all_events.csv                                        ║
║  Step 2 — Train TGN model            │                                                       ║
║  ┌───────────────────────────────────▼─────────────────────────────────────────────────┐    ║
║  │  tgn/tgn_train.py   (PyTorch)                                                       │    ║
║  │                                                                                     │    ║
║  │  Data split: Stratified temporal 70/15/15 per scenario per class                    │    ║
║  │    → Attack + benign events within each scenario split independently                │    ║
║  │    → Sorted by recv_time_s (temporal order preserved — no shuffling)                │    ║
║  │    → Prevents all attack events ending up in test only                              │    ║
║  │                                                                                     │    ║
║  │  Model architecture: TGNModel (PyTorch)                                             │    ║
║  │    GRU:  dim=32, input_size=38 (32 hidden + 6 features)                            │    ║
║  │    MP:   2 rounds × 3-node subgraph                                                 │    ║
║  │    Heads: w_score(32), b_score(scalar=-0.85), Wcls(3×32), b_cls(3)                 │    ║
║  │                                                                                     │    ║
║  │  Loss:   total = BCE + 0.3×CE + 0.5×margin                                         │    ║
║  │    BCE_loss    = BCEWithLogitsLoss(pos_weight = n_benign/n_attack)                  │    ║
║  │    CE_loss     = CrossEntropyLoss on attack events (variant head: TTW/BSHH/ME)      │    ║
║  │    margin_loss = max(0, 0.35 − (mean_attack_score − mean_benign_score))             │    ║
║  │                  forces class score distributions apart                              │    ║
║  │                                                                                     │    ║
║  │  Training loop:                                                                     │    ║
║  │    MAX_RESTARTS = 5   (restart with fresh random weights if MCC not good enough)    │    ║
║  │    TARGET_VAL_MCC = 0.975  (stop early if reached)                                 │    ║
║  │    Optimizer: Adam  lr=0.001  weight_decay=1e-4                                    │    ║
║  │    Scheduler: CosineAnnealingLR  50 epochs                                         │    ║
║  │    Gradient clipping: max norm 1.0                                                  │    ║
║  │    1-step TBPTT: detach hidden state between events                                 │    ║
║  │    Xavier initialisation for all weight matrices                                    │    ║
║  │    Global best state tracked across ALL restarts                                    │    ║
║  │                                                                                     │    ║
║  │  Threshold selection (θ_FS):                                                        │    ║
║  │    Sweep θ in [0.001, 0.999] on validation set                                     │    ║
║  │    Choose θ that maximises MCC                                                      │    ║
║  │    Cross-check: gap midpoint between min(attack_scores) and max(benign_scores)      │    ║
║  │    Both methods must agree within TOLERANCE = 0.15                                  │    ║
║  │    Default θ_FS = 0.40                                                              │    ║
║  │                                                                                     │    ║
║  │  Weight export → tgn/tgn_weights.bin  (float64, row-major, 276 KB)                 │    ║
║  │    Layout: [dim,layers int32] Wz Uz bz Wr Ur br Wn Un bn                           │    ║
║  │            W_layer[0] b_layer[0] W_layer[1] b_layer[1]                             │    ║
║  │            w_score(32) b_score(1) Wcls(3×32) b_cls(3)                              │    ║
║  └───────────────────────────────────┬─────────────────────────────────────────────────┘    ║
║                                      │ tgn/tgn_weights.bin                                   ║
║                                      │ loaded at runtime via --tgn_weights flag              ║
╚══════════════════════════════════════╪═══════════════════════════════════════════════════════╝
                                       │
╔══════════════════════════════════════╪═══════════════════════════════════════════════════════╗
║  routing.cc BINARY  (single process) │                                                       ║
║  ./waf --run "scratch/routing        │                                                       ║
║    --simTime=60 --N_Vehicles=4       │                                                       ║
║    --N_RSUs=1 --attack_scenario=1    │  ◄─── tgn_weights.bin loaded here                    ║
║    --tgn_weights=tgn/tgn_weights.bin"│                                                       ║
║    --tgn_theta=0.40                  │                                                       ║
║    --tgn_l_link=43                   │                                                       ║
║    --tgn_dim=32 --tgn_layers=2"      │                                                       ║
║                                      │                                                       ║
╠══════════════════════════════════════╪═══════════════════════════════════════════════════════╣
║  LAYER 0 — NS-3 SIMULATION  (routing.cc)                                                     ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  NETWORK NODES                                                                      │    ║
║  │                                                                                     │    ║
║  │  Vehicle_Nodes   (0–200 nodes)          RSU_Nodes  (0–2 nodes)                     │    ║
║  │  ┌────────────┐                         ┌──────────────────┐                       │    ║
║  │  │  V0  V1    │  DSRC 802.11p (5.9GHz)  │     RSU_0        │                       │    ║
║  │  │  V2  V3    │ ◄──────────────────────►│  DSRC + CSMA     │                       │    ║
║  │  │  V4  ...   │  Ch178 CCH (CCH=safety) │  Ethernet        │                       │    ║
║  │  │            │  Ch172–184 SCH (service) │                  │                       │    ║
║  │  │  V2V range │  T_b = 100ms per beacon │                  │                       │    ║
║  │  │  300m DSRC │  Broadcast 802.11p      │                  │                       │    ║
║  │  │  mobility  │  ethertype 0x88dc       │                  │                       │    ║
║  │  │  via SUMO  │                         └────────┬─────────┘                       │    ║
║  │  │  traces    │                                  │ CSMA Ethernet                   │    ║
║  │  └────────────┘                                  │ 10.1.1.0/24                     │    ║
║  │                                                  │ UDP port 7777                   │    ║
║  │                                                  │ SimpleUdpApplication            │    ║
║  │  controller_Node (1 node)   ◄───────────────────┘ HandleReadOne()                  │    ║
║  │  ┌─────────────────────────────────────────────────────────────────────────────┐   │    ║
║  │  │  SDN Controller — PRIMARY ATTACK TARGET                                     │   │    ║
║  │  │  ttw_controller_table      std::map<string, TopologyPacket>                 │   │    ║
║  │  │    key="srcId_seenId"      TopologyPacket{src_id, seen_id, ts, is_forged}  │   │    ║
║  │  │  bshh_controller_liveness  std::map<uint32_t, HeartbeatPacket>             │   │    ║
║  │  │    key=vehicle_id          HeartbeatPacket{claimed,physical,ts,is_replayed}│   │    ║
║  │  │  me_echo_reports           std::vector<MEEchoReport>                       │   │    ║
║  │  │    MEEchoReport{link_src,link_dst,false_reporter,ts,is_echo}               │   │    ║
║  │  │  topology_divergence_delta uint32_t  (Eq 3.1 — controller-origin detector) │   │    ║
║  │  └─────────────────────────────────────────────────────────────────────────────┘   │    ║
║  │                                                                                     │    ║
║  │  RADIO TAGS (NS-3 Tag subclasses — travel over 802.11p air interface)               │    ║
║  │    CustomDataTag1          node_id, pos(x,y,z), vel, accel, neighbours[], ts        │    ║
║  │    CustomHeartbeatTag      claimed_sender_id(4B) + timestamp(8B) + is_replayed(1B) │    ║
║  │    CustomMetaDataUnicastTag0   RSU→Controller aggregated topology (CSMA)           │    ║
║  │    182 more tag classes    7 channels × 26 neighbour-count variants                 │    ║
║  │                                                                                     │    ║
║  │  DSRC CHANNELS  (mobility_scenario=1 rural power levels)                           │    ║
║  │    Ch172  5.860GHz  SCH  23.0 dBm  (shortest reach ~150m)                         │    ║
║  │    Ch174  5.870GHz  SCH  26.5 dBm                                                  │    ║
║  │    Ch176  5.880GHz  SCH  30.0 dBm                                                  │    ║
║  │    Ch178  5.890GHz  CCH  33.5 dBm  ← all beacons+heartbeats sent here             │    ║
║  │    Ch180  5.900GHz  SCH  37.0 dBm                                                  │    ║
║  │    Ch182  5.910GHz  SCH  40.5 dBm                                                  │    ║
║  │    Ch184  5.920GHz  SCH  44.0 dBm  (longest reach ~500m)                          │    ║
║  │                                                                                     │    ║
║  │  ACTIVE DATA PATH  (paper=0, distributed RL routing)                               │    ║
║  │    distributed_dsrc_data_broadcast()  every 100ms per vehicle on Ch178             │    ║
║  │    RSU_dataunicast_agent()            RSU→Controller topology upload (CSMA)        │    ║
║  │    send_LTE_data_agent()              Vehicle→Controller topology upload (LTE)      │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  ATTACK INJECTION LAYER  (inside routing.cc — scheduled via Simulator::Schedule)            ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  12 ATTACK SCENARIOS — controlled by --attack_scenario=N                           │    ║
║  │                                                                                     │    ║
║  │  TTW — Topology Time-Warp                                                          │    ║
║  │  ┌───────────────────────────────────────────────────────────────────────────┐     │    ║
║  │  │  Attacker stores real packet <Vsrc sees Vdst, ts=T_old> when link exists  │     │    ║
║  │  │  Waits for link to break (vehicle drives >300m away)                      │     │    ║
║  │  │  Replays with forged ts=T_now → controller believes broken link is active │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S1 (scenario=1)  TTW_ReplayAttack()          malicious vehicle, no RSU  │     │    ║
║  │  │    t=10s  HELLO V0↔V1, legitimate topology update to controller          │     │    ║
║  │  │    t=10s  V0 stores old packet <V0 sees V1, ts=10>                       │     │    ║
║  │  │    t=15s  V1 moves away → link breaks                                    │     │    ║
║  │  │    t=20s  V0 forges ts → sends <V0 sees V1, ts=20> to controller        │     │    ║
║  │  │    t=20.05s  PEM detection fires (50ms delay)                            │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S2 (scenario=2)  TTWS2_ReplayAttack()        malicious RSU              │     │    ║
║  │  │  S3 (scenario=3)  TTWS3_InternalReplay()      malicious ctrl, no RSU    │     │    ║
║  │  │  S4 (scenario=4)  TTWS4_InternalReplay()      malicious ctrl + RSU      │     │    ║
║  │  │    S3/S4: physical_sender_id = 9999 (controller sentinel)                │     │    ║
║  │  │    manipulation happens inside controller memory — no external packet     │     │    ║
║  │  └───────────────────────────────────────────────────────────────────────────┘     │    ║
║  │                                                                                     │    ║
║  │  BSHH — Beacon State Heartbeat Hijack                                              │    ║
║  │  ┌───────────────────────────────────────────────────────────────────────────┐     │    ║
║  │  │  Attacker stores heartbeat from V1 (ts=T_old), replays impersonating V1  │     │    ║
║  │  │  Controller gets conflicting heartbeats → wrong liveness state            │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S5 (scenario=5)  BSHH_S1_ReplayAttack()      malicious vehicle, no RSU │     │    ║
║  │  │    t=5s   V1→V2 heartbeat, both → controller (legitimate)                │     │    ║
║  │  │    t=5.1s V2 stores old heartbeat <sender=V1, ts=0>                      │     │    ║
║  │  │    t=10s  V2 → controller: <sender=V1, ts=0>  (FORGED — V2 impersonates)│     │    ║
║  │  │           Controller: conflicting ts=5 (real) vs ts=0 (stale)            │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S6 (scenario=6)  BSHH_S2_ReplayAttack()      malicious RSU              │     │    ║
║  │  │  S7 (scenario=7)  BSHH_S3_InternalReplay()    malicious ctrl, no RSU    │     │    ║
║  │  │  S8 (scenario=8)  BSHH_S4_InternalReplay()    malicious ctrl + RSU      │     │    ║
║  │  └───────────────────────────────────────────────────────────────────────────┘     │    ║
║  │                                                                                     │    ║
║  │  ME — Multipath Echo                                                                │    ║
║  │  ┌───────────────────────────────────────────────────────────────────────────┐     │    ║
║  │  │  Real link V1↔V2 exists. Malicious nodes echo it under false reporters   │     │    ║
║  │  │  Controller infers phantom paths V1→V3→V2, V1→V4→V2 (never exist)       │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S9  (scenario=9)   ME_S1_EchoAttack()        malicious V3,V4, no RSU   │     │    ║
║  │  │    t=10s  V1→ctrl:<V1 sees V2>, V2→ctrl:<V2 sees V1>  (legitimate)      │     │    ║
║  │  │    t=10.1s V3→ctrl:<V1 sees V2>, V4→ctrl:<V1 sees V2>  (ECHO)          │     │    ║
║  │  │           Controller infers 4 paths: V1→V2, V1→V3→V2, V1→V4→V2, ...    │     │    ║
║  │  │                                                                           │     │    ║
║  │  │  S10 (scenario=10)  ME_S2_InjectEchoReports() malicious RSU              │     │    ║
║  │  │  S11 (scenario=11)  ME_S3_InjectPhantomPaths()malicious ctrl, no RSU    │     │    ║
║  │  │  S12 (scenario=12)  ME_S4_InjectPhantomPaths()malicious ctrl + RSU      │     │    ║
║  │  └───────────────────────────────────────────────────────────────────────────┘     │    ║
║  │                                                                                     │    ║
║  │  Every attack function sets:                                                        │    ║
║  │    pem_attack_injection_time = Simulator::Now().GetSeconds()                       │    ║
║  │    pem_attack_active = true                                                        │    ║
║  │    Then calls PemEmitEvent(..., attack_label=true)                                 │    ║
║  │    or PemEmitHeartbeatEvent(..., attack_label=true)  [BSHH only]                  │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                          │                                                                   ║
║                          │ PemEmitEvent() / PemEmitHeartbeatEvent()                         ║
║                          ▼                                                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  LAYER 1 — CRYPTO PRE-FILTER  (.crypto_src/ → SDVN-Temporal-Attacks/crypto/)               ║
║  PemCryptoPreFilter()  — called inline inside PemEmitEvent(), runs during simulation        ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  Five crypto modules (#included in routing.cc at lines 88–93)                      │    ║
║  │                                                                                     │    ║
║  │  ┌─────────────────────┐    ┌──────────────────────────────────────────────────┐   │    ║
║  │  │  hmac_filter.cc     │    │  dilithium.cc                                    │   │    ║
║  │  │                     │    │                                                  │   │    ║
║  │  │  HMAC-SHA256        │    │  ML-DSA-87  (Post-Quantum Digital Signature)    │   │    ║
║  │  │  Eq 3.15: integrity │    │  Eq 3.26: threshold aggregate signature check   │   │    ║
║  │  │  check per packet   │    │  t-of-n witnesses must co-sign topology claim   │   │    ║
║  │  └─────────────────────┘    └──────────────────────────────────────────────────┘   │    ║
║  │                                                                                     │    ║
║  │  ┌─────────────────────────────────────────┐  ┌────────────────────────────────┐   │    ║
║  │  │  kem.cc                                 │  │  location_binding.cc           │   │    ║
║  │  │                                         │  │                                │   │    ║
║  │  │  Kyber-1024 + FireSaber Hybrid-KEM      │  │  Haversine distance formula    │   │    ║
║  │  │  K = KDF(ss_kyber ⊕ ss_saber)          │  │  Eq 3.27–3.29: range check    │   │    ║
║  │  │  (liboqs ≥ 0.10: FireSaber→ML-KEM-1024)│  │  Reporter must be within       │   │    ║
║  │  │  Session key establishment               │  │  300m of claimed link          │   │    ║
║  │  └─────────────────────────────────────────┘  └────────────────────────────────┘   │    ║
║  │                                                                                     │    ║
║  │  ┌─────────────────────────────────────────┐                                       │    ║
║  │  │  lkh_mgmt.cc                            │                                       │    ║
║  │  │                                         │                                       │    ║
║  │  │  LKH (Logical Key Hierarchy)            │                                       │    ║
║  │  │  Group key management                   │                                       │    ║
║  │  │  Eq 3.30: quorum / witness check        │                                       │    ║
║  │  │  Node revocation support                │                                       │    ║
║  │  └─────────────────────────────────────────┘                                       │    ║
║  │                                                                                     │    ║
║  │  Controller-origin bypass:                                                          │    ║
║  │    if (is_malicious_controller) → PemCryptoPreFilter returns true immediately       │    ║
║  │    physical_sender_id=9999 → all crypto checks skipped                             │    ║
║  │    (controller holds all keys — crypto cannot defend against it)                   │    ║
║  │                                                                                     │    ║
║  │  Packets failing → pem_crypto_drop_* counters incremented, event silently dropped  │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                          │                                                                   ║
║                          │ events that pass → PemRecordObservation()                        ║
║                          ▼                                                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  LAYER 2 — LW DETECTOR  (9-Signature Weighted PEM Scorer)                                   ║
║  Runs inline during simulation — one call per event                                          ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  PemEvent struct — one instance per event appended to pem_all_events[]              │    ║
║  │    type               PEM_EVENT_BEACON / TOPOLOGY_UPDATE / HEARTBEAT               │    ║
║  │    physical_sender_id who actually sent the packet                                  │    ║
║  │    claimed_sender_id  who the packet claims to be from                             │    ║
║  │    reporter_id        who forwarded it to the controller                            │    ║
║  │    link_src_id        topology link endpoint A                                      │    ║
║  │    link_dst_id        topology link endpoint B                                      │    ║
║  │    sender_timestamp   τ_s: claimed observation time inside the packet               │    ║
║  │    reception_timestamp τ_r: when the detector received it                           │    ║
║  │    attack_label       ground truth: true = this is a forged event                  │    ║
║  │    triggered[9]       which of the 9 signatures fired                               │    ║
║  │    score              PEM weighted score Σ w_i × sig_i(e)  (Eq 3.12)              │    ║
║  │    alert_raised       true if score ≥ 0.075                                        │    ║
║  │    detection_latency_ms  τ_r − pem_attack_injection_time                           │    ║
║  │                                                                                     │    ║
║  │  9 DETECTION SIGNATURES  (weight w_i = 1/9 = 0.111 each)                          │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  i=0  TTW-S1   |τ_r − τ_s| > T_b + ε = 110ms                               │  │    ║
║  │  │                Catches any packet whose claimed timestamp is too stale        │  │    ║
║  │  │                Also checks: pem_last_authentic_beacon_reception               │  │    ║
║  │  │                  (keyed by claimed_sender_id — TTW Fix 2)                    │  │    ║
║  │  │                ttw_link_lifetime_bound L_link computed at startup:            │  │    ║
║  │  │                  urban=43s, rural=20s, highway=9s  (TTW Fix 1)               │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=1  TTW-S2   Current τ_s < previous τ_s from same node (regression)       │  │    ║
║  │  │                Catches TTW-S2 where replayed old timestamp goes backwards     │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=2  TTW-S3   Same link reported by two reporters with |ts gap| > T_b       │  │    ║
║  │  │                Cross-reporter timestamp inconsistency                         │  │    ║
║  │  │                pem_link_report_history trimmed by L_link window  (TTW Fix 3) │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=3  BSHH-S1  Two heartbeats with same claimed_sender, diff physical_sender │  │    ║
║  │  │                Identity hijack: V2 transmitting as V1                         │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=4  BSHH-S2  Heartbeat τ_s < last known τ_s for this identity             │  │    ║
║  │  │                Out-of-order / stale heartbeat replay                          │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=5  BSHH-S3  Heartbeat arrived for identity with no prior beacon in 400ms  │  │    ║
║  │  │                window  (ghost liveness — PEM_HEARTBEAT_WINDOW_S = 400ms)     │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=6  ME-S1    reporter_count > density bound  (Eq 3.8)                      │  │    ║
║  │  │                bound = (1+μ) × 2 × r_comm(300m) × λ̂                         │  │    ║
║  │  │                Too many nodes claiming to witness the same link               │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=7  ME-S2    Path count for a link increased by > Δ_max in one update      │  │    ║
║  │  │                Sudden path count explosion                                    │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  i=8  ME-S3    Reporter position outside 300m range of both link endpoints   │  │    ║
║  │  │                Geometrically impossible witness                               │  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  SCORING                                                                            │    ║
║  │    s(e) = Σ_{i=0}^{8}  (1/9) × 1[sig_i fired]         (Eq 3.12)                  │    ║
║  │    Single signature fires → s(e) = 0.111 > threshold   → alert_raised = true       │    ║
║  │    Threshold θ_LW = PEM_SCORE_THRESHOLD = 0.075                                    │    ║
║  │                                                                                     │    ║
║  │  TEMPORAL PRESSURE (reported score only, does NOT affect alert_raised)             │    ║
║  │    pressure = Σ_{e' in 200ms window} score(e') × exp(−age(e')/τ_decay)            │    ║
║  │    τ_decay = PEM_DECAY_TAU_S = 200ms                                               │    ║
║  │    total_reported = s(e) + min(pressure × 0.05, 0.30)                              │    ║
║  │                                                                                     │    ║
║  │  PARALLEL CONTROLLER-ORIGIN DETECTOR                                               │    ║
║  │    topology_divergence_delta  (Eq 3.1) — uint32_t counter                         │    ║
║  │    incremented when controller's stored topology diverges from received evidence    │    ║
║  │    primary detector for S3/S4/S7/S8/S11/S12 (controller insider attacks)          │    ║
║  │                                                                                     │    ║
║  │  PEM OUTPUT FILES (written at end of simulation)                                   │    ║
║  │    pem_event_log.csv      per-event: sim_time, event_type, physical_sender,        │    ║
║  │                           claimed_sender, triggered_sigs, score, alert_raised,      │    ║
║  │                           detection_latency_ms                                      │    ║
║  │    pem_run_summary.csv    per-run: tp, tn, fp, fn, mcc, auroc, tdet_ms,            │    ║
║  │                           pdr_under_attack_pct, pdr_post_mitigation_pct,           │    ║
║  │                           te2e_under_attack_ms, te2e_post_mitigation_ms            │    ║
║  │    tgn_alerts.json        PEM-only alerts written by PemWriteAlertsJson()          │    ║
║  │                           (blockchain-ready even without TGN weights)               │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                          │                                                                   ║
║                          │ pem_all_events[] vector — all events accumulated in RAM           ║
║                          │ Simulator::Destroy() called here                                  ║
║                          ▼                                                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  LAYER 3 — SECONDARY CRYPTO GATE  (.tgn_src/ → SDVN-Temporal-Attacks/tgn/tgn_core.cc)     ║
║  TGN_ApplyCryptoFilter(pem_all_events)                                                       ║
║  Runs POST-SIMULATION as batch pass over all collected events                                ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  Controller sentinel bypass (physical_sender_id == 9999 → PASS ALL, skip rules)    │    ║
║  │  RSU path detection: rsu_id_base = N_Controllers + 1 + N_Vehicles                  │    ║
║  │    physical_is_rsu = (id >= rsu_id_base) AND (id < rsu_id_base + N_RSUs)          │    ║
║  │    (upper bound required — without it, 9999 >= N_Vehicles satisfies RSU check)     │    ║
║  │                                                                                     │    ║
║  │  Step 1 — HMAC / MAC Integrity  (Eq 3.15)                                         │    ║
║  │    mac_valid = physical_is_rsu                         (RSU forwarding is trusted)  │    ║
║  │              OR (physical_sender_id == claimed_sender_id)  (own-key signing)        │    ║
║  │    DROP-MAC: physical ≠ claimed AND not RSU path                                   │    ║
║  │      Catches BSHH-S1/S2: V2 transmitting with V1's claimed identity               │    ║
║  │                                                                                     │    ║
║  │  Step 2 — Timestamp Freshness  (Eq 3.16)                                           │    ║
║  │    PASS if |τ_r − τ_s| ≤ FRESHNESS_S = 0.110s  (T_b + ε = 100ms + 10ms)         │    ║
║  │    DROP-STALE: packet too old                                                       │    ║
║  │      Catches BSHH-S1/S2: stored heartbeat has τ_s from seconds ago                │    ║
║  │      Does NOT catch TTW: attacker forges τ_s = current time → |τ_r − τ_s| ≈ 0    │    ║
║  │                                                                                     │    ║
║  │  Step 3 — Nonce Novelty  (Eq 3.17)                                                 │    ║
║  │    nonce = (reporter_id, claimed_sender_id, sender_timestamp)                      │    ║
║  │    DROP-NONCE: same triplet already seen in seen_nonces set                        │    ║
║  │      Catches exact packet replays                                                   │    ║
║  │                                                                                     │    ║
║  │  Output: crypto_filter_log.txt  (per-drop: DROP-MAC / DROP-STALE / DROP-NONCE)    │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                          │                                                                   ║
║                          │ filtered[] — events that passed all 3 rules                       ║
║                          ▼                                                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════════════╣
║  LAYER 4 — TGN INFERENCE  (.tgn_src/ → SDVN-Temporal-Attacks/tgn/tgn_core.cc)             ║
║  TGN_ProcessAllEvents(filtered)                                                               ║
║  Runs POST-SIMULATION as batch pass — for each event in reception-time order                 ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  GLOBAL STATE MAPS (persist across events)                                          │    ║
║  │    g_tgn_last_sender_ts[node_id]         last seen τ_s per node  (for seq_gap)     │    ║
║  │    g_tgn_link_reporters[link_key]        set of reporters per link  (for rho_v)     │    ║
║  │    g_tgn_beacon_windows[node_id]         sliding window of W_max=430 entries        │    ║
║  │    link_key = "link_src_link_dst"        DIRECTED string key                        │    ║
║  │                                                                                     │    ║
║  │  STEP 0 — Zero-init new nodes  (Eq 3.34)                                           │    ║
║  │    h_v(t⁻) = zeros(dim=32)   on first appearance                                   │    ║
║  │                                                                                     │    ║
║  │  STEP 1 — Feature Extraction  TGN_ExtractFeatures(e)                               │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  6-element feature vector x_v  (Eq 3.19, Table 4.7)                          │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  f1  τ_dev = clip((τ_r − τ_s) / T_b, −50, +50)                              │  │    ║
║  │  │       how stale the packet is in beacon intervals                             │  │    ║
║  │  │       ≈0 → fresh,  50 → 5s old  (TTW signal when timestamp NOT forged)      │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  f2  c_v^W = beacon_count                                                     │  │    ║
║  │  │       events from claimed_sender_id in last W_max=430 window entries          │  │    ║
║  │  │       W_max = ceil(L_link/T_b) = ceil(43/0.1) = 430  (urban)                 │  │    ║
║  │  │       measures how established/active this node has been                      │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  f3  Δs_v = seq_gap = max(0, last_τ_s[node] − current_τ_s)                  │  │    ║
║  │  │       how much sender timestamp went backwards                                │  │    ║
║  │  │       0 → monotonic increase (normal),  5s → TTW replay regression           │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  f4  ρ_v = reporter_count                                                     │  │    ║
║  │  │       distinct nodes that reported the same (link_src, link_dst)              │  │    ║
║  │  │       RSU/ctrl path: tracks claimed_sender_id (not reporter_id)               │  │    ║
║  │  │       high count → ME echo attack (phantom witnesses)                         │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  f5  ι_v = identity_mismatch                                                  │  │    ║
║  │  │       1.0 if physical ≠ claimed AND NOT RSU path AND NOT sentinel 9999        │  │    ║
║  │  │       0.0 otherwise (RSU forwarding suppressed — not impersonation)           │  │    ║
║  │  │       1.0 → BSHH signal (V2 transmitting as V1)                              │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  φ  = log(1 + Δt / T_b)                                                      │  │    ║
║  │  │       Δt = recv_time − last_event_time for this node                          │  │    ║
║  │  │       how long the node was silent (log-scaled)                               │  │    ║
║  │  │       T_b=0.1s → φ=0.693 (steady),  10s silence → φ=4.615                   │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  NOTE: raw node_id and raw τ_s are intentionally EXCLUDED                    │  │    ║
║  │  │    id_v excluded: model must learn patterns, not memorise "node 3 = attacker" │  │    ║
║  │  │    τ_s excluded:  absolute timestamps don't generalise across runs            │  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  STEP 2 — Edge Freshness  A_uv  (Eq 3.20/3.21)   TGN_EdgeFreshness()              │    ║
║  │    stale_excess = max(0, (τ_r − τ_s) − T_b)                                       │    ║
║  │    A_uv = exp(−stale_excess / (γ × T_b))                                          │    ║
║  │    γ = TGN_GAMMA = L_link / (2 × T_b × ln2)                                      │    ║
║  │      urban:   L_link=43s  → γ = 43/(2×0.1×0.693) = 310                           │    ║
║  │      highway: L_link=9s   → γ = 9/(2×0.1×0.693) ≈ 65                             │    ║
║  │    age < T_b  → A_uv = 1.0   (fresh, no penalty)                                  │    ║
║  │    age = 30s  → A_uv ≈ 0.38  (stale, down-weighted in message passing)            │    ║
║  │    TTW with forged ts: age≈0 → A_uv≈1.0 → TGN relies on seq_gap + GRU memory    │    ║
║  │                                                                                     │    ║
║  │  STEP 3 — GRU Temporal Memory Update  (Eq 3.22)   UpdateNodeMemory()              │    ║
║  │    gru_input = [h_v(t⁻) ‖ τ_dev, c_v^W, Δs_v, ρ_v, ι_v, φ]                     │    ║
║  │               (32 + 6 = 38 elements = gs)                                          │    ║
║  │                                                                                     │    ║
║  │    GRU gates:                                                                       │    ║
║  │      z = σ(Wz·gru_input + Uz·h + bz)    update gate  (32×38 + 32×32)             │    ║
║  │      r = σ(Wr·gru_input + Ur·h + br)    reset gate                               │    ║
║  │      n = tanh(Wn·gru_input + Un·(r⊙h) + bn)  candidate                           │    ║
║  │      h_v(t) = (1−z)⊙h + z⊙n            new memory                               │    ║
║  │                                                                                     │    ║
║  │    Heuristic mode (no weights loaded): h updated but not used for scoring          │    ║
║  │    Trained mode: h carries attack pattern memory across sequence of events         │    ║
║  │                                                                                     │    ║
║  │  STEP 4 — Neighbourhood Aggregation L=2 rounds  (Eq 3.23)                         │    ║
║  │    3-node induced subgraph: active = {reporter_node, link_src, link_dst}           │    ║
║  │    Adjacency set: adj[reporter][link_dst] = A_uv  (symmetric)                     │    ║
║  │                                                                                     │    ║
║  │    For l = 0, 1:                                                                   │    ║
║  │      For each node v in active:                                                     │    ║
║  │        if N(v) ∩ active = ∅: H^(l+1)[v] = H^(l)[v]  (passthrough)               │    ║
║  │        else: agg = MEAN{ A_uv × H^(l)[u] : u ∈ N(v) ∩ active }                  │    ║
║  │              H^(l+1)[v] = ReLU(W^(l) · agg + b^(l))                              │    ║
║  │    W^(0), W^(1): each (32×32)   b^(0), b^(1): each (32,)                         │    ║
║  │                                                                                     │    ║
║  │  STEP 5 — Anomaly Score  (Eq 3.24)                                                 │    ║
║  │    Trained mode:   ŷ_v = σ(w_score · h_v^(L) + b_score)                           │    ║
║  │      w_score: (32,),  b_score: scalar (initialised −0.85 → default score≈0.30)    │    ║
║  │                                                                                     │    ║
║  │    Heuristic mode (no tgn_weights.bin):                                             │    ║
║  │      s += clip(staleness − T_b, 0, 2T_b) / T_b    (TTW staleness)                │    ║
║  │      s += min(1, seq_gap / 5)                       (TTW seq regression)           │    ║
║  │      s += identity_mismatch × 1.5                   (BSHH identity hijack)        │    ║
║  │      s += min(2, (reporter_count−1)×0.8) if count>1.5  (ME density)              │    ║
║  │      s += 2.0 × (1 − edge_freshness)                (stale edge signal)           │    ║
║  │                                                                                     │    ║
║  │    Alert fires if ŷ_v ≥ θ_FS = 0.40  (auto-tuned on validation set)              │    ║
║  │                                                                                     │    ║
║  │  STEP 6 — Variant Classification  (Eq 3.25, only when alert fires + weights loaded)│    ║
║  │    logits  = Wcls · h_v^(L) + b_cls     (Wcls: 3×32,  b_cls: 3,)                 │    ║
║  │    α̂_v    = argmax(logits)  →  0=TTW / 1=BSHH / 2=ME                             │    ║
║  │    Heuristic mode: variant = TGN_AlphaFromScenario(attack_scenario)               │    ║
║  │                                                                                     │    ║
║  │  TGN OUTPUT FILES                                                                  │    ║
║  │    tgn_events.csv         per-event: 6 features + A_uv + tgn_score + tgn_alert    │    ║
║  │                           + variant + is_attack + pem_score + pem_alert            │    ║
║  │    tgn_alerts.json        confirmed alerts → fed to blockchain                     │    ║
║  │    tgn_detection_log_s{N}.txt   human-readable detection log per scenario          │    ║
║  │    tgn_attack{N}.txt      per-scenario attack + detection summary                  │    ║
║  │    tgn_summary.csv        per-run: tp, tn, fp, fn, mcc, auroc, tdet_ms,           │    ║
║  │                           dim, layers, gamma, wmax, theta_fs                       │    ║
║  │    crypto_filter_log.txt  per-dropped-event: DROP-MAC/DROP-STALE/DROP-NONCE       │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
║                          │                                                                   ║
║                          │ tgn_alerts.json  written to disk                                  ║
╚══════════════════════════╪═══════════════════════════════════════════════════════════════════╝
                           │
                           │  (file handoff — separate process starts here)
                           ▼
╔══════════════════════════════════════════════════════════════════════════════════════════════╗
║  LAYER 5 — BLOCKCHAIN  (Hyperledger Fabric — completely separate process)                   ║
║  Reads tgn_alerts.json, submits via trust-weighted PBFT consensus                           ║
║                                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  blockchain/client/submitToFabric.js  (Node.js)                                    │    ║
║  │    Reads tgn_alerts.json                                                            │    ║
║  │    Signs with Falcon-1024 post-quantum signature (per SubmitAlert spec)             │    ║
║  │    Calls SubmitAlert(trustedNodeID, alertJSON, ctrlTopoJSON, intervalTS)            │    ║
║  └───────────────────────────────────────┬─────────────────────────────────────────────┘    ║
║                                          │ trust-weighted PBFT consensus                    ║
║  ┌───────────────────────────────────────▼─────────────────────────────────────────────┐    ║
║  │  blockchain/chaincode/temporalecho/  (Go chaincode — Algorithm 4: FS-MITIGATE)      │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ DATA FLOWS INTO THE LEDGER ════════════════════════════         │    ║
║  │                                                                                     │    ║
║  │  Flow 1 — Beacon Evidence  SubmitBeaconEvidence(evidenceJSON)                      │    ║
║  │    Stores BeaconEvidenceRecord keyed BEACON:<peerID>:<intervalTS>                  │    ║
║  │    Gate: post-bootstrap → peer must have τk ≥ τ^gt_min=0.50 OR IsRSUPeer=true     │    ║
║  │    Verified with Falcon-1024 peer signature                                         │    ║
║  │    Used by: aggregateEvidenceLinkSet (divergence check ground truth)               │    ║
║  │                                                                                     │    ║
║  │  Flow 2 — Detection Events  SubmitDetectionEvent / SubmitLWDetectionResult         │    ║
║  │    LW path: SubmitLWDetectionResult(callerRSU, vehicleID, score, sigsCSV,          │    ║
║  │                                     variant, intervalTS, peerSigHex)               │    ║
║  │      Verifies Falcon-1024 sig over callerRSU:vehicleID:score:variant:interval      │    ║
║  │      Only Tier 1 RSU (IsRSUPeer=true, score≥1.0) may submit via LW path           │    ║
║  │    FS path: SubmitAlert → called by submitToFabric.js after TGN inference          │    ║
║  │                                                                                     │    ║
║  │  Flow 3 — Controller Topology Claim  SubmitControllerTopology(ctrlTopoJSON)        │    ║
║  │    Stores CTRL_TOPO:<ctrl>:<interval> as untrusted claim                           │    ║
║  │    Immediately triggers checkControllerDivergence (divergence.go)                  │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ ALGORITHM 4 ENTRY POINTS ══════════════════════════            │    ║
║  │                                                                                     │    ║
║  │  SubmitAlert(trustedNodeID, alertJSON, ctrlTopoJSON, intervalTS)                   │    ║
║  │    TE-06: verify caller trust ≥ TrustMin=0.10 and not Flagged                     │    ║
║  │    Stores DetectionEvent on ledger                                                  │    ║
║  │    Optionally runs divergence check on ctrlTopoJSON                                 │    ║
║  │    Computes thresholdT = n/2+1 (dynamic from active peer count — TE-02)            │    ║
║  │    Calls runMitigation(events, θ_FS=0.40, thresholdT)                             │    ║
║  │                                                                                     │    ║
║  │  Mitigate(alertsJSON, beaconEvidJSON, ctrlTopoJSON, thetaFS, thresholdT)           │    ║
║  │    SF-1: persist inline beacon evidence before divergence check                    │    ║
║  │    Computes divergence; if δ > δ_thresh appends CTRL_ORIGIN DetectionEvent        │    ║
║  │    Calls runMitigation(all_events, thetaFS, thresholdT)                            │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ runMitigation (Algorithm 4 body) ══════════════════════        │    ║
║  │                                                                                     │    ║
║  │  Step 1 — TRUST-WEIGHTED PBFT CONSENSUS GATE  (Eq. 3.47, TE-01)                   │    ║
║  │    approvingPeers = {PeerID of each submitting alert}                              │    ║
║  │    activePeers   = selectPeers(loadAllPeerIDs())  — top-np=8 by trust             │    ║
║  │    Σ_{k∈Papprove} τk / Σ_{k∈Pactive} τk > 2/3  → proceed                         │    ║
║  │    else abort:  "PBFT consensus not reached"                                       │    ║
║  │    NOTE: trust-weighted (not simple node-count) per Eq. 3.47                      │    ║
║  │                                                                                     │    ║
║  │  Step 2 — BOOTSTRAP GATE  (MF-02)                                                  │    ║
║  │    isBootstrapComplete = count(τk ≥ τ^gt_min=0.50) ≥ np=8                        │    ║
║  │    if NOT complete: log-only, skip enforcement                                     │    ║
║  │    Bootstrap ends after Rmin = ceil((0.50−0.10)/0.05) = 8 trust rounds            │    ║
║  │                                                                                     │    ║
║  │  Step 3 — PER-ALERT ACTIONS  (for each alert with score > θ_FS=0.40)              │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  variant = TTW / BSHH / TTW_BSHH_COMBINED:                                  │  │    ║
║  │  │    verifyThresholdSig(evidence, thresholdT)  → or abort                      │  │    ║
║  │  │    pushFlowModDrop(vehicleID)      priority=65000  eth_src=vehicleMAC        │  │    ║
║  │  │      (skipped in no-RSU mode — no OpenFlow switches)                         │  │    ║
║  │  │    revokeSessionKey(vehicleID)     → emits KeyRevocation event               │  │    ║
║  │  │    publishBlacklistBeacon(vehicleID)  → BLACKLIST_BEACON:<vid> on ledger     │  │    ║
║  │  │    revokeVehicleCert(vehicleID)    → CERT_REVOKED:<vid> + event              │  │    ║
║  │  │    if attacker IsRSUPeer:          triggerRSUZoneReassignment()               │  │    ║
║  │  │      (BEFORE updateTrust — demotePeerToClient clears IsRSUPeer in Stage 1)   │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  variant = ME:                                                                │  │    ║
║  │  │    verifyQuorum(witnesses, thresholdT, lat, lon)  → or abort                 │  │    ║
║  │  │    invalidateFalsePaths(vehicleID) → FALSE_PATHS:<vid> on ledger             │  │    ║
║  │  │    pushRerouteFlowMod(vehicleID)   priority=50000  (skipped no-RSU)          │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  variant = CTRL_ORIGIN:                                                       │  │    ║
║  │  │    pushFlowModOverride(controllerID, beaconEvidence):                         │  │    ║
║  │  │      catch-all FlowMod priority=65535 → all traffic forwarded normally        │  │    ║
║  │  │      per-vehicle FlowMods priority=65534 → bypass poisoned routes            │  │    ║
║  │  │      (skipped in no-RSU mode — no OpenFlow switches)                         │  │    ║
║  │  │    CheckControllerTrustAndReassign(controllerID, allCtrls):                   │  │    ║
║  │  │      score -= TrustDeltaCtrl=0.20  (TE-04: SOLE penalty authority)           │  │    ║
║  │  │      if score < TrustCtrlMin=0.30:                                            │  │    ║
║  │  │        selectBackupController → argmax(τCk > 0.30, k ≠ Cj)                   │  │    ║
║  │  │        write CTRL_REASSIGN:<ctrl>:<ts> + CTRL_REVOKED:<ctrl>                 │  │    ║
║  │  │        publishControllerRevokedBeacon(ctrl, backup):                          │  │    ║
║  │  │          InterimFallbackIntervals = ceil(L_link/T_b) = 430 (urban)           │  │    ║
║  │  │          no-RSU path: Ck* solicits topology via V2X; vehicles use distributed │  │    ║
║  │  │        emits ControllerRemoved + ControllerCredentialRevocationRequested      │  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  Step 4 — VEHICLE ISOLATION  (non-CTRL_ORIGIN only)                                │    ║
║  │    flagReauth(vehicleID, variant)   → REAUTH:<vid> on ledger                      │    ║
║  │    updateTrust(vehicleID, false, zero=true):                                       │    ║
║  │      if IsRSUPeer: demotePeerToClient  (3-stage pipeline)                         │    ║
║  │      else: score = 0 immediately                                                   │    ║
║  │                                                                                     │    ║
║  │  Step 5 — HONEST PEER REWARD  (TE-07)                                              │    ║
║  │    for each peer in activePeers not in attackerSet:                                │    ║
║  │      updateTrust(peer, correct=true, zero=false)  → score += 0.05                 │    ║
║  │                                                                                     │    ║
║  │  Step 6 — SUPERVISOR FEEDBACK                                                      │    ║
║  │    for each QUARANTINED peer: monitorAndRemovePeer()                               │    ║
║  │      if (now − DemotedAt) < 30,000ms: keep monitoring                             │    ║
║  │      else if score ≤ 0.10: PeerStateRemoved + CertRevocationRequested             │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ trust.go ══════════════════════════════════════════════        │    ║
║  │                                                                                     │    ║
║  │  TRUST SCORING (Eqs. 3.38–3.41)                                                    │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  Constants:                                                                   │  │    ║
║  │  │    TrustDeltaPlus=0.05   TrustDeltaMinus=0.10   TrustDeltaCtrl=0.20         │  │    ║
║  │  │    TrustMin=0.10 (participation floor)    TrustMinGT=0.50 (ground truth)     │  │    ║
║  │  │    TrustCtrlMin=0.30 (controller removal) NpConsensus=8 (3f+1 for f=2)      │  │    ║
║  │  │    TrustInitTier1=1.00 (RSU)              TrustInitTier2=0.10 (OBU)          │  │    ║
║  │  │    QuarantineMonitorMs=30000 (30s Stage 2 window)                            │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  updateTrust(peerID, correct, zero) → Eq. 3.38                               │  │    ║
║  │  │    zero=true, IsRSUPeer=true  → demotePeerToClient  (Stage 1 pipeline)       │  │    ║
║  │  │    zero=true, IsRSUPeer=false → score=0 immediately                          │  │    ║
║  │  │    correct=true               → score = min(1.0, score+0.05)                 │  │    ║
║  │  │    correct=false              → score = max(0.0, score-0.10)                 │  │    ║
║  │  │                               if QUARANTINED → monitorAndRemovePeer()        │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  updateCtrlTrust(ctrlID) → Eq. 3.39                                          │  │    ║
║  │  │    score = max(0.0, score-0.20); DivergenceCount++                           │  │    ║
║  │  │    penalty-only; no positive delta for controllers                            │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  selectPeers(allPeers) → Pactive  Eq. 3.41                                   │  │    ║
║  │  │    Exclusions: Flagged, QUARANTINED, REMOVED, score < 0.10                   │  │    ║
║  │  │    OBU eligibility gates — Eq. 3.40 (5 conditions):                          │  │    ║
║  │  │      c1: τk ≥ τ_min=0.10                                                     │  │    ║
║  │  │      c2: HWCapacity ≥ 2048 MB   (bypassed in SIM_NO_RSU_MODE)               │  │    ║
║  │  │      c3: dwell ≥ T_min=max(3·T_PBFT, L_link/2)  (bypassed no-RSU)          │  │    ║
║  │  │      c4: not Flagged                                                          │  │    ║
║  │  │      c5: obuHasSyncedFromRecentCheckpoint()  [always enforced]               │  │    ║
║  │  │    Sort eligible by trust desc → top np=8                                    │  │    ║
║  │  │    RSU peers (Tier 1) always satisfy c2/c3/c5 — they start at 1.0           │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  checkPBFTTrustWeight(approving, active) → Eq. 3.47                          │  │    ║
║  │  │    sumActive  = Σ_{k∈Pactive}  τk  (flagged excluded)                        │  │    ║
║  │  │    sumApprove = Σ_{k∈Papprove} τk                                            │  │    ║
║  │  │    return sumApprove/sumActive > 2/3                                          │  │    ║
║  │  │    (trust-weighted, NOT simple node count)                                   │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  THREE-STAGE RSU DEMOTION PIPELINE:                                           │  │    ║
║  │  │    Stage 1 — demotePeerToClient():                                            │  │    ║
║  │  │      score=0, Flagged=true, IsRSUPeer=false (stripped of peer role)          │  │    ║
║  │  │      State=QUARANTINED_CLIENT, excluded from Pactive immediately              │  │    ║
║  │  │      Emits PeerQuarantined → eventListener writes suspension marker           │  │    ║
║  │  │    Stage 2 — monitorAndRemovePeer():                                          │  │    ║
║  │  │      Called on each trust degradation or PeriodicPeerReSelection              │  │    ║
║  │  │      if (now − DemotedAt) < 30,000ms: return  (still monitoring)             │  │    ║
║  │  │    Stage 3 — if score ≤ 0.10 after window:                                   │  │    ║
║  │  │      State=REMOVED                                                            │  │    ║
║  │  │      CERT_REVOKED:<peerID> written to ledger                                  │  │    ║
║  │  │      Emits CertRevocationRequested (CA call done off-chain)                   │  │    ║
║  │  │      Emits PeerRemoved → eventListener logs + updates /tmp/quarantined_peers  │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  TIER 2 OBU PEER MODE (no-RSU scenarios 1,3,5,7,9,11):                       │  │    ║
║  │  │    RegisterOBUPeer(peerID, hwCapMB, hwStorageGB)  starts at τ=0.10           │  │    ║
║  │  │    Bootstrap: Rmin = ceil((0.50-0.10)/0.05) = 8 rounds needed                │  │    ║
║  │  │    GetBootstrapStatus() reports rmin_rounds, qualified_peers                  │  │    ║
║  │  │    SIM_NO_RSU_MODE="1" ledger key: set by SetSimParams for odd scenarios      │  │    ║
║  │  │    During bootstrap: all OBUs above 0.10 may submit evidence & UpdateTrust   │  │    ║
║  │  │    Post-bootstrap: only OBUs above 0.50 contribute ground truth              │  │    ║
║  │  │    UpdateTrustRound TR-01: bootstrap mode → highest-trust OBU may drive      │  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ divergence.go ═════════════════════════════════════════════    │    ║
║  │                                                                                     │    ║
║  │  CONTROLLER-ORIGIN DIVERGENCE CHECK  (Eq. 3.45)                                    │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  checkControllerDivergence(claim ControllerTopologyClaim):                   │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  ctrlLinkSet = buildLinkSet(claim.Links)                                     │  │    ║
║  │  │    Converts TopologyLink[] → canonical "A:B" set (A<B sorted)                │  │    ║
║  │  │    This is E_t^C — what the controller claims the topology is                 │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  evidenceLinkSet = aggregateEvidenceLinkSet(intervalTS)                      │  │    ║
║  │  │    This is E_t^trusted  (Eq. 3.44) — NEVER uses controller data              │  │    ║
║  │  │    Sources: BEACON_EVIDENCE records for this intervalTS                       │  │    ║
║  │  │    Eligibility gate (DV-04): peer must have τk ≥ 0.50 OR IsRSUPeer=true     │  │    ║
║  │  │    Flagged peers EXCLUDED                                                     │  │    ║
║  │  │    Method 1: HELLO-confirmed explicit neighbour lists (most accurate)         │  │    ║
║  │  │    Method 2: GPS proximity fallback (only if no explicit data)                │  │    ║
║  │  │      r_fallback = 150m (half of r_comm=300m — DV-01 fix prevents phantoms)  │  │    ║
║  │  │      Mutual proximity required: both vehicles must be within 150m each       │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  δ = symmetricDifference(ctrlLinkSet, evidenceLinkSet) = |E_t^C △ E_t^nodes| │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  δ_thresh = computeDeltaThreshold (Eq. 3.46):                                │  │    ║
║  │  │    λ̂ = n_unique_vehicles / (2 × 300)  (dynamic, DV-02 fix)                  │  │    ║
║  │  │    thresh = ceil((1+0.1) × λ̂ × 2 × 300) + 1,  min=2                        │  │    ║
║  │  │    (fixed λ=0.02 caused FP in dense/sparse scenarios — now estimated)        │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  if δ > δ_thresh:                                                            │  │    ║
║  │  │    Store DETECTION:DIVERGENCE:<ctrl>:<interval> on ledger                    │  │    ║
║  │  │    Emit ControllerOriginAttack event (delta, threshold, ctrl_trust_score)    │  │    ║
║  │  │    DV-03: does NOT apply trust penalty here — runMitigation is sole authority│  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ flowmod.go ════════════════════════════════════════════════    │    ║
║  │                                                                                     │    ║
║  │  EMERGENCY CHANNEL BYPASS (FlowMods never go through the SDN controller)           │    ║
║  │  ┌──────────────────────────────────────────────────────────────────────────────┐  │    ║
║  │  │  FlowMod path:                                                                │  │    ║
║  │  │    chaincode writes PendingFlowMod to Fabric ledger                          │  │    ║
║  │  │    eventListener.js reads ledger                                              │  │    ║
║  │  │    POSTs directly to RSU Ryu agent (port 8080) — NEVER through controller    │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  pushFlowModDrop(vehicleID)    priority=65000  eth_src=MAC                   │  │    ║
║  │  │    EntryID includes tx-timestamp to prevent key collision (FM-02 fix)        │  │    ║
║  │  │    Installed on RSU OpenFlow switch to DROP packets from attacker             │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  pushRerouteFlowMod(vehicleID) priority=50000  match=FALSE_PATH_<vid>        │  │    ║
║  │  │    Removes phantom ME paths from the forwarding table                        │  │    ║
║  │  │                                                                               │  │    ║
║  │  │  pushFlowModOverride(ctrlID, evidence[]) — CTRL_ORIGIN bypass:               │  │    ║
║  │  │    catch-all:     priority=65535  match={}  action=OUTPUT:NORMAL             │  │    ║
║  │  │    per-vehicle:   priority=65534  match=eth_src=MAC  action=OUTPUT:NORMAL    │  │    ║
║  │  │    These rules override any routes the malicious controller installed        │  │    ║
║  │  │    catch-all key "FLOWMOD_OVERRIDE_CTRL_<ctrl>" — fixed for idempotency      │  │    ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘  │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ anchor.go ═════════════════════════════════════════════════    │    ║
║  │  CreateAnchorCheckpoint(createdByPeer, blockHeight)                                │    ║
║  │    Stores ANCHOR:<n> + increments ANCHOR_CTR counter                              │    ║
║  │    SyncedPeers[] tracks which OBUs have synced from this checkpoint               │    ║
║  │  SyncFromAnchorCheckpoint(checkpointID, obuPeerID)                                │    ║
║  │    Adds obuPeerID to checkpoint.SyncedPeers                                       │    ║
║  │    Required before OBU can join Pactive (obuHasSyncedFromRecentCheckpoint)        │    ║
║  │  GetLatestAnchorCheckpoint() uses deterministic ANCHOR_CTR counter                │    ║
║  │    (NOT CouchDB sort — avoids snapshot-isolation across endorsers, BC-11 fix)     │    ║
║  │                                                                                     │    ║
║  │  ══════════════════ verification.go ═══════════════════════════════════════════    │    ║
║  │  verifyThresholdSig(evidence[], thresholdT)  → t-of-n aggregate sig check         │    ║
║  │  verifyQuorum(witnesses[], thresholdT, lat, lon)  → location-bounded quorum       │    ║
║  │  haversineDistanceM(lat1,lon1,lat2,lon2)  → on-chain distance (metres)            │    ║
║  │  resolveDualPath(alerts[])  → merges LW+FS alerts for same vehicle                │    ║
║  │  verifyFalcon1024Sig(sig, msg, pubKey)  → post-quantum signature verification     │    ║
║  └───────────────────────────────────────┬─────────────────────────────────────────────┘    ║
║                                          │ on-chain events emitted                          ║
║  ┌───────────────────────────────────────▼─────────────────────────────────────────────┐    ║
║  │  blockchain/client/eventListener.js  (Node.js — off-chain action executor)          │    ║
║  │                                                                                     │    ║
║  │  EMERGENCY CHANNEL URLS (never routed through SDN controller):                     │    ║
║  │    RSU_FLOWMOD_URLS  peer0.rsu{1..5} → http://ryu-rsu{1..5}:8080  (OpenFlow)      │    ║
║  │    RSU_MGMT_URLS     peer0.rsu{1..5} → http://ryu-rsu{1..5}:8081  (southbound)    │    ║
║  │    Adaptive FlowMod timeout: 100ms budget − Fabric delivery latency − 5ms         │    ║
║  │                                                                                     │    ║
║  │  PERIODIC TRUST ROUND (every 100ms = T_b):                                         │    ║
║  │    UpdateTrustRound(callerRSU, participating[], all[])                             │    ║
║  │      Every 5th round: rsu5 absent → score drops 0.10                              │    ║
║  │      Every 10th round: obu3 absent → score drops 0.10                             │    ║
║  │    PeriodicPeerReSelection(SELECT_PEERS_POOL)                                      │    ║
║  │      no-RSU mode (--no_rsu): pool=ALL_OBU_PEERS only                              │    ║
║  │      Emits PeerPromoted / PeerDroppedFromActive                                    │    ║
║  │      Advances QUARANTINED peers past their 30s monitoring window                  │    ║
║  │    Score table logged every 10th round                                             │    ║
║  │                                                                                     │    ║
║  │  AttackDetected event → executeFlowMod:                                            │    ║
║  │    ME variant → REROUTE FlowMod  |  other → DROP FlowMod                          │    ║
║  │    Reads GetAllPendingFlowMods → finds latest unexecuted for this vehicle+action  │    ║
║  │    POSTs to RSU Ryu agent (port 8080) with adaptive timeout                       │    ║
║  │    AcknowledgeFlowMod → marks executed on ledger (T-2 idempotency)               │    ║
║  │                                                                                     │    ║
║  │  KeyRevocation event → handleKeyRevocation:                                        │    ║
║  │    Writes revoked_keys.json (polled by crypto_pipeline.cc)                        │    ║
║  │    POSTs to LKH manager http://localhost:8090/revoke (EL-03: O(log n) KEK update)│    ║
║  │    Calls Fabric CA /revoke to permanently revoke vehicle certificate              │    ║
║  │                                                                                     │    ║
║  │  ControllerOriginAttack event → handleControllerOriginAttack:                      │    ║
║  │    Gets "FLOWMOD_OVERRIDE_CTRL_<ctrl>" from ledger                                 │    ║
║  │    Executes priority-65535 catch-all OVERRIDE via RSU Ryu agent (port 8080)       │    ║
║  │    Scans all unexecuted OVERRIDE FlowMods → executes each                          │    ║
║  │    BYPASS: sent directly to RSU OpenFlow agents, not through controller            │    ║
║  │                                                                                     │    ║
║  │  ControllerRemoved event → handleControllerRemoved (EL-01):                        │    ║
║  │    Reads ControllerReassignment from ledger (backup controller ID, zoneID)         │    ║
║  │    POSTs to ALL RSU_MGMT_URLS /southbound/switch in parallel (Promise.allSettled) │    ║
║  │      payload: { zone_id, removed_ctrl, backup_ctrl, emergency_bypass: true }      │    ║
║  │    Each RSU agent switches OpenFlow southbound connection to backup controller     │    ║
║  │    Logs how many RSUs successfully switched                                        │    ║
║  │    BYPASS: RSU management API (port 8081) never goes through malicious controller  │    ║
║  │                                                                                     │    ║
║  │  PeerQuarantined event → handlePeerQuarantined (Stage 1 demotion):                 │    ║
║  │    Writes /tmp/quarantined_peers.json → NS-3 bridge suppresses this RSU's data    │    ║
║  │                                                                                     │    ║
║  │  PeerRemoved event → handlePeerRemoved (Stage 3 demotion):                         │    ║
║  │    Updates /tmp/quarantined_peers.json to REMOVED state                            │    ║
║  │    Logs "ADMIN_ACTION_REQUIRED" — manual RegisterRSUPeer needed to re-admit        │    ║
║  │                                                                                     │    ║
║  │  ControllerRemovalFailed event → handleControllerRemovalFailed:                    │    ║
║  │    No backup controller above τC_min=0.30 available                                │    ║
║  │    Logs "CRITICAL — MANUAL OPERATOR INTERVENTION REQUIRED"                        │    ║
║  │                                                                                     │    ║
║  │  BlacklistBeaconPublished event → handleBlacklistBeaconPublished:                  │    ║
║  │    Writes /tmp/blacklist_beacons.json (OBU agent cache)                            │    ║
║  │    Writes /tmp/blacklist_vehicle_ids.txt (NS-3 IPC — read by routing.cc)          │    ║
║  │                                                                                     │    ║
║  │  AnchorCheckpointCreated → log for OBU sync awareness                              │    ║
║  │    OBU peers must call SyncFromAnchorCheckpoint before joining Pactive             │    ║
║  │                                                                                     │    ║
║  │  On startup: replayPendingFlowMods() — replay missed FlowMods from ledger (T-2)   │    ║
║  │    GetAllPendingFlowMods → execute unacknowledged → AcknowledgeFlowMod each       │    ║
║  └─────────────────────────────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## KEY NUMBERS AT A GLANCE

```
DSRC / NETWORK
  Communication range (r_comm)       300 m
  Beacon interval (T_b)              100 ms
  DSRC Control Channel               178  (5.890 GHz)
  Urban vehicle speed                ~14 m/s → L_link ≈ 43 s
  Highway vehicle speed              ~67 m/s → L_link ≈  9 s

PEM (Layer 2 — LW Detector)
  Signatures                         9   (uniform weight 1/9 = 0.111 each)
  Alert threshold (θ_LW)             0.075  → 1 signature always triggers alert
  Heartbeat window                   400 ms
  Temporal decay (τ_decay)           200 ms
  TTW L_link (urban)                 43 s   (auto-computed from mobility_scenario)
  TTW L_link (rural)                 20 s
  TTW L_link (highway)               9 s

CRYPTO PRE-FILTER (Layer 1 inline + Layer 3 post-sim)
  Freshness window (T_b + ε)         110 ms  (Eq 3.16)
  Nonce triplet                      (reporter_id, claimed_sender_id, τ_s)
  Controller bypass sentinel         9999

TGN (Layer 4)
  Embedding dimension (d)            32
  GRU input size (gs)                38  (d + 6 features)
  Message-passing rounds (L)         2
  3-node subgraph                    {reporter, link_src, link_dst}
  Alert threshold (θ_FS)             0.40  (auto-tuned on validation set)
  γ urban                            310   (L_link/(2·T_b·ln2))
  γ highway                          ~65
  W_max urban                        430   (ceil(L_link/T_b))
  W_max highway                      90
  b_score init                       −0.85 → default score ≈ 0.30
  Heuristic mode                     active when no --tgn_weights given

TRAINING
  Split                              70/15/15 stratified per scenario per class
  Loss                               BCE + 0.3·CE + 0.5·margin
  Margin (MARGIN)                    0.35
  pos_weight                         n_benign / n_attack  (dynamic)
  Max restarts                       5
  Target val MCC to stop             0.975
  Optimizer                          Adam  lr=0.001  wd=1e-4
  Gradient clip                      max norm 1.0
  Scheduler                          CosineAnnealingLR  50 epochs

DETECTION QUALITY TARGETS
  MCC     > 0.85
  AUROC   > 0.90
  Tdet    < 100 ms  (within one beacon interval)
  PDR post-mitigation significantly higher than under attack
```

---

## FILE-TO-LAYER MAP

```
File                                    Layer    Role
──────────────────────────────────────────────────────────────────────────────────────
routing.cc                              0,1,2    Main simulation + PEM LW detector
  └─ .crypto_src/ → crypto/            1        Crypto pre-filter (inline during sim)
       hmac_filter.cc                            HMAC-SHA256 integrity (Eq 3.15)
       dilithium.cc                              ML-DSA-87 post-quantum signatures
       kem.cc                                   Kyber-1024 + FireSaber Hybrid-KEM
       lkh_mgmt.cc                              LKH group key + quorum check
       location_binding.cc                      Haversine range binding
       teta_guard_types.h                       Shared crypto type definitions
  └─ .tgn_src/ → tgn/                  3,4      Secondary crypto gate + TGN inference
       tgn_core.cc                              TGN_ApplyCryptoFilter() (Layer 3)
                                                TGN_ProcessAllEvents()  (Layer 4)
                                                TGN_RunPipeline()  (orchestrator)

tgn/tgn_train.py                       Training Python training + weight export
tgn/tgn_weights.bin                    4        Trained weights loaded at runtime (276KB)
tgn/tgn_detector.cc                    —        Standalone binary (old approach, not used)

blockchain/client/submitToFabric.js    5        Alert submission to Hyperledger Fabric
blockchain/client/eventListener.js     5        On-chain event handler + OpenFlow installer
blockchain/chaincode/temporalecho/
  temporalecho.go                      5        Smart contract main entry
  trust.go                             5        Trust scoring + PBFT on ledger
  flowmod.go                           5        SDN flow rule management on ledger
  anchor.go                            5        Anchor checkpoints for peer sync
  divergence.go                        5        On-chain Eq 3.1 controller divergence
  verification.go                      5        Threshold sig + quorum + location verify
  structs.go                           5        All shared chaincode data structures
```

---

## HOW EACH ATTACK IS CAUGHT

```
Attack  PEM signatures that fire       Crypto filter        TGN primary signal
──────  ───────────────────────────    ─────────────────    ───────────────────
TTW-S1  sig[0]: |τr−τs|>110ms if ts    Layer3 Step2         seq_gap + GRU memory
        not forged; sig[1] if forged   catches if not       if ts forged: A_uv≈1
        ts creates seq regression      forged (stale)       but seq_gap fires
TTW-S2  sig[1]: ts regression          Same                 Same
TTW-S3  sig[2]: cross-reporter gap     Same                 Same
TTW-S4  same as S3 + div_delta        S3/S4: 9999→bypass   Same; TGN primary
BSHH-S1 sig[3]: diff physical/claimed  Layer3 Step1          identity_mismatch=1
        sig[4]: ts went backward       DROP-MAC catches it
        sig[5]: no prior beacon        Step2 DROP-STALE
BSHH-S2 Same as S1                    Same                  Same
BSHH-S3 same + div_delta             9999→bypass           identity_mismatch=1
BSHH-S4 Same as S3                   9999→bypass           Same
ME-S1   sig[6]: reporter_count > ρ    Layer3 Step3          reporter_count high
        sig[8]: reporter out of range  DROP-NONCE catches
ME-S2   Same as S1                    Same                  reporter_count high
ME-S3   same + div_delta             9999→bypass           reporter_count high
ME-S4   Same as S3                   9999→bypass           Same
```
