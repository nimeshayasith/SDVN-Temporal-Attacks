# TETA-GUARD Blockchain — Complete Technical Guide

**Project:** Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection:
Countering Temporal-Echo Topology Poisoning Attacks in SDVNs
**Platform:** Hyperledger Fabric (permissioned blockchain)
**Chaincode language:** Go (contractapi)
**Off-chain client:** Node.js (fabric-network SDK 2.2)
**Crypto:** Falcon-1024 / Dilithium2 (post-quantum) — simulation stub: HMAC-SHA256

> **Purpose of this document:** Written for a teammate who is completely new to this codebase.
> Covers everything from first principles through every implementation detail, including all bugs
> that were found and fixed during development. Read this top-to-bottom before touching any file.

---

## Table of Contents

1. [What Problem Does the Blockchain Solve?](#1-what-problem-does-the-blockchain-solve)
2. [What Is Hyperledger Fabric?](#2-what-is-hyperledger-fabric)
3. [System Architecture — How All Layers Connect](#3-system-architecture--how-all-layers-connect)
4. [File Structure](#4-file-structure)
5. [Core Concepts You Must Understand First](#5-core-concepts-you-must-understand-first)
   - 5.1 [Fabric Peers, Channels, and Chaincode](#51-fabric-peers-channels-and-chaincode)
   - 5.2 [The Ledger and State Database (CouchDB)](#52-the-ledger-and-state-database-couchdb)
   - 5.3 [Fabric Events](#53-fabric-events)
   - 5.4 [PBFT Consensus in This Project](#54-pbft-consensus-in-this-project)
6. [Two Deployment Modes: With-RSU and No-RSU](#6-two-deployment-modes-with-rsu-and-no-rsu)
7. [Peer Tiers and Trust Score System](#7-peer-tiers-and-trust-score-system)
   - 7.1 [Tier 1 RSU Peers](#71-tier-1-rsu-peers)
   - 7.2 [Tier 2 OBU Peers](#72-tier-2-obu-peers)
   - 7.3 [Trust Update Rules](#73-trust-update-rules)
   - 7.4 [The Active Peer Set — Pactive](#74-the-active-peer-set--pactive)
   - 7.5 [Peer Eligibility Conditions (Eq. 3.40)](#75-peer-eligibility-conditions-eq-340)
   - 7.6 [Bootstrap Phase](#76-bootstrap-phase)
8. [Data Structures — Every Struct Explained](#8-data-structures--every-struct-explained)
   - 8.1 [TrustRecord](#81-trustrecord)
   - 8.2 [ControllerTrustRecord](#82-controllertrustrecord)
   - 8.3 [BeaconEvidenceRecord (Flow 1)](#83-beaconevidencerecord-flow-1)
   - 8.4 [DetectionEvent (Flow 2)](#84-detectionevent-flow-2)
   - 8.5 [ControllerTopologyClaim (Flow 3)](#85-controllerlogyclaim-flow-3)
   - 8.6 [MitigationLogEntry](#86-mitigationlogentry)
   - 8.7 [AnchorCheckpoint](#87-anchorcheckpoint)
   - 8.8 [PendingFlowMod](#88-pendingflowmod)
   - 8.9 [ReauthFlag, BlacklistBeacon, ControllerRevokedBeacon](#89-reauthflag-blacklistbeacon-controllerrevokedbeacon)
   - 8.10 [RSUZoneReassignment](#810-rsuzoneareassignment)
9. [Ledger Key Namespace — Complete Reference](#9-ledger-key-namespace--complete-reference)
10. [Three Data Flows Into the Blockchain](#10-three-data-flows-into-the-blockchain)
    - 10.1 [Flow 1 — Beacon Evidence (SubmitBeaconEvidence)](#101-flow-1--beacon-evidence-submitbeaconevidence)
    - 10.2 [Flow 2 — Detection Events (SubmitDetectionEvent)](#102-flow-2--detection-events-submitdetectionevent)
    - 10.3 [Flow 3 — Controller Topology Claim (SubmitControllerTopology)](#103-flow-3--controller-topology-claim-submitcontrollertopology)
11. [Algorithm 4 — FS-MITIGATE: The Heart of the System](#11-algorithm-4--fs-mitigate-the-heart-of-the-system)
    - 11.1 [Entry Points That Call runMitigation](#111-entry-points-that-call-runmitigation)
    - 11.2 [runMitigation — Step by Step](#112-runmitigation--step-by-step)
    - 11.3 [TTW and BSHH Variant — Full Action Sequence](#113-ttw-and-bshh-variant--full-action-sequence)
    - 11.4 [ME Variant — Path Invalidation](#114-me-variant--path-invalidation)
    - 11.5 [CTRL_ORIGIN Variant — Controller Removal](#115-ctrl_origin-variant--controller-removal)
    - 11.6 [Honest Peer Rewards](#116-honest-peer-rewards)
    - 11.7 [Mode-Conditional FlowMods — The No-RSU Rule](#117-mode-conditional-flowmods--the-no-rsu-rule)
12. [Controller Divergence Detection](#12-controller-divergence-detection)
13. [Controller Removal — Full Process](#13-controller-removal--full-process)
    - 13.1 [With-RSU Path](#131-with-rsu-path)
    - 13.2 [No-RSU Path (Three-Step Process)](#132-no-rsu-path-three-step-process)
14. [RSU Peer Demotion Pipeline (3-Stage)](#14-rsu-peer-demotion-pipeline-3-stage)
    - 14.1 [Three Triggers for Removal](#141-three-triggers-for-removal)
    - 14.2 [CA Certificate Revocation Pattern](#142-ca-certificate-revocation-pattern)
15. [RSU Zone Reassignment](#15-rsu-zone-reassignment)
16. [Anchor Checkpoint Protocol](#16-anchor-checkpoint-protocol)
    - 16.1 [With-RSU Mode](#161-with-rsu-mode)
    - 16.2 [No-RSU Mode — Bootstrap Deadlock Resolution](#162-no-rsu-mode--bootstrap-deadlock-resolution)
17. [FlowMod Enforcement Interface](#17-flowmod-enforcement-interface)
18. [Cryptography Layer](#18-cryptography-layer)
19. [Off-Chain Event Listener (eventListener.js)](#19-off-chain-event-listener-eventlistenerjs)
20. [submitToFabric.js — CLI Tool](#20-submittofabricjs--cli-tool)
21. [Constants Reference](#21-constants-reference)
22. [Complete Chaincode Function Index](#22-complete-chaincode-function-index)
23. [Complete Fabric Event Index](#23-complete-fabric-event-index)
24. [Walk-Through: A Full TTW Attack Detection Cycle](#24-walk-through-a-full-ttw-attack-detection-cycle)
25. [Walk-Through: No-RSU Scenario Startup](#25-walk-through-no-rsu-scenario-startup)
26. [Bugs Fixed During Development](#26-bugs-fixed-during-development)

---

## 1. What Problem Does the Blockchain Solve?

The NS-3 simulation detects three attack families (TTW, BSHH, ME) using the PEM layer (9 detection
signatures) and the TGN detector. Once an attack is detected, the system must:

1. **Record the alert immutably** — so it cannot be tampered with or denied later.
2. **Reach consensus** — multiple trusted nodes must agree before any enforcement action.
3. **Enforce isolation** — block the attacker from the network.
4. **Audit the decision** — every action is permanently logged on the ledger.

Without blockchain, a single node could raise false alerts, a malicious controller could ignore
alerts, or evidence could be deleted. The Hyperledger Fabric blockchain provides:

- **Immutability** — once written, ledger records cannot be changed
- **Decentralised trust** — no single node can unilaterally trigger enforcement
- **PBFT consensus** — weighted agreement across trusted RSU peers
- **Smart contract logic** — Algorithm 4 (FS-MITIGATE) runs deterministically on-chain

---

## 2. What Is Hyperledger Fabric?

Hyperledger Fabric is a permissioned blockchain platform — unlike public blockchains (Bitcoin,
Ethereum), every participant is known and enrolled via a Certificate Authority (CA).

Key concepts relevant to this project:

| Concept | What it means here |
|---|---|
| **Peer** | A node that holds a copy of the ledger and runs chaincode. Here: RSU peers (rsu1–rsu5) and OBU peers. |
| **Chaincode** | Smart contract code deployed on peers. Here: `TemporalEchoMitigator` (Go). |
| **Channel** | A private sub-network. Here: `teta-channel`. All peers join this channel. |
| **Ledger** | Two parts: the blockchain (append-only transaction log) + world state (CouchDB key-value database). |
| **Transaction** | A chaincode function call that reads/writes the ledger. Endorsed by peers, ordered, then committed. |
| **Event** | Chaincode can emit named events. Off-chain listeners (eventListener.js) receive them. |
| **MSP** | Membership Service Provider — manages identities and certificates. |
| **Wallet** | Local storage of your enrolled identity (cert + private key) used by SDK clients. |

**Why Fabric and not Ethereum?**
- No transaction fees (no gas)
- Deterministic execution (important for automotive safety)
- Pluggable consensus — we implement our own trust-weighted PBFT
- Private data with known participants

---

## 3. System Architecture — How All Layers Connect

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           NS-3 Simulation Layer                              │
│                                                                              │
│  [Vehicle OBUs] ──DSRC 802.11p──► [RSU Nodes] ──CSMA/UDP──► [SDN Ctrl]     │
│                                                                              │
│  routing.cc:                                                                 │
│    PEM 9-signature detector fires                                            │
│    TGN (GNN) detector computes ŷ_v                                           │
│    Writes tgn_alerts.json when ŷ_v > 0.12                                   │
└────────────────────────────────┬─────────────────────────────────────────────┘
                                 │  submit_alerts.py polls tgn_alerts.json
                                 │  pem_to_alerts.py converts PEM output
                                 ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                      Hyperledger Fabric Blockchain Layer                     │
│                                                                              │
│  TemporalEchoMitigator Smart Contract  (temporalecho chaincode)             │
│                                                                              │
│  Flow 1: SubmitBeaconEvidence     ← ground-truth B_nk(t) from RSU/OBU      │
│  Flow 2: SubmitDetectionEvent     ← individual detection alert O_rk         │
│  Flow 3: SubmitControllerTopology ← G_t^C + divergence check               │
│                                                                              │
│  SubmitAlert / SubmitLWDetectionResult / Mitigate                           │
│    → runMitigation (Algorithm 4 FS-MITIGATE)                                │
│      → PBFT trust-weighted consensus gate (>2/3 by weight)                 │
│      → per-variant enforcement (TTW/BSHH/ME/CTRL_ORIGIN)                   │
│      → PendingFlowMod written to ledger                                     │
│      → BlacklistBeacon / ControllerRevokedBeacon published                  │
│      → peer trust rewards/penalties applied                                 │
│                                                                              │
│  Ledger (CouchDB): BEACON:*, DETECTION:*, TRUST:*, ANCHOR:*, MITIG:*, …    │
└────────────────────────────────┬─────────────────────────────────────────────┘
                                 │  Fabric chaincode events (contract listener)
                                 ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Off-Chain Event Listener (Node.js)                       │
│                         blockchain/client/eventListener.js                   │
│                                                                              │
│  AttackDetected    → read PendingFlowMod → POST to Ryu SDN agent (HTTP)     │
│  KeyRevocation     → write revoked_keys.json                                │
│  ControllerRemoved → action zone southbound switch reassignment             │
│  BlacklistBeacon   → write /tmp/blacklist_vehicle_ids.txt (NS-3 IPC)        │
│  PeerQuarantined / PeerRemoved → operator alerts                            │
│  CertRevocationRequested       → CA call to revoke peer certificate         │
└────────────────────────────────┬─────────────────────────────────────────────┘
                                 │
                                 ▼
                     [Ryu SDN OpenFlow Controller]
                     POST /stats/flowentry/add  → DROP / REROUTE / OVERRIDE
                     POST /stats/flowentry/delete → DELETE (post re-auth)
```

**The key insight:** Chaincode cannot make HTTP calls (it runs in a sandboxed container). So the
chaincode writes `PendingFlowMod` records to the ledger, and eventListener.js reads these and
executes the actual HTTP POST to Ryu off-chain.

---

## 4. File Structure

```
blockchain/
├── chaincode/temporalecho/
│   ├── temporalecho.go       ← Smart contract entry points + runMitigation
│   ├── trust.go              ← Trust scores, peer selection, PBFT, controller removal
│   ├── anchor.go             ← Anchor checkpoint protocol
│   ├── divergence.go         ← Controller topology divergence detection
│   ├── flowmod.go            ← FlowMod record writing (ledger side only)
│   ├── structs.go            ← All data structures and ledger key scheme
│   ├── verification.go       ← Sig verification helpers, loadFloatParam, haversine
│   ├── verification_stub.go  ← Simulation: HMAC-SHA256 (build without liboqs)
│   └── verification_liboqs.go ← Production: real Falcon-1024 (build -tags liboqs)
├── client/
│   ├── eventListener.js      ← Node.js event listener + FlowMod HTTP executor
│   └── submitToFabric.js     ← CLI tool for manual alert submission
├── network/
│   ├── docker-compose-teta.yaml ← Fabric network (peers, orderer, CA, CouchDB)
│   ├── configtx.yaml            ← Channel and policy configuration
│   ├── crypto-config.yaml       ← MSP certificate generation
│   └── bootstrap.sh             ← Bring-up script (generates certs, starts network)
└── scripts/
    ├── deploy_chaincode.sh   ← Package → install → approve → commit chaincode lifecycle
    └── create_channel.sh     ← Channel creation
```

---

## 5. Core Concepts You Must Understand First

### 5.1 Fabric Peers, Channels, and Chaincode

In this project, "peer" means a Fabric peer node — not a vehicle. There are two kinds:

- **RSU Fabric peers** (`peer0.rsu1.tetaguard.net` through `peer0.rsu5.tetaguard.net`): these run
  on RSU hardware. Their `IsRSUPeer = true` in their TrustRecord. Initial trust score τk = 1.0.
- **OBU Fabric peers**: run on vehicle On-Board Units. `IsRSUPeer = false`. Initial τk = 0.10.

All peers join `teta-channel`. The `temporalecho` chaincode runs on every peer. When a client
submits a transaction, endorsing peers each execute the chaincode, compare results, and if they
match, the transaction is committed to the ledger.

### 5.2 The Ledger and State Database (CouchDB)

The world state (current values) is stored in CouchDB. Each key holds a JSON document. Chaincode
reads/writes via `ctx.GetStub().GetState(key)` and `ctx.GetStub().PutState(key, data)`.

Rich queries use CouchDB Mango syntax:
```go
qs := `{"selector":{"doc_type":"TRUST_RECORD","is_rsu_peer":true}}`
iter, _ := ctx.GetStub().GetQueryResult(qs)
```

The append-only blockchain log records every transaction permanently (cannot be deleted).

### 5.3 Fabric Events

Chaincode emits named events:
```go
ctx.GetStub().SetEvent("AttackDetected", payloadBytes)
```

eventListener.js receives these in real time via the Fabric contract listener. Each event
triggers a specific action (FlowMod POST, file write, operator alert, etc.).

### 5.4 PBFT Consensus in This Project

Standard Fabric consensus is Raft (ordering service level). This project adds an **application-level
trust-weighted PBFT gate** inside chaincode, implemented via `checkPBFTTrustWeight`:

```
Consensus passes ⟺  Σ τk(approving peers) / Σ τk(all active peers)  >  2/3
```

This is more stringent than a simple majority. A peer with τk = 0.05 barely contributes even if it
approves. A peer with τk = 1.0 carries 20× more weight. If consensus does not pass, `runMitigation`
aborts — no enforcement action fires.

---

## 6. Two Deployment Modes: With-RSU and No-RSU

This is the most important architectural concept for understanding the code. Every major function
checks which mode is active.

| Aspect | With-RSU (NS-3: N_RSUs > 0) | No-RSU (NS-3: N_RSUs = 0) |
|---|---|---|
| Fabric peer pool | RSU peers (IsRSUPeer=true) drive everything | OBU peers only |
| Pactive composition | RSU peers + eligible OBUs | OBU peers only |
| Trust round driver | Tier 1 RSU peer (τk ≥ 1.0) | Highest-trust OBU above TrustMin |
| Anchor checkpoint creator | Tier 1 RSU (τk ≥ 1.0) | OBU with τk ≥ TrustMinGT (0.50) |
| OpenFlow switches present? | Yes — RSU runs Ryu agent | No — no OpenFlow infrastructure |
| DROP FlowMod | Sent to Ryu | Skipped (logs FLOWMOD_DROP_SKIPPED_NO_RSU) |
| REROUTE FlowMod | Sent to Ryu | Skipped |
| OVERRIDE FlowMod | Sent to Ryu | Skipped |
| Primary isolation | OpenFlow DROP rule | Blacklist beacon + OBU V2V propagation |
| Controller removal | RSU emergency channel | OBU V2V + ControllerRevokedBeacon + Ck* solicits |
| Bootstrap duration | Immediate (RSU starts at τ=1.0) | ⌈(0.50-0.10)/0.05⌉ = 8 correct rounds |
| Scenarios | 2, 4, 6, 8, 10, 12 (even IDs) | 1, 3, 5, 7, 9, 11 (odd IDs) |

**The ledger key `SIM_NO_RSU_MODE`** controls this. Set via:
```go
SetSimParams(rCommMetersStr, rssiMinDBmStr, noRSUModeStr)
// noRSUModeStr = "1" for no-RSU; "0" for with-RSU
```

**Critical code note:** `selectPeers` reads this ledger key — it does NOT infer from peer
existence. This is because RSU Docker containers always exist as Fabric infrastructure regardless
of NS-3 scenario type, so peer-existence detection would always find RSU peers and always think
it's with-RSU mode. The ledger flag is the authoritative source.

---

## 7. Peer Tiers and Trust Score System

### 7.1 Tier 1 RSU Peers

Registered via `RegisterRSUPeer(ctx, peerID)`:
- Initial score: `TrustInitTier1 = 1.0`
- `IsRSUPeer = true`
- Can create anchor checkpoints
- Can drive trust rounds (`UpdateTrustRound`)
- Can call `ZeroTrust` and `DemotePeerToClient`
- Can submit `SubmitLWDetectionResult`
- Always eligible for Pactive (skip HW/dwell checks)

### 7.2 Tier 2 OBU Peers

Registered via `RegisterOBUPeer(ctx, peerID, joinedAtMsStr, hwCapacityMBStr, hwStorageGBStr)`:
- Initial score: `TrustInitTier2 = 0.10`
- `IsRSUPeer = false`
- Must meet all five eligibility conditions before joining Pactive
- Trust accumulates via UpdateTrustRound (8 correct rounds to reach TrustMinGT)

### 7.3 Trust Update Rules

| Event | Change | Code |
|---|---|---|
| Correct round participation | +0.05 (capped at 1.0) | `updateTrust(ctx, pid, true, false)` |
| Missed/inconsistent round | -0.10 (floor 0.0) | `updateTrust(ctx, pid, false, false)` |
| Confirmed attack (OBU/vehicle) | 0.0 immediately, Flagged=true | `updateTrust(ctx, vid, false, true)` |
| Confirmed attack (RSU peer) | Stage 1 demotion pipeline | `demotePeerToClient(ctx, pid)` |
| Controller divergence confirmed | -0.20 (floor 0.0) | `updateCtrlTrust(ctx, ctrlID)` |

The difference between RSU peers and OBU peers on attack detection is intentional: RSU peers are
critical infrastructure and go through a supervised 30-second monitoring window before permanent
removal. OBU/vehicle trust is zeroed immediately because vehicles are the direct attacker nodes
in most scenarios.

### 7.4 The Active Peer Set — Pactive

`selectPeers` computes Pactive = top-np peers ranked by trust score, from the set of eligible peers.

```
np = NpConsensus = 8  (supports f=2 Byzantine faults: np ≥ 3f+1 = 7)
```

The active set is recomputed every beacon interval by `PeriodicPeerReSelection`. The result is
persisted to `ACTIVE_PEER_SET` on the ledger so membership changes (promotions, de-listings) can
be detected and emitted as events.

### 7.5 Peer Eligibility Conditions (Eq. 3.40)

For OBU peers, five conditions must ALL pass:

| # | Condition | Check | No-RSU bypass? |
|---|---|---|---|
| 1 | Valid cert / not flagged | `!r.Flagged && r.Score >= TrustMin` | No — always enforced |
| 2 | HW capacity ≥ Cmin RAM (2048 MB) | `r.HWCapacity >= HWCapacityMinMB` | Yes — bypassed |
| 3 | Dwell time ≥ Tmin | `now - r.JoinedAtMs >= tMinMs` | Yes — bypassed |
| 4 | τk ≥ TrustMin (0.10) | `r.Score >= TrustMin` | No — always enforced |
| 5 | Not in demotion pipeline | `state != QUARANTINED && != REMOVED` | No — always enforced |

Plus one additional gate that is **NOT** one of Eq. 3.40's five conditions (this is a common point
of confusion):

| Gate | Condition | Source | No-RSU bypass? |
|---|---|---|---|
| Checkpoint-sync | `obuHasSyncedFromRecentCheckpoint(ctx, pid)` | §5.1 anchor-checkpoint protocol | No — always enforced |

Conditions 2 and 3 are bypassed in no-RSU mode because the lightweight OBU hardware deployment
that characterises no-RSU scenarios would otherwise prevent any peer from ever joining consensus.

RSU peers skip all OBU checks — they are always eligible if unflagged.

### 7.6 Bootstrap Phase

Bootstrap is complete when `count(peers with τk ≥ TrustMinGT=0.50 and !Flagged) ≥ np=8`.

During bootstrap:
- `SubmitBeaconEvidence` is accepted at the lower TrustMin floor (0.10)
- Evidence is stored on ledger but NOT used for ground-truth divergence checks
- `runMitigation` logs `BOOTSTRAP_PRELIMINARY_NO_ENFORCEMENT` and skips ALL enforcement
- This prevents false mitigations before sufficient trust is established

In no-RSU mode, an OBU starts at τ=0.10 and needs ⌈(0.50-0.10)/0.05⌉ = **8 correct consecutive
rounds** to reach τ=0.50. Then 8 such OBUs must qualify before bootstrap completes.

---

## 8. Data Structures — Every Struct Explained

All structs are defined in `structs.go`. The `doc_type` field in every struct enables CouchDB
rich queries — without it, selectors cannot distinguish between different record types.

### 8.1 TrustRecord

Stored at `TRUST:<peer_id>`. Tracks τk for a Fabric peer (RSU or OBU).

```go
type TrustRecord struct {
    PeerID      string    // "peer0.rsu1.tetaguard.net"
    Score       float64   // τk ∈ [0.0, 1.0]
    IsRSUPeer   bool      // true = Tier 1 (RSU)
    ZoneID      string    // geographic zone (RSU only; set via SetRSUZone)
    Flagged     bool      // true = confirmed attack or demotion initiated
    FlaggedAt   int64     // ms timestamp when flagged
    UpdatedAt   int64     // ms timestamp of last update
    JoinedAtMs  int64     // when OBU first entered RSU coverage (dwell tracking)
    HWCapacity  int       // RAM in MB (0 = not declared / RSU)
    HWStorageGB int       // Storage in GB (0 = not declared / RSU)
    State       PeerState // "ACTIVE" | "QUARANTINED_CLIENT" | "REMOVED"
    DemotedAt   int64     // when Stage 1 demotion happened (for 30s monitoring)
    DocType     string    // "TRUST_RECORD"
}
```

**Why `ZoneID` on TrustRecord?** RSU peers cover a geographic zone. When an RSU is detected as
malicious, the zone needs coverage reassignment. The zone ID is stored here so `triggerRSUZoneReassignment`
can look up which zone to reassign without a separate query.

### 8.2 ControllerTrustRecord

Stored at `CTRL_TRUST:<controller_id>`. Separate from TrustRecord — controllers are not Fabric
peers; they are SDN network entities.

```go
type ControllerTrustRecord struct {
    ControllerID    string  // "ctrl0"
    Score           float64 // τCj ∈ [0.0, 1.0]; starts at 1.0; penalty-only (no reward)
    ZoneID          string  // which physical zone this controller manages
    DivergenceCount int     // total confirmed divergences
    UpdatedAt       int64
    DocType         string  // "CTRL_TRUST_RECORD"
}
```

### 8.3 BeaconEvidenceRecord (Flow 1)

Stored at `BEACON:<peer_id>:<interval_ts>`. Ground-truth vehicle observations.

```go
type BeaconEvidenceRecord struct {
    PeerID       string               // submitting peer (RSU or OBU)
    IntervalTS   int64                // beacon interval timestamp (ms)
    Observations []VehicleObservation // what vehicles the peer observed this interval
    PeerSig      []byte               // Falcon-1024 signature over the JSON
    PeerPubKey   []byte               // corresponding public key
    IsRSUPeer    bool                 // copied from TrustRecord at submission time
    DocType      string               // "BEACON_EVIDENCE"
}

type VehicleObservation struct {
    VehicleID         string   // "v001"
    SenderTSMs        int64    // timestamp in the vehicle's DSRC beacon
    GPSLat, GPSLon   float64  // GPS position
    RSSIdBm           float32  // signal strength from this vehicle
    NeighbourVehicles []string // V2V HELLO-confirmed neighbours (D-1 method)
}
```

The `NeighbourVehicles` list is the primary input for divergence detection. When a vehicle's
HELLO-confirmed neighbours do not match what the controller claims, it is a sign of topology
poisoning.

### 8.4 DetectionEvent (Flow 2)

Stored at `DETECTION:<peer_id>:<vehicle_id>:<ts>`. One alert per attacker vehicle.

```go
type DetectionEvent struct {
    PeerID        string  // which peer submitted this alert
    VehicleID     string  // the accused attacker vehicle
    AttackVariant string  // "TTW" | "BSHH" | "ME" | "CTRL_ORIGIN"
    AnomalyScore  float32 // ŷ_v (TGN output) or s(e) (PEM score)
    TriggeredSigs uint32  // 9-bit bitmask — which of the 9 PEM signatures fired
    AlertTS       int64   // ms timestamp of the alert
    FromLWPath    bool    // true = came from SubmitLWDetectionResult (PEM/RSU hardware)
    FromFSPath    bool    // true = came from SubmitAlert (TGN/full-stack)
    PeerSig       []byte
    DocType       string  // "DETECTION_EVENT"
}
```

### 8.5 ControllerTopologyClaim (Flow 3)

Stored at `CTRL_TOPO:<controller_id>:<ts>`. The controller's claimed view of the network topology.
**This is treated as untrusted input** — it is stored then compared against beacon evidence.

```go
type ControllerTopologyClaim struct {
    ControllerID string         // which controller submitted this
    IntervalTS   int64
    Links        []TopologyLink // {NodeA, NodeB, TS_ms}
    CtrlSig      []byte         // controller's own signature (treated as untrusted)
    DocType      string         // "CTRL_TOPOLOGY"
}
```

### 8.6 MitigationLogEntry

Stored at `MITIG:<entry_id>`. Immutable audit record of what Algorithm 4 did.

```go
type MitigationLogEntry struct {
    EntryID        string   // UUID derived from TxID+counter (deterministic, unique)
    VehicleID      string   // attacker vehicle or controller ID
    AttackVariant  string   // "TTW", "BSHH", "ME", "CTRL_ORIGIN"
    AnomalyScore   float32
    AlertTS        int64
    Actions        []string // e.g. ["FLOWMOD_DROP","KEY_REVOKED","BLACKLIST_BEACON_PUBLISHED"]
    ConsensusRound int      // ANCHOR_CTR value at time of mitigation
    DocType        string   // "MITIGATION_LOG"
}
```

The `Actions` slice is the audit trail. Every step inside `runMitigation` appends a string to it,
so you can reconstruct exactly what happened and why.

### 8.7 AnchorCheckpoint

Stored at `ANCHOR:<block_height>`. PBFT-signed ledger digest.

```go
type AnchorCheckpoint struct {
    CheckpointID   string   // TxID of the creation transaction
    BlockHeight    uint64   // monotonic counter from ANCHOR_CTR
    StateRootHash  string   // SHA-256(TxID || channelID || blockHeight) — deterministic
    CreatedByPeer  string   // who created it (Tier 1 RSU or qualified OBU in no-RSU)
    PeerSig        []byte   // Falcon-1024 over "createdByPeer:blockHeight:stateRoot"
    PeerPubKey     []byte
    CreatedAtMs    int64    // wall-clock metadata only (NOT part of hash)
    IntervalBlocks int      // ⌊Tmin/Tb⌋ — how often checkpoints are created
    SyncedPeers    []string // OBU peer IDs that confirmed sync
    DocType        string   // "ANCHOR_CHECKPOINT"
}
```

**Key design decision (AN-01):** The ledger key uses `BlockHeight` (deterministic), not wall-clock
time. Two endorsing peers creating a checkpoint at slightly different wall-clock times would write
to different keys, causing Fabric MVCC phantom-read conflicts. Using the monotonic counter (which
all endorsers increment in the same transaction) produces identical keys.

### 8.8 PendingFlowMod

Stored at `FLOWMOD_<TYPE>_<vid>_<ms>`. The instruction for eventListener.js to execute.

```go
type PendingFlowMod struct {
    EntryID      string
    VehicleID    string
    Action       string                   // "DROP" | "REROUTE" | "OVERRIDE" | "DELETE"
    Priority     int                      // 65000=DROP, 50000=REROUTE, 65535/65534=OVERRIDE
    Match        map[string]interface{}   // e.g. {"eth_src": "02:00:00:00:00:01"}
    FlowActions  []map[string]interface{} // empty for DROP; route for REROUTE
    Executed     bool                     // set to true by AcknowledgeFlowMod
    ExecutedAtMs int64
    DocType      string                   // "PENDING_FLOWMOD"
}
```

### 8.9 ReauthFlag, BlacklistBeacon, ControllerRevokedBeacon

**`ReauthFlag`** (`REAUTH:<vehicle_id>`): blocks a vehicle from rejoining until re-authentication.
Only written for TTW/BSHH/ME variants — NOT for CTRL_ORIGIN (controller re-admission uses
`RegisterController`, not the vehicle re-auth flow).

**`BlacklistBeacon`** (`BLACKLIST_BEACON:<vehicle_id>`): revocation fingerprint published when a
vehicle is permanently isolated. In no-RSU mode, this is the primary isolation mechanism.
eventListener.js writes the vehicle ID to `/tmp/blacklist_vehicle_ids.txt`, which NS-3 polls
every 1 second via `ReadBlacklistFile()`.

**`ControllerRevokedBeacon`** (`CTRL_REVOKED_BEACON:<controller_id>`): published when a controller
is removed. Contains:
```go
type ControllerRevokedBeacon struct {
    ControllerID             string
    BackupCtrlID             string
    PublishedAtMs            int64
    PublisherPeerID          string
    InterimFallbackIntervals int    // ⌈Llink/Tb⌉ — routing degradation window
    DocType                  string
}
```
`InterimFallbackIntervals = ⌈(2·rComm/vMax)/Tb⌉` — computed from SIM_RCOMM and SIM_VMAX_KMH.
This tells the network how long to run in degraded (distributed) routing mode while Ck* accumulates
enough topology observations.

### 8.10 RSUZoneReassignment

Stored at `RSU_ZONE_REASSIGN:<rsu_id>:<ts>`. Written in parallel with RSU demotion when a
malicious RSU's geographic zone needs a new coverage controller.

```go
type RSUZoneReassignment struct {
    CompromisedRSUID string
    ZoneID           string   // zone the malicious RSU was covering
    BackupCtrlID     string   // controller taking over partial coverage
    BackupCtrlScore  float64
    AssignedAtMs     int64
    DocType          string   // "RSU_ZONE_REASSIGNMENT"
}
```

---

## 9. Ledger Key Namespace — Complete Reference

| Key pattern | Struct | Purpose |
|---|---|---|
| `TRUST:<peer_id>` | TrustRecord | τk for every Fabric peer |
| `CTRL_TRUST:<ctrl_id>` | ControllerTrustRecord | τCj for every SDN controller |
| `CTRL_REGISTRY` | `[]string` | List of all registered controller IDs |
| `BEACON:<peer_id>:<interval_ts>` | BeaconEvidenceRecord | Ground-truth observations (Flow 1) |
| `DETECTION:<peer_id>:<vid>:<ts>` | DetectionEvent | Per-alert detection records (Flow 2) |
| `DETECTION:LW:<peer_id>:<vid>:<ts>` | DetectionEvent | LW-path alerts |
| `CTRL_TOPO:<ctrl_id>:<ts>` | ControllerTopologyClaim | Controller topology claim (Flow 3) |
| `MITIG:<entry_id>` | MitigationLogEntry | Immutable Algorithm 4 audit log |
| `REAUTH:<vehicle_id>` | ReauthFlag | Re-authentication block (NOT for CTRL_ORIGIN) |
| `SIG_EVIDENCE:<vid>:<ts>:<signer_id>` | IndividualSigEvidence | Threshold sig evidence (TTW/BSHH) |
| `WITNESS:<vid>:<ts>:<reporter_id>` | WitnessRecord | ME quorum witness records |
| `VMAC_<vehicle_id>` | raw string | Vehicle MAC address (for FlowMod match field) |
| `ANCHOR:<block_height>` | AnchorCheckpoint | PBFT-signed ledger digest |
| `ANCHOR_CTR` | uint64 string | Monotonic block counter (AN-01) |
| `PEERKEY:<peer_id>` | raw bytes | Falcon-1024 public key |
| `BLACKLIST_BEACON:<vid>` | BlacklistBeacon | Vehicle revocation fingerprint |
| `CTRL_REVOKED_BEACON:<ctrl_id>` | ControllerRevokedBeacon | Controller removal beacon |
| `CTRL_REASSIGN:<ctrl_id>:<ts>` | ControllerReassignment | Controller reassignment record |
| `CTRL_REVOKED:<ctrl_id>` | raw JSON | Controller credential revocation marker |
| `CERT_REVOKED:<id>` | raw JSON | CA cert revocation marker (peer, controller, or vehicle) |
| `RSU_ZONE_REASSIGN:<rsu_id>:<ts>` | RSUZoneReassignment | RSU zone handoff record |
| `FALSE_PATHS:<vid>` | raw JSON | Invalidated ME phantom paths |
| `ACTIVE_PEER_SET` | `[]string` | Current Pactive (persisted for event diff) |
| `SIM_RCOMM` | float64 string | DSRC communication range in metres (default 300) |
| `SIM_RSSI_MIN` | float64 string | Minimum RSSI in dBm (default -85) |
| `SIM_TPBFT_MS` | int64 string | PBFT round-trip latency in ms (default 100) |
| `SIM_VMAX_KMH` | float64 string | Maximum vehicle speed in km/h (default 80) |
| `SIM_NO_RSU_MODE` | "0" or "1" | No-RSU mode flag (set by SetSimParams) |
| `SIM_THETA_FS` | float64 string | θFS threshold (default 0.40, ledger-configurable) |
| `SIM_THETA_LW` | float64 string | θLW threshold (default 0.30, ledger-configurable) |

---

## 10. Three Data Flows Into the Blockchain

### 10.1 Flow 1 — Beacon Evidence (SubmitBeaconEvidence)

**Who calls it:** RSU Fabric peers (in with-RSU mode) or qualified OBU peers (in no-RSU mode).
**When:** Every beacon interval Tb = 100ms.
**What it stores:** `B_nk(t)` — the peer's observation of all visible vehicles this interval.

**Trust gate (two phases):**
```
if bootstrapDone:
    require IsRSUPeer OR τk ≥ TrustMinGT (0.50)
else (bootstrap):
    require τk ≥ TrustMin (0.10)
```

**Why this design?** During bootstrap, no peer has reached 0.50 yet, so using the stricter threshold
would prevent any evidence from being stored, and trust would never accumulate — deadlock.
`aggregateEvidenceLinkSet` independently enforces the stricter threshold when building the actual
ground-truth set, so bootstrap-phase evidence is safely stored but never misused.

**Signature verification:** `verifyFalcon1024Sig(record.PeerSig, evidenceJSON, record.PeerPubKey)`

### 10.2 Flow 2 — Detection Events (SubmitDetectionEvent)

Individual alert from any trusted peer. Signature verified against `PEERKEY:<peerID>`.
Stored at `DETECTION:<peer>:<vid>:<ts>`. Used to populate the `TriggeredSigs` bitmask in reports.

### 10.3 Flow 3 — Controller Topology Claim (SubmitControllerTopology)

The SDN controller submits its current view of the network as `G_t^C`. This is stored as an
**untrusted claim** and immediately triggers `checkControllerDivergence`.

The controller's claim is **never used as ground truth** — it is only compared against the
trusted beacon evidence to detect manipulation.

---

## 11. Algorithm 4 — FS-MITIGATE: The Heart of the System

Algorithm 4 (FS-MITIGATE) is the core of the smart contract. It makes the actual enforcement
decisions. It runs inside `runMitigation` in `temporalecho.go`.

### 11.1 Entry Points That Call runMitigation

| Entry Point | Who Calls It | θ Threshold |
|---|---|---|
| `SubmitAlert` | submit_alerts.py (after TGN fires) | θFS = 0.40 (ledger-configurable) |
| `SubmitLWDetectionResult` | RSU hardware running PEM 9-sig detection | θLW = 0.30 (ledger-configurable) |
| `Mitigate` | Node.js SDK directly (manual or batch) | caller-provided or ledger default |

Both θFS and θLW are calibration values marked as TBD in the thesis (Table 4.7). They are stored
in the ledger via `SetSimParams` so they can be tuned without redeploying chaincode.

### 11.2 runMitigation — Step by Step

```
Step 1: Collect approving peers from alerts (collectApprovingPeers)
        — these are the PeerID fields of the incoming alerts

Step 2: selectPeers(ctx, allPeerIDs) → Pactive
        — recomputes the active peer set at runtime

Step 3: checkPBFTTrustWeight(approving, active)
        — Σ τk(approving) / Σ τk(active) > 2/3?
        — if NO: return error, ABORT (no enforcement action fires)

Step 4: resolveDualPath(alerts)
        — if both LW and FS paths fired for the same vehicle,
          merge into one alert: FromLWPath=true, FromFSPath=true
          take higher anomaly score; merge TriggeredSigs bitmasks

Step 5: isBootstrapComplete?
        — if NOT complete: log BOOTSTRAP_PRELIMINARY_NO_ENFORCEMENT, skip all enforcement

Step 6: Read ANCHOR_CTR → ConsensusRound (ST-02 audit tracking)

Step 7: For each alert where score > θ (or variant == "CTRL_ORIGIN"):
        — Build MitigationLogEntry (EntryID from generateUUID)
        — Read SIM_NO_RSU_MODE → isNoRSU flag
        — Switch on variant: TTW/BSHH, ME, or CTRL_ORIGIN
        — Apply variant-specific enforcement (see sections 11.3–11.5)
        — commitLog(ctx, logEntry)
        — SetEvent("AttackDetected", payload)

Step 8: Reward honest peers (TE-07)
        — for each pid in Pactive where pid ∉ attackerSet:
          updateTrust(ctx, pid, correct=true, zero=false) → τk += 0.05

Step 9: Supervisor feedback — re-evaluate QUARANTINED peers
        — for each peer in QUARANTINED state: monitorAndRemovePeer
```

### 11.3 TTW and BSHH Variant — Full Action Sequence

When `variant == "TTW"` or `"BSHH"` or `"TTW_BSHH_COMBINED"`:

```
1. getSignatureEvidence(vid, alertTS)
   — CouchDB query for SIG_EVIDENCE:<vid>:* in window [alertTS-100ms, alertTS+100ms]
   
2. verifyThresholdSig(evidence, thresholdT = n/2+1)
   — verify each Falcon-1024 signature in evidence
   — count valid sigs; must be ≥ thresholdT
   — if FAIL: log THRESHOLD_SIG_FAIL, continue (no enforcement for this alert)

3. if !isNoRSU: pushFlowModDrop(vid)
       → writes FLOWMOD_DROP_<vid>_<ms> to ledger
       → eventListener reads it, POSTs DROP rule to Ryu (priority 65000)
   else: log FLOWMOD_DROP_SKIPPED_NO_RSU

4. revokeSessionKey(vid)
   — emits "KeyRevocation" Fabric event
   — eventListener appends to revoked_keys.json

5. publishBlacklistBeacon(vid)
   — writes BLACKLIST_BEACON:<vid> to ledger
   — emits "BlacklistBeaconPublished" event
   — in no-RSU mode: this IS the primary isolation mechanism
   — eventListener writes /tmp/blacklist_vehicle_ids.txt for NS-3 IPC

6. revokeVehicleCert(vid)
   — writes CERT_REVOKED:<vid> to ledger
   — emits "VehicleCertRevocationRequested" event
   — eventListener actions the actual CA call off-chain

7. RSU-specific check (MUST happen BEFORE updateTrust):
   attackerTrust := loadTrust(ctx, vid)
   if attackerTrust.IsRSUPeer:
       triggerRSUZoneReassignment(ctx, vid, attackerTrust.ZoneID)
   — WHY BEFORE: demotePeerToClient (called by updateTrust with zero=true) clears
     IsRSUPeer. If this check ran AFTER updateTrust, IsRSUPeer would be false and
     zone reassignment would be silently skipped.

8. if variant != "CTRL_ORIGIN":  [always true here]
       flagReauth(ctx, vid, variant)
       — writes REAUTH:<vid> to ledger

9. if variant != "CTRL_ORIGIN":  [always true here]
       updateTrust(ctx, vid, false, true)
       — if IsRSUPeer: demotePeerToClient (3-stage pipeline)
       — if OBU/vehicle: τk = 0.0, Flagged = true (immediate)
```

### 11.4 ME Variant — Path Invalidation

When `variant == "ME"` (Multipath Echo attack):

```
1. getWitnesses(vid, alertTS)
   — CouchDB query for WITNESS:<vid>:* in window [alertTS±100ms]

2. getLinkEndpoint(vid) → (lat, lon)
   — finds the GPS position of this vehicle from beacon evidence

3. verifyQuorum(ctx, witnesses, thresholdT, lat, lon)
   — for each witness: verify Falcon-1024 sig
   — check: witness is within r_comm metres of link endpoint (from SIM_RCOMM)
   — check: witness RSSI >= rssiMin (from SIM_RSSI_MIN)
   — count valid witnesses; must be ≥ thresholdT
   — if FAIL: log QUORUM_FAIL, continue

4. invalidateFalsePaths(vid)
   — writes FALSE_PATHS:<vid> = {invalidated: true, invalidated_at: now}

5. if !isNoRSU: pushRerouteFlowMod(vid)
       → FLOWMOD_REROUTE_<vid>_<ms>, priority 50000, action DELETE existing routes
   else: log REROUTE_FLOWMOD_SKIPPED_NO_RSU

6. flagReauth(vid, "ME")  [vehicle must re-authenticate before rejoining]
7. updateTrust(vid, false, true)  [zero trust immediately]
```

### 11.5 CTRL_ORIGIN Variant — Controller Removal

When `variant == "CTRL_ORIGIN"` (malicious controller detected):

```
1. if !isNoRSU: pushFlowModOverride(ctrlID, beaconEvidence)
       — FLOWMOD_OVERRIDE_CTRL_<ctrl> at priority 65535 (catch-all override)
       — FLOWMOD_OVERRIDE_<vid> at priority 65534 for each vehicle
       — eventListener POSTs OVERRIDE rules to Ryu; these override the malicious
         controller's existing routes with trusted routes derived from beacon evidence
   else: log CTRL_OVERRIDE_FLOWMOD_SKIPPED_NO_RSU
   (Note: OVERRIDE FlowMod IS thesis-specified in Algorithm 4. The only gap vs. the
    thesis is the southbound-repoint: RSU agents physically switching TCP connection
    from Cj to Ck*. That requires live OpenFlow infrastructure outside NS-3 scope.)

2. [No flagReauth for CTRL_ORIGIN — controllers use RegisterController re-admission,
   not the vehicle re-authentication flow. Writing REAUTH:<ctrl_id> would pollute
   the ClearReauth audit trail with semantically wrong entries.]

3. [No updateTrust for CTRL_ORIGIN — controllers use updateCtrlTrust via
   CheckControllerTrustAndReassign. Calling updateTrust would apply a vehicle-level
   zero, not the controller penalty ΔC- = 0.20.]

4. CheckControllerTrustAndReassign(ctx, ctrlID, allCtrls)
   — updateCtrlTrust(ctx, ctrlID): τCj -= 0.20, floor 0.0
   — if τCj < TrustCtrlMin (0.30):
       selectBackupController → Ck* = argmax(τCk) where τCk > 0.30, k ≠ j
       write CTRL_REASSIGN:<ctrl>:<ts>
       write CTRL_REVOKED:<ctrl>
       emit ControllerCredentialRevocationRequested (→ CA call off-chain)
       emit ControllerRemoved (→ eventListener actions zone reassignment)
       publishControllerRevokedBeacon(ctrlID, backupID)
         → write CTRL_REVOKED_BEACON:<ctrl>
         → emit ControllerRevokedBeaconPublished
   — if no backup available:
       emit ControllerRemovalFailed (critical alert)

5. log "CTRL_TRUST_PENALISED_AND_CHECKED" or "CTRL_REASSIGN_FAIL:<reason>"
```

### 11.6 Honest Peer Rewards

After processing all alerts, every active peer that was NOT an attacker gets a trust reward:

```go
for _, pid := range activePeers {
    if !attackerSet[pid] {
        updateTrust(ctx, pid, true, false)  // τk += 0.05
    }
}
```

This ensures trust continues to grow for honest participants, which is required for OBU bootstrap.

### 11.7 Mode-Conditional FlowMods — The No-RSU Rule

The `isNoRSU` flag is read **once per alert, before the variant switch**:

```go
noRSUFlag, _ := ctx.GetStub().GetState("SIM_NO_RSU_MODE")
isNoRSU := string(noRSUFlag) == "1"
```

Then all three FlowMod calls use `!isNoRSU` as a gate:

| Variant | FlowMod type | With-RSU | No-RSU |
|---|---|---|---|
| TTW/BSHH | DROP (priority 65000) | ✓ sent to Ryu | FLOWMOD_DROP_SKIPPED_NO_RSU |
| ME | REROUTE (priority 50000) | ✓ sent to Ryu | REROUTE_FLOWMOD_SKIPPED_NO_RSU |
| CTRL_ORIGIN | OVERRIDE (priority 65535/65534) | ✓ sent to Ryu | CTRL_OVERRIDE_FLOWMOD_SKIPPED_NO_RSU |

In no-RSU mode, the blacklist beacon + CA cert revocation + OBU V2V propagation replaces
the OpenFlow DROP rule as the primary isolation mechanism.

---

## 12. Controller Divergence Detection

Implemented in `divergence.go`, triggered by `SubmitControllerTopology` (Flow 3).

**What it detects:** A malicious controller submitting a false view of network topology.

**How it works:**

```
G_t^C = what the controller claims (submitted via SubmitControllerTopology)
E_t^nodes = what the trusted peers actually observed (aggregated from beacon evidence)

δ = |G_t^C △ E_t^nodes|   (symmetric difference — links present in one but not the other)

δ_thresh = ⌈(1 + τprop/Tb) · λ̂ · 2·rComm⌉ + 1

where:
  τprop = propagation delay (from SIM_TPBFT_MS, default 100ms)
  Tb    = beacon interval = 100ms  → τprop/Tb ≈ 1  → multiplier ≈ 2
  λ̂     = estimated vehicle arrival rate = n_vehicles / (2·rComm)
  rComm = SIM_RCOMM (default 300m)

If δ > δ_thresh:
  Store DETECTION:DIVERGENCE:<ctrl>:<ts>
  Emit "ControllerOriginAttack" Fabric event
  [does NOT apply trust penalty — DV-03: penalty is runMitigation's exclusive job]
```

**Building E_t^nodes (aggregateEvidenceLinkSet):**

- **Primary method (D-1):** Uses `NeighbourVehicles` from `VehicleObservation` — HELLO-confirmed
  links (most accurate, no false positives).
- **Fallback (DV-01):** GPS proximity with half the communication range (150m) and mutual
  confirmation requirement — used only when no explicit neighbour data exists.
- **Trust filter (DV-04):** Only evidence from `τk ≥ TrustMinGT (0.50)` peers (or Tier 1 RSUs)
  contributes. Sub-threshold OBU evidence is excluded to prevent evidence poisoning.

**No-RSU limitation:** During bootstrap in no-RSU mode, all OBUs start at τ=0.10 (below 0.50).
The divergence check won't build a useful E_t^nodes until bootstrap completes. This is acceptable
because the NS-3 PEM layer independently detects attacks and submits alerts via `SubmitAlert`,
bypassing the divergence path entirely.

---

## 13. Controller Removal — Full Process

### 13.1 With-RSU Path

```
SubmitAlert detects CTRL_ORIGIN
  → runMitigation → CTRL_ORIGIN branch
      → pushFlowModOverride (OVERRIDE rules via RSU's Ryu agent)
      → CheckControllerTrustAndReassign:
          updateCtrlTrust → τCj -= 0.20
          if τCj < 0.30:
            selectBackupController → Ck* (highest τCk above 0.30)
            write CTRL_REASSIGN record
            write CTRL_REVOKED record
            emit ControllerCredentialRevocationRequested → off-chain CA revocation
            emit ControllerRemoved → eventListener.handleControllerRemoved
              → PUT request to RSU management API (RSU_MGMT_URLS)
              → RSU OpenFlow agents repoint southbound TCP to Ck*
            publishControllerRevokedBeacon
              → emit ControllerRevokedBeaconPublished
```

**Documented gap:** The thesis specifies RSU agents physically switching their southbound
connection from Cj to Ck* and Ck* receiving an instant topology snapshot from RSU beacon evidence.
This requires live OpenFlow controller infrastructure outside NS-3 scope. eventListener.js
calls the RSU management API, but the actual TCP repoint is simulated.

### 13.2 No-RSU Path (Three-Step Process)

```
Step i:   CA credential revocation
          → write CTRL_REVOKED:<ctrl> to ledger
          → emit ControllerCredentialRevocationRequested
          → Cj's CA certificate is revoked off-chain; Cj can no longer authenticate

Step ii:  ControllerRevokedBeacon propagation
          → write CTRL_REVOKED_BEACON:<ctrl> to ledger
          → InterimFallbackIntervals = ⌈(2·rComm/vMax) / Tb⌉
            = ⌈(2·300 / (80/3.6)) / 0.1⌉ = ⌈27s / 0.1s⌉ = 270 intervals
          → OBU peers read this beacon from ledger and distribute via V2V DSRC
          → Vehicles stop sending topology updates to Cj

Step iii: Ck* actively solicits topology from vehicles
          → direction: Ck* → vehicles (NOT vehicles → Ck*)
          → Ck* uses its own V2X interface to request observations
          → During InterimFallbackIntervals: routing falls back to distributed
            vehicle-level decisions (no centralised control)
          → After Ck* has sufficient observations: centralised routing resumes
```

**Why Ck* solicits from vehicles (not the other way)?** Without RSU beacon evidence, Ck* has
no topology knowledge when it takes over. It must actively pull observations from vehicles.
Vehicles don't know Ck* needs to bootstrap — Ck* must initiate.

---

## 14. RSU Peer Demotion Pipeline (3-Stage)

RSU peers are consortium infrastructure, so they get a supervised removal process rather than
immediate zeroing. OBU/vehicle peers are zeroed immediately.

```
ACTIVE ──(confirmed attack)──► QUARANTINED_CLIENT (Stage 1)
                                    │
                                    │  monitored every mitigation round +
                                    │  every PeriodicPeerReSelection call
                                    │  (third trigger: inside updateTrust on
                                    │   failed round for already-QUARANTINED peer)
                                    │
                               30 seconds elapsed AND τk ≤ TrustMin?
                                    │
                                    ▼
                                 REMOVED (Stage 3) ──► PeerRemoved event
```

**Stage 1 — `demotePeerToClient(ctx, peerID)`:**
- τk = 0.0
- Flagged = true
- State = QUARANTINED_CLIENT
- IsRSUPeer = false (stripped — important for RSU zone reassignment ordering)
- DemotedAt = now
- Emits `PeerQuarantined`

**Stage 2 — monitoring (`monitorAndRemovePeer`):**
- If `now - DemotedAt < 30000ms`: keep monitoring, return
- Trust cannot recover from 0.0 without explicit intervention

**Stage 3 — removal:**
- State = REMOVED
- Writes `CERT_REVOKED:<peer_id>` (thesis: removal includes CA cert revocation)
- Emits `PeerRemoved` with `cert_revoked: true`
- Emits separate `CertRevocationRequested` (for eventListener CA handler)

### 14.1 Three Triggers for Removal

The supervisor monitoring loop is called from three places:

1. **End of `runMitigation`**: after every mitigation execution, all QUARANTINED peers are checked.
2. **`PeriodicPeerReSelection`**: called every beacon interval by the client — re-evaluates all peers.
3. **Inside `updateTrust`**: when a trust penalty fires for a peer already in QUARANTINED state,
   `monitorAndRemovePeer` is called immediately. This handles the case where a quarantined peer
   continues to behave badly even during the monitoring window.

### 14.2 CA Certificate Revocation Pattern

Three actor types all follow the same pattern:

| Actor | Ledger key | Fabric event |
|---|---|---|
| RSU Fabric peer | `CERT_REVOKED:<peer_id>` | `CertRevocationRequested` |
| SDN Controller | `CERT_REVOKED:<ctrl_id>` (via `CTRL_REVOKED`) | `ControllerCredentialRevocationRequested` |
| Vehicle | `CERT_REVOKED:<vehicle_id>` | `VehicleCertRevocationRequested` |

The chaincode writes the ledger record and emits the event. The actual CA call (CRL update, OCSP)
happens off-chain in eventListener.js when it receives the corresponding event.

---

## 15. RSU Zone Reassignment

When an RSU Fabric peer is confirmed malicious (TTW or BSHH variant, with the attacker being
an RSU peer), two parallel actions fire:

1. **Consortium-peer role** (handled by `updateTrust` → `demotePeerToClient`): the RSU is
   removed from Pactive, its trust zeroed, its `IsRSUPeer` cleared.

2. **Data-plane role** (handled by `triggerRSUZoneReassignment`): the RSU's geographic coverage
   zone is handed to an adjacent trusted controller.

**Critical ordering:** RSU zone reassignment must read `IsRSUPeer` BEFORE `updateTrust` is called.
`demotePeerToClient` sets `IsRSUPeer = false`. If the check ran after `updateTrust`, the attacker
would look like a vehicle and zone reassignment would be silently skipped.

**Backup controller selection rule:**
```
1. First: find a controller with ZoneID matching the compromised RSU's ZoneID
   (zone-ID match = geographic adjacency proxy)
2. Fallback: highest-trust controller above TrustCtrlMin (0.30)
```

This selection rule is an **implementation design choice** for an underspecified thesis mechanism.
The thesis says "transfer rk's coverage to the adjacent trusted controller" without defining
adjacency. This is NOT the same as the `selectBackupController` function (Eq. 3.43 argmax logic)
used for controller removal — they are different mechanisms for different scenarios.

---

## 16. Anchor Checkpoint Protocol

OBU peers must sync from the latest anchor checkpoint before they can join Pactive (§5.1). This
ensures they have an up-to-date ledger view before voting in consensus rounds.

Checkpoints are produced every `⌊Tmin/Tb⌋` blocks:

| Scenario | Tmin | Interval |
|---|---|---|
| Urban (80 km/h, 300m rComm) | ≈27s | 270 blocks |
| Highway (120 km/h, 300m rComm) | ≈9s | 90 blocks |

`Tmin = max(3·TPBFT, Llink/2)` where `Llink = 2·rComm/vMax` (link lifetime estimate).

### 16.1 With-RSU Mode

- Creator: Tier 1 RSU peer (IsRSUPeer=true, τk ≥ 1.0)
- State root hash: `SHA-256(TxID || channelID || blockHeight)` — deterministic, no wall-clock
- Ledger key: `ANCHOR:<blockHeight>` (monotonic counter, not timestamp — AN-01 fix)

### 16.2 No-RSU Mode — Bootstrap Deadlock Resolution

**The problem:** OBUs need checkpoint-sync to join Pactive. Only RSU Tier 1 peers can create
checkpoints. But in no-RSU mode there are no RSU peers. Deadlock.

**Resolution (implementation design decision — thesis is silent on this):**
In no-RSU mode, an OBU with `τk ≥ TrustMinGT (0.50)` may create anchor checkpoints. This uses
the same evidence-quality threshold (0.50) as the rest of the no-RSU bootstrap.

Why 0.50 (TrustMinGT) and not 0.10 (TrustMin)?
- Anchor checkpoints are PBFT-signed state digests that every new peer bootstraps from
- Allowing a barely-admitted OBU (τ=0.10) to be the chain anchor would let a low-trust peer
  define the authoritative ledger state
- TrustMinGT = 0.50 matches the existing bar for submitting ground-truth evidence, which has
  comparable downstream trust-chain consequence

`SyncFromAnchorCheckpoint` mirrors this: in no-RSU mode, it verifies the creator had τk ≥ 0.50.

---

## 17. FlowMod Enforcement Interface

### Architecture

```
Chaincode (ledger side — deterministic)     Off-chain (eventListener.js — HTTP)
─────────────────────────────────────────   ────────────────────────────────────────
pushFlowModDrop(vid)                        "AttackDetected" event →
  PutState("FLOWMOD_DROP_<vid>_<ms>",         GetAllPendingFlowMods()
           PendingFlowMod{...})                find latest unexecuted for vehicle
                                              executeParsedFlowMod → POST to Ryu
                                              AcknowledgeFlowMod(entryID)
```

### Four FlowMod Types

| Function | Action | Ryu Endpoint | Priority | Trigger |
|---|---|---|---|---|
| `pushFlowModDrop` | DROP all traffic from attacker MAC | `/stats/flowentry/add` | 65000 | TTW, BSHH (with-RSU only) |
| `pushRerouteFlowMod` | DELETE existing routes, force reroute | `/stats/flowentry/delete` | 50000 | ME (with-RSU only) |
| `pushFlowModOverride` | OVERRIDE with trusted routes (two rules) | `/stats/flowentry/add` | 65535 + 65534 | CTRL_ORIGIN (with-RSU only) |
| `ClearReauth` → DELETE | DELETE the DROP rule (re-admission) | `/stats/flowentry/delete` | 65000 | Post re-authentication |

**EntryID includes millisecond timestamp** (FM-02) to prevent key collision when the same vehicle
is attacked multiple times in the same session.

**Catch-up replay (T-2):** eventListener.js calls `GetAllPendingFlowMods()` at startup and
executes all unexecuted records. This ensures FlowMods are not lost during listener downtime.

### Adaptive FlowMod Timeout (EL-02)

The paper requires end-to-end FlowMod delivery within 100ms of alert creation. eventListener.js
measures how much of this budget Fabric already consumed:

```javascript
const elapsedMs = Date.now() - eventTimestampMs;
const flowModTimeout = Math.max(10, TOTAL_LATENCY_BUDGET_MS - elapsedMs - 5);
```

If Fabric event delivery consumed 60ms, only 35ms remains for the HTTP POST to Ryu.

---

## 18. Cryptography Layer

### Two Build Modes

| Build | File | Primitive | How to build |
|---|---|---|---|
| Simulation (default) | `verification_stub.go` | HMAC-SHA256 | `go build ./...` |
| Production | `verification_liboqs.go` | Real Falcon-1024 (FIPS 204 ML-DSA) | `go build -tags liboqs ./...` |

### Simulation Mode — HMAC-SHA256

```go
func SimSign(message string, pubKey []byte) []byte {
    if len(pubKey) == 0 { return []byte("SIM_NOSIG") }
    h := hmac.New(sha256.New, pubKey)
    h.Write([]byte(message))
    return h.Sum(nil)
}

func verifyFalcon1024Sig(sig []byte, message string, pubKey []byte) bool {
    if len(pubKey) == 0 { return len(sig) > 0 }  // bootstrap: accept any non-empty sig
    return hmac.Equal(sig, SimSign(message, pubKey))
}
```

**Bootstrap phase:** Before `RegisterPeerKey` is called, `pubKey` is nil — any non-empty
signature is accepted. After key registration, only the correct HMAC passes.

### Where Signatures Are Verified

| Function | What is signed |
|---|---|
| `SubmitBeaconEvidence` | Full `evidenceJSON` string |
| `SubmitDetectionEvent` | Full `eventJSON` string |
| `SubmitLWDetectionResult` | `"callerPeerID:vehicleID:score:variant:intervalTS"` |
| `SubmitIndividualSigEvidence` | `e.Message` field |
| `SubmitWitnessRecord` | `w.Message` field (optional — verified only if sig+key present) |
| `SyncFromAnchorCheckpoint` | `"createdByPeer:blockHeight:stateRoot"` |
| `CreateAnchorCheckpoint` | Same format (signing side) |

---

## 19. Off-Chain Event Listener (eventListener.js)

### Startup

```bash
node eventListener.js [--node_id peer0.rsu1.tetaguard.net] [--rsu_url http://ryu-rsu1:8080] \
                      [--no_rsu] [--interval_ms 100]
```

In no-RSU mode (`--no_rsu`), `SELECT_PEERS_POOL` switches from `RSU_PEERS` to `ALL_OBU_PEERS`.
The periodic `PeriodicPeerReSelection` call also uses this binary pool.

### Events Handled

| Event | Action |
|---|---|
| `AttackDetected` | `GetAllPendingFlowMods()` → find unexecuted → `executeParsedFlowMod` → POST Ryu → `AcknowledgeFlowMod` |
| `KeyRevocation` | Append `{vehicle_id, action: "REVOKE_SESSION_KEY"}` to `revoked_keys.json` |
| `ControllerOriginAttack` | Log + escalate to operator; trigger OVERRIDE FlowMods |
| `ControllerRemoved` | PUT to RSU management API (`RSU_MGMT_URLS`) for southbound switch reassignment |
| `ControllerRemovalFailed` | Critical alert: no backup controller available |
| `AnchorCheckpointCreated` | Log checkpoint for OBU sync coordination |
| `PeerQuarantined` | Operator alert + suspend RSU data relay functions |
| `PeerRemoved` | Operator alert (permanent) |
| `CertRevocationRequested` | Action CA call (off-chain) to revoke peer certificate |
| `VehicleCertRevocationRequested` | Action CA call (off-chain) to revoke vehicle certificate |
| `ControllerCredentialRevocationRequested` | Action CA call to revoke controller credentials |
| `BlacklistBeaconPublished` | Write vehicle ID to `/tmp/blacklist_vehicle_ids.txt` for NS-3 IPC |
| `ControllerRevokedBeaconPublished` | Log + notify backup controller to begin V2X solicitation |
| `RSUZoneReassignmentTriggered` | Log zone handoff details for operator |
| `PeerPromoted` | Log OBU entering active set |
| `PeerDroppedFromActive` | Log peer leaving active set |

### Per-RSU FlowMod URL Routing (E-2)

Each RSU runs its own Ryu agent. The listener maps peer IDs to URLs:

```javascript
const RSU_FLOWMOD_URLS = {
    'peer0.rsu1.tetaguard.net': process.env.RSU1_OPENFLOW_URL || 'http://ryu-rsu1:8080',
    'peer0.rsu2.tetaguard.net': process.env.RSU2_OPENFLOW_URL || 'http://ryu-rsu2:8080',
    // ...
};
```

### Periodic Trust Round Timer

Every 100ms (`intervalMs`), eventListener calls:

```javascript
await contract.submitTransaction('UpdateTrustRound', nodeID,
    JSON.stringify(participating), JSON.stringify(ALL_PEERS));
await contract.submitTransaction('PeriodicPeerReSelection',
    JSON.stringify(SELECT_PEERS_POOL));
await contract.submitTransaction('CreateAnchorCheckpoint',
    nodeID, intervalBlocks.toString());
```

`participating` simulates which peers sent beacons this interval (rsu5 absent every 5th round,
obu3 absent every 10th). Score table is printed every 10th round.

### NS-3 IPC — `/tmp/blacklist_vehicle_ids.txt`

When `BlacklistBeaconPublished` fires:
1. eventListener extracts numeric vehicle ID from `vehicle_id` field
2. Appends to `/tmp/blacklist_vehicle_ids.txt`
3. NS-3 `routing.cc` polls this file every 1 second via `ReadBlacklistFile()`
4. NS-3 broadcasts blacklist via `CustomBlacklistTag` over DSRC every 5 seconds
5. Receiving vehicles update `g_blacklisted_nodes` and drop all DSRC packets from those IDs

---

## 20. submitToFabric.js — CLI Tool

Manual alert submission tool. Used when `pem_to_alerts.py` cannot auto-submit.

```bash
node submitToFabric.js \
    --node_id peer0.rsu1.tetaguard.net \
    --vehicle_id v001 \
    --alpha TTW \
    --score 0.85 \
    --sigs 0,1,2 \
    --alert_ts 1709000000000 \
    [--no_rsu]           # switches to OBU peer pool
    [--ctrl_topo '{"controller_id":"ctrl0","links":[...]}']
```

With `--no_rsu`, the `allRSUPeers` variable switches from `RSU_PEERS` to `OBU_PEERS`.
`PeriodicPeerReSelection` also uses this binary list — it does not mix OBU and RSU peers.

---

## 21. Constants Reference

All trust constants are in `trust.go`:

| Constant | Value | Meaning |
|---|---|---|
| `TrustDeltaPlus` | 0.05 | Trust reward per correct round |
| `TrustDeltaMinus` | 0.10 | Trust penalty per missed/inconsistent round |
| `TrustDeltaCtrl` | 0.20 | Controller trust penalty per confirmed divergence |
| `TrustMin` | 0.10 | Participation floor (minimum to submit evidence) |
| `TrustMinGT` | 0.50 | Ground-truth floor (minimum for evidence to count; anchor authority in no-RSU) |
| `TrustCtrlMin` | 0.30 | Controller removal threshold (τCj < 0.30 → remove) |
| `TrustInitTier1` | 1.00 | RSU Fabric peer initial trust |
| `TrustInitTier2` | 0.10 | OBU Fabric peer initial trust |
| `HWCapacityMinMB` | 2048 | Minimum OBU RAM for Pactive eligibility (2 GB) |
| `HWStorageMinGB` | 8 | Minimum OBU storage for Pactive eligibility (8 GB) |
| `FaultToleranceF` | 2 | Byzantine fault tolerance (tolerate f=2 Byzantine peers) |
| `NpConsensus` | 8 | Active peer slots: np ≥ 3f+1=7, rounded to 8 for redundancy |
| `QuarantineMonitorMs` | 30000 | 30s monitoring window before permanent RSU removal |
| `AnchorIntervalBlocksUrban` | 215 | Checkpoint every ≈21.5s (urban, Tb=100ms) |
| `AnchorIntervalBlocksHighway` | 45 | Checkpoint every ≈4.5s (highway) |
| θFS (ledger) | 0.40 default | Full-stack (TGN) detection threshold (TBD per thesis) |
| θLW (ledger) | 0.30 default | Lightweight (PEM) detection threshold (TBD per thesis) |
| `TOTAL_LATENCY_BUDGET_MS` (JS) | 100 | End-to-end FlowMod delivery budget |

---

## 22. Complete Chaincode Function Index

### Entry Points (client-callable)

| Function | File | Purpose |
|---|---|---|
| `SubmitBeaconEvidence` | temporalecho.go | Flow 1: store B_nk(t) ground truth |
| `SubmitDetectionEvent` | temporalecho.go | Flow 2: store O_rk detection alert |
| `SubmitControllerTopology` | temporalecho.go | Flow 3: store G_t^C + trigger divergence check |
| `SubmitAlert` | temporalecho.go | Primary TGN→blockchain entry (calls runMitigation) |
| `SubmitLWDetectionResult` | temporalecho.go | LW/PEM path (RSU hardware) → runMitigation |
| `Mitigate` | temporalecho.go | Direct Algorithm 4 invocation (SDK path) |
| `ClearReauth` | temporalecho.go | Re-admit vehicle after re-authentication + write DELETE FlowMod |
| `RegisterController` | temporalecho.go | Register SDN controller with zone ID |
| `RegisterPeerKey` | temporalecho.go | Store Falcon-1024 public key for a peer |
| `SetSimParams` | temporalecho.go | Set rComm, rssiMin, noRSUMode at bootstrap |
| `SetMobilityParams` | temporalecho.go | Set T_PBFT, v_max at bootstrap |
| `SubmitIndividualSigEvidence` | temporalecho.go | TTW/BSHH threshold signature evidence |
| `SubmitWitnessRecord` | temporalecho.go | ME quorum witness record |
| `SubmitVehicleMAC` | temporalecho.go | Register vehicle MAC for FlowMod match fields |
| `RegisterRSUPeer` | trust.go | Register RSU Fabric peer at τk=1.0, IsRSUPeer=true |
| `RegisterOBUPeer` | trust.go | Register OBU at τk=0.10 with dwell tracking |
| `SetRSUZone` | trust.go | Set ZoneID on RSU TrustRecord |
| `UpdateTrustRound` | trust.go | Apply per-round trust rewards/penalties |
| `ZeroTrust` | trust.go | Initiate demotion (Tier 1 RSU caller required, detection event key required) |
| `DemotePeerToClient` | trust.go | Public Stage 1 demotion entry |
| `PeriodicPeerReSelection` | trust.go | Recompute Pactive + emit promotion/de-listing events |
| `SelectPeers` | trust.go | Query Pactive (read-only) |
| `CheckPBFTConsensus` | trust.go | Query consensus result for given peer sets |
| `CheckControllerTrustAndReassign` | trust.go | Apply ΔC- + trigger reassignment if τCj < TrustCtrlMin |
| `GetTrustScore` | trust.go | Query τk for a peer |
| `GetControllerTrustScore` | trust.go | Query τCj for a controller |
| `GetBootstrapStatus` | trust.go | Query bootstrap phase status (qualified peers, Rmin) |
| `GetTrustedEvidence` | trust.go | Query beacon evidence from τk≥TrustMinGT peers only |
| `CreateAnchorCheckpoint` | anchor.go | Create PBFT-signed ledger digest |
| `SyncFromAnchorCheckpoint` | anchor.go | OBU confirms sync (required for Pactive eligibility) |
| `GetLatestAnchorCheckpoint` | anchor.go | Query most recent checkpoint |
| `GetMitigationHistory` | temporalecho.go | Query all MitigationLogEntry for a vehicle |
| `GetReauthFlag` | temporalecho.go | Query re-authentication block status |
| `GetPendingFlowMod` | temporalecho.go | Read one PendingFlowMod by key |
| `GetAllPendingFlowMods` | temporalecho.go | Read all unexecuted FlowMods (catch-up replay) |
| `AcknowledgeFlowMod` | temporalecho.go | Mark FlowMod executed (by eventListener after HTTP POST) |
| `QueryDetectionEventsByVehicle` | temporalecho.go | CouchDB rich query for detection history |
| `QueryBeaconEvidenceByInterval` | temporalecho.go | CouchDB rich query for beacon records |
| `GetDivergenceDelta` | temporalecho.go | Query δ and δ_thresh for a controller/interval |
| `GetLatestControllerReassignment` | temporalecho.go | Query reassignment record |

---

## 23. Complete Fabric Event Index

| Event name | Emitted by | When | eventListener action |
|---|---|---|---|
| `AttackDetected` | `runMitigation` | After each alert processed | POST FlowMod to Ryu |
| `KeyRevocation` | `revokeSessionKey` | TTW/BSHH/ME variant | Append revoked_keys.json |
| `BlacklistBeaconPublished` | `publishBlacklistBeacon` | TTW/BSHH variant | Write /tmp/blacklist_vehicle_ids.txt |
| `VehicleCertRevocationRequested` | `revokeVehicleCert` | TTW/BSHH variant | CA call off-chain |
| `RSUZoneReassignmentTriggered` | `triggerRSUZoneReassignment` | TTW/BSHH if attacker is RSU | Log zone handoff |
| `ControllerOriginAttack` | `checkControllerDivergence` | δ > δ_thresh | Operator escalation |
| `ControllerRemoved` | `CheckControllerTrustAndReassign` | τCj < TrustCtrlMin | RSU mgmt API call |
| `ControllerRemovalFailed` | `CheckControllerTrustAndReassign` | No backup controller | Critical alert |
| `ControllerCredentialRevocationRequested` | `CheckControllerTrustAndReassign` | τCj < TrustCtrlMin | CA call off-chain |
| `ControllerRevokedBeaconPublished` | `publishControllerRevokedBeacon` | τCj < TrustCtrlMin | Log; notify Ck* |
| `PeerQuarantined` | `demotePeerToClient` | Stage 1 demotion | Operator alert; suspend relay |
| `PeerRemoved` | `monitorAndRemovePeer` | Stage 3 removal | Operator alert |
| `CertRevocationRequested` | `monitorAndRemovePeer` | Stage 3 removal | CA call off-chain |
| `PeerPromoted` | `PeriodicPeerReSelection` | OBU enters Pactive | Log |
| `PeerDroppedFromActive` | `PeriodicPeerReSelection` | Peer falls below eligibility | Log |
| `AnchorCheckpointCreated` | `CreateAnchorCheckpoint` | Every ⌊Tmin/Tb⌋ blocks | Log checkpoint ID |

---

## 24. Walk-Through: A Full TTW Attack Detection Cycle

This traces every step from NS-3 detection to OpenFlow enforcement for TTW-S2 (Malicious RSU).

```
NS-3 simulation, t=20.05s:
  PEM detector: TTW-S1 signature #0 fires, score > 0.12
  tgn_detector.cc: ŷ_v = 0.85 > 0.40 → writes tgn_alerts.json

submit_alerts.py reads tgn_alerts.json:
  calls SubmitAlert("peer0.rsu1.tetaguard.net", alertJSON, ctrlTopoJSON, "1709000200000")

SubmitAlert (chaincode):
  ① TE-06: verify caller trust → τk(rsu1) = 0.95 ≥ TrustMin ✓
  ② Parse alert: {VehicleID:"v002", Alpha:"TTW", YHat:0.85, STrig:[0]}
  ③ Store DetectionEvent at DETECTION:peer0.rsu1:v002:1709000200050
  ④ SubmitControllerTopology inline → checkControllerDivergence
       G_t^C has ghost link V0↔V1; E_t^nodes does not → δ=1 > δ_thresh? Maybe not yet.
  ⑤ selectPeers → Pactive = {rsu1, rsu2, rsu3, rsu4} [four RSU peers above threshold]
     thresholdT = 4/2+1 = 3
  ⑥ runMitigation([event], θFS=0.40, T=3)

runMitigation:
  PBFT: approvingPeers = ["peer0.rsu1"] (only one submitter so far)
         Σ τk(approving) / Σ τk(active) = 0.95 / (0.95+0.92+0.88+0.91) = 0.26 < 2/3
         → PBFT FAIL → return error (no enforcement yet)

[Meanwhile, rsu2 and rsu3 also detect the attack via SubmitLWDetectionResult]

SubmitLWDetectionResult from rsu2, then rsu3:
  Each stores their own DETECTION:LW record
  Third call finally passes: Σ τk(rsu1+rsu2+rsu3) / Σ τk(all four) = 2.75/3.66 = 0.75 > 2/3 ✓

runMitigation proceeds:
  isNoRSU = false (SIM_NO_RSU_MODE = "0")
  variant = "TTW"
  isBootstrapComplete = true (5 RSU peers × τk > 0.50)

  getSignatureEvidence("v002", alertTS) → [{rsu1_sig}, {rsu2_sig}, {rsu3_sig}]
  verifyThresholdSig(evidence, T=3) → 3 valid ≥ 3 ✓

  pushFlowModDrop("v002")
    → PutState("FLOWMOD_DROP_v002_1709000200100", PendingFlowMod{
          Action:"DROP", Priority:65000, Match:{eth_src:"02:00:00:00:02"}
      })

  revokeSessionKey("v002") → SetEvent("KeyRevocation", {vehicle_id:"v002"})

  publishBlacklistBeacon("v002")
    → PutState("BLACKLIST_BEACON:v002", BlacklistBeacon{...})
    → SetEvent("BlacklistBeaconPublished", {vehicle_id:"v002"})

  revokeVehicleCert("v002")
    → PutState("CERT_REVOKED:v002", {...})
    → SetEvent("VehicleCertRevocationRequested", {vehicle_id:"v002"})

  attackerTrust = loadTrust("v002") → IsRSUPeer = false (it's a vehicle)
  [no zone reassignment needed]

  flagReauth("v002", "TTW") → PutState("REAUTH:v002", ReauthFlag{...})
  updateTrust("v002", false, true) → τk=0.0, Flagged=true

  SetEvent("AttackDetected", {vehicle_id:"v002", attack_variant:"TTW", ...})

  Reward honest peers: rsu1,rsu2,rsu3,rsu4 each → τk += 0.05

Off-chain (eventListener.js, ~60ms later):
  "AttackDetected" received:
    GetAllPendingFlowMods() → finds FLOWMOD_DROP_v002_1709000200100
    executeParsedFlowMod → POST to http://ryu-rsu2:8080/stats/flowentry/add
      body: {priority:65000, match:{eth_src:"02:00:00:00:00:02"}, actions:[]}
    AcknowledgeFlowMod("FLOWMOD_DROP_v002_1709000200100") → Executed=true

  "KeyRevocation" received:
    append {vehicle_id:"v002", action:"REVOKE_SESSION_KEY"} to revoked_keys.json

  "BlacklistBeaconPublished" received:
    append "2" to /tmp/blacklist_vehicle_ids.txt

NS-3 routing.cc, ~1s later:
  ReadBlacklistFile() reads "2" → g_blacklisted_nodes.insert(2)
  BroadcastBlacklist() via DSRC (CustomBlacklistTag)
  Rx(): all nodes receiving from v002 now drop its packets
```

Total latency from NS-3 detection to OpenFlow DROP: ~100ms (within the paper's budget).

---

## 25. Walk-Through: No-RSU Scenario Startup

This shows what happens when a no-RSU scenario (e.g., attack_scenario=1, TTW-S1) starts.

```
bootstrap.sh:
  SetSimParams("300", "-85", "1")
    → SIM_RCOMM = "300"
    → SIM_RSSI_MIN = "-85"
    → SIM_NO_RSU_MODE = "1"

  SetMobilityParams("100", "80")
    → SIM_TPBFT_MS = "100"
    → SIM_VMAX_KMH = "80"

  RegisterOBUPeer("obu001", "0", "3072", "16")   [τk=0.10, JoinedAt=0, 3GB RAM, 16GB storage]
  RegisterOBUPeer("obu002", "0", "3072", "16")
  ... (register all OBU peers)

  [NO RegisterRSUPeer calls — no RSU infrastructure]

eventListener.js --no_rsu:
  SELECT_PEERS_POOL = ALL_OBU_PEERS = ["obu001","obu002",...]
  ALL_PEERS = ALL_OBU_PEERS  [same — no RSU peers in pool]

First 8 beacon intervals (t=0.1s to t=0.8s):
  UpdateTrustRound("obu001", ALL_OBU_PEERS, ALL_OBU_PEERS)
    → each OBU: τk += 0.05 per correct round
    → After 8 rounds: τk(obu001) = 0.10 + 8×0.05 = 0.50 = TrustMinGT ✓

CreateAnchorCheckpoint("obu001", "270"):
  → SIM_NO_RSU_MODE = "1" → noRSUMode = true
  → load trust(obu001): τk=0.50 ≥ TrustMinGT ✓ and !Flagged ✓
  → blockHeight = anchorIncrementCounter = 1
  → stateRoot = SHA-256(TxID || teta-channel || 1)
  → PutState("ANCHOR:1", AnchorCheckpoint{...})
  → emit AnchorCheckpointCreated

SyncFromAnchorCheckpoint("CHECKPOINT_TX_ID_1", "obu002"):
  → load trust(obu002): τk=0.50 ≥ TrustMin ✓
  → latest checkpoint = ANCHOR:1 → matches ✓
  → verify creator obu001: τk ≥ TrustMinGT ✓ (no-RSU path)
  → add "obu002" to SyncedPeers
  → obu002 is now eligible for Pactive

PeriodicPeerReSelection(ALL_OBU_PEERS):
  selectPeers → noRSUMode = true
    → for each OBU: skip HW check, skip dwell check
    → check τk ≥ TrustMin ✓
    → check !Flagged ✓
    → check obuHasSyncedFromRecentCheckpoint ← MUST pass
    → rank by τk, take top 8
  → emit PeerPromoted for each newly eligible OBU

isBootstrapComplete():
  count(τk ≥ 0.50 and !Flagged) = 8 ≥ np=8 ✓
  Bootstrap complete → enforcement enabled

Attack at t=10s (TTW replay at t=20s):
  NS-3 PEM fires → SubmitAlert
  selectPeers → Pactive = [obu001..obu008]
  PBFT: Σ τk(approving) / Σ τk(active) > 2/3?
    3 OBUs submit: (0.90+0.85+0.88) / Σ all 8 = 2.63 / (sum) > 0.67 ✓

  runMitigation:
    isNoRSU = true
    variant = "TTW"
    isBootstrapComplete = true

    verifyThresholdSig → 3 valid ≥ T=5 (8/2+1=5)?
    [needs more submitters to reach threshold — LW path covers the rest]

    pushFlowModDrop → SKIPPED (FLOWMOD_DROP_SKIPPED_NO_RSU)
    revokeSessionKey → emits KeyRevocation ✓ (mode-independent)
    publishBlacklistBeacon → emits BlacklistBeaconPublished ✓ (primary isolation)
    revokeVehicleCert → emits VehicleCertRevocationRequested ✓

    flagReauth, updateTrust → vehicle zeroed

  eventListener (--no_rsu):
    BlacklistBeaconPublished → write /tmp/blacklist_vehicle_ids.txt
    [no FlowMod POST — no Ryu agent in no-RSU scenarios]
```

---

## 26. Bugs Fixed During Development

This section documents every significant bug that was found and fixed, in chronological order.
Understanding these bugs helps you avoid repeating them.

### Bug 1: Stray text causing compile error
**File:** `routing.cc` (NS-3 side)
**Error:** `'hjhjhj' was not declared`
**Cause:** `using namespace ns3;hjhjhj` — accidental keystrokes in namespace declaration.
**Fix:** `sed -i 's/using namespace ns3;hjhjhj/using namespace ns3;/' scratch/routing.cc`

### Bug 2: `SIM_NO_RSU_MODE` ignored by `selectPeers`
**File:** `trust.go`, `selectPeers` function
**Error:** No-RSU scenarios still used RSU-only peer pool.
**Root cause:** The original code detected no-RSU mode by checking whether any RSU peers
existed (`for _, pid := range allPeers { if loadTrust(...).IsRSUPeer { hasRSU=true } }`).
But RSU Docker containers are always registered on the Fabric network regardless of NS-3
scenario type, so `hasRSU` was always `true`.
**Fix:** Read `SIM_NO_RSU_MODE` from ledger directly. Written by `SetSimParams` at bootstrap.

### Bug 3: `HWStorageGB` field missing from TrustRecord
**File:** `structs.go`, `trust.go`
**Error:** `r.HWStorageGB undefined`, `undefined: HWStorageMinGB`
**Fix:** Added `HWStorageGB int` to `TrustRecord` and `HWStorageMinGB = 8` constant.

### Bug 4: `loadFloatParam` undefined
**File:** `verification.go`
**Error:** Function used in `temporalecho.go` for θFS/θLW but not defined.
**Fix:** Added `loadFloatParam(ctx, key, defaultVal float64) float64` to `verification.go`.

### Bug 5: `math` package not imported
**File:** `temporalecho.go`
**Error:** `undefined: math` when `math.Ceil` was added for `InterimFallbackIntervals`.
**Fix:** Added `"math"` to imports list.

### Bug 6: `revokeVehicleCert` undefined
**File:** `temporalecho.go`
**Error:** Called in `runMitigation` but function not yet defined.
**Fix:** Added `revokeVehicleCert(ctx, vehicleID)` helper.

### Bug 7: `triggerRSUZoneReassignment` undefined
**File:** `temporalecho.go`
**Error:** Called in `runMitigation` but function not yet defined.
**Fix:** Added `triggerRSUZoneReassignment(ctx, compromisedRSUID, zoneID)` helper.

### Bug 8: Checkpoint-sync comment incorrectly attributed to Eq. 3.40
**File:** `trust.go`, `selectPeers` comment
**Error:** Comment said "Eq. 3.40 condition 6 (checkpoint-sync)" — Eq. 3.40 has only FIVE
conditions. Checkpoint-sync is from the anchor-checkpoint protocol (§5.1), not Eq. 3.40.
**Fix:** Updated comment to explicitly state checkpoint-sync is NOT one of Eq. 3.40's five
conditions and is not subject to the no-RSU bypass.

### Bug 9: Double trust penalty for CTRL_ORIGIN
**File:** `temporalecho.go`, `runMitigation`
**Error:** Original code called both `updateCtrlTrust(ctx, vid)` AND `CheckControllerTrustAndReassign`.
`CheckControllerTrustAndReassign` internally calls `updateCtrlTrust`. Double penalty applied.
**Fix:** Removed the direct `updateCtrlTrust` call; `CheckControllerTrustAndReassign` is the
sole penalty authority (TE-04/TE-03 fix).

### Bug 10: Anchor checkpoint key collision (AN-01)
**File:** `anchor.go`, `CreateAnchorCheckpoint`
**Error:** Original key was `ANCHOR:<now_ms>` (wall-clock). Two endorsing peers creating a
checkpoint at slightly different times wrote to different keys, causing Fabric MVCC
PHANTOM_READ_CONFLICT and rejected transactions.
**Fix:** Key changed to `ANCHOR:<blockHeight>` where blockHeight comes from monotonic counter
`ANCHOR_CTR`. All endorsers increment the same counter in the same transaction → same key.

### Bug 11: `isNoRSU` flag scoped inside TTW/BSHH block only
**File:** `temporalecho.go`, `runMitigation`
**Error:** `noRSUFlag, _ := ctx.GetStub().GetState("SIM_NO_RSU_MODE")` was declared inside
the `if variant == "TTW" || variant == "BSHH"` block. ME and CTRL_ORIGIN could not see the
`isNoRSU` variable — the compiler would have caught this if the other branches tried to use it,
but instead the other branches were missing the mode-check entirely.
**Fix:** Hoisted `isNoRSU` declaration to before the `variant :=` line, so all three variant
branches share the same flag read.

### Bug 12: `pushRerouteFlowMod` not mode-conditional (ME variant)
**File:** `temporalecho.go`, `runMitigation`, ME branch
**Error:** In no-RSU mode, there are no OpenFlow switches to receive the REROUTE FlowMod. The
ME branch always called `pushRerouteFlowMod` regardless of mode.
**Fix:** Wrapped in `if !isNoRSU { ... } else { logEntry.Actions = append(..., "REROUTE_FLOWMOD_SKIPPED_NO_RSU") }`.

### Bug 13: `pushFlowModOverride` not mode-conditional (CTRL_ORIGIN variant)
**File:** `temporalecho.go`, `runMitigation`, CTRL_ORIGIN branch
**Error:** Same problem as Bug 12 for the controller override path.
**Fix:** Same pattern: `if !isNoRSU { ... } else { log CTRL_OVERRIDE_FLOWMOD_SKIPPED_NO_RSU }`.

### Bug 14: `flagReauth` called for CTRL_ORIGIN variant
**File:** `temporalecho.go`, `runMitigation`
**Error:** `flagReauth(ctx, alert.VehicleID, variant)` was called unconditionally for all
variants including CTRL_ORIGIN. For CTRL_ORIGIN, `alert.VehicleID` is a controller ID, not
a vehicle ID. This wrote `REAUTH:<controller_id>` to the ledger — a vehicle mechanism applied
to a controller. Controllers use `RegisterController` for re-admission, not the REAUTH flow.
**Fix:** Guarded with `if variant != "CTRL_ORIGIN"`.

### Bug 15: Anchor checkpoint authority in no-RSU used wrong threshold
**File:** `anchor.go`, `CreateAnchorCheckpoint`
**Error:** No-RSU path used `TrustMin (0.10)` as the authority threshold. This would allow a
barely-admitted OBU to become the chain anchor — a security issue.
**Fix:** Changed to `TrustMinGT (0.50)`. Matches the evidence-quality threshold already used
for divergence detection ground truth. `SyncFromAnchorCheckpoint` made symmetric.

### Bug 16: CTRL_ORIGIN direction for `publishControllerRevokedBeacon` stated incorrectly
**File:** `structs.go`, `ControllerRevokedBeacon` doc comment
**Error:** Comment said "vehicles solicit from Ck*". Thesis says Ck* solicits FROM vehicles.
**Fix:** Updated all comments and event payload to `solicitation_direction: "backup_controller_solicits_from_vehicles"`.

### Bug 17: Zone-reassignment selection comment implied Eq. 3.43
**File:** `temporalecho.go`, `triggerRSUZoneReassignment`
**Error:** Comment implied the zone-ID match heuristic reused the Eq. 3.43 argmax-trust logic
from `selectBackupController` / `CheckControllerTrustAndReassign`. They are different mechanisms.
Eq. 3.43 is for controller removal; zone reassignment is for RSU data-plane handoff.
**Fix:** Added explicit comment that this is an implementation design choice for an underspecified
thesis mechanism, and is NOT Eq. 3.43.

### Bug 18: `IsRSUPeer` read after `updateTrust` (ordering bug)
**File:** `temporalecho.go`, `runMitigation`, TTW/BSHH branch
**Error:** In the original ordering, `updateTrust(vid, false, true)` was called BEFORE the
`attackerTrust.IsRSUPeer` check. `demotePeerToClient` (called by `updateTrust` for RSU peers)
sets `IsRSUPeer = false`. So the zone reassignment check would always see `IsRSUPeer = false`
and silently skip zone reassignment for malicious RSU peers.
**Fix:** Moved the `loadTrust(vid)` and `IsRSUPeer` check to run BEFORE `updateTrust`. Comment
explains the invariant explicitly.

---

*Document written for: TETA-GUARD FYP — Department of EIE, University of Ruhuna*
*Supervisor: Dr. Nilmantha Wijesekara | Co-supervisor: Dr. Prabath Weerasingha*
*Last updated: reflects current production state of all chaincode files (all 18 bugs resolved)*
