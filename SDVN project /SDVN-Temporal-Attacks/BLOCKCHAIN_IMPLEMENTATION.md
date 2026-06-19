# TETA-GUARD Blockchain Implementation
## Full Technical Reference — TemporalEchoMitigator Smart Contract

**Project:** Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection:
Countering Temporal-Echo Topology Poisoning Attacks in SDVNs
**Platform:** Hyperledger Fabric (permissioned blockchain)
**Chaincode language:** Go (contractapi)
**Off-chain client:** Node.js (fabric-network SDK 2.2)
**Crypto:** Dilithium2 (FIPS 204 ML-DSA) — simulation stub: HMAC-SHA256

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [File Structure](#2-file-structure)
3. [Data Structures and Ledger Key Scheme](#3-data-structures-and-ledger-key-scheme)
4. [Three-Flow Data Ingestion](#4-three-flow-data-ingestion)
5. [Trust Management System](#5-trust-management-system)
6. [Algorithm 4 — FS-MITIGATE (runMitigation)](#6-algorithm-4--fs-mitigate-runmitigation)
7. [Controller Divergence Detection](#7-controller-divergence-detection)
8. [Anchor Checkpoint Protocol](#8-anchor-checkpoint-protocol)
9. [FlowMod Enforcement Interface](#9-flowmod-enforcement-interface)
10. [Cryptography Layer](#10-cryptography-layer)
11. [Off-Chain Event Listener (eventListener.js)](#11-off-chain-event-listener-eventlistenerjs)
12. [WITH RSU — Full Operation](#12-with-rsu--full-operation)
13. [WITHOUT RSU — No-RSU / OBU-Only Mode](#13-without-rsu--no-rsu--obu-only-mode)
14. [Bootstrap Phase](#14-bootstrap-phase)
15. [Peer State Machine (Demotion Pipeline)](#15-peer-state-machine-demotion-pipeline)
16. [Constants Reference](#16-constants-reference)
17. [Complete Chaincode Function Index](#17-complete-chaincode-function-index)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          NS-3 Simulation Layer                              │
│                                                                             │
│  [Vehicle OBUs] ──DSRC 802.11p──► [RSU Nodes] ──CSMA/UDP──► [SDN Ctrl]    │
│                                                                             │
│  routing.cc: PEM 9-signature detector fires → writes tgn_alerts.json       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  submit_alerts.py polls tgn_alerts.json
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Hyperledger Fabric Blockchain Layer                     │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │         TemporalEchoMitigator Smart Contract (Go)                    │   │
│  │                                                                      │   │
│  │  Flow 1: SubmitBeaconEvidence     ── ground-truth B_nk(t)            │   │
│  │  Flow 2: SubmitDetectionEvent     ── per-alert O_rk                  │   │
│  │  Flow 3: SubmitControllerTopology ── G_t^C + divergence check        │   │
│  │                                                                      │   │
│  │  SubmitAlert / SubmitLWDetectionResult / Mitigate                    │   │
│  │    → runMitigation (Algorithm 4 FS-MITIGATE)                         │   │
│  │      → PBFT trust-weighted consensus gate                            │   │
│  │      → per-variant enforcement (TTW/BSHH/ME/CTRL_ORIGIN)            │   │
│  │      → PendingFlowMod written to ledger                              │   │
│  │      → BlacklistBeacon / ControllerRevokedBeacon published           │   │
│  │      → peer trust rewards/penalties                                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Ledger (CouchDB): BEACON:*, DETECTION:*, TRUST:*, ANCHOR:*, MITIG:*, …   │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │  Fabric events (contract listener)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Off-Chain Event Listener (Node.js)                      │
│                                                                             │
│  AttackDetected      → read PendingFlowMod → POST HTTP to Ryu agent        │
│  KeyRevocation       → write revoked_keys.json                             │
│  ControllerRemoved   → action zone southbound switch reassignment          │
│  BlacklistBeacon     → write /tmp/blacklist_vehicle_ids.txt (NS-3 IPC)     │
│  AnchorCheckpoint    → log for OBU sync                                    │
│  PeerQuarantined/    → operator alerts, RSU data relay suspension          │
│  PeerRemoved                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                         [Ryu OpenFlow Controller]
                         POST /stats/flowentry/add
                         DROP / REROUTE / OVERRIDE / DELETE
```

---

## 2. File Structure

```
blockchain/
├── chaincode/temporalecho/
│   ├── temporalecho.go      ← smart contract main: entry points, runMitigation
│   ├── trust.go             ← trust scores, peer selection, PBFT, controller removal
│   ├── anchor.go            ← anchor checkpoint protocol
│   ├── divergence.go        ← controller topology divergence detection
│   ├── flowmod.go           ← FlowMod record writing (ledger side)
│   ├── structs.go           ← all data structures and ledger key scheme
│   ├── verification.go      ← common verification helper interface
│   ├── verification_stub.go ← simulation mode: HMAC-SHA256 (build !liboqs)
│   └── verification_liboqs.go ← production: real Dilithium2 (build liboqs)
├── client/
│   ├── eventListener.js     ← Node.js off-chain listener + FlowMod executor
│   └── submitToFabric.js    ← CLI tool to submit alerts manually
├── network/
│   ├── docker-compose-teta.yaml ← Fabric network definition
│   ├── configtx.yaml           ← channel / policy configuration
│   ├── crypto-config.yaml      ← MSP certificate generation
│   └── bootstrap.sh            ← network bring-up script
└── scripts/
    ├── deploy_chaincode.sh  ← chaincode lifecycle (package → install → commit)
    └── create_channel.sh    ← channel creation
```

---

## 3. Data Structures and Ledger Key Scheme

### Ledger Key Namespace

| Key prefix | Go struct | Purpose |
|---|---|---|
| `BEACON:<peer>:<ts>` | `BeaconEvidenceRecord` | Ground-truth vehicle observations |
| `DETECTION:<peer>:<vid>:<ts>` | `DetectionEvent` | Per-alert detection records |
| `CTRL_TOPO:<ctrl>:<ts>` | `ControllerTopologyClaim` | Controller topology claims |
| `MITIG:<entryID>` | `MitigationLogEntry` | Immutable mitigation audit log |
| `REAUTH:<vid>` | `ReauthFlag` | Re-authentication block |
| `SIG_EVIDENCE:<vid>:<ts>:<signer>` | `IndividualSigEvidence` | Threshold signature evidence |
| `WITNESS:<vid>:<ts>:<reporter>` | `WitnessRecord` | ME quorum witness records |
| `TRUST:<peerID>` | `TrustRecord` | Peer trust scores (τk) |
| `CTRL_TRUST:<ctrlID>` | `ControllerTrustRecord` | Controller trust scores (τCj) |
| `CTRL_REGISTRY` | `[]string` | Registered controller IDs |
| `CTRL_REASSIGN:<ctrl>:<ts>` | `ControllerReassignment` | Controller reassignment records |
| `CTRL_REVOKED:<ctrl>` | raw JSON | Controller credential revocation |
| `ANCHOR:<blockHeight>` | `AnchorCheckpoint` | PBFT-signed ledger digest |
| `ANCHOR_CTR` | uint64 string | Monotonic block counter |
| `PEERKEY:<peerID>` | raw bytes | Dilithium2 public keys |
| `VMAC_<vid>` | raw string | Vehicle MAC addresses |
| `BLACKLIST_BEACON:<vid>` | `BlacklistBeacon` | Revocation fingerprints |
| `CTRL_REVOKED_BEACON:<ctrl>` | `ControllerRevokedBeacon` | Controller revocation beacons |
| `ACTIVE_PEER_SET` | `[]string` | Current active consensus set |
| `FALSE_PATHS:<vid>` | raw JSON | Invalidated ME phantom paths |
| `SIM_TPBFT_MS` | int64 string | PBFT round-trip latency (ms) |
| `SIM_VMAX_KMH` | float64 string | Maximum vehicle speed (km/h) |
| `SIM_RCOMM` | float64 string | DSRC communication range (m) |
| `SIM_RSSI_MIN` | float64 string | Minimum RSSI threshold (dBm) |

### Core Struct Summary

**`BeaconEvidenceRecord`** — B_nk(t), Flow 1 ground truth:
```go
PeerID, IntervalTS, Observations []VehicleObservation
PeerSig []byte (Dilithium2/HMAC), PeerPubKey []byte, IsRSUPeer bool
```

**`DetectionEvent`** — O_rk, Flow 2 alert:
```go
PeerID, VehicleID, AttackVariant string   // "TTW"|"BSHH"|"ME"|"CTRL_ORIGIN"
AnomalyScore float32, TriggeredSigs uint32 // 9-bit bitmask
AlertTS int64, FromLWPath bool, FromFSPath bool
```

**`TrustRecord`** — τk per Fabric peer:
```go
Score float64 [0,1], IsRSUPeer bool, Flagged bool
State PeerState // ACTIVE|QUARANTINED_CLIENT|REMOVED
JoinedAtMs, HWCapacity, DemotedAt
```

**`ControllerTrustRecord`** — τCj per SDN controller:
```go
Score float64 [0,1], ZoneID string, DivergenceCount int
// Penalty only: -ΔC- = -0.20 on each confirmed divergence
```

---

## 4. Three-Flow Data Ingestion

### Flow 1 — `SubmitBeaconEvidence`

Ground-truth vehicle observations submitted every beacon interval Tb.

**With RSU:** Tier 1 RSU peers (IsRSUPeer=true, τk=1.0) submit their observations of nearby vehicles (GPS, RSSI, HELLO-confirmed neighbour lists). These become the authoritative E_t^nodes set for divergence checks.

**Without RSU:** OBU peers with τk ≥ TrustMinGT (0.50) may submit evidence during and after bootstrap. During bootstrap (before np=4 qualified peers exist), all peers at the participation floor (τk ≥ 0.10) can submit — evidence is stored but never used as authoritative ground truth until bootstrap completes.

**Trust gate logic:**
```
bootstrapDone = qualified(τk ≥ 0.50) ≥ np = 3f+1 = 4
if bootstrapDone:
    require IsRSUPeer OR τk ≥ TrustMinGT (0.50)
else:
    require τk ≥ TrustMin (0.10)  ← allows OBU-only accumulation
```

**Signature verification:** `verifyDilithium2Sig(record.PeerSig, evidenceJSON, record.PeerPubKey)`

### Flow 2 — `SubmitDetectionEvent`

Individual detection alert from any trusted peer. Signature verified against stored `PEERKEY:<peerID>`. Stored at `DETECTION:<peer>:<vid>:<ts>`.

### Flow 3 — `SubmitControllerTopology`

Controller submits its claimed topology G_t^C. Stored as untrusted claim, then immediately triggers `checkControllerDivergence`. The controller's claim is NEVER used as evidence — only as a value to test against E_t^nodes.

---

## 5. Trust Management System

### Peer Tiers

| Tier | Who | Initial τk | Role |
|---|---|---|---|
| Tier 1 | RSU Fabric peers | 1.00 | Drive trust rounds, create anchor checkpoints, submit LW results, call ZeroTrust |
| Tier 2 | OBU Fabric peers | 0.10 | Candidate for promotion into Pactive when vacancy exists |

### Trust Update Rules (Δ+ = 0.05, Δ- = 0.10, ΔC- = 0.20)

| Event | Peer trust change |
|---|---|
| Correct beacon participation | τk = min(1.0, τk + 0.05) |
| Missed/inconsistent beacon | τk = max(0.0, τk - 0.10) |
| Confirmed attack (RSU peer) | Demotion pipeline (Stage 1: QUARANTINED_CLIENT) |
| Confirmed attack (OBU/vehicle) | τk = 0.0 immediately, Flagged = true |
| Controller confirmed divergence | τCj = max(0.0, τCj - 0.20) |

### `UpdateTrustRound` — called every Tb=100ms

```
Caller:   Tier 1 RSU peer (or highest-trust OBU in no-RSU bootstrap mode)
Input:    participatingPeers JSON, allPeers JSON
Effect:   for each peer in allPeers:
            if peer ∈ participatingPeers → +Δ+
            else → -Δ-
```

**No-RSU bootstrap mode (TR-01):** When no RSU peers are registered, the highest-trust OBU above TrustMin may drive trust rounds. This allows trust to accumulate in a pure OBU deployment.

### `selectPeers` — Pactive computation (Eq. 3.40–3.41)

Active set Pactive = top-np eligible peers ranked by τk.

**Eligibility predicate for OBU peers:**
1. τk ≥ TrustMin (0.10) — meets participation floor
2. Not flagged, not QUARANTINED_CLIENT, not REMOVED
3. Dwell time: `now - JoinedAtMs ≥ T_min` (dynamic, see below)
4. HWCapacity ≥ 2048 MB (if declared)
5. Has synced from the latest anchor checkpoint (`obuHasSyncedFromRecentCheckpoint`)

**RSU peers:** always eligible if unflagged and τk ≥ 1.0.

**np = 3f+1 = 4** (FaultToleranceF=1).

### Dynamic T_min — `computeTMinMs`

```
T_min = max(3·T_PBFT, L_link / 2)

where:
  T_PBFT = SIM_TPBFT_MS ledger value  (default 100 ms)
  L_link = 2·r_comm / v_max            (link lifetime estimate)
  v_max  = SIM_VMAX_KMH / 3600 m/ms   (default 80 km/h → 0.0222 m/ms)
  r_comm = SIM_RCOMM meters            (default 300 m)

Urban  (80 km/h, 300 m): L_link = 2·300/0.0222 ≈ 27000 ms → T_min = max(300, 13500) = 13500 ms
Highway (120 km/h, 300m): L_link ≈ 9000 ms → T_min = max(300, 4500) = 4500 ms
```

Configured at bootstrap via `SetMobilityParams(tPBFTMsStr, vMaxKmhStr)`.

### Trust-Weighted PBFT Consensus — `checkPBFTTrustWeight`

```
Consensus = Σ τk(approving peers) / Σ τk(active peers) > 2/3
```

Called inside `runMitigation` before any enforcement action. If consensus is not reached, mitigation aborts.

---

## 6. Algorithm 4 — FS-MITIGATE (`runMitigation`)

Called from `SubmitAlert`, `SubmitLWDetectionResult`, and `Mitigate`.

### Detection Thresholds

| Path | Threshold | Called from |
|---|---|---|
| FS (Full-Stack, TGN) | θFS = 0.40 | `SubmitAlert`, `Mitigate` |
| LW (Lightweight, PEM 9-sig) | θLW = 0.30 | `SubmitLWDetectionResult` |

### Step-by-Step Flow

```
Step 1: Collect approving peers from alert PeerID fields
Step 2: selectPeers(allPeers) → Pactive
Step 3: checkPBFTTrustWeight(approving, active) → 2/3 consensus gate
         ↳ if fail → return error, no enforcement
Step 4: resolveDualPath(alerts) → merge LW+FS alerts for same vehicle
Step 5: isBootstrapComplete? → if not → log-only mode (BOOTSTRAP_PRELIMINARY_NO_ENFORCEMENT)
Step 6: readBlockCounter(ctx) → consensusRound for audit log (ST-02)

For each alert where score > θ:
  Build MitigationLogEntry with EntryID = generateUUID (deterministic from TxID)

  TTW or BSHH or TTW_BSHH_COMBINED:
    ├── getSignatureEvidence(vid, alertTS) ← window [alertTS-100ms, alertTS+100ms]
    ├── verifyThresholdSig(evidence, thresholdT=n/2+1)
    │     ↳ if fail → log THRESHOLD_SIG_FAIL, continue
    ├── pushFlowModDrop(vid) → PENDING_FLOWMOD key "FLOWMOD_DROP_<vid>_<ms>"
    ├── revokeSessionKey(vid) → Fabric event "KeyRevocation"
    └── publishBlacklistBeacon(vid) → ledger "BLACKLIST_BEACON:<vid>"
                                    → Fabric event "BlacklistBeaconPublished"

  ME:
    ├── getWitnesses(vid, alertTS) ← window [alertTS-100ms, alertTS+100ms]
    ├── getLinkEndpoint(vid) ← GPS from beacon evidence
    ├── verifyQuorum(witnesses, thresholdT, lat, lon) ← r_comm + RSSI checks
    │     ↳ if fail → log QUORUM_FAIL, continue
    ├── invalidateFalsePaths(vid) → ledger "FALSE_PATHS:<vid>"
    └── pushRerouteFlowMod(vid) → PENDING_FLOWMOD "FLOWMOD_REROUTE_<vid>_<ms>"

  CTRL_ORIGIN:
    ├── getAllBeaconEvidence(alertTS)
    └── pushFlowModOverride(ctrlID, evidence) → PENDING_FLOWMOD "FLOWMOD_OVERRIDE_CTRL_<ctrl>"
                                              + per-vehicle OVERRIDE FlowMods

  All variants:
    ├── flagReauth(vid, variant) → ledger "REAUTH:<vid>"
    ├── updateTrust(vid, false, true)  [OBU/vehicle: zero immediately]
    │                                  [RSU peer: demotePeerToClient]
    └── CTRL_ORIGIN only:
        └── CheckControllerTrustAndReassign(ctrlID, allCtrls)
              ├── updateCtrlTrust(ctrl) → τCj -= 0.20
              └── if τCj < TrustCtrlMin (0.30):
                    selectBackupController → write CTRL_REASSIGN record
                    publishControllerRevokedBeacon → "ControllerRevokedBeaconPublished"
                    Fabric event "ControllerRemoved"

Step 7 (TE-07): Reward honest peers
  for pid in Pactive where pid ∉ attackerSet:
    updateTrust(pid, correct=true, zero=false) → τk += 0.05

Step 8: Re-evaluate QUARANTINED peers
  for each quarantined peer: monitorAndRemovePeer
```

### `resolveDualPath` — LW+FS Merge

When both `SubmitLWDetectionResult` (LW path) and `SubmitAlert` (FS path) fire for the same vehicle, `resolveDualPath` deduplicates by vehicle ID, keeping the higher-score alert and marking `FromLWPath=true, FromFSPath=true` on the merged record.

### Dynamic Threshold T — TE-02

```go
thresholdT = n/2 + 1   where n = len(selectPeers(ctx, loadAllPeerIDs(ctx)))
```

Never hardcoded to 1. A single malicious RSU cannot bypass `verifyThresholdSig` alone.

---

## 7. Controller Divergence Detection

### `checkControllerDivergence` (Flow 3, §8)

Compares G_t^C (controller claim) against E_t^nodes (aggregated beacon evidence):

```
δ = |E_t^C △ E_t^nodes|     (symmetric difference count)
δ_thresh = ⌈(1 + τprop/Tb) · λ̂ · 2·rComm⌉ + 1

λ̂ = n_vehicles / (2·rComm)  (estimated dynamically from beacon count at intervalTS)
```

**If δ > δ_thresh:**
- Stores `DETECTION:DIVERGENCE:<ctrl>:<ts>` record
- Emits Fabric event `ControllerOriginAttack` with delta, threshold, and current τCj score
- Does NOT apply trust penalty (DV-03: penalty is applied only in `runMitigation`)

### `aggregateEvidenceLinkSet` — Building E_t^nodes

**Primary method (D-1):** HELLO-confirmed neighbour lists from beacon observations — most accurate.

**Fallback method (DV-01):** GPS proximity — only used when no explicit neighbour data. Uses **half** the communication range (150 m) and **mutual confirmation** to prevent phantom link creation in dense environments.

**Trust filter (DV-04):** Only evidence from τk ≥ TrustMinGT (0.50) peers or Tier 1 RSU peers contributes to E_t^nodes. Sub-threshold OBU evidence excluded.

---

## 8. Anchor Checkpoint Protocol

Produced every `⌊T_min/Tb⌋` blocks by Tier 1 RSU peers.

| Scenario | T_min | Interval |
|---|---|---|
| Urban (80 km/h) | ≈21.5 s | 215 blocks at Tb=100ms |
| Highway (120 km/h) | ≈4.5 s | 45 blocks |

### `CreateAnchorCheckpoint`

```
Caller: Tier 1 RSU peer (IsRSUPeer=true, τk≥1.0)
1. anchorIncrementCounter(ctx) → deterministic blockHeight (ANCHOR_CTR)
2. stateRoot = SHA-256(TxID || channelID || blockHeight)
   (no wall-clock component → deterministic across all endorsers)
3. peerSig = SimSign(sigInput, peerPubKey)  [HMAC-SHA256 in sim mode]
4. Write AnchorCheckpoint to "ANCHOR:<blockHeight>"
5. Emit "AnchorCheckpointCreated" event
```

**AN-01:** Ledger key uses blockHeight (deterministic), not wall-clock time. Prevents Fabric MVCC PHANTOM_READ_CONFLICT from two endorsers writing different keys.

### `SyncFromAnchorCheckpoint`

OBU must sync from the **latest** checkpoint (AN-02: rejects any non-latest checkpoint ID). Verifies Dilithium2 signature. Verifies creator is Tier 1 RSU. Adds OBU to `SyncedPeers` list. This is the final gate for OBU promotion into Pactive.

---

## 9. FlowMod Enforcement Interface

### Architecture

```
Chaincode (ledger side)                  Off-chain (eventListener.js)
─────────────────────────────────        ─────────────────────────────────────
pushFlowModDrop(vid)                     AttackDetected event →
  PutState("FLOWMOD_DROP_<vid>_<ms>",     executeFlowMod(network, vid, "DROP")
           PendingFlowMod{...})             GetAllPendingFlowMods()
                                            find latest unexecuted for vehicle
                                            executeParsedFlowMod → POST Ryu
                                            AcknowledgeFlowMod(entryID)
```

### Three FlowMod Types

| Function | Action | Ryu endpoint | Priority | Trigger |
|---|---|---|---|---|
| `pushFlowModDrop` | DROP | `/stats/flowentry/add` | 65000 | TTW, BSHH |
| `pushRerouteFlowMod` | REROUTE | `/stats/flowentry/delete` | 50000 | ME |
| `pushFlowModOverride` | OVERRIDE | `/stats/flowentry/add` | 65535/65534 | CTRL_ORIGIN |
| `ClearReauth` → DELETE | DELETE | `/stats/flowentry/delete` | 65000 | Post re-auth |

**FM-02:** EntryID includes millisecond timestamp to prevent key collision when the same vehicle is attacked multiple times.

**T-2 Catch-up Replay:** `replayPendingFlowMods` runs at listener startup, fetching all unexecuted `PENDING_FLOWMOD` records from the ledger and executing them. This ensures FlowMods are not lost during listener downtime.

### `ClearReauth` — Re-admission

After a vehicle passes re-authentication:
1. Marks `REAUTH:<vid>.Cleared = true`
2. Writes DELETE FlowMod to ledger (FM-01)
3. eventListener.js posts DELETE to Ryu to remove the DROP rule

---

## 10. Cryptography Layer

### Build Modes

| Build tag | File | Signature primitive |
|---|---|---|
| `!liboqs` (default) | `verification_stub.go` | HMAC-SHA256 (simulation mode) |
| `liboqs` | `verification_liboqs.go` | Real Dilithium2 (FIPS 204 ML-DSA) |

### Simulation Mode — HMAC-SHA256

```go
func SimSign(message string, pubKey []byte) []byte {
    if len(pubKey) == 0 { return []byte("SIM_NOSIG") }
    h := hmac.New(sha256.New, pubKey)
    h.Write([]byte(message))
    return h.Sum(nil)
}

func verifyDilithium2Sig(sig []byte, message string, pubKey []byte) bool {
    if len(pubKey) == 0 { return len(sig) > 0 }  // bootstrap: accept any non-empty sig
    return hmac.Equal(sig, SimSign(message, pubKey))
}
```

**Bootstrap phase:** Before `RegisterPeerKey` is called for a peer, `pubKey` is nil and any non-empty signature is accepted. After key registration, only the correct HMAC passes.

### Production Mode — Dilithium2

Build with:
```bash
go get github.com/open-quantum-safe/liboqs-go
go build -tags liboqs ./...
```

### Where Signatures Are Verified

| Location | What is signed | Verified by |
|---|---|---|
| `SubmitBeaconEvidence` | `evidenceJSON` | `verifyDilithium2Sig(record.PeerSig, evidenceJSON, record.PeerPubKey)` |
| `SubmitDetectionEvent` | `eventJSON` | stored `PEERKEY:<peerID>` |
| `SubmitLWDetectionResult` | `peerID:vid:score:variant:ts` | stored `PEERKEY:<callerPeerID>` |
| `SubmitIndividualSigEvidence` | `e.Message` | `e.PubKey` |
| `SubmitWitnessRecord` | `w.Message` | `w.PubKey` |
| `SyncFromAnchorCheckpoint` | `createdByPeer:blockHeight:stateRoot` | `cp.PeerPubKey` |
| `CreateAnchorCheckpoint` | `peerID:blockHeight:stateRoot` | `SimSign` (signing) |

---

## 11. Off-Chain Event Listener (`eventListener.js`)

### Startup

```
node eventListener.js [--node_id <peer>] [--rsu_url <url>] [--no_rsu] [--interval_ms <ms>]
```

Defaults: `node_id=peer0.rsu1.tetaguard.net`, `interval_ms=100`.

### Events Handled

| Event | Action |
|---|---|
| `AttackDetected` | Read `PendingFlowMod` → POST to Ryu → `AcknowledgeFlowMod` |
| `KeyRevocation` | Append to `revoked_keys.json` |
| `ControllerOriginAttack` | Escalate to operator + execute OVERRIDE FlowMods |
| `ControllerRemoved` | Action zone southbound switch via RSU mgmt API |
| `AnchorCheckpointCreated` | Log for OBU sync coordination |
| `PeerQuarantined` | Operator alert + suspend RSU data relay |
| `PeerRemoved` | Operator alert (permanent removal) |
| `ControllerRemovalFailed` | Critical alert: no backup controller |
| `BlacklistBeaconPublished` | Write `/tmp/blacklist_vehicle_ids.txt` (NS-3 IPC) |
| `ControllerRevokedBeaconPublished` | Log + notify backup controller |
| `PeerPromoted` | Log OBU promotion into active set |
| `PeerDroppedFromActive` | Log peer leaving active set |

### `/tmp/blacklist_vehicle_ids.txt` — NS-3 IPC

When `BlacklistBeaconPublished` fires, `handleBlacklistBeaconPublished` extracts the numeric vehicle ID from the `vehicle_id` field and appends it to `/tmp/blacklist_vehicle_ids.txt`. NS-3 `routing.cc` polls this file every 1 second via `ReadBlacklistFile()` and broadcasts the blacklist via `CustomBlacklistTag` over DSRC every 5 seconds.

### Adaptive FlowMod Timeout (EL-02)

```javascript
const TOTAL_LATENCY_BUDGET_MS = 100;  // paper latency budget

elapsedMs = Date.now() - eventTimestampMs;
flowModTimeout = max(10, 100 - elapsedMs - 5);
```

If Fabric event delivery already consumed 60 ms, only 35 ms remains for the HTTP POST to Ryu.

### Per-RSU FlowMod URL Routing (E-2)

Each RSU runs its own Ryu agent. The listener maps peer IDs to URLs:
```
peer0.rsu1.tetaguard.net → http://ryu-rsu1:8080  (or RSU1_OPENFLOW_URL env var)
peer0.rsu2.tetaguard.net → http://ryu-rsu2:8080
...
```

### Periodic Trust Round Timer

```javascript
setInterval(async () => {
    // Simulate participation: rsu5 or obu3 absent every 5th/10th round
    await c.submitTransaction('UpdateTrustRound', nodeID,
        JSON.stringify(participating), JSON.stringify(ALL_PEERS));
    await c.submitTransaction('PeriodicPeerReSelection',
        JSON.stringify(SELECT_PEERS_POOL));
    await c.submitTransaction('CreateAnchorCheckpoint',
        nodeID, intervalBlocks);
}, intervalMs);  // default 100ms = T_b
```

Score table printed every 10th round to avoid log flood.

---

## 12. WITH RSU — Full Operation

This section describes the complete operational flow when RSU infrastructure is present in NS-3 (N_RSUs > 0) and the corresponding Fabric RSU peers (rsu1–rsu5) are registered.

### Setup

```bash
# Bootstrap with RSU peers registered at τk=1.0
RegisterRSUPeer("peer0.rsu1.tetaguard.net")
RegisterRSUPeer("peer0.rsu2.tetaguard.net")
...
RegisterRSUPeer("peer0.rsu5.tetaguard.net")

# Set mobility and DSRC parameters
SetSimParams(rCommMeters="300", rssiMinDBm="-85")
SetMobilityParams(tPBFTMs="100", vMaxKmh="80")

# Register controller(s)
RegisterController("ctrl0", "zone-1")
RegisterController("ctrl1", "zone-2")
```

### Normal Beacon Interval (every 100ms)

```
NS-3 layer:
  Vehicles broadcast CustomDataTag1 via DSRC (Ch178, 5.89GHz)
  RSU nodes receive these, aggregate into topology snapshot
  RSU → Controller via CSMA/UDP (RSU_dataunicast_agent)
  PEM 9-signature detector evaluates each topology update

Blockchain layer (every T_b = 100ms):
  RSU Fabric peer → SubmitBeaconEvidence(B_nk(t))
    ├── Stores BEACON:<peer>:<ts> on ledger
    └── Evidence used for divergence checks in Flow 3

  Periodic trust round:
    UpdateTrustRound(nodeID, participating, all) → rewards/penalties
    PeriodicPeerReSelection(allPeers) → recomputes Pactive
    CreateAnchorCheckpoint(nodeID, intervalBlocks=215) → every 215 rounds (≈21.5s urban)
```

### Attack Detection → Mitigation (TTW-S2 example: Malicious RSU)

```
t=10s  V1, V2 broadcast DSRC beacons
t=10s  Malicious RSU stores <V1 sees V2, t=10> legitimately

t=15s  Physical link V1↔V2 breaks (V1 moves away)

t=20s  Malicious RSU sends forged <V1 sees V2, t=20> to controller
       Controller installs ghost route

NS-3 PEM fires at t=20.05s:
  Score > PEM_SCORE_THRESHOLD (0.12)
  TTW-S1 signature #0 triggered

submit_alerts.py reads tgn_alerts.json:
  Calls SubmitAlert("peer0.rsu1", alertJSON, ctrlTopoJSON, intervalTS)

SubmitAlert:
  ① Verify caller trust (TE-06): τk(rsu1) = 1.0 ≥ TrustMin ✓
  ② Store DetectionEvent on ledger
  ③ SubmitControllerTopology → checkControllerDivergence
     δ = |ghost links| = 1, δ_thresh = ⌈(1.1)·λ̂·600⌉+1 ≈ 2
     if δ > thresh → emit ControllerOriginAttack
  ④ selectPeers → Pactive = {rsu1, rsu2, rsu3, rsu4}  [np=4]
     thresholdT = 4/2+1 = 3
  ⑤ runMitigation(alerts, θFS=0.40, T=3):
     PBFT: Σ τk(approving) / Σ τk(active) = 1.0/4.0 = 0.25 < 2/3
     → PBFT FAIL (only 1 peer submitted the alert)
     → SubmitLWDetectionResult from multiple RSU peers needed for quorum

SubmitLWDetectionResult (from rsu1, rsu2, rsu3):
  Each RSU verifies locally → submits independently
  runMitigation with 3 approving peers:
  PBFT: 3·1.0 / 4·1.0 = 0.75 > 2/3 ✓

  Bootstrap complete (5 RSU peers × τk=1.0 ≥ TrustMinGT):
    isPreliminary = false → enforcement enabled

  TTW variant:
    getSignatureEvidence(vid, alertTS) → [rsu1_sig, rsu2_sig, rsu3_sig]
    verifyThresholdSig(evidence, T=3) → 3 ≥ 3 ✓
    pushFlowModDrop(vid) → ledger "FLOWMOD_DROP_V2_<ms>"
    revokeSessionKey(vid) → event "KeyRevocation"
    publishBlacklistBeacon(vid) → event "BlacklistBeaconPublished"
    flagReauth(vid, "TTW") → REAUTH:V2
    updateTrust(V2, zero=true) → demotePeerToClient (if RSU) or zero (if OBU)

  Reward honest peers:
    rsu1,rsu2,rsu3,rsu4: τk += 0.05 (V2 excluded as attacker)

Off-chain eventListener:
  AttackDetected → executeFlowMod → POST http://ryu-rsu2:8080/stats/flowentry/add
    {priority:65000, match:{eth_src:"02:00:00:00:00:02"}, actions:[]}
  KeyRevocation → append to revoked_keys.json
  BlacklistBeaconPublished → write /tmp/blacklist_vehicle_ids.txt: "2"

NS-3 routing.cc (1s later):
  ReadBlacklistFile() reads "2" → g_blacklisted_nodes.insert(2)
  BroadcastBlacklist() → CustomBlacklistTag DSRC broadcast
  Rx() handler: drops all CustomDataTag1 from node 2
```

### Controller Origin Attack (TTW-S3/S4: Malicious Controller)

```
t=20s  Malicious controller internally replays old topology entry
       SubmitControllerTopology called with forged G_t^C

checkControllerDivergence:
  E_t^nodes from beacon evidence = {V1↔V2: false (link broke at t=15s)}
  G_t^C = {V1↔V2: true (controller's claim)}
  δ = 1 > δ_thresh → ControllerOriginAttack event emitted

runMitigation (variant = CTRL_ORIGIN):
  getAllBeaconEvidence(alertTS)
  pushFlowModOverride(ctrlID, evidence)
    → FLOWMOD_OVERRIDE_CTRL_<ctrl> at priority 65535 (catch-all)
    → FLOWMOD_OVERRIDE_<vid> at priority 65534 (per-vehicle)

  CheckControllerTrustAndReassign(ctrl, allCtrls):
    updateCtrlTrust(ctrl) → τCj -= 0.20
    if τCj < 0.30:
      selectBackupController → backup with highest τCj
      Write CTRL_REASSIGN record
      publishControllerRevokedBeacon → event "ControllerRevokedBeaconPublished"
      event "ControllerRemoved"

Off-chain eventListener:
  ControllerRemoved → RSU mgmt API: PUT new primary controller
  ControllerRevokedBeaconPublished → log backup notification
```

---

## 13. WITHOUT RSU — No-RSU / OBU-Only Mode

This section describes operation when N_RSUs=0 in NS-3. Fabric RSU Docker containers still exist (they are the blockchain infrastructure), but the NS-3 vehicular RSU nodes do not. The "no-RSU" label refers to the physical roadside unit nodes in the vehicular network.

### Key Differences from With-RSU Mode

| Aspect | With RSU | Without RSU (NS-3 layer) |
|---|---|---|
| Topology relay | Vehicle → RSU → Controller | Vehicle → Controller (LTE or DSRC direct) |
| Fabric evidence source | RSU Fabric peers (τk=1.0) | OBU Fabric peers (τk starts at 0.10) |
| Trust round driver | Tier 1 RSU Fabric peers | Highest-trust OBU (TR-01 bootstrap mode) |
| Bootstrap duration | Immediate (RSU τk=1.0≥0.50) | R_min rounds to reach TrustMinGT |
| `selectPeers` pool | RSUs + OBUs | OBUs only (SELECT_PEERS_POOL=ALL_OBU_PEERS) |
| Controller removal | RSU emergency channel | OBU V2V + ControllerRevokedBeacon |
| Blacklist propagation | RSU → DSRC broadcast | OBU V2V (⌈diam(Gt)⌉ hops) |

### Bootstrap Duration in No-RSU Mode

Starting from τk = TrustInitTier2 = 0.10 for OBU peers:

```
R_min = ⌈(TrustMinGT - TrustInitTier2) / TrustDeltaPlus⌉
      = ⌈(0.50 - 0.10) / 0.05⌉
      = ⌈8⌉ = 8 rounds
```

After 8 consecutive correct rounds, an OBU reaches τk = 0.50 = TrustMinGT. Then np=4 OBU peers must each reach this threshold before `isBootstrapComplete` returns true.

During bootstrap:
- `SubmitBeaconEvidence` is accepted at the lower TrustMin floor (0.10)
- Evidence is stored on ledger but NOT used for divergence ground-truth
- `runMitigation` logs `BOOTSTRAP_PRELIMINARY_NO_ENFORCEMENT` and skips all enforcement
- This prevents false mitigations before trust is established

### No-RSU Trust Round Driver (TR-01)

```go
// In UpdateTrustRound:
if hasRSU {
    // Normal: require Tier 1 RSU caller
} else {
    // No RSU: highest-trust OBU above TrustMin may call
    if callerTrust.Score < TrustMin || callerTrust.Flagged {
        return error
    }
}
```

The Fabric RSU Docker peer (`peer0.rsu1.tetaguard.net`) is registered and always present as the CALLER of `UpdateTrustRound` — but its `IsRSUPeer` flag in the trust record controls the gate, not the TCP connection. In no-RSU NS-3 scenarios the eventListener sets `noRSU=true`, changing `SELECT_PEERS_POOL` to OBU-only. The Fabric RSU peer still calls `UpdateTrustRound` as the technical submitter; the distinction is in what `hasRSU` finds when scanning `TRUST:*` records.

### No-RSU Attack Mitigation Path

When a vehicle is confirmed malicious (TTW/BSHH):

```
runMitigation → pushFlowModDrop → ledger FLOWMOD_DROP_<vid>
              → publishBlacklistBeacon → event "BlacklistBeaconPublished"

eventListener:
  BlacklistBeaconPublished:
    writes /tmp/blacklist_vehicle_ids.txt
    
NS-3 routing.cc:
  ReadBlacklistFile() every 1s → g_blacklisted_nodes.insert(vid)
  BroadcastBlacklist(node) every 5s:
    CustomBlacklistTag DSRC broadcast (802.11p Ch178)
    Rx() callback on each receiving node:
      merge blacklist → g_blacklisted_nodes.insert(each_id)
      drop CustomDataTag1 packets from blacklisted senders
```

Propagation delay: ⌈diam(G_t)⌉ × 5s beacon intervals for full network coverage.

### No-RSU Controller Removal

When controller trust falls below TrustCtrlMin (0.30):

```
CheckControllerTrustAndReassign:
  selectBackupController(allCtrls) → best non-failed controller
  publishControllerRevokedBeacon(ctrlID, backupCtrlID)
    → Fabric event "ControllerRevokedBeaconPublished"
    → ledger "CTRL_REVOKED_BEACON:<ctrlID>"

eventListener.handleControllerRevokedBeaconPublished:
  logs: "Backup controller notified to solicit topology via V2X"
  (in production: OBU peers query ledger for CTRL_REVOKED_BEACON:*
   and distribute via V2V DSRC to inform vehicles of controller change)

Vehicles begin sending topology directly to backup controller
```

---

## 14. Bootstrap Phase

### State Machine

```
All peers at τk=0.10 (Tier 2 initial) OR τk=1.0 (Tier 1 RSU)

Bootstrap active: isBootstrapComplete = false
  → evidence stored but excluded from ground truth
  → mitigation in log-only mode (no enforcement)
  → OBU trust accumulates via UpdateTrustRound

Bootstrap complete when:
  count(peers with τk ≥ 0.50 and not Flagged) ≥ np = 4

After bootstrap:
  → SubmitBeaconEvidence enforces τk ≥ 0.50 for non-RSU peers
  → runMitigation enforces all mitigations
  → OBU promotion into Pactive becomes active
```

### `GetBootstrapStatus`

Returns current state: `qualified_peers`, `required_peers_np=4`, `tau_mingt=0.50`, `rmin_rounds=8`, `bootstrap_complete bool`.

---

## 15. Peer State Machine (Demotion Pipeline)

RSU Fabric peers go through a 3-stage demotion when confirmed malicious. OBU/vehicle trust is zeroed immediately.

```
ACTIVE ──(confirmed attack)──► QUARANTINED_CLIENT
                                    │
                                    │ monitorAndRemovePeer called every round
                                    │ (runMitigation + PeriodicPeerReSelection)
                                    │
                            QuarantineMonitorMs = 30,000ms elapsed?
                                    │
                              τk ≤ TrustMin (0.10)?
                                    │
                                    ▼
                                 REMOVED  ──► PeerRemoved event
```

**Stage 1 — `demotePeerToClient`:**
- τk = 0.0, Flagged = true, State = QUARANTINED_CLIENT
- IsRSUPeer = false (stripped of peer role; becomes client observer)
- Excluded from Pactive immediately
- Emits `PeerQuarantined` event

**Stage 2 — monitoring:**
- `monitorAndRemovePeer` checks elapsed time
- If still within 30s window: keep monitoring, no action
- Trust continues to be updated (cannot recover from 0 without explicit intervention)

**Stage 3 — `REMOVED`:**
- Quarantine window elapsed and τk ≤ TrustMin
- State = REMOVED, permanent expulsion
- Emits `PeerRemoved` event

---

## 16. Constants Reference

| Constant | Value | Meaning |
|---|---|---|
| `TrustDeltaPlus` | 0.05 | Trust reward per correct round |
| `TrustDeltaMinus` | 0.10 | Trust penalty per missed round |
| `TrustDeltaCtrl` | 0.20 | Controller trust penalty per divergence |
| `TrustMin` | 0.10 | Participation floor (must have to submit) |
| `TrustMinGT` | 0.50 | Ground-truth floor (must have for evidence to count) |
| `TrustCtrlMin` | 0.30 | Controller removal threshold |
| `TrustInitTier1` | 1.00 | RSU Fabric peer initial trust |
| `TrustInitTier2` | 0.10 | OBU Fabric peer initial trust |
| `TrustMinDwellMs` | 3000 | Legacy constant (replaced by dynamic computeTMinMs) |
| `HWCapacityMinMB` | 2048 | Minimum OBU RAM for Pactive eligibility |
| `FaultToleranceF` | 1 | Byzantine fault tolerance parameter |
| `np = 3f+1` | 4 | Active peer set size |
| `QuarantineMonitorMs` | 30000 | 30s monitoring window before permanent removal |
| `AnchorIntervalBlocksUrban` | 215 | Checkpoint interval (urban, ≈21.5s) |
| `AnchorIntervalBlocksHighway` | 45 | Checkpoint interval (highway, ≈4.5s) |
| `θFS` | 0.40 | Full-stack (TGN) detection threshold |
| `θLW` | 0.30 | Lightweight (PEM) detection threshold |
| `PEM_SCORE_THRESHOLD` (NS-3) | 0.12 | PEM score to raise alert (routing.cc) |
| `TOTAL_LATENCY_BUDGET_MS` | 100 | End-to-end FlowMod delivery budget |

---

## 17. Complete Chaincode Function Index

### Entry Points (callable by clients)

| Function | File | Purpose |
|---|---|---|
| `SubmitBeaconEvidence` | temporalecho.go | Flow 1: store ground-truth observations |
| `SubmitDetectionEvent` | temporalecho.go | Flow 2: store per-alert O_rk |
| `SubmitControllerTopology` | temporalecho.go | Flow 3: store + check G_t^C |
| `SubmitAlert` | temporalecho.go | Primary TGN→blockchain entry point |
| `SubmitLWDetectionResult` | temporalecho.go | LW path: RSU local detection result |
| `Mitigate` | temporalecho.go | Direct Algorithm 4 invocation |
| `ClearReauth` | temporalecho.go | Re-admit vehicle after re-authentication |
| `RegisterController` | temporalecho.go | Register SDN controller + zone |
| `RegisterPeerKey` | temporalecho.go | Store Dilithium2 public key |
| `SetSimParams` | temporalecho.go | Set rComm, rssiMin at bootstrap |
| `SetMobilityParams` | temporalecho.go | Set T_PBFT, v_max at bootstrap |
| `SubmitIndividualSigEvidence` | temporalecho.go | TTW/BSHH threshold sig evidence |
| `SubmitWitnessRecord` | temporalecho.go | ME quorum witness record |
| `SubmitVehicleMAC` | temporalecho.go | Register vehicle MAC address |
| `RegisterRSUPeer` | trust.go | Register RSU Fabric peer at τk=1.0 |
| `RegisterOBUPeer` | trust.go | Register OBU at τk=0.10 with dwell tracking |
| `UpdateTrustRound` | trust.go | Apply per-round trust rewards/penalties |
| `ZeroTrust` | trust.go | Initiate demotion (Tier 1 RSU caller required) |
| `DemotePeerToClient` | trust.go | Public demotion pipeline entry |
| `PeriodicPeerReSelection` | trust.go | Recompute Pactive + emit events |
| `SelectPeers` | trust.go | Query Pactive (read-only) |
| `CheckPBFTConsensus` | trust.go | Query consensus result (read-only) |
| `CheckControllerTrustAndReassign` | trust.go | Apply ΔC- + trigger reassignment |
| `GetTrustScore` | trust.go | Query τk for a peer |
| `GetControllerTrustScore` | trust.go | Query τCj for a controller |
| `GetBootstrapStatus` | trust.go | Query bootstrap phase status |
| `GetTrustedEvidence` | trust.go | Query beacon evidence from τk≥0.50 peers |
| `CreateAnchorCheckpoint` | anchor.go | PBFT-signed ledger digest |
| `SyncFromAnchorCheckpoint` | anchor.go | OBU confirms sync from latest checkpoint |
| `GetLatestAnchorCheckpoint` | anchor.go | Query most recent checkpoint |
| `GetMitigationHistory` | temporalecho.go | Query MITIGATION_LOG by vehicle |
| `GetReauthFlag` | temporalecho.go | Query re-authentication block |
| `GetPendingFlowMod` | temporalecho.go | Read one FlowMod by key |
| `GetAllPendingFlowMods` | temporalecho.go | Read all unexecuted FlowMods (T-2) |
| `AcknowledgeFlowMod` | temporalecho.go | Mark FlowMod executed |
| `QueryDetectionEventsByVehicle` | temporalecho.go | Query detection events (T-5) |
| `QueryBeaconEvidenceByInterval` | temporalecho.go | Query beacon records (T-5) |
| `GetDivergenceDelta` | temporalecho.go | Query δ for a controller/interval |
| `GetLatestControllerReassignment` | temporalecho.go | Query reassignment record (E-3) |

---

*Generated: TETA-GUARD FYP — Department of EIE, University of Ruhuna*
*Supervisor: Dr. Nilmantha Wijesekara | Co-supervisor: Dr. Prabath Weerasingha*
