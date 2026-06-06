# Blockchain Layer — TETA-Guard Layer 5 (Hyperledger Fabric)

**Files:** `blockchain/` · `submit_alerts.py`
**Paper reference:** Section 3.4.10, Eqs. 3.1, 3.24, 3.27–3.28, 3.36, Algorithm 4 (FS-MITIGATE)

---

## Overview

The blockchain layer provides tamper-evident evidence logging and automated enforcement independent of a potentially malicious SDN controller. It is grounded in RSU-level evidence — **never** controller-reported data.

```
tgn_detector.cc
    │  tgn_alerts.json  (Eq. 3.36 AlertObject)
    ▼
submit_alerts.py  ←  beacon_evidence.json (optional)
    │  peer chaincode invoke SubmitAlert
    ▼
┌─────────────────────────────────────────────────────────┐
│  Hyperledger Fabric 3.0 — 5-RSU Consortium             │
│  Channel: teta-channel                                  │
│  Chaincode: temporalecho (TemporalEchoMitigator)        │
│                                                         │
│  Endorsement policy: OutOf(3, RSU1..RSU5)              │
│  PBFT tolerance: ⌊(5−1)/3⌋ = 1 Byzantine peer         │
└─────────────────────────────────────────────────────────┘
```

---

## Architecture

### Three Independent Data Flows (none via controller)

**Flow 1 — RSU Beacon Evidence Log**
Each RSU submits signed beacon evidence directly to its Fabric peer:
```
B_nk(t) = {(vid, τs, pos_v, RSSI_v, σ_nk) : v ∈ V_nk(t)}
```
Establishes tamper-evident ground truth of what each RSU observed.

**Flow 2 — RSU-Level LW Detection Events**
Each RSU runs Algorithm 1 (LW-DETECT) locally and submits detection events:
```
O_rk = (vid, α, s(e), S_trig, t_alert)
```
Submitted directly to its Fabric peer — no controller in the path.

**Flow 3 — Controller Topology Claim**
The controller submits its topology view G^C_t to Fabric. The smart contract compares it against RSU beacon evidence. Divergence exceeding δ_thresh (Eq. 3.1) triggers a controller-origin alert without relying on the controller's own reporting.

---

## Network Structure

```
blockchain/
├── chaincode/
│   └── temporalecho/
│       ├── temporalecho.go         — SubmitAlert, Mitigate, SubmitBeaconEvidence (Algorithm 4 full)
│       ├── structs.go              — AlertObject, DetectionEvent, BeaconEvidenceRecord, PendingFlowMod
│       ├── verification.go         — shared: verifyThresholdSig (Eq.3.24), verifyQuorum (Eqs.3.27-3.28)
│       ├── verification_stub.go    — default build: Dilithium2 stub + init() warning banner
│       ├── verification_liboqs.go  — real build (-tags liboqs): real OQS Dilithium2 verify
│       ├── divergence.go           — computeDivergence (Eq.3.1), checkControllerDivergence
│       ├── flowmod.go              — writes PendingFlowMod to ledger (no HTTP calls in chaincode)
│       ├── go.mod
│       └── go.sum
├── network/
│   ├── docker-compose-teta.yaml  — 5 RSU peers + 1 orderer  (MSP: TetaGuardMSP)
│   ├── crypto-config.yaml        — MSP and TLS certificates
│   └── configtx.yaml             — channel and policy configuration
├── client/
│   ├── submitToFabric.js    — Fabric Gateway SDK client; pre-flight cert checks added
│   ├── eventListener.js     — listens for events AND executes FlowMod HTTP POST to Ryu off-chain
│   └── package.json
├── scripts/
│   ├── bootstrap.sh         — full network setup
│   ├── create_channel.sh    — create teta-channel
│   └── deploy_chaincode.sh  — package, install, approve, commit
└── config/
    └── connection-profile.json
```

---

## Smart Contract — TemporalEchoMitigator

### Primary Entry: `SubmitAlert` (Algorithm 4 Step 12–22)

Called by `submit_alerts.py` after TGN writes `tgn_alerts.json`.

**Input (Eq. 3.36 AlertObject):**
```json
{
  "v_id":    "3",
  "alpha":   "TTW",
  "y_hat":   0.8731,
  "S_trig":  [0, 1],
  "t_alert": 20050
}
```

**Execution flow:**
```
1. Parse AlertObject JSON
2. Convert to DetectionEvent, store on ledger (immutable log)
3. Optional divergence check vs RSU beacon evidence (Eq. 3.1)
4. Call runMitigation() for variant-specific response
```

### Full Mitigation: `Mitigate` (Algorithm 4 complete)

Called by the Node.js SDK client with full beacon evidence and controller topology claim.

```
Step 3:  δ = |E_t^C △ E_t^nodes|  →  if δ > δ_thresh: add CTRL_ORIGIN alert
Step 12: resolveDualPath() — union of LW + FS alerts, most restrictive wins
Step 15: verifyThresholdSig() (Eq.3.24) — TTW/BSHH
Step 16: PUSH_FLOWMOD(DROP, vid) → SDN controller isolation
Step 17: revokeSessionKey() — LKH O(log n) update
Step 19: getWitnesses() — ME
Step 20: verifyQuorum() (Eqs.3.27–3.28) — spatial + RSSI plausibility
Step 21: invalidateFalsePaths() — remove phantom ME paths
Step 22: PUSH_REROUTE_FLOWMOD()
         FLAG_REAUTH(vid)
         LOG(ledger, immutable)
         EMIT(AttackDetected, {vid, α, ŷ_v, t})
```

### Controller-Origin Detection (Eq. 3.1)

```go
// divergence.go
delta = |E_t^C △ E_t^nodes|    // symmetric difference of edge sets
if delta > deltaThresh:
    append CTRL_ORIGIN alert
    override controller routing table with RSU evidence
```

### Cryptographic Verification Helpers (`verification.go`)

**`verifyThresholdSig` — Eq. 3.24:**
```go
|{i : Verify(σi, msgi, PKVi) = 1}| ≥ t
```
Requires strict majority of individual Dilithium2 signatures. Production: liboqs-go.

**`verifyQuorum` — Eqs. 3.27–3.28:**
```go
for each witness Vk:
    Verify(σ_Vk, PK_Vk)                   // cryptographic
    d(pos_Vk, e_ij) ≤ 300 m               // spatial plausibility
    RSSI_Vk←Vi ≥ −85 dBm                  // signal plausibility
accepted ≥ t  →  ACCEPT
```

### Alert Interface — Eq. 3.36

```
O = (vid, α, ŷ_v, S_trig, t_alert)

vid     — offending node identifier
α       — "TTW" | "BSHH" | "ME" | "CTRL_ORIGIN"
ŷ_v     — anomaly score from TGN (Eq.3.23) or LW score (Eq.3.11)
S_trig  — triggered signature indices subset of {0,...,8}
t_alert — alert timestamp (ms)
```

### FlowMod Enforcement — Off-Chain Pattern

**Critical architectural note:** Fabric chaincode runs in a deterministic sandboxed container and **cannot make HTTP calls**. The correct pattern is:

```
Chaincode (temporalecho.go)
  └─ writes PendingFlowMod record to ledger

eventListener.js (off-chain)
  └─ receives AttackDetected event
  └─ reads PendingFlowMod from ledger
  └─ POSTs to Ryu SDN controller HTTP REST API
       http://ryu-controller:8080/stats/flowentry/add
```

`flowmod.go` no longer contains `net/http` — it only writes `PendingFlowMod` structs to the Fabric ledger via `g_ctx.GetStub().PutState()`. `eventListener.js` is the off-chain executor of the actual FlowMod HTTP call.

### Vehicle MAC Address Resolution

`vehicleMAC()` now uses a two-tier lookup:
1. **Ledger table** (`VMAC_<vehicleID>` key) — populated at network setup via `SubmitVehicleMAC()`
2. **Fallback** `ns3VehicleIDtoMAC()` — derives locally-administered unicast MAC: `02:00:00:00:HH:LL` from vehicle index (e.g. `V2` → `02:00:00:00:00:02`)

The old implementation (ASCII bytes of the vehicle ID string) produced invalid MACs that would not match real NIC addresses.

### Dual-Path Conflict Resolution

When both LW and FS paths raise alerts for the same node simultaneously:
- Smart contract takes **union** of detected variants
- **FlowMod DROP** takes precedence over path invalidation
- Prevents race conditions at the SDN controller

---

## PBFT Consensus

```
Endorsement policy: OutOf(3, RSU1..RSU5)
Byzantine tolerance: ⌊(5−1)/3⌋ = 1 faulty peer tolerated

If consensus not reached → ABORT (no mitigation on single-peer evidence)
```

Smart contract execution latency: 50–200 ms. The LW path provides immediate provisional isolation (within `O(|W|)`) while blockchain consensus completes.

---

## JSON Schema Compatibility

`tgn_alerts.json` → `submit_alerts.py` → `SubmitAlert` → `AlertObject` in `structs.go`:

| tgn_detector.cc writes | submit_alerts.py reads | structs.go JSON tag |
|------------------------|------------------------|---------------------|
| `"v_id"` | `alert.get("v_id")` | `json:"v_id"` |
| `"alpha"` | `alert.get("alpha")` | `json:"alpha"` |
| `"y_hat"` | `alert.get("y_hat")` | `json:"y_hat"` |
| `"S_trig"` | `alert.get("S_trig")` | `json:"S_trig"` |
| `"t_alert"` | `alert.get("t_alert")` | `json:"t_alert"` |

All three files use identical JSON field names — no schema mismatch.

---

## Build and Run

### 1. Prerequisites (Ubuntu)
```bash
# Docker and Docker Compose
sudo apt-get install docker.io docker-compose

# Go 1.21+
sudo apt-get install golang-go

# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Hyperledger Fabric binaries and Docker images
cd blockchain
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

### 2. Start the Fabric Network
```bash
cd blockchain/scripts
chmod +x bootstrap.sh create_channel.sh deploy_chaincode.sh

# Full setup (network + channel + chaincode)
bash bootstrap.sh

# Or step by step:
cd ../network
docker-compose -f docker-compose-teta.yaml up -d        # start peers + orderer
cd ../scripts
bash create_channel.sh                                    # create teta-channel
bash deploy_chaincode.sh                                  # deploy TemporalEchoMitigator
```

### 3. Verify Network is Running
```bash
docker ps                                                 # should show 5 RSU peers + orderer
peer chaincode list --installed -C teta-channel           # should show temporalecho
```

### 4. Submit TGN Alerts (after tgn_detector run)
```bash
# Simple path (peer CLI)
python3 submit_alerts.py --alerts tgn_alerts.json

# With beacon evidence for divergence check
python3 submit_alerts.py --alerts tgn_alerts.json --evidence beacon_evidence.json

# Dry run (print commands without executing)
python3 submit_alerts.py --alerts tgn_alerts.json --dry-run

# Custom network path
python3 submit_alerts.py --alerts tgn_alerts.json --network /path/to/blockchain/network
```

### 5. Full SDK Path (Node.js)
```bash
cd blockchain/client
npm install
node submitToFabric.js --alerts tgn_alerts.json
node submitToFabric.js --alerts tgn_alerts.json --evidence beacon_evidence.json --ctrl_topo ctrl_topo.json
```

### 6. Monitor Events
```bash
node blockchain/client/eventListener.js
# Listens for AttackDetected events on teta-channel
```

### 7. Tear Down
```bash
cd blockchain/network
docker-compose -f docker-compose-teta.yaml down -v       # stop and remove volumes
```

---

## Output

| File | Contents |
|------|----------|
| `blockchain_submission_log.txt` | Per-alert 4-step trace: alert received → Fabric invocation → PBFT consensus → smart contract actions |
| Fabric ledger | Immutable `DetectionEvent` and `MitigationLogEntry` records |

### Example `blockchain_submission_log.txt` entry
```
────────────────────────────────────────
[14:23:07]  ALERT 1/2

  STEP ①  ALERT RECEIVED FROM TGN  (Eq. 3.36)
    Vid        : 2
    α (variant): TTW
    ŷ_v (score): 0.8731
    S_trig     : [0, 1]  →  TTW-S1, TTW-S2
    t_alert    : 20050 ms

  STEP ②  FABRIC INVOCATION  (Section 9.3)
    Channel    : teta-channel
    Chaincode  : temporalecho
    Function   : SubmitAlert
    Endorsers  : 3/5 peers required

  STEP ③  PBFT CONSENSUS  (§3.4.10)
    Policy     : OutOf(3, RSU1..RSU5)
    Tolerance  : 1 faulty peer(s) tolerated

  STEP ④  SMART CONTRACT ACTIONS  (Algorithm 4)
    VERIFY_THRESHOLD_SIG(V2)
    PUSH_FLOWMOD(DROP, V2)
    REVOKE_SESSION_KEY(V2)
    LOG(L, {V2, 0.8731, 20050})
    EMIT(AttackDetected, {V2, TTW, 0.8731})

  VERDICT: COMMITTED — record immutable
```
