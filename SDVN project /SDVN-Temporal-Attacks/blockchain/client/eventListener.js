/**
 * eventListener.js — Hyperledger Fabric event listener + FlowMod executor (§10.2)
 *
 * Listens for chaincode events from TemporalEchoMitigator and executes the
 * actual HTTP FlowMod calls to the Ryu SDN controller OFF-CHAIN.
 *
 * WHY OFF-CHAIN:
 *   Fabric chaincode runs in a deterministic sandboxed container — it cannot
 *   make HTTP calls.  The chaincode writes PendingFlowMod records to the
 *   ledger; this listener reads them and executes the real HTTP POST to Ryu.
 *
 * Five events handled:
 *   AttackDetected          → read PendingFlowMod from ledger → POST to Ryu
 *   KeyRevocation           → write revoked_keys.json (polled by crypto_pipeline)
 *   ControllerOriginAttack  → operator escalation + OVERRIDE FlowMods
 *   ControllerRemoved       → E-3: action zone southbound switch
 *   AnchorCheckpointCreated → E-3: log new checkpoint for OBU sync
 *   PeerQuarantined         → log demotion; alert operator; suspend RSU data relay
 *   PeerRemoved             → log permanent removal; alert operator
 *   ControllerRemovalFailed → critical alert: no backup controller available
 *
 * E-2: Per-RSU Ryu agent URL mapping. Each RSU runs a local Ryu OpenFlow agent
 *      on port 8080.  In docker-compose add ryu-rsu1..ryu-rsu5 services.
 *      Override via env vars: RSU1_OPENFLOW_URL, RSU2_OPENFLOW_URL, etc.
 *
 * Usage:
 *   node eventListener.js [--node_id <peer>] [--rsu_url <url>]
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const fs   = require('fs');
const path = require('path');

const CHANNEL      = 'teta-channel';
const CHAINCODE    = 'temporalecho';
const PEER_ID      = 'peer0.rsu1.tetaguard.net';
const WALLET_PATH  = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');
const REVOKED_KEYS_FILE = path.join(__dirname, '..', '..', 'revoked_keys.json');
const LOG_FILE     = path.join(__dirname, '..', '..', 'blockchain_submission_log.txt');

// E-2 FIX: Per-RSU Ryu OpenFlow agent URL mapping.
const RSU_FLOWMOD_URLS = {
    'peer0.rsu1.tetaguard.net': process.env.RSU1_OPENFLOW_URL || 'http://ryu-rsu1:8080',
    'peer0.rsu2.tetaguard.net': process.env.RSU2_OPENFLOW_URL || 'http://ryu-rsu2:8080',
    'peer0.rsu3.tetaguard.net': process.env.RSU3_OPENFLOW_URL || 'http://ryu-rsu3:8080',
    'peer0.rsu4.tetaguard.net': process.env.RSU4_OPENFLOW_URL || 'http://ryu-rsu4:8080',
    'peer0.rsu5.tetaguard.net': process.env.RSU5_OPENFLOW_URL || 'http://ryu-rsu5:8080',
};

// EL-01: Per-RSU southbound management API for controller reassignment.
const RSU_MGMT_URLS = {
    'peer0.rsu1.tetaguard.net': process.env.RSU1_MGMT_URL || 'http://ryu-rsu1:8081',
    'peer0.rsu2.tetaguard.net': process.env.RSU2_MGMT_URL || 'http://ryu-rsu2:8081',
    'peer0.rsu3.tetaguard.net': process.env.RSU3_MGMT_URL || 'http://ryu-rsu3:8081',
    'peer0.rsu4.tetaguard.net': process.env.RSU4_MGMT_URL || 'http://ryu-rsu4:8081',
    'peer0.rsu5.tetaguard.net': process.env.RSU5_MGMT_URL || 'http://ryu-rsu5:8081',
};

// Fallback for unknown node IDs
let RSU_OPENFLOW_BASE = process.env.RSU_OPENFLOW_BASE || 'http://ryu-rsu1:8080';

// EL-02: Total latency budget (100 ms). FlowMod timeout = budget - Fabric delivery latency.
const TOTAL_LATENCY_BUDGET_MS = 100;
const FLOWMOD_MIN_TIMEOUT_MS  = 10;

// ─── HTTP FlowMod execution (off-chain) ───────────────────────────────────────

/**
 * executeParsedFlowMod sends a pre-parsed PendingFlowMod to the Ryu SDN agent.
 *
 * EL-02 FIX: Adaptive timeout. The paper budgets 100 ms total from alert creation
 * to FlowMod delivery. If Fabric event delivery already consumed 60 ms, we have
 * only 40 ms left for the HTTP POST. Using a fixed 50 ms timeout could exceed
 * the budget; being too aggressive could abort a valid POST prematurely.
 * eventTimestampMs (when the alert was created on-chain) enables measurement.
 */
async function executeParsedFlowMod(pendingFM, callerNodeID, eventTimestampMs) {
    const ryuBase = RSU_FLOWMOD_URLS[callerNodeID] || RSU_OPENFLOW_BASE;
    const action  = pendingFM.action || 'DROP';
    const url     = (action === 'REROUTE' || action === 'DELETE')
        ? `${ryuBase}/stats/flowentry/delete`
        : `${ryuBase}/stats/flowentry/add`;

    const ryuFM = {
        dpid:         1,
        table_id:     0,
        idle_timeout: 0,
        hard_timeout: 0,
        priority:     pendingFM.priority,
        match:        pendingFM.match || {},
        actions:      pendingFM.flow_actions || []
    };
    const body = JSON.stringify(ryuFM);
    console.log(`[FlowMod] POST ${url}  action=${action}  vehicle=${pendingFM.vehicle_id}`);

    // EL-02: compute adaptive timeout from remaining budget
    let flowModTimeout;
    if (eventTimestampMs && eventTimestampMs > 0) {
        const elapsedMs = Date.now() - eventTimestampMs;
        flowModTimeout  = Math.max(FLOWMOD_MIN_TIMEOUT_MS, TOTAL_LATENCY_BUDGET_MS - elapsedMs - 5);
    } else {
        flowModTimeout  = TOTAL_LATENCY_BUDGET_MS / 2; // fallback: half the budget
    }

    try {
        const fetchFn  = globalThis.fetch || require('node-fetch');
        const abortCtl = new AbortController();
        const timer    = setTimeout(() => abortCtl.abort(), flowModTimeout);
        const resp = await fetchFn(url, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
            signal:  abortCtl.signal
        });
        clearTimeout(timer);
        if (resp.ok) {
            console.log(`[FlowMod] ✓  ${action} installed  vehicle=${pendingFM.vehicle_id}  HTTP ${resp.status}`);
            appendLog(`FlowMod ${action} executed  vehicle=${pendingFM.vehicle_id}  HTTP ${resp.status}`);
        } else {
            console.warn(`[FlowMod] ✗  Ryu rejected FlowMod: HTTP ${resp.status}`);
        }
    } catch (err) {
        if (err.name === 'AbortError') {
            console.warn(`[FlowMod] ✗  Ryu timeout (${flowModTimeout}ms budget)  vehicle=${pendingFM.vehicle_id}`);
        } else {
            console.warn(`[FlowMod] ✗  Could not reach Ryu at ${ryuBase}: ${err.message}`);
        }
    }
}

/**
 * executeFlowMod reads PendingFlowMod from the ledger and POSTs to Ryu.
 * E-2: uses per-RSU URL mapping via callerNodeID.
 */
// executeFlowMod: look up latest matching FlowMod via GetAllPendingFlowMods
// (FM-02: EntryIDs now include timestamps so a fixed key lookup would miss them).
// Falls back to constructing a default FlowMod if no ledger record is found.
async function executeFlowMod(network, vehicleID, action, callerNodeID, eventTimestampMs) {
    const nodeForURL = callerNodeID || RSU_OPENFLOW_BASE;
    let pendingFM    = null;

    try {
        const contract = network.getContract(CHAINCODE);
        // FM-02: query all records and find the latest matching this vehicle+action
        const allResult = await contract.evaluateTransaction('GetAllPendingFlowMods');
        if (allResult && allResult.length > 0) {
            const fmList = JSON.parse(allResult.toString());
            if (Array.isArray(fmList)) {
                // Find the most recent unexecuted FlowMod for this vehicle+action
                const matches = fmList.filter(f =>
                    f.vehicle_id === vehicleID && f.action === action && !f.executed
                );
                if (matches.length > 0) {
                    // Take the one with the latest timestamp (embedded in entry_id suffix)
                    pendingFM = matches[matches.length - 1];
                }
            }
        }
    } catch (err) {
        console.warn(`[FlowMod] Could not read FlowMod list from ledger: ${err.message}`);
    }

    // If no ledger record found, build a synthetic one for local execution only.
    // fromLedger=false means the caller must NOT call AcknowledgeFlowMod for it.
    const fromLedger = !!pendingFM;
    if (!pendingFM) {
        pendingFM = {
            entry_id:     `FLOWMOD_${action}_${vehicleID}`,
            vehicle_id:   vehicleID,
            action:       action,
            priority:     action === 'DROP' ? 65000 : 50000,
            match:        {},
            flow_actions: [],
            fromLedger:   false
        };
    } else {
        pendingFM.fromLedger = true;
    }

    await executeParsedFlowMod(pendingFM, nodeForURL, eventTimestampMs);
    return fromLedger ? pendingFM : null; // null → caller skips AcknowledgeFlowMod
}

// ─── Main listener ────────────────────────────────────────────────────────────

async function startEventListener(nodeID = PEER_ID, noRSU = false, intervalMs = 100) {
    const gateway = new Gateway();
    try {
        const connProfile = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
        const wallet      = await Wallets.newFileSystemWallet(WALLET_PATH);

        const identity = await wallet.get(nodeID);
        if (!identity) {
            throw new Error(
                `Identity '${nodeID}' not found. Run scripts/bootstrap.sh first.`
            );
        }

        await gateway.connect(connProfile, {
            wallet,
            identity:  nodeID,
            discovery: { enabled: true, asLocalhost: true }
        });

        const network = await gateway.getNetwork(CHANNEL);
        console.log(`[EventListener] Connected to '${CHANNEL}' as '${nodeID}'`);
        console.log(`[EventListener] RSU OpenFlow agents (emergency channel):`);
        for (const [peer, url] of Object.entries(RSU_FLOWMOD_URLS)) {
            console.log(`  ${peer} → ${url}`);
        }

        // On startup: replay any FlowMods missed during listener downtime (T-2)
        await replayPendingFlowMods(network, nodeID);

        // ── Contract event listener (Fabric SDK 2.2 correct API) ─────────────
        const contract = network.getContract(CHAINCODE);
        await contract.addContractListener(async (event) => {
            const payload = (event.payload && event.payload.length > 0)
                ? JSON.parse(event.payload.toString())
                : {};

            switch (event.eventName) {
                case 'AttackDetected':
                    await handleAttackDetected(network, payload, nodeID);
                    break;
                case 'KeyRevocation':
                    await handleKeyRevocation(payload);
                    break;
                case 'ControllerOriginAttack':
                    await handleControllerOriginAttack(network, payload, nodeID);
                    break;
                case 'ControllerRemoved':
                    await handleControllerRemoved(network, payload);
                    break;
                case 'AnchorCheckpointCreated':
                    await handleAnchorCheckpoint(network, payload);
                    break;
                case 'PeerQuarantined':
                    await handlePeerQuarantined(payload);
                    break;
                case 'PeerRemoved':
                    await handlePeerRemoved(payload);
                    break;
                case 'ControllerRemovalFailed':
                    await handleControllerRemovalFailed(payload);
                    break;
                case 'BlacklistBeaconPublished':
                    await handleBlacklistBeaconPublished(payload);
                    break;
                case 'ControllerRevokedBeaconPublished':
                    await handleControllerRevokedBeaconPublished(payload);
                    break;
                case 'PeerPromoted':
                    handlePeerPromoted(payload);
                    break;
                case 'PeerDroppedFromActive':
                    handlePeerDroppedFromActive(payload);
                    break;
                default:
                    console.log(`[EventListener] Unknown event: ${event.eventName}`);
            }
        });

        console.log('[EventListener] Listening for AttackDetected, KeyRevocation, ' +
                    'ControllerOriginAttack, ControllerRemoved, AnchorCheckpointCreated, ' +
                    'PeerQuarantined, PeerRemoved, ControllerRemovalFailed, ' +
                    'BlacklistBeaconPublished, ControllerRevokedBeaconPublished, ' +
                    'PeerPromoted, PeerDroppedFromActive ...');
        console.log(`[EventListener] Trust round timer: every ${intervalMs}ms  (T_prs = T_b from design)`);
        console.log(`[EventListener] Mode: ${noRSU ? 'NO-RSU (OBU peers only for SelectPeers)' : 'RSU present'}`);
        console.log('[EventListener] Press Ctrl+C to stop.\n');

        // ── Periodic trust round: reward/penalise peers based on participation ──
        const ALL_RSU_PEERS = [
            'peer0.rsu1.tetaguard.net',
            'peer0.rsu2.tetaguard.net',
            'peer0.rsu3.tetaguard.net',
            'peer0.rsu4.tetaguard.net',
            'peer0.rsu5.tetaguard.net',
        ];
        const ALL_OBU_PEERS = [
            'peer0.obu1.tetaguard.net',
            'peer0.obu2.tetaguard.net',
            'peer0.obu3.tetaguard.net',
        ];
        // In no-RSU NS-3 scenario, OBUs ARE the peer set for SelectPeers.
        // UpdateTrustRound still uses the RSU Fabric peer as caller because the
        // RSU Fabric infrastructure (Docker containers) is always present and
        // always registered on the ledger — the "no RSU" label refers to NS-3
        // vehicular RSU nodes, not the Fabric peer infrastructure.
        const SELECT_PEERS_POOL = noRSU ? ALL_OBU_PEERS : [...ALL_RSU_PEERS, ...ALL_OBU_PEERS];
        const ALL_PEERS         = [...ALL_RSU_PEERS, ...ALL_OBU_PEERS];

        let trustRoundIndex = 0;

        const trustTimer = intervalMs > 0 ? setInterval(async () => {
            trustRoundIndex++;
            try {
                const c = network.getContract(CHAINCODE);

                // Simulate participation: every 5th round rsu5 or obu3 misses a beacon.
                let participating = [...ALL_PEERS];
                if (trustRoundIndex % 10 === 0) {
                    participating = ALL_PEERS.filter(p => p !== 'peer0.obu3.tetaguard.net');
                    console.log(`[TrustRound #${trustRoundIndex}] obu3 ABSENT → score will drop`);
                } else if (trustRoundIndex % 5 === 0) {
                    participating = ALL_PEERS.filter(p => p !== 'peer0.rsu5.tetaguard.net');
                    console.log(`[TrustRound #${trustRoundIndex}] rsu5 ABSENT → score will drop`);
                }

                // Caller must be a Tier 1 RSU peer (IsRSUPeer=true, score≥1.0).
                // RSU Fabric peers are always registered, so nodeID is always valid here.
                await c.submitTransaction(
                    'UpdateTrustRound',
                    nodeID,                        // callerPeerID
                    JSON.stringify(participating),
                    JSON.stringify(ALL_PEERS)
                );

                // Print full score table every 10th round to avoid console flood at 100ms cadence.
                if (trustRoundIndex % 10 === 0) {
                    const lines = [];
                    for (const peer of ALL_PEERS) {
                        try {
                            const res = await c.evaluateTransaction('GetTrustScore', peer);
                            const sc  = parseFloat(res.toString()).toFixed(4);
                            const tag = ALL_OBU_PEERS.includes(peer) ? ' [OBU]' : ' [RSU]';
                            lines.push(`  ${peer.padEnd(38)}${tag}  score=${sc}`);
                        } catch (_) {
                            lines.push(`  ${peer.padEnd(38)}  (not registered)`);
                        }
                    }
                    console.log(`\n[TrustRound #${trustRoundIndex}] scores:`);
                    console.log(lines.join('\n'));
                }

                // SelectPeers: show which peers are currently active
                // In no-RSU mode, pass only OBU IDs so OBUs are selected as the peer set.
                // PeriodicPeerReSelection: detects promotions and de-listings by
                // comparing the new active set against the ledger-stored previous set.
                // Emits PeerPromoted / PeerDroppedFromActive events (handled above).
                // Also advances any QUARANTINED peers past their 30s monitoring window.
                try {
                    const prRes   = await c.submitTransaction(
                        'PeriodicPeerReSelection', JSON.stringify(SELECT_PEERS_POOL));
                    const selected = JSON.parse(prRes.toString());
                    console.log(`[TrustRound #${trustRoundIndex}] Active set (${noRSU ? 'OBU-only' : 'all'} pool, np=${3*1+1}) → [${selected.join(', ')}]`);
                    appendLog(`TrustRound #${trustRoundIndex}  active=${JSON.stringify(selected)}`);
                } catch (prErr) {
                    console.warn(`[TrustRound #${trustRoundIndex}] PeriodicPeerReSelection failed: ${prErr.message}`);
                }

                appendLog(`TrustRound #${trustRoundIndex}  participating=${participating.length}/${ALL_PEERS.length}  mode=${noRSU ? 'no-rsu' : 'rsu'}`);
            } catch (err) {
                console.warn(`[TrustRound #${trustRoundIndex}] UpdateTrustRound failed: ${err.message}`);
            }
        }, intervalMs) : null;

        // keep alive until Ctrl+C; clean up timer on exit
        await new Promise((resolve) => {
            process.on('SIGINT',  () => { if (trustTimer) clearInterval(trustTimer); resolve(); });
            process.on('SIGTERM', () => { if (trustTimer) clearInterval(trustTimer); resolve(); });
        });

    } catch (err) {
        console.error('[EventListener] Fatal:', err.message);
        gateway.disconnect();
        process.exit(1);
    }
}

// ─── Event handlers ───────────────────────────────────────────────────────────

/**
 * replayPendingFlowMods: on startup, fetch all unexecuted FlowMods and replay them.
 * T-2: handles the case where listener crashed between event and FlowMod execution.
 */
async function replayPendingFlowMods(network, nodeID) {
    try {
        const contract = network.getContract(CHAINCODE);
        const result   = await contract.evaluateTransaction('GetAllPendingFlowMods');
        if (!result || result.length === 0) return;
        const fmList = JSON.parse(result.toString());
        if (!Array.isArray(fmList)) return;
        let replayed = 0;
        for (const fm of fmList) {
            if (fm.executed) continue;  // already acknowledged
            await executeParsedFlowMod(fm, nodeID);
            await contract.submitTransaction('AcknowledgeFlowMod', fm.entry_id);
            replayed++;
        }
        if (replayed > 0) {
            console.log(`[EventListener] Replayed ${replayed} pending FlowMod(s) from ledger.`);
        }
    } catch (err) {
        console.warn(`[EventListener] FlowMod replay on startup failed: ${err.message}`);
    }
}

/**
 * handleAttackDetected: read PendingFlowMod from ledger → POST to Ryu → acknowledge.
 */
async function handleAttackDetected(network, payload, nodeID) {
    const vid   = payload.vehicle_id     || '?';
    const alpha = payload.attack_variant || '?';
    const score = payload.anomaly_score  || 0;
    const ts    = Number(payload.timestamp) || Date.now(); // EL-02: alert creation time

    console.log(`[AttackDetected] vehicle=${vid}  α=${alpha}  ` +
                `ŷ=${Number(score).toFixed(4)}  t=${ts}ms`);
    appendLog(`AttackDetected  vehicle=${vid}  variant=${alpha}  score=${score}`);

    const action = (alpha === 'ME') ? 'REROUTE' : 'DROP';

    // EL-02: pass event timestamp so executeFlowMod can compute adaptive budget
    const fm = await executeFlowMod(network, vid, action, nodeID, ts);

    // T-2: acknowledge executed FlowMod to prevent replay on restart
    if (fm && fm.entry_id) {
        try {
            const contract = network.getContract(CHAINCODE);
            await contract.submitTransaction('AcknowledgeFlowMod', fm.entry_id);
        } catch (_) {}
    }
}

/**
 * handleKeyRevocation: write revoked_keys.json AND push to LKH manager.
 *
 * EL-03 FIX: Polling revoked_keys.json introduces arbitrary delay (up to poll
 * interval, potentially 1 s+). The paper requires LKH KEK updates within the
 * next beacon interval (Tb=100 ms). Now pushes immediately to the LKH key
 * manager via HTTP in addition to writing the JSON file for legacy polling.
 */
async function handleKeyRevocation(payload) {
    const vid    = payload.vehicle_id || '?';
    const action = payload.action     || 'REVOKE_SESSION_KEY';

    console.log(`[KeyRevocation] vehicle=${vid}  action=${action}`);

    // Write JSON file (legacy polling path for crypto_pipeline.cc)
    let revoked = [];
    if (fs.existsSync(REVOKED_KEYS_FILE)) {
        try { revoked = JSON.parse(fs.readFileSync(REVOKED_KEYS_FILE, 'utf8')); }
        catch (_) {}
    }
    if (!revoked.find(r => r.vehicle_id === vid)) {
        revoked.push({ vehicle_id: vid, revoked_at: Date.now(),
                       action, source: 'blockchain_KeyRevocation' });
        fs.writeFileSync(REVOKED_KEYS_FILE, JSON.stringify(revoked, null, 2));
        console.log(`[KeyRevocation] ✓  ${REVOKED_KEYS_FILE} updated`);
    }

    // EL-03: also push immediately to LKH key manager for O(log n) KEK update
    const lkhUrl = process.env.LKH_MANAGER_URL || 'http://localhost:8090/revoke';
    try {
        const fetchFn = globalThis.fetch || require('node-fetch');
        const resp = await fetchFn(lkhUrl, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ vehicle_id: vid, revoked_at: Date.now() }),
            signal:  AbortSignal.timeout ? AbortSignal.timeout(50) : undefined
        });
        if (resp && resp.ok) {
            console.log(`[KeyRevocation] ✓  LKH manager notified (${lkhUrl})  vehicle=${vid}`);
            appendLog(`KeyRevocation  vehicle=${vid}  LKH push OK  O(log n) KEK update`);
        } else {
            console.warn(`[KeyRevocation]  LKH push returned HTTP ${resp ? resp.status : '?'} — crypto_pipeline will poll`);
            appendLog(`KeyRevocation  vehicle=${vid}  LKH push HTTP error — falling back to poll`);
        }
    } catch (e) {
        console.warn(`[KeyRevocation]  LKH push failed (${e.message}) — crypto_pipeline will poll via ${REVOKED_KEYS_FILE}`);
        appendLog(`KeyRevocation  vehicle=${vid}  LKH push failed: ${e.message}`);
    }

    // CA certificate revocation (paper §Conflict Resolution item 4 — permanent removal).
    // Calls Fabric CA /revoke endpoint to permanently revoke the vehicle's certificate.
    // Manual re-admission required after this point.
    const caUrl = process.env.FABRIC_CA_URL || 'http://ca.tetaguard.net:7054';
    const caRevoke = `${caUrl}/revoke`;
    try {
        const fetchFn = globalThis.fetch || require('node-fetch');
        const resp = await fetchFn(caRevoke, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                id:     vid,
                reason: 'keycompromise',
                caname: 'ca-tetaguard'
            }),
            signal: AbortSignal.timeout ? AbortSignal.timeout(200) : undefined
        });
        if (resp && resp.ok) {
            console.log(`[KeyRevocation] ✓  Fabric CA cert revoked  vehicle=${vid}  (manual re-admission required)`);
            appendLog(`KeyRevocation  vehicle=${vid}  CA cert REVOKED — permanent removal`);
        } else {
            console.warn(`[KeyRevocation]  Fabric CA revoke HTTP ${resp ? resp.status : '?'}  vehicle=${vid} — cert not revoked at CA`);
            appendLog(`KeyRevocation  vehicle=${vid}  CA revoke HTTP error ${resp ? resp.status : '?'}`);
        }
    } catch (e) {
        console.warn(`[KeyRevocation]  Fabric CA unreachable (${e.message})  vehicle=${vid} — cert not revoked at CA`);
        appendLog(`KeyRevocation  vehicle=${vid}  CA unreachable: ${e.message}`);
    }
}

/**
 * handleControllerOriginAttack: operator escalation + OVERRIDE FlowMods.
 * E-1 FIX: Key now matches pushFlowModOverride's EntryID format:
 *   "FLOWMOD_OVERRIDE_CTRL_<controllerID>"
 * Previously used "FLOWMOD_OVERRIDE_<ctrl>" which never matched, causing
 * a default empty FlowMod to be executed (doing nothing).
 */
async function handleControllerOriginAttack(network, payload, nodeID) {
    const delta    = payload.delta      || 0;
    const ctrl     = payload.controller || '?';
    const interval = payload.interval   || 0;

    console.error(`\n[CRITICAL] CONTROLLER_ORIGIN_ATTACK`);
    console.error(`  controller=${ctrl}  δ=${delta}  t=${interval}ms`);
    console.error(`  Issuing priority-65535 OVERRIDE FlowMods from RSU evidence\n`);
    appendLog(`CRITICAL ControllerOriginAttack  ctrl=${ctrl}  delta=${delta}`);

    // E-1 FIX: key matches PendingFlowMod EntryID from pushFlowModOverride:
    // "FLOWMOD_OVERRIDE_CTRL_<controllerID>"
    const catchAllKey = `FLOWMOD_OVERRIDE_CTRL_${ctrl}`;

    try {
        const contract = network.getContract(CHAINCODE);

        // Execute the catch-all override rule first
        const result = await contract.evaluateTransaction('GetPendingFlowMod', catchAllKey);
        if (result && result.length > 0) {
            const fm = JSON.parse(result.toString());
            await executeParsedFlowMod(fm, nodeID);
            await contract.submitTransaction('AcknowledgeFlowMod', catchAllKey);
        }

        // T-2: also execute any unacknowledged per-vehicle OVERRIDE FlowMods
        const allResult = await contract.evaluateTransaction('GetAllPendingFlowMods');
        if (allResult && allResult.length > 0) {
            const fmList = JSON.parse(allResult.toString());
            for (const pending of fmList) {
                if (pending.action === 'OVERRIDE' && !pending.executed) {
                    await executeParsedFlowMod(pending, nodeID);
                    await contract.submitTransaction('AcknowledgeFlowMod', pending.entry_id);
                }
            }
        }
    } catch (err) {
        console.warn(`[ControllerOrigin] FlowMod execution failed: ${err.message}`);
    }
}

/**
 * E-3 NEW: handleControllerRemoved — action zone southbound switch when a
 * malicious controller is removed (τCj < τCmin, Section 5.7).
 * Reads the ControllerReassignment record and logs the zone switch.
 * In a real deployment: signal each RSU OpenFlow agent via REST to change
 * its southbound controller endpoint from removedCtrl to backupCtrl.
 */
/**
 * handleControllerRemoved: action zone southbound switch (EL-01).
 *
 * EL-01 FIX: Previously only logged that "RSU agents should switch" without
 * making any HTTP call. The malicious controller thus stayed in place
 * indefinitely after τCj < τCmin. Now calls each RSU's management API
 * (port 8081) to switch its southbound OpenFlow connection from removedCtrl
 * to backupCtrl, completing the emergency bypass described in §3.4.10.
 */
async function handleControllerRemoved(network, payload) {
    const removedCtrl = payload.removed_ctrl || '?';
    const backupCtrl  = payload.backup_ctrl  || '?';
    const zoneID      = payload.zone_id      || '?';
    const ts          = payload.timestamp_ms || Date.now();

    console.error(`\n[CRITICAL] CONTROLLER_REMOVED`);
    console.error(`  Removed: ${removedCtrl}  →  Backup: ${backupCtrl}  zone=${zoneID}  t=${ts}ms`);
    appendLog(`ControllerRemoved  from=${removedCtrl}  to=${backupCtrl}  zone=${zoneID}`);

    // Read the authoritative ControllerReassignment record from the ledger
    let reassignment = null;
    try {
        const contract = network.getContract(CHAINCODE);
        const result = await contract.evaluateTransaction('GetLatestControllerReassignment', removedCtrl);
        if (result && result.length > 0) {
            reassignment = JSON.parse(result.toString());
        }
    } catch (err) {
        console.warn(`[ControllerRemoved] Could not read reassignment record: ${err.message}`);
    }

    const actualBackup  = (reassignment && reassignment.backup_ctrl_id) || backupCtrl;
    const actualZone    = (reassignment && reassignment.zone_id)        || zoneID;

    console.log(`[ControllerRemoved] Zone ${actualZone}: switching southbound from ${removedCtrl} to ${actualBackup}`);
    appendLog(`Zone ${actualZone} southbound switching from ${removedCtrl} to ${actualBackup}`);

    // EL-01: signal every RSU OpenFlow agent to switch southbound controller
    const fetchFn = globalThis.fetch || require('node-fetch');
    const switchPayload = JSON.stringify({
        zone_id:          actualZone,
        removed_ctrl:     removedCtrl,
        backup_ctrl:      actualBackup,
        emergency_bypass: true,
    });
    const switchResults = await Promise.allSettled(
        Object.entries(RSU_MGMT_URLS).map(async ([peer, mgmtUrl]) => {
            const url = `${mgmtUrl}/southbound/switch`;
            try {
                const resp = await fetchFn(url, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    switchPayload,
                    signal:  AbortSignal.timeout ? AbortSignal.timeout(200) : undefined
                });
                if (resp && resp.ok) {
                    console.log(`[ControllerRemoved] ✓  ${peer} southbound switched to ${actualBackup}`);
                    appendLog(`${peer} southbound switched to ${actualBackup}`);
                } else {
                    console.warn(`[ControllerRemoved] ✗  ${peer} mgmt API returned HTTP ${resp ? resp.status : '?'}`);
                }
            } catch (e) {
                console.warn(`[ControllerRemoved] ✗  ${peer} mgmt API unreachable: ${e.message}`);
            }
        })
    );
    const succeeded = switchResults.filter(r => r.status === 'fulfilled').length;
    console.log(`[ControllerRemoved] Southbound switch signalled to ${succeeded}/${switchResults.length} RSU agents.`);
}

/**
 * E-3 NEW: handleAnchorCheckpoint — log new anchor checkpoint for OBU sync awareness.
 * Tier 2 OBU peers listening here should call SyncFromAnchorCheckpoint.
 */
async function handleAnchorCheckpoint(_network, payload) {
    const cpID      = payload.checkpoint_id   || '?';
    const blockH    = payload.block_height    || 0;
    const createdBy = payload.created_by_peer || '?';
    const createdAt = payload.created_at_ms   || Date.now();

    console.log(`[AnchorCheckpoint] New checkpoint  id=${cpID}  block=${blockH}  by=${createdBy}  t=${createdAt}ms`);
    appendLog(`AnchorCheckpoint created  id=${cpID}  block=${blockH}  by=${createdBy}`);
    // OBU peers should call: contract.submitTransaction('SyncFromAnchorCheckpoint', cpID, obuPeerID)
}

/**
 * handlePeerQuarantined — Stage 1 of the RSU demotion pipeline.
 * Fired by demotePeerToClient() when a malicious RSU peer is confirmed
 * and moved from ACTIVE to QUARANTINED_CLIENT.
 *
 * Actions:
 *  - Log the demotion with timestamp and peer ID.
 *  - Write a suspension marker file so the data-relay agent for this
 *    RSU stops forwarding NS-3 topology data to the controller.
 *  - Alert the operator via console (in production: send to monitoring).
 */
/**
 * handleControllerRemovalFailed — critical fallback when CheckControllerTrustAndReassign
 * finds no eligible backup controller (all remaining controllers are also below tau_C_min).
 * There is no automated recovery path — operator intervention is mandatory.
 */
async function handleControllerRemovalFailed(payload) {
    const failedCtrl = payload.failed_ctrl  || 'unknown';
    const score      = payload.trust_score  !== undefined ? payload.trust_score : 0;
    const tsMs       = payload.timestamp_ms || Date.now();

    console.error(`[ControllerRemovalFailed] ✖  CRITICAL — no backup controller available`);
    console.error(`  failed_ctrl : ${failedCtrl}`);
    console.error(`  trust_score : ${score}`);
    console.error(`  timestamp   : ${new Date(tsMs).toISOString()}`);
    console.error(`  Action      : MANUAL OPERATOR INTERVENTION REQUIRED`);
    console.error(`                Promote a healthy controller via RegisterController`);
    console.error(`                and re-run CheckControllerTrustAndReassign`);

    appendLog(`ControllerRemovalFailed  ctrl=${failedCtrl}  trust=${score}  ts=${new Date(tsMs).toISOString()}  CRITICAL_OPERATOR_ACTION_REQUIRED`);
}

async function handlePeerQuarantined(payload) {
    const peerID    = payload.peer_id    || 'unknown';
    const demotedAt = payload.demoted_at_ms || Date.now();
    const msg       = payload.message    || '';

    console.warn(`[PeerQuarantined] ⚠  RSU peer demoted to QUARANTINED_CLIENT`);
    console.warn(`  peer_id    : ${peerID}`);
    console.warn(`  demoted_at : ${new Date(demotedAt).toISOString()}`);
    console.warn(`  message    : ${msg}`);
    console.warn(`  Action     : peer excluded from Pactive — monitoring trust score`);

    appendLog(`PeerQuarantined  peer=${peerID}  demoted_at=${new Date(demotedAt).toISOString()}`);

    // Write a suspension marker so the NS-3 bridge skips this peer's data relay.
    // The bridge process polls QUARANTINED_PEERS_FILE and suppresses forwarding.
    const quarFile = '/tmp/quarantined_peers.json';
    try {
        let existing = {};
        if (fs.existsSync(quarFile)) {
            existing = JSON.parse(fs.readFileSync(quarFile, 'utf8'));
        }
        existing[peerID] = { demoted_at_ms: demotedAt, state: 'QUARANTINED_CLIENT' };
        fs.writeFileSync(quarFile, JSON.stringify(existing, null, 2));
        console.log(`[PeerQuarantined] ✓  suspension marker written → ${quarFile}`);
    } catch (e) {
        console.warn(`[PeerQuarantined]  could not write suspension marker: ${e.message}`);
    }
}

/**
 * handlePeerRemoved — Stage 3 of the RSU demotion pipeline.
 * Fired by monitorAndRemovePeer() after the quarantine window T_quar
 * has elapsed and the peer's trust has not recovered above tau_min.
 * The peer is now permanently expelled from the consortium.
 *
 * Actions:
 *  - Log the permanent removal.
 *  - Update the suspension marker file to REMOVED state.
 *  - Alert the operator — manual administrator action is required to
 *    re-admit this peer via RegisterRSUPeer.
 */
async function handlePeerRemoved(payload) {
    const peerID    = payload.peer_id      || 'unknown';
    const removedAt = payload.removed_at_ms || Date.now();
    const score     = payload.trust_score  !== undefined ? payload.trust_score : 0;
    const msg       = payload.message      || '';

    console.error(`[PeerRemoved] ✖  RSU peer PERMANENTLY REMOVED from consortium`);
    console.error(`  peer_id    : ${peerID}`);
    console.error(`  removed_at : ${new Date(removedAt).toISOString()}`);
    console.error(`  trust_score: ${score}`);
    console.error(`  message    : ${msg}`);
    console.error(`  Action     : MANUAL ADMIN RE-REGISTRATION REQUIRED via RegisterRSUPeer`);

    appendLog(`PeerRemoved  peer=${peerID}  removed_at=${new Date(removedAt).toISOString()}  trust=${score}  ADMIN_ACTION_REQUIRED`);

    // Update suspension marker to REMOVED so the bridge permanently suppresses this peer.
    const quarFile = '/tmp/quarantined_peers.json';
    try {
        let existing = {};
        if (fs.existsSync(quarFile)) {
            existing = JSON.parse(fs.readFileSync(quarFile, 'utf8'));
        }
        existing[peerID] = { removed_at_ms: removedAt, state: 'REMOVED', trust_score: score };
        fs.writeFileSync(quarFile, JSON.stringify(existing, null, 2));
        console.log(`[PeerRemoved] ✓  removal marker written → ${quarFile}`);
    } catch (e) {
        console.warn(`[PeerRemoved]  could not write removal marker: ${e.message}`);
    }
}

/**
 * handleBlacklistBeaconPublished: vehicle permanently blacklisted via Tier-2 path.
 *
 * Writes two IPC files:
 *   /tmp/blacklist_beacons.json      — full record for OBU agents querying the ledger cache
 *   /tmp/blacklist_vehicle_ids.txt   — one NS-3 node ID per line, read by routing.cc every 1s
 *                                      to drop packets from and refuse routes via blacklisted nodes
 */
async function handleBlacklistBeaconPublished(payload) {
    const vid         = payload.vehicle_id       || '?';
    const fingerprint = payload.cert_fingerprint || '?';
    const publishedAt = payload.published_at_ms  || Date.now();

    console.log(`[BlacklistBeacon] vehicle=${vid}  fingerprint=${fingerprint}`);
    console.log(`[BlacklistBeacon]   Ledger record written — cert permanently blacklisted`);
    appendLog(`BlacklistBeaconPublished  vehicle=${vid}  fingerprint=${fingerprint}  ts=${new Date(publishedAt).toISOString()}`);

    // ── JSON cache for OBU agents ────────────────────────────────────────────
    const blacklistFile = '/tmp/blacklist_beacons.json';
    let list = [];
    if (fs.existsSync(blacklistFile)) {
        try { list = JSON.parse(fs.readFileSync(blacklistFile, 'utf8')); } catch (_) {}
    }
    if (!list.find(e => e.vehicle_id === vid)) {
        list.push({ vehicle_id: vid, cert_fingerprint: fingerprint,
                    blacklisted_at: publishedAt, source: 'blockchain_BlacklistBeacon' });
        try {
            fs.writeFileSync(blacklistFile, JSON.stringify(list, null, 2));
            console.log(`[BlacklistBeacon] ✓  ${blacklistFile} updated`);
        } catch (e) {
            console.warn(`[BlacklistBeacon]  could not write blacklist file: ${e.message}`);
        }
    }

    // ── NS-3 IPC: one NS-3 node ID per line for routing.cc ReadBlacklistFile() ──
    // vehicle_id is the NS-3 numeric node ID (uint32) as a string.
    const nsIpcFile = '/tmp/blacklist_vehicle_ids.txt';
    const vidNum = parseInt(vid, 10);
    if (!isNaN(vidNum)) {
        let ids = [];
        if (fs.existsSync(nsIpcFile)) {
            try {
                ids = fs.readFileSync(nsIpcFile, 'utf8')
                        .split('\n')
                        .map(s => s.trim())
                        .filter(s => s.length > 0)
                        .map(Number);
            } catch (_) {}
        }
        if (!ids.includes(vidNum)) {
            ids.push(vidNum);
            try {
                fs.writeFileSync(nsIpcFile, ids.join('\n') + '\n');
                console.log(`[BlacklistBeacon] ✓  ${nsIpcFile} updated  node_id=${vidNum}`);
            } catch (e) {
                console.warn(`[BlacklistBeacon]  could not write NS-3 IPC file: ${e.message}`);
            }
        }
    }
}

/**
 * handleControllerRevokedBeaconPublished: controller permanently removed via Tier-2 path.
 * Writes the backup controller ID so local OBU agents can redirect topology solicitation
 * to the backup controller directly via V2X without going through the revoked controller.
 * V2V propagation via DSRC is future work (requires NS-3/routing.cc integration).
 */
async function handleControllerRevokedBeaconPublished(payload) {
    const ctrlID   = payload.controller_id || '?';
    const backupID = payload.backup_ctrl   || '?';
    const ts       = payload.published_at  || Date.now();

    console.log(`[ControllerRevokedBeacon] revoked=${ctrlID}  backup=${backupID}`);
    console.log(`[ControllerRevokedBeacon]   Backup controller notified via ledger to solicit topology via V2X`);
    console.log(`[ControllerRevokedBeacon]   V2V propagation via DSRC: future work`);
    appendLog(`ControllerRevokedBeaconPublished  revoked=${ctrlID}  backup=${backupID}  ts=${new Date(ts).toISOString()}`);

    const beaconFile = '/tmp/controller_revoked_beacon.json';
    try {
        fs.writeFileSync(beaconFile, JSON.stringify({
            revoked_controller: ctrlID,
            backup_controller:  backupID,
            revoked_at:         ts,
            source:             'blockchain_ControllerRevokedBeacon'
        }, null, 2));
        console.log(`[ControllerRevokedBeacon] ✓  ${beaconFile} written`);
    } catch (e) {
        console.warn(`[ControllerRevokedBeacon]  could not write beacon file: ${e.message}`);
    }
}

/**
 * handlePeerPromoted — an OBU passed all five eligibility conditions AND a vacancy
 * opened in the top-np active set. Promotion is vacancy-driven: the OBU's trust
 * crossed τ_min earlier, but it only joins Pactive when a slot is free.
 * No quarantine/monitoring stage on the way up — symmetric update rule, asymmetric
 * pipeline structure.
 */
function handlePeerPromoted(payload) {
    const peer    = payload.peer_id      || 'unknown';
    const score   = payload.trust_score  !== undefined ? Number(payload.trust_score).toFixed(4) : '?';
    const count   = payload.active_count !== undefined ? payload.active_count : '?';
    const np      = payload.np           !== undefined ? payload.np : '?';
    const ts      = payload.promoted_at  || Date.now();

    console.log(`\n[PeerPromoted] ✦  OBU peer joined active consensus set`);
    console.log(`  peer_id      : ${peer}`);
    console.log(`  trust_score  : ${score}  (cleared τ_min=0.10 + dwell gate + checkpoint sync)`);
    console.log(`  active_count : ${count}/${np}  (vacancy filled)`);
    console.log(`  promoted_at  : ${new Date(ts).toISOString()}`);
    console.log(`  Note: promotion is vacancy-driven — trust crossing the floor is necessary`);
    console.log(`        but not sufficient; the OBU waited for a slot to open in top-${np}\n`);
    appendLog(`PeerPromoted  peer=${peer}  score=${score}  active=${count}/${np}`);
}

/**
 * handlePeerDroppedFromActive — a peer fell below an eligibility condition (trust
 * drift, dwell expired, flag set) and was removed from Pactive this round.
 * Distinguished from the formal 3-stage demotion pipeline: no quarantine, no
 * monitoring window — just absent from the re-ranking result.
 */
function handlePeerDroppedFromActive(payload) {
    const peer  = payload.peer_id      || 'unknown';
    const score = payload.trust_score  !== undefined ? Number(payload.trust_score).toFixed(4) : '?';
    const count = payload.active_count !== undefined ? payload.active_count : '?';
    const ts    = payload.dropped_at   || Date.now();

    console.log(`[PeerDroppedFromActive] ↓  Peer left active set (eligibility drift)`);
    console.log(`  peer_id      : ${peer}`);
    console.log(`  trust_score  : ${score}`);
    console.log(`  active_count : ${count}  (slot now open for next-ranked eligible peer)`);
    console.log(`  dropped_at   : ${new Date(ts).toISOString()}`);
    appendLog(`PeerDroppedFromActive  peer=${peer}  score=${score}  active=${count}`);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function appendLog(msg) {
    try {
        fs.appendFileSync(LOG_FILE,
            `[${new Date().toISOString()}] ${msg}\n`);
    } catch (_) {}
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let nodeID        = PEER_ID;
let noRSU         = false;    // --no_rsu: use OBU peers only for SelectPeers (no-RSU NS-3 scenario)
let intervalMs    = 100;      // --interval_ms: trust round timer in ms (design: T_prs = T_b = 100 ms)
let noTrustRounds = false;    // --no_trust_rounds: disable background trust round scheduler
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--node_id'        && args[i+1]) nodeID     = args[++i];
    if (args[i] === '--rsu_url'        && args[i+1]) RSU_OPENFLOW_BASE = args[++i];
    if (args[i] === '--no_rsu')                      noRSU      = true;
    if (args[i] === '--no_trust_rounds')             noTrustRounds = true;
    if (args[i] === '--interval_ms'    && args[i+1]) intervalMs = parseInt(args[++i], 10) || 100;
}

if (noTrustRounds) intervalMs = 0;
startEventListener(nodeID, noRSU, intervalMs);
