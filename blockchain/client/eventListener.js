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

    if (!pendingFM) {
        pendingFM = {
            entry_id:     `FLOWMOD_${action}_${vehicleID}`,
            vehicle_id:   vehicleID,
            action:       action,
            priority:     action === 'DROP' ? 65000 : 50000,
            match:        {},
            flow_actions: []
        };
    }

    await executeParsedFlowMod(pendingFM, nodeForURL, eventTimestampMs);
    return pendingFM; // return so caller can acknowledge by entry_id
}

// ─── Main listener ────────────────────────────────────────────────────────────

async function startEventListener(nodeID = PEER_ID) {
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

        // ── Block-level listener ──────────────────────────────────────────────
        await network.addBlockListener(async (block) => {
            for (const event of (block.events || [])) {
                const payload = event.payload
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
                    case 'ControllerRemoved':          // E-3: NEW handler
                        await handleControllerRemoved(network, payload);
                        break;
                    case 'AnchorCheckpointCreated':   // E-3: NEW handler
                        await handleAnchorCheckpoint(network, payload);
                        break;
                }
            }
        }, { type: 'full' });

        console.log('[EventListener] Listening for AttackDetected, KeyRevocation, ' +
                    'ControllerOriginAttack, ControllerRemoved, AnchorCheckpointCreated ...');
        console.log('[EventListener] Press Ctrl+C to stop.\n');

        await new Promise(() => {});   // keep alive

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

// ─── Utilities ────────────────────────────────────────────────────────────────

function appendLog(msg) {
    try {
        fs.appendFileSync(LOG_FILE,
            `[${new Date().toISOString()}] ${msg}\n`);
    } catch (_) {}
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let nodeID = PEER_ID;
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--node_id' && args[i+1]) nodeID = args[++i];
    if (args[i] === '--rsu_url' && args[i+1])  RSU_OPENFLOW_BASE = args[++i];
}

startEventListener(nodeID);
