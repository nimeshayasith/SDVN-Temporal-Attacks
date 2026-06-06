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
 * Three events handled:
 *   AttackDetected        → read PendingFlowMod from ledger → POST to Ryu
 *   KeyRevocation         → write revoked_keys.json (polled by crypto_pipeline)
 *   ControllerOriginAttack→ operator escalation + OVERRIDE FlowMods
 *
 * Configuration:
 *   RYU_REST_BASE env var (default: http://ryu-controller:8080)
 *   --node_id peer0.rsu1.tetaguard.net
 *
 * Usage:
 *   node eventListener.js [--node_id <peer>] [--ryu_url <url>]
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

// Ryu SDN controller REST base — override with --ryu_url or RYU_REST_BASE env var
let RYU_REST_BASE  = process.env.RYU_REST_BASE || 'http://ryu-controller:8080';
const FLOWMOD_TIMEOUT_MS = 50;  // must fit within 100 ms FlowMod budget

// ─── HTTP FlowMod execution (off-chain) ───────────────────────────────────────

/**
 * executeFlowMod reads PendingFlowMod records written by the chaincode and
 * POSTs them to the Ryu SDN controller REST API.
 *
 * This is the correct Fabric pattern: chaincode writes to ledger,
 * off-chain component executes the external call.
 */
async function executeFlowMod(network, vehicleID, action) {
    // Read PendingFlowMod record from ledger
    let pendingKey = `FLOWMOD_${action}_${vehicleID}`;
    let pendingFM  = null;

    try {
        const contract = network.getContract(CHAINCODE);
        const result   = await contract.evaluateTransaction('GetState', pendingKey);
        if (result && result.length > 0) {
            pendingFM = JSON.parse(result.toString());
        }
    } catch (err) {
        console.warn(`[FlowMod] Could not read ${pendingKey} from ledger: ${err.message}`);
    }

    if (!pendingFM) {
        // Construct a default FlowMod if ledger read failed
        pendingFM = {
            entry_id:    pendingKey,
            vehicle_id:  vehicleID,
            action:      action,
            priority:    action === 'DROP' ? 65000 : 50000,
            match:       {},
            flow_actions: []
        };
    }

    // Build Ryu REST API FlowMod body
    const ryuFM = {
        dpid:         1,
        table_id:     0,
        idle_timeout: 0,
        hard_timeout: 0,
        priority:     pendingFM.priority,
        match:        pendingFM.match || {},
        actions:      pendingFM.flow_actions || []
    };

    const url     = action === 'REROUTE'
        ? `${RYU_REST_BASE}/stats/flowentry/delete`
        : `${RYU_REST_BASE}/stats/flowentry/add`;
    const payload = JSON.stringify(ryuFM);

    console.log(`[FlowMod] POST ${url}  action=${action}  vehicle=${vehicleID}`);

    try {
        // Use node-fetch or built-in fetch (Node 18+)
        const fetchFn = globalThis.fetch
            || require('node-fetch');   // fallback for Node < 18

        const controller = new AbortController();
        const timeout    = setTimeout(() => controller.abort(), FLOWMOD_TIMEOUT_MS);

        const resp = await fetchFn(url, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    payload,
            signal:  controller.signal
        });
        clearTimeout(timeout);

        if (resp.ok) {
            console.log(`[FlowMod] ✓  ${action} rule installed  vehicle=${vehicleID}` +
                        `  HTTP ${resp.status}`);
            appendLog(`FlowMod ${action} executed  vehicle=${vehicleID}  HTTP ${resp.status}`);
        } else {
            console.warn(`[FlowMod] ✗  Ryu rejected FlowMod: HTTP ${resp.status}`);
        }
    } catch (err) {
        if (err.name === 'AbortError') {
            console.warn(`[FlowMod] ✗  Ryu timeout (${FLOWMOD_TIMEOUT_MS}ms)  vehicle=${vehicleID}`);
        } else {
            console.warn(`[FlowMod] ✗  Could not reach Ryu at ${RYU_REST_BASE}: ${err.message}`);
            console.warn(`           Is the SDN controller running?`);
        }
    }
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
        console.log(`[EventListener] Ryu controller: ${RYU_REST_BASE}`);

        // ── Block-level listener ──────────────────────────────────────────────
        await network.addBlockListener(async (block) => {
            for (const event of (block.events || [])) {
                const payload = event.payload
                    ? JSON.parse(event.payload.toString())
                    : {};

                switch (event.eventName) {
                    case 'AttackDetected':
                        await handleAttackDetected(network, payload);
                        break;
                    case 'KeyRevocation':
                        await handleKeyRevocation(payload);
                        break;
                    case 'ControllerOriginAttack':
                        await handleControllerOriginAttack(network, payload);
                        break;
                }
            }
        }, { type: 'full' });

        console.log('[EventListener] Listening for AttackDetected, ' +
                    'KeyRevocation, ControllerOriginAttack ...');
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
 * handleAttackDetected:
 *   1. Log confirmed attack
 *   2. Read PendingFlowMod record from ledger
 *   3. POST FlowMod to Ryu SDN controller (the actual enforcement)
 */
async function handleAttackDetected(network, payload) {
    const vid   = payload.vehicle_id     || '?';
    const alpha = payload.attack_variant || '?';
    const score = payload.anomaly_score  || 0;
    const ts    = payload.timestamp      || Date.now();

    console.log(`[AttackDetected] vehicle=${vid}  α=${alpha}  ` +
                `ŷ=${Number(score).toFixed(4)}  t=${ts}ms`);

    appendLog(`AttackDetected  vehicle=${vid}  variant=${alpha}  score=${score}`);

    // Execute the FlowMod against the SDN controller
    const action = (alpha === 'ME') ? 'REROUTE' : 'DROP';
    await executeFlowMod(network, vid, action);
}

/**
 * handleKeyRevocation: write revoked_keys.json polled by crypto_pipeline.cc
 */
async function handleKeyRevocation(payload) {
    const vid    = payload.vehicle_id || '?';
    const action = payload.action     || 'REVOKE_SESSION_KEY';

    console.log(`[KeyRevocation] vehicle=${vid}  action=${action}`);

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
        appendLog(`KeyRevocation  vehicle=${vid}  LKH O(log n) update triggered`);
    }
}

/**
 * handleControllerOriginAttack: operator escalation + OVERRIDE FlowMods
 */
async function handleControllerOriginAttack(network, payload) {
    const delta    = payload.delta      || 0;
    const ctrl     = payload.controller || '?';
    const interval = payload.interval   || 0;

    console.error(`\n[CRITICAL] CONTROLLER_ORIGIN_ATTACK`);
    console.error(`  controller=${ctrl}  δ=${delta}  t=${interval}ms`);
    console.error(`  Issuing priority-65535 OVERRIDE FlowMods from RSU evidence\n`);

    appendLog(`CRITICAL ControllerOriginAttack  ctrl=${ctrl}  delta=${delta}`);
    await executeFlowMod(network, ctrl, 'OVERRIDE');
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
    if (args[i] === '--ryu_url' && args[i+1])  RYU_REST_BASE = args[++i];
}

startEventListener(nodeID);
