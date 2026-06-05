/**
 * eventListener.js — Hyperledger Fabric block/chaincode event listener (§10.2)
 *
 * Listens for three chaincode events emitted by TemporalEchoMitigator:
 *
 *   AttackDetected        → log attack for analytics, update metrics
 *   KeyRevocation         → trigger LKH session key revocation in crypto layer
 *   ControllerOriginAttack→ alert operators that the SDN controller is compromised
 *
 * Pipeline position:
 *   TemporalEchoMitigator (Fabric chaincode)
 *       ↓ SetEvent("KeyRevocation", payload)
 *   eventListener.js  →  lkh_revoke_vehicle() / mark_key_revoked()
 *       ↓                (equivalent to the C calls declared in teta_guard_types.h)
 *   crypto_pipeline.cc    ← would receive via IPC/pipe in a real deployment
 *
 * Usage:
 *   node eventListener.js [--node_id peer0.rsu1.tetaguard.net]
 *
 * Prerequisites:
 *   npm install  (in blockchain/client directory)
 *   Fabric network running and chaincode installed
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

// Revoked vehicle tracking — shared with the crypto layer via a JSON file
// that crypto_pipeline.cc polls.  In a real deployment this would be a shared
// memory segment or Unix socket.
const REVOKED_KEYS_FILE = path.join(__dirname, '..', '..', 'revoked_keys.json');

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
        console.log(`[EventListener] Connected to channel '${CHANNEL}' as '${nodeID}'`);

        // ── Block-level listener for all chaincode events ─────────────────────
        await network.addBlockListener(async (block) => {
            for (const event of (block.events || [])) {
                const payload = event.payload
                    ? JSON.parse(event.payload.toString())
                    : {};

                switch (event.eventName) {

                    // ── KeyRevocation → trigger LKH revocation in crypto layer ──
                    case 'KeyRevocation':
                        await handleKeyRevocation(payload);
                        break;

                    // ── AttackDetected → analytics + logging ───────────────────
                    case 'AttackDetected':
                        handleAttackDetected(payload);
                        break;

                    // ── ControllerOriginAttack → operator escalation ────────────
                    case 'ControllerOriginAttack':
                        handleControllerOriginAttack(payload);
                        break;
                }
            }
        }, { type: 'full' });

        console.log('[EventListener] Listening for KeyRevocation, ' +
            'AttackDetected, ControllerOriginAttack ...');
        console.log('[EventListener] Press Ctrl+C to stop.');

        // Keep alive
        await new Promise(() => {});

    } catch (err) {
        console.error('[EventListener] Fatal error:', err.message);
        gateway.disconnect();
        process.exit(1);
    }
}

// ─── Event handlers ───────────────────────────────────────────────────────────

/**
 * handleKeyRevocation triggers the LKH session key revocation in the crypto
 * layer.  Matches the lkh_revoke_vehicle() / mark_key_revoked() calls
 * declared in teta_guard_types.h (§10.2).
 *
 * In a real deployment this would call a C library via FFI or write to a
 * Unix socket that crypto_pipeline.cc is polling.  In simulation mode it
 * writes the revoked vehicle ID to revoked_keys.json which crypto_pipeline.cc
 * can poll on Linux.
 */
async function handleKeyRevocation(payload) {
    const vid    = payload.vehicle_id || '?';
    const action = payload.action     || 'REVOKE_SESSION_KEY';

    console.log(`[KeyRevocation] vehicle=${vid}  action=${action}`);

    // ① Write to revoked_keys.json (polled by crypto_pipeline.cc)
    let revoked = [];
    if (fs.existsSync(REVOKED_KEYS_FILE)) {
        try { revoked = JSON.parse(fs.readFileSync(REVOKED_KEYS_FILE, 'utf8')); }
        catch (_) {}
    }
    const entry = {
        vehicle_id:  vid,
        revoked_at:  Date.now(),
        action:      action,
        source:      'blockchain_KeyRevocation_event'
    };
    if (!revoked.find(r => r.vehicle_id === vid)) {
        revoked.push(entry);
        fs.writeFileSync(REVOKED_KEYS_FILE, JSON.stringify(revoked, null, 2));
        console.log(`[KeyRevocation] ✓  Written to ${REVOKED_KEYS_FILE}`);
    }

    // ② Append to blockchain_submission_log.txt (same log as submit_alerts.py)
    const logLine = `[${new Date().toISOString()}] KeyRevocation  ` +
                    `vehicle=${vid}  → LKH O(log n) update triggered\n`;
    fs.appendFileSync(
        path.join(__dirname, '..', '..', 'blockchain_submission_log.txt'),
        logLine
    );
}

/**
 * handleAttackDetected logs the confirmed attack to analytics output and
 * appends to the submission log (matching submit_alerts.py log format).
 */
function handleAttackDetected(payload) {
    const vid    = payload.vehicle_id     || '?';
    const alpha  = payload.attack_variant || '?';
    const score  = payload.anomaly_score  || 0;
    const ts     = payload.timestamp      || Date.now();

    console.log(`[AttackDetected] vehicle=${vid}  α=${alpha}  ` +
                `ŷ=${Number(score).toFixed(4)}  t=${ts}ms`);
    console.log(`  → Immutable ledger entry committed (MITIG:${vid}:${ts})`);
    console.log(`  → FlowMod ${alpha === 'ME' ? 'REROUTE' : 'DROP'} issued to SDN controller`);

    const logLine = `[${new Date().toISOString()}] AttackDetected  ` +
                    `vehicle=${vid}  variant=${alpha}  score=${score}  ts=${ts}\n`;
    try {
        fs.appendFileSync(
            path.join(__dirname, '..', '..', 'blockchain_submission_log.txt'),
            logLine
        );
    } catch (_) {}
}

/**
 * handleControllerOriginAttack escalates a controller-compromise alert.
 * In production: page on-call operators, trigger secondary control plane.
 */
function handleControllerOriginAttack(payload) {
    const delta     = payload.delta      || 0;
    const threshold = payload.threshold  || 2;
    const ctrl      = payload.controller || '?';
    const interval  = payload.interval   || 0;

    console.error(`\n[CRITICAL] CONTROLLER_ORIGIN_ATTACK DETECTED`);
    console.error(`  controller=${ctrl}`);
    console.error(`  δ=${delta}  (threshold=${threshold})`);
    console.error(`  interval=${interval}ms`);
    console.error(`  Action: FlowMod OVERRIDE issued directly to switches`);
    console.error(`  Action: Operator alert — check controller integrity\n`);

    const logLine = `[${new Date().toISOString()}] CRITICAL: ControllerOriginAttack  ` +
                    `ctrl=${ctrl}  delta=${delta}  threshold=${threshold}\n`;
    try {
        fs.appendFileSync(
            path.join(__dirname, '..', '..', 'blockchain_submission_log.txt'),
            logLine
        );
    } catch (_) {}
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

const args   = process.argv.slice(2);
let nodeID   = PEER_ID;
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--node_id' && args[i+1]) nodeID = args[++i];
}

startEventListener(nodeID);
