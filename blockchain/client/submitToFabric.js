/**
 * submitToFabric.js — TGN → Hyperledger Fabric blockchain client
 *
 * Implements SUBMIT_TO_FABRIC(nk, A, B_nk(t)) from Algorithm 2 Step 22 (§10.1).
 *
 * Pipeline position:
 *   tgn_detector.cc  →  tgn_alerts.json
 *   submit_alerts.py →  peer chaincode invoke SubmitAlert   (simple path)
 *   submitToFabric.js→  Fabric Gateway SDK SubmitAlert       (full SDK path)
 *
 * The full SDK path (this file) also submits beacon evidence (Flow 1) and
 * triggers the divergence check (Flow 3) in addition to SubmitAlert.
 *
 * Usage:
 *   node submitToFabric.js --alerts tgn_alerts.json [--evidence beacon_evidence.json]
 *   node submitToFabric.js --alerts tgn_alerts.json --ctrl_topo ctrl_topo.json
 *
 * Prerequisites:
 *   - Fabric network running (docker-compose -f ../network/docker-compose-teta.yaml up -d)
 *   - Channel created and chaincode installed (scripts/bootstrap.sh)
 *   - npm install (in this directory)
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const fs   = require('fs');
const path = require('path');

// ─── Configuration ────────────────────────────────────────────────────────────

const CHANNEL          = 'teta-channel';
const CHAINCODE        = 'temporalecho';
const PEER_ID          = 'peer0.rsu1.tetaguard.net';  // submitting peer identity
const WALLET_PATH      = path.join(__dirname, 'wallet');
const CONN_PROFILE     = path.join(__dirname, '..', 'config', 'connection-profile.json');

// Anomaly threshold θ_FS (Eq. 3.23) — matches tgn_detector.cc TGN_THETA_FS
const THETA_FS = '0.40';

// ─── Main export — SUBMIT_TO_FABRIC(nk, A, B_nk(t)) §10.1 ────────────────────

/**
 * submitToFabric — main entry point implementing Algorithm 2, Step 22.
 *
 * @param {string} trustedNodeID   — nk identifier (peer ID)
 * @param {Array}  alertSet        — array of AlertObject from tgn_alerts.json
 * @param {Object} beaconEvidence  — BeaconEvidenceRecord B_nk(t) for this interval
 * @param {number} beaconInterval  — current beacon interval timestamp (ms)
 * @param {Object} ctrlTopo        — optional ControllerTopologyClaim for Flow 3
 */
async function submitToFabric(
    trustedNodeID,
    alertSet,
    beaconEvidence,
    beaconInterval,
    ctrlTopo = null
) {
    const gateway = new Gateway();
    try {
        // ── Pre-flight: verify required files exist before Fabric SDK init ───
        // The SDK throws an unhandled exception on missing certs, so check first.
        if (!fs.existsSync(CONN_PROFILE)) {
            throw new Error(
                `Connection profile not found: ${CONN_PROFILE}\n` +
                '  Run scripts/bootstrap.sh to generate crypto material and profiles.'
            );
        }

        // Check that the admin cert and private key referenced in the profile exist
        const connProfileRaw = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
        const org = connProfileRaw.organizations && connProfileRaw.organizations['TetaGuardMSP'];
        if (org && org.adminPrivateKey && org.adminPrivateKey.path) {
            if (!fs.existsSync(org.adminPrivateKey.path)) {
                throw new Error(
                    `Admin private key not found: ${org.adminPrivateKey.path}\n` +
                    '  Run scripts/bootstrap.sh first to generate crypto-config.'
                );
            }
        }
        if (org && org.signedCert && org.signedCert.path) {
            if (!fs.existsSync(org.signedCert.path)) {
                throw new Error(
                    `Admin signed cert not found: ${org.signedCert.path}\n` +
                    '  Run scripts/bootstrap.sh first to generate crypto-config.'
                );
            }
        }

        if (!fs.existsSync(WALLET_PATH)) {
            throw new Error(
                `Wallet directory not found: ${WALLET_PATH}\n` +
                '  Run scripts/bootstrap.sh to enrol peer identities into the wallet.'
            );
        }

        // ── Connect to Fabric network ────────────────────────────────────────
        const connProfile = connProfileRaw;
        const wallet      = await Wallets.newFileSystemWallet(WALLET_PATH);
        const identity    = await wallet.get(trustedNodeID);

        if (!identity) {
            throw new Error(
                `Identity '${trustedNodeID}' not found in wallet at ${WALLET_PATH}.\n` +
                'Run scripts/bootstrap.sh first to enrol the peer identity.'
            );
        }

        await gateway.connect(connProfile, {
            wallet,
            identity:  trustedNodeID,
            discovery: { enabled: true, asLocalhost: true }
        });

        const network  = await gateway.getNetwork(CHANNEL);
        const contract = network.getContract(CHAINCODE);

        // ── Flow 1: Submit beacon evidence B_nk(t) ───────────────────────────
        if (beaconEvidence && beaconEvidence.observations &&
                beaconEvidence.observations.length > 0) {
            const evidenceRecord = {
                peer_id:       trustedNodeID,
                interval_ts:   beaconInterval,
                observations:  beaconEvidence.observations,
                peer_sig:      signWithDilithium2(trustedNodeID, JSON.stringify(beaconEvidence)),
                peer_pub_key:  getPeerPubKey(trustedNodeID),
                is_rsu_peer:   true,
                doc_type:      'BEACON_EVIDENCE'
            };
            await contract.submitTransaction(
                'SubmitBeaconEvidence',
                JSON.stringify(evidenceRecord)
            );
            console.log(`[Fabric] Flow 1 ✓  SubmitBeaconEvidence  ` +
                `interval=${beaconInterval}  n_obs=${beaconEvidence.observations.length}`);
        }

        // ── Flow 3: Submit controller topology claim (optional) ──────────────
        if (ctrlTopo) {
            const claim = {
                controller_id: ctrlTopo.controller_id || 'sdn-controller',
                interval_ts:   beaconInterval,
                links:         ctrlTopo.links || [],
                ctrl_sig:      [],
                doc_type:      'CTRL_TOPOLOGY'
            };
            await contract.submitTransaction(
                'SubmitControllerTopology',
                JSON.stringify(claim)
            );
            console.log(`[Fabric] Flow 3 ✓  SubmitControllerTopology  ` +
                `links=${claim.links.length}`);
        }

        // ── Flow 2 + SubmitAlert: submit each detection event ─────────────────
        for (const alert of alertSet) {
            // SubmitAlert wraps Flow 2 + Algorithm 4 in a single transaction
            const ctrlTopoStr = ctrlTopo ? JSON.stringify(ctrlTopo) : '{}';
            await contract.submitTransaction(
                'SubmitAlert',
                JSON.stringify(alert),
                ctrlTopoStr,
                String(alert.t_alert)
            );
            console.log(`[Fabric] Flow 2 + Algorithm 4 ✓  SubmitAlert` +
                `  v_id=${alert.v_id}  α=${alert.alpha}  ŷ=${alert.y_hat.toFixed(4)}`);
        }

        // ── Full Mitigate call (if alerts exist) ──────────────────────────────
        if (alertSet.length > 0) {
            const detEvents = alertSet.map(a => ({
                peer_id:        trustedNodeID,
                vehicle_id:     a.v_id,
                attack_variant: a.alpha,
                anomaly_score:  a.y_hat,
                triggered_sigs: sTrigsToMask(a.S_trig),
                alert_ts_ms:    a.t_alert,
                from_lw_path:   a.from_lw_path || false,
                from_fs_path:   true,
            }));

            const ctrlClaim = ctrlTopo || {
                controller_id: 'sdn-controller',
                interval_ts:   beaconInterval,
                links:         []
            };

            const thresholdT = String(Math.floor(alertSet.length / 2) + 1);

            await contract.submitTransaction(
                'Mitigate',
                JSON.stringify(detEvents),
                JSON.stringify(beaconEvidence || { observations: [] }),
                JSON.stringify(ctrlClaim),
                THETA_FS,
                thresholdT
            );
            console.log(`[Fabric] Algorithm 4 ✓  Mitigate  n_alerts=${alertSet.length}`);
        }

        console.log('[Fabric] SUBMIT_TO_FABRIC complete.');

    } finally {
        gateway.disconnect();
    }
}

// ─── Crypto stubs ─────────────────────────────────────────────────────────────

/**
 * signWithDilithium2 produces a Dilithium2 signature σ_nk over message.
 * In production: call liboqs Node.js binding OQS.sign(msg, sk).
 * Simulation: returns a deterministic placeholder so the chaincode's
 * verifyDilithium2Sig (simulation mode) accepts it.
 */
function signWithDilithium2(trustedNodeID, message) {
    // Placeholder — replace with liboqs-node OQS.sign() call in production.
    const placeholder = Buffer.from(`SIM_SIG:${trustedNodeID}:${message.length}`);
    return Array.from(placeholder);
}

/**
 * getPeerPubKey returns the peer's Dilithium2 public key bytes.
 * In production: load from the wallet identity certificate.
 */
function getPeerPubKey(trustedNodeID) {
    return Array.from(Buffer.from(`SIMKEY:${trustedNodeID}`));
}

/** Convert S_trig index array to a 9-bit bitmask. */
function sTrigsToMask(strig) {
    let mask = 0;
    for (const i of (strig || [])) {
        if (i >= 0 && i < 32) mask |= (1 << i);
    }
    return mask;
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    let alertsPath   = 'tgn_alerts.json';
    let evidencePath = null;
    let ctrlTopoPath = null;
    let nodeID       = PEER_ID;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--alerts'   && args[i+1]) alertsPath   = args[++i];
        if (args[i] === '--evidence' && args[i+1]) evidencePath = args[++i];
        if (args[i] === '--ctrl_topo'&& args[i+1]) ctrlTopoPath = args[++i];
        if (args[i] === '--node_id'  && args[i+1]) nodeID       = args[++i];
    }

    if (!fs.existsSync(alertsPath)) {
        console.error(`[ERROR] Alerts file not found: ${alertsPath}`);
        console.error('  Run tgn_detector first: ./waf --run "scratch/tgn_detector ..."');
        process.exit(1);
    }

    const alerts = JSON.parse(fs.readFileSync(alertsPath, 'utf8'));
    console.log(`[Bridge] Loaded ${alerts.length} alert(s) from '${alertsPath}'`);

    const beaconEvidence = evidencePath && fs.existsSync(evidencePath)
        ? JSON.parse(fs.readFileSync(evidencePath, 'utf8'))
        : { observations: [] };

    const ctrlTopo = ctrlTopoPath && fs.existsSync(ctrlTopoPath)
        ? JSON.parse(fs.readFileSync(ctrlTopoPath, 'utf8'))
        : null;

    const beaconInterval = alerts.length > 0 ? alerts[0].t_alert : Date.now();

    await submitToFabric(nodeID, alerts, beaconEvidence, beaconInterval, ctrlTopo);
}

main().catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
});

module.exports = { submitToFabric };
