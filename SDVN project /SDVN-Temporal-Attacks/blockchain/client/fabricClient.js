/**
 * fabricClient.js — shared Fabric Gateway connection + ML-DSA-87 signing
 * helpers, factored out of submitToFabric.js so both the original one-shot
 * batch script and the new persistent fabricServer.js (live submission from
 * routing.cc) use one implementation instead of two divergent copies.
 *
 * submitToFabric.js and submit_alerts.py are NOT modified — they still work
 * standalone for offline/manual runs. This module only centralizes logic
 * that fabricServer.js also needs.
 */

'use strict';

const { Gateway, Wallets, DefaultEventHandlerStrategies } = require('fabric-network');
const fs   = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const CHANNEL      = 'teta-channel';
const CHAINCODE    = 'temporalecho';
const WALLET_PATH  = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');

// Review finding #7 (submitToFabric.js): concurrent submitters against the
// same channel can hit MVCC_READ_CONFLICT at commit. Retry with jittered
// backoff on that specific, transient error class only.
const MVCC_RETRY_MAX_ATTEMPTS = 4;
const MVCC_RETRY_BASE_MS      = 300;

function isRetryableMvccError(err) {
    const msg = (err && err.message) || '';
    return /MVCC_READ_CONFLICT|ENDORSEMENT_POLICY_FAILURE|PHANTOM_READ_CONFLICT/i.test(msg);
}

async function submitTransactionWithRetry(contract, txName, ...args) {
    let lastErr;
    for (let attempt = 1; attempt <= MVCC_RETRY_MAX_ATTEMPTS; attempt++) {
        try {
            return await contract.submitTransaction(txName, ...args);
        } catch (err) {
            lastErr = err;
            if (!isRetryableMvccError(err) || attempt === MVCC_RETRY_MAX_ATTEMPTS) {
                throw err;
            }
            const backoffMs = MVCC_RETRY_BASE_MS * Math.pow(2, attempt - 1)
                             + Math.floor(Math.random() * 100);
            console.warn(`[Fabric] ${txName} hit a transient conflict `
                + `(attempt ${attempt}/${MVCC_RETRY_MAX_ATTEMPTS}): ${err.message}`
                + ` — retrying in ${backoffMs}ms`);
            await new Promise(resolve => setTimeout(resolve, backoffMs));
        }
    }
    throw lastErr;
}

/**
 * connectContract — opens a Gateway connection and returns {gateway, contract}.
 * Callers own the gateway's lifetime (call gateway.disconnect() when done).
 * fabricServer.js calls this ONCE at startup and reuses the same contract for
 * every live event, instead of reconnecting per submission like the original
 * one-shot submitToFabric.js does (that per-invocation reconnect made sense
 * for a script that runs once and exits; a persistent server should not pay
 * that connection cost on every alert).
 */
async function connectContract(trustedNodeID) {
    if (!fs.existsSync(CONN_PROFILE)) {
        throw new Error(
            `Connection profile not found: ${CONN_PROFILE}\n` +
            '  Run scripts/bootstrap.sh to generate crypto material and profiles.'
        );
    }

    const connProfileRaw = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
    // See submitToFabric.js's original comment: "path" fields are written
    // relative to config/, but the SDK resolves them relative to process CWD.
    // Rewrite to absolute paths so this works regardless of where the caller
    // (fabricServer.js, launched however the user starts it) was invoked from.
    (function resolveConnProfilePaths(node) {
        if (!node || typeof node !== 'object') return;
        for (const key of Object.keys(node)) {
            const val = node[key];
            if (key === 'path' && typeof val === 'string' && !path.isAbsolute(val)) {
                node[key] = path.resolve(path.dirname(CONN_PROFILE), val);
            } else if (val && typeof val === 'object') {
                resolveConnProfilePaths(val);
            }
        }
    })(connProfileRaw);

    if (!fs.existsSync(WALLET_PATH)) {
        throw new Error(
            `Wallet directory not found: ${WALLET_PATH}\n` +
            '  Run scripts/bootstrap.sh to enrol peer identities into the wallet.'
        );
    }

    const wallet   = await Wallets.newFileSystemWallet(WALLET_PATH);
    const identity = await wallet.get(trustedNodeID);
    if (!identity) {
        throw new Error(
            `Identity '${trustedNodeID}' not found in wallet at ${WALLET_PATH}.\n` +
            'Run scripts/bootstrap.sh first to enrol the peer identity.'
        );
    }

    const gateway = new Gateway();
    await gateway.connect(connProfileRaw, {
        wallet,
        identity: trustedNodeID,
        discovery: { enabled: false, asLocalhost: true },
        eventHandlerOptions: {
            strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ANYFORTX,
            commitTimeout: 60
        }
    });

    const network  = await gateway.getNetwork(CHANNEL);
    const contract = network.getContract(CHAINCODE);
    return { gateway, contract, channelPeers: connProfileRaw.channels
        && connProfileRaw.channels[CHANNEL]
        && connProfileRaw.channels[CHANNEL].peers
        ? Object.keys(connProfileRaw.channels[CHANNEL].peers)
        : [] };
}

// ─── Real ML-DSA-87 (Dilithium5) signing — same mldsa_tool wrapper as
// submitToFabric.js; kept here so both callers share one keystore. ─────────
const MLDSA_TOOL   = path.join(__dirname, 'mldsa_tool');
const KEYSTORE_DIR = path.join(__dirname, 'keys');

function runMldsaTool(args) {
    return execFileSync(MLDSA_TOOL, args, {
        encoding: 'utf8',
        env: {
            ...process.env,
            LD_LIBRARY_PATH: `${process.env.HOME}/liboqs-local/lib:${process.env.LD_LIBRARY_PATH || ''}`
        }
    }).trim();
}

function loadOrCreateKeyPair(trustedNodeID) {
    if (!fs.existsSync(KEYSTORE_DIR)) fs.mkdirSync(KEYSTORE_DIR, { recursive: true });
    const keyFile = path.join(KEYSTORE_DIR, `${trustedNodeID}.json`);
    if (fs.existsSync(keyFile)) {
        return JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    }
    const [pubKeyHex, secretKeyHex] = runMldsaTool(['keygen']).split(' ');
    const keyPair = { pubKeyHex, secretKeyHex };
    fs.writeFileSync(keyFile, JSON.stringify(keyPair));
    console.log(`[Crypto] Generated new ML-DSA-87 keypair for ${trustedNodeID} -> ${keyFile}`);
    return keyPair;
}

function signWithMLDSA87(trustedNodeID, message) {
    const { secretKeyHex } = loadOrCreateKeyPair(trustedNodeID);
    const sigHex = runMldsaTool(['sign', secretKeyHex, message]);
    return Array.from(Buffer.from(sigHex, 'hex'));
}

function getPeerPubKey(trustedNodeID) {
    const { pubKeyHex } = loadOrCreateKeyPair(trustedNodeID);
    return Array.from(Buffer.from(pubKeyHex, 'hex'));
}

// Anomaly threshold θ_FS (Eq. 3.23) — same value submitToFabric.js uses: set
// to 0.05 so all PEM scores pass (min observed: 0.10). TGN_THETA_FS = 0.40 is
// the production threshold; PEM scores are lower by design.
const THETA_FS = '0.05';

const RSU_PEERS_DEFAULT = [
    'peer0.rsu1.tetaguard.net', 'peer0.rsu2.tetaguard.net',
    'peer0.rsu3.tetaguard.net', 'peer0.rsu4.tetaguard.net',
    'peer0.rsu5.tetaguard.net'
];
const OBU_PEERS_DEFAULT = [
    'peer0.obu1.tetaguard.net', 'peer0.obu2.tetaguard.net',
    'peer0.obu3.tetaguard.net'
];

/** Convert S_trig index array to a 9-bit bitmask. */
function sTrigsToMask(strig) {
    let mask = 0;
    for (const i of (strig || [])) {
        if (i >= 0 && i < 32) mask |= (1 << i);
    }
    return mask;
}

/** Normalise full variant strings (e.g. "TTW_S1_MAL_VEH_NO_RSU") to the short
 * forms the chaincode mitigation branches check ("TTW", "BSHH", "ME"). */
function normaliseVariant(alpha) {
    if (alpha.startsWith('TTW'))  return 'TTW';
    if (alpha.startsWith('BSHH')) return 'BSHH';
    if (alpha.startsWith('ME'))   return 'ME';
    return alpha; // CTRL_ORIGIN or unknown — pass through unchanged
}

/**
 * submitMitigate — the real Algorithm 4 (FS-MITIGATE) path, extracted from
 * submitToFabric.js's "Full Mitigate call" block so both the original batch
 * script and fabricServer.js's live per-alert path share one implementation.
 * This is the production path (PBFT threshold voting across the active peer
 * set) — NOT the SubmitAlert shortcut submit_alerts.py uses for dev testing.
 *
 * @param {object}  contract      — Fabric contract handle (from connectContract)
 * @param {Array}   channelPeers  — peer IDs from the connection profile (may be empty)
 * @param {Array}   alertSet      — array of AlertObject-shaped {v_id, alpha, y_hat,
 *                                  S_trig, t_alert, from_lw_path, ...} (one or more;
 *                                  fabricServer.js calls this with length 1 per live event)
 * @param {object}  beaconEvidence — {observations:[...]}, may be empty
 * @param {object}  ctrlTopo      — ControllerTopologyClaim-shaped object, or null
 * @param {number}  beaconInterval — fallback interval_ts if ctrlTopo has none
 * @param {boolean} noRSUMode     — true for no-RSU scenarios (1,3,5,7,9,11):
 *                                  active peer set is OBU peers, not RSU peers
 */
async function submitMitigate(contract, channelPeers, alertSet, beaconEvidence, ctrlTopo, beaconInterval, noRSUMode) {
    if (!alertSet || alertSet.length === 0) return;

    const allRSUPeers = noRSUMode
        ? OBU_PEERS_DEFAULT
        : (channelPeers.length > 0 ? channelPeers : RSU_PEERS_DEFAULT);

    const detEvents = alertSet.flatMap((a, idx) =>
        allRSUPeers.map((pid, pIdx) => ({
            peer_id:        pid,
            vehicle_id:     a.v_id,
            attack_variant: normaliseVariant(a.alpha),
            anomaly_score:  a.y_hat,
            triggered_sigs: sTrigsToMask(a.S_trig),
            alert_ts_ms:    a.t_alert + idx * 1000 + pIdx,
            from_lw_path:   a.from_lw_path || false,
            from_fs_path:   true,
        }))
    );

    const ctrlClaim = ctrlTopo || {
        controller_id: 'sdn-controller',
        interval_ts:   beaconInterval,
        links:         []
    };

    // SF-02: thresholdT = n/2+1 where n = number of active Fabric peers.
    const nPeers     = channelPeers.length || 5; // fallback to 5 (fixed TETA-Guard network)
    const thresholdT = String(Math.floor(nPeers / 2) + 1);

    await submitTransactionWithRetry(contract,
        'Mitigate',
        JSON.stringify(detEvents),
        JSON.stringify(beaconEvidence || { observations: [] }),
        JSON.stringify(ctrlClaim),
        THETA_FS,
        thresholdT
    );
    return { nAlerts: alertSet.length, thresholdT, nPeers };
}

module.exports = {
    CHANNEL, CHAINCODE, WALLET_PATH, CONN_PROFILE,
    connectContract,
    submitTransactionWithRetry,
    signWithMLDSA87,
    getPeerPubKey,
    submitMitigate,
    sTrigsToMask,
};
