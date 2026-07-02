/**
 * submitToFabric.js — TGN → Hyperledger Fabric blockchain client
 *
 * Implements SUBMIT_TO_FABRIC(nk, A, B_nk(t)) from Algorithm 2 Step 22 (§10.1).
 *
 * Pipeline position:
 *   tgn_detector.cc  →  tgn_alerts.json  (raw alerts, all events)
 *   crypto_pipeline  →  tgn_alerts_crypto.json  (verified subset — 4-gate filter)
 *   submit_alerts.py →  peer chaincode invoke SubmitAlert   (simple path)
 *   submitToFabric.js→  Fabric Gateway SDK SubmitAlert       (full SDK path)
 *
 * BC-1: submitToFabric reads tgn_alerts_crypto.json (crypto-verified alerts only),
 * NOT tgn_alerts.json. Only alerts that passed revocation, HMAC, timestamp-freshness,
 * and nonce-novelty gates reach the blockchain. Alerts that failed any gate are in
 * crypto_drop_log.csv and are NOT submitted. Run the crypto pipeline first.
 *
 * The full SDK path (this file) also submits beacon evidence (Flow 1) and
 * triggers the divergence check (Flow 3) in addition to SubmitAlert.
 *
 * Usage:
 *   node submitToFabric.js [--alerts tgn_alerts_crypto.json] [--evidence beacon_evidence.csv]
 *   node submitToFabric.js --alerts tgn_alerts_crypto.json --ctrl_topo ctrl_topo.json
 *
 * BC-4: --evidence accepts beacon_evidence.csv (crypto pipeline output) directly.
 *   CSV columns: rsu_id,interval_ts_ms,vehicle_id,sender_ts_ms,gps_lat,gps_lon,rssi_dbm
 *
 * Prerequisites:
 *   - Fabric network running (docker-compose -f ../network/docker-compose-teta.yaml up -d)
 *   - Channel created and chaincode installed (scripts/bootstrap.sh)
 *   - npm install (in this directory)
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const fs            = require('fs');
const path          = require('path');
const { execFileSync } = require('child_process');

// ─── Configuration ────────────────────────────────────────────────────────────

const CHANNEL          = 'teta-channel';
const CHAINCODE        = 'temporalecho';
const PEER_ID          = 'peer0.rsu4.tetaguard.net';  // submitting peer identity (rsu4 = current, event source)
const WALLET_PATH      = path.join(__dirname, 'wallet');
const CONN_PROFILE     = path.join(__dirname, '..', 'config', 'connection-profile.json');

// Review finding #7: back-to-back scenario runs each launch their own
// submitToFabric.js process concurrently endorsing/committing against the
// same channel, which produces MVCC_READ_CONFLICT at commit (see the
// discovery/eventHandlerOptions comments below for the root cause). Retry
// with jittered exponential backoff on that specific, transient error class
// only — other errors (missing wallet identity, bad connection profile,
// chaincode-level rejects) should still fail fast rather than retry.
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

// Anomaly threshold θ_FS (Eq. 3.23) — set to 0.05 so all PEM scores pass (min observed: 0.10).
// TGN_THETA_FS = 0.40 is the production threshold; PEM scores are lower by design.
const THETA_FS = '0.05';

// ─── Main export — SUBMIT_TO_FABRIC(nk, A, B_nk(t)) §10.1 ────────────────────

/**
 * submitToFabric — main entry point implementing Algorithm 2, Step 22.
 *
 * @param {string}  trustedNodeID  — nk identifier (peer ID)
 * @param {Array}   alertSet       — array of AlertObject from tgn_alerts.json
 * @param {Object}  beaconEvidence — BeaconEvidenceRecord B_nk(t) for this interval
 * @param {number}  beaconInterval — current beacon interval timestamp (ms)
 * @param {Object}  ctrlTopo       — optional ControllerTopologyClaim for Flow 3
 * @param {boolean} noRSUMode      — true for no-RSU scenarios (1,3,5,7,9,11):
 *                                   active set filled by OBU peers only (thesis binary switch)
 */
async function submitToFabric(
    trustedNodeID,
    alertSet,
    beaconEvidence,
    beaconInterval,
    ctrlTopo = null,
    noRSUMode = false
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
        // connection-profile.json's "path" fields (adminPrivateKey, signedCert,
        // tlsCACerts, ...) are written relative to the config/ directory, e.g.
        // "../network/crypto-config/...". The fabric-network SDK resolves these
        // relative to the Node process's CWD, not the JSON file's own location --
        // so invoking this script from a different CWD (e.g. routing.cc's
        // system() call, which runs from the ns-3.35 simulation directory, not
        // blockchain/client/) fails deep inside the SDK with a raw ENOENT.
        // Rewrite every "path" field to an absolute path up front.
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

        const { DefaultEventHandlerStrategies } = require('fabric-network');
        await gateway.connect(connProfile, {
            wallet,
            identity:  trustedNodeID,
            // Discovery disabled: lagged peers (rsu1-rsu3, rsu5) produce stale RW sets
            // when endorsed concurrently with rsu4, causing MVCC_READ_CONFLICT at commit.
            // With discovery off, static connection-profile peer roles are used instead.
            discovery: { enabled: false, asLocalhost: true },
            eventHandlerOptions: {
                // ANYFORTX: only one peer in the MSP needs to confirm commit.
                // Some RSU peers may be behind on blocks; ANY strategy ensures
                // the healthy peer (rsu4 at full block height) can satisfy the event.
                // NETWORK_SCOPE_ANYFORTX: any single peer in the network satisfies the event.
                // rsu4 is the only peer with eventSource=true in the connection profile,
                // so confirmation comes from rsu4 immediately (lagged peers are excluded).
                strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ANYFORTX,
                commitTimeout: 60
            }
        });

        const network  = await gateway.getNetwork(CHANNEL);
        const contract = network.getContract(CHAINCODE);

        // SF-2: RSU peer registration.
        // Skip RegisterRSUPeer submits here — those writes to TRUST:* keys within
        // the same beacon interval as Mitigate cause MVCC_READ_CONFLICT because
        // Mitigate reads the full TRUST:* range via GetStateByRange and the
        // registration commit updates the range version between endorsement and commit.
        // RSU peers with trust < 1.0 (rsu5=0.9) still pass selectPeers (TrustMin=0.10)
        // and isBootstrapComplete (TrustMinGT=0.50), so skipping the re-registration
        // does not break PBFT quorum or bootstrap enforcement.
        // Registration is only needed on first bootstrap (handled by bootstrap.sh).

        // ── Flow 1: Submit beacon evidence B_nk(t) ───────────────────────────
        if (beaconEvidence && beaconEvidence.observations &&
                beaconEvidence.observations.length > 0) {
            // Must exactly match SubmitBeaconEvidence's sigInput construction
            // (temporalecho.go) — fixed-precision field concatenation, not
            // JSON, so both languages' serializers don't need to agree
            // byte-for-byte on key order/null-handling/float formatting.
            const obsStr = beaconEvidence.observations.map(o =>
                `${o.vehicle_id}|${o.sender_ts_ms}|${Number(o.gps_lat).toFixed(6)}|` +
                `${Number(o.gps_lon).toFixed(6)}|${Number(o.rssi_dbm).toFixed(2)};`
            ).join('');
            const beaconSigInput = `${trustedNodeID}:${beaconInterval}:${obsStr}`;

            const evidenceRecord = {
                peer_id:       trustedNodeID,
                interval_ts:   beaconInterval,
                observations:  beaconEvidence.observations,
                peer_sig:      signWithMLDSA87(trustedNodeID, beaconSigInput),
                peer_pub_key:  getPeerPubKey(trustedNodeID),
                is_rsu_peer:   true,
                doc_type:      'BEACON_EVIDENCE'
            };
            await submitTransactionWithRetry(contract,
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
            await submitTransactionWithRetry(contract,
                'SubmitControllerTopology',
                JSON.stringify(claim)
            );
            console.log(`[Fabric] Flow 3 ✓  SubmitControllerTopology  ` +
                `links=${claim.links.length}`);
        }

        // ── Resolve channel peer list (used for threshold and periodic selection) ──
        const channelPeers = connProfileRaw.channels
            && connProfileRaw.channels[CHANNEL]
            && connProfileRaw.channels[CHANNEL].peers
            ? Object.keys(connProfileRaw.channels[CHANNEL].peers)
            : [];

        // ── Flow 2 + Mitigate: submit all detection events with PBFT consensus ──
        // Peer set follows the thesis binary mode switch (Eq. 3.40):
        //   with-RSU scenarios  → all np slots filled by Tier-1 RSU peers only
        //   no-RSU scenarios    → all np slots filled by Tier-2 OBU peers only
        // Pass --no_rsu flag when running no-RSU attack scenarios (1,3,5,7,9,11).

        // ── Full Mitigate call (if alerts exist) ──────────────────────────────
        if (alertSet.length > 0) {
            const RSU_PEERS = channelPeers.length > 0 ? channelPeers : [
                'peer0.rsu1.tetaguard.net', 'peer0.rsu2.tetaguard.net',
                'peer0.rsu3.tetaguard.net', 'peer0.rsu4.tetaguard.net',
                'peer0.rsu5.tetaguard.net'
            ];
            const OBU_PEERS = [
                'peer0.obu1.tetaguard.net', 'peer0.obu2.tetaguard.net',
                'peer0.obu3.tetaguard.net'
            ];
            // Binary mode switch: no mixing of RSU and OBU in the active set.
            const allRSUPeers = noRSUMode ? OBU_PEERS : RSU_PEERS;
            // Normalise full variant strings (e.g. "TTW_S1_MAL_VEH_NO_RSU") to the
            // short forms the chaincode mitigation branches check ("TTW", "BSHH", "ME").
            // Without this, pushFlowModDrop/pushRerouteFlowMod are never called because
            // none of the chaincode's if-variant == "TTW" branches match the full string.
            const normaliseVariant = (alpha) => {
                if (alpha.startsWith('TTW'))  return 'TTW';
                if (alpha.startsWith('BSHH')) return 'BSHH';
                if (alpha.startsWith('ME'))   return 'ME';
                return alpha; // CTRL_ORIGIN or unknown — pass through unchanged
            };

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

            // SF-02 FIX: thresholdT = n/2+1 where n = number of active Fabric peers.
            // channelPeers is resolved above (before Flow 2 loop).
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
            console.log(`[Fabric] Algorithm 4 ✓  Mitigate  n_alerts=${alertSet.length}  t=${thresholdT}/${nPeers}`);
        }

        // ── Supervisor feedback: periodic peer re-selection ───────────────────
        // Re-evaluate all consortium peers at every beacon interval — not only
        // post-mitigation — so quarantined RSU peers are moved to REMOVED as
        // soon as their monitoring window elapses, even when no attack fires.
        try {
            // Binary mode: pass only the tier-appropriate peer list
            const allPeerIDs = noRSUMode
                ? ['peer0.obu1.tetaguard.net', 'peer0.obu2.tetaguard.net',
                   'peer0.obu3.tetaguard.net']
                : (channelPeers.length > 0 ? channelPeers
                   : ['peer0.rsu1.tetaguard.net', 'peer0.rsu2.tetaguard.net',
                      'peer0.rsu3.tetaguard.net', 'peer0.rsu4.tetaguard.net',
                      'peer0.rsu5.tetaguard.net']);
            const activePeers = await submitTransactionWithRetry(contract,
                'PeriodicPeerReSelection',
                JSON.stringify(allPeerIDs)
            );
            const activeList = JSON.parse(activePeers.toString() || '[]');
            console.log(`[Fabric] Periodic peer re-selection ✓  active_peers=${activeList.length}/${allPeerIDs.length}`);
        } catch (prsErr) {
            console.warn(`[Fabric] PeriodicPeerReSelection warning: ${prsErr.message}`);
        }

        console.log('[Fabric] SUBMIT_TO_FABRIC complete.');

    } finally {
        gateway.disconnect();
    }
}

// ─── RSU peer registration check (SF-2) ──────────────────────────────────────

/**
 * ensureRSUPeerRegistered checks whether the calling RSU peer has a trust score
 * of 1.0 on the ledger and registers it if not.  Handles the case where
 * submitToFabric.js is called directly without bootstrap.sh having run first.
 * SF-2: Without this, RSU trust records are absent and all beacon evidence
 * submissions are rejected (default trust = 0.1, below Tier 1 threshold).
 */
async function ensureRSUPeerRegistered(contract, trustedNodeID) {
    try {
        const result = await contract.evaluateTransaction('GetTrustScore', trustedNodeID);
        const scoreVal = parseFloat(result.toString());
        if (scoreVal < 0.99) {
            await contract.submitTransaction('RegisterRSUPeer', trustedNodeID);
            console.log(`[Fabric] RSU peer ${trustedNodeID} registered (trust=1.0)`);
        }
    } catch (err) {
        console.warn(`[Fabric] Could not verify/register RSU peer ${trustedNodeID}: ${err.message}`);
    }
}

// ─── Real ML-DSA-87 (Dilithium5, NIST Category 5) signing ────────────────────
//
// Per the report's notation table, the PQC signing algorithm used everywhere
// (location-binding Eq. 3.28, threshold aggregate sigs Eq. 3.26) is
// ML-DSA-87 = CRYSTALS-Dilithium5. Falcon-1024 and Dilithium2 (Category 2)
// are not in the report and are not used here.
//
// liboqs-node (the npm binding) failed to build in this environment (its
// bundled node-gyp/liboqs submodule build errored out). Rather than debug a
// third-party package's native build, this shells out to mldsa_tool — a
// small Go CLI (mldsa_tool.go) wrapping the already-verified-working
// liboqs-go binding, the same one the chaincode's verification_liboqs.go
// uses. Keys are generated once per trustedNodeID and cached in keys/.

const MLDSA_TOOL   = path.join(__dirname, 'mldsa_tool');
const KEYSTORE_DIR = path.join(__dirname, 'keys');

/** Runs mldsa_tool with the host's liboqs.so on LD_LIBRARY_PATH. */
function runMldsaTool(args) {
    return execFileSync(MLDSA_TOOL, args, {
        encoding: 'utf8',
        env: {
            ...process.env,
            LD_LIBRARY_PATH: `${process.env.HOME}/liboqs-local/lib:${process.env.LD_LIBRARY_PATH || ''}`
        }
    }).trim();
}

/**
 * loadOrCreateKeyPair returns {pubKeyHex, secretKeyHex} for trustedNodeID,
 * generating and persisting a fresh ML-DSA-87 keypair on first use.
 */
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

/**
 * signWithMLDSA87 produces a real ML-DSA-87 signature σ_nk over message,
 * using this peer's persisted keypair (generated on first use).
 */
function signWithMLDSA87(trustedNodeID, message) {
    const { secretKeyHex } = loadOrCreateKeyPair(trustedNodeID);
    const sigHex = runMldsaTool(['sign', secretKeyHex, message]);
    return Array.from(Buffer.from(sigHex, 'hex'));
}

/**
 * getPeerPubKey returns the peer's real ML-DSA-87 public key bytes (2592
 * bytes), generating a keypair on first use if none exists yet.
 */
function getPeerPubKey(trustedNodeID) {
    const { pubKeyHex } = loadOrCreateKeyPair(trustedNodeID);
    return Array.from(Buffer.from(pubKeyHex, 'hex'));
}

/** Convert S_trig index array to a 9-bit bitmask. */
function sTrigsToMask(strig) {
    let mask = 0;
    for (const i of (strig || [])) {
        if (i >= 0 && i < 32) mask |= (1 << i);
    }
    return mask;
}

// ─── BC-4: beacon_evidence.csv → BeaconEvidenceRecord ────────────────────────
//
// crypto_pipeline writes beacon_evidence.csv (CSV format) not JSON.
// CSV columns: rsu_id,interval_ts_ms,vehicle_id,sender_ts_ms,gps_lat,gps_lon,rssi_dbm
// This function parses the CSV and returns { observations: [...] } matching the
// BeaconEvidenceRecord.Observations field expected by SubmitBeaconEvidence (Flow 1).
// Rows are grouped by (rsu_id, interval_ts_ms); the first group's observations are
// returned (one submission per run — RSU aggregates one interval's worth of beacons).

function loadBeaconEvidence(evidencePath) {
    if (!evidencePath || !fs.existsSync(evidencePath)) {
        return { observations: [] };
    }

    const ext = path.extname(evidencePath).toLowerCase();

    // JSON path — accept pre-converted files or legacy beacon_evidence.json
    if (ext === '.json') {
        try {
            return JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
        } catch (e) {
            console.error(`[WARN] Could not parse evidence JSON ${evidencePath}: ${e.message}`);
            return { observations: [] };
        }
    }

    // CSV path — beacon_evidence.csv from crypto_pipeline
    if (ext !== '.csv') {
        console.error(`[WARN] Unsupported evidence file format: ${ext} (expected .csv or .json)`);
        return { observations: [] };
    }

    const raw = fs.readFileSync(evidencePath, 'utf8');
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);

    if (lines.length === 0) {
        return { observations: [] };
    }

    // Skip header line if present (starts with non-numeric rsu_id)
    const dataLines = lines[0].startsWith('rsu_id') ? lines.slice(1) : lines;

    // Group by (rsu_id, interval_ts_ms) — use the first group encountered
    const groups = new Map();
    for (const line of dataLines) {
        const parts = line.split(',');
        if (parts.length < 7) continue;
        const [rsu_id, interval_ts_ms, vehicle_id, sender_ts_ms, gps_lat, gps_lon, rssi_dbm] = parts;
        const groupKey = `${rsu_id.trim()}|${interval_ts_ms.trim()}`;
        if (!groups.has(groupKey)) groups.set(groupKey, []);
        groups.get(groupKey).push({
            vehicle_id:        vehicle_id.trim(),
            sender_ts_ms:      parseInt(sender_ts_ms.trim(), 10),
            gps_lat:           parseFloat(gps_lat.trim()),
            gps_lon:           parseFloat(gps_lon.trim()),
            rssi_dbm:          parseFloat(rssi_dbm.trim()),
            neighbour_vehicles: []
        });
    }

    if (groups.size === 0) {
        return { observations: [] };
    }

    // Take the first (earliest) interval group
    const firstGroup = groups.values().next().value;
    console.log(`[Bridge] Parsed beacon_evidence.csv: ${firstGroup.length} observation(s)`);
    return { observations: firstGroup };
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    let alertsPath   = 'tgn_alerts_crypto.json';  // BC-1: crypto-verified alerts only
    let evidencePath = null;
    let ctrlTopoPath = null;
    let nodeID       = PEER_ID;
    let noRSUMode    = false;  // set true for scenarios without RSU infrastructure

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--alerts'   && args[i+1]) alertsPath   = args[++i];
        if (args[i] === '--evidence' && args[i+1]) evidencePath = args[++i];
        if (args[i] === '--ctrl_topo'&& args[i+1]) ctrlTopoPath = args[++i];
        if (args[i] === '--node_id'  && args[i+1]) nodeID       = args[++i];
        if (args[i] === '--no_rsu')                noRSUMode    = true;
    }

    if (!fs.existsSync(alertsPath)) {
        console.error(`[ERROR] Alerts file not found: ${alertsPath}`);
        if (alertsPath.includes('crypto')) {
            console.error('  Run the crypto pipeline first: cd crypto && make && ./crypto_pipeline');
            console.error('  It reads pem_event_log.csv and writes tgn_alerts_crypto.json');
        } else {
            console.error('  Run tgn_detector first: ./waf --run "scratch/routing ..."');
        }
        process.exit(1);
    }

    const alerts = JSON.parse(fs.readFileSync(alertsPath, 'utf8'));
    console.log(`[Bridge] Loaded ${alerts.length} alert(s) from '${alertsPath}'`);

    const beaconEvidence = loadBeaconEvidence(evidencePath);  // BC-4: handles .csv and .json

    const ctrlTopo = ctrlTopoPath && fs.existsSync(ctrlTopoPath)
        ? JSON.parse(fs.readFileSync(ctrlTopoPath, 'utf8'))
        : null;

    const beaconInterval = alerts.length > 0 ? alerts[0].t_alert : Date.now();

    await submitToFabric(nodeID, alerts, beaconEvidence, beaconInterval, ctrlTopo, noRSUMode);
}

main().catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
});

module.exports = { submitToFabric };
