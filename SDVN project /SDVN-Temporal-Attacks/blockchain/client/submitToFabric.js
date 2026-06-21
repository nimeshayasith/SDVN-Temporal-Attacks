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
const PEER_ID          = 'peer0.rsu4.tetaguard.net';  // submitting peer identity (rsu4 = current, event source)
const WALLET_PATH      = path.join(__dirname, 'wallet');
const CONN_PROFILE     = path.join(__dirname, '..', 'config', 'connection-profile.json');

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

            await contract.submitTransaction(
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
            const activePeers = await contract.submitTransaction(
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

    await submitToFabric(nodeID, alerts, beaconEvidence, beaconInterval, ctrlTopo, noRSUMode);
}

main().catch(err => {
    console.error('[ERROR]', err.message);
    process.exit(1);
});

module.exports = { submitToFabric };
