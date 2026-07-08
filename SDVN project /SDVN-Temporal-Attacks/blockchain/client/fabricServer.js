/**
 * fabricServer.js — persistent live-submission bridge between routing.cc and
 * Hyperledger Fabric.
 *
 * routing.cc (--live_blockchain=1) opens ONE persistent Unix domain socket
 * connection to this process at simulation start and writes one
 * newline-delimited line per event for the rest of the run — it speaks
 * nothing but "write a line to a socket" (no HTTP, no libcurl, no fork/exec;
 * see PemLiveSend/PemLiveSocketConnect in routing.cc). This process owns
 * everything past that point: parsing, queueing, and submitting to Fabric.
 *
 * Crypto gating (HMAC/nonce/timestamp/revocation, Algorithm 3) already ran
 * INSIDE routing.cc itself before an event ever reaches this socket —
 * routing.cc compiles the crypto layer directly via its .crypto_src/*
 * includes (PemCryptoPreFilter/TetaGuardCryptoFilter), so nothing here
 * re-gates events. This process's only jobs are: parse, queue, submit,
 * retry.
 *
 * Wire protocol (newline-delimited, one message per line):
 *   "E:" + 22 comma-separated pem_event_log.csv columns (see
 *          PemBuildEventCsvRow in routing.cc) + "," + base64(AlertObject
 *          JSON) + "," + base64(ControllerTopologyClaim JSON)
 *     -> chaincode Mitigate(...) — Algorithm 4 (FS-MITIGATE), the same real
 *        PBFT-threshold production path submitToFabric.js's batch script
 *        uses (fabricClient.submitMitigate, extracted from there). This is
 *        NOT the SubmitAlert shortcut submit_alerts.py uses for dev testing —
 *        each live alert is submitted as a length-1 batch through the real
 *        Mitigate flow, replicated across the active peer set exactly like
 *        the batch path does.
 *   "W:" + base64(WitnessRecord JSON, already ML-DSA-87-signed by routing.cc)
 *     -> chaincode SubmitWitnessRecord(witnessJSON)
 *
 * Fabric -> simulation feedback is NOT this process's job: eventListener.js
 * already subscribes to BlacklistBeaconPublished and already writes
 * /tmp/blacklist_vehicle_ids.txt, which routing.cc's PemReadBlacklistFile()
 * already polls every 0.5s. That loop needs no changes and is not touched
 * here.
 *
 * Usage:
 *   node fabricServer.js [--node_id <peer>] [--socket /path/to.sock] [--no_rsu]
 *
 * Pass --no_rsu when the routing.cc run you're about to start is a no-RSU
 * attack scenario (1,3,5,7,9,11) — same convention as submit_alerts.py /
 * submitToFabric.js, since Mitigate's active peer set is a binary switch
 * (RSU peers vs OBU peers, never mixed).
 */

'use strict';

const net  = require('net');
const fs   = require('fs');
const path = require('path');
const fabricClient = require('./fabricClient');

const SOCKET_PATH_DEFAULT = '/tmp/teta_guard_live.sock';
const PEER_ID_DEFAULT     = 'peer0.rsu4.tetaguard.net';
const LOG_FILE = path.join(__dirname, '..', '..', 'blockchain_submission_log.txt');

// Same drop-oldest backpressure policy as routing.cc's send buffer, applied
// consistently here too (per review: one policy across every hop, not
// different behavior per queue).
const QUEUE_MAX = 500;

function parseArgs() {
    const args = process.argv.slice(2);
    let socketPath = SOCKET_PATH_DEFAULT;
    let nodeID     = PEER_ID_DEFAULT;
    let noRSUMode  = false; // pass --no_rsu when running no-RSU scenarios (1,3,5,7,9,11)
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--socket'  && args[i + 1]) socketPath = args[++i];
        if (args[i] === '--node_id' && args[i + 1]) nodeID     = args[++i];
        if (args[i] === '--no_rsu')                 noRSUMode  = true;
    }
    return { socketPath, nodeID, noRSUMode };
}

let logStream = null;
function log(msg) {
    const line = `[${new Date().toISOString()}] ${msg}`;
    console.log(line);
    if (logStream) logStream.write(line + '\n');
}

/** Splits one "E:" line's payload into the 22 CSV columns + 2 base64 fields. */
function parseAlertLine(payload) {
    const cols = payload.split(',');
    if (cols.length < 24) {
        throw new Error(`E: line has ${cols.length} columns, expected >=24`);
    }
    const alertJsonB64    = cols[cols.length - 2];
    const ctrlTopoJsonB64 = cols[cols.length - 1];
    const simTimeS = parseFloat(cols[0]);
    return {
        simTimeS,
        alertJson:    Buffer.from(alertJsonB64, 'base64').toString('utf8'),
        ctrlTopoJson: Buffer.from(ctrlTopoJsonB64, 'base64').toString('utf8'),
    };
}

function parseWitnessLine(payload) {
    return Buffer.from(payload, 'base64').toString('utf8');
}

async function main() {
    const { socketPath, nodeID, noRSUMode } = parseArgs();

    logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });
    log(`fabricServer starting — socket=${socketPath} node_id=${nodeID} no_rsu=${noRSUMode}`);

    log('Connecting to Fabric gateway...');
    // The Fabric SDK's gateway.connect() can hang indefinitely (rather than
    // fail fast) when peers are unreachable (DNS/network down, network not
    // bootstrapped yet) — race it against a timeout so a misconfigured
    // environment gets a clear, actionable error instead of hanging forever.
    const CONNECT_TIMEOUT_MS = 20000;
    const { gateway, contract, channelPeers } = await Promise.race([
        fabricClient.connectContract(nodeID),
        new Promise((_, reject) => setTimeout(
            () => reject(new Error(
                `Timed out after ${CONNECT_TIMEOUT_MS}ms connecting to Fabric. ` +
                'Is the network up? (docker-compose -f blockchain/network/docker-compose-teta.yaml up -d)'
            )), CONNECT_TIMEOUT_MS))
    ]);
    log(`Connected (${channelPeers.length || 'default'} channel peer(s)). Ready to receive live events from routing.cc.`);

    // Single bounded queue, drained by one worker loop so Fabric submissions
    // are serialized (avoids self-inflicted MVCC conflicts from firing many
    // concurrent submitTransaction calls) without blocking the socket reader
    // — Node's event loop keeps accepting/parsing incoming lines regardless
    // of how long the current queue item's Fabric call takes.
    const queue = [];
    let draining = false;

    function enqueue(item) {
        if (queue.length >= QUEUE_MAX) {
            queue.shift(); // drop-oldest backpressure policy
            log(`[WARN] queue full (${QUEUE_MAX}) — dropped oldest item`);
        }
        queue.push(item);
        drain();
    }

    async function drain() {
        if (draining) return;
        draining = true;
        while (queue.length > 0) {
            const item = queue[0];
            try {
                if (item.kind === 'alert') {
                    const alertObj    = JSON.parse(item.alertJson);
                    const ctrlTopoObj = JSON.parse(item.ctrlTopoJson);
                    const beaconInterval = Math.round(item.simTimeS * 1000);
                    const info = await fabricClient.submitMitigate(
                        contract, channelPeers, [alertObj],
                        { observations: [] }, // beacon evidence travels via separate "W:" witness records
                        ctrlTopoObj, beaconInterval, noRSUMode
                    );
                    log(`[Alert] Mitigate submitted OK (t=${item.simTimeS}s, `
                        + `v_id=${alertObj.v_id}, alpha=${alertObj.alpha}, `
                        + `t=${info.thresholdT}/${info.nPeers})`);
                } else if (item.kind === 'witness') {
                    await fabricClient.submitTransactionWithRetry(
                        contract, 'SubmitWitnessRecord', item.witnessJson
                    );
                    log('[Witness] submitted OK');
                }
                queue.shift();
            } catch (err) {
                // Retry on a short delay rather than dropping — item stays at
                // the front of the queue. A persistently-failing item (e.g.
                // malformed payload) would retry forever; acceptable for a
                // research simulation (known limitation, see the plan's
                // "in-memory queue lost on crash" note — this is the same
                // class of limitation, not a new one).
                log(`[ERROR] submission failed, will retry in 2s: ${err.message}`);
                await new Promise(r => setTimeout(r, 2000));
            }
        }
        draining = false;
    }

    // ── Unix domain socket server for routing.cc's live event stream ──────
    if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath); // stale socket from a prior run
    const server = net.createServer((socket) => {
        log('routing.cc connected.');
        let buf = '';
        socket.on('data', (chunk) => {
            buf += chunk.toString('utf8');
            let idx;
            while ((idx = buf.indexOf('\n')) >= 0) {
                const line = buf.slice(0, idx);
                buf = buf.slice(idx + 1);
                if (!line) continue;
                try {
                    if (line.startsWith('E:')) {
                        const { simTimeS, alertJson, ctrlTopoJson } = parseAlertLine(line.slice(2));
                        enqueue({ kind: 'alert', simTimeS, alertJson, ctrlTopoJson });
                    } else if (line.startsWith('W:')) {
                        const witnessJson = parseWitnessLine(line.slice(2));
                        enqueue({ kind: 'witness', witnessJson });
                    } else {
                        log(`[WARN] unrecognized line prefix, ignoring: ${line.slice(0, 20)}...`);
                    }
                } catch (err) {
                    log(`[WARN] failed to parse line, ignoring: ${err.message}`);
                }
            }
        });
        socket.on('error', (err) => log(`[WARN] socket error: ${err.message}`));
        socket.on('close', () => log('routing.cc disconnected (will accept a new connection on reconnect).'));
    });

    server.listen(socketPath, () => {
        log(`Listening on ${socketPath} — waiting for routing.cc (--live_blockchain=1)...`);
    });

    // ── Graceful shutdown: stop accepting, drain what's queued, then exit ──
    let shuttingDown = false;
    async function shutdown(signal) {
        if (shuttingDown) return;
        shuttingDown = true;
        log(`Received ${signal} — draining queue (${queue.length} item(s)) before exit...`);
        server.close();
        const deadline = Date.now() + 5000;
        while (queue.length > 0 && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 100));
        }
        if (queue.length > 0) {
            log(`[WARN] exiting with ${queue.length} item(s) still queued (shutdown grace period elapsed).`);
        }
        await gateway.disconnect();
        if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
        log('Shutdown complete.');
        process.exit(0);
    }
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));
}

main().catch((err) => {
    console.error('[FATAL]', err);
    process.exit(1);
});
