/**
 * measure_texec_fabric.js — real T_exec_fabric measurement
 *
 * Reviewer-flagged Issue 4: T_exec_compute (0.037ms, measured in routing.cc)
 * is local chaincode computation only, NOT comparable to the 50-200ms
 * Hyperledger Fabric literature figure (T_exec_fabric), which is the full
 * client-observed endorse+order+commit round trip. This script measures
 * T_exec_fabric directly against the real, already-running TETA-Guard
 * Fabric 3.1 SmartBFT network (4 orderers, 8 peers: rsu1-5 + obu1-3),
 * using the SAME Gateway SDK connection pattern as submitToFabric.js.
 *
 * Submits N real SetSimParams transactions (a genuine chaincode write, not a
 * mock -- chosen because it requires no signature/crypto payload and is
 * safely repeatable/idempotent, unlike SubmitBeaconEvidence which needs a
 * signed BeaconEvidenceRecord) and times each submission from
 * contract.submitTransaction() call to promise resolution (i.e. after the
 * transaction has been endorsed, ordered, AND committed to the ledger --
 * the full Fabric pipeline, unlike T_exec_compute which only covers local
 * chaincode computation). Any submitTransaction call goes through the same
 * endorse->order->commit round trip regardless of the target function's own
 * internal logic, so this measures the real pipeline cost accurately.
 *
 * Usage: node measure_texec_fabric.js [--n 30] [--channel teta-channel]
 */
'use strict';

const { Gateway, Wallets } = require('fabric-network');
const fs   = require('fs');
const path = require('path');

const WALLET_PATH  = path.join(__dirname, 'wallet');
const CONN_PROFILE  = path.join(__dirname, '..', 'config', 'connection-profile.json');
const IDENTITY      = 'peer0.rsu3.tetaguard.net';

function parseArgs() {
    const args = process.argv.slice(2);
    let n = 30, channel = 'teta-channel';
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--n' && args[i + 1]) n = parseInt(args[++i], 10);
        if (args[i] === '--channel' && args[i + 1]) channel = args[++i];
    }
    return { n, channel };
}

async function main() {
    const { n, channel } = parseArgs();
    const connProfile = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
    const wallet = await Wallets.newFileSystemWallet(WALLET_PATH);
    const identity = await wallet.get(IDENTITY);
    if (!identity) {
        throw new Error(`Identity '${IDENTITY}' not found in wallet at ${WALLET_PATH}`);
    }

    const gateway = new Gateway();
    await gateway.connect(connProfile, {
        wallet,
        identity: IDENTITY,
        discovery: { enabled: false, asLocalhost: true },
    });

    const network  = await gateway.getNetwork(channel);
    const contract = network.getContract('temporalecho');

    console.log(`[measure] Connected to channel '${channel}' as ${IDENTITY}. Submitting ${n} real SetSimParams transactions...`);

    const latenciesMs = [];
    let okCount = 0, failCount = 0;
    for (let i = 0; i < n; i++) {
        // Alternate the value slightly each call so each write is a genuine
        // new ledger state change, not a repeated no-op.
        const rComm = (170 + (i % 5)).toString();
        const t0 = process.hrtime.bigint();
        try {
            await contract.submitTransaction('SetSimParams', rComm, '-85', '0');
            const t1 = process.hrtime.bigint();
            const ms = Number(t1 - t0) / 1e6;
            latenciesMs.push(ms);
            okCount++;
            console.log(`  [${i + 1}/${n}] committed in ${ms.toFixed(2)} ms`);
        } catch (e) {
            failCount++;
            console.log(`  [${i + 1}/${n}] FAILED: ${e.message.split('\n')[0]}`);
        }
    }

    gateway.disconnect();

    if (latenciesMs.length === 0) {
        console.log('[measure] No successful transactions -- cannot compute T_exec_fabric.');
        process.exit(1);
    }

    latenciesMs.sort((a, b) => a - b);
    const sum = latenciesMs.reduce((a, b) => a + b, 0);
    const mean = sum / latenciesMs.length;
    const max = latenciesMs[latenciesMs.length - 1];
    const min = latenciesMs[0];
    const p95 = latenciesMs[Math.floor(0.95 * (latenciesMs.length - 1))];

    console.log('\n=== T_exec_fabric (real, measured) ===');
    console.log(`  n_committed=${okCount}  n_failed=${failCount}`);
    console.log(`  mean=${mean.toFixed(2)} ms  min=${min.toFixed(2)} ms  p95=${p95.toFixed(2)} ms  max=${max.toFixed(2)} ms`);
    console.log(`  literature range: 50-200ms`);

    const outCsv = path.join(__dirname, '..', '..', 'documents', 'T_EXEC_FABRIC_MEASURED.csv');
    const writeHdr = !fs.existsSync(outCsv);
    const fout = fs.createWriteStream(outCsv, { flags: 'a' });
    if (writeHdr) {
        fout.write('channel,n_committed,n_failed,mean_ms,min_ms,p95_ms,max_ms,timestamp\n');
    }
    fout.write(`${channel},${okCount},${failCount},${mean.toFixed(3)},${min.toFixed(3)},${p95.toFixed(3)},${max.toFixed(3)},${new Date().toISOString()}\n`);
    fout.end();
    console.log(`\n[measure] Appended to ${outCsv}`);
}

main().catch((e) => {
    console.error('[measure] FATAL:', e);
    process.exit(1);
});
