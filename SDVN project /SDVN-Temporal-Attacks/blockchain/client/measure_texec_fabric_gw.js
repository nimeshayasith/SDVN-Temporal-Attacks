/**
 * measure_texec_fabric_gw.js — real T_exec_fabric measurement via the
 * modern @hyperledger/fabric-gateway SDK (gRPC Gateway service, Fabric
 * 2.4+/3.x standard client), NOT the legacy fabric-network SDK.
 *
 * Investigation finding (2026-07-29): measure_texec_fabric.js (legacy
 * fabric-network Gateway/contract.submitTransaction) showed a consistent
 * ~10s floor per transaction even after the real orderer-side bug
 * (RequestForwardTimeout/RequestComplainTimeout misconfiguration in
 * configtx.yaml) was fixed and confirmed via live orderer log tracing
 * (consensus completing in 20-30ms). Instrumenting global setTimeout during
 * a single transaction showed multiple grpc-js BackoffTimeout/
 * TRANSIENT_FAILURE retry cycles (~1s+2s+3s per channel) across the
 * separate Endorser/EventService/Committer gRPC channels that
 * fabric-network's PREFER_MSPID_SCOPE_ALLFORTX event-handler strategy
 * opens per transaction to listen for the commit event -- a known
 * architectural cost of the legacy client-side event-listening model, not
 * a network/orderer misconfiguration. The modern fabric-gateway SDK
 * avoids this entirely: endorse+order+commit-wait happens as a single
 * server-side gRPC call (Gateway.EndorseAndSubmit / SubmitAsync +
 * CommitStatus) over one long-lived channel, which is the architecture
 * Hyperledger recommends for Fabric 2.4+ and is what a production
 * TETA-Guard deployment should use.
 *
 * Usage: node measure_texec_fabric_gw.js [--n 30] [--channel teta-channel]
 */
'use strict';

const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const NETWORK_DIR = path.join(__dirname, '..', 'network');
const MSP_DIR = path.join(NETWORK_DIR, 'crypto-config', 'peerOrganizations', 'tetaguard.net', 'users', 'Admin@tetaguard.net', 'msp');
const PEER_TLS_DIR = path.join(NETWORK_DIR, 'crypto-config', 'peerOrganizations', 'tetaguard.net', 'peers', 'peer0.rsu3.tetaguard.net', 'tls');
const PEER_ENDPOINT = 'localhost:7053';
const PEER_HOST_ALIAS = 'peer0.rsu3.tetaguard.net';
const MSPID = 'TetaGuardMSP';

function parseArgs() {
    const args = process.argv.slice(2);
    let n = 30, channel = 'teta-channel';
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--n' && args[i + 1]) n = parseInt(args[++i], 10);
        if (args[i] === '--channel' && args[i + 1]) channel = args[++i];
    }
    return { n, channel };
}

async function newGateway() {
    const certPath = path.join(MSP_DIR, 'signcerts', fs.readdirSync(path.join(MSP_DIR, 'signcerts'))[0]);
    const keyPath = path.join(MSP_DIR, 'keystore', fs.readdirSync(path.join(MSP_DIR, 'keystore'))[0]);
    const tlsCaPath = path.join(PEER_TLS_DIR, 'ca.crt');

    const credentials = fs.readFileSync(certPath);
    const privateKeyPem = fs.readFileSync(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    const tlsRootCert = fs.readFileSync(tlsCaPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    const client = new grpc.Client(PEER_ENDPOINT, tlsCredentials, {
        'grpc.ssl_target_name_override': PEER_HOST_ALIAS,
    });

    const gateway = connect({
        client,
        identity: { mspId: MSPID, credentials },
        signer,
    });
    return { gateway, client };
}

async function main() {
    const { n, channel } = parseArgs();
    const { gateway, client } = await newGateway();

    try {
        const network = gateway.getNetwork(channel);
        const contract = network.getContract('temporalecho');

        console.log(`[measure-gw] Connected to channel '${channel}' via fabric-gateway. Submitting ${n} real SetSimParams transactions...`);

        const latenciesMs = [];
        let okCount = 0, failCount = 0;
        for (let i = 0; i < n; i++) {
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

        if (latenciesMs.length === 0) {
            console.log('[measure-gw] No successful transactions -- cannot compute T_exec_fabric.');
            process.exit(1);
        }

        latenciesMs.sort((a, b) => a - b);
        const sum = latenciesMs.reduce((a, b) => a + b, 0);
        const mean = sum / latenciesMs.length;
        const max = latenciesMs[latenciesMs.length - 1];
        const min = latenciesMs[0];
        const p95 = latenciesMs[Math.floor(0.95 * (latenciesMs.length - 1))];

        console.log('\n=== T_exec_fabric (real, measured, fabric-gateway SDK) ===');
        console.log(`  n_committed=${okCount}  n_failed=${failCount}`);
        console.log(`  mean=${mean.toFixed(2)} ms  min=${min.toFixed(2)} ms  p95=${p95.toFixed(2)} ms  max=${max.toFixed(2)} ms`);
        console.log(`  literature range: 50-200ms`);

        const outCsv = path.join(__dirname, '..', '..', 'documents', 'T_EXEC_FABRIC_MEASURED.csv');
        const writeHdr = !fs.existsSync(outCsv);
        const fout = fs.createWriteStream(outCsv, { flags: 'a' });
        if (writeHdr) {
            fout.write('channel,n_committed,n_failed,mean_ms,min_ms,p95_ms,max_ms,timestamp\n');
        }
        fout.write(`${channel}-gwSDK,${okCount},${failCount},${mean.toFixed(3)},${min.toFixed(3)},${p95.toFixed(3)},${max.toFixed(3)},${new Date().toISOString()}\n`);
        fout.end();
        console.log(`\n[measure-gw] Appended to ${outCsv}`);
    } finally {
        gateway.close();
        client.close();
    }
}

main().catch((e) => {
    console.error('[measure-gw] FATAL:', e);
    process.exit(1);
});
