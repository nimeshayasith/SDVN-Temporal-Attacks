'use strict';
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const CHANNEL = 'teta-channel';
const CHAINCODE = 'temporalecho';
const PEER_ID = 'peer0.rsu4.tetaguard.net';
const WALLET_PATH = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');

const ALL_PEERS = [
    'peer0.rsu1.tetaguard.net', 'peer0.rsu2.tetaguard.net', 'peer0.rsu3.tetaguard.net',
    'peer0.rsu4.tetaguard.net', 'peer0.rsu5.tetaguard.net',
    'peer0.obu1.tetaguard.net', 'peer0.obu2.tetaguard.net', 'peer0.obu3.tetaguard.net',
];

async function main() {
    const connProfile = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
    const wallet = await Wallets.newFileSystemWallet(WALLET_PATH);
    const gateway = new Gateway();
    await gateway.connect(connProfile, { wallet, identity: PEER_ID, discovery: { enabled: false, asLocalhost: true } });
    const network = await gateway.getNetwork(CHANNEL);
    const contract = network.getContract(CHAINCODE);

    // Check trust records for OBUs
    for (const pid of ALL_PEERS.filter(p => p.includes('obu'))) {
        const raw = await contract.evaluateTransaction('GetTrustRecord', pid).catch(() => null);
        if (raw) {
            const r = JSON.parse(raw.toString());
            console.log('OBU:', pid, '| score:', r.Score, '| JoinedAtMs:', r.JoinedAtMs, '| State:', r.State);
        }
    }
    
    // Check GetLatestAnchorCheckpoint
    console.log('\nGetLatestAnchorCheckpoint:');
    const cpRaw = await contract.evaluateTransaction('GetLatestAnchorCheckpoint').catch(e => { console.log('  Error:', e.message.split('\n')[0]); return null; });
    console.log('  Result:', cpRaw ? JSON.parse(cpRaw.toString()) : 'null');

    // SelectPeers
    console.log('\nSelectPeers result:', (await contract.evaluateTransaction('SelectPeers', JSON.stringify(ALL_PEERS))).toString());

    await gateway.disconnect();
}
main().catch(e => { console.error(e.message); process.exit(1); });
