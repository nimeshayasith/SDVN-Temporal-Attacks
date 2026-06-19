'use strict';
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const CHANNEL = 'teta-channel';
const CHAINCODE = 'temporalecho';
const PEER_ID = 'peer0.rsu4.tetaguard.net';
const WALLET_PATH = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');

const OBU_PEERS = ['peer0.obu1.tetaguard.net', 'peer0.obu2.tetaguard.net', 'peer0.obu3.tetaguard.net'];
const ALL_PEERS = [
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

    // Check OBU scores
    for (const pid of OBU_PEERS) {
        const raw = await contract.evaluateTransaction('GetTrustScore', pid);
        console.log(pid, '→', raw.toString());
    }

    // SelectPeers with only OBUs — should include them if eligible
    console.log('\nSelectPeers(OBU only):');
    const r1 = await contract.evaluateTransaction('SelectPeers', JSON.stringify(OBU_PEERS));
    console.log('  Result:', r1.toString());

    // SelectPeers with rsu4+rsu5+OBUs (rsu1-3 demoted)
    console.log('\nSelectPeers(rsu4+rsu5+OBUs):');
    const r2 = await contract.evaluateTransaction('SelectPeers', JSON.stringify(ALL_PEERS));
    console.log('  Result:', r2.toString());

    // GetLatestAnchorCheckpoint
    console.log('\nGetLatestAnchorCheckpoint:');
    const cp = await contract.evaluateTransaction('GetLatestAnchorCheckpoint').catch(e => `ERROR: ${e.message.split('\n')[0]}`);
    console.log('  Result:', typeof cp === 'string' ? cp : cp.toString());

    await gateway.disconnect();
}
main().catch(e => { console.error(e.message); process.exit(1); });
