'use strict';
const { Gateway, Wallets } = require('fabric-network');
const fs = require('fs'), path = require('path');
const PEER_ID = 'peer0.rsu4.tetaguard.net';
const WALLET_PATH = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');

async function main() {
    const gw = new Gateway();
    await gw.connect(JSON.parse(fs.readFileSync(CONN_PROFILE,'utf8')), {
        wallet: await Wallets.newFileSystemWallet(WALLET_PATH),
        identity: PEER_ID, discovery: { enabled: false, asLocalhost: true }
    });
    const contract = (await gw.getNetwork('teta-channel')).getContract('temporalecho');
    for (const vid of ['V7','V5','V1','V2','V3']) {
        const raw = await contract.evaluateTransaction('QueryMitigationHistory', vid).catch(() => null);
        if (!raw) continue;
        const entries = JSON.parse(raw.toString());
        if (!entries || entries.length === 0) continue;
        console.log(`\n  === Vehicle ${vid}: ${entries.length} mitigation record(s) on ledger ===`);
        for (const e of entries) {
            console.log(`    entry_id      : ${e.entry_id}`);
            console.log(`    attack_variant: ${e.attack_variant}`);
            console.log(`    anomaly_score : ${e.anomaly_score}`);
            console.log(`    actions       : ${JSON.stringify(e.actions)}`);
            console.log(`    interval_ts   : ${e.interval_ts}`);
            console.log(`    doc_type      : ${e.doc_type}`);
            console.log('');
        }
    }
    await gw.disconnect();
}
main().catch(e => console.error(e.message));
