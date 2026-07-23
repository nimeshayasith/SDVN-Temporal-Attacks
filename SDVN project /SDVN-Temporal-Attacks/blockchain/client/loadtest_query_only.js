'use strict';
const { connectContract } = require('./fabricClient');
const PEER_ID = 'peer0.rsu3.tetaguard.net';

async function main() {
    const { gateway, contract } = await connectContract(PEER_ID);
    console.log('[QueryTest] Connected. Running 5 read-only GetLatestAnchorCheckpoint queries...');
    for (let i = 0; i < 5; i++) {
        const start = process.hrtime.bigint();
        try {
            await contract.evaluateTransaction('GetLatestAnchorCheckpoint');
            const ms = Number(process.hrtime.bigint() - start) / 1e6;
            console.log(`[QueryTest] query ${i + 1}/5: ${ms.toFixed(1)} ms`);
        } catch (err) {
            const ms = Number(process.hrtime.bigint() - start) / 1e6;
            console.log(`[QueryTest] query ${i + 1}/5 FAILED after ${ms.toFixed(1)} ms: ${err.message}`);
        }
    }
    await gateway.disconnect();
}
main().catch(err => { console.error(err); process.exit(1); });
