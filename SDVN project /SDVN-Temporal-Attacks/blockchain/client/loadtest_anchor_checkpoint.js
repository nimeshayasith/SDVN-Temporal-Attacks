/**
 * loadtest_anchor_checkpoint.js — real-network throughput/latency check for
 * the AnchorIntervalBlocks fix (215/45 -> 30/30, Table 4.9 sec H).
 *
 * The fix means checkpoints are now created ~7x more often. This measures
 * whether that increased frequency creates any real commit-latency or
 * throughput problem against the live TETA-Guard Fabric network, per this
 * row's own PDF-stated calibration method ("measure synchronisation latency
 * of newly promoted Tier-2 peers in simulation").
 *
 * Not a synthetic/mocked test — submits real transactions to the actual
 * running 4-orderer SmartBFT network + 5 RSU peers.
 */
'use strict';

const { connectContract, submitTransactionWithRetry } = require('./fabricClient');

const NUM_CHECKPOINTS = 30;   // several times the ~7x frequency increase, to see any contention trend
const PEER_ID = 'peer0.rsu3.tetaguard.net';  // confirmed-synced peer, per deploy_chaincode.sh's own note

async function main() {
    console.log(`[LoadTest] Connecting as ${PEER_ID}...`);
    const { gateway, contract } = await connectContract(PEER_ID);
    console.log(`[LoadTest] Connected. Submitting ${NUM_CHECKPOINTS} CreateAnchorCheckpoint calls (interval=30)...`);

    const latenciesMs = [];
    let failures = 0;

    for (let i = 0; i < NUM_CHECKPOINTS; i++) {
        const start = process.hrtime.bigint();
        try {
            await submitTransactionWithRetry(contract, 'CreateAnchorCheckpoint', PEER_ID, '30');
            const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
            latenciesMs.push(elapsedMs);
            console.log(`[LoadTest] checkpoint ${i + 1}/${NUM_CHECKPOINTS}: ${elapsedMs.toFixed(1)} ms`);
        } catch (err) {
            failures++;
            console.error(`[LoadTest] checkpoint ${i + 1}/${NUM_CHECKPOINTS} FAILED: ${err.message}`);
        }
    }

    await gateway.disconnect();

    if (latenciesMs.length > 0) {
        const mean = latenciesMs.reduce((a, b) => a + b, 0) / latenciesMs.length;
        const max = Math.max(...latenciesMs);
        const min = Math.min(...latenciesMs);
        const sorted = [...latenciesMs].sort((a, b) => a - b);
        const p95 = sorted[Math.floor(sorted.length * 0.95)];
        console.log('\n=== Results ===');
        console.log(`successful: ${latenciesMs.length}/${NUM_CHECKPOINTS}  failed: ${failures}`);
        console.log(`commit latency (ms): min=${min.toFixed(1)} mean=${mean.toFixed(1)} p95=${p95.toFixed(1)} max=${max.toFixed(1)}`);
        console.log(`vs. orderer batch timeout budget: 20ms  |  vs. 100ms beacon-interval budget: ${max < 100 ? 'WITHIN' : 'EXCEEDS'}`);
    } else {
        console.log('\n=== Results: ALL CALLS FAILED ===');
    }
}

main().catch(err => {
    console.error('[LoadTest] Fatal error:', err);
    process.exit(1);
});
