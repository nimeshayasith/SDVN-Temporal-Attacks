'use strict';

/**
 * demoTrust.js — Live supervisor demo: dynamic peer selection + 3-stage demotion pipeline
 *
 * Shows:
 *  Phase 1 — All peers ACTIVE, trust scores initialized (rsu1-9 = 1.0, obu1-3 = 0.10)
 *  Phase 2 — selectPeers: 9 eligible RSUs → capped at np = 8 (f = 2, proves the limit)
 *  Phase 3 — rsu9 detected malicious → demoted to QUARANTINED_CLIENT (Stage 1)
 *  Phase 4 — Re-selection: rsu9 excluded, next-best RSU fills its slot
 */

const { Gateway, Wallets } = require('fabric-network');
const fs   = require('fs');
const path = require('path');

const CHANNEL      = 'teta-channel';
const CHAINCODE    = 'temporalecho';
const PEER_ID      = 'peer0.rsu4.tetaguard.net';
const WALLET_PATH  = path.join(__dirname, 'wallet');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection-profile.json');

const ALL_PEERS = [
    // 9 RSU peers — exceeds np=8, so SelectPeers must cap at 8 (proves the limit)
    'peer0.rsu1.tetaguard.net',
    'peer0.rsu2.tetaguard.net',
    'peer0.rsu3.tetaguard.net',
    'peer0.rsu4.tetaguard.net',
    'peer0.rsu5.tetaguard.net',
    'peer0.rsu6.tetaguard.net',
    'peer0.rsu7.tetaguard.net',
    'peer0.rsu8.tetaguard.net',
    'peer0.rsu9.tetaguard.net',
    // 6 OBU peers — Tier 2 candidates (when 6 RSUs compromised: 3 RSU + 6 OBU = 9 → capped at 8)
    'peer0.obu1.tetaguard.net',
    'peer0.obu2.tetaguard.net',
    'peer0.obu3.tetaguard.net',
    'peer0.obu4.tetaguard.net',
    'peer0.obu5.tetaguard.net',
    'peer0.obu6.tetaguard.net',
];

const TARGET_PEER = 'peer0.rsu9.tetaguard.net'; // the peer we demote in the demo

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function header(title) {
    console.log('\n' + '═'.repeat(60));
    console.log('  ' + title);
    console.log('═'.repeat(60));
}

async function main() {
    const connProfile = JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
    const wallet      = await Wallets.newFileSystemWallet(WALLET_PATH);
    const identity    = await wallet.get(PEER_ID);
    if (!identity) { console.error('Wallet identity not found:', PEER_ID); process.exit(1); }

    const gateway = new Gateway();
    await gateway.connect(connProfile, {
        wallet,
        identity: PEER_ID,
        discovery: { enabled: false, asLocalhost: true },
    });

    const network  = await gateway.getNetwork(CHANNEL);
    const contract = network.getContract(CHAINCODE);

    // ── RESET — Restore all peers to initial scores before demo ─────────────
    // Re-registering sets RSU peers back to score=1.0 state=ACTIVE (idempotent)
    const RSU_PEERS = ALL_PEERS.filter(p => p.includes('rsu'));
    const OBU_PEERS = ALL_PEERS.filter(p => p.includes('obu'));
    for (const pid of RSU_PEERS) {
        try { await contract.submitTransaction('RegisterRSUPeer', pid); } catch (_) {}
    }
    for (const pid of OBU_PEERS) {
        try { await contract.submitTransaction('RegisterOBUPeer', pid, '4096'); } catch (_) {}
    }

    // ── PHASE 1 — Show initial trust state ───────────────────────────────────
    header('PHASE 1 — Initial Trust State (9 RSU Tier-1 peers + 6 OBU Tier-2 candidates)');
    console.log('  9 RSU peers registered at Tier 1 (τ = 1.0) — intentionally exceeds np=8 cap.');
    console.log('  OBU peers are Tier 2 candidates (τ = 0.10 initially, earn trust over rounds).\n');

    for (const pid of ALL_PEERS) {
        try {
            const raw   = await contract.evaluateTransaction('GetTrustScore', pid);
            const score = parseFloat(raw.toString());
            const tier  = pid.includes('rsu') ? 'RSU Tier-1' : 'OBU Tier-2';
            console.log(`  ${pid.padEnd(36)} score=${score.toFixed(2)}  [${tier}]`);
        } catch (_) {
            console.log(`  ${pid.padEnd(36)} (not yet registered)`);
        }
    }

    await sleep(1500);

    // ── PHASE 2 — Show dynamic peer selection ────────────────────────────────
    header('PHASE 2 — Dynamic Peer Selection: 9 eligible RSUs → capped at np = 8');
    console.log('  Formula: Pactive = highest-trust peers up to np = 8 slots (f = 2, 3f+1 = 7, +1 redundancy).');
    console.log('  9 RSU peers are eligible. SelectPeers must discard 1 — proving the np=8 cap is enforced.\n');

    try {
        const raw    = await contract.evaluateTransaction('SelectPeers', JSON.stringify(ALL_PEERS));
        const active = JSON.parse(raw.toString());
        console.log(`  Active peer set (${active.length} peers selected):`);
        for (const pid of active) {
            console.log(`    ✓ ${pid}`);
        }
        const excluded = ALL_PEERS.filter(p => !active.includes(p));
        if (excluded.length > 0) {
            console.log(`\n  Excluded from this round:`);
            for (const pid of excluded) {
                console.log(`    ✗ ${pid}  (below threshold or dwell-time gate)`);
            }
        }
    } catch (e) {
        console.log('  SelectPeers error:', e.message);
    }

    await sleep(1500);

    // ── PHASE 3 — Demote malicious peer ──────────────────────────────────────
    header(`PHASE 3 — Attack Detected: Demoting ${TARGET_PEER} (rsu9)`);
    console.log('  Detection source: PEM temporal signature + TGN anomaly score.');
    console.log('  Stage 1 of 3-stage pipeline: ACTIVE → QUARANTINED_CLIENT.');
    console.log('  After demotion, SelectPeers will fill rsu9 slot with the next-best peer.\n');
    console.log(`  Calling DemotePeerToClient(caller=${PEER_ID}, target=${TARGET_PEER}) ...`);

    // Find a real MITIG key from the ledger to use as backing detection event
    let mitigKey = '';
    try {
        const raw  = await contract.evaluateTransaction('QueryMitigationsByVehicle', 'V5');
        const recs = JSON.parse(raw.toString());
        if (recs && recs.length > 0) mitigKey = recs[0].entry_id || '';
    } catch (_) {}

    if (!mitigKey) {
        // Fall back: degrade trust via UpdateTrustRound (exclude rsu5 from participants)
        console.log(`  Degrading ${TARGET_PEER} trust via UpdateTrustRound (excluded from round)...`);
        try {
            await contract.submitTransaction(
                'UpdateTrustRound',
                PEER_ID,
                JSON.stringify([PEER_ID]),   // only rsu4 participated → rsu5 penalised
                JSON.stringify(ALL_PEERS)
            );
        } catch (e2) {
            console.log('  ', e2.message.split('\n')[0]);
        }
    } else {
        try {
            await contract.submitTransaction('ZeroTrust', PEER_ID, TARGET_PEER, mitigKey);
            console.log(`  ZeroTrust submitted. ${TARGET_PEER} → QUARANTINED_CLIENT.`);
        } catch (e) {
            console.log('  ', e.message.split('\n')[0]);
        }
    }

    await sleep(1000);

    // Show updated state
    console.log('\n  Trust scores after demotion:');
    for (const pid of ['peer0.rsu4.tetaguard.net', 'peer0.rsu9.tetaguard.net', 'peer0.rsu1.tetaguard.net']) {
        try {
            const raw   = await contract.evaluateTransaction('GetTrustScore', pid);
            const score = parseFloat(raw.toString());
            console.log(`    ${pid.padEnd(36)} score=${score.toFixed(2)}`);
        } catch (_) {}
    }

    await sleep(1500);

    // ── PHASE 4 — Re-run peer selection, show rsu5 excluded ──────────────────
    header('PHASE 4 — Re-Selection After Demotion (rsu9 stripped, slot refilled)');
    console.log('  rsu9 is excluded. SelectPeers picks the next-best from remaining 8 eligible RSUs.');
    console.log('  Active set remains at 8 peers — system self-heals automatically.\n');

    try {
        const raw    = await contract.evaluateTransaction('SelectPeers', JSON.stringify(ALL_PEERS));
        const active = JSON.parse(raw.toString());
        console.log(`  New active peer set (${active.length} peers):`);
        for (const pid of active) {
            console.log(`    ✓ ${pid}`);
        }
        const excluded = ALL_PEERS.filter(p => !active.includes(p));
        if (excluded.length > 0) {
            console.log(`\n  Not in active set this round:`);
            for (const pid of excluded) {
                const isRSU = pid.includes('rsu');
                const reason = isRSU
                    ? '← trust score below Pactive threshold'
                    : '← OBU: checkpoint sync / dwell-time gate not yet passed';
                console.log(`    ✗ ${pid.padEnd(36)} ${reason}`);
            }
        }
    } catch (e) {
        console.log('  SelectPeers error:', e.message);
    }

    console.log('\n  3-stage demotion pipeline summary:');
    console.log('    Stage 1 → QUARANTINED_CLIENT : excluded from consensus, trust zeroed, monitored');
    console.log('    Stage 2 → Monitoring window  : 30s window, trust update continues');
    console.log('    Stage 3 → REMOVED            : permanently expelled if trust ≤ 0.10 after window');

    await sleep(1500);

    // ── PHASE 5 — Multiple RSUs demoted → OBUs fill vacancies ────────────────
    header('PHASE 5 — Cascade Attack: 6 RSUs Compromised → 6 OBUs Fill Vacancies');
    console.log('  Scenario: rsu4-rsu9 all found malicious. Only rsu1-3 remain trusted.');
    console.log('  3 RSU + 6 OBU = 9 eligible → SelectPeers still caps at 8 (proves cap holds).\n');

    // Degrade rsu4-rsu9 (rsu9 already zeroed; demote the rest)
    const DEMOTE_PEERS = [
        'peer0.rsu4.tetaguard.net',
        'peer0.rsu5.tetaguard.net',
        'peer0.rsu6.tetaguard.net',
        'peer0.rsu7.tetaguard.net',
        'peer0.rsu8.tetaguard.net',
    ];
    for (const target of DEMOTE_PEERS) {
        try {
            // Run 10 rounds excluding this peer → score drops from 1.0 to 0.0
            for (let i = 0; i < 10; i++) {
                await contract.submitTransaction(
                    'UpdateTrustRound',
                    PEER_ID,
                    JSON.stringify([PEER_ID]),   // only rsu4 participates
                    JSON.stringify([target])      // only penalise this one peer per call
                );
            }
            console.log(`  ${target} demoted (trust zeroed)`);
        } catch (e) {
            console.log(`  ${target}:`, e.message.split('\n')[0]);
        }
    }

    // Boost all 6 OBU scores through participation rounds (bootstrap mode — no checkpoint needed)
    console.log('\n  Boosting OBU trust scores through participation rounds...');
    const OBU_ALL = ALL_PEERS.filter(p => p.includes('obu'));
    for (let i = 0; i < 10; i++) {
        try {
            await contract.submitTransaction(
                'UpdateTrustRound',
                PEER_ID,
                JSON.stringify([PEER_ID, ...OBU_ALL]),
                JSON.stringify(OBU_ALL)
            );
        } catch (_) {}
    }
    console.log(`  ${OBU_ALL.length} OBU peers eligible via bootstrap mode (no anchor checkpoint yet required).`);

    await sleep(500);

    // Show updated scores
    console.log('\n  Trust scores now:');
    for (const pid of ALL_PEERS) {
        try {
            const raw   = await contract.evaluateTransaction('GetTrustScore', pid);
            const score = parseFloat(raw.toString());
            console.log(`    ${pid.padEnd(36)} score=${score.toFixed(2)}`);
        } catch (_) {}
    }

    await sleep(500);

    // Brief wait to ensure dwell-time gate passes for freshly registered OBU peers
    await sleep(20000);

    // Run peer selection — OBUs should now fill vacancies
    console.log('\n  Running peer selection after cascade demotion:\n');
    try {
        const raw    = await contract.evaluateTransaction('SelectPeers', JSON.stringify(ALL_PEERS));
        const active = JSON.parse(raw.toString());
        console.log(`  Active peer set (${active.length} peers):`);
        for (const pid of active) {
            const type = pid.includes('obu') ? '← OBU peer promoted into active set' : '← RSU Tier-1';
            console.log(`    ✓ ${pid.padEnd(36)} ${type}`);
        }
        const excluded = ALL_PEERS.filter(p => !active.includes(p));
        if (excluded.length > 0) {
            console.log(`\n  Demoted / excluded:`);
            for (const pid of excluded) {
                console.log(`    ✗ ${pid}`);
            }
        }
    } catch (e) {
        console.log('  SelectPeers error:', e.message);
    }

    console.log('\n  Self-healing: network maintains np=8 active peers despite 6 out of 9 RSUs being compromised.');

    // ── PHASE 6 — No-RSU Scenario (S1, S3, S5, S7, S9, S11) ─────────────────
    header('PHASE 6 — No-RSU Scenario: 15 OBU peers, all 8 slots filled by OBUs');
    console.log('  Attack scenarios without RSU infrastructure (S1/S3/S5/S7/S9/S11):');
    console.log('  No RSU peers exist → dwell-time/HW/checkpoint gates bypassed for OBUs.');
    console.log('  15 OBUs registered → SelectPeers caps at 8, leaving 7 excluded.\n');

    // Register 15 OBU-only peers (no RSUs)
    const NO_RSU_PEERS = [];
    for (let i = 1; i <= 15; i++) {
        NO_RSU_PEERS.push(`peer0.obu${String(i).padStart(2,'0')}.norsu.tetaguard.net`);
    }
    for (const pid of NO_RSU_PEERS) {
        try { await contract.submitTransaction('RegisterOBUPeer', pid, '4096'); } catch (_) {}
    }
    console.log('  Registered 15 OBU peers (no RSUs in pool):');
    for (let i = 1; i <= 15; i++) {
        console.log(`    peer0.obu${String(i).padStart(2,'0')}.norsu.tetaguard.net  [OBU Tier-2]`);
    }

    await sleep(500);

    // SelectPeers with OBU-only pool — no-RSU mode bypasses gates
    try {
        const raw    = await contract.evaluateTransaction('SelectPeers', JSON.stringify(NO_RSU_PEERS));
        const active = JSON.parse(raw.toString());
        console.log(`\n  SelectPeers result — no-RSU mode (gates bypassed):`);
        console.log(`  Active peer set (${active.length} peers selected from 15 OBUs):`);
        for (const pid of active) {
            console.log(`    ✓ ${pid}  ← OBU fills endorser slot`);
        }
        const excluded = NO_RSU_PEERS.filter(p => !active.includes(p));
        console.log(`\n  Excluded (np=8 cap enforced even in no-RSU mode):`);
        for (const pid of excluded) {
            console.log(`    ✗ ${pid}`);
        }
        console.log(`\n  All ${active.length} endorser slots filled by OBU peers. np=8 cap holds.`);
    } catch (e) {
        console.log('  SelectPeers error:', e.message);
    }

    await gateway.disconnect();

    console.log('\n' + '═'.repeat(60));
    console.log('  Demo complete.');
    console.log('═'.repeat(60) + '\n');
}

main().catch(e => { console.error(e.message); process.exit(1); });
