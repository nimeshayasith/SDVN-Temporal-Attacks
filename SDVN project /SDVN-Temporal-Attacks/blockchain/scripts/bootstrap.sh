#!/bin/bash
# bootstrap.sh — Full TETA-Guard Fabric network bring-up
#
# Fabric 3.1 with SmartBFT (Byzantine Fault Tolerant) ordering (§7).
# 4 orderer nodes: 3f+1 = 4 for f=1 Byzantine fault tolerance.
#
# Runs on Linux/macOS/WSL.  Requires:
#   - Docker + docker-compose
#   - Hyperledger Fabric 3.1 binaries (cryptogen, configtxgen, peer, osnadmin) in PATH
#     Download: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 3.1.0
#
# What this script does:
#   1. Generate MSP crypto material for 4 orderers + 5 RSU peers (cryptogen)
#   2. Generate channel genesis block (configtxgen, Fabric 3.x — no system channel)
#   3. Start Docker containers (4 SmartBFT orderers + 5 RSU peers)
#   4. Join orderers via osnadmin; join RSU peers via peer channel join
#   5. Package, install, approve and commit the TemporalEchoMitigator chaincode
#   6. Enrol admin identity into the Node.js wallet

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"
CLIENT_DIR="$SCRIPT_DIR/../client"
CHAINCODE_DIR="$SCRIPT_DIR/../chaincode/temporalecho"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:/home/sdvn_echo_topology/Group_33/teta-guard/fabric-samples/bin"

CHANNEL="teta-channel"
CHAINCODE="temporalecho"
CC_VERSION="1.0"
CC_SEQUENCE=1
# Point all peer-side chaincode invoke commands at orderer1 (SmartBFT leader candidate).
# Any of the 4 orderers work; orderer1:7050 is the primary client-facing port.
ORDERER="orderer1.tetaguard.net:7050"
ORDERER_CA="$NETWORK_DIR/crypto-config/ordererOrganizations/orderer.tetaguard.net/orderers/orderer1.tetaguard.net/tls/ca.crt"
PEER_MSP_DIR="$NETWORK_DIR/crypto-config/peerOrganizations/tetaguard.net"
ADMIN_MSP="$PEER_MSP_DIR/users/Admin@tetaguard.net/msp"
MSPID="TetaGuardMSP"

RSU_PEERS=(
    "peer0.rsu1.tetaguard.net:7051"
    "peer0.rsu2.tetaguard.net:7052"
    "peer0.rsu3.tetaguard.net:7053"
    "peer0.rsu4.tetaguard.net:7055"
    "peer0.rsu5.tetaguard.net:7056"
)

# ─── Scenario-derived peer counts (Issue #9) ─────────────────────────────────
# The 5 RSU / 3 OBU peers above are the FIXED deployment pool: their Docker
# containers (docker-compose-teta.yaml) and MSP crypto material (crypto-config)
# are pre-provisioned and cannot be changed here. What CAN be scenario-derived
# is how many of that fixed pool actually get registered — a scenario with
# fewer RSUs than the pool size should not register peers with no corresponding
# NS-3 simulation entity (report: RSU/OBU counts are configurable scenario
# parameters). Falls back to registering the full pool if the scenario config
# is missing, so existing behaviour is preserved when routing.cc hasn't run yet
# or predates this fix.
SCENARIO_CONFIG="$SCRIPT_DIR/../../scenario_config.json"
N_RSUS_SCENARIO="${#RSU_PEERS[@]}"
# OBU registration is a MODE switch, not a per-vehicle headcount: the report
# and this script's own Step 5c-2 comment treat "OBU peers active" as
# synonymous with "N_RSUs=0" (Tier 2 / no-RSU deployment), not a formula
# mapping vehicle count to OBU peer count. Registering a partial OBU_PEERS
# subset derived from N_Vehicles would invent a mapping the report never
# specifies, so this stays a boolean derived from N_RSUS_SCENARIO below,
# not a scenario-derived headcount like N_RSUS_SCENARIO is.
if [ -f "$SCENARIO_CONFIG" ]; then
    parsed_rsus="$(grep -o '"n_rsus"[[:space:]]*:[[:space:]]*[0-9]*' "$SCENARIO_CONFIG" | grep -o '[0-9]*$' || true)"
    if [ -n "$parsed_rsus" ]; then
        N_RSUS_SCENARIO="$parsed_rsus"
        log "  scenario_config.json found — scenario reports N_RSUs=$N_RSUS_SCENARIO"
    else
        log "  WARNING: scenario_config.json present but n_rsus unparsable — registering full RSU pool"
    fi
else
    log "  WARNING: scenario_config.json not found at $SCENARIO_CONFIG — registering full RSU pool (run routing.cc first for scenario-derived registration)"
fi
# Clamp to pool capacity — never try to register more peers than exist.
if [ "$N_RSUS_SCENARIO" -gt "${#RSU_PEERS[@]}" ]; then
    log "  WARNING: scenario N_RSUs=$N_RSUS_SCENARIO exceeds provisioned pool (${#RSU_PEERS[@]}) — clamping to pool size"
    N_RSUS_SCENARIO="${#RSU_PEERS[@]}"
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

log() { echo -e "\n\033[1;32m[bootstrap]\033[0m $*"; }
err() { echo -e "\n\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

peer_cmd() {
    local host_port="$1"; shift
    local host="${host_port%%:*}"
    local port="${host_port##*:}"
    local peer_tls="$PEER_MSP_DIR/peers/$host/tls/ca.crt"
    CORE_PEER_LOCALMSPID="$MSPID" \
    CORE_PEER_TLS_ENABLED=true \
    CORE_PEER_TLS_ROOTCERT_FILE="$peer_tls" \
    CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP" \
    CORE_PEER_ADDRESS="$host_port" \
    peer "$@"
}

# ─── Step 1: Crypto material ─────────────────────────────────────────────────

log "Step 1/6 — Generating MSP crypto material"
cd "$NETWORK_DIR"
if [ -d crypto-config ]; then
    log "  crypto-config already exists — skipping cryptogen"
else
    cryptogen generate --config=./crypto-config.yaml --output=./crypto-config \
        || err "cryptogen failed — is fabric bin in PATH?"
    log "  crypto-config generated"
fi

# ─── Step 2: Genesis block and channel tx ────────────────────────────────────

log "Step 2/6 — Generating channel genesis block (Fabric 3.x — no system channel)"
mkdir -p "$NETWORK_DIR/channel-artifacts"
# Fabric 3.x + SmartBFT: generate the application channel genesis block directly.
# There is no TetaGuardGenesis / system channel in Fabric 3.x.
# Orderers join via osnadmin (see create_channel.sh); no genesis.block for orderer startup.
if [ ! -f "$NETWORK_DIR/channel-artifacts/teta-channel.block" ]; then
    configtxgen -profile TetaChannel -channelID "$CHANNEL" \
        -outputBlock "$NETWORK_DIR/channel-artifacts/teta-channel.block" \
        || err "configtxgen channel block failed"
fi
log "  channel genesis block ready: channel-artifacts/teta-channel.block"

# ─── Step 3: Start Docker containers ─────────────────────────────────────────

log "Step 3/6 — Starting Fabric 3.1 Docker network (4 SmartBFT orderers + 5 RSU peers)"
cd "$NETWORK_DIR"
docker compose -f docker-compose-teta.yaml up -d \
    orderer1.tetaguard.net orderer2.tetaguard.net \
    orderer3.tetaguard.net orderer4.tetaguard.net \
    ca.tetaguard.net \
    peer0.rsu1.tetaguard.net peer0.rsu2.tetaguard.net peer0.rsu3.tetaguard.net \
    peer0.rsu4.tetaguard.net peer0.rsu5.tetaguard.net \
    couchdb.rsu1 couchdb.rsu2 couchdb.rsu3 couchdb.rsu4 couchdb.rsu5 \
    || err "docker compose failed"
log "  Containers started — waiting 12 s for SmartBFT orderers to initialise"
sleep 12

# ─── Step 4: Create channel and join peers ───────────────────────────────────

log "Step 4/6 — Creating channel '$CHANNEL' and joining all RSU peers"
bash "$SCRIPT_DIR/create_channel.sh"

# ─── Step 5: Deploy chaincode ────────────────────────────────────────────────

log "Step 5/6 — Deploying TemporalEchoMitigator chaincode"
bash "$SCRIPT_DIR/deploy_chaincode.sh"

# ─── Step 5b: Create initial anchor checkpoint ───────────────────────────────
# DISABLED: initial anchor checkpoint creation is skipped so that OBU peers
# enter bootstrap mode (no checkpoint → auto-eligible after dwell-time passes).
# If CreateAnchorCheckpoint is re-enabled, a CouchDB index on block_height must
# exist in every peer's state database before OBUs can call SyncFromAnchorCheckpoint.
# The index is created by deploy_chaincode.sh when chaincode is upgraded to v2.0+.
log "Step 5b — Skipping initial anchor checkpoint (bootstrap mode for OBU promotion demo)"

# ─── Step 5c: Register RSU peers in the Fabric trust ledger ─────────────────
# B-1 FIX: RegisterRSUPeer must be called for every peer so their trust score
# is set to 1.0 (Tier 1).  Without this, GetTrustScore returns 0.1 (TrustInitTier2)
# and all beacon evidence submissions are rejected in production.
log "Step 5c — Registering RSU peers (trust = 1.0), scenario N_RSUs=$N_RSUS_SCENARIO of pool size ${#RSU_PEERS[@]}"
for ((rsu_idx=0; rsu_idx<N_RSUS_SCENARIO; rsu_idx++)); do
    peer_hp="${RSU_PEERS[$rsu_idx]}"
    peer_host="${peer_hp%%:*}"
    peer_cmd "$FIRST_PEER" chaincode invoke \
        -o "$ORDERER" \
        --ordererTLSHostnameOverride orderer1.tetaguard.net \
        --tls --cafile "$ORDERER_CA" \
        -C "$CHANNEL" -n "$CHAINCODE" \
        --peerAddresses "$FIRST_PEER" \
        --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
        -c "{\"function\":\"RegisterRSUPeer\",\"Args\":[\"${peer_host}\"]}" \
        || log "  WARNING: RegisterRSUPeer failed for ${peer_host}"
    log "  Registered RSU peer: ${peer_host}"
done
if [ "$N_RSUS_SCENARIO" -lt "${#RSU_PEERS[@]}" ]; then
    log "  Skipped ${#RSU_PEERS[@]}-minus-$N_RSUS_SCENARIO RSU peer(s) with no corresponding scenario entity"
fi

# ─── Step 5c-2: Register OBU peers (Tier 2 — used when N_RSUs=0) ────────────
# When no physical RSUs exist in the NS-3 scenario, OBU peers act as the
# blockchain endorsing peers. RegisterOBUPeer sets trust=0.10 (TrustInitTier2)
# and IsRSUPeer=false. selectPeers will include them when RSU peers are absent.
OBU_PEERS=(
    "peer0.obu1.tetaguard.net:7061"
    "peer0.obu2.tetaguard.net:7062"
    "peer0.obu3.tetaguard.net:7063"
)
if [ "$N_RSUS_SCENARIO" -eq 0 ]; then
    log "Step 5c-2 — Registering OBU peers (trust = 0.10, Tier 2) — scenario N_RSUs=0, no-RSU mode"
    for peer_hp in "${OBU_PEERS[@]}"; do
        peer_host="${peer_hp%%:*}"
        peer_cmd "$FIRST_PEER" chaincode invoke \
            -o "$ORDERER" \
            --ordererTLSHostnameOverride orderer1.tetaguard.net \
            --tls --cafile "$ORDERER_CA" \
            -C "$CHANNEL" -n "$CHAINCODE" \
            --peerAddresses "$FIRST_PEER" \
            --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
            -c "{\"function\":\"RegisterOBUPeer\",\"Args\":[\"${peer_host}\",\"4096\"]}" \
            || log "  WARNING: RegisterOBUPeer failed for ${peer_host}"
        log "  Registered OBU peer: ${peer_host} (hw=4096MB)"
    done
else
    log "Step 5c-2 — Skipping OBU peer registration — scenario N_RSUs=$N_RSUS_SCENARIO (RSU-present mode, OBUs not needed as endorsing peers)"
fi

# ─── Step 5d: Register SDN controller(s) in the Fabric consortium ───────────
# B-1 FIX: RegisterController must be called so loadControllerRegistry returns
# a populated list.  Without this, CheckControllerTrustAndReassign can never
# find a backup controller (allCtrls is empty) and CTRL_ORIGIN reassignment
# is always a no-op even when τCj drops below τCmin.
log "Step 5d — Registering SDN controller(s)"
peer_cmd "$FIRST_PEER" chaincode invoke \
    -o "$ORDERER" \
    --ordererTLSHostnameOverride orderer1.tetaguard.net \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CHAINCODE" \
    --peerAddresses "$FIRST_PEER" \
    --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
    -c '{"function":"RegisterController","Args":["sdn-controller","zone-1"]}' \
    || log "  WARNING: RegisterController failed for sdn-controller"
log "  Registered SDN controller: sdn-controller (zone-1)"

# Register backup controller so reassignment has a valid target
peer_cmd "$FIRST_PEER" chaincode invoke \
    -o "$ORDERER" \
    --ordererTLSHostnameOverride orderer1.tetaguard.net \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CHAINCODE" \
    --peerAddresses "$FIRST_PEER" \
    --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
    -c '{"function":"RegisterController","Args":["sdn-controller-backup","zone-1"]}' \
    || log "  WARNING: RegisterController failed for sdn-controller-backup"
log "  Registered SDN controller backup: sdn-controller-backup (zone-1)"

# ─── Step 5e: Register Dilithium2 public keys for all RSU peers (MF-04) ────
# MF-04 FIX: Without RegisterPeerKey, getPeerPubKey() returns nil and
# verifyDilithium2Sig() rejects ALL beacon evidence in -tags liboqs (production)
# mode. Every RSU needs its Dilithium2 public key stored under PEERKEY:<peer_id>
# before any detection events or beacon evidence can be verified.
#
# Simulation mode (TETA_SIMULATION_MODE=1): keys can be placeholder hex strings.
# Production mode (-tags liboqs): replace <HEX_PUBKEY_...> with real ML-DSA-44
# public key hex strings (2528 bytes = 5056 hex chars) generated by:
#   python3 -c "import oqs,binascii; s=oqs.Signature('Dilithium2'); pk=s.generate_keypair(); print(binascii.hexlify(pk).decode())"
log "Step 5e — Registering Dilithium2 public keys for RSU peers"

# Simulation-mode placeholder keys (32 bytes each = 64 hex chars).
# Replace with real 2528-byte ML-DSA-44 keys in production.
declare -A RSU_PUBKEYS=(
    ["peer0.rsu1.tetaguard.net"]="5349474b45593a706565723072737531000000000000000000000000000000"
    ["peer0.rsu2.tetaguard.net"]="5349474b45593a706565723072737532000000000000000000000000000000"
    ["peer0.rsu3.tetaguard.net"]="5349474b45593a706565723072737533000000000000000000000000000000"
    ["peer0.rsu4.tetaguard.net"]="5349474b45593a706565723072737534000000000000000000000000000000"
    ["peer0.rsu5.tetaguard.net"]="5349474b45593a706565723072737535000000000000000000000000000000"
)

for ((rsu_idx=0; rsu_idx<N_RSUS_SCENARIO; rsu_idx++)); do
    peer_hp="${RSU_PEERS[$rsu_idx]}"
    peer_host="${peer_hp%%:*}"
    pubkey_hex="${RSU_PUBKEYS[$peer_host]:-}"
    if [ -z "$pubkey_hex" ]; then
        log "  WARNING: No pubkey configured for ${peer_host} — skipping RegisterPeerKey"
        continue
    fi
    peer_cmd "$FIRST_PEER" chaincode invoke \
        -o "$ORDERER" \
        --ordererTLSHostnameOverride orderer1.tetaguard.net \
        --tls --cafile "$ORDERER_CA" \
        -C "$CHANNEL" -n "$CHAINCODE" \
        --peerAddresses "$FIRST_PEER" \
        --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
        -c "{\"function\":\"RegisterPeerKey\",\"Args\":[\"${peer_host}\",\"${pubkey_hex}\"]}" \
        || log "  WARNING: RegisterPeerKey failed for ${peer_host}"
    log "  Registered Dilithium2 public key for: ${peer_host}"
done

# ─── Step 6: Enrol admin wallet identity for Node.js SDK ────────────────────

log "Step 6/6 — Enrolling admin identity into Node.js wallet"
mkdir -p "$CLIENT_DIR/wallet"
# Write a local filesystem wallet identity from the Admin@tetaguard.net MSP
node - <<'EOF'
const { Wallets } = require('fabric-network');
const fs   = require('fs');
const path = require('path');

const walletPath = path.join(__dirname, '..', 'client', 'wallet');
const mspDir     = process.env.ADMIN_MSP;

async function enroll() {
    const wallet   = await Wallets.newFileSystemWallet(walletPath);
    const certPath = path.join(mspDir, 'signcerts', 'cert.pem');
    const keyDir   = path.join(mspDir, 'keystore');
    const keyFile  = fs.readdirSync(keyDir)[0];

    const identity = {
        credentials: {
            certificate: fs.readFileSync(certPath).toString(),
            privateKey:  fs.readFileSync(path.join(keyDir, keyFile)).toString(),
        },
        mspId:   'TetaGuardMSP',
        type:    'X.509',
    };
    for (const peer of ['peer0.rsu1.tetaguard.net','peer0.rsu2.tetaguard.net',
                        'peer0.rsu3.tetaguard.net','peer0.rsu4.tetaguard.net',
                        'peer0.rsu5.tetaguard.net']) {
        await wallet.put(peer, identity);
    }
    console.log('Wallet identities enrolled for all 5 RSU peers');
}
enroll().catch(console.error);
EOF

log "Bootstrap complete."
log ""
log "Next steps:"
log "  ① Start event listener : node blockchain/client/eventListener.js"
log "  ② Run TGN simulation   : ./waf --run 'scratch/tgn_detector ...'"
log "  ③ Submit alerts (simple): python3 submit_alerts.py"
log "  ④ Submit alerts (SDK)  : node blockchain/client/submitToFabric.js"
