#!/bin/bash
# bootstrap.sh — Full TETA-Guard Fabric network bring-up
#
# Runs on Linux/macOS/WSL.  Requires:
#   - Docker + docker-compose
#   - Hyperledger Fabric binaries (cryptogen, configtxgen, peer) in PATH
#     Download: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 3.0.0
#
# What this script does:
#   1. Generate MSP crypto material (cryptogen)
#   2. Generate genesis block + channel tx (configtxgen)
#   3. Start Docker containers (docker-compose)
#   4. Create teta-channel and join all 5 RSU peers
#   5. Package, install, approve and commit the TemporalEchoMitigator chaincode
#   6. Enrol admin identity into the Node.js wallet

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"
CLIENT_DIR="$SCRIPT_DIR/../client"
CHAINCODE_DIR="$SCRIPT_DIR/../chaincode/temporalecho"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:$HOME/fabric-samples/bin"  # update if installed elsewhere

CHANNEL="teta-channel"
CHAINCODE="temporalecho"
CC_VERSION="1.0"
CC_SEQUENCE=1
ORDERER="orderer.tetaguard.net:7050"
ORDERER_CA="$NETWORK_DIR/crypto-config/ordererOrganizations/orderer.tetaguard.net/tlsca/tlsca.tetaguard.net-cert.pem"
PEER_MSP_DIR="$NETWORK_DIR/crypto-config/peerOrganizations/tetaguard.net"
ADMIN_MSP="$PEER_MSP_DIR/users/Admin@tetaguard.net/msp"
MSPID="TetaGuardMSP"

RSU_PEERS=(
    "peer0.rsu1.tetaguard.net:7051"
    "peer0.rsu2.tetaguard.net:7052"
    "peer0.rsu3.tetaguard.net:7053"
    "peer0.rsu4.tetaguard.net:7054"
    "peer0.rsu5.tetaguard.net:7055"
)

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

log "Step 2/6 — Generating genesis block and channel tx"
mkdir -p "$NETWORK_DIR/channel-artifacts"
if [ ! -f "$NETWORK_DIR/channel-artifacts/genesis.block" ]; then
    configtxgen -profile TetaGuardGenesis -channelID system-channel \
        -outputBlock "$NETWORK_DIR/channel-artifacts/genesis.block" \
        || err "configtxgen genesis failed"
fi
if [ ! -f "$NETWORK_DIR/channel-artifacts/teta-channel.tx" ]; then
    configtxgen -profile TetaChannel -channelID "$CHANNEL" \
        -outputCreateChannelTx "$NETWORK_DIR/channel-artifacts/teta-channel.tx" \
        || err "configtxgen channel tx failed"
fi
log "  channel artifacts ready"

# ─── Step 3: Start Docker containers ─────────────────────────────────────────

log "Step 3/6 — Starting Fabric Docker network"
cd "$NETWORK_DIR"
docker-compose -f docker-compose-teta.yaml up -d \
    || err "docker-compose failed"
log "  Containers started — waiting 10 s for peers to initialise"
sleep 10

# ─── Step 4: Create channel and join peers ───────────────────────────────────

log "Step 4/6 — Creating channel '$CHANNEL' and joining all RSU peers"
bash "$SCRIPT_DIR/create_channel.sh"

# ─── Step 5: Deploy chaincode ────────────────────────────────────────────────

log "Step 5/6 — Deploying TemporalEchoMitigator chaincode"
bash "$SCRIPT_DIR/deploy_chaincode.sh"

# ─── Step 5b: Create initial anchor checkpoint ───────────────────────────────
# The anchor interval ⌊Tmin/Tb⌋ must match the vehicular scenario so that
# Tier 2 OBU peers synchronise before joining consensus.
#   Urban (L_link≈43 s):  Tmin = max(600ms, 21500ms) → ⌊21500/100⌋ = 215 blocks
#   Highway (L_link≈9 s): Tmin = max(600ms, 4500ms)  → ⌊4500/100⌋  =  45 blocks
# Set ANCHOR_INTERVAL_BLOCKS=45 before running bootstrap for highway deployments.
ANCHOR_INTERVAL="${ANCHOR_INTERVAL_BLOCKS:-215}"
log "Step 5b — Creating initial anchor checkpoint (interval=${ANCHOR_INTERVAL} blocks)"

FIRST_PEER="${RSU_PEERS[0]}"
peer_cmd "$FIRST_PEER" chaincode invoke \
    -o "$ORDERER" \
    --ordererTLSHostnameOverride orderer.tetaguard.net \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CHAINCODE" \
    --peerAddresses "$FIRST_PEER" \
    --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
    -c "{\"function\":\"CreateAnchorCheckpoint\",\"Args\":[\"${FIRST_PEER%%:*}\",\"${ANCHOR_INTERVAL}\"]}" \
    || log "  WARNING: anchor checkpoint creation failed — OBU peers must sync manually"
log "  Anchor checkpoint created with interval=${ANCHOR_INTERVAL}"

# ─── Step 5c: Register RSU peers in the Fabric trust ledger ─────────────────
# B-1 FIX: RegisterRSUPeer must be called for every peer so their trust score
# is set to 1.0 (Tier 1).  Without this, GetTrustScore returns 0.1 (TrustInitTier2)
# and all beacon evidence submissions are rejected in production.
log "Step 5c — Registering RSU peers (trust = 1.0)"
for peer_hp in "${RSU_PEERS[@]}"; do
    peer_host="${peer_hp%%:*}"
    peer_cmd "$FIRST_PEER" chaincode invoke \
        -o "$ORDERER" \
        --ordererTLSHostnameOverride orderer.tetaguard.net \
        --tls --cafile "$ORDERER_CA" \
        -C "$CHANNEL" -n "$CHAINCODE" \
        --peerAddresses "$FIRST_PEER" \
        --tlsRootCertFiles "$PEER_MSP_DIR/peers/${FIRST_PEER%%:*}/tls/ca.crt" \
        -c "{\"function\":\"RegisterRSUPeer\",\"Args\":[\"${peer_host}\"]}" \
        || log "  WARNING: RegisterRSUPeer failed for ${peer_host}"
    log "  Registered RSU peer: ${peer_host}"
done

# ─── Step 5d: Register SDN controller(s) in the Fabric consortium ───────────
# B-1 FIX: RegisterController must be called so loadControllerRegistry returns
# a populated list.  Without this, CheckControllerTrustAndReassign can never
# find a backup controller (allCtrls is empty) and CTRL_ORIGIN reassignment
# is always a no-op even when τCj drops below τCmin.
log "Step 5d — Registering SDN controller(s)"
peer_cmd "$FIRST_PEER" chaincode invoke \
    -o "$ORDERER" \
    --ordererTLSHostnameOverride orderer.tetaguard.net \
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
    --ordererTLSHostnameOverride orderer.tetaguard.net \
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

for peer_hp in "${RSU_PEERS[@]}"; do
    peer_host="${peer_hp%%:*}"
    pubkey_hex="${RSU_PUBKEYS[$peer_host]:-}"
    if [ -z "$pubkey_hex" ]; then
        log "  WARNING: No pubkey configured for ${peer_host} — skipping RegisterPeerKey"
        continue
    fi
    peer_cmd "$FIRST_PEER" chaincode invoke \
        -o "$ORDERER" \
        --ordererTLSHostnameOverride orderer.tetaguard.net \
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
