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
MSPID="TetagaurdMSP"

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
        mspId:   'TetagaurdMSP',
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
