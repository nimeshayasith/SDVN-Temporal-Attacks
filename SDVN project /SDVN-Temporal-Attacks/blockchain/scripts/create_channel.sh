#!/bin/bash
# create_channel.sh — Create teta-channel and join all 5 RSU peers
#
# Fabric 3.x + SmartBFT flow (replaces legacy peer channel create / system channel):
#   1. configtxgen creates the channel genesis block (application channel only)
#   2. osnadmin joins each of the 4 SmartBFT orderers to the channel
#   3. peer channel join fetches the genesis block and joins each RSU peer
#
# Called by bootstrap.sh.  Can also be run standalone after Docker containers are up.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:/home/sdvn_echo_topology/Group_33/teta-guard/fabric-samples/bin"

CHANNEL="teta-channel"
CHANNEL_BLOCK="$NETWORK_DIR/channel-artifacts/${CHANNEL}.block"
PEER_MSP_DIR="$NETWORK_DIR/crypto-config/peerOrganizations/tetaguard.net"
ORDERER_MSP_DIR="$NETWORK_DIR/crypto-config/ordererOrganizations/orderer.tetaguard.net"
ADMIN_MSP="$PEER_MSP_DIR/users/Admin@tetaguard.net/msp"
ORDERER_ADMIN_TLS_CA="$ORDERER_MSP_DIR/tlsca/tlsca.orderer.tetaguard.net-cert.pem"
ORDERER_ADMIN_CLIENT_CERT="$ORDERER_MSP_DIR/users/Admin@orderer.tetaguard.net/tls/client.crt"
ORDERER_ADMIN_CLIENT_KEY="$ORDERER_MSP_DIR/users/Admin@orderer.tetaguard.net/tls/client.key"
MSPID="TetaGuardMSP"

# 4 SmartBFT orderers: (host:port, admin_port)
ORDERERS=(
    "orderer1.tetaguard.net:7050:9443"
    "orderer2.tetaguard.net:7150:9543"
    "orderer3.tetaguard.net:7250:9643"
    "orderer4.tetaguard.net:7350:9743"
)

RSU_PEERS=(
    "peer0.rsu1.tetaguard.net:7051"
    "peer0.rsu2.tetaguard.net:7052"
    "peer0.rsu3.tetaguard.net:7053"
    "peer0.rsu4.tetaguard.net:7055"
    "peer0.rsu5.tetaguard.net:7056"
)

log() { echo -e "\033[1;36m[create_channel]\033[0m $*"; }

set_peer_env() {
    local peer_host="${1%%:*}"
    export CORE_PEER_LOCALMSPID="$MSPID"
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_TLS_ROOTCERT_FILE="$PEER_MSP_DIR/peers/$peer_host/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP"
    export CORE_PEER_ADDRESS="$1"
}

# ── Step 1: Generate channel genesis block (Fabric 3.x — application channel only) ──
log "Step 1: Generating channel genesis block"
mkdir -p "$NETWORK_DIR/channel-artifacts"

if [ ! -f "$CHANNEL_BLOCK" ]; then
    configtxgen -profile TetaChannel -channelID "$CHANNEL" \
        -outputBlock "$CHANNEL_BLOCK" \
        || { echo "[ERROR] configtxgen failed"; exit 1; }
    log "  Genesis block created: $CHANNEL_BLOCK"
else
    log "  Genesis block already exists — skipping configtxgen"
fi

# ── Step 2: Join all 4 SmartBFT orderers to the channel via osnadmin ─────────
# osnadmin uses the orderer admin TLS API (port 94xx, not the ordering port 7050).
# Each orderer must join independently; SmartBFT consensus starts once a quorum (3) join.
log "Step 2: Joining SmartBFT orderers to channel '$CHANNEL' via osnadmin"
for orderer_entry in "${ORDERERS[@]}"; do
    orderer_host="${orderer_entry%%:*}"
    orderer_rest="${orderer_entry#*:}"
    orderer_port="${orderer_rest%%:*}"
    admin_port="${orderer_rest##*:}"

    log "  Joining orderer $orderer_host (admin port $admin_port)"
    osnadmin channel join \
        --channelID "$CHANNEL" \
        --config-block "$CHANNEL_BLOCK" \
        -o "${orderer_host}:${admin_port}" \
        --ca-file "$ORDERER_ADMIN_TLS_CA" \
        --client-cert "$ORDERER_ADMIN_CLIENT_CERT" \
        --client-key  "$ORDERER_ADMIN_CLIENT_KEY" \
        2>/dev/null \
        && log "    $orderer_host joined" \
        || log "    $orderer_host may already be in channel — continuing"
done

# Wait for SmartBFT quorum (3-of-4 orderers must be ready before peers can join).
log "  Waiting 8s for SmartBFT quorum to elect a leader..."
sleep 8

# ── Step 3: Join all RSU peers to the channel ─────────────────────────────────
# Fabric 3.x peer join is unchanged: fetch block from any orderer, then join.
# Point at orderer1 for block fetch (any orderer in the BFT cluster works).
FIRST_ORDERER_HOST="orderer1.tetaguard.net"
FIRST_ORDERER_PORT="7050"
ORDERER_TLS_CA="$ORDERER_MSP_DIR/orderers/orderer1.tetaguard.net/tls/ca.crt"

log "Step 3: Joining RSU peers to channel '$CHANNEL'"
for peer_hp in "${RSU_PEERS[@]}"; do
    peer_host="${peer_hp%%:*}"
    local_block="$NETWORK_DIR/channel-artifacts/${peer_host}-${CHANNEL}.block"

    log "  Fetching genesis block for $peer_host"
    set_peer_env "$peer_hp"
    peer channel fetch 0 "$local_block" \
        -o "${FIRST_ORDERER_HOST}:${FIRST_ORDERER_PORT}" \
        -c "$CHANNEL" \
        --tls --cafile "$ORDERER_TLS_CA"

    log "  Joining $peer_host"
    peer channel join -b "$local_block" \
        || log "    $peer_host may already be in channel — continuing"

    log "    $peer_host joined"
done

# ── Step 4: Update anchor peer ────────────────────────────────────────────────
log "Step 4: Updating anchor peer (peer0.rsu1)"
set_peer_env "${RSU_PEERS[0]}"

# Generate anchor peer update tx if not already present
ANCHOR_TX="$NETWORK_DIR/channel-artifacts/TetaGuardMSPanchors.tx"
if [ ! -f "$ANCHOR_TX" ]; then
    configtxgen -profile TetaChannel -channelID "$CHANNEL" \
        -outputAnchorPeersUpdate "$ANCHOR_TX" \
        -asOrg TetaGuardMSP 2>/dev/null || true
fi

if [ -f "$ANCHOR_TX" ]; then
    peer channel update \
        -o "${FIRST_ORDERER_HOST}:${FIRST_ORDERER_PORT}" \
        -c "$CHANNEL" \
        -f "$ANCHOR_TX" \
        --tls --cafile "$ORDERER_TLS_CA" \
        2>/dev/null || true
fi

log "create_channel.sh complete"
log "  SmartBFT orderer cluster:  4 nodes (f=1 BFT fault tolerance)"
log "  RSU peers joined:          ${#RSU_PEERS[@]}"
