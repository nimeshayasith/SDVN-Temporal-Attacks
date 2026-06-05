#!/bin/bash
# create_channel.sh — Create teta-channel and join all 5 RSU peers
#
# Called by bootstrap.sh.  Can also be run standalone after the Docker
# containers are up.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:$HOME/fabric-samples/bin"

CHANNEL="teta-channel"
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

log() { echo -e "\033[1;36m[create_channel]\033[0m $*"; }

peer_env() {
    local peer_host="${1%%:*}"
    echo "CORE_PEER_LOCALMSPID=$MSPID \
          CORE_PEER_TLS_ENABLED=true \
          CORE_PEER_TLS_ROOTCERT_FILE=$PEER_MSP_DIR/peers/$peer_host/tls/ca.crt \
          CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP \
          CORE_PEER_ADDRESS=$1"
}

# Create channel (use first peer)
log "Creating channel '$CHANNEL'"
env $(peer_env "${RSU_PEERS[0]}") \
peer channel create \
    -o "$ORDERER" \
    -c "$CHANNEL" \
    -f "$NETWORK_DIR/channel-artifacts/teta-channel.tx" \
    --tls --cafile "$ORDERER_CA" \
    --outputBlock "$NETWORK_DIR/channel-artifacts/${CHANNEL}.block" \
    2>/dev/null || log "  Channel may already exist — continuing"

# Fetch genesis block on each peer and join
for peer_hp in "${RSU_PEERS[@]}"; do
    peer_host="${peer_hp%%:*}"
    log "Joining $peer_host to $CHANNEL"

    env $(peer_env "$peer_hp") \
    peer channel fetch 0 \
        "$NETWORK_DIR/channel-artifacts/${peer_host}-${CHANNEL}.block" \
        -o "$ORDERER" -c "$CHANNEL" --tls --cafile "$ORDERER_CA"

    env $(peer_env "$peer_hp") \
    peer channel join \
        -b "$NETWORK_DIR/channel-artifacts/${peer_host}-${CHANNEL}.block" \
    || log "  $peer_host may already be in channel — continuing"

    log "  $peer_host joined"
done

# Update anchor peer
log "Updating anchor peer"
env $(peer_env "${RSU_PEERS[0]}") \
peer channel update \
    -o "$ORDERER" -c "$CHANNEL" \
    -f "$NETWORK_DIR/channel-artifacts/TetagaurdMSPanchors.tx" \
    --tls --cafile "$ORDERER_CA" 2>/dev/null || true

log "create_channel.sh complete"
