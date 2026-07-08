#!/bin/bash
# create_channel_norsu.sh — Create teta-channel-norsu and join all 8 peers
# (rsu1-5 + obu1-3). See blockchain/NORSU_CHANNEL_PLAN.md.
#
# Mirrors create_channel.sh exactly, except:
#   - channel = teta-channel-norsu (independent ledger from teta-channel)
#   - ALL 8 peers join (not just the 5 RSU peers) — this channel's whole
#     purpose is giving every peer, including the rsu-labeled ones, a clean
#     Tier-2 identity here (see bootstrap_norsu.sh for the RegisterOBUPeer
#     calls that make that real).
#
# The genesis block for this channel must already exist — generated with a
# SmartBFT-capable configtxgen (v3.1.0, built from source; see
# NORSU_CHANNEL_PLAN.md for why the stock fabric-samples configtxgen can't
# do this). This script only needs the (older, but wire-protocol-compatible)
# peer/osnadmin CLI binaries already in fabric-samples/bin.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:/home/sdvn_echo_topology/Group_33/teta-guard/fabric-samples/bin"

CHANNEL="teta-channel-norsu"
CHANNEL_BLOCK="$NETWORK_DIR/channel-artifacts/${CHANNEL}.block"
PEER_MSP_DIR="$NETWORK_DIR/crypto-config/peerOrganizations/tetaguard.net"
ORDERER_MSP_DIR="$NETWORK_DIR/crypto-config/ordererOrganizations/orderer.tetaguard.net"
ADMIN_MSP="$PEER_MSP_DIR/users/Admin@tetaguard.net/msp"
ORDERER_ADMIN_TLS_CA="$ORDERER_MSP_DIR/tlsca/tlsca.orderer.tetaguard.net-cert.pem"
ORDERER_ADMIN_CLIENT_CERT="$ORDERER_MSP_DIR/users/Admin@orderer.tetaguard.net/tls/client.crt"
ORDERER_ADMIN_CLIENT_KEY="$ORDERER_MSP_DIR/users/Admin@orderer.tetaguard.net/tls/client.key"
MSPID="TetaGuardMSP"

ORDERERS=(
    "orderer1.tetaguard.net:7050:9443"
    "orderer2.tetaguard.net:7150:9543"
    "orderer3.tetaguard.net:7250:9643"
    "orderer4.tetaguard.net:7350:9743"
)

# ALL 8 peers — the entire point of this channel.
ALL_PEERS=(
    "peer0.rsu1.tetaguard.net:7051"
    "peer0.rsu2.tetaguard.net:7052"
    "peer0.rsu3.tetaguard.net:7053"
    "peer0.rsu4.tetaguard.net:7055"
    "peer0.rsu5.tetaguard.net:7056"
    "peer0.obu1.tetaguard.net:7061"
    "peer0.obu2.tetaguard.net:7062"
    "peer0.obu3.tetaguard.net:7063"
)

log() { echo -e "\033[1;35m[create_channel_norsu]\033[0m $*"; }

set_peer_env() {
    local peer_host="${1%%:*}"
    export CORE_PEER_LOCALMSPID="$MSPID"
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_TLS_ROOTCERT_FILE="$PEER_MSP_DIR/peers/$peer_host/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP"
    export CORE_PEER_ADDRESS="$1"
}

log "Step 1: Checking channel genesis block exists"
if [ ! -f "$CHANNEL_BLOCK" ]; then
    echo "[ERROR] $CHANNEL_BLOCK not found. Generate it first with the" \
         "SmartBFT-capable configtxgen (see NORSU_CHANNEL_PLAN.md step 1)."
    exit 1
fi
log "  Found: $CHANNEL_BLOCK"

log "Step 2: Joining SmartBFT orderers to channel '$CHANNEL' via osnadmin"
for orderer_entry in "${ORDERERS[@]}"; do
    orderer_host="${orderer_entry%%:*}"
    orderer_rest="${orderer_entry#*:}"
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

log "  Waiting 8s for SmartBFT quorum to elect a leader..."
sleep 8

FIRST_ORDERER_HOST="orderer1.tetaguard.net"
FIRST_ORDERER_PORT="7050"
ORDERER_TLS_CA="$ORDERER_MSP_DIR/orderers/orderer1.tetaguard.net/tls/ca.crt"

log "Step 3: Joining ALL 8 peers to channel '$CHANNEL'"
for peer_hp in "${ALL_PEERS[@]}"; do
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

log "create_channel_norsu.sh complete"
log "  SmartBFT orderer cluster:  4 nodes (f=1 BFT fault tolerance)"
log "  Peers joined:              ${#ALL_PEERS[@]} (all 8 — rsu1-5 + obu1-3)"
