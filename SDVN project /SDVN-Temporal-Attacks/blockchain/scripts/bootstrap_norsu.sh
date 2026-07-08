#!/bin/bash
# bootstrap_norsu.sh — Register all 8 peers (rsu1-5 + obu1-3) as Tier-2 OBU
# (tau0=0.10) on teta-channel-norsu. No RegisterRSUPeer calls anywhere —
# that's the entire point (see blockchain/NORSU_CHANNEL_PLAN.md).
#
# "4096"/"8" (RAM MB / storage GB) are uniform across all 8 hosts
# intentionally: RegisterOBUPeer's hardware check is a single minimum-
# capacity floor (Cmin: >=2048MB RAM, >=8GB storage), not a per-host-type
# differentiator, and rsu1-5's real hardware only exceeds these floors.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"

export FABRIC_CFG_PATH="$NETWORK_DIR"
export PATH="$PATH:/home/sdvn_echo_topology/Group_33/teta-guard/fabric-samples/bin"

CHANNEL="teta-channel-norsu"
CHAINCODE="temporalecho"
ORDERER="orderer3.tetaguard.net:7250"
ORDERER_CA="$NETWORK_DIR/crypto-config/ordererOrganizations/orderer.tetaguard.net/orderers/orderer3.tetaguard.net/tls/ca.crt"
PEER_MSP_DIR="$NETWORK_DIR/crypto-config/peerOrganizations/tetaguard.net"
ADMIN_MSP="$PEER_MSP_DIR/users/Admin@tetaguard.net/msp"
MSPID="TetaGuardMSP"

# Endorsing/submitting peer: rsu4 confirmed synced and reachable this session.
SUBMIT_PEER="peer0.rsu4.tetaguard.net:7055"

ALL_PEERS=(
    "peer0.rsu1.tetaguard.net"
    "peer0.rsu2.tetaguard.net"
    "peer0.rsu3.tetaguard.net"
    "peer0.rsu4.tetaguard.net"
    "peer0.rsu5.tetaguard.net"
    "peer0.obu1.tetaguard.net"
    "peer0.obu2.tetaguard.net"
    "peer0.obu3.tetaguard.net"
)

log() { echo -e "\033[1;32m[bootstrap_norsu]\033[0m $*"; }

set_peer_env() {
    local peer_host="${1%%:*}"
    export CORE_PEER_LOCALMSPID="$MSPID"
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_TLS_ROOTCERT_FILE="$PEER_MSP_DIR/peers/$peer_host/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP"
    export CORE_PEER_ADDRESS="$1"
}

set_peer_env "$SUBMIT_PEER"

for peer_host in "${ALL_PEERS[@]}"; do
    log "Registering $peer_host as Tier-2 OBU (tau0=0.10)"
    peer chaincode invoke \
        -o "$ORDERER" --tls --cafile "$ORDERER_CA" \
        -C "$CHANNEL" -n "$CHAINCODE" \
        --peerAddresses "$SUBMIT_PEER" \
        --tlsRootCertFiles "$PEER_MSP_DIR/peers/${SUBMIT_PEER%%:*}/tls/ca.crt" \
        -c "{\"function\":\"RegisterOBUPeer\",\"Args\":[\"${peer_host}\",\"4096\",\"8\"]}" \
        --waitForEvent --waitForEventTimeout 45s \
        2>&1 | grep -iE "result|status|error" \
        || log "  WARNING: RegisterOBUPeer may have failed for ${peer_host} — verify with GetTrustScore"
done

log "bootstrap_norsu.sh complete — 8 Tier-2 registrations submitted"
log "Verify with:"
log "  peer chaincode query -C $CHANNEL -n $CHAINCODE -c '{\"function\":\"GetTrustScore\",\"Args\":[\"peer0.rsu1.tetaguard.net\"]}'"
