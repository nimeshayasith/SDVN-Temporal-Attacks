#!/bin/bash
# deploy_chaincode.sh — Package, install, approve and commit TemporalEchoMitigator
#
# Implements the Fabric 2.x/3.x lifecycle:
#   1. go mod tidy  (resolve chaincode dependencies)
#   2. peer lifecycle chaincode package
#   3. peer lifecycle chaincode install        (on all 5 peers)
#   4. peer lifecycle chaincode approveformyorg (on 1 peer — same org)
#   5. peer lifecycle chaincode commit         (to teta-channel)
#
# Called by bootstrap.sh.  Run standalone to upgrade chaincode (bump CC_VERSION
# and CC_SEQUENCE).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR/../network"
CHAINCODE_DIR="$SCRIPT_DIR/../chaincode/temporalecho"

export FABRIC_CFG_PATH="$NETWORK_DIR"
# fabric-bin first: its configtxgen is Fabric 3.x (SmartBFT/ConsenterMapping-aware).
# The Group_33 fabric-samples/bin configtxgen is v2.5.0 and predates BFT support,
# so it must come after (used only for peer/osnadmin/cryptogen, not configtxgen).
export PATH="/home/sdvn_echo_topology/fabric-bin:$PATH:/home/sdvn_echo_topology/Group_33/teta-guard/fabric-samples/bin"

CHANNEL="teta-channel"
CHAINCODE="temporalecho"
# Upgrade to 2.1/3: unconditional per-caller RSU/OBU trust checks in
# ZeroTrust, DemotePeerToClient, SubmitLWDetectionResult,
# Upgrade to 2.3: AnchorIntervalBlocksUrban/Highway fixed from 215/45
# (wrong formula, matched Llink/(2*Tb) instead of floor(Tmin/Tb)) to 30/30
# (matches Table 4.9's actual formula, Tmin=3000ms/Tb=100ms). See
# TABLE_4.9_CALIBRATION_TRACKER.md sec H for the full finding.
# CC_SEQUENCE reset to 1 (2026-07-29): the channel ledger was regenerated
# from a fresh genesis block (RequestForwardTimeout/RequestComplainTimeout
# fix required new genesis), so the prior sequence=5 history no longer
# exists on this channel — Fabric requires the first commit on a new
# channel to be sequence=1 regardless of the chaincode version label.
CC_VERSION="2.3"
CC_SEQUENCE=1
CC_LABEL="${CHAINCODE}_${CC_VERSION}"
# orderer1.tetaguard.net (not the old singular "orderer.tetaguard.net" — leftover
# from the pre-migration single-orderer topology; its cert CN doesn't match any of
# the 4 SmartBFT orderer containers, so TLS hostname verification would fail).
# Matches create_channel.sh's convention: target address = orderer's own hostname,
# so no --ordererTLSHostnameOverride is needed.
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

log() { echo -e "\033[1;33m[deploy_chaincode]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

# Export peer env vars directly (avoids word-splitting on paths with spaces)
set_peer_env() {
    local peer_host="${1%%:*}"
    export CORE_PEER_LOCALMSPID="$MSPID"
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_TLS_ROOTCERT_FILE="$PEER_MSP_DIR/peers/$peer_host/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP"
    export CORE_PEER_ADDRESS="$1"
}

# ─── Step 1: Build chaincode ─────────────────────────────────────────────────
#
# B-2 FIX: The previous step ran "go build -tags liboqs ./..." locally using
# the host machine's liboqs installation.  This does NOT validate what the peer
# container builds — the Fabric peer uses "peer lifecycle chaincode package
# --lang golang" which builds the source inside hyperledger/fabric-ccenv, a
# container that does NOT have liboqs installed.  The local liboqs build would
# pass CI while the peer container build fails with a linker error on -loqs.
#
# Corrected approach:
#   • Step 1a: validate stub (default) build — this is exactly what fabric-ccenv
#     compiles inside the peer container.
#   • Step 1b: optionally validate liboqs build ONLY when a custom ccenv image
#     (teta-ccenv) with liboqs is available.
#
# For production deployment with real Dilithium2 signatures, build a custom
# ccenv image (Dockerfile.ccenv provided in blockchain/chaincode/temporalecho/)
# and set CORE_CHAINCODE_BUILDER=teta-ccenv:latest in the peer environment, OR
# use the external chaincode launcher (Fabric 2.x/3.x cc_launcher.html).

log "Step 1 — Validating Go chaincode (stub build — matches fabric-ccenv)"
cd "$CHAINCODE_DIR"
go mod tidy || err "go mod tidy failed — is Go installed?"

# Step 1a: stub build (no CGO, no liboqs) — this is what the standard ccenv peer builds.
# -o /tmp/... : without an explicit output path, `go build ./...` writes a
# binary named after the module (temporalecho) directly into CHAINCODE_DIR —
# which then gets bundled into the chaincode package by Step 2, corrupting
# it (peer lifecycle chaincode install then fails on every peer with
# "failed to marshal response: string field contains invalid UTF-8", since
# the ELF binary's raw bytes aren't valid UTF-8 wherever Fabric processes
# package contents as strings).
go build -o /tmp/cc_stub_validate ./... || err "go build (stub mode) failed — fix compile errors before packaging"
log "  Stub build OK (this matches what fabric-ccenv will compile)"

# Step 1b: optional liboqs validation (only if custom ccenv image is available)
if docker image inspect teta-ccenv:latest >/dev/null 2>&1; then
    log "  teta-ccenv image found — validating liboqs build inside container"
    # -o /tmp/... : writing the test binary back into the bind-mounted
    # source dir fails with "permission denied" (container user can't write
    # to the host-owned directory) even when the build itself succeeds —
    # that's a false-negative on this validation step, not a real build
    # failure. verification_liboqs.go's build tag was also flipped to be
    # the default (no tag needed) since Fabric's own install path can't be
    # told to pass -tags liboqs — see that file's header — but -tags liboqs
    # here is still harmless (unused tag name, doesn't select anything).
    docker run --rm -v "$CHAINCODE_DIR:/chaincode" teta-ccenv:latest \
        sh -c "cd /chaincode && CGO_ENABLED=1 go build -o /tmp/cc_validate ./..." \
        && log "  liboqs build OK (teta-ccenv)" \
        || log "  WARNING: liboqs build failed in teta-ccenv — check Dockerfile.ccenv"
else
    log "  NOTE: teta-ccenv image not found — skipping liboqs validation."
    log "        For production PQC, build: docker build -t teta-ccenv:latest -f Dockerfile.ccenv ."
    log "        Then set CORE_CHAINCODE_BUILDER=teta-ccenv:latest in peer environment."
fi

# ─── Step 2: Package ─────────────────────────────────────────────────────────

log "Step 2 — Packaging chaincode"
CC_PKG="/tmp/${CC_LABEL}.tar.gz"
set_peer_env "${RSU_PEERS[0]}"
peer lifecycle chaincode package "$CC_PKG" \
    --path "$CHAINCODE_DIR" \
    --lang golang \
    --label "$CC_LABEL" \
    || err "chaincode package failed"
log "  Package: $CC_PKG"

# ─── Step 3: Install on all peers ─────────────────────────────────────────────

log "Step 3 — Installing chaincode on all 5 RSU peers"
PACKAGE_ID=""
for peer_hp in "${RSU_PEERS[@]}"; do
    peer_host="${peer_hp%%:*}"
    log "  Installing on $peer_host"
    set_peer_env "$peer_hp"
    peer lifecycle chaincode install "$CC_PKG" \
        || log "  $peer_host: install returned non-zero (may already be installed)"
done

# Capture package ID from SYNCED_PEER specifically — some peers (rsu1) are
# in an inconsistent gossip/ledger state (see SYNCED_PEER note below) and
# their `queryinstalled` can itself fail; under `set -o pipefail` a failure
# anywhere in the query|grep|awk pipe aborts the whole script, silently,
# with no further steps run. Querying only the known-good peer avoids that.
set_peer_env "peer0.rsu3.tetaguard.net:7053"
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled 2>/dev/null \
    | grep "$CC_LABEL" | awk '{print $3}' | tr -d ',' || true)
log "  Package ID: $PACKAGE_ID"

[ -z "$PACKAGE_ID" ] && err "Could not determine package ID"

# RSU_PEERS[0] (peer0.rsu1) is not reliably reachable for network operations
# in this environment — gossip leader election among the 5 RSU peers doesn't
# always converge, leaving some peers stuck (never receiving new blocks).
# peer0.rsu3 is confirmed to sync correctly (verified during the initial
# 1.0/1 deployment); use it for every step that needs a live, synced peer.
SYNCED_PEER="peer0.rsu3.tetaguard.net:7053"

# ─── Step 4: Approve for org ─────────────────────────────────────────────────

log "Step 4 — Approving chaincode for TetaGuardOrg"
set_peer_env "$SYNCED_PEER"
peer lifecycle chaincode approveformyorg \
    -o "$ORDERER" \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" \
    --name "$CHAINCODE" \
    --version "$CC_VERSION" \
    --package-id "$PACKAGE_ID" \
    --sequence "$CC_SEQUENCE" \
    || err "approveformyorg failed"
log "  Approved"

# ─── Step 5: Check commit readiness ─────────────────────────────────────────

log "Step 5 — Checking commit readiness"
set_peer_env "$SYNCED_PEER"
peer lifecycle chaincode checkcommitreadiness \
    --channelID "$CHANNEL" \
    --name "$CHAINCODE" \
    --version "$CC_VERSION" \
    --sequence "$CC_SEQUENCE" \
    --output json | python3 -m json.tool || true

# ─── Step 6: Commit chaincode ────────────────────────────────────────────────

log "Step 6 — Committing chaincode to '$CHANNEL'"
# Endorsement policy only needs one org member; target the confirmed-synced
# peer rather than looping over all 5 (some of which time out waiting for
# gossip delivery — see SYNCED_PEER note above).
PEER_ARGS_ARRAY=(
    --peerAddresses "$SYNCED_PEER"
    --tlsRootCertFiles "$PEER_MSP_DIR/peers/${SYNCED_PEER%%:*}/tls/ca.crt"
)

set_peer_env "$SYNCED_PEER"
peer lifecycle chaincode commit \
    -o "$ORDERER" \
    --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL" \
    --name "$CHAINCODE" \
    --version "$CC_VERSION" \
    --sequence "$CC_SEQUENCE" \
    "${PEER_ARGS_ARRAY[@]}" \
    || err "chaincode commit failed"

log "TemporalEchoMitigator committed to '$CHANNEL' — ready."
log ""
log "Verify with:"
log "  peer lifecycle chaincode querycommitted -C $CHANNEL --name $CHAINCODE"
