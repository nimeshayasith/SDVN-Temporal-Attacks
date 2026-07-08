# Plan: second Tier-2-only channel for no-RSU scenario testing

## Context

Per Table 3.5 / Eq. 3.40-3.41, a pure no-RSU deployment needs `np = 8`
Tier-2 OBU peers, all cold-started at `τ0 = 0.10`, so the paper's own
bootstrap-round derivation (`Rmin = ⌈(0.5-0.1)/0.05⌉ = 8 rounds`) and the
Tier-2 eligibility gate `ϕ(k)` (Eq. 3.40) are genuinely exercised. Today's
setup falls short of that on two counts:

1. `submit_alerts.py`/`submitToFabric.js`/`fabricClient.js`'s `OBU_PEERS_DEFAULT`
   only lists 3 peers (obu1-3) for no-RSU mode, not 8.
2. `bootstrap.sh` registers rsu1-5 as Tier-1 (`RegisterRSUPeer`, τ_init=1.00)
   **unconditionally**, once, for the one channel (`teta-channel`) that
   currently exists. Since `TrustRecord.IsRSUPeer` is ledger state tied to a
   peer identity on a specific channel, rsu1-5 cannot simultaneously be
   Tier-1 (needed by with-RSU scenarios 2,4,6,8,10,12) and Tier-2 (needed by
   no-RSU scenarios 1,3,5,7,9,11) **on that same channel** — re-registering
   them would silently corrupt the with-RSU scenarios' already-validated
   results.

**Resolution**: create a second Fabric **channel** (not a second network) —
`teta-channel-norsu` — on the *same*, already-running peer containers/certs.
Channels have independent ledgers even on shared peers, so this gives all 8
peers (rsu1-5 + obu1-3) a completely clean, never-touched-by-Tier-1
trust history on the new channel, while `teta-channel` keeps its existing
Tier-1 registrations untouched. Confirmed via chaincode audit
(`anchor.go`, `trust.go`, `temporalecho.go`): every capability gate is
`IsRSUPeer || Score >= TrustMinGT`, not an RSU-exclusive lock — so Tier-2
peers get full capability parity with Tier-1 automatically once they clear
the 8-round bootstrap. **No chaincode changes needed.**

Known pre-existing environment flakiness to expect: `configtx.yaml`'s own
comments already document RSU1 as "confirmed stuck at block height 1" and
RSU3 as the anchor peer chosen specifically because it was more reliable —
and in this session RSU3 itself crashed (`no non-loopback IPv4 interface
detected`, reproducible 3/3 restarts, likely stale volume state). Budget
time for peer flakiness being the norm here, not the exception, when
executing this plan.

## Steps

### 1. Add a second channel profile to `configtx.yaml`

Add a `TetaChannelNoRSU` profile alongside the existing `TetaChannel` one
(same `Organizations`/`Orderer`/`Application` blocks — this is a genuinely
minimal diff, just a second `Profiles:` entry):

```yaml
Profiles:
  TetaChannel:
    # ...existing, unchanged...
  TetaChannelNoRSU:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      Organizations:
        - *OrdererOrg
      Capabilities:
        <<: *OrdererCapabilities
    Application:
      <<: *ApplicationDefaults
      Organizations:
        - *TetaGuardOrg
      Capabilities:
        <<: *ApplicationCapabilities
```

Generate its genesis block (reuses existing crypto material — no `cryptogen`
needed):
```bash
cd blockchain/network
export FABRIC_CFG_PATH=./
configtxgen -profile TetaChannelNoRSU -channelID teta-channel-norsu \
            -outputBlock ./channel-artifacts/teta-channel-norsu.block
```

### 2. Join orderers and all 8 peers to the new channel

Orderers (same pattern as `create_channel.sh` already uses for `teta-channel`,
just pointed at the new block/channelID):
```bash
osnadmin channel join --channelID teta-channel-norsu \
  --config-block ./channel-artifacts/teta-channel-norsu.block \
  -o orderer1.tetaguard.net:9443 \
  --ca-file ./crypto-config/ordererOrganizations/orderer.tetaguard.net/tlsca/tlsca.orderer.tetaguard.net-cert.pem \
  --client-cert ./crypto-config/ordererOrganizations/orderer.tetaguard.net/users/Admin@orderer.tetaguard.net/tls/client.crt \
  --client-key  ./crypto-config/ordererOrganizations/orderer.tetaguard.net/users/Admin@orderer.tetaguard.net/tls/client.key
```
(repeat per orderer if `create_channel.sh` joins all 4 individually — check
that script's existing loop and mirror it for the new channelID.)

Peers — for each of rsu1-5, obu1-3:
```bash
peer channel join -b ./channel-artifacts/teta-channel-norsu.block
```
(set `CORE_PEER_ADDRESS`/MSP env vars per peer first, same as
`deploy_chaincode.sh` already does per-peer for `teta-channel`.)

**Checkpoint**: confirm all 8 report the new channel before proceeding —
`peer channel list` per peer. Given today's rsu3 instability, don't assume
success; verify explicitly. If a peer won't join, that's a real blocker to
resolve before step 3, not something to route around.

### 3. Install, approve, commit the existing chaincode on the new channel

Reuse the exact same `temporalecho` chaincode package already built for
`teta-channel` — same code, just also committed to the new channel:
```bash
# per peer: peer lifecycle chaincode install teta_guard.tar.gz
# per org (once sufficient orgs approved): peer lifecycle chaincode approveformyorg \
#   --channelID teta-channel-norsu --name temporalecho --version 2.0 --sequence 1 ...
# commit: peer lifecycle chaincode commit --channelID teta-channel-norsu ...
```
Mirror `deploy_chaincode.sh`'s existing install/approve/commit sequence,
substituting the channel ID. **Sequencing risk flagged in review**: don't
fire bootstrap registrations (step 4) until `commit` succeeds and
`peer lifecycle chaincode querycommitted --channelID teta-channel-norsu`
confirms it — a partially-committed chaincode is not a clean rollback.

### 4. Bootstrap the new channel: all 8 peers as Tier-2, none as Tier-1

New script `bootstrap-norsu.sh` (copy `bootstrap.sh`, trim to just this):
```bash
for peer_host in peer0.rsu1.tetaguard.net peer0.rsu2.tetaguard.net \
                 peer0.rsu3.tetaguard.net peer0.rsu4.tetaguard.net \
                 peer0.rsu5.tetaguard.net peer0.obu1.tetaguard.net \
                 peer0.obu2.tetaguard.net peer0.obu3.tetaguard.net; do
    peer chaincode invoke -C teta-channel-norsu -n temporalecho \
        -c "{\"function\":\"RegisterOBUPeer\",\"Args\":[\"${peer_host}\",\"4096\",\"8\"]}"
done
```
No `RegisterRSUPeer` calls anywhere in this script — that's the entire point.

`"4096"`/`"8"` (RAM MB / storage GB) are uniform across all 8 hosts
intentionally, not a fidelity shortcut: `RegisterOBUPeer`'s hardware check is
a single minimum-capacity floor (`Cmin`: ≥2048MB RAM, ≥8GB storage), not a
per-host-type differentiator, and rsu1-5's real hardware only exceeds these
floors — so there's no false-negative risk from reusing the same declared
values for the rsu-labeled hosts here.

### 5. New connection profile

Copy `config/connection-profile.json` → `config/connection-profile-norsu.json`,
change `channels` block's key from `teta-channel` to `teta-channel-norsu`
(peer/orderer endpoints, certs, MSP — all identical, since it's the same
containers/certs).

### 6. Auto-selection wiring (code changes, after the network side works)

- `fabricClient.js`: `connectContract(nodeID, channelName)` — accept the
  channel name as a parameter instead of the hardcoded `CHANNEL` constant,
  defaulting to `'teta-channel'`.
- `fabricServer.js`: when started with `--no_rsu`, pass
  `'teta-channel-norsu'` to `connectContract`; also update
  `OBU_PEERS_DEFAULT` in `fabricClient.js` to list all 8 peer IDs (not 3) —
  this was the original, simpler ask, now correctly backed by a real Tier-2
  ledger for all 8 rather than papering over the gap.
- `routing.cc`: derive `no_rsu` automatically from `attack_scenario`
  (1,3,5,7,9,11 = no-RSU) instead of requiring it as a separately-remembered
  CLI flag, and pass it through when spawning/informing `fabricServer.js` —
  or simpler, have `fabricServer.js` read the scenario number itself from
  the first "E:" line's `attack_label`/context if available, avoiding a new
  routing.cc→fabricServer.js protocol field. Decide this detail when
  implementing, not now.

## Verification

1. After step 2: `peer channel list` on all 8 peers shows `teta-channel-norsu`.
2. After step 3: `peer lifecycle chaincode querycommitted -C teta-channel-norsu`
   shows `temporalecho` committed.
3. After step 4: `peer chaincode query -C teta-channel-norsu -n temporalecho
   -c '{"function":"GetTrustScore","Args":["peer0.rsu1.tetaguard.net"]}'`
   returns `0.10` (Tier-2 init), not `1.00` — proves rsu1 is genuinely
   Tier-2 on this channel while remaining Tier-1 on `teta-channel`.
4. Run a no-RSU scenario (e.g. `--attack_scenario=1`) live end-to-end and
   confirm `fabricServer.js`'s Mitigate call targets `teta-channel-norsu`
   with all 8 peers in the replicated `detEvents`, and that trust scores on
   that channel visibly rise across the run (query `GetTrustScore` before/after).
