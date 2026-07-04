# Trust/LW-Detector Layer Fixes + Blockchain Enforcement Gap (2026-07-04)

This document records a code-review pass (7 findings) on `routing.cc`'s
trust/LW-detector layer and the blockchain enforcement path it feeds into.
Findings 1, 3, 4 were fixed and verified in `routing.cc`. Findings 2, 5, 6
were confirmed non-issues. Finding 7 was scoped in detail but intentionally
left unfixed — see the "Project scope" note at the end for why.

---

## Fixed in `routing.cc`

All fixes below were verified by building successfully, re-running affected
scenarios, and confirming TP/TN/FP/FN/MCC/AUROC were byte-identical
before/after (i.e. no detection-metric regression), plus scenario-specific
spot checks of the new behavior (e.g. `RSU7` vs `OBU8888` labeling, PBFT
PASS/FAIL under different peer trust compositions).

### #1 — Witness reporter mislabeled as a fake RSU

`PemWriteWitnessRecordsJson()` hardcoded `"RSU" << reporter_id`, which
fabricated `RSU8888` for the no-RSU synthetic evidence bucket
(`TRUST_OBU_PEER_ID = 8888`). Fixed to call `PemResolvePeerLabel()` instead
(a forward declaration was added earlier in the file, since the real
definition sits later). RSU scenarios now correctly emit `RSU7` (or whatever
the real RSU's node ID is); no-RSU scenarios emit `OBU8888` instead of a
non-existent RSU.

### #3 — Multiple trust-layer miscalibrations vs. Table 3.4/4.9 and the Go chaincode (`trust.go`)

- **Constants corrected** to match the chaincode / Table 4.9 exactly:
  - `TRUST_TAU_MIN_CTRL`: 0.50 → 0.30
  - `TRUST_DELTA_C`: 0.10 → 0.20
  - `TRUST_TMIN_DWELL_S`: 5.0 → 3.0 (the old comment incorrectly claimed this
    value was "unspecified" in the paper — it isn't; Table 4.9 specifies it)

- **PBFT consensus gate made trust-weighted (Eq. 3.47/3.48).**
  `PemPbftConsensusGate()` now takes `sum_approve_tau`/`sum_active_tau` and
  accepts iff the ratio exceeds 2/3 — matching `checkPBFTTrustWeight()` in
  `trust.go` exactly. The call site builds the real peer set (RSU or vehicle
  peers matching whatever `n_peers` was already computed as), excludes
  flagged peers from the denominator (Eq. 3.47: "zero-scored peers
  contribute no voting weight"), and excludes the attacker itself from the
  approving set (a Byzantine peer doesn't vote to convict itself — matches
  the single-external-forger threat model already documented at the gate).
  Verified: with a lone malicious RSU (N_RSUs=1), the gate now correctly
  FAILs (no honest witness exists); with 3 honest + 1 malicious RSU
  (N_RSUs=4), it correctly PASSes (3/4 = 0.75 > 2/3). Detection metrics
  (TP/FP/MCC) are unaffected either way, since `PemRecordObservation` (which
  drives them) runs independently of this mitigation-enforcement gate.

- **Eq. 3.40 eligibility conditions 1 and 2 were missing.** `TrustRecord`
  gained `cert_valid` (bool) and `hw_capacity_mb` (double) fields.
  `TrustIsEligible()` now checks:
  - Condition 1 (certificate validity) — mandatory in every mode. LKH
    revocation (Eq. 3.18) now also sets `cert_valid = false` on the revoked
    node, since a revoked node no longer holds a valid consortium
    credential.
  - Condition 2 (Cmin hardware floor, 2048 MB RAM) — bypassed for OBUs in
    no-RSU mode, per the paper's explicit statement (§3.4.11, p.78): "In
    pure no-RSU deployments, conditions 2 and 3 ... are bypassed for
    appointed OBUs, since no Tier 1 checkpoint infrastructure exists...
    Certificate validity (condition 1) and the trust threshold (condition 4)
    remain mandatory."

- **`witness_records.json` now carries real ML-DSA-87 signature/message/pub_key
  (Eq. 3.27–3.28).** Previously these fields didn't exist at all, meaning
  the chaincode's Eq. 3.29 `Verify(σ_Vk, PK_Vk)=1` gate could never pass —
  `verifyQuorum` skips any witness whose signature doesn't verify, so
  `accepted` was permanently 0 and ME quorum could never be satisfied
  regardless of how many honest witnesses existed.

  The fix signs a **canonical colon-delimited ASCII string**
  (`V<vehicle_id>:<reporter_label>:<lat>:<lon>:<rssi>:<ts_ms>:<nonce_hex>`),
  **not** the raw `LocationBindingPayload` C struct that
  `create_location_bound_report()` signs internally elsewhere in the file —
  that struct contains arbitrary binary bytes (floats, a raw nonce) that
  cannot round-trip through a JSON string field, since JSON strings must be
  valid UTF-8. The base `dilithium5_sign()` primitive is used directly (no
  `LOCBIND:` domain-tag prefix), because the Go-side `verifyMLDSA87Sig`
  verifies the literal bytes of the JSON `message` string with no
  domain-separation awareness — using the domain-separated variant would
  produce a signature that verifies in the C++ path but never verifies
  against the actual chaincode.

  Base64 encoding (`PemBase64Encode()`, via OpenSSL's `EVP_EncodeBlock`) is
  used for the `signature`/`pub_key` JSON fields, matching Go's
  `encoding/json` default `[]byte` marshalling convention. Verified: decoded
  signature/pubkey lengths are exactly 4627/2592 bytes
  (`DILITHIUM5_SIG_LEN`/`DILITHIUM5_PK_LEN`).

  **Important self-consistency requirement, called out in a code comment:**
  the signed message is built from the *same* `reporter_lat`/`reporter_lon`/
  `rssi_from_vi_dbm`/`ts_ms` values written into the structured JSON fields —
  not independently computed. This matters because `verifyQuorum` on the Go
  side verifies the signature against the opaque `message` string completely
  separately from the distance/RSSI checks against the structured fields; if
  the two representations were ever allowed to drift apart in a future edit,
  Eq. 3.27's physical-binding guarantee would become meaningless even though
  the signature itself would still "verify."

  A one-time `NS_LOG_UNCOND` warning now fires if signing keys aren't ready
  (e.g. run with `--latency=0`, or a build without `HAVE_LIBOQS`), so an
  unsigned run is loud instead of silently writing empty signature fields.

### #4 — §3.4.10 anchor-checkpoint sync gate was entirely absent

The paper (§3.4.10) requires that a Tier-2 OBU peer must synchronize from
the most recent anchor checkpoint before joining any PBFT consensus round —
and the chaincode enforces this **unconditionally**, explicitly *not*
subject to the no-RSU bypass that relaxes Eq. 3.40 conditions 2/3:

> `// Checkpoint-sync is enforced unconditionally regardless of mode...`
> `// an OBU must sync from the most recent anchor before it may vote in any consensus round.`

`routing.cc` had no equivalent logic anywhere. Fixed by adding:
- `TRUST_ANCHOR_INTERVAL_S` = `⌊Tmin/Tb⌋` beacon intervals (treating 1
  "block" as 1 beacon interval, since there's no separate ledger
  block-height concept anywhere else in the trust layer).
- A `registered_at` field on `TrustRecord` (sim time the peer entered
  `g_trust_table`).
- `TrustCheckpointSynced()`: RSUs (Tier 1) are always exempt. OBUs are
  exempt during bootstrap (mirrors the chaincode's actual default —
  `obuHasSyncedFromRecentCheckpoint()` returns `true` whenever no anchor
  checkpoint exists yet on the ledger). After bootstrap, an OBU is
  considered synced once it has been registered past one full anchor
  interval.
- Wired into `TrustIsEligible()` **before** the no-RSU-bypass block, so it
  applies in both RSU-present and no-RSU modes — this was the one detail
  that would have been easy to get wrong (bundling it into the bypassed
  block by mistake).

Verified mathematically inert-but-correct under the current
static-registration model: every peer's `registered_at` is stamped from the
same `Simulator::Now()` call inside `TrustInit()`, which runs once at
simulation start, so `registered_at ≈ 0` for every peer. This means the gate
can never actually reject a peer today (re-ran TTW-S2/S3, ME-S1 and
confirmed byte-identical results before/after) — but it's correctly shaped
for whenever dynamic peer promotion/demotion is added, at which point
`registered_at` will actually vary across peers and the gate will do real
work.

---

## Confirmed non-issues, no action taken

- **#2** — `submitToFabric.js`'s `loadBeaconEvidence()` only parses 7 of the
  8 CSV columns routing.cc's `beacon_evidence.csv` writes (`neighbour_vehicles`
  is ignored). Checked `aggregateEvidenceLinkSet()` in `divergence.go`: it
  never reads that column, and no equation anywhere depends on it. Genuinely
  inert, not a hidden bug.
- **#5** — `vehicle_macs.json` is written with real ns-3-assigned MAC
  addresses, but nothing calls `SubmitVehicleMAC` to actually submit it. The
  code's own comment already says this is for a "future bridge script."
  Harmless: the chaincode's `lookupVehicleMAC()` falls back to a derived
  MAC formula (`02:00:00:00:HH:LL` from the numeric vehicle ID), and there's
  no real OpenFlow switch in this simulation to match a real MAC against
  anyway.
- **#6** — `flowmod.go` was read in full (`PendingFlowMod`/`RyuFlowMod`
  structs, `pushFlowModDrop`/`pushRerouteFlowMod`/`pushFlowModOverride`, MAC
  lookup/fallback). Matches the paper's design intent exactly — chaincode
  writes to ledger, `eventListener.js` reads and POSTs to Ryu. No
  discrepancies found.

---

## #7 — Blockchain enforcement is a deterministic no-op today (scoped, not fixed)

Neither `SubmitIndividualSigEvidence` (the TTW/BSHH threshold-signature
path) nor `SubmitWitnessRecord` (the ME quorum path) is ever called by any
client script (`submitToFabric.js`, `eventListener.js`, `demoTrust.js`,
`query_mitig.js`, or any `debug*.js`).

**Consequence:** on a real, deployed Fabric network, `verifyThresholdSig()`
and `verifyQuorum()` in the chaincode always see an empty evidence slice.
Since `thresholdT` is always computed as `n/2 + 1 ≥ 1`, and `0 >= thresholdT`
is always false, both checks mathematically **cannot pass, ever** —
regardless of how many honest reporters/witnesses genuinely exist. This
means:
- Every TTW alert → `THRESHOLD_SIG_FAIL` → no DROP FlowMod, no session-key
  revocation, no blacklist beacon, no cert revocation.
- Every BSHH alert → same failure path.
- Every ME alert → `QUORUM_FAIL` → no path invalidation, no reroute FlowMod.
- Only `CTRL_ORIGIN` (controller-origin attacks) actually completes
  end-to-end, because that branch doesn't go through either verification
  gate.

This is a **deterministic 100% failure by design of omission**, not merely
an untested code path — even standing up the real Fabric network and
running the client scripts exactly as intended would not fix this without
the two bridges described below.

**This does NOT affect `routing.cc`'s own mitigation gate.** `PemApplyMitigation`
→ `PemVerifyThresholdSig()`/`PemVerifyQuorum()` is a fully self-contained
C++ proxy that calls `dilithium5_verify_thresh()`/`verify_quorum()` directly
against the real crypto library, entirely independent of the Fabric
chaincode. Every `FS-MITIGATE ... -> PASS` logged during this session's
testing is real and unaffected by this gap.

### Project scope note (confirmed against the paper's own Section 1.5, "Research Scope")

> "This study is limited to conceptual, theoretical, and analytical
> investigation, without implementation or experimental validation... The
> completed scope of this work includes: formal characterisation of three
> attack variants (TTW, BSHH, ME)... design of the dual-mode (LW/FS)
> detection architecture, and NS-3/SUMO simulation evaluation of the
> lightweight detection layer across all twelve attack scenarios. The
> remaining scope — TGN model training, Hyperledger Fabric blockchain
> deployment, and systematic baseline comparison — is ongoing and forms the
> subject of the next project phase."

Hyperledger Fabric deployment is **explicitly named as next-phase work**,
not silently missing scope. Item 7 lives entirely inside that declared
future-phase boundary — the JS bridge scripts only matter once a real
Fabric network exists to submit transactions to, and standing up that
network is itself declared out of scope for the current phase. What *is* in
current scope — "NS-3/SUMO simulation evaluation of the lightweight
detection layer" — is exactly `routing.cc`, which is exactly what the six
fixes above address.

**Bottom line: item 7 does need to be fixed eventually — when the next
project phase (blockchain deployment) actually starts — but not now, and
not as part of the current phase's deliverable.**

---

## Full scoping for whoever picks this up next (not started)

### Fix A — `SubmitWitnessRecord` bridge (smaller, JS-only, ~1–2h)

`witness_records.json` already has the right shape after fix #3 above. What's
missing:
1. A new `--witness_records <path>` CLI flag in `submitToFabric.js`'s `main()`
   (currently only parses `--alerts`, `--evidence`, `--ctrl_topo`,
   `--node_id`, `--no_rsu`).
2. A loader function mirroring `loadBeaconEvidence()`'s existing pattern to
   parse the JSON array `routing.cc` writes.
3. A submission loop calling
   `contract.submitTransaction('SubmitWitnessRecord', JSON.stringify(record))`
   once per record, using the existing `submitTransactionWithRetry()`
   wrapper (already handles MVCC-conflict retries for every other
   transaction in this file).
4. **Timing matters, not just ordering**: this loop must run *before* the
   `Mitigate` call (line ~319), because `getWitnesses()` reads from the
   ledger within a hardcoded `±100ms` window of the alert timestamp
   (`const Tb int64 = 100` in `temporalecho.go`). Submitting late, or with a
   timestamp outside that window, leaves the record on the ledger but
   `verifyQuorum` still won't find it.
5. **Prerequisite to verify first, separate from anything client-side**:
   `getWitnesses()`/`getSignatureEvidence()` are CouchDB rich queries
   (`GetQueryResult` + JSON selector). If the deployed Fabric network uses
   the default LevelDB state database instead of CouchDB, these queries
   fail outright regardless of any client-side fix — check the network's
   `core.yaml`/`docker-compose` configuration before assuming Fix A alone
   is sufficient.

### Fix B — `SubmitIndividualSigEvidence` bridge (bigger, multi-file, re-opens `routing.cc`)

This is not just a wiring gap — `routing.cc` doesn't currently produce any
file this could bridge from. `PemVerifyThresholdSig()` (the function
implementing the TTW/BSHH threshold-signature check, Eq. 3.26) is entirely
self-contained and in-memory: it signs and verifies `n_reporters` times
using **one shared global keypair** (`g_dil_sk`/`g_dil_pk`), immediately, in
the same function call, with nothing ever written to disk. There is no
`individual_sig_evidence.json`-equivalent file for a JS bridge to read.

To close this fully:
1. **Add a new writer in `routing.cc`** exporting one record per reporting
   node (vehicle/RSU ID, signature, message, pubkey, timestamp) — this is a
   genuine new feature, not a wiring fix, and re-opens the routing.cc-only
   scope boundary this session (and Fix A) maintained.
2. **Decide how to handle the shared-global-keypair limitation.** Right now
   every simulated "reporter" would produce an identical signature from an
   identical key, which defeats the point of a threshold scheme — the
   chaincode's `verifyMLDSA87Sig` would happily accept it, but it wouldn't
   reflect genuinely independent signers. This bumps directly into the
   crypto-layer per-node key-management question this project has
   repeatedly treated as out of scope; picking this up means deciding
   whether to accept the shared-key simplification as-is (and just wire it
   through) or address per-node identity keys first.
3. Add the equivalent `--individual_sig_evidence` CLI flag, loader, and
   submission loop in `submitToFabric.js`, subject to the same `±100ms`
   timing window and CouchDB dependency as Fix A
   (`getSignatureEvidence()` uses an identical rich-query pattern).

**Critical difference from Fix A**: `SubmitIndividualSigEvidence` has **no
graceful degradation**. Unlike `SubmitWitnessRecord` (which skips
verification if `signature`/`pub_key` are empty, per the chaincode's own
"degrades gracefully" comment), it **hard-fails the transaction**
(`return fmt.Errorf(...)`) if the signature doesn't verify. So Fix B cannot
be shipped with placeholder/empty signatures the way #3 above initially
could have been — real, valid signatures are mandatory from the very first
submission.

### Shared constraints for both fixes

- **Neither can be verified in a typical dev environment without a live
  Fabric network with CouchDB.** Every fix in this document that *could* be
  re-tested, was (build + scenario re-run + before/after metrics diff) —
  Fix A and Fix B cannot get that same treatment without an actual Fabric
  deployment to submit transactions against.
- Both gates require the submitted evidence to land inside the same
  `±100ms` alert window that `Mitigate` reads at — a real correctness
  constraint on submission timing, not just an ordering nicety.

### Suggested order if/when picked up

**Fix A first** — it's genuinely self-contained, testable independently
once a Fabric network with CouchDB exists, and validates the ME/quorum path
on its own. **Fix B is a separate, larger follow-up** — it also touches
`routing.cc` and requires a real design decision about per-node signing
keys, so it makes sense as its own scope rather than bundling it with Fix A.
