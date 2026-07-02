package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// txUUIDMu guards txUUIDCounters across goroutines (each tx runs in its own goroutine).
var txUUIDMu sync.Mutex
var txUUIDCounters = map[string]uint64{}

// TemporalEchoMitigator is the Hyperledger Fabric smart contract that executes
// Algorithm 4 (FS-MITIGATE) from the paper.
type TemporalEchoMitigator struct {
	contractapi.Contract
}

// ═══════════════════════════════════════════════════════════════════════════
//  FLOW 1 — Beacon Evidence
// ═══════════════════════════════════════════════════════════════════════════

// SubmitBeaconEvidence stores B_nk(t) on the ledger (§4, Flow 1).
// TE-05: Only peers with τk ≥ τ^gt_min (or RSU Tier 1) may write ground truth.
// A sub-threshold OBU can poison aggregateEvidenceLinkSet and defeat divergence detection.
func (t *TemporalEchoMitigator) SubmitBeaconEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceJSON string,
) error {
	var record BeaconEvidenceRecord
	if err := json.Unmarshal([]byte(evidenceJSON), &record); err != nil {
		return fmt.Errorf("SubmitBeaconEvidence: parse error: %v", err)
	}
	record.DocType = "BEACON_EVIDENCE"

	trust := loadTrust(ctx, record.PeerID)
	if trust.Flagged {
		return fmt.Errorf("SubmitBeaconEvidence: peer %s is flagged", record.PeerID)
	}

	// During bootstrap (no peer has yet crossed the stricter ground-truth threshold),
	// all OBUs already meet the bare participation floor and must be allowed to
	// submit evidence — otherwise trust can never accumulate and bootstrap never ends.
	// Outside bootstrap, only peers that have cleared the stricter threshold (or
	// Tier 1 RSU peers) may write evidence that counts as ground truth.
	// aggregateEvidenceLinkSet independently enforces the stricter threshold when
	// building the ground-truth set for divergence checks, so bootstrap-phase
	// evidence is stored but never misused as authoritative ground truth.
	bootstrapDone := t.isBootstrapComplete(ctx)
	if bootstrapDone {
		if !trust.IsRSUPeer && trust.Score < TrustMinGT {
			return fmt.Errorf("SubmitBeaconEvidence: peer %s trust %.3f below ground-truth threshold",
				record.PeerID, trust.Score)
		}
	} else {
		if trust.Score < TrustMin {
			return fmt.Errorf("SubmitBeaconEvidence: peer %s trust %.3f below participation floor",
				record.PeerID, trust.Score)
		}
	}

	// Canonical signed payload: PeerID, IntervalTS, Observations only —
	// mirrors anchor.go's sigInput pattern (SyncFromAnchorCheckpoint) and
	// SubmitLWDetectionResult's. Verifying against the raw evidenceJSON
	// (the full submitted string, which itself contains PeerSig) was
	// self-referential and could never validate: a signature cannot cover
	// a message that includes that same signature.
	//
	// Fixed-precision field concatenation (not json.Marshal) so the JS
	// client can reproduce this exact string without depending on two
	// different languages' JSON serializers agreeing byte-for-byte (key
	// order, null-handling for fields the JS side never sets, float
	// formatting) — see signWithMLDSA87's call site in submitToFabric.js.
	var obsBuf strings.Builder
	for _, o := range record.Observations {
		fmt.Fprintf(&obsBuf, "%s|%d|%.6f|%.6f|%.2f;",
			o.VehicleID, o.SenderTSMs, o.GPSLat, o.GPSLon, o.RSSIdBm)
	}
	sigInput := fmt.Sprintf("%s:%d:%s", record.PeerID, record.IntervalTS, obsBuf.String())
	if !verifyMLDSA87Sig(record.PeerSig, sigInput, record.PeerPubKey) {
		return fmt.Errorf("SubmitBeaconEvidence: invalid peer signature from %s", record.PeerID)
	}

	key := fmt.Sprintf("BEACON:%s:%d", record.PeerID, record.IntervalTS)
	data, _ := json.Marshal(record)
	return ctx.GetStub().PutState(key, data)
}

// ═══════════════════════════════════════════════════════════════════════════
//  FLOW 2 — Detection Events
// ═══════════════════════════════════════════════════════════════════════════

// SubmitDetectionEvent stores O_rk on the ledger (§4, Flow 2).
func (t *TemporalEchoMitigator) SubmitDetectionEvent(
	ctx contractapi.TransactionContextInterface,
	eventJSON string,
) error {
	var event DetectionEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return fmt.Errorf("SubmitDetectionEvent: parse error: %v", err)
	}
	event.DocType = "DETECTION_EVENT"

	// Canonical signed payload excludes PeerSig itself — same fix as
	// SubmitBeaconEvidence, matching anchor.go/SubmitLWDetectionResult's
	// pattern. Note: this function is not currently invoked by
	// submitToFabric.js (detection events go through Mitigate instead,
	// which does not verify a per-event signature), so this fix is for
	// correctness/future callers rather than the currently exercised path.
	sigInput := fmt.Sprintf("%s:%s:%s:%f:%d:%d",
		event.PeerID, event.VehicleID, event.AttackVariant,
		event.AnomalyScore, event.TriggeredSigs, event.AlertTS)
	if !verifyMLDSA87Sig(event.PeerSig, sigInput, getPeerPubKey(ctx, event.PeerID)) {
		return fmt.Errorf("SubmitDetectionEvent: invalid signature from peer %s", event.PeerID)
	}

	key := fmt.Sprintf("DETECTION:%s:%s:%d",
		event.PeerID, event.VehicleID, event.AlertTS)
	data, _ := json.Marshal(event)
	return ctx.GetStub().PutState(key, data)
}

// ═══════════════════════════════════════════════════════════════════════════
//  FLOW 3 — Controller Topology Claim
// ═══════════════════════════════════════════════════════════════════════════

// SubmitControllerTopology stores G_t^C as untrusted claim and triggers
// divergence check (§4, Flow 3; §8).
// DV-03: checkControllerDivergence no longer applies trust penalties —
// it only emits ControllerOriginAttack. runMitigation is the sole penalty authority.
func (t *TemporalEchoMitigator) SubmitControllerTopology(
	ctx contractapi.TransactionContextInterface,
	topoJSON string,
) error {
	var claim ControllerTopologyClaim
	if err := json.Unmarshal([]byte(topoJSON), &claim); err != nil {
		return fmt.Errorf("SubmitControllerTopology: parse error: %v", err)
	}
	claim.DocType = "CTRL_TOPOLOGY"

	key := fmt.Sprintf("CTRL_TOPO:%s:%d", claim.ControllerID, claim.IntervalTS)
	data, _ := json.Marshal(claim)
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}
	return t.checkControllerDivergence(ctx, claim)
}

// ═══════════════════════════════════════════════════════════════════════════
//  PRIMARY TGN ENTRY POINT — SubmitAlert
// ═══════════════════════════════════════════════════════════════════════════

// SubmitAlert is the primary entry point called by submit_alerts.py after
// tgn_detector.cc writes tgn_alerts.json (Algorithm 2 Step 22).
//
// TE-02: thresholdT is derived dynamically from the active peer count (n/2+1),
// not hardcoded to 1. Hardcoding 1 allows a single malicious RSU to bypass
// verifyThresholdSig entirely.
// TE-06: caller trust verified before executing any action.
func (t *TemporalEchoMitigator) SubmitAlert(
	ctx contractapi.TransactionContextInterface,
	trustedNodeID string,
	alertJSON string,
	ctrlTopoJSON string,
	intervalTSStr string,
) error {
	// TE-06: verify caller trust before any action
	callerTrust := loadTrust(ctx, trustedNodeID)
	if callerTrust.Score < TrustMin || callerTrust.Flagged {
		return fmt.Errorf("SubmitAlert: caller %s not trusted (score=%.3f, flagged=%v)",
			trustedNodeID, callerTrust.Score, callerTrust.Flagged)
	}

	var alert AlertObject
	if err := json.Unmarshal([]byte(alertJSON), &alert); err != nil {
		return fmt.Errorf("SubmitAlert: parse error: %v", err)
	}

	intervalTS := alert.IntervalTSMs
	if intervalTS == 0 {
		fmt.Sscanf(intervalTSStr, "%d", &intervalTS)
	}

	event := DetectionEvent{
		PeerID:        trustedNodeID,
		VehicleID:     alert.VehicleID,
		AttackVariant: alert.Alpha,
		AnomalyScore:  alert.YHat,
		TriggeredSigs: sTrigsToMask(alert.STrig),
		AlertTS:       alert.TAlertMs,
		FromLWPath:    alert.FromLWPath,
		FromFSPath:    alert.FromFSPath,
		DocType:       "DETECTION_EVENT",
	}
	evBytes, _ := json.Marshal(event)
	evKey := fmt.Sprintf("DETECTION:%s:%s:%d",
		trustedNodeID, event.VehicleID, event.AlertTS)
	if err := ctx.GetStub().PutState(evKey, evBytes); err != nil {
		return fmt.Errorf("SubmitAlert: failed to store detection event: %v", err)
	}

	if ctrlTopoJSON != "" && ctrlTopoJSON != "null" && ctrlTopoJSON != "{}" {
		var claim ControllerTopologyClaim
		if err := json.Unmarshal([]byte(ctrlTopoJSON), &claim); err == nil {
			if claim.ControllerID != "" {
				claim.DocType = "CTRL_TOPOLOGY"
				_ = t.checkControllerDivergence(ctx, claim)
			}
		}
	}

	// TE-02: compute thresholdT dynamically from active peer count (n/2+1)
	activePeers := selectPeers(ctx, loadAllPeerIDs(ctx))
	n := len(activePeers)
	if n == 0 {
		n = 1
	}
	thresholdT := n/2 + 1

	return t.runMitigation(ctx, []DetectionEvent{event}, 0.40, thresholdT)
}

// SubmitLWDetectionResult is the Lightweight path chaincode entry point (MF-01).
// Corresponds to Algorithm 1 (LW-DETECT) firing on RSU hardware.
// The RSU evaluates the 9 signatures locally and submits the result here
// for immutable logging and threshold verification.
func (t *TemporalEchoMitigator) SubmitLWDetectionResult(
	ctx contractapi.TransactionContextInterface,
	callerPeerID string,
	vehicleID string,
	anomalyScoreStr string,  // s(e) as decimal string
	triggeredSigsStr string, // comma-separated indices e.g. "0,1,2"
	alphaVariant string,     // "TTW" | "BSHH" | "ME"
	intervalTSStr string,
	peerSigHex string, // ML-DSA-87 (Dilithium5) signature over (callerPeerID:vehicleID:score:variant:intervalTS)
) error {
	// Verify caller is a Tier 1 RSU peer
	callerTrust := loadTrust(ctx, callerPeerID)
	if !callerTrust.IsRSUPeer || callerTrust.Score < TrustInitTier1-1e-9 {
		return fmt.Errorf("SubmitLWDetectionResult: caller %s is not Tier 1 RSU", callerPeerID)
	}

	// ADD: verify signature
    sigBytes, err := hex.DecodeString(peerSigHex)
    if err != nil {
        return fmt.Errorf("SubmitLWDetectionResult: invalid peerSigHex: %v", err)
    }
    sigInput := fmt.Sprintf("%s:%s:%s:%s:%s", callerPeerID, vehicleID, anomalyScoreStr, alphaVariant, intervalTSStr)
    pubKey := getPeerPubKey(ctx, callerPeerID)
    if !verifyMLDSA87Sig(sigBytes, sigInput, pubKey) {
        return fmt.Errorf("SubmitLWDetectionResult: invalid ML-DSA-87 (Dilithium5) sig from %s", callerPeerID)
    }

	var score float64
	fmt.Sscanf(anomalyScoreStr, "%f", &score)

	// Parse triggered signature indices
	var sigMask uint32
	for _, s := range splitComma(triggeredSigsStr) {
		var idx int
		if n, _ := fmt.Sscanf(s, "%d", &idx); n == 1 && idx >= 0 && idx < 32 {
			sigMask |= 1 << uint(idx)
		}
	}

	now := txTimestampMs(ctx)
	var intervalTS int64
	fmt.Sscanf(intervalTSStr, "%d", &intervalTS)

	event := DetectionEvent{
		PeerID:        callerPeerID,
		VehicleID:     vehicleID,
		AttackVariant: alphaVariant,
		AnomalyScore:  float32(score),
		TriggeredSigs: sigMask,
		AlertTS:       now,
		FromLWPath:    true,
		FromFSPath:    false,
		DocType:       "DETECTION_EVENT",
	}

	key := fmt.Sprintf("DETECTION:LW:%s:%s:%d", callerPeerID, vehicleID, now)
	data, _ := json.Marshal(event)
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}

	// LW threshold: same n/2+1 quorum requirement
	activePeers := selectPeers(ctx, loadAllPeerIDs(ctx))
	n := len(activePeers)
	if n == 0 {
		n = 1
	}
	thresholdT := n/2 + 1

	// θLW = 0.30 is a simulation calibration value chosen for this implementation.
	// The thesis (Table 4.7) marks θLW as TBD, to be determined by grid search on
	// collected data. Update via SetSimParams("SIM_THETA_LW", "0.xx") in production.
	thetaLW := loadFloatParam(ctx, "SIM_THETA_LW", 0.30)
	return t.runMitigation(ctx, []DetectionEvent{event}, float32(thetaLW), thresholdT)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ALGORITHM 4 — FS-MITIGATE (full form, called from Node.js SDK path)
// ═══════════════════════════════════════════════════════════════════════════

// Mitigate executes Algorithm 4 (FS-MITIGATE) from the paper (§6.2).
func (t *TemporalEchoMitigator) Mitigate(
	ctx contractapi.TransactionContextInterface,
	alertsJSON string,
	beaconEvidJSON string,
	ctrlTopoJSON string,
	thetaFSStr string,
	thresholdTStr string,
) error {
	var alerts []DetectionEvent
	json.Unmarshal([]byte(alertsJSON), &alerts)

	// θFS = 0.40 is a simulation calibration value (thesis Table 4.7 marks it TBD,
	// to be selected by maximising MCC on collected data).
	// Caller may override via thetaFSStr; ledger key SIM_THETA_FS is the fallback.
	defaultThetaFS := loadFloatParam(ctx, "SIM_THETA_FS", 0.40)
	thetaFS := float32(defaultThetaFS)
	if v, err := strconv.ParseFloat(thetaFSStr, 32); err == nil && v > 0 {
		thetaFS = float32(v)
	}

	// TE-02: use dynamic peer-count threshold if not explicitly provided
	thresholdT := 1
	if v, err := strconv.Atoi(thresholdTStr); err == nil && v > 0 {
		thresholdT = v
	} else {
		activePeers := selectPeers(ctx, loadAllPeerIDs(ctx))
		n := len(activePeers)
		if n == 0 {
			n = 1
		}
		thresholdT = n/2 + 1
	}

	// SF-1: persist inline beacon evidence before divergence check
	if beaconEvidJSON != "" && beaconEvidJSON != "null" &&
		beaconEvidJSON != `{"observations":[]}` && beaconEvidJSON != `{"observations": []}` {
		var inlineEvid BeaconEvidenceRecord
		if err := json.Unmarshal([]byte(beaconEvidJSON), &inlineEvid); err == nil &&
			len(inlineEvid.Observations) > 0 {
			inlineEvid.DocType = "BEACON_EVIDENCE"
			key := fmt.Sprintf("BEACON:%s:%d", inlineEvid.PeerID, inlineEvid.IntervalTS)
			data, _ := json.Marshal(inlineEvid)
			ctx.GetStub().PutState(key, data)
		}
	}

	if ctrlTopoJSON != "" && ctrlTopoJSON != "null" && ctrlTopoJSON != "{}" {
		var ctrlClaim ControllerTopologyClaim
		if err := json.Unmarshal([]byte(ctrlTopoJSON), &ctrlClaim); err != nil {
			return fmt.Errorf("Mitigate: invalid ctrlTopoJSON: %v", err)
		}
		if ctrlClaim.ControllerID != "" {
			delta, deltaThresh := computeDivergence(ctx, ctrlClaim)
			if delta > deltaThresh {
				alerts = append(alerts, DetectionEvent{
					PeerID:        "SYSTEM",
					VehicleID:     ctrlClaim.ControllerID,
					AttackVariant: "CTRL_ORIGIN",
					AnomalyScore:  float32(delta),
					AlertTS:       txTimestampMs(ctx),
				})
			}
		}
	}

	return t.runMitigation(ctx, alerts, thetaFS, thresholdT)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ALGORITHM 4 — Per-alert mitigation logic
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) runMitigation(
	ctx contractapi.TransactionContextInterface,
	alerts []DetectionEvent,
	thetaFS float32,
	thresholdT int,
) error {
	// TE-01: PBFT consensus gate — Algorithm 4 Step 8.
	// Collect approving peers BEFORE resolveDualPath merges per-vehicle alerts,
	// because the merge keeps only the first alert's PeerID.
	approvingPeers := collectApprovingPeers(alerts)
	activePeers := selectPeers(ctx, loadAllPeerIDs(ctx))
	if len(activePeers) > 0 && !checkPBFTTrustWeight(ctx, approvingPeers, activePeers) {
		return fmt.Errorf("runMitigation: PBFT consensus not reached — aborting")
	}

	alerts = resolveDualPath(alerts)

	// MF-02: bootstrap gate — log-only mode until τ^gt_min quorum is reached
	isPreliminary := !t.isBootstrapComplete(ctx)

	// ST-02: read current block height for ConsensusRound tracking
	consensusRound := int(readBlockCounter(ctx))

	for _, alert := range alerts {
		if alert.AnomalyScore <= thetaFS && alert.AttackVariant != "CTRL_ORIGIN" {
			continue
		}

		logEntry := MitigationLogEntry{
			EntryID:        generateUUID(ctx),
			VehicleID:      alert.VehicleID,
			AttackVariant:  alert.AttackVariant,
			AnomalyScore:   alert.AnomalyScore,
			AlertTS:        alert.AlertTS,
			ConsensusRound: consensusRound, // ST-02: populated
			DocType:        "MITIGATION_LOG",
		}

		// MF-02: during bootstrap skip enforcement; log only
		if isPreliminary {
			logEntry.Actions = append(logEntry.Actions, "BOOTSTRAP_PRELIMINARY_NO_ENFORCEMENT")
			commitLog(ctx, logEntry)
			continue
		}

		variant := alert.AttackVariant

		// In no-RSU mode there are no RSU-level OpenFlow switches, so FlowMod
		// records (DROP, REROUTE, OVERRIDE) have nothing to be delivered to.
		// Read once per alert; all three variant branches below use this flag.
		noRSUFlag, _ := ctx.GetStub().GetState("SIM_NO_RSU_MODE")
		isNoRSU := string(noRSUFlag) == "1"

		if variant == "TTW" || variant == "BSHH" || variant == "TTW_BSHH_COMBINED" {
			sigEvidence := getSignatureEvidence(ctx, alert.VehicleID, alert.AlertTS)
			if !verifyThresholdSig(sigEvidence, thresholdT) {
				logEntry.Actions = append(logEntry.Actions, "THRESHOLD_SIG_FAIL")
				commitLog(ctx, logEntry)
				continue
			}

			// DROP FlowMod only in with-RSU mode — no OpenFlow switches in no-RSU.
			if !isNoRSU {
				if err := pushFlowModDrop(ctx, alert.VehicleID); err != nil {
					logEntry.Actions = append(logEntry.Actions, "FLOWMOD_FAIL:"+err.Error())
				} else {
					logEntry.Actions = append(logEntry.Actions, "FLOWMOD_DROP")
				}
			} else {
				logEntry.Actions = append(logEntry.Actions, "FLOWMOD_DROP_SKIPPED_NO_RSU")
			}

			// LKH session-key revocation — both modes.
			if err := revokeSessionKey(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "KEY_REVOKE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "KEY_REVOKED")
			}

			// Cooperative blacklist beacon — both modes. In no-RSU mode this is
			// the primary isolation mechanism (signed beacon propagates via OBU V2V,
			// vehicles locally exclude the node within ⌈diam(Gt)⌉ beacon intervals).
			if err := publishBlacklistBeacon(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "BLACKLIST_BEACON_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "BLACKLIST_BEACON_PUBLISHED")
			}

			// Attacker vehicle's CA certificate revocation — both modes.
			// Thesis §vehicle removal step iv: "Vk's CA certificate is revoked,
			// permanently excluding it until manual re-admission via the consortium CA."
			// The actual CA call is off-chain; the event is the notification boundary.
			if err := revokeVehicleCert(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "VEHICLE_CERT_REVOKE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "VEHICLE_CERT_REVOKED")
			}

			// RSU-specific parallel action: if the attacker is itself an RSU peer,
			// trigger zone-coverage reassignment to an adjacent trusted controller.
			// This runs in parallel with the peer-demotion pipeline (which fires
			// below via updateTrust → demotePeerToClient). The two are independent:
			// demotion handles the consortium-peer role; zone reassignment handles
			// the data-plane coverage continuity for the RSU's geographic zone.
			//
			// Must read IsRSUPeer and ZoneID HERE, before updateTrust runs below.
			// demotePeerToClient (called by updateTrust when zero=true) clears
			// IsRSUPeer as part of Stage 1 demotion. If this check ran after
			// updateTrust, the attacker would look like a vehicle and zone
			// reassignment would be silently skipped — a real correctness bug.
			attackerTrust := loadTrust(ctx, alert.VehicleID)
			if attackerTrust.IsRSUPeer {
				if err := triggerRSUZoneReassignment(ctx, alert.VehicleID, attackerTrust.ZoneID); err != nil {
					logEntry.Actions = append(logEntry.Actions, "RSU_ZONE_REASSIGN_FAIL:"+err.Error())
				} else {
					logEntry.Actions = append(logEntry.Actions, "RSU_ZONE_REASSIGNED")
				}
			}

		} else if variant == "ME" {
			witnesses := getWitnesses(ctx, alert.VehicleID, alert.AlertTS)
			lat, lon := getLinkEndpoint(ctx, alert.VehicleID)
			if !verifyQuorum(ctx, witnesses, thresholdT, lat, lon) {
				logEntry.Actions = append(logEntry.Actions, "QUORUM_FAIL")
				commitLog(ctx, logEntry)
				continue
			}
			if err := invalidateFalsePaths(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "PATH_INVALIDATE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "PATHS_INVALIDATED")
			}
			// REROUTE FlowMod only in with-RSU mode — no OpenFlow switches in no-RSU.
			if !isNoRSU {
				if err := pushRerouteFlowMod(ctx, alert.VehicleID); err != nil {
					logEntry.Actions = append(logEntry.Actions, "REROUTE_FAIL")
				} else {
					logEntry.Actions = append(logEntry.Actions, "REROUTE_FLOWMOD")
				}
			} else {
				logEntry.Actions = append(logEntry.Actions, "REROUTE_FLOWMOD_SKIPPED_NO_RSU")
			}

		} else if variant == "CTRL_ORIGIN" {
			// OVERRIDE FlowMod is explicit in Algorithm 4. In no-RSU mode no OpenFlow
			// switches exist to receive it; the ControllerRevokedBeacon and
			// CheckControllerTrustAndReassign path below handle the no-RSU case.
			if !isNoRSU {
				beaconEvidence := getAllBeaconEvidence(ctx, alert.AlertTS)
				if err := pushFlowModOverride(ctx, alert.VehicleID, beaconEvidence); err != nil {
					logEntry.Actions = append(logEntry.Actions, "CTRL_OVERRIDE_FAIL")
				} else {
					logEntry.Actions = append(logEntry.Actions, "CTRL_OVERRIDE_FLOWMOD")
				}
			} else {
				logEntry.Actions = append(logEntry.Actions, "CTRL_OVERRIDE_FLOWMOD_SKIPPED_NO_RSU")
			}
		}

		// Re-authentication is a vehicle mechanism (REAUTH:<id> → vehicles must
		// pass a fresh identity proof before rejoining). Controllers are not vehicles;
		// their re-admission path is RegisterController after a new trust record is
		// established. Calling flagReauth for a controller ID would write a spurious
		// REAUTH:<ctrl_id> key and pollute the ClearReauth audit trail.
		if variant != "CTRL_ORIGIN" {
			flagReauth(ctx, alert.VehicleID, variant)
			logEntry.Actions = append(logEntry.Actions, "REAUTH_FLAGGED")
		}

		if variant != "CTRL_ORIGIN" {
			if _, err := updateTrust(ctx, alert.VehicleID, false, true); err == nil {
				logEntry.Actions = append(logEntry.Actions, "TRUST_ZEROED")
			}
		}

		// TE-04/TE-03 FIX: For CTRL_ORIGIN, call CheckControllerTrustAndReassign ONLY —
		// it is the single authority that applies the ΔC- penalty and conditionally reassigns.
		// Calling updateCtrlTrust() separately before this would apply a double penalty.
		if variant == "CTRL_ORIGIN" {
			allCtrls := loadControllerRegistry(ctx)
			if reassignErr := t.CheckControllerTrustAndReassign(
				ctx, alert.VehicleID, marshalStringSlice(allCtrls),
			); reassignErr == nil {
				logEntry.Actions = append(logEntry.Actions, "CTRL_TRUST_PENALISED_AND_CHECKED")
			} else {
				logEntry.Actions = append(logEntry.Actions,
					"CTRL_REASSIGN_FAIL:"+reassignErr.Error())
			}
		}

		commitLog(ctx, logEntry)

		// TE-08: include all O=(Vid,α,ŷv,Strig,talert) fields in event payload
		evPayload, _ := json.Marshal(map[string]interface{}{
			"vehicle_id":     alert.VehicleID,
			"attack_variant": variant,
			"anomaly_score":  alert.AnomalyScore,
			"triggered_sigs": alert.TriggeredSigs, // TE-08: Strig bitmask
			"from_lw_path":   alert.FromLWPath,    // TE-08
			"from_fs_path":   alert.FromFSPath,    // TE-08
			"timestamp":      alert.AlertTS,
		})
		ctx.GetStub().SetEvent("AttackDetected", evPayload)
	}

	// TE-07: reward correctly-participating honest peers (Algorithm 4 final step)
	attackerSet := make(map[string]bool, len(alerts))
	for _, a := range alerts {
		attackerSet[a.VehicleID] = true
	}
	for _, pid := range activePeers {
		if !attackerSet[pid] {
			updateTrust(ctx, pid, true, false)
		}
	}

	// Supervisor feedback: re-evaluate peer set after every mitigation execution.
	// This catches trust drift in quarantined peers without waiting for the next
	// explicit PeriodicPeerReSelection call from the client.
	allPeerIDs := loadAllPeerIDs(ctx)
	for _, pid := range allPeerIDs {
		r := loadTrust(ctx, pid)
		if r.State == PeerStateQuarantined {
			_ = monitorAndRemovePeer(ctx, pid)
		}
	}

	return nil
}

// txTimestampMs returns a deterministic millisecond timestamp from the Fabric
// transaction timestamp, which is identical on all endorsing peers.
// Use this everywhere time.Now() is currently called inside chaincode.
func txTimestampMs(ctx contractapi.TransactionContextInterface) int64 {
    ts, err := ctx.GetStub().GetTxTimestamp()
    if err != nil || ts == nil {
        return 0
    }
    return ts.AsTime().UnixMilli()
}

// isBootstrapComplete returns true when ≥ np peers have τk ≥ τ^gt_min.
// MF-02: gates mitigation enforcement during early bootstrap rounds.
func (t *TemporalEchoMitigator) isBootstrapComplete(ctx contractapi.TransactionContextInterface) bool {
	allPeers := loadAllPeerIDs(ctx)
	np := 3*FaultToleranceF + 1
	qualified := 0
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.Score >= TrustMinGT && !r.Flagged {
			qualified++
		}
	}
	return qualified >= np
}

// collectApprovingPeers extracts the submitting peer IDs from a set of alerts.
// Used by TE-01 PBFT gate to build the "approving" set for checkPBFTTrustWeight.
func collectApprovingPeers(alerts []DetectionEvent) []string {
	seen := make(map[string]bool)
	var peers []string
	for _, a := range alerts {
		if a.PeerID != "" && !seen[a.PeerID] {
			seen[a.PeerID] = true
			peers = append(peers, a.PeerID)
		}
	}
	return peers
}

// readBlockCounter reads ANCHOR_CTR for ConsensusRound tracking (ST-02).
func readBlockCounter(ctx contractapi.TransactionContextInterface) uint64 {
	data, err := ctx.GetStub().GetState("ANCHOR_CTR")
	if err != nil || len(data) == 0 {
		return 0
	}
	var v uint64
	fmt.Sscanf(string(data), "%d", &v)
	return v
}

// splitComma splits a comma-separated string into trimmed tokens.
func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			token := s[start:i]
			// trim spaces
			for len(token) > 0 && token[0] == ' ' {
				token = token[1:]
			}
			for len(token) > 0 && token[len(token)-1] == ' ' {
				token = token[:len(token)-1]
			}
			if len(token) > 0 {
				result = append(result, token)
			}
			start = i + 1
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC QUERY / ADMIN FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

// ClearReauth clears the re-authentication block and removes the DROP FlowMod.
// FM-01: after re-authentication, the DROP rule must be explicitly deleted from
// the OpenFlow switch. Without a DELETE FlowMod, the vehicle stays isolated
// even after ClearReauth succeeds.
func (t *TemporalEchoMitigator) ClearReauth(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) error {
	key := "REAUTH:" + vehicleID
	data, err := ctx.GetStub().GetState(key)
	if err != nil || data == nil {
		return fmt.Errorf("ClearReauth: no flag for vehicle %s", vehicleID)
	}
	var flag ReauthFlag
	json.Unmarshal(data, &flag)
	flag.Cleared = true
	updated, _ := json.Marshal(flag)
	if err := ctx.GetStub().PutState(key, updated); err != nil {
		return err
	}

	// FM-01: write a DELETE FlowMod to remove the DROP rule from the OpenFlow switch
	mac := lookupVehicleMAC(ctx, vehicleID)
	deleteFM := PendingFlowMod{
		EntryID:  fmt.Sprintf("FLOWMOD_DELETE_DROP_%s_%d", vehicleID, txTimestampMs(ctx)),
		VehicleID: vehicleID,
		Action:   "DELETE",
		Priority: 65000,
		Match:    map[string]interface{}{"eth_src": mac},
		FlowActions: []map[string]interface{}{},
	}
	return writePendingFlowMod(ctx, deleteFM)
}

// QueryMitigationHistory returns all MitigationLogEntry records for vehicleID.
func (t *TemporalEchoMitigator) QueryMitigationHistory(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) ([]MitigationLogEntry, error) {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"MITIGATION_LOG","vehicle_id":"%s"}}`, vehicleID)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var entries []MitigationLogEntry
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var entry MitigationLogEntry
		if err := json.Unmarshal(qr.Value, &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// GetReauthFlag returns the current re-authentication flag for a vehicle.
func (t *TemporalEchoMitigator) GetReauthFlag(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) (*ReauthFlag, error) {
	data, err := ctx.GetStub().GetState("REAUTH:" + vehicleID)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var flag ReauthFlag
	json.Unmarshal(data, &flag)
	return &flag, nil
}

// GetPendingFlowMod reads a PendingFlowMod record by exact key.
func (t *TemporalEchoMitigator) GetPendingFlowMod(
	ctx contractapi.TransactionContextInterface,
	key string,
) (string, error) {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("GetPendingFlowMod: ledger read failed: %v", err)
	}
	if data == nil {
		return "", nil
	}
	return string(data), nil
}

// GetAllPendingFlowMods returns every PENDING_FLOWMOD record for catch-up replay (T-2).
func (t *TemporalEchoMitigator) GetAllPendingFlowMods(
	ctx contractapi.TransactionContextInterface,
) ([]PendingFlowMod, error) {
	qs := `{"selector":{"doc_type":"PENDING_FLOWMOD"}}`
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, fmt.Errorf("GetAllPendingFlowMods: query failed: %v", err)
	}
	defer iter.Close()

	var fms []PendingFlowMod
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var fm PendingFlowMod
		if json.Unmarshal(qr.Value, &fm) == nil {
			fms = append(fms, fm)
		}
	}
	return fms, nil
}

// AcknowledgeFlowMod marks a PendingFlowMod as executed (T-2).
func (t *TemporalEchoMitigator) AcknowledgeFlowMod(
	ctx contractapi.TransactionContextInterface,
	entryID string,
) error {
	data, err := ctx.GetStub().GetState(entryID)
	if err != nil || data == nil {
		return fmt.Errorf("AcknowledgeFlowMod: record %s not found", entryID)
	}
	var fm PendingFlowMod
	if err := json.Unmarshal(data, &fm); err != nil {
		return err
	}
	fm.Executed = true
	fm.ExecutedAtMs = txTimestampMs(ctx)
	updated, _ := json.Marshal(fm)
	return ctx.GetStub().PutState(entryID, updated)
}

// QueryDetectionEventsByVehicle returns all DetectionEvent records for a vehicle (T-5).
func (t *TemporalEchoMitigator) QueryDetectionEventsByVehicle(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) ([]DetectionEvent, error) {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"DETECTION_EVENT","vehicle_id":"%s"}}`, vehicleID)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var events []DetectionEvent
	for iter.HasNext() {
		qr, _ := iter.Next()
		var e DetectionEvent
		if json.Unmarshal(qr.Value, &e) == nil {
			events = append(events, e)
		}
	}
	return events, nil
}

// QueryBeaconEvidenceByInterval returns beacon evidence for a given interval (T-5).
func (t *TemporalEchoMitigator) QueryBeaconEvidenceByInterval(
	ctx contractapi.TransactionContextInterface,
	intervalTSStr string,
) ([]BeaconEvidenceRecord, error) {
	var intervalTS int64
	fmt.Sscanf(intervalTSStr, "%d", &intervalTS)
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":%d}}`, intervalTS)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var records []BeaconEvidenceRecord
	for iter.HasNext() {
		qr, _ := iter.Next()
		var r BeaconEvidenceRecord
		if json.Unmarshal(qr.Value, &r) == nil {
			records = append(records, r)
		}
	}
	return records, nil
}

// GetDivergenceDelta exposes the divergence check result for a controller (T-5).
func (t *TemporalEchoMitigator) GetDivergenceDelta(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	intervalTSStr string,
) (map[string]interface{}, error) {
	var intervalTS int64
	fmt.Sscanf(intervalTSStr, "%d", &intervalTS)
	claim := ControllerTopologyClaim{ControllerID: controllerID, IntervalTS: intervalTS}
	key := fmt.Sprintf("CTRL_TOPO:%s:%d", controllerID, intervalTS)
	data, err := ctx.GetStub().GetState(key)
	if err == nil && data != nil {
		json.Unmarshal(data, &claim)
	}
	delta, deltaThresh := computeDivergence(ctx, claim)
	return map[string]interface{}{
		"delta":        delta,
		"delta_thresh": deltaThresh,
		"attack":       delta > deltaThresh,
	}, nil
}

// RegisterController adds a controller to the registry (B-1).
func (t *TemporalEchoMitigator) RegisterController(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	zoneID string,
) error {
	ctrls := loadControllerRegistry(ctx)
	for _, c := range ctrls {
		if c == controllerID {
			return nil
		}
	}
	ctrls = append(ctrls, controllerID)
	data, _ := json.Marshal(ctrls)
	if err := ctx.GetStub().PutState("CTRL_REGISTRY", data); err != nil {
		return err
	}
	r := loadCtrlTrust(ctx, controllerID)
	r.ZoneID = zoneID
	return saveCtrlTrust(ctx, r)
}

// RegisterPeerKey stores a peer's ML-DSA-87 (Dilithium5) public key (T-4).
func (t *TemporalEchoMitigator) RegisterPeerKey(
	ctx contractapi.TransactionContextInterface,
	peerID string,
	pubKeyHex string,
) error {
	if peerID == "" || pubKeyHex == "" {
		return fmt.Errorf("RegisterPeerKey: peerID and pubKeyHex are required")
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("RegisterPeerKey: invalid hex pubKey: %v", err)
	}
	return ctx.GetStub().PutState("PEERKEY:"+peerID, pubKeyBytes)
}

// GetLatestControllerReassignment returns the most recent reassignment record (E-3).
func (t *TemporalEchoMitigator) GetLatestControllerReassignment(
	ctx contractapi.TransactionContextInterface,
	removedCtrlID string,
) (*ControllerReassignment, error) {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"CTRL_REASSIGNMENT","removed_ctrl_id":"%s"},`+
			`"sort":[{"assigned_at_ms":"desc"}],"limit":1}`,
		removedCtrlID)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	if iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r ControllerReassignment
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		return &r, nil
	}
	return nil, nil
}

// SetSimParams stores simulation parameters on the ledger (VF-02).
// Called at bootstrap to configure verifyQuorum thresholds and scenario mode.
// noRSUModeStr: "1" for no-RSU scenarios (1,3,5,7,9,11) — selectPeers uses
// OBU-only active set. "0" or "" for with-RSU scenarios (RSU-only active set).
func (t *TemporalEchoMitigator) SetSimParams(
	ctx contractapi.TransactionContextInterface,
	rCommMetersStr string,
	rssiMinDBmStr string,
	noRSUModeStr string,
) error {
	if rCommMetersStr != "" {
		ctx.GetStub().PutState("SIM_RCOMM", []byte(rCommMetersStr))
	}
	if rssiMinDBmStr != "" {
		ctx.GetStub().PutState("SIM_RSSI_MIN", []byte(rssiMinDBmStr))
	}
	if noRSUModeStr == "1" {
		ctx.GetStub().PutState("SIM_NO_RSU_MODE", []byte("1"))
	} else {
		ctx.GetStub().PutState("SIM_NO_RSU_MODE", []byte("0"))
	}
	return nil
}

// SetMobilityParams stores mobility parameters used by computeTMinMs (VF-03).
// tPBFTMsStr  — PBFT round-trip latency in ms (default 100)
// vMaxKmhStr  — maximum vehicle speed in km/h (default 80)
// Called at bootstrap alongside SetSimParams.
func (t *TemporalEchoMitigator) SetMobilityParams(
	ctx contractapi.TransactionContextInterface,
	tPBFTMsStr string,
	vMaxKmhStr string,
) error {
	if tPBFTMsStr != "" {
		ctx.GetStub().PutState("SIM_TPBFT_MS", []byte(tPBFTMsStr))
	}
	if vMaxKmhStr != "" {
		ctx.GetStub().PutState("SIM_VMAX_KMH", []byte(vMaxKmhStr))
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  EVIDENCE SUBMISSION
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) SubmitIndividualSigEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceJSON string,
) error {
	var e IndividualSigEvidence
	if err := json.Unmarshal([]byte(evidenceJSON), &e); err != nil {
		return fmt.Errorf("SubmitIndividualSigEvidence: parse error: %v", err)
	}
	if e.VehicleID == "" || e.SignerID == "" {
		return fmt.Errorf("SubmitIndividualSigEvidence: vehicle_id and signer_id are required")
	}
	e.DocType = "SIG_EVIDENCE"
	if e.TS == 0 {
		e.TS = txTimestampMs(ctx)
	}
	if !verifyMLDSA87Sig(e.Signature, e.Message, e.PubKey) {
		return fmt.Errorf("SubmitIndividualSigEvidence: invalid ML-DSA-87 (Dilithium5) signature from signer %s", e.SignerID)
	}
	key := fmt.Sprintf("SIG_EVIDENCE:%s:%d:%s", e.VehicleID, e.TS, e.SignerID)
	data, _ := json.Marshal(e)
	return ctx.GetStub().PutState(key, data)
}

func (t *TemporalEchoMitigator) SubmitWitnessRecord(
	ctx contractapi.TransactionContextInterface,
	witnessJSON string,
) error {
	var w WitnessRecord
	if err := json.Unmarshal([]byte(witnessJSON), &w); err != nil {
		return fmt.Errorf("SubmitWitnessRecord: parse error: %v", err)
	}
	if w.VehicleID == "" || w.ReporterID == "" {
		return fmt.Errorf("SubmitWitnessRecord: vehicle_id and reporter_id are required")
	}
	w.DocType = "WITNESS"
	// Verify ML-DSA-87 (Dilithium5) signature at submission to prevent forged records
	// polluting the immutable ledger (Eq. 3.28).
	if len(w.Signature) > 0 || len(w.PubKey) > 0 {
    	if !verifyMLDSA87Sig(w.Signature, w.Message, w.PubKey) {
        	return fmt.Errorf("SubmitWitnessRecord: invalid ML-DSA-87 (Dilithium5) signature from reporter %s", w.ReporterID)
    	}
	}
	if w.TS == 0 {
		w.TS = txTimestampMs(ctx)
	}
	key := fmt.Sprintf("WITNESS:%s:%d:%s", w.VehicleID, w.TS, w.ReporterID)
	data, _ := json.Marshal(w)
	return ctx.GetStub().PutState(key, data)
}

func (t *TemporalEchoMitigator) SubmitVehicleMAC(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
	macAddress string,
) error {
	if vehicleID == "" || macAddress == "" {
		return fmt.Errorf("SubmitVehicleMAC: vehicleID and macAddress are required")
	}
	return ctx.GetStub().PutState("VMAC_"+vehicleID, []byte(macAddress))
}

// ═══════════════════════════════════════════════════════════════════════════
//  PRIVATE LEDGER HELPERS
// ═══════════════════════════════════════════════════════════════════════════

func getPeerPubKey(ctx contractapi.TransactionContextInterface, peerID string) []byte {
	data, err := ctx.GetStub().GetState("PEERKEY:" + peerID)
	if err != nil || data == nil {
		return nil
	}
	return data
}

func loadControllerRegistry(ctx contractapi.TransactionContextInterface) []string {
	data, err := ctx.GetStub().GetState("CTRL_REGISTRY")
	if err != nil || data == nil {
		return nil
	}
	var ctrls []string
	json.Unmarshal(data, &ctrls)
	return ctrls
}

func marshalStringSlice(s []string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// getSignatureEvidence returns IndividualSigEvidence for vehicleID within the
// evidence window [alertTS - Tb, alertTS + Tb].
func getSignatureEvidence(ctx contractapi.TransactionContextInterface, vehicleID string, alertTS int64) []IndividualSigEvidence {
	const Tb int64 = 100
	low := alertTS - Tb
	high := alertTS + Tb
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"SIG_EVIDENCE","vehicle_id":"%s","ts_ms":{"$gte":%d,"$lte":%d}}}`,
		vehicleID, low, high)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil
	}
	defer iter.Close()
	var evidence []IndividualSigEvidence
	for iter.HasNext() {
		qr, _ := iter.Next()
		var e IndividualSigEvidence
		if json.Unmarshal(qr.Value, &e) == nil {
			evidence = append(evidence, e)
		}
	}
	return evidence
}

func getWitnesses(
    ctx contractapi.TransactionContextInterface,
    vehicleID string,
    alertTS int64,
) []WitnessRecord {
    const Tb int64 = 100
    low  := alertTS - Tb
    high := alertTS + Tb
    qs := fmt.Sprintf(
        `{"selector":{"doc_type":"WITNESS","vehicle_id":"%s",`+
        `"ts_ms":{"$gte":%d,"$lte":%d}}}`, vehicleID, low, high)
    iter, err := ctx.GetStub().GetQueryResult(qs)
    if err != nil {
        return nil
    }
    defer iter.Close()
    var witnesses []WitnessRecord
    for iter.HasNext() {
        qr, _ := iter.Next()
        var w WitnessRecord
        if json.Unmarshal(qr.Value, &w) == nil {
            witnesses = append(witnesses, w)
        }
    }
    return witnesses
}

func getLinkEndpoint(ctx contractapi.TransactionContextInterface, vehicleID string) (float64, float64) {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"BEACON_EVIDENCE","observations":{"$elemMatch":{"vehicle_id":"%s"}}}}`,
		vehicleID)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil || iter == nil {
		return 0, 0
	}
	defer iter.Close()
	if iter.HasNext() {
		qr, _ := iter.Next()
		var rec BeaconEvidenceRecord
		if json.Unmarshal(qr.Value, &rec) == nil {
			for _, obs := range rec.Observations {
				if obs.VehicleID == vehicleID {
					return obs.GPSLat, obs.GPSLon
				}
			}
		}
	}
	return 0, 0
}

func getAllBeaconEvidence(
    ctx contractapi.TransactionContextInterface,
    intervalTS int64,
) []BeaconEvidenceRecord {
    // Filter to the specific beacon interval under dispute.
    // If intervalTS is 0 (unknown), fall back to all records (degraded mode).
    var qs string
    if intervalTS > 0 {
        const Tb int64 = 100
        low  := intervalTS - Tb
        high := intervalTS + Tb
        qs = fmt.Sprintf(
            `{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":{"$gte":%d,"$lte":%d}}}`,
            low, high)
    } else {
        qs = `{"selector":{"doc_type":"BEACON_EVIDENCE"}}`
    }
    iter, err := ctx.GetStub().GetQueryResult(qs)
    if err != nil {
        return nil
    }
    defer iter.Close()
    var records []BeaconEvidenceRecord
    for iter.HasNext() {
        qr, _ := iter.Next()
        var r BeaconEvidenceRecord
        if json.Unmarshal(qr.Value, &r) == nil {
            records = append(records, r)
        }
    }
    return records
}

func invalidateFalsePaths(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	key := fmt.Sprintf("FALSE_PATHS:%s", vehicleID)
	marker := map[string]interface{}{
		"vehicle_id":     vehicleID,
		"invalidated":    true,
		"invalidated_at": txTimestampMs(ctx),
	}
	data, _ := json.Marshal(marker)
	return ctx.GetStub().PutState(key, data)
}

func flagReauth(ctx contractapi.TransactionContextInterface, vehicleID, reason string) {
	flag := ReauthFlag{
		VehicleID: vehicleID,
		FlaggedTS: txTimestampMs(ctx),
		Reason:    reason,
		Cleared:   false,
		DocType:   "REAUTH_FLAG",
	}
	data, _ := json.Marshal(flag)
	ctx.GetStub().PutState("REAUTH:"+vehicleID, data)
}

func revokeSessionKey(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	payload, _ := json.Marshal(map[string]string{
		"vehicle_id": vehicleID,
		"action":     "REVOKE_SESSION_KEY",
	})
	return ctx.GetStub().SetEvent("KeyRevocation", payload)
}

// publishBlacklistBeacon writes a BlacklistBeacon record to the ledger and
// emits BlacklistBeaconPublished (paper §Conflict Resolution, item 2 — Tier-2 path).
// The cert fingerprint is derived from the vehicle's VehicleKeyRecord on ledger.
// V2V propagation via DSRC is a deployment-time concern (future work).
func publishBlacklistBeacon(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	nowMs := txTimestampMs(ctx)

	// Derive cert fingerprint from stored key bytes (or use TxID as simulation placeholder).
	fingerprint := "SIM_FINGERPRINT:" + vehicleID
	keyBytes, _ := ctx.GetStub().GetState("KEYSTORE:" + vehicleID)
	if len(keyBytes) > 0 {
		h := fmt.Sprintf("%x", keyBytes[:8]) // first 8 bytes as compact hex fingerprint
		fingerprint = h
	}

	beacon := BlacklistBeacon{
		VehicleID:       vehicleID,
		CertFingerprint: fingerprint,
		PublishedAtMs:   nowMs,
		PublisherPeerID: ctx.GetStub().GetTxID(),
		DocType:         "BLACKLIST_BEACON",
	}
	data, _ := json.Marshal(beacon)
	if err := ctx.GetStub().PutState("BLACKLIST_BEACON:"+vehicleID, data); err != nil {
		return err
	}
	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":             "BLACKLIST_BEACON_PUBLISHED",
		"vehicle_id":       vehicleID,
		"cert_fingerprint": fingerprint,
		"published_at_ms":  nowMs,
		"note":             "Tier-2 V2V propagation via DSRC is future work",
	})
	return ctx.GetStub().SetEvent("BlacklistBeaconPublished", evPayload)
}

// publishControllerRevokedBeacon writes a ControllerRevokedBeacon to the ledger
// and emits ControllerRevokedBeaconPublished.
//
// No-RSU path (thesis §No-RSU controller removal):
//   step ii  — beacon propagates via OBU V2V peers telling vehicles to stop
//               submitting topology updates to Cj (credential already revoked)
//   step iii — Ck* reads the beacon on the ledger and begins actively soliciting
//               topology observations from vehicles through its OWN V2X interface
//               (direction: Ck* solicits FROM vehicles, not vehicles soliciting from Ck*)
//
// Because no RSU beacon evidence exists in no-RSU mode, Ck* must rebuild topology
// from scratch.  Routing degrades to distributed vehicle-level decisions for
// InterimFallbackIntervals = ⌈Llink/Tb⌉ beacon intervals until Ck* has sufficient
// observations to resume centralised routing.
//
// With-RSU path: also published, but the southbound switchover in that case is
// simulated via FlowMod OVERRIDE rules installed by runMitigation (see comment
// in CheckControllerTrustAndReassign for the documented deviation).
func publishControllerRevokedBeacon(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	backupCtrlID string,
) error {
	nowMs := txTimestampMs(ctx)

	// Compute ⌈Llink/Tb⌉ — the interim degraded-routing window (no-RSU path only).
	// Llink = 2·r_comm / v_max (ms);  Tb = 100 ms beacon interval.
	rCommM := loadFloatParam(ctx, "SIM_RCOMM", 300.0)
	vMaxKmh := loadFloatParam(ctx, "SIM_VMAX_KMH", 80.0)
	vMaxMperMs := vMaxKmh / 3600.0
	lLinkMs := (2.0 * rCommM) / vMaxMperMs
	const tbMs = 100.0
	interimIntervals := int(math.Ceil(lLinkMs / tbMs))

	beacon := ControllerRevokedBeacon{
		ControllerID:            controllerID,
		BackupCtrlID:            backupCtrlID,
		PublishedAtMs:           nowMs,
		PublisherPeerID:         ctx.GetStub().GetTxID(),
		InterimFallbackIntervals: interimIntervals,
		DocType:                 "CTRL_REVOKED_BEACON",
	}
	data, _ := json.Marshal(beacon)
	if err := ctx.GetStub().PutState("CTRL_REVOKED_BEACON:"+controllerID, data); err != nil {
		return err
	}
	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":                      "CTRL_REVOKED_BEACON_PUBLISHED",
		"controller_id":             controllerID,
		"backup_ctrl":               backupCtrlID,
		"published_at":              nowMs,
		"interim_fallback_intervals": interimIntervals,
		// Ck* actively solicits topology FROM vehicles via its own V2X interface —
		// vehicles do not initiate contact with Ck*.
		"solicitation_direction": "backup_controller_solicits_from_vehicles",
		"note": "Ck* self-solicits topology via V2X; vehicles fall back to distributed routing for interim_fallback_intervals beacon intervals",
	})
	return ctx.GetStub().SetEvent("ControllerRevokedBeaconPublished", evPayload)
}

// revokeVehicleCert writes a CERT_REVOKED:<vehicle_id> ledger record and emits
// VehicleCertRevocationRequested so eventListener.js can action the CA call.
// Thesis §vehicle removal step iv: "Vk's CA certificate is revoked, permanently
// excluding it until manual re-admission through the consortium CA."
// Mirrors the peer (CertRevocationRequested) and controller
// (ControllerCredentialRevocationRequested) revocation patterns.
func revokeVehicleCert(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	nowMs := txTimestampMs(ctx)
	record := map[string]interface{}{
		"vehicle_id":    vehicleID,
		"action":        "REVOKE_VEHICLE_CERTIFICATE",
		"revoked_at_ms": nowMs,
		"reason":        "attack_confirmed_ttw_bshh",
	}
	data, _ := json.Marshal(record)
	if err := ctx.GetStub().PutState("CERT_REVOKED:"+vehicleID, data); err != nil {
		return err
	}
	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":          "VEHICLE_CERT_REVOCATION_REQUESTED",
		"vehicle_id":    vehicleID,
		"revoked_at_ms": nowMs,
	})
	return ctx.GetStub().SetEvent("VehicleCertRevocationRequested", evPayload)
}

// triggerRSUZoneReassignment handles the data-plane role of malicious-RSU removal:
// partial zone-coverage reassignment to an adjacent trusted controller.
// Runs in parallel with the 3-stage peer-demotion pipeline (consortium-peer role).
//
// Selection rule: prefers a controller whose ZoneID matches the compromised RSU's
// zone (closest proxy for geographic adjacency), falling back to the highest-trust
// controller above τCmin if no zone match exists.
//
// This selection rule is an implementation design choice for an underspecified
// thesis mechanism. The thesis says only "transfers rk's coverage area to the
// adjacent trusted controller" — singular, geographic-adjacency-based — without
// specifying how adjacency is determined or how ties are broken. The zone-ID-match
// heuristic is a reasonable interpretation of "adjacent," but it is NOT the same
// as the Eq. 3.43 argmax-τCk backup-controller logic used in
// CheckControllerTrustAndReassign (which covers controller-removal, a different
// mechanism). The thesis does not say to reuse that selection function here.
func triggerRSUZoneReassignment(
	ctx contractapi.TransactionContextInterface,
	compromisedRSUID string,
	zoneID string,
) error {
	allCtrls := loadControllerRegistry(ctx)
	bestID := ""
	bestScore := -1.0
	for _, cid := range allCtrls {
		r := loadCtrlTrust(ctx, cid)
		if r.Score <= TrustCtrlMin {
			continue
		}
		if r.ZoneID == zoneID && zoneID != "" {
			// Zone-ID match: treat as geographically adjacent — use immediately.
			bestID = cid
			bestScore = r.Score
			break
		}
		if r.Score > bestScore {
			bestID = cid
			bestScore = r.Score
		}
	}
	if bestID == "" {
		return fmt.Errorf("triggerRSUZoneReassignment: no eligible controller above τCmin for zone %q", zoneID)
	}

	nowMs := txTimestampMs(ctx)
	reassignment := RSUZoneReassignment{
		CompromisedRSUID: compromisedRSUID,
		ZoneID:           zoneID,
		BackupCtrlID:     bestID,
		BackupCtrlScore:  bestScore,
		AssignedAtMs:     nowMs,
		DocType:          "RSU_ZONE_REASSIGNMENT",
	}
	data, _ := json.Marshal(reassignment)
	key := fmt.Sprintf("RSU_ZONE_REASSIGN:%s:%d", compromisedRSUID, nowMs)
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}
	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":              "RSU_ZONE_REASSIGNMENT_TRIGGERED",
		"compromised_rsu":   compromisedRSUID,
		"zone_id":           zoneID,
		"backup_controller": bestID,
		"backup_score":      bestScore,
		"assigned_at_ms":    nowMs,
	})
	return ctx.GetStub().SetEvent("RSUZoneReassignmentTriggered", evPayload)
}

func commitLog(ctx contractapi.TransactionContextInterface, entry MitigationLogEntry) {
    entry.DocType = "MITIGATION_LOG"
    // Use EntryID (UUID) not vehicle+timestamp, to guarantee uniqueness even
    // when the same vehicle has multiple alerts in one beacon interval.
    if entry.EntryID == "" {
        entry.EntryID = fmt.Sprintf("%s-%d", entry.VehicleID, entry.AlertTS)
    }
    key := fmt.Sprintf("MITIG:%s", entry.EntryID)
    data, _ := json.Marshal(entry)
    ctx.GetStub().PutState(key, data)
}

// generateUUID derives a deterministic ID from the transaction ID and an in-memory
// counter. The counter is per-TxID and stored in a package-level map so that
// repeated calls within the same transaction produce unique, incrementing suffixes.
// GetState/PutState cannot be used for this because GetState reads the snapshot from
// the start of the transaction and cannot see previous PutState writes in the same tx.
func generateUUID(ctx contractapi.TransactionContextInterface) string {
    txID := ctx.GetStub().GetTxID()
    txUUIDMu.Lock()
    txUUIDCounters[txID]++
    ctr := txUUIDCounters[txID]
    txUUIDMu.Unlock()
    return fmt.Sprintf("%s-%d", txID, ctr)
}

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════════

func main() {
	chaincode, err := contractapi.NewChaincode(&TemporalEchoMitigator{})
	if err != nil {
		panic(fmt.Sprintf("Error creating TemporalEchoMitigator chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting TemporalEchoMitigator chaincode: %v", err))
	}
}
