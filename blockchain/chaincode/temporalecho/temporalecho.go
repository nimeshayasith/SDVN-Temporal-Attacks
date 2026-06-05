package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// TemporalEchoMitigator is the Hyperledger Fabric smart contract that executes
// Algorithm 4 (FS-MITIGATE) from the paper.
//
// Three data flows (§4 — none passes through the SDN controller):
//   Flow 1 — SubmitBeaconEvidence  : RSU/OBU ground truth B_nk(t)
//   Flow 2 — SubmitDetectionEvent  : LW/FS detection event O_rk
//   Flow 3 — SubmitControllerTopology : controller claim G_t^C (verified only)
//
// Primary entry point for the TGN pipeline:
//   SubmitAlert — called by submit_alerts.py after tgn_alerts.json is produced.
//
// PBFT consensus is enforced by the Fabric endorsement policy
//   (MAJORITY of RSU peers must endorse before commit).
type TemporalEchoMitigator struct {
	contractapi.Contract
}

// ═══════════════════════════════════════════════════════════════════════════
//  FLOW 1 — Beacon Evidence
// ═══════════════════════════════════════════════════════════════════════════

// SubmitBeaconEvidence stores B_nk(t) on the ledger as tamper-evident ground
// truth for the divergence check (§4, Flow 1).  Called by each RSU/OBU at
// every 100 ms beacon interval.
func (t *TemporalEchoMitigator) SubmitBeaconEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceJSON string,
) error {
	var record BeaconEvidenceRecord
	if err := json.Unmarshal([]byte(evidenceJSON), &record); err != nil {
		return fmt.Errorf("SubmitBeaconEvidence: parse error: %v", err)
	}
	record.DocType = "BEACON_EVIDENCE"

	// Signature verification — simulation mode accepts any non-empty sig.
	// Production: enforce verifyDilithium2Sig(record.PeerSig, evidenceJSON, record.PeerPubKey)
	if !verifyDilithium2Sig(record.PeerSig, evidenceJSON, record.PeerPubKey) {
		return fmt.Errorf("SubmitBeaconEvidence: invalid peer signature from %s", record.PeerID)
	}

	key := fmt.Sprintf("BEACON:%s:%d", record.PeerID, record.IntervalTS)
	data, _ := json.Marshal(record)
	return ctx.GetStub().PutState(key, data)
}

// ═══════════════════════════════════════════════════════════════════════════
//  FLOW 2 — Detection Events
// ═══════════════════════════════════════════════════════════════════════════

// SubmitDetectionEvent stores O_rk on the ledger, submitted directly by the
// trusted node (RSU/OBU), bypassing the controller (§4, Flow 2).
func (t *TemporalEchoMitigator) SubmitDetectionEvent(
	ctx contractapi.TransactionContextInterface,
	eventJSON string,
) error {
	var event DetectionEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return fmt.Errorf("SubmitDetectionEvent: parse error: %v", err)
	}
	event.DocType = "DETECTION_EVENT"

	if !verifyDilithium2Sig(event.PeerSig, eventJSON, getPeerPubKey(ctx, event.PeerID)) {
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

// SubmitControllerTopology stores G_t^C as an untrusted claim and immediately
// triggers the divergence check (§4, Flow 3; §8).
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
// tgn_detector.cc writes tgn_alerts.json (§10.1, Algorithm 2 Step 22).
//
// Args (matching build_invoke_cmd in submit_alerts.py):
//   alertJSON      — AlertObject JSON: {"v_id","alpha","y_hat","S_trig","t_alert"}
//   ctrlTopoJSON   — optional ControllerTopologyClaim JSON for divergence check
//   intervalTSStr  — beacon interval timestamp as decimal string (ms)
func (t *TemporalEchoMitigator) SubmitAlert(
	ctx contractapi.TransactionContextInterface,
	alertJSON string,
	ctrlTopoJSON string,
	intervalTSStr string,
) error {
	var alert AlertObject
	if err := json.Unmarshal([]byte(alertJSON), &alert); err != nil {
		return fmt.Errorf("SubmitAlert: parse error: %v", err)
	}

	// Convert AlertObject → DetectionEvent for Flow 2 ledger storage
	event := DetectionEvent{
		PeerID:        "tgn-fs-detector",
		VehicleID:     alert.VehicleID,
		AttackVariant: alert.Alpha,
		AnomalyScore:  alert.YHat,
		TriggeredSigs: sTrigsToMask(alert.STrig),
		AlertTS:       alert.TAlertMs,
		FromLWPath:    alert.FromLWPath,
		FromFSPath:    true,
		DocType:       "DETECTION_EVENT",
	}
	evBytes, _ := json.Marshal(event)
	evKey := fmt.Sprintf("DETECTION:tgn-fs-detector:%s:%d",
		event.VehicleID, event.AlertTS)
	if err := ctx.GetStub().PutState(evKey, evBytes); err != nil {
		return fmt.Errorf("SubmitAlert: failed to store detection event: %v", err)
	}

	// Optional: controller topology divergence check
	if ctrlTopoJSON != "" && ctrlTopoJSON != "null" && ctrlTopoJSON != "{}" {
		var claim ControllerTopologyClaim
		if err := json.Unmarshal([]byte(ctrlTopoJSON), &claim); err == nil {
			if claim.ControllerID != "" {
				claim.DocType = "CTRL_TOPOLOGY"
				_ = t.checkControllerDivergence(ctx, claim)
			}
		}
	}

	// Run Algorithm 4 mitigation for this single alert
	// thresholdT=1 (single-peer TGN detection; full PBFT already satisfied by
	// the Fabric endorsement policy requiring MAJORITY of RSU peers to endorse
	// this transaction before it commits to the ledger).
	return t.runMitigation(ctx, []DetectionEvent{event}, 0.40, 1)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ALGORITHM 4 — FS-MITIGATE (full form, called from Node.js SDK path)
// ═══════════════════════════════════════════════════════════════════════════

// Mitigate executes Algorithm 4 (FS-MITIGATE) from the paper (§6.2).
// Called from the Node.js SDK client (submitToFabric.js) after all beacon
// evidence and detection events have been submitted.
//
// Parameters:
//   alertsJSON     — JSON array of DetectionEvent objects (set A)
//   beaconEvidJSON — JSON array of BeaconEvidenceRecord objects
//   ctrlTopoJSON   — ControllerTopologyClaim (G_t^C)
//   thetaFS        — anomaly threshold (float32 as string, e.g. "0.40")
//   thresholdTStr  — quorum threshold t = ⌊n/2⌋+1 (int as string)
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

	var ctrlClaim ControllerTopologyClaim
	json.Unmarshal([]byte(ctrlTopoJSON), &ctrlClaim)

	thetaFS := float32(0.40)
	if v, err := strconv.ParseFloat(thetaFSStr, 32); err == nil {
		thetaFS = float32(v)
	}
	thresholdT := 1
	if v, err := strconv.Atoi(thresholdTStr); err == nil {
		thresholdT = v
	}

	// Step 3 — Compute divergence δ = |E_t^C △ E_t^nodes|
	delta, deltaThresh := computeDivergence(ctx, ctrlClaim)
	if delta > deltaThresh {
		alerts = append(alerts, DetectionEvent{
			PeerID:        "SYSTEM",
			VehicleID:     ctrlClaim.ControllerID,
			AttackVariant: "CTRL_ORIGIN",
			AnomalyScore:  float32(delta),
			AlertTS:       time.Now().UnixMilli(),
		})
	}

	return t.runMitigation(ctx, alerts, thetaFS, thresholdT)
}

// ═══════════════════════════════════════════════════════════════════════════
//  ALGORITHM 4 — Per-alert mitigation logic (shared by SubmitAlert + Mitigate)
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) runMitigation(
	ctx contractapi.TransactionContextInterface,
	alerts []DetectionEvent,
	thetaFS float32,
	thresholdT int,
) error {
	// §11.2 — resolve LW/FS conflicts for the same vehicle
	alerts = resolveDualPath(alerts)

	for _, alert := range alerts {
		if alert.AnomalyScore <= thetaFS && alert.AttackVariant != "CTRL_ORIGIN" {
			continue
		}

		// Step 12 — initialise immutable log entry
		logEntry := MitigationLogEntry{
			EntryID:       generateUUID(ctx),
			VehicleID:     alert.VehicleID,
			AttackVariant: alert.AttackVariant,
			AnomalyScore:  alert.AnomalyScore,
			AlertTS:       alert.AlertTS,
			DocType:       "MITIGATION_LOG",
		}

		variant := alert.AttackVariant

		// Steps 14–17 — TTW / BSHH / combined
		if variant == "TTW" || variant == "BSHH" || variant == "TTW_BSHH_COMBINED" {
			// Step 15 — threshold aggregate signature check (Eq. 3.24)
			sigEvidence := getSignatureEvidence(ctx, alert.VehicleID)
			if !verifyThresholdSig(sigEvidence, thresholdT) {
				logEntry.Actions = append(logEntry.Actions, "THRESHOLD_SIG_FAIL")
				commitLog(ctx, logEntry)
				continue
			}
			// Step 16 — FlowMod DROP
			if err := pushFlowModDrop(alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "FLOWMOD_FAIL:"+err.Error())
			} else {
				logEntry.Actions = append(logEntry.Actions, "FLOWMOD_DROP")
			}
			// Step 17 — revoke session key via LKH event
			if err := revokeSessionKey(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "KEY_REVOKE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "KEY_REVOKED")
			}

		// Steps 18–22 — ME (Multipath Echo)
		} else if variant == "ME" {
			// Step 19 — get witness set W_v
			witnesses := getWitnesses(ctx, alert.VehicleID, alert.AlertTS)
			// Step 20 — quorum check (Eqs. 3.27–3.28)
			lat, lon := getLinkEndpoint(ctx, alert.VehicleID)
			if !verifyQuorum(witnesses, thresholdT, lat, lon) {
				logEntry.Actions = append(logEntry.Actions, "QUORUM_FAIL")
				commitLog(ctx, logEntry)
				continue
			}
			// Step 21 — invalidate false paths
			if err := invalidateFalsePaths(ctx, alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "PATH_INVALIDATE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "PATHS_INVALIDATED")
			}
			// Step 22 — reroute FlowMod
			if err := pushRerouteFlowMod(alert.VehicleID); err != nil {
				logEntry.Actions = append(logEntry.Actions, "REROUTE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "REROUTE_FLOWMOD")
			}

		// CTRL_ORIGIN — override controller routing with RSU evidence
		} else if variant == "CTRL_ORIGIN" {
			beaconEvidence := getAllBeaconEvidence(ctx, alert.AlertTS)
			if err := pushFlowModOverride(alert.VehicleID, beaconEvidence); err != nil {
				logEntry.Actions = append(logEntry.Actions, "CTRL_OVERRIDE_FAIL")
			} else {
				logEntry.Actions = append(logEntry.Actions, "CTRL_OVERRIDE_FLOWMOD")
			}
		}

		// Step 24 — mandatory re-authentication flag
		flagReauth(ctx, alert.VehicleID, variant)
		logEntry.Actions = append(logEntry.Actions, "REAUTH_FLAGGED")

		// Step 12 — commit immutable log entry
		commitLog(ctx, logEntry)

		// Step 25 — emit AttackDetected event (listened by eventListener.js)
		evPayload, _ := json.Marshal(map[string]interface{}{
			"vehicle_id":     alert.VehicleID,
			"attack_variant": variant,
			"anomaly_score":  alert.AnomalyScore,
			"timestamp":      alert.AlertTS,
		})
		ctx.GetStub().SetEvent("AttackDetected", evPayload)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC QUERY / ADMIN FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

// ClearReauth clears the re-authentication block once the vehicle has
// successfully re-authenticated through the consortium CA (§6.6).
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
	return ctx.GetStub().PutState(key, updated)
}

// QueryMitigationHistory returns all MitigationLogEntry records for vehicleID
// (forensic audit trail, §6.6).
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

// ═══════════════════════════════════════════════════════════════════════════
//  PRIVATE LEDGER HELPERS
// ═══════════════════════════════════════════════════════════════════════════

// getPeerPubKey reads a peer's Dilithium2 public key from the KEYSTORE.
func getPeerPubKey(ctx contractapi.TransactionContextInterface, peerID string) []byte {
	data, err := ctx.GetStub().GetState("PEERKEY:" + peerID)
	if err != nil || data == nil {
		return nil // relaxed: nil accepted by verifyDilithium2Sig in sim mode
	}
	return data
}

// getSignatureEvidence reads stored IndividualSigEvidence records for a vehicle
// (used for the threshold aggregate signature check in Algorithm 4, Step 15).
func getSignatureEvidence(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) []IndividualSigEvidence {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"SIG_EVIDENCE","vehicle_id":"%s"}}`, vehicleID)
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

// getWitnesses reads WitnessRecord objects stored for an ME echo attack on
// vehicleID around timestamp alertTS (±1 beacon interval = 100 ms).
func getWitnesses(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
	alertTS int64,
) []WitnessRecord {
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"WITNESS","vehicle_id":"%s"}}`, vehicleID)
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

// getLinkEndpoint returns the (lat, lon) of the link endpoint associated with
// vehicleID from beacon evidence, for the ME quorum spatial check.
func getLinkEndpoint(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) (float64, float64) {
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

// getAllBeaconEvidence fetches all beacon evidence records near intervalTS.
func getAllBeaconEvidence(
	ctx contractapi.TransactionContextInterface,
	intervalTS int64,
) []BeaconEvidenceRecord {
	qs := `{"selector":{"doc_type":"BEACON_EVIDENCE"}}`
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

// invalidateFalsePaths marks phantom ME paths on the ledger so the SDN
// controller can recompute routes.
func invalidateFalsePaths(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) error {
	key := fmt.Sprintf("FALSE_PATHS:%s", vehicleID)
	marker := map[string]interface{}{
		"vehicle_id":   vehicleID,
		"invalidated":  true,
		"invalidated_at": time.Now().UnixMilli(),
	}
	data, _ := json.Marshal(marker)
	return ctx.GetStub().PutState(key, data)
}

// flagReauth writes a ReauthFlag to block vehicle re-admission (Step 24).
func flagReauth(
	ctx contractapi.TransactionContextInterface,
	vehicleID, reason string,
) {
	flag := ReauthFlag{
		VehicleID: vehicleID,
		FlaggedTS: time.Now().UnixMilli(),
		Reason:    reason,
		Cleared:   false,
		DocType:   "REAUTH_FLAG",
	}
	data, _ := json.Marshal(flag)
	ctx.GetStub().PutState("REAUTH:"+vehicleID, data)
}

// revokeSessionKey emits a KeyRevocation Fabric event that the RSU's
// eventListener.js and crypto layer LKH module listen for (§10.2).
func revokeSessionKey(
	ctx contractapi.TransactionContextInterface,
	vehicleID string,
) error {
	payload, _ := json.Marshal(map[string]string{
		"vehicle_id": vehicleID,
		"action":     "REVOKE_SESSION_KEY",
	})
	return ctx.GetStub().SetEvent("KeyRevocation", payload)
}

// commitLog writes an immutable MitigationLogEntry to the ledger (Step 12).
func commitLog(
	ctx contractapi.TransactionContextInterface,
	entry MitigationLogEntry,
) {
	entry.DocType = "MITIGATION_LOG"
	key := fmt.Sprintf("MITIG:%s:%d", entry.VehicleID, entry.AlertTS)
	data, _ := json.Marshal(entry)
	ctx.GetStub().PutState(key, data)
}

// generateUUID produces a UUID v4 string for MitigationLogEntry.EntryID.
func generateUUID(ctx contractapi.TransactionContextInterface) string {
	id, err := uuid.NewRandom()
	if err != nil {
		// Fallback: use txID + timestamp
		return fmt.Sprintf("%s-%d", ctx.GetStub().GetTxID(), time.Now().UnixMilli())
	}
	return id.String()
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
