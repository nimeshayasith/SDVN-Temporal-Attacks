package main

// trust.go — Trust Score Management, Peer Tier Selection, Controller Removal

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ═══════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const (
	TrustDeltaPlus  = 0.05
	TrustDeltaMinus = 0.10
	TrustDeltaCtrl  = 0.20

	TrustMin     = 0.10
	TrustMinGT   = 0.50
	TrustCtrlMin = 0.30

	TrustInitTier1 = 1.00
	TrustInitTier2 = 0.10

	TrustMinDwellMs = 3000
	HWCapacityMinMB = 2048
	FaultToleranceF = 1
)

// ═══════════════════════════════════════════════════════════════════════════
//  TRUST RECORD LEDGER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

func loadTrust(ctx contractapi.TransactionContextInterface, peerID string) TrustRecord {
	data, err := ctx.GetStub().GetState("TRUST:" + peerID)
	if err != nil || data == nil {
		return TrustRecord{
			PeerID:    peerID,
			Score:     TrustInitTier2,
			IsRSUPeer: false,
			DocType:   "TRUST_RECORD",
		}
	}
	var r TrustRecord
	json.Unmarshal(data, &r)
	return r
}

func saveTrust(ctx contractapi.TransactionContextInterface, r TrustRecord) error {
	r.DocType = "TRUST_RECORD"
	r.UpdatedAt = time.Now().UnixMilli()
	data, _ := json.Marshal(r)
	return ctx.GetStub().PutState("TRUST:"+r.PeerID, data)
}

func loadCtrlTrust(ctx contractapi.TransactionContextInterface, ctrlID string) ControllerTrustRecord {
	data, err := ctx.GetStub().GetState("CTRL_TRUST:" + ctrlID)
	if err != nil || data == nil {
		return ControllerTrustRecord{
			ControllerID: ctrlID,
			Score:        1.0,
			DocType:      "CTRL_TRUST_RECORD",
		}
	}
	var r ControllerTrustRecord
	json.Unmarshal(data, &r)
	return r
}

func saveCtrlTrust(ctx contractapi.TransactionContextInterface, r ControllerTrustRecord) error {
	r.DocType = "CTRL_TRUST_RECORD"
	r.UpdatedAt = time.Now().UnixMilli()
	data, _ := json.Marshal(r)
	return ctx.GetStub().PutState("CTRL_TRUST:"+r.ControllerID, data)
}

// loadAllPeerIDs scans TRUST:* keys and returns all registered peer IDs.
// TR-02: required by TE-01 (PBFT gate) and TE-07 (peer reward loop).
// Uses GetStateByRange for efficient prefix scan without CouchDB rich query.
func loadAllPeerIDs(ctx contractapi.TransactionContextInterface) []string {
	iter, err := ctx.GetStub().GetStateByRange("TRUST:", "TRUST:~")
	if err != nil {
		return nil
	}
	defer iter.Close()
	var ids []string
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		// Strip "TRUST:" prefix (6 chars) to get the peer ID
		key := qr.Key
		if len(key) > 6 {
			ids = append(ids, key[6:])
		}
	}
	return ids
}

// ═══════════════════════════════════════════════════════════════════════════
//  Trust update functions
// ═══════════════════════════════════════════════════════════════════════════

func updateTrust(ctx contractapi.TransactionContextInterface, peerID string, correct bool, zero bool) (float64, error) {
	r := loadTrust(ctx, peerID)
	if zero {
		r.Score = 0.0
		r.FlaggedAt = time.Now().UnixMilli()
		r.Flagged = true
	} else if correct {
		r.Score = r.Score + TrustDeltaPlus
		if r.Score > 1.0 {
			r.Score = 1.0
		}
	} else {
		r.Score = r.Score - TrustDeltaMinus
		if r.Score < 0.0 {
			r.Score = 0.0
		}
	}
	return r.Score, saveTrust(ctx, r)
}

func updateCtrlTrust(ctx contractapi.TransactionContextInterface, controllerID string) (float64, error) {
	r := loadCtrlTrust(ctx, controllerID)
	r.Score = r.Score - TrustDeltaCtrl
	if r.Score < 0.0 {
		r.Score = 0.0
	}
	r.DivergenceCount++
	return r.Score, saveCtrlTrust(ctx, r)
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC CHAINCODE FUNCTIONS — Peer Registration
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) RegisterRSUPeer(
	ctx contractapi.TransactionContextInterface,
	peerID string,
) error {
	r := TrustRecord{
		PeerID:    peerID,
		Score:     TrustInitTier1,
		IsRSUPeer: true,
		DocType:   "TRUST_RECORD",
	}
	return saveTrust(ctx, r)
}

// RegisterOBUPeer registers an OBU as Tier 2 candidate with dwell time tracking (TR-3).
func (t *TemporalEchoMitigator) RegisterOBUPeer(
	ctx contractapi.TransactionContextInterface,
	peerID string,
	hwCapacityMBStr string,
) error {
	hwCap := 0
	fmt.Sscanf(hwCapacityMBStr, "%d", &hwCap)
	r := TrustRecord{
		PeerID:     peerID,
		Score:      TrustInitTier2,
		IsRSUPeer:  false,
		JoinedAtMs: time.Now().UnixMilli(),
		HWCapacity: hwCap,
		DocType:    "TRUST_RECORD",
	}
	return saveTrust(ctx, r)
}

// UpdateTrustRound applies trust delta for one beacon interval round.
// TR-01: during bootstrap (no RSU peers), the highest-trust OBU may drive trust
// rounds. This allows trust to accumulate in OBU-only / no-RSU deployments.
// TR-04 (from previous fix): when RSU peers ARE present, restricts callers to Tier 1 RSU.
func (t *TemporalEchoMitigator) UpdateTrustRound(
	ctx contractapi.TransactionContextInterface,
	callerPeerID string,
	participatingPeersJSON string,
	allPeersJSON string,
) error {
	callerTrust := loadTrust(ctx, callerPeerID)

	// TR-01: detect whether any RSU peers are registered
	allPeerIDs := loadAllPeerIDs(ctx)
	hasRSU := false
	for _, pid := range allPeerIDs {
		if loadTrust(ctx, pid).IsRSUPeer {
			hasRSU = true
			break
		}
	}

	if hasRSU {
		// Normal mode: only Tier 1 RSU peers may drive trust rounds (TR-04)
		if !callerTrust.IsRSUPeer || callerTrust.Score < TrustInitTier1-1e-9 {
			return fmt.Errorf(
				"UpdateTrustRound: caller %s is not an authorised Tier 1 RSU peer",
				callerPeerID)
		}
	} else {
		// TR-01: Tier 2 / OBU-only bootstrap mode — highest-trust OBU may call
		if callerTrust.Score < TrustMin || callerTrust.Flagged {
			return fmt.Errorf(
				"UpdateTrustRound: caller %s has insufficient trust for bootstrap mode (score=%.3f)",
				callerPeerID, callerTrust.Score)
		}
	}

	var participating []string
	var all []string
	json.Unmarshal([]byte(participatingPeersJSON), &participating)
	json.Unmarshal([]byte(allPeersJSON), &all)

	pset := make(map[string]bool, len(participating))
	for _, p := range participating {
		pset[p] = true
	}
	for _, peerID := range all {
		_, err := updateTrust(ctx, peerID, pset[peerID], false)
		if err != nil {
			return fmt.Errorf("UpdateTrustRound: failed to update %s: %v", peerID, err)
		}
	}
	return nil
}

// ZeroTrust zeros a peer's trust on confirmed attack detection.
// TR-04: restricted to Tier 1 RSU callers with a backing detection event.
func (t *TemporalEchoMitigator) ZeroTrust(
	ctx contractapi.TransactionContextInterface,
	callerID string,
	targetPeerID string,
	detectionEventKey string,
) error {
	// TR-04: only Tier 1 RSU may zero trust
	caller := loadTrust(ctx, callerID)
	if !caller.IsRSUPeer || caller.Score < TrustInitTier1-1e-9 {
		return fmt.Errorf("ZeroTrust: unauthorised caller %s", callerID)
	}
	// TR-04: require a backing detection event
	data, err := ctx.GetStub().GetState(detectionEventKey)
	if err != nil || data == nil {
		return fmt.Errorf("ZeroTrust: no backing detection event %s", detectionEventKey)
	}
	_, err = updateTrust(ctx, targetPeerID, false, true)
	return err
}

// GetTrustScore returns the current trust score for a peer.
func (t *TemporalEchoMitigator) GetTrustScore(
	ctx contractapi.TransactionContextInterface,
	peerID string,
) (float64, error) {
	r := loadTrust(ctx, peerID)
	return r.Score, nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  selectPeers — Pactive = highest-trust eligible peers (Eq. 3.40)
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) SelectPeers(
	ctx contractapi.TransactionContextInterface,
	allPeersJSON string,
) ([]string, error) {
	var allPeers []string
	if err := json.Unmarshal([]byte(allPeersJSON), &allPeers); err != nil {
		return nil, err
	}
	return selectPeers(ctx, allPeers), nil
}

func selectPeers(ctx contractapi.TransactionContextInterface, allPeers []string) []string {
	np := 3*FaultToleranceF + 1
	nowMs := time.Now().UnixMilli()
	const tMinMs = int64(TrustMinDwellMs)

	type peerScore struct {
		id    string
		score float64
	}
	var eligible []peerScore
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.Flagged {
			continue
		}
		if r.Score < TrustMin {
			continue
		}
		if !r.IsRSUPeer {
			if r.JoinedAtMs > 0 && (nowMs-r.JoinedAtMs) < tMinMs {
				continue
			}
			if r.HWCapacity > 0 && r.HWCapacity < HWCapacityMinMB {
				continue
			}
			if !obuHasSyncedFromRecentCheckpoint(ctx, pid) {
				continue
			}
		}
		eligible = append(eligible, peerScore{pid, r.Score})
	}

	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].score > eligible[j].score
	})

	result := make([]string, 0, np)
	for i := 0; i < len(eligible) && i < np; i++ {
		result = append(result, eligible[i].id)
	}
	return result
}

// obuHasSyncedFromRecentCheckpoint verifies an OBU synced from the latest checkpoint.
// TR-05: sorts by block_height DESC (monotonic, spoof-proof) not created_at_ms
// (wall-clock, susceptible to clock manipulation and test collisions).
func obuHasSyncedFromRecentCheckpoint(ctx contractapi.TransactionContextInterface, obuPeerID string) bool {
	// TR-05: sort by block_height (deterministic) not created_at_ms (wall-clock)
	qs := `{"selector":{"doc_type":"ANCHOR_CHECKPOINT"},"sort":[{"block_height":"desc"}],"limit":1}`
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil || iter == nil {
		return true // no checkpoint yet — bootstrap phase
	}
	defer iter.Close()
	if !iter.HasNext() {
		return true // bootstrap phase
	}
	qr, err := iter.Next()
	if err != nil {
		return false
	}
	var cp AnchorCheckpoint
	if json.Unmarshal(qr.Value, &cp) != nil {
		return false
	}
	for _, pid := range cp.SyncedPeers {
		if pid == obuPeerID {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════
//  Trusted Evidence
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) GetTrustedEvidence(
	ctx contractapi.TransactionContextInterface,
	allPeersJSON string,
	intervalTSStr string,
) ([]BeaconEvidenceRecord, error) {
	var allPeers []string
	json.Unmarshal([]byte(allPeersJSON), &allPeers)
	var intervalTS int64
	fmt.Sscanf(intervalTSStr, "%d", &intervalTS)

	qualified := make(map[string]bool)
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.Score >= TrustMinGT && !r.Flagged {
			qualified[pid] = true
		}
	}

	queryStr := fmt.Sprintf(
		`{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":%d}}`, intervalTS)
	iter, err := ctx.GetStub().GetQueryResult(queryStr)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var records []BeaconEvidenceRecord
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var rec BeaconEvidenceRecord
		if json.Unmarshal(qr.Value, &rec) == nil {
			if rec.IsRSUPeer || qualified[rec.PeerID] {
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  Trust-Weighted PBFT Consensus Check (Section 5.6)
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) CheckPBFTConsensus(
	ctx contractapi.TransactionContextInterface,
	approvingPeersJSON string,
	activePeersJSON string,
) (bool, error) {
	var approving []string
	var active []string
	json.Unmarshal([]byte(approvingPeersJSON), &approving)
	json.Unmarshal([]byte(activePeersJSON), &active)
	return checkPBFTTrustWeight(ctx, approving, active), nil
}

func checkPBFTTrustWeight(ctx contractapi.TransactionContextInterface, approving []string, active []string) bool {
	var sumApprove, sumActive float64
	approvingSet := make(map[string]bool, len(approving))
	for _, p := range approving {
		approvingSet[p] = true
	}
	for _, pid := range active {
		r := loadTrust(ctx, pid)
		if r.Flagged {
			continue
		}
		sumActive += r.Score
		if approvingSet[pid] {
			sumApprove += r.Score
		}
	}
	if sumActive == 0 {
		return false
	}
	return sumApprove/sumActive > 2.0/3.0
}

// ═══════════════════════════════════════════════════════════════════════════
//  Controller Removal Mechanism (Section 5.7)
// ═══════════════════════════════════════════════════════════════════════════

// CheckControllerTrustAndReassign is the single authority for applying ΔC- penalties.
// TE-04/DV-03: called ONLY from here — not also from runMitigation or checkControllerDivergence.
func (t *TemporalEchoMitigator) CheckControllerTrustAndReassign(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	allCtrlsJSON string,
) error {
	newScore, err := updateCtrlTrust(ctx, controllerID)
	if err != nil {
		return err
	}
	if newScore >= TrustCtrlMin {
		return nil
	}

	var allCtrls []string
	json.Unmarshal([]byte(allCtrlsJSON), &allCtrls)

	backupID, backupScore := selectBackupController(ctx, controllerID, allCtrls)
	if backupID == "" {
		payload, _ := json.Marshal(map[string]interface{}{
			"type":         "NO_BACKUP_CONTROLLER",
			"failed_ctrl":  controllerID,
			"trust_score":  newScore,
			"timestamp_ms": time.Now().UnixMilli(),
		})
		ctx.GetStub().SetEvent("ControllerRemovalFailed", payload)
		return nil
	}

	// TR-1: read ZoneID from ledger record
	ctrlRecord := loadCtrlTrust(ctx, controllerID)

	reassignment := ControllerReassignment{
		RemovedCtrlID:   controllerID,
		BackupCtrlID:    backupID,
		BackupScore:     backupScore,
		RemovedScore:    newScore,
		AssignedAt:      time.Now().UnixMilli(),
		ZoneID:          ctrlRecord.ZoneID,
		DocType:         "CTRL_REASSIGNMENT",
		EmergencyBypass: true,
	}
	rData, _ := json.Marshal(reassignment)
	key := fmt.Sprintf("CTRL_REASSIGN:%s:%d", controllerID, reassignment.AssignedAt)
	if err := ctx.GetStub().PutState(key, rData); err != nil {
		return err
	}

	credRevoke := map[string]interface{}{
		"controller_id": controllerID,
		"action":        "REVOKE_CTRL_CREDENTIALS",
		"backup_ctrl":   backupID,
		"timestamp_ms":  time.Now().UnixMilli(),
	}
	cData, _ := json.Marshal(credRevoke)
	ctx.GetStub().PutState("CTRL_REVOKED:"+controllerID, cData)

	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":         "CONTROLLER_REASSIGNMENT",
		"removed_ctrl": controllerID,
		"backup_ctrl":  backupID,
		"trust_score":  newScore,
		"zone_id":      ctrlRecord.ZoneID,
		"timestamp_ms": time.Now().UnixMilli(),
	})
	ctx.GetStub().SetEvent("ControllerRemoved", evPayload)
	return nil
}

func selectBackupController(ctx contractapi.TransactionContextInterface, failedCtrlID string, allCtrls []string) (string, float64) {
	bestID := ""
	bestScore := -1.0
	for _, cid := range allCtrls {
		if cid == failedCtrlID {
			continue
		}
		r := loadCtrlTrust(ctx, cid)
		if r.Score > TrustCtrlMin && r.Score > bestScore {
			bestID = cid
			bestScore = r.Score
		}
	}
	return bestID, bestScore
}

// GetControllerTrustScore returns the current trust score for a controller.
func (t *TemporalEchoMitigator) GetControllerTrustScore(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
) (float64, error) {
	r := loadCtrlTrust(ctx, controllerID)
	return r.Score, nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  Bootstrap Phase
// ═══════════════════════════════════════════════════════════════════════════

func (t *TemporalEchoMitigator) GetBootstrapStatus(
	ctx contractapi.TransactionContextInterface,
	allPeersJSON string,
) (map[string]interface{}, error) {
	var allPeers []string
	json.Unmarshal([]byte(allPeersJSON), &allPeers)

	np := 3*FaultToleranceF + 1
	qualified := 0
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.Score >= TrustMinGT && !r.Flagged {
			qualified++
		}
	}

	// TR-02: use math.Ceil (not int truncation) for Rmin
	rmin := int(math.Ceil((TrustMinGT - TrustInitTier2) / TrustDeltaPlus))
	if rmin < 0 {
		rmin = 0
	}

	bootstrapComplete := qualified >= np
	return map[string]interface{}{
		"bootstrap_complete": bootstrapComplete,
		"qualified_peers":    qualified,
		"required_peers_np":  np,
		"tau_mingt":          TrustMinGT,
		"rmin_rounds":        rmin,
		"trust_delta_plus":   TrustDeltaPlus,
		"trust_delta_minus":  TrustDeltaMinus,
	}, nil
}
