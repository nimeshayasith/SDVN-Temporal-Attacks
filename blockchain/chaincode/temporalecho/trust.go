package main

// trust.go — Trust Score Management, Peer Tier Selection, Controller Removal
//
// Implements PDF Sections 5.1–5.7:
//
//   Section 5.2  Trust Score Management
//     τk(t+1) = min(1, τk(t) + Δ+)   if correct participation
//     τk(t+1) = max(0, τk(t) - Δ-)   if failure-to-participate / inconsistent
//     τk(t+1) = 0                     if flagged by LW or FS detector
//     Δ+ = 0.05,  Δ- = 0.10  (trust harder to gain than lose)
//
//   Section 5.1  Peer Tier Management
//     Eligible(Vk) iff: cert ∈ CA, CVk ≥ Cmin, Tdwell ≥ Tmin, τk ≥ τmin,
//                        Vk ∉ Fflagged
//     Pactive = {P : |P|=np, all Eligible, argmax Σ τk}
//
//   Section 5.6  Trust-Weighted PBFT
//     Accept ⟺ Σ(τk : k ∈ Papprove) / Σ(τk : k ∈ Pactive) > 2/3
//
//   Section 5.7  Controller Removal
//     τCj < τCmin → REASSIGN(Zj → Ck*)
//     Ck* = argmax{τCk : k≠j, τCk > τCmin}

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ═══════════════════════════════════════════════════════════════════════════
//  CONSTANTS (Section 5.2 / 5.7)
// ═══════════════════════════════════════════════════════════════════════════

const (
	TrustDeltaPlus  = 0.05 // Δ+ gain per correct participation round
	TrustDeltaMinus = 0.10 // Δ- loss per failure/inconsistency
	TrustDeltaCtrl  = 0.20 // ΔC- controller trust penalty per confirmed divergence

	TrustMin      = 0.10 // τmin — admission threshold for Tier 2 OBU peers
	TrustMinGT    = 0.50 // τmingt — stricter threshold for evidence contribution
	TrustCtrlMin  = 0.30 // τCmin — controller removal threshold

	TrustInitTier1 = 1.00 // RSU peers start at full trust
	TrustInitTier2 = 0.10 // OBU peers start at τ0 = 0.1

	TrustMinDwellMs = 3000 // Tmin = 3 s minimum dwell for OBU peer promotion
	FaultToleranceF = 1    // f for np = 3f+1 (tolerates 1 Byzantine peer)
)

// ═══════════════════════════════════════════════════════════════════════════
//  TRUST RECORD LEDGER FUNCTIONS  (Section 5.2)
//
//  Ledger keys:
//    TRUST:<peer_id>         → TrustRecord
//    CTRL_TRUST:<ctrl_id>    → ControllerTrustRecord
// ═══════════════════════════════════════════════════════════════════════════

// loadTrust reads a TrustRecord from the ledger; returns default if absent.
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

// ═══════════════════════════════════════════════════════════════════════════
//  updateTrust  — Section 5.2, node trust update rule
//
//  Called by the smart contract each round for every participating peer.
//    correct = true  → τk(t+1) = min(1, τk(t) + Δ+)
//    correct = false → τk(t+1) = max(0, τk(t) - Δ-)
//
//  Calling with zero = true forces τk = 0 immediately (attack detection flag).
// ═══════════════════════════════════════════════════════════════════════════

func updateTrust(
	ctx contractapi.TransactionContextInterface,
	peerID string,
	correct bool,
	zero bool,
) (float64, error) {
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

// updateCtrlTrust applies the controller trust penalty rule (Section 5.2).
// Controllers have NO reward path — trust only decreases on confirmed divergence.
//
//	τCj(t+1) = max(0, τCj(t) - ΔC-)
func updateCtrlTrust(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
) (float64, error) {
	r := loadCtrlTrust(ctx, controllerID)
	r.Score = r.Score - TrustDeltaCtrl
	if r.Score < 0.0 {
		r.Score = 0.0
	}
	r.DivergenceCount++
	return r.Score, saveCtrlTrust(ctx, r)
}

// RegisterRSUPeer registers an RSU as a Tier 1 peer with τk = 1.0 (Section 5.1).
// Must be called at network bootstrap via the bootstrap.sh script.
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

// UpdateTrustRound is called once per beacon interval by each RSU peer.
// It applies the trust update rule to all peers that participated (or failed).
//
//  participatingPeersJSON: JSON array of peer IDs that submitted beacon evidence
//  allPeersJSON:           JSON array of all expected peer IDs this round
func (t *TemporalEchoMitigator) UpdateTrustRound(
	ctx contractapi.TransactionContextInterface,
	participatingPeersJSON string,
	allPeersJSON string,
) error {
	var participating []string
	var all []string
	json.Unmarshal([]byte(participatingPeersJSON), &participating)
	json.Unmarshal([]byte(allPeersJSON), &all)

	// Build set of participators
	pset := make(map[string]bool, len(participating))
	for _, p := range participating {
		pset[p] = true
	}

	// Apply Δ+ for correct participation, Δ- for failure-to-participate
	for _, peerID := range all {
		_, err := updateTrust(ctx, peerID, pset[peerID], false)
		if err != nil {
			return fmt.Errorf("UpdateTrustRound: failed to update %s: %v", peerID, err)
		}
	}
	return nil
}

// ZeroTrust immediately zeros a peer's trust score on confirmed attack detection.
// Called from runMitigation (Algorithm 4, Step 5: updateTrust(v, 0)).
func (t *TemporalEchoMitigator) ZeroTrust(
	ctx contractapi.TransactionContextInterface,
	peerID string,
) error {
	_, err := updateTrust(ctx, peerID, false, true)
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
//  selectPeers  — Section 5.1
//
//  Returns Pactive = highest-trust subset of size np = 3f+1 from eligible peers.
//  Eligible(Vk) requires: τk ≥ τmin, not flagged, is registered peer.
// ═══════════════════════════════════════════════════════════════════════════

// SelectPeers returns the np = 3f+1 highest-trust eligible peer IDs.
// allPeersJSON: JSON array of all known peer IDs in the consortium.
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

func selectPeers(
	ctx contractapi.TransactionContextInterface,
	allPeers []string,
) []string {
	np := 3*FaultToleranceF + 1

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
		eligible = append(eligible, peerScore{pid, r.Score})
	}

	// Sort descending by trust score (argmax Σ τk — Section 5.1)
	sort.Slice(eligible, func(i, j int) bool {
		return eligible[i].score > eligible[j].score
	})

	result := make([]string, 0, np)
	for i := 0; i < len(eligible) && i < np; i++ {
		result = append(result, eligible[i].id)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════
//  getTrustedEvidence  — Section 5.4
//
//  Et_trusted = ∪ Bnk(t) for nk ∈ Pactive with τk ≥ τmingt
//
//  Tier 1 (all τk = 1): uses all RSU evidence.
//  Tier 2 (OBU peers):  uses subset with τk ≥ τmingt > τmin.
// ═══════════════════════════════════════════════════════════════════════════

// GetTrustedEvidence returns beacon evidence records from peers with τk ≥ τmingt.
// allPeersJSON: JSON array of active peer IDs (from SelectPeers or bootstrap).
func (t *TemporalEchoMitigator) GetTrustedEvidence(
	ctx contractapi.TransactionContextInterface,
	allPeersJSON string,
	intervalTSStr string,
) ([]BeaconEvidenceRecord, error) {
	var allPeers []string
	json.Unmarshal([]byte(allPeersJSON), &allPeers)

	var intervalTS int64
	fmt.Sscanf(intervalTSStr, "%d", &intervalTS)

	// Collect peer IDs with τk ≥ τmingt
	qualified := make(map[string]bool)
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.Score >= TrustMinGT && !r.Flagged {
			qualified[pid] = true
		}
	}

	// Fetch all beacon evidence and filter by peer
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
			// Include RSU peers unconditionally (τk = 1) or OBUs with τk ≥ τmingt
			if rec.IsRSUPeer || qualified[rec.PeerID] {
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

// ═══════════════════════════════════════════════════════════════════════════
//  Trust-Weighted PBFT Consensus Check  (Section 5.6)
//
//  Accept ⟺ Σ(τk : k ∈ Papprove) / Σ(τk : k ∈ Pactive) > 2/3
// ═══════════════════════════════════════════════════════════════════════════

// CheckPBFTConsensus returns true if the approving peers have > 2/3 of the
// total trust weight in Pactive.
//
//  approvingPeersJSON: JSON array of peer IDs that endorsed the transaction
//  activePeersJSON:    JSON array of all active peer IDs (Pactive)
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

// checkPBFTTrustWeight is the internal consensus weight check (Section 5.6).
func checkPBFTTrustWeight(
	ctx contractapi.TransactionContextInterface,
	approving []string,
	active []string,
) bool {
	var sumApprove, sumActive float64

	approvingSet := make(map[string]bool, len(approving))
	for _, p := range approving {
		approvingSet[p] = true
	}

	for _, pid := range active {
		r := loadTrust(ctx, pid)
		if r.Flagged {
			continue // zeroed trust — excluded from active set immediately
		}
		sumActive += r.Score
		if approvingSet[pid] {
			sumApprove += r.Score
		}
	}

	if sumActive == 0 {
		return false
	}
	// Standard PBFT threshold: > 2/3 of trust weight (Section 5.6)
	return sumApprove/sumActive > 2.0/3.0
}

// ═══════════════════════════════════════════════════════════════════════════
//  Controller Removal Mechanism  (Section 5.7)
//
//  τCj < τCmin → REASSIGN(Zj → Ck*)
//  Ck* = argmax{τCk : k≠j, τCk > τCmin}
//
//  Execution path (via emergency channel, NOT through malicious controller):
//    1. RSU OpenFlow agents switch southbound connection from Cj to Ck*
//    2. Cj's credentials revoked via consortium CA
//    3. Ck* receives topology snapshot from RSU beacon evidence ledger
//    4. Ck* begins managing the zone immediately
//  In simulation: writes ControllerReassignment record; eventListener.js acts.
// ═══════════════════════════════════════════════════════════════════════════

// CheckControllerTrustAndReassign is called after each confirmed divergence.
// If τCj drops below τCmin it selects Ck* and writes reassignment records.
//
//  controllerID:   the suspect controller Cj
//  allCtrlsJSON:   JSON array of all controller IDs in the consortium
func (t *TemporalEchoMitigator) CheckControllerTrustAndReassign(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	allCtrlsJSON string,
) error {
	// Apply trust penalty for this divergence
	newScore, err := updateCtrlTrust(ctx, controllerID)
	if err != nil {
		return err
	}

	if newScore >= TrustCtrlMin {
		return nil // still above removal threshold — monitor only
	}

	// τCj < τCmin — select backup controller Ck*
	var allCtrls []string
	json.Unmarshal([]byte(allCtrlsJSON), &allCtrls)

	backupID, backupScore := selectBackupController(ctx, controllerID, allCtrls)
	if backupID == "" {
		// No eligible backup — log but do not crash; human intervention needed
		payload, _ := json.Marshal(map[string]interface{}{
			"type":          "NO_BACKUP_CONTROLLER",
			"failed_ctrl":   controllerID,
			"trust_score":   newScore,
			"timestamp_ms":  time.Now().UnixMilli(),
		})
		ctx.GetStub().SetEvent("ControllerRemovalFailed", payload)
		return nil
	}

	// Write ControllerReassignment record — consumed by eventListener.js
	reassignment := ControllerReassignment{
		RemovedCtrlID:  controllerID,
		BackupCtrlID:   backupID,
		BackupScore:    backupScore,
		RemovedScore:   newScore,
		AssignedAt:     time.Now().UnixMilli(),
		ZoneID:         "zone-" + controllerID,
		DocType:        "CTRL_REASSIGNMENT",
		EmergencyBypass: true, // commands issued via RSU emergency channel
	}
	rData, _ := json.Marshal(reassignment)
	key := fmt.Sprintf("CTRL_REASSIGN:%s:%d",
		controllerID, reassignment.AssignedAt)
	if err := ctx.GetStub().PutState(key, rData); err != nil {
		return err
	}

	// Revoke credentials — flags the controller so it is excluded from future
	// topology submissions; actual CA revocation handled by eventListener.js
	credRevoke := map[string]interface{}{
		"controller_id": controllerID,
		"action":        "REVOKE_CTRL_CREDENTIALS",
		"backup_ctrl":   backupID,
		"timestamp_ms":  time.Now().UnixMilli(),
	}
	cData, _ := json.Marshal(credRevoke)
	ctx.GetStub().PutState("CTRL_REVOKED:"+controllerID, cData)

	// Emit event for eventListener.js to action via emergency channel
	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":          "CONTROLLER_REASSIGNMENT",
		"removed_ctrl":  controllerID,
		"backup_ctrl":   backupID,
		"trust_score":   newScore,
		"timestamp_ms":  time.Now().UnixMilli(),
	})
	ctx.GetStub().SetEvent("ControllerRemoved", evPayload)

	return nil
}

// selectBackupController returns Ck* = argmax{τCk : k≠j, τCk > τCmin}.
func selectBackupController(
	ctx contractapi.TransactionContextInterface,
	failedCtrlID string,
	allCtrls []string,
) (string, float64) {
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
//  Bootstrap Phase  (Section 5.2)
//
//  Pure no-RSU deployment: all peers start at τ0 = 0.1.
//  Bootstrap ends when ≥ np = 3f+1 peers reach τk ≥ τmingt.
//  Minimum duration: Rmin = ⌈(τmingt - τ0) / Δ+⌉ = 8 rounds.
// ═══════════════════════════════════════════════════════════════════════════

// GetBootstrapStatus returns whether the bootstrap phase is complete.
// allPeersJSON: JSON array of all registered peer IDs.
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

	// Rmin = ⌈(τmingt - τ0) / Δ+⌉ = ⌈(0.5 - 0.1) / 0.05⌉ = 8 rounds
	rmin := int((TrustMinGT - TrustInitTier2) / TrustDeltaPlus)
	if rmin < 0 {
		rmin = 0
	}

	bootstrapComplete := qualified >= np
	return map[string]interface{}{
		"bootstrap_complete":     bootstrapComplete,
		"qualified_peers":        qualified,
		"required_peers_np":      np,
		"tau_mingt":              TrustMinGT,
		"rmin_rounds":            rmin,
		"trust_delta_plus":       TrustDeltaPlus,
		"trust_delta_minus":      TrustDeltaMinus,
	}, nil
}
