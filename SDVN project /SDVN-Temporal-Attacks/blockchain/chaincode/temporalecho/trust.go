package main

// trust.go — Trust Score Management, Peer Tier Selection, Controller Removal

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"

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

	TrustMinDwellMs     = 3000
	HWCapacityMinMB     = 2048  // ≥ 2 GB RAM (Cmin RAM floor)
	HWStorageMinGB      = 8     // ≥ 8 GB storage (Cmin storage floor)
	FaultToleranceF     = 2     // tolerate f=2 Byzantine peers
	NpConsensus         = 8  // active peer slots: np ≥ 3f+1=7, rounded up to 8 for redundancy
	QuarantineMonitorMs = int64(30000) // 30 s monitoring window before permanent removal
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
	r.UpdatedAt = txTimestampMs(ctx)
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
	r.UpdatedAt = txTimestampMs(ctx)
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
		// RSU peers go through the 3-stage demotion pipeline.
		// OBU/vehicle trust is zeroed immediately — they are not consensus peers.
		if r.IsRSUPeer {
			return 0.0, demotePeerToClient(ctx, peerID)
		}
		r.Score = 0.0
		r.FlaggedAt = txTimestampMs(ctx)
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
		// If already quarantined and trust degrades further, trigger removal check.
		if r.State == PeerStateQuarantined {
			_ = monitorAndRemovePeer(ctx, peerID)
			return r.Score, nil
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
		State:     PeerStateActive,
		DocType:   "TRUST_RECORD",
	}
	return saveTrust(ctx, r)
}

// RegisterOBUPeer registers an OBU as Tier 2 candidate with dwell time tracking (TR-3).
// hwCapacityMBStr: RAM in MB (Cmin: ≥ 2048 MB).
// hwStorageGBStr:  storage in GB (Cmin: ≥ 8 GB).
func (t *TemporalEchoMitigator) RegisterOBUPeer(
	ctx contractapi.TransactionContextInterface,
	peerID string,
	hwCapacityMBStr string,
	hwStorageGBStr string,
) error {
	hwCap := 0
	fmt.Sscanf(hwCapacityMBStr, "%d", &hwCap)
	hwStorage := 0
	fmt.Sscanf(hwStorageGBStr, "%d", &hwStorage)
	r := TrustRecord{
		PeerID:      peerID,
		Score:       TrustInitTier2,
		IsRSUPeer:   false,
		JoinedAtMs:  txTimestampMs(ctx),
		HWCapacity:  hwCap,
		HWStorageGB: hwStorage,
		DocType:     "TRUST_RECORD",
	}
	return saveTrust(ctx, r)
}

// SetRSUZone stores the geographic zone ID for an RSU peer.
// Called at bootstrap (alongside RegisterRSUPeer) so that triggerRSUZoneReassignment
// can identify which coverage area to partially reassign on RSU compromise.
func (t *TemporalEchoMitigator) SetRSUZone(
	ctx contractapi.TransactionContextInterface,
	peerID string,
	zoneID string,
) error {
	r := loadTrust(ctx, peerID)
	if !r.IsRSUPeer {
		return fmt.Errorf("SetRSUZone: peer %s is not a Tier 1 RSU", peerID)
	}
	r.ZoneID = zoneID
	return saveTrust(ctx, r)
}

// UpdateTrustRound applies trust delta for one beacon interval round.
// TR-04: caller must be RSU-equivalent standing.
//
// Bug fix (6th instance of the same pattern — see ZeroTrust/DemotePeerToClient/
// SubmitLWDetectionResult/CreateAnchorCheckpoint/SyncFromAnchorCheckpoint):
// the previous hasRSU peer-scan is a deployment-wide check ("does any RSU
// exist anywhere"), the same shape of bug as the SIM_NO_RSU_MODE flag used
// (and since corrected) elsewhere — not a per-caller check. In a mixed
// deployment (RSUs present), any of the legitimately-active, top-trust Tier 2
// OBUs sitting in the same active set as the RSUs would still be rejected
// here, since hasRSU is true whenever any RSU exists. Corrected to the same
// single, unconditional per-caller check as the other five: RSU status
// always qualifies; otherwise the caller's own trust must clear τ ≥ τminGT.
func (t *TemporalEchoMitigator) UpdateTrustRound(
	ctx contractapi.TransactionContextInterface,
	callerPeerID string,
	participatingPeersJSON string,
	allPeersJSON string,
) error {
	callerTrust := loadTrust(ctx, callerPeerID)
	if !(callerTrust.IsRSUPeer || (callerTrust.Score >= TrustMinGT && !callerTrust.Flagged)) {
		return fmt.Errorf(
			"UpdateTrustRound: unauthorised caller %s (not RSU, trust=%.3f < %.2f or flagged=%v)",
			callerPeerID, callerTrust.Score, TrustMinGT, callerTrust.Flagged)
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

// ZeroTrust initiates the demotion pipeline for a peer on confirmed attack detection.
// For RSU peers: demotes to QUARANTINED_CLIENT (Stage 1 of 3-stage pipeline).
// For OBU/vehicle peers: zeroes trust immediately.
// TR-04: caller must be RSU-equivalent standing, with a backing detection event.
//
// Bug fix (2nd pass): the first fix gated the no-RSU exception on the global,
// deployment-wide SIM_NO_RSU_MODE flag — which is false in a mixed deployment
// (RSUs present) even when a specific caller is a legitimately-active,
// top-trust Tier 2 OBU peer sitting in the same active/consensus set as the
// RSUs (selectPeers ranks all eligible peers by trust and fills np=8 slots
// regardless of type — e.g. 5 RSUs + 3 OBUs when both exist). That caller
// would still have been blocked. §3.1.3 of the thesis is a per-node property
// ("each trusted node nk (RSU or designated OBU)"), not a deployment-wide
// switch — it doesn't say "only when no RSU exists anywhere." Corrected to a
// single, unconditional per-caller check: RSU status always qualifies;
// otherwise the caller's own trust must clear the ground-truth bar. This is
// also simpler than the two-branch form it replaces.
func (t *TemporalEchoMitigator) ZeroTrust(
	ctx contractapi.TransactionContextInterface,
	callerID string,
	targetPeerID string,
	detectionEventKey string,
) error {
	caller := loadTrust(ctx, callerID)
	if !(caller.IsRSUPeer || (caller.Score >= TrustMinGT && !caller.Flagged)) {
		return fmt.Errorf(
			"ZeroTrust: unauthorised caller %s (not RSU, trust=%.3f < %.2f or flagged=%v)",
			callerID, caller.Score, TrustMinGT, caller.Flagged)
	}
	// TR-04: require a backing detection event
	data, err := ctx.GetStub().GetState(detectionEventKey)
	if err != nil || data == nil {
		return fmt.Errorf("ZeroTrust: no backing detection event %s", detectionEventKey)
	}
	target := loadTrust(ctx, targetPeerID)
	if target.IsRSUPeer {
		// RSU peer: enter 3-stage demotion pipeline (supervisor feedback)
		return demotePeerToClient(ctx, targetPeerID)
	}
	// OBU/vehicle: immediate zero
	_, err = updateTrust(ctx, targetPeerID, false, true)
	return err
}

// ═══════════════════════════════════════════════════════════════════════════
//  RSU Peer Demotion Pipeline (supervisor feedback: 3-stage)
// ═══════════════════════════════════════════════════════════════════════════

// demotePeerToClient moves a malicious RSU peer from ACTIVE to QUARANTINED_CLIENT.
// Stage 1 of the 3-stage pipeline: peer is excluded from Pactive, trust zeroed,
// but remains on the ledger for continued monitoring.
func demotePeerToClient(ctx contractapi.TransactionContextInterface, peerID string) error {
	r := loadTrust(ctx, peerID)
	nowMs := txTimestampMs(ctx)
	r.Score = 0.0
	r.Flagged = true
	r.FlaggedAt = nowMs
	r.State = PeerStateQuarantined
	r.DemotedAt = nowMs
	r.IsRSUPeer = false // stripped of peer role; becomes a client observer
	if err := saveTrust(ctx, r); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"type":          "PEER_QUARANTINED",
		"peer_id":       peerID,
		"demoted_at_ms": nowMs,
		"message":       "RSU peer demoted to QUARANTINED_CLIENT — monitoring trust score",
	})
	ctx.GetStub().SetEvent("PeerQuarantined", payload)
	return nil
}

// monitorAndRemovePeer evaluates a QUARANTINED peer for permanent removal.
// Stage 2→3 of the pipeline: if the quarantine window has elapsed and trust
// has not recovered above TrustMin, the peer is moved to REMOVED.
// Called periodically via PeriodicPeerReSelection or on each trust degradation.
func monitorAndRemovePeer(ctx contractapi.TransactionContextInterface, peerID string) error {
	r := loadTrust(ctx, peerID)
	if r.State != PeerStateQuarantined {
		return nil
	}
	nowMs := txTimestampMs(ctx)
	if nowMs-r.DemotedAt < QuarantineMonitorMs {
		// Still within quarantine window — keep monitoring
		return nil
	}
	// Quarantine window elapsed: if trust is still at or below minimum, remove permanently
	if r.Score <= TrustMin {
		r.State = PeerStateRemoved
		if err := saveTrust(ctx, r); err != nil {
			return err
		}

		// Write certificate revocation record to ledger (thesis: removal includes
		// cert revocation via the consortium CA; re-admission requires a fresh cert
		// and a new RegisterRSUPeer call). The actual CA interaction is off-chain —
		// eventListener.js reads this record and actions the revocation.
		certRevoke := map[string]interface{}{
			"peer_id":       peerID,
			"action":        "REVOKE_PEER_CERTIFICATE",
			"revoked_at_ms": nowMs,
			"reason":        "quarantine_window_elapsed_trust_not_recovered",
		}
		cData, _ := json.Marshal(certRevoke)
		ctx.GetStub().PutState("CERT_REVOKED:"+peerID, cData)

		payload, _ := json.Marshal(map[string]interface{}{
			"type":          "PEER_REMOVED",
			"peer_id":       peerID,
			"removed_at_ms": nowMs,
			"trust_score":   r.Score,
			"message":       "RSU peer permanently removed after quarantine monitoring",
			"cert_revoked":  true,
		})
		ctx.GetStub().SetEvent("PeerRemoved", payload)

		// Emit separate CertRevocationRequested so eventListener.js can action
		// the CA call independently of the removal event handler.
		certPayload, _ := json.Marshal(map[string]interface{}{
			"type":          "CERT_REVOCATION_REQUESTED",
			"peer_id":       peerID,
			"revoked_at_ms": nowMs,
		})
		ctx.GetStub().SetEvent("CertRevocationRequested", certPayload)
	}
	return nil
}

// DemotePeerToClient is the public chaincode function for the demotion pipeline.
// Called by a trusted node — an RSU, or a Tier 2 OBU with RSU-equivalent
// standing (τ ≥ τminGT, not flagged) — when a consortium peer is confirmed
// malicious. Same bug/fix as ZeroTrust above: this entry point was missed in
// the first pass and had no no-RSU exception at all (not even the incomplete
// global-flag version) — in a no-RSU deployment it was uncallable by anyone.
func (t *TemporalEchoMitigator) DemotePeerToClient(
	ctx contractapi.TransactionContextInterface,
	callerID string,
	targetPeerID string,
	detectionEventKey string,
) error {
	caller := loadTrust(ctx, callerID)
	if !(caller.IsRSUPeer || (caller.Score >= TrustMinGT && !caller.Flagged)) {
		return fmt.Errorf(
			"DemotePeerToClient: unauthorised caller %s (not RSU, trust=%.3f < %.2f or flagged=%v)",
			callerID, caller.Score, TrustMinGT, caller.Flagged)
	}
	data, err := ctx.GetStub().GetState(detectionEventKey)
	if err != nil || data == nil {
		return fmt.Errorf("DemotePeerToClient: no backing detection event %s", detectionEventKey)
	}
	return demotePeerToClient(ctx, targetPeerID)
}

// PeriodicPeerReSelection re-evaluates all peers and returns the updated active set.
// Promotion and de-listing both fall out of the same re-ranking call — there is no
// separate promotion pipeline. An OBU joins Pactive when:
//   (a) it passes all five eligibility conditions, AND
//   (b) a vacancy exists because the current active set has fewer than np members.
// Checkpoint sync (obuHasSyncedFromRecentCheckpoint) is enforced inside selectPeers
// as the final gate before an OBU is included, matching the document requirement that
// a newly promoted peer must sync from the latest anchor checkpoint before voting.
//
// This function persists the active set to the ledger after each call so that
// membership changes (promotions and de-listings) can be detected and emitted as
// events. Clients call this at each beacon interval alongside UpdateTrustRound.
func (t *TemporalEchoMitigator) PeriodicPeerReSelection(
	ctx contractapi.TransactionContextInterface,
	allPeersJSON string,
) ([]string, error) {
	var allPeers []string
	if err := json.Unmarshal([]byte(allPeersJSON), &allPeers); err != nil {
		return nil, fmt.Errorf("PeriodicPeerReSelection: invalid allPeersJSON: %v", err)
	}

	// Advance any QUARANTINED peers whose monitoring window has elapsed.
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		if r.State == PeerStateQuarantined {
			_ = monitorAndRemovePeer(ctx, pid)
		}
	}

	// Load the previous active set from the ledger for change detection.
	prevSet := make(map[string]bool)
	if prevData, _ := ctx.GetStub().GetState("ACTIVE_PEER_SET"); len(prevData) > 0 {
		var prevSlice []string
		if json.Unmarshal(prevData, &prevSlice) == nil {
			for _, p := range prevSlice {
				prevSet[p] = true
			}
		}
	}

	// Recompute Pactive. Both promotions and de-listings fall out of this single call —
	// peers below τ_min or failing any eligibility gate are absent from the result;
	// the next-ranked eligible OBU fills any vacancy automatically.
	newActive := selectPeers(ctx, allPeers)
	newSet := make(map[string]bool, len(newActive))
	for _, p := range newActive {
		newSet[p] = true
	}

	nowMs := txTimestampMs(ctx)

	// Emit PeerPromoted for any OBU that entered the active set this round.
	// RSU peers starting at τ=1.0 are not logged as "promotions" — they are
	// fixed Tier 1 infrastructure. Only OBU (Tier 2) entries are promotions.
	for _, pid := range newActive {
		if prevSet[pid] {
			continue // already active last round
		}
		r := loadTrust(ctx, pid)
		if r.IsRSUPeer {
			continue // Tier 1 RSU peers are not OBU promotions
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"peer_id":      pid,
			"trust_score":  r.Score,
			"promoted_at":  nowMs,
			"active_count": len(newActive),
			"np":           NpConsensus,
			"message":      "OBU peer promoted into active consensus set — vacancy filled after checkpoint sync",
		})
		ctx.GetStub().SetEvent("PeerPromoted", payload)
	}

	// Emit PeerDroppedFromActive for any peer that left the active set this round
	// without entering the formal demotion pipeline (score drift, mobility, etc.).
	// Peers that entered QUARANTINED or REMOVED already have their own events.
	for pid := range prevSet {
		if newSet[pid] {
			continue // still active
		}
		r := loadTrust(ctx, pid)
		if r.State == PeerStateQuarantined || r.State == PeerStateRemoved {
			continue // already handled by demotion pipeline events
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"peer_id":      pid,
			"trust_score":  r.Score,
			"dropped_at":   nowMs,
			"active_count": len(newActive),
			"message":      "Peer fell below eligibility threshold — removed from active set this round",
		})
		ctx.GetStub().SetEvent("PeerDroppedFromActive", payload)
	}

	// Persist the new active set so the next call can detect changes.
	if data, err := json.Marshal(newActive); err == nil {
		ctx.GetStub().PutState("ACTIVE_PEER_SET", data)
	}

	return newActive, nil
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
//  selectPeers — Pactive = highest-trust eligible peers (Eq. 3.41)
//  Eligibility predicate (certificate, HW, dwell, trust ≥ τ_min, no flag) is Eq. 3.40.
//  Vacancy-driven: fills up to np = 3f+1 slots from the eligible set ranked by trust.
//  An OBU is promoted only when a slot opens (active peer quarantined/removed).
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

// computeTMinMs implements T_min = max(3·T_PBFT, L_link/2)
// where L_link = 2·r_comm / v_max  (all in milliseconds).
// Ledger keys SIM_TPBFT_MS, SIM_VMAX_KMH, SIM_RCOMM are set by
// SetMobilityParams at bootstrap; defaults match the FYP scenario.
func computeTMinMs(ctx contractapi.TransactionContextInterface) int64 {
	readInt64 := func(key string, def int64) int64 {
		v, err := ctx.GetStub().GetState(key)
		if err != nil || len(v) == 0 {
			return def
		}
		var n int64
		if _, err2 := fmt.Sscanf(string(v), "%d", &n); err2 != nil || n <= 0 {
			return def
		}
		return n
	}
	readFloat64 := func(key string, def float64) float64 {
		v, err := ctx.GetStub().GetState(key)
		if err != nil || len(v) == 0 {
			return def
		}
		var f float64
		if _, err2 := fmt.Sscanf(string(v), "%f", &f); err2 != nil || f <= 0 {
			return def
		}
		return f
	}

	tPBFTMs  := readInt64("SIM_TPBFT_MS", 100)
	vMaxKmh  := readFloat64("SIM_VMAX_KMH", 80.0)
	rCommM   := readFloat64("SIM_RCOMM", 300.0)

	// v_max in m/ms: 1 km/h = 1000/3600 m/s = 1/3600 m/ms
	vMaxMperMs := vMaxKmh / 3600.0
	lLinkMs := int64((2.0 * rCommM) / vMaxMperMs)

	tFromPBFT := 3 * tPBFTMs
	tFromLink := lLinkMs / 2
	if tFromPBFT > tFromLink {
		return tFromPBFT
	}
	return tFromLink
}

func selectPeers(ctx contractapi.TransactionContextInterface, allPeers []string) []string {
	np := NpConsensus // 8 active peers (np ≥ 3f+1=7 for f=2, +1 for redundancy)
	nowMs := txTimestampMs(ctx)
	tMinMs := computeTMinMs(ctx)

	// Detect no-RSU scenario from the ledger flag set by SetSimParams.
	// Reading from SIM_NO_RSU_MODE rather than inferring from peer existence
	// is necessary because RSU peers are always registered on the Fabric network
	// (bootstrapped at startup) regardless of whether the NS-3 scenario has RSU
	// infrastructure — so peer-existence detection would always return false.
	noRSUMode := false
	if flag, err := ctx.GetStub().GetState("SIM_NO_RSU_MODE"); err == nil && string(flag) == "1" {
		noRSUMode = true
	}

	type peerScore struct {
		id    string
		score float64
	}
	var eligible []peerScore
	for _, pid := range allPeers {
		r := loadTrust(ctx, pid)
		// Exclude peers in the demotion pipeline
		if r.State == PeerStateQuarantined || r.State == PeerStateRemoved {
			continue
		}
		if r.Flagged {
			continue
		}
		if r.Score < TrustMin {
			continue
		}
		if !r.IsRSUPeer {
			// Eq. 3.40 conditions 2 (Cmin hardware floor) and 3 (Tmin dwell time)
			// are bypassed in no-RSU mode; conditions 1, 4, 5 remain mandatory.
			if !noRSUMode {
				if r.JoinedAtMs > 0 && (nowMs-r.JoinedAtMs) < tMinMs {
					continue
				}
				if r.HWCapacity > 0 && r.HWCapacity < HWCapacityMinMB {
					continue
				}
				if r.HWStorageGB > 0 && r.HWStorageGB < HWStorageMinGB {
					continue
				}
			}
			// Checkpoint-sync is enforced unconditionally regardless of mode.
			// It is not one of the five Eq. 3.40 conditions and is not subject
			// to the no-RSU bypass — it is a consensus-participation precondition
			// from the anchor-checkpoint protocol (§5.1): an OBU must sync from
			// the most recent anchor before it may vote in any consensus round.
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
// BC-11 FIX: replaced CouchDB sort query (snapshot-isolation risk across endorsers)
// with deterministic ANCHOR_CTR counter → GetState("ANCHOR:<n>") path, matching
// the same pattern used by GetLatestAnchorCheckpoint in anchor.go.
func obuHasSyncedFromRecentCheckpoint(ctx contractapi.TransactionContextInterface, obuPeerID string) bool {
	data, err := ctx.GetStub().GetState(AnchorBlockCtrKey)
	if err != nil || len(data) == 0 {
		return true // no checkpoint yet — bootstrap phase
	}
	var current uint64
	fmt.Sscanf(string(data), "%d", &current)
	if current == 0 {
		return true // bootstrap phase
	}
	cpData, err := ctx.GetStub().GetState(fmt.Sprintf("ANCHOR:%d", current))
	if err != nil || len(cpData) == 0 {
		return true // checkpoint counter exists but record missing — treat as bootstrap
	}
	var cp AnchorCheckpoint
	if json.Unmarshal(cpData, &cp) != nil {
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
			"timestamp_ms": txTimestampMs(ctx),
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
		AssignedAt:      txTimestampMs(ctx),
		ZoneID:          ctrlRecord.ZoneID,
		DocType:         "CTRL_REASSIGNMENT",
		EmergencyBypass: true,
	}
	rData, _ := json.Marshal(reassignment)
	key := fmt.Sprintf("CTRL_REASSIGN:%s:%d", controllerID, reassignment.AssignedAt)
	if err := ctx.GetStub().PutState(key, rData); err != nil {
		return err
	}

	nowMs := txTimestampMs(ctx)

	credRevoke := map[string]interface{}{
		"controller_id": controllerID,
		"action":        "REVOKE_CTRL_CREDENTIALS",
		"backup_ctrl":   backupID,
		"timestamp_ms":  nowMs,
	}
	cData, _ := json.Marshal(credRevoke)
	ctx.GetStub().PutState("CTRL_REVOKED:"+controllerID, cData)

	// Emit ControllerCredentialRevocationRequested so eventListener.js can action
	// the CA call (thesis: "REVOKE CTRL CRED(Cj)" — both with-RSU and no-RSU paths).
	// The actual CA interaction is off-chain; the event is the notification boundary.
	ctrlCertPayload, _ := json.Marshal(map[string]interface{}{
		"type":          "CTRL_CREDENTIAL_REVOCATION_REQUESTED",
		"controller_id": controllerID,
		"zone_id":       ctrlRecord.ZoneID,
		"revoked_at_ms": nowMs,
	})
	ctx.GetStub().SetEvent("ControllerCredentialRevocationRequested", ctrlCertPayload)

	evPayload, _ := json.Marshal(map[string]interface{}{
		"type":         "CONTROLLER_REASSIGNMENT",
		"removed_ctrl": controllerID,
		"backup_ctrl":  backupID,
		"trust_score":  newScore,
		"zone_id":      ctrlRecord.ZoneID,
		"timestamp_ms": nowMs,
	})
	ctx.GetStub().SetEvent("ControllerRemoved", evPayload)

	// Publish ControllerRevokedBeacon for both paths.
	// No-RSU path: steps ii–iii of the three-step removal (beacon propagation +
	// Ck* self-solicitation via V2X). With-RSU path: also published.
	//
	// The FlowMod OVERRIDE rules (priority 65535/65534) that runMitigation installs
	// ARE a thesis-specified action — Algorithm 4 explicitly includes "the smart
	// contract additionally issues a FlowMod directly overriding the controller's
	// current routing table" as one of its own steps. The OVERRIDE FlowMod is
	// therefore correct per thesis, not a substitute.
	// What IS missing from this implementation is the ADDITIONAL southbound-repoint
	// mechanism: RSU OpenFlow agents physically switching their connection from Cj to
	// Ck*, with Ck* receiving an instant topology snapshot from RSU beacon evidence.
	// That piece requires live OpenFlow controller infrastructure outside the NS-3
	// simulation scope and is the only actual gap relative to the thesis specification.
	_ = publishControllerRevokedBeacon(ctx, controllerID, backupID)

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

	np := NpConsensus
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
