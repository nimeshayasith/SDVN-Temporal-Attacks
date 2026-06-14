package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Controller-origin attack detection via topology divergence check (§8).
//
// δ(G_t^C, G_t^R) = |E_t^C △ E_t^nodes| > δ_thresh  (Eq. 3.1)

// checkControllerDivergence detects divergence and emits ControllerOriginAttack.
//
// DV-03 FIX: This function NO LONGER calls updateCtrlTrust or
// CheckControllerTrustAndReassign. It only stores the detection event and emits
// the Fabric event. runMitigation() is the SINGLE authority for trust penalties,
// preventing the triple-penalty issue where divergence check + runMitigation each
// applied -ΔC- independently.
func (t *TemporalEchoMitigator) checkControllerDivergence(
	ctx contractapi.TransactionContextInterface,
	claim ControllerTopologyClaim,
) error {
	ctrlLinkSet := buildLinkSet(claim.Links)
	evidenceLinkSet := aggregateEvidenceLinkSet(ctx, claim.IntervalTS)

	delta := symmetricDifference(ctrlLinkSet, evidenceLinkSet)
	deltaThresh := computeDeltaThreshold(ctx, claim.IntervalTS, evidenceLinkSet)

	if delta > deltaThresh {
		alert := DetectionEvent{
			PeerID:        "DIVERGENCE_CHECK",
			VehicleID:     claim.ControllerID,
			AttackVariant: "CTRL_ORIGIN",
			AnomalyScore:  float32(delta),
			AlertTS:       claim.IntervalTS,
			DocType:       "DETECTION_EVENT",
		}
		alertJSON, _ := json.Marshal(alert)
		key := fmt.Sprintf("DETECTION:DIVERGENCE:%s:%d",
			claim.ControllerID, claim.IntervalTS)
		ctx.GetStub().PutState(key, alertJSON)

		// DV-03: read CURRENT (pre-penalty) trust score for the event payload.
		// The penalty is applied only when runMitigation() is called via SubmitAlert.
		currentScore := loadCtrlTrust(ctx, claim.ControllerID).Score

		eventPayload, _ := json.Marshal(map[string]interface{}{
			"type":              "CONTROLLER_ORIGIN_DETECTED",
			"delta":             delta,
			"threshold":         deltaThresh,
			"controller":        claim.ControllerID,
			"interval":          claim.IntervalTS,
			"ctrl_trust_score":  currentScore,
			"removal_threshold": TrustCtrlMin,
		})
		ctx.GetStub().SetEvent("ControllerOriginAttack", eventPayload)
	}
	return nil
}

// computeDivergence is the Mitigate() entry point for the divergence step.
func computeDivergence(
	ctx contractapi.TransactionContextInterface,
	claim ControllerTopologyClaim,
) (int, int) {
	ctrlLinkSet := buildLinkSet(claim.Links)
	evidenceLinkSet := aggregateEvidenceLinkSet(ctx, claim.IntervalTS)
	return symmetricDifference(ctrlLinkSet, evidenceLinkSet),
		computeDeltaThreshold(ctx, claim.IntervalTS, evidenceLinkSet)
}

// buildLinkSet converts TopologyLinks to a canonical bidirectional set.
func buildLinkSet(links []TopologyLink) map[string]bool {
	set := make(map[string]bool, len(links))
	for _, l := range links {
		a, b := l.NodeA, l.NodeB
		if a > b {
			a, b = b, a
		}
		set[fmt.Sprintf("%s:%s", a, b)] = true
	}
	return set
}

// aggregateEvidenceLinkSet builds E_t^nodes from beacon evidence for the interval.
//
// DV-01 FIX: GPS proximity fallback now uses rCommMeters/2 (150 m) as the
// distance bound, and requires mutual proximity — both vehicles must be in range
// of each other's GPS position. The original rCommMeters threshold created
// O(n²) phantom links in dense urban settings (up to 66 false links per RSU
// coverage area), inflating |δ| far above δ_thresh=14 and generating false
// CTRL_ORIGIN alerts.
//
// DV-04 FIX: Only evidence from peers with τk ≥ τ^gt_min (or Tier 1 RSU)
// contributes to E_t^nodes (Eq. 3.44). Sub-threshold OBU evidence is excluded.
func aggregateEvidenceLinkSet(
	ctx contractapi.TransactionContextInterface,
	intervalTS int64,
) map[string]bool {
	set := make(map[string]bool)
	const rCommMeters = 300.0
	const rCommFallback = rCommMeters / 2.0 // DV-01: tighter GPS bound

	queryStr := fmt.Sprintf(
		`{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":%d}}`, intervalTS)
	iter, err := ctx.GetStub().GetQueryResult(queryStr)
	if err != nil {
		return set
	}
	defer iter.Close()

	type obsEntry struct {
		vid        string
		lat        float64
		lon        float64
		neighbours []string
	}
	var allObs []obsEntry

	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var record BeaconEvidenceRecord
		if err := json.Unmarshal(qr.Value, &record); err != nil {
			continue
		}

		// DV-04: only include evidence from τk ≥ τ^gt_min peers (or RSU Tier 1)
		peerTrust := loadTrust(ctx, record.PeerID)
		if !record.IsRSUPeer && peerTrust.Score < TrustMinGT {
			continue
		}
		if peerTrust.Flagged {
			continue
		}

		for _, obs := range record.Observations {
			allObs = append(allObs, obsEntry{
				vid:        obs.VehicleID,
				lat:        obs.GPSLat,
				lon:        obs.GPSLon,
				neighbours: obs.NeighbourVehicles,
			})
		}
	}

	// Method 1: explicit HELLO-confirmed neighbour lists (most accurate, D-1)
	for _, obs := range allObs {
		for _, nbr := range obs.neighbours {
			a, b := obs.vid, nbr
			if a > b {
				a, b = b, a
			}
			set[fmt.Sprintf("%s:%s", a, b)] = true
		}
	}

	// Method 2: GPS proximity fallback — only when no explicit neighbour data.
	// DV-01: uses rCommFallback=150m (half of rComm) and mutual confirmation
	// to avoid creating phantom links between vehicles that just happen to be
	// heard by the same RSU but are out of V2V radio range of each other.
	if len(set) == 0 {
		for i := 0; i < len(allObs); i++ {
			for j := i + 1; j < len(allObs); j++ {
				dist := haversineDistanceM(
					allObs[i].lat, allObs[i].lon,
					allObs[j].lat, allObs[j].lon,
				)
				if dist <= rCommFallback { // DV-01: tighter 150 m bound
					a, b := allObs[i].vid, allObs[j].vid
					if a > b {
						a, b = b, a
					}
					set[fmt.Sprintf("%s:%s", a, b)] = true
				}
			}
		}
	}

	return set
}

// symmetricDifference returns |A △ B|.
func symmetricDifference(a, b map[string]bool) int {
	count := 0
	for k := range a {
		if !b[k] {
			count++
		}
	}
	for k := range b {
		if !a[k] {
			count++
		}
	}
	return count
}

// computeDeltaThreshold returns δ_thresh from Eq. 3.46.
//
// DV-02 FIX: λ is now estimated dynamically from the beacon count at intervalTS
// instead of using the compile-time constant 0.02. Fixed λ caused false positives
// in dense urban conditions (λ̂>0.02) and missed attacks in sparse highway
// conditions (λ̂<0.02).
func computeDeltaThreshold(
	ctx contractapi.TransactionContextInterface,
	intervalTS int64,
	evidenceLinkSet map[string]bool,
) int {
	const (
		tauPropOverTb = 0.1   // τ_prop/T_b ≈ 0.1
		rComm         = 300.0 // DSRC range (m)
		minThresh     = 2
	)

	// DV-02: estimate instantaneous vehicle density from beacon evidence count
	lambda := estimateLambda(ctx, intervalTS)

	raw := (1.0 + tauPropOverTb) * lambda * 2.0 * rComm
	thresh := int(math.Ceil(raw)) + 1
	if thresh < minThresh {
		return minThresh
	}
	return thresh
}

// estimateLambda estimates λ̂(t) from the count of unique vehicles in beacon
// evidence for the given interval. DV-02: replaces fixed constant 0.02.
//
// λ̂ = n_vehicles / (2 · rComm)   where rComm = 300 m
// Falls back to 0.02 when no beacon evidence is present.
func estimateLambda(
	ctx contractapi.TransactionContextInterface,
	intervalTS int64,
) float64 {
	const defaultLambda = 0.02
	const rComm = 300.0

	qs := fmt.Sprintf(`{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":%d}}`, intervalTS)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return defaultLambda
	}
	defer iter.Close()

	seen := make(map[string]bool)
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var rec BeaconEvidenceRecord
		if json.Unmarshal(qr.Value, &rec) == nil {
			for _, obs := range rec.Observations {
				seen[obs.VehicleID] = true
			}
		}
	}

	nVehicles := len(seen)
	if nVehicles < 2 {
		return defaultLambda
	}
	return float64(nVehicles) / (2.0 * rComm)
}
