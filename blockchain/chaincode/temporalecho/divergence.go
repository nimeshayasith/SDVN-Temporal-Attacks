package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Controller-origin attack detection via topology divergence check (§8).
//
// Implements Eq. 3.1:
//   δ(G_t^C, G_t^R) = |E_t^C △ E_t^nodes| > δ_thresh
//
// E_t^C     — set of links in the controller's claimed topology G_t^C
// E_t^nodes — set of links attested by ≥1 RSU/OBU beacon evidence record
// △          — symmetric difference
//
// This check is independent of the controller: evidence is already on the
// ledger before the controller submits its claim, so a malicious controller
// cannot suppress it (§8.3).

// checkControllerDivergence is called automatically whenever the controller
// submits a topology claim (Flow 3).  If δ > δ_thresh it emits
// ControllerOriginAttack without waiting for the TGN path.
func (t *TemporalEchoMitigator) checkControllerDivergence(
	ctx contractapi.TransactionContextInterface,
	claim ControllerTopologyClaim,
) error {
	ctrlLinkSet := buildLinkSet(claim.Links)
	evidenceLinkSet := aggregateEvidenceLinkSet(ctx, claim.IntervalTS)

	delta := symmetricDifference(ctrlLinkSet, evidenceLinkSet)
	deltaThresh := computeDeltaThreshold(evidenceLinkSet)

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

		eventPayload, _ := json.Marshal(map[string]interface{}{
			"type":       "CONTROLLER_ORIGIN_DETECTED",
			"delta":      delta,
			"threshold":  deltaThresh,
			"controller": claim.ControllerID,
			"interval":   claim.IntervalTS,
		})
		ctx.GetStub().SetEvent("ControllerOriginAttack", eventPayload)
	}
	return nil
}

// computeDivergence is the Mitigate() entry point for the divergence step.
// Returns (delta, deltaThresh) so the caller can append a CTRL_ORIGIN alert.
func computeDivergence(
	ctx contractapi.TransactionContextInterface,
	claim ControllerTopologyClaim,
) (int, int) {
	ctrlLinkSet := buildLinkSet(claim.Links)
	evidenceLinkSet := aggregateEvidenceLinkSet(ctx, claim.IntervalTS)
	return symmetricDifference(ctrlLinkSet, evidenceLinkSet),
		computeDeltaThreshold(evidenceLinkSet)
}

// buildLinkSet converts a slice of TopologyLinks into a canonical link-ID set.
// Links are bidirectional: key = "minNode:maxNode" so A:B == B:A.
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

// aggregateEvidenceLinkSet builds E_t^nodes from all BeaconEvidenceRecords for
// the given interval.  A link e_ij ∈ E_t^nodes if both Vi and Vj appeared in
// the same peer's observation set (meaning they were in radio range).
func aggregateEvidenceLinkSet(
	ctx contractapi.TransactionContextInterface,
	intervalTS int64,
) map[string]bool {
	set := make(map[string]bool)

	queryStr := fmt.Sprintf(
		`{"selector":{"doc_type":"BEACON_EVIDENCE","interval_ts":%d}}`, intervalTS)
	iter, err := ctx.GetStub().GetQueryResult(queryStr)
	if err != nil {
		return set
	}
	defer iter.Close()

	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			continue
		}
		var record BeaconEvidenceRecord
		if err := json.Unmarshal(qr.Value, &record); err != nil {
			continue
		}
		vids := make([]string, 0, len(record.Observations))
		for _, obs := range record.Observations {
			vids = append(vids, obs.VehicleID)
		}
		for i := 0; i < len(vids); i++ {
			for j := i + 1; j < len(vids); j++ {
				a, b := vids[i], vids[j]
				if a > b {
					a, b = b, a
				}
				set[fmt.Sprintf("%s:%s", a, b)] = true
			}
		}
	}
	return set
}

// symmetricDifference returns |A △ B| = |(A\B) ∪ (B\A)|.
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

// computeDeltaThreshold returns the maximum tolerable divergence δ_thresh for
// the current beacon interval, calibrated from the evidence link set (§12.1).
//
// Formula (derived from vehicular link-churn theory):
//
//	δ_thresh = max(δ_min, ⌈α · L + β · N⌉)
//
//	L = |E_t^nodes|  — number of attested links in beacon evidence
//	N                — unique vehicle count extracted from those link endpoints
//	α = 0.10         — fraction of observed links tolerated as legitimate churn
//	                   (mean link lifetime ≈ 40 s, beacon interval ≈ 100 ms →
//	                    per-interval churn rate ≈ 0.25 %; α adds safety margin)
//	β = 0.05         — per-vehicle allowance for RSU zone-boundary partial
//	                   observations (vehicles straddling two RSU coverage zones
//	                   may appear in one zone's evidence but not another's)
//	δ_min = 2        — minimum threshold even in empty or low-evidence networks
//
// No additional ledger query: the evidenceLinkSet is already fetched by the
// caller (aggregateEvidenceLinkSet), so this function is purely arithmetic.
func computeDeltaThreshold(evidenceLinkSet map[string]bool) int {
	const (
		minThresh      = 2
		alpha          = 0.10 // link-churn fraction
		betaPerVehicle = 0.05 // per-vehicle zone-edge allowance
	)

	L := len(evidenceLinkSet)
	if L == 0 {
		return minThresh
	}

	// Recover unique vehicle IDs from the canonical "minNode:maxNode" keys.
	uniqueNodes := make(map[string]bool, 2*L)
	for key := range evidenceLinkSet {
		if i := strings.IndexByte(key, ':'); i >= 0 {
			uniqueNodes[key[:i]] = true
			uniqueNodes[key[i+1:]] = true
		}
	}
	N := len(uniqueNodes)

	thresh := int(math.Ceil(alpha*float64(L) + betaPerVehicle*float64(N)))
	if thresh < minThresh {
		return minThresh
	}
	return thresh
}
