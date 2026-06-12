package main

import (
	"encoding/json"
	"fmt"
	"math"

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

		// Section 5.7 — apply controller trust penalty on each confirmed divergence
		// τCj(t+1) = max(0, τCj(t) - ΔC-)
		newScore, _ := updateCtrlTrust(ctx, claim.ControllerID)

		eventPayload, _ := json.Marshal(map[string]interface{}{
			"type":              "CONTROLLER_ORIGIN_DETECTED",
			"delta":             delta,
			"threshold":         deltaThresh,
			"controller":        claim.ControllerID,
			"interval":          claim.IntervalTS,
			"ctrl_trust_score":  newScore,
			"removal_threshold": TrustCtrlMin,
			"removal_triggered": newScore < TrustCtrlMin,
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

// computeDeltaThreshold returns δ_thresh using the physics-derived formula
// from PDF Eq. 3.46:
//
//	δ_thresh = ⌈(1 + τ_prop/T_b) · λ · 2·r_comm⌉ + 1
//
//	τ_prop/T_b ≈ 0.1   — propagation delay is ~T_b/10 (10 ms / 100 ms)
//	λ          = 0.02  — vehicle density (vehicles per metre, urban 1D road model)
//	r_comm     = 300.0 — DSRC communication range (metres)
//
//	Numeric result for default parameters:
//	  (1 + 0.1) · 0.02 · 600 = 1.1 · 12 = 13.2  →  ⌈13.2⌉ + 1 = 14
//
// This matches the value stated in Table 11.1 of the PDF (δ_thresh = 14).
// The minimum of 2 guards against degenerate cases with no evidence.
//
// The evidenceLinkSet parameter is retained for API compatibility but is not
// used in this formula — the threshold is a network-physics constant, not
// a function of the observed link count.
func computeDeltaThreshold(evidenceLinkSet map[string]bool) int {
	const (
		tauPropOverTb = 0.1   // τ_prop ≈ T_b/10
		lambda        = 0.02  // vehicle density (veh/m), urban 1D road model
		rComm         = 300.0 // DSRC communication range (m)
		minThresh     = 2
	)

	// δ_thresh = ⌈(1 + τ_prop/T_b) · λ · 2·r_comm⌉ + 1  (Eq. 3.46)
	raw := (1.0 + tauPropOverTb) * lambda * 2.0 * rComm
	thresh := int(math.Ceil(raw)) + 1 // = 14 for default parameters
	if thresh < minThresh {
		return minThresh
	}
	return thresh
}
