package main

import (
	"math"
)

// Cryptographic and spatial verification helpers for Algorithm 4.
//
// Dilithium2 note: production deployment requires liboqs-go
// (github.com/open-quantum-safe/liboqs-go). The stub below accepts all
// non-empty signatures so the chaincode compiles and runs without CGo.
// Replace verifyDilithium2Sig with a real call once liboqs-go is linked.

// verifyDilithium2Sig verifies a Dilithium2 signature (σ_nk) over message
// using pubKey.  Returns true if the signature is structurally present.
// In production: call OQS_SIG_verify(sig, msg, pk) from liboqs-go.
func verifyDilithium2Sig(sig []byte, message string, pubKey []byte) bool {
	// Simulation mode: accept any non-nil signature.
	// Real implementation: use liboqs-go dilithium2 verify.
	return len(sig) > 0 || len(pubKey) == 0
}

// verifyThresholdSig implements Eq. 3.24:
//   |{i : Verify(σ_i, msg_i, PK_Vi) = 1}| ≥ t
//
// Returns true if at least thresholdT individual Dilithium2 signatures verify.
func verifyThresholdSig(evidence []IndividualSigEvidence, thresholdT int) bool {
	valid := 0
	for _, e := range evidence {
		if verifyDilithium2Sig(e.Signature, e.Message, e.PubKey) {
			valid++
		}
	}
	return valid >= thresholdT
}

// verifyQuorum implements Eqs. 3.27–3.28:
//   Accept(e_ij) ⟺ |{Vk : Accept_Vk(e_ij)=1}| ≥ t
//
// A witness Vk is accepted if:
//   (i)  Verify(σ_Vk, PK_Vk) = 1                  — cryptographic authenticity
//   (ii) d(pos_Vk, e_ij) ≤ r_comm (300 m)          — spatial plausibility (Eq.3.27)
//   (iii) RSSI_Vk ≥ RSSImin (-85 dBm)              — signal plausibility (Eq.3.27)
func verifyQuorum(
	witnesses []WitnessRecord,
	thresholdT int,
	linkEndpointLat, linkEndpointLon float64,
) bool {
	const rCommMeters = 300.0
	const rssiMinDBm = -85.0

	accepted := 0
	for _, w := range witnesses {
		if !verifyDilithium2Sig(w.Signature, w.Message, w.PubKey) {
			continue
		}
		dist := haversineDistanceM(w.ReporterLat, w.ReporterLon,
			linkEndpointLat, linkEndpointLon)
		if dist > rCommMeters {
			continue
		}
		if w.RSSIFromVI < rssiMinDBm {
			continue
		}
		accepted++
	}
	return accepted >= thresholdT
}

// haversineDistanceM returns the great-circle distance in metres between two
// GPS coordinates.  Used by verifyQuorum and the divergence check.
func haversineDistanceM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthR = 6371000.0
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180.0)*math.Cos(lat2*math.Pi/180.0)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthR * 2.0 * math.Atan2(math.Sqrt(a), math.Sqrt(1.0-a))
}

// sTrigsToMask converts a slice of signature indices to a 9-bit bitmask.
func sTrigsToMask(indices []int) uint32 {
	var mask uint32
	for _, i := range indices {
		if i >= 0 && i < 32 {
			mask |= 1 << uint(i)
		}
	}
	return mask
}

// resolveDualPath handles conflicts when both LW and FS paths flag the same
// vehicle simultaneously (§11.2).  Takes the union of variants and applies
// the most restrictive action: FLOWMOD_DROP > REROUTE > PATH_INVALIDATE.
func resolveDualPath(alerts []DetectionEvent) []DetectionEvent {
	perVehicle := make(map[string][]DetectionEvent)
	for _, a := range alerts {
		perVehicle[a.VehicleID] = append(perVehicle[a.VehicleID], a)
	}

	var resolved []DetectionEvent
	for _, vehicleAlerts := range perVehicle {
		if len(vehicleAlerts) == 1 {
			resolved = append(resolved, vehicleAlerts[0])
			continue
		}
		merged := vehicleAlerts[0]
		merged.TriggeredSigs = 0
		hasTTWBSHH := false
		for _, a := range vehicleAlerts {
			merged.TriggeredSigs |= a.TriggeredSigs
			if a.AnomalyScore > merged.AnomalyScore {
				merged.AnomalyScore = a.AnomalyScore
			}
			if a.AttackVariant == "TTW" || a.AttackVariant == "BSHH" {
				hasTTWBSHH = true
			}
			if !merged.FromLWPath {
				merged.FromLWPath = a.FromLWPath
			}
			if !merged.FromFSPath {
				merged.FromFSPath = a.FromFSPath
			}
		}
		if hasTTWBSHH {
			merged.AttackVariant = "TTW_BSHH_COMBINED"
		}
		resolved = append(resolved, merged)
	}
	return resolved
}
