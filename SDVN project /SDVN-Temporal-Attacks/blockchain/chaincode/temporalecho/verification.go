package main

import (
	"fmt"
	"math"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Cryptographic and spatial verification helpers for Algorithm 4.
//
// verifyMLDSA87Sig is defined in one of two build-tag files:
//   verification_stub.go   — default build (no liboqs; requires TETA_SIMULATION_MODE=1)
//   verification_liboqs.go — build with: go build -tags liboqs

// verifyThresholdSig implements Eq. 3.26:
//
//	Verify(σagg,PKagg)=1 ⟺ |{i : Verify(σi,msgi,PKVi)=1}| ≥ t, t ≥ ⌊n/2⌋+1
func verifyThresholdSig(evidence []IndividualSigEvidence, thresholdT int) bool {
	valid := 0
	for _, e := range evidence {
		if verifyMLDSA87Sig(e.Signature, e.Message, e.PubKey) {
			valid++
		}
	}
	return valid >= thresholdT
}

// loadFloatParam reads a named float64 parameter from the ledger, returning
// defaultVal when the key is absent or unparseable.  Used for calibration
// values (θFS, θLW) that are TBD in the thesis and set via SetSimParams.
func loadFloatParam(ctx contractapi.TransactionContextInterface, key string, defaultVal float64) float64 {
	d, err := ctx.GetStub().GetState(key)
	if err != nil || len(d) == 0 {
		return defaultVal
	}
	var v float64
	if _, err2 := fmt.Sscanf(string(d), "%f", &v); err2 != nil || v <= 0 {
		return defaultVal
	}
	return v
}

// loadSimParams reads simulation-configurable spatial thresholds from the ledger.
// VF-02 FIX: verifyQuorum previously used compile-time constants rCommMeters=300.0
// and rssiMinDBm=-85.0. Tests with different rcomm values (e.g. 150 m) required
// recompiling the chaincode. These are now ledger-readable via SetSimParams()
// and bootstrap.sh. Falls back to NS-3 defaults if not set.
func loadSimParams(ctx contractapi.TransactionContextInterface) (rCommMeters float64, rssiMinDBm float64) {
	rCommMeters = 300.0
	rssiMinDBm = -85.0

	if d, err := ctx.GetStub().GetState("SIM_RCOMM"); err == nil && len(d) > 0 {
		fmt.Sscanf(string(d), "%f", &rCommMeters)
	}
	if d, err := ctx.GetStub().GetState("SIM_RSSI_MIN"); err == nil && len(d) > 0 {
		fmt.Sscanf(string(d), "%f", &rssiMinDBm)
	}
	return
}

// verifyQuorum implements Eqs. 3.27–3.28:
//
//	Accept(e_ij) ⟺ |{Vk : Accept_Vk(e_ij)=1}| ≥ t
//
// VF-02: accepts ctx to read configurable rComm and rssiMin from ledger.
func verifyQuorum(
	ctx contractapi.TransactionContextInterface,
	witnesses []WitnessRecord,
	thresholdT int,
	linkEndpointLat, linkEndpointLon float64,
) bool {
	rCommMeters, rssiMinDBm := loadSimParams(ctx)

	accepted := 0
	for _, w := range witnesses {
		if !verifyMLDSA87Sig(w.Signature, w.Message, w.PubKey) {
			continue
		}
		dist := haversineDistanceM(w.ReporterLat, w.ReporterLon,
			linkEndpointLat, linkEndpointLon)
		if dist > rCommMeters {
			continue
		}
		if float64(w.RSSIFromVI) < rssiMinDBm {
			continue
		}
		accepted++
	}
	return accepted >= thresholdT
}

// haversineDistanceM returns the great-circle distance in metres between two GPS coordinates.
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

// resolveDualPath handles LW/FS dual-path conflicts (§11.2).
// V-2: tracks hasME separately; TTW/BSHH DROP wins over ME REROUTE.
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
		hasME := false
		for _, a := range vehicleAlerts {
			merged.TriggeredSigs |= a.TriggeredSigs
			if a.AnomalyScore > merged.AnomalyScore {
				merged.AnomalyScore = a.AnomalyScore
			}
			if a.AttackVariant == "TTW" || a.AttackVariant == "BSHH" ||
				a.AttackVariant == "TTW_BSHH_COMBINED" {
				hasTTWBSHH = true
			}
			if a.AttackVariant == "ME" {
				hasME = true
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
		} else if hasME {
			merged.AttackVariant = "ME"
		}
		resolved = append(resolved, merged)
	}
	return resolved
}
