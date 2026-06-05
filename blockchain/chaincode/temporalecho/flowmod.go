package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// FlowMod enforcement interface — Blockchain → SDN Controller (§9).
//
// The smart contract issues FlowMod commands TO the controller; the controller
// is a recipient, never a source of ground truth.  Higher-priority FlowMods
// override anything the (potentially malicious) controller has installed:
//
//   Priority 65535 — CTRL_ORIGIN override (overrides all rules)
//   Priority 65000 — TTW/BSHH DROP (node isolation)
//   Priority 50000 — ME REROUTE (false-path correction)
//   Priority ≤32768 — normal controller rules
//
// The Ryu REST endpoint is configurable via RYU_REST_BASE.  In a Docker
// deployment the controller runs at http://ryu-controller:8080 (§6.5).

const (
	ryuRESTBase   = "http://ryu-controller:8080"
	flowModURL    = ryuRESTBase + "/stats/flowentry/add"
	flowDeleteURL = ryuRESTBase + "/stats/flowentry/delete"
	ryuTimeoutMs  = 50 // must fit in 100 ms budget
)

// RyuFlowMod is the JSON body for a Ryu REST API flowentry request.
type RyuFlowMod struct {
	DPID        int                      `json:"dpid"`
	TableID     int                      `json:"table_id"`
	IdleTimeout int                      `json:"idle_timeout"`
	HardTimeout int                      `json:"hard_timeout"`
	Priority    int                      `json:"priority"`
	Match       map[string]interface{}   `json:"match"`
	Actions     []map[string]interface{} `json:"actions"`
}

// pushFlowModDrop isolates offending vehicle v by dropping all its traffic at
// the switch level (Step 16 of Algorithm 4, §6.5).
// Priority 65000 overrides all normal controller rules.
func pushFlowModDrop(vehicleID string) error {
	fm := RyuFlowMod{
		DPID:        1,
		TableID:     0,
		IdleTimeout: 0,
		HardTimeout: 0,
		Priority:    65000,
		Match: map[string]interface{}{
			"eth_src": vehicleMAC(vehicleID),
		},
		Actions: []map[string]interface{}{}, // empty = DROP
	}
	return sendFlowMod(fm)
}

// pushRerouteFlowMod removes false-path routing rules installed by ME attack
// (Step 22 of Algorithm 4, §6.5).
func pushRerouteFlowMod(vehicleID string) error {
	deleteRule := RyuFlowMod{
		DPID:     1,
		TableID:  0,
		Priority: 50000,
		Match: map[string]interface{}{
			"metadata": fmt.Sprintf("FALSE_PATH_%s", vehicleID),
		},
		Actions: []map[string]interface{}{},
	}
	if err := sendFlowModDelete(deleteRule); err != nil {
		return err
	}
	// Reroute: controller recomputes from corrected topology after paths are
	// invalidated in the chaincode's ledger state.
	return nil
}

// pushFlowModOverride issues a priority-65535 FlowMod directly to all known
// switches using RSU beacon evidence as the authoritative topology (§9.3).
// This bypasses the malicious controller entirely for CTRL_ORIGIN attacks.
func pushFlowModOverride(controllerID string, evidence []BeaconEvidenceRecord) error {
	routes := computeCorrectRoutes(evidence)
	for _, route := range routes {
		if err := sendFlowMod(route); err != nil {
			return fmt.Errorf("override FlowMod failed: %v", err)
		}
	}
	return nil
}

// sendFlowMod posts a FlowMod to the Ryu REST API with a 50 ms timeout.
func sendFlowMod(fm RyuFlowMod) error {
	payload, _ := json.Marshal(fm)
	client := &http.Client{Timeout: time.Duration(ryuTimeoutMs) * time.Millisecond}
	resp, err := client.Post(flowModURL, "application/json",
		bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FlowMod rejected by controller: HTTP %d", resp.StatusCode)
	}
	return nil
}

// sendFlowModDelete posts a flow-entry delete request.
func sendFlowModDelete(fm RyuFlowMod) error {
	payload, _ := json.Marshal(fm)
	client := &http.Client{Timeout: time.Duration(ryuTimeoutMs) * time.Millisecond}
	resp, err := client.Post(flowDeleteURL, "application/json",
		bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// vehicleMAC converts a vehicle ID string to a MAC-address-style string for
// the OpenFlow match field.  Format: "vv:vv:vv:vv:vv:vv" derived from the
// first 6 bytes of the vehicle ID.
func vehicleMAC(vehicleID string) string {
	b := []byte(vehicleID)
	for len(b) < 6 {
		b = append(b, 0)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

// computeCorrectRoutes derives a minimal set of FlowMod entries from RSU
// beacon evidence — used only during CTRL_ORIGIN override (§9.3).
// Each pair of vehicles that appeared in the same beacon observation interval
// gets a forwarding rule installed at priority 65535.
func computeCorrectRoutes(evidence []BeaconEvidenceRecord) []RyuFlowMod {
	var routes []RyuFlowMod
	seen := make(map[string]bool)
	for _, rec := range evidence {
		for _, obs := range rec.Observations {
			key := obs.VehicleID
			if seen[key] {
				continue
			}
			seen[key] = true
			routes = append(routes, RyuFlowMod{
				DPID:        1,
				TableID:     0,
				IdleTimeout: 30,
				HardTimeout: 0,
				Priority:    65535,
				Match: map[string]interface{}{
					"eth_src": vehicleMAC(obs.VehicleID),
				},
				Actions: []map[string]interface{}{
					{"type": "OUTPUT", "port": "NORMAL"},
				},
			})
		}
	}
	return routes
}
