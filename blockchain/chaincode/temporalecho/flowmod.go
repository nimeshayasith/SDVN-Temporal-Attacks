package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// FlowMod enforcement interface — Blockchain → SDN Controller (§9).
//
// ARCHITECTURAL DESIGN:
//   Hyperledger Fabric chaincode runs in a deterministic sandboxed container
//   with no external network access.  It CANNOT make HTTP calls directly to
//   the Ryu SDN controller — any attempt to open a TCP connection will be
//   blocked by the peer.
//
//   Correct Fabric pattern (§9, off-chain listener):
//     1. Chaincode writes a PendingFlowMod record to the ledger.
//     2. Chaincode emits an AttackDetected event (already done in runMitigation).
//     3. Off-chain listener (eventListener.js) picks up the event.
//     4. eventListener.js reads PendingFlowMod records from the ledger.
//     5. eventListener.js makes the actual HTTP POST to Ryu controller.
//
//   FlowMod priority levels:
//     Priority 65535 — CTRL_ORIGIN override (overrides all rules)
//     Priority 65000 — TTW/BSHH DROP (node isolation)
//     Priority 50000 — ME REROUTE (false-path correction)
//     Priority ≤32768 — normal controller rules

// PendingFlowMod is written to the Fabric ledger by the chaincode.
// eventListener.js reads these records and executes the actual HTTP POST.
type PendingFlowMod struct {
	EntryID     string                   `json:"entry_id"`
	VehicleID   string                   `json:"vehicle_id"`
	Action      string                   `json:"action"`    // "DROP" | "REROUTE" | "OVERRIDE"
	Priority    int                      `json:"priority"`
	Match       map[string]interface{}   `json:"match"`
	FlowActions []map[string]interface{} `json:"flow_actions"`
	DocType     string                   `json:"doc_type"`
}

// RyuFlowMod is the JSON body for a Ryu REST API flowentry request.
// Populated by eventListener.js when it reads a PendingFlowMod record.
type RyuFlowMod struct {
	DPID        int                      `json:"dpid"`
	TableID     int                      `json:"table_id"`
	IdleTimeout int                      `json:"idle_timeout"`
	HardTimeout int                      `json:"hard_timeout"`
	Priority    int                      `json:"priority"`
	Match       map[string]interface{}   `json:"match"`
	Actions     []map[string]interface{} `json:"actions"`
}

// pushFlowModDrop writes a DROP PendingFlowMod to the ledger.
// eventListener.js will POST this to Ryu as Priority-65000 DROP rule
// (Step 16 of Algorithm 4, §6.5).
func pushFlowModDrop(vehicleID string) error {
	// vehicleMAC lookup — requires populated VehicleMACTable on ledger.
	// Falls back to vehicleIDtoMAC placeholder if not populated.
	mac := lookupVehicleMAC(vehicleID)

	fm := PendingFlowMod{
		EntryID:   fmt.Sprintf("FLOWMOD_DROP_%s", vehicleID),
		VehicleID: vehicleID,
		Action:    "DROP",
		Priority:  65000,
		Match:     map[string]interface{}{"eth_src": mac},
		FlowActions: []map[string]interface{}{}, // empty = DROP
		DocType:   "PENDING_FLOWMOD",
	}
	return writePendingFlowMod(fm)
}

// pushRerouteFlowMod writes a REROUTE PendingFlowMod to the ledger.
// eventListener.js deletes the false-path rule from Ryu (Step 22 of Algorithm 4).
func pushRerouteFlowMod(vehicleID string) error {
	fm := PendingFlowMod{
		EntryID:   fmt.Sprintf("FLOWMOD_REROUTE_%s", vehicleID),
		VehicleID: vehicleID,
		Action:    "REROUTE",
		Priority:  50000,
		Match:     map[string]interface{}{"metadata": fmt.Sprintf("FALSE_PATH_%s", vehicleID)},
		FlowActions: []map[string]interface{}{},
		DocType:   "PENDING_FLOWMOD",
	}
	return writePendingFlowMod(fm)
}

// pushFlowModOverride writes priority-65535 OVERRIDE FlowMods derived from
// RSU beacon evidence — used for CTRL_ORIGIN attacks (§9.3).
func pushFlowModOverride(controllerID string, evidence []BeaconEvidenceRecord) error {
	seen := make(map[string]bool)
	for _, rec := range evidence {
		for _, obs := range rec.Observations {
			if seen[obs.VehicleID] {
				continue
			}
			seen[obs.VehicleID] = true
			mac := lookupVehicleMAC(obs.VehicleID)
			fm := PendingFlowMod{
				EntryID:   fmt.Sprintf("FLOWMOD_OVERRIDE_%s", obs.VehicleID),
				VehicleID: obs.VehicleID,
				Action:    "OVERRIDE",
				Priority:  65535,
				Match:     map[string]interface{}{"eth_src": mac},
				FlowActions: []map[string]interface{}{
					{"type": "OUTPUT", "port": "NORMAL"},
				},
				DocType: "PENDING_FLOWMOD",
			}
			if err := writePendingFlowMod(fm); err != nil {
				return fmt.Errorf("override FlowMod failed for %s: %v", obs.VehicleID, err)
			}
		}
	}
	return nil
}

// writePendingFlowMod stores the FlowMod record on the Fabric ledger.
// eventListener.js polls for PENDING_FLOWMOD entries and executes them.
//
// NOTE: ctx is not available here because flowmod functions are called from
// runMitigation which receives ctx.  The ctx is threaded through via a
// package-level variable set at the start of each transaction.
var g_ctx contractapi.TransactionContextInterface

func writePendingFlowMod(fm PendingFlowMod) error {
	if g_ctx == nil {
		// No ledger context (unit test mode) — log and return
		data, _ := json.Marshal(fm)
		fmt.Printf("[FlowMod] (no ledger) PendingFlowMod: %s\n", string(data))
		return nil
	}
	data, err := json.Marshal(fm)
	if err != nil {
		return err
	}
	return g_ctx.GetStub().PutState(fm.EntryID, data)
}

// VehicleMACTable maps vehicle IDs to their actual NS-3 / Ethernet MAC
// addresses.  Populated at network setup time via SubmitVehicleMAC().
// Key = vehicle_id (e.g. "V2"), Value = MAC string (e.g. "02:00:00:00:00:02")
//
// Falls back to ns3VehicleIDtoMAC() if the ledger table is empty.
func lookupVehicleMAC(vehicleID string) string {
	if g_ctx != nil {
		key := "VMAC_" + vehicleID
		data, err := g_ctx.GetStub().GetState(key)
		if err == nil && len(data) > 0 {
			return string(data)
		}
	}
	// Fallback: derive a locally-administered MAC from the vehicle index.
	// Format: 02:00:00:00:00:XX  where XX = vehicle number parsed from ID.
	return ns3VehicleIDtoMAC(vehicleID)
}

// ns3VehicleIDtoMAC derives a locally-administered unicast MAC from a vehicle
// ID string such as "V2", "V10", "V100".
// Format: 02:00:00:00:HH:LL  (02 = locally administered unicast bit set)
// e.g. "V2"  → "02:00:00:00:00:02"
//      "V255"→ "02:00:00:00:00:ff"
//      "V256"→ "02:00:00:00:01:00"
func ns3VehicleIDtoMAC(vehicleID string) string {
	// Extract numeric suffix from vehicle ID (strip leading non-digits)
	n := 0
	for _, c := range vehicleID {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	// Encode as two-byte little-endian in the last two octets
	hi := (n >> 8) & 0xff
	lo := n & 0xff
	return fmt.Sprintf("02:00:00:00:%02x:%02x", hi, lo)
}
