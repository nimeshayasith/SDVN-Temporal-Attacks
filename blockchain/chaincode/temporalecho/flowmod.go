package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// FlowMod enforcement interface — Blockchain → SDN Controller (§9).
//
// Correct Fabric pattern: chaincode writes PendingFlowMod to ledger,
// off-chain listener (eventListener.js) reads via GetPendingFlowMod /
// GetAllPendingFlowMods and POSTs to Ryu.

// PendingFlowMod is written to the Fabric ledger by the chaincode.
// T-2: Executed/ExecutedAtMs fields for AcknowledgeFlowMod idempotency.
type PendingFlowMod struct {
	EntryID      string                   `json:"entry_id"`
	VehicleID    string                   `json:"vehicle_id"`
	Action       string                   `json:"action"`
	Priority     int                      `json:"priority"`
	Match        map[string]interface{}   `json:"match"`
	FlowActions  []map[string]interface{} `json:"flow_actions"`
	Executed     bool                     `json:"executed"`
	ExecutedAtMs int64                    `json:"executed_at_ms"`
	DocType      string                   `json:"doc_type"`
}

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

// pushFlowModDrop writes a DROP PendingFlowMod to the ledger.
//
// FM-02 FIX: EntryID now includes a millisecond timestamp to prevent key
// collisions when a vehicle is attacked multiple times. Previously, two attacks
// against the same vehicle produced the same key "FLOWMOD_DROP_<vid>", silently
// overwriting the first FlowMod before eventListener.js could acknowledge it.
// eventListener.js uses GetAllPendingFlowMods (not fixed-key lookup) to replay.
func pushFlowModDrop(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	mac := lookupVehicleMAC(ctx, vehicleID)
	fm := PendingFlowMod{
		EntryID:     fmt.Sprintf("FLOWMOD_DROP_%s_%d", vehicleID, time.Now().UnixMilli()), // FM-02
		VehicleID:   vehicleID,
		Action:      "DROP",
		Priority:    65000,
		Match:       map[string]interface{}{"eth_src": mac},
		FlowActions: []map[string]interface{}{},
	}
	return writePendingFlowMod(ctx, fm)
}

// pushRerouteFlowMod writes a REROUTE PendingFlowMod to the ledger.
// FM-02: timestamped EntryID to avoid key collisions.
func pushRerouteFlowMod(ctx contractapi.TransactionContextInterface, vehicleID string) error {
	fm := PendingFlowMod{
		EntryID:     fmt.Sprintf("FLOWMOD_REROUTE_%s_%d", vehicleID, time.Now().UnixMilli()), // FM-02
		VehicleID:   vehicleID,
		Action:      "REROUTE",
		Priority:    50000,
		Match:       map[string]interface{}{"metadata": fmt.Sprintf("FALSE_PATH_%s", vehicleID)},
		FlowActions: []map[string]interface{}{},
	}
	return writePendingFlowMod(ctx, fm)
}

// pushFlowModOverride writes OVERRIDE FlowMods for CTRL_ORIGIN attacks (§9.3).
//
// F-1: Single priority-65535 catch-all + priority-65534 per-vehicle rules.
// E-1: Catch-all key "FLOWMOD_OVERRIDE_CTRL_<ctrl>" matches eventListener.js lookup.
func pushFlowModOverride(
	ctx contractapi.TransactionContextInterface,
	controllerID string,
	evidence []BeaconEvidenceRecord,
) error {
	// Catch-all override — intentionally fixed key (idempotent: latest override wins)
	catchAll := PendingFlowMod{
		EntryID:  fmt.Sprintf("FLOWMOD_OVERRIDE_CTRL_%s", controllerID),
		VehicleID: controllerID,
		Action:   "OVERRIDE",
		Priority: 65535,
		Match:    map[string]interface{}{},
		FlowActions: []map[string]interface{}{
			{"type": "OUTPUT", "port": "NORMAL"},
		},
	}
	if err := writePendingFlowMod(ctx, catchAll); err != nil {
		return fmt.Errorf("CTRL_ORIGIN catch-all override FlowMod failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, rec := range evidence {
		for _, obs := range rec.Observations {
			if seen[obs.VehicleID] {
				continue
			}
			seen[obs.VehicleID] = true
			mac := lookupVehicleMAC(ctx, obs.VehicleID)
			perVehicle := PendingFlowMod{
				EntryID:  fmt.Sprintf("FLOWMOD_OVERRIDE_%s", obs.VehicleID),
				VehicleID: obs.VehicleID,
				Action:   "OVERRIDE",
				Priority: 65534,
				Match:    map[string]interface{}{"eth_src": mac},
				FlowActions: []map[string]interface{}{
					{"type": "OUTPUT", "port": "NORMAL"},
				},
			}
			if err := writePendingFlowMod(ctx, perVehicle); err != nil {
				return fmt.Errorf("per-vehicle override FlowMod failed for %s: %v",
					obs.VehicleID, err)
			}
		}
	}
	return nil
}

// writePendingFlowMod stores a FlowMod record on the ledger.
// F-2: always enforces DocType = "PENDING_FLOWMOD".
func writePendingFlowMod(ctx contractapi.TransactionContextInterface, fm PendingFlowMod) error {
	fm.DocType = "PENDING_FLOWMOD"
	data, err := json.Marshal(fm)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(fm.EntryID, data)
}

// lookupVehicleMAC returns the MAC address for a vehicle from the ledger.
func lookupVehicleMAC(ctx contractapi.TransactionContextInterface, vehicleID string) string {
	key := "VMAC_" + vehicleID
	data, err := ctx.GetStub().GetState(key)
	if err == nil && len(data) > 0 {
		return string(data)
	}
	return ns3VehicleIDtoMAC(vehicleID)
}

// ns3VehicleIDtoMAC derives a locally-administered unicast MAC from a vehicle ID.
func ns3VehicleIDtoMAC(vehicleID string) string {
	n := 0
	for _, c := range vehicleID {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	hi := (n >> 8) & 0xff
	lo := n & 0xff
	return fmt.Sprintf("02:00:00:00:%02x:%02x", hi, lo)
}
