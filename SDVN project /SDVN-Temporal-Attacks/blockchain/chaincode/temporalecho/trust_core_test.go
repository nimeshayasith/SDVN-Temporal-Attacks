package main

// trust_core_test.go — unit tests for the core chaincode trust/lifecycle
// functions (registration, trust updates, demotion/quarantine/removal
// pipeline, controller reassignment, peer selection, admin deregistration).
//
// Before this file (and trust_sweep_test.go), the entire chaincode package
// had zero automated unit tests — correctness relied entirely on full
// NS-3 + Fabric integration runs, which are slow and don't isolate
// individual functions. These tests use shimtest.MockStub, so they run in
// well under a second with no Docker/NS-3 required.

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
)

func newTestStub(name string) *shimtest.MockStub {
	stub := shimtest.NewMockStub(name, nil)
	stub.MockTransactionStart("t0")
	return stub
}

// ── RegisterRSUPeer / RegisterOBUPeer ───────────────────────────────────────

func TestRegisterRSUPeer(t *testing.T) {
	stub := newTestStub("test-register-rsu")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "rsu1"); err != nil {
		t.Fatalf("RegisterRSUPeer failed: %v", err)
	}
	r := loadTrust(ctx, "rsu1")
	if !r.IsRSUPeer {
		t.Errorf("expected IsRSUPeer=true, got false")
	}
	if r.Score != TrustInitTier1 {
		t.Errorf("expected initial score %.2f (Tier1), got %.2f", TrustInitTier1, r.Score)
	}
	if r.State != PeerStateActive {
		t.Errorf("expected state ACTIVE, got %s", r.State)
	}
}

func TestRegisterOBUPeer(t *testing.T) {
	stub := newTestStub("test-register-obu")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterOBUPeer(ctx, "obu1", "4096", "16"); err != nil {
		t.Fatalf("RegisterOBUPeer failed: %v", err)
	}
	r := loadTrust(ctx, "obu1")
	if r.IsRSUPeer {
		t.Errorf("expected IsRSUPeer=false for an OBU, got true")
	}
	if r.Score != TrustInitTier2 {
		t.Errorf("expected initial score %.2f (Tier2), got %.2f", TrustInitTier2, r.Score)
	}
	if r.HWCapacity != 4096 {
		t.Errorf("expected HWCapacity=4096, got %d", r.HWCapacity)
	}
}

// ── UpdateTrustRound ─────────────────────────────────────────────────────

func TestUpdateTrustRound_RewardsAndPenalizes(t *testing.T) {
	stub := newTestStub("test-update-round")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	// caller must be an RSU (or high-trust) peer to be authorised.
	if err := contract.RegisterRSUPeer(ctx, "caller"); err != nil {
		t.Fatalf("setup RegisterRSUPeer failed: %v", err)
	}
	if err := contract.RegisterOBUPeer(ctx, "honest", "4096", "16"); err != nil {
		t.Fatalf("setup RegisterOBUPeer(honest) failed: %v", err)
	}
	if err := contract.RegisterOBUPeer(ctx, "malicious", "4096", "16"); err != nil {
		t.Fatalf("setup RegisterOBUPeer(malicious) failed: %v", err)
	}

	participating, _ := json.Marshal([]string{"honest"})
	all, _ := json.Marshal([]string{"honest", "malicious"})

	if err := contract.UpdateTrustRound(ctx, "caller", string(participating), string(all)); err != nil {
		t.Fatalf("UpdateTrustRound failed: %v", err)
	}

	honest := loadTrust(ctx, "honest")
	wantHonest := TrustInitTier2 + TrustDeltaPlus
	if honest.Score != wantHonest {
		t.Errorf("honest peer: expected score %.4f after reward, got %.4f", wantHonest, honest.Score)
	}

	malicious := loadTrust(ctx, "malicious")
	wantMalicious := TrustInitTier2 - TrustDeltaMinus
	if wantMalicious < 0 {
		wantMalicious = 0
	}
	if malicious.Score != wantMalicious {
		t.Errorf("non-participating peer: expected score %.4f after penalty, got %.4f", wantMalicious, malicious.Score)
	}
}

func TestUpdateTrustRound_UnauthorisedCallerRejected(t *testing.T) {
	stub := newTestStub("test-update-round-unauth")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	// A freshly-registered OBU (score == TrustMin exactly, the Tier2 init
	// value) is intentionally AUTHORISED to call UpdateTrustRound -- this is
	// the documented bootstrap-accumulation floor, not a bug (see the
	// UpdateTrustRound doc comment: "allows trust to accumulate in OBU-only
	// / no-RSU deployments"). To exercise genuine rejection, the caller's
	// score must be driven strictly BELOW TrustMin -- e.g. via a confirmed
	// malicious round (Delta- penalty).
	if err := contract.RegisterOBUPeer(ctx, "low-trust-caller", "4096", "16"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if _, err := updateTrust(ctx, "low-trust-caller", false, false); err != nil {
		t.Fatalf("setup (penalty round) failed: %v", err)
	}
	caller := loadTrust(ctx, "low-trust-caller")
	if caller.Score >= TrustMin {
		t.Fatalf("test setup invalid: expected caller's score to drop below TrustMin after a penalty, got %.4f (TrustMin=%.4f)", caller.Score, TrustMin)
	}

	all, _ := json.Marshal([]string{"low-trust-caller"})
	err := contract.UpdateTrustRound(ctx, "low-trust-caller", "[]", string(all))
	if err == nil {
		t.Errorf("expected UpdateTrustRound to reject a caller whose score is strictly below TrustMin, got nil error")
	}
}

// ── ZeroTrust / demotion pipeline ───────────────────────────────────────────

func TestZeroTrust_RSUEntersQuarantinePipeline(t *testing.T) {
	stub := newTestStub("test-zerotrust-rsu")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "caller-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterRSUPeer(ctx, "target-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	// ZeroTrust requires a backing detection event on the ledger.
	stub.PutState("DETECT:evt1", []byte(`{"dummy":true}`))

	if err := contract.ZeroTrust(ctx, "caller-rsu", "target-rsu", "DETECT:evt1"); err != nil {
		t.Fatalf("ZeroTrust failed: %v", err)
	}

	target := loadTrust(ctx, "target-rsu")
	if target.State != PeerStateQuarantined {
		t.Errorf("expected demoted RSU peer to be QUARANTINED_CLIENT, got %s", target.State)
	}
	if target.Score != 0.0 {
		t.Errorf("expected demoted peer's score to be zeroed, got %.4f", target.Score)
	}
	if target.IsRSUPeer {
		t.Errorf("expected demoted peer to be stripped of RSU role, still IsRSUPeer=true")
	}
}

func TestZeroTrust_OBUZeroedImmediately(t *testing.T) {
	stub := newTestStub("test-zerotrust-obu")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "caller-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterOBUPeer(ctx, "target-obu", "4096", "16"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub.PutState("DETECT:evt2", []byte(`{"dummy":true}`))

	if err := contract.ZeroTrust(ctx, "caller-rsu", "target-obu", "DETECT:evt2"); err != nil {
		t.Fatalf("ZeroTrust failed: %v", err)
	}

	target := loadTrust(ctx, "target-obu")
	if target.Score != 0.0 {
		t.Errorf("expected OBU's score to be zeroed immediately, got %.4f", target.Score)
	}
	if !target.Flagged {
		t.Errorf("expected OBU to be Flagged=true after ZeroTrust")
	}
	// OBUs are zeroed directly, NOT routed through the RSU quarantine pipeline.
	if target.State == PeerStateQuarantined {
		t.Errorf("OBU should not enter the QUARANTINED_CLIENT pipeline (that's RSU-only)")
	}
}

func TestZeroTrust_NoBackingEventRejected(t *testing.T) {
	stub := newTestStub("test-zerotrust-noevent")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "caller-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterRSUPeer(ctx, "target-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	err := contract.ZeroTrust(ctx, "caller-rsu", "target-rsu", "DETECT:nonexistent")
	if err == nil {
		t.Errorf("expected ZeroTrust to reject a call with no backing detection event on the ledger, got nil error")
	}
}

// ── Full demotion -> quarantine -> time elapses -> removal pipeline ────────

func TestDemoteThenMonitorAndRemove_RemovesAfterQuarantineIfStillLow(t *testing.T) {
	stub := newTestStub("test-demote-remove")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "caller-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterRSUPeer(ctx, "bad-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub.PutState("DETECT:evt3", []byte(`{"dummy":true}`))

	if err := contract.DemotePeerToClient(ctx, "caller-rsu", "bad-rsu", "DETECT:evt3"); err != nil {
		t.Fatalf("DemotePeerToClient failed: %v", err)
	}

	r := loadTrust(ctx, "bad-rsu")
	if r.State != PeerStateQuarantined {
		t.Fatalf("expected QUARANTINED_CLIENT immediately after demotion, got %s", r.State)
	}

	// Simulate the quarantine window having elapsed: backdate DemotedAt
	// directly on the ledger record (see FINAL_CALIBRATED_VALUES_2026-07-29.md's
	// trust-parameter-sweep note for why this is the correct way to
	// fast-forward time in a MockStub test instead of real sleeping).
	r.DemotedAt = r.DemotedAt - QuarantineMonitorMs - 1000
	saveTrust(ctx, r)

	// monitorAndRemovePeer is triggered by any subsequent trust-degrading
	// update while the peer is quarantined (see updateTrust's `if
	// r.State == PeerStateQuarantined` branch) -- simulate that via another
	// confirmed-malicious round.
	if _, err := updateTrust(ctx, "bad-rsu", false, false); err != nil {
		t.Fatalf("updateTrust (post-quarantine) failed: %v", err)
	}

	final := loadTrust(ctx, "bad-rsu")
	if final.State != PeerStateRemoved {
		t.Errorf("expected peer to be REMOVED after quarantine window elapsed with score still <= TrustMin, got state=%s score=%.4f", final.State, final.Score)
	}

	// A certificate revocation record must be written for removed peers.
	if data, err := stub.GetState("CERT_REVOKED:bad-rsu"); err != nil || data == nil {
		t.Errorf("expected a CERT_REVOKED record to be written for the removed peer")
	}
}

func TestDemoteThenMonitor_StaysQuarantinedIfWindowNotYetElapsed(t *testing.T) {
	stub := newTestStub("test-demote-nowindow")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "caller-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterRSUPeer(ctx, "bad-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub.PutState("DETECT:evt4", []byte(`{"dummy":true}`))

	if err := contract.DemotePeerToClient(ctx, "caller-rsu", "bad-rsu", "DETECT:evt4"); err != nil {
		t.Fatalf("DemotePeerToClient failed: %v", err)
	}

	// Do NOT backdate DemotedAt -- quarantine window has not elapsed.
	if err := monitorAndRemovePeer(ctx, "bad-rsu"); err != nil {
		t.Fatalf("monitorAndRemovePeer failed: %v", err)
	}

	r := loadTrust(ctx, "bad-rsu")
	if r.State != PeerStateQuarantined {
		t.Errorf("expected peer to remain QUARANTINED_CLIENT before the quarantine window elapses, got %s", r.State)
	}
}

// ── Controller trust and reassignment ───────────────────────────────────────

func TestCheckControllerTrustAndReassign_TriggersOnLowTrust(t *testing.T) {
	stub := newTestStub("test-ctrl-reassign")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterController(ctx, "ctrl-primary", "zone-1"); err != nil {
		t.Fatalf("RegisterController(primary) failed: %v", err)
	}
	if err := contract.RegisterController(ctx, "ctrl-backup", "zone-1"); err != nil {
		t.Fatalf("RegisterController(backup) failed: %v", err)
	}

	allCtrls, _ := json.Marshal([]string{"ctrl-primary", "ctrl-backup"})

	// Drive ctrl-primary's trust below TrustCtrlMin via repeated divergence
	// penalties (ΔC- = 0.20 fixed), starting from Score=1.0 default.
	// ceil(1.0 / 0.20) = 5 divergences needed to reach 0.
	for i := 0; i < 4; i++ {
		if err := contract.CheckControllerTrustAndReassign(ctx, "ctrl-primary", string(allCtrls)); err != nil {
			t.Fatalf("CheckControllerTrustAndReassign (round %d) failed: %v", i, err)
		}
	}
	before := loadCtrlTrust(ctx, "ctrl-primary")
	if before.Score >= TrustCtrlMin {
		t.Fatalf("test setup: expected ctrl-primary's score to already be below TrustCtrlMin after 4 penalties, got %.4f", before.Score)
	}

	// This call should trigger reassignment and write a CTRL_REASSIGNMENT record.
	if err := contract.CheckControllerTrustAndReassign(ctx, "ctrl-primary", string(allCtrls)); err != nil {
		t.Fatalf("CheckControllerTrustAndReassign (final) failed: %v", err)
	}

	iter, err := stub.GetStateByRange("CTRL_REASSIGN:ctrl-primary:", "CTRL_REASSIGN:ctrl-primary:~")
	if err != nil {
		t.Fatalf("GetStateByRange failed: %v", err)
	}
	defer iter.Close()
	if !iter.HasNext() {
		t.Errorf("expected a CTRL_REASSIGN record to be written once ctrl-primary's trust dropped below TrustCtrlMin")
	}
}

func TestCheckControllerTrustAndReassign_NoReassignAboveThreshold(t *testing.T) {
	stub := newTestStub("test-ctrl-noreassign")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterController(ctx, "ctrl-healthy", "zone-1"); err != nil {
		t.Fatalf("RegisterController failed: %v", err)
	}
	allCtrls, _ := json.Marshal([]string{"ctrl-healthy"})

	// A single divergence (score 1.0 -> 0.8) should stay well above TrustCtrlMin=0.30.
	if err := contract.CheckControllerTrustAndReassign(ctx, "ctrl-healthy", string(allCtrls)); err != nil {
		t.Fatalf("CheckControllerTrustAndReassign failed: %v", err)
	}

	r := loadCtrlTrust(ctx, "ctrl-healthy")
	if r.Score < TrustCtrlMin {
		t.Fatalf("test setup invalid: expected score to remain above TrustCtrlMin after 1 penalty, got %.4f", r.Score)
	}

	iter, _ := stub.GetStateByRange("CTRL_REASSIGN:ctrl-healthy:", "CTRL_REASSIGN:ctrl-healthy:~")
	defer iter.Close()
	if iter.HasNext() {
		t.Errorf("did not expect a CTRL_REASSIGN record for a controller still above TrustCtrlMin")
	}
}

// ── SelectPeers ──────────────────────────────────────────────────────────

func TestSelectPeers_ExcludesQuarantinedAndLowTrust(t *testing.T) {
	stub := newTestStub("test-select-peers")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	// SIM_NO_RSU_MODE=1 bypasses the HW/dwell-time eligibility checks so
	// this test isolates the trust/quarantine filtering logic specifically.
	stub.PutState("SIM_NO_RSU_MODE", []byte("1"))

	if err := contract.RegisterRSUPeer(ctx, "good-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterOBUPeer(ctx, "good-obu", "4096", "16"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.RegisterRSUPeer(ctx, "quarantined-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub.PutState("DETECT:evt5", []byte(`{"dummy":true}`))
	if err := contract.DemotePeerToClient(ctx, "good-rsu", "quarantined-rsu", "DETECT:evt5"); err != nil {
		t.Fatalf("DemotePeerToClient failed: %v", err)
	}

	all, _ := json.Marshal([]string{"good-rsu", "good-obu", "quarantined-rsu"})
	selected, err := contract.SelectPeers(ctx, string(all))
	if err != nil {
		t.Fatalf("SelectPeers failed: %v", err)
	}

	found := map[string]bool{}
	for _, s := range selected {
		found[s] = true
	}
	if !found["good-rsu"] {
		t.Errorf("expected good-rsu to be selected, selected=%v", selected)
	}
	if !found["good-obu"] {
		t.Errorf("expected good-obu to be selected (SIM_NO_RSU_MODE bypasses HW/dwell checks), selected=%v", selected)
	}
	if found["quarantined-rsu"] {
		t.Errorf("did not expect quarantined-rsu to be selected, selected=%v", selected)
	}
}

// ── AdminDeregisterPeer ──────────────────────────────────────────────────

func TestAdminDeregisterPeer_RemovesWithoutAccusation(t *testing.T) {
	stub := newTestStub("test-admin-deregister")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterOBUPeer(ctx, "stray-peer", "4096", "16"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := contract.AdminDeregisterPeer(ctx, "stray-peer"); err != nil {
		t.Fatalf("AdminDeregisterPeer failed: %v", err)
	}

	data, err := stub.GetState("TRUST:stray-peer")
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}
	if data != nil {
		t.Errorf("expected the TRUST record to be fully removed after AdminDeregisterPeer, still found data")
	}
}

func TestAdminDeregisterPeer_RejectsEmptyPeerID(t *testing.T) {
	stub := newTestStub("test-admin-deregister-empty")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.AdminDeregisterPeer(ctx, ""); err == nil {
		t.Errorf("expected AdminDeregisterPeer to reject an empty peerID, got nil error")
	}
}

// ── GetTrustScore / GetControllerTrustScore ────────────────────────────────

func TestGetTrustScore(t *testing.T) {
	stub := newTestStub("test-get-trust-score")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterRSUPeer(ctx, "some-rsu"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	score, err := contract.GetTrustScore(ctx, "some-rsu")
	if err != nil {
		t.Fatalf("GetTrustScore failed: %v", err)
	}
	if score != TrustInitTier1 {
		t.Errorf("expected GetTrustScore to return %.2f, got %.4f", TrustInitTier1, score)
	}
}

func TestGetControllerTrustScore(t *testing.T) {
	stub := newTestStub("test-get-ctrl-trust-score")
	ctx := newCtx(stub)
	contract := &TemporalEchoMitigator{}

	if err := contract.RegisterController(ctx, "ctrl-x", "zone-1"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	score, err := contract.GetControllerTrustScore(ctx, "ctrl-x")
	if err != nil {
		t.Fatalf("GetControllerTrustScore failed: %v", err)
	}
	if score != 1.0 {
		t.Errorf("expected a freshly-registered controller's trust score to be 1.0, got %.4f", score)
	}
}
