package main

// Anchor Checkpoint Protocol (PDF Section 5.1)
//
// Tier 1 (RSU) peers periodically produce PBFT-signed ledger digests
// (anchor checkpoints) that commit the global state root at a fixed block
// height interval.  Tier 2 OBU peers MUST synchronise from the latest anchor
// checkpoint before participating in any PBFT consensus round — this ensures
// all active peers validate transactions from an identical committed base state.
//
// Interval = ⌊Tmin / Tb⌋ blocks
//   Tmin  = max(3·TPBFT, Llink/2)
//   Urban (Llink≈43 s): Tmin = max(600 ms, 21 500 ms) → 215 blocks at Tb=100 ms
//   Highway (Llink≈9 s): Tmin = max(600 ms, 4 500 ms) →  45 blocks
//
// Chaincode functions:
//   CreateAnchorCheckpoint(fromPeerID, intervalBlocksStr)
//     — Tier 1 RSU only; writes AnchorCheckpoint to ANCHOR:<ts> key
//   GetLatestAnchorCheckpoint()
//     — Returns most recent checkpoint; nil during bootstrap phase
//   SyncFromAnchorCheckpoint(checkpointID, obuPeerID)
//     — OBU calls this to record that it has synced from the given checkpoint;
//       τk ≥ τmin required before it may join Pactive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	// AnchorIntervalBlocksUrban is ⌊Tmin/Tb⌋ for urban scenario (default).
	AnchorIntervalBlocksUrban = 215

	// AnchorBlockCtrKey is the ledger key for the monotonic block counter.
	AnchorBlockCtrKey = "ANCHOR_CTR"
)

// CreateAnchorCheckpoint produces a PBFT-signed ledger digest committing the
// current state root hash at the current simulated block height.
//
// Only Tier 1 RSU peers (IsRSUPeer=true, trust score = 1.0) are authorised.
// The checkpoint is written to key ANCHOR:<created_at_ms> and emits the
// AnchorCheckpointCreated event for off-chain listeners (eventListener.js).
//
// intervalBlocksStr — optional; defaults to AnchorIntervalBlocksUrban (215).
//   Pass "45" for highway scenario (Llink≈9 s).
func (t *TemporalEchoMitigator) CreateAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
	fromPeerID string,
	intervalBlocksStr string,
) (string, error) {
	// Only Tier 1 RSU peers may create anchor checkpoints
	trust, err := loadTrust(ctx, fromPeerID)
	if err != nil || !trust.IsRSUPeer || trust.Score < TrustInitTier1-1e-9 {
		return "", fmt.Errorf(
			"CreateAnchorCheckpoint: peer %s is not an authorised Tier 1 RSU (trust=%.3f, isRSU=%v)",
			fromPeerID, trust.Score, trust.IsRSUPeer)
	}

	// Increment the simulated block counter
	blockHeight := anchorIncrementCounter(ctx)

	// Parse optional interval override
	intervalBlocks := AnchorIntervalBlocksUrban
	if intervalBlocksStr != "" {
		var parsed int
		if n, _ := fmt.Sscanf(intervalBlocksStr, "%d", &parsed); n == 1 && parsed > 0 {
			intervalBlocks = parsed
		}
	}

	// State root hash approximation: SHA-256(TxID ‖ created_at_ms)
	// In production this would be the actual ledger state root from the block header.
	now := time.Now().UnixMilli()
	h := sha256.New()
	h.Write([]byte(ctx.GetStub().GetTxID()))
	h.Write([]byte(fmt.Sprintf("%d", now)))
	stateRoot := hex.EncodeToString(h.Sum(nil))

	// Peer public key from KEYSTORE (used as signature placeholder in simulation;
	// production: Sign(SK_nk, stateRoot ‖ blockHeight ‖ fromPeerID) with Dilithium2)
	peerPubKey := getPeerPubKey(ctx, fromPeerID)
	sigInput := fmt.Sprintf("%s:%d:%s", fromPeerID, blockHeight, stateRoot)
	// In simulation mode verifyDilithium2Sig accepts any non-empty bytes,
	// so we store peerPubKey as the signature placeholder.
	peerSig := []byte(sigInput) // replaced by real Dilithium2 sig in -tags liboqs build
	if len(peerPubKey) > 0 {
		peerSig = peerPubKey
	}

	cp := AnchorCheckpoint{
		CheckpointID:   ctx.GetStub().GetTxID(),
		BlockHeight:    blockHeight,
		StateRootHash:  stateRoot,
		CreatedByPeer:  fromPeerID,
		PeerSig:        peerSig,
		PeerPubKey:     peerPubKey,
		CreatedAtMs:    now,
		IntervalBlocks: intervalBlocks,
		SyncedPeers:    []string{},
		DocType:        "ANCHOR_CHECKPOINT",
	}

	data, _ := json.Marshal(cp)
	key := fmt.Sprintf("ANCHOR:%d", now)
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return "", fmt.Errorf("CreateAnchorCheckpoint: ledger write failed: %v", err)
	}

	// Emit event so eventListener.js and OBU peers know a new checkpoint exists
	evPayload, _ := json.Marshal(map[string]interface{}{
		"checkpoint_id":   cp.CheckpointID,
		"block_height":    blockHeight,
		"state_root_hash": stateRoot,
		"created_by_peer": fromPeerID,
		"interval_blocks": intervalBlocks,
		"created_at_ms":   now,
	})
	_ = ctx.GetStub().SetEvent("AnchorCheckpointCreated", evPayload)

	return cp.CheckpointID, nil
}

// GetLatestAnchorCheckpoint returns the most recently created AnchorCheckpoint.
// Returns nil (no error) during the bootstrap phase when no checkpoint exists yet.
//
// Called by Tier 2 OBU peers before joining a consensus round to verify they
// are operating from the committed base state.
func (t *TemporalEchoMitigator) GetLatestAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
) (*AnchorCheckpoint, error) {
	// CouchDB rich query: sort descending by created_at_ms, take one record
	qs := `{"selector":{"doc_type":"ANCHOR_CHECKPOINT"},"sort":[{"created_at_ms":"desc"}],"limit":1}`
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return nil, fmt.Errorf("GetLatestAnchorCheckpoint: query failed: %v", err)
	}
	defer iter.Close()

	if iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("GetLatestAnchorCheckpoint: iterator error: %v", err)
		}
		var cp AnchorCheckpoint
		if err := json.Unmarshal(qr.Value, &cp); err != nil {
			return nil, fmt.Errorf("GetLatestAnchorCheckpoint: unmarshal error: %v", err)
		}
		return &cp, nil
	}
	return nil, nil // bootstrap phase — no checkpoint yet
}

// SyncFromAnchorCheckpoint records that an OBU peer has synchronised its local
// ledger state from the given checkpoint.  The OBU may not participate in PBFT
// consensus until this call succeeds.
//
// Preconditions (§5.1):
//   • obuPeerID must exist in TRUST:<obuPeerID> with score ≥ τmin (0.10)
//   • checkpointID must match an existing AnchorCheckpoint record
//
// On success the OBU's peer ID is appended to checkpoint.SyncedPeers and
// the updated record is written back to the ledger.
func (t *TemporalEchoMitigator) SyncFromAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
	checkpointID string,
	obuPeerID string,
) error {
	// Verify minimum trust for this OBU peer
	trust, err := loadTrust(ctx, obuPeerID)
	if err != nil {
		return fmt.Errorf("SyncFromAnchorCheckpoint: unknown peer %s: %v", obuPeerID, err)
	}
	if trust.Score < TrustMin {
		return fmt.Errorf(
			"SyncFromAnchorCheckpoint: peer %s trust score %.3f is below τmin=%.3f",
			obuPeerID, trust.Score, TrustMin)
	}
	if trust.Flagged {
		return fmt.Errorf("SyncFromAnchorCheckpoint: peer %s is flagged and excluded from consensus", obuPeerID)
	}

	// Locate the checkpoint by its CheckpointID field via rich query
	qs := fmt.Sprintf(
		`{"selector":{"doc_type":"ANCHOR_CHECKPOINT","checkpoint_id":"%s"}}`, checkpointID)
	iter, err := ctx.GetStub().GetQueryResult(qs)
	if err != nil {
		return fmt.Errorf("SyncFromAnchorCheckpoint: query failed: %v", err)
	}
	defer iter.Close()

	if !iter.HasNext() {
		return fmt.Errorf("SyncFromAnchorCheckpoint: checkpoint %s not found", checkpointID)
	}
	qr, err := iter.Next()
	if err != nil {
		return fmt.Errorf("SyncFromAnchorCheckpoint: iterator error: %v", err)
	}

	var cp AnchorCheckpoint
	if err := json.Unmarshal(qr.Value, &cp); err != nil {
		return fmt.Errorf("SyncFromAnchorCheckpoint: unmarshal error: %v", err)
	}

	// Idempotent — skip if already recorded
	for _, pid := range cp.SyncedPeers {
		if pid == obuPeerID {
			return nil
		}
	}
	cp.SyncedPeers = append(cp.SyncedPeers, obuPeerID)

	updated, _ := json.Marshal(cp)
	key := fmt.Sprintf("ANCHOR:%d", cp.CreatedAtMs)
	return ctx.GetStub().PutState(key, updated)
}

// anchorIncrementCounter reads, increments, and persists the monotonic block
// counter at ANCHOR_CTR.  Returns the new value.
func anchorIncrementCounter(ctx contractapi.TransactionContextInterface) uint64 {
	var current uint64
	data, err := ctx.GetStub().GetState(AnchorBlockCtrKey)
	if err == nil && len(data) > 0 {
		fmt.Sscanf(string(data), "%d", &current)
	}
	current++
	_ = ctx.GetStub().PutState(AnchorBlockCtrKey, []byte(fmt.Sprintf("%d", current)))
	return current
}
