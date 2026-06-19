package main

// Anchor Checkpoint Protocol (PDF Section 5.1)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	// AnchorIntervalBlocksUrban is ⌊Tmin/Tb⌋ for urban scenario (Llink≈43 s).
	AnchorIntervalBlocksUrban = 215

	// AnchorIntervalBlocksHighway is ⌊Tmin/Tb⌋ for highway scenario (Llink≈9 s).
	// AN-03: added — bootstrap.sh uses ANCHOR_INTERVAL_BLOCKS=45 for highway,
	// but the constant was missing, making the highway case undiscoverable.
	AnchorIntervalBlocksHighway = 45

	AnchorBlockCtrKey = "ANCHOR_CTR"
)

// CreateAnchorCheckpoint produces a PBFT-signed ledger digest at the current block height.
//
// AN-01 FIX: Ledger key is now ANCHOR:<blockHeight> (deterministic, from the
// monotonic ANCHOR_CTR counter) instead of ANCHOR:<now> (wall-clock, non-deterministic).
// Two endorsing peers calling this at slightly different times previously wrote to
// different keys, causing Fabric MVCC PHANTOM_READ_CONFLICT and rejected transactions.
//
// A-1 (from previous audit): state root hash = SHA-256(TxID||channelID||blockHeight),
// no wall-clock component — deterministic across all endorsers.
func (t *TemporalEchoMitigator) CreateAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
	fromPeerID string,
	intervalBlocksStr string,
) (string, error) {
	trust := loadTrust(ctx, fromPeerID)
	if !trust.IsRSUPeer || trust.Score < TrustInitTier1-1e-9 {
		return "", fmt.Errorf(
			"CreateAnchorCheckpoint: peer %s is not an authorised Tier 1 RSU (trust=%.3f, isRSU=%v)",
			fromPeerID, trust.Score, trust.IsRSUPeer)
	}

	blockHeight := anchorIncrementCounter(ctx)

	intervalBlocks := AnchorIntervalBlocksUrban
	if intervalBlocksStr != "" {
		var parsed int
		if n, _ := fmt.Sscanf(intervalBlocksStr, "%d", &parsed); n == 1 && parsed > 0 {
			intervalBlocks = parsed
		}
	}

	// A-1: deterministic state root — no wall-clock in hash
	h := sha256.New()
	h.Write([]byte(ctx.GetStub().GetTxID()))
	h.Write([]byte(ctx.GetStub().GetChannelID()))
	h.Write([]byte(fmt.Sprintf("%d", blockHeight)))
	stateRoot := hex.EncodeToString(h.Sum(nil))

	now := time.Now().UnixMilli() // metadata only — NOT part of hash or ledger key

	peerPubKey := getPeerPubKey(ctx, fromPeerID)
	sigInput := fmt.Sprintf("%s:%d:%s", fromPeerID, blockHeight, stateRoot)
	peerSig := SimSign(sigInput, peerPubKey)

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
	// AN-01 FIX: key uses blockHeight (deterministic) not now (non-deterministic)
	key := fmt.Sprintf("ANCHOR:%d", blockHeight)
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return "", fmt.Errorf("CreateAnchorCheckpoint: ledger write failed: %v", err)
	}

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
// TR-05 note: reads ANCHOR_CTR (monotonic counter) then fetches ANCHOR:<height> directly.
// This avoids CouchDB sort queries which require a separate index definition.
func (t *TemporalEchoMitigator) GetLatestAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
) (*AnchorCheckpoint, error) {
	// Read the monotonic counter to find the latest block height
	data, err := ctx.GetStub().GetState(AnchorBlockCtrKey)
	if err != nil {
		return nil, fmt.Errorf("GetLatestAnchorCheckpoint: counter read failed: %v", err)
	}
	if len(data) == 0 {
		// No checkpoint has ever been created
		return nil, nil
	}

	var current uint64
	fmt.Sscanf(string(data), "%d", &current)
	if current == 0 {
		return nil, nil
	}

	// Fetch the latest checkpoint by its deterministic key
	key := fmt.Sprintf("ANCHOR:%d", current)
	cpData, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("GetLatestAnchorCheckpoint: state read failed for %s: %v", key, err)
	}
	if len(cpData) == 0 {
		return nil, nil
	}

	var cp AnchorCheckpoint
	if err := json.Unmarshal(cpData, &cp); err != nil {
		return nil, fmt.Errorf("GetLatestAnchorCheckpoint: unmarshal error: %v", err)
	}
	return &cp, nil
}

// SyncFromAnchorCheckpoint records that an OBU peer has synced from a checkpoint.
//
// A-2 (from previous audit): verifies the checkpoint's Dilithium2 signature.
// AN-02 FIX: enforces that the OBU must sync from the LATEST checkpoint, not
// any arbitrary old one. An OBU that synced from a 215-block-old checkpoint
// could participate in consensus with a stale ledger view.
func (t *TemporalEchoMitigator) SyncFromAnchorCheckpoint(
	ctx contractapi.TransactionContextInterface,
	checkpointID string,
	obuPeerID string,
) error {
	trust := loadTrust(ctx, obuPeerID)
	if trust.Score < TrustMin {
		return fmt.Errorf(
			"SyncFromAnchorCheckpoint: peer %s trust score %.3f is below τmin=%.3f",
			obuPeerID, trust.Score, TrustMin)
	}
	if trust.Flagged {
		return fmt.Errorf("SyncFromAnchorCheckpoint: peer %s is flagged and excluded from consensus", obuPeerID)
	}

	// AN-02: verify the provided checkpointID IS the latest checkpoint
	latest, err := t.GetLatestAnchorCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("SyncFromAnchorCheckpoint: could not retrieve latest checkpoint: %v", err)
	}
	if latest == nil {
		// Bootstrap phase — no checkpoint exists yet; allow without check
	} else if latest.CheckpointID != checkpointID {
		return fmt.Errorf(
			"SyncFromAnchorCheckpoint: checkpoint %s is not the latest (latest is %s at block %d)",
			checkpointID, latest.CheckpointID, latest.BlockHeight)
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

	// A-2: verify Falcon-1024 signature over the checkpoint data
	sigInput := fmt.Sprintf("%s:%d:%s", cp.CreatedByPeer, cp.BlockHeight, cp.StateRootHash)
	if !verifyFalcon1024Sig(cp.PeerSig, sigInput, cp.PeerPubKey) {
		return fmt.Errorf(
			"SyncFromAnchorCheckpoint: invalid Falcon-1024 signature on checkpoint %s from peer %s",
			checkpointID, cp.CreatedByPeer)
	}

	// A-2: verify the creating peer is Tier 1 RSU
	creatorTrust := loadTrust(ctx, cp.CreatedByPeer)
	if !creatorTrust.IsRSUPeer {
		return fmt.Errorf(
			"SyncFromAnchorCheckpoint: checkpoint creator %s is not a Tier 1 RSU",
			cp.CreatedByPeer)
	}

	// Idempotent — skip if already recorded
	for _, pid := range cp.SyncedPeers {
		if pid == obuPeerID {
			return nil
		}
	}
	cp.SyncedPeers = append(cp.SyncedPeers, obuPeerID)

	updated, _ := json.Marshal(cp)
	// AN-01: key uses blockHeight
	key := fmt.Sprintf("ANCHOR:%d", cp.BlockHeight)
	return ctx.GetStub().PutState(key, updated)
}

// anchorIncrementCounter increments and returns the monotonic block counter.
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
