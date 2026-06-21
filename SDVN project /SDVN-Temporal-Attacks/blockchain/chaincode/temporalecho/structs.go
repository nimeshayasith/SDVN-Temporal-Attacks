package main

// Data structures for the TemporalEchoMitigator smart contract.
// These mirror the C structs in teta_guard_types.h (TGN→Blockchain boundary).
//
// Ledger key scheme (§13):
//   BEACON:<peer_id>:<interval_ts>              BeaconEvidenceRecord
//   DETECTION:<peer_id>:<vehicle_id>:<ts>       DetectionEvent
//   CTRL_TOPO:<controller_id>:<ts>              ControllerTopologyClaim
//   MITIG:<vehicle_id>:<ts>                     MitigationLogEntry
//   REAUTH:<vehicle_id>                         ReauthFlag
//   KEYSTORE:<peer_id>:<vehicle_id>             VehicleKeyRecord
//   SIG_EVIDENCE:<vehicle_id>:<ts>:<signer_id>  IndividualSigEvidence (threshold sig)
//   WITNESS:<vehicle_id>:<ts>:<reporter_id>     WitnessRecord (ME quorum)
//   VMAC_<vehicle_id>                           raw MAC address string
//   ANCHOR:<created_at_ms>                      AnchorCheckpoint
//   ANCHOR_CTR                                  monotonic block counter (uint64 string)
//   CTRL_REGISTRY                               JSON array of controller IDs ([]string)
//   CTRL_TRUST:<controller_id>                  ControllerTrustRecord
//   CTRL_REASSIGN:<removed_ctrl_id>:<ts_ms>     ControllerReassignment
//   CTRL_REVOKED:<controller_id>                revocation marker (map[string]interface{})
//   PEERKEY:<peer_id>                           raw Falcon-1024 public key bytes

// ─── Flow 1 structs ─────────────────────────────────────────────────────────

// VehicleObservation is one vehicle entry within B_nk(t).
type VehicleObservation struct {
	VehicleID         string   `json:"vehicle_id"`
	SenderTSMs        int64    `json:"sender_ts_ms"`
	GPSLat            float64  `json:"gps_lat"`
	GPSLon            float64  `json:"gps_lon"`
	RSSIdBm           float32  `json:"rssi_dbm"`
	NeighbourVehicles []string `json:"neighbour_vehicles"` // V2V HELLO-confirmed neighbours (D-1)
}

// BeaconEvidenceRecord is B_nk(t) — tamper-evident ground truth submitted by
// each RSU/OBU at every beacon interval (§5.1, Flow 1).
type BeaconEvidenceRecord struct {
	PeerID       string               `json:"peer_id"`
	IntervalTS   int64                `json:"interval_ts"`
	Observations []VehicleObservation `json:"observations"`
	PeerSig      []byte               `json:"peer_sig"`      // σ_nk Falcon-1024
	PeerPubKey   []byte               `json:"peer_pub_key"`
	IsRSUPeer    bool                 `json:"is_rsu_peer"`
	DocType      string               `json:"doc_type"`
}

// ─── Flow 2 structs ─────────────────────────────────────────────────────────

// DetectionEvent is O_rk — alert submitted by trusted node when LW/FS fires (§5.2, Flow 2).
type DetectionEvent struct {
	PeerID        string  `json:"peer_id"`
	VehicleID     string  `json:"vehicle_id"`
	AttackVariant string  `json:"attack_variant"` // "TTW" | "BSHH" | "ME" | "CTRL_ORIGIN"
	AnomalyScore  float32 `json:"anomaly_score"`  // ŷ_v or s(e)
	TriggeredSigs uint32  `json:"triggered_sigs"` // 9-bit bitmask
	AlertTS       int64   `json:"alert_ts_ms"`
	FromLWPath    bool    `json:"from_lw_path"`
	FromFSPath    bool    `json:"from_fs_path"`
	PeerSig       []byte  `json:"peer_sig"`
	DocType       string  `json:"doc_type"`
}

// ─── Flow 3 structs ─────────────────────────────────────────────────────────

// TopologyLink is one directed link in the controller's topology claim.
type TopologyLink struct {
	NodeA string `json:"node_a"`
	NodeB string `json:"node_b"`
	TS    int64  `json:"ts_ms"`
}

// ControllerTopologyClaim is G_t^C — controller's claimed topology (§5.3, Flow 3).
// Treated as a claim to verify, never as authoritative evidence.
type ControllerTopologyClaim struct {
	ControllerID string         `json:"controller_id"`
	IntervalTS   int64          `json:"interval_ts"`
	Links        []TopologyLink `json:"links"`
	CtrlSig      []byte         `json:"ctrl_sig"` // controller sig (untrusted)
	DocType      string         `json:"doc_type"`
}

// ─── Algorithm 4 output structs ─────────────────────────────────────────────

// MitigationLogEntry is the immutable audit record written by Algorithm 4 (§5.4).
type MitigationLogEntry struct {
	EntryID        string   `json:"entry_id"`
	VehicleID      string   `json:"vehicle_id"`
	AttackVariant  string   `json:"attack_variant"`
	AnomalyScore   float32  `json:"anomaly_score"`
	AlertTS        int64    `json:"alert_ts_ms"`
	Actions        []string `json:"actions"`
	ConsensusRound int      `json:"consensus_round"`
	DocType        string   `json:"doc_type"`
}

// ReauthFlag blocks a vehicle from rejoining until it re-authenticates (§5.5).
type ReauthFlag struct {
	VehicleID string `json:"vehicle_id"`
	FlaggedTS int64  `json:"flagged_ts_ms"`
	Reason    string `json:"reason"`
	Cleared   bool   `json:"cleared"`
	DocType   string `json:"doc_type"`
}

// VehicleKeyRecord tracks LKH session keys on-ledger (§13).
type VehicleKeyRecord struct {
	VehicleID     string `json:"vehicle_id"`
	LKHLeafIndex  uint32 `json:"lkh_leaf_index"`
	KeyCreationTS int64  `json:"key_creation_ts_ms"`
	Revoked       bool   `json:"revoked"`
	PeerID        string `json:"peer_id"`
	DocType       string `json:"doc_type"`
}

// ─── TGN → Blockchain boundary struct ───────────────────────────────────────

// AlertObject is the exact JSON object written by tgn_detector.cc to
// tgn_alerts.json and consumed by submit_alerts.py → SubmitAlert chaincode
// function.  Fields match the C DetectionAlert struct in teta_guard_types.h.
type AlertObject struct {
	VehicleID    string  `json:"v_id"`
	Alpha        string  `json:"alpha"`         // "TTW" | "BSHH" | "ME"
	YHat         float32 `json:"y_hat"`         // ŷ_v from Eq.3.23
	STrig        []int   `json:"S_trig"`        // triggered signature indices (0–8)
	TAlertMs     int64   `json:"t_alert"`
	IntervalTSMs int64   `json:"interval_ts_ms"` // beacon interval ts (S-3: not same as alert time)
	FromLWPath   bool    `json:"from_lw_path"`
	FromFSPath   bool    `json:"from_fs_path"`
}

// ─── Verification helper structs ─────────────────────────────────────────────

// IndividualSigEvidence carries one Falcon-1024 signature for threshold checks (§6.3).
//
// Ledger key: SIG_EVIDENCE:<vehicle_id>:<ts_ms>:<signer_id>
// doc_type: "SIG_EVIDENCE"
// vehicle_id: the accused/attacker vehicle (matches getSignatureEvidence query)
// SignerID:   the reporting vehicle that produced this individual signature
type IndividualSigEvidence struct {
	VehicleID string `json:"vehicle_id"` // accused vehicle (query key)
	SignerID   string `json:"signer_id"`  // vehicle submitting this sig
	Signature  []byte `json:"signature"`
	Message    string `json:"message"`
	PubKey     []byte `json:"pub_key"`
	TS         int64  `json:"ts_ms"`
	DocType    string `json:"doc_type"`
}

// WitnessRecord carries one ME witness report for quorum verification (§6.3).
//
// Ledger key: WITNESS:<vehicle_id>:<ts_ms>:<reporter_id>
// doc_type: "WITNESS"
// VehicleID: the accused/attacker vehicle (matches getWitnesses query)
type WitnessRecord struct {
	VehicleID   string  `json:"vehicle_id"`    // accused vehicle (query key)
	ReporterID  string  `json:"reporter_id"`
	ReporterLat float64 `json:"reporter_lat"`
	ReporterLon float64 `json:"reporter_lon"`
	RSSIFromVI  float32 `json:"rssi_from_vi_dbm"`
	Signature   []byte  `json:"signature"`
	Message     string  `json:"message"`
	PubKey      []byte  `json:"pub_key"`
	TS          int64   `json:"ts_ms"`
	DocType     string  `json:"doc_type"`
}

// ─── Peer State Machine (supervisor demotion pipeline) ───────────────────────

// PeerState models the 3-stage demotion pipeline for malicious RSU peers.
//
//	ACTIVE             → normal consensus-participating RSU peer
//	QUARANTINED_CLIENT → detected malicious; demoted from peer role, trust zeroed,
//	                     excluded from Pactive; trust continues to be monitored
//	REMOVED            → quarantine window elapsed, no trust recovery; permanently
//	                     expelled from the consortium
type PeerState string

const (
	PeerStateActive      PeerState = "ACTIVE"
	PeerStateQuarantined PeerState = "QUARANTINED_CLIENT"
	PeerStateRemoved     PeerState = "REMOVED"
)

// ─── Trust Management structs (Section 5.2) ──────────────────────────────────

// TrustRecord holds the trust score τk for a Fabric peer (RSU or OBU).
//
// Ledger key: TRUST:<peer_id>
//
// Update rules (Δ+ = 0.05, Δ- = 0.10):
//
//	correct participation  → min(1, τk + Δ+)
//	failure/inconsistency  → max(0, τk - Δ-)
//	attack detection       → DemotePeerToClient (RSU peer) or zero (OBU)
type TrustRecord struct {
	PeerID      string    `json:"peer_id"`
	Score       float64   `json:"trust_score"`     // τk ∈ [0.0, 1.0]
	IsRSUPeer   bool      `json:"is_rsu_peer"`     // true = Tier 1 (RSU, starts at 1.0)
	ZoneID      string    `json:"zone_id"`         // geographic zone (RSU only; set via SetRSUZone)
	Flagged     bool      `json:"flagged"`         // true = attack-detected
	FlaggedAt   int64     `json:"flagged_at_ms"`
	UpdatedAt   int64     `json:"updated_at_ms"`
	JoinedAtMs  int64     `json:"joined_at_ms"`    // when OBU entered RSU coverage (TR-3)
	HWCapacity  int       `json:"hw_capacity_mb"`  // RAM in MB (0 = unknown/RSU) (Cmin: ≥2048)
	HWStorageGB int       `json:"hw_storage_gb"`   // storage in GB (0 = unknown/RSU) (Cmin: ≥8)
	State       PeerState `json:"state"`           // ACTIVE | QUARANTINED_CLIENT | REMOVED
	DemotedAt   int64     `json:"demoted_at_ms"`   // when first quarantined (for removal check)
	DocType     string    `json:"doc_type"`
}

// ControllerTrustRecord holds the trust score τCj for an SDN controller.
//
// Ledger key: CTRL_TRUST:<controller_id>
//
// Update rule (ΔC- = 0.20, penalty-only — no reward):
//
//	confirmed divergence → max(0, τCj - ΔC-)
//
// When τCj < τCmin: controller removal mechanism triggers (Section 5.7).
type ControllerTrustRecord struct {
	ControllerID    string  `json:"controller_id"`
	Score           float64 `json:"trust_score"`        // τCj ∈ [0.0, 1.0]
	ZoneID          string  `json:"zone_id"`            // Eq. 3.37: C = {(Cj, τCj, Zj)} (TR-1/S-1)
	DivergenceCount int     `json:"divergence_count"`   // total confirmed divergences
	UpdatedAt       int64   `json:"updated_at_ms"`
	DocType         string  `json:"doc_type"`
}

// ControllerReassignment is written to the ledger when τCj < τCmin (Section 5.7).
// eventListener.js reads this record and actions the reassignment via the
// RSU emergency channel, bypassing the malicious controller entirely.
//
// Ledger key: CTRL_REASSIGN:<removed_ctrl_id>:<timestamp_ms>
type ControllerReassignment struct {
	RemovedCtrlID   string  `json:"removed_ctrl_id"`
	BackupCtrlID    string  `json:"backup_ctrl_id"`   // Ck* = argmax trust
	RemovedScore    float64 `json:"removed_score"`    // τCj at time of removal
	BackupScore     float64 `json:"backup_score"`     // τCk* at time of selection
	ZoneID          string  `json:"zone_id"`
	AssignedAt      int64   `json:"assigned_at_ms"`
	EmergencyBypass bool    `json:"emergency_bypass"` // always true — bypasses Cj
	DocType         string  `json:"doc_type"`
}

// ─── Tier-2 Removal Beacon Records (no-RSU path) ────────────────────────────

// BlacklistBeacon is published to the ledger when a vehicle is permanently
// removed on the Tier-2 (no-RSU) path.  The smart contract appends the
// revoked certificate fingerprint so OBU peers can propagate it over V2V
// within ⌈diam(Gt)⌉ beacon intervals (paper §Conflict Resolution, item 2).
//
// Ledger key: BLACKLIST_BEACON:<vehicle_id>
// doc_type:   "BLACKLIST_BEACON"
//
// Note: V2V propagation requires NS-3/routing.cc integration and is
// future work.  The ledger record itself is the authoritative revocation
// source used by any Tier-2 OBU that queries the ledger directly.
type BlacklistBeacon struct {
	VehicleID       string `json:"vehicle_id"`
	CertFingerprint string `json:"cert_fingerprint"` // SHA-256 of VehicleKeyRecord key bytes
	PublishedAtMs   int64  `json:"published_at_ms"`
	PublisherPeerID string `json:"publisher_peer_id"` // TxID (simulation) or peer MSPID
	DocType         string `json:"doc_type"`
}

// ControllerRevokedBeacon is published to the ledger when a controller is
// removed on the no-RSU path.  The three-step no-RSU removal process
// (thesis §No-RSU controller removal):
//   step i  — Cj's CA certificate is revoked via ControllerCredentialRevocationRequested
//   step ii — this beacon propagates via OBU V2V peers, telling vehicles to stop
//              submitting topology updates to Cj
//   step iii— Ck* reads the beacon on the ledger and begins actively soliciting
//              topology observations from vehicles through its own V2X interface
//              (direction: Ck* → vehicles, not vehicles → Ck*)
//
// Because there is no RSU beacon evidence available in no-RSU mode (unlike the
// with-RSU path where Ck* gets an instant snapshot), Ck* must rebuild topology
// state from scratch.  Routing falls back to distributed vehicle-level decisions
// for InterimFallbackIntervals = ⌈Llink/Tb⌉ beacon intervals while Ck* accumulates
// sufficient observations to resume centralised routing.
//
// Ledger key: CTRL_REVOKED_BEACON:<controller_id>
// doc_type:   "CTRL_REVOKED_BEACON"
type ControllerRevokedBeacon struct {
	ControllerID            string `json:"controller_id"`
	BackupCtrlID            string `json:"backup_ctrl_id"`
	PublishedAtMs           int64  `json:"published_at_ms"`
	PublisherPeerID         string `json:"publisher_peer_id"`
	InterimFallbackIntervals int   `json:"interim_fallback_intervals"` // ⌈Llink/Tb⌉
	DocType                 string `json:"doc_type"`
}

// ─── RSU Zone Reassignment (malicious RSU removal) ──────────────────────────
//
// RSUZoneReassignment is written when a malicious RSU peer is confirmed via
// TTW or BSHH detection.  The compromised RSU's coverage zone is partially
// reassigned to an adjacent trusted controller so the physical area is not
// left without SDN management (thesis §RSU removal, data-plane role).
//
// This runs in parallel with the 3-stage peer-demotion pipeline — the
// demotion pipeline handles the consortium-peer role (removing rk from Pactive,
// zeroing trust, CA-cert revocation); this record handles the data-plane role
// (zone coverage continuity).
//
// Ledger key: RSU_ZONE_REASSIGN:<rsu_id>:<assigned_at_ms>
// doc_type:   "RSU_ZONE_REASSIGNMENT"
type RSUZoneReassignment struct {
	CompromisedRSUID string `json:"compromised_rsu_id"`
	ZoneID           string `json:"zone_id"`           // zone the RSU was covering
	BackupCtrlID     string `json:"backup_ctrl_id"`    // controller assuming partial coverage
	BackupCtrlScore  float64 `json:"backup_ctrl_score"`
	AssignedAtMs     int64  `json:"assigned_at_ms"`
	DocType          string `json:"doc_type"`
}

// ─── Anchor Checkpoint Protocol (Section 5.1) ────────────────────────────────

// AnchorCheckpoint is a PBFT-signed ledger digest produced by Tier 1 RSU peers
// at fixed block intervals so Tier 2 OBU peers can synchronise from a committed
// base state before joining consensus rounds.
//
// Interval  = ⌊Tmin/Tb⌋ blocks
//
//	Tmin    = max(3·TPBFT, Llink/2) ≈ 21.5 s (urban)  →  215 blocks at Tb=100ms
//	Highway: Tmin = max(3·TPBFT, 4.5s) ≈ 4.5s          →   45 blocks
//
// Ledger key: ANCHOR:<created_at_ms>
// doc_type:   "ANCHOR_CHECKPOINT"
type AnchorCheckpoint struct {
	CheckpointID   string   `json:"checkpoint_id"`    // TxID of creation transaction
	BlockHeight    uint64   `json:"block_height"`     // monotonic block counter (ANCHOR_CTR)
	StateRootHash  string   `json:"state_root_hash"`  // SHA-256(TxID||channelID||blockHeight)
	CreatedByPeer  string   `json:"created_by_peer"`  // Tier 1 RSU peer ID
	PeerSig        []byte   `json:"peer_sig"`          // σ_nk Falcon-1024 over checkpoint data
	PeerPubKey     []byte   `json:"peer_pub_key"`
	CreatedAtMs    int64    `json:"created_at_ms"`
	IntervalBlocks int      `json:"interval_blocks"`  // ⌊Tmin/Tb⌋
	SyncedPeers    []string `json:"synced_peers"`     // OBU peers that confirmed sync
	DocType        string   `json:"doc_type"`
}
