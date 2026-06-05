package main

// Data structures for the TemporalEchoMitigator smart contract.
// These mirror the C structs in teta_guard_types.h (TGN→Blockchain boundary).
//
// Ledger key scheme (§13):
//   BEACON:<peer_id>:<interval_ts>          BeaconEvidenceRecord
//   DETECTION:<peer_id>:<vehicle_id>:<ts>   DetectionEvent
//   CTRL_TOPO:<controller_id>:<ts>          ControllerTopologyClaim
//   MITIG:<vehicle_id>:<ts>                 MitigationLogEntry
//   REAUTH:<vehicle_id>                     ReauthFlag
//   KEYSTORE:<peer_id>:<vehicle_id>         VehicleKeyRecord
//   WITNESS:<vehicle_id>:<ts>               WitnessRecord (ME quorum)

// ─── Flow 1 structs ─────────────────────────────────────────────────────────

// VehicleObservation is one vehicle entry within B_nk(t).
type VehicleObservation struct {
	VehicleID  string  `json:"vehicle_id"`
	SenderTSMs int64   `json:"sender_ts_ms"`
	GPSLat     float64 `json:"gps_lat"`
	GPSLon     float64 `json:"gps_lon"`
	RSSIdBm    float32 `json:"rssi_dbm"`
}

// BeaconEvidenceRecord is B_nk(t) — tamper-evident ground truth submitted by
// each RSU/OBU at every beacon interval (§5.1, Flow 1).
type BeaconEvidenceRecord struct {
	PeerID       string               `json:"peer_id"`
	IntervalTS   int64                `json:"interval_ts"`
	Observations []VehicleObservation `json:"observations"`
	PeerSig      []byte               `json:"peer_sig"`      // σ_nk Dilithium2
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
	VehicleID  string  `json:"v_id"`
	Alpha      string  `json:"alpha"`       // "TTW" | "BSHH" | "ME"
	YHat       float32 `json:"y_hat"`       // ŷ_v from Eq.3.23
	STrig      []int   `json:"S_trig"`      // triggered signature indices (0–8)
	TAlertMs   int64   `json:"t_alert"`
	FromLWPath bool    `json:"from_lw_path"`
	FromFSPath bool    `json:"from_fs_path"`
}

// ─── Verification helper structs ─────────────────────────────────────────────

// IndividualSigEvidence carries one Dilithium2 signature for threshold checks (§6.3).
type IndividualSigEvidence struct {
	VehicleID string `json:"vehicle_id"`
	Signature []byte `json:"signature"`
	Message   string `json:"message"`
	PubKey    []byte `json:"pub_key"`
}

// WitnessRecord carries one ME witness report for quorum verification (§6.3).
type WitnessRecord struct {
	ReporterID  string  `json:"reporter_id"`
	ReporterLat float64 `json:"reporter_lat"`
	ReporterLon float64 `json:"reporter_lon"`
	RSSIFromVI  float32 `json:"rssi_from_vi_dbm"`
	Signature   []byte  `json:"signature"`
	Message     string  `json:"message"`
	PubKey      []byte  `json:"pub_key"`
}
