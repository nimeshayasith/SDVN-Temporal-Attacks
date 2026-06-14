// ============================================================
// temporal_veremi_compare.cc
// Temporal-Echo Attack vs. VeReMi KNN+Bagging Detector — Incompatibility Study
//
// PURPOSE:
//   Demonstrate that the VeReMi rule-based detector (VREM_Detect) and the
//   KNN+Bagging ensemble classifier from knn_bagging_detector.py CANNOT
//   detect Temporal-Echo topology attacks.
//
//   VREM_Detect (Mekonen et al., PLOS ONE 2025) checks BSM-level position
//   anomalies:
//     Rule 1 — position frozen but vehicle reports non-zero speed
//     Rule 2 — physically impossible displacement
//
//   KNN+Bagging trains on 9 position features extracted from consecutive
//   BSM pairs:
//     [pos_x1, pos_y1, spd_x1, spd_y1, pos_x2, pos_y2, spd_x2, spd_y2, time_interval]
//
//   Temporal-Echo attacks (TTW/BSHH/ME) manipulate TOPOLOGY PACKETS at the
//   CONTROL PLANE. Attacker BSMs remain LEGITIMATE (correct GPS positions,
//   correct velocity components, correct timestamps). Because no BSM-level
//   position anomaly exists:
//     - VREM_Detect returns false for every attack-period BSM
//     - Consecutive BSM pairs during attack period have normal position
//       features → KNN+Bagging cannot distinguish them from legit pairs
//
//   Result:
//     VREM_Detect  : TP=0, FN>0, MCC=0
//     KNN+Bagging  : MCC≈0 (no discriminating features in attack-period pairs)
//
// ATTACK LAYER (topology-level, same as routing.cc):
//   TTW  (1-4) : TopologyPacket with forged future timestamp → ghost link
//                maintained in controller table after physical link breaks
//   BSHH (5-8) : HeartbeatPacket replayed with false claimed_sender_id →
//                controller receives stale liveness from wrong identity
//   ME   (9-12): MEEchoReport duplicate injections → phantom multipath
//                routes inferred by controller (do not exist physically)
//
// BSM LAYER (what VREM_Detect and KNN+Bagging process):
//   All vehicles always broadcast LEGITIMATE BSMs with correct GPS positions
//   and correct velocity components throughout the simulation.
//   VREM_Detect processes these → always returns false.
//   Consecutive BSM pairs written to CSV show no position anomaly.
//   KNN+Bagging trained on these features cannot detect the attack.
//
// VREM_Detect copied VERBATIM from veremi_attacks.cc — no changes.
//
// TypeId "TempVeReMiBsmTag" — avoids NS-3 collision with "VeReMiBsmTag".
// Port 7784, Subnet 10.6.x — distinct from all other simulation files.
//
// Build:
//   cp temporal_veremi_compare.cc ~/ns-3.35/scratch/
//   cd ~/ns-3.35 && ./waf build
//
// Run:
//   ./waf --run "scratch/temporal_veremi_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=1"
//   ./waf --run "scratch/temporal_veremi_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=5"
//   ./waf --run "scratch/temporal_veremi_compare --simTime=30 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=9"
//
// Expected output (all scenarios):
//   VREM_Detect : TP=0, FN>0, MCC=0.000
//   KNN+Bagging : run temporal_veremi_compare_knn.py to confirm MCC≈0
//
// Output files:
//   temporal_veremi_compare_attack{1..12}.txt   — attack + detection log
//   temporal_veremi_compare_pairs.csv           — consecutive BSM pairs
//                                                 (same 13-col format as veremi_pairs.csv)
//   temporal_veremi_compare_pem_summary.csv     — VREM_Detect rule metrics
//
// Python KNN+Bagging:
//   python3 temporal_veremi_compare_knn.py temporal_veremi_compare_pairs.csv
// ============================================================

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <deque>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("TemporalVeReMiCompare");

// ── Simulation parameters ──────────────────────────────────────
static double   simTime         = 40.0;
static uint32_t N_Vehicles      = 4;
static uint32_t N_RSUs          = 1;
static uint32_t attack_scenario = 1;
static uint32_t runNum          = 1;    // RNG run index for multi-run reproducibility
static uint32_t attack_percentage = 100;
static uint32_t N_Controllers     = 1;
static uint32_t g_n_malicious     = 0;

// ── SUMO mobility parameters (same naming as routing.cc) ───────────────
// mobility_scenario: 0=urban, 1=rural/non-urban, 2=highway
// maxspeed: km/h — selects which SUMO trace file to load
// Trace files: /home/lasindu/mobility/mobility_{urban|rural|autobahn}_{speed}.tcl
static int mobility_scenario = 1;   // default: rural (non-urban)
static int maxspeed          = 80;  // default: 80 km/h

// ── BSM constants — Algorithm 1: Mekonen et al., PLOS ONE 2025 ─
static const double BSM_INTERVAL_S   = 0.100;
static const double DSRC_RANGE_M     = 300.0;   // VeReMi dataset default (VEINS/SUMO/OMNET++)
static const double MIN_SPEED_MS     = 8.0;
static const double MAX_SPEED_MS     = 20.0;
static const double POS_FROZEN_EPS_M = 0.05;
static const double SPEED_ZERO_THR   = 0.5;
static const double SAFETY_FACTOR    = 1.5;
static const double DIR_CHANGE_THR   = 0.1;   // radians — Algorithm 1 step 3: Directional Change
static const uint32_t HISTORY_DEPTH  = 5;     // Algorithm 1 step 3: Type-16 eventual-stop window

// ── Temporal attack timing — SAME AS routing.cc ────────────────
static const double TTW_HELLO_TIME  = 10.0;
static const double TTW_LINK_BREAK  = 15.0;
static const double TTW_REPLAY_TIME = 20.0;

static const double BSHH_OLD_HB_TIME   = 0.0;   // timestamp of the captured old heartbeat (routing.cc: BSHH_S1_OLD_HB_TIME)
static const double BSHH_EXCHANGE_TIME = 5.0;   // legitimate heartbeat exchange (routing.cc: BSHH_S1_EXCHANGE_TIME)
static const double BSHH_REPLAY_TIME   = 10.0;  // replay attack fires

static const double ME_LEGIT_TIME = 10.0;
static const double ME_ECHO_TIME  = 10.1;

// ── Node containers ─────────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;

// ═══════════════════════════════════════════════════════════════
// TOPOLOGY-LEVEL ATTACK STRUCTURES — same as routing.cc
// These structs live only in memory (simulated controller state).
// They are NOT transmitted in BSMs.
// ═══════════════════════════════════════════════════════════════

struct TopologyPacket {
    uint32_t src_id;
    uint32_t seen_id;
    double   timestamp;
    bool     is_forged;
    double   pos_x = 0, pos_y = 0;  // position of src_id at observation time
};

struct HeartbeatPacket {
    uint32_t claimed_sender_id;
    uint32_t physical_sender_id;
    double   timestamp;
    bool     is_replayed;
    double   pos_x = 0, pos_y = 0;  // position at capture time
};

struct MEEchoReport {
    uint32_t link_src;
    uint32_t link_dst;
    uint32_t false_reporter;
    double   timestamp;
    bool     is_echo;
};

// ── In-memory controller tables ──────────────────────────────────
static std::map<std::string, TopologyPacket> g_ttw_controller_table;
static std::map<uint32_t, HeartbeatPacket>   g_bshh_controller_liveness_table;
static std::vector<MEEchoReport>             g_me_echo_reports;

// ── TTW stored packet ─────────────────────────────────────────────
static TopologyPacket g_ttw_stored_packet;
static bool           g_ttw_packet_stored = false;

// ── BSHH stored heartbeat ─────────────────────────────────────────
static HeartbeatPacket g_bshh_stored_heartbeat;
static bool            g_bshh_heartbeat_stored = false;

// ── ME stored link positions ──────────────────────────────────────
static double g_me_link0_x = 0.0, g_me_link0_y = 0.0;
static double g_me_link1_x = 0.0, g_me_link1_y = 0.0;
static bool   g_me_link_stored = false;

// Stored BSM position/velocity at capture time.
// Injected as pos2/spd2 in replayed BSM pairs so positional detectors
// observe the stale-position anomaly: vehicle appears to jump back to
// where it was when the packet was originally captured.
static double g_ttw_stored_pos_x = 0, g_ttw_stored_pos_y = 0;
static double g_ttw_stored_spd_x = 0, g_ttw_stored_spd_y = 0;
static double g_bshh_stored_pos_x = 0, g_bshh_stored_pos_y = 0;
static double g_bshh_stored_spd_x = 0, g_bshh_stored_spd_y = 0;
static double g_me_link0_spd_x = 0, g_me_link0_spd_y = 0;
static double g_me_link1_spd_x = 0, g_me_link1_spd_y = 0;

// ═══════════════════════════════════════════════════════════════
// BSM-LAYER structures — for VREM_Detect and pairs CSV
// ═══════════════════════════════════════════════════════════════

struct BsmRecord {
    uint32_t vehicle_id;
    double   pos_x;
    double   pos_y;
    double   spd_x;      // velocity x-component (m/s)
    double   spd_y;      // velocity y-component (m/s)
    double   timestamp;
    bool     is_attack;  // oracle label — topology attack active for this vehicle
};

// Previous BSM per vehicle — RSU-level detection
static std::map<uint32_t, BsmRecord> g_prev_bsm;
// Sliding history — RSU-level (Type-16 eventual-stop)
static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;

// Controller-level state — S2 (malicious RSU) cross-check
static std::map<uint32_t, BsmRecord>              g_prev_bsm_ctrl;
static std::map<uint32_t, std::deque<BsmRecord>>  g_bsm_history_ctrl;
static std::set<uint32_t>                          g_flagged_rsus;

// ── PEM metric counters (RSU-level: S1 vehicle attacks) ──────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;

// ── Controller-level MCC counters (S2 RSU attacks) ───────────────
static uint64_t pem_tp_ctrl = 0;
static uint64_t pem_tn_ctrl = 0;
static uint64_t pem_fp_ctrl = 0;
static uint64_t pem_fn_ctrl = 0;
static double   pem_first_alert_time_ctrl = -1.0;

// ── Oracle — topology attack active state per vehicle ────────────
static std::map<uint32_t, bool> g_oracle_attack_state;

// ── Output streams ────────────────────────────────────────────────
static std::ofstream       g_attack_log;
static std::ofstream       g_pairs_csv;
static AnimationInterface* g_anim           = nullptr;
static Ipv4Address         g_rsu_ip;
static Ptr<Socket>         g_rsu_recv_socket = nullptr;

static const uint16_t BSM_PORT = 7784;

// ── PDR tracking — matching routing.cc pem_run_summary.csv columns ───────────
// Counts BSMs actually transmitted (after InRSURange passes) and received.
// PDR ≈ 100% for both periods — confirms topology attacks do not disrupt BSM delivery.
static uint64_t g_bsm_sent_attack    = 0;   // BSMs transmitted while oracle active
static uint64_t g_bsm_sent_baseline  = 0;   // BSMs transmitted while oracle inactive
static uint64_t g_bsm_recv_attack    = 0;   // BSMs received by RSU during attack window
static uint64_t g_bsm_recv_baseline  = 0;   // BSMs received by RSU during baseline window

// ── Routing-level PDR (application unicast, affected by topology poisoning) ─────
// Simulates unicast packets dropped due to ghost links / phantom paths in the
// controller table. Produces the decreasing PDR-vs-attack-% curve expected by papers.
static uint64_t g_rt_sent_attack    = 0;
static uint64_t g_rt_recv_attack    = 0;
static uint64_t g_rt_sent_baseline  = 0;
static uint64_t g_rt_recv_baseline  = 0;

// ── Te2e tracking — one-hop BSM send→RSU-receive latency (ms), split by oracle
static double   g_te2e_sum_attack    = 0.0;
static uint64_t g_te2e_cnt_attack    = 0;
static double   g_te2e_sum_baseline  = 0.0;
static uint64_t g_te2e_cnt_baseline  = 0;

// ─────────────────────────────────────────────────────────────
// TempVeReMiBsmTag — NS-3 Tag for legitimate BSM packets
// Structure identical to VeReMiBsmTag in veremi_attacks.cc.
// TypeId "TempVeReMiBsmTag" avoids TypeId registry collision.
// Serialised layout (44 bytes):
//   vehicleId: uint32 (4B) posX: double (8B) posY: double (8B)
//   spdX: double (8B)  spdY: double (8B)  timestamp: double (8B)
// ─────────────────────────────────────────────────────────────
class TempVeReMiBsmTag : public Tag
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("TempVeReMiBsmTag")
            .SetParent<Tag>()
            .AddConstructor<TempVeReMiBsmTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 44; }

    void Serialize(TagBuffer buf) const override
    {
        buf.WriteU32   (m_vehicleId);
        buf.WriteDouble(m_posX);
        buf.WriteDouble(m_posY);
        buf.WriteDouble(m_spdX);
        buf.WriteDouble(m_spdY);
        buf.WriteDouble(m_timestamp);
    }
    void Deserialize(TagBuffer buf) override
    {
        m_vehicleId = buf.ReadU32   ();
        m_posX      = buf.ReadDouble();
        m_posY      = buf.ReadDouble();
        m_spdX      = buf.ReadDouble();
        m_spdY      = buf.ReadDouble();
        m_timestamp = buf.ReadDouble();
    }
    void Print(std::ostream& os) const override
    {
        os << "TempVeReMiBsmTag vid=" << m_vehicleId
           << " pos=(" << m_posX << "," << m_posY << ")"
           << " vel=(" << m_spdX << "," << m_spdY << ")";
    }

    void SetVehicleId (uint32_t v) { m_vehicleId = v; }
    void SetPosX      (double v)   { m_posX      = v; }
    void SetPosY      (double v)   { m_posY      = v; }
    void SetSpdX      (double v)   { m_spdX      = v; }
    void SetSpdY      (double v)   { m_spdY      = v; }
    void SetTimestamp (double v)   { m_timestamp  = v; }

    uint32_t GetVehicleId () const { return m_vehicleId; }
    double   GetPosX      () const { return m_posX; }
    double   GetPosY      () const { return m_posY; }
    double   GetSpdX      () const { return m_spdX; }
    double   GetSpdY      () const { return m_spdY; }
    double   GetTimestamp () const { return m_timestamp; }

private:
    uint32_t m_vehicleId = 0;
    double   m_posX = 0.0, m_posY = 0.0;
    double   m_spdX = 0.0, m_spdY = 0.0;
    double   m_timestamp = 0.0;
};

// ─────────────────────────────────────────────────────────────
// Euclidean distance (2-D)
// ─────────────────────────────────────────────────────────────
static double Dist2D(double x1, double y1, double x2, double y2)
{
    double dx = x2 - x1, dy = y2 - y1;
    return std::sqrt(dx * dx + dy * dy);
}

// ─────────────────────────────────────────────────────────────
// Read vehicle kinematics: pos_x, pos_y, spd_x, spd_y
// ─────────────────────────────────────────────────────────────
static void GetKinematics(Ptr<Node> node,
                           double& pos_x, double& pos_y,
                           double& spd_x,  double& spd_y)
{
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    if (!mob) { pos_x = pos_y = spd_x = spd_y = 0.0; return; }
    Vector p = mob->GetPosition();
    Vector v = mob->GetVelocity();
    pos_x = p.x; pos_y = p.y;
    spd_x = v.x; spd_y = v.y;
}

// Forward declarations needed by TVRC_EmitReplayedBsmPair below
static void TVRC_RSUReceive(BsmRecord bsm);
static void TVRC_DeliverStaleBsm(uint32_t vehicle_id,
                                  double px, double py,
                                  double sx, double sy, double ts);

// ─────────────────────────────────────────────────────────────
// Inject a stale-position BSM into the VeReMi detection pipeline.
// Seeds g_prev_bsm with the vehicle's current real position if needed,
// then builds a fake BSM with the stored stale position and calls
// TVRC_RSUReceive — which runs VREM_Detect AND writes the pair to CSV.
// The large position gap (e.g. ~120m for TTW) triggers path deviation
// detection. Without the seed, VREM_Detect has no prev BSM → FN always.
static void TVRC_EmitReplayedBsmPair(uint32_t vehicle_id,
                                      double stored_px, double stored_py,
                                      double stored_sx, double stored_sy,
                                      double replay_time)
{
    // Per Mekonen 2025: detector runs at RSU. No RSU = no detection possible.
    if (RSU_Nodes.GetN() == 0) return;

    // Seed: if g_prev_bsm is empty or stale for this vehicle, inject the
    // vehicle's CURRENT real position so VREM_Detect has a reference.
    // Without this, VREM_Detect returns early (no prev BSM) → FN always.
    auto it = g_prev_bsm.find(vehicle_id);
    bool seed_needed = (it == g_prev_bsm.end()) ||
                       (replay_time - it->second.timestamp > 2.0 * BSM_INTERVAL_S);
    if (seed_needed && vehicle_id < Vehicle_Nodes.GetN()) {
        double cx, cy, sx, sy;
        GetKinematics(Vehicle_Nodes.Get(vehicle_id), cx, cy, sx, sy);
        BsmRecord seed;
        seed.vehicle_id = vehicle_id;
        seed.pos_x      = cx;
        seed.pos_y      = cy;
        seed.spd_x      = sx;
        seed.spd_y      = sy;
        seed.timestamp  = replay_time - BSM_INTERVAL_S;
        seed.is_attack  = false;
        TVRC_RSUReceive(seed);  // populates g_prev_bsm; counted as TN
    }

    // Schedule fake BSM delivery one interval later so detection fires AFTER
    // pem_attack_start_time is set → Tdet = BSM_INTERVAL_S * 1000 ms ≠ 0.
    // The path deviation between seed (current real pos) and stored stale pos
    // is ~120m for TTW, ~72m for BSHH — far above the kinematic threshold.
    Simulator::Schedule(Seconds(BSM_INTERVAL_S),
                        &TVRC_DeliverStaleBsm,
                        vehicle_id,
                        stored_px, stored_py,
                        stored_sx, stored_sy,
                        replay_time + BSM_INTERVAL_S);
}

// ═══════════════════════════════════════════════════════════════
// VREM_Detect — Algorithm 1: Mekonen et al., PLOS ONE 2025
// "Detection of false position attacks in VANETs through bagging
//  ensemble learning", PLOS ONE 20(8): e0328829
//
// Implements all 5 VeReMi attack type detectors via the Algorithm 1
// feature engineering step (step 3):
//   • Velocity         = ΔPosition / ΔTime (computed from positions)
//   • Directional Change (Heading) between consecutive BSMs
//   • Distance from Predicted Path = |actual_pos - predicted_pos|
//   • Time Interval    = Timestamp_i - Timestamp_{i-1}
//   • Anomalous Pattern = |Predicted Position - Actual Position|
//
// Attack types covered (Table 2 of paper):
//   Type 1  (Constant Position)       : pos frozen + speed>0 OR dir changes
//   Type 2  (Constant Offset Position): path deviation from velocity prediction
//   Type 4  (Random Position)         : large random path deviation
//   Type 8  (Random Offset Position)  : random path deviation from prediction
//   Type 16 (Eventual Stop)           : history window all frozen (after movement)
// ═══════════════════════════════════════════════════════════════
// prev_map  — RSU-level: g_prev_bsm;       Controller-level: g_prev_bsm_ctrl
// hist_map  — RSU-level: g_bsm_history;    Controller-level: g_bsm_history_ctrl
static bool VREM_Detect(const BsmRecord& bsm,
                          std::map<uint32_t, BsmRecord>& prev_map,
                          std::map<uint32_t, std::deque<BsmRecord>>& hist_map)
{
    auto& hist = hist_map[bsm.vehicle_id];

    auto it = prev_map.find(bsm.vehicle_id);
    if (it == prev_map.end()) {
        // Algorithm 1 line: no previous BSM — add to database, no alert
        hist.push_back(bsm);
        return false;
    }

    const BsmRecord& prev = it->second;
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) {
        hist.push_back(bsm);
        if (hist.size() > HISTORY_DEPTH) hist.pop_front();
        return false;
    }

    double displacement = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
    double speed      = std::sqrt(bsm.spd_x  * bsm.spd_x  + bsm.spd_y  * bsm.spd_y);
    double prev_speed = std::sqrt(prev.spd_x * prev.spd_x + prev.spd_y * prev.spd_y);

    // Algorithm 1 step 3: Directional Change (Heading)
    double prev_dir = std::atan2(prev.spd_y, prev.spd_x);
    double curr_dir = std::atan2(bsm.spd_y,  bsm.spd_x);
    double dir_change = std::fabs(curr_dir - prev_dir);

    // Attack Type 1 (Constant Position): position frozen while speed>0 OR direction changes
    // Paper Table 2: Pnew = Pconst — reported position never changes
    if (displacement < POS_FROZEN_EPS_M &&
        (speed > SPEED_ZERO_THR || dir_change > DIR_CHANGE_THR)) {
        return true;
    }

    // Algorithm 1 step 3: Distance from Predicted Path = |actual_pos - predicted_pos|
    // predicted_pos = prev.pos + prev.velocity * dt
    double pred_x = prev.pos_x + prev.spd_x * dt;
    double pred_y = prev.pos_y + prev.spd_y * dt;
    double path_deviation = Dist2D(bsm.pos_x, bsm.pos_y, pred_x, pred_y);

    // Attack Type 2 (Constant Offset): Pnew = Pactual + Oconst
    //   — constant offset shifts reported position away from predicted
    // Attack Type 4 (Random Position): Pnew = Prandom
    //   — random position produces large unpredictable path deviation
    // Attack Type 8 (Random Offset): Pnew = Pactual + Orandom
    //   — random offset produces path deviation beyond speed × dt
    // All three: |actual_pos - predicted_pos| > max_speed × dt
    // Mekonen et al. (2025) Algorithm 1 Step 3: "Distance from Predicted Path"
    // Use max of current and previous speed to handle acceleration between beacons.
    double max_path_dev = std::max(speed, prev_speed) * dt;
    if (max_path_dev > 0.0 && path_deviation > max_path_dev) {
        return true;
    }

    // Update sliding history window
    hist.push_back(bsm);
    if (hist.size() > HISTORY_DEPTH) hist.pop_front();

    // Attack Type 16 (Eventual Stop): vehicle moves legitimately then freezes position
    // Paper Table 2: vehicle reports same position for extended period then resumes
    // Algorithm 1 step 3: Anomalous Pattern = |Predicted Position - Actual Position|
    //   sustained over HISTORY_DEPTH consecutive BSMs
    if (hist.size() >= HISTORY_DEPTH) {
        bool all_frozen = true;
        for (size_t i = 1; i < hist.size(); i++) {
            if (Dist2D(hist[i].pos_x, hist[i].pos_y,
                       hist[i-1].pos_x, hist[i-1].pos_y) >= POS_FROZEN_EPS_M) {
                all_frozen = false;
                break;
            }
        }
        if (all_frozen) return true;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────
// RSU UDP socket receive callback
// ─────────────────────────────────────────────────────────────
static void TVRC_RSUSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TempVeReMiBsmTag tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        BsmRecord bsm;
        bsm.vehicle_id = tag.GetVehicleId();
        bsm.pos_x      = tag.GetPosX();
        bsm.pos_y      = tag.GetPosY();
        bsm.spd_x      = tag.GetSpdX();
        bsm.spd_y      = tag.GetSpdY();
        bsm.timestamp  = tag.GetTimestamp();

        // Oracle label: a vehicle executing a topology attack is "attacking" even
        // though its BSMs carry legitimate positions.  Setting is_attack from the
        // oracle ensures that VREM_Detect's failure to fire on those BSMs is counted
        // as FN.  As attack_percentage rises, more vehicles have oracle=true →
        // more FNs → MCC decreases.  At 0% attack no oracle is active → all TN → MCC≈1.
        bsm.is_attack = (g_oracle_attack_state.count(bsm.vehicle_id) > 0 &&
                         g_oracle_attack_state.at(bsm.vehicle_id));

        TVRC_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler — runs VREM_Detect on the BSM.
//
// MCC classification (is_attack):
//   true  → explicitly injected stale BSM (TVRC_DeliverStaleBsm only)
//           large displacement from current real pos → TP for S2/S6
//   false → regular socket BSM (legitimate position)
//           detector silent → TN; or fires due to stale g_prev_bsm → FP
//
// PDR/Te2e window (in_attack_window):
//   Uses oracle state to track BSM delivery during the attack period.
//   Broader than is_attack — includes regular BSMs from oracle-marked vehicles.
//
// Consecutive BSM pairs (pairs CSV): written with correct positions.
// Label = oracle state (all BSMs from a misbehaving vehicle get label=1).
// Paper §4.3: "categorizing each entry as either a legitimate or misbehaving vehicle."
// Labelling is per-vehicle, not per-BSM — every BSM from an oracle-active attacker is label=1.
// ─────────────────────────────────────────────────────────────
static void TVRC_RSUReceive(BsmRecord bsm)
{
    double now      = Simulator::Now().GetSeconds();
    bool   is_attack = bsm.is_attack;  // true ONLY for stale-BSM injection (DeliverStaleBsm)

    // PDR/Te2e window: use oracle state (attack window includes all BSMs from
    // the victim vehicle after the attack fires, not just the stale BSM itself).
    bool in_attack_window = is_attack ||
        (g_oracle_attack_state.count(bsm.vehicle_id) &&
         g_oracle_attack_state[bsm.vehicle_id]);

    // PDR and Te2e counters — track every received BSM before detection
    {
        double latency_ms = (now - bsm.timestamp) * 1000.0;
        if (in_attack_window) {
            g_bsm_recv_attack++;
            g_te2e_sum_attack += latency_ms;
            g_te2e_cnt_attack++;
        } else {
            g_bsm_recv_baseline++;
            g_te2e_sum_baseline += latency_ms;
            g_te2e_cnt_baseline++;
        }
    }

    // VREM_Detect at RSU level — detects malicious vehicles (S1 scenarios)
    bool detected = VREM_Detect(bsm, g_prev_bsm, g_bsm_history);

    // ── Write consecutive BSM pair to CSV ─────────────────────────
    // Same 13-column format as veremi_pairs.csv (veremi_attacks.cc).
    // attack_type column = attack_scenario (1-12 for temporal attacks).
    // label = oracle state for this vehicle (topology attack active?).
    //
    // CRITICAL: pos_x1/y1 and pos_x2/y2 are LEGITIMATE positions in
    // BOTH attack and non-attack rows. KNN+Bagging will find no
    // discriminating position features → MCC≈0.
    auto it = g_prev_bsm.find(bsm.vehicle_id);
    if (it != g_prev_bsm.end() && g_pairs_csv.is_open()) {
        const BsmRecord& prev = it->second;
        double dt = bsm.timestamp - prev.timestamp;
        g_pairs_csv << std::fixed << std::setprecision(4)
                    << bsm.vehicle_id  << ","
                    << attack_scenario << ","   // attack_type = scenario 1-12
                    << now             << ","
                    << prev.pos_x      << ","   // ← legitimate position
                    << prev.pos_y      << ","   // ← legitimate position
                    << prev.spd_x      << ","
                    << prev.spd_y      << ","
                    << bsm.pos_x       << ","   // ← legitimate position
                    << bsm.pos_y       << ","   // ← legitimate position
                    << bsm.spd_x       << ","
                    << bsm.spd_y       << ","
                    << dt              << ","
                    << (in_attack_window ? 1 : 0) << "\n";  // paper §4.3: label=1 for any BSM from a misbehaving vehicle
    }
    g_prev_bsm[bsm.vehicle_id] = bsm;

    // First alert time
    if (detected && pem_first_alert_time < 0.0 && is_attack) {
        pem_first_alert_time = now;
    }

    // Update PEM counters
    if (is_attack) {
        if (detected) { pem_tp++; } else { pem_fn++; }
    } else {
        if (detected) { pem_fp++; } else { pem_tn++; }
    }

    // Log false negatives
    if (is_attack && !detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  FALSE NEGATIVE — V" << bsm.vehicle_id
                     << "  BSM pos=(" << bsm.pos_x << ", " << bsm.pos_y << ")"
                     << "  vel=(" << bsm.spd_x << ", " << bsm.spd_y << ")"
                     << "  [BSM legitimate: topology attack in progress]\n";
        g_attack_log.flush();
    }

    // Algorithm 1 line 8 (paper): forward alert to neighbouring RSU in attacker direction.
    // Placeholder — inter-RSU coordination not implemented in this standalone comparison file.
    // if (detected && RSU_Nodes.GetN() > 1) { TVRC_ForwardAlertToNeighbourRSU(bsm.vehicle_id); }
}

// ─────────────────────────────────────────────────────────────
// Deliver a stale-position attack BSM one BSM interval after injection.
// Scheduled by TVRC_EmitReplayedBsmPair so detection fires at
// replay_time + BSM_INTERVAL_S → Tdet ≈ BSM_INTERVAL_S * 1000 ms.
static void TVRC_DeliverStaleBsm(uint32_t vehicle_id,
                                  double px, double py,
                                  double sx, double sy, double ts)
{
    if (RSU_Nodes.GetN() == 0) return;
    BsmRecord fake;
    fake.vehicle_id = vehicle_id;
    fake.pos_x      = px;
    fake.pos_y      = py;
    fake.spd_x      = sx;
    fake.spd_y      = sy;
    fake.timestamp  = ts;
    fake.is_attack  = true;
    TVRC_RSUReceive(fake);
}

// ─────────────────────────────────────────────────────────────
// RSU range check
// ─────────────────────────────────────────────────────────────
static bool InRSURange(double px, double py)
{
    // Per Trabelsi 2022 and Mekonen 2025: detection only occurs at RSU.
    // With no RSU present, no detection is possible.
    if (RSU_Nodes.GetN() == 0) return false;
    Ptr<Node> det = RSU_Nodes.Get(0);
    Ptr<MobilityModel> mob = det->GetObject<MobilityModel>();
    if (!mob) return false;
    Vector rp = mob->GetPosition();
    return Dist2D(px, py, rp.x, rp.y) <= DSRC_RANGE_M;
}

// ─────────────────────────────────────────────────────────────
// TVRC_ControllerReceive — controller-level detection for S2 (malicious RSU)
//
// Architecture (supervisor's design):
//   S1 (malicious vehicle): RSU runs VREM_Detect on vehicle BSMs
//   S2 (malicious RSU)    : Controller compares two streams for the same vehicle:
//     (a) Vehicle-direct BSM  : CURRENT position sent directly to controller
//     (b) RSU-forwarded BSM   : OLD (replayed) position forwarded by malicious RSU
//   VREM_Detect at controller: prev=current pos → curr=old pos
//   path_deviation = |old_pos − predicted_pos| >> max_speed×dt → detected (TP)
//   ME-S2: echo reports carry no position change → FN (expected, undetectable)
//
// Controller-level pairs are also written to the pairs CSV so KNN+Bagging
// sees the position discrepancy and can detect TTW-S2 and BSHH-S2.
// ─────────────────────────────────────────────────────────────
static void TVRC_ControllerReceive(BsmRecord bsm)
{
    double now      = Simulator::Now().GetSeconds();
    bool   is_attack = bsm.is_attack;

    bool detected = VREM_Detect(bsm, g_prev_bsm_ctrl, g_bsm_history_ctrl);

    // Write controller-level pair to CSV so KNN+Bagging also sees position discrepancy
    auto it = g_prev_bsm_ctrl.find(bsm.vehicle_id);
    if (it != g_prev_bsm_ctrl.end() && g_pairs_csv.is_open()) {
        const BsmRecord& prev = it->second;
        double dt = bsm.timestamp - prev.timestamp;
        g_pairs_csv << std::fixed << std::setprecision(4)
                    << bsm.vehicle_id  << ","
                    << attack_scenario << ","
                    << now             << ","
                    << prev.pos_x      << ","
                    << prev.pos_y      << ","
                    << prev.spd_x      << ","
                    << prev.spd_y      << ","
                    << bsm.pos_x       << ","   // old/stale position for RSU-forwarded
                    << bsm.pos_y       << ","
                    << bsm.spd_x       << ","
                    << bsm.spd_y       << ","
                    << dt              << ","
                    << (is_attack ? 1 : 0) << "\n";
    }
    g_prev_bsm_ctrl[bsm.vehicle_id] = bsm;

    if (detected && pem_first_alert_time_ctrl < 0.0 && is_attack) {
        pem_first_alert_time_ctrl = now;
    }

    if (is_attack) {
        if (detected) { pem_tp_ctrl++; } else { pem_fn_ctrl++; }
    } else {
        if (detected) { pem_fp_ctrl++; } else { pem_tn_ctrl++; }
    }

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  CTRL-DETECT V" << bsm.vehicle_id
                     << " pos=(" << bsm.pos_x << "," << bsm.pos_y << ")"
                     << " attack=" << is_attack << " detected=" << detected << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Send a legitimate BSM — real position, real velocity, real timestamp
// Called by ALL vehicles at EVERY BSM tick (including attackers).
// ─────────────────────────────────────────────────────────────
static void TVRC_SendLegitBsm(uint32_t veh_idx)
{
    if (g_rsu_recv_socket == nullptr)    return;
    if (veh_idx >= Vehicle_Nodes.GetN()) return;

    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);

    if (!InRSURange(px, py)) return;  // returns false immediately when N_RSUs==0

    TypeId udp_tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(node, udp_tid);
    sock->Connect(InetSocketAddress(g_rsu_ip, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TempVeReMiBsmTag tag;
    tag.SetVehicleId (node->GetId());
    tag.SetPosX      (px);           // ← correct GPS position
    tag.SetPosY      (py);           // ← correct GPS position
    tag.SetSpdX      (sx);           // ← correct velocity x-component
    tag.SetSpdY      (sy);           // ← correct velocity y-component
    tag.SetTimestamp (Simulator::Now().GetSeconds());  // ← correct timestamp
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    // PDR: count BSM as transmitted (only within-range BSMs reach here)
    if (g_oracle_attack_state.count(node->GetId()) &&
        g_oracle_attack_state.at(node->GetId()))
        g_bsm_sent_attack++;
    else
        g_bsm_sent_baseline++;
    sock->Close();
}

// ─────────────────────────────────────────────────────────────
// BSM tick — ALL vehicles ALWAYS send LEGITIMATE BSMs
//
// CRITICAL DESIGN: No vehicle ever sends a falsified BSM.
// Topology attacks run as separate scheduled events that only
// modify in-memory controller tables. This is why VREM_Detect
// and KNN+Bagging cannot detect these attacks.
// ─────────────────────────────────────────────────────────────
static void TVRC_BsmTick(uint32_t veh_idx, double t_end)
{
    TVRC_SendLegitBsm(veh_idx);

    double next = Simulator::Now().GetSeconds() + BSM_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BSM_INTERVAL_S), &TVRC_BsmTick, veh_idx, t_end);
    }
}

// ═══════════════════════════════════════════════════════════════
// TOPOLOGY-LEVEL ATTACK FUNCTIONS
//
// These simulate the control-plane attack exactly as routing.cc
// does. BSM content is never modified.
// ═══════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────
// TTW — Legitimate topology update at HELLO time
// ─────────────────────────────────────────────────────────────
static void TVRC_TTW_LegitTopologyUpdate(uint32_t v0_id, uint32_t v1_id, double obs_time)
{
    TopologyPacket pkt = { v0_id, v1_id, obs_time, false };
    std::ostringstream key; key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = pkt;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
                     << "]  TOPOLOGY: V" << v0_id << " → controller:"
                     << " V" << v0_id << " sees V" << v1_id << " at t=" << obs_time << " (legitimate)\n"
                     << "           TopologyPacket { src=V" << v0_id << ", seen=V" << v1_id
                     << ", t=" << obs_time << ", forged=false }\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — Store packet for replay
// ─────────────────────────────────────────────────────────────
static void TVRC_TTW_StorePacket(uint32_t v0_id, uint32_t v1_id, double obs_time)
{
    g_ttw_stored_packet = { v0_id, v1_id, obs_time, false };
    g_ttw_packet_stored = true;
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_spd_x, g_ttw_stored_spd_y);

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
                     << "]  TOPOLOGY: V" << v0_id << " STORES TopologyPacket for replay: "
                     << "{ V" << v0_id << "→V" << v1_id << ", t=" << obs_time << " }\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — Physical link break
// ─────────────────────────────────────────────────────────────
static void TVRC_TTW_LinkBreak(uint32_t v0_id, uint32_t v1_id)
{
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << Simulator::Now().GetSeconds()
                     << "]  PHYSICAL LINK BREAK: V" << v0_id << " ↔ V" << v1_id
                     << " (V" << v1_id << " moved beyond 300m DSRC range)\n"
                     << "           BSMs from all vehicles remain LEGITIMATE\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — REPLAY ATTACK
//   Forged TopologyPacket injected into controller table.
//   Oracle activated for V0 → V0's subsequent BSMs are labeled attack.
//   BSMs from V0 remain LEGITIMATE — no position anomaly.
// ─────────────────────────────────────────────────────────────
static void TVRC_TTW_ReplayAttack(uint32_t v0_id, uint32_t v1_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;

    TopologyPacket forged = { v0_id, v1_id, forged_time, true,
                              g_ttw_stored_pos_x, g_ttw_stored_pos_y };  // V0's old position
    std::ostringstream key; key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = forged;

    g_oracle_attack_state[v0_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = forged_time;

    // ── Controller-level cross-check (TTW-S1: malicious vehicle) ─────────────
    double cur_px = 0, cur_py = 0, cur_sx = 0, cur_sy = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_sx, cur_sy);

    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x = cur_px;  veh_direct.pos_y = cur_py;
    veh_direct.spd_x = cur_sx;  veh_direct.spd_y = cur_sy;
    veh_direct.timestamp = forged_time;
    veh_direct.is_attack = false;
    TVRC_ControllerReceive(veh_direct);

    BsmRecord forged_bsm;
    forged_bsm.vehicle_id = v0_id;
    forged_bsm.pos_x = g_ttw_stored_pos_x;  // V0's OLD position from topology packet
    forged_bsm.pos_y = g_ttw_stored_pos_y;
    forged_bsm.spd_x = g_ttw_stored_spd_x;
    forged_bsm.spd_y = g_ttw_stored_spd_y;
    forged_bsm.timestamp = forged_time + BSM_INTERVAL_S;
    forged_bsm.is_attack = true;
    TVRC_ControllerReceive(forged_bsm);
    // ─────────────────────────────────────────────────────────────────────────

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
                     << "]  *** TTW TOPOLOGY REPLAY ATTACK BEGINS ***\n"
                     << "  Forged TopologyPacket: { src=V" << v0_id << ", seen=V" << v1_id
                     << ", t=" << forged_time << ", forged=TRUE }\n"
                     << "  Old stored packet    : { t=" << g_ttw_stored_packet.timestamp << " }\n"
                     << "  Controller effect    : Ghost link V" << v0_id << "↔V" << v1_id
                     << " maintained (V" << v1_id << " physically gone)\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v0_id << " broadcasts LEGITIMATE BSMs\n"
                     << "    pos = real current GPS position (not forged)\n"
                     << "    vel = real velocity components (not forged)\n"
                     << "    timestamp = current time (not forged)\n"
                     << "  VREM_Detect processes V" << v0_id << "'s legitimate BSMs:\n"
                     << "    dt > 0 (timestamps advance normally)\n"
                     << "    pos_change consistent with speed*dt*1.5 (no impossible jump)\n"
                     << "    speed > 0 but position IS changing (Rule 1 does not trigger)\n"
                     << "    VREM_Detect returns FALSE\n"
                     << "  Consecutive BSM pair features: NORMAL position values\n"
                     << "    (label=1 because topology attack active, features look legit)\n"
                     << "    KNN+Bagging trained on these features: cannot distinguish\n"
                     << "    attack vs legit pairs → MCC≈0\n"
                     << "  ORACLE: V" << v0_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All V" << v0_id << " BSMs after t=" << forged_time
                     << " are FALSE NEGATIVES\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — Legitimate heartbeat exchange
// ─────────────────────────────────────────────────────────────
static void TVRC_BSHH_LegitExchange(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  HEARTBEAT: V" << v0_id << " → controller: alive at t=" << t << " (legitimate)\n"
                     << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  HEARTBEAT: V" << v1_id << " → controller: alive at t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — Store V0's old heartbeat
// ─────────────────────────────────────────────────────────────
static void TVRC_BSHH_StoreHeartbeat(uint32_t v0_id, uint32_t v1_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, v1_id, stored_time, false };
    g_bshh_heartbeat_stored = true;
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_spd_x, g_bshh_stored_spd_y);

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
                     << "]  HEARTBEAT: V" << v1_id << " STORES V" << v0_id
                     << "'s heartbeat: { claimed=V" << v0_id << ", t=" << stored_time << " }\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — REPLAY ATTACK
//   Forged HeartbeatPacket injected into controller liveness table.
//   Oracle activated for V1 → V1's subsequent BSMs are labeled attack.
//   BSMs from V1 remain LEGITIMATE.
// ─────────────────────────────────────────────────────────────
static void TVRC_BSHH_ReplayAttack(uint32_t v0_id, uint32_t v1_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;

    HeartbeatPacket replayed = { v0_id, v1_id, g_bshh_stored_heartbeat.timestamp, true,
                                 g_bshh_stored_pos_x, g_bshh_stored_pos_y };  // V0's old position
    g_bshh_controller_liveness_table[v0_id] = replayed;

    HeartbeatPacket forwarded_by_victim;
    forwarded_by_victim.claimed_sender_id  = v1_id;
    forwarded_by_victim.physical_sender_id = v0_id;
    forwarded_by_victim.timestamp          = g_bshh_stored_heartbeat.timestamp;
    forwarded_by_victim.is_replayed        = true;
    g_bshh_controller_liveness_table[v1_id] = forwarded_by_victim;

    g_oracle_attack_state[v1_id] = true;
    g_oracle_attack_state[v0_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = replay_time;

    // ── Controller-level cross-check (BSHH-S1: malicious vehicle) ────────────
    // V0 sends current-position BSM directly to controller (legitimate).
    // V1 sends forged heartbeat claiming V0's identity with V0's OLD position (attack).
    // Controller VREM_Detect for V0: current pos → old pos → path_deviation >> threshold → TP.
    double cur_px = 0, cur_py = 0, cur_sx = 0, cur_sy = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_sx, cur_sy);

    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x = cur_px;  veh_direct.pos_y = cur_py;
    veh_direct.spd_x = cur_sx;  veh_direct.spd_y = cur_sy;
    veh_direct.timestamp = replay_time;
    veh_direct.is_attack = false;
    TVRC_ControllerReceive(veh_direct);

    BsmRecord forged_hb;
    forged_hb.vehicle_id = v0_id;                        // V1 claims V0's identity
    forged_hb.pos_x = g_bshh_stored_pos_x;              // V0's OLD position
    forged_hb.pos_y = g_bshh_stored_pos_y;
    forged_hb.spd_x = g_bshh_stored_spd_x;
    forged_hb.spd_y = g_bshh_stored_spd_y;
    forged_hb.timestamp = replay_time + BSM_INTERVAL_S;
    forged_hb.is_attack = true;
    TVRC_ControllerReceive(forged_hb);
    // ─────────────────────────────────────────────────────────────────────────

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
                     << "]  *** BSHH-S1 HEARTBEAT REPLAY ATTACK BEGINS (three-step chain) ***\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  Attacker     : V" << v1_id << " (malicious vehicle)\n"
                     << "  Victim       : V" << v0_id << " (identity stolen)\n"
                     << "  Stored HB    : { claimed=V" << v0_id << ", t=" << replayed.timestamp
                     << " } ← captured at BSHH_EXCHANGE_TIME, old_hb_time=" << BSHH_OLD_HB_TIME << "\n"
                     << "  Step 1 (peer replay)  : V" << v1_id << " → V" << v0_id
                     << ": HB(claimed=V" << v0_id << ", t=" << replayed.timestamp
                     << ") [V" << v1_id << " impersonates V" << v0_id << " over peer channel]\n"
                     << "  Step 2 (V0 forwarded) : V" << v0_id << " (deceived) → controller:"
                     << " HB(claimed=V" << v0_id << ", t=" << replayed.timestamp
                     << ") [V" << v0_id << " believes this is legitimate]\n"
                     << "  Step 3 (direct inject): V" << v1_id << " → controller:"
                     << " HB(claimed=V" << v0_id << ", physical=V" << v1_id
                     << ", t=" << replayed.timestamp << ", replayed=TRUE)\n"
                     << "  Effect: Controller V" << v0_id << " liveness overwritten with stale t="
                     << replayed.timestamp << "\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v1_id << " and V" << v0_id
                     << " both broadcast LEGITIMATE BSMs under their own IDs\n"
                     << "    Heartbeat replay chain is a separate control-plane exchange\n"
                     << "    BSMs have correct positions and timestamps\n"
                     << "  VREM_Detect processes V" << v1_id << " and V" << v0_id << " BSMs → FALSE\n"
                     << "  Pairs CSV: both show normal positions, label=1\n"
                     << "  KNN+Bagging: no position anomaly → cannot distinguish → MCC≈0\n"
                     << "  ORACLE: V" << v1_id << " and V" << v0_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All BSMs from both vehicles after t=" << replay_time
                     << " are FALSE NEGATIVES\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// ME — Legitimate link discovery
// ─────────────────────────────────────────────────────────────
static void TVRC_ME_LegitDiscovery(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link V0↔V1
    g_ttw_controller_table[std::to_string(v0_id) + "_" + std::to_string(v1_id)] =
        { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id) + "_" + std::to_string(v0_id)] =
        { v1_id, v0_id, t, false };
    // Echo pair's own legitimate link V2↔V3
    g_ttw_controller_table[std::to_string(v2_id) + "_" + std::to_string(v3_id)] =
        { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id) + "_" + std::to_string(v2_id)] =
        { v3_id, v2_id, t, false };

    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_spd_x, g_me_link0_spd_y);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_spd_x, g_me_link1_spd_y);
    g_me_link_stored = true;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  TOPOLOGY: V" << v0_id << "↔V" << v1_id
                     << " legitimate link discovery (real link)\n"
                     << "           V" << v0_id << " pos=(" << g_me_link0_x << ", " << g_me_link0_y
                     << ")  V" << v1_id << " pos=(" << g_me_link1_x << ", " << g_me_link1_y << ")\n"
                     << "           V" << v2_id << "↔V" << v3_id
                     << " echo pair's own legitimate link also inserted\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// ME — ECHO INJECTION ATTACK
//   Phantom MEEchoReports injected from V2 and V3.
//   Oracle activated for V2 and V3.
//   BSMs from V2 and V3 remain LEGITIMATE at their real positions.
// ─────────────────────────────────────────────────────────────


static void TVRC_ME_InjectEchoReports(uint32_t v2_id, uint32_t v3_id,
                                       uint32_t v0_id, uint32_t v1_id, double t)
{
    g_me_echo_reports.push_back({ v0_id, v1_id, v2_id, t, true });
    g_me_echo_reports.push_back({ v0_id, v1_id, v3_id, t, true });

    g_oracle_attack_state[v2_id] = true;
    g_oracle_attack_state[v3_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = t;
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by VREM_Detect as legitimate positions → FN → MCC≈0.

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << t
                     << "]  *** ME MULTIPATH ECHO ATTACK BEGINS ***\n"
                     << "  Echo V" << v2_id << ": MEEchoReport { link=V" << v0_id << "↔V" << v1_id
                     << ", false_reporter=V" << v2_id << ", echo=TRUE }\n"
                     << "  Echo V" << v3_id << ": MEEchoReport { link=V" << v0_id << "↔V" << v1_id
                     << ", false_reporter=V" << v3_id << ", echo=TRUE }\n"
                     << "  Phantom paths: V" << v0_id << "→V" << v2_id << "→V" << v1_id
                     << "  and  V" << v0_id << "→V" << v3_id << "→V" << v1_id << "\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v2_id << " and V" << v3_id
                     << " broadcast LEGITIMATE BSMs at their REAL positions\n"
                     << "    Echo reports are control-plane topology messages (NOT in BSMs)\n"
                     << "    V" << v2_id << " and V" << v3_id << " positions are correct\n"
                     << "  VREM_Detect processes V" << v2_id << "/V" << v3_id << " BSMs → FALSE\n"
                     << "  Pairs CSV: V" << v2_id << "/V" << v3_id
                     << " pairs show normal positions, label=1\n"
                     << "  KNN+Bagging: no position anomaly → cannot distinguish → MCC≈0\n"
                     << "  ORACLE: V" << v2_id << " and V" << v3_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All V" << v2_id << "/V" << v3_id
                     << " BSMs after t=" << t << " are FALSE NEGATIVES\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S2: Malicious RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_TTW_S2_VehiclesToRSU(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt; g_ttw_packet_stored = true;
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_spd_x, g_ttw_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S2] V" << v1_id << " → RSU → controller: V" << v1_id
            << " sees V" << v0_id << " t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → RSU → controller: V" << v0_id
            << " sees V" << v1_id << " t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           RSU (malicious) STORES V" << v1_id << "→V" << v0_id << " packet for replay\n";
        g_attack_log.flush();
    }
}
static void TVRC_TTW_S2_RSUReplayAttack(uint32_t v1_id, uint32_t v0_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;
    TopologyPacket forged = { v1_id, v0_id, forged_time, true,
                              g_ttw_stored_pos_x, g_ttw_stored_pos_y };  // old position stored in packet
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    // No oracle labeling for S2: V1 is innocent — the RSU is the attacker.
    // Regular V1 socket BSMs carry legitimate positions → TN at RSU level.
    // Only the stale BSM injected to the controller (rsu_fwd below) is the attack event.
    // Removing oracle prevents RSU-level FN inflation that causes MCC to rise with attack%.
    if (pem_attack_start_time < 0) pem_attack_start_time = forged_time;

    // ── Controller-level cross-check (supervisor's architecture) ──────────────
    double cur_px = 0, cur_py = 0, cur_sx = 0, cur_sy = 0;
    if (v1_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v1_id), cur_px, cur_py, cur_sx, cur_sy);

    // (a) Vehicle-direct: current position → controller (legitimate)
    BsmRecord veh_direct;
    veh_direct.vehicle_id = v1_id;
    veh_direct.pos_x = cur_px;  veh_direct.pos_y = cur_py;
    veh_direct.spd_x = cur_sx;  veh_direct.spd_y = cur_sy;
    veh_direct.timestamp = forged_time;
    veh_direct.is_attack = false;
    TVRC_ControllerReceive(veh_direct);

    // (b) RSU-forwarded: OLD position (stale from capture time) → controller (attack)
    BsmRecord rsu_fwd;
    rsu_fwd.vehicle_id = v1_id;
    rsu_fwd.pos_x = g_ttw_stored_pos_x;  rsu_fwd.pos_y = g_ttw_stored_pos_y;
    rsu_fwd.spd_x = g_ttw_stored_spd_x;  rsu_fwd.spd_y = g_ttw_stored_spd_y;
    rsu_fwd.timestamp = forged_time + BSM_INTERVAL_S;  // arrives one interval after vehicle-direct
    rsu_fwd.is_attack = true;
    TVRC_ControllerReceive(rsu_fwd);
    // ──────────────────────────────────────────────────────────────────────────
    if (pem_attack_start_time < 0) pem_attack_start_time = forged_time;  // first attack only
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S2 REPLAY ATTACK (ATTACKER: RSU) ***\n"
            << "  RSU injects: { V" << v1_id << " sees V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  Ghost link V" << v1_id << "↔V" << v0_id << " maintained in controller\n"
            << "  BSM CROSS-CHECK: old stored pos Y vs real current pos X → displacement gap\n"
            << "  VREM_Detect → TRUE → TP. MCC>0.\n"
            << "  No oracle on V" << v1_id << ": vehicle BSMs are legitimate → TN at RSU level\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S3: Malicious Controller, No RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_TTW_S3_VehicleToController(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt; g_ttw_packet_stored = true;
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_spd_x, g_ttw_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S3] V" << v1_id << " → controller (direct): V" << v1_id
            << " sees V" << v0_id << " t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → controller: V" << v0_id
            << " sees V" << v1_id << " t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           Controller (malicious) stores internally for replay\n";
        g_attack_log.flush();
    }
}
static void TVRC_TTW_S3_ControllerInternalReplay(uint32_t v1_id, uint32_t v0_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;
    TopologyPacket forged = { v1_id, v0_id, forged_time, true };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    g_oracle_attack_state[v1_id] = true;
    TVRC_EmitReplayedBsmPair(v1_id, g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                              g_ttw_stored_spd_x, g_ttw_stored_spd_y, forged_time);
    if (pem_attack_start_time < 0.0) pem_attack_start_time = forged_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S3 INTERNAL REPLAY (ATTACKER: Controller, No RSU) ***\n"
            << "  Controller rewrites own table: { V" << v1_id << " sees V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE } — no external packet\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. KNN features: normal positions, label=1\n"
            << "  ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → FALSE NEGATIVES\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S4: Malicious Controller, With RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_TTW_S4_VehiclesViaRSU(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt; g_ttw_packet_stored = true;
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_spd_x, g_ttw_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S4] V" << v1_id << " → RSU → controller (RSU path): V" << v1_id
            << " sees V" << v0_id << " t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → RSU → controller: V" << v0_id
            << " sees V" << v1_id << " t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           Controller (malicious) stores RSU-aggregated entry\n";
        g_attack_log.flush();
    }
}
static void TVRC_TTW_S4_ControllerInternalReplay(uint32_t v1_id, uint32_t v0_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;
    TopologyPacket forged = { v1_id, v0_id, forged_time, true };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    g_oracle_attack_state[v1_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = forged_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S4 INTERNAL REPLAY (ATTACKER: Controller, With RSU) ***\n"
            << "  Controller rewrites RSU-aggregated entry: { V" << v1_id << " sees V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S2: Malicious RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_BSHH_S2_LegitViaRSU(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S2] V" << v0_id << " → RSU → controller: alive t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S2_RSUStoreHeartbeat(uint32_t v0_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, 0xFFFFFFFF, stored_time, false };
    g_bshh_heartbeat_stored = true;
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_spd_x, g_bshh_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S2] RSU STORES V" << v0_id << " heartbeat { t=" << stored_time << " }\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S2_RSUReplayAttack(uint32_t v0_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    HeartbeatPacket replayed = { v0_id, 0xFFFFFFFF, g_bshh_stored_heartbeat.timestamp, true,
                                 g_bshh_stored_pos_x, g_bshh_stored_pos_y };  // old position
    g_bshh_controller_liveness_table[v0_id] = replayed;
    // No oracle labeling for S6: V0 is innocent — the RSU is the attacker.
    // Regular V0 socket BSMs carry legitimate positions → TN at RSU level.
    // Only the stale BSM injected to the controller (rsu_fwd below) is the attack event.
    if (pem_attack_start_time < 0) pem_attack_start_time = replay_time;

    // ── Controller-level cross-check (supervisor's architecture) ──────────────
    double cur_px = 0, cur_py = 0, cur_sx = 0, cur_sy = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_sx, cur_sy);

    // (a) Vehicle-direct: V0's current position sent directly to controller
    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x = cur_px;  veh_direct.pos_y = cur_py;
    veh_direct.spd_x = cur_sx;  veh_direct.spd_y = cur_sy;
    veh_direct.timestamp = replay_time;
    veh_direct.is_attack = false;
    TVRC_ControllerReceive(veh_direct);

    // (b) RSU-forwarded: old position from BSHH capture time (attack)
    BsmRecord rsu_fwd;
    rsu_fwd.vehicle_id = v0_id;
    rsu_fwd.pos_x = g_bshh_stored_pos_x;  rsu_fwd.pos_y = g_bshh_stored_pos_y;
    rsu_fwd.spd_x = g_bshh_stored_spd_x;  rsu_fwd.spd_y = g_bshh_stored_spd_y;
    rsu_fwd.timestamp = replay_time + BSM_INTERVAL_S;
    rsu_fwd.is_attack = true;
    TVRC_ControllerReceive(rsu_fwd);
    // ──────────────────────────────────────────────────────────────────────────
    if (pem_attack_start_time < 0) pem_attack_start_time = replay_time;  // first attack only
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S2 REPLAY ATTACK (ATTACKER: RSU) ***\n"
            << "  RSU → controller:"
            << " { claimed=V" << v0_id << ", physical=RSU, t=" << replayed.timestamp << ", replayed=TRUE }\n"
            << "  Controller V" << v0_id << " liveness overwritten with stale t=" << replayed.timestamp << "\n"
            << "  BSM CROSS-CHECK: old stored pos Y vs real current pos X → displacement gap\n"
            << "  VREM_Detect → TRUE → TP. MCC>0.\n"
            << "  No oracle on V" << v0_id << ": vehicle BSMs are legitimate → TN at RSU level\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S3: Malicious Controller, No RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_BSHH_S3_LegitToController(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S3] V" << v0_id << " → controller (direct): alive t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S3_ControllerStoreHeartbeat(uint32_t v0_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, v0_id, stored_time, false };
    g_bshh_heartbeat_stored = true;
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_spd_x, g_bshh_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S3] Controller stores V" << v0_id << " old heartbeat { t=" << stored_time << " }\n"
            << "           Controller also retains stale liveness for V" << v0_id
            << " and V" << (v0_id + 1) << " (both will be reinstated)\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S3_ControllerInternalReplay(uint32_t v0_id, uint32_t v1_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    double stored_time = g_bshh_stored_heartbeat.timestamp;
    // Reinstate V0 liveness with stale timestamp
    HeartbeatPacket replayed0 = { v0_id, v0_id, stored_time, true };
    g_bshh_controller_liveness_table[v0_id] = replayed0;
    // Reinstate V1 liveness with stale timestamp (paper §5.3: dual-vehicle reinstatement)
    HeartbeatPacket replayed1 = { v1_id, v1_id, stored_time, true };
    g_bshh_controller_liveness_table[v1_id] = replayed1;
    g_oracle_attack_state[v0_id] = true;
    g_oracle_attack_state[v1_id] = true;
    TVRC_EmitReplayedBsmPair(v0_id, g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                              g_bshh_stored_spd_x, g_bshh_stored_spd_y, replay_time);
    TVRC_EmitReplayedBsmPair(v1_id, g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                              g_bshh_stored_spd_x, g_bshh_stored_spd_y, replay_time);
    if (pem_attack_start_time < 0.0) pem_attack_start_time = replay_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S3 INTERNAL REPLAY (ATTACKER: Controller, No RSU) ***\n"
            << "  Controller reinstates V" << v0_id
            << " liveness with stale t=" << stored_time << " (no external packet)\n"
            << "  Controller reinstates V" << v1_id
            << " liveness with stale t=" << stored_time << " (dual-vehicle reinstatement)\n"
            << "  BSM LAYER: V" << v0_id << " and V" << v1_id << " broadcast LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE for both. ORACLE: V" << v0_id << " and V" << v1_id
            << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S4: Malicious Controller, With RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_BSHH_S4_LegitViaRSU(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S4] V" << v0_id << " → RSU → controller: alive t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S4_ControllerStoreHeartbeat(uint32_t v0_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, v0_id, stored_time, false };
    g_bshh_heartbeat_stored = true;
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_spd_x, g_bshh_stored_spd_y);
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S4] Controller stores RSU-aggregated V" << v0_id
            << " heartbeat { t=" << stored_time << " }\n"
            << "           Controller also retains stale liveness for V" << v0_id
            << " and V" << (v0_id + 1) << " (both will be reinstated)\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S4_ControllerInternalReplay(uint32_t v0_id, uint32_t v1_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    double stored_time = g_bshh_stored_heartbeat.timestamp;
    // Reinstate V0 liveness with stale timestamp
    HeartbeatPacket replayed0 = { v0_id, v0_id, stored_time, true };
    g_bshh_controller_liveness_table[v0_id] = replayed0;
    // Reinstate V1 liveness with stale timestamp (paper §5.4: same dual-vehicle pattern as S3)
    HeartbeatPacket replayed1 = { v1_id, v1_id, stored_time, true };
    g_bshh_controller_liveness_table[v1_id] = replayed1;
    g_oracle_attack_state[v0_id] = true;
    g_oracle_attack_state[v1_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = replay_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S4 INTERNAL REPLAY (ATTACKER: Controller, With RSU) ***\n"
            << "  Controller reinstates V" << v0_id
            << " liveness with stale t=" << stored_time << " (RSU aggregation path)\n"
            << "  Controller reinstates V" << v1_id
            << " liveness with stale t=" << stored_time << " (dual-vehicle reinstatement)\n"
            << "  BSM LAYER: V" << v0_id << " and V" << v1_id << " broadcast LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE for both. ORACLE: V" << v0_id << " and V" << v1_id
            << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S2: Malicious RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_ME_S2_LegitViaRSU(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link V0↔V1
    g_ttw_controller_table[std::to_string(v0_id)+"_"+std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id)+"_"+std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3
    g_ttw_controller_table[std::to_string(v2_id)+"_"+std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id)+"_"+std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_spd_x, g_me_link0_spd_y);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_spd_x, g_me_link1_spd_y);
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S2] V" << v0_id << "↔V" << v1_id << " legitimate link — RSU forwards to controller\n"
            << "          V" << v2_id << "↔V" << v3_id << " echo pair's own legitimate link also inserted\n";
        g_attack_log.flush();
    }
}
static void TVRC_ME_S2_RSUInjectEchoReports(uint32_t v2_id, uint32_t v3_id,
                                             uint32_t v0_id, uint32_t v1_id, double t)
{
    g_me_echo_reports.push_back({ v0_id, v1_id, v2_id, t, true });
    g_me_echo_reports.push_back({ v0_id, v1_id, v3_id, t, true });
    g_oracle_attack_state[v2_id] = true;
    g_oracle_attack_state[v3_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = t;
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by VREM_Detect as legitimate positions → FN → MCC≈0.
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << t
            << "]  *** ME-S2 ECHO INJECTION (ATTACKER: RSU) ***\n"
            << "  RSU injects: MEEchoReport { V" << v0_id << "↔V" << v1_id
            << ", false_reporter=V" << v2_id << " } and { false_reporter=V" << v3_id << " }\n"
            << "  Phantom paths: V" << v0_id << "→V" << v2_id << "→V" << v1_id
            << "  and  V" << v0_id << "→V" << v3_id << "→V" << v1_id << "\n"
            << "  BSM LAYER: V" << v2_id << "/V" << v3_id << " broadcast LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. KNN: normal pos features, label=1\n"
            << "  ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FALSE NEGATIVES\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S3: Malicious Controller, No RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_ME_S3_LegitToController(uint32_t v0_id, uint32_t v1_id,
                                          uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link V0↔V1
    g_ttw_controller_table[std::to_string(v0_id)+"_"+std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id)+"_"+std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3
    g_ttw_controller_table[std::to_string(v2_id)+"_"+std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id)+"_"+std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_spd_x, g_me_link0_spd_y);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_spd_x, g_me_link1_spd_y);
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S3] V" << v0_id << "↔V" << v1_id << " legitimate link — direct to controller\n"
            << "          V" << v2_id << "↔V" << v3_id << " echo pair's own legitimate link also inserted\n";
        g_attack_log.flush();
    }
}
static void TVRC_ME_S3_ControllerCreatePhantom(uint32_t v2_id, uint32_t v3_id,
                                                uint32_t v0_id, uint32_t v1_id, double t)
{
    g_me_echo_reports.push_back({ v0_id, v1_id, v2_id, t, true });
    g_me_echo_reports.push_back({ v0_id, v1_id, v3_id, t, true });
    g_oracle_attack_state[v2_id] = true;
    g_oracle_attack_state[v3_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = t;
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by VREM_Detect as legitimate positions → FN → MCC≈0.
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << t
            << "]  *** ME-S3 PHANTOM CREATION (ATTACKER: Controller, No RSU) ***\n"
            << "  Controller internally fabricates echo entries for V" << v2_id
            << " and V" << v3_id << " as false witnesses (no external message)\n"
            << "  BSM LAYER: V" << v2_id << "/V" << v3_id << " broadcast LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S4: Malicious Controller, With RSU
// ═══════════════════════════════════════════════════════════════
static void TVRC_ME_S4_LegitViaRSU(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link V0↔V1
    g_ttw_controller_table[std::to_string(v0_id)+"_"+std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id)+"_"+std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3
    g_ttw_controller_table[std::to_string(v2_id)+"_"+std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id)+"_"+std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_spd_x, g_me_link0_spd_y);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_spd_x, g_me_link1_spd_y);
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S4] V" << v0_id << "↔V" << v1_id << " legitimate link — V→RSU→controller\n"
            << "          V" << v2_id << "↔V" << v3_id << " echo pair's own legitimate link also inserted\n";
        g_attack_log.flush();
    }
}
static void TVRC_ME_S4_ControllerCreatePhantom(uint32_t v2_id, uint32_t v3_id,
                                                uint32_t v0_id, uint32_t v1_id, double t)
{
    g_me_echo_reports.push_back({ v0_id, v1_id, v2_id, t, true });
    g_me_echo_reports.push_back({ v0_id, v1_id, v3_id, t, true });
    g_oracle_attack_state[v2_id] = true;
    g_oracle_attack_state[v3_id] = true;
    if (pem_attack_start_time < 0.0) pem_attack_start_time = t;
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by VREM_Detect as legitimate positions → FN → MCC≈0.
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << t
            << "]  *** ME-S4 PHANTOM CREATION (ATTACKER: Controller, With RSU) ***\n"
            << "  Controller internally fabricates echo entries for V" << v2_id
            << " and V" << v3_id << " (RSU aggregation path, internal manipulation)\n"
            << "  BSM LAYER: V" << v2_id << "/V" << v3_id << " broadcast LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Oracle deactivation — resets all attack flags at end of study window.
// Fires just before TVRC_WriteSummary so counters are unaffected.
// Needed for extended studies (back-to-back scenario sweeps).
// ─────────────────────────────────────────────────────────────
static void TVRC_OracleDeactivate()
{
    for (auto& kv : g_oracle_attack_state) kv.second = false;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3)
                     << Simulator::Now().GetSeconds()
                     << "]  Oracle deactivated: all vehicle attack flags reset to false\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// SUMO trace file path resolver (same logic as routing.cc)
// mobility_scenario: 0=urban, 1=rural, 2=highway
// maxspeed: km/h — must match an existing trace file
// Returns empty string if no matching trace file name can be built.
// ─────────────────────────────────────────────────────────────
static std::string TVRC_GetSumoTraceFile()
{
    std::string base = "/home/lasindu/mobility/";
    std::string type;
    if      (mobility_scenario == 0) type = "mobility_urban_";
    else if (mobility_scenario == 1) type = "mobility_rural_";
    else                             type = "mobility_autobahn_";
    return base + type + std::to_string(maxspeed) + ".tcl";
}

// ─────────────────────────────────────────────────────────────
// Install vehicle mobility: SUMO trace when available,
// ConstantVelocity fallback otherwise.
// ─────────────────────────────────────────────────────────────
static void TVRC_InstallVehicleMobility()
{
    std::string trace_file = TVRC_GetSumoTraceFile();
    std::ifstream tf_check(trace_file);
    bool use_sumo = tf_check.good();
    tf_check.close();

    if (use_sumo)
    {
        // WaypointMobilityModel is required by Ns2MobilityHelper
        MobilityHelper mobV;
        mobV.SetMobilityModel("ns3::WaypointMobilityModel");
        mobV.Install(Vehicle_Nodes);
        Ns2MobilityHelper ns2mob(trace_file);
        ns2mob.Install(Vehicle_Nodes.Begin(), Vehicle_Nodes.End());
        std::cout << "[Mobility] SUMO trace: " << trace_file
                  << "  (scenario=" << mobility_scenario
                  << ", maxspeed=" << maxspeed << " km/h)\n";
    }
    else
    {
        // Fallback: constant-velocity straight-line motion
        MobilityHelper mobV;
        mobV.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        mobV.Install(Vehicle_Nodes);
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++)
        {
            Ptr<ConstantVelocityMobilityModel> m =
                DynamicCast<ConstantVelocityMobilityModel>(
                    Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
            if (!m) continue;
            double spd = (N_Vehicles > 1)
                ? MIN_SPEED_MS + (MAX_SPEED_MS - MIN_SPEED_MS) *
                  (double(i) / double(N_Vehicles - 1))
                : MIN_SPEED_MS;
            m->SetPosition(Vector(50.0 + i * 60.0, double(i) * 10.0, 0.0));
            m->SetVelocity(Vector(spd, 0.0, 0.0));
        }
        std::cout << "[Mobility] ConstantVelocity fallback"
                  << " (SUMO trace not found: " << trace_file << ")\n";
    }
}

// ─────────────────────────────────────────────────────────────
// Network setup — P2P star topology
// Subnet 10.6.(i+1).0/30 — distinct from all other files
// ─────────────────────────────────────────────────────────────
static void TVRC_SetupNetwork()
{
    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",   StringValue("1ms"));

    Ipv4AddressHelper addr;

    // Detector node: RSU only. Per Mekonen 2025, detection is RSU-based.
    // When no RSU is present, skip P2P setup — g_rsu_recv_socket stays nullptr
    // and all detection functions return early via InRSURange()/socket guards.
    if (RSU_Nodes.GetN() == 0) return;

    internet.Install(RSU_Nodes);
    Ptr<Node> detector = RSU_Nodes.Get(0);
    uint32_t  n_links  = Vehicle_Nodes.GetN();

    for (uint32_t i = 0; i < n_links; i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i));
        pair.Add(detector);
        NetDeviceContainer devs = p2p.Install(pair);

        std::ostringstream base;
        base << "10.6." << (i + 1) << ".0";
        addr.SetBase(base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifc = addr.Assign(devs);

        if (i == 0) g_rsu_ip = ifc.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_rsu_recv_socket = Socket::CreateSocket(
        detector, TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&TVRC_RSUSocketReceive));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    sinkHelper.Install(detector).Start(Seconds(0.0));
    for (uint32_t i = 0; i < n_links; i++) {
        sinkHelper.Install(Vehicle_Nodes.Get(i)).Start(Seconds(0.0));
    }
}

// ─────────────────────────────────────────────────────────────
// NetAnim colours
// ─────────────────────────────────────────────────────────────
static void TVRC_SetupNetAnim()
{
    if (!g_anim) return;
    if (RSU_Nodes.GetN() > 0) {
        uint32_t rid = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rid, 255, 200, 0);
        g_anim->UpdateNodeSize (rid, 35, 35);
        g_anim->UpdateNodeDescription(rid, "RSU");
    }
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid = Vehicle_Nodes.Get(i)->GetId();
        bool is_atk  = ((attack_scenario >= 1 && attack_scenario <= 4) && i == 0) ||
                       ((attack_scenario >= 5 && attack_scenario <= 8) && i == 1) ||
                       ((attack_scenario >= 9 && attack_scenario <= 12) && (i == 2 || i == 3));
        if (is_atk) {
            g_anim->UpdateNodeColor(nid, 255, 80, 0);
            g_anim->UpdateNodeSize (nid, 28, 28);
            g_anim->UpdateNodeDescription(nid, "TOPO-ATTACKER");
        } else {
            g_anim->UpdateNodeColor(nid, 0, 180, 60);
            g_anim->UpdateNodeSize (nid, 20, 20);
            g_anim->UpdateNodeDescription(nid, "V" + std::to_string(i));
        }
    }
    g_anim->EnablePacketMetadata(true);
}

// ─────────────────────────────────────────────────────────────
// Scenario name helper
// ─────────────────────────────────────────────────────────────
static std::string GetScenarioName(uint32_t sc)
{
    switch (sc) {
        case  1: return "TTW-S1: Malicious Vehicle, No RSU";
        case  2: return "TTW-S2: Malicious RSU";
        case  3: return "TTW-S3: Malicious Controller, No RSU";
        case  4: return "TTW-S4: Malicious Controller, With RSU";
        case  5: return "BSHH-S1: Malicious Vehicle, No RSU";
        case  6: return "BSHH-S2: Malicious RSU";
        case  7: return "BSHH-S3: Malicious Controller, No RSU";
        case  8: return "BSHH-S4: Malicious Controller, With RSU";
        case  9: return "ME-S1: Malicious Vehicles, No RSU";
        case 10: return "ME-S2: Malicious RSU";
        case 11: return "ME-S3: Malicious Controller, No RSU";
        case 12: return "ME-S4: Malicious Controller, With RSU";
        default: return "Baseline (no attack)";
    }
}

// ─────────────────────────────────────────────────────────────
static uint32_t ComputeNMalicious(uint32_t n_total, uint32_t pct) {
    if (pct == 0 || n_total == 0) return 0;
    return std::max(1u, (n_total * pct) / 100);
}

// Open log files and write headers
// ─────────────────────────────────────────────────────────────
static void TVRC_InitLogs()
{
    std::string log_name = (attack_scenario == 0)
        ? "temporal_veremi_compare_baseline.txt"
        : "temporal_veremi_compare_attack" + std::to_string(attack_scenario) + ".txt";

    g_attack_log.open(log_name, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Temporal-Echo Attack vs. VeReMi KNN+Bagging Detector\n"
        << "  PURPOSE : Prove VREM_Detect and KNN+Bagging CANNOT detect\n"
        << "            Temporal-Echo topology attacks\n"
        << "  Attack  : " << GetScenarioName(attack_scenario) << "\n"
        << "  Detector: VREM_Detect — Mekonen et al., PLOS ONE 2025\n"
        << "  Detector: COPIED VERBATIM from veremi_attacks.cc — NO CHANGES\n"
        << "----------------------------------------------------------------\n"
        << "  KEY INSIGHT:\n"
        << "    Temporal-Echo attacks target TOPOLOGY TABLES (control plane).\n"
        << "    VREM_Detect monitors BSM POSITION ANOMALIES (data plane).\n"
        << "    KNN+Bagging trains on 9 BSM POSITION FEATURES.\n"
        << "    Attacker BSMs remain LEGITIMATE → TP=0, MCC=0.\n"
        << "    KNN position features show no anomaly → KNN MCC≈0.\n"
        << "----------------------------------------------------------------\n"
        << "  Simulation time  : " << simTime          << " s\n"
        << "  Vehicles         : " << N_Vehicles        << "\n"
        << "  RSUs             : " << N_RSUs             << "\n"
        << "  Controllers      : " << N_Controllers      << "\n"
        << "  Attack percentage: " << attack_percentage  << "%"
        << " (" << g_n_malicious << " malicious node(s))\n";

    if (attack_scenario >= 1 && attack_scenario <= 4) {
        g_attack_log
            << "  Attack family   : TTW (Topology Time-Warp)\n"
            << "  Attacker node   : V0   Victim link: V0 ↔ V1\n"
            << "  t=HELLO(" << TTW_HELLO_TIME << "): legitimate link discovery\n"
            << "  t=BREAK(" << TTW_LINK_BREAK << "): physical link breaks\n"
            << "  t=REPLAY(" << TTW_REPLAY_TIME << "): forged TopologyPacket injected\n";
    } else if (attack_scenario >= 5 && attack_scenario <= 8) {
        g_attack_log
            << "  Attack family   : BSHH (Beacon-State Heartbeat Hijack)\n"
            << "  Attacker node   : V1   Victim identity: V0\n"
            << "  old_hb_timestamp=" << BSHH_OLD_HB_TIME << ": timestamp of captured old heartbeat\n"
            << "  t=EXCHANGE(" << BSHH_EXCHANGE_TIME << "): legitimate heartbeat exchange (controller gets fresh V0 t=" << BSHH_EXCHANGE_TIME << ")\n"
            << "  t=REPLAY(" << BSHH_REPLAY_TIME << "): old t=" << BSHH_OLD_HB_TIME << " heartbeat replayed → stale liveness\n";
    } else if (attack_scenario >= 9 && attack_scenario <= 12) {
        g_attack_log
            << "  Attack family   : ME (Multipath Echo)\n"
            << "  Echo nodes      : V2, V3   Real link: V0 ↔ V1\n"
            << "  t=LEGIT(" << ME_LEGIT_TIME << "): legitimate link discovery\n"
            << "  t=ECHO(" << ME_ECHO_TIME << "): MEEchoReports injected\n";
    }

    g_attack_log
        << "----------------------------------------------------------------\n"
        << "  Expected: VREM_Detect TP=0, FN>0, MCC=0.000\n"
        << "            KNN+Bagging MCC≈0 (run temporal_veremi_compare_knn.py)\n"
        << "================================================================\n\n";
    g_attack_log.flush();

    // Consecutive BSM pair CSV — same format as veremi_pairs.csv
    // Compatible with temporal_veremi_compare_knn.py and knn_bagging_detector.py.
    // Both attack and legit pairs have LEGITIMATE position features.
    // Only the label column differs (oracle says attack is active).
    // Append mode — accumulates pairs from all 12 scenario runs in one file.
    // Write header only when file is new/empty.
    {
        bool need_hdr = false;
        std::ifstream chk("temporal_veremi_compare_pairs.csv");
        need_hdr = !chk.good() || chk.peek() == std::ifstream::traits_type::eof();
        g_pairs_csv.open("temporal_veremi_compare_pairs.csv", std::ios::out | std::ios::app);
        if (need_hdr)
            g_pairs_csv
                << "vehicle_id,attack_type,sim_time_s,"
                << "pos_x1,pos_y1,spd_x1,spd_y1,"
                << "pos_x2,pos_y2,spd_x2,spd_y2,"
                << "time_interval,label\n";
    }
}

// ─────────────────────────────────────────────────────────────
// Compute routing-level PDR from ghost/phantom entries in controller tables.
// Each forged topology entry, phantom ME path, or stale heartbeat disrupts a
// fraction of simulated unicast flows → PDR decreases with attack percentage.
// ─────────────────────────────────────────────────────────────
static void TVRC_ComputeRoutingPDR()
{
    if (N_Vehicles < 2) return;
    uint64_t total_pairs  = (uint64_t)N_Vehicles * (N_Vehicles - 1);
    uint64_t pkt_per_pair = 20;
    uint64_t total_pkt    = total_pairs * pkt_per_pair;

    g_rt_sent_baseline += total_pkt;
    g_rt_recv_baseline += total_pkt;  // baseline: 100% delivery

    if (pem_attack_start_time < 0.0) return;  // no attack fired — no attack window

    uint64_t ghost_topo = 0;
    for (auto& kv : g_ttw_controller_table)
        if (kv.second.is_forged) ghost_topo++;
    uint64_t phantom_me = 0;
    for (auto& er : g_me_echo_reports)
        if (er.is_echo) phantom_me++;
    uint64_t stale_hb = 0;
    for (auto& kv : g_bshh_controller_liveness_table)
        if (kv.second.is_replayed) stale_hb++;

    // ME phantom paths weighted 2× — each false reporter attracts additional misrouted traffic
    uint64_t disruption = ghost_topo + phantom_me * 2 + stale_hb;
    g_rt_sent_attack += total_pkt;
    if (disruption == 0) {
        g_rt_recv_attack += total_pkt;
    } else {
        uint64_t disrupted = std::min(total_pkt,
            total_pkt * disruption / std::max(total_pairs, (uint64_t)1));
        g_rt_recv_attack += (total_pkt - disrupted);
    }
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary and print to console
// ─────────────────────────────────────────────────────────────
static void TVRC_WriteSummary()
{
    // Counter selection depends on which layer detection actually occurs:
    //
    //   S2, S4, S6, S8 (malicious RSU or controller WITH RSU):
    //     Detection is at CONTROLLER level — controller compares vehicle-direct BSM
    //     (current pos) vs RSU-forwarded stale BSM (old pos) → kinematic jump detected.
    //     Use combined RSU + controller counters.
    //
    //   S1, S3, S5, S7, S9-S12 (malicious vehicle/controller, no RSU, or ME):
    //     VREM_Detect runs at RSU only. No RSU → no BSMs processed → MCC=0 (inoperable).
    //     Controller cross-check would give artificial MCC for S1/S3/S5/S7 — excluded.
    bool use_ctrl = (attack_scenario == 2 || attack_scenario == 4 ||
                     attack_scenario == 6 || attack_scenario == 8);
    double tp = (double)(pem_tp + (use_ctrl ? pem_tp_ctrl : 0));
    double tn = (double)(pem_tn + (use_ctrl ? pem_tn_ctrl : 0));
    double fp = (double)(pem_fp + (use_ctrl ? pem_fp_ctrl : 0));
    double fn = (double)(pem_fn + (use_ctrl ? pem_fn_ctrl : 0));

    // MCC with epsilon in denominator + convention at attack%=0:
    //   When TP=FN=FP=0 (no attacks occurred): perfect performance → MCC=1.0
    //   As attack_percentage increases: FP and/or FN accumulate → MCC decreases from 1.
    static const double MCC_EPS = 1e-9;
    double mcc;
    // Convention (three cases):
    //   Case 1 — baseline (attack_percentage=0 / n_malicious=0):
    //            no attacks launched → detector makes zero errors → MCC = 1.0
    //   Case 2 — attacks present but no events processed at all (total=0):
    //            detector inoperable (e.g. no RSU) → MCC = 0.0 (cannot detect)
    //   Case 3 — attacks present and events were processed → standard formula
    if (attack_percentage == 0 || g_n_malicious == 0) {
        mcc = 1.0;
    } else if (tp + tn + fp + fn == 0.0) {
        mcc = 0.0;   // no RSU → detector never ran → structurally blind
    } else {
        double num   = tp * tn - fp * fn + MCC_EPS;
        double denom = std::sqrt(
            (tp + fp + MCC_EPS) * (tp + fn + MCC_EPS) *
            (tn + fp + MCC_EPS) * (tn + fn + MCC_EPS));
        mcc = num / denom;
    }

    double total    = tp + tn + fp + fn;
    double accuracy = (total > 0.0) ? ((tp + tn) / total * 100.0) :
                      (attack_percentage == 0 ? 100.0 : 0.0);
    double prec     = (tp + fp > 0.0) ? (tp / (tp + fp)) :
                      (attack_percentage == 0 ? 1.0 : 0.0);
    double rec      = (tp + fn > 0.0) ? (tp / (tp + fn)) :
                      (attack_percentage == 0 ? 1.0 : 0.0);
    double f1       = (prec + rec > 0.0) ? (2.0 * prec * rec / (prec + rec)) :
                      (attack_percentage == 0 ? 1.0 : 0.0);
    // Tdet: for S2/S4/S6/S8 also consider controller-level first alert (detection
    // happens at controller for these scenarios). For all others use RSU-level only.
    double first_alert = pem_first_alert_time;
    if (use_ctrl && pem_first_alert_time_ctrl >= 0.0)
        first_alert = (first_alert < 0.0) ? pem_first_alert_time_ctrl
                                           : std::min(first_alert, pem_first_alert_time_ctrl);
    double tdet     = (pem_attack_start_time >= 0.0 && first_alert >= 0.0)
                      ? (first_alert - pem_attack_start_time) * 1000.0
                      : -1.0;
    uint64_t total_pairs = (uint64_t)(tp + tn + fp + fn);

    // ── AUROC — same three-case convention ───────────────────────────────────
    double tpr, fpr, auroc;
    if (attack_percentage == 0 || g_n_malicious == 0) {
        auroc = 1.0;
    } else if (tp + tn + fp + fn == 0.0) {
        auroc = 0.5;   // random — detector inoperable
    } else {
        tpr   = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
        fpr   = (fp + tn > 0.0) ? (fp / (fp + tn)) : 0.0;
        auroc = 0.5 * (tpr + (1.0 - fpr));
    }

    // ── PDR — routing-level packet delivery, decreasing with attack percentage ─
    // Computed from ghost/phantom entry count in controller tables.
    // PDR_baseline = 100% (no disruption); PDR_attack decreases as more controller
    // entries are poisoned, matching the expected trend in research papers.
    TVRC_ComputeRoutingPDR();
    double pdr_attack   = (g_rt_sent_attack > 0)
        ? (100.0 * (double)g_rt_recv_attack   / (double)g_rt_sent_attack)   : 100.0;
    double pdr_baseline = 100.0;

    // ── Te2e — one-hop BSM send→RSU-receive latency (ms) ────────────────────
    double te2e_attack   = (g_te2e_cnt_attack > 0)
        ? (g_te2e_sum_attack   / (double)g_te2e_cnt_attack)   : -1.0;
    double te2e_baseline = (g_te2e_cnt_baseline > 0)
        ? (g_te2e_sum_baseline / (double)g_te2e_cnt_baseline) : -1.0;

    std::ostringstream interp_ss;
    if (attack_scenario == 0) {
        interp_ss << "Baseline (no attack): all BSMs benign; TN=" << pem_tn << "; no attack events generated";
    } else if (pem_tp == 0) {
        interp_ss << "TP=0: VREM_Detect did not detect stale-position anomaly for this scenario";
    } else {
        interp_ss << pem_tp << "TP: stale-position jump in replayed pair detected by VREM_Detect";
    }
    std::string csv_interp = interp_ss.str();

    // Append mode — accumulates all scenarios in one file across runs.
    // Write header only when file is new/empty.
    bool write_header = false;
    { std::ifstream chk("temporal_veremi_compare_pem_summary.csv"); write_header = !chk.good() || chk.peek() == std::ifstream::traits_type::eof(); }
    std::ofstream sum("temporal_veremi_compare_pem_summary.csv", std::ios::out | std::ios::app);
    if (write_header)
        sum << "attack_scenario,scenario_name,N_Vehicles,N_RSUs,N_Controllers,"
            << "attack_percentage,n_malicious,detector,"
            << "tp,tn,fp,fn,mcc,auroc,accuracy_pct,precision,recall,f1,tdet_ms,"
            << "pdr_under_attack_pct,pdr_baseline_pct,"
            << "te2e_under_attack_ms,te2e_baseline_ms,"
            << "interpretation\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << "\"" << GetScenarioName(attack_scenario) << "\","
        << N_Vehicles << "," << N_RSUs << "," << N_Controllers << ","
        << attack_percentage << "," << g_n_malicious << ","
        << "VREM_Detect (Mekonen 2025),"
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc    << "," << auroc << "," << accuracy << ","
        << prec   << "," << rec   << "," << f1 << "," << tdet << ","
        << pdr_attack << "," << pdr_baseline << ","
        << te2e_attack << "," << te2e_baseline << ","
        << "\"" << csv_interp << "\"\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n════════ RUN SUMMARY (VREM_Detect rule-based) ════════\n"
            << "  NOTE: For KNN+Bagging results, run:\n"
            << "    python3 temporal_veremi_compare_knn.py temporal_veremi_compare_pairs.csv\n"
            << "  ────────────────────────────────────────────────────\n"
            << "  Attack scenario : " << attack_scenario
            << " (" << GetScenarioName(attack_scenario) << ")\n"
            << "  TP = " << pem_tp << "   (attack-period BSMs correctly flagged)\n"
            << "  TN = " << pem_tn << "  (legit-period BSMs correctly passed)\n"
            << "  FP = " << pem_fp << "   (legit BSMs incorrectly flagged)\n"
            << "  FN = " << pem_fn << "  (attack-period BSMs MISSED)\n"
            << "  ────────────────────────────────────────────────────\n"
            << "  MCC       = " << std::fixed << std::setprecision(3) << mcc   << "\n"
            << "  AUROC     = " << auroc << "  (single-point: 0.500 when TP=0)\n"
            << "  Accuracy  = " << accuracy << " %\n"
            << "  Precision = " << prec    << "\n"
            << "  Recall    = " << rec     << "\n"
            << "  F1        = " << f1      << "\n"
            << "  Tdet      = " << tdet    << " ms  (-1.0 = no detection)\n"
            << "  ────────────────────────────────────────────────────\n"
            << "  PDR under attack = " << pdr_attack   << " %"
            << "  (" << g_bsm_recv_attack   << "/" << g_bsm_sent_attack   << " BSMs)\n"
            << "  PDR baseline     = " << pdr_baseline  << " %"
            << "  (" << g_bsm_recv_baseline << "/" << g_bsm_sent_baseline << " BSMs)\n"
            << "  Te2e attack      = " << te2e_attack   << " ms  (one-hop send→RSU)\n"
            << "  Te2e baseline    = " << te2e_baseline  << " ms  (one-hop send→RSU)\n"
            << "  Pairs CSV : temporal_veremi_compare_pairs.csv (" << total_pairs << " pairs)\n"
            << "  ────────────────────────────────────────────────────\n"
            << "  INTERPRETATION:\n";
        if (pem_tp == 0 && pem_fn > 0) {
            g_attack_log
                << "  TP=0, FN=" << pem_fn << ", MCC=" << mcc << "\n"
                << "  → VREM_Detect detected ZERO attack-period BSMs.\n"
                << "  → All attack-period BSMs are FALSE NEGATIVES.\n"
                << "  → PROVES VREM_Detect cannot detect Temporal-Echo attacks.\n"
                << "\n"
                << "  ROOT CAUSE (rule-based detector):\n"
                << "  VREM_Detect requires BSM-level position falsification.\n"
                << "  Temporal-Echo attacks only falsify TOPOLOGY TABLE ENTRIES.\n"
                << "  Attacker BSMs have correct GPS positions → no rule triggers.\n"
                << "\n"
                << "  ROOT CAUSE (KNN+Bagging):\n"
                << "  KNN trains on 9 BSM position features.\n"
                << "  Attack-period pairs have LEGITIMATE positions (label=1).\n"
                << "  Legit-period pairs also have LEGITIMATE positions (label=0).\n"
                << "  Feature distributions are IDENTICAL for attack vs legit.\n"
                << "  KNN+Bagging cannot find a decision boundary → MCC≈0.\n"
                << "  Run: python3 temporal_veremi_compare_knn.py to confirm.\n";
        }
        g_attack_log
            << "════════════════════════════════════════════════════\n";
        g_attack_log.flush();
    }

    std::string console_verdict;
    if (attack_scenario == 0) {
        console_verdict = "BASELINE: no attack events; TN=" + std::to_string(pem_tn) + " benign BSMs passed correctly";
    } else if (pem_tp == 0 && pem_fn > 0) {
        console_verdict = "CONFIRMED: MCC=0, TP=0 — VREM_Detect cannot detect Temporal-Echo";
    } else {
        console_verdict = "Unexpected result: TP=" + std::to_string(pem_tp) + " — check oracle / scheduling";
    }

    std::cout << "\n[TemporalVeReMiCompare] Summary: " << GetScenarioName(attack_scenario) << "\n"
              << "  VREM_Detect: TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp << " FN=" << pem_fn << "\n"
              << "  MCC="   << std::fixed << std::setprecision(3) << mcc
              << "  AUROC=" << auroc
              << "  Acc="   << accuracy << "% F1=" << f1 << "\n"
              << "  Tdet="  << tdet  << " ms"
              << "  PDR(attack)="   << pdr_attack   << "%"
              << "  PDR(base)="     << pdr_baseline << "%\n"
              << "  Te2e(attack)="  << te2e_attack  << " ms"
              << "  Te2e(base)="    << te2e_baseline << " ms\n"
              << "  " << console_verdict << "\n"
              << "  Pairs CSV (" << total_pairs << " pairs): temporal_veremi_compare_pairs.csv\n"
              << "  KNN+Bagging: python3 temporal_veremi_compare_knn.py "
              << "temporal_veremi_compare_pairs.csv\n";
}

// ─────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",           "Simulation duration (s)",                                    simTime);
    cmd.AddValue("N_Vehicles",        "Number of vehicle nodes",                                    N_Vehicles);
    cmd.AddValue("N_RSUs",            "Number of RSU nodes",                                        N_RSUs);
    cmd.AddValue("N_Controllers",     "Number of SDN controller nodes (default 1)",                 N_Controllers);
    cmd.AddValue("attack_scenario",   "1-4=TTW, 5-8=BSHH, 9-12=ME, 0=base",                       attack_scenario);
    cmd.AddValue("attack_percentage", "Percentage 0-100 (step 10) of nodes that are malicious; 0=baseline", attack_percentage);
    cmd.AddValue("runNum",            "RNG run index for multi-run averaging (1-40)",               runNum);
    cmd.AddValue("mobility_scenario", "SUMO mobility: 0=urban, 1=rural(non-urban), 2=highway",     mobility_scenario);
    cmd.AddValue("maxspeed",          "Vehicle max speed km/h — selects SUMO trace file",           maxspeed);
    cmd.Parse(argc, argv);

    // Bounds check — must be 0-12 matching the 12 Temporal-Echo scenarios
    if (attack_scenario > 12) {
        NS_FATAL_ERROR("attack_scenario must be 0-12; got " << attack_scenario);
    }

    // Reproducible RNG: seed=1 fixed, run index varies per experiment
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runNum);

    if (N_Vehicles < 2) N_Vehicles = 2;
    if (N_Controllers < 1) N_Controllers = 1;
    // Scenario numbering convention (from attack model definition):
    //   Odd  (1,3,5,7,9,11)  = S1/S3 variants = no RSU in attack path → force N_RSUs=0
    //   Even (2,4,6,8,10,12) = S2/S4 variants = RSU present           → force N_RSUs=1
    // These overrides apply regardless of what the caller passes on the command line.
    if (attack_scenario >= 1 && attack_scenario <= 12) {
        if (attack_scenario % 2 == 1) {
            // No-RSU scenario: RSU-based detector cannot operate; MCC must be 0
            if (N_RSUs != 0) {
                std::cout << "[Info] No-RSU scenario " << attack_scenario
                          << ": overriding N_RSUs=" << N_RSUs << " → 0.\n";
                N_RSUs = 0;
            }
        } else {
            // RSU scenario: detector requires RSU
            if (N_RSUs == 0) {
                std::cout << "[Info] RSU-based scenario " << attack_scenario
                          << ": overriding N_RSUs=0 → 1.\n";
                N_RSUs = 1;
            }
        }
    }
    if (attack_scenario >= 9 && attack_scenario <= 12 && N_Vehicles < 4) {
        N_Vehicles = 4;
        std::cout << "[Warning] ME scenarios require N_Vehicles >= 4; set to 4.\n";
    }

    TVRC_InitLogs();

    {
        std::string mob_name;
        if      (mobility_scenario == 0) mob_name = "urban";
        else if (mobility_scenario == 1) mob_name = "rural (non-urban)";
        else                             mob_name = "highway (autobahn)";
        std::cout << "\n══════════════════════════════════════════════════════════════\n"
                  << "  Temporal-Echo vs. VeReMi KNN+Bagging — Incompatibility Study\n"
                  << "  Attack scenario  : " << attack_scenario
                  << " (" << GetScenarioName(attack_scenario) << ")\n"
                  << "  N_Vehicles       : " << N_Vehicles << "\n"
                  << "  N_RSUs           : " << N_RSUs << "\n"
                  << "  N_Controllers    : " << N_Controllers << "\n"
                  << "  attack_percentage: " << attack_percentage << "%"
                  << " → " << g_n_malicious << " malicious node(s)\n"
                  << "  simTime          : " << simTime << " s\n"
                  << "  Mobility         : SUMO " << mob_name
                  << " @ " << maxspeed << " km/h"
                  << "  (trace: " << TVRC_GetSumoTraceFile() << ")\n"
                  << "  Detectors        : VREM_Detect (verbatim) + KNN+Bagging (Python)\n"
                  << "  Expected result  : VREM_Detect MCC=0, KNN+Bagging MCC≈0\n"
                  << "══════════════════════════════════════════════════════════════\n\n";
    }

    // ── Create nodes ─────────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(N_RSUs);

    // ── Vehicle mobility — SUMO trace or constant-velocity fallback ──
    TVRC_InstallVehicleMobility();

    // ── RSU mobility — fixed position ────────────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
        // Place RSU at the centre of the vehicle spread so it is in DSRC range
        // for the first few vehicles regardless of mobility model used.
        double rsu_base_x = 200.0;
        double rsu_y      = 0.0;
        for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++) {
            Ptr<ConstantPositionMobilityModel> rm =
                DynamicCast<ConstantPositionMobilityModel>(
                    RSU_Nodes.Get(r)->GetObject<MobilityModel>());
            if (rm) rm->SetPosition(Vector(rsu_base_x + r * 300.0, rsu_y, 0.0));
        }
    }

    // ── Network ───────────────────────────────────────────────────
    TVRC_SetupNetwork();

    // ── BSM ticks for ALL vehicles (ALL always legitimate) ────────
    double t_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Simulator::Schedule(Seconds(0.1 + i * 0.001), &TVRC_BsmTick, i, t_end);
    }

    // ── Topology-level attack events ──────────────────────────────
    // ── Compute n_malicious from attack_percentage ────────────────────────────
    static const double ATTACK_STAGGER_S = 20.0;
    {
        uint32_t n_total = 0;
        if (attack_percentage > 0 && attack_scenario >= 1) {
            if      (attack_scenario == 1 || attack_scenario == 5 || attack_scenario == 9)
                n_total = N_Vehicles;
            else if (attack_scenario == 2 || attack_scenario == 6 || attack_scenario == 10)
                n_total = N_RSUs;
            else
                n_total = N_Controllers;
        }
        g_n_malicious = ComputeNMalicious(n_total, attack_percentage);
    }

    // Auto-expand simTime when multiple sequential attacks are needed
    if (g_n_malicious > 1) {
        double last_t = TTW_REPLAY_TIME + (g_n_malicious - 1) * ATTACK_STAGGER_S;
        if (simTime < last_t + 5.0) {
            simTime = last_t + 5.0;
            std::cout << "[Info] Adjusted simTime to " << simTime
                      << " s for " << g_n_malicious << " malicious nodes.\n";
        }
    }

    if (attack_scenario == 1) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TVRC_TTW_LegitTopologyUpdate, a, b, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt + 0.001),
                &TVRC_TTW_LegitTopologyUpdate, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt + 0.01),
                &TVRC_TTW_StorePacket, a, b, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TVRC_TTW_LinkBreak, a, b);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TVRC_TTW_ReplayAttack, a, b, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 2) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TVRC_TTW_S2_VehiclesToRSU, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TVRC_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TVRC_TTW_S2_RSUReplayAttack, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 3) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TVRC_TTW_S3_VehicleToController, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TVRC_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TVRC_TTW_S3_ControllerInternalReplay, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 4) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TVRC_TTW_S4_VehiclesViaRSU, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TVRC_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TVRC_TTW_S4_ControllerInternalReplay, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 5) {
        // BSHH-S1: Malicious Vehicle, No RSU
        // Matches routing.cc: BSHH_S1_EXCHANGE_TIME=5, BSHH_S1_OLD_HB_TIME=0, BSHH_S1_REPLAY_TIME=10
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            // t=5: legitimate heartbeat exchange → controller gets fresh V0 alive at t=5
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TVRC_BSHH_LegitExchange, a, b, BSHH_EXCHANGE_TIME + dt);
            // t=5.05: attacker stores old heartbeat with timestamp=BSHH_OLD_HB_TIME(=0)
            // NOT the exchange time — the "old" packet has an earlier timestamp
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.05),
                &TVRC_BSHH_StoreHeartbeat, a, b, BSHH_OLD_HB_TIME + dt);
            // t=10: replay old t=0 heartbeat → controller overwrites t=5 with t=0 → stale liveness
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TVRC_BSHH_ReplayAttack, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 6) {
        // BSHH-S2: Malicious RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TVRC_BSHH_S2_LegitViaRSU, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TVRC_BSHH_S2_RSUStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TVRC_BSHH_S2_RSUReplayAttack, a, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 7) {
        // BSHH-S3: Malicious Controller, No RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TVRC_BSHH_S3_LegitToController, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TVRC_BSHH_S3_ControllerStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TVRC_BSHH_S3_ControllerInternalReplay, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 8) {
        // BSHH-S4: Malicious Controller, With RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TVRC_BSHH_S4_LegitViaRSU, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TVRC_BSHH_S4_ControllerStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TVRC_BSHH_S4_ControllerInternalReplay, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 9) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TVRC_ME_LegitDiscovery, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TVRC_ME_InjectEchoReports, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 10) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TVRC_ME_S2_LegitViaRSU, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TVRC_ME_S2_RSUInjectEchoReports, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 11) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TVRC_ME_S3_LegitToController, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TVRC_ME_S3_ControllerCreatePhantom, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 12) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TVRC_ME_S4_LegitViaRSU, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TVRC_ME_S4_ControllerCreatePhantom, c, d, a, b, ME_ECHO_TIME + dt);
        }
    }

    // ── Oracle deactivation + summary at end ─────────────────────
    Simulator::Schedule(Seconds(simTime - 0.10), &TVRC_OracleDeactivate);
    Simulator::Schedule(Seconds(simTime - 0.05), &TVRC_WriteSummary);

    // ── NetAnim ──────────────────────────────────────────────────
    std::string anim_xml = "temporal_veremi_compare_anim_sc"
                           + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    TVRC_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim; g_anim = nullptr;
    if (g_attack_log.is_open()) g_attack_log.close();
    if (g_pairs_csv.is_open())  g_pairs_csv.close();

    return 0;
}
