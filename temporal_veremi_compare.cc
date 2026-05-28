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

// ── BSM constants — Algorithm 1: Mekonen et al., PLOS ONE 2025 ─
static const double BSM_INTERVAL_S   = 0.100;
static const double DSRC_RANGE_M     = 250.0;
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

static const double BSHH_STORE_TIME  = 4.0;
static const double BSHH_REPLAY_TIME = 10.0;

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
};

struct HeartbeatPacket {
    uint32_t claimed_sender_id;
    uint32_t physical_sender_id;
    double   timestamp;
    bool     is_replayed;
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

// Previous BSM per vehicle (for consecutive pair generation and VREM_Detect)
static std::map<uint32_t, BsmRecord> g_prev_bsm;

// Sliding BSM history per vehicle — Algorithm 1 step 3: Type-16 eventual-stop detection
static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;

// ── PEM metric counters ──────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;

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
static bool VREM_Detect(const BsmRecord& bsm)
{
    auto& hist = g_bsm_history[bsm.vehicle_id];

    auto it = g_prev_bsm.find(bsm.vehicle_id);
    if (it == g_prev_bsm.end()) {
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
    //   — constant offset from true position shifts reported position away from predicted
    // Attack Type 4 (Random Position): Pnew = Prandom
    //   — random position produces large unpredictable path deviation
    // Attack Type 8 (Random Offset): Pnew = Pactual + Orandom
    //   — random offset also produces path deviation > speed * dt * SAFETY_FACTOR
    // All three: |actual_pos - predicted_pos| > SAFETY_FACTOR * speed * dt
    // Use max of current and previous speed to handle hard-acceleration edge case.
    double max_path_dev = std::max(speed, prev_speed) * dt * SAFETY_FACTOR;
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

// Forward declaration
static void TVRC_RSUReceive(BsmRecord bsm);

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

        // Oracle: is the topology attack active for this vehicle?
        // BSM content is LEGITIMATE regardless of oracle state.
        bsm.is_attack = (g_oracle_attack_state.count(bsm.vehicle_id) &&
                         g_oracle_attack_state[bsm.vehicle_id]);

        TVRC_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler
//
// Runs VREM_Detect on the legitimate BSM.
// Writes the consecutive BSM pair to the pairs CSV (same format
// as veremi_pairs.csv, compatible with temporal_veremi_compare_knn.py).
//
// KEY BEHAVIOUR:
//   All BSMs are legitimate (correct positions, correct timestamps).
//   The oracle flag (bsm.is_attack) indicates the TOPOLOGY attack is
//   active — NOT that the BSM position is falsified.
//
//   VREM_Detect always returns false for legitimate BSMs during the
//   topology attack period → these are FN events.
//
//   Consecutive BSM pairs during attack period contain NORMAL position
//   features → KNN+Bagging cannot distinguish them from legit pairs.
// ─────────────────────────────────────────────────────────────
static void TVRC_RSUReceive(BsmRecord bsm)
{
    double now      = Simulator::Now().GetSeconds();
    bool   is_attack = bsm.is_attack;

    // PDR and Te2e counters — track every received BSM before detection
    {
        double latency_ms = (now - bsm.timestamp) * 1000.0;
        if (is_attack) {
            g_bsm_recv_attack++;
            g_te2e_sum_attack += latency_ms;
            g_te2e_cnt_attack++;
        } else {
            g_bsm_recv_baseline++;
            g_te2e_sum_baseline += latency_ms;
            g_te2e_cnt_baseline++;
        }
    }

    // VREM_Detect processes the legitimate BSM
    bool detected = VREM_Detect(bsm);

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
                    << (is_attack ? 1 : 0) << "\n";  // label = oracle (not BSM anomaly)
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
// RSU range check
// ─────────────────────────────────────────────────────────────
static bool InRSURange(double px, double py)
{
    if (RSU_Nodes.GetN() == 0) return false;
    Ptr<MobilityModel> mob = RSU_Nodes.Get(0)->GetObject<MobilityModel>();
    if (!mob) return false;
    Vector rp = mob->GetPosition();
    return Dist2D(px, py, rp.x, rp.y) <= DSRC_RANGE_M;
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

    if (!InRSURange(px, py)) return;

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

    TopologyPacket forged = { v0_id, v1_id, forged_time, true };
    std::ostringstream key; key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = forged;

    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = forged_time;

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

    HeartbeatPacket replayed = { v0_id, v1_id, g_bshh_stored_heartbeat.timestamp, true };
    g_bshh_controller_liveness_table[v0_id] = replayed;

    // Step 5: victim (V0) forwards attacker's own old heartbeat to controller → attacker liveness poisoned
    HeartbeatPacket forwarded_by_victim;
    forwarded_by_victim.claimed_sender_id  = v1_id;
    forwarded_by_victim.physical_sender_id = v0_id;
    forwarded_by_victim.timestamp          = g_bshh_stored_heartbeat.timestamp;
    forwarded_by_victim.is_replayed        = true;
    g_bshh_controller_liveness_table[v1_id] = forwarded_by_victim;

    // Activate oracle: V1 is the attacker; V0 is deceived into forwarding stale HB
    g_oracle_attack_state[v1_id] = true;
    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = replay_time;

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
                     << "]  *** BSHH-S1 HEARTBEAT REPLAY ATTACK BEGINS (three-step chain) ***\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  Attacker     : V" << v1_id << " (malicious vehicle)\n"
                     << "  Victim       : V" << v0_id << " (identity stolen)\n"
                     << "  Stored HB    : { claimed=V" << v0_id << ", t=" << replayed.timestamp
                     << " } ← captured at BSHH_STORE_TIME\n"
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

    if (Vehicle_Nodes.GetN() > v0_id) {
        double sx, sy;
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, sx, sy);
    }
    if (Vehicle_Nodes.GetN() > v1_id) {
        double sx, sy;
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, sx, sy);
    }
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
    pem_attack_start_time = t;

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
    TopologyPacket forged = { v1_id, v0_id, forged_time, true };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    g_oracle_attack_state[v1_id] = true;
    pem_attack_start_time = forged_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S2 REPLAY ATTACK (ATTACKER: RSU) ***\n"
            << "  RSU injects: { V" << v1_id << " sees V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  Ghost link V" << v1_id << "↔V" << v0_id << " maintained in controller\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. KNN features: normal positions, label=1\n"
            << "  ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → FALSE NEGATIVES\n\n";
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
    pem_attack_start_time = forged_time;
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
    pem_attack_start_time = forged_time;
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
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S2] RSU STORES V" << v0_id << " heartbeat { t=" << stored_time << " }\n";
        g_attack_log.flush();
    }
}
static void TVRC_BSHH_S2_RSUReplayAttack(uint32_t v0_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    HeartbeatPacket replayed = { v0_id, 0xFFFFFFFF, g_bshh_stored_heartbeat.timestamp, true };
    g_bshh_controller_liveness_table[v0_id] = replayed;
    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = replay_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S2 REPLAY ATTACK (ATTACKER: RSU) ***\n"
            << "  RSU → controller:"
            << " { claimed=V" << v0_id << ", physical=RSU, t=" << replayed.timestamp << ", replayed=TRUE }\n"
            << "  Controller V" << v0_id << " liveness overwritten with stale t=" << replayed.timestamp << "\n"
            << "  BSM LAYER: V" << v0_id << " broadcasts LEGITIMATE BSMs\n"
            << "  VREM_Detect → FALSE. KNN: normal pos features, label=1\n"
            << "  ORACLE: V" << v0_id << " BSMs labeled attack=TRUE → FALSE NEGATIVES\n\n";
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
    pem_attack_start_time = replay_time;
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
    pem_attack_start_time = replay_time;
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
    if (Vehicle_Nodes.GetN() > v0_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, sx, sy); }
    if (Vehicle_Nodes.GetN() > v1_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, sx, sy); }
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
    pem_attack_start_time = t;
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
    if (Vehicle_Nodes.GetN() > v0_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, sx, sy); }
    if (Vehicle_Nodes.GetN() > v1_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, sx, sy); }
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
    pem_attack_start_time = t;
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
    if (Vehicle_Nodes.GetN() > v0_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, sx, sy); }
    if (Vehicle_Nodes.GetN() > v1_id) { double sx,sy; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, sx, sy); }
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
    pem_attack_start_time = t;
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
// Network setup — P2P star topology
// Subnet 10.6.(i+1).0/30 — distinct from all other files
// ─────────────────────────────────────────────────────────────
static void TVRC_SetupNetwork()
{
    if (RSU_Nodes.GetN() == 0) return;

    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);
    internet.Install(RSU_Nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",   StringValue("1ms"));

    Ipv4AddressHelper addr;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i));
        pair.Add(RSU_Nodes.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);

        std::ostringstream base;
        base << "10.6." << (i + 1) << ".0";
        addr.SetBase(base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifc = addr.Assign(devs);

        if (i == 0) g_rsu_ip = ifc.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_rsu_recv_socket = Socket::CreateSocket(
        RSU_Nodes.Get(0),
        TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&TVRC_RSUSocketReceive));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    sinkHelper.Install(RSU_Nodes.Get(0)).Start(Seconds(0.0));
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
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
        << "  Simulation time : " << simTime   << " s\n"
        << "  Vehicles        : " << N_Vehicles << "\n"
        << "  RSUs            : " << N_RSUs     << "\n";

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
            << "  t=STORE(" << BSHH_STORE_TIME << "): V1 captures V0's old heartbeat\n"
            << "  t=REPLAY(" << BSHH_REPLAY_TIME << "): forged HeartbeatPacket injected\n";
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
    g_pairs_csv.open("temporal_veremi_compare_pairs.csv", std::ios::out | std::ios::trunc);
    g_pairs_csv
        << "vehicle_id,attack_type,sim_time_s,"
        << "pos_x1,pos_y1,spd_x1,spd_y1,"
        << "pos_x2,pos_y2,spd_x2,spd_y2,"
        << "time_interval,label\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary and print to console
// ─────────────────────────────────────────────────────────────
static void TVRC_WriteSummary()
{
    double tp = (double)pem_tp, tn = (double)pem_tn;
    double fp = (double)pem_fp, fn = (double)pem_fn;

    double denom    = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc      = (denom > 0.0) ? ((tp * tn - fp * fn) / denom) : 0.0;
    double total    = tp + tn + fp + fn;
    double accuracy = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;
    double prec     = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double rec      = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double f1       = (prec + rec > 0.0) ? (2.0 * prec * rec / (prec + rec)) : 0.0;
    double tdet     = (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0)
                      ? (pem_first_alert_time - pem_attack_start_time) * 1000.0
                      : -1.0;
    uint64_t total_pairs = pem_tp + pem_tn + pem_fp + pem_fn;

    // ── AUROC — single-point formula for rule-based binary detector ──────────
    // AUROC = 0.5*(TPR + TNR).  When TP=0, FP=0: AUROC = 0.5*(0+1) = 0.500.
    // Matches routing.cc pem_run_summary.csv column layout.
    double tpr   = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double fpr   = (fp + tn > 0.0) ? (fp / (fp + tn)) : 0.0;
    double auroc = 0.5 * (tpr + (1.0 - fpr));

    // ── PDR — packet delivery ratio, split by oracle window ─────────────────
    // PDR ≈ 100% for both periods: topology attacks do NOT disrupt BSM delivery.
    double pdr_attack   = (g_bsm_sent_attack > 0)
        ? (100.0 * (double)g_bsm_recv_attack   / (double)g_bsm_sent_attack)   : -1.0;
    double pdr_baseline = (g_bsm_sent_baseline > 0)
        ? (100.0 * (double)g_bsm_recv_baseline / (double)g_bsm_sent_baseline) : -1.0;

    // ── Te2e — one-hop BSM send→RSU-receive latency (ms) ────────────────────
    double te2e_attack   = (g_te2e_cnt_attack > 0)
        ? (g_te2e_sum_attack   / (double)g_te2e_cnt_attack)   : -1.0;
    double te2e_baseline = (g_te2e_cnt_baseline > 0)
        ? (g_te2e_sum_baseline / (double)g_te2e_cnt_baseline) : -1.0;

    std::string csv_interp = (attack_scenario == 0)
        ? "Baseline (no attack): all BSMs benign; TN=" + std::to_string(pem_tn) + "; no attack events generated"
        : "TP=0: VREM_Detect cannot detect topology-level Temporal-Echo attacks";

    std::ofstream sum("temporal_veremi_compare_pem_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,scenario_name,detector,"
        << "tp,tn,fp,fn,mcc,auroc,accuracy_pct,precision,recall,f1,tdet_ms,"
        << "pdr_under_attack_pct,pdr_baseline_pct,"
        << "te2e_under_attack_ms,te2e_baseline_ms,"
        << "interpretation\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << "\"" << GetScenarioName(attack_scenario) << "\","
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
    cmd.AddValue("simTime",         "Simulation duration (s)",              simTime);
    cmd.AddValue("N_Vehicles",      "Number of vehicle nodes",              N_Vehicles);
    cmd.AddValue("N_RSUs",          "Number of RSU nodes (0 or 1)",         N_RSUs);
    cmd.AddValue("attack_scenario", "1-4=TTW, 5-8=BSHH, 9-12=ME, 0=base", attack_scenario);
    cmd.AddValue("runNum",          "RNG run index for multi-run averaging (1-40)", runNum);
    cmd.Parse(argc, argv);

    // Bounds check — must be 0-12 matching the 12 Temporal-Echo scenarios
    if (attack_scenario > 12) {
        NS_FATAL_ERROR("attack_scenario must be 0-12; got " << attack_scenario);
    }

    // Reproducible RNG: seed=1 fixed, run index varies per experiment
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runNum);

    if (N_Vehicles < 2) N_Vehicles = 2;
    if (N_RSUs > 1)     N_RSUs     = 1;
    if (attack_scenario >= 9 && attack_scenario <= 12 && N_Vehicles < 4) {
        N_Vehicles = 4;
        std::cout << "[Warning] ME scenarios require N_Vehicles >= 4; set to 4.\n";
    }
    // RSU-based scenarios require at least one RSU
    if ((attack_scenario == 2 || attack_scenario == 4 ||
         attack_scenario == 6 || attack_scenario == 8 ||
         attack_scenario == 10 || attack_scenario == 12) && N_RSUs == 0) {
        N_RSUs = 1;
        std::cout << "[Info] RSU-based scenario requires N_RSUs>=1; set to 1.\n";
    }

    TVRC_InitLogs();

    std::cout << "\n══════════════════════════════════════════════════════════════\n"
              << "  Temporal-Echo vs. VeReMi KNN+Bagging — Incompatibility Study\n"
              << "  Attack scenario : " << attack_scenario
              << " (" << GetScenarioName(attack_scenario) << ")\n"
              << "  N_Vehicles      : " << N_Vehicles << "\n"
              << "  N_RSUs          : " << N_RSUs << "\n"
              << "  simTime         : " << simTime << " s\n"
              << "  Detectors       : VREM_Detect (verbatim) + KNN+Bagging (Python)\n"
              << "  Expected result : VREM_Detect MCC=0, KNN+Bagging MCC≈0\n"
              << "══════════════════════════════════════════════════════════════\n\n";

    // ── Create nodes ─────────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(1);

    // ── Vehicle mobility ─────────────────────────────────────────
    MobilityHelper mobV;
    mobV.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobV.Install(Vehicle_Nodes);
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Ptr<ConstantVelocityMobilityModel> m =
            DynamicCast<ConstantVelocityMobilityModel>(
                Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
        if (!m) continue;
        double spd = (N_Vehicles > 1)
            ? MIN_SPEED_MS + (MAX_SPEED_MS - MIN_SPEED_MS) *
              (double(i) / (N_Vehicles - 1))
            : MIN_SPEED_MS;
        m->SetPosition(Vector(50.0 + i * 60.0, double(i) * 10.0, 0.0));
        m->SetVelocity(Vector(spd, 0.0, 0.0));
    }

    // ── RSU mobility ─────────────────────────────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
        Ptr<ConstantPositionMobilityModel> rm =
            DynamicCast<ConstantPositionMobilityModel>(
                RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (rm)
            rm->SetPosition(Vector(50.0 + (N_Vehicles / 2.0) * 60.0,
                                   (N_Vehicles > 1) ? (N_Vehicles - 1) * 5.0 : 0.0,
                                   0.0));
    }

    // ── Network ───────────────────────────────────────────────────
    TVRC_SetupNetwork();

    // ── BSM ticks for ALL vehicles (ALL always legitimate) ────────
    double t_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Simulator::Schedule(Seconds(0.1 + i * 0.001), &TVRC_BsmTick, i, t_end);
    }

    // ── Topology-level attack events ──────────────────────────────
    uint32_t v0_id = (Vehicle_Nodes.GetN() > 0) ? Vehicle_Nodes.Get(0)->GetId() : 0;
    uint32_t v1_id = (Vehicle_Nodes.GetN() > 1) ? Vehicle_Nodes.Get(1)->GetId() : 1;
    uint32_t v2_id = (Vehicle_Nodes.GetN() > 2) ? Vehicle_Nodes.Get(2)->GetId() : 2;
    uint32_t v3_id = (Vehicle_Nodes.GetN() > 3) ? Vehicle_Nodes.Get(3)->GetId() : 3;

    if (attack_scenario == 1) {
        // TTW-S1: Malicious Vehicle V0
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TVRC_TTW_LegitTopologyUpdate, v0_id, v1_id, TTW_HELLO_TIME);
        // Bidirectional HELLO: V1 also reports seeing V0 (paper §4.2)
        Simulator::Schedule(Seconds(TTW_HELLO_TIME + 0.001),
            &TVRC_TTW_LegitTopologyUpdate, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_HELLO_TIME + 0.01),
            &TVRC_TTW_StorePacket, v0_id, v1_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TVRC_TTW_LinkBreak, v0_id, v1_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TVRC_TTW_ReplayAttack, v0_id, v1_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 2) {
        // TTW-S2: Malicious RSU
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TVRC_TTW_S2_VehiclesToRSU, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TVRC_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TVRC_TTW_S2_RSUReplayAttack, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 3) {
        // TTW-S3: Malicious Controller, No RSU
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TVRC_TTW_S3_VehicleToController, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TVRC_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TVRC_TTW_S3_ControllerInternalReplay, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 4) {
        // TTW-S4: Malicious Controller, With RSU
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TVRC_TTW_S4_VehiclesViaRSU, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TVRC_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TVRC_TTW_S4_ControllerInternalReplay, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 5) {
        // BSHH-S1: Malicious Vehicle V1
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TVRC_BSHH_StoreHeartbeat, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.5),
            &TVRC_BSHH_LegitExchange, v0_id, v1_id, BSHH_STORE_TIME + 0.5);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TVRC_BSHH_ReplayAttack, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 6) {
        // BSHH-S2: Malicious RSU
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TVRC_BSHH_S2_LegitViaRSU, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TVRC_BSHH_S2_RSUStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TVRC_BSHH_S2_RSUReplayAttack, v0_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 7) {
        // BSHH-S3: Malicious Controller, No RSU — reinstates both V0 and V1 liveness
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TVRC_BSHH_S3_LegitToController, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TVRC_BSHH_S3_ControllerStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TVRC_BSHH_S3_ControllerInternalReplay, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 8) {
        // BSHH-S4: Malicious Controller, With RSU — reinstates both V0 and V1 liveness
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TVRC_BSHH_S4_LegitViaRSU, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TVRC_BSHH_S4_ControllerStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TVRC_BSHH_S4_ControllerInternalReplay, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 9) {
        // ME-S1: Malicious Vehicles V2, V3
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TVRC_ME_LegitDiscovery, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TVRC_ME_InjectEchoReports, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 10) {
        // ME-S2: Malicious RSU
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TVRC_ME_S2_LegitViaRSU, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TVRC_ME_S2_RSUInjectEchoReports, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 11) {
        // ME-S3: Malicious Controller, No RSU
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TVRC_ME_S3_LegitToController, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TVRC_ME_S3_ControllerCreatePhantom, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 12) {
        // ME-S4: Malicious Controller, With RSU
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TVRC_ME_S4_LegitViaRSU, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TVRC_ME_S4_ControllerCreatePhantom, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);
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
