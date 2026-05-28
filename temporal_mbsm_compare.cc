// ============================================================
// temporal_mbsm_compare.cc
// Temporal-Echo Attack vs. Multi-BSM Detector — Incompatibility Study
//
// PURPOSE:
//   Demonstrate that the Multi-BSM detection algorithm (MBSM_Detect)
//   from multibsm_attacks.cc CANNOT detect Temporal-Echo topology attacks.
//
//   The Multi-BSM detector (Trabelsi et al., Electronics 2022) checks for
//   BSM-level position anomalies:
//     Trigger A — position frozen but speed > 0
//     Trigger B — physically impossible displacement
//
//   Temporal-Echo attacks (TTW/BSHH/ME) manipulate TOPOLOGY PACKETS at the
//   CONTROL PLANE (TopologyPacket timestamps, HeartbeatPacket identities,
//   MEEchoReport phantom paths). The attacker's BSMs remain LEGITIMATE
//   (correct GPS positions, correct timestamps). Because no BSM anomaly
//   exists, MBSM_Detect returns false for every attack-period BSM.
//
//   Result: TP=0, FN=all_attack_period_BSMs, MCC=0
//   Interpretation: MBSM_Detect is a DATA-PLANE detector; Temporal-Echo
//   is a CONTROL-PLANE attack. They operate on different protocol layers.
//
// ATTACK LAYER (topology-level, same as routing.cc):
//   TTW  (1-4) : TopologyPacket with forged future timestamp injected into
//                controller table — ghost link maintained after physical break
//   BSHH (5-8) : HeartbeatPacket replayed with false claimed_sender_id —
//                controller receives stale liveness from wrong identity
//   ME   (9-12): MEEchoReport duplicate injections — controller infers
//                phantom multipath routes that do not exist
//
// BSM LAYER (what MBSM_Detect processes):
//   All vehicles always broadcast LEGITIMATE BSMs with correct GPS
//   positions and correct timestamps throughout the simulation.
//   MBSM_Detect_Verbatim processes these → always returns false.
//
// MBSM_Detect implements Trabelsi et al. (Electronics 2022) with paper parameters:
//   - HISTORY_DEPTH = 3  (paper Table 3)
//   - MAX_ACCEL_MS2 = 2.6 m/s²  (paper Table 2)
//   - Type 2 kinematic bound: (v_max×Δt + 0.5×a_max×Δt²) × safety_factor
//   - RSU central database (g_flagged_vehicles) per paper §4.2
//   - Algorithm 1 alert forwarding: broadcast to in-range vehicles + inter-RSU (Fig.2)
//
// TypeId "TempBsmTag" — avoids NS-3 collision with "BsmTag".
// Port 7783, Subnet 10.5.x — distinct from all other simulation files.
//
// Build:
//   cp temporal_mbsm_compare.cc ~/ns-3.35/scratch/
//   cd ~/ns-3.35 && ./waf build
//
// Run:
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=1"
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=5"
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=30 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=9"
//
// Expected output (all scenarios):
//   TP=0, FN>0, MCC=0.000
//   → proves MBSM_Detect cannot detect Temporal-Echo topology attacks
//
// Output files:
//   temporal_mbsm_compare_attack{1..12}.txt  — detailed attack + detection log
//   temporal_mbsm_compare_events.csv         — per-BSM event log (same format as multibsm_events.csv)
//   temporal_mbsm_compare_summary.csv        — detection metrics (TP/TN/FP/FN/MCC)
// ============================================================

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("TemporalMbsmCompare");

// ── Simulation parameters ──────────────────────────────────────
static double   simTime         = 40.0;
static uint32_t N_Vehicles      = 4;
static uint32_t N_RSUs          = 1;
static uint32_t attack_scenario = 1;
static uint32_t runNum          = 1;    // RNG run index for multi-run reproducibility

// ── BSM constants — SAME AS multibsm_attacks.cc ────────────────
static const double BSM_INTERVAL_S   = 0.050;
static const double DSRC_RANGE_M     = 250.0;
static const double MIN_SPEED_MS     = 12.0;
static const double MAX_SPEED_MS     = 20.0;
static const double SAFETY_FACTOR    = 1.5;
static const double POS_FROZEN_EPS_M = 0.05;
static const double SPEED_ZERO_THR   = 0.5;
static const double DIR_CHANGE_THR   = 0.1;   // radians (~5.7 deg) — Type 1 sub-trigger
static const double MAX_ACCEL_MS2    = 2.6;   // paper Table 2: max vehicle deceleration (m/s²)
static const uint32_t HISTORY_DEPTH  = 3;     // paper Table 3: 3 consecutive BSMs for Type 3

// ── Temporal attack timing — SAME AS routing.cc ────────────────
static const double TTW_HELLO_TIME  = 10.0;   // t=10: legitimate link exchange
static const double TTW_LINK_BREAK  = 15.0;   // t=15: physical link breaks
static const double TTW_REPLAY_TIME = 20.0;   // t=20: forged TopologyPacket injected

static const double BSHH_STORE_TIME  = 4.0;   // t=4 : attacker stores old heartbeat
static const double BSHH_REPLAY_TIME = 10.0;  // t=10: replayed HeartbeatPacket injected

static const double ME_LEGIT_TIME = 10.0;     // t=10: legitimate link discovery
static const double ME_ECHO_TIME  = 10.1;     // t=10.1: phantom echo reports injected

// ── Node containers ─────────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;

// ═══════════════════════════════════════════════════════════════
// TOPOLOGY-LEVEL ATTACK STRUCTURES — same as routing.cc
// These structs represent the in-memory state that the SDN
// controller would hold. They are NOT transmitted in BSMs.
// ═══════════════════════════════════════════════════════════════

// TTW — topology time-warp replay record
struct TopologyPacket {
    uint32_t src_id;     // node reporting the link
    uint32_t seen_id;    // neighbour being reported
    double   timestamp;  // simulation time of observation
    bool     is_forged;  // true = attacker tampered this timestamp
};

// BSHH — heartbeat liveness record
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity this heartbeat claims
    uint32_t physical_sender_id;  // who actually transmitted it
    double   timestamp;           // time heartbeat was originally generated
    bool     is_replayed;         // true = this is a stored replay
};

// ME — multipath echo injection record
struct MEEchoReport {
    uint32_t link_src;        // V1 (real link endpoint)
    uint32_t link_dst;        // V2 (real link endpoint)
    uint32_t false_reporter;  // V3 or V4 (fake witness)
    double   timestamp;
    bool     is_echo;         // always true for phantom reports
};

// ── In-memory controller tables (simulated SDN controller state) ─
static std::map<std::string, TopologyPacket>  g_ttw_controller_table;
static std::map<uint32_t, HeartbeatPacket>    g_bshh_controller_liveness_table;
static std::vector<MEEchoReport>              g_me_echo_reports;

// ── TTW stored packet ────────────────────────────────────────────
static TopologyPacket g_ttw_stored_packet;
static bool           g_ttw_packet_stored = false;

// ── BSHH stored heartbeat ────────────────────────────────────────
static HeartbeatPacket g_bshh_stored_heartbeat;
static bool            g_bshh_heartbeat_stored = false;

// ── ME stored link info ──────────────────────────────────────────
static double g_me_link0_x = 0.0, g_me_link0_y = 0.0;
static double g_me_link1_x = 0.0, g_me_link1_y = 0.0;
static bool   g_me_link_stored = false;

// ═══════════════════════════════════════════════════════════════
// BSM-LAYER structures — for MBSM_Detect processing
// ═══════════════════════════════════════════════════════════════

struct BsmRecord {
    uint32_t vehicle_id;
    double   pos_x;
    double   pos_y;
    double   speed_ms;
    double   direction;
    double   timestamp;
    bool     is_attack;   // oracle label — topology attack active for this vehicle
};

static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;

// ── PEM metric counters ──────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;

// ── Oracle — topology attack active state per vehicle ────────────
// Set to true when topology attack begins (NOT when BSM is falsified).
// BSMs from these vehicles are legitimate but labeled attack=true.
static std::map<uint32_t, bool> g_oracle_attack_state;

// ── Network/output state ─────────────────────────────────────────
static std::ofstream       g_attack_log;
static std::ofstream       g_events_csv;
static AnimationInterface* g_anim           = nullptr;
static Ipv4Address         g_rsu_ip;
static Ptr<Socket>         g_rsu_recv_socket = nullptr;

static const uint16_t BSM_PORT = 7783;

// ── Paper algorithm state — Algorithm 1, §4.2 ───────────────────
static std::set<uint32_t> g_flagged_vehicles;       // central RSU database of flagged vehicles
static uint64_t           g_rsu_alert_tx_count = 0; // total alert transmissions (broadcast + inter-RSU)

// ─────────────────────────────────────────────────────────────
// TempBsmTag — NS-3 Tag for legitimate BSM packets
// Structure identical to BsmTag in multibsm_attacks.cc.
// TypeId "TempBsmTag" avoids NS-3 TypeId registry collision.
// Serialised size: 4+8+8+8+8+8 = 44 bytes.
// ─────────────────────────────────────────────────────────────
class TempBsmTag : public Tag
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("TempBsmTag")
            .SetParent<Tag>()
            .AddConstructor<TempBsmTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 44; }

    void Serialize(TagBuffer buf) const override
    {
        buf.WriteU32   (m_vehicleId);
        buf.WriteDouble(m_posX);
        buf.WriteDouble(m_posY);
        buf.WriteDouble(m_speed);
        buf.WriteDouble(m_direction);
        buf.WriteDouble(m_timestamp);
    }
    void Deserialize(TagBuffer buf) override
    {
        m_vehicleId = buf.ReadU32   ();
        m_posX      = buf.ReadDouble();
        m_posY      = buf.ReadDouble();
        m_speed     = buf.ReadDouble();
        m_direction = buf.ReadDouble();
        m_timestamp = buf.ReadDouble();
    }
    void Print(std::ostream& os) const override
    {
        os << "TempBsmTag vid=" << m_vehicleId
           << " pos=(" << m_posX << "," << m_posY << ")"
           << " spd=" << m_speed;
    }

    void SetVehicleId (uint32_t v) { m_vehicleId = v; }
    void SetPosX      (double v)   { m_posX      = v; }
    void SetPosY      (double v)   { m_posY      = v; }
    void SetSpeed     (double v)   { m_speed     = v; }
    void SetDirection (double v)   { m_direction = v; }
    void SetTimestamp (double v)   { m_timestamp = v; }

    uint32_t GetVehicleId () const { return m_vehicleId; }
    double   GetPosX      () const { return m_posX; }
    double   GetPosY      () const { return m_posY; }
    double   GetSpeed     () const { return m_speed; }
    double   GetDirection () const { return m_direction; }
    double   GetTimestamp () const { return m_timestamp; }

private:
    uint32_t m_vehicleId  = 0;
    double   m_posX       = 0.0;
    double   m_posY       = 0.0;
    double   m_speed      = 0.0;
    double   m_direction  = 0.0;
    double   m_timestamp  = 0.0;
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
// Read vehicle kinematics from NS-3 MobilityModel
// ─────────────────────────────────────────────────────────────
static void GetKinematics(Ptr<Node> node,
                           double& pos_x, double& pos_y,
                           double& speed,  double& direction)
{
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    if (!mob) { pos_x = pos_y = speed = direction = 0.0; return; }
    Vector p = mob->GetPosition();
    Vector v = mob->GetVelocity();
    pos_x     = p.x;
    pos_y     = p.y;
    speed     = std::sqrt(v.x * v.x + v.y * v.y);
    direction = std::atan2(v.y, v.x);
}

// ═══════════════════════════════════════════════════════════════
// MBSM_Detect — Algorithm 1: Trabelsi et al., Electronics 2022
// Implements all three attack type detectors from the paper:
//   Type 1: position frozen while speed>0 OR direction changes
//   Type 2: displacement physically impossible given speed×dt
//   Type 3: entire history window shows frozen position
// ═══════════════════════════════════════════════════════════════
static bool MBSM_Detect(const BsmRecord& bsm)
{
    auto& hist = g_bsm_history[bsm.vehicle_id];

    // Paper §4.2: if vehicle already in RSU central database, keep flagging
    bool already_flagged = (g_flagged_vehicles.count(bsm.vehicle_id) > 0);

    // Algorithm 1 line 13: no previous record → add to database, no alert
    if (hist.empty()) {
        hist.push_back(bsm);
        return already_flagged;
    }

    const BsmRecord& prev = hist.back();
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) {
        // Type 2 (kinematic bound) requires dt > 0 — skip it.
        // Type 1 and Type 3 only use position/speed/direction — run them.
        double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
        double dir_change = std::fabs(std::remainder(bsm.direction - prev.direction, 2 * M_PI));
        bool type1 = (pos_change < POS_FROZEN_EPS_M &&
                      (bsm.speed_ms > SPEED_ZERO_THR || dir_change > DIR_CHANGE_THR));
        hist.push_back(bsm);
        if (hist.size() > HISTORY_DEPTH) hist.pop_front();
        if (type1) return true;
        if (hist.size() >= HISTORY_DEPTH) {
            bool all_frozen = true;
            for (size_t i = 1; i < hist.size(); i++) {
                if (Dist2D(hist[i].pos_x, hist[i].pos_y,
                           hist[i-1].pos_x, hist[i-1].pos_y) >= POS_FROZEN_EPS_M) {
                    all_frozen = false; break;
                }
            }
            if (all_frozen) return true;
        }
        return already_flagged;
    }

    double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
    // Gap 2 fix: use remainder to handle circular wrapping of direction (radians in -π..+π)
    double dir_change = std::fabs(std::remainder(bsm.direction - prev.direction, 2 * M_PI));

    // Attack Type 1: position frozen while speed is non-zero OR direction changes
    // Paper: "position is not changing" AND ("speed ≠ 0" OR "direction is changing")
    if (pos_change < POS_FROZEN_EPS_M &&
        (bsm.speed_ms > SPEED_ZERO_THR || dir_change > DIR_CHANGE_THR)) {
        // Gap 1 fix: always update history window so the next BSM compares against
        // the most recent record, not the last non-flagged one (paper §4.2 DB update)
        hist.push_back(bsm);
        if (hist.size() > HISTORY_DEPTH) hist.pop_front();
        return true;
    }

    // Attack Type 2: kinematic bound — paper Table 2, §4.2
    // max_possible = (v_max × Δt + 0.5 × a_max × Δt²) × safety_factor
    // Accounts for maximum possible acceleration in addition to observed speed.
    double v_max = std::max(bsm.speed_ms, prev.speed_ms);
    double max_possible = (v_max * dt + 0.5 * MAX_ACCEL_MS2 * dt * dt) * SAFETY_FACTOR;
    if (max_possible > 0.0 && pos_change > max_possible) {
        // Gap 1 fix: always update history window on detection
        hist.push_back(bsm);
        if (hist.size() > HISTORY_DEPTH) hist.pop_front();
        return true;
    }

    // Update sliding history window (no anomaly detected on Type 1/2)
    hist.push_back(bsm);
    if (hist.size() > HISTORY_DEPTH) hist.pop_front();

    // Attack Type 3: all HISTORY_DEPTH consecutive BSMs show frozen position
    // Paper Table 3: window depth = 3; all pairs must be below POS_FROZEN_EPS_M
    if (hist.size() >= HISTORY_DEPTH) {
        bool all_frozen = true;
        for (size_t i = 1; i < hist.size(); i++) {
            if (Dist2D(hist[i].pos_x, hist[i].pos_y,
                       hist[i-1].pos_x, hist[i-1].pos_y) >= POS_FROZEN_EPS_M) {
                all_frozen = false;
                break;
            }
        }
        if (all_frozen) {
            return true;
        }
    }

    return already_flagged;
}

// Forward declarations
static void TEMP_RSUReceive(BsmRecord bsm);
static void TEMP_RSUForwardAlert(uint32_t flagged_vid);

// ─────────────────────────────────────────────────────────────
// RSU UDP socket receive callback
// ─────────────────────────────────────────────────────────────
static void TEMP_RSUSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TempBsmTag tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        BsmRecord bsm;
        bsm.vehicle_id = tag.GetVehicleId();
        bsm.pos_x      = tag.GetPosX();
        bsm.pos_y      = tag.GetPosY();
        bsm.speed_ms   = tag.GetSpeed();
        bsm.direction  = tag.GetDirection();
        bsm.timestamp  = tag.GetTimestamp();

        // Oracle: is the topology attack active for this vehicle?
        // Note: BSM content is LEGITIMATE regardless of oracle state.
        bsm.is_attack = (g_oracle_attack_state.count(bsm.vehicle_id) &&
                         g_oracle_attack_state[bsm.vehicle_id]);

        TEMP_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler — runs MBSM_Detect on legitimate BSM
//
// KEY BEHAVIOUR: All BSMs are legitimate. The oracle flag
// (bsm.is_attack) indicates the topology attack is active,
// NOT that the BSM position is falsified.
//
// MBSM_Detect always returns false for legitimate BSMs
// during the topology attack period → these are FN events.
// ─────────────────────────────────────────────────────────────
static void TEMP_RSUReceive(BsmRecord bsm)
{
    double now       = Simulator::Now().GetSeconds();
    bool   is_attack = bsm.is_attack;

    // MBSM_Detect processes the legitimate BSM
    bool detected = MBSM_Detect(bsm);

    // Algorithm 1 (lines 6-8, Figure 2): forward alert to in-range vehicles + neighbouring RSU
    if (detected) {
        TEMP_RSUForwardAlert(bsm.vehicle_id);
    }

    // First alert time (for Tdet computation)
    if (detected && pem_first_alert_time < 0.0 && is_attack) {
        pem_first_alert_time = now;
    }

    // Update PEM counters
    if (is_attack) {
        if (detected) { pem_tp++; } else { pem_fn++; }
    } else {
        if (detected) { pem_fp++; } else { pem_tn++; }
    }

    // Write event log
    if (g_events_csv.is_open()) {
        g_events_csv << attack_scenario << ","
                     << std::fixed << std::setprecision(3)
                     << now            << ","
                     << bsm.vehicle_id << ","
                     << bsm.pos_x      << ","
                     << bsm.pos_y      << ","
                     << bsm.speed_ms   << ","
                     << bsm.direction  << ","
                     << (is_attack ? 1 : 0) << ","
                     << (detected  ? 1 : 0) << "\n";
    }

    // Log false negatives (attack-period BSMs that were not detected)
    if (is_attack && !detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  FALSE NEGATIVE — V" << bsm.vehicle_id
                     << "  BSM pos=(" << bsm.pos_x << ", " << bsm.pos_y << ")"
                     << "  spd=" << bsm.speed_ms << " m/s"
                     << "  [BSM legitimate: topology attack in progress]\n";
        g_attack_log.flush();
    }

    // Unexpected false positive (should not occur with legitimate BSMs)
    if (!is_attack && detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  UNEXPECTED FP — V" << bsm.vehicle_id
                     << "  (legitimate BSM triggered anomaly check)\n";
        g_attack_log.flush();
    }
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
// TEMP_RSUForwardAlert — Algorithm 1 (lines 6-8), Figure 2
// Paper: Trabelsi et al., Electronics 2022
// When MBSM_Detect flags a vehicle:
//   1. Mark vehicle in RSU central database (g_flagged_vehicles)
//   2. Broadcast alert to all in-range vehicles (Algorithm 1 line 6)
//   3. Transmit alert to neighbouring RSU in attacker direction (line 8, Fig.2)
// Steps 2-3 are simulated by counting transmissions — no real 802.11p needed
// in this standalone incompatibility-study file.
// ─────────────────────────────────────────────────────────────
static void TEMP_RSUForwardAlert(uint32_t flagged_vid)
{
    bool newly_flagged = g_flagged_vehicles.insert(flagged_vid).second;
    double now = Simulator::Now().GetSeconds();

    // Algorithm 1 line 6: broadcast alert to every in-range vehicle
    uint32_t in_range_count = 0;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        if (Vehicle_Nodes.Get(i)->GetId() == flagged_vid) continue;
        double px, py, spd, dir;
        GetKinematics(Vehicle_Nodes.Get(i), px, py, spd, dir);
        if (InRSURange(px, py)) in_range_count++;
    }
    g_rsu_alert_tx_count += in_range_count;

    // Algorithm 1 line 8 / Figure 2: forward to neighbouring RSU in attacker direction.
    // Paper §3 assumes all RSUs are interconnected; always count 1 inter-RSU forward.
    g_rsu_alert_tx_count += 1;

    if (g_attack_log.is_open() && newly_flagged) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  RSU ALERT (Algorithm 1, §4.2): V" << flagged_vid
                     << " added to RSU central database\n"
                     << "           Broadcast to " << in_range_count
                     << " in-range vehicles (Algorithm 1 line 6)\n"
                     << "           Total alert TX count: " << g_rsu_alert_tx_count << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Send a legitimate BSM — real position, real speed, real timestamp
// Called by ALL vehicles at EVERY BSM tick (including attackers).
// ─────────────────────────────────────────────────────────────
static void TEMP_SendLegitBsm(uint32_t veh_idx)
{
    if (g_rsu_recv_socket == nullptr)     return;
    if (veh_idx >= Vehicle_Nodes.GetN())  return;

    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, spd, dir;
    GetKinematics(node, px, py, spd, dir);

    if (!InRSURange(px, py)) return;

    TypeId udp_tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(node, udp_tid);
    sock->Connect(InetSocketAddress(g_rsu_ip, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TempBsmTag tag;
    tag.SetVehicleId (node->GetId());
    tag.SetPosX      (px);            // ← correct GPS position
    tag.SetPosY      (py);            // ← correct GPS position
    tag.SetSpeed     (spd);           // ← correct speed
    tag.SetDirection (dir);
    tag.SetTimestamp (Simulator::Now().GetSeconds());  // ← correct current timestamp
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    sock->Close();
}

// ─────────────────────────────────────────────────────────────
// BSM tick — ALL vehicles ALWAYS send LEGITIMATE BSMs
//
// CRITICAL DESIGN DECISION: Unlike multibsm_attacks.cc, no vehicle
// ever sends a falsified BSM in this file. The topology-level attacks
// (TTW/BSHH/ME) run as separate scheduled events that only modify
// in-memory controller tables. This is why MBSM_Detect cannot detect
// these attacks — it processes BSMs, not topology table state.
// ─────────────────────────────────────────────────────────────
static void TEMP_BsmTick(uint32_t veh_idx, double t_end)
{
    // All vehicles — including attackers — always send legitimate BSMs
    TEMP_SendLegitBsm(veh_idx);

    double next = Simulator::Now().GetSeconds() + BSM_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BSM_INTERVAL_S), &TEMP_BsmTick, veh_idx, t_end);
    }
}

// ═══════════════════════════════════════════════════════════════
// TOPOLOGY-LEVEL ATTACK FUNCTIONS
//
// These functions simulate the control-plane attack effect:
// modifying in-memory controller tables exactly as routing.cc does.
// They do NOT modify any BSM content.
// The oracle is updated here to mark which vehicles' BSMs are
// considered "attack-period" events.
// ═══════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────
// TTW — Step 1: Legitimate topology update at HELLO time
//   V0 sends TopologyPacket(V0 sees V1, t=10) to controller
//   Controller accepts it as valid link discovery
// ─────────────────────────────────────────────────────────────
static void TEMP_TTW_LegitTopologyUpdate(uint32_t v0_id, uint32_t v1_id, double obs_time)
{
    TopologyPacket pkt;
    pkt.src_id    = v0_id;
    pkt.seen_id   = v1_id;
    pkt.timestamp = obs_time;
    pkt.is_forged = false;

    std::ostringstream key;
    key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = pkt;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
                     << "]  TOPOLOGY: V" << v0_id << " → controller: V" << v0_id
                     << " sees V" << v1_id << " at t=" << obs_time << " (legitimate)\n"
                     << "           TopologyPacket { src=" << v0_id << ", seen=" << v1_id
                     << ", t=" << obs_time << ", forged=false }\n"
                     << "           Controller table: V" << v0_id << "→V" << v1_id
                     << " ACCEPTED as valid link\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — Step 2: Attacker stores old TopologyPacket
//   V0 keeps a copy of the legitimate packet for replay
// ─────────────────────────────────────────────────────────────
static void TEMP_TTW_StorePacket(uint32_t v0_id, uint32_t v1_id, double obs_time)
{
    g_ttw_stored_packet.src_id    = v0_id;
    g_ttw_stored_packet.seen_id   = v1_id;
    g_ttw_stored_packet.timestamp = obs_time;
    g_ttw_stored_packet.is_forged = false;
    g_ttw_packet_stored           = true;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
                     << "]  TOPOLOGY: V" << v0_id << " STORES TopologyPacket for replay\n"
                     << "           Stored: { src=" << v0_id << ", seen=" << v1_id
                     << ", t=" << obs_time << " }\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — Step 3: Physical link breaks (V1 moves away)
// ─────────────────────────────────────────────────────────────
static void TEMP_TTW_LinkBreak(uint32_t v0_id, uint32_t v1_id)
{
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << Simulator::Now().GetSeconds()
                     << "]  PHYSICAL LINK BREAK: V" << v0_id << " ↔ V" << v1_id << " broken\n"
                     << "           (V1 has moved beyond 300m DSRC range)\n"
                     << "           Controller table still holds: V" << v0_id << "→V" << v1_id << "\n"
                     << "           (awaiting timeout — attack will prevent this)\n"
                     << "           BSMs from all vehicles remain LEGITIMATE throughout\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// TTW — Step 4: REPLAY ATTACK
//   V0 forges TopologyPacket(V0 sees V1, t=20) with future timestamp
//   Injects into controller table → controller believes ghost link is live
//   Oracle activated: V0's BSMs labeled as attack-period events
//
//   WHY MBSM_Detect FAILS:
//     V0 continues broadcasting LEGITIMATE BSMs (correct position).
//     MBSM_Detect checks: (1) frozen pos + speed>0, (2) impossible jump.
//     V0's legitimate BSMs fail neither check.
//     MBSM_Detect returns false → ALL V0 BSMs after t=20 are FN.
// ─────────────────────────────────────────────────────────────
static void TEMP_TTW_ReplayAttack(uint32_t v0_id, uint32_t v1_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;

    // Forge the topology packet with a current/future timestamp
    TopologyPacket forged;
    forged.src_id    = v0_id;
    forged.seen_id   = v1_id;
    forged.timestamp = forged_time;  // ← forged: makes controller think link is fresh
    forged.is_forged = true;

    std::ostringstream key;
    key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = forged;  // inject into controller table

    // Activate oracle: V0's BSMs are now "attack-period" events
    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = forged_time;

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
                     << "]  *** TOPOLOGY REPLAY ATTACK BEGINS ***\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  Attacker     : V" << v0_id << "\n"
                     << "  Forged packet: { src=V" << v0_id << ", seen=V" << v1_id
                     << ", t=" << forged_time << ", forged=TRUE }\n"
                     << "  Old packet   : { src=V" << v0_id << ", seen=V" << v1_id
                     << ", t=" << g_ttw_stored_packet.timestamp << " } ← stored at HELLO_TIME\n"
                     << "  Effect       : Controller table V" << v0_id << "→V" << v1_id
                     << " refreshed to t=" << forged_time << "\n"
                     << "  Result       : Controller believes GHOST LINK V" << v0_id
                     << "↔V" << v1_id << " is still active\n"
                     << "                 (V" << v1_id << " physically gone since t=" << TTW_LINK_BREAK << ")\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v0_id << " continues broadcasting LEGITIMATE BSMs\n"
                     << "    - Correct GPS position (real current location)\n"
                     << "    - Correct timestamp (current simulation time)\n"
                     << "    - Correct speed (real velocity)\n"
                     << "  MBSM_Detect processes V" << v0_id << "'s BSMs:\n"
                     << "    - dt = current_t - prev_t > 0  (correct forward timestamps)\n"
                     << "    - pos_change = legitimate movement (consistent with speed)\n"
                     << "    - Trigger A: pos frozen + speed>0? NO — position advances normally\n"
                     << "    - Trigger B: impossible jump? NO — displacement <= speed*dt*1.5\n"
                     << "    - MBSM_Detect returns FALSE\n"
                     << "  ORACLE: V" << v0_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All subsequent V" << v0_id << " BSMs are FALSE NEGATIVES\n"
                     << "  WHY:    MBSM_Detect is a DATA-PLANE detector (BSM positions).\n"
                     << "          TTW is a CONTROL-PLANE attack (topology timestamps).\n"
                     << "          Different protocol layers — detector is structurally blind.\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — Step 1: Legitimate heartbeat exchange
//   Both V0 and V1 send legitimate HeartbeatPackets to controller
// ─────────────────────────────────────────────────────────────
static void TEMP_BSHH_LegitExchange(uint32_t v0_id, uint32_t v1_id, double t)
{
    HeartbeatPacket hb0, hb1;
    hb0.claimed_sender_id  = v0_id;
    hb0.physical_sender_id = v0_id;
    hb0.timestamp          = t;
    hb0.is_replayed        = false;
    g_bshh_controller_liveness_table[v0_id] = hb0;

    hb1.claimed_sender_id  = v1_id;
    hb1.physical_sender_id = v1_id;
    hb1.timestamp          = t;
    hb1.is_replayed        = false;
    g_bshh_controller_liveness_table[v1_id] = hb1;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  HEARTBEAT: V" << v0_id << " → controller: alive at t=" << t << " (legitimate)\n"
                     << "           HeartbeatPacket { claimed=V" << v0_id
                     << ", physical=V" << v0_id << ", t=" << t << ", replayed=false }\n"
                     << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  HEARTBEAT: V" << v1_id << " → controller: alive at t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — Step 2: Attacker V1 stores V0's old heartbeat
// ─────────────────────────────────────────────────────────────
static void TEMP_BSHH_StoreHeartbeat(uint32_t v0_id, uint32_t v1_id, double stored_time)
{
    g_bshh_stored_heartbeat.claimed_sender_id  = v0_id;
    g_bshh_stored_heartbeat.physical_sender_id = v1_id;  // V1 is the attacker
    g_bshh_stored_heartbeat.timestamp          = stored_time;
    g_bshh_stored_heartbeat.is_replayed        = false;
    g_bshh_heartbeat_stored                    = true;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
                     << "]  HEARTBEAT: V" << v1_id << " STORES V" << v0_id
                     << "'s heartbeat for replay\n"
                     << "           Stored: { claimed=V" << v0_id << ", t=" << stored_time << " }\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH — Step 3: REPLAY ATTACK
//   V1 injects old HeartbeatPacket claiming V0's identity
//   Controller liveness table receives stale entry for V0
//   Oracle activated: V1's BSMs labeled as attack-period events
//
//   WHY MBSM_Detect FAILS:
//     V1 broadcasts LEGITIMATE BSMs under V1's own ID.
//     The heartbeat replay only affects controller's liveness table.
//     MBSM_Detect sees V1's legitimate BSMs → returns false.
// ─────────────────────────────────────────────────────────────
static void TEMP_BSHH_ReplayAttack(uint32_t v0_id, uint32_t v1_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;

    // Replay the stored heartbeat with V0's identity
    HeartbeatPacket replayed;
    replayed.claimed_sender_id  = v0_id;   // ← claims to be from V0
    replayed.physical_sender_id = v1_id;   // ← actually sent by V1
    replayed.timestamp          = g_bshh_stored_heartbeat.timestamp;  // ← old timestamp
    replayed.is_replayed        = true;

    g_bshh_controller_liveness_table[v0_id] = replayed;  // overwrite V0's liveness entry (step 6: attacker hijacks victim identity)

    // Step 5: victim (V0) forwards attacker's own old heartbeat to controller → attacker liveness poisoned
    HeartbeatPacket forwarded_by_victim;
    forwarded_by_victim.claimed_sender_id  = v1_id;   // ← attacker's identity
    forwarded_by_victim.physical_sender_id = v0_id;   // ← V0 forwarded it (deceived)
    forwarded_by_victim.timestamp          = g_bshh_stored_heartbeat.timestamp;  // ← old timestamp
    forwarded_by_victim.is_replayed        = true;
    g_bshh_controller_liveness_table[v1_id] = forwarded_by_victim;  // attacker's liveness also poisoned

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
                     << "  Effect       : Controller liveness table V" << v0_id
                     << " overwritten with STALE t=" << replayed.timestamp << "\n"
                     << "                 Controller believes V" << v0_id
                     << " is alive as of t=" << replayed.timestamp << " (incorrect)\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v1_id << " and V" << v0_id
                     << " both broadcast LEGITIMATE BSMs under their own IDs\n"
                     << "    - Correct GPS positions (real current locations)\n"
                     << "    - Correct timestamps (current simulation time)\n"
                     << "    - The heartbeat replay chain is a SEPARATE control-plane exchange\n"
                     << "  MBSM_Detect processes V" << v1_id << " and V" << v0_id << " BSMs:\n"
                     << "    - Timestamps advance normally → dt > 0\n"
                     << "    - Position changes consistent with velocity\n"
                     << "    - MBSM_Detect returns FALSE for both\n"
                     << "  ORACLE: V" << v1_id << " and V" << v0_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All subsequent BSMs from both vehicles are FALSE NEGATIVES\n"
                     << "  WHY:    MBSM_Detect monitors BSM POSITIONS.\n"
                     << "          BSHH replays HEARTBEAT LIVENESS messages (different message type).\n"
                     << "          MBSM_Detect has no visibility into heartbeat messages.\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// ME — Step 1: Legitimate link discovery
//   V0 and V1 exchange HELLO; send legitimate topology updates
// ─────────────────────────────────────────────────────────────
static void TEMP_ME_LegitDiscovery(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link pair: V0↔V1
    g_ttw_controller_table[std::to_string(v0_id) + "_" + std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id) + "_" + std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Echo pair's own legitimate link: V2↔V3 (they are in overhearing range but have no link to V0/V1)
    g_ttw_controller_table[std::to_string(v2_id) + "_" + std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id) + "_" + std::to_string(v2_id)] = { v3_id, v2_id, t, false };

    // Capture link positions for logging
    if (Vehicle_Nodes.GetN() > 0) {
        double spd, dir;
        if (Vehicle_Nodes.GetN() > v0_id)
            GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, spd, dir);
        if (Vehicle_Nodes.GetN() > v1_id)
            GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, spd, dir);
        g_me_link_stored = true;
    }

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
                     << "]  TOPOLOGY: V" << v0_id << "↔V" << v1_id << " real link established\n"
                     << "           V" << v0_id << " → controller: <V" << v0_id
                     << " sees V" << v1_id << ", t=" << t << "> (real reporter)\n"
                     << "           V" << v1_id << " → controller: <V" << v1_id
                     << " sees V" << v0_id << ", t=" << t << "> (real reporter)\n"
                     << "           V" << v2_id << " → controller: <V" << v2_id
                     << " sees V" << v3_id << ", t=" << t << "> (echo pair own link)\n"
                     << "           V" << v3_id << " → controller: <V" << v3_id
                     << " sees V" << v2_id << ", t=" << t << "> (echo pair own link)\n"
                     << "           [V" << v2_id << " and V" << v3_id
                     << " have NO direct link to V" << v0_id << " or V" << v1_id << "]\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// ME — Step 2: ECHO INJECTION ATTACK
//   V2 and V3 each inject an echo report for V0↔V1 link
//   Controller infers phantom paths: V0→V2→V1, V0→V3→V1
//   Oracle activated: V2 and V3's BSMs labeled as attack-period events
//
//   WHY MBSM_Detect FAILS:
//     V2 and V3 continue broadcasting LEGITIMATE BSMs at their real positions.
//     The echo injections only add phantom entries to the topology table.
//     MBSM_Detect sees V2/V3's legitimate BSMs → returns false.
// ─────────────────────────────────────────────────────────────
static void TEMP_ME_InjectEchoReports(uint32_t v2_id, uint32_t v3_id,
                                       uint32_t v0_id, uint32_t v1_id, double t)
{
    // Echo report from V2: claims V2 also witnesses V0↔V1 link
    MEEchoReport echo2;
    echo2.link_src       = v0_id;
    echo2.link_dst       = v1_id;
    echo2.false_reporter = v2_id;
    echo2.timestamp      = t;
    echo2.is_echo        = true;
    g_me_echo_reports.push_back(echo2);

    // Echo report from V3: claims V3 also witnesses V0↔V1 link
    MEEchoReport echo3;
    echo3.link_src       = v0_id;
    echo3.link_dst       = v1_id;
    echo3.false_reporter = v3_id;
    echo3.timestamp      = t;
    echo3.is_echo        = true;
    g_me_echo_reports.push_back(echo3);

    // Activate oracle: V2 and V3 BSMs are now "attack-period" events
    g_oracle_attack_state[v2_id] = true;
    g_oracle_attack_state[v3_id] = true;
    pem_attack_start_time = t;

    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << t
                     << "]  *** ME MULTIPATH ECHO ATTACK BEGINS ***\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  Echo V" << v2_id << " → controller: MEEchoReport { V" << v0_id
                     << " sees V" << v1_id << ", false_reporter=V" << v2_id << ", echo=TRUE }\n"
                     << "  Echo V" << v3_id << " → controller: MEEchoReport { V" << v0_id
                     << " sees V" << v1_id << ", false_reporter=V" << v3_id << ", echo=TRUE }\n"
                     << "  Effect: Controller infers PHANTOM PATHS:\n"
                     << "            V" << v0_id << " → V" << v2_id << " → V" << v1_id << "  (PHANTOM)\n"
                     << "            V" << v0_id << " → V" << v3_id << " → V" << v1_id << "  (PHANTOM)\n"
                     << "          V" << v2_id << " and V" << v3_id
                     << " have no physical link to V" << v0_id << " or V" << v1_id << "\n"
                     << "  ─────────────────────────────────────────────────────────────\n"
                     << "  BSM LAYER: V" << v2_id << " and V" << v3_id
                     << " broadcast LEGITIMATE BSMs at their REAL positions\n"
                     << "    - V" << v2_id << " real position: not near V" << v0_id
                     << " or V" << v1_id << " link endpoints\n"
                     << "    - Correct timestamps (current simulation time)\n"
                     << "    - Echo reports are control-plane messages (NOT in BSMs)\n"
                     << "  MBSM_Detect processes V" << v2_id << " and V" << v3_id << " BSMs:\n"
                     << "    - Timestamps advance normally → dt > 0\n"
                     << "    - Position changes consistent with velocity\n"
                     << "    - MBSM_Detect returns FALSE\n"
                     << "  ORACLE: V" << v2_id << " and V" << v3_id << " BSMs labeled attack=TRUE\n"
                     << "  RESULT: All subsequent V" << v2_id << "/V" << v3_id << " BSMs are FALSE NEGATIVES\n"
                     << "  WHY:    MBSM_Detect monitors per-vehicle BSM POSITION consistency.\n"
                     << "          ME injects TOPOLOGY ECHO REPORTS (different message type).\n"
                     << "          Echo reports do not appear in BSM streams at all.\n"
                     << "  ─────────────────────────────────────────────────────────────\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S2: Malicious RSU
//   V1 sends legitimate topology to RSU → RSU forwards to controller.
//   RSU also STORES V1's packet and later replays it with forged timestamp.
//   Oracle: V1's BSMs labeled attack (V1's topology was stolen by RSU).
// ═══════════════════════════════════════════════════════════════
static void TEMP_TTW_S2_VehiclesToRSU(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    // Primary direction: V1 sees V0
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt;
    g_ttw_packet_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S2] V" << v1_id << " → RSU → controller:"
            << " V" << v1_id << " sees V" << v0_id << " at t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → RSU → controller:"
            << " V" << v0_id << " sees V" << v1_id << " at t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           RSU (malicious) STORES V" << v1_id << "→V" << v0_id << " packet for replay\n";
        g_attack_log.flush();
    }
}
static void TEMP_TTW_S2_RSUReplayAttack(uint32_t v1_id, uint32_t v0_id, double forged_time)
{
    if (!g_ttw_packet_stored) return;
    TopologyPacket forged = { v1_id, v0_id, forged_time, true };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    g_oracle_attack_state[v1_id] = true;
    pem_attack_start_time = forged_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S2 REPLAY ATTACK BEGINS (ATTACKER: RSU) ***\n"
            << "  RSU injects: { src=V" << v1_id << ", seen=V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  Old stored:  { t=" << g_ttw_stored_packet.timestamp << " }\n"
            << "  Controller effect: Ghost link V" << v1_id << "↔V" << v0_id << " maintained\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs (correct GPS)\n"
            << "  MBSM_Detect processes V" << v1_id << "'s legitimate BSMs → FALSE\n"
            << "  ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → all are FALSE NEGATIVES\n"
            << "  WHY: MBSM_Detect is DATA-PLANE; RSU topology replay is CONTROL-PLANE\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S3: Malicious Controller, No RSU
//   V1 sends legitimate topology directly to controller.
//   Controller stores it internally, then INTERNALLY REPLAYS with forged timestamp.
//   No external packet — pure internal controller manipulation.
// ═══════════════════════════════════════════════════════════════
static void TEMP_TTW_S3_VehicleToController(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt;
    g_ttw_packet_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S3] V" << v1_id << " → controller (direct): V" << v1_id
            << " sees V" << v0_id << " at t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → controller: V" << v0_id
            << " sees V" << v1_id << " at t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           Controller (malicious) stores packet internally for replay\n";
        g_attack_log.flush();
    }
}
static void TEMP_TTW_S3_ControllerInternalReplay(uint32_t v1_id, uint32_t v0_id, double forged_time)
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
            << "  Controller rewrites own table: { src=V" << v1_id << ", seen=V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  No external packet — pure INTERNAL controller manipulation\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs (correct GPS)\n"
            << "  MBSM_Detect processes V" << v1_id << "'s legitimate BSMs → FALSE\n"
            << "  ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → all are FALSE NEGATIVES\n"
            << "  WHY: MBSM_Detect monitors BSM positions; controller table is CONTROL-PLANE\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// TTW-S4: Malicious Controller, With RSU
//   V1 sends via RSU → controller (normal RSU aggregation path).
//   Controller stores the RSU-aggregated entry, then INTERNALLY REPLAYS.
// ═══════════════════════════════════════════════════════════════
static void TEMP_TTW_S4_VehiclesViaRSU(uint32_t v1_id, uint32_t v0_id, double obs_time)
{
    TopologyPacket pkt = { v1_id, v0_id, obs_time, false };
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = pkt;
    // Bidirectional HELLO: also insert reverse entry V0 sees V1 (paper §4.2)
    TopologyPacket pkt_rev = { v0_id, v1_id, obs_time, false };
    std::ostringstream key_rev; key_rev << v0_id << "_" << v1_id;
    g_ttw_controller_table[key_rev.str()] = pkt_rev;
    g_ttw_stored_packet = pkt;
    g_ttw_packet_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << obs_time
            << "]  [TTW-S4] V" << v1_id << " → RSU → controller (RSU aggregation path)\n"
            << "           V" << v1_id << " sees V" << v0_id << " at t=" << obs_time << " (legitimate)\n"
            << "           V" << v0_id << " → RSU → controller: V" << v0_id
            << " sees V" << v1_id << " at t=" << obs_time << " (legitimate — bidirectional)\n"
            << "           Controller (malicious) stores RSU-aggregated entry for internal replay\n";
        g_attack_log.flush();
    }
}
static void TEMP_TTW_S4_ControllerInternalReplay(uint32_t v1_id, uint32_t v0_id, double forged_time)
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
            << "  Controller rewrites own table (RSU-aggregated entry): { src=V" << v1_id
            << ", seen=V" << v0_id << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  BSM LAYER: V" << v1_id << " broadcasts LEGITIMATE BSMs\n"
            << "  MBSM_Detect → FALSE. ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S2: Malicious RSU
//   V0 sends legitimate heartbeat to RSU; RSU stores it.
//   RSU replays { claimed=V0, physical=RSU } to controller.
//   Oracle: V0's BSMs labeled (V0's identity stolen by RSU).
// ═══════════════════════════════════════════════════════════════
static void TEMP_BSHH_S2_LegitViaRSU(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S2] V" << v0_id << " → RSU → controller: alive at t=" << t << " (legitimate)\n"
            << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S2] V" << v1_id << " → RSU → controller: alive at t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TEMP_BSHH_S2_RSUStoreHeartbeat(uint32_t v0_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, 0xFFFFFFFF, stored_time, false }; // physical=RSU (sentinel)
    g_bshh_heartbeat_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S2] RSU STORES V" << v0_id
            << "'s heartbeat { claimed=V" << v0_id << ", t=" << stored_time << " }\n";
        g_attack_log.flush();
    }
}
static void TEMP_BSHH_S2_RSUReplayAttack(uint32_t v0_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    // Single injection: RSU sends stored heartbeat claiming victim's identity
    HeartbeatPacket forged = { v0_id, 0xFFFFFFFF, g_bshh_stored_heartbeat.timestamp, true };
    g_bshh_controller_liveness_table[v0_id] = forged;
    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = replay_time;
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S2 REPLAY ATTACK BEGINS (ATTACKER: RSU) ***\n"
            << "  RSU → controller: { claimed=V" << v0_id
            << ", physical=RSU(sentinel), t=" << forged.timestamp << ", replayed=TRUE }\n"
            << "  Controller V" << v0_id << " liveness overwritten with stale t=" << forged.timestamp << "\n"
            << "  BSM LAYER: V" << v0_id << " broadcasts LEGITIMATE BSMs (correct GPS)\n"
            << "  MBSM_Detect → FALSE. ORACLE: V" << v0_id << " BSMs labeled attack=TRUE → FN\n"
            << "  WHY: MBSM_Detect monitors BSM POSITIONS; BSHH replays HEARTBEAT LIVENESS\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S3: Malicious Controller, No RSU
//   V0 sends heartbeat directly to controller.
//   Controller stores old heartbeat, then internally overwrites with stale entry.
// ═══════════════════════════════════════════════════════════════
static void TEMP_BSHH_S3_LegitToController(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S3] V" << v0_id << " → controller (direct): alive at t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TEMP_BSHH_S3_ControllerStoreHeartbeat(uint32_t v0_id, double stored_time)
{
    g_bshh_stored_heartbeat = { v0_id, v0_id, stored_time, false };
    g_bshh_heartbeat_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << stored_time
            << "]  [BSHH-S3] Controller stores V" << v0_id
            << "'s old heartbeat { t=" << stored_time << " } for internal replay\n"
            << "           Controller also retains stale liveness for V" << v0_id
            << " and V" << (v0_id + 1) << " (both will be reinstated)\n";
        g_attack_log.flush();
    }
}
static void TEMP_BSHH_S3_ControllerInternalReplay(uint32_t v0_id, uint32_t v1_id, double replay_time)
{
    if (!g_bshh_heartbeat_stored) return;
    double stored_time = g_bshh_stored_heartbeat.timestamp;
    // Reinstate V0 liveness with stale timestamp
    HeartbeatPacket replayed0 = { v0_id, v0_id, stored_time, true };
    g_bshh_controller_liveness_table[v0_id] = replayed0;
    // Reinstate V1 liveness with stale timestamp (paper §5.3: controller reinstates both vehicles)
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
            << "  Both vehicles' liveness entries now reflect old controller state\n"
            << "  BSM LAYER: V" << v0_id << " and V" << v1_id << " broadcast LEGITIMATE BSMs\n"
            << "  MBSM_Detect → FALSE for both. ORACLE: V" << v0_id << " and V" << v1_id
            << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// BSHH-S4: Malicious Controller, With RSU
//   V0 sends heartbeat via RSU to controller.
//   Controller stores and internally replays with stale entry.
// ═══════════════════════════════════════════════════════════════
static void TEMP_BSHH_S4_LegitViaRSU(uint32_t v0_id, uint32_t v1_id, double t)
{
    g_bshh_controller_liveness_table[v0_id] = { v0_id, v0_id, t, false };
    g_bshh_controller_liveness_table[v1_id] = { v1_id, v1_id, t, false };
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [BSHH-S4] V" << v0_id << " → RSU → controller: alive at t=" << t << " (legitimate)\n";
        g_attack_log.flush();
    }
}
static void TEMP_BSHH_S4_ControllerStoreHeartbeat(uint32_t v0_id, double stored_time)
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
static void TEMP_BSHH_S4_ControllerInternalReplay(uint32_t v0_id, uint32_t v1_id, double replay_time)
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
            << "  MBSM_Detect → FALSE for both. ORACLE: V" << v0_id << " and V" << v1_id
            << " BSMs labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S2: Malicious RSU
//   V0↔V1 legitimate link forwarded by RSU to controller (normal).
//   RSU ADDITIONALLY injects echo reports attributing V0↔V1 to V2 and V3.
// ═══════════════════════════════════════════════════════════════
static void TEMP_ME_S2_LegitViaRSU(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link pair V0↔V1
    g_ttw_controller_table[std::to_string(v0_id) + "_" + std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id) + "_" + std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3 (forwarded via RSU as well)
    g_ttw_controller_table[std::to_string(v2_id) + "_" + std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id) + "_" + std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, spd, dir); }
    if (Vehicle_Nodes.GetN() > v1_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, spd, dir); }
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S2] V" << v0_id << "↔V" << v1_id
            << " legitimate link — V" << v0_id << " → RSU → controller (normal path)\n"
            << "           V" << v2_id << "↔V" << v3_id
            << " legitimate link — phantom reporters' own link forwarded via RSU\n";
        g_attack_log.flush();
    }
}
static void TEMP_ME_S2_RSUInjectEchoReports(uint32_t v2_id, uint32_t v3_id,
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
            << ", false_reporter=V" << v2_id << ", echo=TRUE }\n"
            << "  RSU injects: MEEchoReport { V" << v0_id << "↔V" << v1_id
            << ", false_reporter=V" << v3_id << ", echo=TRUE }\n"
            << "  Phantom paths: V" << v0_id << "→V" << v2_id << "→V" << v1_id
            << "  and  V" << v0_id << "→V" << v3_id << "→V" << v1_id << "\n"
            << "  BSM LAYER: V" << v2_id << "/V" << v3_id << " broadcast LEGITIMATE BSMs\n"
            << "  MBSM_Detect → FALSE. ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S3: Malicious Controller, No RSU
//   V0↔V1 sent directly to controller.
//   Controller INTERNALLY creates phantom echo entries for V2 and V3.
// ═══════════════════════════════════════════════════════════════
static void TEMP_ME_S3_LegitToController(uint32_t v0_id, uint32_t v1_id,
                                          uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link pair V0↔V1
    g_ttw_controller_table[std::to_string(v0_id) + "_" + std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id) + "_" + std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3 (directly sent to controller)
    g_ttw_controller_table[std::to_string(v2_id) + "_" + std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id) + "_" + std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, spd, dir); }
    if (Vehicle_Nodes.GetN() > v1_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, spd, dir); }
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S3] V" << v0_id << "↔V" << v1_id
            << " legitimate link — V" << v0_id << " → controller (direct)\n"
            << "           V" << v2_id << "↔V" << v3_id
            << " legitimate link — phantom reporters' own link (direct)\n";
        g_attack_log.flush();
    }
}
static void TEMP_ME_S3_ControllerCreatePhantom(uint32_t v2_id, uint32_t v3_id,
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
            << "  Controller internally fabricates: MEEchoReport { V" << v0_id << "↔V" << v1_id
            << ", false_reporter=V" << v2_id << " } (no external message)\n"
            << "  Controller internally fabricates: MEEchoReport { V" << v0_id << "↔V" << v1_id
            << ", false_reporter=V" << v3_id << " } (no external message)\n"
            << "  BSM LAYER: V" << v2_id << "/V" << v3_id << " broadcast LEGITIMATE BSMs\n"
            << "  MBSM_Detect → FALSE. ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ═══════════════════════════════════════════════════════════════
// ME-S4: Malicious Controller, With RSU
//   V0↔V1 arrives via RSU → controller (normal RSU aggregation).
//   Controller INTERNALLY creates phantom echo entries for V2 and V3.
// ═══════════════════════════════════════════════════════════════
static void TEMP_ME_S4_LegitViaRSU(uint32_t v0_id, uint32_t v1_id,
                                    uint32_t v2_id, uint32_t v3_id, double t)
{
    // Real link pair V0↔V1
    g_ttw_controller_table[std::to_string(v0_id) + "_" + std::to_string(v1_id)] = { v0_id, v1_id, t, false };
    g_ttw_controller_table[std::to_string(v1_id) + "_" + std::to_string(v0_id)] = { v1_id, v0_id, t, false };
    // Phantom reporters' own legitimate link V2↔V3 (forwarded via RSU)
    g_ttw_controller_table[std::to_string(v2_id) + "_" + std::to_string(v3_id)] = { v2_id, v3_id, t, false };
    g_ttw_controller_table[std::to_string(v3_id) + "_" + std::to_string(v2_id)] = { v3_id, v2_id, t, false };
    if (Vehicle_Nodes.GetN() > v0_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y, spd, dir); }
    if (Vehicle_Nodes.GetN() > v1_id) { double spd,dir; GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y, spd, dir); }
    g_me_link_stored = true;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << t
            << "]  [ME-S4] V" << v0_id << "↔V" << v1_id
            << " legitimate link — V" << v0_id << " → RSU → controller\n"
            << "           V" << v2_id << "↔V" << v3_id
            << " legitimate link — phantom reporters' own link forwarded via RSU\n";
        g_attack_log.flush();
    }
}
static void TEMP_ME_S4_ControllerCreatePhantom(uint32_t v2_id, uint32_t v3_id,
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
            << "  MBSM_Detect → FALSE. ORACLE: V" << v2_id << "/V" << v3_id << " labeled attack=TRUE → FN\n\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Oracle deactivation — resets all attack flags at end of study window.
// Fires just before TEMP_WriteSummary so counters are unaffected.
// Needed for extended studies (back-to-back scenario sweeps).
// ─────────────────────────────────────────────────────────────
static void TEMP_OracleDeactivate()
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
// Subnet 10.5.(i+1).0/30 — distinct from all other files
// ─────────────────────────────────────────────────────────────
static void TEMP_SetupNetwork()
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
        base << "10.5." << (i + 1) << ".0";
        addr.SetBase(base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifc = addr.Assign(devs);

        if (i == 0) g_rsu_ip = ifc.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_rsu_recv_socket = Socket::CreateSocket(
        RSU_Nodes.Get(0),
        TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&TEMP_RSUSocketReceive));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    sinkHelper.Install(RSU_Nodes.Get(0)).Start(Seconds(0.0));
    sinkHelper.Get(0)->SetStopTime(Seconds(simTime));
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        sinkHelper.Install(Vehicle_Nodes.Get(i)).Start(Seconds(0.0));
    }
}

// ─────────────────────────────────────────────────────────────
// NetAnim colours
// ─────────────────────────────────────────────────────────────
static void TEMP_SetupNetAnim()
{
    if (!g_anim) return;
    if (RSU_Nodes.GetN() > 0) {
        uint32_t rid = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rid, 255, 200, 0);
        g_anim->UpdateNodeSize (rid, 35, 35);
        g_anim->UpdateNodeDescription(rid, "RSU");
    }
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid  = Vehicle_Nodes.Get(i)->GetId();
        bool is_atk   = ((attack_scenario >= 1 && attack_scenario <= 4) &&
                          nid == Vehicle_Nodes.Get(0)->GetId()) ||
                        ((attack_scenario >= 5 && attack_scenario <= 8) &&
                          Vehicle_Nodes.GetN() > 1 && nid == Vehicle_Nodes.Get(1)->GetId()) ||
                        ((attack_scenario >= 9 && attack_scenario <= 12) &&
                          Vehicle_Nodes.GetN() > 3 &&
                          (nid == Vehicle_Nodes.Get(2)->GetId() ||
                           nid == Vehicle_Nodes.Get(3)->GetId()));
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
// Scenario name helpers
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
static void TEMP_InitLogs()
{
    std::string log_name = (attack_scenario == 0)
        ? "temporal_mbsm_compare_baseline.txt"
        : "temporal_mbsm_compare_attack" + std::to_string(attack_scenario) + ".txt";

    g_attack_log.open(log_name, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Temporal-Echo Attack vs. Multi-BSM Detector\n"
        << "  PURPOSE : Prove MBSM_Detect CANNOT detect Temporal-Echo attacks\n"
        << "  Attack  : " << GetScenarioName(attack_scenario) << "\n"
        << "  Detector: MBSM_Detect — Trabelsi et al., Electronics 2022\n"
        << "  Detector: COPIED VERBATIM from multibsm_attacks.cc — NO CHANGES\n"
        << "----------------------------------------------------------------\n"
        << "  KEY INSIGHT:\n"
        << "    Temporal-Echo attacks target TOPOLOGY TABLES (control plane).\n"
        << "    MBSM_Detect monitors BSM POSITIONS (data plane).\n"
        << "    These are DIFFERENT PROTOCOL LAYERS.\n"
        << "    Attacker BSMs remain LEGITIMATE throughout → TP=0, MCC=0.\n"
        << "----------------------------------------------------------------\n"
        << "  Simulation time : " << simTime   << " s\n"
        << "  Vehicles        : " << N_Vehicles << "\n"
        << "  RSUs            : " << N_RSUs     << "\n";

    if (attack_scenario >= 1 && attack_scenario <= 4) {
        g_attack_log
            << "  Attack family   : TTW (Topology Time-Warp)\n"
            << "  Attacker node   : V0 (vehicle index 0)\n"
            << "  Victim link     : V0 ↔ V1\n"
            << "  t=HELLO(" << TTW_HELLO_TIME << "): legitimate link discovery\n"
            << "  t=BREAK(" << TTW_LINK_BREAK << "): physical link breaks\n"
            << "  t=REPLAY(" << TTW_REPLAY_TIME << "): forged TopologyPacket injected\n";
    } else if (attack_scenario >= 5 && attack_scenario <= 8) {
        g_attack_log
            << "  Attack family   : BSHH (Beacon-State Heartbeat Hijack)\n"
            << "  Attacker node   : V1 (vehicle index 1)\n"
            << "  Victim identity : V0\n"
            << "  t=STORE(" << BSHH_STORE_TIME << "): V1 captures V0's old heartbeat\n"
            << "  t=REPLAY(" << BSHH_REPLAY_TIME << "): forged HeartbeatPacket injected\n";
    } else if (attack_scenario >= 9 && attack_scenario <= 12) {
        g_attack_log
            << "  Attack family   : ME (Multipath Echo)\n"
            << "  Echo nodes      : V2, V3 (vehicle indices 2, 3)\n"
            << "  Real link       : V0 ↔ V1\n"
            << "  t=LEGIT(" << ME_LEGIT_TIME << "): legitimate link discovery\n"
            << "  t=ECHO(" << ME_ECHO_TIME << "): MEEchoReports injected (phantom paths)\n";
    }

    g_attack_log
        << "----------------------------------------------------------------\n"
        << "  Expected result: TP=0, FN>0, MCC=0.000\n"
        << "  Reason         : No BSM anomaly → MBSM_Detect always returns false\n"
        << "================================================================\n\n";
    g_attack_log.flush();

    g_events_csv.open("temporal_mbsm_compare_events.csv", std::ios::out | std::ios::trunc);
    g_events_csv
        << "attack_scenario,sim_time_s,vehicle_id,reported_pos_x,reported_pos_y,"
        << "speed_ms,direction_rad,is_attack,alert_raised\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary and print to console
// ─────────────────────────────────────────────────────────────
static void TEMP_WriteSummary()
{
    double tp = (double)pem_tp, tn = (double)pem_tn;
    double fp = (double)pem_fp, fn = (double)pem_fn;

    double denom = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc   = (denom > 0.0) ? ((tp * tn - fp * fn) / denom) : 0.0;
    double total = tp + tn + fp + fn;
    double acr   = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;
    double prec  = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double rec   = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double tdet  = (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0)
                   ? (pem_first_alert_time - pem_attack_start_time) * 1000.0
                   : -1.0;

    std::string csv_interp = (attack_scenario == 0)
        ? "Baseline (no attack): all BSMs benign; TN=" + std::to_string(pem_tn) + "; no attack events generated"
        : "TP=0: MBSM_Detect cannot detect topology-level Temporal-Echo attacks";

    std::ofstream sum("temporal_mbsm_compare_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,scenario_name,detector,tp,tn,fp,fn,mcc,acr_pct,precision,recall,"
        << "tdet_ms,flagged_vehicles,alert_tx_count,interpretation\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << "\"" << GetScenarioName(attack_scenario) << "\","
        << "MBSM_Detect (Trabelsi 2022),"
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc << "," << acr << "," << prec << "," << rec << "," << tdet << ","
        << g_flagged_vehicles.size() << "," << g_rsu_alert_tx_count << ","
        << "\"" << csv_interp << "\"\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n════════════════════ RUN SUMMARY ════════════════════\n"
            << "  Detector        : MBSM_Detect — Trabelsi et al., Electronics 2022\n"
            << "  Attack scenario : " << attack_scenario
            << " (" << GetScenarioName(attack_scenario) << ")\n"
            << "  ──────────────────────────────────────────────────\n"
            << "  TP = " << pem_tp << "   (attack-period BSMs correctly flagged)\n"
            << "  TN = " << pem_tn << "  (legit-period BSMs correctly passed)\n"
            << "  FP = " << pem_fp << "   (legit BSMs incorrectly flagged)\n"
            << "  FN = " << pem_fn << "  (attack-period BSMs MISSED — MBSM_Detect returned false)\n"
            << "  ──────────────────────────────────────────────────\n"
            << "  MCC              = " << std::fixed << std::setprecision(3) << mcc  << "\n"
            << "  ACR              = " << acr  << " %\n"
            << "  Precision        = " << prec << "\n"
            << "  Recall           = " << rec  << "\n"
            << "  Tdet             = " << tdet << " ms\n"
            << "  ──────────────────────────────────────────────────\n"
            << "  Algorithm 1 state (paper §4.2, Figure 2):\n"
            << "  Flagged vehicles = " << g_flagged_vehicles.size()
            << "  (RSU central DB entries)\n"
            << "  Alert TX count   = " << g_rsu_alert_tx_count
            << "  (broadcast + inter-RSU forwarding)\n"
            << "  HISTORY_DEPTH    = " << HISTORY_DEPTH << "  (paper Table 3)\n"
            << "  MAX_ACCEL_MS2    = " << MAX_ACCEL_MS2 << " m/s²  (paper Table 2)\n"
            << "  ──────────────────────────────────────────────────\n"
            << "  INTERPRETATION:\n";
        if (pem_tp == 0 && pem_fn > 0) {
            g_attack_log
                << "  TP=0, FN=" << pem_fn << ", MCC=" << mcc << "\n"
                << "  → MBSM_Detect detected ZERO attack-period BSMs.\n"
                << "  → All attack-period BSMs were FALSE NEGATIVES.\n"
                << "  → This PROVES MBSM_Detect cannot detect Temporal-Echo attacks.\n"
                << "\n"
                << "  ROOT CAUSE:\n"
                << "  Temporal-Echo attacks manipulate TOPOLOGY PACKETS (control plane).\n"
                << "  MBSM_Detect monitors BSM POSITION ANOMALIES (data plane).\n"
                << "  Attackers broadcast legitimate BSMs throughout — no position anomaly.\n"
                << "  MBSM_Detect's physics rules (frozen-pos, impossible-jump) require\n"
                << "  BSM-level falsification, which Temporal-Echo attacks do NOT produce.\n"
                << "  Therefore TP=0 and MCC=0 for all 12 Temporal-Echo scenarios.\n";
        } else if (pem_tp == 0 && pem_fn == 0) {
            g_attack_log << "  No attack events were evaluated (check simTime/N_Vehicles).\n";
        } else {
            g_attack_log << "  Unexpected: TP=" << pem_tp << " — check oracle logic.\n";
        }
        g_attack_log
            << "═════════════════════════════════════════════════════\n";
        g_attack_log.flush();
    }

    std::string console_verdict;
    if (attack_scenario == 0) {
        console_verdict = "BASELINE: no attack events; TN=" + std::to_string(pem_tn) + " benign BSMs passed correctly";
    } else if (pem_tp == 0 && pem_fn > 0) {
        console_verdict = "RESULT CONFIRMED: MCC=0, TP=0 — MBSM_Detect cannot detect Temporal-Echo";
    } else {
        console_verdict = "Unexpected result: TP=" + std::to_string(pem_tp) + " — check oracle / scheduling";
    }

    std::cout << "\n[TemporalMbsmCompare] Summary: " << GetScenarioName(attack_scenario) << "\n"
              << "  TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp << " FN=" << pem_fn << "\n"
              << "  MCC=" << std::fixed << std::setprecision(3) << mcc
              << "  ACR=" << acr << "%" << "\n"
              << "  FlaggedVehicles=" << g_flagged_vehicles.size()
              << "  AlertTxCount=" << g_rsu_alert_tx_count << "\n"
              << "  " << console_verdict << "\n"
              << "  Summary CSV: temporal_mbsm_compare_summary.csv\n";
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
    // S2/S4/S6/S8/S10/S12 need an RSU
    if ((attack_scenario == 2 || attack_scenario == 4 ||
         attack_scenario == 6 || attack_scenario == 8 ||
         attack_scenario == 10 || attack_scenario == 12) && N_RSUs == 0) {
        N_RSUs = 1;
        std::cout << "[Info] RSU-based scenario requires N_RSUs>=1; set to 1.\n";
    }
    if (attack_scenario >= 9 && attack_scenario <= 12 && N_Vehicles < 4) {
        N_Vehicles = 4;
        std::cout << "[Warning] ME scenarios require N_Vehicles >= 4; set to 4.\n";
    }

    TEMP_InitLogs();

    std::cout << "\n══════════════════════════════════════════════════════════════\n"
              << "  Temporal-Echo vs. Multi-BSM — Incompatibility Study\n"
              << "  Attack scenario : " << attack_scenario
              << " (" << GetScenarioName(attack_scenario) << ")\n"
              << "  N_Vehicles      : " << N_Vehicles << "\n"
              << "  N_RSUs          : " << N_RSUs << "\n"
              << "  simTime         : " << simTime << " s\n"
              << "  Detector        : MBSM_Detect (verbatim from multibsm_attacks.cc)\n"
              << "  Expected result : TP=0, MCC=0 (detector is data-plane only)\n"
              << "══════════════════════════════════════════════════════════════\n\n";

    // ── Create nodes ─────────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(1);

    // ── Vehicle mobility: constant velocity, staggered lanes ──────
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

    // ── RSU mobility: fixed central position ─────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
        Ptr<ConstantPositionMobilityModel> rm =
            DynamicCast<ConstantPositionMobilityModel>(
                RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (rm) {
            rm->SetPosition(Vector(50.0 + (N_Vehicles / 2.0) * 60.0,
                                   (N_Vehicles > 1) ? (N_Vehicles - 1) * 5.0 : 0.0,
                                   0.0));
        }
    }

    // ── Network ───────────────────────────────────────────────────
    TEMP_SetupNetwork();

    // ── Schedule BSM ticks for ALL vehicles (ALL always legitimate) ─
    double t_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Simulator::Schedule(Seconds(0.1 + i * 0.001), &TEMP_BsmTick, i, t_end);
    }

    // ── Schedule TOPOLOGY-LEVEL attack events ─────────────────────
    // These do NOT affect BSM content — they only modify
    // in-memory controller tables and set the oracle flag.

    uint32_t v0_id = (Vehicle_Nodes.GetN() > 0) ? Vehicle_Nodes.Get(0)->GetId() : 0;
    uint32_t v1_id = (Vehicle_Nodes.GetN() > 1) ? Vehicle_Nodes.Get(1)->GetId() : 1;
    uint32_t v2_id = (Vehicle_Nodes.GetN() > 2) ? Vehicle_Nodes.Get(2)->GetId() : 2;
    uint32_t v3_id = (Vehicle_Nodes.GetN() > 3) ? Vehicle_Nodes.Get(3)->GetId() : 3;

    if (attack_scenario == 1) {
        // TTW-S1: Malicious Vehicle V0 — directly replays to controller
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TEMP_TTW_LegitTopologyUpdate, v0_id, v1_id, TTW_HELLO_TIME);
        // Bidirectional HELLO: V1 also reports seeing V0 (paper §4.2)
        Simulator::Schedule(Seconds(TTW_HELLO_TIME + 0.001),
            &TEMP_TTW_LegitTopologyUpdate, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_HELLO_TIME + 0.01),
            &TEMP_TTW_StorePacket, v0_id, v1_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TEMP_TTW_LinkBreak, v0_id, v1_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TEMP_TTW_ReplayAttack, v0_id, v1_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 2) {
        // TTW-S2: Malicious RSU — stores V1's topology, replays to controller
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TEMP_TTW_S2_VehiclesToRSU, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TEMP_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TEMP_TTW_S2_RSUReplayAttack, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 3) {
        // TTW-S3: Malicious Controller, No RSU — internally replays stored entry
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TEMP_TTW_S3_VehicleToController, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TEMP_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TEMP_TTW_S3_ControllerInternalReplay, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 4) {
        // TTW-S4: Malicious Controller, With RSU — V1→RSU→controller, controller replays
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),
            &TEMP_TTW_S4_VehiclesViaRSU, v1_id, v0_id, TTW_HELLO_TIME);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),
            &TEMP_TTW_LinkBreak, v1_id, v0_id);
        Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
            &TEMP_TTW_S4_ControllerInternalReplay, v1_id, v0_id, TTW_REPLAY_TIME);

    } else if (attack_scenario == 5) {
        // BSHH-S1: Malicious Vehicle V1 — stores V0's heartbeat, replays to controller
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TEMP_BSHH_StoreHeartbeat, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.5),
            &TEMP_BSHH_LegitExchange, v0_id, v1_id, BSHH_STORE_TIME + 0.5);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TEMP_BSHH_ReplayAttack, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 6) {
        // BSHH-S2: Malicious RSU — stores V0's heartbeat, replays to controller
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TEMP_BSHH_S2_LegitViaRSU, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TEMP_BSHH_S2_RSUStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TEMP_BSHH_S2_RSUReplayAttack, v0_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 7) {
        // BSHH-S3: Malicious Controller, No RSU — internally replays both V0 and V1 liveness
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TEMP_BSHH_S3_LegitToController, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TEMP_BSHH_S3_ControllerStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TEMP_BSHH_S3_ControllerInternalReplay, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 8) {
        // BSHH-S4: Malicious Controller, With RSU — V0→RSU→controller, controller reinstates both
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TEMP_BSHH_S4_LegitViaRSU, v0_id, v1_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_STORE_TIME + 0.01),
            &TEMP_BSHH_S4_ControllerStoreHeartbeat, v0_id, BSHH_STORE_TIME);
        Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
            &TEMP_BSHH_S4_ControllerInternalReplay, v0_id, v1_id, BSHH_REPLAY_TIME);

    } else if (attack_scenario == 9) {
        // ME-S1: Malicious Vehicles V2, V3 — directly inject echo reports
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TEMP_ME_LegitDiscovery, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TEMP_ME_InjectEchoReports, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 10) {
        // ME-S2: Malicious RSU — forwards legit link + phantom reporters' own link, also injects echo reports
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TEMP_ME_S2_LegitViaRSU, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TEMP_ME_S2_RSUInjectEchoReports, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 11) {
        // ME-S3: Malicious Controller, No RSU — internally creates phantom entries
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TEMP_ME_S3_LegitToController, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TEMP_ME_S3_ControllerCreatePhantom, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);

    } else if (attack_scenario == 12) {
        // ME-S4: Malicious Controller, With RSU — topology via RSU, controller adds phantoms
        Simulator::Schedule(Seconds(ME_LEGIT_TIME),
            &TEMP_ME_S4_LegitViaRSU, v0_id, v1_id, v2_id, v3_id, ME_LEGIT_TIME);
        Simulator::Schedule(Seconds(ME_ECHO_TIME),
            &TEMP_ME_S4_ControllerCreatePhantom, v2_id, v3_id, v0_id, v1_id, ME_ECHO_TIME);
    }

    // ── Oracle deactivation + summary at end ─────────────────────
    Simulator::Schedule(Seconds(simTime - 0.10), &TEMP_OracleDeactivate);
    Simulator::Schedule(Seconds(simTime - 0.05), &TEMP_WriteSummary);

    // ── NetAnim ──────────────────────────────────────────────────
    std::string anim_xml = "temporal_mbsm_compare_anim_sc"
                           + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    TEMP_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim; g_anim = nullptr;
    if (g_attack_log.is_open()) g_attack_log.close();
    if (g_events_csv.is_open()) g_events_csv.close();

    return 0;
}
