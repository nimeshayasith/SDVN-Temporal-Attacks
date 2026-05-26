// ============================================================
// veremi_attacks.cc
// VeReMi Position Falsification Attack Simulation
//
// Based on: Mekonen, H.D.; Bitew, M.A.; Kifle, M.
//   "VeReMi Dataset-Based Detection of Position Falsification
//    Attacks Using K-Nearest Neighbor and Bagging Ensemble
//    Learning in IoV."  PLOS ONE 2025
//
// Implements five VeReMi attack types as a standalone NS-3 simulation.
//
// Scenario ID = VeReMi attack type + 20 (consistent with codebase):
//   attack_scenario=21 → Type 1  : Constant Position
//   attack_scenario=22 → Type 2  : Constant Offset
//   attack_scenario=24 → Type 4  : Random Position
//   attack_scenario=28 → Type 8  : Random Offset
//   attack_scenario=36 → Type 16 : Eventual Stop
//   attack_scenario=0  → Baseline (no attack)
//
// (13-15 = multibsm_attacks.cc  |  16-17 = attack_link_latency.cc)
//
// Copy to ns-3.35/scratch/ and build with:
//   ./waf build
//
// Run examples:
//   ./waf --run "scratch/veremi_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=21"
//   ./waf --run "scratch/veremi_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=22 --T2_offset_x=100 --T2_offset_y=80"
//   ./waf --run "scratch/veremi_attacks --simTime=60 --N_Vehicles=8 --N_RSUs=1 --attack_scenario=24"
//   ./waf --run "scratch/veremi_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=28 --T8_max_offset=150"
//   ./waf --run "scratch/veremi_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=36 --T16_prob_inc=0.025"
//
// Output files:
//   veremi_attack{21|22|24|28|36}.txt  — human-readable attack log
//   veremi_pairs.csv                    — consecutive BSM pair features (9 features + label)
//   veremi_pem_summary.csv              — rule-based detection metrics summary
//
// Full KNN+Bagging detection (Python):
//   python3 knn_bagging_detector.py veremi_pairs.csv
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
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("VeReMiAttacks");

// ─────────────────────────────────────────────────────────────
// Simulation parameters (overridable via command line)
// ─────────────────────────────────────────────────────────────
static double   simTime         = 60.0;
static uint32_t N_Vehicles      = 6;
static uint32_t N_RSUs          = 1;
static uint32_t attack_scenario = 21;
static uint32_t attacker_idx    = 0;     // 0-based index, used when N_Attackers=1
static uint32_t N_Attackers     = 1;     // number of malicious vehicles

// ── Type 2 (Constant Offset) ──────────────────────────────────
static double T2_offset_x = 100.0;      // constant x-offset added to true GPS (m)
static double T2_offset_y = 100.0;      // constant y-offset added to true GPS (m)

// ── Type 8 (Random Offset) ───────────────────────────────────
static double T8_max_offset = 100.0;    // uniform half-width for offset rectangle (m)

// ── Type 16 (Eventual Stop) ──────────────────────────────────
static double T16_prob_inc = 0.025;     // freeze-probability increment per BSM tick

// ─────────────────────────────────────────────────────────────
// BSM and channel constants
// ─────────────────────────────────────────────────────────────
static const double BSM_INTERVAL_S   = 0.100;   // 100 ms BSM interval
static const double DSRC_RANGE_M     = 250.0;   // DSRC communication range (m)
static const double MIN_SPEED_MS     = 8.0;     // minimum vehicle speed (m/s)
static const double MAX_SPEED_MS     = 20.0;    // maximum vehicle speed (m/s)
static const double POS_FROZEN_EPS_M = 0.05;    // "position unchanged" threshold (m)
static const double SPEED_ZERO_THR   = 0.5;     // "vehicle stopped" speed threshold (m/s)
static const double SAFETY_FACTOR    = 1.5;     // max-displacement safety margin
static const double SIM_AREA_MAX     = 1000.0;  // Type 4 random playground boundary (m)

// ─────────────────────────────────────────────────────────────
// Node containers
// ─────────────────────────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;

// ─────────────────────────────────────────────────────────────
// BSM record — one snapshot stored at the RSU
// ─────────────────────────────────────────────────────────────
struct BsmRecord {
    uint32_t vehicle_id;
    double   pos_x;
    double   pos_y;
    double   spd_x;       // velocity x-component (m/s)
    double   spd_y;       // velocity y-component (m/s)
    double   timestamp;   // simulation seconds
    bool     is_attack;   // ground-truth label — from oracle, NOT from the packet
};

// ─────────────────────────────────────────────────────────────
// RSU state: previous BSM per vehicle for consecutive pair logging
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, BsmRecord> g_prev_bsm;

// ─────────────────────────────────────────────────────────────
// Type 1 (Constant Position) per-vehicle freeze state
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, bool>   g_t1_frozen;
static std::map<uint32_t, double> g_t1_freeze_x;
static std::map<uint32_t, double> g_t1_freeze_y;

// ─────────────────────────────────────────────────────────────
// Type 16 (Eventual Stop) per-vehicle freeze state
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, double> g_t16_freeze_prob;
static std::map<uint32_t, bool>   g_t16_is_frozen;
static std::map<uint32_t, double> g_t16_freeze_x;
static std::map<uint32_t, double> g_t16_freeze_y;

// ─────────────────────────────────────────────────────────────
// PEM metric counters (rule-based detector in NS-3)
// Full KNN+Bagging detection is done in knn_bagging_detector.py
// ─────────────────────────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;
static bool     pem_attack_active     = false;

// ─────────────────────────────────────────────────────────────
// Simulation oracle — RSU cannot access this
// Tracks per-vehicle ground-truth attack state.
// No "is_attack" field exists in VeReMiBsmTag packets.
// Models real network behaviour (oracle pattern from multibsm_attacks.cc).
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, bool> g_oracle_attack_state;

// ─────────────────────────────────────────────────────────────
// Multi-attacker support
// ─────────────────────────────────────────────────────────────
static std::vector<uint32_t> g_attacker_indices;

// ─────────────────────────────────────────────────────────────
// Output streams
// ─────────────────────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_pairs_csv;    // consecutive BSM pair features for KNN+Bagging

// ─────────────────────────────────────────────────────────────
// Random engine (fixed seed; pass --RngRun for variation)
// ─────────────────────────────────────────────────────────────
static std::mt19937 g_rng(54321);

// ─────────────────────────────────────────────────────────────
// BSM protocol port (7778 to avoid collision with multibsm port 7777)
// ─────────────────────────────────────────────────────────────
static const uint16_t BSM_PORT = 7778;

// ─────────────────────────────────────────────────────────────
// NetAnim state
// ─────────────────────────────────────────────────────────────
static AnimationInterface*      g_anim            = nullptr;
static Ipv4Address              g_rsu_ip_anim;
static std::vector<Ipv4Address> g_veh_ip_anim;
static Ptr<Socket>              g_rsu_recv_socket = nullptr;

// ─────────────────────────────────────────────────────────────
// VeReMiBsmTag — NS-3 Tag for VeReMi BSM packets
//
// Carries GPS position and velocity components only.
// No ground-truth attack flag — oracle pattern (as in multibsm_attacks.cc).
// Pattern mirrors BsmTag / CustomHeartbeatTag in routing.cc:
//   pkt->AddPacketTag(tag)   — attached by vehicle at transmit time
//   pkt->PeekPacketTag(tag)  — read by RSU in socket receive callback
//
// Serialised layout (44 bytes):
//   vehicleId : uint32  (4 B)
//   posX      : double  (8 B)
//   posY      : double  (8 B)
//   spdX      : double  (8 B)  velocity x-component (m/s)
//   spdY      : double  (8 B)  velocity y-component (m/s)
//   timestamp : double  (8 B)
// ─────────────────────────────────────────────────────────────
class VeReMiBsmTag : public Tag
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("VeReMiBsmTag")
            .SetParent<Tag>()
            .AddConstructor<VeReMiBsmTag>();
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
        os << "VeReMiBsmTag vid=" << m_vehicleId
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
    uint32_t m_vehicleId  = 0;
    double   m_posX       = 0.0;
    double   m_posY       = 0.0;
    double   m_spdX       = 0.0;
    double   m_spdY       = 0.0;
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
// Read a vehicle node's ground-truth kinematics from NS-3
// Returns: pos_x, pos_y, spd_x (velocity.x), spd_y (velocity.y)
// ─────────────────────────────────────────────────────────────
static void GetKinematics(Ptr<Node> node,
                           double& pos_x, double& pos_y,
                           double& spd_x,  double& spd_y)
{
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    if (!mob) { pos_x = pos_y = spd_x = spd_y = 0.0; return; }
    Vector p = mob->GetPosition();
    Vector v = mob->GetVelocity();
    pos_x = p.x;  pos_y = p.y;
    spd_x = v.x;  spd_y = v.y;
}

// ─────────────────────────────────────────────────────────────
// Get VeReMi type number from attack_scenario
// Mapping: attack_scenario = VeReMi_type + 20
//   21→1, 22→2, 24→4, 28→8, 36→16
// ─────────────────────────────────────────────────────────────
static uint32_t GetVeReMiType()
{
    if (attack_scenario == 0) return 0;
    return attack_scenario - 20;
}

// ─────────────────────────────────────────────────────────────
// Physics-based rule detector (NS-3 side)
//
// Detects: Type 1 (frozen position), Type 4 (impossible jump),
//          Type 16 (eventually frozen position)
// Does NOT reliably detect Type 2 or Type 8 — those need the
// KNN+Bagging classifier in knn_bagging_detector.py.
//
// Returns true when an anomaly is detected.
// ─────────────────────────────────────────────────────────────
static bool VREM_Detect(const BsmRecord& bsm)
{
    auto it = g_prev_bsm.find(bsm.vehicle_id);
    if (it == g_prev_bsm.end()) return false;

    const BsmRecord& prev = it->second;
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) return false;

    double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
    double speed = std::sqrt(bsm.spd_x * bsm.spd_x + bsm.spd_y * bsm.spd_y);

    // Rule 1: position frozen but vehicle reports non-zero speed
    // Catches Type 1 (always frozen) and Type 16 (frozen after threshold)
    if (pos_change < POS_FROZEN_EPS_M && speed > SPEED_ZERO_THR) {
        return true;
    }

    // Rule 2: physically impossible displacement
    // Catches Type 4 (random teleportation across the playground)
    double max_possible = speed * dt * SAFETY_FACTOR;
    if (max_possible > 0.0 && pos_change > max_possible) {
        return true;
    }

    return false;
}

// Forward declaration
static void VREM_RSUReceive(BsmRecord bsm);

// ─────────────────────────────────────────────────────────────
// RSU UDP socket receive callback
// Fires when a VeReMiBsmTag packet arrives on BSM_PORT.
// Reads the tag (PeekPacketTag), reconstructs BsmRecord.
// Ground truth comes from oracle, not from the packet.
// Mirrors Rx() / PeekPacketTag pattern in routing.cc and multibsm_attacks.cc.
// ─────────────────────────────────────────────────────────────
static void VREM_RSUSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        VeReMiBsmTag tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        BsmRecord bsm;
        bsm.vehicle_id = tag.GetVehicleId();
        bsm.pos_x      = tag.GetPosX();
        bsm.pos_y      = tag.GetPosY();
        bsm.spd_x      = tag.GetSpdX();
        bsm.spd_y      = tag.GetSpdY();
        bsm.timestamp  = tag.GetTimestamp();
        // Ground truth from oracle — NOT from the packet (models real network)
        bsm.is_attack  = g_oracle_attack_state.count(bsm.vehicle_id) &&
                         g_oracle_attack_state[bsm.vehicle_id];

        VREM_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// Create a VeReMiBsmTag packet and send it from vehicle veh_idx to RSU.
// No is_attack parameter — oracle is updated by the caller before this runs.
// ─────────────────────────────────────────────────────────────
static void VREM_SendBsm(uint32_t veh_idx,
                          double px, double py,
                          double sx, double sy)
{
    if (g_rsu_recv_socket == nullptr)     return;
    if (veh_idx >= Vehicle_Nodes.GetN())  return;

    Ptr<Node> src = Vehicle_Nodes.Get(veh_idx);

    TypeId udp_tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(src, udp_tid);
    sock->Connect(InetSocketAddress(g_rsu_ip_anim, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    VeReMiBsmTag tag;
    tag.SetVehicleId (src->GetId());
    tag.SetPosX      (px);
    tag.SetPosY      (py);
    tag.SetSpdX      (sx);
    tag.SetSpdY      (sy);
    tag.SetTimestamp (Simulator::Now().GetSeconds());
    pkt->AddPacketTag(tag);

    sock->Send (pkt);
    sock->Close();
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler
// Runs physics-based detection, logs consecutive BSM pair to CSV,
// updates PEM counters and human-readable log.
// ─────────────────────────────────────────────────────────────
static void VREM_RSUReceive(BsmRecord bsm)
{
    double now      = Simulator::Now().GetSeconds();
    bool is_attack  = bsm.is_attack;
    bool detected   = VREM_Detect(bsm);

    // ── Write consecutive BSM pair to veremi_pairs.csv (for KNN+Bagging) ──
    auto it = g_prev_bsm.find(bsm.vehicle_id);
    if (it != g_prev_bsm.end() && g_pairs_csv.is_open())
    {
        const BsmRecord& prev = it->second;
        double dt = bsm.timestamp - prev.timestamp;
        g_pairs_csv << std::fixed << std::setprecision(4)
                    << bsm.vehicle_id   << ","
                    << GetVeReMiType()  << ","
                    << now              << ","
                    << prev.pos_x       << ","
                    << prev.pos_y       << ","
                    << prev.spd_x       << ","
                    << prev.spd_y       << ","
                    << bsm.pos_x        << ","
                    << bsm.pos_y        << ","
                    << bsm.spd_x        << ","
                    << bsm.spd_y        << ","
                    << dt               << ","
                    << (is_attack ? 1 : 0) << "\n";
    }
    // Update previous BSM for this vehicle
    g_prev_bsm[bsm.vehicle_id] = bsm;

    // ── Record first detection time ─────────────────────────────────────
    if (detected && pem_first_alert_time < 0.0 && is_attack) {
        pem_first_alert_time = now;
    }

    // ── PEM counters ────────────────────────────────────────────────────
    if (is_attack) {
        if (detected) { pem_tp++; } else { pem_fn++; }
    } else {
        if (detected) { pem_fp++; } else { pem_tn++; }
    }

    // ── Human-readable rule-based alert ─────────────────────────────────
    if (detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  RULE-ALERT  V" << bsm.vehicle_id
                     << "  pos=(" << bsm.pos_x << ", " << bsm.pos_y << ")"
                     << "  vel=(" << bsm.spd_x << ", " << bsm.spd_y << ")"
                     << "  ground_truth=" << (is_attack ? "MALICIOUS" : "legitimate")
                     << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Check whether vehicle at (px, py) is within RSU range
// ─────────────────────────────────────────────────────────────
static bool InRSURange(double px, double py)
{
    if (RSU_Nodes.GetN() == 0) return false;
    Ptr<MobilityModel> rsu_mob = RSU_Nodes.Get(0)->GetObject<MobilityModel>();
    if (!rsu_mob) return false;
    Vector rp = rsu_mob->GetPosition();
    return Dist2D(px, py, rp.x, rp.y) <= DSRC_RANGE_M;
}

// ─────────────────────────────────────────────────────────────
// Legitimate BSM sender
// ─────────────────────────────────────────────────────────────
static void VREM_SendLegit(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);

    g_oracle_attack_state[node->GetId()] = false;

    if (InRSURange(px, py)) {
        VREM_SendBsm(veh_idx, px, py, sx, sy);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 1: Constant Position
//
// VeReMi Type 1: attacker freezes its reported position at the
// first attack tick. All subsequent BSMs report the same (px, py).
// Velocity is broadcast truthfully, so position frozen + speed > 0
// is the detection signal.
// ─────────────────────────────────────────────────────────────
static void VREM_SendType1(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t  nid  = node->GetId();
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);
    double now = Simulator::Now().GetSeconds();

    if (!g_t1_frozen[nid]) {
        g_t1_frozen  [nid] = true;
        g_t1_freeze_x[nid] = px;
        g_t1_freeze_y[nid] = py;
        if (!pem_attack_active) {
            pem_attack_active     = true;
            pem_attack_start_time = now;
        }
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 1 (CONSTANT POSITION) BEGINS  V" << nid
                         << "\n  Real pos     : (" << px << ", " << py << ")\n"
                         << "  Frozen pos   : (" << g_t1_freeze_x[nid] << ", "
                                                  << g_t1_freeze_y[nid] << ")  [captured at activation]\n"
                         << "  Mechanism    : OBU locks GPS output to first-seen coordinate\n\n";
            g_attack_log.flush();
        }
    }

    g_oracle_attack_state[nid] = true;

    if (InRSURange(px, py)) {
        VREM_SendBsm(veh_idx, g_t1_freeze_x[nid], g_t1_freeze_y[nid], sx, sy);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 2: Constant Offset
//
// VeReMi Type 2: attacker adds a fixed (T2_offset_x, T2_offset_y)
// to its true position in every BSM. Velocity is broadcast truthfully.
// Position change between consecutive BSMs is physically consistent
// (same as real movement + constant bias), so rule-based detection
// fails — KNN+Bagging is needed.
// ─────────────────────────────────────────────────────────────
static void VREM_SendType2(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t  nid  = node->GetId();
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);
    double now = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 2 (CONSTANT OFFSET) BEGINS  V" << nid
                         << "\n  Fixed offset : (" << T2_offset_x << ", " << T2_offset_y << ") m\n"
                         << "  True pos     : (" << px << ", " << py << ")\n"
                         << "  Reported pos : (" << (px + T2_offset_x) << ", "
                                                  << (py + T2_offset_y) << ")\n"
                         << "  Mechanism    : OBU adds constant bias vector to GPS each BSM\n\n";
            g_attack_log.flush();
        }
    }

    g_oracle_attack_state[nid] = true;

    if (InRSURange(px, py)) {
        VREM_SendBsm(veh_idx, px + T2_offset_x, py + T2_offset_y, sx, sy);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 4: Random Position
//
// VeReMi Type 4: attacker broadcasts a uniformly random position
// from the simulation playground boundary every BSM.
// Produces large, physically impossible jumps — detected by Rule 2.
// ─────────────────────────────────────────────────────────────
static void VREM_SendType4(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t  nid  = node->GetId();
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);
    double now = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 4 (RANDOM POSITION) BEGINS  V" << nid
                         << "\n  Area      : [0, " << SIM_AREA_MAX << "] x [0, "
                                                    << SIM_AREA_MAX << "] m\n"
                         << "  Mechanism : OBU injects a fresh random (x,y) into every BSM\n\n";
            g_attack_log.flush();
        }
    }

    std::uniform_real_distribution<double> rand_coord(0.0, SIM_AREA_MAX);
    double fake_x = rand_coord(g_rng);
    double fake_y = rand_coord(g_rng);

    g_oracle_attack_state[nid] = true;

    if (InRSURange(px, py)) {
        VREM_SendBsm(veh_idx, fake_x, fake_y, sx, sy);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 8: Random Offset
//
// VeReMi Type 8: attacker adds a per-BSM random offset drawn
// uniformly from [-T8_max_offset, +T8_max_offset] in each axis.
// Position change between consecutive BSMs is often within plausible
// range (if offset is small), so rule-based detection misses it.
// KNN+Bagging handles it via the offset pattern in the feature vector.
// ─────────────────────────────────────────────────────────────
static void VREM_SendType8(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t  nid  = node->GetId();
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);
    double now = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 8 (RANDOM OFFSET) BEGINS  V" << nid
                         << "\n  Max offset   : +" << T8_max_offset << " m per axis\n"
                         << "  Mechanism    : OBU adds a fresh uniform random offset each BSM\n\n";
            g_attack_log.flush();
        }
    }

    std::uniform_real_distribution<double> rand_off(-T8_max_offset, T8_max_offset);
    double off_x = rand_off(g_rng);
    double off_y = rand_off(g_rng);

    g_oracle_attack_state[nid] = true;

    if (InRSURange(px, py)) {
        VREM_SendBsm(veh_idx, px + off_x, py + off_y, sx, sy);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 16: Eventual Stop
//
// VeReMi Type 16: the probability of the vehicle reporting a frozen
// position increases by T16_prob_inc per BSM tick (default 0.025).
// When a freeze decision fires (rand < prob), position is locked.
// Once frozen, the vehicle stays frozen for all subsequent BSMs.
// Models a compromised OBU that gradually loses GPS reliability
// until it completely stops updating.
//
// Legitimate ticks (pre-freeze) are labeled oracle=false.
// Frozen ticks are labeled oracle=true.
// ─────────────────────────────────────────────────────────────
static void VREM_SendType16(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t  nid  = node->GetId();
    double px, py, sx, sy;
    GetKinematics(node, px, py, sx, sy);
    double now = Simulator::Now().GetSeconds();

    // Initialise per-vehicle Type 16 state on first call
    if (g_t16_freeze_prob.find(nid) == g_t16_freeze_prob.end()) {
        g_t16_freeze_prob[nid] = 0.0;
        g_t16_is_frozen  [nid] = false;
        g_t16_freeze_x   [nid] = px;
        g_t16_freeze_y   [nid] = py;
    }

    // Increment freeze probability each tick
    g_t16_freeze_prob[nid] = std::min(1.0, g_t16_freeze_prob[nid] + T16_prob_inc);

    if (!g_t16_is_frozen[nid]) {
        std::uniform_real_distribution<double> uni(0.0, 1.0);
        if (uni(g_rng) < g_t16_freeze_prob[nid]) {
            // Vehicle freezes now — record freeze position
            g_t16_is_frozen[nid]  = true;
            g_t16_freeze_x [nid]  = px;
            g_t16_freeze_y [nid]  = py;
            if (!pem_attack_active) {
                pem_attack_active     = true;
                pem_attack_start_time = now;
            }
            if (g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                             << "]  ATTACK TYPE 16 (EVENTUAL STOP) FROZEN  V" << nid
                             << "\n  Freeze pos      : (" << g_t16_freeze_x[nid]
                                                           << ", " << g_t16_freeze_y[nid] << ")\n"
                             << "  Freeze prob now : " << g_t16_freeze_prob[nid] << "\n\n";
                g_attack_log.flush();
            }
        }
    }

    bool this_tick_attack = g_t16_is_frozen[nid];
    g_oracle_attack_state[nid] = this_tick_attack;

    if (InRSURange(px, py)) {
        if (this_tick_attack) {
            VREM_SendBsm(veh_idx, g_t16_freeze_x[nid], g_t16_freeze_y[nid], sx, sy);
        } else {
            VREM_SendBsm(veh_idx, px, py, sx, sy);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// One BSM tick — dispatches to the correct sender
// ─────────────────────────────────────────────────────────────
static void VREM_BsmTick(uint32_t veh_idx, double t_end)
{
    bool is_attacker = (attack_scenario != 0) &&
        std::find(g_attacker_indices.begin(), g_attacker_indices.end(), veh_idx)
            != g_attacker_indices.end();

    if (is_attacker) {
        switch (attack_scenario) {
            case 21: VREM_SendType1 (veh_idx); break;
            case 22: VREM_SendType2 (veh_idx); break;
            case 24: VREM_SendType4 (veh_idx); break;
            case 28: VREM_SendType8 (veh_idx); break;
            case 36: VREM_SendType16(veh_idx); break;
            default: VREM_SendLegit (veh_idx); break;
        }
    } else {
        VREM_SendLegit(veh_idx);
    }

    double next = Simulator::Now().GetSeconds() + BSM_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BSM_INTERVAL_S), &VREM_BsmTick, veh_idx, t_end);
    }
}

// ─────────────────────────────────────────────────────────────
// Build a lightweight P2P star topology (vehicle_i ↔ RSU) for
// NetAnim packet arrows and real UDP socket delivery.
// Uses subnet 10.2.(i+1).0/30 to avoid collision with multibsm (10.1.x).
// Same pattern as MBSM_SetupNetworkForAnim() in multibsm_attacks.cc.
// ─────────────────────────────────────────────────────────────
static void VREM_SetupNetwork()
{
    if (RSU_Nodes.GetN() == 0) return;

    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);
    internet.Install(RSU_Nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",   StringValue("1ms"));

    Ipv4AddressHelper addr;
    g_veh_ip_anim.resize(Vehicle_Nodes.GetN());

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i));
        pair.Add(RSU_Nodes.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);

        std::ostringstream base_ip;
        base_ip << "10.2." << (i + 1) << ".0";
        addr.SetBase(base_ip.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);

        g_veh_ip_anim[i] = ifaces.GetAddress(0);
        if (i == 0) {
            g_rsu_ip_anim = ifaces.GetAddress(1);   // RSU IP on first link
        }
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ── RSU BSM receive socket (port 7778) ────────────────────────────
    g_rsu_recv_socket = Socket::CreateSocket(
        RSU_Nodes.Get(0),
        TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&VREM_RSUSocketReceive));

    // ── PacketSink on port 9 so animation packets are accepted ─────────
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    ApplicationContainer rsuSink = sinkHelper.Install(RSU_Nodes.Get(0));
    rsuSink.Start(Seconds(0.0));
    rsuSink.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        ApplicationContainer vehSink = sinkHelper.Install(Vehicle_Nodes.Get(i));
        vehSink.Start(Seconds(0.0));
        vehSink.Stop(Seconds(simTime));
    }
}

// ─────────────────────────────────────────────────────────────
// Apply NetAnim node colours and labels
// Colour scheme: attacker=red, legit vehicle=green, RSU=amber
// ─────────────────────────────────────────────────────────────
static void VREM_SetupNetAnim()
{
    if (!g_anim) return;

    if (RSU_Nodes.GetN() > 0) {
        uint32_t rsu_id = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rsu_id, 255, 200, 0);
        g_anim->UpdateNodeSize (rsu_id, 35, 35);
        g_anim->UpdateNodeDescription(rsu_id, "RSU");
    }

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid = Vehicle_Nodes.Get(i)->GetId();
        bool is_attacker = (attack_scenario != 0) &&
            std::find(g_attacker_indices.begin(), g_attacker_indices.end(), i)
                != g_attacker_indices.end();
        if (is_attacker) {
            g_anim->UpdateNodeColor(nid, 255, 0, 0);
            g_anim->UpdateNodeSize (nid, 30, 30);
            g_anim->UpdateNodeDescription(nid, "ATTACKER");
        } else {
            g_anim->UpdateNodeColor(nid, 0, 200, 60);
            g_anim->UpdateNodeSize (nid, 20, 20);
            g_anim->UpdateNodeDescription(nid, "V" + std::to_string(i));
        }
    }

    g_anim->EnablePacketMetadata(true);
}

// ─────────────────────────────────────────────────────────────
// Open log files and write headers
// ─────────────────────────────────────────────────────────────
static void VREM_InitLogs()
{
    std::string log_filename;
    std::string attack_name;
    switch (attack_scenario) {
        case 21: log_filename = "veremi_attack21.txt";
                 attack_name  = "Type 1 — Constant Position";  break;
        case 22: log_filename = "veremi_attack22.txt";
                 attack_name  = "Type 2 — Constant Offset";    break;
        case 24: log_filename = "veremi_attack24.txt";
                 attack_name  = "Type 4 — Random Position";    break;
        case 28: log_filename = "veremi_attack28.txt";
                 attack_name  = "Type 8 — Random Offset";      break;
        case 36: log_filename = "veremi_attack36.txt";
                 attack_name  = "Type 16 — Eventual Stop";     break;
        default: log_filename = "veremi_baseline.txt";
                 attack_name  = "Baseline (No Attack)";         break;
    }

    g_attack_log.open(log_filename, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  VeReMi Position Falsification Attack Log\n"
        << "  Attack  : " << attack_name << "  (scenario " << attack_scenario << ")\n"
        << "  Based on: Mekonen, H.D. et al., PLOS ONE 2025\n"
        << "----------------------------------------------------------------\n"
        << "  Simulation time : " << simTime        << " s\n"
        << "  Vehicles        : " << N_Vehicles      << "\n"
        << "  RSUs            : " << N_RSUs          << "\n"
        << "  N_Attackers     : " << N_Attackers     << "\n";
    g_attack_log << "  Attacker nodes  : [";
    for (size_t k = 0; k < g_attacker_indices.size(); k++) {
        if (k) g_attack_log << ", ";
        g_attack_log << "V" << g_attacker_indices[k];
    }
    g_attack_log << "]\n"
        << "  Ground truth    : simulation oracle (not in BSM packets)\n"
        << "  BSM interval    : " << BSM_INTERVAL_S  << " s\n"
        << "  DSRC range      : " << DSRC_RANGE_M    << " m\n";
    if (attack_scenario == 22)
        g_attack_log << "  Offset          : (" << T2_offset_x << ", " << T2_offset_y << ") m\n";
    if (attack_scenario == 28)
        g_attack_log << "  Max offset      : ±" << T8_max_offset << " m per axis\n";
    if (attack_scenario == 36)
        g_attack_log << "  Prob increment  : " << T16_prob_inc << " per BSM tick\n";
    g_attack_log
        << "================================================================\n\n";
    g_attack_log.flush();

    // ── Consecutive BSM pair CSV ─────────────────────────────────────────
    // Columns match FEATURE_COLS in knn_bagging_detector.py
    g_pairs_csv.open("veremi_pairs.csv", std::ios::out | std::ios::trunc);
    g_pairs_csv
        << "vehicle_id,attack_type,sim_time_s,"
        << "pos_x1,pos_y1,spd_x1,spd_y1,"
        << "pos_x2,pos_y2,spd_x2,spd_y2,"
        << "time_interval,label\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary CSV and print to console
// Called at the end of the simulation
// ─────────────────────────────────────────────────────────────
static void VREM_WriteSummary()
{
    double tp = static_cast<double>(pem_tp);
    double tn = static_cast<double>(pem_tn);
    double fp = static_cast<double>(pem_fp);
    double fn = static_cast<double>(pem_fn);

    double mcc_denom = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc = (mcc_denom > 0.0) ? ((tp * tn - fp * fn) / mcc_denom) : 0.0;

    double total     = tp + tn + fp + fn;
    double accuracy  = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;
    double precision = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double recall    = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double f1        = (precision + recall > 0.0)
                       ? (2.0 * precision * recall / (precision + recall)) : 0.0;

    double tdet_ms = -1.0;
    if (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0)
        tdet_ms = (pem_first_alert_time - pem_attack_start_time) * 1000.0;

    uint64_t total_pairs = pem_tp + pem_tn + pem_fp + pem_fn;

    std::ofstream sum("veremi_pem_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,veremi_type,tp,tn,fp,fn,mcc,accuracy_pct,"
        << "precision,recall,f1,tdet_ms\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << "," << GetVeReMiType() << ","
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc << "," << accuracy << "," << precision << ","
        << recall << "," << f1 << "," << tdet_ms << "\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n====== RUN SUMMARY (rule-based detector) ======\n"
            << "  NOTE: Full KNN+Bagging detection via Python:\n"
            << "    python3 knn_bagging_detector.py veremi_pairs.csv\n"
            << "------------------------------------------------\n"
            << "  attack_scenario : " << attack_scenario
            << "  (VeReMi Type "  << GetVeReMiType() << ")\n"
            << "  TP / TN / FP / FN : "
            << pem_tp << " / " << pem_tn << " / " << pem_fp << " / " << pem_fn << "\n"
            << "  MCC       : " << std::fixed << std::setprecision(3) << mcc  << "\n"
            << "  Accuracy  : " << accuracy   << " %\n"
            << "  Precision : " << precision  << "\n"
            << "  Recall    : " << recall     << "\n"
            << "  F1        : " << f1         << "\n"
            << "  Tdet      : " << tdet_ms    << " ms\n"
            << "  Pair CSV  : veremi_pairs.csv  (" << total_pairs << " pairs)\n"
            << "================================================\n";
        g_attack_log.flush();
    }

    std::cout << "\n[VeReMi] Summary written to veremi_pem_summary.csv\n"
              << "  Scenario " << attack_scenario
              << "  (VeReMi Type " << GetVeReMiType() << ")\n"
              << "  TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp  << " FN=" << pem_fn << "\n"
              << "  MCC=" << std::fixed << std::setprecision(3) << mcc
              << "  Acc=" << accuracy << "% F1=" << f1 << "\n"
              << "  Consecutive pair CSV: veremi_pairs.csv  ("
              << total_pairs << " pairs)\n"
              << "  Run: python3 knn_bagging_detector.py veremi_pairs.csv\n";
}

// ─────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",
                 "Simulation duration (s)",
                 simTime);
    cmd.AddValue("N_Vehicles",
                 "Number of vehicle nodes",
                 N_Vehicles);
    cmd.AddValue("N_RSUs",
                 "Number of RSU nodes (0 or 1 supported)",
                 N_RSUs);
    cmd.AddValue("attack_scenario",
                 "21=Type1, 22=Type2, 24=Type4, 28=Type8, 36=Type16, 0=baseline",
                 attack_scenario);
    cmd.AddValue("attacker_idx",
                 "0-based index of the malicious vehicle (when N_Attackers=1)",
                 attacker_idx);
    cmd.AddValue("N_Attackers",
                 "Number of malicious vehicles (default 1)",
                 N_Attackers);
    cmd.AddValue("T2_offset_x",
                 "Type 2: constant x-offset added to GPS (m)",
                 T2_offset_x);
    cmd.AddValue("T2_offset_y",
                 "Type 2: constant y-offset added to GPS (m)",
                 T2_offset_y);
    cmd.AddValue("T8_max_offset",
                 "Type 8: uniform random offset half-width per axis (m)",
                 T8_max_offset);
    cmd.AddValue("T16_prob_inc",
                 "Type 16: freeze probability increment per BSM tick",
                 T16_prob_inc);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 1)             N_Vehicles   = 1;
    if (N_RSUs > 1)                 N_RSUs        = 1;
    if (N_Attackers > N_Vehicles)   N_Attackers   = N_Vehicles;
    if (attacker_idx >= N_Vehicles) attacker_idx  = 0;

    // Build attacker index list
    // N_Attackers=1: use attacker_idx (command-line selectable specific vehicle)
    // N_Attackers>1: assign first N_Attackers vehicles as attackers
    g_attacker_indices.clear();
    if (attack_scenario != 0) {
        if (N_Attackers == 1) {
            g_attacker_indices.push_back(attacker_idx);
        } else {
            for (uint32_t k = 0; k < N_Attackers; k++) {
                g_attacker_indices.push_back(k);
            }
        }
    }

    VREM_InitLogs();

    std::cout << "\n======== VeReMi Attack Simulation ========\n"
              << "  attack_scenario  : " << attack_scenario
              << "  (VeReMi Type " << GetVeReMiType() << ")\n"
              << "  N_Vehicles       : " << N_Vehicles   << "\n"
              << "  N_Attackers      : " << N_Attackers  << "\n"
              << "  N_RSUs           : " << N_RSUs       << "\n"
              << "  simTime          : " << simTime      << " s\n";
    std::cout << "  Attacker indices : [";
    for (size_t k = 0; k < g_attacker_indices.size(); k++) {
        if (k) std::cout << ", ";
        std::cout << g_attacker_indices[k];
    }
    std::cout << "]\n";
    if (attack_scenario == 22)
        std::cout << "  T2_offset        : (" << T2_offset_x << ", " << T2_offset_y << ") m\n";
    if (attack_scenario == 28)
        std::cout << "  T8_max_offset    : ±" << T8_max_offset << " m\n";
    if (attack_scenario == 36)
        std::cout << "  T16_prob_inc     : " << T16_prob_inc << "/tick\n";
    std::cout << "  Ground truth     : oracle (not in BSM packets)\n"
              << "==========================================\n\n";

    // ── Create nodes ─────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(1);

    // ── Vehicle mobility — ConstantVelocityMobilityModel ─────
    // Vehicles spread along an x-axis road; each in its own lane (y = i*10 m)
    // Speeds range uniformly from MIN_SPEED_MS to MAX_SPEED_MS
    MobilityHelper mobVeh;
    mobVeh.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobVeh.Install(Vehicle_Nodes);

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Ptr<ConstantVelocityMobilityModel> mob =
            DynamicCast<ConstantVelocityMobilityModel>(
                Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
        if (!mob) continue;

        double start_x = 50.0 + i * 60.0;
        double lane_y  = static_cast<double>(i) * 10.0;
        double spd_i   = (N_Vehicles > 1)
            ? (MIN_SPEED_MS + (MAX_SPEED_MS - MIN_SPEED_MS) *
               (static_cast<double>(i) / (N_Vehicles - 1)))
            : MIN_SPEED_MS;

        mob->SetPosition(Vector(start_x, lane_y, 0.0));
        mob->SetVelocity(Vector(spd_i,   0.0,    0.0));
    }

    // ── RSU mobility — fixed at road centre ──────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobRsu;
        mobRsu.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobRsu.Install(RSU_Nodes);

        Ptr<ConstantPositionMobilityModel> rsu_mob =
            DynamicCast<ConstantPositionMobilityModel>(
                RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (rsu_mob) {
            double centre_x = 50.0 + (N_Vehicles / 2.0) * 60.0;
            double centre_y = (N_Vehicles > 1)
                ? ((N_Vehicles - 1) * 10.0 / 2.0) : 0.0;
            rsu_mob->SetPosition(Vector(centre_x, centre_y, 0.0));
        }
    }

    // ── Setup P2P star network and RSU receive socket ─────────
    VREM_SetupNetwork();

    // ── Schedule BSM ticks for all vehicles ──────────────────
    // Staggered 1 ms per vehicle to avoid collision at t=0
    double t_bsm_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        double t_start = 0.1 + i * 0.001;
        Simulator::Schedule(Seconds(t_start), &VREM_BsmTick, i, t_bsm_end);
    }

    // ── Write summary at simulation end ──────────────────────
    Simulator::Schedule(Seconds(simTime - 0.05), &VREM_WriteSummary);

    // ── NetAnim animation file ────────────────────────────────
    std::string anim_xml = "veremi_anim_scenario"
                           + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    VREM_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim;
    g_anim = nullptr;

    if (g_attack_log.is_open()) g_attack_log.close();
    if (g_pairs_csv.is_open())  g_pairs_csv.close();

    return 0;
}
