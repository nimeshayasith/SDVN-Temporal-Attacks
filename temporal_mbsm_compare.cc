// ============================================================
// temporal_mbsm_compare.cc
// Temporal-Echo Attack Simulation — Multi-BSM Detection Comparison
//
// Implements all 12 Temporal-Echo attack scenarios with the
// EXACT SAME detection algorithm as multibsm_attacks.cc:
//   Algorithm 1 (MBSM_Detect) — Trabelsi et al., Electronics 2022
//   COPIED VERBATIM — no changes to detection logic.
//
// Attack families:
//   Scenarios 1-4  (TTW S1-S4)  : Topology Time-Warp
//     Attacker replays old stored position → backward jump in BSM stream
//   Scenarios 5-8  (BSHH S1-S4) : Beacon-State Heartbeat Hijack
//     Attacker impersonates victim vehicle with old stored position → impossible jump
//   Scenarios 9-12 (ME S1-S4)   : Multipath Echo
//     Echo vehicles teleport to link endpoint positions → impossible jump
//
// All three families produce BSM-level position anomalies detectable
// by the unmodified Multi-BSM physics rules (frozen-position + impossible-jump).
//
// TypeId "TempBsmTag" — avoids NS-3 collision with "BsmTag" in multibsm_attacks.cc
// Port 7783, Subnet 10.5.x — distinct from all other simulation files.
//
// Copy to ns-3.35/scratch/ and build:
//   ./waf build
//
// Run examples:
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=1"
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=5"
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=25 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=9"
//   ./waf --run "scratch/temporal_mbsm_compare --simTime=40 --N_Vehicles=4 --N_RSUs=1 --attack_scenario=0"
//
// Output files:
//   temporal_mbsm_compare_attack{1..12}.txt  — human-readable attack log
//   temporal_mbsm_compare_events.csv         — per-BSM event log (same format as multibsm_events.csv)
//   temporal_mbsm_compare_summary.csv        — detection metrics summary
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
#include <random>
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

// ── BSM and channel constants (same as multibsm_attacks.cc) ────
static const double BSM_INTERVAL_S   = 0.050;
static const double DSRC_RANGE_M     = 250.0;
static const double MIN_SPEED_MS     = 12.0;
static const double MAX_SPEED_MS     = 20.0;
static const double SAFETY_FACTOR    = 1.5;
static const double POS_FROZEN_EPS_M = 0.05;
static const double SPEED_ZERO_THR   = 0.5;
static const uint32_t HISTORY_DEPTH  = 5;

// ── Temporal attack timing constants ───────────────────────────
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

// ── BSM record — one snapshot stored at the RSU ─────────────────
struct BsmRecord {
    uint32_t vehicle_id;
    double   pos_x;
    double   pos_y;
    double   speed_ms;
    double   direction;
    double   timestamp;
    bool     is_falsified;
};

// ── RSU per-vehicle BSM history ──────────────────────────────────
static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;

// ── PEM metric counters ──────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;
static bool     pem_attack_active     = false;

// ── Simulation oracle ────────────────────────────────────────────
static std::map<uint32_t, bool> g_oracle_attack_state;

// ── TTW attack state ─────────────────────────────────────────────
static bool   g_ttw_stored    = false;
static double g_ttw_stored_x  = 0.0;
static double g_ttw_stored_y  = 0.0;
static bool   g_ttw_attack_on = false;

// ── BSHH attack state ────────────────────────────────────────────
static uint32_t g_bshh_victim_ns3id  = 0;
static bool     g_bshh_stored        = false;
static double   g_bshh_stored_x      = 0.0;
static double   g_bshh_stored_y      = 0.0;
static double   g_bshh_stored_speed  = 0.0;
static double   g_bshh_stored_dir    = 0.0;
static bool     g_bshh_attack_on     = false;

// ── ME attack state ──────────────────────────────────────────────
static bool   g_me_stored    = false;
static double g_me_link0_x   = 0.0;
static double g_me_link0_y   = 0.0;
static double g_me_link1_x   = 0.0;
static double g_me_link1_y   = 0.0;
static bool   g_me_attack_on = false;

// ── Output streams ───────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_events_csv;

// ── NetAnim / network state ──────────────────────────────────────
static AnimationInterface*      g_anim           = nullptr;
static Ipv4Address              g_rsu_ip_anim;
static std::vector<Ipv4Address> g_veh_ip_anim;
static Ptr<Socket>              g_rsu_recv_socket = nullptr;

// ── Random engine ────────────────────────────────────────────────
static std::mt19937 g_rng(22345);

// ── BSM protocol port (7783 — distinct from all other files) ─────
static const uint16_t BSM_PORT = 7783;

// ─────────────────────────────────────────────────────────────
// TempBsmTag — NS-3 Tag for temporal-compare BSM packets
//
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

// ─────────────────────────────────────────────────────────────
// RSU Multi-BSM detection algorithm
// ═══════════════════════════════════════════════════════════════
// VERBATIM COPY from multibsm_attacks.cc — NOT MODIFIED.
// Algorithm 1 of Trabelsi et al., Electronics 2022, 11, 3282.
// ═══════════════════════════════════════════════════════════════
static bool MBSM_Detect(const BsmRecord& bsm)
{
    auto& hist = g_bsm_history[bsm.vehicle_id];

    if (hist.empty()) {
        hist.push_back(bsm);
        return false;
    }

    const BsmRecord& prev = hist.back();
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) {
        return false;
    }

    double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);

    // ── Trigger A: position frozen but speed is non-zero
    if (pos_change < POS_FROZEN_EPS_M && bsm.speed_ms > SPEED_ZERO_THR) {
        return true;
    }

    // ── Trigger B: physically impossible displacement
    double max_possible = bsm.speed_ms * dt * SAFETY_FACTOR;
    if (max_possible > 0.0 && pos_change > max_possible) {
        return true;
    }

    // Legitimate — update history
    hist.push_back(bsm);
    if (hist.size() > HISTORY_DEPTH) {
        hist.pop_front();
    }
    return false;
}

// Forward declaration
static void TEMP_RSUReceive(BsmRecord bsm);

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
        bsm.vehicle_id   = tag.GetVehicleId();
        bsm.pos_x        = tag.GetPosX();
        bsm.pos_y        = tag.GetPosY();
        bsm.speed_ms     = tag.GetSpeed();
        bsm.direction    = tag.GetDirection();
        bsm.timestamp    = tag.GetTimestamp();
        bsm.is_falsified = g_oracle_attack_state.count(bsm.vehicle_id) &&
                           g_oracle_attack_state[bsm.vehicle_id];

        TEMP_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// Create and send a TempBsmTag packet (physical sender's node ID)
// ─────────────────────────────────────────────────────────────
static void TEMP_SendBsm(uint32_t veh_idx,
                          double px, double py,
                          double spd, double dir)
{
    if (g_rsu_recv_socket == nullptr)     return;
    if (veh_idx >= Vehicle_Nodes.GetN())  return;

    Ptr<Node> src = Vehicle_Nodes.Get(veh_idx);
    TypeId udp_tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(src, udp_tid);
    sock->Connect(InetSocketAddress(g_rsu_ip_anim, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TempBsmTag tag;
    tag.SetVehicleId (src->GetId());
    tag.SetPosX      (px);
    tag.SetPosY      (py);
    tag.SetSpeed     (spd);
    tag.SetDirection (dir);
    tag.SetTimestamp (Simulator::Now().GetSeconds());
    pkt->AddPacketTag(tag);

    sock->Send (pkt);
    sock->Close();
}

// ─────────────────────────────────────────────────────────────
// Send with a claimed (spoofed) vehicle ID — for BSHH impersonation
// ─────────────────────────────────────────────────────────────
static void TEMP_SendBsmAs(uint32_t physical_sender_idx,
                            uint32_t claimed_vehicle_id,
                            double px, double py,
                            double spd, double dir)
{
    if (g_rsu_recv_socket == nullptr)               return;
    if (physical_sender_idx >= Vehicle_Nodes.GetN()) return;

    Ptr<Node> src = Vehicle_Nodes.Get(physical_sender_idx);
    TypeId udp_tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(src, udp_tid);
    sock->Connect(InetSocketAddress(g_rsu_ip_anim, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TempBsmTag tag;
    tag.SetVehicleId (claimed_vehicle_id);   // ← spoofed victim ID
    tag.SetPosX      (px);
    tag.SetPosY      (py);
    tag.SetSpeed     (spd);
    tag.SetDirection (dir);
    tag.SetTimestamp (Simulator::Now().GetSeconds());
    pkt->AddPacketTag(tag);

    sock->Send (pkt);
    sock->Close();
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler: run detection, update PEM, write event log
// ─────────────────────────────────────────────────────────────
static void TEMP_RSUReceive(BsmRecord bsm)
{
    double now            = Simulator::Now().GetSeconds();
    bool   is_attack      = bsm.is_falsified;
    bool   anomaly_raised = MBSM_Detect(bsm);

    if (anomaly_raised && pem_first_alert_time < 0.0 && is_attack) {
        pem_first_alert_time = now;
    }

    if (is_attack) {
        if (anomaly_raised) { pem_tp++; } else { pem_fn++; }
    } else {
        if (anomaly_raised) { pem_fp++; } else { pem_tn++; }
    }

    if (g_events_csv.is_open()) {
        g_events_csv << std::fixed << std::setprecision(3)
                     << now                << ","
                     << bsm.vehicle_id     << ","
                     << bsm.pos_x          << ","
                     << bsm.pos_y          << ","
                     << bsm.speed_ms       << ","
                     << bsm.direction      << ","
                     << (is_attack      ? 1 : 0) << ","
                     << (anomaly_raised ? 1 : 0) << "\n";
    }

    if (anomaly_raised && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ALERT  V" << bsm.vehicle_id
                     << "  pos=(" << bsm.pos_x << ", " << bsm.pos_y << ")"
                     << "  speed=" << bsm.speed_ms << " m/s"
                     << "  ground_truth=" << (is_attack ? "MALICIOUS" : "legitimate")
                     << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// RSU range check
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
static void TEMP_SendLegit(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, spd, dir;
    GetKinematics(node, px, py, spd, dir);

    g_oracle_attack_state[node->GetId()] = false;

    if (InRSURange(px, py)) {
        TEMP_SendBsm(veh_idx, px, py, spd, dir);
    }
}

// ─────────────────────────────────────────────────────────────
// TTW attack sender (scenarios 1-4)
//
// Temporal Time-Warp at BSM level:
//   Pre-attack  (t < TTW_HELLO_TIME) : legitimate BSMs
//   Store phase (t >= TTW_HELLO_TIME): record attacker's position (once)
//   Gap phase   (t < TTW_REPLAY_TIME): legitimate BSMs continue
//   Replay phase(t >= TTW_REPLAY_TIME): send FROZEN stored position
//
// The RSU sees: ...(legit at t=19.95)...(frozen old pos at t=20.0)
// pos_change >> max_possible → MBSM_Detect Trigger B fires.
// ─────────────────────────────────────────────────────────────
static void TEMP_SendTTW(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, spd, dir;
    GetKinematics(node, px, py, spd, dir);
    double now = Simulator::Now().GetSeconds();

    // Store position at HELLO_TIME (once)
    if (!g_ttw_stored && now >= TTW_HELLO_TIME) {
        g_ttw_stored   = true;
        g_ttw_stored_x = px;
        g_ttw_stored_y = py;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  TTW HELLO: V" << node->GetId()
                         << " stores pos=(" << px << ", " << py << ")\n";
            g_attack_log.flush();
        }
    }

    if (now >= TTW_REPLAY_TIME) {
        if (!g_ttw_attack_on) {
            g_ttw_attack_on       = true;
            pem_attack_active     = true;
            pem_attack_start_time = now;
            if (g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                             << "]  TTW REPLAY BEGINS  V" << node->GetId()
                             << "\n  Real position    : (" << px << ", " << py << ")\n"
                             << "  Replayed position: (" << g_ttw_stored_x << ", "
                             << g_ttw_stored_y << ")  [stored at t=" << TTW_HELLO_TIME << "]\n"
                             << "  Mechanism        : Temporal topology replay\n\n";
                g_attack_log.flush();
            }
        }

        // Oracle: attack tick
        g_oracle_attack_state[node->GetId()] = true;

        if (InRSURange(px, py)) {
            // Send frozen old position with real current speed
            // → backward teleportation → MBSM_Detect Trigger B fires
            TEMP_SendBsm(veh_idx, g_ttw_stored_x, g_ttw_stored_y, spd, dir);
        }
    } else {
        // Legitimate phase
        g_oracle_attack_state[node->GetId()] = false;
        if (InRSURange(px, py)) {
            TEMP_SendBsm(veh_idx, px, py, spd, dir);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// BSHH attack sender — attacker side (scenarios 5-8)
//
// Beacon-State Heartbeat Hijack at BSM level:
//   Store phase  (t >= BSHH_STORE_TIME) : V1 records V0's pos (once)
//   Replay phase (t >= BSHH_REPLAY_TIME): V1 sends BSM with V0 ID + old pos
//
// The RSU sees V0's ID with an old position:
//   previous V0 legit BSM at t≈9.95, pos = V0_at_9.95
//   attack BSM at t=10.0 with V0.ID, pos = V0_at_4.0 (stored)
// pos_change >> max_possible → MBSM_Detect Trigger B fires.
// ─────────────────────────────────────────────────────────────
static void TEMP_SendBSHH(uint32_t attacker_veh_idx)
{
    Ptr<Node> attacker = Vehicle_Nodes.Get(attacker_veh_idx);
    double att_px, att_py, att_spd, att_dir;
    GetKinematics(attacker, att_px, att_py, att_spd, att_dir);
    double now = Simulator::Now().GetSeconds();

    // Store victim's position at BSHH_STORE_TIME (once)
    if (!g_bshh_stored && now >= BSHH_STORE_TIME) {
        if (Vehicle_Nodes.GetN() > 0) {
            Ptr<Node> victim = Vehicle_Nodes.Get(0);   // victim = V0
            g_bshh_victim_ns3id = victim->GetId();
            double vx, vy, vs, vd;
            GetKinematics(victim, vx, vy, vs, vd);
            g_bshh_stored       = true;
            g_bshh_stored_x     = vx;
            g_bshh_stored_y     = vy;
            g_bshh_stored_speed = vs;
            g_bshh_stored_dir   = vd;
            if (g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                             << "]  BSHH STORE: V" << attacker->GetId()
                             << " captures V" << g_bshh_victim_ns3id
                             << " pos=(" << vx << ", " << vy << ")\n";
                g_attack_log.flush();
            }
        }
    }

    if (now >= BSHH_REPLAY_TIME && g_bshh_stored) {
        if (!g_bshh_attack_on) {
            g_bshh_attack_on      = true;
            pem_attack_active     = true;
            pem_attack_start_time = now;
            if (g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                             << "]  BSHH REPLAY BEGINS\n"
                             << "  Attacker         : V" << attacker->GetId() << "\n"
                             << "  Impersonating    : V" << g_bshh_victim_ns3id << "\n"
                             << "  Stored victim pos: (" << g_bshh_stored_x
                             << ", " << g_bshh_stored_y
                             << ")  [captured at t=" << BSHH_STORE_TIME << "]\n"
                             << "  Mechanism        : Identity spoofing with stale position\n\n";
                g_attack_log.flush();
            }
        }

        // Oracle: victim's ID is under attack this tick
        g_oracle_attack_state[g_bshh_victim_ns3id] = true;

        if (InRSURange(att_px, att_py)) {
            // Send BSM claiming victim's ID with victim's OLD stored position
            TEMP_SendBsmAs(attacker_veh_idx,
                           g_bshh_victim_ns3id,
                           g_bshh_stored_x, g_bshh_stored_y,
                           g_bshh_stored_speed, g_bshh_stored_dir);
        }
    } else {
        // Pre-attack: attacker sends legitimate BSMs under its own ID
        g_oracle_attack_state[attacker->GetId()] = false;
        if (InRSURange(att_px, att_py)) {
            TEMP_SendBsm(attacker_veh_idx, att_px, att_py, att_spd, att_dir);
        }
    }
}

// ─────────────────────────────────────────────────────────────
// ME echo sender (scenarios 9-12)
//
// Multipath Echo at BSM level:
//   V2 and V3 echo V0↔V1 link by teleporting to their positions
//
// The RSU sees V2's history:
//   previous V2 BSM at t=10.0, pos = V2_real (e.g. x≈347m)
//   echo BSM at t=10.1, V2 claims pos = V0_at_10.0 (e.g. x≈170m)
// Huge backward jump → MBSM_Detect Trigger B fires.
// ─────────────────────────────────────────────────────────────
static void TEMP_SendME(uint32_t echo_veh_idx)
{
    if (!g_me_stored) return;

    Ptr<Node> echo_node = Vehicle_Nodes.Get(echo_veh_idx);
    double real_px, real_py, real_spd, real_dir;
    GetKinematics(echo_node, real_px, real_py, real_spd, real_dir);
    double now = Simulator::Now().GetSeconds();

    if (!g_me_attack_on) {
        g_me_attack_on        = true;
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ME ECHO BEGINS  V" << echo_node->GetId()
                         << "\n  Real pos    : (" << real_px << ", " << real_py << ")\n"
                         << "  Echo target : V0 at (" << g_me_link0_x << ", " << g_me_link0_y << ")\n"
                         << "  Mechanism   : Echo vehicle claims link endpoint position\n\n";
            g_attack_log.flush();
        }
    }

    // Oracle: echo BSM is an attack
    g_oracle_attack_state[echo_node->GetId()] = true;

    if (InRSURange(real_px, real_py)) {
        // V2 (even index) echoes V0's position; V3 (odd index) echoes V1's position
        double echo_x = (echo_veh_idx % 2 == 0) ? g_me_link0_x : g_me_link1_x;
        double echo_y = (echo_veh_idx % 2 == 0) ? g_me_link0_y : g_me_link1_y;
        TEMP_SendBsm(echo_veh_idx, echo_x, echo_y, real_spd, real_dir);
    }
}

// ─────────────────────────────────────────────────────────────
// Capture V0 and V1 positions for ME echo (called once at ME_LEGIT_TIME)
// ─────────────────────────────────────────────────────────────
static void TEMP_StoreMELinkPositions()
{
    if (Vehicle_Nodes.GetN() < 2) return;

    Ptr<Node> v0 = Vehicle_Nodes.Get(0);
    Ptr<Node> v1 = Vehicle_Nodes.Get(1);
    double spd, dir;

    GetKinematics(v0, g_me_link0_x, g_me_link0_y, spd, dir);
    GetKinematics(v1, g_me_link1_x, g_me_link1_y, spd, dir);
    g_me_stored = true;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3)
                     << Simulator::Now().GetSeconds()
                     << "]  ME LINK ESTABLISHED: V0=(" << g_me_link0_x
                     << ", " << g_me_link0_y << ")  V1=("
                     << g_me_link1_x << ", " << g_me_link1_y << ")\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// One BSM tick — dispatches to correct sender for this scenario
// ─────────────────────────────────────────────────────────────
static void TEMP_BsmTick(uint32_t veh_idx, double t_end)
{
    double now = Simulator::Now().GetSeconds();

    bool is_ttw_attacker  = (attack_scenario >= 1 && attack_scenario <= 4)  && (veh_idx == 0);
    bool is_bshh_attacker = (attack_scenario >= 5 && attack_scenario <= 8)  && (veh_idx == 1);
    bool is_me_echo       = (attack_scenario >= 9 && attack_scenario <= 12)
                             && (veh_idx == 2 || veh_idx == 3)
                             && (now >= ME_ECHO_TIME);

    if (is_ttw_attacker) {
        TEMP_SendTTW(veh_idx);
    } else if (is_bshh_attacker) {
        TEMP_SendBSHH(veh_idx);
    } else if (is_me_echo) {
        TEMP_SendME(veh_idx);
    } else {
        TEMP_SendLegit(veh_idx);
    }

    double next = now + BSM_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BSM_INTERVAL_S),
                            &TEMP_BsmTick, veh_idx, t_end);
    }
}

// ─────────────────────────────────────────────────────────────
// Build P2P star topology for NetAnim and real UDP socket delivery
// Subnet 10.5.(i+1).0/30 — distinct from all other simulation files
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
    g_veh_ip_anim.resize(Vehicle_Nodes.GetN());

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i));
        pair.Add(RSU_Nodes.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);

        std::ostringstream base_ip;
        base_ip << "10.5." << (i + 1) << ".0";
        addr.SetBase(base_ip.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);

        g_veh_ip_anim[i] = ifaces.GetAddress(0);
        if (i == 0) {
            g_rsu_ip_anim = ifaces.GetAddress(1);
        }
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_rsu_recv_socket = Socket::CreateSocket(
        RSU_Nodes.Get(0),
        TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&TEMP_RSUSocketReceive));

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
// Apply NetAnim node colours
// ─────────────────────────────────────────────────────────────
static void TEMP_SetupNetAnim()
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
        bool is_atk = false;

        if (attack_scenario >= 1 && attack_scenario <= 4)  is_atk = (i == 0);
        if (attack_scenario >= 5 && attack_scenario <= 8)  is_atk = (i == 1);
        if (attack_scenario >= 9 && attack_scenario <= 12) is_atk = (i == 2 || i == 3);

        if (is_atk) {
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
// Scenario name helpers
// ─────────────────────────────────────────────────────────────
static std::string GetAttackFamilyName(uint32_t sc)
{
    if (sc >= 1  && sc <= 4)  return "TTW (Topology Time-Warp)";
    if (sc >= 5  && sc <= 8)  return "BSHH (Beacon-State Heartbeat Hijack)";
    if (sc >= 9  && sc <= 12) return "ME (Multipath Echo)";
    return "Baseline (No Attack)";
}

static std::string GetScenarioVariantName(uint32_t sc)
{
    switch (sc) {
        case 1:  return "TTW-S1: Malicious Vehicle, No RSU";
        case 2:  return "TTW-S2: Malicious RSU";
        case 3:  return "TTW-S3: Malicious Controller, No RSU";
        case 4:  return "TTW-S4: Malicious Controller, With RSU";
        case 5:  return "BSHH-S1: Malicious Vehicle, No RSU";
        case 6:  return "BSHH-S2: Malicious RSU";
        case 7:  return "BSHH-S3: Malicious Controller, No RSU";
        case 8:  return "BSHH-S4: Malicious Controller, With RSU";
        case 9:  return "ME-S1: Malicious Vehicles, No RSU";
        case 10: return "ME-S2: Malicious RSU";
        case 11: return "ME-S3: Malicious Controller, No RSU";
        case 12: return "ME-S4: Malicious Controller, With RSU";
        default: return "Baseline";
    }
}

// ─────────────────────────────────────────────────────────────
// Open log files and write headers
// ─────────────────────────────────────────────────────────────
static void TEMP_InitLogs()
{
    std::string log_filename;
    if (attack_scenario == 0) {
        log_filename = "temporal_mbsm_compare_baseline.txt";
    } else {
        log_filename = "temporal_mbsm_compare_attack"
                       + std::to_string(attack_scenario) + ".txt";
    }

    g_attack_log.open(log_filename, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Temporal-Echo Attack — Multi-BSM Detection Comparison\n"
        << "  Attack  : " << GetScenarioVariantName(attack_scenario) << "\n"
        << "  Family  : " << GetAttackFamilyName(attack_scenario) << "\n"
        << "  Detector: Multi-BSM Algorithm 1 (Trabelsi et al., Electronics 2022)\n"
        << "  NOTE    : MBSM_Detect function COPIED VERBATIM — no changes\n"
        << "----------------------------------------------------------------\n"
        << "  Simulation time : " << simTime    << " s\n"
        << "  Vehicles        : " << N_Vehicles  << "\n"
        << "  RSUs            : " << N_RSUs      << "\n";
    if (attack_scenario >= 1 && attack_scenario <= 4) {
        g_attack_log
            << "  TTW attacker    : V0 (vehicle index 0)\n"
            << "  HELLO time      : " << TTW_HELLO_TIME << " s\n"
            << "  Link break      : " << TTW_LINK_BREAK << " s\n"
            << "  Replay time     : " << TTW_REPLAY_TIME << " s\n";
    } else if (attack_scenario >= 5 && attack_scenario <= 8) {
        g_attack_log
            << "  BSHH attacker   : V1 (vehicle index 1)\n"
            << "  BSHH victim     : V0 (vehicle index 0)\n"
            << "  Store time      : " << BSHH_STORE_TIME << " s\n"
            << "  Replay time     : " << BSHH_REPLAY_TIME << " s\n";
    } else if (attack_scenario >= 9 && attack_scenario <= 12) {
        g_attack_log
            << "  ME echo vehicles: V2, V3 (indices 2, 3)\n"
            << "  Real link       : V0 <-> V1\n"
            << "  Legit time      : " << ME_LEGIT_TIME << " s\n"
            << "  Echo start      : " << ME_ECHO_TIME << " s\n";
    }
    g_attack_log
        << "  Ground truth    : simulation oracle (not in BSM packets)\n"
        << "  BSM interval    : " << BSM_INTERVAL_S << " s\n"
        << "  DSRC range      : " << DSRC_RANGE_M   << " m\n"
        << "================================================================\n\n";
    g_attack_log.flush();

    g_events_csv.open("temporal_mbsm_compare_events.csv",
                      std::ios::out | std::ios::trunc);
    g_events_csv
        << "sim_time_s,vehicle_id,reported_pos_x,reported_pos_y,"
        << "speed_ms,direction_rad,is_attack,alert_raised\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary and print to console
// ─────────────────────────────────────────────────────────────
static void TEMP_WriteSummary()
{
    double tp = static_cast<double>(pem_tp);
    double tn = static_cast<double>(pem_tn);
    double fp = static_cast<double>(pem_fp);
    double fn = static_cast<double>(pem_fn);

    double mcc_denom = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc       = (mcc_denom > 0.0) ? ((tp * tn - fp * fn) / mcc_denom) : 0.0;
    double total     = tp + tn + fp + fn;
    double acr       = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;
    double precision = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double recall    = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;

    double tdet_ms = -1.0;
    if (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0) {
        tdet_ms = (pem_first_alert_time - pem_attack_start_time) * 1000.0;
    }

    std::ofstream sum("temporal_mbsm_compare_summary.csv",
                      std::ios::out | std::ios::trunc);
    sum << "attack_scenario,scenario_name,tp,tn,fp,fn,mcc,acr_pct,precision,recall,tdet_ms\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << "\"" << GetScenarioVariantName(attack_scenario) << "\","
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc << "," << acr << "," << precision << "," << recall << ","
        << tdet_ms << "\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n========== RUN SUMMARY ==========\n"
            << "  Detector        : Multi-BSM MBSM_Detect (verbatim copy)\n"
            << "  attack_scenario : " << attack_scenario
            << "  (" << GetScenarioVariantName(attack_scenario) << ")\n"
            << "  TP              : " << pem_tp   << "\n"
            << "  TN              : " << pem_tn   << "\n"
            << "  FP              : " << pem_fp   << "\n"
            << "  FN              : " << pem_fn   << "\n"
            << "  MCC             : " << std::fixed << std::setprecision(3) << mcc << "\n"
            << "  ACR             : " << acr       << " %\n"
            << "  Precision       : " << precision << "\n"
            << "  Recall          : " << recall    << "\n"
            << "  Tdet            : " << tdet_ms   << " ms\n"
            << "==================================\n";
        g_attack_log.flush();
    }

    std::cout << "\n[TemporalMbsmCompare] Summary written to temporal_mbsm_compare_summary.csv\n"
              << "  " << GetScenarioVariantName(attack_scenario) << "\n"
              << "  TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp << " FN=" << pem_fn << "\n"
              << "  MCC=" << std::fixed << std::setprecision(3) << mcc
              << "  ACR=" << acr << "%"
              << "  Tdet=" << tdet_ms << " ms\n";
}

// ─────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",         "Simulation duration (s)",                      simTime);
    cmd.AddValue("N_Vehicles",      "Number of vehicle nodes",                      N_Vehicles);
    cmd.AddValue("N_RSUs",          "Number of RSU nodes (0 or 1 supported)",       N_RSUs);
    cmd.AddValue("attack_scenario", "1-4=TTW, 5-8=BSHH, 9-12=ME, 0=baseline",      attack_scenario);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 2) N_Vehicles = 2;
    if (N_RSUs > 1)     N_RSUs     = 1;

    // ME scenarios require at least 4 vehicles (V0, V1=real link; V2, V3=echo)
    if (attack_scenario >= 9 && attack_scenario <= 12 && N_Vehicles < 4) {
        N_Vehicles = 4;
        std::cout << "[Warning] ME scenarios require N_Vehicles >= 4; adjusted to 4.\n";
    }

    TEMP_InitLogs();

    std::cout << "\n======== Temporal-Echo Multi-BSM Comparison ========\n"
              << "  attack_scenario  : " << attack_scenario  << "\n"
              << "  Scenario         : " << GetScenarioVariantName(attack_scenario) << "\n"
              << "  N_Vehicles       : " << N_Vehicles        << "\n"
              << "  N_RSUs           : " << N_RSUs            << "\n"
              << "  simTime          : " << simTime           << " s\n"
              << "  Detector         : MBSM_Detect (verbatim from multibsm_attacks.cc)\n"
              << "====================================================\n\n";

    // ── Create nodes ─────────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(1);

    // ── Vehicle mobility ─────────────────────────────────────────
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

    // ── RSU mobility ─────────────────────────────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobRsu;
        mobRsu.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobRsu.Install(RSU_Nodes);

        Ptr<ConstantPositionMobilityModel> rsu_mob =
            DynamicCast<ConstantPositionMobilityModel>(
                RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (rsu_mob) {
            double centre_x = 50.0 + (N_Vehicles / 2.0) * 60.0;
            double centre_y = (N_Vehicles > 1) ? ((N_Vehicles - 1) * 10.0 / 2.0) : 0.0;
            rsu_mob->SetPosition(Vector(centre_x, centre_y, 0.0));
        }
    }

    // ── Setup network ─────────────────────────────────────────────
    TEMP_SetupNetwork();

    // ── Schedule BSM events ──────────────────────────────────────
    double t_bsm_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        double t_start = 0.1 + i * 0.001;
        Simulator::Schedule(Seconds(t_start), &TEMP_BsmTick, i, t_bsm_end);
    }

    // ── ME: capture link positions at ME_LEGIT_TIME ──────────────
    if (attack_scenario >= 9 && attack_scenario <= 12) {
        Simulator::Schedule(Seconds(ME_LEGIT_TIME), &TEMP_StoreMELinkPositions);
    }

    // ── Write summary at end ─────────────────────────────────────
    Simulator::Schedule(Seconds(simTime - 0.05), &TEMP_WriteSummary);

    // ── NetAnim ──────────────────────────────────────────────────
    std::string anim_xml = "temporal_mbsm_compare_anim_scenario"
                           + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    TEMP_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim;
    g_anim = nullptr;

    if (g_attack_log.is_open())  g_attack_log.close();
    if (g_events_csv.is_open())  g_events_csv.close();

    return 0;
}
