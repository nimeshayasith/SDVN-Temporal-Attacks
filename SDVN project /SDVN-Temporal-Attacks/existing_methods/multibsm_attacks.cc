// ============================================================
// multibsm_attacks.cc
// Position Falsification Attack Simulation — Multi-BSM
//
// Based on: Trabelsi, Z.; Shah, S.S.; Hayawi, K.
//   "Multi-BSM: An Anomaly Detection and Position Falsification
//    Attack Mitigation Approach in Connected Vehicles."
//   Electronics 2022, 11, 3282.
//
// Implements three attack types as standalone NS-3 simulation:
//   attack_scenario=13 → Type 1: Fixed position falsification
//   attack_scenario=14 → Type 2: Random position falsification
//   attack_scenario=15 → Type 3: Stealthy (delayed) falsification
//   attack_scenario=0  → Baseline (no attack)
//
// Copy to ns-3.35/scratch/ and build with:
//   ./waf build
//
// Run examples:
//   ./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=13"
//   ./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=14"
//   ./waf --run "scratch/multibsm_attacks --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=15 --T3_legit_duration=20.0"
//
// Output files:
//   multibsm_attack{13|14|15}.txt  — human-readable attack log
//   multibsm_events.csv            — per-BSM event log
//   multibsm_pem_summary.csv       — detection metrics summary
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
NS_LOG_COMPONENT_DEFINE("MultiBsmAttacks");

// ── Simulation parameters (overridable via command line) ──────
static double   simTime           = 60.0;
static uint32_t N_Vehicles        = 6;
static uint32_t N_RSUs            = 1;
static uint32_t attack_scenario   = 13;
static uint32_t attacker_idx      = 0;     // 0-based index into Vehicle_Nodes
static double   T3_legit_duration = 20.0;  // Type 3: legitimate phase length (s)

// ── BSM and channel constants (Table 2 of the paper) ─────────
static const double BSM_INTERVAL_S   = 0.050;   // 50 ms — optimal per paper
static const double DSRC_RANGE_M     = 250.0;   // 250 m transmission range
static const double MIN_SPEED_MS     = 12.0;    // m/s (paper: 12–20 m/s)
static const double MAX_SPEED_MS     = 20.0;
static const double SAFETY_FACTOR    = 1.5;     // margin for impossible-jump check
static const double POS_FROZEN_EPS_M = 0.05;    // m — "position unchanged" threshold
static const double SPEED_ZERO_THR   = 0.5;     // m/s — "vehicle stopped" threshold
static const uint32_t HISTORY_DEPTH  = 5;       // BSMs retained per vehicle at RSU

// ── Fixed falsified position for Type 1 ──────────────────────
static const double T1_FIXED_X = 1000.0;
static const double T1_FIXED_Y = 2000.0;

// ── Random position space for Type 2 (paper: 3 km × 3 km) ───
static const double SIM_AREA_MAX = 3000.0;

// ── Node containers ───────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;

// ── BSM record — one snapshot stored at the RSU ──────────────
struct BsmRecord {
    uint32_t vehicle_id;
    double   pos_x;
    double   pos_y;
    double   speed_ms;     // m/s
    double   direction;    // radians — atan2(vy, vx)
    double   timestamp;    // simulation seconds
    bool     is_falsified; // ground-truth label (from oracle, not from packet)
};

// ── RSU per-vehicle BSM history (key = NS-3 node ID) ─────────
static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;

// ── Type 3 state ──────────────────────────────────────────────
static bool   g_t3_phase2_active = false;
static double g_t3_freeze_x      = 0.0;
static double g_t3_freeze_y      = 0.0;

// ── PEM metric counters ───────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;
static bool     pem_attack_active     = false;

// ── Simulation oracle — RSU cannot access this ───────────────────────────
// Tracks per-vehicle attack state. Only PEM bookkeeping reads it.
// In a real network no "is_falsified" field exists in BSM packets.
static std::map<uint32_t, bool> g_oracle_attack_state;

// ── Multi-attacker support ────────────────────────────────────────────────
static uint32_t N_Attackers = 1;   // number of malicious vehicles
static std::vector<uint32_t> g_attacker_indices;  // which vehicles are attackers

// ── Output streams ────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_events_csv;

// ── Random engine (fixed seed for reproducibility; pass --RngRun for variation)
static std::mt19937 g_rng(12345);

// ── BSM protocol port ─────────────────────────────────────────────────────
static const uint16_t BSM_PORT = 7777;

// ── BsmTag: NS-3 Tag for BSM (Basic Safety Message) packets ──────────────
// Carries GPS position and kinematics only — no ground-truth cheat field.
// Pattern mirrors CustomDataTag1 / CustomHeartbeatTag in routing.cc:
//   pkt->AddPacketTag(tag)  — attached by vehicle at transmit time
//   pkt->PeekPacketTag(tag) — read by RSU in socket receive callback
// Serialised size: 4+8+8+8+8+8 = 44 bytes.
class BsmTag : public Tag
{
public:
    static TypeId GetTypeId ()
    {
        static TypeId tid = TypeId ("BsmTag")
            .SetParent<Tag> ()
            .AddConstructor<BsmTag> ();
        return tid;
    }
    TypeId GetInstanceTypeId () const override { return GetTypeId (); }

    uint32_t GetSerializedSize () const override { return 44; }

    void Serialize (TagBuffer buf) const override
    {
        buf.WriteU32    (m_vehicleId);
        buf.WriteDouble (m_posX);
        buf.WriteDouble (m_posY);
        buf.WriteDouble (m_speed);
        buf.WriteDouble (m_direction);
        buf.WriteDouble (m_timestamp);
    }
    void Deserialize (TagBuffer buf) override
    {
        m_vehicleId   = buf.ReadU32    ();
        m_posX        = buf.ReadDouble ();
        m_posY        = buf.ReadDouble ();
        m_speed       = buf.ReadDouble ();
        m_direction   = buf.ReadDouble ();
        m_timestamp   = buf.ReadDouble ();
    }
    void Print (std::ostream& os) const override
    {
        os << "BsmTag vid=" << m_vehicleId
           << " pos=(" << m_posX << "," << m_posY << ")"
           << " spd=" << m_speed;
    }

    void SetVehicleId   (uint32_t v) { m_vehicleId   = v; }
    void SetPosX        (double v)   { m_posX        = v; }
    void SetPosY        (double v)   { m_posY        = v; }
    void SetSpeed       (double v)   { m_speed       = v; }
    void SetDirection   (double v)   { m_direction   = v; }
    void SetTimestamp   (double v)   { m_timestamp   = v; }

    uint32_t GetVehicleId   () const { return m_vehicleId; }
    double   GetPosX        () const { return m_posX; }
    double   GetPosY        () const { return m_posY; }
    double   GetSpeed       () const { return m_speed; }
    double   GetDirection   () const { return m_direction; }
    double   GetTimestamp   () const { return m_timestamp; }

private:
    uint32_t m_vehicleId   = 0;
    double   m_posX        = 0.0;
    double   m_posY        = 0.0;
    double   m_speed       = 0.0;
    double   m_direction   = 0.0;
    double   m_timestamp   = 0.0;
};

// ── NetAnim / network-layer state ─────────────────────────────────────────
static AnimationInterface* g_anim        = nullptr;
static Ipv4Address         g_rsu_ip_anim;                  // RSU IP on vehicle-0 link
static std::vector<Ipv4Address> g_veh_ip_anim;             // vehicle i's own P2P IP
// RSU UDP socket for receiving BsmTag packets (set up in MBSM_SetupNetworkForAnim)
static Ptr<Socket> g_rsu_recv_socket = nullptr;

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
// ─────────────────────────────────────────────────────────────
static void GetKinematics(Ptr<Node> node,
                           double& pos_x, double& pos_y,
                           double& speed,  double& direction)
{
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    if (!mob) {
        pos_x = pos_y = speed = direction = 0.0;
        return;
    }
    Vector p = mob->GetPosition();
    Vector v = mob->GetVelocity();
    pos_x     = p.x;
    pos_y     = p.y;
    speed     = std::sqrt(v.x * v.x + v.y * v.y);
    direction = std::atan2(v.y, v.x);
}

// ─────────────────────────────────────────────────────────────
// RSU Multi-BSM detection algorithm (Algorithm 1 of the paper)
//
// Implements detection for all three attack types:
//   Type 1 — pos_change ≈ 0 AND speed > threshold
//   Type 2 — pos_change / Δt >> speed (physically impossible)
//   Type 3 — same trigger as Type 1, but fires only after the
//             legitimate warm-up phase ends (implicit: no special
//             code needed — the check fires whenever the condition
//             first becomes true, which is delayed by T3_legit_duration)
//
// History management follows the paper: anomalous BSMs are NOT
// added to the history (the clean record is preserved).
// Returns true when an anomaly is detected.
// ─────────────────────────────────────────────────────────────
static bool MBSM_Detect(const BsmRecord& bsm)
{
    auto& hist = g_bsm_history[bsm.vehicle_id];

    if (hist.empty()) {
        // First-ever BSM from this vehicle — store and pass
        hist.push_back(bsm);
        return false;
    }

    const BsmRecord& prev = hist.back();
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) {
        // Clock skew or duplicate — skip comparison
        return false;
    }

    double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);

    // ── Trigger A: position frozen but speed is non-zero
    //    Catches Type 1 (always frozen) and Type 3 (frozen after legit phase)
    if (pos_change < POS_FROZEN_EPS_M && bsm.speed_ms > SPEED_ZERO_THR) {
        return true;
    }

    // ── Trigger B: physically impossible displacement
    //    Catches Type 2 (random teleportation)
    //    max_possible = v * Δt * safety_factor
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

// Forward declaration — MBSM_RSUReceive is defined after MBSM_RSUSocketReceive
static void MBSM_RSUReceive(BsmRecord bsm);

// ─────────────────────────────────────────────────────────────
// RSU UDP socket receive callback
// Fires when a BsmTag packet arrives on BSM_PORT.
// Reads the tag (PeekPacketTag), reconstructs BsmRecord, calls MBSM_RSUReceive.
// Mirrors the Rx() callback / PeekPacketTag pattern in routing.cc.
// ─────────────────────────────────────────────────────────────
static void MBSM_RSUSocketReceive (Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv ()))
    {
        BsmTag tag;
        if (!pkt->PeekPacketTag (tag)) continue;

        BsmRecord bsm;
        bsm.vehicle_id   = tag.GetVehicleId ();
        bsm.pos_x        = tag.GetPosX ();
        bsm.pos_y        = tag.GetPosY ();
        bsm.speed_ms     = tag.GetSpeed ();
        bsm.direction    = tag.GetDirection ();
        bsm.timestamp    = tag.GetTimestamp ();
        // Ground truth comes from simulation oracle, not from the packet
        bsm.is_falsified = g_oracle_attack_state.count(bsm.vehicle_id) &&
                           g_oracle_attack_state[bsm.vehicle_id];

        MBSM_RSUReceive (bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// Create a BsmTag packet and send it from vehicle veh_idx to RSU.
// Replaces the direct MBSM_RSUReceive(bsm) call in the send functions.
// InRSURange check must be done by the caller before calling this.
// ─────────────────────────────────────────────────────────────
// No is_falsified parameter — tag carries observable fields only.
// Oracle (g_oracle_attack_state) is updated by the caller before this runs.
static void MBSM_SendBsm (uint32_t veh_idx,
                           double px, double py,
                           double spd, double dir)
{
    if (g_rsu_recv_socket == nullptr)      return;   // network not yet set up
    if (veh_idx >= Vehicle_Nodes.GetN ())  return;

    Ptr<Node> src = Vehicle_Nodes.Get (veh_idx);

    TypeId udp_tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket (src, udp_tid);
    sock->Connect (InetSocketAddress (g_rsu_ip_anim, BSM_PORT));

    Ptr<Packet> pkt = Create<Packet> (0);
    BsmTag tag;
    tag.SetVehicleId (src->GetId ());
    tag.SetPosX      (px);
    tag.SetPosY      (py);
    tag.SetSpeed     (spd);
    tag.SetDirection (dir);
    tag.SetTimestamp (Simulator::Now ().GetSeconds ());
    pkt->AddPacketTag (tag);

    sock->Send  (pkt);
    sock->Close ();
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler
// Runs detection, updates PEM counters, writes event log
// ─────────────────────────────────────────────────────────────
static void MBSM_RSUReceive(BsmRecord bsm)
{
    double now            = Simulator::Now().GetSeconds();
    bool   is_attack      = bsm.is_falsified;
    bool   anomaly_raised = MBSM_Detect(bsm);

    // Record first alert time
    if (anomaly_raised && pem_first_alert_time < 0.0 && is_attack) {
        pem_first_alert_time = now;
    }

    // PEM accounting
    if (is_attack) {
        if (anomaly_raised) { pem_tp++; } else { pem_fn++; }
    } else {
        if (anomaly_raised) { pem_fp++; } else { pem_tn++; }
    }

    // Per-event CSV
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

    // Human-readable alert
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
static void MBSM_SendLegit(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double px, py, spd, dir;
    GetKinematics(node, px, py, spd, dir);

    // Oracle: this vehicle is behaving legitimately
    g_oracle_attack_state[node->GetId()] = false;

    if (InRSURange(px, py)) {
        MBSM_SendBsm(veh_idx, px, py, spd, dir);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 1: fixed position falsification
// Attacker always reports (T1_FIXED_X, T1_FIXED_Y) while
// continuing to broadcast realistic speed and direction values.
// ─────────────────────────────────────────────────────────────
static void MBSM_SendType1(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double real_px, real_py, real_spd, real_dir;
    GetKinematics(node, real_px, real_py, real_spd, real_dir);
    double now = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 1 BEGINS  V" << node->GetId()
                         << "\n"
                         << "  Real position  : (" << real_px << ", " << real_py << ")\n"
                         << "  Falsified pos  : (" << T1_FIXED_X << ", " << T1_FIXED_Y << ")  [hardcoded]\n"
                         << "  Real speed     : " << real_spd << " m/s  [broadcast unchanged]\n"
                         << "  Mechanism      : OBU overwrites GPS with fixed coordinate\n\n";
            g_attack_log.flush();
        }
    }

    // Oracle: this vehicle is attacking this tick
    g_oracle_attack_state[node->GetId()] = true;

    // Send forged BsmTag packet to RSU (physical radio range check on real position)
    if (InRSURange(real_px, real_py)) {
        MBSM_SendBsm(veh_idx, T1_FIXED_X, T1_FIXED_Y, real_spd, real_dir);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 2: random position falsification
// Attacker broadcasts a uniformly random coordinate each BSM.
// ─────────────────────────────────────────────────────────────
static void MBSM_SendType2(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double real_px, real_py, real_spd, real_dir;
    GetKinematics(node, real_px, real_py, real_spd, real_dir);
    double now = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
        if (g_attack_log.is_open()) {
            g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                         << "]  ATTACK TYPE 2 BEGINS  V" << node->GetId()
                         << "\n"
                         << "  Mechanism: OBU injects a fresh random (x, y) into every BSM\n"
                         << "  Area     : [0, " << SIM_AREA_MAX << "] x [0, " << SIM_AREA_MAX << "] m\n\n";
            g_attack_log.flush();
        }
    }

    std::uniform_real_distribution<double> rand_coord(0.0, SIM_AREA_MAX);
    double fake_x = rand_coord(g_rng);
    double fake_y = rand_coord(g_rng);

    // Oracle: this vehicle is attacking this tick
    g_oracle_attack_state[node->GetId()] = true;

    if (InRSURange(real_px, real_py)) {
        MBSM_SendBsm(veh_idx, fake_x, fake_y, real_spd, real_dir);
    }
}

// ─────────────────────────────────────────────────────────────
// Attack Type 3: stealthy (delayed) position falsification
//
// Phase 1 (t < T3_legit_duration): attacker broadcasts real GPS
//   data, building a trusted history at the RSU.
// Phase 2 (t ≥ T3_legit_duration): attacker freezes its reported
//   position at the last real coordinate and never updates it,
//   even as the vehicle continues to move and report non-zero speed.
// ─────────────────────────────────────────────────────────────
static void MBSM_SendType3(uint32_t veh_idx)
{
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    double real_px, real_py, real_spd, real_dir;
    GetKinematics(node, real_px, real_py, real_spd, real_dir);
    double now = Simulator::Now().GetSeconds();

    if (now < T3_legit_duration) {
        // Phase 1 — legitimate behaviour
        // Cache real position so Phase 2 knows where to freeze
        g_t3_freeze_x = real_px;
        g_t3_freeze_y = real_py;

        // Oracle: legitimate this tick
        g_oracle_attack_state[node->GetId()] = false;

        if (InRSURange(real_px, real_py)) {
            MBSM_SendBsm(veh_idx, real_px, real_py, real_spd, real_dir);
        }
    } else {
        // Phase 2 — freeze reported position at last known real coordinate
        if (!g_t3_phase2_active) {
            g_t3_phase2_active    = true;
            pem_attack_active     = true;
            pem_attack_start_time = now;
            if (g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                             << "]  ATTACK TYPE 3 PHASE 2 BEGINS  V" << node->GetId()
                             << "\n"
                             << "  Legitimate phase ended after " << T3_legit_duration << " s\n"
                             << "  Freeze position : (" << g_t3_freeze_x << ", " << g_t3_freeze_y << ")\n"
                             << "  Real position   : (" << real_px << ", " << real_py << ")\n"
                             << "  Mechanism       : OBU locks GPS to last real coordinate\n\n";
                g_attack_log.flush();
            }
        }

        // Oracle: attacking this tick
        g_oracle_attack_state[node->GetId()] = true;

        if (InRSURange(real_px, real_py)) {
            MBSM_SendBsm(veh_idx, g_t3_freeze_x, g_t3_freeze_y, real_spd, real_dir);
        }
    }
}

// MBSM_AnimSend is no longer needed — real BsmTag packets (BSM_PORT 7777)
// generate NetAnim arrows automatically when EnablePacketMetadata(true) is set.
// The function stub is kept so MBSM_BsmTick's existing call compiles without error;
// it does nothing since g_anim guards are satisfied by the real packets.
static void MBSM_AnimSend(uint32_t /*veh_idx*/)
{
    // Real BsmTag packet flow provides animation arrows; no separate anim packet needed.
}

// ─────────────────────────────────────────────────────────────
// Build a lightweight P2P star topology (vehicle_i ↔ RSU) purely
// for NetAnim packet arrows. Also installs Internet stack and
// a UDP PacketSink on port 9 on every node.
// ─────────────────────────────────────────────────────────────
static void MBSM_SetupNetworkForAnim()
{
    if (RSU_Nodes.GetN() == 0) {
        // No RSU present — skip (no vehicle→RSU arrows possible)
        return;
    }

    // Install Internet stack on all nodes
    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);
    internet.Install(RSU_Nodes);

    // P2P star: vehicle_i ↔ RSU  on subnet 10.1.(i+1).0/30
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
        base_ip << "10.1." << (i + 1) << ".0";
        addr.SetBase(base_ip.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);

        g_veh_ip_anim[i] = ifaces.GetAddress(0);   // vehicle i: .1
        if (i == 0) {
            // RSU's address on the first link — reachable from all
            // vehicles via global routing
            g_rsu_ip_anim = ifaces.GetAddress(1);   // 10.1.1.2
        }
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ── RSU BSM receive socket (port BSM_PORT = 7777) ─────────────────────
    // Accepts BsmTag packets from vehicles; invokes MBSM_RSUSocketReceive.
    // Mirrors the Rx() / PeekPacketTag pattern used in routing.cc.
    g_rsu_recv_socket = Socket::CreateSocket (
        RSU_Nodes.Get (0),
        TypeId::LookupByName ("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind (
        InetSocketAddress (Ipv4Address::GetAny (), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback (MakeCallback (&MBSM_RSUSocketReceive));

    // Install PacketSink on UDP port 9 so animation packets are accepted
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
// Apply NetAnim node colours, sizes, and labels.
// Must be called AFTER AnimationInterface is constructed.
// Colour scheme (matches routing.cc TTW/ME/BSHH convention):
//   attacker vehicle  → red  (255, 0, 0)
//   legitimate vehicles → green (0, 200, 60)
//   RSU               → amber (255, 200, 0)
// ─────────────────────────────────────────────────────────────
static void MBSM_SetupNetAnim()
{
    if (!g_anim) return;

    // RSU — amber/yellow
    if (RSU_Nodes.GetN() > 0) {
        uint32_t rsu_id = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rsu_id, 255, 200, 0);
        g_anim->UpdateNodeSize(rsu_id, 35, 35);
        g_anim->UpdateNodeDescription(rsu_id, "RSU");
    }

    // Vehicles
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid = Vehicle_Nodes.Get(i)->GetId();
        bool is_attacker = (attack_scenario != 0) &&
            std::find(g_attacker_indices.begin(), g_attacker_indices.end(), i)
                != g_attacker_indices.end();
        if (is_attacker) {
            g_anim->UpdateNodeColor(nid, 255, 0, 0);      // red
            g_anim->UpdateNodeSize(nid, 30, 30);
            g_anim->UpdateNodeDescription(nid, "ATTACKER");
        } else {
            g_anim->UpdateNodeColor(nid, 0, 200, 60);     // green
            g_anim->UpdateNodeSize(nid, 20, 20);
            g_anim->UpdateNodeDescription(nid, "V" + std::to_string(i));
        }
    }

    g_anim->EnablePacketMetadata(true);
}

// ─────────────────────────────────────────────────────────────
// One BSM tick for a single vehicle — dispatches to the correct
// sender based on attack_scenario and veh_idx
// ─────────────────────────────────────────────────────────────
static void MBSM_BsmTick(uint32_t veh_idx, double t_end)
{
    bool is_attacker = (attack_scenario != 0) &&
        std::find(g_attacker_indices.begin(), g_attacker_indices.end(), veh_idx)
            != g_attacker_indices.end();

    if (is_attacker) {
        switch (attack_scenario) {
            case 13: MBSM_SendType1(veh_idx); break;
            case 14: MBSM_SendType2(veh_idx); break;
            case 15: MBSM_SendType3(veh_idx); break;
            default: MBSM_SendLegit(veh_idx); break;
        }
    } else {
        MBSM_SendLegit(veh_idx);
    }

    // NetAnim: one arrow per vehicle per second (throttled inside MBSM_AnimSend)
    if (g_anim && RSU_Nodes.GetN() > 0) {
        Simulator::Schedule(Seconds(0.001), &MBSM_AnimSend, veh_idx);
    }

    double next = Simulator::Now().GetSeconds() + BSM_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BSM_INTERVAL_S),
                            &MBSM_BsmTick, veh_idx, t_end);
    }
}

// ─────────────────────────────────────────────────────────────
// Open log files and write headers
// ─────────────────────────────────────────────────────────────
static void MBSM_InitLogs()
{
    std::string log_filename;
    std::string attack_name;
    switch (attack_scenario) {
        case 13:
            log_filename = "multibsm_attack13.txt";
            attack_name  = "Type 1 — Fixed Position Falsification";
            break;
        case 14:
            log_filename = "multibsm_attack14.txt";
            attack_name  = "Type 2 — Random Position Falsification";
            break;
        case 15:
            log_filename = "multibsm_attack15.txt";
            attack_name  = "Type 3 — Stealthy (Delayed) Position Falsification";
            break;
        default:
            log_filename = "multibsm_baseline.txt";
            attack_name  = "Baseline (No Attack)";
            break;
    }

    g_attack_log.open(log_filename, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Multi-BSM Position Falsification Attack Log\n"
        << "  Attack  : " << attack_name << "\n"
        << "  Based on: Trabelsi et al., Electronics 2022, 11, 3282\n"
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
    if (attack_scenario == 15) {
        g_attack_log
            << "  Legit phase     : " << T3_legit_duration << " s\n";
    }
    g_attack_log
        << "================================================================\n\n";
    g_attack_log.flush();

    g_events_csv.open("multibsm_events.csv", std::ios::out | std::ios::trunc);
    g_events_csv
        << "sim_time_s,vehicle_id,reported_pos_x,reported_pos_y,"
        << "speed_ms,direction_rad,is_attack,alert_raised\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary CSV and print to console
// Called at the end of the simulation
// ─────────────────────────────────────────────────────────────
static void MBSM_WriteSummary()
{
    double tp = static_cast<double>(pem_tp);
    double tn = static_cast<double>(pem_tn);
    double fp = static_cast<double>(pem_fp);
    double fn = static_cast<double>(pem_fn);

    // Matthews Correlation Coefficient
    double mcc_denom = std::sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    double mcc = (mcc_denom > 0.0) ? ((tp * tn - fp * fn) / mcc_denom) : 0.0;

    // Accuracy Rate (ACR) — metric used in the paper
    double total = tp + tn + fp + fn;
    double acr   = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;

    // Detection Precision and Recall
    double precision = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double recall    = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;

    // Detection latency
    double tdet_ms = -1.0;
    if (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0) {
        tdet_ms = (pem_first_alert_time - pem_attack_start_time) * 1000.0;
    }

    // Write CSV
    std::ofstream sum("multibsm_pem_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,tp,tn,fp,fn,mcc,acr_pct,precision,recall,tdet_ms\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc << ","
        << acr << ","
        << precision << ","
        << recall << ","
        << tdet_ms << "\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n========== RUN SUMMARY ==========\n"
            << "  attack_scenario : " << attack_scenario << "\n"
            << "  TP              : " << pem_tp      << "\n"
            << "  TN              : " << pem_tn      << "\n"
            << "  FP              : " << pem_fp      << "\n"
            << "  FN              : " << pem_fn      << "\n"
            << "  MCC             : " << std::fixed << std::setprecision(3) << mcc  << "\n"
            << "  ACR             : " << acr          << " %\n"
            << "  Precision       : " << precision    << "\n"
            << "  Recall          : " << recall       << "\n"
            << "  Tdet            : " << tdet_ms      << " ms\n"
            << "==================================\n";
        g_attack_log.flush();
    }

    std::cout << "\n[Multi-BSM] Summary written to multibsm_pem_summary.csv\n"
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
    cmd.AddValue("simTime",          "Simulation duration (s)",                     simTime);
    cmd.AddValue("N_Vehicles",       "Number of vehicle nodes",                     N_Vehicles);
    cmd.AddValue("N_RSUs",           "Number of RSU nodes (0 or 1 supported)",      N_RSUs);
    cmd.AddValue("attack_scenario",  "13=Type1, 14=Type2, 15=Type3, 0=baseline",    attack_scenario);
    cmd.AddValue("attacker_idx",     "0-based index of the malicious vehicle (N_Attackers=1)", attacker_idx);
    cmd.AddValue("N_Attackers",      "Number of malicious vehicles (default 1)",      N_Attackers);
    cmd.AddValue("T3_legit_duration","Type 3: legitimate phase length (s)",           T3_legit_duration);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 1)              N_Vehicles   = 1;
    if (N_RSUs > 1)                  N_RSUs        = 1;
    if (N_Attackers > N_Vehicles)    N_Attackers   = N_Vehicles;
    if (attacker_idx >= N_Vehicles)  attacker_idx  = 0;

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

    MBSM_InitLogs();

    std::cout << "\n======== Multi-BSM Attack Simulation ========\n"
              << "  attack_scenario  : " << attack_scenario  << "\n"
              << "  N_Vehicles       : " << N_Vehicles       << "\n"
              << "  N_Attackers      : " << N_Attackers      << "\n"
              << "  N_RSUs           : " << N_RSUs           << "\n"
              << "  simTime          : " << simTime          << " s\n";
    std::cout << "  Attacker indices : [";
    for (size_t k = 0; k < g_attacker_indices.size(); k++) {
        if (k) std::cout << ", ";
        std::cout << g_attacker_indices[k];
    }
    std::cout << "]\n";
    if (attack_scenario == 15) {
        std::cout << "  T3_legit_duration: " << T3_legit_duration << " s\n";
    }
    std::cout << "  Ground truth     : oracle (not in BSM packets)\n"
              << "=============================================\n\n";

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
            // Centred among initial vehicle spread, at y = lane mid-point
            double centre_x = 50.0 + (N_Vehicles / 2.0) * 60.0;
            double centre_y = (N_Vehicles > 1)
                ? ((N_Vehicles - 1) * 10.0 / 2.0) : 0.0;
            rsu_mob->SetPosition(Vector(centre_x, centre_y, 0.0));
        }
    }

    // ── Setup lightweight P2P network for NetAnim arrows ────────
    MBSM_SetupNetworkForAnim();

    // ── Schedule BSM events ──────────────────────────────────
    // Each vehicle starts sending BSMs at t=0.1s, staggered by 1 ms
    double t_bsm_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        double t_start = 0.1 + i * 0.001;
        Simulator::Schedule(Seconds(t_start),
                            &MBSM_BsmTick, i, t_bsm_end);
    }

    // ── Write summary at end ─────────────────────────────────
    Simulator::Schedule(Seconds(simTime - 0.05), &MBSM_WriteSummary);

    // ── NetAnim: create animation file ───────────────────────
    std::string anim_xml = "multibsm_anim_scenario"
                           + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    MBSM_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim;
    g_anim = nullptr;

    if (g_attack_log.is_open())  g_attack_log.close();
    if (g_events_csv.is_open())  g_events_csv.close();

    return 0;
}
