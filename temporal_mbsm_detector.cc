// ============================================================
// temporal_mbsm_detector.cc
// Temporal-Echo Topology Poisoning Attack Simulation
// with Multi-BSM Style Rule-Based Detection
//
// Based on: Trabelsi, Z.; Shah, S.S.; Hayawi, K.
//   "Multi-BSM: An Anomaly Detection and Position Falsification
//    Attack Mitigation Approach in Connected Vehicles."
//   Electronics 2022, 11, 3282.
//
// Algorithm 1 of the paper is adapted for Temporal-Echo attacks:
//   TTW  — Trigger A: (rx_time - claimed_ts) > BEACON_INTERVAL + STALE_EPS
//           Trigger B: claimed_ts  < prev_claimed_ts  (timestamp regression)
//   BSHH — Trigger A: physical_sender != claimed_sender (identity conflict)
//           Trigger B: hb_ts < last_known_hb_ts for claimed_sender (replay)
//   ME   — Trigger A: reporter_count > rhoMax * SAFETY_FACTOR (density excess)
//           Trigger B: reporter outside COMM_RANGE of both link endpoints
//
// Attack scenarios (match routing.cc numbering exactly):
//   0  = Baseline (no attack)
//   1  = TTW-S1: Malicious Vehicle, No RSU
//   2  = TTW-S2: Malicious RSU, With RSU
//   3  = TTW-S3: Malicious Controller, No RSU
//   4  = TTW-S4: Malicious Controller, With RSU
//   5  = BSHH-S1: Malicious Vehicle, No RSU
//   6  = BSHH-S2: Malicious RSU, With RSU
//   7  = BSHH-S3: Malicious Controller, No RSU
//   8  = BSHH-S4: Malicious Controller, With RSU
//   9  = ME-S1: Malicious Vehicles, No RSU
//   10 = ME-S2: Malicious RSU, With RSU
//   11 = ME-S3: Malicious Controller, No RSU
//   12 = ME-S4: Malicious Controller, With RSU
//
// Run examples:
//   ./waf --run "scratch/temporal_mbsm_detector --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"
//   ./waf --run "scratch/temporal_mbsm_detector --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=2"
//   ./waf --run "scratch/temporal_mbsm_detector --simTime=60 --N_Vehicles=8 --N_RSUs=1 --attack_scenario=10"
//   ./waf --run "scratch/temporal_mbsm_detector --simTime=60 --N_Vehicles=4 --N_RSUs=0 --attack_scenario=9"
//
// Output files:
//   temporal_mbsm_attack{1..12}.txt    — human-readable attack log
//   temporal_mbsm_events.csv           — per-event detection log
//   temporal_mbsm_summary.csv          — TP/TN/FP/FN/MCC/ACR/Tdet per run
//   temporal_mbsm_anim_scenario{N}.xml — NetAnim visualisation
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
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("TemporalMbsmDetector");

// ─────────────────────────────────────────────────────────────
// Simulation parameters (command-line overridable)
// ─────────────────────────────────────────────────────────────
static double   simTime        = 60.0;
static uint32_t N_Vehicles     = 6;
static uint32_t N_RSUs         = 0;
static uint32_t attack_scenario= 1;
static uint32_t attacker_idx   = 0;    // 0-based vehicle index

// ─────────────────────────────────────────────────────────────
// Physical / protocol constants
// ─────────────────────────────────────────────────────────────
static const double COMM_RANGE_M      = 300.0;   // DSRC comm range (routing.cc TTW_COMM_RANGE)
static const double BEACON_INTERVAL_S = 1.0;     // topology update period (s)
static const double STALE_EPS_S       = 3.0;     // Trigger A slack beyond one interval
static const double SPEED_MIN_MS      = 8.0;     // m/s vehicle speed range
static const double SPEED_MAX_MS      = 20.0;
static const double ME_SAFETY_FACTOR  = 1.5;     // from Multi-BSM paper (SAFETY_FACTOR)
static const uint32_t HISTORY_DEPTH   = 5;       // max events kept per link

// Attack timing (matches routing.cc timing constants)
static const double TTW_HELLO_TIME   = 10.0;
static const double TTW_LINK_BREAK   = 15.0;
static const double TTW_REPLAY_TIME  = 20.0;
static const double BSHH_STORE_TIME  = 5.0;
static const double BSHH_REPLAY_TIME = 10.0;
static const double ME_ECHO_TIME     = 10.05;

// Network addressing (subnet 10.3.x — avoids 10.1.x multibsm, 10.2.x veremi)
static const uint16_t TOPO_PORT  = 7779;
static const uint16_t HB_PORT   = 7780;

// ─────────────────────────────────────────────────────────────
// Node containers and addressing
// ─────────────────────────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;
static NodeContainer Controller_Node;

static std::vector<Ipv4Address> g_ctrl_ip_for_veh;   // controller IP reachable from veh[i]
static Ipv4Address              g_ctrl_ip_for_rsu;    // controller IP reachable from RSU
static Ipv4Address              g_rsu_ip;             // RSU's IP (first P2P link)
static std::vector<Ipv4Address> g_veh_ip;             // vehicle[i]'s own IP

static Ptr<Socket> g_ctrl_topo_sock = nullptr;   // controller receives topology packets
static Ptr<Socket> g_ctrl_hb_sock   = nullptr;   // controller receives heartbeat packets

// ─────────────────────────────────────────────────────────────
// NetAnim
// ─────────────────────────────────────────────────────────────
static AnimationInterface* g_anim = nullptr;

// ─────────────────────────────────────────────────────────────
// PEM counters (Table 5 pattern from Multi-BSM paper)
// ─────────────────────────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;
static bool     pem_attack_active     = false;

// ─────────────────────────────────────────────────────────────
// Oracle maps — ground truth, NOT present in packets
// oracle_topo_attack[reporter_id] = true when attacker is injecting
// oracle_hb_attack  [physical_id] = true when attacker is replaying
// Same pattern as g_oracle_attack_state in multibsm_attacks.cc
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, bool> g_oracle_topo_attack;
static std::map<uint32_t, bool> g_oracle_hb_attack;

// ─────────────────────────────────────────────────────────────
// Controller topology state (Algorithm 1 history)
// ─────────────────────────────────────────────────────────────
struct TopoRecord {
    uint32_t src_id;
    uint32_t dst_id;
    double   claimed_ts;
    uint32_t reporter_id;
    double   rx_time;
};
// key = "srcId_dstId"
static std::map<std::string, std::deque<TopoRecord>> g_topo_history;
static std::map<std::string, std::set<uint32_t>>     g_link_reporters;   // ME reporter sets

// Controller heartbeat liveness table
struct HBRecord {
    uint32_t claimed_sender;
    uint32_t physical_sender;
    double   hb_ts;
    double   rx_time;
};
// key = claimed_sender_id
static std::map<uint32_t, HBRecord> g_hb_history;

// ─────────────────────────────────────────────────────────────
// Output streams
// ─────────────────────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_events_csv;

// ─────────────────────────────────────────────────────────────
// TemporalTopoTag — NS-3 Tag for topology update packets
// Carries: src_id, dst_id, claimed_ts, reporter_id
// Size: 4+4+8+4 = 20 bytes
// Pattern mirrors BsmTag in multibsm_attacks.cc
// ─────────────────────────────────────────────────────────────
class TemporalTopoTag : public Tag
{
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("TemporalTopoTag")
            .SetParent<Tag>().AddConstructor<TemporalTopoTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 20; }

    void Serialize(TagBuffer buf) const override {
        buf.WriteU32(m_srcId);
        buf.WriteU32(m_dstId);
        buf.WriteDouble(m_claimedTs);
        buf.WriteU32(m_reporterId);
    }
    void Deserialize(TagBuffer buf) override {
        m_srcId      = buf.ReadU32();
        m_dstId      = buf.ReadU32();
        m_claimedTs  = buf.ReadDouble();
        m_reporterId = buf.ReadU32();
    }
    void Print(std::ostream& os) const override {
        os << "TopoTag src=" << m_srcId << " dst=" << m_dstId
           << " ts=" << m_claimedTs << " rep=" << m_reporterId;
    }

    void SetSrcId     (uint32_t v) { m_srcId      = v; }
    void SetDstId     (uint32_t v) { m_dstId      = v; }
    void SetClaimedTs (double   v) { m_claimedTs  = v; }
    void SetReporterId(uint32_t v) { m_reporterId = v; }

    uint32_t GetSrcId     () const { return m_srcId;     }
    uint32_t GetDstId     () const { return m_dstId;     }
    double   GetClaimedTs () const { return m_claimedTs; }
    uint32_t GetReporterId() const { return m_reporterId;}

private:
    uint32_t m_srcId      = 0;
    uint32_t m_dstId      = 0;
    double   m_claimedTs  = 0.0;
    uint32_t m_reporterId = 0;
};

// ─────────────────────────────────────────────────────────────
// TemporalHBTag — NS-3 Tag for heartbeat (liveness) packets
// Carries: claimed_sender, physical_sender, hb_ts
// Size: 4+4+8 = 16 bytes
// Mirrors CustomHeartbeatTag from routing.cc Section 17
// ─────────────────────────────────────────────────────────────
class TemporalHBTag : public Tag
{
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("TemporalHBTag")
            .SetParent<Tag>().AddConstructor<TemporalHBTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 16; }

    void Serialize(TagBuffer buf) const override {
        buf.WriteU32(m_claimedSender);
        buf.WriteU32(m_physicalSender);
        buf.WriteDouble(m_hbTs);
    }
    void Deserialize(TagBuffer buf) override {
        m_claimedSender  = buf.ReadU32();
        m_physicalSender = buf.ReadU32();
        m_hbTs           = buf.ReadDouble();
    }
    void Print(std::ostream& os) const override {
        os << "HBTag claimed=" << m_claimedSender
           << " physical=" << m_physicalSender << " ts=" << m_hbTs;
    }

    void SetClaimedSender (uint32_t v) { m_claimedSender  = v; }
    void SetPhysicalSender(uint32_t v) { m_physicalSender = v; }
    void SetHbTs          (double   v) { m_hbTs           = v; }

    uint32_t GetClaimedSender () const { return m_claimedSender; }
    uint32_t GetPhysicalSender() const { return m_physicalSender;}
    double   GetHbTs          () const { return m_hbTs;          }

private:
    uint32_t m_claimedSender  = 0;
    uint32_t m_physicalSender = 0;
    double   m_hbTs           = 0.0;
};

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────
static double Dist2D(double x1, double y1, double x2, double y2)
{
    double dx = x2-x1, dy = y2-y1;
    return std::sqrt(dx*dx + dy*dy);
}

static void GetKinematics(Ptr<Node> node, double& px, double& py,
                          double& vx, double& vy)
{
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    if (!mob) { px=py=vx=vy=0.0; return; }
    Vector p = mob->GetPosition();
    Vector v = mob->GetVelocity();
    px=p.x; py=p.y; vx=v.x; vy=v.y;
}

static bool IsAttacker(uint32_t veh_idx)
{
    return (attack_scenario != 0) && (veh_idx == attacker_idx);
}

// ME: expected reporters = 2 (V1 and V2 see each other) but allow up to rhoMax*SAFETY
static double ComputeRhoMax()
{
    return std::max(2.0, static_cast<double>(N_Vehicles) / 4.0);
}

// ─────────────────────────────────────────────────────────────
// Multi-BSM Algorithm 1 — adapted for TTW topology events
//
// Trigger A (≡ "frozen position + speed > 0"):
//   (rx_time − claimed_ts) > BEACON_INTERVAL_S + STALE_EPS_S
//   → timestamp is too stale to be a fresh observation
//
// Trigger B (≡ "physically impossible displacement"):
//   claimed_ts < last known claimed_ts for same link
//   → claimed observation time went backwards (replay)
//
// Returns true if an anomaly is detected.
// ─────────────────────────────────────────────────────────────
static bool TMBSM_DetectTopo(uint32_t src_id, uint32_t dst_id,
                              double claimed_ts, uint32_t reporter_id,
                              double rx_time)
{
    std::string key = std::to_string(src_id) + "_" + std::to_string(dst_id);

    // --- Trigger A: stale timestamp (analogous to position-frozen + speed > 0) ---
    double staleness = rx_time - claimed_ts;
    if (staleness > BEACON_INTERVAL_S + STALE_EPS_S) {
        return true;
    }

    // --- Trigger B: timestamp regression (analogous to impossible displacement) ---
    auto& hist = g_topo_history[key];
    if (!hist.empty()) {
        double last_claimed_ts = hist.back().claimed_ts;
        if (claimed_ts < last_claimed_ts) {
            return true;   // claimed time moved backwards — classic replay signature
        }
    }

    // Legitimate: update history, cap at HISTORY_DEPTH
    TopoRecord rec = {src_id, dst_id, claimed_ts, reporter_id, rx_time};
    hist.push_back(rec);
    if (hist.size() > HISTORY_DEPTH) hist.pop_front();

    // ME: track reporter set for this link
    g_link_reporters[key].insert(reporter_id);
    return false;
}

// ─────────────────────────────────────────────────────────────
// Multi-BSM Algorithm 1 — adapted for ME reporter density/range
//
// Trigger A: reporter_count > rhoMax * SAFETY_FACTOR
// Trigger B: reporter outside COMM_RANGE of both link endpoints
// ─────────────────────────────────────────────────────────────
static bool TMBSM_DetectME(uint32_t link_src, uint32_t link_dst,
                            uint32_t reporter_id, double claimed_ts, double rx_time,
                            double rep_x, double rep_y,
                            double src_x, double src_y,
                            double dst_x, double dst_y)
{
    std::string key = std::to_string(link_src) + "_" + std::to_string(link_dst);
    g_link_reporters[key].insert(reporter_id);
    uint32_t count = static_cast<uint32_t>(g_link_reporters[key].size());

    // --- Trigger A: too many reporters (density excess) ---
    double rhoMax = ComputeRhoMax();
    if (count > rhoMax * ME_SAFETY_FACTOR) {
        return true;
    }

    // --- Trigger B: reporter physically cannot observe this link ---
    double d_src = Dist2D(rep_x, rep_y, src_x, src_y);
    double d_dst = Dist2D(rep_x, rep_y, dst_x, dst_y);
    if (d_src > COMM_RANGE_M && d_dst > COMM_RANGE_M) {
        return true;
    }

    // Legitimate reporter — update topo history
    TopoRecord rec = {link_src, link_dst, claimed_ts, reporter_id, rx_time};
    g_topo_history[key].push_back(rec);
    if (g_topo_history[key].size() > HISTORY_DEPTH) g_topo_history[key].pop_front();
    return false;
}

// ─────────────────────────────────────────────────────────────
// Multi-BSM Algorithm 1 — adapted for BSHH heartbeat events
//
// Trigger A (≡ "position frozen + speed > 0"):
//   physical_sender != claimed_sender
//   → someone is impersonating another vehicle
//
// Trigger B (≡ "physically impossible displacement"):
//   hb_ts < last_known_hb_ts for claimed_sender
//   → heartbeat timestamp went backwards (stale replay)
// ─────────────────────────────────────────────────────────────
static bool TMBSM_DetectHB(uint32_t claimed_sender, uint32_t physical_sender,
                             double hb_ts, double rx_time)
{
    // --- Trigger A: identity conflict (analogous to position-frozen + speed > 0) ---
    if (physical_sender != claimed_sender) {
        return true;
    }

    // --- Trigger B: heartbeat timestamp regression (analogous to impossible displacement) ---
    auto it = g_hb_history.find(claimed_sender);
    if (it != g_hb_history.end()) {
        if (hb_ts < it->second.hb_ts) {
            return true;
        }
    }

    // Legitimate: update history
    g_hb_history[claimed_sender] = {claimed_sender, physical_sender, hb_ts, rx_time};
    return false;
}

// ─────────────────────────────────────────────────────────────
// Shared post-detection bookkeeping
// Called after each detect-or-pass decision.
// ─────────────────────────────────────────────────────────────
static void TMBSM_RecordOutcome(bool is_attack, bool detected, double rx_time,
                                 const std::string& event_type,
                                 uint32_t physical_id, uint32_t claimed_id,
                                 uint32_t link_src, uint32_t link_dst,
                                 double claimed_ts, bool trig_a, bool trig_b)
{
    // First alert time
    if (detected && is_attack && pem_first_alert_time < 0.0)
        pem_first_alert_time = rx_time;

    // PEM counters
    if (is_attack) { if (detected) pem_tp++; else pem_fn++; }
    else           { if (detected) pem_fp++; else pem_tn++; }

    // Events CSV
    if (g_events_csv.is_open()) {
        g_events_csv << std::fixed << std::setprecision(4)
            << rx_time       << ","
            << attack_scenario << ","
            << event_type    << ","
            << physical_id   << ","
            << claimed_ts    << ","
            << rx_time       << ","
            << (rx_time - claimed_ts) << ","   // rx_delay
            << physical_id   << ","
            << link_src      << ","
            << link_dst      << ","
            << physical_id   << ","
            << claimed_id    << ","
            << (is_attack ? 1:0) << ","
            << (trig_a    ? 1:0) << ","
            << (trig_b    ? 1:0) << ","
            << (detected  ? 1:0) << "\n";
    }

    // Human-readable alert
    if (detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                     << "]  ALERT  " << event_type
                     << "  physical=" << physical_id
                     << "  claimed=" << claimed_id
                     << "  link=" << link_src << "↔" << link_dst
                     << "  claimed_ts=" << claimed_ts
                     << "  rx_delay=" << (rx_time-claimed_ts)
                     << "  ground_truth=" << (is_attack ? "ATTACK" : "legitimate")
                     << "  trig_A=" << trig_a << "  trig_B=" << trig_b
                     << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Controller socket: receive topology updates (TTW / ME)
// Fires when a TemporalTopoTag packet arrives on TOPO_PORT
// ─────────────────────────────────────────────────────────────
static void TMBSM_TopoSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TemporalTopoTag tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        uint32_t src      = tag.GetSrcId();
        uint32_t dst      = tag.GetDstId();
        double   cts      = tag.GetClaimedTs();
        uint32_t rep      = tag.GetReporterId();
        double   rx_time  = Simulator::Now().GetSeconds();

        // Oracle
        bool is_attack = g_oracle_topo_attack.count(rep) && g_oracle_topo_attack[rep];

        // Positions for ME range check
        double rep_x=0, rep_y=0, src_x=0, src_y=0, dst_x=0, dst_y=0, _v=0;
        if (src < Vehicle_Nodes.GetN()) GetKinematics(Vehicle_Nodes.Get(src), src_x, src_y, _v, _v);
        if (dst < Vehicle_Nodes.GetN()) GetKinematics(Vehicle_Nodes.Get(dst), dst_x, dst_y, _v, _v);
        if (rep < Vehicle_Nodes.GetN()) GetKinematics(Vehicle_Nodes.Get(rep), rep_x, rep_y, _v, _v);
        else if (RSU_Nodes.GetN() > 0) {
            GetKinematics(RSU_Nodes.Get(0), rep_x, rep_y, _v, _v);
        }

        // Determine if this is ME (multiple reporters) or TTW (same reporter replays)
        bool is_me_scenario = (attack_scenario >= 9 && attack_scenario <= 12);

        bool detected = false;
        bool trig_a   = false;
        bool trig_b   = false;

        if (is_me_scenario) {
            // ME detection: reporter density + range check
            std::string key = std::to_string(src) + "_" + std::to_string(dst);
            uint32_t before_count = static_cast<uint32_t>(g_link_reporters[key].size());
            detected = TMBSM_DetectME(src, dst, rep, cts, rx_time,
                                       rep_x, rep_y, src_x, src_y, dst_x, dst_y);
            uint32_t after_count  = static_cast<uint32_t>(g_link_reporters[key].size());
            double rhoMax = ComputeRhoMax();
            trig_a = (after_count > rhoMax * ME_SAFETY_FACTOR);
            trig_b = (Dist2D(rep_x,rep_y,src_x,src_y) > COMM_RANGE_M &&
                      Dist2D(rep_x,rep_y,dst_x,dst_y) > COMM_RANGE_M);
        } else {
            // TTW detection: stale timestamp + regression
            trig_a = ((rx_time - cts) > BEACON_INTERVAL_S + STALE_EPS_S);
            std::string key = std::to_string(src) + "_" + std::to_string(dst);
            trig_b = (!g_topo_history[key].empty() &&
                      cts < g_topo_history[key].back().claimed_ts);
            detected = TMBSM_DetectTopo(src, dst, cts, rep, rx_time);
        }

        if (is_attack && !pem_attack_active) {
            pem_attack_active     = true;
            pem_attack_start_time = rx_time;
        }

        TMBSM_RecordOutcome(is_attack, detected, rx_time, "TOPO_UPDATE",
                             rep, src, src, dst, cts, trig_a, trig_b);
    }
}

// ─────────────────────────────────────────────────────────────
// Controller socket: receive heartbeats (BSHH)
// Fires when a TemporalHBTag packet arrives on HB_PORT
// ─────────────────────────────────────────────────────────────
static void TMBSM_HBSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TemporalHBTag tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        uint32_t claimed  = tag.GetClaimedSender();
        uint32_t physical = tag.GetPhysicalSender();
        double   hb_ts    = tag.GetHbTs();
        double   rx_time  = Simulator::Now().GetSeconds();

        bool is_attack = g_oracle_hb_attack.count(physical) && g_oracle_hb_attack[physical];

        bool trig_a = (physical != claimed);
        bool trig_b = (g_hb_history.count(claimed) && hb_ts < g_hb_history[claimed].hb_ts);
        bool detected = TMBSM_DetectHB(claimed, physical, hb_ts, rx_time);

        if (is_attack && !pem_attack_active) {
            pem_attack_active     = true;
            pem_attack_start_time = rx_time;
        }

        TMBSM_RecordOutcome(is_attack, detected, rx_time, "HEARTBEAT",
                             physical, claimed, claimed, 0, hb_ts, trig_a, trig_b);
    }
}

// ─────────────────────────────────────────────────────────────
// Send helpers — create real NS-3 UDP packets with tags
// ─────────────────────────────────────────────────────────────
static void TMBSM_SendTopoPacket(uint32_t veh_idx,
                                   uint32_t src_id, uint32_t dst_id,
                                   double claimed_ts, uint32_t reporter_id,
                                   bool is_attack_oracle)
{
    if (veh_idx >= Vehicle_Nodes.GetN() && veh_idx != 0xFFFFFFFF) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_topo_attack[reporter_id] = is_attack_oracle;

    Ptr<Node> src_node = Vehicle_Nodes.Get(veh_idx);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(src_node, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_veh[veh_idx], TOPO_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalTopoTag tag;
    tag.SetSrcId(src_id);
    tag.SetDstId(dst_id);
    tag.SetClaimedTs(claimed_ts);
    tag.SetReporterId(reporter_id);
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    sock->Close();
}

static void TMBSM_RSUSendTopoPacket(uint32_t src_id, uint32_t dst_id,
                                      double claimed_ts, uint32_t reporter_id,
                                      bool is_attack_oracle)
{
    if (RSU_Nodes.GetN() == 0) return;

    g_oracle_topo_attack[reporter_id] = is_attack_oracle;

    Ptr<Node> rsu = RSU_Nodes.Get(0);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, TOPO_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalTopoTag tag;
    tag.SetSrcId(src_id);
    tag.SetDstId(dst_id);
    tag.SetClaimedTs(claimed_ts);
    tag.SetReporterId(reporter_id);
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    sock->Close();
}

static void TMBSM_SendHBPacket(uint32_t veh_idx,
                                uint32_t claimed_sender, uint32_t physical_sender,
                                double hb_ts, bool is_attack_oracle)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_hb_attack[physical_sender] = is_attack_oracle;

    Ptr<Node> src_node = Vehicle_Nodes.Get(veh_idx);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(src_node, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_veh[veh_idx], HB_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalHBTag tag;
    tag.SetClaimedSender(claimed_sender);
    tag.SetPhysicalSender(physical_sender);
    tag.SetHbTs(hb_ts);
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    sock->Close();
}

static void TMBSM_RSUSendHBPacket(uint32_t claimed_sender, uint32_t physical_sender,
                                    double hb_ts, bool is_attack_oracle)
{
    if (RSU_Nodes.GetN() == 0) return;
    uint32_t rsu_id = RSU_Nodes.Get(0)->GetId();
    g_oracle_hb_attack[physical_sender] = is_attack_oracle;

    Ptr<Node> rsu = RSU_Nodes.Get(0);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, HB_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalHBTag tag;
    tag.SetClaimedSender(claimed_sender);
    tag.SetPhysicalSender(physical_sender);
    tag.SetHbTs(hb_ts);
    pkt->AddPacketTag(tag);

    sock->Send(pkt);
    sock->Close();
    (void)rsu_id;
}

// ─────────────────────────────────────────────────────────────
// For S3/S4 (malicious controller): direct table injection
// No actual packet sent. The monitoring module detects at inject time.
// ─────────────────────────────────────────────────────────────
static void TMBSM_ControllerInternalTopoReplay(uint32_t src_id, uint32_t dst_id,
                                                 double stale_ts)
{
    double rx_time = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = rx_time;
    }

    bool trig_a = ((rx_time - stale_ts) > BEACON_INTERVAL_S + STALE_EPS_S);
    std::string key = std::to_string(src_id) + "_" + std::to_string(dst_id);
    bool trig_b = (!g_topo_history[key].empty() &&
                   stale_ts < g_topo_history[key].back().claimed_ts);
    bool detected = trig_a || trig_b;

    if (detected && pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
    if (detected) pem_tp++; else pem_fn++;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                     << "]  CTRL-INTERNAL-REPLAY  link=" << src_id << "↔" << dst_id
                     << "  stale_ts=" << stale_ts
                     << "  rx_delay=" << (rx_time-stale_ts)
                     << "  trig_A=" << trig_a << "  trig_B=" << trig_b
                     << "  detected=" << detected << "\n";
        g_attack_log.flush();
    }

    if (g_events_csv.is_open()) {
        g_events_csv << std::fixed << std::setprecision(4)
            << rx_time << "," << attack_scenario << ",CTRL_REPLAY,"
            << 0 << "," << stale_ts << "," << rx_time << ","
            << (rx_time-stale_ts) << ","
            << 0 << "," << src_id << "," << dst_id << ","
            << 0 << "," << src_id << ","
            << 1 << "," << (trig_a?1:0) << "," << (trig_b?1:0) << ","
            << (detected?1:0) << "\n";
    }
}

static void TMBSM_ControllerInternalHBReplay(uint32_t claimed_sender, double stale_ts)
{
    double rx_time = Simulator::Now().GetSeconds();

    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = rx_time;
    }

    bool trig_a = false;  // controller "claims" it is replaying its own entry — no sender mismatch visible
    bool trig_b = (g_hb_history.count(claimed_sender) &&
                   stale_ts < g_hb_history[claimed_sender].hb_ts);
    bool detected = trig_b;   // only Trigger B fires for S3/S4 BSHH

    if (detected && pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
    if (detected) pem_tp++; else pem_fn++;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                     << "]  CTRL-INTERNAL-HB-REPLAY  claimed=" << claimed_sender
                     << "  stale_ts=" << stale_ts
                     << "  trig_B=" << trig_b
                     << "  detected=" << detected << "\n";
        g_attack_log.flush();
    }

    if (g_events_csv.is_open()) {
        g_events_csv << std::fixed << std::setprecision(4)
            << rx_time << "," << attack_scenario << ",CTRL_HB_REPLAY,"
            << claimed_sender << "," << stale_ts << "," << rx_time << ","
            << (rx_time-stale_ts) << ","
            << claimed_sender << "," << 0 << "," << 0 << ","
            << claimed_sender << "," << claimed_sender << ","
            << 1 << "," << 0 << "," << (trig_b?1:0) << ","
            << (detected?1:0) << "\n";
    }
}

// ─────────────────────────────────────────────────────────────
// Legitimate periodic topology sender (TTW / ME baseline)
// ─────────────────────────────────────────────────────────────
static void TMBSM_LegitTopoTick(uint32_t veh_idx, double t_end)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t nid = node->GetId();
    double now = Simulator::Now().GetSeconds();

    // Each vehicle reports itself as observing its nearest neighbour
    // For simplicity, report (self → next_veh) link
    uint32_t next_veh = (veh_idx + 1) % Vehicle_Nodes.GetN();
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_topo_attack[nid] = false;
    TMBSM_SendTopoPacket(veh_idx, nid, next_veh, now, nid, false);

    // Schedule next legitimate tick
    double next = now + BEACON_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BEACON_INTERVAL_S),
                            &TMBSM_LegitTopoTick, veh_idx, t_end);
    }
}

// ─────────────────────────────────────────────────────────────
// Legitimate periodic heartbeat sender (BSHH baseline)
// ─────────────────────────────────────────────────────────────
static void TMBSM_LegitHBTick(uint32_t veh_idx, double t_end)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    uint32_t nid = node->GetId();
    double now = Simulator::Now().GetSeconds();

    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_hb_attack[nid] = false;
    TMBSM_SendHBPacket(veh_idx, nid, nid, now, false);

    double next = now + BEACON_INTERVAL_S;
    if (next < t_end) {
        Simulator::Schedule(Seconds(BEACON_INTERVAL_S),
                            &TMBSM_LegitHBTick, veh_idx, t_end);
    }
}

// ─────────────────────────────────────────────────────────────
// TTW Attack Functions
// ─────────────────────────────────────────────────────────────

// Stored packet (simulated — attacker notes the obs_time)
static double g_ttw_stored_ts  = 0.0;
static uint32_t g_ttw_src_id   = 0;
static uint32_t g_ttw_dst_id   = 1;

static void TMBSM_TTW_HelloAndStore(uint32_t src_id, uint32_t dst_id)
{
    double now = Simulator::Now().GetSeconds();
    g_ttw_stored_ts = now;
    g_ttw_src_id    = src_id;
    g_ttw_dst_id    = dst_id;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW STEP 1+2: Hello exchange + legitimate topology update\n"
                     << "  V" << src_id << " sees V" << dst_id << "  claimed_ts=" << now << "\n"
                     << "  Attacker stores this packet for later replay.\n\n";
        g_attack_log.flush();
    }
}

static void TMBSM_TTW_LinkBreak(uint32_t src_id, uint32_t dst_id)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW STEP 3: Physical link V" << src_id << "↔V" << dst_id
                     << " broken (vehicles moved apart)\n\n";
        g_attack_log.flush();
    }
}

// S1: Malicious vehicle replays
static void TMBSM_TTW_S1_Replay(uint32_t attacker_veh_idx,
                                   uint32_t src_id, uint32_t dst_id, double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S1 ATTACK: Malicious V" << attacker_veh_idx
                     << " replays <V" << src_id << " sees V" << dst_id
                     << "> with FORGED claimed_ts=" << forged_ts
                     << " (stored at t=" << g_ttw_stored_ts << ")\n"
                     << "  Reception delay will be ~" << (now - forged_ts)
                     << "s  (threshold=" << (BEACON_INTERVAL_S + STALE_EPS_S) << "s)\n\n";
        g_attack_log.flush();
    }

    uint32_t attacker_node_id = Vehicle_Nodes.Get(attacker_veh_idx)->GetId();
    TMBSM_SendTopoPacket(attacker_veh_idx, src_id, dst_id, forged_ts, attacker_node_id, true);
}

// S2: Malicious RSU replays (forwards forged packet to controller)
static void TMBSM_TTW_S2_Replay(uint32_t src_id, uint32_t dst_id, double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    uint32_t rsu_node_id = (RSU_Nodes.GetN() > 0) ? RSU_Nodes.Get(0)->GetId() : 0xFFFE;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S2 ATTACK: Malicious RSU replays <V" << src_id
                     << " sees V" << dst_id << "> with FORGED claimed_ts=" << forged_ts << "\n\n";
        g_attack_log.flush();
    }

    TMBSM_RSUSendTopoPacket(src_id, dst_id, forged_ts, rsu_node_id, true);
}

// S3/S4: Malicious controller internally replays
static void TMBSM_TTW_S34_InternalReplay(uint32_t src_id, uint32_t dst_id, double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S3/S4 ATTACK: Malicious controller internally replays\n"
                     << "  <V" << src_id << " sees V" << dst_id
                     << "> with FORGED claimed_ts=" << forged_ts << "\n\n";
        g_attack_log.flush();
    }
    TMBSM_ControllerInternalTopoReplay(src_id, dst_id, forged_ts);
}

// ─────────────────────────────────────────────────────────────
// BSHH Attack Functions
// ─────────────────────────────────────────────────────────────

static double g_bshh_stored_hb_ts  = 0.0;
static uint32_t g_bshh_victim_id   = 1;

static void TMBSM_BSHH_StoreHeartbeat(uint32_t victim_id, double hb_ts)
{
    g_bshh_stored_hb_ts = hb_ts;
    g_bshh_victim_id    = victim_id;
    double now = Simulator::Now().GetSeconds();

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH STEP 1: Attacker captures V" << victim_id
                     << "'s heartbeat (ts=" << hb_ts << ")\n\n";
        g_attack_log.flush();
    }
}

// S1: Malicious vehicle hijacks victim's identity
static void TMBSM_BSHH_S1_Replay(uint32_t attacker_veh_idx,
                                    uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    uint32_t attacker_id = Vehicle_Nodes.Get(attacker_veh_idx)->GetId();

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S1 ATTACK: V" << attacker_id
                     << " impersonates V" << victim_id
                     << "  claimed_sender=" << victim_id
                     << "  physical_sender=" << attacker_id
                     << "  hb_ts=" << stored_ts << "\n"
                     << "  Triggers: A (identity mismatch) + B (ts regression if < last known)\n\n";
        g_attack_log.flush();
    }

    TMBSM_SendHBPacket(attacker_veh_idx, victim_id, attacker_id, stored_ts, true);
}

// S2: Malicious RSU replays victim's heartbeat
static void TMBSM_BSHH_S2_Replay(uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    uint32_t rsu_id = (RSU_Nodes.GetN() > 0) ? RSU_Nodes.Get(0)->GetId() : 0xFFFE;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S2 ATTACK: Malicious RSU replays V" << victim_id
                     << "'s heartbeat  physical_sender=RSU(" << rsu_id << ")"
                     << "  claimed=" << victim_id
                     << "  hb_ts=" << stored_ts << "\n\n";
        g_attack_log.flush();
    }

    TMBSM_RSUSendHBPacket(victim_id, rsu_id, stored_ts, true);
}

// S3/S4: Malicious controller internally re-injects stale heartbeat
static void TMBSM_BSHH_S34_InternalReplay(uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S3/S4 ATTACK: Malicious controller replays V" << victim_id
                     << "'s heartbeat internally  hb_ts=" << stored_ts << "\n\n";
        g_attack_log.flush();
    }
    TMBSM_ControllerInternalHBReplay(victim_id, stored_ts);
}

// ─────────────────────────────────────────────────────────────
// ME Attack Functions
// ─────────────────────────────────────────────────────────────

// S1: Echo vehicles (V3, V4) report the same V1↔V2 link
static void TMBSM_ME_S1_EchoAttack(uint32_t echo_v3_idx, uint32_t echo_v4_idx,
                                     uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S1 ATTACK: Echo vehicles V" << echo_v3_idx
                     << " and V" << echo_v4_idx
                     << " report V" << link_src << "↔V" << link_dst
                     << " (phantom paths created)\n\n";
        g_attack_log.flush();
    }

    if (echo_v3_idx < Vehicle_Nodes.GetN()) {
        uint32_t v3_id = Vehicle_Nodes.Get(echo_v3_idx)->GetId();
        TMBSM_SendTopoPacket(echo_v3_idx, link_src, link_dst, t, v3_id, true);
    }
    if (echo_v4_idx < Vehicle_Nodes.GetN()) {
        uint32_t v4_id = Vehicle_Nodes.Get(echo_v4_idx)->GetId();
        TMBSM_SendTopoPacket(echo_v4_idx, link_src, link_dst, t, v4_id, true);
    }
}

// S2: Malicious RSU injects fake echo reports for phantom reporters
static void TMBSM_ME_S2_EchoAttack(uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    uint32_t fake_v3 = 9901;  // phantom reporter IDs that don't exist as real nodes
    uint32_t fake_v4 = 9902;

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S2 ATTACK: Malicious RSU injects fake reporters "
                     << fake_v3 << " and " << fake_v4
                     << " for V" << link_src << "↔V" << link_dst << "\n\n";
        g_attack_log.flush();
    }

    // RSU sends two topology packets with fake reporter IDs
    g_oracle_topo_attack[fake_v3] = true;
    g_oracle_topo_attack[fake_v4] = true;

    if (RSU_Nodes.GetN() > 0) {
        Ptr<Node> rsu = RSU_Nodes.Get(0);
        TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");

        // fake_v3 echo
        {
            Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
            sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, TOPO_PORT));
            Ptr<Packet> pkt = Create<Packet>(0);
            TemporalTopoTag tag;
            tag.SetSrcId(link_src); tag.SetDstId(link_dst);
            tag.SetClaimedTs(t); tag.SetReporterId(fake_v3);
            pkt->AddPacketTag(tag);
            sock->Send(pkt); sock->Close();
        }
        // fake_v4 echo
        {
            Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
            sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, TOPO_PORT));
            Ptr<Packet> pkt = Create<Packet>(0);
            TemporalTopoTag tag;
            tag.SetSrcId(link_src); tag.SetDstId(link_dst);
            tag.SetClaimedTs(t); tag.SetReporterId(fake_v4);
            pkt->AddPacketTag(tag);
            sock->Send(pkt); sock->Close();
        }
    }
}

// S3/S4: Malicious controller directly adds phantom echo entries
static void TMBSM_ME_S34_EchoAttack(uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = now;
    }

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S3/S4 ATTACK: Malicious controller adds phantom echo entries "
                     << "for V" << link_src << "↔V" << link_dst << "\n\n";
        g_attack_log.flush();
    }

    std::string key = std::to_string(link_src) + "_" + std::to_string(link_dst);
    g_link_reporters[key].insert(9901);
    g_link_reporters[key].insert(9902);

    uint32_t count = static_cast<uint32_t>(g_link_reporters[key].size());
    double rhoMax  = ComputeRhoMax();
    bool trig_a    = (count > rhoMax * ME_SAFETY_FACTOR);
    bool detected  = trig_a;

    if (detected && pem_first_alert_time < 0.0) pem_first_alert_time = now;
    if (detected) pem_tp++; else pem_fn++;

    if (g_events_csv.is_open()) {
        g_events_csv << std::fixed << std::setprecision(4)
            << now << "," << attack_scenario << ",CTRL_ME_ECHO,"
            << 0 << "," << t << "," << now << ","
            << (now-t) << ","
            << 9901 << "," << link_src << "," << link_dst << ","
            << 9901 << "," << link_src << ","
            << 1 << "," << (trig_a?1:0) << ",0,"
            << (detected?1:0) << "\n";
    }

    if (detected && g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ALERT  CTRL_ME_ECHO  reporter_count=" << count
                     << "  rhoMax=" << rhoMax << "  detected=YES\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Network setup — P2P star, each vehicle/RSU → controller
// Subnet 10.3.x.x (avoids 10.1 multibsm, 10.2 veremi)
// ─────────────────────────────────────────────────────────────
static void TMBSM_SetupNetwork()
{
    Controller_Node.Create(1);

    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);
    internet.Install(Controller_Node);
    if (RSU_Nodes.GetN() > 0) internet.Install(RSU_Nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",   StringValue("1ms"));

    Ipv4AddressHelper addr;
    g_veh_ip.resize(Vehicle_Nodes.GetN());
    g_ctrl_ip_for_veh.resize(Vehicle_Nodes.GetN());

    // Vehicle[i] ↔ Controller on 10.3.(i+1).0/30
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i));
        pair.Add(Controller_Node.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);

        std::ostringstream ip_base;
        ip_base << "10.3." << (i + 1) << ".0";
        addr.SetBase(ip_base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);
        g_veh_ip[i]            = ifaces.GetAddress(0);
        g_ctrl_ip_for_veh[i]   = ifaces.GetAddress(1);
    }

    // RSU ↔ Controller on 10.3.100.0/30
    if (RSU_Nodes.GetN() > 0) {
        NodeContainer pair;
        pair.Add(RSU_Nodes.Get(0));
        pair.Add(Controller_Node.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);
        addr.SetBase("10.3.100.0", "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);
        g_rsu_ip           = ifaces.GetAddress(0);
        g_ctrl_ip_for_rsu  = ifaces.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Controller topology socket (TOPO_PORT)
    g_ctrl_topo_sock = Socket::CreateSocket(
        Controller_Node.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_ctrl_topo_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), TOPO_PORT));
    g_ctrl_topo_sock->SetRecvCallback(MakeCallback(&TMBSM_TopoSocketReceive));

    // Controller heartbeat socket (HB_PORT)
    g_ctrl_hb_sock = Socket::CreateSocket(
        Controller_Node.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_ctrl_hb_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), HB_PORT));
    g_ctrl_hb_sock->SetRecvCallback(MakeCallback(&TMBSM_HBSocketReceive));

    // PacketSink on port 9 for NetAnim compatibility
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), 9));
    ApplicationContainer sinks = sink.Install(Controller_Node.Get(0));
    sinks.Start(Seconds(0.0)); sinks.Stop(Seconds(simTime));
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        ApplicationContainer vs = sink.Install(Vehicle_Nodes.Get(i));
        vs.Start(Seconds(0.0)); vs.Stop(Seconds(simTime));
    }
    if (RSU_Nodes.GetN() > 0) {
        ApplicationContainer rs = sink.Install(RSU_Nodes.Get(0));
        rs.Start(Seconds(0.0)); rs.Stop(Seconds(simTime));
    }
}

// ─────────────────────────────────────────────────────────────
// NetAnim — colour scheme: red=attacker, green=legit, amber=RSU, blue=controller
// ─────────────────────────────────────────────────────────────
static void TMBSM_SetupNetAnim()
{
    if (!g_anim) return;

    // Controller: blue
    uint32_t ctrl_id = Controller_Node.Get(0)->GetId();
    g_anim->UpdateNodeColor(ctrl_id, 0, 100, 255);
    g_anim->UpdateNodeSize(ctrl_id, 40, 40);
    g_anim->UpdateNodeDescription(ctrl_id, "CONTROLLER");

    // RSU: amber
    if (RSU_Nodes.GetN() > 0) {
        uint32_t rsu_id = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rsu_id, 255, 200, 0);
        g_anim->UpdateNodeSize(rsu_id, 35, 35);
        g_anim->UpdateNodeDescription(rsu_id,
            (attack_scenario == 2 || attack_scenario == 6 || attack_scenario == 10)
            ? "MALICIOUS-RSU" : "RSU");
    }

    // Vehicles
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid = Vehicle_Nodes.Get(i)->GetId();
        bool is_attacker = (attack_scenario != 0) && (i == attacker_idx) &&
                           (attack_scenario % 4 == 1);  // S1 attacks: vehicle is malicious
        if (is_attacker) {
            g_anim->UpdateNodeColor(nid, 255, 0, 0);
            g_anim->UpdateNodeSize(nid, 30, 30);
            g_anim->UpdateNodeDescription(nid, "ATTACKER");
        } else {
            g_anim->UpdateNodeColor(nid, 0, 200, 60);
            g_anim->UpdateNodeSize(nid, 20, 20);
            g_anim->UpdateNodeDescription(nid, "V" + std::to_string(i));
        }
    }
    g_anim->EnablePacketMetadata(true);
}

// ─────────────────────────────────────────────────────────────
// Log initialisation
// ─────────────────────────────────────────────────────────────
static const std::string AttackName(uint32_t s)
{
    switch (s) {
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
        default: return "Baseline (No Attack)";
    }
}

static void TMBSM_InitLogs()
{
    std::string txt_name = (attack_scenario == 0)
        ? "temporal_mbsm_baseline.txt"
        : "temporal_mbsm_attack" + std::to_string(attack_scenario) + ".txt";

    g_attack_log.open(txt_name, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Temporal-Echo Attack Log — Multi-BSM Detection\n"
        << "  Attack   : " << AttackName(attack_scenario) << "\n"
        << "  Based on : Trabelsi et al., Electronics 2022, 11, 3282\n"
        << "  Adapted  : Algorithm 1 for TTW / BSHH / ME temporal attacks\n"
        << "----------------------------------------------------------------\n"
        << "  sim_time  : " << simTime       << " s\n"
        << "  Vehicles  : " << N_Vehicles     << "\n"
        << "  RSUs      : " << N_RSUs         << "\n"
        << "  Scenario  : " << attack_scenario << "\n"
        << "  Detection thresholds:\n"
        << "    Trigger A staleness > " << (BEACON_INTERVAL_S + STALE_EPS_S) << " s\n"
        << "    Trigger B = timestamp regression (ts < prev_ts)\n"
        << "    ME Trigger A = reporters > " << ComputeRhoMax() * ME_SAFETY_FACTOR << "\n"
        << "    ME Trigger B = reporter > " << COMM_RANGE_M << " m from link\n"
        << "================================================================\n\n";
    g_attack_log.flush();

    g_events_csv.open("temporal_mbsm_events.csv", std::ios::out | std::ios::trunc);
    g_events_csv
        << "sim_time_s,attack_scenario,event_type,physical_sender_id,"
        << "claimed_ts,rx_time,rx_delay_s,reporter_id,link_src_id,link_dst_id,"
        << "physical_sender_id2,claimed_sender_id,is_attack,trigger_a,trigger_b,alert_raised\n";
}

// ─────────────────────────────────────────────────────────────
// Write PEM run summary — mirrors MBSM_WriteSummary() pattern
// ─────────────────────────────────────────────────────────────
static void TMBSM_WriteSummary()
{
    double tp = static_cast<double>(pem_tp);
    double tn = static_cast<double>(pem_tn);
    double fp = static_cast<double>(pem_fp);
    double fn = static_cast<double>(pem_fn);

    double mcc_denom = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    double mcc = (mcc_denom > 0.0) ? ((tp*tn - fp*fn) / mcc_denom) : 0.0;

    double total     = tp + tn + fp + fn;
    double acr       = (total > 0.0) ? ((tp+tn) / total * 100.0) : 0.0;
    double precision = (tp+fp > 0.0) ? (tp / (tp+fp)) : 0.0;
    double recall    = (tp+fn > 0.0) ? (tp / (tp+fn)) : 0.0;
    double tdet_ms   = -1.0;
    if (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0)
        tdet_ms = (pem_first_alert_time - pem_attack_start_time) * 1000.0;

    std::ofstream sum("temporal_mbsm_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,attack_name,tp,tn,fp,fn,mcc,acr_pct,precision,recall,tdet_ms\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ",\"" << AttackName(attack_scenario) << "\","
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc << "," << acr << "," << precision << "," << recall << "," << tdet_ms << "\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n========== RUN SUMMARY (Multi-BSM adapted detection) ==========\n"
            << "  attack_scenario : " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
            << "  TP / TN / FP / FN : " << pem_tp << " / " << pem_tn << " / " << pem_fp << " / " << pem_fn << "\n"
            << "  MCC               : " << std::fixed << std::setprecision(3) << mcc << "\n"
            << "  ACR (Accuracy)    : " << acr << " %\n"
            << "  Precision         : " << precision << "\n"
            << "  Recall            : " << recall << "\n"
            << "  Tdet              : " << tdet_ms << " ms\n"
            << "================================================================\n";
        g_attack_log.flush();
    }

    std::cout << "\n[TemporalMBSM] Summary → temporal_mbsm_summary.csv\n"
              << "  Scenario " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
              << "  TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp  << " FN=" << pem_fn
              << "  MCC=" << std::fixed << std::setprecision(3) << mcc
              << "  ACR=" << acr << "%  Tdet=" << tdet_ms << " ms\n";
}

// ─────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",         "Simulation duration (s)",             simTime);
    cmd.AddValue("N_Vehicles",      "Number of vehicle nodes",             N_Vehicles);
    cmd.AddValue("N_RSUs",          "Number of RSU nodes (0 or 1)",        N_RSUs);
    cmd.AddValue("attack_scenario", "1-12 = specific attack; 0 = baseline",attack_scenario);
    cmd.AddValue("attacker_idx",    "0-based index of malicious vehicle",   attacker_idx);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 2)            N_Vehicles   = 2;
    if (N_RSUs     > 1)            N_RSUs        = 1;
    if (attacker_idx >= N_Vehicles) attacker_idx = 0;

    // S2/S4/S6/S8/S10/S12 require RSU; enforce consistency
    bool needs_rsu = (attack_scenario == 2 || attack_scenario == 4 ||
                      attack_scenario == 6 || attack_scenario == 8 ||
                      attack_scenario == 10|| attack_scenario == 12);
    if (needs_rsu && N_RSUs == 0) { N_RSUs = 1; }

    // ME scenarios need at least 4 vehicles
    bool is_me = (attack_scenario >= 9 && attack_scenario <= 12);
    if (is_me && N_Vehicles < 4) N_Vehicles = 4;

    TMBSM_InitLogs();

    std::cout << "\n======== Temporal-Echo Multi-BSM Detector ========\n"
              << "  attack_scenario : " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
              << "  N_Vehicles      : " << N_Vehicles  << "\n"
              << "  N_RSUs          : " << N_RSUs      << "\n"
              << "  simTime         : " << simTime     << " s\n"
              << "  attacker_idx    : " << attacker_idx << "\n"
              << "  Detection       : Multi-BSM Algorithm 1 (adapted)\n"
              << "==================================================\n\n";

    // ── Create nodes ─────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(1);

    // ── Vehicle mobility ─────────────────────────────────────
    MobilityHelper mobV;
    mobV.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobV.Install(Vehicle_Nodes);

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        auto mob = DynamicCast<ConstantVelocityMobilityModel>(
            Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
        if (!mob) continue;
        double spd = SPEED_MIN_MS + (SPEED_MAX_MS - SPEED_MIN_MS) *
                     (N_Vehicles > 1 ? static_cast<double>(i) / (N_Vehicles - 1) : 0.0);
        mob->SetPosition(Vector(50.0 + i * 80.0, static_cast<double>(i) * 8.0, 0.0));
        mob->SetVelocity(Vector(spd, 0.0, 0.0));
    }

    // ── RSU mobility — fixed at road centre ──────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
        auto mob = DynamicCast<ConstantPositionMobilityModel>(
            RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (mob) {
            double cx = 50.0 + (N_Vehicles / 2.0) * 80.0;
            double cy = (N_Vehicles > 1) ? ((N_Vehicles - 1) * 8.0 / 2.0) : 0.0;
            mob->SetPosition(Vector(cx, cy, 0.0));
        }
    }

    // ── Controller mobility — fixed ───────────────────────────
    // Created inside SetupNetwork(); position set after
    TMBSM_SetupNetwork();

    {
        MobilityHelper mobC;
        mobC.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobC.Install(Controller_Node);
        auto mob = DynamicCast<ConstantPositionMobilityModel>(
            Controller_Node.Get(0)->GetObject<MobilityModel>());
        if (mob) mob->SetPosition(Vector(500.0, -50.0, 0.0));
    }

    // ── Schedule attack events ────────────────────────────────
    bool is_ttw  = (attack_scenario >= 1 && attack_scenario <= 4);
    bool is_bshh = (attack_scenario >= 5 && attack_scenario <= 8);
    // is_me already set above

    double t_end = simTime - 1.0;

    if (attack_scenario == 0) {
        // Baseline: all vehicles send legitimate topology beacons
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
            Simulator::Schedule(Seconds(0.1 + i * 0.01), &TMBSM_LegitTopoTick, i, t_end);
        }
    } else if (is_ttw) {
        // Legitimate topology beacons from all vehicles before attack
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
            Simulator::Schedule(Seconds(0.1 + i * 0.01), &TMBSM_LegitTopoTick, i, t_end);
        }

        uint32_t src_id = (attack_scenario == 1) ? Vehicle_Nodes.Get(0)->GetId() : Vehicle_Nodes.Get(1)->GetId();
        uint32_t dst_id = (attack_scenario == 1) ? Vehicle_Nodes.Get(1)->GetId() : Vehicle_Nodes.Get(2 % N_Vehicles)->GetId();

        // Store packet at HELLO_TIME
        Simulator::Schedule(Seconds(TTW_HELLO_TIME),  &TMBSM_TTW_HelloAndStore, src_id, dst_id);
        // Physical link breaks at LINK_BREAK
        Simulator::Schedule(Seconds(TTW_LINK_BREAK),  &TMBSM_TTW_LinkBreak, src_id, dst_id);

        if (attack_scenario == 1) {
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
                &TMBSM_TTW_S1_Replay, attacker_idx, src_id, dst_id, TTW_HELLO_TIME);
        } else if (attack_scenario == 2) {
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
                &TMBSM_TTW_S2_Replay, src_id, dst_id, TTW_HELLO_TIME);
        } else if (attack_scenario == 3 || attack_scenario == 4) {
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME),
                &TMBSM_TTW_S34_InternalReplay, src_id, dst_id, TTW_HELLO_TIME);
        }
    } else if (is_bshh) {
        // Legitimate heartbeats from all vehicles
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
            Simulator::Schedule(Seconds(0.1 + i * 0.01), &TMBSM_LegitHBTick, i, t_end);
        }

        uint32_t victim_id    = Vehicle_Nodes.Get(1 % N_Vehicles)->GetId();
        uint32_t attacker_nid = Vehicle_Nodes.Get(attacker_idx)->GetId();
        (void)attacker_nid;

        // Attacker captures victim's heartbeat at STORE_TIME
        Simulator::Schedule(Seconds(BSHH_STORE_TIME),
            &TMBSM_BSHH_StoreHeartbeat, victim_id, BSHH_STORE_TIME - 1.0);

        if (attack_scenario == 5) {
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
                &TMBSM_BSHH_S1_Replay, attacker_idx, victim_id, BSHH_STORE_TIME - 1.0);
        } else if (attack_scenario == 6) {
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
                &TMBSM_BSHH_S2_Replay, victim_id, BSHH_STORE_TIME - 1.0);
        } else if (attack_scenario == 7 || attack_scenario == 8) {
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME),
                &TMBSM_BSHH_S34_InternalReplay, victim_id, BSHH_STORE_TIME - 1.0);
        }
    } else if (is_me) {
        uint32_t v1 = Vehicle_Nodes.Get(0)->GetId();
        uint32_t v2 = Vehicle_Nodes.Get(1 % N_Vehicles)->GetId();

        // Legitimate discovery: V1 and V2 report each other
        Simulator::Schedule(Seconds(9.9), [v1, v2]() {
            if (Vehicle_Nodes.GetN() > 0 && !g_ctrl_ip_for_veh.empty())
                TMBSM_SendTopoPacket(0, v1, v2, 9.9, v1, false);
        });
        Simulator::Schedule(Seconds(9.95), [v1, v2]() {
            if (Vehicle_Nodes.GetN() > 1 && !g_ctrl_ip_for_veh.empty())
                TMBSM_SendTopoPacket(1, v2, v1, 9.95, v2, false);
        });

        // Legitimate ongoing beacons
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
            Simulator::Schedule(Seconds(0.1 + i * 0.01), &TMBSM_LegitTopoTick, i, t_end);
        }

        if (attack_scenario == 9) {
            uint32_t v3_idx = 2 % N_Vehicles;
            uint32_t v4_idx = 3 % N_Vehicles;
            Simulator::Schedule(Seconds(ME_ECHO_TIME),
                &TMBSM_ME_S1_EchoAttack, v3_idx, v4_idx, v1, v2, 10.0);
        } else if (attack_scenario == 10) {
            Simulator::Schedule(Seconds(ME_ECHO_TIME),
                &TMBSM_ME_S2_EchoAttack, v1, v2, 10.0);
        } else if (attack_scenario == 11 || attack_scenario == 12) {
            Simulator::Schedule(Seconds(ME_ECHO_TIME),
                &TMBSM_ME_S34_EchoAttack, v1, v2, 10.0);
        }
    }

    // ── Write summary at end ─────────────────────────────────
    Simulator::Schedule(Seconds(simTime - 0.05), &TMBSM_WriteSummary);

    // ── NetAnim ───────────────────────────────────────────────
    std::string anim_xml = "temporal_mbsm_anim_scenario" +
                           std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    TMBSM_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim; g_anim = nullptr;
    if (g_attack_log.is_open()) g_attack_log.close();
    if (g_events_csv.is_open()) g_events_csv.close();

    return 0;
}
