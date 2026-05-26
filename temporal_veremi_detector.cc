// ============================================================
// temporal_veremi_detector.cc
// Temporal-Echo Attack Simulation — VeReMi-Style Feature Extraction
//
// Based on: Mekonen, H.D.; Bitew, M.A.; Kifle, M.
//   "VeReMi Dataset-Based Detection of Position Falsification
//    Attacks Using K-Nearest Neighbor and Bagging Ensemble
//    Learning in IoV."  PLOS ONE 2025
//
// Adapts the consecutive BSM-pair feature extraction approach of
// VeReMi to extract 9 temporal features from consecutive topology /
// heartbeat events for the Temporal-Echo attack families:
//   TTW  — 9 features from consecutive topology update pairs
//   BSHH — 9 features from consecutive heartbeat pairs
//   ME   — 9 features from consecutive reporter-count snapshots
//
// The 9 unified temporal features (per consecutive event pair):
//   1. ev_ts1         — previous event's claimed timestamp
//   2. ev_ts2         — current  event's claimed timestamp
//   3. ts_delta       — ev_ts2 - ev_ts1 (timestamp progression claimed)
//   4. rx_time1       — previous reception time
//   5. rx_time2       — current  reception time
//   6. time_interval  — rx_time2 - rx_time1 (actual inter-arrival)
//   7. rx_delay2      — rx_time2 - ev_ts2   (current packet staleness)
//   8. identity_match — 1.0 = physical_sender==claimed; 0.0 = mismatch
//   9. reporter_count — distinct reporters for this link/entity
//
// Attack scenarios (identical to routing.cc and temporal_mbsm_detector.cc):
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
//   ./waf --run "scratch/temporal_veremi_detector --simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1"
//   ./waf --run "scratch/temporal_veremi_detector --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=6"
//   ./waf --run "scratch/temporal_veremi_detector --simTime=60 --N_Vehicles=8 --N_RSUs=1 --attack_scenario=10"
//
// Then run the Python classifier on the output CSV:
//   python3 temporal_knn_detector.py temporal_veremi_pairs.csv
//
// Output files:
//   temporal_veremi_attack{1..12}.txt   — human-readable log
//   temporal_veremi_pairs.csv           — 9-feature consecutive event pairs
//   temporal_veremi_pem_summary.csv     — rule-based PEM (same as mbsm_detector)
//   temporal_veremi_anim_scenario{N}.xml — NetAnim visualisation
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
NS_LOG_COMPONENT_DEFINE("TemporalVeremiDetector");

// ─────────────────────────────────────────────────────────────
// Simulation parameters (command-line overridable)
// ─────────────────────────────────────────────────────────────
static double   simTime         = 60.0;
static uint32_t N_Vehicles      = 6;
static uint32_t N_RSUs          = 0;
static uint32_t attack_scenario = 1;
static uint32_t attacker_idx    = 0;

// ─────────────────────────────────────────────────────────────
// Physical / protocol constants
// ─────────────────────────────────────────────────────────────
static const double COMM_RANGE_M      = 300.0;
static const double BEACON_INTERVAL_S = 1.0;
static const double STALE_EPS_S       = 3.0;    // for rule-based PEM summary only
static const double SPEED_MIN_MS      = 8.0;
static const double SPEED_MAX_MS      = 20.0;
static const double ME_SAFETY_FACTOR  = 1.5;

static const double TTW_HELLO_TIME   = 10.0;
static const double TTW_LINK_BREAK   = 15.0;
static const double TTW_REPLAY_TIME  = 20.0;
static const double BSHH_STORE_TIME  = 5.0;
static const double BSHH_REPLAY_TIME = 10.0;
static const double ME_ECHO_TIME     = 10.05;

// Network: subnet 10.4.x (avoids 10.1=multibsm, 10.2=veremi, 10.3=mbsm-temporal)
static const uint16_t TOPO_PORT = 7781;
static const uint16_t HB_PORT   = 7782;

// ─────────────────────────────────────────────────────────────
// Node containers
// ─────────────────────────────────────────────────────────────
static NodeContainer Vehicle_Nodes;
static NodeContainer RSU_Nodes;
static NodeContainer Controller_Node;

static std::vector<Ipv4Address> g_ctrl_ip_for_veh;
static Ipv4Address              g_ctrl_ip_for_rsu;
static std::vector<Ipv4Address> g_veh_ip;

static Ptr<Socket> g_ctrl_topo_sock = nullptr;
static Ptr<Socket> g_ctrl_hb_sock   = nullptr;

static AnimationInterface* g_anim = nullptr;

// ─────────────────────────────────────────────────────────────
// Rule-based PEM counters (for pem_summary, same as MBSM file)
// Full KNN+Bagging classification done by temporal_knn_detector.py
// ─────────────────────────────────────────────────────────────
static uint64_t pem_tp = 0;
static uint64_t pem_tn = 0;
static uint64_t pem_fp = 0;
static uint64_t pem_fn = 0;
static double   pem_attack_start_time = -1.0;
static double   pem_first_alert_time  = -1.0;
static bool     pem_attack_active     = false;

// ─────────────────────────────────────────────────────────────
// Oracle maps — NOT in packets, same pattern as veremi_attacks.cc
// ─────────────────────────────────────────────────────────────
static std::map<uint32_t, bool> g_oracle_topo_attack;
static std::map<uint32_t, bool> g_oracle_hb_attack;

// ─────────────────────────────────────────────────────────────
// Previous-event state for consecutive pair extraction
// Mirrors g_prev_bsm in veremi_attacks.cc
// key for topo: "srcId_dstId"
// key for HB:   claimed_sender_id
// ─────────────────────────────────────────────────────────────
struct TemporalPrev {
    double   ev_ts;         // claimed timestamp of the previous event
    double   rx_time;       // reception time of the previous event
    uint32_t physical_id;   // physical sender
    uint32_t claimed_id;    // claimed sender/src
    bool     was_attack;    // oracle label of the previous event
};
static std::map<std::string, TemporalPrev> g_prev_topo;  // key = "src_dst"
static std::map<uint32_t, TemporalPrev>   g_prev_hb;     // key = claimed_sender

// Reporter sets for ME reporter_count feature
static std::map<std::string, std::set<uint32_t>> g_link_reporters;

// ─────────────────────────────────────────────────────────────
// Output streams
// ─────────────────────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_pairs_csv;   // 9-feature consecutive pairs → for KNN+Bagging

// ─────────────────────────────────────────────────────────────
// TemporalTopoTag2 — NS-3 Tag for topology packets in this file
// Different TypeId name ("TemporalTopoTag2") to avoid collision
// if both files are ever compiled into the same build tree.
// Size: src_id(4) + dst_id(4) + claimed_ts(8) + reporter_id(4) = 20 bytes
// ─────────────────────────────────────────────────────────────
class TemporalTopoTag2 : public Tag
{
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("TemporalTopoTag2")
            .SetParent<Tag>().AddConstructor<TemporalTopoTag2>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 20; }

    void Serialize(TagBuffer buf) const override {
        buf.WriteU32(m_srcId); buf.WriteU32(m_dstId);
        buf.WriteDouble(m_claimedTs); buf.WriteU32(m_reporterId);
    }
    void Deserialize(TagBuffer buf) override {
        m_srcId      = buf.ReadU32(); m_dstId      = buf.ReadU32();
        m_claimedTs  = buf.ReadDouble(); m_reporterId = buf.ReadU32();
    }
    void Print(std::ostream& os) const override {
        os << "TopoTag2 src=" << m_srcId << " dst=" << m_dstId
           << " ts=" << m_claimedTs << " rep=" << m_reporterId;
    }

    void SetSrcId(uint32_t v)     { m_srcId      = v; }
    void SetDstId(uint32_t v)     { m_dstId      = v; }
    void SetClaimedTs(double v)   { m_claimedTs  = v; }
    void SetReporterId(uint32_t v){ m_reporterId = v; }

    uint32_t GetSrcId()     const { return m_srcId;     }
    uint32_t GetDstId()     const { return m_dstId;     }
    double   GetClaimedTs() const { return m_claimedTs; }
    uint32_t GetReporterId()const { return m_reporterId;}

private:
    uint32_t m_srcId=0, m_dstId=0, m_reporterId=0;
    double   m_claimedTs=0.0;
};

// ─────────────────────────────────────────────────────────────
// TemporalHBTag2 — NS-3 Tag for heartbeat packets in this file
// Size: claimed_sender(4) + physical_sender(4) + hb_ts(8) = 16 bytes
// ─────────────────────────────────────────────────────────────
class TemporalHBTag2 : public Tag
{
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("TemporalHBTag2")
            .SetParent<Tag>().AddConstructor<TemporalHBTag2>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 16; }

    void Serialize(TagBuffer buf) const override {
        buf.WriteU32(m_claimedSender); buf.WriteU32(m_physicalSender);
        buf.WriteDouble(m_hbTs);
    }
    void Deserialize(TagBuffer buf) override {
        m_claimedSender  = buf.ReadU32(); m_physicalSender = buf.ReadU32();
        m_hbTs           = buf.ReadDouble();
    }
    void Print(std::ostream& os) const override {
        os << "HBTag2 claimed=" << m_claimedSender
           << " physical=" << m_physicalSender << " ts=" << m_hbTs;
    }

    void SetClaimedSender(uint32_t v) { m_claimedSender  = v; }
    void SetPhysicalSender(uint32_t v){ m_physicalSender = v; }
    void SetHbTs(double v)            { m_hbTs           = v; }

    uint32_t GetClaimedSender()  const { return m_claimedSender;  }
    uint32_t GetPhysicalSender() const { return m_physicalSender; }
    double   GetHbTs()           const { return m_hbTs;           }

private:
    uint32_t m_claimedSender=0, m_physicalSender=0;
    double   m_hbTs=0.0;
};

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────
static double Dist2D(double x1,double y1,double x2,double y2)
{ double dx=x2-x1,dy=y2-y1; return std::sqrt(dx*dx+dy*dy); }

static void GetKinematics(Ptr<Node> n, double& px, double& py, double& vx, double& vy)
{
    auto mob = n->GetObject<MobilityModel>();
    if (!mob){px=py=vx=vy=0.0;return;}
    Vector p=mob->GetPosition(), v=mob->GetVelocity();
    px=p.x;py=p.y;vx=v.x;vy=v.y;
}

static double ComputeRhoMax()
{ return std::max(2.0,static_cast<double>(N_Vehicles)/4.0); }

// ─────────────────────────────────────────────────────────────
// Physics-based rule detector — same as VREM_Detect() in veremi_attacks.cc
// Used for rule-based PEM summary only (Trigger A + B).
// Full ML classification is in temporal_knn_detector.py.
// ─────────────────────────────────────────────────────────────
static bool TVER_DetectTopo(double prev_claimed_ts, double curr_claimed_ts,
                             double rx_time, uint32_t reporter_count_)
{
    // Trigger A: stale timestamp (equiv. position frozen + speed > 0)
    double staleness = rx_time - curr_claimed_ts;
    if (staleness > BEACON_INTERVAL_S + STALE_EPS_S) return true;

    // Trigger B: claimed timestamp regression (equiv. impossible displacement)
    if (curr_claimed_ts < prev_claimed_ts) return true;

    // ME Trigger A: too many reporters
    double rhoMax = ComputeRhoMax();
    if (reporter_count_ > rhoMax * ME_SAFETY_FACTOR) return true;

    return false;
}

static bool TVER_DetectHB(double prev_hb_ts, double curr_hb_ts,
                           bool identity_mismatch)
{
    if (identity_mismatch)          return true;  // Trigger A
    if (curr_hb_ts < prev_hb_ts)   return true;  // Trigger B
    return false;
}

// ─────────────────────────────────────────────────────────────
// Feature pair emission — writes one row to temporal_veremi_pairs.csv
// Mirrors the pair-write pattern in VREM_RSUReceive() in veremi_attacks.cc
//
// 9 features: ev_ts1, ev_ts2, ts_delta, rx_time1, rx_time2,
//             time_interval, rx_delay2, identity_match, reporter_count
// ─────────────────────────────────────────────────────────────
static void TVER_EmitPair(uint32_t entity_id,      // vehicle or link "owner"
                           uint32_t attack_type_col,
                           double sim_time_s,
                           // feature values
                           double ev_ts1, double ev_ts2,
                           double rx_time1, double rx_time2,
                           double identity_match, double reporter_count,
                           int label)
{
    if (!g_pairs_csv.is_open()) return;

    double ts_delta      = ev_ts2 - ev_ts1;
    double time_interval = rx_time2 - rx_time1;
    double rx_delay2     = rx_time2 - ev_ts2;

    g_pairs_csv << std::fixed << std::setprecision(4)
        << entity_id       << ","
        << attack_type_col << ","
        << sim_time_s      << ","
        << ev_ts1          << ","
        << ev_ts2          << ","
        << ts_delta        << ","
        << rx_time1        << ","
        << rx_time2        << ","
        << time_interval   << ","
        << rx_delay2       << ","
        << identity_match  << ","
        << reporter_count  << ","
        << label           << "\n";
}

// ─────────────────────────────────────────────────────────────
// Controller socket: receive topology updates (TTW / ME)
// Extracts features and writes pair to CSV
// ─────────────────────────────────────────────────────────────
static void TVER_TopoSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TemporalTopoTag2 tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        uint32_t src     = tag.GetSrcId();
        uint32_t dst     = tag.GetDstId();
        double   cts     = tag.GetClaimedTs();
        uint32_t rep     = tag.GetReporterId();
        double   rx_time = Simulator::Now().GetSeconds();

        bool is_attack = g_oracle_topo_attack.count(rep) && g_oracle_topo_attack[rep];

        // Update reporter count for ME feature
        std::string key = std::to_string(src) + "_" + std::to_string(dst);
        g_link_reporters[key].insert(rep);
        double rcount = static_cast<double>(g_link_reporters[key].size());

        // Emit consecutive pair if we have a previous event for this link
        auto it = g_prev_topo.find(key);
        if (it != g_prev_topo.end()) {
            const TemporalPrev& prev = it->second;

            // Rule-based detect
            bool detected = TVER_DetectTopo(prev.ev_ts, cts, rx_time,
                                             static_cast<uint32_t>(rcount));

            // PEM
            if (is_attack && !pem_attack_active) {
                pem_attack_active = true;
                pem_attack_start_time = rx_time;
            }
            if (is_attack) {
                if (detected) {
                    pem_tp++;
                    if (pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
                } else { pem_fn++; }
            } else {
                if (detected) pem_fp++; else pem_tn++;
            }

            // Feature pair CSV
            TVER_EmitPair(rep, attack_scenario, rx_time,
                           prev.ev_ts, cts,
                           prev.rx_time, rx_time,
                           1.0,    // topology reporters always use own identity
                           rcount,
                           (is_attack ? 1 : 0));

            if (detected && g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                             << "]  RULE-ALERT  TOPO  link=" << src << "↔" << dst
                             << "  rx_delay=" << (rx_time-cts)
                             << "  reporters=" << rcount
                             << "  ground_truth=" << (is_attack ? "ATTACK" : "legit")
                             << "\n";
                g_attack_log.flush();
            }
        }

        // Update previous event
        g_prev_topo[key] = {cts, rx_time, rep, src, is_attack};
    }
}

// ─────────────────────────────────────────────────────────────
// Controller socket: receive heartbeats (BSHH)
// ─────────────────────────────────────────────────────────────
static void TVER_HBSocketReceive(Ptr<Socket> sock)
{
    Ptr<Packet> pkt;
    while ((pkt = sock->Recv()))
    {
        TemporalHBTag2 tag;
        if (!pkt->PeekPacketTag(tag)) continue;

        uint32_t claimed  = tag.GetClaimedSender();
        uint32_t physical = tag.GetPhysicalSender();
        double   hb_ts    = tag.GetHbTs();
        double   rx_time  = Simulator::Now().GetSeconds();

        bool is_attack = g_oracle_hb_attack.count(physical) && g_oracle_hb_attack[physical];
        bool id_match  = (claimed == physical);

        auto it = g_prev_hb.find(claimed);
        if (it != g_prev_hb.end()) {
            const TemporalPrev& prev = it->second;

            bool detected = TVER_DetectHB(prev.ev_ts, hb_ts, !id_match);

            if (is_attack && !pem_attack_active) {
                pem_attack_active     = true;
                pem_attack_start_time = rx_time;
            }
            if (is_attack) {
                if (detected) {
                    pem_tp++;
                    if (pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
                } else { pem_fn++; }
            } else {
                if (detected) pem_fp++; else pem_tn++;
            }

            TVER_EmitPair(claimed, attack_scenario, rx_time,
                           prev.ev_ts, hb_ts,
                           prev.rx_time, rx_time,
                           (id_match ? 1.0 : 0.0),   // identity_match = key BSHH feature
                           1.0,                        // reporter_count always 1 for HB
                           (is_attack ? 1 : 0));

            if (detected && g_attack_log.is_open()) {
                g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                             << "]  RULE-ALERT  HB  claimed=" << claimed
                             << "  physical=" << physical
                             << "  id_match=" << id_match
                             << "  ts_delta=" << (hb_ts-prev.ev_ts)
                             << "  ground_truth=" << (is_attack ? "ATTACK" : "legit")
                             << "\n";
                g_attack_log.flush();
            }
        }

        g_prev_hb[claimed] = {hb_ts, rx_time, physical, claimed, is_attack};
    }
}

// ─────────────────────────────────────────────────────────────
// Send helpers (same structure as temporal_mbsm_detector.cc,
// using Tag2 classes and ports 7781/7782)
// ─────────────────────────────────────────────────────────────
static void TVER_SendTopoPacket(uint32_t veh_idx, uint32_t src_id, uint32_t dst_id,
                                 double claimed_ts, uint32_t reporter_id,
                                 bool is_attack_oracle)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_topo_attack[reporter_id] = is_attack_oracle;

    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(node, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_veh[veh_idx], TOPO_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalTopoTag2 tag;
    tag.SetSrcId(src_id); tag.SetDstId(dst_id);
    tag.SetClaimedTs(claimed_ts); tag.SetReporterId(reporter_id);
    pkt->AddPacketTag(tag);
    sock->Send(pkt); sock->Close();
}

static void TVER_RSUSendTopoPacket(uint32_t src_id, uint32_t dst_id,
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
    TemporalTopoTag2 tag;
    tag.SetSrcId(src_id); tag.SetDstId(dst_id);
    tag.SetClaimedTs(claimed_ts); tag.SetReporterId(reporter_id);
    pkt->AddPacketTag(tag);
    sock->Send(pkt); sock->Close();
}

static void TVER_SendHBPacket(uint32_t veh_idx,
                               uint32_t claimed_sender, uint32_t physical_sender,
                               double hb_ts, bool is_attack_oracle)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;

    g_oracle_hb_attack[physical_sender] = is_attack_oracle;

    Ptr<Node> node = Vehicle_Nodes.Get(veh_idx);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(node, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_veh[veh_idx], HB_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalHBTag2 tag;
    tag.SetClaimedSender(claimed_sender);
    tag.SetPhysicalSender(physical_sender);
    tag.SetHbTs(hb_ts);
    pkt->AddPacketTag(tag);
    sock->Send(pkt); sock->Close();
}

static void TVER_RSUSendHBPacket(uint32_t claimed_sender, uint32_t physical_sender,
                                  double hb_ts, bool is_attack_oracle)
{
    if (RSU_Nodes.GetN() == 0) return;
    g_oracle_hb_attack[physical_sender] = is_attack_oracle;

    Ptr<Node> rsu = RSU_Nodes.Get(0);
    TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
    sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, HB_PORT));

    Ptr<Packet> pkt = Create<Packet>(0);
    TemporalHBTag2 tag;
    tag.SetClaimedSender(claimed_sender);
    tag.SetPhysicalSender(physical_sender);
    tag.SetHbTs(hb_ts);
    pkt->AddPacketTag(tag);
    sock->Send(pkt); sock->Close();
}

// ─────────────────────────────────────────────────────────────
// For S3/S4: direct controller internal injection
// Emits a synthetic pair row with the internal-replay signature.
// ─────────────────────────────────────────────────────────────
static void TVER_ControllerInternalTopoReplay(uint32_t src_id, uint32_t dst_id,
                                               double stale_ts)
{
    double rx_time = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = rx_time;
    }

    std::string key = std::to_string(src_id) + "_" + std::to_string(dst_id);
    double rcount = static_cast<double>(g_link_reporters[key].size()) + 1.0;

    auto it = g_prev_topo.find(key);
    double prev_ts   = (it != g_prev_topo.end()) ? it->second.ev_ts   : stale_ts;
    double prev_rx   = (it != g_prev_topo.end()) ? it->second.rx_time : stale_ts;

    bool detected = TVER_DetectTopo(prev_ts, stale_ts, rx_time,
                                     static_cast<uint32_t>(rcount));
    if (detected) {
        pem_tp++;
        if (pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
    } else { pem_fn++; }

    TVER_EmitPair(src_id, attack_scenario, rx_time,
                   prev_ts, stale_ts, prev_rx, rx_time,
                   1.0, rcount, 1);

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                     << "]  CTRL-INTERNAL-REPLAY  link=" << src_id << "↔" << dst_id
                     << "  stale_ts=" << stale_ts
                     << "  rx_delay=" << (rx_time-stale_ts)
                     << "  detected=" << detected << "\n";
        g_attack_log.flush();
    }
}

static void TVER_ControllerInternalHBReplay(uint32_t claimed_sender, double stale_ts)
{
    double rx_time = Simulator::Now().GetSeconds();
    if (!pem_attack_active) {
        pem_attack_active     = true;
        pem_attack_start_time = rx_time;
    }

    auto it = g_prev_hb.find(claimed_sender);
    double prev_ts = (it != g_prev_hb.end()) ? it->second.ev_ts   : stale_ts;
    double prev_rx = (it != g_prev_hb.end()) ? it->second.rx_time : stale_ts;

    bool detected = TVER_DetectHB(prev_ts, stale_ts, false);  // no identity mismatch for ctrl
    if (detected) {
        pem_tp++;
        if (pem_first_alert_time < 0.0) pem_first_alert_time = rx_time;
    } else { pem_fn++; }

    TVER_EmitPair(claimed_sender, attack_scenario, rx_time,
                   prev_ts, stale_ts, prev_rx, rx_time,
                   1.0, 1.0, 1);

    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << rx_time
                     << "]  CTRL-INTERNAL-HB-REPLAY  claimed=" << claimed_sender
                     << "  stale_ts=" << stale_ts
                     << "  detected=" << detected << "\n";
        g_attack_log.flush();
    }
}

// ─────────────────────────────────────────────────────────────
// Legitimate periodic senders (topology + heartbeat)
// ─────────────────────────────────────────────────────────────
static void TVER_LegitTopoTick(uint32_t veh_idx, double t_end)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;
    uint32_t nid  = Vehicle_Nodes.Get(veh_idx)->GetId();
    uint32_t next = (veh_idx + 1) % Vehicle_Nodes.GetN();
    double   now  = Simulator::Now().GetSeconds();

    TVER_SendTopoPacket(veh_idx, nid, next, now, nid, false);

    double t_next = now + BEACON_INTERVAL_S;
    if (t_next < t_end)
        Simulator::Schedule(Seconds(BEACON_INTERVAL_S), &TVER_LegitTopoTick, veh_idx, t_end);
}

static void TVER_LegitHBTick(uint32_t veh_idx, double t_end)
{
    if (veh_idx >= Vehicle_Nodes.GetN()) return;
    if (veh_idx >= g_ctrl_ip_for_veh.size()) return;
    uint32_t nid = Vehicle_Nodes.Get(veh_idx)->GetId();
    double   now = Simulator::Now().GetSeconds();

    TVER_SendHBPacket(veh_idx, nid, nid, now, false);

    double t_next = now + BEACON_INTERVAL_S;
    if (t_next < t_end)
        Simulator::Schedule(Seconds(BEACON_INTERVAL_S), &TVER_LegitHBTick, veh_idx, t_end);
}

// ─────────────────────────────────────────────────────────────
// TTW Attack Functions (VeReMi feature variant)
// ─────────────────────────────────────────────────────────────
static double   g_ttw_stored_ts = 0.0;
static uint32_t g_ttw_src_id    = 0;
static uint32_t g_ttw_dst_id    = 1;

static void TVER_TTW_HelloAndStore(uint32_t src_id, uint32_t dst_id)
{
    g_ttw_stored_ts = Simulator::Now().GetSeconds();
    g_ttw_src_id = src_id; g_ttw_dst_id = dst_id;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << g_ttw_stored_ts
                     << "]  TTW STEP 1+2: Hello + store <V" << src_id << " sees V" << dst_id
                     << " at t=" << g_ttw_stored_ts << ">\n\n";
        g_attack_log.flush();
    }
}

static void TVER_TTW_LinkBreak(uint32_t src_id, uint32_t dst_id)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW STEP 3: Physical link V" << src_id << "↔V" << dst_id << " broken\n\n";
        g_attack_log.flush();
    }
}

static void TVER_TTW_S1_Replay(uint32_t veh_idx, uint32_t src_id, uint32_t dst_id,
                                 double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    uint32_t atk_id = Vehicle_Nodes.Get(veh_idx)->GetId();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S1 ATTACK: V" << atk_id
                     << " replays with forged_ts=" << forged_ts << "\n\n";
        g_attack_log.flush();
    }
    TVER_SendTopoPacket(veh_idx, src_id, dst_id, forged_ts, atk_id, true);
}

static void TVER_TTW_S2_Replay(uint32_t src_id, uint32_t dst_id, double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    uint32_t rsu_id = (RSU_Nodes.GetN()>0) ? RSU_Nodes.Get(0)->GetId() : 0xFFFE;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S2 ATTACK: RSU replays with forged_ts=" << forged_ts << "\n\n";
        g_attack_log.flush();
    }
    TVER_RSUSendTopoPacket(src_id, dst_id, forged_ts, rsu_id, true);
}

static void TVER_TTW_S34_InternalReplay(uint32_t src_id, uint32_t dst_id, double forged_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  TTW-S3/S4 ATTACK: Controller internal replay  forged_ts=" << forged_ts << "\n\n";
        g_attack_log.flush();
    }
    TVER_ControllerInternalTopoReplay(src_id, dst_id, forged_ts);
}

// ─────────────────────────────────────────────────────────────
// BSHH Attack Functions (VeReMi feature variant)
// ─────────────────────────────────────────────────────────────
static double   g_bshh_stored_hb_ts = 0.0;

static void TVER_BSHH_StoreHeartbeat(uint32_t victim_id, double hb_ts)
{
    g_bshh_stored_hb_ts = hb_ts;
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH STEP 1: Attacker captures V" << victim_id
                     << "'s HB at ts=" << hb_ts << "\n\n";
        g_attack_log.flush();
    }
}

static void TVER_BSHH_S1_Replay(uint32_t atk_idx, uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    uint32_t atk_id = Vehicle_Nodes.Get(atk_idx)->GetId();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S1 ATTACK: V" << atk_id << " claims V" << victim_id
                     << "'s identity  hb_ts=" << stored_ts
                     << "  → identity_match=0 in feature pair\n\n";
        g_attack_log.flush();
    }
    TVER_SendHBPacket(atk_idx, victim_id, atk_id, stored_ts, true);
}

static void TVER_BSHH_S2_Replay(uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    uint32_t rsu_id = (RSU_Nodes.GetN()>0) ? RSU_Nodes.Get(0)->GetId() : 0xFFFE;
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S2 ATTACK: RSU claims V" << victim_id
                     << "'s identity  hb_ts=" << stored_ts << "\n\n";
        g_attack_log.flush();
    }
    TVER_RSUSendHBPacket(victim_id, rsu_id, stored_ts, true);
}

static void TVER_BSHH_S34_InternalReplay(uint32_t victim_id, double stored_ts)
{
    double now = Simulator::Now().GetSeconds();
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  BSHH-S3/S4 ATTACK: Controller internal HB replay  hb_ts=" << stored_ts << "\n\n";
        g_attack_log.flush();
    }
    TVER_ControllerInternalHBReplay(victim_id, stored_ts);
}

// ─────────────────────────────────────────────────────────────
// ME Attack Functions (VeReMi feature variant)
// ─────────────────────────────────────────────────────────────
static void TVER_ME_S1_EchoAttack(uint32_t echo_v3_idx, uint32_t echo_v4_idx,
                                    uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S1 ATTACK: Echo V" << echo_v3_idx << " and V" << echo_v4_idx
                     << " report V" << link_src << "↔V" << link_dst
                     << "  → reporter_count increases in feature pair\n\n";
        g_attack_log.flush();
    }
    if (echo_v3_idx < Vehicle_Nodes.GetN()) {
        uint32_t v3_id = Vehicle_Nodes.Get(echo_v3_idx)->GetId();
        TVER_SendTopoPacket(echo_v3_idx, link_src, link_dst, t, v3_id, true);
    }
    if (echo_v4_idx < Vehicle_Nodes.GetN()) {
        uint32_t v4_id = Vehicle_Nodes.Get(echo_v4_idx)->GetId();
        TVER_SendTopoPacket(echo_v4_idx, link_src, link_dst, t, v4_id, true);
    }
}

static void TVER_ME_S2_EchoAttack(uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S2 ATTACK: RSU injects fake reporters 9901+9902 for link "
                     << link_src << "↔" << link_dst << "\n\n";
        g_attack_log.flush();
    }
    uint32_t fake_v3 = 9901, fake_v4 = 9902;
    g_oracle_topo_attack[fake_v3] = true;
    g_oracle_topo_attack[fake_v4] = true;

    if (RSU_Nodes.GetN() > 0) {
        Ptr<Node> rsu = RSU_Nodes.Get(0);
        TypeId udp = TypeId::LookupByName("ns3::UdpSocketFactory");
        for (uint32_t fid : {fake_v3, fake_v4}) {
            Ptr<Socket> sock = Socket::CreateSocket(rsu, udp);
            sock->Connect(InetSocketAddress(g_ctrl_ip_for_rsu, TOPO_PORT));
            Ptr<Packet> pkt = Create<Packet>(0);
            TemporalTopoTag2 tag;
            tag.SetSrcId(link_src); tag.SetDstId(link_dst);
            tag.SetClaimedTs(t); tag.SetReporterId(fid);
            pkt->AddPacketTag(tag);
            sock->Send(pkt); sock->Close();
        }
    }
}

static void TVER_ME_S34_EchoAttack(uint32_t link_src, uint32_t link_dst, double t)
{
    double now = Simulator::Now().GetSeconds();
    if (!pem_attack_active) { pem_attack_active = true; pem_attack_start_time = now; }
    if (g_attack_log.is_open()) {
        g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                     << "]  ME-S3/S4 ATTACK: Controller adds phantom echo entries "
                     << "for link " << link_src << "↔" << link_dst << "\n\n";
        g_attack_log.flush();
    }
    // Direct table injection → synthetic pair emit
    std::string key = std::to_string(link_src) + "_" + std::to_string(link_dst);
    g_link_reporters[key].insert(9901);
    g_link_reporters[key].insert(9902);
    double rcount = static_cast<double>(g_link_reporters[key].size());

    auto it = g_prev_topo.find(key);
    double prev_ts = (it != g_prev_topo.end()) ? it->second.ev_ts   : t;
    double prev_rx = (it != g_prev_topo.end()) ? it->second.rx_time : t;

    bool detected = TVER_DetectTopo(prev_ts, t, now, static_cast<uint32_t>(rcount));
    if (detected) {
        pem_tp++;
        if (pem_first_alert_time < 0.0) pem_first_alert_time = now;
    } else { pem_fn++; }

    TVER_EmitPair(link_src, attack_scenario, now,
                   prev_ts, t, prev_rx, now,
                   1.0, rcount, 1);
}

// ─────────────────────────────────────────────────────────────
// Network setup — P2P star 10.4.x, ports 7781/7782
// ─────────────────────────────────────────────────────────────
static void TVER_SetupNetwork()
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

    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        NodeContainer pair;
        pair.Add(Vehicle_Nodes.Get(i)); pair.Add(Controller_Node.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);
        std::ostringstream ip_base;
        ip_base << "10.4." << (i+1) << ".0";
        addr.SetBase(ip_base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);
        g_veh_ip[i]           = ifaces.GetAddress(0);
        g_ctrl_ip_for_veh[i]  = ifaces.GetAddress(1);
    }

    if (RSU_Nodes.GetN() > 0) {
        NodeContainer pair;
        pair.Add(RSU_Nodes.Get(0)); pair.Add(Controller_Node.Get(0));
        NetDeviceContainer devs = p2p.Install(pair);
        addr.SetBase("10.4.100.0", "255.255.255.252");
        Ipv4InterfaceContainer ifaces = addr.Assign(devs);
        g_ctrl_ip_for_rsu = ifaces.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_ctrl_topo_sock = Socket::CreateSocket(
        Controller_Node.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_ctrl_topo_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), TOPO_PORT));
    g_ctrl_topo_sock->SetRecvCallback(MakeCallback(&TVER_TopoSocketReceive));

    g_ctrl_hb_sock = Socket::CreateSocket(
        Controller_Node.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_ctrl_hb_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), HB_PORT));
    g_ctrl_hb_sock->SetRecvCallback(MakeCallback(&TVER_HBSocketReceive));

    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), 9));
    ApplicationContainer sa = sink.Install(Controller_Node.Get(0));
    sa.Start(Seconds(0.0)); sa.Stop(Seconds(simTime));
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        ApplicationContainer va = sink.Install(Vehicle_Nodes.Get(i));
        va.Start(Seconds(0.0)); va.Stop(Seconds(simTime));
    }
    if (RSU_Nodes.GetN() > 0) {
        ApplicationContainer ra = sink.Install(RSU_Nodes.Get(0));
        ra.Start(Seconds(0.0)); ra.Stop(Seconds(simTime));
    }
}

// ─────────────────────────────────────────────────────────────
// NetAnim
// ─────────────────────────────────────────────────────────────
static void TVER_SetupNetAnim()
{
    if (!g_anim) return;
    uint32_t ctrl_id = Controller_Node.Get(0)->GetId();
    g_anim->UpdateNodeColor(ctrl_id, 0, 100, 255);
    g_anim->UpdateNodeSize(ctrl_id, 40, 40);
    g_anim->UpdateNodeDescription(ctrl_id, "CONTROLLER");

    if (RSU_Nodes.GetN() > 0) {
        uint32_t rsu_id = RSU_Nodes.Get(0)->GetId();
        g_anim->UpdateNodeColor(rsu_id, 255, 200, 0);
        g_anim->UpdateNodeSize(rsu_id, 35, 35);
        g_anim->UpdateNodeDescription(rsu_id,
            (attack_scenario==2||attack_scenario==6||attack_scenario==10)
            ? "MALICIOUS-RSU" : "RSU");
    }
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        uint32_t nid = Vehicle_Nodes.Get(i)->GetId();
        bool is_atk = (attack_scenario!=0) && (i==attacker_idx) && (attack_scenario%4==1);
        if (is_atk) {
            g_anim->UpdateNodeColor(nid,255,0,0);
            g_anim->UpdateNodeSize(nid,30,30);
            g_anim->UpdateNodeDescription(nid,"ATTACKER");
        } else {
            g_anim->UpdateNodeColor(nid,0,200,60);
            g_anim->UpdateNodeSize(nid,20,20);
            g_anim->UpdateNodeDescription(nid,"V"+std::to_string(i));
        }
    }
    g_anim->EnablePacketMetadata(true);
}

// ─────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────
static const std::string AttackName(uint32_t s)
{
    switch(s){
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

static void TVER_InitLogs()
{
    std::string txt_name = (attack_scenario==0)
        ? "temporal_veremi_baseline.txt"
        : "temporal_veremi_attack" + std::to_string(attack_scenario) + ".txt";

    g_attack_log.open(txt_name, std::ios::out | std::ios::trunc);
    g_attack_log << std::fixed << std::setprecision(3);
    g_attack_log
        << "================================================================\n"
        << "  Temporal-Echo Attack Log — VeReMi KNN+Bagging Feature Extraction\n"
        << "  Attack   : " << AttackName(attack_scenario) << "\n"
        << "  Based on : Mekonen et al., PLOS ONE 2025\n"
        << "  Adapted  : 9-feature consecutive event pairs for temporal attacks\n"
        << "----------------------------------------------------------------\n"
        << "  sim_time : " << simTime       << " s\n"
        << "  Vehicles : " << N_Vehicles     << "\n"
        << "  RSUs     : " << N_RSUs         << "\n"
        << "  Scenario : " << attack_scenario << "\n"
        << "  9 features: ev_ts1, ev_ts2, ts_delta, rx_time1, rx_time2,\n"
        << "              time_interval, rx_delay2, identity_match, reporter_count\n"
        << "================================================================\n\n";
    g_attack_log.flush();

    // Consecutive pair CSV — columns match FEATURE_COLS in temporal_knn_detector.py
    g_pairs_csv.open("temporal_veremi_pairs.csv", std::ios::out | std::ios::trunc);
    g_pairs_csv
        << "vehicle_id,attack_scenario,sim_time_s,"
        << "ev_ts1,ev_ts2,ts_delta,"
        << "rx_time1,rx_time2,time_interval,"
        << "rx_delay2,identity_match,reporter_count,"
        << "label\n";
}

static void TVER_WriteSummary()
{
    double tp=static_cast<double>(pem_tp), tn=static_cast<double>(pem_tn);
    double fp=static_cast<double>(pem_fp), fn=static_cast<double>(pem_fn);

    double mcc_d = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    double mcc   = (mcc_d>0.0) ? ((tp*tn-fp*fn)/mcc_d) : 0.0;
    double total = tp+tn+fp+fn;
    double acr   = (total>0.0) ? ((tp+tn)/total*100.0) : 0.0;
    double prec  = (tp+fp>0.0) ? (tp/(tp+fp)) : 0.0;
    double rec   = (tp+fn>0.0) ? (tp/(tp+fn)) : 0.0;
    double f1    = (prec+rec>0.0) ? (2.0*prec*rec/(prec+rec)) : 0.0;
    double tdet  = -1.0;
    if (pem_attack_start_time>=0.0 && pem_first_alert_time>=0.0)
        tdet = (pem_first_alert_time - pem_attack_start_time)*1000.0;

    uint64_t pairs = pem_tp+pem_tn+pem_fp+pem_fn;

    std::ofstream sum("temporal_veremi_pem_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,attack_name,tp,tn,fp,fn,mcc,acr_pct,precision,recall,f1,tdet_ms\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ",\"" << AttackName(attack_scenario) << "\","
        << pem_tp<<","<<pem_tn<<","<<pem_fp<<","<<pem_fn<<","
        << mcc<<","<<acr<<","<<prec<<","<<rec<<","<<f1<<","<<tdet<<"\n";
    sum.close();

    if (g_attack_log.is_open()) {
        g_attack_log
            << "\n====== RUN SUMMARY (rule-based — see temporal_knn_detector.py for ML) ======\n"
            << "  Scenario : " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
            << "  TP/TN/FP/FN : " << pem_tp<<"/"<<pem_tn<<"/"<<pem_fp<<"/"<<pem_fn<<"\n"
            << "  MCC : " << std::fixed << std::setprecision(3) << mcc << "\n"
            << "  ACR : " << acr << " %\n"
            << "  F1  : " << f1  << "\n"
            << "  Tdet: " << tdet << " ms\n"
            << "  Pair CSV: temporal_veremi_pairs.csv  (" << pairs << " pairs)\n"
            << "  Run ML: python3 temporal_knn_detector.py temporal_veremi_pairs.csv\n"
            << "=========================================================================\n";
        g_attack_log.flush();
    }

    std::cout << "\n[TemporalVeReMi] Summary → temporal_veremi_pem_summary.csv\n"
              << "  Scenario " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
              << "  TP=" << pem_tp << " TN=" << pem_tn
              << " FP=" << pem_fp  << " FN=" << pem_fn
              << "  MCC=" << std::fixed << std::setprecision(3) << mcc
              << "  F1=" << f1 << "\n"
              << "  Feature pairs: temporal_veremi_pairs.csv  (" << pairs << " pairs)\n"
              << "  Run: python3 temporal_knn_detector.py temporal_veremi_pairs.csv\n";
}

// ─────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",         "Simulation duration (s)",            simTime);
    cmd.AddValue("N_Vehicles",      "Number of vehicle nodes",            N_Vehicles);
    cmd.AddValue("N_RSUs",          "Number of RSU nodes (0 or 1)",       N_RSUs);
    cmd.AddValue("attack_scenario", "1-12 = specific attack; 0=baseline", attack_scenario);
    cmd.AddValue("attacker_idx",    "0-based index of malicious vehicle",  attacker_idx);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 2)            N_Vehicles   = 2;
    if (N_RSUs     > 1)            N_RSUs        = 1;
    if (attacker_idx >= N_Vehicles) attacker_idx = 0;

    bool needs_rsu = (attack_scenario==2||attack_scenario==4||attack_scenario==6||
                      attack_scenario==8||attack_scenario==10||attack_scenario==12);
    if (needs_rsu && N_RSUs==0) N_RSUs = 1;

    bool is_me = (attack_scenario>=9 && attack_scenario<=12);
    if (is_me && N_Vehicles<4) N_Vehicles = 4;

    TVER_InitLogs();

    std::cout << "\n======== Temporal-Echo VeReMi Feature Extractor ========\n"
              << "  attack_scenario : " << attack_scenario << " — " << AttackName(attack_scenario) << "\n"
              << "  N_Vehicles      : " << N_Vehicles << "\n"
              << "  N_RSUs          : " << N_RSUs     << "\n"
              << "  simTime         : " << simTime    << " s\n"
              << "  9-feature pairs → temporal_veremi_pairs.csv\n"
              << "  ML classifier  → python3 temporal_knn_detector.py temporal_veremi_pairs.csv\n"
              << "=========================================================\n\n";

    // ── Nodes ────────────────────────────────────────────────
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
        double spd = SPEED_MIN_MS + (SPEED_MAX_MS-SPEED_MIN_MS)*
                     (N_Vehicles>1 ? static_cast<double>(i)/(N_Vehicles-1) : 0.0);
        mob->SetPosition(Vector(50.0+i*80.0, static_cast<double>(i)*8.0, 0.0));
        mob->SetVelocity(Vector(spd, 0.0, 0.0));
    }

    // ── RSU mobility ─────────────────────────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
        auto mob = DynamicCast<ConstantPositionMobilityModel>(
            RSU_Nodes.Get(0)->GetObject<MobilityModel>());
        if (mob) {
            double cx=50.0+(N_Vehicles/2.0)*80.0;
            double cy=(N_Vehicles>1)?((N_Vehicles-1)*8.0/2.0):0.0;
            mob->SetPosition(Vector(cx,cy,0.0));
        }
    }

    // ── Network ───────────────────────────────────────────────
    TVER_SetupNetwork();

    {
        MobilityHelper mobC;
        mobC.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobC.Install(Controller_Node);
        auto mob = DynamicCast<ConstantPositionMobilityModel>(
            Controller_Node.Get(0)->GetObject<MobilityModel>());
        if (mob) mob->SetPosition(Vector(500.0,-50.0,0.0));
    }

    // ── Attack scheduling ─────────────────────────────────────
    bool is_ttw  = (attack_scenario>=1 && attack_scenario<=4);
    bool is_bshh = (attack_scenario>=5 && attack_scenario<=8);
    double t_end = simTime - 1.0;

    if (attack_scenario == 0) {
        for (uint32_t i=0; i<Vehicle_Nodes.GetN(); i++)
            Simulator::Schedule(Seconds(0.1+i*0.01), &TVER_LegitTopoTick, i, t_end);
    } else if (is_ttw) {
        for (uint32_t i=0; i<Vehicle_Nodes.GetN(); i++)
            Simulator::Schedule(Seconds(0.1+i*0.01), &TVER_LegitTopoTick, i, t_end);

        uint32_t src_id=(attack_scenario==1)?Vehicle_Nodes.Get(0)->GetId():Vehicle_Nodes.Get(1)->GetId();
        uint32_t dst_id=(attack_scenario==1)?Vehicle_Nodes.Get(1)->GetId():Vehicle_Nodes.Get(2%N_Vehicles)->GetId();

        Simulator::Schedule(Seconds(TTW_HELLO_TIME), &TVER_TTW_HelloAndStore, src_id, dst_id);
        Simulator::Schedule(Seconds(TTW_LINK_BREAK), &TVER_TTW_LinkBreak, src_id, dst_id);

        if (attack_scenario==1)
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME), &TVER_TTW_S1_Replay, attacker_idx, src_id, dst_id, TTW_HELLO_TIME);
        else if (attack_scenario==2)
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME), &TVER_TTW_S2_Replay, src_id, dst_id, TTW_HELLO_TIME);
        else
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME), &TVER_TTW_S34_InternalReplay, src_id, dst_id, TTW_HELLO_TIME);
    } else if (is_bshh) {
        for (uint32_t i=0; i<Vehicle_Nodes.GetN(); i++)
            Simulator::Schedule(Seconds(0.1+i*0.01), &TVER_LegitHBTick, i, t_end);

        uint32_t victim_id = Vehicle_Nodes.Get(1%N_Vehicles)->GetId();

        Simulator::Schedule(Seconds(BSHH_STORE_TIME), &TVER_BSHH_StoreHeartbeat, victim_id, BSHH_STORE_TIME-1.0);

        if (attack_scenario==5)
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME), &TVER_BSHH_S1_Replay, attacker_idx, victim_id, BSHH_STORE_TIME-1.0);
        else if (attack_scenario==6)
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME), &TVER_BSHH_S2_Replay, victim_id, BSHH_STORE_TIME-1.0);
        else
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME), &TVER_BSHH_S34_InternalReplay, victim_id, BSHH_STORE_TIME-1.0);
    } else if (is_me) {
        uint32_t v1=Vehicle_Nodes.Get(0)->GetId();
        uint32_t v2=Vehicle_Nodes.Get(1%N_Vehicles)->GetId();

        Simulator::Schedule(Seconds(9.9),  [v1,v2](){ if(!g_ctrl_ip_for_veh.empty()) TVER_SendTopoPacket(0,v1,v2,9.9,v1,false); });
        Simulator::Schedule(Seconds(9.95), [v1,v2](){ if(Vehicle_Nodes.GetN()>1&&!g_ctrl_ip_for_veh.empty()) TVER_SendTopoPacket(1,v2,v1,9.95,v2,false); });

        for (uint32_t i=0; i<Vehicle_Nodes.GetN(); i++)
            Simulator::Schedule(Seconds(0.1+i*0.01), &TVER_LegitTopoTick, i, t_end);

        if (attack_scenario==9)
            Simulator::Schedule(Seconds(ME_ECHO_TIME), &TVER_ME_S1_EchoAttack, 2%N_Vehicles, 3%N_Vehicles, v1, v2, 10.0);
        else if (attack_scenario==10)
            Simulator::Schedule(Seconds(ME_ECHO_TIME), &TVER_ME_S2_EchoAttack, v1, v2, 10.0);
        else
            Simulator::Schedule(Seconds(ME_ECHO_TIME), &TVER_ME_S34_EchoAttack, v1, v2, 10.0);
    }

    Simulator::Schedule(Seconds(simTime-0.05), &TVER_WriteSummary);

    std::string anim_xml = "temporal_veremi_anim_scenario" + std::to_string(attack_scenario) + ".xml";
    g_anim = new AnimationInterface(anim_xml);
    TVER_SetupNetAnim();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    delete g_anim; g_anim = nullptr;
    if (g_attack_log.is_open()) g_attack_log.close();
    if (g_pairs_csv.is_open())  g_pairs_csv.close();

    return 0;
}
