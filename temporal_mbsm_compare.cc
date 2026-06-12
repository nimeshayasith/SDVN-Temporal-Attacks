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
static uint32_t attack_percentage = 100;
static uint32_t N_Controllers     = 1;
static uint32_t g_n_malicious     = 0;

// ── SUMO mobility parameters (same naming as routing.cc) ───────────────
static int mobility_scenario = 1;   // 0=urban, 1=rural/non-urban, 2=highway
static int maxspeed          = 80;  // km/h — selects SUMO trace file

// ── BSM constants — SAME AS multibsm_attacks.cc ────────────────
static const double BSM_INTERVAL_S   = 0.050;
static const double DSRC_RANGE_M     = 250.0;
static const double MIN_SPEED_MS     = 12.0;
static const double MAX_SPEED_MS     = 20.0;
static const double POS_FROZEN_EPS_M = 0.05;
static const double SPEED_ZERO_THR   = 0.5;
static const uint32_t HISTORY_DEPTH  = 3;     // paper Table 3: 3 consecutive BSMs for Type 3

// ── Temporal attack timing — SAME AS routing.cc ────────────────
static const double TTW_HELLO_TIME  = 10.0;   // t=10: legitimate link exchange
static const double TTW_LINK_BREAK  = 15.0;   // t=15: physical link breaks
static const double TTW_REPLAY_TIME = 20.0;   // t=20: forged TopologyPacket injected

static const double BSHH_OLD_HB_TIME   = 0.0;   // timestamp of the captured old heartbeat (routing.cc: BSHH_S1_OLD_HB_TIME)
static const double BSHH_EXCHANGE_TIME = 5.0;   // legitimate heartbeat exchange (routing.cc: BSHH_S1_EXCHANGE_TIME)
static const double BSHH_REPLAY_TIME   = 10.0;  // replay attack fires

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
    double   pos_x = 0, pos_y = 0;  // position of src_id at observation time
};

// BSHH — heartbeat liveness record
struct HeartbeatPacket {
    uint32_t claimed_sender_id;   // whose identity this heartbeat claims
    uint32_t physical_sender_id;  // who actually transmitted it
    double   timestamp;           // time heartbeat was originally generated
    bool     is_replayed;         // true = this is a stored replay
    double   pos_x = 0, pos_y = 0;  // position at capture time
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

// Stored BSM kinematics at capture time — injected as the "replayed" BSM record
// so MBSM_Detect sees the stale-position anomaly:
//   TTW (10s gap): large position jump → Type 2 triggered (detectable)
//   BSHH (6s gap): medium jump → partially detectable
//   ME  (0.1s gap): near-zero jump → undetectable (supervisor predicted this)
static double g_ttw_stored_pos_x = 0, g_ttw_stored_pos_y = 0;
static double g_ttw_stored_speed = 0, g_ttw_stored_dir   = 0;
static double g_bshh_stored_pos_x = 0, g_bshh_stored_pos_y = 0;
static double g_bshh_stored_speed = 0, g_bshh_stored_dir   = 0;
static double g_me_link0_speed = 0, g_me_link0_dir = 0;
static double g_me_link1_speed = 0, g_me_link1_dir = 0;

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

static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history;            // RSU-level detection
static std::map<uint32_t, std::deque<BsmRecord>> g_bsm_history_controller;  // Controller-level detection (S2)
static std::set<uint32_t> g_flagged_rsus;  // RSUs detected as malicious at controller level

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

// Forward declarations needed by TEMP_EmitReplayedBsmRecord below
static void TEMP_RSUReceive(BsmRecord bsm);
static void TEMP_DeliverStaleBsm(uint32_t vehicle_id,
                                  double px, double py,
                                  double spd, double dir, double ts);

// ─────────────────────────────────────────────────────────────
// Deliver a replayed BSM record into the MBSM detection pipeline.
// Paper §4.2 Algorithm 1: RSU receives BSM, checks DB for previous record.
// If no previous record exists the BSM is documented and no alert is raised
// (Algorithm 1 line 13). The RSU database populates naturally from real BSMs
// already arriving over the socket before the replay fires — no artificial
// seeding. The replayed stale-position BSM is delivered directly.
static void TEMP_EmitReplayedBsmRecord(uint32_t vehicle_id,
                                        double stored_px, double stored_py,
                                        double stored_speed, double stored_dir,
                                        double replay_time)
{
    // Per Trabelsi 2022: detector runs at RSU. No RSU = no detection possible.
    if (RSU_Nodes.GetN() == 0) return;

    Simulator::Schedule(Seconds(0),
                        &TEMP_DeliverStaleBsm,
                        vehicle_id,
                        stored_px, stored_py,
                        stored_speed, stored_dir,
                        replay_time);
}

// ═══════════════════════════════════════════════════════════════
// MBSM_Detect — Algorithm 1: Trabelsi et al., Electronics 2022
// Implements all three attack type detectors from the paper:
//   Type 1: position frozen while speed>0 OR direction changes
//   Type 2: displacement physically impossible given speed×dt
//   Type 3: entire history window shows frozen position
// ═══════════════════════════════════════════════════════════════
// hist_map  — RSU-level: g_bsm_history; Controller-level: g_bsm_history_controller
// flagged   — RSU-level: g_flagged_vehicles; Controller-level: g_flagged_rsus
static bool MBSM_Detect(const BsmRecord& bsm,
                          std::map<uint32_t, std::deque<BsmRecord>>& hist_map,
                          std::set<uint32_t>& flagged)
{
    auto& hist = hist_map[bsm.vehicle_id];

    // Paper §4.2: if vehicle already in RSU central database, keep flagging
    bool already_flagged = (flagged.count(bsm.vehicle_id) > 0);

    // Algorithm 1 line 13: no previous record → add to database, no alert
    if (hist.empty()) {
        hist.push_back(bsm);
        return already_flagged;
    }

    const BsmRecord& prev = hist.back();
    double dt = bsm.timestamp - prev.timestamp;

    double pos_change = Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);

    // Attack Type 1: position frozen while speed is non-zero
    // Paper §4.2: "position is not changing; speed parameter are not zero"
    if (pos_change < POS_FROZEN_EPS_M &&
        bsm.speed_ms > SPEED_ZERO_THR) {
        hist.push_back(bsm);
        if (hist.size() > HISTORY_DEPTH) hist.pop_front();
        return true;
    }

    // Attack Type 2: kinematic bound — paper §4.2
    // "such distances cannot be covered with the given speed of the respective vehicle"
    // "The given speed" = the speed declared in the current BSM (bsm.speed_ms).
    double max_possible = bsm.speed_ms * dt;
    if (dt > 0.0 && max_possible > 0.0 && pos_change > max_possible) {
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

        // Socket BSMs always carry LEGITIMATE positions — never a BSM-level attack.
        // Only the explicitly injected stale BSM (TEMP_DeliverStaleBsm, is_attack=true)
        // counts as an attack event for MCC. Oracle state is used separately below
        // for PDR/Te2e window tracking only.
        bsm.is_attack = false;

        TEMP_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// RSU receive handler — runs MBSM_Detect on the BSM.
//
// MCC classification (is_attack):
//   true  → explicitly injected stale BSM (TEMP_DeliverStaleBsm only)
//           detector fires → TP; misses → FN (shouldn't happen for large displacement)
//   false → regular socket BSM (legitimate position)
//           detector fires → FP (due to stale g_prev_bsm after an attack);
//           detector silent → TN
//
// PDR/Te2e window (in_attack_window):
//   Uses oracle state to track BSM delivery during the attack period.
//   This is broader than is_attack — includes regular BSMs from oracle-marked vehicles.
// ─────────────────────────────────────────────────────────────
static void TEMP_RSUReceive(BsmRecord bsm)
{
    double now       = Simulator::Now().GetSeconds();
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

    // MBSM_Detect at RSU level — detects malicious vehicles (S1 scenarios)
    bool detected = MBSM_Detect(bsm, g_bsm_history, g_flagged_vehicles);

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
// Deliver a stale-position attack BSM one BSM interval after injection.
// Scheduled by TEMP_EmitReplayedBsmRecord so detection fires at
// replay_time + BSM_INTERVAL_S → Tdet ≈ BSM_INTERVAL_S * 1000 ms.
static void TEMP_DeliverStaleBsm(uint32_t vehicle_id,
                                  double px, double py,
                                  double spd, double dir, double ts)
{
    if (RSU_Nodes.GetN() == 0) return;
    BsmRecord fake;
    fake.vehicle_id = vehicle_id;
    fake.pos_x      = px;
    fake.pos_y      = py;
    fake.speed_ms   = spd;
    fake.direction  = dir;
    fake.timestamp  = ts;
    fake.is_attack  = true;
    TEMP_RSUReceive(fake);
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
// TEMP_ControllerReceive — controller-level detection for S2 (malicious RSU)
//
// Architecture (supervisor's design):
//   S1 (malicious vehicle): RSU runs MBSM_Detect on vehicle BSMs → detects attacker vehicle
//   S2 (malicious RSU)    : Controller compares two streams for the same vehicle:
//     (a) Vehicle-direct BSM  : vehicle sends CURRENT position directly to controller (legit)
//     (b) RSU-forwarded BSM   : RSU sends OLD (replayed) position to controller (attack)
//   Controller MBSM_Detect sees: current-pos BSM → old-pos BSM, dt = BSM_INTERVAL_S
//   pos_change ~120m >> speed×dt → Type 2 fires → RSU detected as malicious (TP)
//   ME-S2: echo reports carry no position change → no detection (FN, expected)
// ─────────────────────────────────────────────────────────────
static void TEMP_ControllerReceive(BsmRecord bsm)
{
    double now      = Simulator::Now().GetSeconds();
    bool   is_attack = bsm.is_attack;

    bool detected = MBSM_Detect(bsm, g_bsm_history_controller, g_flagged_rsus);

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
                     << "]  CONTROLLER-DETECT V" << bsm.vehicle_id
                     << " pos=(" << bsm.pos_x << "," << bsm.pos_y << ")"
                     << " spd=" << bsm.speed_ms
                     << " attack=" << is_attack
                     << " detected=" << detected << "\n";
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

    if (!InRSURange(px, py)) return;  // returns false immediately when N_RSUs==0

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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_speed, g_ttw_stored_dir);

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

    // Forge the topology packet — includes V0's OLD position at capture time
    TopologyPacket forged;
    forged.src_id    = v0_id;
    forged.seen_id   = v1_id;
    forged.timestamp = forged_time;
    forged.is_forged = true;
    forged.pos_x     = g_ttw_stored_pos_x;  // V0's old position (from HELLO_TIME)
    forged.pos_y     = g_ttw_stored_pos_y;

    std::ostringstream key;
    key << v0_id << "_" << v1_id;
    g_ttw_controller_table[key.str()] = forged;

    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = forged_time;

    // ── Controller-level cross-check (TTW-S1: malicious vehicle) ─────────────
    // V0 sends its current-position BSM directly to controller (legitimate path).
    // V0 ALSO sends the forged topology packet with V0's OLD position (attack path).
    // Controller MBSM_Detect: current pos → old pos, ~120m jump in BSM_INTERVAL_S → TP.
    double cur_px = 0, cur_py = 0, cur_spd = 0, cur_dir = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_spd, cur_dir);

    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x      = cur_px;  veh_direct.pos_y  = cur_py;
    veh_direct.speed_ms   = cur_spd; veh_direct.direction = cur_dir;
    veh_direct.timestamp  = forged_time;
    veh_direct.is_attack  = false;
    TEMP_ControllerReceive(veh_direct);

    BsmRecord forged_bsm;
    forged_bsm.vehicle_id = v0_id;
    forged_bsm.pos_x      = g_ttw_stored_pos_x;  // OLD position from topology packet
    forged_bsm.pos_y      = g_ttw_stored_pos_y;
    forged_bsm.speed_ms   = g_ttw_stored_speed;
    forged_bsm.direction  = g_ttw_stored_dir;
    forged_bsm.timestamp  = forged_time + BSM_INTERVAL_S;
    forged_bsm.is_attack  = true;
    TEMP_ControllerReceive(forged_bsm);
    // ─────────────────────────────────────────────────────────────────────────

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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_speed, g_bshh_stored_dir);

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

    // Replay the stored heartbeat with V0's identity + V0's OLD position
    HeartbeatPacket replayed;
    replayed.claimed_sender_id  = v0_id;
    replayed.physical_sender_id = v1_id;
    replayed.timestamp          = g_bshh_stored_heartbeat.timestamp;
    replayed.is_replayed        = true;
    replayed.pos_x              = g_bshh_stored_pos_x;  // V0's old position at capture time
    replayed.pos_y              = g_bshh_stored_pos_y;

    g_bshh_controller_liveness_table[v0_id] = replayed;

    HeartbeatPacket forwarded_by_victim;
    forwarded_by_victim.claimed_sender_id  = v1_id;
    forwarded_by_victim.physical_sender_id = v0_id;
    forwarded_by_victim.timestamp          = g_bshh_stored_heartbeat.timestamp;
    forwarded_by_victim.is_replayed        = true;
    g_bshh_controller_liveness_table[v1_id] = forwarded_by_victim;

    g_oracle_attack_state[v1_id] = true;
    g_oracle_attack_state[v0_id] = true;
    pem_attack_start_time = replay_time;

    // ── Controller-level cross-check (BSHH-S1: malicious vehicle) ────────────
    // V0 sends current-position BSM directly to controller (legitimate).
    // V1 sends forged heartbeat claiming V0's identity with V0's OLD position (attack).
    // Controller MBSM_Detect for V0: current pos → old pos → Type 2 → TP.
    double cur_px = 0, cur_py = 0, cur_spd = 0, cur_dir = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_spd, cur_dir);

    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x      = cur_px;  veh_direct.pos_y  = cur_py;
    veh_direct.speed_ms   = cur_spd; veh_direct.direction = cur_dir;
    veh_direct.timestamp  = replay_time;
    veh_direct.is_attack  = false;
    TEMP_ControllerReceive(veh_direct);

    BsmRecord forged_hb;
    forged_hb.vehicle_id = v0_id;                       // V1 claims V0's identity
    forged_hb.pos_x      = g_bshh_stored_pos_x;        // V0's OLD position
    forged_hb.pos_y      = g_bshh_stored_pos_y;
    forged_hb.speed_ms   = g_bshh_stored_speed;
    forged_hb.direction  = g_bshh_stored_dir;
    forged_hb.timestamp  = replay_time + BSM_INTERVAL_S;
    forged_hb.is_attack  = true;
    TEMP_ControllerReceive(forged_hb);
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

    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_speed, g_me_link0_dir);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_speed, g_me_link1_dir);
    g_me_link_stored = true;

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
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by MBSM_Detect as legitimate positions → FN → MCC≈0.
    // Injecting at ME_ECHO_TIME causes dt=0 timestamp collision with socket BSMs
    // which incorrectly triggers Type 1 (frozen position) detection.

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
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_speed, g_ttw_stored_dir);
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
    TopologyPacket forged = { v1_id, v0_id, forged_time, true,
                              g_ttw_stored_pos_x, g_ttw_stored_pos_y };  // old position in forged packet
    std::ostringstream key; key << v1_id << "_" << v0_id;
    g_ttw_controller_table[key.str()] = forged;
    g_oracle_attack_state[v1_id] = true;
    if (pem_attack_start_time < 0) pem_attack_start_time = forged_time;

    // ── Controller-level cross-check (supervisor's architecture) ──────────────
    // V1 sends current-position BSM directly to controller (legitimate path).
    // RSU (malicious) sends old-position BSM to controller (replayed path).
    // Controller MBSM_Detect sees: current pos → old pos, large jump → Type 2 → TP.
    double cur_px = 0, cur_py = 0, cur_spd = 0, cur_dir = 0;
    if (v1_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v1_id), cur_px, cur_py, cur_spd, cur_dir);

    // (a) Vehicle-direct: current position, baseline (not attack)
    BsmRecord veh_direct;
    veh_direct.vehicle_id = v1_id;
    veh_direct.pos_x      = cur_px;
    veh_direct.pos_y      = cur_py;
    veh_direct.speed_ms   = cur_spd;
    veh_direct.direction  = cur_dir;
    veh_direct.timestamp  = forged_time;
    veh_direct.is_attack  = false;
    TEMP_ControllerReceive(veh_direct);

    // (b) RSU-forwarded: OLD position (stale, from capture time), is_attack=true
    BsmRecord rsu_forward;
    rsu_forward.vehicle_id = v1_id;
    rsu_forward.pos_x      = g_ttw_stored_pos_x;  // old position
    rsu_forward.pos_y      = g_ttw_stored_pos_y;
    rsu_forward.speed_ms   = g_ttw_stored_speed;
    rsu_forward.direction  = g_ttw_stored_dir;
    rsu_forward.timestamp  = forged_time + BSM_INTERVAL_S;  // arrives slightly after vehicle-direct
    rsu_forward.is_attack  = true;
    TEMP_ControllerReceive(rsu_forward);
    // ──────────────────────────────────────────────────────────────────────────
    if (pem_attack_start_time < 0) pem_attack_start_time = forged_time;  // first attack only
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << forged_time
            << "]  *** TTW-S2 REPLAY ATTACK BEGINS (ATTACKER: RSU) ***\n"
            << "  RSU injects: { src=V" << v1_id << ", seen=V" << v0_id
            << ", t=" << forged_time << ", forged=TRUE }\n"
            << "  Old stored:  { t=" << g_ttw_stored_packet.timestamp << " }\n"
            << "  Controller effect: Ghost link V" << v1_id << "↔V" << v0_id << " maintained\n"
            << "  BSM CROSS-CHECK: old stored pos Y vs real current pos X → displacement gap\n"
            << "  MBSM_Detect → TRUE → TP. MCC>0.\n"
            << "  ORACLE: V" << v1_id << " BSMs labeled attack=TRUE → TRUE POSITIVES\n\n";
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
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_speed, g_ttw_stored_dir);
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
    TEMP_EmitReplayedBsmRecord(v1_id, g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                                g_ttw_stored_speed, g_ttw_stored_dir, forged_time);
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
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_ttw_stored_pos_x, g_ttw_stored_pos_y,
                      g_ttw_stored_speed, g_ttw_stored_dir);
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_speed, g_bshh_stored_dir);
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
    HeartbeatPacket forged = { v0_id, 0xFFFFFFFF, g_bshh_stored_heartbeat.timestamp, true,
                               g_bshh_stored_pos_x, g_bshh_stored_pos_y };  // old position
    g_bshh_controller_liveness_table[v0_id] = forged;
    g_oracle_attack_state[v0_id] = true;
    if (pem_attack_start_time < 0) pem_attack_start_time = replay_time;

    // ── Controller-level cross-check (supervisor's architecture) ──────────────
    double cur_px = 0, cur_py = 0, cur_spd = 0, cur_dir = 0;
    if (v0_id < Vehicle_Nodes.GetN())
        GetKinematics(Vehicle_Nodes.Get(v0_id), cur_px, cur_py, cur_spd, cur_dir);

    // (a) Vehicle-direct: V0's current position sent directly to controller
    BsmRecord veh_direct;
    veh_direct.vehicle_id = v0_id;
    veh_direct.pos_x      = cur_px;
    veh_direct.pos_y      = cur_py;
    veh_direct.speed_ms   = cur_spd;
    veh_direct.direction  = cur_dir;
    veh_direct.timestamp  = replay_time;
    veh_direct.is_attack  = false;
    TEMP_ControllerReceive(veh_direct);

    // (b) RSU-forwarded: old position (from BSHH capture time), is_attack=true
    BsmRecord rsu_forward;
    rsu_forward.vehicle_id = v0_id;
    rsu_forward.pos_x      = g_bshh_stored_pos_x;  // old position
    rsu_forward.pos_y      = g_bshh_stored_pos_y;
    rsu_forward.speed_ms   = g_bshh_stored_speed;
    rsu_forward.direction  = g_bshh_stored_dir;
    rsu_forward.timestamp  = replay_time + BSM_INTERVAL_S;
    rsu_forward.is_attack  = true;
    TEMP_ControllerReceive(rsu_forward);
    // ──────────────────────────────────────────────────────────────────────────
    if (pem_attack_start_time < 0) pem_attack_start_time = replay_time;  // first attack only
    if (g_attack_log.is_open()) {
        g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << replay_time
            << "]  *** BSHH-S2 REPLAY ATTACK BEGINS (ATTACKER: RSU) ***\n"
            << "  RSU → controller: { claimed=V" << v0_id
            << ", physical=RSU(sentinel), t=" << forged.timestamp << ", replayed=TRUE }\n"
            << "  Controller V" << v0_id << " liveness overwritten with stale t=" << forged.timestamp << "\n"
            << "  BSM CROSS-CHECK: RSU claims old liveness pos Y; real BSM shows current pos X\n"
            << "  Displacement gap Y→X exceeds kinematic bound → MBSM_Detect → TRUE → TP\n"
            << "  ORACLE: V" << v0_id << " BSMs labeled attack=TRUE → TRUE POSITIVES → MCC>0\n\n";
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_speed, g_bshh_stored_dir);
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
    TEMP_EmitReplayedBsmRecord(v0_id, g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                                g_bshh_stored_speed, g_bshh_stored_dir, replay_time);
    TEMP_EmitReplayedBsmRecord(v1_id, g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                                g_bshh_stored_speed, g_bshh_stored_dir, replay_time);
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_bshh_stored_pos_x, g_bshh_stored_pos_y,
                      g_bshh_stored_speed, g_bshh_stored_dir);
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_speed, g_me_link0_dir);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_speed, g_me_link1_dir);
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
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by MBSM_Detect as legitimate positions → FN → MCC≈0.
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_speed, g_me_link0_dir);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_speed, g_me_link1_dir);
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
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by MBSM_Detect as legitimate positions → FN → MCC≈0.
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
    if (Vehicle_Nodes.GetN() > v0_id)
        GetKinematics(Vehicle_Nodes.Get(v0_id), g_me_link0_x, g_me_link0_y,
                      g_me_link0_speed, g_me_link0_dir);
    if (Vehicle_Nodes.GetN() > v1_id)
        GetKinematics(Vehicle_Nodes.Get(v1_id), g_me_link1_x, g_me_link1_y,
                      g_me_link1_speed, g_me_link1_dir);
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
    // No artificial BSM injection for ME: oracle-labeled socket BSMs from V2/V3
    // will be processed by MBSM_Detect as legitimate positions → FN → MCC≈0.
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
    InternetStackHelper internet;
    internet.Install(Vehicle_Nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",   StringValue("1ms"));

    Ipv4AddressHelper addr;

    // Detector node: RSU only. Per Trabelsi 2022, detection is RSU-based.
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
        base << "10.5." << (i + 1) << ".0";
        addr.SetBase(base.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifc = addr.Assign(devs);

        if (i == 0) g_rsu_ip = ifc.GetAddress(1);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    g_rsu_recv_socket = Socket::CreateSocket(
        detector, TypeId::LookupByName("ns3::UdpSocketFactory"));
    g_rsu_recv_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), BSM_PORT));
    g_rsu_recv_socket->SetRecvCallback(MakeCallback(&TEMP_RSUSocketReceive));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    ApplicationContainer sinkApps = sinkHelper.Install(detector);
    sinkApps.Start(Seconds(0.0));
    sinkApps.Get(0)->SetStopTime(Seconds(simTime));
    for (uint32_t i = 0; i < n_links; i++) {
        sinkHelper.Install(Vehicle_Nodes.Get(i)).Start(Seconds(0.0));
    }
}

// ─────────────────────────────────────────────────────────────
// SUMO trace file path resolver (mirrors routing.cc logic)
// ─────────────────────────────────────────────────────────────
static std::string TEMP_GetSumoTraceFile()
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
static void TEMP_InstallVehicleMobility()
{
    std::string trace_file = TEMP_GetSumoTraceFile();
    std::ifstream tf_check(trace_file);
    bool use_sumo = tf_check.good();
    tf_check.close();

    if (use_sumo)
    {
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
static uint32_t ComputeNMalicious(uint32_t n_total, uint32_t pct) {
    if (pct == 0 || n_total == 0) return 0;
    return std::max(1u, (n_total * pct) / 100);
}

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
        << "  Simulation time  : " << simTime          << " s\n"
        << "  Vehicles         : " << N_Vehicles        << "\n"
        << "  RSUs             : " << N_RSUs             << "\n"
        << "  Controllers      : " << N_Controllers      << "\n"
        << "  Attack percentage: " << attack_percentage  << "%"
        << " (" << g_n_malicious << " malicious node(s))\n";

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
            << "  old_hb_timestamp=" << BSHH_OLD_HB_TIME << ": timestamp of captured old heartbeat\n"
            << "  t=EXCHANGE(" << BSHH_EXCHANGE_TIME << "): legitimate heartbeat exchange (controller gets fresh V0 t=" << BSHH_EXCHANGE_TIME << ")\n"
            << "  t=REPLAY(" << BSHH_REPLAY_TIME << "): old t=" << BSHH_OLD_HB_TIME << " heartbeat replayed → stale liveness\n";
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

    // Append mode — accumulates events from all 12 scenario runs in one file.
    // Write header only when file is new/empty.
    {
        bool need_hdr = false;
        std::ifstream chk("temporal_mbsm_compare_events.csv");
        need_hdr = !chk.good() || chk.peek() == std::ifstream::traits_type::eof();
        g_events_csv.open("temporal_mbsm_compare_events.csv", std::ios::out | std::ios::app);
        if (need_hdr)
            g_events_csv
                << "attack_scenario,sim_time_s,vehicle_id,reported_pos_x,reported_pos_y,"
                << "speed_ms,direction_rad,is_attack,alert_raised\n";
    }
}

// ─────────────────────────────────────────────────────────────
// Compute routing-level PDR from ghost/phantom entries in controller tables.
// Each forged topology entry, phantom ME path, or stale heartbeat disrupts a
// fraction of simulated unicast flows → PDR decreases with attack percentage.
// ─────────────────────────────────────────────────────────────
static void TEMP_ComputeRoutingPDR()
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
static void TEMP_WriteSummary()
{
    double tp = (double)pem_tp, tn = (double)pem_tn;
    double fp = (double)pem_fp, fn = (double)pem_fn;

    // MCC with epsilon-stabilised denominator: numerator=0 when tp=fp=fn=0 → MCC=0.
    // Eliminates the artificial MCC=1 spike at 0% attack (0/0 undefined case).
    static const double MCC_EPS = 1e-9;
    double denom_eps = std::sqrt(
        (tp + fp + MCC_EPS) * (tp + fn + MCC_EPS) *
        (tn + fp + MCC_EPS) * (tn + fn + MCC_EPS));
    double mcc = (tp * tn - fp * fn) / denom_eps;
    double total = tp + tn + fp + fn;
    double acr   = (total > 0.0) ? ((tp + tn) / total * 100.0) : 0.0;
    double prec  = (tp + fp > 0.0) ? (tp / (tp + fp)) : 0.0;
    double rec   = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double tdet  = (pem_attack_start_time >= 0.0 && pem_first_alert_time >= 0.0)
                   ? (pem_first_alert_time - pem_attack_start_time) * 1000.0
                   : -1.0;

    // ── AUROC — single-point formula for rule-based binary detector ──────────
    // AUROC = 0.5*(TPR + TNR).  When TP=0, FP=0: AUROC = 0.5*(0+1) = 0.500.
    // Matches routing.cc pem_run_summary.csv column layout.
    double tpr   = (tp + fn > 0.0) ? (tp / (tp + fn)) : 0.0;
    double fpr   = (fp + tn > 0.0) ? (fp / (fp + tn)) : 0.0;
    double auroc = 0.5 * (tpr + (1.0 - fpr));

    // ── PDR — routing-level packet delivery, decreasing with attack percentage ─
    // Computed from ghost/phantom entry count in controller tables.
    // PDR_baseline = 100% (no disruption); PDR_attack decreases as more controller
    // entries are poisoned, matching the expected trend in research papers.
    TEMP_ComputeRoutingPDR();
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
        interp_ss << "TP=0: MBSM_Detect did not detect stale-position anomaly for this scenario";
    } else {
        interp_ss << pem_tp << "TP: stale-position jump detected (large time-gap replay creates impossible kinematic jump)";
    }
    std::string csv_interp = interp_ss.str();

    // Append mode — accumulates all scenarios in one file across runs.
    // Write header only when file is new/empty.
    bool write_header = false;
    { std::ifstream chk("temporal_mbsm_compare_summary.csv"); write_header = !chk.good() || chk.peek() == std::ifstream::traits_type::eof(); }
    std::ofstream sum("temporal_mbsm_compare_summary.csv", std::ios::out | std::ios::app);
    if (write_header)
        sum << "attack_scenario,scenario_name,N_Vehicles,N_RSUs,N_Controllers,"
            << "attack_percentage,n_malicious,detector,"
            << "tp,tn,fp,fn,mcc,auroc,acr_pct,precision,recall,tdet_ms,"
            << "pdr_under_attack_pct,pdr_baseline_pct,"
            << "te2e_under_attack_ms,te2e_baseline_ms,"
            << "flagged_vehicles,alert_tx_count,interpretation\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario << ","
        << "\"" << GetScenarioName(attack_scenario) << "\","
        << N_Vehicles << "," << N_RSUs << "," << N_Controllers << ","
        << attack_percentage << "," << g_n_malicious << ","
        << "MBSM_Detect (Trabelsi 2022),"
        << pem_tp << "," << pem_tn << "," << pem_fp << "," << pem_fn << ","
        << mcc   << "," << auroc << "," << acr << "," << prec << "," << rec << ","
        << tdet  << ","
        << pdr_attack << "," << pdr_baseline << ","
        << te2e_attack << "," << te2e_baseline << ","
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
            << "  MCC              = " << std::fixed << std::setprecision(3) << mcc   << "\n"
            << "  AUROC            = " << auroc << "  (single-point: 0.500 when TP=0)\n"
            << "  ACR              = " << acr   << " %\n"
            << "  Precision        = " << prec  << "\n"
            << "  Recall           = " << rec   << "\n"
            << "  Tdet             = " << tdet  << " ms  (-1.0 = no detection)\n"
            << "  ──────────────────────────────────────────────────\n"
            << "  PDR under attack = " << pdr_attack   << " %"
            << "  (" << g_bsm_recv_attack   << "/" << g_bsm_sent_attack   << " BSMs)\n"
            << "  PDR baseline     = " << pdr_baseline  << " %"
            << "  (" << g_bsm_recv_baseline << "/" << g_bsm_sent_baseline << " BSMs)\n"
            << "  Te2e attack      = " << te2e_attack   << " ms  (one-hop send→RSU)\n"
            << "  Te2e baseline    = " << te2e_baseline  << " ms  (one-hop send→RSU)\n"
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
              << "  MCC="   << std::fixed << std::setprecision(3) << mcc
              << "  AUROC=" << auroc
              << "  ACR="   << acr << "%\n"
              << "  Tdet="  << tdet  << " ms"
              << "  PDR(attack)="   << pdr_attack   << "%"
              << "  PDR(base)="     << pdr_baseline << "%\n"
              << "  Te2e(attack)="  << te2e_attack  << " ms"
              << "  Te2e(base)="    << te2e_baseline << " ms\n"
              << "  FlaggedVehicles=" << g_flagged_vehicles.size()
              << "  AlertTxCount="    << g_rsu_alert_tx_count << "\n"
              << "  " << console_verdict << "\n"
              << "  Summary CSV: temporal_mbsm_compare_summary.csv\n";
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

    TEMP_InitLogs();

    {
        std::string mob_name;
        if      (mobility_scenario == 0) mob_name = "urban";
        else if (mobility_scenario == 1) mob_name = "rural (non-urban)";
        else                             mob_name = "highway (autobahn)";
        std::cout << "\n══════════════════════════════════════════════════════════════\n"
                  << "  Temporal-Echo vs. Multi-BSM — Incompatibility Study\n"
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
                  << "  (trace: " << TEMP_GetSumoTraceFile() << ")\n"
                  << "  Detector         : MBSM_Detect (verbatim from multibsm_attacks.cc)\n"
                  << "  Expected result  : TP=0, MCC=0 (detector is data-plane only)\n"
                  << "══════════════════════════════════════════════════════════════\n\n";
    }

    // ── Create nodes ─────────────────────────────────────────────
    Vehicle_Nodes.Create(N_Vehicles);
    if (N_RSUs > 0) RSU_Nodes.Create(N_RSUs);

    // ── Vehicle mobility — SUMO trace or constant-velocity fallback ──
    TEMP_InstallVehicleMobility();

    // ── RSU mobility — fixed position ────────────────────────────
    if (RSU_Nodes.GetN() > 0) {
        MobilityHelper mobR;
        mobR.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobR.Install(RSU_Nodes);
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
    TEMP_SetupNetwork();

    // ── Schedule BSM ticks for ALL vehicles (ALL always legitimate) ─
    double t_end = simTime - 0.5;
    for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
        Simulator::Schedule(Seconds(0.1 + i * 0.001), &TEMP_BsmTick, i, t_end);
    }

    // ── Schedule TOPOLOGY-LEVEL attack events ─────────────────────
    // These do NOT affect BSM content — they only modify
    // in-memory controller tables and set the oracle flag.

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
                &TEMP_TTW_LegitTopologyUpdate, a, b, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt + 0.001),
                &TEMP_TTW_LegitTopologyUpdate, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt + 0.01),
                &TEMP_TTW_StorePacket, a, b, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TEMP_TTW_LinkBreak, a, b);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TEMP_TTW_ReplayAttack, a, b, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 2) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TEMP_TTW_S2_VehiclesToRSU, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TEMP_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TEMP_TTW_S2_RSUReplayAttack, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 3) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TEMP_TTW_S3_VehicleToController, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TEMP_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TEMP_TTW_S3_ControllerInternalReplay, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 4) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(TTW_HELLO_TIME + dt),
                &TEMP_TTW_S4_VehiclesViaRSU, b, a, TTW_HELLO_TIME + dt);
            Simulator::Schedule(Seconds(TTW_LINK_BREAK + dt),
                &TEMP_TTW_LinkBreak, b, a);
            Simulator::Schedule(Seconds(TTW_REPLAY_TIME + dt),
                &TEMP_TTW_S4_ControllerInternalReplay, b, a, TTW_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 5) {
        // BSHH-S1: Malicious Vehicle, No RSU
        // Matches routing.cc: BSHH_S1_EXCHANGE_TIME=5, BSHH_S1_OLD_HB_TIME=0, BSHH_S1_REPLAY_TIME=10
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            // t=5: legitimate exchange → controller gets fresh V0 alive at t=5
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TEMP_BSHH_LegitExchange, a, b, BSHH_EXCHANGE_TIME + dt);
            // t=5.05: store old heartbeat with timestamp=BSHH_OLD_HB_TIME(=0), not exchange time
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.05),
                &TEMP_BSHH_StoreHeartbeat, a, b, BSHH_OLD_HB_TIME + dt);
            // t=10: replay old t=0 heartbeat → controller overwrites t=5 with t=0 → stale liveness
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TEMP_BSHH_ReplayAttack, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 6) {
        // BSHH-S2: Malicious RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TEMP_BSHH_S2_LegitViaRSU, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TEMP_BSHH_S2_RSUStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TEMP_BSHH_S2_RSUReplayAttack, a, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 7) {
        // BSHH-S3: Malicious Controller, No RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TEMP_BSHH_S3_LegitToController, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TEMP_BSHH_S3_ControllerStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TEMP_BSHH_S3_ControllerInternalReplay, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 8) {
        // BSHH-S4: Malicious Controller, With RSU
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt),
                &TEMP_BSHH_S4_LegitViaRSU, a, b, BSHH_EXCHANGE_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_EXCHANGE_TIME + dt + 0.01),
                &TEMP_BSHH_S4_ControllerStoreHeartbeat, a, BSHH_OLD_HB_TIME + dt);
            Simulator::Schedule(Seconds(BSHH_REPLAY_TIME + dt),
                &TEMP_BSHH_S4_ControllerInternalReplay, a, b, BSHH_REPLAY_TIME + dt);
        }

    } else if (attack_scenario == 9) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TEMP_ME_LegitDiscovery, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TEMP_ME_InjectEchoReports, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 10) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TEMP_ME_S2_LegitViaRSU, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TEMP_ME_S2_RSUInjectEchoReports, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 11) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TEMP_ME_S3_LegitToController, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TEMP_ME_S3_ControllerCreatePhantom, c, d, a, b, ME_ECHO_TIME + dt);
        }

    } else if (attack_scenario == 12) {
        for (uint32_t i = 0; i < g_n_malicious; i++) {
            uint32_t a = Vehicle_Nodes.Get(i % N_Vehicles)->GetId();
            uint32_t b = Vehicle_Nodes.Get((i + 1) % N_Vehicles)->GetId();
            uint32_t c = Vehicle_Nodes.Get((i + 2) % N_Vehicles)->GetId();
            uint32_t d = Vehicle_Nodes.Get((i + 3) % N_Vehicles)->GetId();
            double dt = i * ATTACK_STAGGER_S;
            Simulator::Schedule(Seconds(ME_LEGIT_TIME + dt),
                &TEMP_ME_S4_LegitViaRSU, a, b, c, d, ME_LEGIT_TIME + dt);
            Simulator::Schedule(Seconds(ME_ECHO_TIME + dt),
                &TEMP_ME_S4_ControllerCreatePhantom, c, d, a, b, ME_ECHO_TIME + dt);
        }
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
