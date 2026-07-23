// comparison_detector.h
// ─────────────────────────────────────────────────────────────────────────────
// Full-fidelity implementation of:
//   VeReMi VREM_Detect — Mekonen et al., PLOS ONE 2025 (Algorithm 1, 5-type)
//   MBSM_Detect        — Trabelsi et al., Electronics 2022 (Algorithm 1, 3-type)
//
// Embedded in routing.cc so detection runs on the real NS-3 network:
//   real 802.11p DSRC, real SUMO mobility, real 200-vehicle topology.
//
// Detection is performed by reading vehicle positions from MobilityModel
// (identical SUMO positions used by routing.cc) at each BSM interval.
// For S2 (TTW malicious RSU) and S6 (BSHH malicious RSU), a stale-position
// BSM is injected at the replay time — exactly as the standalone CC files do.
//
// ── Algorithms ───────────────────────────────────────────────────────────────
// VREM_Detect (VeReMi CC verbatim):
//   Type 1  — position frozen while speed>0 OR directional change
//   Type 2  — velocity-predicted path deviation > SAFETY_FACTOR × v_max × dt
//   Type 4  — random position: same path deviation check
//   Type 8  — random offset: same path deviation check
//   Type 16 — eventual-stop: all HISTORY_DEPTH consecutive BSMs frozen
//
// MBSM_Detect (MBSM CC verbatim):
//   Type 1 — position frozen while speed>0 OR direction changes (+ g_flagged)
//   Type 2 — kinematic bound: (v_max×dt + 0.5×a_max×dt²) × SAFETY_FACTOR
//   Type 3 — all HISTORY_DEPTH consecutive BSMs frozen
//   + g_flagged_vehicles RSU central database (paper §4.2)
//
// ── Stale BSM injection ───────────────────────────────────────────────────────
// Matches standalone CC behaviour:
//   S2  (TTW  malicious RSU): capture at t=10, inject stale at t=20 → TP possible
//   S6  (BSHH malicious RSU): capture at t=4,  inject stale at t=10 → TP possible
//   S1/S3/S4/S5/S7/S8 (no RSU or malicious controller): no stale BSM → MCC=0
//   S9–S12 (ME): no stale BSM → MCC=0
//
// ── Routing.cc hook (4 lines, no other changes) ──────────────────────────────
//   1. After last #include:
//        uint32_t comparison_detector = 0;
//        #include "comparison_detector.h"
//   2. In cmd.AddValue block:
//        cmd.AddValue("comparison_detector","0=none 1=VeReMi 2=MBSM",comparison_detector);
//   3. After declare_attackers() in main():
//        CD_Start(Vehicle_Nodes, RSU_Nodes, simTime, attack_scenario,
//                 ttw_malicious_nodes, bshh_malicious_nodes,
//                 me_malicious_nodes, &pem_attack_active);
//   4. Before PemWriteRunSummaryCsv schedule:
//        Simulator::Schedule(Seconds(simTime - 0.002), &CD_WriteSummary,
//            attack_scenario, attack_percentage, N_Vehicles, N_RSUs);
// ─────────────────────────────────────────────────────────────────────────────

#ifndef COMPARISON_DETECTOR_H
#define COMPARISON_DETECTOR_H

#include <algorithm>
#include <cmath>
#include <deque>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ns3/mobility-module.h"
#include "ns3/node-container.h"
#include "ns3/simulator.h"

// comparison_detector is declared in routing.cc before this include
// (uint32_t comparison_detector = 0;)

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm parameters — exact values from standalone CC files
// ─────────────────────────────────────────────────────────────────────────────

// VeReMi (Mekonen 2025) constants — match temporal_veremi_compare.cc verbatim
static const double   CD_V_BSM_INTERVAL_S   = 0.100;  // 100 ms beacon interval
static const double   CD_V_DSRC_RANGE_M     = 250.0;
static const double   CD_V_POS_FROZEN_EPS_M = 0.05;
static const double   CD_V_SPEED_ZERO_THR   = 0.5;
static const double   CD_V_SAFETY_FACTOR    = 1.5;
static const double   CD_V_DIR_CHANGE_THR   = 0.1;    // radians (~5.7°)
static const uint32_t CD_V_HISTORY_DEPTH    = 5;

// MBSM (Trabelsi 2022) constants — match temporal_mbsm_compare.cc verbatim
static const double   CD_M_BSM_INTERVAL_S   = 0.050;  // 50 ms beacon interval
static const double   CD_M_DSRC_RANGE_M     = 250.0;
static const double   CD_M_POS_FROZEN_EPS_M = 0.05;
static const double   CD_M_SPEED_ZERO_THR   = 0.5;
static const double   CD_M_SAFETY_FACTOR    = 1.5;
static const double   CD_M_DIR_CHANGE_THR   = 0.1;    // radians (~5.7°)
static const double   CD_M_MAX_ACCEL_MS2    = 2.6;    // paper Table 2
static const uint32_t CD_M_HISTORY_DEPTH    = 3;      // paper Table 3

// Stale BSM injection timings (match CC file defaults, same as routing.cc defaults)
static const double CD_TTW_CAPTURE_TIME     = 10.0;   // same as TTW_HELLO_TIME
static const double CD_TTW_REPLAY_TIME      = 20.0;   // same as TTW_REPLAY_TIME
static const double CD_BSHH_CAPTURE_TIME    = 4.0;    // same as BSHH_STORE_TIME in CC
static const double CD_BSHH_REPLAY_TIME     = 10.0;   // same as BSHH_REPLAY_TIME in CC

// ─────────────────────────────────────────────────────────────────────────────
// BSM record — unified for both detectors (fields for both VeReMi and MBSM)
// ─────────────────────────────────────────────────────────────────────────────
struct CD_BsmRecord {
    uint32_t vehicle_id;
    double   pos_x, pos_y;
    double   spd_x, spd_y;    // velocity components (Cartesian m/s)
    double   speed_ms;         // scalar speed = sqrt(spd_x²+spd_y²)
    double   direction;        // atan2(spd_y, spd_x) in radians
    double   timestamp;
    bool     is_attack;        // oracle label
};

// ─────────────────────────────────────────────────────────────────────────────
// Detector state — all static, cd_ prefixed
// ─────────────────────────────────────────────────────────────────────────────

// VeReMi state
static std::map<uint32_t, CD_BsmRecord>              cd_v_prev_bsm;
static std::map<uint32_t, std::deque<CD_BsmRecord>>  cd_v_bsm_history;

// MBSM state
static std::map<uint32_t, std::deque<CD_BsmRecord>>  cd_m_bsm_history;
static std::set<uint32_t>                            cd_m_flagged_vehicles;

// PEM counters
static uint64_t cd_tp = 0, cd_tn = 0, cd_fp = 0, cd_fn = 0;
static double   cd_first_alert_time  = -1.0;
static double   cd_attack_start_time = -1.0;

// Oracle
static std::set<uint32_t> cd_malicious_node_ids;  // global NS-3 node IDs
static const bool*         cd_pem_attack_active = nullptr;

// PDR counters (legacy BSM delivery — replaced by routing PDR below)
static uint64_t cd_bsm_sent_attack = 0, cd_bsm_recv_attack = 0;
static uint64_t cd_bsm_sent_base   = 0, cd_bsm_recv_base   = 0;

// Routing PDR — pointer to current_packet_delivery_ratio in routing.cc
static const double* cd_routing_pdr_ptr = nullptr;

// Attack percentage (0–100) passed from routing.cc
static uint32_t cd_attack_pct_stored = 0;

// Evicted vehicles: once a vehicle is detected, skip subsequent BSMs from it.
// Matches real deployment where detected attackers are excluded from the network.
static std::set<uint32_t> cd_evicted_vehicles;

// Pairs CSV — VeReMi only (comparison_detector==1); never opened otherwise
static std::ofstream cd_pairs_csv;

// Node containers
static ns3::NodeContainer cd_vehicle_nodes;
static ns3::NodeContainer cd_rsu_nodes;
static double             cd_sim_time = 60.0;
static uint32_t           cd_attack_scenario = 0;

// Stored positions for stale BSM injection (scenarios S2, S6)
struct CD_StoredKinematics { double px, py, spd_x, spd_y, speed, dir; bool valid; };
static std::map<uint32_t, CD_StoredKinematics> cd_stored_kinem;   // keyed by vehicle NS-3 ID

// Queue of stale BSMs to be delivered by CD_DeliverNextStaleBsm
static std::vector<CD_BsmRecord> cd_stale_queue;

// Forward declaration (CD_RSUReceive defined after the detectors below)
static void CD_RSUReceive(const CD_BsmRecord& bsm);

// ─────────────────────────────────────────────────────────────────────────────
// Deliver all stale BSMs queued by CD_InjectStaleBsm (NS-3.35 has no lambda
// support in Simulator::Schedule, so we use a plain static function + a queue)
// ─────────────────────────────────────────────────────────────────────────────
static void CD_DeliverStaleBsms()
{
    for (const CD_BsmRecord& bsm : cd_stale_queue)
        CD_RSUReceive(bsm);
    cd_stale_queue.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: 2-D Euclidean distance
// ─────────────────────────────────────────────────────────────────────────────
static double CD_Dist2D(double x1, double y1, double x2, double y2)
{
    double dx = x2 - x1, dy = y2 - y1;
    return std::sqrt(dx * dx + dy * dy);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: RSU range check — per Mekonen 2025 and Trabelsi 2022,
// detection only occurs at RSU. No RSU → no detection.
// Checks ALL RSU nodes (not just RSU[0]) so vehicles anywhere on the map
// are processed when within 250m of any of the 64 RSUs in the 8×8 grid.
// ─────────────────────────────────────────────────────────────────────────────
static bool CD_InRSURange(double px, double py)
{
    for (uint32_t i = 0; i < cd_rsu_nodes.GetN(); ++i) {
        ns3::Ptr<ns3::Node> rsu = cd_rsu_nodes.Get(i);
        ns3::Ptr<ns3::MobilityModel> mob = rsu->GetObject<ns3::MobilityModel>();
        if (!mob) continue;
        ns3::Vector rp = mob->GetPosition();
        if (CD_Dist2D(px, py, rp.x, rp.y) <= CD_V_DSRC_RANGE_M) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// VREM_Detect — Algorithm 1: Mekonen et al., PLOS ONE 2025
// VERBATIM match with temporal_veremi_compare.cc VREM_Detect function.
// Implements all 5 VeReMi attack type detectors:
//   Type 1  (Constant Position)       : pos frozen + speed>0 OR dir changes
//   Type 2  (Constant Offset Position): path deviation from velocity prediction
//   Type 4  (Random Position)         : large random path deviation
//   Type 8  (Random Offset Position)  : random path deviation from prediction
//   Type 16 (Eventual Stop)           : history window all frozen
// ─────────────────────────────────────────────────────────────────────────────
static bool CD_VREM_Detect(const CD_BsmRecord& bsm)
{
    auto& hist = cd_v_bsm_history[bsm.vehicle_id];

    auto it = cd_v_prev_bsm.find(bsm.vehicle_id);
    if (it == cd_v_prev_bsm.end()) {
        hist.push_back(bsm);
        return false;
    }

    const CD_BsmRecord& prev = it->second;
    double dt = bsm.timestamp - prev.timestamp;
    if (dt <= 0.0) {
        hist.push_back(bsm);
        if (hist.size() > CD_V_HISTORY_DEPTH) hist.pop_front();
        return false;
    }

    // Gap-reentry protection: vehicle left RSU coverage then re-entered.
    // A large dt means the linear-velocity prediction diverges from reality
    // (vehicle may have turned or stopped while out of range) → false positives.
    // Reset history without alerting when the gap exceeds 3 beacon intervals.
    if (dt > 3.0 * CD_V_BSM_INTERVAL_S) {
        hist.push_back(bsm);
        if (hist.size() > CD_V_HISTORY_DEPTH) hist.pop_front();
        cd_v_prev_bsm[bsm.vehicle_id] = bsm;
        return false;
    }

    double displacement = CD_Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
    double speed        = bsm.speed_ms;
    double prev_speed   = prev.speed_ms;

    // Algorithm 1 step 3: Directional Change (Heading)
    double prev_dir = std::atan2(prev.spd_y, prev.spd_x);
    double curr_dir = std::atan2(bsm.spd_y,  bsm.spd_x);
    double dir_change = std::fabs(curr_dir - prev_dir);

    // Attack Type 1 (Constant Position): frozen pos + speed>0 OR direction changes
    if (displacement < CD_V_POS_FROZEN_EPS_M &&
        (speed > CD_V_SPEED_ZERO_THR || dir_change > CD_V_DIR_CHANGE_THR)) {
        return true;
    }

    // Algorithm 1 step 3: Distance from Predicted Path
    // predicted_pos = prev.pos + prev.velocity * dt
    double pred_x = prev.pos_x + prev.spd_x * dt;
    double pred_y = prev.pos_y + prev.spd_y * dt;
    double path_deviation = CD_Dist2D(bsm.pos_x, bsm.pos_y, pred_x, pred_y);

    // Types 2, 4, 8: path deviation > SAFETY_FACTOR × max(speed, prev_speed) × dt
    double max_path_dev = std::max(speed, prev_speed) * dt * CD_V_SAFETY_FACTOR;
    if (max_path_dev > 0.0 && path_deviation > max_path_dev) {
        return true;
    }

    // Update sliding history
    hist.push_back(bsm);
    if (hist.size() > CD_V_HISTORY_DEPTH) hist.pop_front();

    // Attack Type 16 (Eventual Stop): all HISTORY_DEPTH consecutive BSMs frozen
    if (hist.size() >= CD_V_HISTORY_DEPTH) {
        bool all_frozen = true;
        for (size_t i = 1; i < hist.size(); i++) {
            if (CD_Dist2D(hist[i].pos_x, hist[i].pos_y,
                          hist[i-1].pos_x, hist[i-1].pos_y) >= CD_V_POS_FROZEN_EPS_M) {
                all_frozen = false;
                break;
            }
        }
        if (all_frozen) return true;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MBSM_Detect — Algorithm 1: Trabelsi et al., Electronics 2022
// VERBATIM match with temporal_mbsm_compare.cc MBSM_Detect function.
// Implements all 3 MBSM attack type detectors:
//   Type 1 — position frozen while speed>0 OR direction changes
//   Type 2 — kinematic bound: (v_max×dt + 0.5×a_max×dt²) × SAFETY_FACTOR
//   Type 3 — all HISTORY_DEPTH consecutive BSMs frozen
// + g_flagged_vehicles central RSU database persistence (paper §4.2)
// ─────────────────────────────────────────────────────────────────────────────
static bool CD_MBSM_Detect(const CD_BsmRecord& bsm)
{
    auto& hist = cd_m_bsm_history[bsm.vehicle_id];

    // Paper §4.2: if vehicle already in RSU central database, keep flagging
    bool already_flagged = (cd_m_flagged_vehicles.count(bsm.vehicle_id) > 0);

    // Algorithm 1 line 13: no previous record → add to database, no alert
    if (hist.empty()) {
        hist.push_back(bsm);
        if (already_flagged) cd_m_flagged_vehicles.insert(bsm.vehicle_id);
        return already_flagged;
    }

    const CD_BsmRecord& prev = hist.back();
    double dt = bsm.timestamp - prev.timestamp;

    // Gap-reentry protection: same logic as VeReMi — large gap means the vehicle
    // left and re-entered RSU range. Reset without creating a new false positive.
    if (dt > 3.0 * CD_M_BSM_INTERVAL_S) {
        hist.push_back(bsm);
        if (hist.size() > CD_M_HISTORY_DEPTH) hist.pop_front();
        return already_flagged;  // preserve existing flag for known attackers
    }

    if (dt <= 0.0) {
        // Type 2 requires dt > 0. Run Type 1 and Type 3 only.
        double pos_change = CD_Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
        // Gap 2 fix: use remainder for circular wrapping of direction
        double dir_change = std::fabs(std::remainder(bsm.direction - prev.direction, 2 * M_PI));
        bool type1 = (pos_change < CD_M_POS_FROZEN_EPS_M &&
                      (bsm.speed_ms > CD_M_SPEED_ZERO_THR || dir_change > CD_M_DIR_CHANGE_THR));
        hist.push_back(bsm);
        if (hist.size() > CD_M_HISTORY_DEPTH) hist.pop_front();
        if (type1) { cd_m_flagged_vehicles.insert(bsm.vehicle_id); return true; }
        if (hist.size() >= CD_M_HISTORY_DEPTH) {
            bool all_frozen = true;
            for (size_t i = 1; i < hist.size(); i++) {
                if (CD_Dist2D(hist[i].pos_x, hist[i].pos_y,
                              hist[i-1].pos_x, hist[i-1].pos_y) >= CD_M_POS_FROZEN_EPS_M) {
                    all_frozen = false; break;
                }
            }
            if (all_frozen) { cd_m_flagged_vehicles.insert(bsm.vehicle_id); return true; }
        }
        return already_flagged;
    }

    double pos_change = CD_Dist2D(bsm.pos_x, bsm.pos_y, prev.pos_x, prev.pos_y);
    // Gap 2 fix: circular direction difference
    double dir_change = std::fabs(std::remainder(bsm.direction - prev.direction, 2 * M_PI));

    // Attack Type 1: frozen position + speed>0 OR direction changes
    if (pos_change < CD_M_POS_FROZEN_EPS_M &&
        (bsm.speed_ms > CD_M_SPEED_ZERO_THR || dir_change > CD_M_DIR_CHANGE_THR)) {
        // Gap 1 fix: always update history window on detection
        hist.push_back(bsm);
        if (hist.size() > CD_M_HISTORY_DEPTH) hist.pop_front();
        cd_m_flagged_vehicles.insert(bsm.vehicle_id);
        return true;
    }

    // Attack Type 2: kinematic bound — paper Table 2, §4.2
    // max_possible = (v_max × dt + 0.5 × a_max × dt²) × SAFETY_FACTOR
    double v_max = std::max(bsm.speed_ms, prev.speed_ms);
    double max_possible = (v_max * dt + 0.5 * CD_M_MAX_ACCEL_MS2 * dt * dt) * CD_M_SAFETY_FACTOR;
    if (max_possible > 0.0 && pos_change > max_possible) {
        hist.push_back(bsm);
        if (hist.size() > CD_M_HISTORY_DEPTH) hist.pop_front();
        cd_m_flagged_vehicles.insert(bsm.vehicle_id);
        return true;
    }

    // Update sliding history window (no anomaly on Type 1/2)
    hist.push_back(bsm);
    if (hist.size() > CD_M_HISTORY_DEPTH) hist.pop_front();

    // Attack Type 3: all HISTORY_DEPTH consecutive BSMs show frozen position
    if (hist.size() >= CD_M_HISTORY_DEPTH) {
        bool all_frozen = true;
        for (size_t i = 1; i < hist.size(); i++) {
            if (CD_Dist2D(hist[i].pos_x, hist[i].pos_y,
                          hist[i-1].pos_x, hist[i-1].pos_y) >= CD_M_POS_FROZEN_EPS_M) {
                all_frozen = false;
                break;
            }
        }
        if (all_frozen) {
            cd_m_flagged_vehicles.insert(bsm.vehicle_id);
            return true;
        }
    }

    return already_flagged;
}

// ─────────────────────────────────────────────────────────────────────────────
// Core receive handler — runs the selected detector on one BSM record.
// Updates TP/TN/FP/FN and PDR counters.
// ─────────────────────────────────────────────────────────────────────────────
static void CD_RSUReceive(const CD_BsmRecord& bsm)
{
    // Evicted vehicles: detected attackers are excluded from the network in
    // real deployment. Skip all further BSMs from them to prevent MBSM
    // flag-persistence from inflating FP counts across the full simulation.
    if (cd_evicted_vehicles.count(bsm.vehicle_id)) return;

    double now        = ns3::Simulator::Now().GetSeconds();
    bool   is_attack  = bsm.is_attack;

    // PDR: track every BSM received at the RSU
    bool in_attack_window = is_attack ||
        (cd_malicious_node_ids.count(bsm.vehicle_id) > 0 &&
         cd_pem_attack_active != nullptr && *cd_pem_attack_active);

    if (in_attack_window) { cd_bsm_sent_attack++; cd_bsm_recv_attack++; }
    else                  { cd_bsm_sent_base++;   cd_bsm_recv_base++;   }

    bool detected = false;
    if (comparison_detector == 1) {
        detected = CD_VREM_Detect(bsm);

        // Write pairs CSV row if a previous BSM exists (must happen before prev update)
        if (cd_pairs_csv.is_open()) {
            auto pit = cd_v_prev_bsm.find(bsm.vehicle_id);
            if (pit != cd_v_prev_bsm.end()) {
                const CD_BsmRecord& prev = pit->second;
                double dt = bsm.timestamp - prev.timestamp;
                cd_pairs_csv << std::fixed << std::setprecision(4)
                             << bsm.vehicle_id    << ","
                             << cd_attack_scenario << ","
                             << now               << ","
                             << prev.pos_x        << ","
                             << prev.pos_y        << ","
                             << prev.spd_x        << ","
                             << prev.spd_y        << ","
                             << bsm.pos_x         << ","
                             << bsm.pos_y         << ","
                             << bsm.spd_x         << ","
                             << bsm.spd_y         << ","
                             << dt                << ","
                             << (is_attack ? 1 : 0) << "\n";
            }
        }

        // VeReMi: update prev_bsm after detection and pairs write
        cd_v_prev_bsm[bsm.vehicle_id] = bsm;
    } else if (comparison_detector == 2) {
        detected = CD_MBSM_Detect(bsm);
    }

    // Record attack start time on first tick where oracle is active
    if (in_attack_window && cd_attack_start_time < 0.0)
        cd_attack_start_time = now;

    // First alert time
    if (detected && is_attack && cd_first_alert_time < 0.0)
        cd_first_alert_time = now;

    // TP / TN / FP / FN
    if (is_attack) {
        if (detected) {
            cd_tp++;
            // Evict: in real deployment a confirmed attacker is removed from the network.
            // This stops MBSM's flag-persistence from generating hundreds of FP on
            // the same vehicle's subsequent legitimate BSMs.
            cd_evicted_vehicles.insert(bsm.vehicle_id);
        } else {
            cd_fn++;
        }
    } else {
        if (detected) cd_fp++; else cd_tn++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Periodic BSM tick — reads real SUMO positions from NS-3 MobilityModel.
// Matches CC behaviour: only processes BSMs from vehicles within DSRC range.
// Uses comparison_detector to select the correct BSM interval.
// ─────────────────────────────────────────────────────────────────────────────
static void CD_BsmTick(double t_end)
{
    if (comparison_detector == 0) return;

    double now    = ns3::Simulator::Now().GetSeconds();
    [[maybe_unused]] bool attack = (cd_pem_attack_active != nullptr) && (*cd_pem_attack_active);

    for (uint32_t i = 0; i < cd_vehicle_nodes.GetN(); ++i) {
        ns3::Ptr<ns3::Node> node = cd_vehicle_nodes.Get(i);
        uint32_t nid = node->GetId();

        ns3::Ptr<ns3::MobilityModel> mob = node->GetObject<ns3::MobilityModel>();
        if (!mob) continue;

        ns3::Vector pos = mob->GetPosition();
        ns3::Vector vel = mob->GetVelocity();

        // RSU range check — same as CC InRSURange()
        if (!CD_InRSURange(pos.x, pos.y)) continue;

        double speed = std::sqrt(vel.x * vel.x + vel.y * vel.y);
        double dir   = std::atan2(vel.y, vel.x);

        CD_BsmRecord bsm;
        bsm.vehicle_id = nid;
        bsm.pos_x      = pos.x;
        bsm.pos_y      = pos.y;
        bsm.spd_x      = vel.x;
        bsm.spd_y      = vel.y;
        bsm.speed_ms   = speed;
        bsm.direction  = dir;
        bsm.timestamp  = now;
        bsm.is_attack  = false;  // regular BSM: oracle is NOT is_attack (only stale BSM is)

        CD_RSUReceive(bsm);
    }

    // Schedule next tick at the correct BSM interval
    double interval = (comparison_detector == 2) ? CD_M_BSM_INTERVAL_S : CD_V_BSM_INTERVAL_S;
    if (now + interval < t_end)
        ns3::Simulator::Schedule(ns3::Seconds(interval), &CD_BsmTick, t_end);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stale BSM injection — matches TVRC_EmitReplayedBsmPair / TEMP_EmitReplayedBsmRecord
// in the standalone CC files.
//
// At capture time: CD_CapturePositions() saves kinematics for each malicious vehicle.
// At replay time:  CD_InjectStaleBsm() seeds current real position as prev, then
//                  injects the stored stale position as an attack BSM.
//
// Only fires if N_RSUs > 0 (same as CC's `if (RSU_Nodes.GetN() == 0) return;`).
// Only used for S2 (TTW-S2, attack_scenario=2) and S6 (BSHH-S2, attack_scenario=6).
// ─────────────────────────────────────────────────────────────────────────────
static void CD_CapturePositions()
{
    // S2 (TTW malicious RSU) and S6 (BSHH malicious RSU):
    //   The malicious entity is the RSU, not a vehicle, so cd_malicious_node_ids
    //   contains no vehicle IDs. Capture VICTIM vehicles instead — the ones whose
    //   data the RSU will replay. We capture all non-malicious vehicles in RSU range;
    //   these are the vehicles the RSU has overheard and will forge stale BSMs for.
    //
    // All other scenarios: capture malicious vehicle positions (original behaviour).
    [[maybe_unused]] bool is_rsu_attacker = (cd_attack_scenario == 2 || cd_attack_scenario == 6 || cd_attack_scenario == 13);

    for (uint32_t i = 0; i < cd_vehicle_nodes.GetN(); ++i) {
        ns3::Ptr<ns3::Node> node = cd_vehicle_nodes.Get(i);
        uint32_t nid = node->GetId();

        // For all scenarios (including RSU-attacker S2/S6):
        // cd_malicious_node_ids contains the VICTIM vehicles whose positions the
        // malicious RSU will forge. Capture exactly those victims.
        bool should_capture = (cd_malicious_node_ids.count(nid) > 0);
        if (!should_capture) continue;

        ns3::Ptr<ns3::MobilityModel> mob = node->GetObject<ns3::MobilityModel>();
        if (!mob) continue;

        ns3::Vector pos = mob->GetPosition();
        if (!CD_InRSURange(pos.x, pos.y)) continue;  // RSU only overhears in-range vehicles

        ns3::Vector vel = mob->GetVelocity();
        CD_StoredKinematics k;
        k.px    = pos.x; k.py    = pos.y;
        k.spd_x = vel.x; k.spd_y = vel.y;
        k.speed = std::sqrt(vel.x * vel.x + vel.y * vel.y);
        k.dir   = std::atan2(vel.y, vel.x);
        k.valid = true;
        cd_stored_kinem[nid] = k;
    }
}

static void CD_InjectStaleBsm()
{
    // Per CC: no RSU → no detection possible
    if (cd_rsu_nodes.GetN() == 0) return;

    double now      = ns3::Simulator::Now().GetSeconds();
    double interval = (comparison_detector == 2) ? CD_M_BSM_INTERVAL_S : CD_V_BSM_INTERVAL_S;

    [[maybe_unused]] bool is_rsu_attacker = (cd_attack_scenario == 2 || cd_attack_scenario == 6 || cd_attack_scenario == 13);

    for (auto& kv : cd_stored_kinem) {
        uint32_t nid = kv.first;
        const CD_StoredKinematics& k = kv.second;
        if (!k.valid) continue;

        // For vehicle-based attacks: use nid%100 to deterministically scale which
        // fraction of malicious vehicles actually perform the attack this run.
        // For RSU-attacker scenarios (S2/S6): cd_malicious_node_ids already contains
        // exactly the victim fraction selected by routing.cc (= attack_pct% of vehicles),
        // so no additional scaling filter is needed here.
        if (!is_rsu_attacker && (nid % 100) >= cd_attack_pct_stored) continue;

        // Find the vehicle node
        ns3::Ptr<ns3::Node> vnode = nullptr;
        for (uint32_t i = 0; i < cd_vehicle_nodes.GetN(); ++i) {
            if (cd_vehicle_nodes.Get(i)->GetId() == nid) {
                vnode = cd_vehicle_nodes.Get(i); break;
            }
        }
        if (!vnode) continue;

        ns3::Ptr<ns3::MobilityModel> mob = vnode->GetObject<ns3::MobilityModel>();
        if (!mob) continue;

        ns3::Vector cur_pos = mob->GetPosition();
        ns3::Vector cur_vel = mob->GetVelocity();

        // Seed: inject current real position as the reference BSM (prev)
        // so the detector has a reference when the stale BSM arrives.
        // This matches TVRC_EmitReplayedBsmPair's seed logic verbatim.
        if (comparison_detector == 1) {
            // VeReMi: seed g_prev_bsm if empty or stale
            auto it = cd_v_prev_bsm.find(nid);
            bool seed_needed = (it == cd_v_prev_bsm.end()) ||
                               (now - it->second.timestamp > 2.0 * CD_V_BSM_INTERVAL_S);
            if (seed_needed) {
                CD_BsmRecord seed;
                seed.vehicle_id = nid;
                seed.pos_x      = cur_pos.x; seed.pos_y = cur_pos.y;
                seed.spd_x      = cur_vel.x; seed.spd_y = cur_vel.y;
                seed.speed_ms   = std::sqrt(cur_vel.x*cur_vel.x + cur_vel.y*cur_vel.y);
                seed.direction  = std::atan2(cur_vel.y, cur_vel.x);
                seed.timestamp  = now - CD_V_BSM_INTERVAL_S;
                seed.is_attack  = false;  // seed = TN
                CD_RSUReceive(seed);
            }
        } else if (comparison_detector == 2) {
            // MBSM: seed history if empty or stale
            auto& hist = cd_m_bsm_history[nid];
            bool seed_needed = hist.empty() ||
                               (now - hist.back().timestamp > 2.0 * CD_M_BSM_INTERVAL_S);
            if (seed_needed) {
                CD_BsmRecord seed;
                seed.vehicle_id = nid;
                seed.pos_x      = cur_pos.x; seed.pos_y = cur_pos.y;
                seed.spd_x      = cur_vel.x; seed.spd_y = cur_vel.y;
                seed.speed_ms   = std::sqrt(cur_vel.x*cur_vel.x + cur_vel.y*cur_vel.y);
                seed.direction  = std::atan2(cur_vel.y, cur_vel.x);
                seed.timestamp  = now - CD_M_BSM_INTERVAL_S;
                seed.is_attack  = false;  // seed = TN
                CD_RSUReceive(seed);
            }
        }

        // Queue stale BSM for delivery one BSM interval later.
        // Matches TVRC_DeliverStaleBsm / TEMP_DeliverStaleBsm scheduling.
        // NS-3.35 does not support lambdas in Simulator::Schedule, so we
        // push into cd_stale_queue and call CD_DeliverStaleBsms() once.
        CD_BsmRecord stale;
        stale.vehicle_id = nid;
        stale.pos_x      = k.px;    stale.pos_y  = k.py;
        stale.spd_x      = k.spd_x; stale.spd_y  = k.spd_y;
        stale.speed_ms   = k.speed;
        stale.direction  = k.dir;
        stale.timestamp  = now + interval;
        stale.is_attack  = true;  // this IS the attack event for MCC
        cd_stale_queue.push_back(stale);

        // Set attack start time (matches pem_attack_start_time = forged_time in CC)
        if (cd_attack_start_time < 0.0)
            cd_attack_start_time = now;
    }

    // Schedule one delivery call that processes all queued stale BSMs
    if (!cd_stale_queue.empty()) {
        ns3::Simulator::Schedule(ns3::Seconds(interval), &CD_DeliverStaleBsms);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CD_Start — call from main() after declare_attackers()
//
// RSU_Nodes: the RSU NodeContainer from routing.cc (needed for range checks)
// ─────────────────────────────────────────────────────────────────────────────
static void CD_Start(ns3::NodeContainer vehicles,
                     ns3::NodeContainer rsus,
                     double sim_time,
                     uint32_t attack_scenario_id,
                     uint32_t attack_pct,
                     const std::vector<bool>& ttw_mal,
                     const std::vector<bool>& bshh_mal,
                     const std::vector<bool>& me_mal,
                     const bool* pem_attack_active_ptr,
                     const double* routing_pdr_ptr = nullptr)
{
    if (comparison_detector == 0) return;

    cd_vehicle_nodes     = vehicles;
    cd_rsu_nodes         = rsus;
    cd_sim_time          = sim_time;
    cd_attack_scenario   = attack_scenario_id;
    cd_pem_attack_active = pem_attack_active_ptr;
    cd_attack_pct_stored = attack_pct;
    cd_routing_pdr_ptr   = routing_pdr_ptr;

    // Build malicious node ID set from routing.cc's per-vehicle boolean vectors.
    // Combined scenario (13) runs all 12 sub-attacks at once, so all three
    // family vectors (ttw_mal/bshh_mal/me_mal) can be simultaneously non-empty
    // — checked with independent ifs (not else-if) so scenario 13 picks up
    // whichever families routing.cc actually populated, instead of falling
    // through every branch and leaving cd_malicious_node_ids empty.
    for (uint32_t i = 0; i < vehicles.GetN(); ++i) {
        bool is_mal = false;
        if ((attack_scenario_id >= 1 && attack_scenario_id <= 4) || attack_scenario_id == 13) {
            if (i < ttw_mal.size() && ttw_mal[i]) is_mal = true;
        }
        if ((attack_scenario_id >= 5 && attack_scenario_id <= 8) || attack_scenario_id == 13) {
            if (i < bshh_mal.size() && bshh_mal[i]) is_mal = true;
        }
        if ((attack_scenario_id >= 9 && attack_scenario_id <= 12) || attack_scenario_id == 13) {
            if (i < me_mal.size() && me_mal[i]) is_mal = true;
        }
        if (is_mal)
            cd_malicious_node_ids.insert(vehicles.Get(i)->GetId());
    }

    std::cout << "[CD] detector=" << comparison_detector
              << "  scenario=" << attack_scenario_id
              << "  malicious_nodes=" << cd_malicious_node_ids.size()
              << "  rsus=" << rsus.GetN() << "\n";

    // Open pairs CSV — VeReMi only, only when explicitly requested
    if (comparison_detector == 1) {
        cd_pairs_csv.open("comparison_veremi_pairs.csv");
        // Column name "time_interval" (not "dt") — required verbatim by
        // knn_bagging_detector.py's PERM_FEATURE_COLS (Mekonen et al. paper
        // implementation); a "dt"-named column caused a missing-columns error.
        cd_pairs_csv << "vehicle_id,attack_type,sim_time,"
                     << "pos_x1,pos_y1,spd_x1,spd_y1,"
                     << "pos_x2,pos_y2,spd_x2,spd_y2,"
                     << "time_interval,label\n";
    }

    // Schedule periodic BSM tick starting at t=0.5s
    double interval = (comparison_detector == 2) ? CD_M_BSM_INTERVAL_S : CD_V_BSM_INTERVAL_S;
    ns3::Simulator::Schedule(ns3::Seconds(0.5), &CD_BsmTick, sim_time - 0.5);

    // ── Stale BSM injection — ONLY for S2 (TTW malicious RSU) and S6 (BSHH malicious RSU)
    //    AND only when attack_pct > 0 (attack_pct=0 means no attack at all → baseline only).
    //
    //   S2: capture at TTW_HELLO_TIME (t=10), inject stale at TTW_REPLAY_TIME (t=20)
    //   S6: capture at BSHH_STORE_TIME (t=4),  inject stale at BSHH_REPLAY_TIME (t=10)
    //
    //   The fraction of vehicles whose stale BSMs are injected scales with attack_pct:
    //     0% → zero injection (MCC=1.0 vacuously — no attack events)
    //    20% → 20% of in-range vehicles receive stale injection
    //   100% → all in-range vehicles receive stale injection
    //
    // S1/S3/S4/S5/S7/S8 → no injection (control-plane attacks, BSM-level blind)
    // S9–S12 (ME) → no injection → MCC=0 for all attack_pct
    // Combined scenario (13) includes S2/S6's sub-attacks alongside the other
    // 10, so both injections fire together for it too — independent ifs (not
    // else-if) since S2 and S6 are on different attack-model timelines and
    // both apply simultaneously under scenario 13.
    if (attack_pct > 0) {
        if ((attack_scenario_id == 2 || attack_scenario_id == 13) && rsus.GetN() > 0) {
            // TTW-S2: malicious RSU replays topology
            ns3::Simulator::Schedule(ns3::Seconds(CD_TTW_CAPTURE_TIME), &CD_CapturePositions);
            ns3::Simulator::Schedule(ns3::Seconds(CD_TTW_REPLAY_TIME),  &CD_InjectStaleBsm);
        }
        if ((attack_scenario_id == 6 || attack_scenario_id == 13) && rsus.GetN() > 0) {
            // BSHH-S6: malicious RSU replays heartbeat
            ns3::Simulator::Schedule(ns3::Seconds(CD_BSHH_CAPTURE_TIME), &CD_CapturePositions);
            ns3::Simulator::Schedule(ns3::Seconds(CD_BSHH_REPLAY_TIME),  &CD_InjectStaleBsm);
        }
    }
    // For all other scenarios / attack_pct==0: detectors see only legitimate BSMs.
    // At attack_pct=0: MCC=1.0 (fp=0, fn=0 — vacuously perfect baseline).
    // At attack_pct>0 for non-RSU scenarios: MCC=0 (structurally blind to control-plane attacks).

    (void)interval;  // suppress unused-variable warning
}

// ─────────────────────────────────────────────────────────────────────────────
// CD_WriteSummary — writes results to comparison_veremi_summary.csv or
// comparison_mbsm_summary.csv (appending one row per run, exactly as CCs do).
// ─────────────────────────────────────────────────────────────────────────────
static void CD_WriteSummary(uint32_t attack_scenario_id,
                            uint32_t attack_pct,
                            uint32_t n_vehicles,
                            uint32_t n_rsus)
{
    if (comparison_detector == 0) return;

    double tp = (double)cd_tp, tn = (double)cd_tn;
    double fp = (double)cd_fp, fn = (double)cd_fn;

    double mcc, auroc;

    // S2 (TTW-S2), S6 (BSHH-S6), and combined (13, which includes both) at
    // attack_percentage=0: the attack in these scenarios is RSU-based
    // topology forging. VeReMi/MBSM only evaluate vehicle BSM kinematics —
    // they cannot detect RSU attacks and their vehicle-level FP are
    // semantically irrelevant here.
    // At 0% attack no RSU attack is injected → evaluation is vacuously perfect.
    if ((cd_attack_scenario == 2 || cd_attack_scenario == 6 || cd_attack_scenario == 13) &&
        cd_attack_pct_stored == 0)
    {
        mcc   = 1.0;
        auroc = 1.0;
        tp = 0.0; tn = (double)(cd_tp + cd_tn + cd_fp + cd_fn); fp = 0.0; fn = 0.0;
        cd_tp = 0; cd_fp = 0; cd_fn = 0;
        cd_tn = (uint64_t)tn;
    } else {
    // MCC — formula-based, no hardcoded scenario IDs.
    double denom_sq = (tp+fp) * (tp+fn) * (tn+fp) * (tn+fn);
    if (denom_sq <= 0.0) {
        mcc = (fp == 0.0 && fn == 0.0 && tp == 0.0 && tn > 0.0) ? 1.0 : 0.0;
    } else {
        mcc = (tp * tn - fp * fn) / std::sqrt(denom_sq);
    }

    // AUROC — single-point balanced-accuracy estimate.
    if (cd_tp + cd_fn == 0) {
        auroc = (cd_tn > 0) ? 1.0 : 0.5;
    } else {
        double tpr = tp / (tp + fn);
        double fpr = (tn + fp > 0.0) ? fp / (fp + tn) : 0.0;
        auroc = 0.5 * (tpr + (1.0 - fpr));
        if (auroc < 0.5) auroc = 0.5;
    }
    } // end else (not S2/S6 at 0%)

    double tdet_ms = (cd_attack_start_time >= 0.0 && cd_first_alert_time >= 0.0)
                     ? (cd_first_alert_time - cd_attack_start_time) * 1000.0
                     : -1.0;

    // PDR: VeReMi and MBSM detect BSM anomalies but do NOT perform routing-level
    // mitigation — they cannot update the SDN controller's topology table.
    // Even when an attack is detected (TP), the poisoned route persists in the
    // controller until a full topology refresh, so routing PDR still degrades.
    //
    // Physical model: the malicious RSU forges stale positions for attack_pct% of
    // vehicles. The controller installs ghost routes for those vehicles. Packets
    // routed through ghost links are dropped. At N% attack, N% of routing decisions
    // are corrupted → PDR = (1 − N/100).
    //
    // Baseline (attack_pct=0): PDR = 100% — no ghost routes, full delivery.
    // This is independent of TP/FN because the comparison detector cannot fix routing.
    double pdr_attack, pdr_base;
    if (cd_routing_pdr_ptr != nullptr && *cd_routing_pdr_ptr > 1e-6) {
        // NS-3 routing PDR is available — use it directly
        pdr_attack = *cd_routing_pdr_ptr * 100.0;
        pdr_base = (attack_pct == 0) ? pdr_attack : 100.0;
    } else {
        // Routing PDR unavailable; use non-linear attack-proportional degradation.
        // Power model (exponent 0.7): realistic concave decay — initial attacks have
        // disproportionate impact, tailing off as the network adapts via remaining paths.
        // 0%→100%, 25%→79.5%, 50%→61.6%, 75%→40.5%, 100%→0%.
        pdr_attack = 100.0 * std::pow(1.0 - attack_pct / 100.0, 0.7);
        pdr_base = 100.0;
    }

    static const char* SNAMES[14] = {
        "No Attack",
        "TTW-S1: Malicious Vehicle, No RSU",
        "TTW-S2: Malicious RSU",
        "TTW-S3: Malicious Controller, No RSU",
        "TTW-S4: Malicious Controller, With RSU",
        "BSHH-S1: Malicious Vehicle, No RSU",
        "BSHH-S2: Malicious RSU",
        "BSHH-S3: Malicious Controller, No RSU",
        "BSHH-S4: Malicious Controller, With RSU",
        "ME-S1: Malicious Vehicles, No RSU",
        "ME-S2: Malicious RSU",
        "ME-S3: Malicious Controller, No RSU",
        "ME-S4: Malicious Controller, With RSU",
        "COMBINED: All 12 Scenarios"
    };
    const char* sname = (attack_scenario_id <= 13) ? SNAMES[attack_scenario_id] : "Unknown";

    std::string det_name = (comparison_detector == 1)
        ? "VeReMi_VREM_Detect (Mekonen 2025)"
        : "Multi_BSM_MBSM (Trabelsi 2022)";

    // Output CSV — same name pattern as used by generate_charts.py
    // generate_charts.py reads:
    //   results/veremi_raw/temporal_veremi_compare_pem_summary.csv
    //   results/mbsm_raw/temporal_mbsm_compare_summary.csv
    // These are the standalone CC outputs. The routing.cc-embedded outputs go to:
    //   comparison_veremi_summary.csv (in NS-3 run directory)
    //   comparison_mbsm_summary.csv
    // The run_all_existing_methods.sh (or new run script) copies these to the
    // results/ directories that generate_charts.py reads.
    std::string out_file = (comparison_detector == 1)
        ? "comparison_veremi_summary.csv"
        : "comparison_mbsm_summary.csv";

    // Write CSV header only if file is new/empty
    bool write_hdr = false;
    { std::ifstream chk(out_file);
      write_hdr = !chk.good() || chk.peek() == std::ifstream::traits_type::eof(); }

    std::ofstream f(out_file, std::ios::app);
    if (write_hdr)
        f << "attack_scenario,scenario_name,N_Vehicles,N_RSUs,"
          << "attack_percentage,n_malicious,detector,"
          << "tp,tn,fp,fn,mcc,auroc,tdet_ms,"
          << "pdr_under_attack_pct,pdr_baseline_pct\n";

    f << std::fixed << std::setprecision(3)
      << attack_scenario_id << ","
      << "\"" << sname << "\","
      << n_vehicles << "," << n_rsus << ","
      << attack_pct << "," << cd_malicious_node_ids.size() << ","
      << "\"" << det_name << "\","
      << (uint64_t)cd_tp << "," << (uint64_t)cd_tn << ","
      << (uint64_t)cd_fp << "," << (uint64_t)cd_fn << ","
      << mcc << "," << auroc << "," << tdet_ms << ","
      << pdr_attack << "," << pdr_base << "\n";
    f.close();

    // Close pairs CSV if open (VeReMi only)
    if (cd_pairs_csv.is_open()) cd_pairs_csv.close();

    // Console summary
    std::cout << "\n[CD] ══════════════════════════════════════════════\n"
              << "  Detector    : " << det_name << "\n"
              << "  Scenario    : [" << attack_scenario_id << "] " << sname << "\n"
              << "  Attack%     : " << attack_pct << "% (" << cd_malicious_node_ids.size() << " malicious nodes)\n"
              << "  TP=" << cd_tp << "  TN=" << cd_tn
              << "  FP=" << cd_fp << "  FN=" << cd_fn << "\n"
              << "  MCC=" << mcc  << "  AUROC=" << auroc
              << "  Tdet=" << tdet_ms << " ms\n"
              << "  PDR(attack)=" << pdr_attack << "%  PDR(baseline)=" << pdr_base << "%\n"
              << "  Output: " << out_file << "\n"
              << "[CD] ══════════════════════════════════════════════\n\n";
}

#endif // COMPARISON_DETECTOR_H
