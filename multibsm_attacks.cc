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
    bool     is_falsified; // ground-truth label for PEM
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

// ── Output streams ────────────────────────────────────────────
static std::ofstream g_attack_log;
static std::ofstream g_events_csv;

// ── Random engine (fixed seed for reproducibility; pass --RngRun for variation)
static std::mt19937 g_rng(12345);

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

    BsmRecord bsm;
    bsm.vehicle_id  = node->GetId();
    bsm.pos_x       = px;
    bsm.pos_y       = py;
    bsm.speed_ms    = spd;
    bsm.direction   = dir;
    bsm.timestamp   = Simulator::Now().GetSeconds();
    bsm.is_falsified = false;

    if (InRSURange(px, py)) {
        MBSM_RSUReceive(bsm);
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

    BsmRecord bsm;
    bsm.vehicle_id  = node->GetId();
    bsm.pos_x       = T1_FIXED_X;   // frozen — never changes
    bsm.pos_y       = T1_FIXED_Y;
    bsm.speed_ms    = real_spd;      // realistic
    bsm.direction   = real_dir;      // realistic — may change
    bsm.timestamp   = now;
    bsm.is_falsified = true;

    // RSU receives from the attacker's actual position (physical radio range)
    if (InRSURange(real_px, real_py)) {
        MBSM_RSUReceive(bsm);
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

    BsmRecord bsm;
    bsm.vehicle_id  = node->GetId();
    bsm.pos_x       = rand_coord(g_rng);
    bsm.pos_y       = rand_coord(g_rng);
    bsm.speed_ms    = real_spd;
    bsm.direction   = real_dir;
    bsm.timestamp   = now;
    bsm.is_falsified = true;

    if (InRSURange(real_px, real_py)) {
        MBSM_RSUReceive(bsm);
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

    BsmRecord bsm;
    bsm.vehicle_id  = node->GetId();
    bsm.speed_ms    = real_spd;
    bsm.direction   = real_dir;
    bsm.timestamp   = now;

    if (now < T3_legit_duration) {
        // Phase 1 — legitimate behaviour
        bsm.pos_x       = real_px;
        bsm.pos_y       = real_py;
        bsm.is_falsified = false;
        // Cache the current position so Phase 2 knows where to freeze
        g_t3_freeze_x = real_px;
        g_t3_freeze_y = real_py;
    } else {
        // Phase 2 — freeze
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
        bsm.pos_x       = g_t3_freeze_x;
        bsm.pos_y       = g_t3_freeze_y;
        bsm.is_falsified = true;
    }

    if (InRSURange(real_px, real_py)) {
        MBSM_RSUReceive(bsm);
    }
}

// ─────────────────────────────────────────────────────────────
// One BSM tick for a single vehicle — dispatches to the correct
// sender based on attack_scenario and veh_idx
// ─────────────────────────────────────────────────────────────
static void MBSM_BsmTick(uint32_t veh_idx, double t_end)
{
    bool is_attacker = (veh_idx == attacker_idx) && (attack_scenario != 0);

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
        << "  Attacker node   : V" << attacker_idx   << "\n"
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
    cmd.AddValue("attacker_idx",     "0-based index of the malicious vehicle",      attacker_idx);
    cmd.AddValue("T3_legit_duration","Type 3: legitimate phase length (s)",         T3_legit_duration);
    cmd.Parse(argc, argv);

    if (N_Vehicles < 1)             N_Vehicles  = 1;
    if (attacker_idx >= N_Vehicles) attacker_idx = 0;
    if (N_RSUs > 1)                 N_RSUs       = 1;  // one RSU modelled

    MBSM_InitLogs();

    std::cout << "\n======== Multi-BSM Attack Simulation ========\n"
              << "  attack_scenario  : " << attack_scenario  << "\n"
              << "  N_Vehicles       : " << N_Vehicles       << "\n"
              << "  N_RSUs           : " << N_RSUs           << "\n"
              << "  simTime          : " << simTime          << " s\n"
              << "  attacker_idx     : " << attacker_idx     << "\n";
    if (attack_scenario == 15) {
        std::cout << "  T3_legit_duration: " << T3_legit_duration << " s\n";
    }
    std::cout << "=============================================\n\n";

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

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    if (g_attack_log.is_open())  g_attack_log.close();
    if (g_events_csv.is_open())  g_events_csv.close();

    return 0;
}
