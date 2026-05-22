/*
 * attack_link_latency.cc — Link Latency Attack (LLA) Simulation
 *
 * Based on: Soltani et al., "Security Analysis of SDN Topology Discovery
 * Mechanism and Defense Proposal", CNSM 2021.
 *
 * Standalone NS-3.35 file — place in ns-3.35/scratch/ and build with:
 *   ./waf --run "scratch/attack_link_latency --simTime=60 --attack_scenario=16"
 *
 * Attack Scenarios:
 *   0  = Baseline (no attack, legitimate LLDP discovery only)
 *  16  = Full LLA: Overload Phase + Relay Phase → TopoGuard+ FAILS, MLLG detects
 *  17  = Relay only (no overload) → TopoGuard+ SUCCEEDS (shows overload is necessary)
 *
 * Topology: s1 — s2 — s3  (RSU switches, wired)
 *           h1..h6 attached to s1..s3 (2 hosts per switch)
 *           h1 (at s1) and h2 (at s3) are the compromised nodes
 *           Controller connected to all switches via separate control plane
 *
 * TopoGuard+ Link Latency Inspector (LLI):
 *   Tl = TLLDP − Tp1 − Tp2          (Eq. 1)
 *   Th = Q3 + 3*(Q3 − Q1)           (Eq. 2, upper fence from probe RTT history)
 *   ALARM if Tl > Th
 *   VULNERABILITY: negative Tl silently passes (Tl < 0 ≤ Th, no alarm)
 *
 * MLLG defense (simplified):
 *   Flag if Tl < 0  OR  any Tp > MLLG_TP_THRESHOLD
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include <cmath>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

// ── Simulation parameters ──────────────────────────────────────────────────

static uint32_t g_attack_scenario = 0;
static double   g_simTime         = 60.0;

// ── Physical link/propagation constants (ms) ──────────────────────────────

static const double CTRL_TO_SW_MS        = 0.5;    // one-way ctrl↔switch
static const double SW_TO_SW_DELAY_MS    = 5.0;    // s1–s2 and s2–s3 physical link
static const double HOST_SW_DELAY_MS     = 0.5;    // host–switch physical link
static const double OOB_DELAY_MS         = 10.0;   // h1→h2 out-of-band relay

// LLDP timestamps (physical, do NOT change under overload):
//   Legit link s1–s2: TLLDP = 2*CTRL_TO_SW + SW_TO_SW = 1 + 5 = 6 ms
//   Fake link s1–s3 (relay): TLLDP = 2*CTRL_TO_SW + SW_TO_SW*2 + OOB = 1+10+10 = 21 ms
static const double TLLDP_LEGIT_MS       = 6.0;
static const double TLLDP_RELAY_FAKE_MS  = 21.0;

// Probe RTTs (Tp):
static const double PROBE_RTT_NORMAL_MS     = 1.0;    // no overload
static const double PROBE_RTT_OVERLOADED_MS = 130.0;  // after ARP flood

// MLLG anomaly threshold
static const double MLLG_TP_THRESHOLD_MS = 50.0;

// Attack phases
static const double OVERLOAD_START_S  = 5.0;   // ARP flood begins
static const double OVERLOAD_END_S    = 55.0;  // ARP flood ends (whole sim)
static const double RELAY_START_S     = 10.0;  // relay phase begins
static const double LLDP_INTERVAL_S   = 5.0;   // LLDP discovery period

// ── Node containers ────────────────────────────────────────────────────────

NodeContainer g_Switch_Nodes;      // s1=0, s2=1, s3=2
NodeContainer g_Host_Nodes;        // h1=0..h6=5  (h1=idx0 at s1, h2=idx1 at s3)
NodeContainer g_Controller_Nodes;  // single controller

// ── TopoGuard+ state ───────────────────────────────────────────────────────

// Per-switch probe RTT history (sliding window for IQR threshold)
static const uint32_t PROBE_HISTORY_DEPTH = 20;
std::deque<double> g_probe_history_s1;
std::deque<double> g_probe_history_s2;
std::deque<double> g_probe_history_s3;

// Whether the overload phase is currently active
bool g_overload_active = false;

// Fake link record: has the fake s1–s3 link been accepted into topology?
bool g_fake_link_accepted = false;
double g_fake_link_accept_time = -1.0;

// ── PEM counters ───────────────────────────────────────────────────────────

uint64_t g_pem_tp = 0;  // TopoGuard+ TP
uint64_t g_pem_tn = 0;
uint64_t g_pem_fp = 0;
uint64_t g_pem_fn = 0;

uint64_t g_mllg_tp = 0;  // MLLG TP
uint64_t g_mllg_tn = 0;
uint64_t g_mllg_fp = 0;
uint64_t g_mllg_fn = 0;

double g_attack_start_time     = -1.0;
double g_tg_first_alert_time   = -1.0;
double g_mllg_first_alert_time = -1.0;

// ── Output files ───────────────────────────────────────────────────────────

std::ofstream g_attack_log;
std::ofstream g_events_csv;

// ── Helper: IQR-based threshold (Eq. 2) ───────────────────────────────────

static double ComputeThreshold(const std::deque<double>& history)
{
    if (history.size() < 4) return 10.0;  // fallback until enough samples

    std::vector<double> sorted(history.begin(), history.end());
    std::sort(sorted.begin(), sorted.end());
    size_t n = sorted.size();

    double q1 = sorted[n / 4];
    double q3 = sorted[3 * n / 4];
    return q3 + 3.0 * (q3 - q1);
}

// ── Helper: current probe RTT for a switch ────────────────────────────────

static double GetProbeRTT(uint32_t sw_idx)
{
    if (g_overload_active) return PROBE_RTT_OVERLOADED_MS;
    return PROBE_RTT_NORMAL_MS;
}

// ── Helper: push probe sample into history ───────────────────────────────

static void RecordProbeSample(uint32_t sw_idx, double rtt_ms)
{
    auto& hist = (sw_idx == 0) ? g_probe_history_s1
               : (sw_idx == 1) ? g_probe_history_s2
                               : g_probe_history_s3;

    hist.push_back(rtt_ms);
    if (hist.size() > PROBE_HISTORY_DEPTH) hist.pop_front();
}

// ── TopoGuard+ Link Latency Inspector ────────────────────────────────────

struct LLI_Result {
    double tl_ms;
    double th_ms;
    double tp1_ms;
    double tp2_ms;
    bool   topoguard_alarm;
    bool   mllg_alarm;
    bool   is_attack_event;
};

static LLI_Result RunLLI(double tlldp_ms,
                          uint32_t sw1_idx,
                          uint32_t sw2_idx,
                          bool is_attack_event)
{
    LLI_Result r;
    r.tp1_ms = GetProbeRTT(sw1_idx);
    r.tp2_ms = GetProbeRTT(sw2_idx);

    RecordProbeSample(sw1_idx, r.tp1_ms);
    RecordProbeSample(sw2_idx, r.tp2_ms);

    r.tl_ms = tlldp_ms - r.tp1_ms - r.tp2_ms;

    // Threshold from s1 history (the ingress switch)
    auto& hist = (sw1_idx == 0) ? g_probe_history_s1
               : (sw1_idx == 1) ? g_probe_history_s2
                                : g_probe_history_s3;
    r.th_ms = ComputeThreshold(hist);

    // TopoGuard+ alarm fires only when Tl > Th
    r.topoguard_alarm = (r.tl_ms > r.th_ms);

    // MLLG: flag negative Tl or inflated Tp
    r.mllg_alarm = (r.tl_ms < 0.0) ||
                   (r.tp1_ms > MLLG_TP_THRESHOLD_MS) ||
                   (r.tp2_ms > MLLG_TP_THRESHOLD_MS);

    r.is_attack_event = is_attack_event;
    return r;
}

// ── CSV event logging ─────────────────────────────────────────────────────

static void LogEvent(double sim_time_s,
                     const std::string& event_type,
                     uint32_t sw1_idx,
                     uint32_t sw2_idx,
                     const LLI_Result& r)
{
    if (!g_events_csv.is_open()) return;

    g_events_csv << std::fixed << std::setprecision(3)
                 << sim_time_s << ","
                 << event_type << ","
                 << (sw1_idx + 1) << ","     // 1-indexed switch IDs
                 << (sw2_idx + 1) << ","
                 << r.tl_ms << ","
                 << r.th_ms << ","
                 << r.tp1_ms << ","
                 << r.tp2_ms << ","
                 << (r.topoguard_alarm ? 1 : 0) << ","
                 << (r.mllg_alarm ? 1 : 0) << ","
                 << (r.is_attack_event ? 1 : 0)
                 << "\n";
}

// ── PEM accounting ────────────────────────────────────────────────────────

static void AccountPEM(const LLI_Result& r)
{
    double now = Simulator::Now().GetSeconds();

    // TopoGuard+ accounting
    if (r.is_attack_event) {
        if (r.topoguard_alarm) {
            g_pem_tp++;
            if (g_tg_first_alert_time < 0.0) g_tg_first_alert_time = now;
        } else {
            g_pem_fn++;  // attack event not caught by TopoGuard+
        }
    } else {
        if (r.topoguard_alarm) g_pem_fp++;
        else                   g_pem_tn++;
    }

    // MLLG accounting
    if (r.is_attack_event) {
        if (r.mllg_alarm) {
            g_mllg_tp++;
            if (g_mllg_first_alert_time < 0.0) g_mllg_first_alert_time = now;
        } else {
            g_mllg_fn++;
        }
    } else {
        if (r.mllg_alarm) g_mllg_fp++;
        else               g_mllg_tn++;
    }
}

// ── MCC helper ────────────────────────────────────────────────────────────

static double MCC(uint64_t tp, uint64_t tn, uint64_t fp, uint64_t fn)
{
    double denom = std::sqrt(
        static_cast<double>((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)));
    if (denom < 1e-9) return 0.0;
    return static_cast<double>(tp * tn - fp * fn) / denom;
}

// ── Overload phase control ────────────────────────────────────────────────

static void LLA_OverloadBegin()
{
    g_overload_active = true;
    double now = Simulator::Now().GetSeconds();
    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] OVERLOAD PHASE START: h1 & h2 begin ARP flood.\n"
                 << "  → Probe RTTs inflated: " << PROBE_RTT_NORMAL_MS
                 << " ms → " << PROBE_RTT_OVERLOADED_MS << " ms\n"
                 << "  → TopoGuard+ threshold will freeze at inflated values\n\n";
    std::cout << "[LLA] t=" << now << "s  Overload phase STARTED (Tp → "
              << PROBE_RTT_OVERLOADED_MS << " ms)\n";
}

static void LLA_OverloadEnd()
{
    g_overload_active = false;
    double now = Simulator::Now().GetSeconds();
    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] OVERLOAD PHASE END.\n\n";
}

// ── Legitimate LLDP discovery event ──────────────────────────────────────

static void LLA_LegitLLDP(uint32_t sw1_idx, uint32_t sw2_idx, double tlldp_ms)
{
    double now = Simulator::Now().GetSeconds();
    LLI_Result r = RunLLI(tlldp_ms, sw1_idx, sw2_idx, false);
    AccountPEM(r);

    std::string ev = "LLDP_LEGIT";
    LogEvent(now, ev, sw1_idx, sw2_idx, r);

    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] LEGIT LLDP: s" << (sw1_idx+1)
                 << "→s" << (sw2_idx+1)
                 << "  TLLDP=" << tlldp_ms << " ms"
                 << "  Tp1=" << r.tp1_ms << " ms"
                 << "  Tp2=" << r.tp2_ms << " ms"
                 << "  Tl=" << r.tl_ms << " ms"
                 << "  Th=" << r.th_ms << " ms"
                 << "  TG=" << (r.topoguard_alarm ? "ALARM" : "OK")
                 << "  MLLG=" << (r.mllg_alarm ? "ALARM" : "OK")
                 << "\n";
}

// ── Relay phase: fake LLDP event injected at s3 (claiming s1–s3 link) ────

static void LLA_RelayLLDP()
{
    double now = Simulator::Now().GetSeconds();

    if (g_attack_start_time < 0.0)
        g_attack_start_time = now;

    // sw1_idx=0 (s1), sw2_idx=2 (s3)
    // TLLDP physically reflects the OOB relay path: 21 ms
    LLI_Result r = RunLLI(TLLDP_RELAY_FAKE_MS, 0, 2, true);
    AccountPEM(r);

    std::string ev = "LLDP_RELAY_FAKE";
    LogEvent(now, ev, 0, 2, r);

    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] ** RELAY ATTACK **: h1 sniffs LLDP(s1), relays OOB→h2→s3\n"
                 << "  Fake link: s1 ↔ s3 (no physical connection)\n"
                 << "  TLLDP=" << TLLDP_RELAY_FAKE_MS << " ms"
                 << "  Tp1=" << r.tp1_ms << " ms  (s1 probe RTT)"
                 << "  Tp2=" << r.tp2_ms << " ms  (s3 probe RTT)\n"
                 << "  Tl = " << TLLDP_RELAY_FAKE_MS << " - "
                 << r.tp1_ms << " - " << r.tp2_ms
                 << " = " << r.tl_ms << " ms\n"
                 << "  Th=" << r.th_ms << " ms\n";

    if (!r.topoguard_alarm) {
        g_fake_link_accepted = true;
        g_fake_link_accept_time = now;
        g_attack_log << "  TopoGuard+: NO ALARM (Tl=" << r.tl_ms
                     << " ≤ Th=" << r.th_ms << ") → FAKE LINK ACCEPTED!\n"
                     << "  Controller now believes s1↔s3 link exists — routing CORRUPTED\n";
    } else {
        g_attack_log << "  TopoGuard+: ALARM RAISED (Tl=" << r.tl_ms
                     << " > Th=" << r.th_ms << ") → attack blocked\n";
    }

    if (r.mllg_alarm) {
        g_attack_log << "  MLLG: ALARM (Tl=" << r.tl_ms << " ms is negative"
                     << " OR Tp > " << MLLG_TP_THRESHOLD_MS << " ms) → DETECTED\n";
    } else {
        g_attack_log << "  MLLG: NO ALARM\n";
    }

    g_attack_log << "\n";

    std::cout << "[LLA] t=" << now << "s  Relay LLDP injected"
              << "  Tl=" << r.tl_ms << " ms"
              << "  TG=" << (r.topoguard_alarm ? "ALARM" : "PASS")
              << "  MLLG=" << (r.mllg_alarm ? "ALARM" : "PASS")
              << "\n";
}

// ── Periodic LLDP scheduler ───────────────────────────────────────────────

static void LLA_ScheduleLLDP(double t_end);

static void LLA_LLDPTick(double t_end)
{
    double now = Simulator::Now().GetSeconds();
    if (now >= t_end) return;

    // Legitimate links: s1–s2 and s2–s3
    LLA_LegitLLDP(0, 1, TLLDP_LEGIT_MS);
    LLA_LegitLLDP(1, 2, TLLDP_LEGIT_MS);

    // For relay scenarios, also inject the fake s1–s3 link starting at RELAY_START_S
    if ((g_attack_scenario == 16 || g_attack_scenario == 17) &&
        now >= RELAY_START_S)
    {
        LLA_RelayLLDP();
    }

    // Reschedule
    Simulator::Schedule(Seconds(LLDP_INTERVAL_S), &LLA_LLDPTick, t_end);
}

// ── Summary CSV ───────────────────────────────────────────────────────────

static void LLA_WriteSummary()
{
    std::ofstream csv("lla_pem_summary.csv");
    if (!csv.is_open()) {
        std::cerr << "[LLA] ERROR: cannot open lla_pem_summary.csv\n";
        return;
    }

    csv << "attack_scenario,detector,tp,tn,fp,fn,mcc,tdet_ms,"
        << "fake_link_accepted,fake_link_accept_time_s\n";

    double tg_tdet = (g_tg_first_alert_time >= 0.0 && g_attack_start_time >= 0.0)
                   ? (g_tg_first_alert_time - g_attack_start_time) * 1000.0
                   : -1.0;

    double mllg_tdet = (g_mllg_first_alert_time >= 0.0 && g_attack_start_time >= 0.0)
                     ? (g_mllg_first_alert_time - g_attack_start_time) * 1000.0
                     : -1.0;

    csv << g_attack_scenario << ",TopoGuard+,"
        << g_pem_tp << "," << g_pem_tn << "," << g_pem_fp << "," << g_pem_fn << ","
        << std::fixed << std::setprecision(4)
        << MCC(g_pem_tp, g_pem_tn, g_pem_fp, g_pem_fn) << ","
        << tg_tdet << ","
        << (g_fake_link_accepted ? 1 : 0) << ","
        << g_fake_link_accept_time << "\n";

    csv << g_attack_scenario << ",MLLG,"
        << g_mllg_tp << "," << g_mllg_tn << "," << g_mllg_fp << "," << g_mllg_fn << ","
        << MCC(g_mllg_tp, g_mllg_tn, g_mllg_fp, g_mllg_fn) << ","
        << mllg_tdet << ","
        << (g_fake_link_accepted ? 1 : 0) << ","
        << g_fake_link_accept_time << "\n";

    csv.close();

    // Human-readable summary to log
    g_attack_log << "=== SIMULATION SUMMARY (scenario=" << g_attack_scenario << ") ===\n\n";
    g_attack_log << "Attack injection time : "
                 << std::fixed << std::setprecision(3)
                 << g_attack_start_time << " s\n";
    g_attack_log << "Fake link accepted    : " << (g_fake_link_accepted ? "YES" : "NO") << "\n";
    if (g_fake_link_accepted)
        g_attack_log << "Fake link accept time : " << g_fake_link_accept_time << " s\n";

    g_attack_log << "\n--- TopoGuard+ LLI Results ---\n";
    g_attack_log << "  TP=" << g_pem_tp << "  TN=" << g_pem_tn
                 << "  FP=" << g_pem_fp << "  FN=" << g_pem_fn << "\n";
    g_attack_log << "  MCC=" << MCC(g_pem_tp, g_pem_tn, g_pem_fp, g_pem_fn) << "\n";
    g_attack_log << "  Tdet=" << tg_tdet << " ms\n";

    g_attack_log << "\n--- MLLG Results ---\n";
    g_attack_log << "  TP=" << g_mllg_tp << "  TN=" << g_mllg_tn
                 << "  FP=" << g_mllg_fp << "  FN=" << g_mllg_fn << "\n";
    g_attack_log << "  MCC=" << MCC(g_mllg_tp, g_mllg_tn, g_mllg_fp, g_mllg_fn) << "\n";
    g_attack_log << "  Tdet=" << mllg_tdet << " ms\n";

    std::cout << "[LLA] Summary written to lla_pem_summary.csv\n";
}

// ── Log file initialization ───────────────────────────────────────────────

static void LLA_InitLogs()
{
    std::string log_name;
    if      (g_attack_scenario == 16) log_name = "lla_attack16.txt";
    else if (g_attack_scenario == 17) log_name = "lla_attack17.txt";
    else                               log_name = "lla_baseline.txt";

    g_attack_log.open(log_name);
    g_attack_log << "================================================\n"
                 << " Link Latency Attack (LLA) — Scenario "
                 << g_attack_scenario << "\n"
                 << "================================================\n"
                 << "Based on: Soltani et al., CNSM 2021\n\n";

    if (g_attack_scenario == 16) {
        g_attack_log << "Attack type: FULL LLA (Overload Phase + Relay Phase)\n"
                     << "Expected: TopoGuard+ FAILS, MLLG DETECTS\n\n";
        g_attack_log << "Phase 1 — Overload:\n"
                     << "  h1 & h2 flood ARP traffic at s1 & s3\n"
                     << "  Switch queue delay inflates Tp1, Tp2: "
                     << PROBE_RTT_NORMAL_MS << " ms → "
                     << PROBE_RTT_OVERLOADED_MS << " ms\n"
                     << "  TopoGuard+ Th threshold rises (IQR on inflated samples)\n\n"
                     << "Phase 2 — Relay:\n"
                     << "  h1 captures LLDP(s1) and relays via OOB channel ("
                     << OOB_DELAY_MS << " ms) to h2\n"
                     << "  h2 injects relayed LLDP at s3 — controller sees LLDP(s1→s3)\n"
                     << "  TLLDP_fake = " << TLLDP_RELAY_FAKE_MS << " ms\n"
                     << "  Tl = " << TLLDP_RELAY_FAKE_MS << " - "
                     << PROBE_RTT_OVERLOADED_MS << " - " << PROBE_RTT_OVERLOADED_MS
                     << " = "
                     << (TLLDP_RELAY_FAKE_MS - PROBE_RTT_OVERLOADED_MS - PROBE_RTT_OVERLOADED_MS)
                     << " ms  (NEGATIVE → passes TopoGuard+)\n\n";
    } else if (g_attack_scenario == 17) {
        g_attack_log << "Attack type: RELAY ONLY (no overload)\n"
                     << "Expected: TopoGuard+ DETECTS (no inflated Tp)\n\n"
                     << "  h1 relays LLDP(s1) via OOB → h2 → s3\n"
                     << "  TLLDP_fake = " << TLLDP_RELAY_FAKE_MS << " ms\n"
                     << "  Tp1 = Tp2 = " << PROBE_RTT_NORMAL_MS << " ms (not inflated)\n"
                     << "  Tl = " << TLLDP_RELAY_FAKE_MS << " - "
                     << PROBE_RTT_NORMAL_MS << " - " << PROBE_RTT_NORMAL_MS
                     << " = "
                     << (TLLDP_RELAY_FAKE_MS - PROBE_RTT_NORMAL_MS - PROBE_RTT_NORMAL_MS)
                     << " ms > Th → TopoGuard+ ALARMS\n\n";
    } else {
        g_attack_log << "Attack type: BASELINE (no attack)\n"
                     << "Expected: All events LEGIT, no alarms\n\n";
    }

    g_attack_log << "Simulation time: " << g_simTime << " s\n"
                 << "LLDP interval:   " << LLDP_INTERVAL_S << " s\n"
                 << "Topology: s1 ─ s2 ─ s3  (s1↔s3 has NO physical link)\n\n"
                 << "─────────────────────────────────────────────────\n\n";

    g_events_csv.open("lla_events.csv");
    g_events_csv << "sim_time_s,event_type,sw1_id,sw2_id,"
                 << "tl_ms,th_ms,tp1_ms,tp2_ms,"
                 << "topoguard_alarm,mllg_alarm,is_attack_event\n";

    std::cout << "[LLA] Logs initialised: " << log_name << ", lla_events.csv\n";
}

// ── Mobility setup ────────────────────────────────────────────────────────

static void SetupMobility()
{
    // Switches arranged linearly: s1(0,0), s2(500,0), s3(1000,0)
    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> sw_pos = CreateObject<ListPositionAllocator>();
    sw_pos->Add(Vector(0.0,   0.0, 0.0));   // s1
    sw_pos->Add(Vector(500.0, 0.0, 0.0));   // s2
    sw_pos->Add(Vector(1000.0,0.0, 0.0));   // s3
    mob.SetPositionAllocator(sw_pos);
    mob.Install(g_Switch_Nodes);

    // Hosts around their switch (2 per switch)
    Ptr<ListPositionAllocator> h_pos = CreateObject<ListPositionAllocator>();
    h_pos->Add(Vector(0.0,    50.0, 0.0));   // h1 (idx0) — compromised, at s1
    h_pos->Add(Vector(1000.0, 50.0, 0.0));  // h2 (idx1) — compromised, at s3
    h_pos->Add(Vector(500.0,  50.0, 0.0));  // h3 at s2
    h_pos->Add(Vector(500.0, -50.0, 0.0));  // h4 at s2
    h_pos->Add(Vector(0.0,   -50.0, 0.0));  // h5 at s1
    h_pos->Add(Vector(1000.0,-50.0, 0.0));  // h6 at s3
    mob.SetPositionAllocator(h_pos);
    mob.Install(g_Host_Nodes);

    // Controller at center-top
    Ptr<ListPositionAllocator> c_pos = CreateObject<ListPositionAllocator>();
    c_pos->Add(Vector(500.0, 300.0, 0.0));
    mob.SetPositionAllocator(c_pos);
    mob.Install(g_Controller_Nodes);
}

// ── Pre-populate probe history so Th is meaningful from start ─────────────

static void PrePopulateProbeHistory()
{
    for (uint32_t i = 0; i < PROBE_HISTORY_DEPTH; i++) {
        g_probe_history_s1.push_back(PROBE_RTT_NORMAL_MS);
        g_probe_history_s2.push_back(PROBE_RTT_NORMAL_MS);
        g_probe_history_s3.push_back(PROBE_RTT_NORMAL_MS);
    }
}

// ── main ──────────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",        "Simulation time (s)",            g_simTime);
    cmd.AddValue("attack_scenario","0=none, 16=full LLA, 17=relay",  g_attack_scenario);
    cmd.Parse(argc, argv);

    // Create nodes
    g_Switch_Nodes.Create(3);      // s1, s2, s3
    g_Host_Nodes.Create(6);        // h1..h6
    g_Controller_Nodes.Create(1);  // controller

    SetupMobility();
    PrePopulateProbeHistory();
    LLA_InitLogs();

    g_attack_log << "NODE MAP:\n"
                 << "  Switch nodes: s1=node" << g_Switch_Nodes.Get(0)->GetId()
                 << "  s2=node" << g_Switch_Nodes.Get(1)->GetId()
                 << "  s3=node" << g_Switch_Nodes.Get(2)->GetId() << "\n"
                 << "  Host nodes:   h1=node" << g_Host_Nodes.Get(0)->GetId()
                 << " (compromised, at s1)"
                 << "  h2=node" << g_Host_Nodes.Get(1)->GetId()
                 << " (compromised, at s3)\n"
                 << "  Controller:   node"  << g_Controller_Nodes.Get(0)->GetId() << "\n\n";

    // ── Schedule events ───────────────────────────────────────────────────

    // Overload phase (scenario 16 only)
    if (g_attack_scenario == 16) {
        if (OVERLOAD_START_S < g_simTime) {
            Simulator::Schedule(Seconds(OVERLOAD_START_S), &LLA_OverloadBegin);
        }
        if (OVERLOAD_END_S < g_simTime) {
            Simulator::Schedule(Seconds(OVERLOAD_END_S), &LLA_OverloadEnd);
        }
    }

    // LLDP discovery ticks
    double lldp_start = 1.0;
    if (lldp_start < g_simTime) {
        Simulator::Schedule(Seconds(lldp_start), &LLA_LLDPTick, g_simTime - 0.5);
    }

    // Write summary at end
    Simulator::Schedule(Seconds(g_simTime - 0.01), &LLA_WriteSummary);

    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();

    g_attack_log.close();
    g_events_csv.close();

    std::cout << "[LLA] Simulation complete (scenario=" << g_attack_scenario
              << ", simTime=" << g_simTime << "s)\n"
              << "[LLA] Fake link accepted: " << (g_fake_link_accepted ? "YES" : "NO") << "\n";

    return 0;
}
