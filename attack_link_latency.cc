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
 *  16  = Full LLA: Overload Phase + Relay Phase -> TopoGuard+ FAILS, MLLG detects
 *  17  = Relay only (no overload) -> TopoGuard+ SUCCEEDS (shows overload is necessary)
 *  18  = Basic LFA: direct data-plane LLDP injection -> TopoGuard+ DETECTS (Tl > Th)
 *  19  = Gradual LFA: incrementally inflate Tl history to raise Th, then relay ->
 *        TopoGuard+ FAILS (Tl_relay < inflated Th), MLLG detects via Th drift
 *
 * Topology: s1 -- s2 -- s3  (RSU switches, wired)
 *           h1..h6 attached to s1..s3 (2 hosts per switch)
 *           h1 (at s1) and h2 (at s3) are the compromised nodes
 *           Controller connected to all switches via separate control plane
 *
 * TopoGuard+ Link Latency Inspector (LLI):
 *   Tl = TLLDP - Tp1 - Tp2          (Eq. 1)
 *   Th = Q3 + 3*(Q3 - Q1)           (Eq. 2, IQR fence on Tl history)
 *   ALARM if Tl > Th
 *   VULNERABILITY (scenario 16): overloading switches inflates Tp -> Tl goes negative
 *   -> negative Tl silently passes (Tl < 0 <= Th, no alarm)
 *   VULNERABILITY (scenario 19): gradually injecting high-Tl LLDPs inflates Th
 *   -> after Th > relay Tl, relay passes undetected
 *
 * MLLG defense (enhanced):
 *   Flag if Tl < 0                   (catches scenario 16)
 *         OR Tp > MLLG_TP_THRESHOLD  (catches scenario 16)
 *         OR Tl > MLLG_TL_HIGH       (catches scenarios 17, 18, 19 relay)
 *         OR Th drift > MLLG_DRIFT   (catches scenario 19 gradual inflation)
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include <algorithm>
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

static const double CTRL_TO_SW_MS        = 0.5;    // one-way ctrl<->switch
static const double SW_TO_SW_DELAY_MS    = 5.0;    // s1-s2 and s2-s3 physical link
static const double HOST_SW_DELAY_MS     = 5.0;    // host-switch physical link (paper Fig.4)
static const double OOB_DELAY_MS         = 10.0;   // h1->h2 out-of-band relay

// LLDP timestamps (physical, do NOT change under overload):
//   Legit link s1-s2:   TLLDP = 2*CTRL_TO_SW + SW_TO_SW = 1 + 5 = 6 ms
//   Relay fake s1-s3:   TLLDP = 2*CTRL_TO_SW + 2*SW_TO_SW + OOB = 1+10+10 = 21 ms
//   Basic LFA s1-s3:    TLLDP = 2*CTRL_TO_SW + HOST_SW + 2*SW_TO_SW = 1+5+10 = 16 ms
static const double TLLDP_LEGIT_MS       = 6.0;
static const double TLLDP_RELAY_FAKE_MS  = 21.0;
static const double TLLDP_BASIC_FAKE_MS  = 2.0*CTRL_TO_SW_MS + HOST_SW_DELAY_MS
                                           + 2.0*SW_TO_SW_DELAY_MS;  // = 16.0 ms

// Probe RTTs (Tp):
static const double PROBE_RTT_NORMAL_MS     = 1.0;    // no overload
static const double PROBE_RTT_OVERLOADED_MS = 130.0;  // after ARP flood

// MLLG anomaly thresholds
static const double MLLG_TP_THRESHOLD_MS = 50.0;  // Tp inflation alarm
static const double MLLG_TL_HIGH_MS      = 8.0;   // high Tl alarm (catches basic/relay LFA)
static const double MLLG_TH_DRIFT_MS     = 2.0;   // per-event Th increase alarm (catches gradual LFA)

// Tl history for IQR threshold computation (Eq. 2 — history of Tl values, not Tp)
static const uint32_t TL_HISTORY_DEPTH = 20;
// Legit Tl = TLLDP_LEGIT - 2*PROBE_RTT_NORMAL = 6 - 1 - 1 = 4 ms
static const double TL_LEGIT_BASELINE_MS = TLLDP_LEGIT_MS
                                           - 2.0*PROBE_RTT_NORMAL_MS;  // = 4.0 ms

// Attack phase timing
static const double OVERLOAD_START_S  = 5.0;    // ARP flood begins (scenarios 16)
static const double OVERLOAD_END_S    = 55.0;   // ARP flood ends
static const double RELAY_START_S     = 10.0;   // relay phase begins (scenarios 16, 17, 18)
static const double GRADUAL_START_S   = 10.0;   // first gradual injection (scenario 19)
static const double GRADUAL_RELAY_S   = 35.0;   // final relay attempt (scenario 19)
static const double LLDP_INTERVAL_S   = 5.0;    // LLDP discovery period

// ── Node containers ────────────────────────────────────────────────────────

NodeContainer g_Switch_Nodes;      // s1=0, s2=1, s3=2
NodeContainer g_Host_Nodes;        // h1=0..h6=5  (h1=idx0 at s1, h2=idx1 at s3)
NodeContainer g_Controller_Nodes;  // single controller

// ── TopoGuard+ state ───────────────────────────────────────────────────────

// Tl history (sliding window — used for IQR Th computation, Eq. 2)
std::deque<double> g_tl_history;

// Previous Th value for MLLG drift detection
double g_prev_th = TL_LEGIT_BASELINE_MS;  // initial Th from pre-populated history

// Whether the overload phase is currently active
bool g_overload_active = false;

// Fake link record: has the fake s1-s3 link been accepted into topology?
bool   g_fake_link_accepted    = false;
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

// ── Helper: IQR-based threshold from Tl history (Eq. 2) ───────────────────

static double ComputeThreshold(const std::deque<double>& history)
{
    if (history.size() < 4) return TL_LEGIT_BASELINE_MS + 6.0;  // fallback

    std::vector<double> sorted(history.begin(), history.end());
    std::sort(sorted.begin(), sorted.end());
    size_t n = sorted.size();

    double q1 = sorted[n / 4];
    double q3 = sorted[3 * n / 4];
    return q3 + 3.0 * (q3 - q1);
}

// ── Helper: record a Tl value into the sliding history ───────────────────

static void RecordTlSample(double tl_ms)
{
    g_tl_history.push_back(tl_ms);
    if (g_tl_history.size() > TL_HISTORY_DEPTH) g_tl_history.pop_front();
}

// ── Helper: current probe RTT for any switch ─────────────────────────────

static double GetProbeRTT(uint32_t /*sw_idx*/)
{
    return g_overload_active ? PROBE_RTT_OVERLOADED_MS : PROBE_RTT_NORMAL_MS;
}

// ── TopoGuard+ Link Latency Inspector ────────────────────────────────────

struct LLI_Result {
    double tl_ms;
    double th_ms;
    double tp1_ms;
    double tp2_ms;
    bool   topoguard_alarm;
    bool   mllg_alarm;
    // MLLG sub-reasons (for logging)
    bool   mllg_neg_tl;
    bool   mllg_high_tp;
    bool   mllg_high_tl;
    bool   mllg_th_drift;
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
    r.tl_ms  = tlldp_ms - r.tp1_ms - r.tp2_ms;

    // Record Tl into history and compute new Th (Eq. 2 on Tl history)
    RecordTlSample(r.tl_ms);
    r.th_ms = ComputeThreshold(g_tl_history);

    // TopoGuard+ alarm fires only when Tl > Th
    r.topoguard_alarm = (r.tl_ms > r.th_ms);

    // MLLG multi-trigger checks
    r.mllg_neg_tl  = (r.tl_ms < 0.0);
    r.mllg_high_tp = (r.tp1_ms > MLLG_TP_THRESHOLD_MS) || (r.tp2_ms > MLLG_TP_THRESHOLD_MS);
    r.mllg_high_tl = (r.tl_ms > MLLG_TL_HIGH_MS);
    r.mllg_th_drift = (r.th_ms - g_prev_th > MLLG_TH_DRIFT_MS);
    g_prev_th = r.th_ms;  // update for next event

    r.mllg_alarm = r.mllg_neg_tl || r.mllg_high_tp || r.mllg_high_tl || r.mllg_th_drift;
    r.is_attack_event = is_attack_event;
    return r;
}

// ── MLLG reason string helper ─────────────────────────────────────────────

static std::string MllgReason(const LLI_Result& r)
{
    if (!r.mllg_alarm) return "NONE";
    std::string s;
    if (r.mllg_neg_tl)   { if (!s.empty()) s += "|"; s += "NEG_TL";   }
    if (r.mllg_high_tp)  { if (!s.empty()) s += "|"; s += "HIGH_TP";  }
    if (r.mllg_high_tl)  { if (!s.empty()) s += "|"; s += "HIGH_TL";  }
    if (r.mllg_th_drift) { if (!s.empty()) s += "|"; s += "TH_DRIFT"; }
    return s;
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
                 << sim_time_s       << ","
                 << event_type       << ","
                 << (sw1_idx + 1)    << ","
                 << (sw2_idx + 1)    << ","
                 << r.tl_ms          << ","
                 << r.th_ms          << ","
                 << r.tp1_ms         << ","
                 << r.tp2_ms         << ","
                 << (r.topoguard_alarm ? 1 : 0) << ","
                 << (r.mllg_alarm    ? 1 : 0)   << ","
                 << MllgReason(r)    << ","
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
            g_pem_fn++;
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
                 << "  -> Probe RTTs inflated: " << PROBE_RTT_NORMAL_MS
                 << " ms -> " << PROBE_RTT_OVERLOADED_MS << " ms\n"
                 << "  -> Tl will go negative (TLLDP << Tp1+Tp2)\n\n";
    std::cout << "[LLA] t=" << now << "s  Overload STARTED (Tp -> "
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
    LogEvent(now, "LLDP_LEGIT", sw1_idx, sw2_idx, r);

    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] LEGIT LLDP s" << (sw1_idx+1) << "<->s" << (sw2_idx+1)
                 << "  TLLDP=" << tlldp_ms
                 << "  Tl=" << r.tl_ms
                 << "  Th=" << r.th_ms
                 << "  TG=" << (r.topoguard_alarm ? "ALARM" : "OK")
                 << "  MLLG=" << (r.mllg_alarm ? MllgReason(r) : "OK")
                 << "\n";
}

// ── Relay LLDP: fake LLDP claiming non-existent s1-s3 link ───────────────
// Used by scenarios 16 (with overload), 17 (no overload), 19 (after threshold inflation)

static void LLA_RelayLLDP()
{
    double now = Simulator::Now().GetSeconds();

    if (g_attack_start_time < 0.0) g_attack_start_time = now;

    LLI_Result r = RunLLI(TLLDP_RELAY_FAKE_MS, 0, 2, true);
    AccountPEM(r);
    LogEvent(now, "LLDP_RELAY_FAKE", 0, 2, r);

    g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << now
                 << "s] ** RELAY ATTACK **: h1 sniffs LLDP(s1), relays OOB->h2->s3\n"
                 << "  Fake link: s1 <-> s3 (no physical link exists)\n"
                 << "  TLLDP=" << TLLDP_RELAY_FAKE_MS
                 << "  Tp1=" << r.tp1_ms << "  Tp2=" << r.tp2_ms << "\n"
                 << "  Tl = " << TLLDP_RELAY_FAKE_MS << " - "
                 << r.tp1_ms << " - " << r.tp2_ms << " = " << r.tl_ms << " ms\n"
                 << "  Th = " << r.th_ms << " ms\n";

    if (!r.topoguard_alarm) {
        g_fake_link_accepted    = true;
        g_fake_link_accept_time = now;
        g_attack_log << "  TopoGuard+: NO ALARM (Tl=" << r.tl_ms
                     << " <= Th=" << r.th_ms << ") -> FAKE LINK ACCEPTED!\n"
                     << "  Controller now believes s1<->s3 link exists -- routing CORRUPTED\n";
    } else {
        g_attack_log << "  TopoGuard+: ALARM (Tl=" << r.tl_ms
                     << " > Th=" << r.th_ms << ") -> attack BLOCKED\n";
    }

    if (r.mllg_alarm) {
        g_attack_log << "  MLLG: ALARM [" << MllgReason(r) << "] -> DETECTED\n";
    } else {
        g_attack_log << "  MLLG: NO ALARM\n";
    }
    g_attack_log << "\n";

    std::cout << "[LLA] t=" << now << "s  Relay LLDP  Tl=" << r.tl_ms
              << "  Th=" << r.th_ms
              << "  TG=" << (r.topoguard_alarm ? "ALARM" : "PASS")
              << "  MLLG=" << (r.mllg_alarm ? "ALARM" : "PASS") << "\n";
}

// ── Basic LFA: direct data-plane LLDP injection (scenario 18) ────────────
// No OOB delay, no overload. Attacker at h1 injects fake LLDP claiming s1-s3.
// TLLDP_BASIC = 2*CTRL_TO_SW + HOST_SW + 2*SW_TO_SW = 16 ms
// Tl = 16 - 1 - 1 = 14 ms > Th=4 ms -> TopoGuard+ DETECTS

static void LLA_BasicLFA()
{
    double now = Simulator::Now().GetSeconds();

    if (g_attack_start_time < 0.0) g_attack_start_time = now;

    LLI_Result r = RunLLI(TLLDP_BASIC_FAKE_MS, 0, 2, true);
    AccountPEM(r);
    LogEvent(now, "LLDP_BASIC_LFA", 0, 2, r);

    g_attack_log << "\n[t=" << std::fixed << std::setprecision(3) << now
                 << "s] ** BASIC LFA **: attacker injects LLDP at s3 via data plane\n"
                 << "  Path: CTRL->s1 (" << CTRL_TO_SW_MS
                 << "ms) + s1->h1 (" << HOST_SW_DELAY_MS
                 << "ms host-sw) + h1->s3 (" << 2.0*SW_TO_SW_DELAY_MS
                 << "ms) + s3->CTRL (" << CTRL_TO_SW_MS << "ms)\n"
                 << "  TLLDP_basic = " << TLLDP_BASIC_FAKE_MS << " ms\n"
                 << "  Tp1=" << r.tp1_ms << "  Tp2=" << r.tp2_ms
                 << "  Tl=" << r.tl_ms << " ms  Th=" << r.th_ms << " ms\n";

    if (!r.topoguard_alarm) {
        g_fake_link_accepted    = true;
        g_fake_link_accept_time = now;
        g_attack_log << "  TopoGuard+: NO ALARM -> FAKE LINK ACCEPTED!\n";
    } else {
        g_attack_log << "  TopoGuard+: ALARM (Tl=" << r.tl_ms
                     << " > Th=" << r.th_ms << ") -> attack BLOCKED\n";
    }

    if (r.mllg_alarm) {
        g_attack_log << "  MLLG: ALARM [" << MllgReason(r) << "] -> DETECTED\n";
    } else {
        g_attack_log << "  MLLG: NO ALARM\n";
    }
    g_attack_log << "\n";

    std::cout << "[LLA] t=" << now << "s  Basic LFA  Tl=" << r.tl_ms
              << "  Th=" << r.th_ms
              << "  TG=" << (r.topoguard_alarm ? "ALARM" : "PASS")
              << "  MLLG=" << (r.mllg_alarm ? "ALARM" : "PASS") << "\n";
}

// ── Gradual LFA: single fake injection with specified Tl (scenario 19) ───
// Attacker sends fake LLDP with a synthetic timestamp to produce fake_tl_ms.
// TLLDP_syn = fake_tl_ms + Tp1 + Tp2 = fake_tl_ms + 2 ms (no overload).
// Each batch of 3 injections gradually inflates Tl history -> raises Th.

static void LLA_GradualLFA_Inject(double fake_tl_ms)
{
    double now = Simulator::Now().GetSeconds();

    if (g_attack_start_time < 0.0) g_attack_start_time = now;

    // Synthetic TLLDP that would be measured for this fake_tl
    double tlldp_syn = fake_tl_ms + 2.0 * PROBE_RTT_NORMAL_MS;

    LLI_Result r = RunLLI(tlldp_syn, 0, 2, true);
    AccountPEM(r);
    LogEvent(now, "LLDP_GRADUAL_INJECT", 0, 2, r);

    g_attack_log << "[t=" << std::fixed << std::setprecision(3) << now
                 << "s] GRADUAL INJECT: fake Tl=" << fake_tl_ms
                 << " ms  Th=" << r.th_ms
                 << "  TG=" << (r.topoguard_alarm ? "ALARM" : "OK")
                 << "  MLLG=" << (r.mllg_alarm ? MllgReason(r) : "OK")
                 << "\n";

    if (r.mllg_th_drift) {
        g_attack_log << "  [!] MLLG Th drift detected: Th increased to "
                     << r.th_ms << " ms (delta > "
                     << MLLG_TH_DRIFT_MS << " ms)\n";
    }
}

// ── Periodic LLDP scheduler ───────────────────────────────────────────────

static void LLA_LLDPTick(double t_end)
{
    double now = Simulator::Now().GetSeconds();
    if (now >= t_end) return;

    // Legitimate links: s1-s2 and s2-s3
    LLA_LegitLLDP(0, 1, TLLDP_LEGIT_MS);
    LLA_LegitLLDP(1, 2, TLLDP_LEGIT_MS);

    // Scenarios 16 & 17: relay every tick after RELAY_START_S
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
                   ? (g_tg_first_alert_time - g_attack_start_time) * 1000.0 : -1.0;
    double mllg_tdet = (g_mllg_first_alert_time >= 0.0 && g_attack_start_time >= 0.0)
                     ? (g_mllg_first_alert_time - g_attack_start_time) * 1000.0 : -1.0;

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

    // Human-readable summary
    g_attack_log << "\n=== SIMULATION SUMMARY (scenario=" << g_attack_scenario << ") ===\n\n";

    const char* attack_name = "BASELINE";
    if      (g_attack_scenario == 16) attack_name = "FULL LLA (Overload + Relay)";
    else if (g_attack_scenario == 17) attack_name = "RELAY ONLY (no overload)";
    else if (g_attack_scenario == 18) attack_name = "BASIC LFA (direct injection)";
    else if (g_attack_scenario == 19) attack_name = "GRADUAL LFA (threshold inflation + relay)";
    g_attack_log << "Attack type           : " << attack_name << "\n";
    g_attack_log << "Attack injection time : "
                 << std::fixed << std::setprecision(3) << g_attack_start_time << " s\n";
    g_attack_log << "Fake link accepted    : " << (g_fake_link_accepted ? "YES" : "NO") << "\n";
    if (g_fake_link_accepted)
        g_attack_log << "Fake link accept time : " << g_fake_link_accept_time << " s\n";

    g_attack_log << "\n--- TopoGuard+ LLI Results ---\n"
                 << "  TP=" << g_pem_tp  << "  TN=" << g_pem_tn
                 << "  FP=" << g_pem_fp  << "  FN=" << g_pem_fn  << "\n"
                 << "  MCC=" << MCC(g_pem_tp, g_pem_tn, g_pem_fp, g_pem_fn) << "\n"
                 << "  Tdet=" << tg_tdet << " ms\n";

    g_attack_log << "\n--- MLLG Results ---\n"
                 << "  TP=" << g_mllg_tp << "  TN=" << g_mllg_tn
                 << "  FP=" << g_mllg_fp << "  FN=" << g_mllg_fn << "\n"
                 << "  MCC=" << MCC(g_mllg_tp, g_mllg_tn, g_mllg_fp, g_mllg_fn) << "\n"
                 << "  Tdet=" << mllg_tdet << " ms\n";

    g_attack_log << "\nTh at end of simulation: "
                 << ComputeThreshold(g_tl_history) << " ms\n";

    std::cout << "[LLA] Summary written to lla_pem_summary.csv\n";
}

// ── Log file initialization ───────────────────────────────────────────────

static void LLA_InitLogs()
{
    std::string log_name;
    if      (g_attack_scenario == 16) log_name = "lla_attack16.txt";
    else if (g_attack_scenario == 17) log_name = "lla_attack17.txt";
    else if (g_attack_scenario == 18) log_name = "lla_attack18.txt";
    else if (g_attack_scenario == 19) log_name = "lla_attack19.txt";
    else                               log_name = "lla_baseline.txt";

    g_attack_log.open(log_name);
    g_attack_log << "================================================\n"
                 << " Link Latency Attack (LLA) -- Scenario "
                 << g_attack_scenario << "\n"
                 << "================================================\n"
                 << "Based on: Soltani et al., CNSM 2021\n\n"
                 << "TopoGuard+ Eq.1:  Tl = TLLDP - Tp1 - Tp2\n"
                 << "TopoGuard+ Eq.2:  Th = Q3 + 3*(Q3-Q1)  [on Tl history, depth="
                 << TL_HISTORY_DEPTH << "]\n"
                 << "Initial Th (legit baseline): " << TL_LEGIT_BASELINE_MS
                 << " + 3*0 = " << TL_LEGIT_BASELINE_MS << " ms\n\n";

    if (g_attack_scenario == 16) {
        g_attack_log
            << "Attack type: FULL LLA\n"
            << "Expected: TopoGuard+ FAILS (Tl < 0), MLLG DETECTS (NEG_TL + HIGH_TP)\n\n"
            << "Phase 1 -- Overload (t=" << OVERLOAD_START_S << "s):\n"
            << "  h1/h2 ARP flood inflates Tp: "
            << PROBE_RTT_NORMAL_MS << "ms -> " << PROBE_RTT_OVERLOADED_MS << " ms\n"
            << "  Legit Tl becomes: " << TLLDP_LEGIT_MS << " - 2*"
            << PROBE_RTT_OVERLOADED_MS << " = "
            << (TLLDP_LEGIT_MS - 2.0*PROBE_RTT_OVERLOADED_MS) << " ms (NEGATIVE)\n\n"
            << "Phase 2 -- Relay (t=" << RELAY_START_S << "s):\n"
            << "  Fake TLLDP=" << TLLDP_RELAY_FAKE_MS
            << "  Tl=" << TLLDP_RELAY_FAKE_MS << "-"
            << PROBE_RTT_OVERLOADED_MS << "-" << PROBE_RTT_OVERLOADED_MS << "="
            << (TLLDP_RELAY_FAKE_MS - 2.0*PROBE_RTT_OVERLOADED_MS)
            << " ms (NEGATIVE => passes Th)\n\n";
    } else if (g_attack_scenario == 17) {
        g_attack_log
            << "Attack type: RELAY ONLY (no overload)\n"
            << "Expected: TopoGuard+ DETECTS (Tl=19ms > Th=4ms)\n\n"
            << "  Relay Tl = " << TLLDP_RELAY_FAKE_MS << " - 2*"
            << PROBE_RTT_NORMAL_MS << " = "
            << (TLLDP_RELAY_FAKE_MS - 2.0*PROBE_RTT_NORMAL_MS)
            << " ms > Th=" << TL_LEGIT_BASELINE_MS << " ms => BLOCKED\n\n";
    } else if (g_attack_scenario == 18) {
        g_attack_log
            << "Attack type: BASIC LFA (direct data-plane injection)\n"
            << "Expected: TopoGuard+ DETECTS (Tl=14ms > Th=4ms)\n"
            << "          MLLG DETECTS (Tl=14ms > MLLG_TL_HIGH=" << MLLG_TL_HIGH_MS << "ms)\n\n"
            << "  Attacker path: CTRL->s1->h1->s3->CTRL\n"
            << "  TLLDP_basic = 2*" << CTRL_TO_SW_MS << " + " << HOST_SW_DELAY_MS
            << " + 2*" << SW_TO_SW_DELAY_MS << " = " << TLLDP_BASIC_FAKE_MS << " ms\n"
            << "  Tl = " << TLLDP_BASIC_FAKE_MS << " - 2*" << PROBE_RTT_NORMAL_MS
            << " = " << (TLLDP_BASIC_FAKE_MS - 2.0*PROBE_RTT_NORMAL_MS)
            << " ms > Th=" << TL_LEGIT_BASELINE_MS << " ms => BLOCKED\n\n";
    } else if (g_attack_scenario == 19) {
        g_attack_log
            << "Attack type: GRADUAL LFA (incremental Tl inflation + relay)\n"
            << "Expected: TopoGuard+ FAILS after Th inflated to 20ms, MLLG DETECTS (Th drift)\n\n"
            << "Phase 1 -- Gradual injection (t=" << GRADUAL_START_S << "s, every "
            << LLDP_INTERVAL_S << "s, 5 batches of 3):\n"
            << "  Batch 1 (t=10s): inject Tl=5ms x3 -> Th stays ~4ms\n"
            << "  Batch 2 (t=15s): inject Tl=6ms x3 -> Th rises to ~8ms [MLLG drift]\n"
            << "  Batch 3 (t=20s): inject Tl=7ms x3 -> Th rises to ~12ms [MLLG drift]\n"
            << "  Batch 4 (t=25s): inject Tl=8ms x3 -> Th rises to ~16ms [MLLG drift]\n"
            << "  Batch 5 (t=30s): inject Tl=9ms x3 -> Th rises to ~20ms [MLLG drift+HIGH_TL]\n\n"
            << "Phase 2 -- Relay (t=" << GRADUAL_RELAY_S << "s):\n"
            << "  Relay Tl = " << (TLLDP_RELAY_FAKE_MS - 2.0*PROBE_RTT_NORMAL_MS)
            << " ms < Th=20ms => TopoGuard+ PASSES (ATTACK SUCCEEDS)\n"
            << "  MLLG: Tl=19ms > MLLG_TL_HIGH=" << MLLG_TL_HIGH_MS << "ms => DETECTED\n\n";
    } else {
        g_attack_log
            << "Attack type: BASELINE (no attack)\n"
            << "Expected: All events LEGIT, no alarms\n\n";
    }

    g_attack_log << "Simulation time: " << g_simTime << " s\n"
                 << "LLDP interval:   " << LLDP_INTERVAL_S << " s\n"
                 << "Topology: s1 -- s2 -- s3  (s1<->s3 has NO physical link)\n"
                 << "MLLG thresholds: TP_max=" << MLLG_TP_THRESHOLD_MS
                 << "ms  TL_high=" << MLLG_TL_HIGH_MS
                 << "ms  Th_drift=" << MLLG_TH_DRIFT_MS << "ms\n"
                 << "-------------------------------------------------\n\n";

    g_events_csv.open("lla_events.csv");
    g_events_csv << "sim_time_s,event_type,sw1_id,sw2_id,"
                 << "tl_ms,th_ms,tp1_ms,tp2_ms,"
                 << "topoguard_alarm,mllg_alarm,mllg_reason,is_attack_event\n";

    std::cout << "[LLA] Logs initialised: " << log_name << ", lla_events.csv\n";
}

// ── Mobility setup ────────────────────────────────────────────────────────

static void SetupMobility()
{
    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> sw_pos = CreateObject<ListPositionAllocator>();
    sw_pos->Add(Vector(0.0,    0.0, 0.0));
    sw_pos->Add(Vector(500.0,  0.0, 0.0));
    sw_pos->Add(Vector(1000.0, 0.0, 0.0));
    mob.SetPositionAllocator(sw_pos);
    mob.Install(g_Switch_Nodes);

    Ptr<ListPositionAllocator> h_pos = CreateObject<ListPositionAllocator>();
    h_pos->Add(Vector(0.0,    50.0,  0.0));  // h1 (compromised, at s1)
    h_pos->Add(Vector(1000.0, 50.0,  0.0));  // h2 (compromised, at s3)
    h_pos->Add(Vector(500.0,  50.0,  0.0));  // h3 at s2
    h_pos->Add(Vector(500.0, -50.0,  0.0));  // h4 at s2
    h_pos->Add(Vector(0.0,   -50.0,  0.0));  // h5 at s1
    h_pos->Add(Vector(1000.0,-50.0,  0.0));  // h6 at s3
    mob.SetPositionAllocator(h_pos);
    mob.Install(g_Host_Nodes);

    Ptr<ListPositionAllocator> c_pos = CreateObject<ListPositionAllocator>();
    c_pos->Add(Vector(500.0, 300.0, 0.0));
    mob.SetPositionAllocator(c_pos);
    mob.Install(g_Controller_Nodes);
}

// ── Pre-populate Tl history so Th is meaningful from simulation start ─────

static void PrePopulateHistory()
{
    // Fill with TL_LEGIT_BASELINE_MS = 4ms (= TLLDP_LEGIT - 2*PROBE_RTT_NORMAL)
    // -> Q1=Q3=4ms -> Th = 4ms initially
    for (uint32_t i = 0; i < TL_HISTORY_DEPTH; i++)
        g_tl_history.push_back(TL_LEGIT_BASELINE_MS);

    g_prev_th = ComputeThreshold(g_tl_history);  // = 4.0 ms
}

// ── main ──────────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    CommandLine cmd;
    cmd.AddValue("simTime",
                 "Simulation time (s)",
                 g_simTime);
    cmd.AddValue("attack_scenario",
                 "0=baseline, 16=full LLA, 17=relay only, 18=basic LFA, 19=gradual LFA",
                 g_attack_scenario);
    cmd.Parse(argc, argv);

    // Create nodes
    g_Switch_Nodes.Create(3);
    g_Host_Nodes.Create(6);
    g_Controller_Nodes.Create(1);

    SetupMobility();
    PrePopulateHistory();
    LLA_InitLogs();

    g_attack_log << "NODE MAP:\n"
                 << "  s1=node" << g_Switch_Nodes.Get(0)->GetId()
                 << "  s2=node" << g_Switch_Nodes.Get(1)->GetId()
                 << "  s3=node" << g_Switch_Nodes.Get(2)->GetId() << "\n"
                 << "  h1=node" << g_Host_Nodes.Get(0)->GetId()
                 << " (compromised, at s1)"
                 << "  h2=node" << g_Host_Nodes.Get(1)->GetId()
                 << " (compromised, at s3)\n"
                 << "  ctrl=node" << g_Controller_Nodes.Get(0)->GetId() << "\n\n"
                 << "Initial Th = " << g_prev_th << " ms  (pre-populated "
                 << TL_HISTORY_DEPTH << "x" << TL_LEGIT_BASELINE_MS << "ms)\n\n"
                 << "-------------------------------------------------\n\n";

    // ── Schedule legitimate LLDP ticks ────────────────────────────────────
    double lldp_start = 1.0;
    if (lldp_start < g_simTime)
        Simulator::Schedule(Seconds(lldp_start), &LLA_LLDPTick, g_simTime - 0.5);

    // ── Scenario-specific event scheduling ────────────────────────────────

    if (g_attack_scenario == 16) {
        // Full LLA: overload + relay
        if (OVERLOAD_START_S < g_simTime)
            Simulator::Schedule(Seconds(OVERLOAD_START_S), &LLA_OverloadBegin);
        if (OVERLOAD_END_S < g_simTime)
            Simulator::Schedule(Seconds(OVERLOAD_END_S),   &LLA_OverloadEnd);
        // Note: relay is handled inside LLA_LLDPTick() for scenarios 16/17

    } else if (g_attack_scenario == 17) {
        // Relay only — no extra scheduling needed (LLA_LLDPTick handles it)

    } else if (g_attack_scenario == 18) {
        // Basic LFA: single injection at RELAY_START_S
        if (RELAY_START_S < g_simTime)
            Simulator::Schedule(Seconds(RELAY_START_S), &LLA_BasicLFA);

    } else if (g_attack_scenario == 19) {
        // Gradual LFA: 5 batches of 3 injections + final relay
        // Injection values: 5, 6, 7, 8, 9 ms (incrementing each batch)
        const double GRADUAL_BASE_TL = 5.0;
        const uint32_t BATCHES = 5;
        const uint32_t PER_BATCH = 3;

        for (uint32_t batch = 0; batch < BATCHES; batch++) {
            double t_inj  = GRADUAL_START_S + batch * LLDP_INTERVAL_S;  // 10,15,20,25,30s
            double fake_tl = GRADUAL_BASE_TL + static_cast<double>(batch); // 5,6,7,8,9ms
            for (uint32_t k = 0; k < PER_BATCH; k++) {
                double t_k = t_inj + 0.1 * static_cast<double>(k);
                if (t_k < g_simTime)
                    Simulator::Schedule(Seconds(t_k),
                                        &LLA_GradualLFA_Inject, fake_tl);
            }
        }

        // Final relay at GRADUAL_RELAY_S — succeeds because Th has been inflated
        if (GRADUAL_RELAY_S < g_simTime)
            Simulator::Schedule(Seconds(GRADUAL_RELAY_S), &LLA_RelayLLDP);
    }

    // ── Write summary at end ───────────────────────────────────────────────
    Simulator::Schedule(Seconds(g_simTime - 0.01), &LLA_WriteSummary);

    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();

    g_attack_log.close();
    g_events_csv.close();

    std::cout << "[LLA] Simulation complete"
              << "  scenario=" << g_attack_scenario
              << "  simTime=" << g_simTime << "s\n"
              << "[LLA] Fake link accepted: " << (g_fake_link_accepted ? "YES" : "NO") << "\n"
              << "[LLA] Initial Th = 4ms  |  Final Th = "
              << ComputeThreshold(g_tl_history) << " ms\n";

    return 0;
}
