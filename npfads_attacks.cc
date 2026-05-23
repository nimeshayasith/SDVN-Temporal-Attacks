// ── npfads_attacks.cc ──────────────────────────────────────────────────────────
// Standalone NS-3 simulation of IoV position falsification attacks
// Based on: Ilango, Ma & Su (2022), Eng. Applications of AI 116, 105380
//
// Place in ns-3.35/scratch/npfads_attacks.cc
// Build:  cd ~/ns-3.35 && ./waf build
// Run:    ./waf --run "scratch/npfads_attacks --attack_type=1 --N_Vehicles=20 --N_Attackers=4"
//
// Attack type IDs (matching VeReMi dataset label convention):
//   0  = Benign (no attack)
//   1  = Type 1: Constant fixed position (5560, 5820)
//   2  = Type 2: Constant offset (+250, -150) added to true position
//   4  = Type 4: Fully random position across playground
//   8  = Type 8: Bounded random offset (±300 m) from true position
//   16 = Type 16: Eventual stop (freeze probability increases +0.025 per beacon)
//   31 = All types mixed (attackers assigned types round-robin: 1,2,4,8,16,1,2,…)
//
// Output CSV files:
//   npfads_bsm_log.csv      — every BSM with ground-truth label and true position
//   npfads_eigenvalues.csv  — per-sender mobility matrix eigenvalues (preprocessing)
//   npfads_metrics.csv      — precision / recall / F1 per attack type

#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace ns3;

// ── Attack type IDs ───────────────────────────────────────────────────────────
static const int BENIGN  = 0;
static const int TYPE_1  = 1;
static const int TYPE_2  = 2;
static const int TYPE_4  = 4;
static const int TYPE_8  = 8;
static const int TYPE_16 = 16;

// ── Playground bounds (metres) — matching VeReMi simulation defaults ──────────
static const double X_MIN = 0.0;
static const double X_MAX = 10000.0;
static const double Y_MIN = 0.0;
static const double Y_MAX = 10000.0;

// ── Paper-specified attack parameters ─────────────────────────────────────────
static const double TYPE1_XPOS      = 5560.0;   // fixed broadcast position
static const double TYPE1_YPOS      = 5820.0;
static const double TYPE2_DX        =  250.0;   // constant offset
static const double TYPE2_DY        = -150.0;
static const double TYPE8_BOUND     =  300.0;   // random offset bound (metres)
static const double TYPE16_PROB_INC =    0.025; // stop-probability increment per BSM

// Minimum BSMs per sender required to include in eigenvalue analysis
static const int MIN_BSMS = 8;

// ── Data structures ───────────────────────────────────────────────────────────

struct BSMRecord {
    double   sendTime;
    uint32_t senderId;
    double   xPos, yPos;        // reported (possibly falsified) position
    double   xSpd, ySpd;        // velocity — attackers do not falsify speed
    double   xAcc, yAcc;        // derived: ΔV / Δt from consecutive BSMs
    int      attackType;         // ground-truth label (BENIGN / TYPE_N)
    double   trueXPos, trueYPos; // actual position from MobilityModel
};

struct AttackerState {           // per-node mutable state for Type 16
    double stopProb    = 0.0;
    double frozenXPos  = 0.0;
    double frozenYPos  = 0.0;
    bool   initialized = false;
};

// ── Global simulation state ───────────────────────────────────────────────────
static std::vector<BSMRecord>            g_bsmLog;
static std::map<uint32_t, BSMRecord>     g_lastBSM;
static std::map<uint32_t, AttackerState> g_attackerState;
static std::map<uint32_t, int>           g_nodeAttackType;  // 0 = benign, else TYPE_N
static Ptr<UniformRandomVariable>        g_rng;
static NodeContainer                     g_nodes;
static NetDeviceContainer                g_waveDevices;
static std::set<std::pair<uint32_t,double>> g_loggedBSMs;  // (senderId, sendTime) dedup

// Simulation parameters (set in main, read by callbacks)
static double   g_beaconInterval = 0.1;   // seconds
static double   g_simTime        = 120.0; // seconds

// ── NPFADSBSMTag — NS-3 packet tag carrying one BSM over DSRC ─────────────────
// Models the same role as CustomDataTag1 in routing.cc, but restricted to the
// fields that travel over the air.  Only m_xPos / m_yPos carry falsified values;
// velocity is always true.  Acceleration is NOT in the tag — receivers derive it
// from successive velocity deltas and store it in BSMRecord.
// Serialized layout: 4 + 5×8 + 4 = 48 bytes.
class NPFADSBSMTag : public Tag
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::NPFADSBSMTag")
                                .SetParent<Tag>()
                                .AddConstructor<NPFADSBSMTag>();
        return tid;
    }
    TypeId GetInstanceTypeId() const override { return GetTypeId(); }

    uint32_t GetSerializedSize() const override { return 48; }

    void Serialize(TagBuffer buf) const override
    {
        buf.WriteU32(m_nodeId);
        buf.WriteDouble(m_sendTime);
        buf.WriteDouble(m_xPos);
        buf.WriteDouble(m_yPos);
        buf.WriteDouble(m_xSpd);
        buf.WriteDouble(m_ySpd);
        buf.WriteU32(static_cast<uint32_t>(m_attackType));
    }

    void Deserialize(TagBuffer buf) override
    {
        m_nodeId     = buf.ReadU32();
        m_sendTime   = buf.ReadDouble();
        m_xPos       = buf.ReadDouble();
        m_yPos       = buf.ReadDouble();
        m_xSpd       = buf.ReadDouble();
        m_ySpd       = buf.ReadDouble();
        m_attackType = static_cast<int>(buf.ReadU32());
    }

    void Print(std::ostream& os) const override
    {
        os << "NPFADSBSMTag[id=" << m_nodeId
           << " t=" << m_sendTime
           << " pos=(" << m_xPos << "," << m_yPos << ")"
           << " type=" << m_attackType << "]";
    }

    void SetNodeId(uint32_t v)           { m_nodeId = v; }
    void SetSendTime(double v)           { m_sendTime = v; }
    void SetPosition(double x, double y) { m_xPos = x; m_yPos = y; }
    void SetVelocity(double x, double y) { m_xSpd = x; m_ySpd = y; }
    void SetAttackType(int v)            { m_attackType = v; }

    uint32_t GetNodeId()     const { return m_nodeId; }
    double   GetSendTime()   const { return m_sendTime; }
    double   GetXPos()       const { return m_xPos; }
    double   GetYPos()       const { return m_yPos; }
    double   GetXSpd()       const { return m_xSpd; }
    double   GetYSpd()       const { return m_ySpd; }
    int      GetAttackType() const { return m_attackType; }

private:
    uint32_t m_nodeId     = 0;
    double   m_sendTime   = 0.0;
    double   m_xPos       = 0.0;   // falsified for attackers; true for benign nodes
    double   m_yPos       = 0.0;
    double   m_xSpd       = 0.0;
    double   m_ySpd       = 0.0;
    int      m_attackType = 0;
};

// ── Position falsification ────────────────────────────────────────────────────
// Returns the position that the attacker broadcasts; benign nodes return truePos.
static Vector FalsifyPosition(uint32_t nodeId, int attackType, const Vector& truePos)
{
    switch (attackType) {
    case TYPE_1:
        // Always broadcast the same fixed coordinates regardless of true location
        return Vector(TYPE1_XPOS, TYPE1_YPOS, truePos.z);

    case TYPE_2:
        // Add a constant offset; movement pattern is preserved → hardest to detect
        return Vector(truePos.x + TYPE2_DX, truePos.y + TYPE2_DY, truePos.z);

    case TYPE_4:
        // Broadcast fully random coordinates across the playground
        return Vector(g_rng->GetValue(X_MIN, X_MAX),
                      g_rng->GetValue(Y_MIN, Y_MAX),
                      truePos.z);

    case TYPE_8:
        // Add a bounded random offset each beacon cycle
        return Vector(truePos.x + g_rng->GetValue(-TYPE8_BOUND, TYPE8_BOUND),
                      truePos.y + g_rng->GetValue(-TYPE8_BOUND, TYPE8_BOUND),
                      truePos.z);

    case TYPE_16: {
        AttackerState& s = g_attackerState[nodeId];
        if (!s.initialized) {
            s.frozenXPos  = truePos.x;
            s.frozenYPos  = truePos.y;
            s.stopProb    = 0.0;
            s.initialized = true;
        }
        Vector result;
        if (g_rng->GetValue(0.0, 1.0) < s.stopProb) {
            // Freeze: broadcast the last-known frozen position
            result = Vector(s.frozenXPos, s.frozenYPos, truePos.z);
        } else {
            // Still moving: advance the frozen-position target to current true location
            s.frozenXPos = truePos.x;
            s.frozenYPos = truePos.y;
            result       = truePos;
        }
        // Increment stop probability after every BSM (capped at 1.0)
        s.stopProb = std::min(s.stopProb + TYPE16_PROB_INC, 1.0);
        return result;
    }

    default:  // BENIGN or unrecognised
        return truePos;
    }
}

// ── BSM generation callback (self-rescheduling) ───────────────────────────────
// Sender responsibility: falsify position and broadcast over DSRC.
// Logging is done entirely by OnBSMReceived on the receiver side.
static void GenerateBSM(uint32_t nodeId)
{
    double now = Simulator::Now().GetSeconds();
    if (now >= g_simTime || nodeId >= g_nodes.GetN()) return;

    Ptr<MobilityModel> mob = g_nodes.Get(nodeId)->GetObject<MobilityModel>();
    Vector truePos = mob ? mob->GetPosition() : Vector(0, 0, 0);
    Vector vel     = mob ? mob->GetVelocity()  : Vector(0, 0, 0);

    int    atype       = g_nodeAttackType.count(nodeId) ? g_nodeAttackType.at(nodeId) : BENIGN;
    Vector reportedPos = FalsifyPosition(nodeId, atype, truePos);

    // Build and broadcast the BSM tag — only reported (falsified) position and
    // true velocity travel over the air.  Acceleration is derived by receivers.
    Ptr<WifiNetDevice> wdev = DynamicCast<WifiNetDevice>(g_waveDevices.Get(nodeId));
    if (wdev) {
        NPFADSBSMTag bsmTag;
        bsmTag.SetNodeId(nodeId);
        bsmTag.SetSendTime(now);
        bsmTag.SetPosition(reportedPos.x, reportedPos.y);
        bsmTag.SetVelocity(vel.x, vel.y);
        bsmTag.SetAttackType(atype);
        Ptr<Packet> pkt = Create<Packet>(0);
        pkt->AddPacketTag(bsmTag);
        wdev->Send(pkt, Mac48Address::GetBroadcast(), 0x88dc);
    }

    Simulator::Schedule(Seconds(g_beaconInterval), &GenerateBSM, nodeId);
}

// ── BSM receive callback ──────────────────────────────────────────────────────
// Installed on every vehicle node.  Runs when a DSRC packet arrives.
// Populates g_bsmLog; derives acceleration from velocity deltas; adds true
// position (a simulation-only privilege — the real detector cannot know this,
// but we need it for ground-truth CSV output and eigenvalue analysis).
static bool OnBSMReceived(Ptr<NetDevice> /*dev*/,
                           Ptr<const Packet> packet,
                           uint16_t          /*protocol*/,
                           const Address&    /*src*/)
{
    NPFADSBSMTag tag;
    if (!packet->PeekPacketTag(tag)) return true;

    uint32_t senderId = tag.GetNodeId();
    double   sendTime = tag.GetSendTime();

    // First receiver to see this BSM logs it; all others discard the duplicate
    auto key = std::make_pair(senderId, sendTime);
    if (g_loggedBSMs.count(key)) return true;
    g_loggedBSMs.insert(key);

    // Derive acceleration from velocity delta vs the previous logged BSM
    double xAcc = 0.0, yAcc = 0.0;
    auto prevIt = g_lastBSM.find(senderId);
    if (prevIt != g_lastBSM.end()) {
        double dt = sendTime - prevIt->second.sendTime;
        if (dt > 1e-9) {
            xAcc = (tag.GetXSpd() - prevIt->second.xSpd) / dt;
            yAcc = (tag.GetYSpd() - prevIt->second.ySpd) / dt;
        }
    }

    // True position — only available because this is a simulation
    double trueX = 0.0, trueY = 0.0;
    if (senderId < g_nodes.GetN()) {
        Ptr<MobilityModel> mob = g_nodes.Get(senderId)->GetObject<MobilityModel>();
        if (mob) {
            Vector tp = mob->GetPosition();
            trueX = tp.x;
            trueY = tp.y;
        }
    }

    BSMRecord r;
    r.sendTime  = sendTime;
    r.senderId  = senderId;
    r.xPos      = tag.GetXPos();    // falsified position (what the network sees)
    r.yPos      = tag.GetYPos();
    r.xSpd      = tag.GetXSpd();
    r.ySpd      = tag.GetYSpd();
    r.xAcc      = xAcc;
    r.yAcc      = yAcc;
    r.attackType = tag.GetAttackType();
    r.trueXPos  = trueX;
    r.trueYPos  = trueY;

    g_bsmLog.push_back(r);
    g_lastBSM[senderId] = r;

    return true;
}

// ── Matrix algebra ────────────────────────────────────────────────────────────
using Mat7 = std::array<std::array<double, 7>, 7>;

// Subtract column means in-place (step 2 of paper's preprocessing pipeline)
static void CenterColumns(std::vector<std::array<double, 7>>& M)
{
    if (M.empty()) return;
    double n = static_cast<double>(M.size());
    for (int c = 0; c < 7; ++c) {
        double sum = 0.0;
        for (const auto& row : M) sum += row[c];
        double mean = sum / n;
        for (auto& row : M) row[c] -= mean;
    }
}

// Compute A = M^T * M  (7×7 symmetric positive semi-definite)
// Non-zero eigenvalues of A equal those of M * M^T, but A is far smaller (7×7 vs n×n).
static Mat7 TransposeMultiply(const std::vector<std::array<double, 7>>& M)
{
    Mat7 A{};
    for (auto& row : A) row.fill(0.0);
    for (const auto& row : M)
        for (int i = 0; i < 7; ++i)
            for (int j = 0; j < 7; ++j)
                A[i][j] += row[i] * row[j];
    return A;
}

// Jacobi eigenvalue algorithm for symmetric 7×7 matrix.
// Returns eigenvalues sorted descending.
// Uses a relative convergence criterion to handle large column magnitudes.
static std::array<double, 7> JacobiEigenvalues(Mat7 A,
                                                int    maxIter = 5000,
                                                double relTol  = 1e-10)
{
    const int N = 7;

    // Compute initial off-diagonal Frobenius norm for relative tolerance
    double initNorm = 0.0;
    for (int i = 0; i < N; ++i)
        for (int j = i + 1; j < N; ++j)
            initNorm += A[i][j] * A[i][j];
    initNorm = std::sqrt(initNorm);
    double absTol = (initNorm < 1.0) ? relTol : relTol * initNorm;

    for (int iter = 0; iter < maxIter; ++iter) {
        // Locate the largest off-diagonal element
        int    p = 0, q = 1;
        double maxOff = std::abs(A[0][1]);
        for (int i = 0; i < N; ++i)
            for (int j = i + 1; j < N; ++j)
                if (std::abs(A[i][j]) > maxOff) {
                    maxOff = std::abs(A[i][j]);
                    p = i; q = j;
                }

        if (maxOff < absTol) break;

        // Rotation angle that zeros A[p][q]
        double diff  = A[q][q] - A[p][p];
        double theta = (std::abs(diff) < 1e-14) ? (M_PI / 4.0)
                                                 : (0.5 * std::atan2(2.0 * A[p][q], diff));
        double c = std::cos(theta);
        double s = std::sin(theta);

        // Update the (p, p), (q, q), and (p, q) entries
        double App = A[p][p], Aqq = A[q][q], Apq = A[p][q];
        A[p][p] = c*c*App - 2.0*s*c*Apq + s*s*Aqq;
        A[q][q] = s*s*App + 2.0*s*c*Apq + c*c*Aqq;
        A[p][q] = A[q][p] = 0.0;

        // Update the remaining row/column pairs
        for (int i = 0; i < N; ++i) {
            if (i == p || i == q) continue;
            double Aip = A[i][p], Aiq = A[i][q];
            A[i][p] = A[p][i] = c*Aip - s*Aiq;
            A[i][q] = A[q][i] = s*Aip + c*Aiq;
        }
    }

    std::array<double, 7> eigs;
    for (int i = 0; i < N; ++i) eigs[i] = A[i][i];
    std::sort(eigs.begin(), eigs.end(),
              [](double a, double b) { return a > b; });
    return eigs;
}

// ── Post-processing ────────────────────────────────────────────────────────────
// Runs after Simulator::Run() completes.  Writes three CSV files.
static void PostProcess(const std::string& outputDir)
{
    // ── 1. Write raw BSM log ────────────────────────────────────────────────
    {
        std::ofstream f(outputDir + "/npfads_bsm_log.csv");
        f << std::fixed << std::setprecision(6);
        f << "sendTime,senderId,xPos,yPos,xSpd,ySpd,xAcc,yAcc,"
             "attackType,trueXPos,trueYPos\n";
        for (const auto& r : g_bsmLog) {
            f << r.sendTime  << "," << r.senderId
              << "," << r.xPos    << "," << r.yPos
              << "," << r.xSpd    << "," << r.ySpd
              << "," << r.xAcc    << "," << r.yAcc
              << "," << r.attackType
              << "," << r.trueXPos << "," << r.trueYPos << "\n";
        }
        NS_LOG_UNCOND("[NPFADS] BSM log -> " << outputDir << "/npfads_bsm_log.csv"
                      << "  (" << g_bsmLog.size() << " records)");
    }

    // ── 2. Group BSMs by sender and build eigenvalue records ──────────────
    std::map<uint32_t, std::vector<BSMRecord>> bySender;
    for (const auto& r : g_bsmLog) bySender[r.senderId].push_back(r);

    struct EigRecord {
        uint32_t              senderId;
        std::array<double, 7> eigs;
        int                   attackType;
        size_t                nBsms;
        double                posVar;  // A[1][1] + A[2][2]: xPos + yPos column variance
    };
    std::vector<EigRecord> eigRecs;

    for (auto& kv : bySender) {
        const auto& bsms = kv.second;
        if ((int)bsms.size() < MIN_BSMS) continue;

        // Build mobility matrix: row k = [sendTime, xPos, yPos, xSpd, ySpd, xAcc, yAcc]
        std::vector<std::array<double, 7>> M;
        M.reserve(bsms.size());
        for (const auto& r : bsms)
            M.push_back({r.sendTime, r.xPos, r.yPos,
                         r.xSpd,    r.ySpd,
                         r.xAcc,    r.yAcc});

        CenterColumns(M);
        Mat7   A    = TransposeMultiply(M);
        double pv   = A[1][1] + A[2][2];  // variance in xPos and yPos columns
        auto   eigs = JacobiEigenvalues(A);

        // All BSMs from a single sender share the same attack type
        eigRecs.push_back({kv.first, eigs, bsms.front().attackType, bsms.size(), pv});
    }

    // ── 3. Write eigenvalue dataset ────────────────────────────────────────
    {
        std::ofstream f(outputDir + "/npfads_eigenvalues.csv");
        f << std::fixed << std::setprecision(6);
        f << "senderId,lambda1,lambda2,lambda3,lambda4,lambda5,lambda6,lambda7,"
             "attackType,n_bsms\n";
        for (const auto& er : eigRecs) {
            f << er.senderId;
            for (double e : er.eigs) f << "," << e;
            f << "," << er.attackType << "," << er.nBsms << "\n";
        }
        NS_LOG_UNCOND("[NPFADS] Eigenvalue dataset -> " << outputDir
                      << "/npfads_eigenvalues.csv  (" << eigRecs.size() << " senders)");
    }

    // ── 4. Anomaly scoring and metrics ─────────────────────────────────────
    //
    // Anomaly score = | log1p(posVar_i) - mean_log1p(posVar_benign) |
    //
    // This measures how far the observed position-column variance deviates
    // from what benign senders produce.  The sign-agnostic absolute value
    // means both near-zero posVar (Type 1, Type 16) and huge posVar
    // (Type 4, Type 8) score high.  Type 2 — whose offset is erased by
    // column centering — scores near zero, correctly reflecting the paper's
    // finding that it is the hardest attack to detect.

    // Mean log1p(posVar) for benign senders
    double benignLogMean = 0.0;
    int    nBenign       = 0;
    for (const auto& er : eigRecs) {
        if (er.attackType == BENIGN) {
            benignLogMean += std::log1p(er.posVar);
            ++nBenign;
        }
    }
    if (nBenign > 0) benignLogMean /= nBenign;

    struct SenderScore {
        uint32_t sid;
        double   score;
        int      attackType;
    };
    std::vector<SenderScore> sScores;
    sScores.reserve(eigRecs.size());
    for (const auto& er : eigRecs)
        sScores.push_back({er.senderId,
                           std::abs(std::log1p(er.posVar) - benignLogMean),
                           er.attackType});

    // Separate benign scores for the threshold sweep
    std::vector<const SenderScore*> benignPtrs;
    for (const auto& ss : sScores)
        if (ss.attackType == BENIGN) benignPtrs.push_back(&ss);

    // Collect attack types present
    std::set<int> attackTypes;
    for (const auto& ss : sScores)
        if (ss.attackType != BENIGN) attackTypes.insert(ss.attackType);

    // ── 5. Write metrics CSV ───────────────────────────────────────────────
    {
        std::ofstream f(outputDir + "/npfads_metrics.csv");
        f << std::fixed << std::setprecision(6);
        f << "attack_type,n_attackers,n_benign,TP,FP,FN,TN,"
             "precision,recall,f1,opt_threshold\n";

        for (int atype : attackTypes) {
            // Collect pointers to this attack type's scores
            std::vector<const SenderScore*> atkPtrs;
            for (const auto& ss : sScores)
                if (ss.attackType == atype) atkPtrs.push_back(&ss);

            // Build sorted threshold candidates from this (benign + attack) subset
            std::vector<double> candidates;
            for (auto* p : benignPtrs)  candidates.push_back(p->score);
            for (auto* p : atkPtrs)     candidates.push_back(p->score);
            std::sort(candidates.begin(), candidates.end());
            candidates.erase(
                std::unique(candidates.begin(), candidates.end()),
                candidates.end());

            // Sweep threshold: classify as attack if score > threshold
            int    bestTP = 0, bestFP = 0, bestFN = 0, bestTN = 0;
            double bestF1 = -1.0, bestThresh = 0.0;

            for (double thresh : candidates) {
                int tp = 0, fp = 0, fn = 0, tn = 0;
                for (auto* p : benignPtrs)
                    (p->score > thresh ? fp : tn)++;
                for (auto* p : atkPtrs)
                    (p->score > thresh ? tp : fn)++;

                double prec = (tp + fp > 0) ? (double)tp / (tp + fp) : 0.0;
                double rec  = (tp + fn > 0) ? (double)tp / (tp + fn) : 0.0;
                double f1   = (prec + rec > 0) ? 2.0 * prec * rec / (prec + rec) : 0.0;
                if (f1 > bestF1) {
                    bestF1 = f1; bestThresh = thresh;
                    bestTP = tp; bestFP = fp; bestFN = fn; bestTN = tn;
                }
            }

            double prec = (bestTP + bestFP > 0) ? (double)bestTP / (bestTP + bestFP) : 0.0;
            double rec  = (bestTP + bestFN > 0) ? (double)bestTP / (bestTP + bestFN) : 0.0;

            f << atype
              << "," << atkPtrs.size()
              << "," << benignPtrs.size()
              << "," << bestTP << "," << bestFP << "," << bestFN << "," << bestTN
              << "," << prec << "," << rec << "," << bestF1 << "," << bestThresh << "\n";

            NS_LOG_UNCOND("[NPFADS] Type " << std::setw(2) << atype
                          << " | attackers=" << std::setw(3) << atkPtrs.size()
                          << "  P=" << std::setprecision(3) << prec
                          << "  R=" << rec
                          << "  F1=" << bestF1);
        }

        NS_LOG_UNCOND("[NPFADS] Metrics -> " << outputDir << "/npfads_metrics.csv");
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    uint32_t    nVehicles  = 20;
    uint32_t    nAttackers = 4;
    int         attackType = TYPE_1;
    uint32_t    seed       = 42;
    std::string outputDir  = ".";

    CommandLine cmd;
    cmd.AddValue("simTime",
                 "Simulation duration (s)",
                 g_simTime);
    cmd.AddValue("N_Vehicles",
                 "Total vehicle node count",
                 nVehicles);
    cmd.AddValue("N_Attackers",
                 "Attacker count; first N nodes are attackers",
                 nAttackers);
    cmd.AddValue("attack_type",
                 "Attack variant: 0=benign 1 2 4 8 16 31=all-mixed (other values are rejected)",
                 attackType);
    cmd.AddValue("beacon_interval",
                 "BSM generation period (s)",
                 g_beaconInterval);
    cmd.AddValue("seed",
                 "RNG seed",
                 seed);
    cmd.AddValue("output_dir",
                 "Directory for output CSV files",
                 outputDir);
    cmd.Parse(argc, argv);

    // Validate attack_type: only the five VeReMi types (plus 0 and 31) are valid
    {
        static const int kValid[] = {0, 1, 2, 4, 8, 16, 31};
        bool ok = false;
        for (int v : kValid) if (attackType == v) { ok = true; break; }
        NS_ABORT_MSG_IF(!ok,
            "Invalid --attack_type=" << attackType
            << ".  Choose from: 0 1 2 4 8 16 31");
    }

    if (nAttackers > nVehicles) nAttackers = nVehicles;

    SeedManager::SetSeed(seed);
    SeedManager::SetRun(1);

    g_rng = CreateObject<UniformRandomVariable>();

    // Create vehicle nodes
    g_nodes.Create(nVehicles);

    // Install RandomWaypoint mobility across the playground
    ObjectFactory posFactory;
    posFactory.SetTypeId("ns3::RandomRectanglePositionAllocator");
    posFactory.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=10000.0]"));
    posFactory.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=10000.0]"));
    Ptr<PositionAllocator> posAlloc = posFactory.Create()->GetObject<PositionAllocator>();

    MobilityHelper mobility;
    mobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed",             StringValue("ns3::UniformRandomVariable[Min=10.0|Max=30.0]"),
        "Pause",             StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
        "PositionAllocator", PointerValue(posAlloc));
    mobility.SetPositionAllocator(posAlloc);
    mobility.Install(g_nodes);

    // Install 802.11p DSRC radio on all vehicle nodes (CCH channel 178, 5.89 GHz)
    // Range capped at 300 m via RangePropagationLossModel — matches routing.cc TTW_COMM_RANGE.
    YansWifiChannelHelper wifiCh = YansWifiChannelHelper::Default();
    wifiCh.AddPropagationLoss("ns3::RangePropagationLossModel",
                              "MaxRange", DoubleValue(300.0));
    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
    wifiPhy.SetChannel(wifiCh.Create());
    wifiPhy.Set("TxPowerStart", DoubleValue(33.5));
    wifiPhy.Set("TxPowerEnd",   DoubleValue(33.5));
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::OcbWifiMac");
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",    StringValue("OfdmRate6MbpsBW10MHz"),
                                 "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));
    g_waveDevices = wifi.Install(wifiPhy, wifiMac, g_nodes);

    // Register the receive callback on every node so that OnBSMReceived fires
    // whenever a DSRC packet arrives within 300 m range
    for (uint32_t i = 0; i < nVehicles; ++i)
        g_waveDevices.Get(i)->SetReceiveCallback(MakeCallback(&OnBSMReceived));

    // Assign attack types: nodes 0..(nAttackers-1) are attackers; rest are benign.
    // attack_type=31 assigns types 1,2,4,8,16 round-robin across attackers.
    static const int kTypeRoundRobin[5] = {TYPE_1, TYPE_2, TYPE_4, TYPE_8, TYPE_16};
    for (uint32_t i = 0; i < nVehicles; ++i) {
        if (i < nAttackers)
            g_nodeAttackType[i] = (attackType == 31)
                                      ? kTypeRoundRobin[i % 5]
                                      : attackType;
        else
            g_nodeAttackType[i] = BENIGN;
    }

    NS_LOG_UNCOND("[NPFADS] Starting simulation"
                  << "  simTime="        << g_simTime        << "s"
                  << "  N_Vehicles="     << nVehicles
                  << "  N_Attackers="    << nAttackers
                  << "  attack_type="    << attackType
                  << "  beacon="         << g_beaconInterval << "s"
                  << "  seed="           << seed);

    // ── NetAnim visualization ─────────────────────────────────────────────────
    AnimationInterface anim("npfads-animation.xml");
    anim.SetMaxPktsPerTraceFile(5000000);

    for (uint32_t i = 0; i < nVehicles; ++i) {
        int ntype = g_nodeAttackType[i];
        if (ntype != BENIGN) {
            // Attackers: red, labelled with their attack type
            anim.UpdateNodeColor(g_nodes.Get(i), 255, 0, 0);
            anim.UpdateNodeDescription(g_nodes.Get(i),
                                       "ATK-T" + std::to_string(ntype));
        } else {
            // Benign vehicles: blue
            anim.UpdateNodeColor(g_nodes.Get(i), 0, 100, 255);
            anim.UpdateNodeDescription(g_nodes.Get(i),
                                       "V" + std::to_string(i));
        }
        // Node size scaled for a 10 000 m × 10 000 m playground
        anim.UpdateNodeSize(g_nodes.Get(i)->GetId(), 250.0, 250.0);
    }

    // Schedule first BSM generation for every node
    for (uint32_t i = 0; i < nVehicles; ++i)
        Simulator::Schedule(Seconds(g_beaconInterval), &GenerateBSM, i);

    Simulator::Stop(Seconds(g_simTime));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_UNCOND("[NPFADS] Simulation complete.  Total BSMs logged: "
                  << g_bsmLog.size());

    PostProcess(outputDir);

    return 0;
}
