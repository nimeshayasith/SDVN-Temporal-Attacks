// ============================================================
// tgn_detector.cc
// Temporal Graph Neural Network (TGN) Detector
//
// Paper reference: Section 3.4.3 and Algorithm 2 (FS-DETECT) from
// "A Transfer-Learned GNN and Blockchain-Based Framework for
//  Temporal Fraud Detection in SDVNs"
//
// Equations implemented (paper numbering):
//   Eq 3.18  Graph snapshot  G_t = (V_t, E_t, X_t, A_t)
//   Eq 3.19  Node feature vector  x_v = [tau_dev | c_v^W | delta_s_v | rho_v | iota_v]  (Table 4.7 current default; id_v excluded)
//   Eq 3.20  Edge freshness weight  A_uv = exp(-max(0, age - T_b) / (gamma * T_b))
//   Eq 3.21  GRU temporal memory  m_v(t) = GRU(h_v(t-), x_v(t), phi(delta_t_v))
//   Eq 3.22  Message passing  h_v^(l+1) = sigma(W^(l) * MEAN{h_u*A_uv} + b^(l))
//   Eq 3.23  Anomaly score  y_hat_v(t) = sigmoid(w^T * h_v^(L))
//   Eq 3.34  Zero-init for new nodes  h_{V_new}(t-) = 0
//
// Integration:
//   routing.cc is included as a compilation-unit header:
//     - ROUTING_CC_AS_HEADER suppresses routing.cc's main()
//     - routing.cc's RoutingMain() runs the full attack simulation
//     - After RoutingMain() returns, pem_all_events holds every PEM event
//     - TGN_ProcessAllEvents() feeds those events through the TGN pipeline
//     - Results written to tgn_events.csv and tgn_summary.csv
//
// Build (inside ns-3.35/scratch/):
//   From repo root: cp tgn/tgn_detector.cc ~/ns-3.35/scratch/tgn_detector.cc
//   Also copy routing.cc: cp routing.cc ~/ns-3.35/scratch/routing.cc
//   In scratch/, the #include "../routing.cc" becomes "routing.cc" — adjust:
//     sed -i 's|#include "../routing.cc"|#include "routing.cc"|' ~/ns-3.35/scratch/tgn_detector.cc
//   cd ~/ns-3.35 && ./waf build
//
// NOTE: VS Code IntelliSense errors for ns3/ headers are expected on Windows.
//       This file compiles only on Linux inside NS-3.35.
//
// Run:
//   ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1"
//   ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --N_RSUs=1 --attack_scenario=6"
//
// Load trained weights (produced by tgn_train.py):
//   ./waf --run "scratch/tgn_detector ... --tgn_weights=tgn_weights.bin"
//
// Output files:
//   tgn_events.csv      per-event TGN scores + features
//   tgn_summary.csv     TP/TN/FP/FN/MCC/AUROC/Tdet (compatible with mbsm_summary.csv)
// ============================================================

// ── Suppress routing.cc's main() so this file can define its own ─────────────
// tgn/ subfolder — routing.cc lives one level up
#define ROUTING_CC_AS_HEADER
#include "../routing.cc"

// routing.cc defines min/max as C-style function-like macros (line ~118) which
// conflict with std::max / std::min inside the tgn:: template/namespace code
// below ("expected unqualified-id before numeric constant").  Undefine them
// immediately so the rest of this file can use std::max / std::min normally.
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

// ── Standard headers not already pulled in by routing.cc ─────────────────────
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

// =============================================================================
//  SECTION 1  Constants
// =============================================================================

static const double TGN_BEACON_INTERVAL = 0.1;    // T_b (s) — IEEE 802.11p beacon = 100 ms
static const int    TGN_DIM             = 32;     // embedding dimensionality d
static const int    TGN_LAYERS          = 2;      // message-passing rounds L
static const int    TGN_NP_OBU          = 8;      // np — max OBU peers selected in Tier 2 (no-RSU)
// γ (edge freshness decay) — separate from W_max, different formula:
//   γ = (L_link/2) / (T_b · ln2)  — Eq. 9.3 (urban L_link≈43s → γ≈310)
// Override at runtime with --tgn_l_link=<seconds> to recalibrate for highway (9 s).
static const double TGN_GAMMA_DEFAULT   = 310.0;  // urban: (43/2)/(0.1*ln2)
static       double TGN_GAMMA           = TGN_GAMMA_DEFAULT;
static const double TGN_THETA_FS        = 0.40;   // initial threshold; tgn_train.py optimises by MCC
// W_max (beacon sliding-window capacity) — separate from γ, different formula:
//   W_max = ⌈L_link / T_b⌉  — Eq. 9.2 (urban L_link≈43s → W_max=430)
// Must match tgn_train.py WMAX=430 so beacon_count is comparable at train/infer.
static       int    TGN_WMAX            = 430;    // urban default: ceil(43/0.1); recalibrated via --tgn_l_link

// =============================================================================
//  SECTION 2  Minimal linear-algebra helpers (no external BLAS)
// =============================================================================

namespace tgn {

using Vec = std::vector<double>;
using Mat = std::vector<Vec>;

inline double dot(const Vec& a, const Vec& b)
{
    double s = 0.0;
    for (size_t i = 0; i < a.size(); ++i) s += a[i] * b[i];
    return s;
}

inline Vec hadamard(const Vec& a, const Vec& b)
{
    Vec c(a.size());
    for (size_t i = 0; i < a.size(); ++i) c[i] = a[i] * b[i];
    return c;
}

inline Vec vadd(const Vec& a, const Vec& b)
{
    Vec c(a.size());
    for (size_t i = 0; i < a.size(); ++i) c[i] = a[i] + b[i];
    return c;
}

inline Vec scale(double s, const Vec& a)
{
    Vec c(a.size());
    for (size_t i = 0; i < a.size(); ++i) c[i] = s * a[i];
    return c;
}

// y = W * x  (no bias version used internally before adding bias separately)
inline Vec matvec(const Mat& W, const Vec& x)
{
    Vec y(W.size(), 0.0);
    for (size_t i = 0; i < W.size(); ++i)
        y[i] = dot(W[i], x);
    return y;
}

inline Vec relu(const Vec& x)
{
    Vec y(x.size());
    for (size_t i = 0; i < x.size(); ++i) y[i] = std::max(0.0, x[i]);
    return y;
}

inline Vec sigmoid_vec(const Vec& x)
{
    Vec y(x.size());
    for (size_t i = 0; i < x.size(); ++i) y[i] = 1.0 / (1.0 + std::exp(-x[i]));
    return y;
}

inline Vec tanh_vec(const Vec& x)
{
    Vec y(x.size());
    for (size_t i = 0; i < x.size(); ++i) y[i] = std::tanh(x[i]);
    return y;
}

inline double sigmoid(double x) { return 1.0 / (1.0 + std::exp(-x)); }

inline Vec zeros(int n) { return Vec(n, 0.0); }

// Xavier uniform initialisation
inline Mat xavier_mat(int rows, int cols)
{
    double lim = std::sqrt(6.0 / (rows + cols));
    Mat M(rows, Vec(cols));
    for (auto& row : M)
        for (auto& v : row)
            v = lim * (2.0 * (double)rand() / RAND_MAX - 1.0);
    return M;
}

inline Vec small_vec(int n, double scale_val = 0.01)
{
    Vec v(n);
    for (auto& x : v)
        x = scale_val * (2.0 * (double)rand() / RAND_MAX - 1.0);
    return v;
}

// =============================================================================
//  SECTION 3  Data structures
// =============================================================================

// --- TGN parameters (Section 3.4.3) -----------------------------------------
struct TGNParams {
    int    dim        = TGN_DIM;
    int    layers     = TGN_LAYERS;
    double gamma      = TGN_GAMMA;
    double theta_fs   = TGN_THETA_FS;
    double T_b        = TGN_BEACON_INTERVAL;
    int    wmax       = TGN_WMAX;
};

// --- Node feature vector  x_v  (Eq 3.20, Table 4.7 "current default") --------
// x_v = [tau_dev, c_v^W, delta_s_v, rho_v, iota_v] in R^5
// GRU input: gs = dim + 6 = dim + 5(x_v) + 1(phi)  — matches tgn_train.py gs = dim + 6
// Legacy gs = dim + 7 (id_v_norm + raw tau_s) is REMOVED per Table 4.7 action item.
struct NodeFeatures {
    uint32_t node_id;
    double   tau_s;            // raw sender timestamp — used to compute tau_deviation in UpdateNodeMemory
    double   beacon_count;     // c_v^W  — events in sliding window
    double   seq_gap;          // delta_s_v — timestamp regression (TTW-S2 signal)
    double   reporter_count;   // rho_v — distinct reporters for adjacent links (ME-S1)
    double   identity_mismatch; // iota_v: 1.0 if physical != claimed (BSHH signal)
};

// --- Per-node GRU state (Eq 3.21, 3.34) -------------------------------------
struct NodeState {
    Vec    memory;           // m_v(t) — GRU hidden state, dim-dimensional
    Vec    embedding;        // h_v^(L) — embedding after last message-passing
    double last_event_time;  // t of previous event for this node
};

// --- Alert record ------------------------------------------------------------
struct TGNAlert {
    uint32_t node_id;
    double   score;
    double   time_t;
};
using AlertSet = std::vector<TGNAlert>;

// --- Learnable weights -------------------------------------------------------
struct TGNWeights {
    // GRU input size = dim (prior h) + 6 = dim + 5(x_v) + 1(phi)
    //   x_v = [tau_dev, c_vW, seq_gap, rho_v, id_mis]  (Eq 3.20, Table 4.7)
    //   gs = dim + 6  — matches tgn_train.py gs = dim + 6
    int gru_input_size  = 0;
    int gru_hidden_size = 0;

    // GRU gates: update (z), reset (r), candidate (n)  — Eq 3.21
    Mat Wz, Wr, Wn;   // (dim × gru_input_size)
    Mat Uz, Ur, Un;   // (dim × dim)  recurrent
    Vec bz, br, bn;   // (dim)        biases

    // Message-passing layers  — Eq 3.22
    std::vector<Mat> W_layers;   // layers × (dim × dim)
    std::vector<Vec> b_layers;   // layers × dim

    // Scoring readout  — Eq 3.23
    Vec    w_score;    // dim-dimensional
    double b_score = 0.0;  // scalar bias; written after w_score in binary file

    // Variant classification head  — Section 4.7
    // α̂_v = softmax(Wcls · h_v^(L) + b_cls),  α = argmax ∈ {TTW=0, BSHH=1, ME=2}
    // Trained jointly with binary scorer via multi-class cross-entropy loss.
    Mat Wcls;      // (3 × dim)
    Vec b_cls;     // (3)

    bool loaded = false;   // true after LoadWeights() succeeds
};

// =============================================================================
//  SECTION 4  TGNDetector class  (Algorithm 2: FS-DETECT)
// =============================================================================

class TGNDetector {
public:
    explicit TGNDetector(const TGNParams& p = TGNParams{}) : params_(p)
    {
        srand(42);   // reproducible random weights
        InitWeightsRandom();
    }

    // ── Load trained weights from binary checkpoint ─────────────────────────
    // File format (written by tgn_train.py):
    //   [4 bytes: dim][4 bytes: layers]
    //   GRU weight matrices in row-major double order (Wz,Uz,bz, Wr,Ur,br, Wn,Un,bn)
    //   Layer matrices W_layers[0..L-1], b_layers[0..L-1]
    //   Scoring vector w_score
    //   Variant classification head: Wcls (3×dim row-major), b_cls (3)
    bool LoadWeights(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "[TGN] Weight file '" << path
                      << "' not found — using heuristic scoring.\n";
            return false;
        }

        int dim, layers;
        f.read(reinterpret_cast<char*>(&dim),    sizeof(int));
        f.read(reinterpret_cast<char*>(&layers), sizeof(int));
        params_.dim    = dim;
        params_.layers = layers;
        InitWeightsRandom();

        auto read_mat = [&](Mat& M, int r, int c) {
            M.assign(r, Vec(c));
            for (int i = 0; i < r; ++i)
                f.read(reinterpret_cast<char*>(M[i].data()), c * sizeof(double));
        };
        auto read_vec = [&](Vec& v, int n) {
            v.resize(n);
            f.read(reinterpret_cast<char*>(v.data()), n * sizeof(double));
        };

        int gs = weights_.gru_input_size;
        read_mat(weights_.Wz, dim, gs); read_mat(weights_.Uz, dim, dim);
        read_vec(weights_.bz, dim);
        read_mat(weights_.Wr, dim, gs); read_mat(weights_.Ur, dim, dim);
        read_vec(weights_.br, dim);
        read_mat(weights_.Wn, dim, gs); read_mat(weights_.Un, dim, dim);
        read_vec(weights_.bn, dim);
        for (int l = 0; l < layers; ++l) {
            read_mat(weights_.W_layers[l], dim, dim);
            read_vec(weights_.b_layers[l], dim);
        }
        read_vec(weights_.w_score, dim);
        f.read(reinterpret_cast<char*>(&weights_.b_score), sizeof(double));
        read_mat(weights_.Wcls,    3,   dim);
        read_vec(weights_.b_cls,   3);

        weights_.loaded = true;
        std::cout << "[TGN] Weights loaded from '" << path
                  << "'  (dim=" << dim << " layers=" << layers << ")\n";
        return true;
    }

    void SetThreshold(double t) { params_.theta_fs = t; }
    double GetThreshold() const { return params_.theta_fs; }
    const TGNParams& GetParams() const { return params_; }

    // ── Variant classification head (Section 4.7) ───────────────────────────
    // α̂_v = softmax(Wcls · h_v^(L) + b_cls),  α = argmax ∈ {TTW=0, BSHH=1, ME=2}
    // Uses the embedding stored by the most recent ProcessEvent() call for node_id.
    // Returns "" when weights are not loaded — caller falls back to heuristic.
    std::string PredictVariant(uint32_t node_id) const
    {
        if (!weights_.loaded) return "";
        auto it = states_.find(node_id);
        if (it == states_.end()) return "";

        const Vec& h = it->second.embedding;
        Vec logits(3);
        for (int c = 0; c < 3; ++c)
            logits[c] = dot(weights_.Wcls[c], h) + weights_.b_cls[c];

        int best = 0;
        for (int c = 1; c < 3; ++c)
            if (logits[c] > logits[best]) best = c;

        if (best == 0) return "TTW";
        if (best == 1) return "BSHH";
        return "ME";
    }

    // ── Main entry: process one topology / heartbeat event ──────────────────
    // Returns anomaly score in (0, 1).
    double ProcessEvent(const NodeFeatures& feat,
                        uint32_t            link_src,
                        uint32_t            link_dst,
                        double              recv_time)
    {
        // New-node zero-init  (Eq 3.34)
        if (states_.find(feat.node_id) == states_.end()) {
            NodeState ns;
            ns.memory          = zeros(params_.dim);
            ns.embedding       = zeros(params_.dim);
            ns.last_event_time = recv_time;
            states_[feat.node_id] = ns;
        }

        // Step 1 — Temporal memory update  (Eq 3.21)
        UpdateNodeMemory(feat, recv_time);

        // Step 2 — Build mini adjacency for this event's endpoints
        std::unordered_map<uint32_t, std::unordered_map<uint32_t, double>> adj;
        double age          = recv_time - feat.tau_s;
        double stale_age    = std::max(0.0, age - params_.T_b);
        double edge_fresh   = std::exp(-stale_age / (params_.gamma * params_.T_b));
        adj[feat.node_id][link_dst] = edge_fresh;
        adj[link_dst][feat.node_id] = edge_fresh;
        // Ensure link endpoints have state
        for (uint32_t ep : {link_src, link_dst}) {
            if (states_.find(ep) == states_.end()) {
                NodeState ns;
                ns.memory          = zeros(params_.dim);
                ns.embedding       = zeros(params_.dim);
                ns.last_event_time = recv_time;
                states_[ep] = ns;
            }
        }

        // Step 3 — L rounds of message passing  (Eq 3.22)
        std::set<uint32_t> active = {feat.node_id, link_src, link_dst};
        std::unordered_map<uint32_t, Vec> H;
        for (uint32_t v : active) H[v] = states_[v].memory;

        for (int l = 0; l < params_.layers; ++l)
            H = MessagePassingRound(H, adj, active, l);

        // Store final embeddings
        for (uint32_t v : active) states_[v].embedding = H[v];

        // Step 4 — Anomaly score  (Eq 3.23 / heuristic)
        double score;
        if (weights_.loaded) {
            // Neural readout: ŷ_v(t) = sigmoid(w^T · h_v^(L) + b_score)
            score = sigmoid(dot(weights_.w_score, states_[feat.node_id].embedding) + weights_.b_score);
        } else {
            // Heuristic readout — explicit anomaly feature combination
            score = HeuristicScore(feat, edge_fresh);
        }

        return score;
    }

    void ResetState(uint32_t node_id) { states_.erase(node_id); }

private:
    // ── 4.1  Weight initialisation ──────────────────────────────────────────
    void InitWeightsRandom()
    {
        int d  = params_.dim;
        int gs = d + 6;           // hidden (d) + [tau_dev, c_vW, seq_gap, rho_v, id_mis, phi]  (Eq 3.20, Table 4.7)
        weights_.gru_input_size  = gs;
        weights_.gru_hidden_size = d;

        weights_.Wz = xavier_mat(d, gs); weights_.Uz = xavier_mat(d, d);
        weights_.bz = zeros(d);
        weights_.Wr = xavier_mat(d, gs); weights_.Ur = xavier_mat(d, d);
        weights_.br = zeros(d);
        weights_.Wn = xavier_mat(d, gs); weights_.Un = xavier_mat(d, d);
        weights_.bn = zeros(d);

        weights_.W_layers.resize(params_.layers);
        weights_.b_layers.resize(params_.layers);
        for (int l = 0; l < params_.layers; ++l) {
            weights_.W_layers[l] = xavier_mat(d, d);
            weights_.b_layers[l] = zeros(d);
        }
        weights_.w_score = small_vec(d, 0.1);
        weights_.Wcls    = xavier_mat(3, d);
        weights_.b_cls   = zeros(3);
        weights_.loaded  = false;
    }

    // ── 4.2  GRU temporal memory update  (Eq 3.21) ──────────────────────────
    //
    //   phi(delta_t) = log(1 + delta_t / T_b)
    //   gru_input    = concat( h_v(t-), [tau_dev, c_vW, seq_gap, rho_v, id_mis, phi] )
    //                = dim + 6 elements  →  gs = dim + 6  (Eq 3.20, Table 4.7 current default)
    //   z = sigmoid( Wz * gru_input + Uz * h + bz )    (update gate)
    //   r = sigmoid( Wr * gru_input + Ur * h + br )    (reset gate)
    //   n = tanh(    Wn * gru_input + Un * (r⊙h) + bn ) (candidate)
    //   m_v(t) = (1-z)⊙h + z⊙n
    //
    void UpdateNodeMemory(const NodeFeatures& feat, double recv_time)
    {
        NodeState& ns = states_[feat.node_id];
        const Vec& h  = ns.memory;

        double delta_t     = std::max(0.0, recv_time - ns.last_event_time);
        double phi         = std::log(1.0 + delta_t / params_.T_b);
        double tau_deviation = (feat.tau_s > 0.0)
            ? std::min(50.0, std::max(-50.0, (recv_time - feat.tau_s) / params_.T_b))
            : 0.0;

        // 5-element x_v + phi  (Eq 3.20: tau_dev, c_vW, delta_s_v, rho_v, iota_v, phi)
        Vec raw = { tau_deviation,
                    feat.beacon_count,
                    feat.seq_gap,
                    feat.reporter_count,
                    feat.identity_mismatch,
                    phi };

        // GRU input: [h || raw]  — dim + 6 elements total (gs = dim + 6)
        Vec gru_in;
        gru_in.reserve(params_.dim + 6);
        gru_in.insert(gru_in.end(), h.begin(), h.end());
        gru_in.insert(gru_in.end(), raw.begin(), raw.end());

        Vec zg = sigmoid_vec(vadd(vadd(matvec(weights_.Wz, gru_in),
                                       matvec(weights_.Uz, h)),
                                   weights_.bz));
        Vec rg = sigmoid_vec(vadd(vadd(matvec(weights_.Wr, gru_in),
                                       matvec(weights_.Ur, h)),
                                   weights_.br));
        Vec rh = hadamard(rg, h);
        Vec ng = tanh_vec(vadd(vadd(matvec(weights_.Wn, gru_in),
                                     matvec(weights_.Un, rh)),
                                weights_.bn));

        Vec new_h(params_.dim);
        for (int i = 0; i < params_.dim; ++i)
            new_h[i] = (1.0 - zg[i]) * h[i] + zg[i] * ng[i];

        ns.memory          = new_h;
        ns.last_event_time = recv_time;
    }

    // ── 4.3  Message-passing round  (Eq 3.22) ────────────────────────────────
    //
    //   h_v^(l+1) = ReLU( W^(l) * MEAN{ h_u^(l) * A_uv : u in N(v,t) } + b^(l) )
    //
    std::unordered_map<uint32_t, Vec>
    MessagePassingRound(
        const std::unordered_map<uint32_t, Vec>&                  H_in,
        const std::unordered_map<uint32_t,
              std::unordered_map<uint32_t, double>>&               adj,
        const std::set<uint32_t>&                                   active,
        int layer) const
    {
        std::unordered_map<uint32_t, Vec> H_out;

        for (uint32_t v : active) {
            auto adj_it = adj.find(v);
            if (adj_it == adj.end() || adj_it->second.empty()) {
                H_out[v] = H_in.count(v) ? H_in.at(v) : zeros(params_.dim);
                continue;
            }

            Vec agg = zeros(params_.dim);
            int cnt = 0;
            for (const auto& [u, Auv] : adj_it->second) {
                if (active.find(u) == active.end()) continue;
                const Vec& hu = H_in.count(u) ? H_in.at(u) : zeros(params_.dim);
                agg = vadd(agg, scale(Auv, hu));
                ++cnt;
            }
            if (cnt > 0)
                for (auto& x : agg) x /= static_cast<double>(cnt);

            Vec t_vec = vadd(matvec(weights_.W_layers[layer], agg),
                             weights_.b_layers[layer]);
            H_out[v] = relu(t_vec);
        }
        return H_out;
    }

    // ── 4.4  Heuristic anomaly score (used when weights not loaded) ───────────
    //
    // Explicitly encodes the three attack signatures as a weighted sum that
    // maps to (0, 1) via sigmoid.  The centering at 2.0 gives score ≈ 0.5
    // when two moderate anomaly signals co-occur; benign events score < 0.15.
    //
    // Component            Signal             Covered attack
    // ──────────────────── ────────────────── ──────────────────────────────
    // staleness_excess     rx_time - ts - T_b TTW (all variants)
    // seq_gap_term         delta_s / 5        TTW-S2 (sequence regression)
    // identity_term        physical != claimed BSHH-S1, S2
    // reporter_excess      rho > rhoMax*1.5   ME (all variants)
    // freshness_penalty    1 - A_uv           TTW (stale edge down-weights)
    //
    double HeuristicScore(const NodeFeatures& feat, double edge_freshness) const
    {
        double s = 0.0;

        // Staleness beyond one beacon interval (TTW primary — via edge freshness)
        // edge_freshness is already computed by caller; low value = stale link.
        s += 2.0 * (1.0 - edge_freshness);

        // Sequence regression (TTW-S2)
        s += std::min(1.0, feat.seq_gap / 5.0);

        // Identity mismatch (BSHH-S1, S2)
        s += feat.identity_mismatch * 1.5;

        // Reporter density excess (ME-S1 / ME-S2)
        // Without RSU: the expected count for a single honest link is 2 (both
        //   endpoints report it).  Threshold = max(2, N/4) * 1.5.
        // With RSU: the RSU aggregates, so a single honest link has count=1
        //   (one vehicle's claimed_sender per link in the RSU-path set).
        //   Use a lower threshold (1.5) so a single injected false witness
        //   (ME-S2) already crosses the detection boundary.
        const bool in_rsu_path = (N_RSUs > 0);
        double rhoMax = in_rsu_path
            ? 1.5
            : std::max(2.0, static_cast<double>(N_Vehicles) / 4.0) * 1.5;
        if (feat.reporter_count > rhoMax)
            s += std::min(2.0, (feat.reporter_count - (in_rsu_path ? 1.0 : 2.0)) * 0.8);

        // Sigmoid centred at 2.0 — tuned for theta_fs = 0.40
        return sigmoid(s - 2.0);
    }

    // ── Member data ──────────────────────────────────────────────────────────
    TGNParams   params_;
    TGNWeights  weights_;
    std::unordered_map<uint32_t, NodeState> states_;
};

} // namespace tgn

// =============================================================================
//  SECTION 5  Global TGN state
// =============================================================================

static tgn::TGNDetector* g_tgn = nullptr;
static tgn::TGNParams    g_tgn_params;
static std::string       g_tgn_weight_file = "";

// Per-event tracking state built during TGN_ProcessAllEvents()
static std::map<uint32_t, double>                      g_last_sender_ts;   // seq_gap
static std::map<std::string, std::set<uint32_t>>       g_link_reporters;   // reporter_count
static std::map<uint32_t, std::vector<double>>         g_beacon_windows;   // beacon_count

// TGN detection metrics (computed during TGN_ProcessAllEvents)
static uint64_t g_tgn_tp = 0, g_tgn_tn = 0, g_tgn_fp = 0, g_tgn_fn = 0;
static double   g_tgn_first_alert_time  = -1.0;
static double   g_tgn_attack_start_time = -1.0;

static std::vector<double> g_tgn_pos_scores;   // scores of attack events (for AUROC)
static std::vector<double> g_tgn_neg_scores;   // scores of benign events (for AUROC)

// Output streams
static std::ofstream g_tgn_events_csv;
static std::ofstream g_tgn_summary_txt;
static std::ofstream g_tgn_detail_log;   /* tgn_detection_log.txt — per-event steps */

// Parallel record of (event, tgn_score) for non-beacon events — used by TGN_WriteAlertsJson
static std::vector<std::pair<PemEvent, double>> g_tgn_scored_events;

// =============================================================================
//  CRYPTO PRE-FILTER  (Algorithm 3 — LW-MITIGATE, Section 4.4)
//
//  Wires the Pre-Detection Cryptographic Filter into the TGN data path.
//  Called after RoutingMain() fills pem_all_events, before TGN_ProcessAllEvents().
//
//  Conditions applied (matching lw_mitigate() in hmac_filter.cc):
//    ① Freshness   (Eq. 3.15): |τr − τs| ≤ T_b + ε = 110 ms
//       Drops BSHH-S5 (malicious vehicle) and BSHH-S6 (malicious RSU):
//       the stored heartbeat carries an old τs so |τr-τs| >> 110 ms.
//       BSHH-S7 and BSHH-S8 (malicious controller, physical_sender==9999)
//       are NOT dropped here — they bypass to the controller path below
//       and are detected by the TGN instead.
//       TTW passes because it forges τs to be current — HMAC then fails in
//       the real system, but here the nonce proxy catches intra-session dupes.
//    ② Nonce novelty (Eq. 3.16): (reporter_id, claimed_sender_id, τs) not seen before
//       Proxy for nonce uniqueness: same (reporter, sender, timestamp) triplet
//       cannot appear twice at the same receiving node.
//    ③ Key revocation: after first alert fires, attacker's events are dropped
//       (mirrors LKH revocation by TemporalEchoMitigator — Eq. 3.17).
//
//  Bypass: controller-origin events (physical_sender == 9999 sentinel) pass
//  through unconditionally — insider holds valid credentials; TGN is the
//  primary defence for those scenarios (per Cryptographic Placement Analysis).
//
//  Output: crypto_filter_log.txt  (one line per dropped event with reason)
// =============================================================================
static std::vector<PemEvent> TGN_ApplyCryptoFilter(const std::vector<PemEvent>& events)
{
    // Eq. 3.15 freshness window: T_b + ε = 100 ms + 10 ms = 110 ms
    static const double CRYPTO_FRESHNESS_S = 0.110;

    // Nonce proxy: (reporter_id, claimed_sender_id, sender_timestamp)
    // Represents the per-RSU nonce cache from Eq. 3.16.
    std::set<std::tuple<uint32_t, uint32_t, double>> seen_nonces;

    // Revoked nodes — populated once pem_first_alert_time is known.
    std::set<uint32_t> revoked_nodes;

    std::ofstream log("crypto_filter_log.txt", std::ios::out | std::ios::trunc);
    log << std::fixed << std::setprecision(4)
        << "================================================================\n"
           "  TGN Pre-Detection Crypto Filter  (Algorithm 3 — LW-MITIGATE)\n"
           "  Eq. 3.15 freshness window : " << CRYPTO_FRESHNESS_S * 1000.0 << " ms\n"
           "  Eq. 3.16 nonce proxy      : (reporter, sender, τs) triplet\n"
           "  Eq. 3.17 revocation       : attacker dropped after first alert\n"
           "  Controller bypass         : physical_sender==9999 → pass through\n"
           "================================================================\n\n";

    std::vector<PemEvent> filtered;
    int n_fresh = 0, n_nonce = 0, n_revoked = 0, n_ctrl = 0, n_pass = 0;

    for (const PemEvent& e : events)
    {
        // Beacon events carry no topology claim — pass through directly.
        if (e.type == PEM_EVENT_BEACON)
        {
            filtered.push_back(e);
            n_pass++;
            continue;
        }

        // Controller-origin bypass (insider cannot be pre-filtered by crypto).
        if (e.physical_sender_id == 9999u)
        {
            filtered.push_back(e);
            n_ctrl++;
            continue;
        }

        // ① Eq. 3.15 — Timestamp freshness
        const double age = std::abs(e.reception_timestamp - e.sender_timestamp);
        if (age > CRYPTO_FRESHNESS_S)
        {
            log << "[DROP-STALE]   t=" << e.reception_timestamp
                << "s  sender=" << e.claimed_sender_id
                << "  |τr-τs|=" << age * 1000.0 << "ms > "
                << CRYPTO_FRESHNESS_S * 1000.0 << "ms  (Eq.3.15)\n";
            n_fresh++;
            continue;
        }

        // ② Eq. 3.16 — Nonce novelty (replay detection via timestamp proxy)
        const auto nonce = std::make_tuple(
            e.reporter_id, e.claimed_sender_id, e.sender_timestamp);
        if (seen_nonces.count(nonce))
        {
            log << "[DROP-REPLAY]  t=" << e.reception_timestamp
                << "s  reporter=" << e.reporter_id
                << "  sender=" << e.claimed_sender_id
                << "  τs=" << e.sender_timestamp << "s  (Eq.3.16)\n";
            n_nonce++;
            continue;
        }
        seen_nonces.insert(nonce);

        // ③ Eq. 3.17 — Key revocation: revoke attacker after first alert
        if (pem_first_alert_time > 0.0 &&
            e.reception_timestamp > pem_first_alert_time &&
            e.attack_label)
        {
            revoked_nodes.insert(e.physical_sender_id);
        }
        if (!revoked_nodes.empty() &&
            revoked_nodes.count(e.physical_sender_id) &&
            pem_first_alert_time > 0.0 &&
            e.reception_timestamp > pem_first_alert_time)
        {
            log << "[DROP-REVOKED] t=" << e.reception_timestamp
                << "s  sender=" << e.physical_sender_id
                << "  revoked after t=" << pem_first_alert_time << "s  (Eq.3.17)\n";
            n_revoked++;
            continue;
        }

        filtered.push_back(e);
        n_pass++;
    }

    log << "\n================================================================\n"
        << "  In     : " << events.size()  << " events\n"
        << "  Pass   : " << n_pass         << "\n"
        << "  Ctrl   : " << n_ctrl         << "  (bypassed — insider)\n"
        << "  Stale  : " << n_fresh        << "  (Eq.3.15 freshness)\n"
        << "  Replay : " << n_nonce        << "  (Eq.3.16 nonce)\n"
        << "  Revoked: " << n_revoked      << "  (Eq.3.17 LKH)\n"
        << "  Out    : " << filtered.size()<< " events → TGN_ProcessAllEvents()\n"
        << "================================================================\n";
    log.close();

    std::cout << "[CryptoFilter] "
              << events.size() << " in → "
              << filtered.size() << " out  ("
              << (n_fresh + n_nonce + n_revoked) << " dropped: "
              << n_fresh << " stale, "
              << n_nonce << " replay, "
              << n_revoked << " revoked)\n"
              << "              log: crypto_filter_log.txt\n";

    return filtered;
}

// =============================================================================
//  SECTION 6  Feature extraction helpers
// =============================================================================

// Edge freshness weight  A_uv(t)  (Eq 3.20)
// Uses excess staleness: max(0, age - T_b) so a fresh packet (age < T_b)
// gets A_uv = 1.0 rather than penalising sub-interval propagation latency.
static double TGN_EdgeFreshness(double recv_time, double sender_ts)
{
    double stale_excess = std::max(0.0, (recv_time - sender_ts) - TGN_BEACON_INTERVAL);
    return std::exp(-stale_excess / (TGN_GAMMA * TGN_BEACON_INTERVAL));
}

// Build NodeFeatures from a PemEvent plus incrementally maintained state.
// Called in temporal order so that seq_gap and reporter_count are correct.
static tgn::NodeFeatures TGN_ExtractFeatures(const PemEvent& e)
{
    tgn::NodeFeatures f;
    f.node_id = e.claimed_sender_id;
    f.tau_s   = e.sender_timestamp;   // raw ts — tau_deviation computed in UpdateNodeMemory

    // --- beacon_count: events from this node in window wmax ──────────────
    auto& win = g_beacon_windows[e.claimed_sender_id];
    win.push_back(e.reception_timestamp);
    while (static_cast<int>(win.size()) > TGN_WMAX)
        win.erase(win.begin());
    f.beacon_count = static_cast<double>(win.size());

    // --- seq_gap (delta_s_v): timestamp regression (TTW-S2 signal) ──────
    // Positive seq_gap means the claimed_sender_ts went backwards — a replay.
    f.seq_gap = 0.0;
    {
        auto it = g_last_sender_ts.find(e.claimed_sender_id);
        if (it != g_last_sender_ts.end()) {
            double prev_ts = it->second;
            if (e.sender_timestamp < prev_ts)
                f.seq_gap = prev_ts - e.sender_timestamp;  // regression magnitude
        }
        g_last_sender_ts[e.claimed_sender_id] = e.sender_timestamp;
    }

    // --- RSU-path detection ───────────────────────────────────────────────
    // Vehicle NS-3 node IDs are 0 … N_Vehicles-1.
    // RSU nodes are created after all vehicles, so their IDs are >= N_Vehicles.
    // When N_RSUs > 0 and physical_sender_id >= N_Vehicles, the event arrived
    // via the RSU aggregation path (Vehicle → RSU → Controller).
    // This is NORMAL behaviour — RSU is a legitimate forwarder, not an attacker.
    const bool physical_is_rsu = (N_RSUs > 0) &&
                                  (e.physical_sender_id >= N_Vehicles);

    // --- reporter_count (rho_v): distinct reporters for this link ────────
    //
    // WITHOUT RSU (S1/S3/S5/S7/S9/S11 scenarios):
    //   Each vehicle that physically observes and reports a link increments the
    //   count.  ME-S1 is detected because V3/V4 echo V1↔V2 → count rises above
    //   the expected density bound.
    //
    // WITH RSU (S2/S4/S6/S8/S10/S12 scenarios):
    //   The physical reporter is always the RSU (one node), so tracking
    //   reporter_id would always give count=1 and miss ME-S2.
    //   Instead we track the *claimed_sender_id*: a malicious RSU injecting
    //   V3/V4 as false witnesses for link V1↔V2 produces claimed_sender=V3 then
    //   V4, raising the count to 2 and triggering the ME density signal.
    //   Legitimate RSU forwarding adds exactly one distinct claimed_sender per
    //   vehicle that actually sent a beacon (count stays ≤ 1 per honest report).
    std::string link_key =
        std::to_string(e.link_src_id) + "_" + std::to_string(e.link_dst_id);
    if (physical_is_rsu) {
        g_link_reporters[link_key].insert(e.claimed_sender_id);
    } else {
        g_link_reporters[link_key].insert(e.reporter_id);
    }
    f.reporter_count = static_cast<double>(g_link_reporters[link_key].size());

    // --- identity_mismatch: physical != claimed (BSHH signal) ───────────
    //
    // WITHOUT RSU: fire whenever the physical transmitter differs from the
    //   node whose identity the packet claims (BSHH V2-impersonates-V1 case).
    //
    // WITH RSU: the physical sender is the RSU node, which legitimately carries
    //   topology data from vehicles under their own vehicle IDs.  This is NOT
    //   impersonation.  We therefore suppress the mismatch flag for RSU-path
    //   events.  BSHH-S2 (malicious RSU replaying a stale heartbeat) is still
    //   caught by the seq_gap and staleness signals, which are RSU-agnostic.
    f.identity_mismatch =
        (!physical_is_rsu && e.physical_sender_id != e.claimed_sender_id)
        ? 1.0 : 0.0;

    return f;
}

// =============================================================================
//  SECTION 7  AUROC computation
// =============================================================================

static double TGN_ComputeAUROC()
{
    const auto& pos = g_tgn_pos_scores;
    const auto& neg = g_tgn_neg_scores;
    if (pos.empty() || neg.empty()) return 0.5;

    // Mann-Whitney U statistic
    double auc = 0.0;
    for (double p : pos)
        for (double n : neg)
            auc += (p > n) ? 1.0 : (p == n ? 0.5 : 0.0);
    return auc / (static_cast<double>(pos.size()) * static_cast<double>(neg.size()));
}

// =============================================================================
//  SECTION 8  Event processing loop  (Algorithm 2: FS-DETECT applied post-hoc)
// =============================================================================

// Write one row to tgn_events.csv
static void TGN_WriteEventRow(const PemEvent& e,
                               const tgn::NodeFeatures& feat,
                               double edge_freshness,
                               double tgn_score,
                               bool   tgn_alert)
{
    if (!g_tgn_events_csv.is_open()) return;

    auto pem_sig_str = [&]() -> std::string {
        std::string s;
        const char* names[] = {
            "TTW-S1","TTW-S2","TTW-S3",
            "BSHH-S1","BSHH-S2","BSHH-S3",
            "ME-S1","ME-S2","ME-S3" };
        for (int i = 0; i < 9; ++i)
            if (e.triggered[i]) { if (!s.empty()) s += "|"; s += names[i]; }
        return s.empty() ? "none" : s;
    };

    const char* etype = (e.type == PEM_EVENT_TOPOLOGY_UPDATE) ? "TOPO_UPDATE"
                      : (e.type == PEM_EVENT_HEARTBEAT)        ? "HEARTBEAT"
                                                               : "BEACON";

    g_tgn_events_csv
        << std::fixed << std::setprecision(4)
        << e.sim_time                  << ","
        << attack_scenario             << ","
        << etype                       << ","
        << e.physical_sender_id        << ","
        << e.claimed_sender_id         << ","
        << e.link_src_id               << ","
        << e.link_dst_id               << ","
        << e.sender_timestamp          << ","
        << e.reception_timestamp       << ","
        << (e.reception_timestamp - e.sender_timestamp) << ","   // rx_delay
        << edge_freshness              << ","
        << feat.seq_gap                << ","
        << feat.reporter_count         << ","
        << feat.identity_mismatch      << ","
        << pem_sig_str()               << ","
        << e.score                     << ","   // PEM score
        << (e.alert_raised ? 1 : 0)    << ","   // PEM alert
        << tgn_score                   << ","
        << (tgn_alert  ? 1 : 0)        << ","
        << (e.attack_label ? 1 : 0)    << "\n";
}

static void TGN_ProcessAllEvents()
{
    if (!g_tgn) return;

    // Sort events by reception time (ascending — online temporal order)
    std::vector<PemEvent> sorted = pem_all_events;
    std::sort(sorted.begin(), sorted.end(),
        [](const PemEvent& a, const PemEvent& b) {
            return a.reception_timestamp < b.reception_timestamp;
        });

    // Reset feature-extraction state
    g_last_sender_ts.clear();
    g_link_reporters.clear();
    g_beacon_windows.clear();

    for (const PemEvent& e : sorted)
    {
        // Skip pure beacon events — TGN focuses on topology/heartbeat anomalies
        if (e.type == PEM_EVENT_BEACON) continue;

        // Online per-event mode (not end-of-interval batch): processes each
        // PEM event the instant it arrives, ordered by reception_timestamp.
        // This is necessary because attackers inject mid-interval — a batch
        // model would not see the attack until the beacon interval closes,
        // adding up to T_b = 100 ms of blind time.  Online mode ensures the
        // GRU memory update (Eq. 3.21) and anomaly score (Eq. 3.23) are
        // computed immediately on receipt, meeting the Tdet < T_b budget.

        // Build feature vector (online, incremental)
        tgn::NodeFeatures feat = TGN_ExtractFeatures(e);

        // Edge freshness weight (Eq 3.20)
        double edge_fresh = TGN_EdgeFreshness(e.reception_timestamp, e.sender_timestamp);

        // Run TGN pipeline — returns anomaly score in (0, 1)
        double tgn_score = g_tgn->ProcessEvent(
            feat,
            e.link_src_id,
            e.link_dst_id,
            e.reception_timestamp);

        bool tgn_alert = (tgn_score > g_tgn->GetThreshold());

        // ── Per-event detailed log ────────────────────────────────────────
        if (g_tgn_detail_log.is_open()) {
            static const char* sig_names[] = {
                "TTW-S1","TTW-S2","TTW-S3",
                "BSHH-S1","BSHH-S2","BSHH-S3",
                "ME-S1","ME-S2","ME-S3"
            };
            static const double sig_weights[] = {
                0.15,0.15,0.10, 0.15,0.10,0.10, 0.10,0.075,0.075
            };
            const char* etype = (e.type == PEM_EVENT_TOPOLOGY_UPDATE) ? "TOPO_UPDATE"
                              : (e.type == PEM_EVENT_HEARTBEAT)        ? "HEARTBEAT"
                                                                       : "BEACON";

            g_tgn_detail_log
                << "────────────────────────────────────────────────────────────────\n"
                << "[t=" << e.reception_timestamp << "]  EVENT  "
                << etype << "  "
                << (e.attack_label ? "*** ATTACK ***" : "(benign)") << "\n"
                << "  Physical sender  : V" << e.physical_sender_id << "\n"
                << "  Claimed sender   : V" << e.claimed_sender_id  << "\n"
                << "  Link             : V" << e.link_src_id
                << " <-> V" << e.link_dst_id << "\n\n";

            // STEP 1: Feature vector
            g_tgn_detail_log
                << "  STEP ①  Feature Vector x_v  (Eq. 3.19)\n"
                << "    id_v      = V" << e.physical_sender_id << "\n"
                << "    τ_s^(v)   = " << e.sender_timestamp    << " s\n"
                << "    c_v^W     = " << feat.beacon_count      << "  (liveness)\n"
                << "    Δs_v      = " << feat.seq_gap           << "  (seq gap)\n"
                << "    ρ_v       = " << feat.reporter_count    << "  (reporter count)\n\n";

            // STEP 2: Edge freshness
            g_tgn_detail_log
                << "  STEP ②  Edge Freshness A_{uv}(t)  (Eq. 3.20)\n"
                << "    τ_r        = " << e.reception_timestamp << " s\n"
                << "    τ_s        = " << e.sender_timestamp    << " s\n"
                << "    γ          = " << g_tgn->GetParams().gamma << "\n"
                << "    T_b        = " << g_tgn->GetParams().T_b  << " s\n"
                << "    A_{uv}(t)  = " << edge_fresh
                << "  (0=stale, 1=fresh)\n\n";

            // STEP 3: LW signatures
            g_tgn_detail_log
                << "  STEP ③  LW Path — 9 Signatures  (Eqs. 3.2–3.11)\n";
            double lw_score = 0.0;
            std::string triggered_list;
            for (int k = 0; k < 9; k++) {
                bool fired = (k < (int)(sizeof(e.triggered)/sizeof(e.triggered[0])))
                             && e.triggered[k];
                lw_score += fired ? sig_weights[k] : 0.0;
                g_tgn_detail_log
                    << "    Sig[" << k << "] " << sig_names[k]
                    << std::string(12 - strlen(sig_names[k]), ' ')
                    << ": " << (fired ? "TRIGGERED" : "not fired ")
                    << "  w=" << sig_weights[k] << "\n";
                if (fired) {
                    if (!triggered_list.empty()) triggered_list += " | ";
                    triggered_list += sig_names[k];
                }
            }
            g_tgn_detail_log
                << "    ── s(e) = Σ w_k = " << lw_score
                << "  θ_LW = " << g_tgn->GetThreshold()
                << "  → " << (e.alert_raised ? "LW ALERT RAISED" : "below threshold")
                << "\n"
                << "    Triggered: "
                << (triggered_list.empty() ? "none" : triggered_list) << "\n\n";

            // STEP 4: FS/TGN score
            g_tgn_detail_log
                << "  STEP ④  FS/TGN Path  (Eqs. 3.21–3.23)\n"
                << "    GRU memory update : m_v(t) = GRU(h_v(t⁻), x_v(t), φ(Δt_v))\n"
                << "    Message passing   : L=" << g_tgn->GetParams().layers << " rounds\n"
                << "    Anomaly score     : ŷ_v = σ(w^T h_v^(L)) = "
                << tgn_score << "\n"
                << "    Threshold θ_FS    : " << g_tgn->GetThreshold() << "\n"
                << "    FS Alert          : "
                << (tgn_alert ? "RAISED  ← DetectionAlert queued" : "not raised") << "\n\n";

            // Verdict
            g_tgn_detail_log
                << "  VERDICT: "
                << (tgn_alert ? "ANOMALY DETECTED" : "CLEAN") << "\n";
            if (tgn_alert) {
                g_tgn_detail_log
                    << "  → DetectionAlert(V" << e.claimed_sender_id
                    << ", score=" << tgn_score << ") queued\n"
                    << "  → Will be written to tgn_alerts.json\n"
                    << "  → submit_alerts.py will invoke TemporalEchoMitigator::SubmitAlert\n";
            }
            g_tgn_detail_log << "\n";
            g_tgn_detail_log.flush();
        }

        // Track detection metrics
        if (e.attack_label) {
            if (g_tgn_attack_start_time < 0.0)
                g_tgn_attack_start_time = e.reception_timestamp;

            if (tgn_alert) {
                ++g_tgn_tp;
                if (g_tgn_first_alert_time < 0.0)
                    g_tgn_first_alert_time = e.reception_timestamp;
            } else {
                ++g_tgn_fn;
            }
            g_tgn_pos_scores.push_back(tgn_score);
        } else {
            if (tgn_alert) ++g_tgn_fp;
            else           ++g_tgn_tn;
            g_tgn_neg_scores.push_back(tgn_score);
        }

        TGN_WriteEventRow(e, feat, edge_fresh, tgn_score, tgn_alert);

        // Store for TGN_WriteAlertsJson (Eq. 3.36 output)
        g_tgn_scored_events.emplace_back(e, tgn_score);
    }
}

// =============================================================================
//  SECTION 9  Output helpers
// =============================================================================

static const std::string TGN_AttackName(uint32_t s)
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

static void TGN_InitOutputFiles()
{
    // Events CSV
    g_tgn_events_csv.open("tgn_events.csv", std::ios::out | std::ios::trunc);
    g_tgn_events_csv
        << "sim_time_s,attack_scenario,event_type,"
        << "physical_sender_id,claimed_sender_id,"
        << "link_src_id,link_dst_id,"
        << "claimed_ts_s,recv_time_s,rx_delay_s,"
        << "edge_freshness,seq_gap,reporter_count,identity_mismatch,"
        << "pem_signatures,pem_score,pem_alert,"
        << "tgn_score,tgn_alert,is_attack\n";

    // Per-event detailed detection log
    std::string det_name = (attack_scenario == 0)
        ? "tgn_detection_log.txt"
        : "tgn_detection_log_s" + std::to_string(attack_scenario) + ".txt";
    g_tgn_detail_log.open(det_name, std::ios::out | std::ios::trunc);
    g_tgn_detail_log << std::fixed << std::setprecision(4)
        << "================================================================\n"
        << "  TGN DETECTOR — Step-by-Step Detection Log\n"
        << "  Attack    : " << TGN_AttackName(attack_scenario) << "\n"
        << "  LW path   : Eqs. 3.2–3.11  (9-signature weighted score)\n"
        << "  FS path   : Eqs. 3.18–3.23 (Temporal GNN anomaly score)\n"
        << "  Threshold : θ_LW = θ_FS = " << TGN_THETA_FS << "\n"
        << "================================================================\n\n"
        << "  Per-event format:\n"
        << "    STEP ①  Feature vector x_v  (Eq. 3.19)\n"
        << "    STEP ②  Edge freshness A_{uv}(t)  (Eq. 3.20)\n"
        << "    STEP ③  LW path — 9 signatures  (Eqs. 3.2–3.11)\n"
        << "    STEP ④  FS/TGN path — GRU + message passing  (Eqs. 3.21–3.23)\n"
        << "    VERDICT: alert or pass, DetectionAlert → tgn_alerts.json\n\n"
        << "================================================================\n\n";
    g_tgn_detail_log.flush();

    // Human-readable summary log
    std::string txt = (attack_scenario == 0)
        ? "tgn_baseline.txt"
        : "tgn_attack" + std::to_string(attack_scenario) + ".txt";
    g_tgn_summary_txt.open(txt, std::ios::out | std::ios::trunc);
    g_tgn_summary_txt << std::fixed << std::setprecision(3)
        << "================================================================\n"
        << "  TGN Detector — Temporal-Echo Attack Analysis\n"
        << "  Attack    : " << TGN_AttackName(attack_scenario) << "\n"
        << "  Equations : Eq 3.18-3.23, 3.34  (Section 3.4.3)\n"
        << "  Algorithm : FS-DETECT (Algorithm 2)\n"
        << "----------------------------------------------------------------\n"
        << "  sim_time  : " << simTime        << " s\n"
        << "  Vehicles  : " << N_Vehicles     << "\n"
        << "  RSUs      : " << N_RSUs         << "\n"
        << "  Scenario  : " << attack_scenario << "\n"
        << "  TGN dim   : " << g_tgn_params.dim    << "\n"
        << "  TGN layers: " << g_tgn_params.layers << "\n"
        << "  gamma     : " << g_tgn_params.gamma  << "\n"
        << "  theta_FS  : " << g_tgn_params.theta_fs << "\n"
        << "  T_b       : " << g_tgn_params.T_b    << " s\n"
        << "  Weights   : "
        << (g_tgn->GetParams().dim == TGN_DIM && !g_tgn_weight_file.empty()
            ? g_tgn_weight_file : "Xavier random (heuristic scoring)")
        << "\n"
        << "================================================================\n\n";
    g_tgn_summary_txt.flush();
}

static void TGN_WriteSummary()
{
    double tp = static_cast<double>(g_tgn_tp);
    double tn = static_cast<double>(g_tgn_tn);
    double fp = static_cast<double>(g_tgn_fp);
    double fn = static_cast<double>(g_tgn_fn);

    double denom_mcc = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    double mcc       = (denom_mcc > 0.0) ? (tp*tn - fp*fn) / denom_mcc : 0.0;
    double total     = tp + tn + fp + fn;
    double acr       = (total > 0.0) ? (tp + tn) / total * 100.0 : 0.0;
    double precision = (tp + fp > 0.0) ? tp / (tp + fp) : 0.0;
    double recall    = (tp + fn > 0.0) ? tp / (tp + fn) : 0.0;
    double tdet_ms   = -1.0;
    if (g_tgn_attack_start_time >= 0.0 && g_tgn_first_alert_time >= 0.0)
        tdet_ms = (g_tgn_first_alert_time - g_tgn_attack_start_time) * 1000.0;
    double auroc = TGN_ComputeAUROC();

    // Summary CSV — same column order as temporal_mbsm_summary.csv + TGN extras
    std::ofstream sum("tgn_summary.csv", std::ios::out | std::ios::trunc);
    sum << "attack_scenario,attack_name,tp,tn,fp,fn,"
        << "mcc,acr_pct,precision,recall,tdet_ms,auroc,theta_fs,dim,layers\n";
    sum << std::fixed << std::setprecision(3)
        << attack_scenario
        << ",\"" << TGN_AttackName(attack_scenario) << "\","
        << g_tgn_tp << "," << g_tgn_tn << ","
        << g_tgn_fp << "," << g_tgn_fn << ","
        << mcc      << "," << acr       << ","
        << precision << "," << recall   << ","
        << tdet_ms  << "," << auroc     << ","
        << g_tgn_params.theta_fs << ","
        << g_tgn_params.dim      << ","
        << g_tgn_params.layers   << "\n";
    sum.close();

    // Console + text log summary
    std::ostringstream out;
    out << std::fixed << std::setprecision(3)
        << "\n========== TGN DETECTION SUMMARY ==========\n"
        << "  Scenario  : " << attack_scenario
        << " — " << TGN_AttackName(attack_scenario) << "\n"
        << "  TP/TN/FP/FN : "
        << g_tgn_tp << " / " << g_tgn_tn << " / "
        << g_tgn_fp << " / " << g_tgn_fn << "\n"
        << "  MCC         : " << mcc      << "\n"
        << "  AUROC       : " << auroc    << "\n"
        << "  ACR         : " << acr      << " %\n"
        << "  Precision   : " << precision << "\n"
        << "  Recall      : " << recall    << "\n"
        << "  Tdet        : " << tdet_ms   << " ms\n"
        << "  theta_FS    : " << g_tgn_params.theta_fs << "\n"
        << "  PEM events processed : " << (g_tgn_tp+g_tgn_tn+g_tgn_fp+g_tgn_fn) << "\n"
        << "============================================\n";

    std::cout << out.str();
    if (g_tgn_summary_txt.is_open()) {
        g_tgn_summary_txt << out.str();
        g_tgn_summary_txt.flush();
    }
}

// =============================================================================
//  SECTION 9b  Alert JSON output  (Eq. 3.36 AlertObject for TemporalEchoMitigator)
//
//  Writes tgn_alerts.json — an array of AlertObject records matching exactly
//  the Go struct in temporalecho.go:
//      type AlertObject struct { NodeID, AttackVariant, AnomalyScore,
//                                TriggeredSigs, AlertTime }
//
//  submit_alerts.py reads this file and calls SubmitAlert on the Fabric peer.
// =============================================================================

static std::string TGN_AlphaFromScenario(uint32_t sc)
{
    if (sc >= 1  && sc <= 4)  return "TTW";
    if (sc >= 5  && sc <= 8)  return "BSHH";
    if (sc >= 9  && sc <= 12) return "ME";
    return "UNKNOWN";
}

static std::vector<int> TGN_SigIndicesFromEvent(const PemEvent& e)
{
    // PEM signature indices 0-8: TTW(0-2), BSHH(3-5), ME(6-8)
    std::vector<int> idx;
    for (int i = 0; i < 9; ++i)
        if (e.triggered[i]) idx.push_back(i);
    return idx;
}

// Write tgn_alerts.json — AlertObject array for TemporalEchoMitigator::SubmitAlert
// Called after TGN_ProcessAllEvents(); uses g_tgn_scored_events populated there.
static void TGN_WriteAlertsJson()
{
    std::ofstream f("tgn_alerts.json", std::ios::out | std::ios::trunc);
    f << std::fixed << std::setprecision(6);
    f << "[\n";

    bool  first       = true;
    size_t alert_count = 0;

    for (const auto& pair : g_tgn_scored_events)
    {
        const PemEvent& e     = pair.first;
        double          score = pair.second;

        if (score <= g_tgn->GetThreshold()) continue;

        std::vector<int> sigs = TGN_SigIndicesFromEvent(e);

        // Derive alpha from triggered signatures (more precise than scenario number)
        std::string alpha = g_tgn ? g_tgn->PredictVariant(e.claimed_sender_id) : "";
        if (alpha.empty()) {
            alpha = TGN_AlphaFromScenario(attack_scenario);
            for (int s : sigs) {
                if      (s <= 2) { alpha = "TTW";  break; }
                else if (s <= 5) { alpha = "BSHH"; break; }
                else             { alpha = "ME";   break; }
            }
        }

        // t_alert in ms (int64) — matches temporalecho.go AlertObject.AlertTime
        int64_t t_ms = static_cast<int64_t>(e.reception_timestamp * 1000.0);

        if (!first) f << ",\n";
        first = false;

        f << "  {\n"
          << "    \"v_id\": \""   << e.claimed_sender_id << "\",\n"
          << "    \"alpha\": \""  << alpha               << "\",\n"
          << "    \"y_hat\": "    << score               << ",\n"
          << "    \"S_trig\": [";
        for (size_t k = 0; k < sigs.size(); ++k) {
            if (k) f << ", ";
            f << sigs[k];
        }
        f << "],\n"
          << "    \"t_alert\": "  << t_ms                << "\n"
          << "  }";

        ++alert_count;
    }

    f << "\n]\n";
    f.close();

    std::cout << "[TGN] tgn_alerts.json  →  " << alert_count << " alerts  "
              << "(submit_alerts.py → SubmitAlert on temporalecho chaincode)\n";

    // ── Write blockchain handoff section to detail log ────────────────────
    if (g_tgn_detail_log.is_open()) {
        g_tgn_detail_log
            << "================================================================\n"
            << "  TGN → BLOCKCHAIN HANDOFF  (Section 9, Eq. 3.36)\n"
            << "================================================================\n\n"
            << "  tgn_alerts.json written  →  " << alert_count << " DetectionAlert(s)\n\n";

        // Re-iterate alerts for the log
        size_t log_n = 0;
        for (const auto& pair : g_tgn_scored_events) {
            const PemEvent& e  = pair.first;
            double          sc = pair.second;
            if (sc <= g_tgn->GetThreshold()) continue;

            std::string alpha = TGN_AlphaFromScenario(attack_scenario);
            for (int s : TGN_SigIndicesFromEvent(e)) {
                if      (s <= 2) { alpha = "TTW";  break; }
                else if (s <= 5) { alpha = "BSHH"; break; }
                else             { alpha = "ME";   break; }
            }
            int64_t t_ms = static_cast<int64_t>(e.reception_timestamp * 1000.0);

            g_tgn_detail_log
                << "  Alert #" << ++log_n << "\n"
                << "    Vid       : V"   << e.claimed_sender_id  << "\n"
                << "    α (type)  : "    << alpha                << "\n"
                << "    ŷ_v       : "    << sc                   << "\n"
                << "    t_alert   : "    << t_ms                 << " ms\n"
                << "    S_trig    : ";
            for (int s : TGN_SigIndicesFromEvent(e))
                g_tgn_detail_log << s << " ";
            g_tgn_detail_log << "\n\n"
                << "    ─── Smart Contract Actions (Algorithm 4) ───────────\n";
            if (alpha == "TTW" || alpha == "BSHH") {
                g_tgn_detail_log
                    << "    VERIFY_THRESHOLD_SIG(V" << e.claimed_sender_id << ")\n"
                    << "    PUSH_FLOWMOD(DROP, V"    << e.claimed_sender_id << ")\n"
                    << "    REVOKE_SESSION_KEY(V"    << e.claimed_sender_id
                    << ")  → LKH O(log n) update\n"
                    << "    FLAG_REAUTH(V"           << e.claimed_sender_id << ")\n";
            } else {
                g_tgn_detail_log
                    << "    GET_WITNESSES(e_ij, t)\n"
                    << "    VERIFY_QUORUM(W_v, t)\n"
                    << "    INVALIDATE_PATHS(P_false)\n"
                    << "    PUSH_REROUTE_FLOWMOD()\n"
                    << "    FLAG_REAUTH(V" << e.claimed_sender_id << ")\n";
            }
            g_tgn_detail_log
                << "    LOG(L, {V" << e.claimed_sender_id
                << ", " << sc << ", " << t_ms << "})  ← immutable ledger\n"
                << "    EMIT(AttackDetected, {V" << e.claimed_sender_id
                << ", " << alpha << ", " << sc << "})\n\n";
        }

        g_tgn_detail_log
            << "  ─── PBFT Consensus (§3.4.10) ─────────────────────────────\n"
            << "  Endorsement policy : OutOf(3, RSU1..RSU5)\n"
            << "  Byzantine tolerance: ⌊(5-1)/3⌋ = 1 faulty peer tolerated\n"
            << "  Next step          : python3 submit_alerts.py "
               "--alerts tgn_alerts.json\n\n"
            << "================================================================\n"
            << "  TGN RUN SUMMARY\n"
            << "================================================================\n\n"
            << "  TP = " << g_tgn_tp << "  TN = " << g_tgn_tn
            << "  FP = " << g_tgn_fp << "  FN = " << g_tgn_fn << "\n"
            << "  Tdet (first alert) : "
            << (g_tgn_first_alert_time >= 0.0
                ? std::to_string((g_tgn_first_alert_time
                                  - g_tgn_attack_start_time) * 1000.0) + " ms"
                : "n/a") << "\n"
            << "  Output files written:\n"
            << "    tgn_events.csv        — per-event scores\n"
            << "    tgn_alerts.json       — DetectionAlert array → Fabric\n"
            << "    tgn_detection_log.txt — this file\n\n";
        g_tgn_detail_log.close();
    }
}

// =============================================================================
//  SECTION 10  main()
//
//  1. Parse --tgn_* flags (additional to routing.cc flags).
//  2. Initialise TGN pipeline.
//  3. Call RoutingMain() — runs the full attack simulation using routing.cc's
//     existing main logic and fills pem_all_events.
//  4. Post-process pem_all_events through TGN (TGN_ProcessAllEvents).
//  5. Write tgn_events.csv and tgn_summary.csv.
// =============================================================================

int main(int argc, char *argv[])
{
    // ── Extra command-line parameters for TGN ───────────────────────────────
    // These are parsed BEFORE forwarding to RoutingMain so waf doesn't complain
    // about unknown flags.  We pull them out and strip them from argv.
    std::string tgn_weights_path = "";
    double      tgn_theta        = TGN_THETA_FS;
    double      tgn_gamma        = TGN_GAMMA_DEFAULT;
    double      tgn_l_link       = 43.0;   // urban default L_link (s)
    int         tgn_dim          = TGN_DIM;
    int         tgn_layers       = TGN_LAYERS;

    // Build a filtered argc/argv for RoutingMain (without TGN-specific flags)
    std::vector<char*> filtered_argv;
    filtered_argv.push_back(argv[0]);

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto starts = [&](const std::string& pfx) {
            return arg.rfind(pfx, 0) == 0;
        };
        if (starts("--tgn_weights=")) {
            tgn_weights_path = arg.substr(std::string("--tgn_weights=").size());
        } else if (starts("--tgn_theta=")) {
            tgn_theta = std::stod(arg.substr(std::string("--tgn_theta=").size()));
        } else if (starts("--tgn_gamma=")) {
            tgn_gamma = std::stod(arg.substr(std::string("--tgn_gamma=").size()));
        } else if (starts("--tgn_l_link=")) {
            // γ = (L_link/2) / (T_b · ln2)  — Eq. 9.3 calibration rule
            tgn_l_link = std::stod(arg.substr(std::string("--tgn_l_link=").size()));
            tgn_gamma  = (tgn_l_link / 2.0) / (TGN_BEACON_INTERVAL * std::log(2.0));
            // W_max = ⌈L_link / T_b⌉  — Eq. 9.2
            TGN_WMAX   = static_cast<int>(std::ceil(tgn_l_link / TGN_BEACON_INTERVAL));
            std::cout << "[TGN] L_link=" << tgn_l_link << "s  "
                      << "→ gamma=" << tgn_gamma << "  W_max=" << TGN_WMAX << "\n";
        } else if (starts("--tgn_dim=")) {
            tgn_dim = std::stoi(arg.substr(std::string("--tgn_dim=").size()));
        } else if (starts("--tgn_layers=")) {
            tgn_layers = std::stoi(arg.substr(std::string("--tgn_layers=").size()));
        } else {
            filtered_argv.push_back(argv[i]);
        }
    }
    int filtered_argc = static_cast<int>(filtered_argv.size());

    // ── Initialise TGN pipeline ──────────────────────────────────────────────
    g_tgn_params.dim       = tgn_dim;
    g_tgn_params.layers    = tgn_layers;
    g_tgn_params.gamma     = tgn_gamma;
    g_tgn_params.theta_fs  = tgn_theta;
    g_tgn_params.T_b       = TGN_BEACON_INTERVAL;
    g_tgn_params.wmax      = TGN_WMAX;
    g_tgn_weight_file      = tgn_weights_path;

    g_tgn = new tgn::TGNDetector(g_tgn_params);

    if (!tgn_weights_path.empty()) {
        g_tgn->LoadWeights(tgn_weights_path);
    } else {
        std::cerr
            << "\n"
            << "╔══════════════════════════════════════════════════════════════════╗\n"
            << "║  WARNING — TGN HEURISTIC MODE  (tgn_detector.cc)               ║\n"
            << "║                                                                  ║\n"
            << "║  No tgn_weights.bin provided. The GNN described in the paper   ║\n"
            << "║  (Eqs. 3.21–3.23, GRU + message passing) is NOT running.       ║\n"
            << "║  Falling back to HeuristicScore() — a manually tuned weighted  ║\n"
            << "║  sum of staleness, seq_gap, identity mismatch, reporter excess, ║\n"
            << "║  and edge freshness. This is NOT the trained TGN.              ║\n"
            << "║                                                                  ║\n"
            << "║  To enable the full GNN:                                        ║\n"
            << "║    1. Generate training data:                                   ║\n"
            << "║         bash generate_training_data.sh                          ║\n"
            << "║    2. Train TGN weights:                                        ║\n"
            << "║         python3 tgn_train.py all_events.csv --output tgn_weights.bin\n"
            << "║    3. Re-run with weights:                                      ║\n"
            << "║         --tgn_weights=tgn_weights.bin                           ║\n"
            << "╚══════════════════════════════════════════════════════════════════╝\n\n";
    }

    // ── Run routing.cc simulation ────────────────────────────────────────────
    // RoutingMain() parses the remaining argv, sets up NS-3 nodes, installs
    // attacks, runs Simulator::Run(), and returns after Simulator::Destroy().
    // Everything in pem_all_events, pem_positive_scores, pem_negative_scores
    // and the global attack_scenario / N_Vehicles etc. is populated by it.
    std::cout << "\n[TGN] Starting routing.cc simulation...\n";
    int sim_result = RoutingMain(filtered_argc, filtered_argv.data());

    // ── Post-simulation: open output files now that attack_scenario is known ─
    TGN_InitOutputFiles();

    // ── Crypto pre-filter (Algorithm 3 — LW-MITIGATE, Eqs. 3.14–3.17) ──────
    // Wires the Pre-Detection Cryptographic Filter into the TGN data path.
    // Filters pem_all_events in-place before TGN sees any event.
    // Controller-origin events bypass (insider with valid credentials).
    std::cout << "[CryptoFilter] Applying pre-detection filter to "
              << pem_all_events.size() << " events...\n";
    pem_all_events = TGN_ApplyCryptoFilter(pem_all_events);

    // ── Feed filtered pem_all_events through TGN ─────────────────────────────
    std::cout << "[TGN] Processing " << pem_all_events.size()
              << " crypto-filtered events through TGN pipeline...\n";
    TGN_ProcessAllEvents();

    // ── Write Eq. 3.36 alert objects for TemporalEchoMitigator ──────────────
    TGN_WriteAlertsJson();

    // ── Write summary outputs ────────────────────────────────────────────────
    TGN_WriteSummary();

    // ── Cleanup ──────────────────────────────────────────────────────────────
    delete g_tgn;
    g_tgn = nullptr;

    if (g_tgn_events_csv.is_open())  g_tgn_events_csv.close();
    if (g_tgn_summary_txt.is_open()) g_tgn_summary_txt.close();

    return sim_result;
}
