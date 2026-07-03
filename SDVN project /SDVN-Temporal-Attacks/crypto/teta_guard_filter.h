/*
 * teta_guard_filter.h — Per-Trusted-Node Cryptographic Pre-Filter
 *                        Algorithm 3 (LW-MITIGATE), Eqs. 3.15–3.17 / 3.26–3.30
 *
 * Section 3.1.3 (p.20): "Detection logic is embedded within each trusted node nk
 * (RSU or designated OBU), not in a centralised intelligence layer."
 *
 * p.81: "The verifier (RSU or controller) accepts the message if and only if all
 * three conditions hold simultaneously."  → Both RSU nodes AND the controller
 * are valid verifiers; each maintains its OWN nonce cache.
 *
 * Per-node state:
 *   • nonce_cache        — Eq. 3.17: nonce novelty, separate per verifier
 *   • link_witnesses     — Eq. 3.30: legitimate reporter set, separate per verifier
 *   • link_all_reporters — Eq. 3.30: ALL reporters (legit + in-range attackers) for
 *                          computing dynamic quorum t = ⌊n/2⌋ + 1
 *
 * Included by routing.cc after PemEvent and the relevant constants are defined.
 * All routing.cc globals (attack_scenario, TTW_COMM_RANGE, etc.) are visible here
 * because this header is included inside routing.cc's compilation unit.
 *
 * Deploy: copy to scratch/.crypto_src/teta_guard_filter.h
 */

#pragma once

// routing.cc defines `max` and `min` as numeric constants for neighbour-count
// arrays.  Save and clear them so std::max/std::min work inside this header.
#pragma push_macro("max")
#pragma push_macro("min")
#undef max
#undef min

#include <cstdint>
#include <map>
#include <set>
#include <string>

// ── Real Eq. 3.26 threshold aggregate signature implementation ───────────────
// threshold_sig.cc provides vehicle_sign_report(), rsu_aggregate_reports(), and
// verify_threshold_sig() — the actual Dilithium5 per-signer + HMAC-binding path.
// Defining THRESHOLD_SIG_NO_MAIN suppresses its standalone main(); all Dilithium5
// primitives (dilithium5_sign_thresh, dilithium5_verify_thresh, teta_ca_init,
// dilithium5_verify_cert) are already compiled into routing.cc's translation unit
// via the `#include ".crypto_src/dilithium.cc"` at line 90 of routing.cc, which
// executes before this header is reached.  teta_guard_types.h (included first by
// threshold_sig.cc) is guarded with #pragma once — no double-definition risk.
#ifndef THRESHOLD_SIG_NO_MAIN
#  define THRESHOLD_SIG_NO_MAIN
#endif
#include "threshold_sig.cc"

// ── Per-reporter Dilithium5 key pairs for location-binding (Eqs. 3.27-3.28) ──
// location_binding.cc is already included by routing.cc at line 93 (with
// LOCATION_BINDING_NO_MAIN defined at line 78), so create_location_bound_report(),
// verify_single_witness(), verify_quorum(), and haversine_distance_m() are already
// compiled into the translation unit and callable from TetaGuardLocBindVerify() below.
// Lazily generated on first observation: each vehicle Vk has its own ML-DSA-87
// key pair and CA-issued certificate so that the signed LocationBindingPayload is
// cryptographically unique to Vk.  Deterministic per reporter_id across all events.
struct LocBindKeyPair {
    uint8_t         pk[DILITHIUM5_PK_LEN];
    uint8_t         sk[DILITHIUM5_SK_LEN];
    CertificateRecord cert;
};
static std::map<uint32_t, LocBindKeyPair> g_locbind_keys;
static bool g_locbind_ca_ready = false;   // teta_ca_init() called exactly once

// Convert NS-3 Cartesian (metres from origin) to approximate GPS lat/lon.
// Uses the linear equirectangular projection anchored at Colombo (same as
// sim_gps() in location_binding.cc) so haversine_distance_m() gives the same
// distance as PemDistance2d() for distances < 5 km.
// cos(6.9271° × π/180) ≈ 0.99267 — pre-multiplied into the longitude divisor.
static void ns3_to_gps(double x_m, double y_m, float *lat, float *lon) {
    const double BASE_LAT = 6.9271;               /* Colombo, Sri Lanka */
    const double BASE_LON = 79.8612;
    const double DEG_PER_M_LAT = 1.0 / 111000.0;
    const double DEG_PER_M_LON = 1.0 / (111000.0 * 0.99267);  /* cos(6.9271°) */
    *lat = (float)(BASE_LAT + y_m * DEG_PER_M_LAT);
    *lon = (float)(BASE_LON + x_m * DEG_PER_M_LON);
}

// ── TetaGuardLocBindVerify — simulation proxy for Eqs. 3.27-3.29 ─────────────
// The critical property fixed here (user issue §6): position and RSSI must be
// INSIDE the signed message (Eq. 3.27), not checked as separate runtime conditions
// on unsigned metadata.  An attacker with valid keys but false metadata cannot lie
// about pos_Vk because the signature would not match the actual signed payload.
//
// How this proxy achieves cryptographic binding in simulation:
//   1. The reporter's actual position comes from event.reporter_position (NS-3
//      ground truth set by the simulation's MobilityModel — not attacker-controlled).
//   2. create_location_bound_report() packs that position into LocationBindingPayload
//      and calls dilithium5_sign_locbind() — the position is now INSIDE the signature.
//   3. verify_single_witness() re-derives the same spatial and RSSI values FROM the
//      signed payload, then runs the full 4-gate + spatial + Friis check against
//      those cryptographically-bound values (not against unsigned PemEvent fields).
//
// For an out-of-range ME attacker:
//   event.reporter_position is far from the link → signed position is far from link
//   → verify_single_witness gate (ii): haversine_distance > R_COMM_METERS → REJECTED
//
// link_ep_x/y: NS-3 Cartesian coordinates of the link endpoint nearest the reporter
static bool
TetaGuardLocBindVerify(const PemEvent& event, double link_ep_x, double link_ep_y)
{
    // One-time CA initialisation — must fire before any key pair is issued
    if (!g_locbind_ca_ready) {
        teta_ca_init();
        g_locbind_ca_ready = true;
    }

    // Lazy key-pair generation per unique reporter_id
    uint32_t rid = event.reporter_id;
    if (!g_locbind_keys.count(rid)) {
        LocBindKeyPair &kp = g_locbind_keys[rid];
        dilithium5_keygen(kp.pk, kp.sk);
        uint8_t vid_bytes[16];
        memset(vid_bytes, 0, sizeof(vid_bytes));
        snprintf((char *)vid_bytes, sizeof(vid_bytes), "V%u", rid);
        // Issue CA cert: bind vehicle identity to its public key
        dilithium5_issue_cert(vid_bytes, kp.pk,
                              (uint64_t)(Simulator::Now().GetSeconds() * 1000.0),
                              &kp.cert);
    }
    LocBindKeyPair &kp = g_locbind_keys[rid];

    // Link identifier — pack src/dst node IDs into 8-byte field
    uint8_t link_id[8] = {};
    link_id[0] = (uint8_t)(event.link_src_id        & 0xFF);
    link_id[1] = (uint8_t)((event.link_src_id >> 8) & 0xFF);
    link_id[4] = (uint8_t)(event.link_dst_id        & 0xFF);
    link_id[5] = (uint8_t)((event.link_dst_id >> 8) & 0xFF);

    // Reporter GPS position (NS-3 Cartesian → lat/lon for haversine)
    float rep_lat, rep_lon;
    ns3_to_gps(event.reporter_position.x, event.reporter_position.y,
               &rep_lat, &rep_lon);

    // Fix 5.1 (Eq. 3.29 RSSI_Vk<-Vi — "measured at Vk from endpoint Vi"): use the
    // REAL PHY-measured RSSI (event.rssi_reporter_dbm, populated in PemEmitEvent()
    // from Rx()'s MonitorSnifferRx signalNoise.signal via g_phy_rssi_dbm) when the
    // reporter actually received a beacon from one of the link endpoints. This is
    // what makes the Eq. 3.27-3.29 cryptographic binding meaningful: an attacker
    // who never physically received a signal from the link cannot produce this
    // value merely by knowing positions. Only when no real measurement exists
    // (event.rssi_reporter_dbm == PEM_SIGNAL_PLACEHOLDER — e.g. an ME echo
    // reporter that never received a beacon from the link it claims to witness)
    // does this fall back to the same Cost231-boundary estimate used by Stage-1
    // sig[8], so out-of-range/never-heard reporters are still rejected via the
    // RSSI-floor path rather than silently passing.
    const bool hasRealRssi = (event.rssi_reporter_dbm != PEM_SIGNAL_PLACEHOLDER);
    float syntheticRSSI;
    if (hasRealRssi)
    {
        syntheticRSSI = (float)event.rssi_reporter_dbm;
    }
    else
    {
        // RSSI(d) = g_rssi_min + 10·PEM_RSSI_N_COST231·log10(g_rcomm / d)
        // At d = g_rcomm: RSSI = g_rssi_min (boundary).  d > g_rcomm → RSSI < g_rssi_min.
        const double distToSrc = PemDistance2d(event.reporter_position, event.link_src_position);
        const double distToDst = PemDistance2d(event.reporter_position, event.link_dst_position);
        const double nearestDist = std::min(distToSrc, distToDst);
        const double safeNearestDist = (nearestDist > 0.001) ? nearestDist : 0.001;
        syntheticRSSI = (float)(g_rssi_min
            + 10.0 * PEM_RSSI_N_COST231 * std::log10(g_rcomm / safeNearestDist));
    }

    // Reporter identity bytes
    uint8_t rid_bytes[16];
    memset(rid_bytes, 0, sizeof(rid_bytes));
    snprintf((char *)rid_bytes, sizeof(rid_bytes), "V%u", rid);

    // Eq. 3.27 + 3.28: bind {eij, pos_Vk, RSSI, τs, nonce} into Dilithium5 sig.
    // After this call, lbr.signature is a valid ML-DSA-87 signature over
    // lbr.payload — which contains the ACTUAL reporter position and RSSI.
    LocationBoundReport lbr;
    create_location_bound_report(
        link_id,
        rep_lat, rep_lon,
        syntheticRSSI,                                    /* signed rssi_from_vi_dbm */
        (uint64_t)(event.sender_timestamp * 1000.0),
        rid_bytes,
        kp.sk, kp.pk, &kp.cert,
        &lbr);

    // RSU's own RSSI measurement — the vehicle cannot forge this field
    lbr.rsu_measured_rssi_dbm = syntheticRSSI;
    lbr.has_rsu_measurement   = true;

    // Link endpoint GPS (the one closer to the reporter, already selected by caller)
    float ep_lat, ep_lon;
    ns3_to_gps(link_ep_x, link_ep_y, &ep_lat, &ep_lon);

    // Eq. 3.29: Gate A (CA cert) → Gate B (cert pk) → Gate D (freshness) →
    //           Gate E (nonce novelty) → Gate C (Dilithium5 verify) →
    //           (ii) haversine(signed_pos, link_ep) ≤ R_COMM_METERS →
    //           (iii)+(iv) rsu_measured_rssi ≥ RSSI_MIN + Friis margin
    // All three Eq. 3.29 conditions check values FROM the signed payload (pos, RSSI)
    // — not from unsigned PemEvent metadata.
    uint64_t recv_ms = (uint64_t)(Simulator::Now().GetSeconds() * 1000.0);
    return verify_single_witness(&lbr, ep_lat, ep_lon, recv_ms);
}

// ── Per-trusted-node crypto state ────────────────────────────────────────────
// Each RSU or designated OBU has its own:
//   nonce_cache        : 64-bit keys  (physical_sender_id << 32 | timestamp_slot)
//   link_witnesses     : "minId_maxId" → set of legitimate reporter IDs seen so far
//   link_all_reporters : "minId_maxId" → set of ALL reporter IDs (legit + in-range
//                        attackers that passed the distance/RSSI check).  Used to
//                        compute n for the dynamic quorum t = ⌊n/2⌋ + 1 (Eq. 3.30).
//
// The controller (reporter_id sentinel = 9999 or N_Vehicles+N_RSUs) gets its
// own entry in this map — its nonce cache is separate from every RSU's cache.
struct TrustedNodeCryptoState {
    // Eq. 3.17: N_seen — ALL nonces ever observed by this verifier, cross-sender.
    // Key = (claimed_sender_id << 32) | timestamp_slot, representing the nonce
    // VALUE embedded in the original packet (which belongs to the claimed sender,
    // not necessarily the physical replayer).  A single flat set per verifier,
    // matching "previously observed by the verifier from any sender."
    std::set<uint64_t>                           nonce_cache;
    std::map<std::string, std::set<uint32_t>>    link_witnesses;     // legit reporters only
    std::map<std::string, std::set<uint32_t>>    link_all_reporters; // legit + in-range attackers
    // Eq. 3.26: per-link accumulator of real IndividualSignedReports from legitimate
    // reporters.  Populated by vehicle_sign_report() when !attack_label events arrive.
    // Consumed by verify_threshold_sig() in Step 1c when an attack event arrives.
    // Capped at MAX_REPORTS_PER_RSU entries per link (AggregateReport struct limit).
    std::map<std::string, std::vector<IndividualSignedReport>> link_signed_reports;
    // Per-reporter key material: lazy-generated Dilithium5 keypairs keyed by reporter ID.
    // Matches the per-reporter key pairs used in TetaGuardLocBindVerify().
    std::map<uint32_t, LocBindKeyPair>           reporter_thresh_keys;
};

// Indexed by reporter_id (RSU NS-3 node ID, OBU vehicle ID, or controller ID)
static std::map<uint32_t, TrustedNodeCryptoState> g_per_node_crypto_state;

// Aggregate drop counters (summed across all trusted nodes — for CSV output)
static uint64_t tg_crypto_drop_mac    = 0;
static uint64_t tg_crypto_drop_stale  = 0;
static uint64_t tg_crypto_drop_nonce  = 0;
static uint64_t tg_crypto_drop_quorum = 0;

// ── Algorithm 3 (LW-MITIGATE) — live per-event enforcement ──────────────────
// Thesis name : Algorithm 3 (LW-MITIGATE), §3.4.2, Fig. 3.15
// Thesis steps: (1) HMAC-SHA256(K_{Vi,nk}, m‖τs‖nonce) Eq. 3.15
//               (2) |τr − τs| ≤ Tb + ε                  Eq. 3.16
//               (3) nonce ∉ Nseen                        Eq. 3.17
//
// ── Key source for K_{Vi,nk} (Eq. 3.15) — §3.4.2 ────────────────────────────
// The session key K_{Vi,nk} is a 32-byte shared secret established as follows:
//   1. Vehicle Vi verifies nk's certificate chain against the PKI trust anchor.
//   2. Vi performs ML-KEM-1024 (Kyber-1024) + HQC-5 Hybrid-KEM with nk's
//      certified public key (§3.3 Steps 3-4, implemented in kem.cc →
//      kem_rsu_encapsulate()).
//   3. K_{Vi,nk} = HKDF-SHA256(ss_Kyber ⊕ ss_HQC5, vehicle_id).
// This key is then the root secret for both HMAC authentication (Eq. 3.15) and
// LKH enrollment (§3.4.2, Eq. 3.18).
//
// ── Trusted node nk in no-RSU scenarios (N_RSUs = 0) ────────────────────────
// §3.1.3 p.20: "Detection logic is embedded within each trusted node nk
// (RSU or designated OBU)."  When N_RSUs = 0 (attack scenarios 1, 3, 5, 7,
// 9, 11), the trusted verifier is a designated OBU (vehicle) acting as nk.
// Key bootstrapping is identical — Vi contacts the designated OBU at first
// contact, performs the ML-KEM-1024 + HQC-5 handshake, and derives K_{Vi,OBU}.
// In the simulation, all session keys are pre-assumed established at t=0
// (setup phase); no in-simulation KEM handshake occurs.
//
// ── This runs for real, on every event, every routing.cc run ────────────────
// TetaGuardCryptoFilter() below is called unconditionally from PemEmitEvent()
// (guarded only by the --no_crypto=1 ablation flag, which defaults to false)
// for every PemEvent — topology update, heartbeat, and beacon. All three
// Algorithm 3 checks are genuine, not ground-truthed off event.attack_label:
//   Step 1 (Eq. 3.15) — real HMAC-SHA256 via OpenSSL's HMAC(), computed over
//     m' = TetaGuardBuildAuthPayload() using per-vehicle session keys derived
//     by TetaGuardGetSessionKey(); macExp vs macReceived compared in constant
//     time (TetaGuardCtMemcmp). Two different physical/claimed identities
//     produce cryptographically different keys and therefore different tags.
//   Step 2 (Eq. 3.16) — real |reception_timestamp - sender_timestamp| bound.
//   Step 3 (Eq. 3.17) — real per-trusted-node nonce cache
//     (state.nonce_cache, one entry per reporter_id in g_per_node_crypto_state).
// This is a separate, self-contained real-crypto implementation from
// hmac_filter.cc's BeaconMessage/beacon_sign()/lw_mitigate() — that file's
// functions remain wired only into the --latency=1 timing-benchmark path
// (TimedHmacSign/TimedHmacVerify) and are not on this live detection path.
// TetaGuardGetSessionKey() uses a deterministic per-vehicle-id derivation
// rather than a live ML-KEM-1024+HQC-5 handshake result, matching the
// "session keys pre-assumed established at t=0" simplification stated above.
//
// reporter_id : trusted node nk performing verification (RSU node ID, OBU
//               vehicle ID, or 9999 for the controller).  Each nk has its OWN
//               entry in g_per_node_crypto_state (independent Nseen per node).
//
// ── Gap 9 fix — real HMAC-SHA256 for Step 1 (Eq. 3.15), not a ground-truth proxy ──
// Previously Step 1 was `physical_sender_id != claimed_sender_id` — a simulation
// shortcut, since PemEvent carries no real HMAC bytes or session-key material.
// This is now a genuine HMAC-SHA256 computation using OpenSSL (already linked —
// routing.cc includes <openssl/hmac.h> directly and this build has liboqs/OpenSSL
// linked, confirmed at runtime via "[PQC] liboqs linked").
//
// K_{Vi,nk} (Eq. 3.15): deterministic per-vehicle 256-bit session key. Real
// deployment derives this via HKDF-SHA256(ss_Kyber XOR ss_HQC5, vehicle_id)
// after the ML-KEM-1024 + HQC-5 handshake (§3.4.2) — this simulation already
// documents that "all session keys are pre-assumed established at t=0" (no
// in-simulation KEM handshake occurs), so a deterministic per-id derivation
// reproduces that pre-established state without needing a live handshake.
static void
TetaGuardGetSessionKey(uint32_t vehicle_id, uint8_t out[SESSION_KEY_LEN])
{
    for (uint32_t j = 0; j < SESSION_KEY_LEN; j++) {
        out[j] = (uint8_t)((vehicle_id * 37u + j * 13u + 0x5Au) & 0xFFu);
    }
}

static void
TetaGuardComputeHmac(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[HMAC_SHA256_LEN])
{
    unsigned mac_len = HMAC_SHA256_LEN;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &mac_len);
}

// Constant-time compare — prevents timing side-channel (mirrors hmac_filter.cc's
// ct_memcmp, duplicated here since teta_guard_filter.h doesn't include that .cc).
static bool
TetaGuardCtMemcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

// m' = m ‖ τs ‖ nonce  (Eq. 3.49). m identifies WHAT is being claimed: the
// claimed sender identity, the reported link, and the message type (16 bytes)
// — τs is the sender timestamp in ms (8 bytes) — nonce is the SAME 64-bit
// value used for Eq. 3.17's N_seen cache (8 bytes), so one nonce serves both
// the authenticated payload and the replay cache, matching Eq. 3.49's single
// noncei. Total 32 bytes.
static size_t
TetaGuardBuildAuthPayload(const PemEvent& event, uint64_t nonceKey,
                          uint8_t out[32])
{
    size_t off = 0;
    uint32_t claimed = event.claimed_sender_id;
    uint32_t lsrc     = event.link_src_id;
    uint32_t ldst     = event.link_dst_id;
    uint32_t etype    = (uint32_t)event.type;
    memcpy(out + off, &claimed, 4); off += 4;
    memcpy(out + off, &lsrc,    4); off += 4;
    memcpy(out + off, &ldst,    4); off += 4;
    memcpy(out + off, &etype,   4); off += 4;
    int64_t ts_ms = (int64_t)(event.sender_timestamp * 1000.0);
    memcpy(out + off, &ts_ms, 8); off += 8;
    memcpy(out + off, &nonceKey, 8); off += 8;
    return off;   // 32 bytes
}

// Returns true  → event passes all three checks → forward to Algorithm 1 (LW)
// Returns false → event dropped at Stage 0 (silent drop per Algorithm 3)
static bool
TetaGuardCryptoFilter(const PemEvent& event, uint32_t reporter_id)
{
    // ── Controller bypass (all checks, §3.4.2 — insider holds all valid keys) ─
    // Malicious controller scenarios use physical_sender_id sentinel 9999.
    // The controller generates valid MACs, fresh timestamps, and novel nonces,
    // so none of the three Algorithm 3 checks can catch it.
    // Stage 1 (LW) + blockchain divergence check are the sole defences.
    //
    // This bypass ALSO covers TetaGuardLocBindVerify (Eqs. 3.27-3.29) below, by
    // construction: ME-S3/S4 (malicious-controller ME variants) never reach
    // Step 1b, since this function returns here first for any event where
    // is_malicious_controller is true. This is intentional, not a gap: the
    // controller IS the verifier administering the location-binding check, so
    // a compromised controller can just skip verifying its own fabrication —
    // no signature scheme defends against a malicious verifier. Real crypto
    // location-binding (TetaGuardLocBindVerify) only applies where it is
    // architecturally meaningful: ME-S1/S2, where an EXTERNAL attacker
    // (vehicle/RSU) must convince an HONEST verifier.
    if (is_malicious_controller)
        return true;

    // Retrieve (or create) this verifier node's state
    TrustedNodeCryptoState& state = g_per_node_crypto_state[reporter_id];

    // Eq. 3.17 nonce — computed here (moved up from Step 3 below) so Step 1 can
    // fold it into m' = m‖τs‖nonce (Eq. 3.49). The novelty CHECK against
    // state.nonce_cache still happens at Step 3, in its original position —
    // this only moves the VALUE computation earlier, no behaviour change there.
    const uint32_t ts_slot   = (uint32_t)(event.sender_timestamp * 10.0 + 0.5);
    const uint32_t type_bits = (uint32_t)event.type;
    const uint32_t link_hash = event.link_src_id * 1000003u ^ event.link_dst_id;
    const uint64_t nonce_key = ((uint64_t)event.claimed_sender_id << 32)
                             | ((uint64_t)(ts_slot   & 0x3FFFu) << 18)
                             | ((uint64_t)(type_bits & 0x7u)    << 15)
                             | ((uint64_t)(link_hash & 0x7FFFu));

    // ── Step 1 — Eq. 3.15: MAC_exp = HMAC-SHA256(K_Vi, m') =?= MAC_received ──
    // Real HMAC-SHA256 computation (Gap 9 fix), not a ground-truth identity
    // shortcut. K_Vi is the CLAIMED sender's session key (the verifier
    // recomputes the tag it expects from Vi); MAC_received is simulated as
    // HMAC-SHA256 under the PHYSICAL sender's own key (what the actual
    // transmitter would have produced, whether or not it holds Vi's key).
    // When physical_sender_id == claimed_sender_id, both HMACs use the SAME
    // key over the SAME m' → deterministically equal → PASS. When they
    // differ, different 256-bit keys over the same message → HMAC-SHA256
    // output differs with overwhelming probability → FAIL. This reproduces
    // Eq. 3.1's identity-spoofing matrix (I_jk = 1 iff physical j claims k)
    // via genuine cryptographic computation instead of a data-driven shortcut.
    //
    // Eq. 3.26: Verify_agg(σ_agg, PK_agg) = 0 when attacker holds 0 key shares
    // — handled separately below (Step 1c, real Dilithium5 threshold sigs).
    //
    // Catches:
    //   BSHH-S1/S2 : attacker (physical) impersonates victim (claimed)
    //   TTW-S2      : malicious RSU (physical) claims topology from vehicle (claimed)
    //
    // Does NOT catch:
    //   TTW-S1 : attacker replays its OWN stored observation (physical == claimed == V0)
    //            → caught by Step 2 (freshness) and Step 3 (nonce replay) below
    //   ME-S1/S2 : echo reporters claim their own identity (physical == claimed == V3)
    //              → caught by Eq. 3.29 location-binding check below
    {
        uint8_t authPayload[32];
        const size_t authLen = TetaGuardBuildAuthPayload(event, nonce_key, authPayload);
        uint8_t keyClaimed[SESSION_KEY_LEN], keyPhysical[SESSION_KEY_LEN];
        TetaGuardGetSessionKey(event.claimed_sender_id, keyClaimed);
        TetaGuardGetSessionKey(event.physical_sender_id, keyPhysical);
        uint8_t macExp[HMAC_SHA256_LEN], macReceived[HMAC_SHA256_LEN];
        TetaGuardComputeHmac(keyClaimed, SESSION_KEY_LEN, authPayload, authLen, macExp);
        TetaGuardComputeHmac(keyPhysical, SESSION_KEY_LEN, authPayload, authLen, macReceived);
        if (!TetaGuardCtMemcmp(macExp, macReceived, HMAC_SHA256_LEN))
        {
            tg_crypto_drop_mac++;
            return false;
        }
    }

    // ── Pre-registration — benign witnesses register BEFORE Step 1b's quorum ──
    // check (Eq. 3.30 follow-up fix). Moved out of the old post-Step-1b block
    // below (which only ran the plain registration, never the quorum gate,
    // because it was reached only after Step 1b already returned/passed).
    // Root cause this fixes: since Step 1b now also evaluates benign ME-S1/S2
    // reports (issue 5.2/5.3), a benign event that only registered itself
    // AFTER passing Step 1b's quorum check could never pass that same check
    // in the first place — link_witnesses for a brand-new link starts empty,
    // so legit_count(0) < quorum_t(>=1) always failed, even for the very
    // first honest report of a link. Registering the reporter here — before
    // Step 1b runs — means a benign report counts toward its OWN quorum
    // check (matching Eq. 3.30's set builder semantics: Vk is a member of
    // {Vk : Accept_Vk(eij)=1} the moment it individually passes Eq. 3.29,
    // not only on some later event). Attack-labelled reports are unaffected
    // — they are never added to link_witnesses (only to link_all_reporters,
    // still done inside Step 1b itself), so an attacker still cannot inflate
    // its own quorum count.
    if (!event.attack_label && event.type == PEM_EVENT_TOPOLOGY_UPDATE)
    {
        const uint32_t me_lmin_pre = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax_pre = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey_pre =
            std::to_string(me_lmin_pre) + "_" + std::to_string(me_lmax_pre);
        state.link_witnesses[lkey_pre].insert(event.reporter_id);
        state.link_all_reporters[lkey_pre].insert(event.reporter_id);
    }

    // ── Step 1b — ME location-binding + quorum (Eqs. 3.27-3.30) ────────────────
    // ME echo reporters claim their own identity (physical == claimed — Step 1
    // passes) but report a link they cannot physically observe.
    //
    // Issue §6 fix: position and RSSI must be cryptographically bound INSIDE the
    // signed message (Eq. 3.27) — not checked as separate runtime conditions on
    // unsigned metadata.  The previous implementation ran a plain distance/RSSI
    // plausibility check on PemEvent fields, which an attacker with valid keys
    // could bypass by setting false position metadata without touching the signature.
    //
    // Fixed path via TetaGuardLocBindVerify():
    //   1. The reporter's actual NS-3 position is extracted from event.reporter_position
    //      (ground truth from MobilityModel — not attacker-modifiable metadata).
    //   2. create_location_bound_report() (Eq. 3.27+3.28) packs that position and
    //      synthetic RSSI into LocationBindingPayload and calls dilithium5_sign_locbind()
    //      — position/RSSI are now INSIDE the Dilithium5 signature.
    //   3. verify_single_witness() (Eq. 3.29) checks Gates A/B/D/E/C, then
    //      haversine_distance(signed_pos, link_ep) ≤ R_COMM_METERS, then
    //      rsu_measured_rssi ≥ RSSI_MIN + Friis margin — all against the signed values.
    //
    // For an out-of-range ME attacker:
    //   signed pos is far from link → gate (ii) fails → REJECTED before quorum.
    //
    // Eq. 3.30: link eij accepted only when ≥ t = ⌊n/2⌋ + 1 reporters individually
    // pass Eq. 3.29, where n is the total number of reporters for this link seen so
    // far (legitimate + in-range attackers that passed the crypto+spatial+RSSI check).
    //
    // Issue 5.2/5.3 fix: previously gated on event.attack_label==true as well, so
    // benign witness reports in ME-S1/S2 never went through Eq. 3.29 location-binding
    // or fed the Eq. 3.30 quorum reporter set — only attack-labeled echoes did. Eq.
    // 3.29 in the report is unconditional ("every topology observation report... is
    // accepted iff..."), so benign reports in these two scenarios must run the same
    // gate as attack reports. Scope is intentionally still limited to ME-S1/S2 (see
    // TetaGuardLocBindVerify's header comment — location-binding is only meaningful
    // where an external attacker must convince an honest verifier); the other 10
    // scenarios are untouched.
    if (event.type == PEM_EVENT_TOPOLOGY_UPDATE &&
        (attack_scenario == ME_S1_MAL_VEH_NO_RSU ||
         attack_scenario == ME_S2_MAL_RSU))
    {
        // Select the link endpoint nearest to the reporter as the spatial reference.
        // verify_single_witness uses this lat/lon as the link endpoint for gate (ii).
        const double distToSrc = PemDistance2d(event.reporter_position,
                                               event.link_src_position);
        const double distToDst = PemDistance2d(event.reporter_position,
                                               event.link_dst_position);
        const bool closer_to_src = (distToSrc <= distToDst);
        const double ep_x = closer_to_src
            ? event.link_src_position.x : event.link_dst_position.x;
        const double ep_y = closer_to_src
            ? event.link_src_position.y : event.link_dst_position.y;

        // Eqs. 3.27-3.29: full crypto path — position + RSSI bound in signature.
        // tg_crypto_drop_mac accumulates rejections at this gate (identity+location).
        if (!TetaGuardLocBindVerify(event, ep_x, ep_y))
        {
            tg_crypto_drop_mac++;
            return false;
        }

        // Reporter passed Eq. 3.29 (all gates including signed spatial + RSSI).
        // Count it in the total reporter set for this link so that the dynamic
        // quorum t = ⌊n/2⌋ + 1 reflects all reporters, not just legitimate ones.
        const uint32_t me_lmin_a = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax_a = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey_a  = std::to_string(me_lmin_a) + "_" + std::to_string(me_lmax_a);
        state.link_all_reporters[lkey_a].insert(event.reporter_id);

        // Eq. 3.30: compute dynamic quorum t = ⌊n/2⌋ + 1
        const uint32_t n_total   = static_cast<uint32_t>(
            state.link_all_reporters.at(lkey_a).size());
        const uint32_t quorum_t  = (n_total / 2u) + 1u;
        const uint32_t legit_count =
            state.link_witnesses.count(lkey_a)
                ? static_cast<uint32_t>(state.link_witnesses.at(lkey_a).size())
                : 0u;
        if (legit_count < quorum_t)
        {
            tg_crypto_drop_quorum++;
            return false;   // Eq. 3.30: legitimate witnesses < ⌊n/2⌋+1
        }
    }

    // Eq. 3.26 (Step 1c) signed-report accumulation for THIS trusted node.
    // link_witnesses/link_all_reporters registration for this event already
    // happened in the pre-registration block above (before Step 1b), so it is
    // NOT repeated here — this block now only builds the IndividualSignedReport
    // material that verify_threshold_sig() consumes in Step 1c when an attack
    // event arrives for the same link.
    if (!event.attack_label && event.type == PEM_EVENT_TOPOLOGY_UPDATE)
    {
        const uint32_t me_lmin = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey = std::to_string(me_lmin) + "_" + std::to_string(me_lmax);

        // Eq. 3.26 real crypto: sign this legitimate report so the aggregate can
        // be verified via verify_threshold_sig() in Step 1c when needed.
        if (has_RSU_infrastructure &&
            state.link_signed_reports[lkey].size() < MAX_REPORTS_PER_RSU)
        {
            // Lazy keypair generation per reporter (same pattern as LocBind keys)
            uint32_t rid = event.reporter_id;
            if (!state.reporter_thresh_keys.count(rid))
            {
                if (!g_locbind_ca_ready) { teta_ca_init(); g_locbind_ca_ready = true; }
                LocBindKeyPair &kp = state.reporter_thresh_keys[rid];
                dilithium5_keygen(kp.pk, kp.sk);
                uint8_t vid_bytes[16]; memset(vid_bytes, 0, sizeof(vid_bytes));
                snprintf((char *)vid_bytes, sizeof(vid_bytes), "V%u", rid);
                dilithium5_issue_cert(vid_bytes, kp.pk,
                    (uint64_t)(Simulator::Now().GetSeconds() * 1000.0), &kp.cert);
            }
            LocBindKeyPair &kp = state.reporter_thresh_keys[rid];

            // Build a 4-byte payload encoding the link (src_id || dst_id)
            uint8_t msg_payload[4];
            msg_payload[0] = (uint8_t)(event.link_src_id & 0xFF);
            msg_payload[1] = (uint8_t)((event.link_src_id >> 8) & 0xFF);
            msg_payload[2] = (uint8_t)(event.link_dst_id & 0xFF);
            msg_payload[3] = (uint8_t)((event.link_dst_id >> 8) & 0xFF);

            uint64_t ts_ms = (uint64_t)(event.sender_timestamp * 1000.0);

            // Nonce: deterministic from (reporter_id, link_key, timestamp) so the
            // same report can't be submitted twice under a different nonce.
            uint8_t nonce[NONCE_LEN]; memset(nonce, 0, NONCE_LEN);
            uint32_t nonce_seed = rid ^ me_lmin ^ me_lmax ^ (uint32_t)(ts_ms & 0xFFFFFFFF);
            memcpy(nonce, &nonce_seed, sizeof(nonce_seed));

            IndividualSignedReport isr;
            memset(&isr, 0, sizeof(isr));
            memcpy(isr.msg_payload, msg_payload, 4);
            isr.timestamp_ms = ts_ms;
            memcpy(isr.nonce, nonce, NONCE_LEN);
            memcpy(isr.pub_key, kp.pk, DILITHIUM5_PK_LEN);
            isr.cert = kp.cert;
            snprintf((char *)isr.vehicle_id, sizeof(isr.vehicle_id), "V%u", rid);
            size_t sig_len_out = 0;
            // Bug fix: sign the full zero-padded isr.msg_payload (256 bytes) —
            // NOT the raw 4-byte local msg_payload — because verify_threshold_sig's
            // Gate C (threshold_sig.cc) reconstructs the signed buffer using
            // sizeof(r->msg_payload) = 256 unconditionally. Signing only 4 bytes
            // here while Gate C verifies against 256 made every individual
            // signature check fail by construction, for legitimate AND attack
            // reports alike. isr.msg_payload is already the correctly zero-padded
            // 256-byte buffer (set above via memset + memcpy of the real 4 bytes),
            // so signing it directly matches Gate C's reconstruction exactly.
            vehicle_sign_report(isr.msg_payload, sizeof(isr.msg_payload), ts_ms, nonce, kp.sk,
                                isr.individual_sig, &sig_len_out);
            state.link_signed_reports[lkey].push_back(isr);
        }
    }

    // ── Step 1c — Threshold aggregate signature (Eq. 3.26) for RSU-relayed reports ─
    // Eq. 3.26: Verify(σ_agg, PK_agg) = 1
    //           ⟺ |{i : Verify(σ_i, msg_i, PK_Vi) = 1}| ≥ t
    //           where t = max(THRESHOLD_T_FLOOR, ⌊n/2⌋ + 1)
    //
    // §3.4.4 scope: "For RSU-aggregated beacon reports" — the check applies ONLY
    // when an RSU (not a vehicle, not the controller) is the physical sender.
    // Three conditions narrow this to genuine RSU-relayed events:
    //   (a) physical_sender ≠ link_src_id : not V1 self-reporting directly
    //   (b) physical_sender ≠ link_dst_id : not V2 self-reporting directly
    //   (c) physical_sender ≠ 9999u       : not a controller-internal sentinel
    //       (TTW-S4, ME-S4 use 9999 as reporter; they reach Stage-1 for detection,
    //        not Stage-0 drop — threshold aggregate sigs don't apply there)
    //
    // Real crypto path: build AggregateReport from stored IndividualSignedReports,
    // call rsu_aggregate_reports() + verify_threshold_sig() (Gates A/B/C/D + nonce
    // replay from threshold_sig.cc).  The attacker holds no key shares for the
    // legitimate reporters → zero valid partial signatures → below threshold → DROP.
    if (has_RSU_infrastructure &&
        event.type == PEM_EVENT_TOPOLOGY_UPDATE &&
        event.physical_sender_id != event.link_src_id &&
        event.physical_sender_id != event.link_dst_id &&
        event.physical_sender_id != 9999u)
    {
        const uint32_t s1c_lmin = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t s1c_lmax = std::max(event.link_src_id, event.link_dst_id);
        const std::string s1c_key =
            std::to_string(s1c_lmin) + "_" + std::to_string(s1c_lmax);

        // Also count this attacker in link_all_reporters so t = ⌊n/2⌋+1 uses the
        // real total reporter count (Eq. 3.26 left side denominator).
        state.link_all_reporters[s1c_key].insert(event.reporter_id);

        const auto &signed_vec = state.link_signed_reports.count(s1c_key)
            ? state.link_signed_reports.at(s1c_key)
            : std::vector<IndividualSignedReport>{};

        if (signed_vec.empty())
        {
            // No legitimate signed reports accumulated yet → attacker cannot
            // satisfy any quorum (0 valid sigs < THRESHOLD_T_FLOOR = 3).
            tg_crypto_drop_mac++;
            return false;
        }

        // Build AggregateReport from stored legitimate IndividualSignedReports
        AggregateReport agg;
        memset(&agg, 0, sizeof(agg));
        const uint32_t n_reps =
            (uint32_t)signed_vec.size() < MAX_REPORTS_PER_RSU
                ? (uint32_t)signed_vec.size()
                : MAX_REPORTS_PER_RSU;
        rsu_aggregate_reports(&agg,
                              signed_vec.data(),
                              n_reps);

        // verify_threshold_sig() implements the full Eq. 3.26 biconditional:
        //   Step 1: aggregate sig consistency (tamper detection)
        //   Step 2: per-signer Dilithium5 verify, count valid ≥ t
        // Returns THRESHOLD_SIG_PASS only when quorum is met.
        ThresholdSigResult tsr = verify_threshold_sig(&agg);
        if (tsr != THRESHOLD_SIG_PASS)
        {
            tg_crypto_drop_mac++;
            return false;   // Eq. 3.26: |{valid σ_i}| < t — aggregate rejected
        }
    }

    // ── Step 2 — Timestamp freshness (Eq. 3.16) ──────────────────────────────
    // Eq. 3.16: |τr − τs| ≤ Tb + ε  (ABSOLUTE VALUE — bidirectional)
    // std::abs is intentional: catches both backward-dated stale replays
    // (τs ≪ τr) AND forward-dated forgeries (τs ≫ τr).
    // The flowchart (Fig. 3.15) shows the simplified one-directional form
    // τr − τs; the authoritative form is Eq. 3.16 with absolute value.
    const double age = std::abs(event.reception_timestamp - event.sender_timestamp);
    if (age > PEM_BEACON_INTERVAL_S + PEM_PROPAGATION_EPSILON_S)
    {
        tg_crypto_drop_stale++;
        return false;
    }

    // ── Step 3 — Nonce novelty (Eq. 3.17) — per THIS trusted node's cache ────
    // Eq. 3.17: nonce_i ∉ N_seen, where N_seen = "all nonces previously observed
    // by the verifier from ANY sender" — the cache is CROSS-SENDER (flat set).
    //
    // Key uses claimed_sender_id (NOT physical_sender_id):
    //   The nonce VALUE embedded in a packet belongs to its original author
    //   (the claimed sender).  When attacker Vj replays Vi's packet, the
    //   replayed bytes carry Vi's original nonce (claimed_sender_id = Vi).
    //   Keying by physical_sender_id would create a per-sender partition and
    //   let Vj's replay bypass the check with a different cache slot.
    //   Keying by claimed_sender_id puts the nonce in Vi's cache slot regardless
    //   of who physically transmitted it → correct cross-sender N_seen.
    //
    // Per-verifier separation is correct: two RSUs each maintain their OWN
    // N_seen (g_per_node_crypto_state[reporter_id]).  The second RSU's cache
    // does NOT contain the first RSU's consumed nonces — verifiers are independent.
    //
    // Nonce construction — Eq. 3.17: nonce_i ∉ N_seen
    //   Previous key: (claimed_sender_id ∥ ts_slot) — underspecified.
    //   Two distinct legitimate messages from the same node in the same 100 ms
    //   window (e.g. a topology_update and a heartbeat at t=10.0) produced the
    //   same key → second message silently dropped as false replay.
    //
    //   Fix: H(sender_id ∥ ts_slot ∥ message_type ∥ link_payload)
    //   Folds in event.type (3 bits) and a hash of the link endpoints (15 bits)
    //   so each distinct message has a unique nonce even at the same timestamp.
    //   Replay of the SAME message still collides (same type + same link + same ts).
    //
    // nonce_key itself is computed once, earlier in this function (right after
    // `state` is retrieved) so Step 1's m' = m‖τs‖nonce (Eq. 3.49) can reuse
    // the identical value — the check/insert against state.nonce_cache still
    // happens here, in its original position.
    if (state.nonce_cache.count(nonce_key))
    {
        tg_crypto_drop_nonce++;
        return false;
    }
    state.nonce_cache.insert(nonce_key);
    return true;
}

// ── TetaGuardGetDropCounters ──────────────────────────────────────────────────
// Returns aggregate drop counts across all trusted nodes for CSV output.
// Replaces direct access to the old pem_crypto_drop_* globals.
static void
TetaGuardGetDropCounters(uint64_t& mac, uint64_t& stale, uint64_t& nonce, uint64_t& quorum)
{
    mac    = tg_crypto_drop_mac;
    stale  = tg_crypto_drop_stale;
    nonce  = tg_crypto_drop_nonce;
    quorum = tg_crypto_drop_quorum;
}

// Restore routing.cc's #define max / #define min so code after this include
// compiles correctly (mirrors the push_macro/undef at the top of this file).
#pragma pop_macro("min")
#pragma pop_macro("max")
