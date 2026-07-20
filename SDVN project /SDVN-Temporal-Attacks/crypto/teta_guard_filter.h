/*
 * teta_guard_filter.h — Per-Trusted-Node Cryptographic Pre-Filter
 *                        Algorithm 3 (LW-MITIGATE), Eqs. 3.15–3.17 / 3.28, 3.29–3.32
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
 *   • link_witnesses     — Eq. 3.32: legitimate reporter set, separate per verifier
 *   • link_all_reporters — Eq. 3.32: ALL reporters (legit + in-range attackers) for
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

// ── Real Eq. 3.28 threshold aggregate signature implementation ───────────────
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

// ── Per-reporter Dilithium5 key pairs for location-binding (Eqs. 3.29-3.30) ──
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

// ── TetaGuardLocBindVerify — simulation proxy for Eqs. 3.29-3.31 ─────────────
// The critical property fixed here (user issue §6): position and RSSI must be
// INSIDE the signed message (Eq. 3.29), not checked as separate runtime conditions
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

    // Fix 5.1 (Eq. 3.31 RSSI_Vk<-Vi — "measured at Vk from endpoint Vi"):
    // event.rssi_reporter_dbm would carry a REAL PHY-measured signal here if
    // one were available (Rx()'s MonitorSnifferRx callback does receive a
    // genuine NS-3-simulated signalNoise.signal per reception — see Rx() in
    // routing.cc), but that value is only ever logged, not captured into any
    // state PemEmitEvent can read. So in the current build, event.rssi_reporter_dbm
    // is always PEM_SIGNAL_PLACEHOLDER at this point (Stage-0 runs before
    // Stage-1 ever computes a real value for topology events, and beacon-type
    // events never set it at all) — hasRealRssi below is unconditionally
    // false today, and every call falls back to the same Cost231-boundary
    // distance estimate Stage-1 sig[8] uses. That fallback is still a
    // legitimate, real-position-derived check (not a bypass — out-of-range/
    // never-heard reporters are still correctly rejected via the RSSI-floor
    // path), it just isn't the genuine PHY-layer measurement this comment
    // used to claim was wired in. Threading Rx()'s real signalNoise.signal
    // through to here would let this branch actually activate; it is not
    // currently implemented.
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

    // Eq. 3.29 + 3.30: bind {eij, pos_Vk, RSSI, τs, nonce} into Dilithium5 sig.
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

    // Eq. 3.31: Gate A (CA cert) → Gate B (cert pk) → Gate D (freshness) →
    //           Gate E (nonce novelty) → Gate C (Dilithium5 verify) →
    //           (ii) haversine(signed_pos, link_ep) ≤ R_COMM_METERS →
    //           (iii)+(iv) rsu_measured_rssi ≥ RSSI_MIN + Friis margin
    // All three Eq. 3.31 conditions check values FROM the signed payload (pos, RSSI)
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
//                        compute n for the dynamic quorum t = ⌊n/2⌋ + 1 (Eq. 3.32).
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
    // link_signed_reports / reporter_thresh_keys (Eq. 3.28 accumulator + per-
    // reporter Dilithium5 keys for the removed Step 1c threshold-sig gate)
    // removed — Step 1c was a mis-layered Stage-0 duplicate of the correctly-
    // placed post-detection PemVerifyThresholdSig (routing.cc, called from
    // PemApplyMitigation per Algorithm 4's FS-MITIGATE dispatch). See removed-
    // code comment further below in this function for the full rationale.
};

// Indexed by reporter_id (RSU NS-3 node ID, OBU vehicle ID, or controller ID)
static std::map<uint32_t, TrustedNodeCryptoState> g_per_node_crypto_state;

// Aggregate drop counters (summed across all trusted nodes — for CSV output)
static uint64_t tg_crypto_drop_mac    = 0;
static uint64_t tg_crypto_drop_stale  = 0;
static uint64_t tg_crypto_drop_nonce  = 0;
static uint64_t tg_crypto_drop_quorum = 0;
// New (consolidation fix): LKH revocation (Eq. 3.18) drops at this pipeline.
// Kept as a standalone counter (not threaded into TetaGuardGetDropCounters'
// existing 4-field signature / the pem_run_summary.csv row it feeds) so this
// addition can't shift that CSV's existing column layout for any
// already-written analysis scripts. Exposed via its own getter below.
static uint64_t tg_crypto_drop_revoked = 0;

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
//   Step 1 (Eq. 3.15) — real HMAC-SHA256 via OpenSSL's HMAC(), verifying a
//     genuinely CARRIED tag (event.message_mac, set at emission time by
//     TetaGuardSignEvent()) against the tag recomputed from the CLAIMED
//     sender's pairwise key (CryptoGetPairwiseSessionKey, real K_{Vi,nk}
//     scoped to the specific verifying node), compared in constant time
//     (TetaGuardCtMemcmp). physical_sender_id plays no role in this
//     comparison — it is ground truth (who really transmitted the packet),
//     not something an attacker's code can forge; what an attacker forges is
//     the claimed identity and, if it possesses the right key, a matching
//     MAC. See TetaGuardSignEvent's doc comment for how attack-injection
//     code computes message_mac using either its own key (honest signer,
//     will mismatch when claiming a different identity) or a genuinely
//     stolen victim key (sophisticated attacker, will correctly match).
//   Step 2 (Eq. 3.16) — real |reception_timestamp - sender_timestamp| bound.
//   Step 3 (Eq. 3.17) — real per-trusted-node nonce cache
//     (state.nonce_cache, one entry per reporter_id in g_per_node_crypto_state).
// This is a separate, self-contained real-crypto implementation from
// hmac_filter.cc's BeaconMessage/beacon_sign()/lw_mitigate() — that file's
// functions remain wired only into the --latency=1 timing-benchmark path
// (TimedHmacSign/TimedHmacVerify) and are not on this live detection path.
//
// reporter_id : trusted node nk performing verification (RSU node ID, OBU
//               vehicle ID, or 9999 for the controller).  Each nk has its OWN
//               entry in g_per_node_crypto_state (independent Nseen per node).
//
// K_{Vi,nk} (Eq. 3.15): real per-vehicle 256-bit base secret when the t=0
// ML-KEM-1024 + HQC-5 handshake (§3.4.2) succeeded for vehicle_id (falls back
// to a deterministic per-id derivation otherwise — see
// CryptoGetVehicleSessionKey() in routing.cc), HKDF-derived per (vehicle,
// receiver) pair by CryptoGetPairwiseSessionKey() so the final verification
// key genuinely depends on which node is verifying, not just which vehicle
// is claimed — a key exfiltrated from one link does not, by itself, produce
// a valid key for a different verifying node.

static void
TetaGuardComputeHmac(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[HMAC_SHA256_LEN])
{
    unsigned mac_len = HMAC_SHA256_LEN;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &mac_len);
}

// TetaGuardComputeNonceKey — Eq. 3.17 nonce value, factored out of
// TetaGuardCryptoFilter's Step 1/Step 3 so emission-time signing
// (TetaGuardSignEvent, below) can compute the IDENTICAL nonce_key the
// verifier will later derive, without duplicating this formula.
static uint64_t
TetaGuardComputeNonceKey(const PemEvent& event)
{
    const uint32_t ts_slot   = (uint32_t)(event.sender_timestamp * 10.0 + 0.5);
    const uint32_t type_bits = (uint32_t)event.type;
    const uint32_t link_hash = event.link_src_id * 1000003u ^ event.link_dst_id;
    return ((uint64_t)event.claimed_sender_id << 32)
         | ((uint64_t)(ts_slot   & 0x3FFFu) << 18)
         | ((uint64_t)(type_bits & 0x7u)    << 15)
         | ((uint64_t)(link_hash & 0x7FFFu));
}

// TetaGuardSignEvent — computes a genuine HMAC-SHA256 over this event's
// Eq. 3.15 auth payload using signingKeyOwnerId's pairwise session key
// (CryptoGetPairwiseSessionKey, routing.cc — real K_{Vi,nk}, scoped to the
// specific (vehicle, verifying-node) pair) and stores it into
// event.message_mac. Called from PemEmitEvent before Stage-0 verification
// runs, so the event "carries" a real MAC the way an actual packet would —
// signingKeyOwnerId is normally the true physical sender's own ID (the
// honest default), but a sophisticated key-exfiltration attacker can pass a
// stolen victim ID here instead, modeling "this attacker genuinely possesses
// the victim's real key" rather than just relabeling physical_sender_id.
// Forward-declared: full definition (with doc comment) appears later in this
// file, after TetaGuardSignEvent — TetaGuardSignEvent needs it before then.
static size_t TetaGuardBuildAuthPayload(const PemEvent& event, uint64_t nonceKey,
                                         uint8_t out[32]);

static void
TetaGuardSignEvent(PemEvent& event, uint32_t signingKeyOwnerId, uint32_t reporterId)
{
    const uint64_t nonceKey = TetaGuardComputeNonceKey(event);
    uint8_t authPayload[32];
    const size_t authLen = TetaGuardBuildAuthPayload(event, nonceKey, authPayload);
    uint8_t signingKey[SESSION_KEY_LEN];
    CryptoGetPairwiseSessionKey(signingKeyOwnerId, reporterId, signingKey);
    TetaGuardComputeHmac(signingKey, SESSION_KEY_LEN, authPayload, authLen, event.message_mac);
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
    // This bypass ALSO covers TetaGuardLocBindVerify (Eqs. 3.29-3.31) below, by
    // construction: ME-S3/S4 (malicious-controller ME variants) never reach
    // Step 1b, since this function returns here first for any event where
    // is_malicious_controller is true. This is intentional, not a gap: the
    // controller IS the verifier administering the location-binding check, so
    // a compromised controller can just skip verifying its own fabrication —
    // no signature scheme defends against a malicious verifier. Real crypto
    // location-binding (TetaGuardLocBindVerify) only applies where it is
    // architecturally meaningful: ME-S1/S2, where an EXTERNAL attacker
    // (vehicle/RSU) must convince an HONEST verifier.
    // Combined-mode (attack_scenario==13) fix: is_malicious_controller is a
    // plain global contaminated for the whole run once ANY controller-origin
    // scenario's setup executes (see PemEventIsMaliciousControllerOrigin's
    // own comment, routing.cc). Reading the raw global here bypassed Stage-0
    // crypto verification for EVERY event in combined mode, not just
    // controller-origin ones -- PemEventIsMaliciousControllerOrigin resolves
    // the per-event-correct answer instead, with zero behavior change for
    // every single-scenario run (attack_scenario != 13 passes the global
    // through unchanged).
    if (PemEventIsMaliciousControllerOrigin(event))
        return true;

    // ── Revocation (Eq. 3.18) — LKH check added to this pipeline ────────────
    // This pipeline previously had no LKH revocation check at all — only
    // Rx()'s independent lw_mitigate() call (hmac_filter.cc) consulted the
    // real LKH tree (g_lkh_tree/lkh_is_revoked). Meanwhile PemEmitEvent()
    // already runs a SEPARATE, independent revocation-adjacent check before
    // ever reaching this function: g_blacklisted_nodes, populated by
    // PemReadBlacklistFile() polling the Tier-2 cooperative BlacklistBeacon
    // IPC file. That is not a duplicate of LKH — per the paper's §3.4.10
    // Node Removal Mechanism, LKH session-key revocation (Eq. 3.18, O(log n),
    // both Tier 1 and Tier 2) and the Tier-2-only cooperative blacklist-beacon
    // propagation (no-OpenFlow networks) are two distinct, both-legitimate
    // mechanisms — this adds the missing one (LKH) here; it does not replace
    // or duplicate the existing blacklist-file gate in PemEmitEvent.
    // Same leaf-index convention as every other LKH call site in this
    // codebase (physical_sender_id % g_lkh_n_leaves indexes g_lkh_vids).
    if (g_lkh_ready && g_lkh_n_leaves > 0u) {
        const uint32_t leaf_idx = event.physical_sender_id % g_lkh_n_leaves;
        if (lkh_is_revoked(&g_lkh_tree, g_lkh_vids[leaf_idx])) {
            tg_crypto_drop_revoked++;
            return false;
        }
    }

    // Retrieve (or create) this verifier node's state
    TrustedNodeCryptoState& state = g_per_node_crypto_state[reporter_id];

    // Eq. 3.17 nonce — computed here (moved up from Step 3 below) so Step 1 can
    // fold it into m' = m‖τs‖nonce (Eq. 3.49). The novelty CHECK against
    // state.nonce_cache still happens at Step 3, in its original position —
    // this only moves the VALUE computation earlier, no behaviour change there.
    // Factored into TetaGuardComputeNonceKey() so emission-time signing
    // (TetaGuardSignEvent) derives the identical value.
    const uint64_t nonce_key = TetaGuardComputeNonceKey(event);

    // ── Step 1 — Eq. 3.15: MAC_exp = HMAC-SHA256(K_claimed, m') =?= event.message_mac ──
    // Real HMAC-SHA256 verification against a genuinely CARRIED MAC value —
    // event.message_mac, set at emission time by TetaGuardSignEvent() using
    // whichever key the sender actually possesses (its own honest key, or a
    // stolen victim key for a sophisticated attacker). This recomputes the
    // EXPECTED tag from the CLAIMED sender's pairwise key (real K_{Vi,nk},
    // scoped to this specific verifying node) and compares it against the
    // carried value — physical_sender_id plays no role in this comparison
    // at all, matching the fact that it isn't something a real attacker can
    // forge (it's ground truth: who actually transmitted this packet). A
    // sender who signed with the wrong key (its own, while claiming to be
    // someone else) produces a mismatching tag; a sender who genuinely holds
    // the claimed identity's key (honestly, or via real key exfiltration)
    // produces a matching one — the same accept/reject outcome the previous
    // physical-vs-claimed key comparison produced, now via a literal
    // forged-vs-genuine MAC comparison instead of an identity-equality proxy.
    //
    // Eq. 3.28: Verify_agg(σ_agg, PK_agg) = 0 when attacker holds 0 key shares
    // — this is handled at the correct layer by routing.cc's PemVerifyThresholdSig
    // (post-detection, called from PemApplyMitigation), not here at Stage-0;
    // see the removed Step 1c comment further below for why.
    {
        uint8_t authPayload[32];
        const size_t authLen = TetaGuardBuildAuthPayload(event, nonce_key, authPayload);
        uint8_t keyClaimed[SESSION_KEY_LEN];
        CryptoGetPairwiseSessionKey(event.claimed_sender_id, reporter_id, keyClaimed);
        uint8_t macExp[HMAC_SHA256_LEN];
        TetaGuardComputeHmac(keyClaimed, SESSION_KEY_LEN, authPayload, authLen, macExp);
        if (!TetaGuardCtMemcmp(macExp, event.message_mac, HMAC_SHA256_LEN))
        {
            tg_crypto_drop_mac++;
            return false;
        }
    }

    // ── Pre-registration — benign witnesses register BEFORE Step 1b's quorum ──
    // check (Eq. 3.32 follow-up fix). Moved out of the old post-Step-1b block
    // below (which only ran the plain registration, never the quorum gate,
    // because it was reached only after Step 1b already returned/passed).
    // Root cause this fixes: since Step 1b now also evaluates benign ME-S1/S2
    // reports (issue 5.2/5.3), a benign event that only registered itself
    // AFTER passing Step 1b's quorum check could never pass that same check
    // in the first place — link_witnesses for a brand-new link starts empty,
    // so legit_count(0) < quorum_t(>=1) always failed, even for the very
    // first honest report of a link. Registering the reporter here — before
    // Step 1b runs — means a benign report counts toward its OWN quorum
    // check (matching Eq. 3.32's set builder semantics: Vk is a member of
    // {Vk : Accept_Vk(eij)=1} the moment it individually passes Eq. 3.31,
    // not only on some later event). Attack-labelled reports are unaffected
    // — they are never added to link_witnesses (only to link_all_reporters,
    // still done inside Step 1b itself), so an attacker still cannot inflate
    // its own quorum count.
    if (event.type == PEM_EVENT_TOPOLOGY_UPDATE)
    {
        const uint32_t me_lmin_pre = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax_pre = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey_pre =
            std::to_string(me_lmin_pre) + "_" + std::to_string(me_lmax_pre);
        // Structural (not ground-truth) self-report test: the CLAIMED identity
        // (not the physical transmitter) IS one of the two link endpoints, i.e.
        // this event asserts a directly-observed link belonging to that claimed
        // identity, not a third party vouching for a link between two OTHER
        // nodes. Using claimed_sender_id (not physical_sender_id) here matters:
        // an RSU relaying V1's own genuine self-report has physical_sender_id=
        // RSU but claimed_sender_id=V1==link_src_id — still a self-report being
        // transported, not an independent witness claim. Checking
        // physical_sender_id here would misclassify every RSU-relayed self-report
        // (e.g. TTW-S2's legitimate/sophisticated-forged relay of V1's identity)
        // as a third-party ME-style witness claim, when no such claim was ever
        // made — TTW-S2 never asserts "I (the RSU) witnessed a link between two
        // OTHER nodes"; it relays/forges V1's own claim about V1's own link.
        // Third-party reports (CLAIMED identity differs from both endpoints) are
        // handled in Step 1b below and only become witnesses after passing Eq. 3.31.
        const bool is_self_report_pre =
            (event.claimed_sender_id == event.link_src_id) ||
            (event.claimed_sender_id == event.link_dst_id);
        if (is_self_report_pre)
        {
            state.link_witnesses[lkey_pre].insert(event.reporter_id);
        }
        state.link_all_reporters[lkey_pre].insert(event.reporter_id);
    }

    // ── Step 1b — ME location-binding + quorum (Eqs. 3.29-3.32) ────────────────
    // ME echo reporters claim their own identity (physical == claimed — Step 1
    // passes) but report a link they cannot physically observe.
    //
    // Issue §6 fix: position and RSSI must be cryptographically bound INSIDE the
    // signed message (Eq. 3.29) — not checked as separate runtime conditions on
    // unsigned metadata.  The previous implementation ran a plain distance/RSSI
    // plausibility check on PemEvent fields, which an attacker with valid keys
    // could bypass by setting false position metadata without touching the signature.
    //
    // Fixed path via TetaGuardLocBindVerify():
    //   1. The reporter's actual NS-3 position is extracted from event.reporter_position
    //      (ground truth from MobilityModel — not attacker-modifiable metadata).
    //   2. create_location_bound_report() (Eq. 3.29+3.30) packs that position and
    //      synthetic RSSI into LocationBindingPayload and calls dilithium5_sign_locbind()
    //      — position/RSSI are now INSIDE the Dilithium5 signature.
    //   3. verify_single_witness() (Eq. 3.31) checks Gates A/B/D/E/C, then
    //      haversine_distance(signed_pos, link_ep) ≤ R_COMM_METERS, then
    //      rsu_measured_rssi ≥ RSSI_MIN + Friis margin — all against the signed values.
    //
    // For an out-of-range ME attacker:
    //   signed pos is far from link → gate (ii) fails → REJECTED before quorum.
    //
    // Eq. 3.32: link eij accepted only when ≥ t = ⌊n/2⌋ + 1 reporters individually
    // pass Eq. 3.31, where n is the total number of reporters for this link seen so
    // far (legitimate + in-range attackers that passed the crypto+spatial+RSSI check).
    //
    // Issue 5.2/5.3 fix: previously gated on event.attack_label==true as well, so
    // benign witness reports never went through Eq. 3.31 location-binding or fed
    // the Eq. 3.32 quorum reporter set — only attack-labeled echoes did. Eq. 3.31
    // in the report is unconditional ("every topology observation report... is
    // accepted iff..."), so benign reports must run the same gate as attack reports.
    //
    // Gate scoping fix (post-review): previously conditioned on
    // attack_scenario == ME_S1/ME_S2, a run-level CLI parameter that only exists
    // in this scripted 12-scenario harness. A real/blind SUMO+NS-3 run has no such
    // label, so that gate would never fire regardless of whether a genuine
    // out-of-range echo occurred. Replaced with a structural per-report
    // condition (the same shape once also used by the now-removed Step 1c
    // threshold-sig gate, §Eq. 3.28 — see its removed-code comment further
    // below): does the
    // reporter differ from both link endpoints, and is it not the 9999 controller
    // sentinel. This is exactly the paper's reporter-set definition (§3.4.6,
    // Eq. 3.11 ME-S3 signature — "Vk asserts it witnessed link eij", i.e. a third
    // party, not a self-report) and matches the Cryptographic Placement Analysis's
    // vehicle/RSU-vs-controller scoping on structural grounds rather than on which
    // canned scenario is configured. Controller-origin fabrications (ME-S3/S4) tag
    // physical_sender_id = 9999u (see ME_S3_InjectPhantomPaths / ME_S4_InjectPhantomPaths
    // in routing.cc), so they are still excluded here — per Eq. 3.31's own scope,
    // external cryptographic validation does not apply when there is no external
    // message to validate.
    //
    // Ground-truth leak fix (threats-to-validity review): this gate's "legitimate
    // witness" membership can no longer be decided by event.attack_label — a real
    // verifier has no oracle telling it in advance which arriving report is "the
    // attack one". legit_count below is fed exclusively by (a) direct self-reports
    // (claimed_sender_id IS a link endpoint, registered unconditionally in the
    // pre-registration block above — reporting your own directly-observed link is
    // definitionally not an echo) and (b) third-party reports that INDIVIDUALLY
    // pass Eq. 3.31's cryptographic + spatial + RSSI gate below (TetaGuardLocBindVerify),
    // registered into link_witnesses only after that gate succeeds (see below,
    // post-loc-bind-verify). A sophisticated in-range echo with valid keys can still
    // pass Eq. 3.31 and be counted — exactly the real-world failure mode Eq. 3.32's
    // majority quorum (not per-report crypto alone) is meant to catch.
    //
    // Scoping fix: gated on claimed_sender_id (not physical_sender_id) vs the
    // link endpoints, matching the pre-registration block's fix above and for
    // the same reason — this is Eq. 3.31's own reporter-set definition R(eij,t),
    // "vehicles CLAIMING to have witnessed link eij" (a third-party witness
    // assertion), not "whoever physically transmitted the packet". An RSU
    // relaying/forging V1's own self-report (claimed_sender_id==link_src_id,
    // e.g. TTW-S2's sophisticated key-exfiltration path) is an identity-relay
    // event, not a witness claim about a link between two OTHER nodes — it was
    // never in ME's domain and must reach its own designated mechanism
    // (Eq. 3.15-3.17 HMAC/nonce, then LW+TGN/ι_v) instead of being intercepted
    // and silently substituted here.
    if (event.type == PEM_EVENT_TOPOLOGY_UPDATE &&
        event.claimed_sender_id != event.link_src_id &&
        event.claimed_sender_id != event.link_dst_id &&
        event.physical_sender_id != 9999u)
    {
        // Ground-truth leak fix (threats-to-validity review): event.link_src_position
        // / event.link_dst_position are a live GetPosition() read on V1/V2 — two
        // OTHER nodes' true simulator state at verification time — not something
        // this reporter (or any real verifier) could know. A real RSU/controller
        // only knows wherever V1/V2 last authenticated themselves as being, via
        // their own broadcasts. Use g_last_self_reported_position (stamped only
        // from each vehicle's own genuine beacon — see its declaration comment in
        // routing.cc, next to g_pem_last_beacon_time) as the spatial reference
        // instead, falling back to the event field only for the (t≈0) edge case
        // where an endpoint hasn't yet broadcast in this run. This is the same
        // fix already applied to the Stage-1 ME-S3 signature check in routing.cc —
        // this closes the identical oracle in the Stage-0 crypto gate that actually
        // accepts/rejects the packet (a strictly more consequential instance of it).
        const Vector& effectiveSrcPosLb =
            g_last_self_reported_position.count(event.link_src_id)
                ? g_last_self_reported_position.at(event.link_src_id)
                : event.link_src_position;
        const Vector& effectiveDstPosLb =
            g_last_self_reported_position.count(event.link_dst_id)
                ? g_last_self_reported_position.at(event.link_dst_id)
                : event.link_dst_position;

        // Select the link endpoint nearest to the reporter as the spatial reference.
        // verify_single_witness uses this lat/lon as the link endpoint for gate (ii).
        const double distToSrc = PemDistance2d(event.reporter_position,
                                               effectiveSrcPosLb);
        const double distToDst = PemDistance2d(event.reporter_position,
                                               effectiveDstPosLb);
        const bool closer_to_src = (distToSrc <= distToDst);
        const double ep_x = closer_to_src
            ? effectiveSrcPosLb.x : effectiveDstPosLb.x;
        const double ep_y = closer_to_src
            ? effectiveSrcPosLb.y : effectiveDstPosLb.y;

        // Eqs. 3.29-3.31: full crypto path — position + RSSI bound in signature.
        // tg_crypto_drop_mac accumulates rejections at this gate (identity+location).
        if (!TetaGuardLocBindVerify(event, ep_x, ep_y))
        {
            tg_crypto_drop_mac++;
            return false;
        }

        // Reporter passed Eq. 3.31 (all gates including signed spatial + RSSI).
        // Count it in the total reporter set for this link so that the dynamic
        // quorum t = ⌊n/2⌋ + 1 reflects all reporters, not just legitimate ones.
        const uint32_t me_lmin_a = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax_a = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey_a  = std::to_string(me_lmin_a) + "_" + std::to_string(me_lmax_a);
        state.link_all_reporters[lkey_a].insert(event.reporter_id);

        // Eq. 3.32: compute dynamic quorum t = ⌊n/2⌋ + 1
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
            return false;   // Eq. 3.32: legitimate witnesses < ⌊n/2⌋+1
        }
    }

    // Eq. 3.28 signed-report accumulation REMOVED along with Step 1c
    // (see removed-code comment below) — its only consumer was the Stage-0
    // gate that was just removed for wrong-layer placement, so this was pure
    // dead-weight overhead: a real ~1.6ms Dilithium5 sign per topology-update
    // event (dilithium5_keygen + vehicle_sign_report) with no reader left.

    // ── Step 1c REMOVED — Eq. 3.28 threshold-aggregate-signature check ──────
    // Placement fix: per Algorithm 4, VERIFY_THRESHOLD_SIG runs inside
    // FS-MITIGATE for alpha in {TTW, BSHH} — i.e. AFTER Stage-1 (LW) + Stage-2
    // (TGN) have already raised an alert, as a mitigation-confirmation gate
    // ("is this node's own signing identity legitimate before we punish it"),
    // not as a Stage-0 pre-detection filter deciding whether the event is
    // even VISIBLE to LW+TGN. routing.cc's PemVerifyThresholdSig (called from
    // PemApplyMitigation, family != "ME") already implements this correctly
    // at that layer, using the paper's actual t = floor(n/2)+1 with no fixed
    // floor constant — this Stage-0 duplicate is not needed and was
    // structurally mis-scoped besides (see removed code: gated on
    // physical_sender_id vs the link endpoints, the same wrong-family/
    // wrong-layer pattern already fixed for the Step 1b ME location-binding
    // gate above). Its practical effect: it silently intercepted TTW-S2/
    // BSHH-S2's sophisticated (key-exfiltration) events at Stage-0 and
    // returned false before they ever reached LW+TGN/ι_v — for any link
    // with fewer real contributing signers than the removed
    // THRESHOLD_T_FLOOR=3 (e.g. a normal 2-endpoint link with no
    // third-party witnesses), this was unconditional and unrelated to
    // whether the event was genuinely an attack.

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

// Standalone getter for the new revocation-drop counter (consolidation fix —
// see tg_crypto_drop_revoked's declaration above for why this is separate
// from TetaGuardGetDropCounters rather than a 5th out-param there).
static uint64_t
TetaGuardGetRevokedDropCount()
{
    return tg_crypto_drop_revoked;
}

// Restore routing.cc's #define max / #define min so code after this include
// compiles correctly (mirrors the push_macro/undef at the top of this file).
#pragma pop_macro("min")
#pragma pop_macro("max")
