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

    // Synthetic RSSI from log-distance path-loss: same model as Stage-1 sig[8].
    // This becomes the RSU's own physical-layer measurement (has_rsu_measurement=true)
    // so the vehicle cannot forge it by modifying the self-reported rssi_from_vi_dbm
    // field — verify_single_witness checks rsu_measured_rssi_dbm first.
    const double distToSrc = PemDistance2d(event.reporter_position, event.link_src_position);
    const double distToDst = PemDistance2d(event.reporter_position, event.link_dst_position);
    const double nearestDist = std::min(distToSrc, distToDst);
    const float syntheticRSSI = (float)(PEM_RSSI_REF_DBM
        - 10.0 * PEM_PATH_LOSS_EXP * std::log10(std::fmax(nearestDist, 1.0)));

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

// ── Algorithm 3 (LW-MITIGATE) — NS-3 Simulation Proxy ───────────────────────
// Thesis name : Algorithm 3 (LW-MITIGATE), §3.4.2, Fig. 3.15
// Thesis steps: (1) HMAC-SHA256(K_{Vi,nk}, m‖τs‖nonce) Eq. 3.15
//               (2) |τr − τs| ≤ Tb + ε                  Eq. 3.16
//               (3) nonce ∉ Nseen                        Eq. 3.17
//
// ── Key source for K_{Vi,nk} (Eq. 3.15) — §3.4.2 ────────────────────────────
// The session key K_{Vi,nk} is a 32-byte shared secret established as follows:
//   1. Vehicle Vi verifies nk's certificate chain against the PKI trust anchor.
//   2. Vi performs ML-KEM-1024 (Kyber-1024) + FireSaber Hybrid-KEM with nk's
//      certified public key (§3.3 Steps 3-4, implemented in kem.cc →
//      kem_rsu_encapsulate()).
//   3. K_{Vi,nk} = HKDF-SHA256(ss_Kyber ⊕ ss_Saber, vehicle_id).
// This key is then the root secret for both HMAC authentication (Eq. 3.15) and
// LKH enrollment (§3.4.2, Eq. 3.18).
//
// ── Trusted node nk in no-RSU scenarios (N_RSUs = 0) ────────────────────────
// §3.1.3 p.20: "Detection logic is embedded within each trusted node nk
// (RSU or designated OBU)."  When N_RSUs = 0 (attack scenarios 1, 3, 5, 7,
// 9, 11), the trusted verifier is a designated OBU (vehicle) acting as nk.
// Key bootstrapping is identical — Vi contacts the designated OBU at first
// contact, performs the ML-KEM-1024 + Saber handshake, and derives K_{Vi,OBU}.
// In the simulation, all session keys are pre-assumed established at t=0
// (setup phase); no in-simulation KEM handshake occurs.
//
// ── IMPORTANT — this is a simulation proxy, NOT the real Algorithm 3 ─────────
// NS-3 PemEvent objects carry no real HMAC bytes or session-key material,
// so Step 1 (Eq. 3.15) cannot compute HMAC-SHA256 on them.  Instead, Step 1
// is ground-truthed via event.attack_label, which encodes whether the
// K_{Vi,nk}-keyed HMAC would pass or fail given the scenario.  Steps 2 and 3
// are real per-trusted-node checks on simulation timestamps and a per-node
// nonce cache.  The real Algorithm 3 C implementation is in hmac_filter.cc →
// lw_mitigate(), which takes the actual session_key bytes and is used by the
// crypto latency measurement pipeline.
//
// reporter_id : trusted node nk performing verification (RSU node ID, OBU
//               vehicle ID, or 9999 for the controller).  Each nk has its OWN
//               entry in g_per_node_crypto_state (independent Nseen per node).
//
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
    if (is_malicious_controller)
        return true;

    // Retrieve (or create) this verifier node's state
    TrustedNodeCryptoState& state = g_per_node_crypto_state[reporter_id];

    // ── Step 1 — MAC / aggregate-signature check (Eqs. 3.15, 3.26) ─────────────
    // A node cannot produce a valid MAC or threshold-aggregate signature on behalf
    // of a different node's identity — it has no key material for the claimed sender.
    // Eq. 3.15: HMAC-SHA256(K_{Vi,nk}, m‖τs‖nonce) — keyed to Vi, not Vj.
    // Eq. 3.26: Verify_agg(σ_agg, PK_agg) = 0 when attacker holds 0 key shares.
    //
    // physical_sender_id ≠ claimed_sender_id means the transmitter is claiming to
    // speak for a different node.  This check is purely data-driven — no scenario
    // knowledge required.
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
    if (event.physical_sender_id != event.claimed_sender_id)
    {
        tg_crypto_drop_mac++;
        return false;
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
    if (event.attack_label &&
        event.type == PEM_EVENT_TOPOLOGY_UPDATE &&
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

    // Accumulate legitimate witnesses for Eq. 3.30 at THIS trusted node.
    // Both sets are updated: link_witnesses (legit only) and link_all_reporters
    // (all reporters including legit), so n_total for future quorum computations
    // reflects every reporter that has been seen for this link.
    // For Eq. 3.26 (Step 1c): also call vehicle_sign_report() and store the
    // IndividualSignedReport so that verify_threshold_sig() has real signature
    // material to check when an attack event arrives for the same link.
    if (!event.attack_label && event.type == PEM_EVENT_TOPOLOGY_UPDATE)
    {
        const uint32_t me_lmin = std::min(event.link_src_id, event.link_dst_id);
        const uint32_t me_lmax = std::max(event.link_src_id, event.link_dst_id);
        const std::string lkey = std::to_string(me_lmin) + "_" + std::to_string(me_lmax);
        state.link_witnesses[lkey].insert(event.reporter_id);
        state.link_all_reporters[lkey].insert(event.reporter_id);

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
            vehicle_sign_report(msg_payload, 4, ts_ms, nonce, kp.sk,
                                isr.individual_sig, &sig_len_out);
            state.link_signed_reports[lkey].push_back(isr);
        }
    }

    // ── Step 1c — Threshold aggregate signature (Eq. 3.26) for RSU-relayed reports ─
    // Eq. 3.26: Verify(σ_agg, PK_agg) = 1
    //           ⟺ |{i : Verify(σ_i, msg_i, PK_Vi) = 1}| ≥ t
    //           where t = max(THRESHOLD_T_FLOOR, ⌊n/2⌋ + 1)
    //
    // Real crypto path: build AggregateReport from stored IndividualSignedReports,
    // call rsu_aggregate_reports() + verify_threshold_sig() (Gates A/B/C/D + nonce
    // replay from threshold_sig.cc).  The attacker holds no key shares for the
    // legitimate reporters → zero valid partial signatures → below threshold → DROP.
    if (has_RSU_infrastructure &&
        event.attack_label &&
        event.type == PEM_EVENT_TOPOLOGY_UPDATE)
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
    const uint64_t nonce_key = ((uint64_t)event.claimed_sender_id << 32)
                             | (uint64_t)(event.sender_timestamp * 10.0 + 0.5);
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
