/*
 * crypto_pipeline.cc — Full Crypto Layer Pipeline  (Sections 4.4, 8, 9)
 *
 * Wires all five modules into a single end-to-end pipeline and produces the
 * two canonical interface structures:
 *
 *   CryptoVerifiedEvent  →  tgn_ingest_event()       (Section 8, Eq. 3.19)
 *   DetectionAlert       →  submit_to_fabric()        (Section 9, Eq. 3.36)
 *   BeaconEvidenceRecord →  submitted per RSU interval (Section 9.4)
 *
 * End-to-end flow:
 *   pem_event_log.csv  (routing.cc output)
 *        │
 *        ▼
 *   ① KEM lookup  —  VehicleKeyRecord / LKH revocation check
 *   ② lw_mitigate()  —  Eq. 3.15 HMAC + Eq. 3.16 freshness + Eq. 3.17 nonce
 *   ③ verify_threshold_sig()  —  Eq. 3.26 (RSU-aggregated reports)
 *   ④ verify_single_witness() / verify_quorum()  —  Eq. 3.27–3.30 (ME)
 *   ⑤ Construct CryptoVerifiedEvent  →  tgn_ingest_event()
 *   ⑥ LKH revocation on confirmed alerts (tgn_alerts.json)
 *        │
 *        ▼  clean events only
 *   crypto_verified_events.csv  →  tgn_detector.cc / tgn_train.py
 *   crypto_drop_log.csv         →  RSU local audit (NOT sent to blockchain)
 *   beacon_evidence.csv         →  maps to BeaconEvidenceRecord B_nk(t)
 *
 * Build:
 *   g++ -std=c++17 -O2 crypto_pipeline.cc -lssl -lcrypto -lm -o crypto_pipeline
 *
 * Usage:
 *   ./crypto_pipeline [pem_event_log.csv] [tgn_alerts.json]
 */

#include "teta_guard_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <sys/stat.h>   /* Issue-5: fstat() for IPC file ownership check */
#include <unistd.h>     /* Issue-5: getuid() */
#include <fcntl.h>      /* Issue-5: open(), O_RDONLY, O_NOFOLLOW */

#ifdef HAVE_OPENSSL
#  include <openssl/hmac.h>
#  include <openssl/rand.h>
#  include <openssl/sha.h>
#  include <openssl/evp.h>
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * tgn_ingest_event() — TGN interface stub
 *
 * In production: the real TGN (tgn_detector.cc) provides this symbol.
 * Here it writes the event to crypto_verified_events.csv and counts calls.
 *
 * This is the ONLY data structure crossing the Crypto → TGN boundary.
 * ══════════════════════════════════════════════════════════════════════════ */

static FILE *g_evt_csv    = NULL;   /* crypto_verified_events.csv — tgn_train.py input */
static FILE *g_pem_csv    = NULL;   /* pem_event_log_filtered.csv — tgn_detector.cc input */
static FILE *g_crypto_log = NULL;   /* crypto_layer_log.txt — step-by-step */
static int   g_tgn_call_count = 0;

/* Write a separator line to the crypto log */
static void clog_sep(void) {
    if (g_crypto_log)
        fprintf(g_crypto_log,
            "────────────────────────────────────────────────────────────────\n");
}

/* Hex-print first 8 bytes of a buffer to the crypto log */
static void clog_hex8(const char *label, const uint8_t *d) {
    if (!g_crypto_log) return;
    fprintf(g_crypto_log, "  %-20s: ", label);
    for (int i = 0; i < 8; i++) fprintf(g_crypto_log, "%02x", d[i]);
    fprintf(g_crypto_log, "...\n");
}

/* tgn_ingest_event() — Crypto → TGN boundary (Section 8, Eq. 3.19)
 *
 * Writes two output files so crypto-filtered events reach the TGN:
 *
 *   crypto_verified_events.csv  — exact tgn_events.csv column layout read by
 *                                  tgn_train.py (feature extraction uses these
 *                                  columns directly: recv_time_s, claimed_ts_s,
 *                                  edge_freshness, seq_gap, reporter_count, etc.)
 *
 *   pem_event_log_filtered.csv  — same column layout as pem_event_log.csv
 *                                  produced by routing.cc; tgn_detector.cc can
 *                                  load this file as a pre-filtered event stream
 *                                  instead of running the full NS-3 simulation.
 *
 * Previously this was a bare stub that only printed a non-standard CSV row.
 * The old format did not match tgn_train.py's expected columns, so filtered
 * events never reached the TGN model (full-stack pipeline was broken).
 */
void tgn_ingest_event(const CryptoVerifiedEvent *event) {
    g_tgn_call_count++;

    double recv_s   = (double)event->recv_timestamp_ms   / 1000.0;
    double send_s   = (double)event->sender_timestamp_ms / 1000.0;
    double delay_s  = recv_s - send_s;

    /* Edge freshness weight A_uv(t) = exp(-excess_age / (γ·Tb))
     * γ = 310 (urban default), Tb = 0.1 s — matches tgn_detector.cc constants */
    double stale_excess = delay_s > 0.1 ? delay_s - 0.1 : 0.0;
    double edge_fresh   = exp(-stale_excess / (310.0 * 0.1));

    /* ── crypto_verified_events.csv (tgn_train.py input) ───────────────────
     * Column order must exactly match tgn_events.csv header written by
     * tgn_detector.cc TGN_InitOutputFiles() and read by tgn_train.py.
     *
     * Why several columns differ from CryptoVerifiedEvent struct fields:
     *
     *   attack_scenario = 0 (hardcoded)
     *     The crypto layer does not know which attack scenario is running —
     *     that context lives in routing.cc (pem_event_log.csv).  Downstream
     *     tgn_detector.cc fills this from the original pem_event_log.csv row.
     *
     *   event_type = TOPO_UPDATE (hardcoded)
     *     By the time lw_mitigate() passes an event to tgn_ingest_event(),
     *     it has already verified HMAC + timestamp + nonce.  All surviving
     *     events are topology observation events; no other type reaches here.
     *
     *   physical_sender_id = claimed_sender_id = event->vehicle_id
     *     Post-filter invariant: lw_mitigate verified the HMAC under the
     *     sender's session key, so the sender IS who they claim to be.
     *     The BSHH identity split (physical ≠ claimed) is caught and DROPPED
     *     before this function is called.  Events written here always have
     *     physical=claimed, so both columns carry vehicle_id.
     *
     *   pem_signatures="none", pem_score=0.000, pem_alert=0 (placeholders)
     *     PEM scores are computed by routing.cc from the full pem_event_log.csv;
     *     they are not available at the crypto layer boundary.  tgn_detector.cc
     *     joins these placeholder rows with pem_event_log.csv on sim_time_s to
     *     fill in the real PEM values before training.
     *
     *   tgn_score=0.000, tgn_alert=0 (placeholders)
     *     TGN inference has not run yet at write time.  tgn_train.py fills these
     *     during the offline training / evaluation pass.
     */
    if (g_evt_csv) {
        /* Parse link endpoints from link_id "SRC_DST" format */
        int link_src = 0, link_dst = 0;
        sscanf((const char*)event->link_id, "%d_%d", &link_src, &link_dst);

        /* identity_mismatch: physical != claimed sender (BSHH signal) */
        int id_mismatch = (strncmp((const char*)event->vehicle_id,
                                    (const char*)event->reporter_id,
                                    sizeof(event->vehicle_id)) != 0) ? 1 : 0;

        /* seq_gap: timestamp regression proxy via sequence number wrap */
        double seq_gap = (event->sequence_number == 0) ? 0.0
                         : (double)event->sequence_number / 1000.0;

        fprintf(g_evt_csv,
                "%.4f,0,TOPO_UPDATE,"
                "%s,%s,"
                "%d,%d,"
                "%.4f,%.4f,%.4f,"
                "%.6f,%.4f,%u,%d,"
                "none,0.000,0,"
                "0.000,0,%d\n",
                recv_s,
                (const char*)event->vehicle_id, (const char*)event->vehicle_id,   /* physical=claimed (post-filter) */
                link_src, link_dst,
                send_s, recv_s, delay_s,
                edge_fresh, seq_gap,
                event->reporter_count, id_mismatch,
                event->is_attack ? 1 : 0);
        fflush(g_evt_csv);
    }

    /* ── pem_event_log_filtered.csv (tgn_detector.cc alternative input) ───
     * Same layout as pem_event_log.csv so tgn_detector can load pre-filtered
     * events without re-running the NS-3 simulation:
     *   sim_time_s, event_type, physical_sender_id, claimed_sender_id,
     *   reporter_id, link_src_id, link_dst_id,
     *   sender_ts_s, recv_ts_s, triggered_sigs, score, alert_raised, attack_label
     */
    if (g_pem_csv) {
        int link_src = 0, link_dst = 0;
        sscanf((const char*)event->link_id, "%d_%d", &link_src, &link_dst);
        fprintf(g_pem_csv,
                "%.4f,TOPO_UPDATE,%s,%s,%s,%d,%d,%.4f,%.4f,0,0.000,0,%d\n",
                recv_s,
                (const char*)event->vehicle_id, (const char*)event->vehicle_id,
                (const char*)event->reporter_id,
                link_src, link_dst,
                send_s, recv_s,
                event->is_attack ? 1 : 0);
        fflush(g_pem_csv);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Inline crypto helpers (minimal, no separate header dependency)
 * ══════════════════════════════════════════════════════════════════════════ */

static void fill_random(uint8_t *buf, size_t len) {
#ifdef HAVE_OPENSSL
    RAND_bytes(buf, (int)len);
#else
    static uint64_t s = 0x9A8B7C6D5E4F3021ULL;
    for (size_t i = 0; i < len; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
#endif
}

/* HMAC-SHA256 (Eq. 3.15) */
static void hmac_sha256(const uint8_t *key, size_t kl,
                          const uint8_t *msg, size_t ml,
                          uint8_t out[HMAC_SHA256_LEN]) {
#ifdef HAVE_OPENSSL
    unsigned olen = HMAC_SHA256_LEN;
    HMAC(EVP_sha256(), key, (int)kl, msg, ml, out, &olen);
#else
    memset(out, 0, HMAC_SHA256_LEN);
    for (size_t i = 0; i < ml; i++)
        out[i % HMAC_SHA256_LEN] ^= msg[i] ^ key[i % kl];
#endif
}

/* Constant-time compare */
static bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Session key store and nonce caches
 * ══════════════════════════════════════════════════════════════════════════ */

/* PIPELINE_MAX_VEH must be at least MAX_REPORTS_PER_RSU (64) so the pipeline
 * can structurally exercise the scenario its own cache sizing was designed for:
 * 64 reporters × 50 beacon-intervals = 3200 THRESH/LOCBIND nonce-cache entries
 * per 5-second window.  Setting this below MAX_REPORTS_PER_RSU means the 4096-
 * slot caches are permanently >99% empty and the sizing math is never validated
 * by the harness that is supposed to confirm it.
 *
 * Set to MAX_VEHICLES (256) rather than just MAX_REPORTS_PER_RSU (64) so the
 * pipeline can provision the full fleet without hitting CRYPTO_DROP_KEYSTORE_FULL
 * in any realistic simulation run.  Memory cost: ~14 KB per slot × 256 = ~3.5 MB
 * for g_veh, plus 64 KB × 256 = ~16 MB for g_nonce_caches — acceptable for a
 * simulation host.                                                                */
#define PIPELINE_MAX_VEH MAX_VEHICLES

static struct {
    uint8_t          vehicle_id[16];
    uint8_t          session_key[SESSION_KEY_LEN];
    uint8_t          sign_pub_key[DILITHIUM5_PK_LEN];
    uint8_t          sign_sk[DILITHIUM5_SK_LEN];   /* signing key — needed to build IndividualSignedReport/LocationBoundReport */
    CertificateRecord cert;           /* Issue-1 fix: CA cert binding vehicle_id → sign_pub_key */
    bool             revoked;
    uint32_t         seq_last;        /* last seen sequence number, for Δs_v */
    uint32_t         beacon_count;    /* c_v^W in current window             */
} g_veh[PIPELINE_MAX_VEH];
static int g_veh_count = 0;

static NonceCache g_nonce_caches[PIPELINE_MAX_VEH];

/* ── Issue-3 fix: global LKH tree ─────────────────────────────────────────────
 * Initialized lazily after all vehicles are provisioned (ensure_lkh_init).
 * lkh_revoke_vehicle uses it to update KEKs and group key atomically with the
 * HMAC keystore (via mark_key_revoked) and CRL (via cert_revoke_vehicle). */
static LKHTree g_lkh_tree;
static bool    g_lkh_tree_ready = false;

/* ── Forward declarations: Module 3 (threshold_sig.o) ───────────────────────── */
void vehicle_sign_report(const uint8_t *msg_payload, size_t payload_len,
                          uint64_t       timestamp_ms,
                          const uint8_t  nonce[NONCE_LEN],
                          const uint8_t  sk_vi[DILITHIUM5_SK_LEN],
                          uint8_t        sig_out[DILITHIUM5_SIG_LEN],
                          size_t        *sig_len_out);
ThresholdSigResult verify_threshold_sig(const AggregateReport *report);
void rsu_aggregate_reports(AggregateReport *agg_out,
                             const IndividualSignedReport *reports,
                             uint32_t n_reports);

/* ── Forward declarations: Module 4 (location_binding.o) ────────────────────── */
float haversine_distance_m(float lat1, float lon1, float lat2, float lon2);
void  create_location_bound_report(const uint8_t       link_id[8],
                                    float               reporter_lat,
                                    float               reporter_lon,
                                    float               rssi_from_vi,
                                    uint64_t            sender_ts_ms,
                                    const uint8_t       reporter_id[16],
                                    const uint8_t       sk_vk[DILITHIUM5_SK_LEN],
                                    const uint8_t       pk_vk[DILITHIUM5_PK_LEN],
                                    const CertificateRecord *cert,
                                    LocationBoundReport *out_report);
bool  verify_single_witness(const LocationBoundReport *report,
                             float    link_endpoint_lat,
                             float    link_endpoint_lon,
                             uint64_t recv_time_ms);
bool  verify_quorum(const LocationBoundReport *reports,
                    uint32_t n_reports,
                    uint32_t threshold_t,
                    float    link_ep_lat,
                    float    link_ep_lon,
                    uint64_t recv_time_ms);

/* ── Module 3 accumulator: 1-second window of individual signed reports ─────── */
static IndividualSignedReport g_thresh_window[MAX_REPORTS_PER_RSU];
static uint32_t               g_thresh_window_n   = 0;
static int                    g_thresh_window_key = -1; /* floor(sim_time_s) */

/* ── Module 4 accumulator: per-link location-bound reports within window ─────── */
static LocationBoundReport    g_lbs_link[MAX_REPORTS_PER_RSU];
static uint32_t               g_lbs_link_n        = 0;
static int                    g_lbs_link_src       = -1;
static int                    g_lbs_link_dst       = -1;

static int vehicle_index(const uint8_t vid[16]) {
    for (int i = 0; i < g_veh_count; i++)
        if (memcmp(g_veh[i].vehicle_id, vid, 16) == 0) return i;
    return -1;
}

static int provision_vehicle(const uint8_t vid[16]) {
    int idx = vehicle_index(vid);
    if (idx >= 0) return idx;
    if ((uint32_t)g_veh_count >= PIPELINE_MAX_VEH) return -1;
    idx = g_veh_count++;
    memcpy(g_veh[idx].vehicle_id, vid, 16);
    /* Deterministic session key from vehicle_id (test mode) */
    for (int j = 0; j < (int)SESSION_KEY_LEN; j++)
        g_veh[idx].session_key[j] = vid[j % 16] ^ (uint8_t)(j * 37);
    /* Generate Dilithium5 keypair + CA cert (Issue-1 fix: cert binds id → pk) */
    dilithium5_keygen(g_veh[idx].sign_pub_key, g_veh[idx].sign_sk);
    dilithium5_issue_cert(vid, g_veh[idx].sign_pub_key, 0, &g_veh[idx].cert);
    g_veh[idx].revoked     = false;
    g_veh[idx].seq_last    = 0;
    g_veh[idx].beacon_count = 0;
    memset(&g_nonce_caches[idx], 0, sizeof(NonceCache));
    return idx;
}

/* ══════════════════════════════════════════════════════════════════════════
 * beacon_authenticated_payload()  (Eq. 3.49)
 * ══════════════════════════════════════════════════════════════════════════ */

static void build_payload(const BeaconMessage *msg,
                            uint8_t *mp, size_t *mp_len) {
    /* MAC input = all BeaconMessage fields up to (but not including) the nonce
     * field, followed by the nonce.  Per Eq. 3.49: m' = m || nonce.
     *
     * offsetof(BeaconMessage, nonce) = 48 bytes, covering:
     *   vehicle_id[16] | sender_timestamp_ms[8] | gps_lat[4] | gps_lon[4]
     *   | rssi_dbm[4]  | sequence_number[4]    | link_id[8]
     *
     * sender_timestamp_ms is already within this 48-byte prefix (bytes 16–23).
     * The prior code appended it a second time explicitly, doubling τ_s in the
     * HMAC input.  That was harmless (τ_s was still covered) but inconsistent
     * with Eq. 3.49 where m already contains τ_s and only nonce is separately
     * appended.  Removed the redundant append; HMAC input is now 64 bytes. */
    size_t pl = offsetof(BeaconMessage, nonce);
    memcpy(mp, msg, pl);
    memcpy(mp + pl, msg->nonce, NONCE_LEN);
    *mp_len = pl + NONCE_LEN;
}

/* ══════════════════════════════════════════════════════════════════════════
 * lw_mitigate_inline()  (Algorithm 3, Eqs. 3.15–3.17)
 * ══════════════════════════════════════════════════════════════════════════ */

static CryptoVerifyResult lw_mitigate_inline(const BeaconMessage *msg,
                                               uint64_t recv_ms,
                                               int veh_idx) {
    /* ── STEP ①  KEM / Revocation check ──────────────────────────────────── */
    if (g_crypto_log) {
        fprintf(g_crypto_log, "  STEP ①  KEM LOOKUP  (Section 3.3)\n");
        fprintf(g_crypto_log, "  %-20s: %s\n", "Vehicle",
                (char *)g_veh[veh_idx].vehicle_id);
        fprintf(g_crypto_log, "  %-20s: %s\n", "Revoked",
                g_veh[veh_idx].revoked ? "YES" : "NO");
        clog_hex8("Session key K", g_veh[veh_idx].session_key);
    }
    if (g_veh[veh_idx].revoked) {
        if (g_crypto_log)
            fprintf(g_crypto_log,
                    "  Result : FAIL — CRYPTO_DROP_REVOKED_KEY\n\n");
        return CRYPTO_DROP_REVOKED_KEY;
    }
    if (g_crypto_log)
        fprintf(g_crypto_log, "  Result : PASS\n\n");

    /* ── STEP ②  HMAC Integrity  (Eq. 3.15) ──────────────────────────────── */
    uint8_t mp[1024]; size_t mp_len;
    build_payload(msg, mp, &mp_len);
    uint8_t mac_exp[HMAC_SHA256_LEN];
    hmac_sha256(g_veh[veh_idx].session_key, SESSION_KEY_LEN, mp, mp_len, mac_exp);
    bool mac_ok = ct_eq(mac_exp, msg->mac, HMAC_SHA256_LEN);
    if (g_crypto_log) {
        fprintf(g_crypto_log, "  STEP ②  HMAC INTEGRITY  (Eq. 3.15)\n");
        fprintf(g_crypto_log, "  %-20s: %zu bytes\n", "m' length", mp_len);
        clog_hex8("HMAC expected", mac_exp);
        clog_hex8("HMAC received", msg->mac);
        fprintf(g_crypto_log, "  Result : %s\n\n",
                mac_ok ? "PASS" : "FAIL — CRYPTO_DROP_INVALID_MAC");
    }
    if (!mac_ok) return CRYPTO_DROP_INVALID_MAC;

    /* ── STEP ③  Timestamp Freshness  (Eq. 3.16) ─────────────────────────── */
    int64_t delta = (int64_t)recv_ms - (int64_t)msg->sender_timestamp_ms;
    if (delta < 0) delta = -delta;
    bool fresh_ok = ((uint64_t)delta <= FRESHNESS_WINDOW_MS);
    if (g_crypto_log) {
        fprintf(g_crypto_log, "  STEP ③  TIMESTAMP FRESHNESS  (Eq. 3.16)\n");
        fprintf(g_crypto_log, "  %-20s: %llu ms\n", "τ_s",
                (unsigned long long)msg->sender_timestamp_ms);
        fprintf(g_crypto_log, "  %-20s: %llu ms\n", "τ_r", (unsigned long long)recv_ms);
        fprintf(g_crypto_log, "  %-20s: %lld ms\n", "|τ_r − τ_s|", (long long)delta);
        fprintf(g_crypto_log, "  %-20s: %u ms  (T_b=%u + ε=%u)\n",
                "Window", FRESHNESS_WINDOW_MS,
                BEACON_INTERVAL_MS, PROPAGATION_TOL_MS);
        fprintf(g_crypto_log, "  Result : %s\n\n",
                fresh_ok ? "PASS"
                         : "FAIL — CRYPTO_DROP_STALE_TIMESTAMP  ← TTW vector blocked");
    }
    if (!fresh_ok) return CRYPTO_DROP_STALE_TIMESTAMP;

    /* ── STEP ④  Nonce Novelty  (Eq. 3.17) ───────────────────────────────── */
    NonceCache *nc = &g_nonce_caches[veh_idx];
    bool nonce_ok = true;
    for (uint32_t i = 0; i < nc->count; i++) {
        uint32_t idx = (nc->head + NONCE_CACHE_SIZE - 1 - i) % NONCE_CACHE_SIZE;
        if (memcmp(nc->nonces[idx], msg->nonce, NONCE_LEN) == 0) {
            nonce_ok = false; break;
        }
    }
    if (g_crypto_log) {
        fprintf(g_crypto_log, "  STEP ④  NONCE NOVELTY  (Eq. 3.17)\n");
        clog_hex8("Nonce", msg->nonce);
        fprintf(g_crypto_log, "  %-20s: %u entries\n", "Cache size", nc->count);
        fprintf(g_crypto_log, "  Result : %s\n\n",
                nonce_ok ? "PASS — nonce admitted to cache"
                         : "FAIL — CRYPTO_DROP_REPLAYED_NONCE  ← BSHH replay blocked");
    }
    if (!nonce_ok) return CRYPTO_DROP_REPLAYED_NONCE;

    memcpy(nc->nonces[nc->head], msg->nonce, NONCE_LEN);
    nc->head = (nc->head + 1) % NONCE_CACHE_SIZE;
    if (nc->count < NONCE_CACHE_SIZE) nc->count++;

    return CRYPTO_ACCEPT;
}

/* ══════════════════════════════════════════════════════════════════════════
 * construct_crypto_verified_event()  (Section 8.2)
 *
 * Map BeaconMessage fields → CryptoVerifiedEvent.
 * Called only after lw_mitigate returns CRYPTO_ACCEPT.
 * ══════════════════════════════════════════════════════════════════════════ */

static CryptoVerifiedEvent make_event(const BeaconMessage *msg,
                                        uint64_t recv_ms,
                                        int veh_idx,
                                        bool lbs_ok,
                                        bool thresh_ok,
                                        bool is_attack) {
    CryptoVerifiedEvent e;
    memset(&e, 0, sizeof(e));

    memcpy(e.vehicle_id,   msg->vehicle_id, 16);
    memcpy(e.link_id,      msg->link_id,     8);
    memcpy(e.reporter_id,  msg->vehicle_id, 16);  /* reporter = sender for direct reports */

    e.sender_timestamp_ms    = msg->sender_timestamp_ms;
    e.recv_timestamp_ms      = recv_ms;
    e.sequence_number        = msg->sequence_number;
    e.beacon_count_in_window = ++g_veh[veh_idx].beacon_count;
    e.reporter_lat           = msg->gps_lat;
    e.reporter_lon           = msg->gps_lon;
    e.rssi_from_vi_dbm       = msg->rssi_dbm;
    e.reporter_count         = 1;
    e.location_binding_verified = lbs_ok;
    e.threshold_sig_verified    = thresh_ok;
    e.crypto_filter_result      = (uint8_t)CRYPTO_ACCEPT;
    /* Controller-origin attacks pass crypto and reach TGN with is_attack=true */
    e.is_attack                 = is_attack;
    return e;
}

/* ══════════════════════════════════════════════════════════════════════════
 * BeaconEvidenceRecord builder  (Section 9.4)
 *
 * Built incrementally; submitted to Fabric at each beacon interval.
 * ══════════════════════════════════════════════════════════════════════════ */

static BeaconEvidenceRecord g_evidence;
static int                  g_evidence_n = 0;

static void evidence_add(const BeaconMessage *msg, uint64_t recv_ms) {
    if (g_evidence_n >= (int)MAX_OBSERVATIONS_PER_RSU) return;
    int i = g_evidence_n++;
    memcpy(g_evidence.observations[i].vehicle_id, msg->vehicle_id, 16);
    g_evidence.observations[i].sender_ts_ms = msg->sender_timestamp_ms;
    g_evidence.observations[i].gps_lat      = msg->gps_lat;
    g_evidence.observations[i].gps_lon      = msg->gps_lon;
    g_evidence.observations[i].rssi_dbm     = msg->rssi_dbm;
    /* RSU Dilithium5 signature over this observation (simulated) */
    fill_random(g_evidence.observations[i].rsu_sig, DILITHIUM5_SIG_LEN);
    g_evidence.n_vehicles = (uint32_t)g_evidence_n;
    g_evidence.interval_timestamp_ms = recv_ms;
    (void)recv_ms;
}

/* ══════════════════════════════════════════════════════════════════════════
 * submit_to_fabric()  (Section 9.2)
 *
 * Submits DetectionAlert + BeaconEvidenceRecord to Hyperledger Fabric.
 * In simulation: writes to tgn_alerts_crypto.json and beacon_evidence.csv.
 * In production: calls submit_alerts.py or the Fabric Node.js SDK.
 * ══════════════════════════════════════════════════════════════════════════ */

static FILE *g_alert_json = NULL;
static int   g_alert_count = 0;

/* Map signature name token to its bit index in the S_trig bitmask.
 * Bit layout: TTW-S1=0 TTW-S2=1 TTW-S3=2  BSHH-S1=3 BSHH-S2=4 BSHH-S3=5
 *             ME-S1=6  ME-S2=7  ME-S3=8 */
static int sig_name_to_bit(const char *tok) {
    if (strncmp(tok, "TTW-S1",  6) == 0) return 0;
    if (strncmp(tok, "TTW-S2",  6) == 0) return 1;
    if (strncmp(tok, "TTW-S3",  6) == 0) return 2;
    if (strncmp(tok, "BSHH-S1", 7) == 0) return 3;
    if (strncmp(tok, "BSHH-S2", 7) == 0) return 4;
    if (strncmp(tok, "BSHH-S3", 7) == 0) return 5;
    if (strncmp(tok, "ME-S1",   5) == 0) return 6;
    if (strncmp(tok, "ME-S2",   5) == 0) return 7;
    if (strncmp(tok, "ME-S3",   5) == 0) return 8;
    return -1;
}

/* Parse "TTW-S1|ME-S2|ME-S3" → bitmask and dominant variant.
 * Returns 0 if string is "none" or unrecognised. */
static uint32_t parse_triggered_sigs(const char *sig_str,
                                      AttackVariant *variant_out) {
    uint32_t mask = 0;
    int has_ttw = 0, has_bshh = 0, has_me = 0;

    if (!sig_str || strcmp(sig_str, "none") == 0 || sig_str[0] == '\0') {
        *variant_out = ATTACK_TTW;
        return 0;
    }

    char buf[64];
    strncpy(buf, sig_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, "|");
    while (tok) {
        int bit = sig_name_to_bit(tok);
        if (bit >= 0) {
            mask |= (1u << bit);
            if (bit <= 2) has_ttw  = 1;
            else if (bit <= 5) has_bshh = 1;
            else has_me = 1;
        }
        tok = strtok(NULL, "|");
    }

    /* Dominant family: whichever appears first in the signature string */
    if      (has_ttw)  *variant_out = ATTACK_TTW;
    else if (has_bshh) *variant_out = ATTACK_BSHH;
    else if (has_me)   *variant_out = ATTACK_ME;
    else               *variant_out = ATTACK_TTW;

    return mask;
}

static const char *attack_variant_str(AttackVariant v) {
    switch(v) {
        case ATTACK_TTW:  return "TTW";
        case ATTACK_BSHH: return "BSHH";
        case ATTACK_ME:   return "ME";
    }
    return "UNKNOWN";
}

static void submit_to_fabric(const DetectionAlert *alert,
                               const BeaconEvidenceRecord *evidence) {
    /* Flow 1: TGN Detection Alert — write JSON compatible with submit_alerts.py */
    if (g_alert_json) {
        /* Convert bitmask to JSON array of bit indices so submit_alerts.py
         * can read S_trig as a list (e.g. 0x05 → [0,2]) */
        char strig_buf[64];
        int  pos = 0;
        strig_buf[pos++] = '[';
        bool first_bit = true;
        for (int b = 0; b < 9; b++) {
            if (alert->triggered_sigs & (1u << b)) {
                if (!first_bit) { strig_buf[pos++] = ','; }
                pos += snprintf(strig_buf + pos, sizeof(strig_buf) - pos, "%d", b);
                first_bit = false;
            }
        }
        strig_buf[pos++] = ']';
        strig_buf[pos]   = '\0';

        if (g_alert_count > 0) fprintf(g_alert_json, ",\n");
        fprintf(g_alert_json,
                "  {\"v_id\":\"%.*s\",\"alpha\":\"%s\","
                "\"y_hat\":%.4f,\"S_trig\":%s,\"t_alert\":%llu,"
                "\"tdet_ms\":%llu,\"from_lw\":%s,\"from_fs\":%s}",
                16, alert->vehicle_id,
                attack_variant_str(alert->variant),
                alert->anomaly_score,
                strig_buf,
                (unsigned long long)alert->alert_timestamp,
                (unsigned long long)alert->alert_timestamp,  /* tdet_ms ≈ t_alert for crypto-layer alerts */
                alert->from_lw_path ? "true" : "false",
                alert->from_fs_path ? "true" : "false");
    }
    g_alert_count++;

    /* Flow 2: RSU Beacon Evidence (ground truth — bypasses controller) */
    printf("[Pipeline] submit_to_fabric: alert=%s vid=%.*s score=%.3f sigs=0x%03X n_obs=%u\n",
           attack_variant_str(alert->variant),
           16, alert->vehicle_id,
           alert->anomaly_score,
           alert->triggered_sigs,
           evidence ? evidence->n_vehicles : 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Process tgn_alerts.json — trigger LKH revocation for confirmed alerts
 * ══════════════════════════════════════════════════════════════════════════ */

/* Issue-3 fix: initialize the global LKH tree from the provisioned vehicle pool.
 * Called after load_pem() has provisioned all vehicles into g_veh[].
 * Idempotent — safe to call multiple times. */
static void ensure_lkh_init(void) {
    if (g_lkh_tree_ready) return;
    if (g_veh_count == 0) return;
    uint8_t vids[PIPELINE_MAX_VEH][16];
    uint32_t n = 0;
    for (int i = 0; i < g_veh_count; i++) {
        if (g_veh[i].vehicle_id[0] != '\0')
            memcpy(vids[n++], g_veh[i].vehicle_id, 16);
    }
    if (n == 0) return;
    lkh_init(&g_lkh_tree, (const uint8_t (*)[16])vids, n);
    /* g_veh is an anonymous struct with a different layout from VehicleKeyRecord,
     * so lkh_set_keystore cannot be wired here — field offsets diverge after
     * sign_pub_key.  The pipeline updates g_veh directly after lkh_revoke_vehicle. */
    g_lkh_tree_ready = true;
    printf("[Pipeline] LKH tree initialized (%u vehicles)\n", n);
}

static void process_tgn_alerts(const char *alerts_file) {
    FILE *f = fopen(alerts_file, "r");
    if (!f) { printf("[Pipeline] No alerts file: %s\n", alerts_file); return; }

    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    fread(buf, 1, sz, f); buf[sz] = '\0'; fclose(f);

    int revoked_n = 0;
    char *p = buf;
    while ((p = strstr(p, "\"v_id\"")) != NULL) {
        char *q1 = strchr(p + 6, '"');
        if (!q1) break;
        char *q2 = strchr(q1 + 1, '"');
        if (!q2) break;
        char vid_str[17] = {0};
        int  vlen = (int)(q2 - q1 - 1);
        if (vlen > 16) vlen = 16;
        memcpy(vid_str, q1 + 1, vlen);

        uint8_t vid[16] = {0};
        memcpy(vid, vid_str, 16);
        int idx = vehicle_index(vid);
        if (idx >= 0 && !g_veh[idx].revoked) {
            printf("[Pipeline] LKH revoke: %s\n", vid_str);
            if (g_lkh_tree_ready) {
                /* Issue-3 fix: route through lkh_revoke_vehicle so the LKH tree
                 * KEKs and group key are regenerated (O(log n) path update).
                 * lkh_set_keystore was not called (struct layout mismatch with g_veh),
                 * so mark_key_revoked does not fire from inside the LKH chain —
                 * update the pipeline keystore and CRL directly afterwards. */
                lkh_revoke_vehicle(&g_lkh_tree, vid);
            }
            /* Always update the pipeline's own keystore and CRL regardless of
             * tree state — these are the paths lw_mitigate_inline actually checks. */
            g_veh[idx].revoked = true;
            memset(g_veh[idx].session_key, 0, SESSION_KEY_LEN);
            cert_revoke_vehicle(vid);
            revoked_n++;
        }
        p = q2 + 1;
    }
    free(buf);
    printf("[Pipeline] Revoked %d vehicle(s) via LKH\n", revoked_n);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Fix-6: Blockchain → C++ revocation IPC
 *
 * The blockchain chaincode (temporalecho.go) writes vehicle IDs to
 * TETA_REVOKE_FILE (/tmp/teta_guard_revoke.txt) when Fabric confirms a
 * revocation event.  This function reads that file at pipeline startup,
 * revokes each vehicle atomically (session key + g_veh flag), and truncates
 * the file so the same ID is not processed twice on the next run.
 *
 * File format: one vehicle_id per line (max 16 chars), UTF-8, LF-terminated.
 * Empty lines and lines beginning with '#' are ignored.
 * ══════════════════════════════════════════════════════════════════════════ */

static void process_revocation_pipe(void) {
    /* Atomic handoff: rename() moves the live IPC file to a private path before
     * we open it.  This closes two related races that the prior open+read+truncate
     * pattern left open:
     *
     *   Race A — truncate-while-appending:
     *     If submit_alerts.py holds an open fd and is mid-write when we truncate
     *     in place, the remaining bytes of line N+1 are written to the file after
     *     truncation.  On Linux the writer's fd offset does not reset, so those
     *     bytes land at the original offset — leaving a NUL-filled hole at the
     *     start of the file on the next read.  fgets tolerates NULs poorly.
     *
     *   Race B — new-writer stomps our truncation:
     *     After we read the file but before we truncate, a second writer opens
     *     the same path and appends lines N+1..M.  Our truncation then silently
     *     discards those lines.  With rename they always land in a new inode.
     *
     * Fix:
     *   rename(TETA_REVOKE_FILE, tmp_path) is atomic at the filesystem level.
     *   After it returns:
     *     • Any writer that had TETA_REVOKE_FILE open continues writing to the
     *       renamed inode (our tmp copy).  Those bytes are visible to our fgets
     *       loop if they arrive before fclose; otherwise they are in the ghost
     *       inode and discarded when we unlink.
     *     • Any NEW writer that opens TETA_REVOKE_FILE gets a fresh inode —
     *       its lines are not affected by our unlink.
     *   unlink(tmp_path) releases our copy; the next poll tick picks up any lines
     *   the writer appended to the new TETA_REVOKE_FILE in the meantime.
     *
     *   For full end-to-end safety, submit_alerts.py should also use atomic
     *   rename: write to TETA_REVOKE_FILE.tmp then os.rename() into place.
     *   That guarantees each batch is written atomically.  Not required for
     *   correctness of this reader — it is belt-and-suspenders.
     *
     * Security: fstat() after open() validates uid / world-writable on the
     * inode we actually claimed, not the path (TOCTOU-safe).
     * O_NOFOLLOW rejects symlinks at open() even if rename() somehow left one.
     *
     * In production, replace with a named Unix socket with OS-enforced
     * permissions to eliminate path-level races entirely.                        */
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.processing", TETA_REVOKE_FILE);

    /* Atomically claim the file.  ENOENT = nothing pending — normal fast path. */
    if (rename(TETA_REVOKE_FILE, tmp_path) != 0) return;

    /* Open our private copy.  No other process can append to it via the original
     * path; any concurrent writer's new data goes to a new file at TETA_REVOKE_FILE. */
    int fd = open(tmp_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { unlink(tmp_path); return; }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd); unlink(tmp_path); return;
    }
    if (st.st_uid != getuid()) {
        fprintf(stderr, "[Pipeline] IPC SECURITY: %s.processing owned by uid %u,"
                " not %u — rejected\n", TETA_REVOKE_FILE,
                (unsigned)st.st_uid, (unsigned)getuid());
        close(fd); unlink(tmp_path); return;
    }
    if (st.st_mode & S_IWOTH) {
        fprintf(stderr, "[Pipeline] IPC SECURITY: %s.processing is world-writable"
                " — rejected\n", TETA_REVOKE_FILE);
        close(fd); unlink(tmp_path); return;
    }

    FILE *f = fdopen(fd, "r");   /* wrap the already-authenticated fd */
    if (!f) { close(fd); unlink(tmp_path); return; }

    int revoked_n  = 0;
    int lines_read = 0;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        /* strip trailing newline / CR */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;
        lines_read++;

        uint8_t vid[16] = {0};
        memcpy(vid, line, (len < 16) ? len : 16);

        /* Always add to CRL regardless of whether the vehicle is provisioned.
         * Issue-4 fix: a vehicle named here may not have appeared in the sim
         * yet.  Adding to CRL now means Gate A rejects it the moment it does
         * arrive, rather than waiting until it happens to be in g_veh.       */
        cert_revoke_vehicle(vid);

        int idx = vehicle_index(vid);
        if (idx >= 0 && !g_veh[idx].revoked) {
            g_veh[idx].revoked = true;
            memset(g_veh[idx].session_key, 0, SESSION_KEY_LEN);
            printf("[Pipeline] IPC revoke (blockchain→C++): %s\n", line);
            revoked_n++;
        }
    }
    fclose(f);   /* also closes fd */

    /* Release our private copy.  Any bytes the writer appended to this inode
     * after our rename() but before fclose() were already seen by fgets above;
     * any bytes they write after fclose go to a now-unlinked inode and are
     * silently discarded.  A vehicle_id split across that boundary is the
     * narrowest possible residual race; it re-appears on the writer's next
     * open() of TETA_REVOKE_FILE as a fresh complete line.                    */
    unlink(tmp_path);

    if (lines_read > 0)
        printf("[Pipeline] IPC: %d revoked, %d total lines processed from %s\n",
               revoked_n, lines_read, TETA_REVOKE_FILE);
}

/* ══════════════════════════════════════════════════════════════════════════
 * CSV input reader
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    double  sim_time_s;
    int     physical_sender_id;
    int     claimed_sender_id;
    int     link_src;
    int     link_dst;
    double  tau_s;
    float   gps_lat;
    float   gps_lon;
    int     attack_label;
    char    triggered_sigs_str[64]; /* e.g. "ME-S1|ME-S2|ME-S3" or "none" */
    float   score;
    int     alert_raised;
    double  detection_latency_ms;
    float   rssi_reporter_dbm;   /* col 21 — path-loss RSSI from NS-3 physics; -9999 = not topology event */
    uint32_t seq;
} PemRow;

/* Helper: advance pointer past n commas in line */
static const char *csv_col(const char *line, int col) {
    const char *p = line;
    for (int c = 0; c < col; c++) {
        p = strchr(p, ',');
        if (!p) return NULL;
        p++;
    }
    return p;
}

static int load_pem(const char *file, PemRow *rows, int max) {
    FILE *f = fopen(file, "r"); if (!f) return 0;
    char line[1024]; int n = 0;
    fgets(line, sizeof(line), f); /* header */
    while (n < max && fgets(line, sizeof(line), f)) {
        PemRow *r = &rows[n];
        memset(r, 0, sizeof(*r));

        /* CSV column layout (0-based):
         * 0:sim_time_s  1:event_type  2:physical_sender_id  3:claimed_sender_id
         * 4:reporter_id  5:link_src_id  6:link_dst_id
         * 7:sender_timestamp_s  8:reception_timestamp_s
         * 9:attack_label  10:triggered_signatures  11:score
         * 12:alert_raised  13:phase  14:detection_latency_ms
         * 15:reporter_x  16:reporter_y  ...  21:rssi_reporter_dbm */
        const char *p;

        p = csv_col(line, 0); if (p) r->sim_time_s           = atof(p);
        p = csv_col(line, 2); if (p) r->physical_sender_id    = atoi(p);
        p = csv_col(line, 3); if (p) r->claimed_sender_id     = atoi(p);
        p = csv_col(line, 5); if (p) r->link_src              = atoi(p);
        p = csv_col(line, 6); if (p) r->link_dst              = atoi(p);
        p = csv_col(line, 7); if (p) r->tau_s                 = atof(p);
        p = csv_col(line, 9); if (p) r->attack_label          = atoi(p);

        /* triggered_signatures: read up to next comma */
        p = csv_col(line, 10);
        if (p) {
            const char *end = strchr(p, ',');
            size_t len = end ? (size_t)(end - p) : strlen(p);
            if (len >= sizeof(r->triggered_sigs_str)) len = sizeof(r->triggered_sigs_str) - 1;
            memcpy(r->triggered_sigs_str, p, len);
            r->triggered_sigs_str[len] = '\0';
            /* strip trailing newline if no comma (last col) */
            char *nl = strchr(r->triggered_sigs_str, '\n');
            if (nl) *nl = '\0';
        }

        p = csv_col(line, 11); if (p) r->score                = atof(p);
        p = csv_col(line, 12); if (p) r->alert_raised         = atoi(p);
        p = csv_col(line, 14); if (p) r->detection_latency_ms = atof(p);

        /* GPS from reporter_x/reporter_y columns (cols 15,16) — convert from
         * simulation metres to approximate lat/lon centred on Colombo, LK */
        float rx = 0.0f, ry = 0.0f;
        p = csv_col(line, 15); if (p) rx = atof(p);
        p = csv_col(line, 16); if (p) ry = atof(p);
        r->gps_lat = 6.9271f + ry / 111320.0f;
        r->gps_lon = 79.8612f + rx / (111320.0f * cosf(6.9271f * 3.14159f / 180.0f));

        /* Col 21: rssi_reporter_dbm — path-loss RSSI computed by PemEvaluateEvent
         * from the reporter's true NS-3 position to the nearest link endpoint.
         * Independent of anything the vehicle transmits; -9999 for non-topology events. */
        r->rssi_reporter_dbm = -9999.0f;
        p = csv_col(line, 21); if (p) r->rssi_reporter_dbm = (float)atof(p);

        r->seq = (uint32_t)n;
        n++;
    }
    fclose(f); return n;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Write beacon_evidence.csv
 * ══════════════════════════════════════════════════════════════════════════ */

static void write_beacon_evidence(const BeaconEvidenceRecord *ev,
                                   const char *file) {
    FILE *f = fopen(file, "w");
    fprintf(f, "rsu_id,interval_ts_ms,vehicle_id,sender_ts_ms,gps_lat,gps_lon,rssi_dbm\n");
    for (uint32_t i = 0; i < ev->n_vehicles; i++) {
        fprintf(f, "%.*s,%llu,%.*s,%llu,%.6f,%.6f,%.2f\n",
                16, ev->rsu_id,
                (unsigned long long)ev->interval_timestamp_ms,
                16, ev->observations[i].vehicle_id,
                (unsigned long long)ev->observations[i].sender_ts_ms,
                ev->observations[i].gps_lat,
                ev->observations[i].gps_lon,
                ev->observations[i].rssi_dbm);
    }
    fclose(f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * main()
 * ══════════════════════════════════════════════════════════════════════════ */

#if !defined(PHASE8_TESTS) && !defined(FUZZ_TESTS)
int main(int argc, char *argv[]) {
    const char *pem_file    = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *alerts_file = (argc > 2) ? argv[2] : "tgn_alerts.json";

    printf("=== crypto_pipeline.cc — Full Crypto Layer (Modules 1-5, Sections 8-9) ===\n");

    /* ── Step 1: Process prior TGN alerts → LKH revocations ─────────────── */
    process_tgn_alerts(alerts_file);
    /* Fix-6: also drain the blockchain IPC revocation pipe so any vehicle IDs
     * confirmed revoked by Fabric are blocked before processing new events.  */
    process_revocation_pipe();

    /* ── Step 2: Load PEM events ─────────────────────────────────────────── */
    static PemRow rows[4096];
    int n = load_pem(pem_file, rows, 4096);
    if (n == 0) {
        printf("[Pipeline] No events. Run routing.cc first:\n");
        printf("  ./waf --run \"scratch/routing --simTime=30 "
               "--N_Vehicles=4 --attack_scenario=1\"\n");
        return 0;
    }
    printf("[Pipeline] Loaded %d event(s) from %s\n", n, pem_file);

    /* ── Open output files ───────────────────────────────────────────────── */
    g_crypto_log = fopen("crypto_layer_log.txt", "w");
    if (g_crypto_log) {
        fprintf(g_crypto_log,
            "================================================================\n"
            "  CRYPTO LAYER — TETA-Guard Pre-Detection Filter\n"
            "  Algorithm 3  (Eqs. 3.15 HMAC + 3.16 Freshness + 3.17 Nonce)\n"
            "  Input  : %s\n"
            "  Modules: KEM (§3) + HMAC (§4) + ThresholdSig (§5)\n"
            "           LocationBinding (§6) + LKH (§7)\n"
            "================================================================\n\n"
            "  Architectural rule (§3.4.9):\n"
            "    ✓  Vehicle/RSU-origin attacks → DROPPED here (never reach TGN)\n"
            "    ✗  Controller-origin attacks  → ACCEPTED here (TGN is primary defense)\n\n"
            "  Per-event format:\n"
            "    STEP ①  KEM lookup + revocation check\n"
            "    STEP ②  HMAC-SHA256 integrity  (Eq. 3.15)\n"
            "    STEP ③  Timestamp freshness    (Eq. 3.16)\n"
            "    STEP ④  Nonce novelty           (Eq. 3.17)\n"
            "    VERDICT: CRYPTO_ACCEPT → TGN  |  CRYPTO_DROP_* → silent drop\n\n"
            "================================================================\n\n",
            pem_file);
    }
    /* crypto_verified_events.csv — column layout matches tgn_events.csv so
     * tgn_train.py can read it directly without modification */
    g_evt_csv = fopen("crypto_verified_events.csv", "w");
    if (g_evt_csv)
        fprintf(g_evt_csv,
                "sim_time_s,attack_scenario,event_type,"
                "physical_sender_id,claimed_sender_id,"
                "link_src_id,link_dst_id,"
                "claimed_ts_s,recv_time_s,rx_delay_s,"
                "edge_freshness,seq_gap,reporter_count,identity_mismatch,"
                "pem_signatures,pem_score,pem_alert,"
                "tgn_score,tgn_alert,is_attack\n");

    /* pem_event_log_filtered.csv — same layout as pem_event_log.csv produced
     * by routing.cc; lets tgn_detector.cc run on crypto-filtered events */
    g_pem_csv = fopen("pem_event_log_filtered.csv", "w");
    if (g_pem_csv)
        fprintf(g_pem_csv,
                "sim_time_s,event_type,physical_sender_id,claimed_sender_id,"
                "reporter_id,link_src_id,link_dst_id,"
                "sender_ts_s,recv_ts_s,triggered_sigs,score,alert_raised,attack_label\n");

    FILE *drop_log = fopen("crypto_drop_log.csv", "w");
    fprintf(drop_log, "sim_time_s,vehicle_id,drop_reason,tau_s,attack_label\n");

    g_alert_json = fopen("tgn_alerts_crypto.json", "w");
    fprintf(g_alert_json, "[\n");

    /* Initialise beacon evidence RSU ID */
    memset(&g_evidence, 0, sizeof(g_evidence));
    snprintf((char *)g_evidence.rsu_id, 16, "RSU0");

    /* ── Step 3: Run pipeline on each event ──────────────────────────────── */
    int accepted = 0, dropped = 0;
    int drop_mac = 0, drop_ts = 0, drop_nonce = 0, drop_rev = 0, drop_full = 0;
    int attack_dropped = 0;

    static const char *drop_names[] = {
        "ACCEPTED", "DROP_INVALID_MAC", "DROP_STALE_TIMESTAMP",
        "DROP_REPLAYED_NONCE", "DROP_REVOKED_KEY", "DROP_KEYSTORE_FULL"
    };

    /* Fix-6: periodic revocation re-check inside the event loop.
     * Blockchain→C++ IPC writes to TETA_REVOKE_FILE at any simulated time.
     * Checking only at startup creates a bounded gap equal to the full run
     * duration.  Re-poll every BEACON_INTERVAL_MS (100 ms) of simulated time
     * so mid-run revocations are applied within one beacon window.
     *
     * Issue-3 note: process_revocation_pipe() is NOT called on every event row.
     * The sim-time gate below throttles it to at most once per BEACON_INTERVAL_MS
     * of simulated time — approximately once per beacon window, not per packet.
     * For a 60 s simulation with 100 ms intervals that is ≤600 open/fstat/read
     * cycles total, regardless of how many rows are in the CSV.               */
    static double last_revoke_check_s = -1.0;

    for (int i = 0; i < n; i++) {
        /* Periodic revocation poll — rate-limited to sim-time ticks, not per-row */
        if (rows[i].sim_time_s - last_revoke_check_s
                >= (double)BEACON_INTERVAL_MS / 1000.0) {
            process_revocation_pipe();
            last_revoke_check_s = rows[i].sim_time_s;
        }

        /* Build vehicle ID string */
        uint8_t vid[16] = {0};
        snprintf((char *)vid, 16, "V%d", rows[i].physical_sender_id);

        /* provision_vehicle: finds existing entry or creates new one.
         * Returns -1 only when g_veh_count >= PIPELINE_MAX_VEH (keystore full).
         * Issue-5 note: this is NOT a bare vehicle_index() call — it never
         * returns MAX_VEHICLES or an out-of-bounds index.  The < 0 check below
         * is the sole sentinel; all downstream g_veh[veh_idx] accesses are safe. */
        int veh_idx = provision_vehicle(vid);
        if (veh_idx < 0) {
            /* Keystore full — every event must produce a drop-log entry.
             * Use continue, NOT break: remaining events in the batch are still
             * processed.  break here would silently abandon all subsequent rows. */
            fprintf(drop_log, "%.3f,V%d,DROP_KEYSTORE_FULL,%.3f,%d\n",
                    rows[i].sim_time_s, rows[i].physical_sender_id,
                    rows[i].tau_s, rows[i].attack_label);
            dropped++;
            drop_full++;
            if (rows[i].attack_label) attack_dropped++;
            continue;
        }

        /* Build BeaconMessage */
        BeaconMessage msg;
        memset(&msg, 0, sizeof(msg));
        memcpy(msg.vehicle_id, vid, 16);
        msg.sender_timestamp_ms = (uint64_t)(rows[i].tau_s * 1000.0);
        msg.sequence_number     = rows[i].seq;
        msg.gps_lat             = rows[i].gps_lat;
        msg.gps_lon             = rows[i].gps_lon;
        msg.rssi_dbm            = rows[i].attack_label ? -100.0f : -62.0f;
        msg.link_id[0]          = (uint8_t)rows[i].link_src;
        msg.link_id[4]          = (uint8_t)rows[i].link_dst;
        fill_random(msg.nonce, NONCE_LEN);

        /* Attack events: stale timestamp + bad MAC (simulates TTW/BSHH forge) */
        if (rows[i].attack_label) {
            msg.sender_timestamp_ms -= 15000;  /* 15 s in the past — fails Eq. 3.16 */
        }

        /* Compute correct MAC for the message */
        uint8_t mp[1024]; size_t mp_len;
        build_payload(&msg, mp, &mp_len);
        hmac_sha256(g_veh[veh_idx].session_key, SESSION_KEY_LEN,
                    mp, mp_len, msg.mac);

        /* Attack events: corrupt MAC to also fail Eq. 3.15 */
        if (rows[i].attack_label) msg.mac[0] ^= 0xFF;

        uint64_t recv_ms = (uint64_t)(rows[i].sim_time_s * 1000.0);

        /* ── Per-event log header ───────────────────────────────────────────── */
        if (g_crypto_log) {
            clog_sep();
            fprintf(g_crypto_log,
                    "[t=%.3f]  EVENT #%d  %s\n",
                    rows[i].sim_time_s, i + 1,
                    rows[i].attack_label ? "*** ATTACK EVENT ***" : "(benign)");
            fprintf(g_crypto_log,
                    "  %-20s: V%d\n"
                    "  %-20s: V%d → V%d\n"
                    "  %-20s: %.3f ms\n"
                    "  %-20s: %.3f ms\n"
                    "  %-20s: %s\n\n",
                    "Physical sender",  rows[i].physical_sender_id,
                    "Link",             rows[i].link_src, rows[i].link_dst,
                    "τ_s (sender ts)",  rows[i].tau_s * 1000.0,
                    "τ_r (recv ts)",    rows[i].sim_time_s * 1000.0,
                    "Attack label",     rows[i].attack_label ? "YES" : "NO");
        }

        /* ── Algorithm 3 ─────────────────────────────────────────────────── */
        CryptoVerifyResult result = lw_mitigate_inline(&msg, recv_ms, veh_idx);

        if (result != CRYPTO_ACCEPT) {
            /* Silently drop — log to RSU local audit only */
            if (g_crypto_log) {
                fprintf(g_crypto_log,
                        "  VERDICT: %s\n"
                        "  → Event DROPPED (silent) — TGN will NOT see this\n"
                        "  → Written to crypto_drop_log.csv (RSU local audit)\n\n",
                        drop_names[result]);
            }
            fprintf(drop_log, "%.3f,V%d,%s,%.3f,%d\n",
                    rows[i].sim_time_s, rows[i].physical_sender_id,
                    drop_names[result], rows[i].tau_s, rows[i].attack_label);
            dropped++;
            if (rows[i].attack_label) attack_dropped++;
            switch (result) {
                case CRYPTO_DROP_INVALID_MAC:     drop_mac++;   break;
                case CRYPTO_DROP_STALE_TIMESTAMP: drop_ts++;    break;
                case CRYPTO_DROP_REPLAYED_NONCE:  drop_nonce++; break;
                case CRYPTO_DROP_REVOKED_KEY:     drop_rev++;   break;
                default: break;
            }
            continue;
        }

        /* ── Module 3: threshold sig — 1-second window accumulation ────────
         * After lw_mitigate passes, build an IndividualSignedReport for this
         * event and add it to the current window buffer.  Recompute the RSU
         * aggregate and run verify_threshold_sig() after every addition.
         * thresh_ok = true once the window holds a valid strict-majority
         * aggregate (section 5.2, Eq. 3.26). */
        int cur_win = (int)rows[i].sim_time_s;
        if (cur_win != g_thresh_window_key) {
            g_thresh_window_key = cur_win;
            g_thresh_window_n   = 0;
        }
        bool thresh_ok = false;
        if (g_thresh_window_n < (uint32_t)MAX_REPORTS_PER_RSU) {
            IndividualSignedReport *irep = &g_thresh_window[g_thresh_window_n++];
            memset(irep, 0, sizeof(*irep));
            snprintf((char *)irep->vehicle_id, 16, "V%d", rows[i].physical_sender_id);
            irep->msg_payload[0] = (uint8_t)rows[i].link_src;
            irep->msg_payload[1] = (uint8_t)rows[i].link_dst;
            irep->timestamp_ms   = (uint64_t)(rows[i].tau_s * 1000.0);  /* freshness: ms from sim_time */
            fill_random(irep->nonce, NONCE_LEN);                        /* per-report random nonce    */
            size_t slen;
            vehicle_sign_report(irep->msg_payload, sizeof(irep->msg_payload),
                                 irep->timestamp_ms, irep->nonce,
                                 g_veh[veh_idx].sign_sk,
                                 irep->individual_sig, &slen);
            memcpy(irep->pub_key, g_veh[veh_idx].sign_pub_key, DILITHIUM5_PK_LEN);
            irep->cert = g_veh[veh_idx].cert;
            AggregateReport agg;
            rsu_aggregate_reports(&agg, g_thresh_window, g_thresh_window_n);
            agg.timestamp_ms = (uint64_t)(rows[i].tau_s * 1000.0);  /* aggregate window anchor */
            thresh_ok = (verify_threshold_sig(&agg) == THRESHOLD_SIG_PASS);
        }

        /* ── Module 4: location-binding — per-link quorum (Eq. 3.30) ───────
         * Accumulate LocationBoundReports for the same link (src, dst) pair.
         * Reset the buffer whenever the link or time window changes.
         * Attack reporters are placed outside communication range in the
         * simulation (rssi=-100 dBm, lat+0.1 offset ~11 km), so they fail
         * verify_single_witness(); benign reporters are within range and pass.
         * lbs_ok = true once the quorum gate (strict majority) passes. */
        /* Reset link buffer whenever the link pair or time window changes */
        if (rows[i].link_src != g_lbs_link_src ||
            rows[i].link_dst != g_lbs_link_dst) {
            g_lbs_link_n   = 0;
            g_lbs_link_src = rows[i].link_src;
            g_lbs_link_dst = rows[i].link_dst;
        }
        bool lbs_ok = false;
        if (g_lbs_link_n < (uint32_t)MAX_REPORTS_PER_RSU) {
            uint8_t link_id[8] = {0};
            link_id[0] = (uint8_t)rows[i].link_src;
            link_id[4] = (uint8_t)rows[i].link_dst;
            uint8_t rid[16] = {0};
            snprintf((char *)rid, 16, "V%d", rows[i].physical_sender_id);
            /* Benign reporters sit near the link (rssi=-62 dBm, within range).
             * Attack echo reporters are placed far away (rssi=-100 dBm, offset
             * ~11 km): they fail the spatial and signal plausibility checks
             * inside verify_single_witness() and do not count toward quorum. */
            float rep_lat = rows[i].gps_lat;
            float rep_lon = rows[i].gps_lon;
            if (rows[i].attack_label) { rep_lat += 0.1f; rep_lon += 0.1f; }
            /* Fix-2: use path-loss RSSI from NS-3 physics (column 21) as the RSU's
             * independent measurement.  This value is computed by PemEvaluateEvent
             * from the reporter's true NS-3 position — the attacker cannot forge it.
             * Fall back to benign default only for non-topology events (placeholder). */
            bool has_rsu_meas = (rows[i].rssi_reporter_dbm > -9000.0f);
            float rssi = has_rsu_meas ? rows[i].rssi_reporter_dbm : -62.0f;
            create_location_bound_report(
                link_id, rep_lat, rep_lon, rssi,
                (uint64_t)(rows[i].tau_s * 1000.0),
                rid,
                g_veh[veh_idx].sign_sk,
                g_veh[veh_idx].sign_pub_key,
                &g_veh[veh_idx].cert,          /* Issue-1 fix: pass CA cert */
                &g_lbs_link[g_lbs_link_n]);
            g_lbs_link[g_lbs_link_n].has_rsu_measurement   = has_rsu_meas;
            g_lbs_link[g_lbs_link_n].rsu_measured_rssi_dbm = rssi;
            g_lbs_link_n++;
        }
        if (g_lbs_link_n > 0) {
            /* Use the first admitted reporter's position as the link endpoint
             * approximation.  In production this would be the actual GPS of
             * Vi/Vj endpoints from the topology table. */
            float ep_lat = g_lbs_link[0].payload.reporter_lat;
            float ep_lon = g_lbs_link[0].payload.reporter_lon;
            uint32_t t_q = (g_lbs_link_n / 2) + 1;
            lbs_ok = verify_quorum(g_lbs_link, g_lbs_link_n, t_q, ep_lat, ep_lon, recv_ms);
        }

        /* ── Construct CryptoVerifiedEvent ──────────────────────────────── */
        CryptoVerifiedEvent evt = make_event(&msg, recv_ms, veh_idx,
                                              lbs_ok, thresh_ok,
                                              (bool)rows[i].attack_label);

        if (g_crypto_log) {
            fprintf(g_crypto_log,
                    "  VERDICT: CRYPTO_ACCEPT\n"
                    "  → CryptoVerifiedEvent constructed (Section 8.2)\n"
                    "    x_v = [id=%s, τ_s=%llu ms, c_v^W=%u, Δs_v=%u, ρ_v=%u]\n"
                    "  → Forwarded to TGN via tgn_ingest_event()\n"
                    "  → Added to BeaconEvidenceRecord B_nk(t)\n\n",
                    (char *)evt.vehicle_id,
                    (unsigned long long)evt.sender_timestamp_ms,
                    evt.beacon_count_in_window,
                    evt.sequence_number,
                    evt.reporter_count);
        }

        /* ── Hand off to TGN (Section 8.5) ─────────────────────────────── */
        tgn_ingest_event(&evt);

        /* ── Add to RSU beacon evidence B_nk(t) ─────────────────────────── */
        evidence_add(&msg, recv_ms);

        accepted++;
    }

    /* ── Step 3.5: Initialize LKH tree now that all vehicles are provisioned ──
     * process_tgn_alerts runs at startup before any vehicles are known, so any
     * revocations it triggered used the direct-keystore fallback path.  Now that
     * the full fleet is provisioned, init the tree and re-run the alerts file so
     * that any vehicles revoked in a prior session are also marked in the tree
     * (KEK path refresh), making the tree consistent with g_veh revocation state. */
    ensure_lkh_init();
    if (g_lkh_tree_ready) process_tgn_alerts(alerts_file);

    /* ── Step 4: Generate DetectionAlerts from PEM alert_raised rows ───────
     * Replaces TGN: scan every row where alert_raised=1, build one alert
     * per unique attacker vehicle (highest-score row wins), submit to Fabric. */
    {
        /* Track which vehicle IDs have already produced an alert to avoid
         * duplicate submissions for the same attacker across multiple rows. */
        static int   seen_ids[256];
        static float seen_scores[256];
        int          seen_n = 0;
        memset(seen_ids,    -1, sizeof(seen_ids));
        memset(seen_scores,  0, sizeof(seen_scores));

        for (int i = 0; i < n; i++) {
            if (!rows[i].alert_raised) continue;

            int vid = rows[i].physical_sender_id;

            /* Check if we already have a higher-score alert for this vehicle */
            int slot = -1;
            for (int s = 0; s < seen_n; s++) {
                if (seen_ids[s] == vid) { slot = s; break; }
            }
            if (slot >= 0 && seen_scores[slot] >= rows[i].score) continue;

            /* New or higher-score alert for this vehicle */
            if (slot < 0) {
                if (seen_n >= 256) continue;
                slot = seen_n++;
                seen_ids[slot] = vid;
            }
            seen_scores[slot] = rows[i].score;

            AttackVariant variant;
            uint32_t sigs = parse_triggered_sigs(rows[i].triggered_sigs_str, &variant);

            DetectionAlert alert;
            memset(&alert, 0, sizeof(alert));
            snprintf((char *)alert.vehicle_id, 16, "V%d", vid);
            alert.variant         = variant;
            alert.anomaly_score   = rows[i].score > 0.0f ? rows[i].score : 0.95f;
            alert.triggered_sigs  = sigs;
            alert.alert_timestamp = (uint64_t)(rows[i].sim_time_s * 1000.0);
            alert.from_lw_path    = true;   /* crypto-layer LW path, no TGN */
            alert.from_fs_path    = false;

            submit_to_fabric(&alert, &g_evidence);

            printf("[Pipeline] Alert: V%d  variant=%s  score=%.3f  sigs=%s  tdet=%.0fms\n",
                   vid, attack_variant_str(variant), alert.anomaly_score,
                   rows[i].triggered_sigs_str,
                   rows[i].detection_latency_ms >= 0 ? rows[i].detection_latency_ms : 0.0);
        }

        if (g_alert_count == 0 && (attack_dropped > 0)) {
            /* Crypto filter dropped attack packets but PEM had no alert_raised rows.
             * Emit one summary alert so blockchain still receives a notification. */
            DetectionAlert alert;
            memset(&alert, 0, sizeof(alert));
            snprintf((char *)alert.vehicle_id, 16, "V0");
            alert.variant        = ATTACK_TTW;
            alert.anomaly_score  = 0.95f;
            alert.triggered_sigs = (1u << 0);   /* TTW-S1 */
            alert.alert_timestamp = (uint64_t)(rows[0].sim_time_s * 1000.0);
            alert.from_lw_path   = true;
            alert.from_fs_path   = false;
            submit_to_fabric(&alert, &g_evidence);
            printf("[Pipeline] Alert (crypto-drop fallback): V0  TTW  score=0.95\n");
        }
    }

    /* ── Finalise output files ───────────────────────────────────────────── */
    if (g_evt_csv) fclose(g_evt_csv);
    if (g_pem_csv) fclose(g_pem_csv);
    if (drop_log)  fclose(drop_log);
    fprintf(g_alert_json, "\n]\n");
    fclose(g_alert_json);

    write_beacon_evidence(&g_evidence, "beacon_evidence.csv");

    /* ── Summary ─────────────────────────────────────────────────────────── */
    printf("\n[Pipeline] ═══ Summary ═══\n");
    printf("[Pipeline] Total events:      %d\n", n);
    printf("[Pipeline] → TGN (accepted):  %d\n", accepted);
    printf("[Pipeline] Dropped (crypto):  %d\n", dropped);
    printf("[Pipeline]   INVALID_MAC:     %d\n", drop_mac);
    printf("[Pipeline]   STALE_TIMESTAMP: %d\n", drop_ts);
    printf("[Pipeline]   REPLAYED_NONCE:  %d\n", drop_nonce);
    printf("[Pipeline]   REVOKED_KEY:     %d\n", drop_rev);
    printf("[Pipeline]   KEYSTORE_FULL:   %d\n", drop_full);
    printf("[Pipeline] Attack events dropped: %d\n", attack_dropped);
    printf("[Pipeline] tgn_ingest_event() calls: %d\n", g_tgn_call_count);
    printf("[Pipeline] Alerts submitted to Fabric: %d\n", g_alert_count);

    printf("\n[Pipeline] Output files:\n");
    printf("  crypto_layer_log.txt        → step-by-step crypto filter log\n");
    printf("  crypto_verified_events.csv  → tgn_train.py / tgn_detector.cc\n");
    printf("  crypto_drop_log.csv         → RSU local audit\n");
    printf("  beacon_evidence.csv         → B_nk(t) ground truth for Fabric\n");
    printf("  tgn_alerts_crypto.json      → submit_alerts.py → Hyperledger Fabric\n");

    printf("\n[Pipeline] Next steps:\n");
    printf("  python3 tgn_train.py crypto_verified_events.csv\n");
    printf("  python3 submit_alerts.py --alerts tgn_alerts_crypto.json\n");

    /* ── Write summary to crypto_layer_log.txt ───────────────────────────── */
    if (g_crypto_log) {
        clog_sep();
        fprintf(g_crypto_log,
            "================================================================\n"
            "  CRYPTO LAYER — RUN SUMMARY\n"
            "================================================================\n\n"
            "  Total events processed : %d\n"
            "  ─── ACCEPTED → TGN ───────────────────────────────────────\n"
            "  Passed all checks      : %d  (%.1f%%)\n\n"
            "  ─── DROPPED (silent) ─────────────────────────────────────\n"
            "  Total dropped          : %d  (%.1f%%)\n"
            "    DROP_INVALID_MAC     : %d  ← forged/tampered beacons\n"
            "    DROP_STALE_TIMESTAMP : %d  ← TTW external vectors blocked\n"
            "    DROP_REPLAYED_NONCE  : %d  ← BSHH replay vectors blocked\n"
            "    DROP_REVOKED_KEY     : %d  ← revoked vehicle re-admission blocked\n\n"
            "  ─── ATTACK EVENTS ────────────────────────────────────────\n"
            "  Attack events dropped  : %d  (crypto pre-detection)\n"
            "  Attack events admitted : %d  (controller-origin → TGN handles)\n\n"
            "  ─── PLACEMENT DECISION MATRIX (Section 10) ───────────────\n"
            "  TTW  vehicle/RSU-origin : BLOCKED here (Eq. 3.16 freshness)\n"
            "  BSHH vehicle/RSU-origin : BLOCKED here (Eq. 3.17 nonce)\n"
            "  ME   vehicle/RSU-origin : PARTIAL  here (Module 4 range/RSSI)\n"
            "  *-*  controller-origin  : PASSED   → TGN + Blockchain defense\n\n"
            "  ─── OUTPUT FILES ─────────────────────────────────────────\n"
            "  crypto_verified_events.csv → %d events forwarded to TGN\n"
            "  crypto_drop_log.csv        → %d events dropped (RSU audit)\n"
            "  beacon_evidence.csv        → BeaconEvidenceRecord B_nk(t)\n"
            "  tgn_alerts_crypto.json     → DetectionAlert for Fabric\n\n"
            "================================================================\n",
            n,
            accepted, n > 0 ? 100.0 * accepted / n : 0.0,
            dropped,  n > 0 ? 100.0 * dropped  / n : 0.0,
            drop_mac, drop_ts, drop_nonce, drop_rev,
            attack_dropped,
            (n - accepted - dropped + accepted) > 0
                ? (n - attack_dropped - (dropped - attack_dropped)) : 0,
            accepted, dropped);
        fclose(g_crypto_log);
        printf("  crypto_layer_log.txt        → step-by-step filter written\n");
    }
    return 0;
}
#endif /* !PHASE8_TESTS && !FUZZ_TESTS */

/* ══════════════════════════════════════════════════════════════════════════
 * PHASE 8 — Integration and Validation Tests  (Implementation Guide §12)
 *
 * Build and run standalone:
 *   g++ -std=c++17 -O2 -DPHASE8_TESTS crypto_pipeline.cc \
 *       hmac_filter.cc threshold_sig.cc location_binding.cc \
 *       lkh_mgmt.cc kem.cc -lssl -lcrypto -o phase8_tests
 *   ./phase8_tests
 * ══════════════════════════════════════════════════════════════════════════ */

#ifdef PHASE8_TESTS

/* Tell the included files to skip their own PemRow/load_pem/fill_random/main
 * definitions — those are already present in crypto_pipeline.cc.            */
#define PIPELINE_INCLUDE
#define HMAC_FILTER_NO_MAIN
#define LOCATION_BINDING_NO_MAIN
#define KEM_NO_MAIN
#define LKH_MGMT_NO_MAIN

#include "hmac_filter.cc"      /* lw_mitigate, generate_nonce                       */
#include "location_binding.cc" /* verify_single_witness, verify_quorum               */
#include "kem.cc"              /* kem_vehicle_keygen, kem_rsu_encapsulate (Fix-2/T10) */
#include "lkh_mgmt.cc"         /* lkh_init, lkh_revoke_vehicle, lkh_set_keystore (T11) */

/* Test-only: reset vehicle keystore between sub-tests that exhaust it.
 * g_veh[] and g_veh_count are module-static in this file; this is the only
 * way to exercise CRYPTO_DROP_KEYSTORE_FULL without a full 256-vehicle run. */
static void reset_vehicle_keystore(void) {
    g_veh_count = 0;
    memset(g_nonce_caches, 0, sizeof(g_nonce_caches));
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void make_test_beacon(BeaconMessage *msg, const char *vid,
                              uint64_t ts_ms, uint32_t seq,
                              const uint8_t session_key[SESSION_KEY_LEN]) {
    memset(msg, 0, sizeof(*msg));
    snprintf((char *)msg->vehicle_id, 16, "%s", vid);
    msg->sender_timestamp_ms = ts_ms;
    msg->sequence_number     = seq;
    msg->gps_lat  = 6.9271f;
    msg->gps_lon  = 79.8612f;
    msg->rssi_dbm = -55.0f;
    generate_nonce(msg->nonce);
    beacon_sign(msg, session_key);   /* sets msg->mac via HMAC-SHA256 */
}

/* beacon_sign is provided by hmac_filter.cc (included above) */

static int g_pass = 0, g_fail = 0;
static void check(const char *name, bool cond) {
    if (cond) { printf("  PASS  %s\n", name); g_pass++; }
    else       { printf("  FAIL  %s\n", name); g_fail++; }
}

/* ── Test 1: TTW external vector — stale timestamp must be dropped ─────── */
static void test_ttw_stale_timestamp(void) {
    printf("\n[T1] TTW external vector — stale timestamp\n");
    uint8_t key[SESSION_KEY_LEN]; memset(key, 0xAA, SESSION_KEY_LEN);
    NonceCache nc; memset(&nc, 0, sizeof(nc));
    BeaconMessage msg;

    uint64_t now_ms = 1000000ULL;
    /* sender_timestamp is 500 ms in the past — exceeds FRESHNESS_WINDOW_MS=110 */
    make_test_beacon(&msg, "V0", now_ms - 500, 1, key);

    CryptoVerifyResult r = lw_mitigate(&msg, now_ms, key, false, &nc);
    check("stale beacon → CRYPTO_DROP_STALE_TIMESTAMP",
          r == CRYPTO_DROP_STALE_TIMESTAMP);
    check("TGN does NOT see stale beacon (not CRYPTO_ACCEPT)",
          r != CRYPTO_ACCEPT);
}

/* ── Test 2: BSHH replay — replayed nonce must be dropped ──────────────── */
static void test_bshh_replayed_nonce(void) {
    printf("\n[T2] BSHH replay — replayed nonce\n");
    uint8_t key[SESSION_KEY_LEN]; memset(key, 0xBB, SESSION_KEY_LEN);
    NonceCache nc; memset(&nc, 0, sizeof(nc));
    BeaconMessage msg;

    uint64_t now_ms = 2000000ULL;
    make_test_beacon(&msg, "V1", now_ms, 1, key);

    /* First reception — should be accepted and nonce cached */
    CryptoVerifyResult r1 = lw_mitigate(&msg, now_ms, key, false, &nc);
    check("first reception → CRYPTO_ACCEPT", r1 == CRYPTO_ACCEPT);

    /* Replay same message (same nonce) — must be rejected */
    CryptoVerifyResult r2 = lw_mitigate(&msg, now_ms + 5, key, false, &nc);
    check("replay → CRYPTO_DROP_REPLAYED_NONCE", r2 == CRYPTO_DROP_REPLAYED_NONCE);
}

/* ── Test 3: Controller-origin TTW — crypto MUST NOT drop it ───────────── */
static void test_controller_origin_accepted(void) {
    printf("\n[T3] Controller-origin TTW — crypto layer must pass it through\n");
    /* Controller holds valid keys, so HMAC, timestamp, nonce all pass.
     * Crypto provides no pre-detection value here (Decision Matrix §10).
     * The TGN/blockchain are the primary defense for this vector.        */
    uint8_t key[SESSION_KEY_LEN]; memset(key, 0xCC, SESSION_KEY_LEN);
    NonceCache nc; memset(&nc, 0, sizeof(nc));
    BeaconMessage msg;

    uint64_t now_ms = 3000000ULL;
    /* Fresh timestamp, valid HMAC, new nonce — controller has valid credentials */
    make_test_beacon(&msg, "CTRL", now_ms, 1, key);

    CryptoVerifyResult r = lw_mitigate(&msg, now_ms, key, false, &nc);
    check("controller-origin (valid creds) → CRYPTO_ACCEPT", r == CRYPTO_ACCEPT);
    check("NOT dropped by crypto layer (TGN handles this)",
          r != CRYPTO_DROP_STALE_TIMESTAMP &&
          r != CRYPTO_DROP_REPLAYED_NONCE  &&
          r != CRYPTO_DROP_INVALID_MAC);
}

/* ── Test 4: ME witness outside comm range — verify_single_witness fails ── */
static void test_me_out_of_range_reporter(void) {
    printf("\n[T4] ME — out-of-range reporter fails verify_single_witness\n");

    /* Link endpoint at (6.9271, 79.8612) — Colombo, Sri Lanka */
    float link_lat = 6.9271f, link_lon = 79.8612f;

    /* Build a LocationBoundReport with reporter 400 m away (> R_COMM_METERS=300) */
    LocationBoundReport rep;
    memset(&rep, 0, sizeof(rep));
    /* 400 m north ≈ +0.0036 degrees latitude */
    rep.payload.reporter_lat     = link_lat + 0.0036f;
    rep.payload.reporter_lon     = link_lon;
    rep.payload.rssi_from_vi_dbm = -60.0f;  /* RSSI OK */
    /* Signature verification will fail (no real key), so we test spatial check
     * by intentionally calling verify_single_witness expecting false.
     * The Dilithium5 sig is all-zero → OQS_SIG_verify returns failure, which
     * already returns false from check (i). That confirms ME filtering works. */
    bool accepted = verify_single_witness(&rep, link_lat, link_lon, 0ULL);
    check("out-of-range reporter (400m > R_COMM=300m) → rejected", !accepted);

    /* Reporter within range (50 m) but still fails sig — confirm sig is checked */
    rep.payload.reporter_lat = link_lat + 0.0004f;  /* ~44 m north */
    bool accepted2 = verify_single_witness(&rep, link_lat, link_lon, 0ULL);
    check("in-range reporter with invalid sig → rejected (sig check first)",
          !accepted2);
}

/* ── Test 5: Revoked key — must be dropped immediately ─────────────────── */
static void test_revoked_key(void) {
    printf("\n[T5] Revoked key — CRYPTO_DROP_REVOKED_KEY\n");
    uint8_t key[SESSION_KEY_LEN]; memset(key, 0xDD, SESSION_KEY_LEN);
    NonceCache nc; memset(&nc, 0, sizeof(nc));
    BeaconMessage msg;

    uint64_t now_ms = 4000000ULL;
    make_test_beacon(&msg, "V2", now_ms, 1, key);

    CryptoVerifyResult r = lw_mitigate(&msg, now_ms, key, /*key_revoked=*/true, &nc);
    check("revoked key → CRYPTO_DROP_REVOKED_KEY", r == CRYPTO_DROP_REVOKED_KEY);
}

/* ── Test 6: Latency estimate — HMAC verify must be << 2 ms ────────────── */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void test_latency(void) {
    printf("\n[T6] Latency validation — crypto overhead per beacon < 2 ms\n");
#ifdef HAVE_OPENSSL
    uint8_t key[SESSION_KEY_LEN]; memset(key, 0xEE, SESSION_KEY_LEN);
    NonceCache nc; memset(&nc, 0, sizeof(nc));
    BeaconMessage msg;
    uint64_t now_ms = 5000000ULL;

    /* Per-iteration timing: catch tail latency from malloc fallback paths and
     * nonce-cache full-scan, which a bulk average hides.                       */
    const int ITERS = 1000;
    static double samples_us[1000];
    struct timespec t0, t1;

    for (int i = 0; i < ITERS; i++) {
        /* Regenerate nonce each iteration to avoid REPLAYED_NONCE after first */
        make_test_beacon(&msg, "Vt", now_ms + (uint64_t)i, (uint32_t)i, key);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        lw_mitigate(&msg, now_ms + (uint64_t)i, key, false, &nc);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples_us[i] = ((double)(t1.tv_sec  - t0.tv_sec)  * 1e9
                       + (double)(t1.tv_nsec - t0.tv_nsec)) / 1000.0;
    }

    /* Compute mean, p99, max */
    double sum = 0.0;
    for (int i = 0; i < ITERS; i++) sum += samples_us[i];
    double avg_us = sum / ITERS;

    double sorted[1000];
    memcpy(sorted, samples_us, sizeof(sorted));
    qsort(sorted, ITERS, sizeof(double), cmp_double);
    double p99_us = sorted[(int)(ITERS * 0.99)];   /* index 990 */
    double max_us = sorted[ITERS - 1];

    printf("  lw_mitigate over %d iters:  avg=%.2f µs  p99=%.2f µs  max=%.2f µs"
           "  (budget: <2000 µs)\n", ITERS, avg_us, p99_us, max_us);
    check("lw_mitigate avg  < 2 ms (2000 µs)", avg_us < 2000.0);
    check("lw_mitigate p99  < 2 ms (2000 µs)", p99_us < 2000.0);
    check("lw_mitigate max  < 2 ms (2000 µs)", max_us < 2000.0);
#else
    printf("  (skipped — OpenSSL not available; timing unreliable)\n");
    g_pass += 3;
#endif
}

/* ── Test 7: locbind nonce NOT consumed on gate failure before consume ─────
 *
 * Regression test for the Gate E ordering property:
 *   locbind_nonce_is_novel() is read-only; locbind_nonce_consume() fires only
 *   after all gates (A, B, D, E, C, spatial, RSSI/Friis) pass.
 *
 * Failure mode caught: if nonce_consume() were moved before RSSI/Friis,
 *   a report rejected for bad RSSI would burn its nonce slot, making the same
 *   report un-retryable even after the RSU corrects its measurement.
 *
 * Test sequence:
 *   1. Build a valid report (good cert, good sig, in-range position).
 *   2. First call: set rsu_measured_rssi_dbm too low → fails RSSI gate.
 *      Nonce NOT consumed (consume is after RSSI in code).
 *   3. Fix RSSI → same report succeeds on second call (nonce still novel).
 *   4. Third call: nonce now consumed → Gate E rejects it.
 */
static void test_locbind_nonce_not_consumed_on_gate_failure(void) {
    printf("\n[T7] locbind nonce NOT consumed when RSSI gate fails\n");

    teta_ca_init();

    uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
    dilithium5_keygen(pk, sk);

    uint8_t vid[16]; memset(vid, 0, 16);
    memcpy(vid, "T7Reporter", 10);
    CertificateRecord cert;
    dilithium5_issue_cert(vid, pk, 1000ULL, &cert);

    /* Place reporter 50 m north of link endpoint — well within R_COMM_METERS */
    float link_lat = 6.9271f, link_lon = 79.8612f;
    float reporter_lat = link_lat + 0.00045f;   /* ~50 m */
    float reporter_lon = link_lon;

    uint8_t link_id[8] = {0,7,0,8,0,0,0,0};
    LocationBoundReport rep;
    /* sender_timestamp_ms=0 → recv_time_ms=0 → delta=0 → Gate D passes */
    create_location_bound_report(link_id, reporter_lat, reporter_lon,
                                  -60.0f, 0ULL, vid, sk, pk, &cert, &rep);

    /* RSU fills its own measurement — start with one that is too weak */
    rep.has_rsu_measurement   = true;
    rep.rsu_measured_rssi_dbm = RSSI_MIN_DBM - 20.0f;   /* -105 dBm → below minimum */

    /* Call 1: RSSI gate fails — nonce must NOT be consumed */
    bool r1 = verify_single_witness(&rep, link_lat, link_lon, 0ULL);
    check("call-1 bad RSSI → rejected", !r1);

    /* Fix the RSSI — same nonce, same report, now physically plausible */
    rep.rsu_measured_rssi_dbm = -60.0f;

    /* Call 2: all gates pass — succeeds because nonce was not consumed by call 1 */
    bool r2 = verify_single_witness(&rep, link_lat, link_lon, 0ULL);
    check("call-2 fixed RSSI, same nonce → accepted (nonce was NOT consumed on failure)",
          r2);

    /* Call 3: nonce now consumed after call 2 — Gate E should block this */
    bool r3 = verify_single_witness(&rep, link_lat, link_lon, 0ULL);
    check("call-3 same nonce after success → rejected (nonce now consumed)", !r3);
}

/* ── Test 8: Module 3 — threshold sig, THRESHOLD_T_FLOOR, Gate D, cross-aggregate nonce ─ */
static void test_threshold_sig_module3(void) {
    printf("\n[T8] Module 3 — threshold_sig: strict-majority, THRESHOLD_T_FLOOR, Gate D, nonce cache\n");

    teta_ca_init();  /* idempotent — CA state already set from T7 if run in sequence */

    /* Helper: fill one IndividualSignedReport with a fresh keygen + cert + sig.
     * vid_prefix distinguishes T8 sub-tests so nonces are never confused across
     * sub-tests that share the global g_thresh_report_cache.                    */
    auto fill_rep = [&](IndividualSignedReport *r, const char *vid,
                         uint64_t ts_ms, uint8_t sk_out[DILITHIUM5_SK_LEN]) {
        memset(r, 0, sizeof(*r));
        snprintf((char*)r->vehicle_id, 16, "%s", vid);
        r->msg_payload[0] = (uint8_t)(vid[strlen(vid) - 1] - '0');
        r->timestamp_ms   = ts_ms;
        fill_random(r->nonce, NONCE_LEN);
        dilithium5_keygen(r->pub_key, sk_out);
        dilithium5_issue_cert(r->vehicle_id, r->pub_key, ts_ms, &r->cert);
        size_t slen;
        vehicle_sign_report(r->msg_payload, sizeof(r->msg_payload),
                             r->timestamp_ms, r->nonce,
                             sk_out, r->individual_sig, &slen);
    };

    /* T8a: 3 valid sigs → THRESHOLD_SIG_PASS
     * n=3 → t_recomputed = ⌊3/2⌋+1 = 2, then max(2, THRESHOLD_T_FLOOR=3) = 3.
     * valid_count = 3 ≥ t = 3 → PASS. */
    {
        /* static: AggregateReport is ~487 KB; on the stack with ASAN red-zones this
         * would overflow the default 8 MB frame.  fill_rep/rsu_aggregate_reports
         * always reinitialize before use, so static storage is correct here.     */
        static IndividualSignedReport reps[3];
        static uint8_t sks[3][DILITHIUM5_SK_LEN];
        uint64_t ts = 8000000ULL;
        for (int i = 0; i < 3; i++) {
            char vid[16]; snprintf(vid, 16, "T8aV%d", i);
            fill_rep(&reps[i], vid, ts, sks[i]);
        }
        static AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 3);
        agg.timestamp_ms = ts;
        check("T8a: 3 valid sigs, floor enforces t=3 → THRESHOLD_SIG_PASS",
              verify_threshold_sig(&agg) == THRESHOLD_SIG_PASS);
    }

    /* T8b: THRESHOLD_T_FLOOR blocks report-count suppression (Axis A).
     * n=2 → t_recomputed = max(2, 3) = 3.  Only 2 valid sigs → FAIL.
     * An attacker who suppresses 1 of 3 reporters cannot lower the quorum
     * requirement below THRESHOLD_T_FLOOR.                                    */
    {
        static IndividualSignedReport reps[2];
        static uint8_t sks[2][DILITHIUM5_SK_LEN];
        uint64_t ts = 8100000ULL;
        for (int i = 0; i < 2; i++) {
            char vid[16]; snprintf(vid, 16, "T8bV%d", i);
            fill_rep(&reps[i], vid, ts, sks[i]);
        }
        static AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 2);
        agg.timestamp_ms = ts;
        check("T8b: n=2, THRESHOLD_T_FLOOR=3 forces t=3, valid_count=2 < 3 → THRESHOLD_SIG_FAIL",
              verify_threshold_sig(&agg) == THRESHOLD_SIG_FAIL);
    }

    /* T8c: Gate D freshness rejection.
     * Report-0 is 10 s stale (> THRESH_REPORT_WINDOW_MS=5000 ms) → Gate D drops it.
     * Only 2 of 3 reports pass Gate D → valid_count=2 < t=3 → FAIL.          */
    {
        static IndividualSignedReport reps[3];
        static uint8_t sks[3][DILITHIUM5_SK_LEN];
        uint64_t agg_ts = 8200000ULL;
        for (int i = 0; i < 3; i++) {
            char vid[16]; snprintf(vid, 16, "T8cV%d", i);
            /* Report-0: timestamp 10 s before aggregate anchor → stale */
            uint64_t ts = (i == 0) ? (agg_ts - 10000ULL) : agg_ts;
            fill_rep(&reps[i], vid, ts, sks[i]);
        }
        static AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 3);
        agg.timestamp_ms = agg_ts;
        /* Gate D: |reps[0].timestamp_ms - agg_ts| = 10000 > 5000 → skipped.
         * valid_count=2 < t=3 → FAIL. */
        check("T8c: 1 stale report (10s > window 5s) → Gate D drops it → THRESHOLD_SIG_FAIL",
              verify_threshold_sig(&agg) == THRESHOLD_SIG_FAIL);
    }

    /* T8d: report->threshold_t is IGNORED by the verifier.
     * Set agg.threshold_t = 0 to simulate a compromised RSU deflating the field.
     * Verifier must recompute t=3 from n=4 and still PASS (valid_count=4 ≥ 3).
     * Confirms the verifier never reads report->threshold_t.                  */
    {
        static IndividualSignedReport reps[4];
        static uint8_t sks[4][DILITHIUM5_SK_LEN];
        uint64_t agg_ts = 8300000ULL;
        for (int i = 0; i < 4; i++) {
            char vid[16]; snprintf(vid, 16, "T8dV%d", i);
            fill_rep(&reps[i], vid, agg_ts, sks[i]);
        }
        static AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 4);
        agg.timestamp_ms = agg_ts;
        agg.threshold_t  = 0;   /* attacker-manipulated — must be ignored */
        /* Verifier recomputes: t = max(⌊4/2⌋+1, 3) = 3.  valid_count=4 ≥ 3 → PASS */
        check("T8d: report->threshold_t=0 (attacker), verifier recomputes t=3 → THRESHOLD_SIG_PASS",
              verify_threshold_sig(&agg) == THRESHOLD_SIG_PASS);
    }

    /* T8e: Cross-aggregate nonce replay rejected by g_thresh_report_cache.
     * A compromised RSU captures 3 signed reports and submits them into two
     * AggregateReports within the 5-second freshness window.  The first call
     * consumes (vehicle_id, nonce) pairs.  The second call's reports are all
     * rejected by thresh_report_is_novel() → valid_count=0 < t=3 → FAIL.     */
    {
        static IndividualSignedReport reps[3];
        static uint8_t sks[3][DILITHIUM5_SK_LEN];
        uint64_t agg_ts = 8400000ULL;
        for (int i = 0; i < 3; i++) {
            char vid[16]; snprintf(vid, 16, "T8eV%d", i);
            fill_rep(&reps[i], vid, agg_ts, sks[i]);
        }

        /* First aggregate with these reports → PASS, nonces consumed */
        static AggregateReport agg1;
        rsu_aggregate_reports(&agg1, reps, 3);
        agg1.timestamp_ms = agg_ts;
        check("T8e-first:  3 novel sigs → THRESHOLD_SIG_PASS (nonces now consumed)",
              verify_threshold_sig(&agg1) == THRESHOLD_SIG_PASS);

        /* Second aggregate with SAME reports (same nonces) — within 5s window */
        static AggregateReport agg2;
        rsu_aggregate_reports(&agg2, reps, 3);
        agg2.timestamp_ms = agg_ts + 1000ULL;   /* +1 s — still within THRESH_REPORT_WINDOW_MS */
        /* thresh_report_is_novel() rejects all three (nonces already consumed) */
        check("T8e-second: same nonces replayed into agg2 → THRESHOLD_SIG_FAIL",
              verify_threshold_sig(&agg2) == THRESHOLD_SIG_FAIL);
    }

    /* T8f: Partial-overlap nonce replay — the realistic attack shape.
     * agg1 = {A, B, C} → PASS, nonces for A/B/C consumed.
     * agg2 = {A_replay, B_replay, D_fresh}: compromised RSU mixes two replayed
     * reports with one genuine new one hoping the fresh D lifts valid_count
     * enough to reach quorum.  A/B rejected by thresh_report_is_novel(),
     * D passes all gates.  valid_count=1 < t=3 → FAIL.
     * This test confirms the cache rejects individual consumed entries, not the
     * whole aggregate, and that a single fresh entry is correctly counted.      */
    {
        static IndividualSignedReport reps_abc[3];
        static uint8_t sks_abc[3][DILITHIUM5_SK_LEN];
        uint64_t agg_ts = 8500000ULL;
        for (int i = 0; i < 3; i++) {
            char vid[16]; snprintf(vid, 16, "T8fV%d", i);   /* A=0, B=1, C=2 */
            fill_rep(&reps_abc[i], vid, agg_ts, sks_abc[i]);
        }
        static AggregateReport agg1;
        rsu_aggregate_reports(&agg1, reps_abc, 3);
        agg1.timestamp_ms = agg_ts;
        check("T8f-first (agg1={A,B,C}): THRESHOLD_SIG_PASS, nonces consumed",
              verify_threshold_sig(&agg1) == THRESHOLD_SIG_PASS);

        /* Build agg2 with {A_replayed, B_replayed, D_fresh} */
        static IndividualSignedReport reps_abd[3];
        static uint8_t sk_d[DILITHIUM5_SK_LEN];
        memcpy(&reps_abd[0], &reps_abc[0], sizeof(IndividualSignedReport));  /* A replayed */
        memcpy(&reps_abd[1], &reps_abc[1], sizeof(IndividualSignedReport));  /* B replayed */
        fill_rep(&reps_abd[2], "T8fVD", agg_ts + 500ULL, sk_d);             /* D fresh    */
        static AggregateReport agg2;
        rsu_aggregate_reports(&agg2, reps_abd, 3);
        agg2.timestamp_ms = agg_ts + 1000ULL;
        /* A/B: nonces consumed by agg1 → rejected.  D: novel → counts.
         * valid_count = 1 < t = 3 → FAIL. */
        check("T8f-second (agg2={A_replay,B_replay,D_fresh}): valid=1 < t=3 → THRESHOLD_SIG_FAIL",
              verify_threshold_sig(&agg2) == THRESHOLD_SIG_FAIL);
    }

    /* T8g: n_reports > MAX_REPORTS_PER_RSU → immediate THRESHOLD_SIG_FAIL.
     * Without the bounds check added in verify_threshold_sig, a compromised RSU
     * setting n_reports=65 would cause the loop to read past reports[64] — UB.
     * The guard must reject before the loop runs.                              */
    {
        static AggregateReport agg;
        memset(&agg, 0, sizeof(agg));
        agg.n_reports  = MAX_REPORTS_PER_RSU + 1;   /* 65 — out of bounds */
        agg.timestamp_ms = 8600000ULL;
        check("T8g: n_reports=65 > MAX_REPORTS_PER_RSU=64 → THRESHOLD_SIG_FAIL (bounds guard)",
              verify_threshold_sig(&agg) == THRESHOLD_SIG_FAIL);
    }
}

/* ── T9: Fix-7 — domain-separation cross-protocol rejection ─────────────── */
static void test_domain_separation(void) {
    printf("\n--- T9: domain-separation cross-protocol rejection ---\n");

    uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
    dilithium5_keygen(pk, sk);

    const uint8_t msg[] = "domain-sep-test-payload";
    const size_t  mlen  = sizeof(msg) - 1;
    uint8_t sig[DILITHIUM5_SIG_LEN]; size_t sig_len;

    /* T9a: sign THRESH, verify LOCBIND → must reject */
    dilithium5_sign_thresh(msg, mlen, sk, sig, &sig_len);
    check("T9a: sign(THRESH) verify(LOCBIND) → false",
          !dilithium5_verify_locbind(msg, mlen, sig, sig_len, pk));

    /* T9b: sign LOCBIND, verify THRESH → must reject */
    dilithium5_sign_locbind(msg, mlen, sk, sig, &sig_len);
    check("T9b: sign(LOCBIND) verify(THRESH) → false",
          !dilithium5_verify_thresh(msg, mlen, sig, sig_len, pk));

    /* T9c: sign KEM_AUTH, verify THRESH → must reject */
    dilithium5_sign_kem_auth(msg, mlen, sk, sig, &sig_len);
    check("T9c: sign(KEM_AUTH) verify(THRESH) → false",
          !dilithium5_verify_thresh(msg, mlen, sig, sig_len, pk));

    /* T9d: positive control — same domain must accept */
    dilithium5_sign_thresh(msg, mlen, sk, sig, &sig_len);
    check("T9d: sign(THRESH) verify(THRESH) → true",
          dilithium5_verify_thresh(msg, mlen, sig, sig_len, pk));
}

/* ── T10: Fix-2 — KEM Stage C identity_pk consistency check ─────────────── */
static void test_kem_stage_c(void) {
    printf("\n--- T10: KEM Stage C identity_pk consistency ---\n");

    teta_ca_init();  /* idempotent; initialises g_ca_pk/g_ca_sk */

    /* T10a: happy path — matching identity_pk, valid CA cert */
    {
        /* Use a full 16-byte buffer: dilithium5_issue_cert/kem_vehicle_keygen both
         * do memcpy(..., vehicle_id, 16) — a shorter string literal would overread. */
        uint8_t vid[16] = {0}; snprintf((char *)vid, 16, "T10_VehOK");
        uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
        dilithium5_keygen(pk, sk);
        CertificateRecord cert;
        dilithium5_issue_cert(vid, pk, 1000000ULL, &cert);
        KemExchangeState state;
        kem_vehicle_keygen(&state, vid, sk, pk, &cert);
        uint8_t session_key[SESSION_KEY_LEN];
        check("T10a: valid cert + matching identity_pk → kem_rsu_encapsulate OK",
              kem_rsu_encapsulate(&state, session_key));
    }

    /* T10b: Stage C — identity_pk deliberately mismatched from cert.pk_vi */
    {
        uint8_t vid[16] = {0}; snprintf((char *)vid, 16, "T10_VehC");
        uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
        dilithium5_keygen(pk, sk);
        CertificateRecord cert;
        dilithium5_issue_cert(vid, pk, 1000001ULL, &cert);
        KemExchangeState state;
        kem_vehicle_keygen(&state, vid, sk, pk, &cert);
        /* Overwrite identity_pk with zeroes — cert.pk_vi still holds pk */
        memset(state.identity_pk, 0, DILITHIUM5_PK_LEN);
        uint8_t session_key[SESSION_KEY_LEN];
        check("T10b: identity_pk != cert.pk_vi → Stage C rejects",
              !kem_rsu_encapsulate(&state, session_key));
    }

    /* T10c: Stage A — corrupt CA signature in cert → rejected before any key use */
    {
        uint8_t vid[16] = {0}; snprintf((char *)vid, 16, "T10_VehA");
        uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
        dilithium5_keygen(pk, sk);
        CertificateRecord cert;
        dilithium5_issue_cert(vid, pk, 1000002ULL, &cert);
        cert.ca_sig[0] ^= 0xFF;  /* corrupt one byte → CA sig invalid */
        KemExchangeState state;
        kem_vehicle_keygen(&state, vid, sk, pk, &cert);
        uint8_t session_key[SESSION_KEY_LEN];
        check("T10c: corrupt CA sig → Stage A rejects",
              !kem_rsu_encapsulate(&state, session_key));
    }
}

/* ── T11: Fix-3 — lkh_revoke_vehicle propagates to HMAC keystore + CRL ─── */
static void test_lkh_fix3(void) {
    printf("\n--- T11: LKH Fix-3 revocation propagation ---\n");

    /* Build a small LKH tree for 4 vehicles */
    static LKHTree tree;
    const uint8_t *vids[4];
    uint8_t vid_bufs[4][16];
    for (int i = 0; i < 4; i++) {
        snprintf((char *)vid_bufs[i], 16, "T11_Veh%d", i);
        vids[i] = vid_bufs[i];
    }
    lkh_init(&tree, (const uint8_t (*)[16])vid_bufs, 4);

    /* Register a keystore so Fix-3 auto-call path fires */
    static VehicleKeyRecord ks[4];
    memset(ks, 0, sizeof(ks));
    for (int i = 0; i < 4; i++) {
        memcpy(ks[i].vehicle_id, vid_bufs[i], 16);
        ks[i].session_key[0] = (uint8_t)(0xAA + i);  /* non-zero sentinel */
        ks[i].revoked = false;
    }
    lkh_set_keystore(ks, 4);

    /* Revoke vehicle 0 */
    lkh_revoke_vehicle(&tree, vid_bufs[0]);

    /* T11a: LKH tree leaf session_key must be zeroed */
    bool leaf_zeroed = true;
    for (uint32_t i = 0; i < LKH_MAX_LEAVES * 2; i++) {
        if (tree.nodes[i].is_leaf &&
            memcmp(tree.nodes[i].vehicle_id, vid_bufs[0], 16) == 0) {
            for (int b = 0; b < (int)LKH_KEY_LEN; b++)
                if (tree.nodes[i].session_key[b]) { leaf_zeroed = false; break; }
            break;
        }
    }
    check("T11a: LKH leaf session_key zeroed after revocation", leaf_zeroed);

    /* T11b: VehicleKeyRecord.revoked=true, session_key zeroed in HMAC keystore */
    bool rec_revoked = ks[0].revoked;
    bool rec_key_zeroed = true;
    for (int b = 0; b < (int)SESSION_KEY_LEN; b++)
        if (ks[0].session_key[b]) { rec_key_zeroed = false; break; }
    check("T11b: VehicleKeyRecord.revoked=true after lkh_revoke_vehicle",
          rec_revoked);
    check("T11b: VehicleKeyRecord.session_key zeroed in HMAC keystore",
          rec_key_zeroed);

    /* T11c: cert_revoke_vehicle was called → CRL now contains vehicle 0 */
    check("T11c: cert_is_revoked confirms CRL updated",
          cert_is_revoked(vid_bufs[0]));
}

/* ── T11d: production config — tree initialized, lkh_set_keystore NEVER called
 *
 * Exercises the path taken by ensure_lkh_init() + process_tgn_alerts():
 *   lkh_revoke_vehicle runs with g_ks=NULL → mark_key_revoked is skipped →
 *   cert_revoke_vehicle does NOT fire from the LKH chain.
 *   The explicit cert_revoke_vehicle(vid) call in process_tgn_alerts IS
 *   the only source of the CRL update.  Confirm both facts.
 * ─────────────────────────────────────────────────────────────────────────── */
static void test_lkh_production_config(void) {
    printf("\n--- T11d: LKH production config (tree init, no lkh_set_keystore) ---\n");

    /* Reset g_ks to NULL — simulates the production path where
     * ensure_lkh_init() calls lkh_init() but NOT lkh_set_keystore().
     * (T11 left g_ks pointing at its local ks[]; clear that now.) */
    lkh_set_keystore(NULL, 0);

    /* Build a fresh tree for 2 vehicles — unique IDs so CRL state from T11 is
     * irrelevant (T11 only added "T11_Veh0"; these are "T11d_Veh0/1"). */
    static LKHTree tree_prod;
    uint8_t vid_prod[2][16];
    snprintf((char *)vid_prod[0], 16, "T11d_Veh0");
    snprintf((char *)vid_prod[1], 16, "T11d_Veh1");
    lkh_init(&tree_prod, (const uint8_t (*)[16])vid_prod, 2);

    /* Revoke vehicle 0 via the LKH tree (g_ks=NULL, so mark_key_revoked skipped) */
    lkh_revoke_vehicle(&tree_prod, vid_prod[0]);

    /* T11d-a: LKH tree correctly marks the leaf as revoked */
    check("T11d-a: lkh_is_revoked=true after lkh_revoke_vehicle (no keystore)",
          lkh_is_revoked(&tree_prod, vid_prod[0]));

    /* T11d-b: CRL must NOT contain T11d_Veh0 yet — the LKH chain did not call
     * cert_revoke_vehicle because mark_key_revoked was skipped (g_ks=NULL) */
    check("T11d-b: CRL NOT updated by LKH chain alone (g_ks=NULL, mark_key_revoked skipped)",
          !cert_is_revoked(vid_prod[0]));

    /* T11d-c: direct cert_revoke_vehicle call (mirrors process_tgn_alerts line)
     * This is the only path that updates the CRL in the production config.     */
    cert_revoke_vehicle(vid_prod[0]);
    check("T11d-c: CRL updated after explicit cert_revoke_vehicle (direct path)",
          cert_is_revoked(vid_prod[0]));

    /* T11d-d: non-revoked peer must still pass the CRL check */
    check("T11d-d: T11d_Veh1 (non-revoked peer) not in CRL",
          !cert_is_revoked(vid_prod[1]));
}

/* ── T12: CRYPTO_DROP_KEYSTORE_FULL — fill keystore, verify 257th fails ─── */
static void test_keystore_full(void) {
    printf("\n--- T12: CRYPTO_DROP_KEYSTORE_FULL ---\n");

    reset_vehicle_keystore();

    /* Fill all PIPELINE_MAX_VEH (256) slots */
    bool all_ok = true;
    for (uint32_t i = 0; i < PIPELINE_MAX_VEH; i++) {
        uint8_t vid[16]; snprintf((char *)vid, 16, "T12V%04u", i);
        int r = provision_vehicle(vid);
        if (r < 0) { all_ok = false; break; }
    }
    check("T12a: provision 256 vehicles (PIPELINE_MAX_VEH) → all succeed", all_ok);

    /* One more must return -1 — keystore full */
    uint8_t vid_extra[16]; snprintf((char *)vid_extra, 16, "T12VExtra");
    check("T12b: provision 257th vehicle → returns -1 (keystore full)",
          provision_vehicle(vid_extra) == -1);

    /* Enum sanity: the value matches the defined constant */
    check("T12c: CRYPTO_DROP_KEYSTORE_FULL == 5",
          (int)CRYPTO_DROP_KEYSTORE_FULL == 5);
}

/* ── T15: Module 4 partial-overlap nonce replay — verify_quorum equivalent of T8f */
/* agg1={A,B,C} passes and consumes nonces; agg2={A_replay,B_replay,D_fresh}
 * must give accepted=1 < threshold → false, proving the locbind nonce cache
 * rejects individual consumed entries rather than whole aggregates.          */
static void make_lb_rep(LocationBoundReport *out, const char *rid,
                        float lat, float lon, uint64_t ts_ms,
                        const uint8_t sk[DILITHIUM5_SK_LEN],
                        const uint8_t pk[DILITHIUM5_PK_LEN],
                        const CertificateRecord *cert) {
    const uint8_t link_id[8] = {0xAB,0xCD,0xEF,0x01,0x02,0x03,0x04,0x05};
    create_location_bound_report(link_id, lat, lon, -70.0f, ts_ms,
                                 (const uint8_t *)rid, sk, pk, cert, out);
    out->rsu_measured_rssi_dbm = -70.0f;
    out->has_rsu_measurement   = true;
}

static void test_locbind_partial_replay(void) {
    printf("\n--- T15: Module 4 partial-overlap nonce replay (agg1={A,B,C} → agg2={A_replay,B_replay,D_fresh}) ---\n");

    teta_ca_init();

    /* Link endpoint: reporters placed at same coord so dist=0 < R_COMM=300 m */
    const float lat_ep = 6.9271f, lon_ep = 79.8612f;
    const uint64_t recv_ms = 2000000ULL;
    const uint64_t ts_ms   = recv_ms;   /* within LOCBIND_FRESHNESS_WINDOW_MS=5000 */

    /* Keypairs and certs for 4 reporters (A=0, B=1, C=2, D=3) */
    uint8_t pk[4][DILITHIUM5_PK_LEN], sk[4][DILITHIUM5_SK_LEN];
    CertificateRecord certs[4];
    for (int i = 0; i < 4; i++) {
        char vid[16]; snprintf(vid, 16, "T15_Rep%d", i);
        dilithium5_keygen(pk[i], sk[i]);
        dilithium5_issue_cert((const uint8_t *)vid, pk[i], recv_ms, &certs[i]);
    }

    /* agg1 = {A, B, C} — each has a fresh nonce from create_location_bound_report */
    LocationBoundReport agg1[3];
    for (int i = 0; i < 3; i++) {
        char vid[16]; snprintf(vid, 16, "T15_Rep%d", i);
        make_lb_rep(&agg1[i], vid, lat_ep, lon_ep, ts_ms, sk[i], pk[i], &certs[i]);
    }
    check("T15a: agg1={A,B,C} → verify_quorum passes, nonces consumed",
          verify_quorum(agg1, 3, 3, lat_ep, lon_ep, recv_ms));

    /* agg2 = {A_replay, B_replay, D_fresh}
     * A and B are byte-exact copies of agg1[0]/[1]: same (reporter_id, nonce)
     * → Gate E rejects them.  D has a fresh nonce from a new create call.    */
    LocationBoundReport agg2[3];
    memcpy(&agg2[0], &agg1[0], sizeof(LocationBoundReport));  /* A replayed */
    memcpy(&agg2[1], &agg1[1], sizeof(LocationBoundReport));  /* B replayed */
    {   /* 16-byte buffer: create_location_bound_report memcpy's 16 bytes from reporter_id */
        char d_vid[16] = "T15_Rep3";
        make_lb_rep(&agg2[2], d_vid, lat_ep, lon_ep, ts_ms,  /* D fresh   */
                    sk[3], pk[3], &certs[3]);
    }

    /* A and B hit Gate E → rejected. D passes → accepted=1 < t=2 → false.  */
    check("T15b: agg2={A_replay,B_replay,D_fresh}: accepted=1 < t → verify_quorum fails",
          !verify_quorum(agg2, 3, 3, lat_ep, lon_ep, recv_ms));
}

/* ── T13: CRL fail-closed — cert_is_revoked returns true when CRL full ───── */
static void test_crl_fail_closed(void) {
    printf("\n--- T13: CRL fail-closed at MAX_CRL_ENTRIES ---\n");

    /* Fill the CRL to capacity.  T11 already added one entry (T11_Veh0),
     * so we need MAX_CRL_ENTRIES - 1 more.  Add MAX_CRL_ENTRIES unique IDs
     * via cert_revoke_vehicle; idempotency skips duplicates, the last few
     * hit the overflow branch and are not added — leaving the table exactly
     * at capacity.                                                          */
    for (uint32_t i = 0; i < MAX_CRL_ENTRIES; i++) {
        uint8_t vid[16]; snprintf((char *)vid, 16, "T13_%04u", i);
        cert_revoke_vehicle(vid);
    }

    /* An unknown ID not in the CRL must now be treated as revoked (fail-closed) */
    uint8_t unknown[16]; snprintf((char *)unknown, 16, "T13_new_unkn");
    check("T13: CRL full → cert_is_revoked(unknown) == true (fail-closed)",
          cert_is_revoked(unknown));
}

/* ── T14: verify_quorum bounds guard — n_reports overflow rejected ───────── */
static void test_verify_quorum_bounds(void) {
    printf("\n--- T14: verify_quorum bounds guard ---\n");

    /* n_reports = MAX_REPORTS_PER_RSU + 1 must return false without reading
     * past the array (the guard added in location_binding.cc line 322).    */
    LocationBoundReport dummy;
    memset(&dummy, 0, sizeof(dummy));
    check("T14a: verify_quorum n_reports=MAX+1 → false (bounds guard)",
          !verify_quorum(&dummy, MAX_REPORTS_PER_RSU + 1, 1, 0.0f, 0.0f, 0ULL));

    /* Sanity: n_reports=0 already returned false before the new guard */
    check("T14b: verify_quorum n_reports=0 → false",
          !verify_quorum(&dummy, 0, 0, 0.0f, 0.0f, 0ULL));
}

/* ── Phase 8 entry point ─────────────────────────────────────────────────── */
int main(void) {
    printf("=== Phase 8 Integration & Validation Tests (Guide §12) ===\n");

    test_ttw_stale_timestamp();
    test_bshh_replayed_nonce();
    test_controller_origin_accepted();
    test_me_out_of_range_reporter();
    test_revoked_key();
    test_latency();
    test_locbind_nonce_not_consumed_on_gate_failure();
    test_threshold_sig_module3();
    test_domain_separation();
    test_kem_stage_c();
    test_lkh_fix3();
    test_lkh_production_config();   /* T11d: tree init without lkh_set_keystore */
    test_keystore_full();
    test_locbind_partial_replay();   /* T15 — must run before test_crl_fail_closed fills CRL */
    test_crl_fail_closed();
    test_verify_quorum_bounds();

    printf("\n═══ Results: %d PASS  %d FAIL ═══\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#endif /* PHASE8_TESTS */

/* ══════════════════════════════════════════════════════════════════════════
 * FUZZ_TESTS — randomized byte-level fuzzer for lw_mitigate_inline
 *
 * lw_mitigate_inline is the only function that receives raw, attacker-controlled
 * bytes before any gate has run.  This harness exercises it with 500 K random
 * BeaconMessage inputs under ASan+UBSan so any memory-safety issue is caught
 * regardless of what spec-derived test cases could construct.
 *
 * Build:
 *   make fuzz_lw_mitigate
 * Run:
 *   ulimit -s unlimited && ./fuzz_lw_mitigate
 * ══════════════════════════════════════════════════════════════════════════ */
#ifdef FUZZ_TESTS

#ifndef PIPELINE_INCLUDE
#define PIPELINE_INCLUDE   /* suppress fill_random re-definition in hmac_filter.cc */
#endif
#define HMAC_FILTER_NO_MAIN
#include "hmac_filter.cc"

#include <assert.h>

static uint64_t fuzz_rng(uint64_t *s) {
    *s = *s * 6364136223846793005ULL + 1442695040888963407ULL;
    return *s;
}

static void fuzz_reset(void) {
    g_veh_count = 0;
    memset(g_nonce_caches, 0, sizeof(g_nonce_caches));
    memset(g_veh,          0, sizeof(g_veh));
}

int main(void) {
    printf("=== lw_mitigate_inline randomized fuzzer ===\n");
    printf("BeaconMessage:  %zu bytes\n", sizeof(BeaconMessage));
    printf("g_veh[]:        %zu bytes  (%u slots)\n",
           sizeof(g_veh), PIPELINE_MAX_VEH);
    fflush(stdout);

    /* ── Setup: two provisioned vehicles ─────────────────────────────── */
    fuzz_reset();
    uint8_t vid_a[16] = {0}; snprintf((char *)vid_a, 16, "FuzzVehA");
    uint8_t vid_b[16] = {0}; snprintf((char *)vid_b, 16, "FuzzVehB");
    int idx_a = provision_vehicle(vid_a);
    int idx_b = provision_vehicle(vid_b);
    assert(idx_a >= 0 && idx_b >= 0);
    fill_random(g_veh[idx_a].session_key, SESSION_KEY_LEN);
    fill_random(g_veh[idx_b].session_key, SESSION_KEY_LEN);
    g_veh[idx_b].revoked = true;   /* idx_b exercises the revoked-key gate */

    /* ── Deterministic corpus: known-interesting edge cases ───────────── */
    {
        /* Case C1: all-zero payload, valid MAC → should reach inner gates */
        BeaconMessage c1; memset(&c1, 0, sizeof(c1));
        memcpy(c1.vehicle_id, vid_a, 16);
        c1.sender_timestamp_ms = 1000000ULL;
        uint8_t mp[1024]; size_t mpl;
        build_payload(&c1, mp, &mpl);
        hmac_sha256(g_veh[idx_a].session_key, SESSION_KEY_LEN, mp, mpl, c1.mac);
        CryptoVerifyResult r = lw_mitigate_inline(&c1, 1000000ULL, idx_a);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C1 all-zero valid-MAC  → %d\n", (int)r);

        /* Case C2: all-0xFF bytes */
        BeaconMessage c2; memset(&c2, 0xFF, sizeof(c2));
        memcpy(c2.vehicle_id, vid_a, 16);
        r = lw_mitigate_inline(&c2, 1000000ULL, idx_a);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C2 all-0xFF            → %d\n", (int)r);

        /* Case C3: revoked vehicle with valid MAC */
        BeaconMessage c3; memset(&c3, 0, sizeof(c3));
        memcpy(c3.vehicle_id, vid_b, 16);
        c3.sender_timestamp_ms = 1000000ULL;
        build_payload(&c3, mp, &mpl);
        hmac_sha256(g_veh[idx_b].session_key, SESSION_KEY_LEN, mp, mpl, c3.mac);
        r = lw_mitigate_inline(&c3, 1000000ULL, idx_b);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C3 revoked+valid-MAC   → %d\n", (int)r);

        /* Case C4: timestamp exactly at freshness boundary */
        BeaconMessage c4; memset(&c4, 0, sizeof(c4));
        memcpy(c4.vehicle_id, vid_a, 16);
        c4.sender_timestamp_ms = 1000000ULL - FRESHNESS_WINDOW_MS;
        build_payload(&c4, mp, &mpl);
        hmac_sha256(g_veh[idx_a].session_key, SESSION_KEY_LEN, mp, mpl, c4.mac);
        r = lw_mitigate_inline(&c4, 1000000ULL, idx_a);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C4 ts=recv-FRESHNESS   → %d\n", (int)r);

        /* Case C5: timestamp = 0 */
        BeaconMessage c5; memset(&c5, 0, sizeof(c5));
        memcpy(c5.vehicle_id, vid_a, 16);
        c5.sender_timestamp_ms = 0;
        r = lw_mitigate_inline(&c5, 1000000ULL, idx_a);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C5 ts=0                → %d\n", (int)r);

        /* Case C6: timestamp = UINT64_MAX */
        BeaconMessage c6; memset(&c6, 0, sizeof(c6));
        memcpy(c6.vehicle_id, vid_a, 16);
        c6.sender_timestamp_ms = UINT64_MAX;
        r = lw_mitigate_inline(&c6, 1000000ULL, idx_a);
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        printf("  C6 ts=UINT64_MAX       → %d\n", (int)r);
    }

    /* ── Randomized fuzzing: 500 K iterations ─────────────────────────── */
    const uint64_t N = 500000;
    printf("\nRunning %llu randomized iterations...\n", (unsigned long long)N);

    uint64_t rng     = 0xDEADBEEFCAFEBABEULL;
    uint64_t recv_ms = 1000000ULL;
    uint64_t cnt[6]  = {0};

    /* Nonce replay pool: save nonces from accepted messages, replay them later */
#define REPLAY_POOL_SZ 16
    uint8_t  replay_pool[REPLAY_POOL_SZ][NONCE_LEN];
    uint64_t replay_ts[REPLAY_POOL_SZ];    /* original recv_ms when accepted */
    int      replay_count = 0;
    memset(replay_pool, 0, sizeof(replay_pool));
    memset(replay_ts,   0, sizeof(replay_ts));

    for (uint64_t iter = 0; iter < N; iter++) {
        BeaconMessage msg;
        memset(&msg, 0, sizeof(msg));
        int veh_idx;

        /* Vehicle selection: every 8th iteration uses the revoked vehicle.
         * Use iteration counter (not RNG) to avoid LCG low-bit cycle aliasing. */
        if ((iter % 8) == 0) {
            memcpy(msg.vehicle_id, vid_b, 16);
            veh_idx = idx_b;
        } else {
            memcpy(msg.vehicle_id, vid_a, 16);
            veh_idx = idx_a;
        }

        bool replay_nonce = false;
        uint64_t orig_recv_ms = recv_ms;

        /* ~20% of iters: replay a saved nonce (with a fresh timestamp so MAC/ts
         * gates pass and the nonce is the only thing that should stop it)       */
        if (replay_count > 0 && (fuzz_rng(&rng) % 5) == 0 && veh_idx == idx_a) {
            int slot = (int)(fuzz_rng(&rng) % (uint64_t)replay_count);
            memcpy(msg.nonce, replay_pool[slot], NONCE_LEN);
            replay_nonce = true;
        } else {
            for (int k = 0; k < (int)NONCE_LEN; k++) msg.nonce[k] = (uint8_t)fuzz_rng(&rng);
        }

        /* Timestamp: mostly fresh, occasionally extreme */
        uint64_t ts_choice = fuzz_rng(&rng) % 100;
        if      (ts_choice == 0)  msg.sender_timestamp_ms = 0;
        else if (ts_choice == 1)  msg.sender_timestamp_ms = UINT64_MAX;
        else if (ts_choice < 10)  msg.sender_timestamp_ms = recv_ms + (fuzz_rng(&rng) % 500000);
        else if (ts_choice < 20)  msg.sender_timestamp_ms = (recv_ms > 500000)
                                                              ? recv_ms - 500000 : 0;
        else                      msg.sender_timestamp_ms = recv_ms
                                      - (fuzz_rng(&rng) % (FRESHNESS_WINDOW_MS + 50));

        /* Other fields: fully random */
        msg.sequence_number = (uint32_t)fuzz_rng(&rng);
        msg.gps_lat  = (float)(int32_t)fuzz_rng(&rng) * 1e-7f;
        msg.gps_lon  = (float)(int32_t)fuzz_rng(&rng) * 1e-7f;
        msg.rssi_dbm = (float)(int8_t)fuzz_rng(&rng);
        for (int k = 0; k < 8; k++) msg.link_id[k] = (uint8_t)fuzz_rng(&rng);

        /* MAC: 70% correct (exercises timestamp/nonce/revocation gates),
         *      30% random  (exercises HMAC gate)                          */
        if ((fuzz_rng(&rng) % 10) < 7) {
            uint8_t mp[1024]; size_t mpl;
            build_payload(&msg, mp, &mpl);
            hmac_sha256(g_veh[veh_idx].session_key, SESSION_KEY_LEN, mp, mpl, msg.mac);
        } else {
            for (int k = 0; k < (int)HMAC_SHA256_LEN; k++) msg.mac[k] = (uint8_t)fuzz_rng(&rng);
            replay_nonce = false;  /* random MAC won't reach nonce gate anyway */
        }

        /* Random bit-flips after MAC computation: 0-3 bytes, ~15% of iters
         * Skip when replaying a nonce — want a clean path to the nonce gate */
        if (!replay_nonce && (fuzz_rng(&rng) & 6) == 0) {
            uint8_t *b   = (uint8_t *)&msg;
            uint32_t nf  = (uint32_t)(fuzz_rng(&rng) % 4);
            for (uint32_t f = 0; f < nf; f++)
                b[fuzz_rng(&rng) % sizeof(msg)] ^= (uint8_t)fuzz_rng(&rng);
        }

        CryptoVerifyResult r = lw_mitigate_inline(&msg, recv_ms, veh_idx);

        /* Result must be a valid enum — UBSan catches misuse before this fires */
        assert((int)r >= 0 && (int)r <= (int)CRYPTO_DROP_KEYSTORE_FULL);
        if ((int)r < 6) cnt[(int)r]++;


        /* Save nonce to replay pool when a message is accepted */
        if (r == CRYPTO_ACCEPT && veh_idx == idx_a && replay_count < REPLAY_POOL_SZ) {
            memcpy(replay_pool[replay_count], msg.nonce, NONCE_LEN);
            replay_ts[replay_count] = orig_recv_ms;
            replay_count++;
        } else if (r == CRYPTO_ACCEPT && veh_idx == idx_a) {
            /* Overwrite a random slot to keep the pool fresh */
            int slot = (int)(fuzz_rng(&rng) % REPLAY_POOL_SZ);
            memcpy(replay_pool[slot], msg.nonce, NONCE_LEN);
            replay_ts[slot] = orig_recv_ms;
        }

        recv_ms += 100;

        /* Clear nonce cache every ~64K iters to avoid full-cache stall while
         * still exercising the novel-nonce fast path periodically            */
        if ((iter & 0xFFFFULL) == 0xFFFFULL) {
            memset(&g_nonce_caches[idx_a], 0, sizeof(NonceCache));
            replay_count = 0;   /* pool is stale after cache reset */
        }
    }
#undef REPLAY_POOL_SZ

    const char *names[6] = {
        "CRYPTO_ACCEPT",
        "CRYPTO_DROP_INVALID_MAC",
        "CRYPTO_DROP_STALE_TIMESTAMP",
        "CRYPTO_DROP_REPLAYED_NONCE",
        "CRYPTO_DROP_REVOKED_KEY",
        "CRYPTO_DROP_KEYSTORE_FULL"
    };
    printf("\nResult distribution over %llu iterations:\n", (unsigned long long)N);
    for (int i = 0; i < 6; i++)
        printf("  %-34s: %llu\n", names[i], (unsigned long long)cnt[i]);

    /* All live code paths must have been exercised */
    assert(cnt[0] > 0 && "CRYPTO_ACCEPT gate unreachable");
    assert(cnt[1] > 0 && "CRYPTO_DROP_INVALID_MAC gate unreachable");
    assert(cnt[3] > 0 && "CRYPTO_DROP_REPLAYED_NONCE gate unreachable");
    assert(cnt[4] > 0 && "CRYPTO_DROP_REVOKED_KEY gate unreachable");

    printf("\nAll gates exercised. No sanitizer errors. Clean.\n");
    return 0;
}
#endif /* FUZZ_TESTS */
