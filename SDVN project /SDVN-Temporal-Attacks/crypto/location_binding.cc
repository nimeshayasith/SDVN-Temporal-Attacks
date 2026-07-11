/*
 * location_binding.cc — Location-Binding Signatures  (Module 4, Section 6)
 *
 * Defends against ME (Multipath Echo) false witness attack.
 * Binds every topology observation to reporter GPS position and RSSI so that
 * out-of-range reporters are detected even if they hold valid Dilithium5 keys.
 *
 * Equations implemented:
 *   Eq. 3.29  m'_{Vk} = e_ij || pos_{Vk} || RSSI_{Vk←Vi} || τ_s || nonce
 *   Eq. 3.30  σ_{Vk}  = Sign(SK_{Vk}, m'_{Vk})
 *   Eq. 3.31  Accept_{Vk}(e_ij):  (i) crypto  (ii) spatial  (iii) signal
 *   Eq. 3.32  Accept(e_ij): |{Vk : Accept_{Vk}=1}| ≥ t, t >= floor(n/2)+1
 *
 * Key function signatures (exactly as per Section 6):
 *   void create_location_bound_report(...)
 *   bool verify_single_witness(const LocationBoundReport*, float lat, float lon)
 *   bool verify_quorum(const LocationBoundReport*, uint32_t n, uint32_t t, float lat, float lon)
 *   float haversine_distance_m(float lat1, float lon1, float lat2, float lon2)
 *
 * Build:
 *   g++ -std=c++17 -O2 location_binding.cc -lssl -lcrypto -lm -o location_binding
 *
 * Input:  pem_event_log.csv
 * Output: location_binding_result.csv
 */

#include "teta_guard_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#ifdef HAVE_OPENSSL
#  include <openssl/hmac.h>
#  include <openssl/rand.h>
#  include <openssl/sha.h>
#endif

#ifdef HAVE_LIBOQS
#  include <oqs/oqs.h>
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Issue-3 fix: per-reporter (reporter_id, nonce) novelty cache.
 *
 * A compromised RSU could collect valid LocationBoundReports from multiple
 * honest vehicles and replay them against different aggregates within the
 * same LOCBIND_FRESHNESS_WINDOW_MS window.  Even with the timestamp gate
 * (Gate D below), replays within the window pass timestamp checks.
 * Solution: module-static circular cache of (reporter_id, nonce) pairs;
 * a pair is consumed on first acceptance and rejected on any subsequent call.
 *
 * Size: LOCBIND_NONCE_CACHE_SIZE=4096
 *   Same math that drove THRESH_REPORT_CACHE_SIZE from 1024→4096 (Issue-6):
 *     max reporters per link:  64
 *     freshness window:      5000 ms  (LOCBIND_FRESHNESS_WINDOW_MS)
 *     beacon interval:        100 ms
 *     peak fill per window:   64 × (5000/100) = 64 × 50 = 3200 entries
 *   4096 provides 28% margin above peak.  Prior value of 1024 covered only
 *   64 × 16 = 1024 = 1.6 s of the 5 s freshness window — leaving a 3.4 s
 *   eviction gap in which a replayed (reporter_id, nonce) could re-enter the
 *   cache; the same vulnerability Issue-6 closed for the threshold cache.
 * ══════════════════════════════════════════════════════════════════════════ */

#define LOCBIND_NONCE_CACHE_SIZE 4096u

typedef struct {
    uint8_t reporter_id[16];
    uint8_t nonce[NONCE_LEN];
} LocBindNonceKey;

static LocBindNonceKey g_locbind_nonce_cache[LOCBIND_NONCE_CACHE_SIZE];
static uint32_t        g_locbind_nonce_head  = 0;
static uint32_t        g_locbind_nonce_count = 0;

static bool locbind_nonce_is_novel(const uint8_t reporter_id[16],
                                    const uint8_t nonce[NONCE_LEN]) {
    for (uint32_t i = 0; i < g_locbind_nonce_count; i++) {
        uint32_t idx = (g_locbind_nonce_head + LOCBIND_NONCE_CACHE_SIZE - 1 - i)
                       % LOCBIND_NONCE_CACHE_SIZE;
        if (memcmp(g_locbind_nonce_cache[idx].reporter_id, reporter_id, 16) == 0 &&
            memcmp(g_locbind_nonce_cache[idx].nonce,       nonce,       NONCE_LEN) == 0)
            return false;
    }
    return true;
}

static void locbind_nonce_consume(const uint8_t reporter_id[16],
                                   const uint8_t nonce[NONCE_LEN]) {
    memcpy(g_locbind_nonce_cache[g_locbind_nonce_head].reporter_id, reporter_id, 16);
    memcpy(g_locbind_nonce_cache[g_locbind_nonce_head].nonce,       nonce,       NONCE_LEN);
    g_locbind_nonce_head = (g_locbind_nonce_head + 1) % LOCBIND_NONCE_CACHE_SIZE;
    if (g_locbind_nonce_count < LOCBIND_NONCE_CACHE_SIZE) g_locbind_nonce_count++;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Nonce generation (for fresh nonce per location-bound report)
 * ══════════════════════════════════════════════════════════════════════════ */

#if !defined(PIPELINE_INCLUDE) && !defined(FILL_RANDOM_DEFINED)
#define FILL_RANDOM_DEFINED
static void fill_random(uint8_t *buf, size_t len) {
#ifdef HAVE_OPENSSL
    RAND_bytes(buf, (int)len);
#else
    static uint64_t s = 0x1234ABCDEF987654ULL;
    for (size_t i = 0; i < len; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
#endif
}
#endif /* PIPELINE_INCLUDE && FILL_RANDOM_DEFINED */

/* ══════════════════════════════════════════════════════════════════════════
 * Dilithium5 sign / verify — delegated to dilithium.cc (Section 3.3)
 *
 * The private dilithium5_sign_lb / dilithium5_verify_lb duplicates have
 * been removed. All signing and verification now uses the shared
 * dilithium5_sign() / dilithium5_verify() declared in teta_guard_types.h
 * and defined in dilithium.cc.
 * ══════════════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════════════════
 * haversine_distance_m  (Section 6.4 helper)
 *   Returns distance in metres between two GPS coordinates.
 * ══════════════════════════════════════════════════════════════════════════ */

float haversine_distance_m(float lat1, float lon1, float lat2, float lon2) {
    const float R = 6371000.0f;   /* Earth radius in metres */
    float dlat = (lat2 - lat1) * (float)M_PI / 180.0f;
    float dlon = (lon2 - lon1) * (float)M_PI / 180.0f;
    float a = sinf(dlat / 2.0f) * sinf(dlat / 2.0f)
            + cosf(lat1 * (float)M_PI / 180.0f)
            * cosf(lat2 * (float)M_PI / 180.0f)
            * sinf(dlon / 2.0f) * sinf(dlon / 2.0f);
    return R * 2.0f * atan2f(sqrtf(a), sqrtf(1.0f - a));
}

/* ══════════════════════════════════════════════════════════════════════════
 * create_location_bound_report()  (Section 6.3, Eqs. 3.27 + 3.28)
 *
 * Vehicle Vk constructs and signs a location-bound topology observation.
 * ══════════════════════════════════════════════════════════════════════════ */

void create_location_bound_report(const uint8_t       link_id[8],
                                   float                reporter_lat,
                                   float                reporter_lon,
                                   float                rssi_from_vi,
                                   uint64_t             sender_ts_ms,
                                   const uint8_t        reporter_id[16],
                                   const uint8_t        sk_vk[DILITHIUM5_SK_LEN],
                                   const uint8_t        pk_vk[DILITHIUM5_PK_LEN],
                                   const CertificateRecord *cert,
                                   LocationBoundReport *out_report) {
    memset(out_report, 0, sizeof(*out_report));

    /* Build m'_{Vk}  (Eq. 3.29) */
    LocationBindingPayload *p = &out_report->payload;
    memcpy(p->link_id,    link_id,     8);
    p->reporter_lat        = reporter_lat;
    p->reporter_lon        = reporter_lon;
    p->reporter_alt        = 0.0f;
    p->rssi_from_vi_dbm    = rssi_from_vi;
    p->sender_timestamp_ms = sender_ts_ms;
    memcpy(p->reporter_id, reporter_id, 16);
    fill_random(p->nonce, NONCE_LEN);   /* fresh nonce per report */

    /* σ_{Vk} = Sign(SK_{Vk}, m'_{Vk})  (Eq. 3.30)
     * Fix-7: domain-separated to prevent cross-protocol replay with threshold
     * and KEM-auth sigs that share the same Dilithium5 keypair.               */
    size_t sig_len;
    dilithium5_sign_locbind((const uint8_t *)p, sizeof(LocationBindingPayload),
                             sk_vk, out_report->signature, &sig_len);

    memcpy(out_report->pub_key, pk_vk, DILITHIUM5_PK_LEN);

    /* Issue-1 fix: embed CA cert so verify_single_witness can run the three-gate
     * cert check without a separate CA lookup.                                  */
    if (cert) out_report->cert = *cert;
}

/* ══════════════════════════════════════════════════════════════════════════
 * verify_single_witness()  (Section 6.4, Eq. 3.31)
 *
 * Accept_{Vk}(e_ij) = 1 iff all hold, evaluated in this order:
 *   Gate A: CA cert valid, CRL clear                  (identity trust root)
 *   Gate B: cert.pk_vi == pub_key                     (key consistency)
 *   Gate D: |recv_time_ms − sender_timestamp_ms| ≤ LOCBIND_FRESHNESS_WINDOW_MS
 *           (Issue-3 freshness)
 *   Gate E: (reporter_id, nonce) not yet consumed — READ-ONLY check here;
 *           consume happens at the very end after all gates pass
 *   Gate C: Dilithium5 sig verifies                   (crypto authenticity)
 *   (ii)  d(pos_{Vk}, e_ij) ≤ r_comm                 (spatial plausibility)
 *  (iii)  RSSI_{Vk←Vi} ≥ RSSI_min + Friis margin     (signal plausibility)
 *
 * Ordering rationale: D and E are cheap integer comparisons and cache lookups;
 * running them before Gate C (Dilithium5 verify, ~1.6 ms) rejects stale and
 * replayed reports without paying the crypto cost.  T4 in the PHASE8 harness
 * asserts crypto fires before spatial checks within the set of gates that do
 * execute; that remains true (C before (ii)/(iii)) regardless of D/E placement.
 *
 * recv_time_ms: RSU wall-clock time in ms when this report was received.
 * link_endpoint_lat/lon: GPS coords of link endpoint Vi (midpoint used).
 * ══════════════════════════════════════════════════════════════════════════ */

bool verify_single_witness(const LocationBoundReport *report,
                            float    link_endpoint_lat,
                            float    link_endpoint_lon,
                            uint64_t recv_time_ms) {
    /* Gate A + Gate B — same three-gate pattern as KEM (Fix-1/2) and threshold_sig */
    if (!dilithium5_verify_cert(&report->cert)) return false;
    if (memcmp(report->cert.pk_vi, report->pub_key, DILITHIUM5_PK_LEN) != 0)
        return false;

    /* Gate D — Issue-3 fix: timestamp freshness.
     * Signed sender_timestamp_ms must be within LOCBIND_FRESHNESS_WINDOW_MS of
     * the RSU's receive time.  Guards against a compromised RSU replaying old
     * reports that were valid when originally signed.                           */
    {
        uint64_t ts = report->payload.sender_timestamp_ms;
        int64_t  delta = (int64_t)recv_time_ms - (int64_t)ts;
        if (delta < 0) delta = -delta;
        if ((uint64_t)delta > LOCBIND_FRESHNESS_WINDOW_MS) return false;
    }

    /* Gate E — Issue-3 fix: per-reporter nonce novelty (cross-aggregate replay).
     *
     * locbind_nonce_is_novel() is a READ-ONLY cache lookup — it does not consume
     * the slot.  Consumption happens at the very bottom of this function, after
     * Gate C (crypto), Gate (ii) (spatial), and Gate (iii+iv) (RSSI/Friis) all
     * pass.  This ordering is intentional:
     *
     *   - An attacker cannot DoS a victim's nonce slot by submitting a report
     *     with a valid (reporter_id, nonce) but an invalid sig: Gate C fires
     *     before the consume, so the slot is never written on crypto failure.
     *   - A report that fails spatial or RSSI also does not consume its nonce.
     *   - Only a report that passes every gate gets its nonce marked consumed.
     *
     * Do NOT move locbind_nonce_consume() earlier in this function.            */
    if (!locbind_nonce_is_novel(report->payload.reporter_id, report->payload.nonce))
        return false;

    /* (i) Cryptographic authenticity — Fix-7: domain-separated locbind verify */
    bool crypto_ok = dilithium5_verify_locbind(
        (const uint8_t *)&report->payload,
        sizeof(LocationBindingPayload),
        report->signature, DILITHIUM5_SIG_LEN,
        report->pub_key);
    if (!crypto_ok) return false;

    /* (ii) Spatial plausibility: d(pos_{Vk}, link endpoint) ≤ r_comm */
    float dist = haversine_distance_m(
        report->payload.reporter_lat, report->payload.reporter_lon,
        link_endpoint_lat, link_endpoint_lon);
    if (dist > R_COMM_METERS) return false;

    /* (iii) Signal plausibility: RSSI ≥ RSSI_min.
     * Fix-5 repair: use rsu_measured_rssi_dbm (RSU's own physical-layer
     * measurement, set by the RSU after reception) rather than
     * payload.rssi_from_vi_dbm (vehicle self-reported — attacker-controlled).
     * rsu_measured_rssi_dbm sits outside the signed payload so the vehicle
     * can never forge it.
     *
     * has_rsu_measurement is checked explicitly (not 0.0f sentinel) because
     * 0.0f is a physically plausible RSSI value and must not be confused with
     * "field not populated."  In a live-radio build has_rsu_measurement must
     * always be true; falling back to the signed payload value is test-only.  */
    float rssi_to_check;
    if (report->has_rsu_measurement) {
        rssi_to_check = report->rsu_measured_rssi_dbm;
    } else {
        /* Stub/unit-test path: RSU did not supply its own measurement.
         * WARNING: this path is insecure — the vehicle controls rssi_from_vi_dbm.
         * Never reachable in a live-radio build.                              */
        fprintf(stderr, "[LocBind] WARNING: has_rsu_measurement=false for reporter %.*s"
                " — falling back to self-reported RSSI (test path only)\n",
                (int)sizeof(report->payload.reporter_id), report->payload.reporter_id);
        rssi_to_check = report->payload.rssi_from_vi_dbm;
    }
    if (rssi_to_check < RSSI_MIN_DBM) return false;

    /* (iv) Fix-5: RSSI-vs-distance Friis plausibility check.
     * If RSSI is weaker than expected by more than RSSI_DISTANCE_MARGIN_DB at
     * the claimed GPS distance, the reporter cannot physically be where it says.
     * expected_rssi at distance d: RSSI_min + 20·log10(R_comm / d) [free-space].
     * We skip the check when d < 0.5 m to avoid division-by-zero noise.       */
    if (dist > 0.5f) {
        float expected_rssi = RSSI_MIN_DBM
                              + 20.0f * log10f(R_COMM_METERS / dist);
        if (rssi_to_check < expected_rssi - RSSI_DISTANCE_MARGIN_DB)
            return false;
    }

    /* All gates passed — consume the (reporter_id, nonce) pair now so it
     * cannot be replayed into a subsequent aggregate call.                   */
    locbind_nonce_consume(report->payload.reporter_id, report->payload.nonce);

    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * verify_quorum()  (Section 6.5, Eq. 3.32)
 *
 * Accept(e_ij) = 1  iff  |{Vk : Accept_Vk(e_ij) = 1}| ≥ t
 *
 * recv_time_ms is passed through to verify_single_witness (Gate D freshness).
 *
 * The strict-majority constraint t ≥ ⌊n/2⌋+1 is enforced internally.
 * If the caller passes a weaker value it is silently raised to the minimum.
 * This prevents a colluding minority smaller than ⌊n/2⌋+1 from passing the
 * quorum gate even if the caller accidentally uses a lower threshold.
 * ══════════════════════════════════════════════════════════════════════════ */

bool verify_quorum(const LocationBoundReport *reports,
                    uint32_t n_reports,
                    uint32_t threshold_t,
                    float    link_ep_lat,
                    float    link_ep_lon,
                    uint64_t recv_time_ms) {
    if (n_reports == 0) return false;
    /* Defensive bounds guard (parallel to T8g fix in verify_threshold_sig):
     * a caller passing n_reports > MAX_REPORTS_PER_RSU would walk off the
     * end of any stack-allocated reports[] — UB.  Reject immediately.        */
    if (n_reports > MAX_REPORTS_PER_RSU) return false;

    /* Enforce strict majority: t must be at least ⌊n/2⌋+1 regardless of what
     * the caller supplied.  This is the anti-collusion requirement from Eq. 3.32. */
    uint32_t min_t = (n_reports / 2) + 1;
    if (threshold_t < min_t) threshold_t = min_t;

    uint32_t accepted = 0;
    for (uint32_t k = 0; k < n_reports; k++) {
        if (verify_single_witness(&reports[k], link_ep_lat, link_ep_lon, recv_time_ms))
            accepted++;
    }
    return accepted >= threshold_t;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Simulated GPS position for a node (for testing without real SUMO data)
 * Place vehicles around a circle of radius ~200 m
 * ══════════════════════════════════════════════════════════════════════════ */

static void sim_gps(int node_id, float *lat, float *lon) {
    /* Base: near Colombo, Sri Lanka (roughly, for realism) */
    const float base_lat =  6.9271f;
    const float base_lon = 79.8612f;
    float angle = node_id * 0.7f;
    /* ~200 m radius: 200 m ≈ 0.0018° latitude, 0.0020° longitude at 7°N */
    *lat = base_lat + 0.0018f * cosf(angle);
    *lon = base_lon + 0.0020f * sinf(angle);
}

/* ══════════════════════════════════════════════════════════════════════════
 * CSV processor
 * ══════════════════════════════════════════════════════════════════════════ */

#if !defined(PIPELINE_INCLUDE) && !defined(PEM_HELPERS_DEFINED)
#define PEM_HELPERS_DEFINED
typedef struct { double t; int phys; int link_src; int link_dst; int attack; } PemRow;

static int load_pem(const char *file, PemRow *rows, int max) {
    FILE *f = fopen(file, "r"); if (!f) return 0;
    char line[512]; int n = 0;
    fgets(line, sizeof(line), f);
    while (n < max && fgets(line, sizeof(line), f)) {
        PemRow *r = &rows[n]; char et[64];
        sscanf(line, "%lf,%63[^,],%d,", &r->t, et, &r->phys);
        char *p = line; int c = 0;
        while (p && c < 5) { p = strchr(p, ','); if (p) { p++; c++; } }
        if (p) r->link_src = atoi(p);
        p = line; c = 0;
        while (p && c < 6) { p = strchr(p, ','); if (p) { p++; c++; } }
        if (p) r->link_dst = atoi(p);
        p = line; c = 0;
        while (p && c < 11) { p = strchr(p, ','); if (p) { p++; c++; } }
        if (p) r->attack = atoi(p);
        n++;
    }
    fclose(f); return n;
}
#endif /* PIPELINE_INCLUDE && PEM_HELPERS_DEFINED */

/* ── main ─────────────────────────────────────────────────────────────────── */

#ifndef LOCATION_BINDING_NO_MAIN
int main(int argc, char *argv[]) {
    const char *input  = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *output = (argc > 2) ? argv[2] : "location_binding_result.csv";

    printf("=== location_binding.cc — Location-Binding Signatures (Eqs. 3.29-3.32) ===\n");
    printf("[LBS] R_COMM=%.0f m   RSSI_min=%.1f dBm\n", R_COMM_METERS, RSSI_MIN_DBM);

    /* Haversine self-test: same point → 0 m */
    {
        float d = haversine_distance_m(6.9271f, 79.8612f, 6.9271f, 79.8612f);
        printf("[LBS] haversine_distance_m self-test (same point): %.2f m (expected 0)\n", d);
        /* ~300 m: 0.0027° lat difference at equator ≈ 300 m */
        float d2 = haversine_distance_m(6.9271f, 79.8612f, 6.9298f, 79.8612f);
        printf("[LBS] haversine ~300m test: %.1f m\n", d2);
    }

    /* Pre-generate Dilithium5 keypairs + CA certs for V0..V9 */
    teta_ca_init();
    static uint8_t pks[10][DILITHIUM5_PK_LEN];
    static uint8_t sks[10][DILITHIUM5_SK_LEN];
    static CertificateRecord certs[10];
    for (int i = 0; i < 10; i++) {
        dilithium5_keygen(pks[i], sks[i]);
        uint8_t vid[16]; memset(vid, 0, 16);
        snprintf((char *)vid, 16, "V%d", i);
        dilithium5_issue_cert(vid, pks[i], (uint64_t)i * 1000, &certs[i]);
    }

    /* Self-test: in-range reporter → accepted.
     * Simulate RSU filling has_rsu_measurement to exercise the secure path.  */
    {
        float lat3, lon3; sim_gps(3, &lat3, &lon3);
        float lat_ep, lon_ep; sim_gps(1, &lat_ep, &lon_ep);
        uint8_t link_id[8] = {0,1,0,2,0,0,0,0};
        uint8_t rid[16] = "V3";
        LocationBoundReport rep;
        create_location_bound_report(link_id, lat3, lon3, -60.0f,
                                      10000, rid, sks[3], pks[3], &certs[3], &rep);
        /* RSU fills its own measurement (not from the vehicle's signed payload) */
        rep.rsu_measured_rssi_dbm = -60.0f;
        rep.has_rsu_measurement   = true;
        bool ok = verify_single_witness(&rep, lat_ep, lon_ep, 10000ULL);
        printf("[LBS] In-range reporter test:   %s\n", ok ? "ACCEPTED" : "REJECTED");
    }

    /* Self-test: out-of-range reporter (10 km away) → rejected */
    {
        float lat_ep, lon_ep; sim_gps(1, &lat_ep, &lon_ep);
        uint8_t link_id[8] = {0,1,0,2,0,0,0,0};
        uint8_t rid[16] = "V7";
        LocationBoundReport rep;
        create_location_bound_report(link_id,
                                      lat_ep + 0.1f,  /* ~11 km away */
                                      lon_ep + 0.1f,
                                      -100.0f,
                                      10000, rid, sks[7], pks[7], &certs[7], &rep);
        bool ok = verify_single_witness(&rep, lat_ep, lon_ep, 10000ULL);
        printf("[LBS] Out-of-range reporter:    %s (expected REJECTED)\n",
               ok ? "ACCEPTED" : "REJECTED");
    }

    /* Self-test: quorum (3 valid of 5, t=3) → accepted */
    {
        float lat_ep, lon_ep; sim_gps(1, &lat_ep, &lon_ep);
        LocationBoundReport reps[5];
        uint8_t link_id[8] = {0,1,0,2,0,0,0,0};
        for (int k = 0; k < 5; k++) {
            uint8_t rid[16]; snprintf((char*)rid, 16, "V%d", k);
            float lat, lon;
            if (k < 3) { sim_gps(k, &lat, &lon); }                /* in range */
            else       { lat = lat_ep + 0.1f; lon = lon_ep; }     /* out of range */
            float rssi = (k < 3) ? -60.0f : -100.0f;
            create_location_bound_report(link_id, lat, lon, rssi,
                                          10000, rid, sks[k], pks[k], &certs[k], &reps[k]);
        }
        bool ok = verify_quorum(reps, 5, 3, lat_ep, lon_ep, 10000ULL);
        printf("[LBS] Quorum test (3/5 valid, t=3): %s\n", ok ? "ACCEPTED" : "REJECTED");
    }

    /* CSV processing */
    static PemRow rows[4096];
    int n = load_pem(input, rows, 4096);
    if (n == 0) { printf("[LBS] No events (run routing.cc first)\n"); return 0; }

    FILE *out = fopen(output, "w");
    fprintf(out, "sim_time_s,vehicle_id,link,dist_to_ep_m,crypto_ok,spatial_ok,"
                 "signal_ok,lbs_accepted,attack_label\n");
    int accepted = 0, rejected = 0;

    for (int i = 0; i < n; i++) {
        int vid = rows[i].phys % 10;
        float lat, lon; sim_gps(vid, &lat, &lon);
        float lat_ep, lon_ep; sim_gps(rows[i].link_src % 10, &lat_ep, &lon_ep);

        /* ME attackers placed 10+ km away */
        if (rows[i].attack) { lat = lat_ep + 0.1f; lon = lon_ep + 0.1f; }

        float rssi = rows[i].attack ? -100.0f : -62.0f;
        uint8_t link_id[8] = {0};
        link_id[0] = (uint8_t)rows[i].link_src;
        link_id[4] = (uint8_t)rows[i].link_dst;
        uint8_t rid[16]; snprintf((char*)rid, 16, "V%d", rows[i].phys);

        LocationBoundReport rep;
        create_location_bound_report(link_id, lat, lon, rssi,
                                      (uint64_t)(rows[i].t * 1000),
                                      rid, sks[vid], pks[vid], &certs[vid], &rep);

        /* Per-condition results — Fix-7: domain-separated locbind verify */
        bool crypto_ok = dilithium5_verify_locbind(
            (const uint8_t *)&rep.payload, sizeof(LocationBindingPayload),
            rep.signature, DILITHIUM5_SIG_LEN, rep.pub_key);

        float dist = haversine_distance_m(lat, lon, lat_ep, lon_ep);
        bool spatial_ok = (dist <= R_COMM_METERS);
        bool signal_ok  = (rssi >= RSSI_MIN_DBM);
        bool lbs_ok     = crypto_ok && spatial_ok && signal_ok;

        fprintf(out, "%.3f,V%d,%d-%d,%.1f,%d,%d,%d,%d,%d\n",
                rows[i].t, rows[i].phys,
                rows[i].link_src, rows[i].link_dst, dist,
                crypto_ok, spatial_ok, signal_ok, lbs_ok, rows[i].attack);

        if (lbs_ok) accepted++; else rejected++;
    }
    fclose(out);

    printf("[LBS] accepted=%d  rejected=%d\n", accepted, rejected);
    printf("[LBS] Wrote %s\n", output);
    return 0;
}
#endif /* LOCATION_BINDING_NO_MAIN */
