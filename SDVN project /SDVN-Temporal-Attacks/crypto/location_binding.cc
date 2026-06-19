/*
 * location_binding.cc — Location-Binding Signatures  (Module 4, Section 6)
 *
 * Defends against ME (Multipath Echo) false witness attack.
 * Binds every topology observation to reporter GPS position and RSSI so that
 * out-of-range reporters are detected even if they hold valid Dilithium2 keys.
 *
 * Equations implemented:
 *   Eq. 3.25  m'_{Vk} = e_ij || pos_{Vk} || RSSI_{Vk←Vi} || τ_s || nonce
 *   Eq. 3.26  σ_{Vk}  = Sign(SK_{Vk}, m'_{Vk})
 *   Eq. 3.27  Accept_{Vk}(e_ij):  (i) crypto  (ii) spatial  (iii) signal
 *   Eq. 3.28  Accept(e_ij): |{Vk : Accept_{Vk}=1}| ≥ t
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
 * Nonce generation (for fresh nonce per location-bound report)
 * ══════════════════════════════════════════════════════════════════════════ */

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

/* ══════════════════════════════════════════════════════════════════════════
 * Dilithium2 sign / verify — delegated to dilithium.cc (Section 3.3)
 *
 * The private dilithium2_sign_lb / dilithium2_verify_lb duplicates have
 * been removed. All signing and verification now uses the shared
 * dilithium2_sign() / dilithium2_verify() declared in teta_guard_types.h
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
 * create_location_bound_report()  (Section 6.3, Eqs. 3.25 + 3.26)
 *
 * Vehicle Vk constructs and signs a location-bound topology observation.
 * ══════════════════════════════════════════════════════════════════════════ */

void create_location_bound_report(const uint8_t   link_id[8],
                                   float            reporter_lat,
                                   float            reporter_lon,
                                   float            rssi_from_vi,
                                   uint64_t         sender_ts_ms,
                                   const uint8_t    reporter_id[16],
                                   const uint8_t    sk_vk[DILITHIUM2_SK_LEN],
                                   const uint8_t    pk_vk[DILITHIUM2_PK_LEN],
                                   LocationBoundReport *out_report) {
    memset(out_report, 0, sizeof(*out_report));

    /* Build m'_{Vk}  (Eq. 3.25) */
    LocationBindingPayload *p = &out_report->payload;
    memcpy(p->link_id,    link_id,     8);
    p->reporter_lat        = reporter_lat;
    p->reporter_lon        = reporter_lon;
    p->reporter_alt        = 0.0f;
    p->rssi_from_vi_dbm    = rssi_from_vi;
    p->sender_timestamp_ms = sender_ts_ms;
    memcpy(p->reporter_id, reporter_id, 16);
    fill_random(p->nonce, NONCE_LEN);   /* fresh nonce per report */

    /* σ_{Vk} = Sign(SK_{Vk}, m'_{Vk})  (Eq. 3.26) */
    size_t sig_len;
    dilithium2_sign((const uint8_t *)p, sizeof(LocationBindingPayload),
                    sk_vk, out_report->signature, &sig_len);

    memcpy(out_report->pub_key, pk_vk, DILITHIUM2_PK_LEN);
}

/* ══════════════════════════════════════════════════════════════════════════
 * verify_single_witness()  (Section 6.4, Eq. 3.27)
 *
 * Accept_{Vk}(e_ij) = 1 iff all three hold:
 *   (i)   Verify(σ_{Vk}, PK_{Vk}) = 1           crypto authenticity
 *   (ii)  d(pos_{Vk}, e_ij) ≤ r_comm             spatial plausibility
 *  (iii)  RSSI_{Vk←Vi} ≥ RSSI_min(r_comm)        signal plausibility
 *
 * link_endpoint_lat/lon: GPS coords of link endpoint Vi (midpoint used).
 * ══════════════════════════════════════════════════════════════════════════ */

bool verify_single_witness(const LocationBoundReport *report,
                            float link_endpoint_lat,
                            float link_endpoint_lon) {
    /* (i) Cryptographic authenticity — Section 3.3 shared module */
    bool crypto_ok = dilithium2_verify(
        (const uint8_t *)&report->payload,
        sizeof(LocationBindingPayload),
        report->signature, DILITHIUM2_SIG_LEN,
        report->pub_key);
    if (!crypto_ok) return false;

    /* (ii) Spatial plausibility: d(pos_{Vk}, link endpoint) ≤ r_comm */
    float dist = haversine_distance_m(
        report->payload.reporter_lat, report->payload.reporter_lon,
        link_endpoint_lat, link_endpoint_lon);
    if (dist > R_COMM_METERS) return false;

    /* (iii) Signal plausibility: RSSI ≥ RSSI_min */
    if (report->payload.rssi_from_vi_dbm < RSSI_MIN_DBM) return false;

    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * verify_quorum()  (Section 6.5, Eq. 3.28)
 *
 * Accept(e_ij) = 1 iff |{Vk : Accept_{Vk}(e_ij)=1}| ≥ t
 * ══════════════════════════════════════════════════════════════════════════ */

bool verify_quorum(const LocationBoundReport *reports,
                    uint32_t n_reports,
                    uint32_t threshold_t,
                    float    link_ep_lat,
                    float    link_ep_lon) {
    uint32_t accepted = 0;
    for (uint32_t k = 0; k < n_reports; k++) {
        if (verify_single_witness(&reports[k], link_ep_lat, link_ep_lon))
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

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *input  = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *output = (argc > 2) ? argv[2] : "location_binding_result.csv";

    printf("=== location_binding.cc — Location-Binding Signatures (Eqs. 3.25-3.28) ===\n");
    printf("[LBS] R_COMM=%.0f m   RSSI_min=%.1f dBm\n", R_COMM_METERS, RSSI_MIN_DBM);

    /* Haversine self-test: same point → 0 m */
    {
        float d = haversine_distance_m(6.9271f, 79.8612f, 6.9271f, 79.8612f);
        printf("[LBS] haversine_distance_m self-test (same point): %.2f m (expected 0)\n", d);
        /* ~300 m: 0.0027° lat difference at equator ≈ 300 m */
        float d2 = haversine_distance_m(6.9271f, 79.8612f, 6.9298f, 79.8612f);
        printf("[LBS] haversine ~300m test: %.1f m\n", d2);
    }

    /* Pre-generate Dilithium2 keypairs for V0..V9 */
    static uint8_t pks[10][DILITHIUM2_PK_LEN];
    static uint8_t sks[10][DILITHIUM2_SK_LEN];
    for (int i = 0; i < 10; i++) {
        fill_random(sks[i], DILITHIUM2_SK_LEN);
#ifdef HAVE_OPENSSL
        SHA256(sks[i], 32, pks[i]);
        for (size_t j = 32; j < DILITHIUM2_PK_LEN; j++)
            pks[i][j] = sks[i][(j * 7) % DILITHIUM2_SK_LEN] ^ 0xA5;
#else
        for (size_t j = 0; j < DILITHIUM2_PK_LEN; j++)
            pks[i][j] = sks[i][(j + 5) % DILITHIUM2_SK_LEN] ^ 0x3C;
#endif
    }

    /* Self-test: in-range reporter → accepted */
    {
        float lat3, lon3; sim_gps(3, &lat3, &lon3);
        float lat_ep, lon_ep; sim_gps(1, &lat_ep, &lon_ep);
        uint8_t link_id[8] = {0,1,0,2,0,0,0,0};
        uint8_t rid[16] = "V3";
        LocationBoundReport rep;
        create_location_bound_report(link_id, lat3, lon3, -60.0f,
                                      10000, rid, sks[3], pks[3], &rep);
        bool ok = verify_single_witness(&rep, lat_ep, lon_ep);
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
                                      10000, rid, sks[7], pks[7], &rep);
        bool ok = verify_single_witness(&rep, lat_ep, lon_ep);
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
                                          10000, rid, sks[k], pks[k], &reps[k]);
        }
        bool ok = verify_quorum(reps, 5, 3, lat_ep, lon_ep);
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
                                      rid, sks[vid], pks[vid], &rep);

        /* Per-condition results — Section 3.3 shared dilithium2_verify */
        bool crypto_ok = dilithium2_verify(
            (const uint8_t *)&rep.payload, sizeof(LocationBindingPayload),
            rep.signature, DILITHIUM2_SIG_LEN, rep.pub_key);

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
