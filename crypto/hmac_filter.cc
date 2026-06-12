/*
 * hmac_filter.cc — HMAC Pre-Detection Filter  (Module 2, Section 4)
 *                  Algorithm 3 — LW-MITIGATE
 *
 * Intercepts every BeaconMessage BEFORE it reaches the TGN or blockchain.
 * Implements the three checks from Eqs. 3.14, 3.15, 3.16.
 *
 * Exact lw_mitigate() signature (Section 4.4):
 *   CryptoVerifyResult lw_mitigate(
 *       const BeaconMessage *msg,
 *       uint64_t             recv_time_ms,
 *       const uint8_t       *session_key,   // K_{Vi,nk}  32 bytes
 *       bool                 key_revoked,
 *       NonceCache          *nonce_cache)
 *
 * Return values → attack blocked:
 *   CRYPTO_ACCEPT               → nothing (forward to TGN)
 *   CRYPTO_DROP_INVALID_MAC     → forged/tampered beacon
 *   CRYPTO_DROP_STALE_TIMESTAMP → TTW external vector
 *   CRYPTO_DROP_REPLAYED_NONCE  → BSHH replay
 *   CRYPTO_DROP_REVOKED_KEY     → revoked vehicle
 *
 * Build:
 *   g++ -std=c++17 -O2 hmac_filter.cc -lssl -lcrypto -o hmac_filter
 *
 * Input:  pem_event_log.csv
 * Output: hmac_filter_result.csv
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
#  include <openssl/evp.h>
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Nonce generation  (Section 4.5)
 * ══════════════════════════════════════════════════════════════════════════ */

void generate_nonce(uint8_t nonce_out[NONCE_LEN]) {
#ifdef HAVE_OPENSSL
    RAND_bytes(nonce_out, NONCE_LEN);
#else
    static uint64_t s = 0xBEEF1234CAFE5678ULL;
    for (unsigned i = 0; i < NONCE_LEN; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        nonce_out[i] = (uint8_t)(s >> 56);
    }
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * Authenticated payload construction  (Section 4.3, Eq. 3.35)
 *   m' = m || τ_s || nonce
 * ══════════════════════════════════════════════════════════════════════════ */

void build_authenticated_payload(const BeaconMessage *msg,
                                  uint8_t *m_prime,
                                  size_t  *m_prime_len) {
    /* Everything before the nonce field is the raw payload m */
    size_t payload_len = offsetof(BeaconMessage, nonce);
    memcpy(m_prime, msg, payload_len);

    /* Append τ_s as 8-byte little-endian uint64 */
    memcpy(m_prime + payload_len,
           &msg->sender_timestamp_ms,
           sizeof(uint64_t));

    /* Append nonce (16 bytes) */
    memcpy(m_prime + payload_len + 8, msg->nonce, NONCE_LEN);

    *m_prime_len = payload_len + 8 + NONCE_LEN;
}

/* ══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 helpers
 * ══════════════════════════════════════════════════════════════════════════ */

static void compute_hmac(const uint8_t *key,    size_t key_len,
                          const uint8_t *data,   size_t data_len,
                          uint8_t out[HMAC_SHA256_LEN]) {
#ifdef HAVE_OPENSSL
    unsigned mac_len = HMAC_SHA256_LEN;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &mac_len);
#else
    /* XOR-fold fallback — simulation only */
    memset(out, 0, HMAC_SHA256_LEN);
    for (size_t i = 0; i < data_len; i++)
        out[i % HMAC_SHA256_LEN] ^= data[i] ^ key[i % key_len];
#endif
}

/* Constant-time memcmp — prevents timing side-channel */
static bool ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Nonce novelty check  (Section 4.4, Eq. 3.16)
 *   Circular per-sender cache; returns true if nonce is new.
 * ══════════════════════════════════════════════════════════════════════════ */

static bool nonce_is_novel(NonceCache *cache, const uint8_t nonce[NONCE_LEN]) {
    /* Search backwards from most recent */
    for (uint32_t i = 0; i < cache->count; i++) {
        uint32_t idx = (cache->head + NONCE_CACHE_SIZE - 1 - i) % NONCE_CACHE_SIZE;
        if (memcmp(cache->nonces[idx], nonce, NONCE_LEN) == 0)
            return false;   /* Replayed */
    }
    return true;
}

static void nonce_add(NonceCache *cache, const uint8_t nonce[NONCE_LEN]) {
    memcpy(cache->nonces[cache->head], nonce, NONCE_LEN);
    cache->head = (cache->head + 1) % NONCE_CACHE_SIZE;
    if (cache->count < NONCE_CACHE_SIZE) cache->count++;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Algorithm 3 — LW-MITIGATE  (Section 4.4)
 *
 * The ONLY entry point for incoming beacons.
 * Returns CRYPTO_ACCEPT iff all three equations pass.
 * ══════════════════════════════════════════════════════════════════════════ */

CryptoVerifyResult lw_mitigate(const BeaconMessage *msg,
                                uint64_t             recv_time_ms,
                                const uint8_t       *session_key,
                                bool                 key_revoked,
                                NonceCache          *nonce_cache) {
    /* ── Revocation check (LKH) ─────────────────────────────────────────── */
    if (key_revoked)
        return CRYPTO_DROP_REVOKED_KEY;

    /* ── Step 1: Build m' = m || τ_s || nonce  (Eq. 3.35) ─────────────── */
    uint8_t m_prime[1024];
    size_t  m_prime_len;
    build_authenticated_payload(msg, m_prime, &m_prime_len);

    /* ── Step 2: Recompute HMAC-SHA256 and compare  (Eq. 3.14) ─────────── */
    uint8_t mac_computed[HMAC_SHA256_LEN];
    compute_hmac(session_key, SESSION_KEY_LEN,
                 m_prime, m_prime_len,
                 mac_computed);

    if (!ct_memcmp(mac_computed, msg->mac, HMAC_SHA256_LEN))
        return CRYPTO_DROP_INVALID_MAC;

    /* ── Step 3: Timestamp freshness  (Eq. 3.15) ────────────────────────── */
    int64_t delta = (int64_t)recv_time_ms - (int64_t)msg->sender_timestamp_ms;
    if (delta < 0) delta = -delta;
    if ((uint64_t)delta > FRESHNESS_WINDOW_MS)
        return CRYPTO_DROP_STALE_TIMESTAMP;

    /* ── Step 4: Nonce novelty  (Eq. 3.16) ──────────────────────────────── */
    if (!nonce_is_novel(nonce_cache, msg->nonce))
        return CRYPTO_DROP_REPLAYED_NONCE;

    /* Admit nonce to cache */
    nonce_add(nonce_cache, msg->nonce);

    return CRYPTO_ACCEPT;
}

/*
 * Compute and attach MAC to a BeaconMessage (vehicle side, before sending).
 * Also generates a fresh nonce.
 */
void beacon_sign(BeaconMessage *msg, const uint8_t session_key[SESSION_KEY_LEN]) {
    generate_nonce(msg->nonce);
    uint8_t m_prime[1024];
    size_t  m_prime_len;
    build_authenticated_payload(msg, m_prime, &m_prime_len);
    compute_hmac(session_key, SESSION_KEY_LEN, m_prime, m_prime_len, msg->mac);
}

/* ══════════════════════════════════════════════════════════════════════════
 * CSV processor — reads pem_event_log.csv, simulates lw_mitigate() per event
 * ══════════════════════════════════════════════════════════════════════════ */

static const char *result_str(CryptoVerifyResult r) {
    switch (r) {
        case CRYPTO_ACCEPT:               return "ACCEPTED";
        case CRYPTO_DROP_INVALID_MAC:     return "DROP_INVALID_MAC";
        case CRYPTO_DROP_STALE_TIMESTAMP: return "DROP_STALE_TIMESTAMP";
        case CRYPTO_DROP_REPLAYED_NONCE:  return "DROP_REPLAYED_NONCE";
        case CRYPTO_DROP_REVOKED_KEY:     return "DROP_REVOKED_KEY";
    }
    return "UNKNOWN";
}

typedef struct {
    double  sim_time_s;
    int     physical_sender_id;
    double  tau_s;
    int     attack_label;
} PemRow;

static int load_pem(const char *file, PemRow *rows, int max_rows) {
    FILE *f = fopen(file, "r");
    if (!f) return 0;
    char line[1024]; int n = 0;
    fgets(line, sizeof(line), f); /* skip header */
    while (n < max_rows && fgets(line, sizeof(line), f)) {
        PemRow *r = &rows[n];
        char event_type[64];
        /* sim_time_s, event_type, phys_sender, claimed, reporter, lsrc, ldst,
           link_str, tau_s, tau_r, triggered, attack_label */
        int parsed = sscanf(line, "%lf,%63[^,],%d,", &r->sim_time_s, event_type, &r->physical_sender_id);
        if (parsed < 2) continue;
        /* Find tau_s (col 8) and attack_label (col 11) */
        char *p = line; int col = 0;
        while (p && col < 8) { p = strchr(p, ','); if (p) { p++; col++; } }
        if (p) r->tau_s = atof(p);
        p = line; col = 0;
        while (p && col < 11) { p = strchr(p, ','); if (p) { p++; col++; } }
        if (p) r->attack_label = atoi(p);
        n++;
    }
    fclose(f);
    return n;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *input  = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *output = (argc > 2) ? argv[2] : "hmac_filter_result.csv";

    printf("=== hmac_filter.cc — Algorithm 3 LW-MITIGATE (Eqs. 3.14-3.16) ===\n");

    /* ── Self-tests ──────────────────────────────────────────────────────── */
    {
        uint8_t key[SESSION_KEY_LEN];
        for (int i = 0; i < (int)SESSION_KEY_LEN; i++) key[i] = (uint8_t)(i * 37);

        NonceCache cache; memset(&cache, 0, sizeof(cache));
        BeaconMessage msg;
        memset(&msg, 0, sizeof(msg));
        snprintf((char *)msg.vehicle_id, 16, "V0");
        msg.sender_timestamp_ms = 10000;
        msg.sequence_number     = 1;
        beacon_sign(&msg, key);

        /* Test 1: fresh message → ACCEPT */
        CryptoVerifyResult r = lw_mitigate(&msg, 10005, key, false, &cache);
        printf("[HMAC] Test1 fresh msg:       %s (expected ACCEPTED)\n", result_str(r));

        /* Test 2: replayed nonce → REPLAYED */
        r = lw_mitigate(&msg, 10005, key, false, &cache);
        printf("[HMAC] Test2 replayed nonce:  %s (expected DROP_REPLAYED_NONCE)\n", result_str(r));

        /* Test 3: stale timestamp (TTW) */
        BeaconMessage msg2 = msg;
        generate_nonce(msg2.nonce);
        beacon_sign(&msg2, key);
        msg2.sender_timestamp_ms = 5000;  /* far in the past */
        r = lw_mitigate(&msg2, 10000, key, false, &cache);
        printf("[HMAC] Test3 stale timestamp: %s (expected DROP_STALE_TIMESTAMP)\n", result_str(r));

        /* Test 4: bad MAC */
        BeaconMessage msg3 = msg;
        generate_nonce(msg3.nonce);
        beacon_sign(&msg3, key);
        msg3.mac[0] ^= 0xFF;
        r = lw_mitigate(&msg3, 10005, key, false, &cache);
        printf("[HMAC] Test4 invalid MAC:     %s (expected DROP_INVALID_MAC)\n", result_str(r));

        /* Test 5: revoked key */
        BeaconMessage msg4 = msg;
        generate_nonce(msg4.nonce);
        beacon_sign(&msg4, key);
        r = lw_mitigate(&msg4, 10005, key, true, &cache);
        printf("[HMAC] Test5 revoked key:     %s (expected DROP_REVOKED_KEY)\n", result_str(r));
    }

    /* ── CSV processing ─────────────────────────────────────────────────── */
    static PemRow rows[4096];
    int n = load_pem(input, rows, 4096);
    if (n == 0) {
        printf("[HMAC] No events (run routing.cc first)\n");
        return 0;
    }
    printf("[HMAC] Processing %d event(s) from %s\n", n, input);

    /* One NonceCache + simulated session key per vehicle (V0..V9) */
    static NonceCache caches[10];
    memset(caches, 0, sizeof(caches));
    uint8_t keys[10][SESSION_KEY_LEN];
    for (int i = 0; i < 10; i++)
        for (int j = 0; j < (int)SESSION_KEY_LEN; j++)
            keys[i][j] = (uint8_t)((i * 37 + j * 13) & 0xFF);

    FILE *out = fopen(output, "w");
    fprintf(out, "sim_time_s,vehicle_id,result,tau_s,recv_time_ms,attack_label\n");

    int accepted=0, drop_mac=0, drop_ts=0, drop_nonce=0;

    for (int i = 0; i < n; i++) {
        int vid = rows[i].physical_sender_id % 10;
        uint64_t recv_ms = (uint64_t)(rows[i].sim_time_s * 1000.0);

        BeaconMessage msg;
        memset(&msg, 0, sizeof(msg));
        snprintf((char *)msg.vehicle_id, 16, "V%d", rows[i].physical_sender_id);
        msg.sender_timestamp_ms = (uint64_t)(rows[i].tau_s * 1000.0);
        msg.sequence_number     = (uint32_t)i;

        /* Attack events get forged timestamps far in the past */
        if (rows[i].attack_label) {
            msg.sender_timestamp_ms = (uint64_t)((rows[i].tau_s - 10.0) * 1000.0);
        }
        beacon_sign(&msg, keys[vid]);
        /* Attack events: corrupt MAC to simulate forge */
        if (rows[i].attack_label) msg.mac[0] ^= 0xFF;

        CryptoVerifyResult r = lw_mitigate(&msg, recv_ms, keys[vid],
                                            false, &caches[vid]);

        fprintf(out, "%.3f,V%d,%s,%.3f,%llu,%d\n",
                rows[i].sim_time_s, rows[i].physical_sender_id,
                result_str(r), rows[i].tau_s,
                (unsigned long long)recv_ms, rows[i].attack_label);

        switch (r) {
            case CRYPTO_ACCEPT:               accepted++;    break;
            case CRYPTO_DROP_INVALID_MAC:     drop_mac++;    break;
            case CRYPTO_DROP_STALE_TIMESTAMP: drop_ts++;     break;
            case CRYPTO_DROP_REPLAYED_NONCE:  drop_nonce++;  break;
            default: break;
        }
    }
    fclose(out);

    printf("[HMAC] accepted=%d  drop_mac=%d  drop_ts=%d  drop_nonce=%d\n",
           accepted, drop_mac, drop_ts, drop_nonce);
    printf("[HMAC] Wrote %s\n", output);
    return 0;
}
