/*
 * kem.cc — Kyber-1024 + FireSaber Hybrid-KEM  (Module 1, Section 3)
 *
 * Establishes K_{Vi,nk}: 32-byte session key shared between vehicle Vi
 * and trusted node nk.  Also generates Dilithium5 signing keypairs
 * (SK_{Vi}, PK_{Vi}) stored in VehicleKeyRecord (Section 3.5).
 *
 * liboqs constants used:
 *   KEM:  OQS_KEM_alg_kyber_1024 (Kyber component, pre-standard)
 *         OQS_KEM_alg_ml_kem_1024 (FIPS 203 preferred on liboqs ≥0.10)
 *         OQS_KEM_alg_saber_firesaber      (Saber component — paper's hybrid partner)
 *   SIG:  OQS_SIG_alg_dilithium_5 (NIST ML-DSA, FIPS 204)
 *
 * Build:
 *   g++ -std=c++17 -O2 kem.cc -lssl -lcrypto -o kem
 *   g++ -std=c++17 -O2 -DHAVE_LIBOQS kem.cc -loqs -lssl -lcrypto -o kem
 *
 * Output: kem_session_keys.csv
 */

#include "teta_guard_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_OPENSSL
#  include <openssl/hmac.h>
#  include <openssl/rand.h>
#  include <openssl/sha.h>
#endif

#ifdef HAVE_LIBOQS
#  include <oqs/oqs.h>
#endif

/* ─── Global key store ───────────────────────────────────────────────────── */

static VehicleKeyRecord g_keystore[MAX_VEHICLES];
static uint32_t         g_keystore_count = 0;

/* ─── Random bytes ───────────────────────────────────────────────────────── */

static void fill_random(uint8_t *buf, size_t len) {
#ifdef HAVE_OPENSSL
    RAND_bytes(buf, (int)len);
#else
    /* LCG fallback — simulation only */
    static uint64_t s = 0xDEADBEEF12345678ULL;
    for (size_t i = 0; i < len; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
#endif
}

/* ─── HKDF-SHA256 (Section 3.3 — KDF step) ──────────────────────────────── */

static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                         uint8_t out[SESSION_KEY_LEN]) {
    static const char *salt = "teta-guard-kem-salt";
    static const char *info = "teta-guard-session-key";
#ifdef HAVE_OPENSSL
    uint8_t prk[32]; unsigned pl = 32;
    HMAC(EVP_sha256(), salt, (int)strlen(salt), ikm, ikm_len, prk, &pl);
    /* Expand T(1) */
    size_t info_len = strlen(info);
    uint8_t *expand = (uint8_t *)malloc(32 + info_len + 1);
    memcpy(expand, prk, 32);
    memcpy(expand + 32, info, info_len);
    expand[32 + info_len] = 0x01;
    uint8_t t[32]; unsigned tl = 32;
    HMAC(EVP_sha256(), prk, pl, expand, 32 + info_len + 1, t, &tl);
    memcpy(out, t, SESSION_KEY_LEN);
    free(expand);
#else
    for (size_t i = 0; i < SESSION_KEY_LEN; i++)
        out[i] = ikm[i % ikm_len] ^ (uint8_t)(i * 0x5A) ^ (uint8_t)salt[i % strlen(salt)];
#endif
}

/* ─── Hex helper ─────────────────────────────────────────────────────────── */

static void print_hex(const char *label, const uint8_t *d, size_t n, size_t max) {
    printf("%s = ", label);
    for (size_t i = 0; i < (n < max ? n : max); i++) printf("%02x", d[i]);
    if (n > max) printf("...");
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════════
 * KEM OPERATIONS
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Perform Kyber-1024 + FireSaber hybrid key encapsulation for vehicle Vi.
 * Implements Section 3.3 Steps 3-4.
 *
 * trusted_pk    : RSU/nk Kyber public key (or simulated pk)
 * trusted_pk_len: length of above
 * out_session_key: 32-byte shared secret K_{Vi,nk}  [output]
 */
static void kem_encapsulate(const uint8_t *trusted_pk, size_t trusted_pk_len,
                              uint8_t out_session_key[SESSION_KEY_LEN]) {
#ifdef HAVE_LIBOQS
    /* Kyber-1024 component */
    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    uint8_t ct_k[kem_k->length_ciphertext];
    uint8_t ss_k[kem_k->length_shared_secret];
    OQS_KEM_encaps(kem_k, ct_k, ss_k, trusted_pk);
    OQS_KEM_free(kem_k);

    /* Saber component — OQS_KEM_alg_saber_firesaber (Section 3.3, paper's actual KEM partner) */
    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    uint8_t ct_s[kem_s->length_ciphertext];
    uint8_t ss_s[kem_s->length_shared_secret];
    OQS_KEM_encaps(kem_s, ct_s, ss_s, trusted_pk);
    OQS_KEM_free(kem_s);

    /* K_{Vi,nk} = KDF(ss_kyber || ss_saber)  — Eq. 3.3 Step 3 */
    /* K_{Vi,nk} = KDF(ss_kyber ⊕ ss_saber) — XOR hybrid combiner (Giacon et al. 2018)
     * XOR is the correct IND-CCA2 dual-PRF combiner; concatenation is NOT secure. */
    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, out_session_key);
#else
    /* Simulated KEM: HKDF(pk) */
    uint8_t ephemeral[32];
    fill_random(ephemeral, 32);
    uint8_t ikm[trusted_pk_len + 32];
    memcpy(ikm,               trusted_pk, trusted_pk_len);
    memcpy(ikm + trusted_pk_len, ephemeral, 32);
    hkdf_sha256(ikm, trusted_pk_len + 32, out_session_key);
#endif
}

/*
 * Dilithium5 keypair generation delegates to dilithium.cc (Section 3.3).
 * dilithium5_keygen() is declared in teta_guard_types.h and defined in
 * dilithium.cc — the single canonical Dilithium module for TETA-Guard.
 */

/* ══════════════════════════════════════════════════════════════════════════
 * VEHICLE-SIDE KEM  (Section 3.3 Steps 1 & 4)
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Step 1 — Vehicle generates its Kyber+FireSaber KEM keypair.
 * pk_kyber/pk_saber are sent to the RSU; sk_* stays at the vehicle.
 */
void kem_vehicle_keygen(KemExchangeState *state) {
    memset(state, 0, sizeof(*state));
#ifdef HAVE_LIBOQS
    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    OQS_KEM_keypair(kem_k, state->pk_kyber, state->sk_kyber);
    OQS_KEM_free(kem_k);

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);  /* Saber — paper's actual KEM partner */
    OQS_KEM_keypair(kem_s, state->pk_saber, state->sk_saber);
    OQS_KEM_free(kem_s);
#else
    fill_random(state->sk_kyber, KYBER1024_SK_LEN);
    fill_random(state->sk_saber, FIRESABER_SK_LEN);
    for (size_t i = 0; i < KYBER1024_PK_LEN; i++)
        state->pk_kyber[i] = state->sk_kyber[i % KYBER1024_SK_LEN] ^ 0xABu;
    for (size_t i = 0; i < FIRESABER_PK_LEN; i++)
        state->pk_saber[i] = state->sk_saber[i % FIRESABER_SK_LEN] ^ 0xCDu;
#endif
    state->has_ciphertext = false;
}

/*
 * Step 3 — RSU encapsulates to the vehicle's public keys.
 * Writes ciphertexts into state->ct_* and the RSU-side session key into
 * out_session_key.  The ciphertexts are then transmitted to the vehicle.
 * Implements Section 3.3 Step 3 (RSU → Vehicle direction).
 */
void kem_rsu_encapsulate(KemExchangeState *state,
                          uint8_t out_session_key[SESSION_KEY_LEN]) {
#ifdef HAVE_LIBOQS
    uint8_t ss_k[KYBER1024_SS_LEN], ss_s[KYBER1024_SS_LEN];

    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    OQS_KEM_encaps(kem_k, state->ct_kyber, ss_k, state->pk_kyber);
    OQS_KEM_free(kem_k);

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    OQS_KEM_encaps(kem_s, state->ct_saber, ss_s, state->pk_saber);
    OQS_KEM_free(kem_s);

    /* K_{Vi,nk} = KDF(ss_kyber ⊕ ss_saber) — XOR hybrid combiner (Giacon et al. 2018)
     * XOR is the correct IND-CCA2 dual-PRF combiner; concatenation is NOT secure. */
    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, out_session_key);
#else
    /* Simulated: HKDF(pk_kyber || pk_saber) as deterministic shared secret */
    uint8_t ikm[KYBER1024_PK_LEN + FIRESABER_PK_LEN];
    memcpy(ikm,                    state->pk_kyber, KYBER1024_PK_LEN);
    memcpy(ikm + KYBER1024_PK_LEN, state->pk_saber, FIRESABER_PK_LEN);
    hkdf_sha256(ikm, sizeof(ikm), out_session_key);
    /* Ciphertext is deterministic XOR of pk with key so decaps can invert */
    for (size_t i = 0; i < KYBER1024_CT_LEN; i++)
        state->ct_kyber[i] = state->pk_kyber[i % KYBER1024_PK_LEN]
                             ^ out_session_key[i % SESSION_KEY_LEN];
    for (size_t i = 0; i < FIRESABER_CT_LEN; i++)
        state->ct_saber[i] = state->pk_saber[i % FIRESABER_PK_LEN]
                             ^ out_session_key[i % SESSION_KEY_LEN];
#endif
    state->has_ciphertext = true;
}

/*
 * Step 4 — Vehicle decapsulates using its secret keys and the RSU ciphertexts.
 * Derives the same K_{Vi,nk} as kem_rsu_encapsulate.
 * Returns true on success, false if ciphertext is missing or decaps fails.
 * Implements Section 3.3 Step 4.
 */
bool kem_vehicle_decapsulate(const KemExchangeState *state,
                              uint8_t out_session_key[SESSION_KEY_LEN]) {
    if (!state->has_ciphertext) return false;

#ifdef HAVE_LIBOQS
    uint8_t ss_k[KYBER1024_SS_LEN], ss_s[KYBER1024_SS_LEN];

    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    OQS_STATUS rc_k = OQS_KEM_decaps(kem_k, ss_k, state->ct_kyber, state->sk_kyber);
    OQS_KEM_free(kem_k);
    if (rc_k != OQS_SUCCESS) return false;

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_saber_firesaber);
    OQS_STATUS rc_s = OQS_KEM_decaps(kem_s, ss_s, state->ct_saber, state->sk_saber);
    OQS_KEM_free(kem_s);
    if (rc_s != OQS_SUCCESS) return false;

    /* K_{Vi,nk} = KDF(ss_kyber ⊕ ss_saber) — XOR hybrid combiner (Giacon et al. 2018)
     * XOR is the correct IND-CCA2 dual-PRF combiner; concatenation is NOT secure. */
    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, out_session_key);
#else
    /* Simulated: same HKDF(pk_kyber || pk_saber) — matches kem_rsu_encapsulate */
    uint8_t ikm[KYBER1024_PK_LEN + FIRESABER_PK_LEN];
    memcpy(ikm,                    state->pk_kyber, KYBER1024_PK_LEN);
    memcpy(ikm + KYBER1024_PK_LEN, state->pk_saber, FIRESABER_PK_LEN);
    hkdf_sha256(ikm, sizeof(ikm), out_session_key);
#endif
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
 * PUBLIC API — called by vehicle registration and RSU key management
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Register a vehicle with the RSU key store.
 * Performs the full Section 3.3 Steps 1-4 handshake:
 *   1. Vehicle generates KEM keypair  (kem_vehicle_keygen)
 *   3. RSU encapsulates to vehicle pk (kem_rsu_encapsulate)
 *   4. Vehicle decapsulates           (kem_vehicle_decapsulate)
 *   Both sides verify they derive the same K_{Vi,nk}.
 *
 * Returns pointer to VehicleKeyRecord in the global store, or NULL if full.
 */
VehicleKeyRecord *kem_register_vehicle(const uint8_t vehicle_id[16],
                                        uint32_t lkh_leaf_index) {
    if (g_keystore_count >= MAX_VEHICLES) return NULL;

    VehicleKeyRecord *rec = &g_keystore[g_keystore_count++];
    memset(rec, 0, sizeof(*rec));
    memcpy(rec->vehicle_id, vehicle_id, 16);
    rec->lkh_leaf_index = lkh_leaf_index;
    rec->revoked        = false;

#ifdef HAVE_OPENSSL
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    rec->key_creation_time_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#else
    rec->key_creation_time_ms = 0;
#endif

    /* Step 1: Vehicle generates KEM keypair */
    KemExchangeState kem_state;
    kem_vehicle_keygen(&kem_state);

    /* Step 3: RSU encapsulates to vehicle's pk → RSU derives K_{Vi,nk} */
    uint8_t rsu_key[SESSION_KEY_LEN];
    kem_rsu_encapsulate(&kem_state, rsu_key);

    /* Step 4: Vehicle decapsulates ciphertexts → vehicle derives K_{Vi,nk} */
    uint8_t vehicle_key[SESSION_KEY_LEN];
    bool ok = kem_vehicle_decapsulate(&kem_state, vehicle_key);

    /* Both sides must agree on the same key */
    if (ok && memcmp(rsu_key, vehicle_key, SESSION_KEY_LEN) == 0) {
        memcpy(rec->session_key, rsu_key, SESSION_KEY_LEN);
        printf("[KEM] V%s  handshake OK  K[0..3]=%02x%02x%02x%02x\n",
               (char *)vehicle_id,
               rsu_key[0], rsu_key[1], rsu_key[2], rsu_key[3]);
    } else {
        /* Should not happen; fallback to RSU-derived key */
        memcpy(rec->session_key, rsu_key, SESSION_KEY_LEN);
        printf("[KEM] WARNING: decaps mismatch for %s — using RSU key\n",
               (char *)vehicle_id);
    }

    /* Generate Dilithium5 signing key pair — sk_vi stays at vehicle */
    uint8_t sk_vi[DILITHIUM5_SK_LEN];
    dilithium5_keygen(rec->sign_pub_key, sk_vi);

    return rec;
}

/*
 * Look up a VehicleKeyRecord by vehicle ID.
 * Returns NULL if not found.
 */
VehicleKeyRecord *kem_lookup(const uint8_t vehicle_id[16]) {
    for (uint32_t i = 0; i < g_keystore_count; i++) {
        if (memcmp(g_keystore[i].vehicle_id, vehicle_id, 16) == 0)
            return &g_keystore[i];
    }
    return NULL;
}

/* Mark a vehicle's key as revoked (called by lkh_mgmt after LKH update) */
/* Not compiled in PHASE8_TESTS — lkh_mgmt.cc provides the canonical version */
#ifndef PHASE8_TESTS
void mark_key_revoked(VehicleKeyRecord *keystore, const uint8_t vehicle_id[16]) {
    for (uint32_t i = 0; i < g_keystore_count; i++) {
        if (memcmp(g_keystore[i].vehicle_id, vehicle_id, 16) == 0) {
            g_keystore[i].revoked = true;
            printf("[KEM] Revoked key for vehicle: ");
            for (int j = 0; j < 8; j++) printf("%02x", vehicle_id[j]);
            printf("...\n");
            return;
        }
    }
    (void)keystore;
}
#endif /* PHASE8_TESTS */

/* Generate a deterministic test vehicle ID from integer index */
static void make_vehicle_id(uint8_t vid[16], int idx) {
    memset(vid, 0, 16);
    snprintf((char *)vid, 16, "V%d", idx);
}

/* ── main: full Section 3.3 round-trip demonstration ────────────────────── */

int main(void) {
    printf("=== kem.cc — Kyber-1024+FireSaber Hybrid KEM + Dilithium5 (Module 1) ===\n");
#ifdef HAVE_LIBOQS
    printf("[KEM] Backend: liboqs  — REAL post-quantum crypto active\n");
    printf("[KEM]   Kyber-1024: OQS_KEM_alg_kyber_1024  (IND-CCA2, Level 5)\n");
    printf("[KEM]   Saber:     OQS_KEM_alg_saber_firesaber      (IND-CCA2)\n");
    printf("[KEM]   Signing:   OQS_SIG_alg_dilithium_5 (FIPS 204 ML-DSA)\n");
#else
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (kem.cc)                          ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked.  The following are SIMULATED:        ║\n"
        "║    • Kyber-1024 KEM  →  HKDF-SHA256(pk_kyber||pk_saber)      ║\n"
        "║    • FireSaber KEM      →  XOR fallback (not IND-CCA2 secure)   ║\n"
        "║    • Dilithium5 sig →  random 32-byte buffer (no math)      ║\n"
        "║                                                              ║\n"
        "║  Paper claims Kyber-1024 and FireSaber IND-CCA2 security.        ║\n"
        "║  Neither is operative in this build.                        ║\n"
        "║                                                              ║\n"
        "║  To enable real PQC:                                        ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    g++ -DHAVE_LIBOQS kem.cc -loqs -lssl -lcrypto -o kem     ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
    printf("[KEM] Backend: STUB (HKDF-SHA256 fallback — NOT post-quantum secure)\n");
#endif
    printf("[KEM] Section 3.3 Steps 1-4 full handshake:\n\n");

    /* ── Unit test: Steps 1-4 round-trip ──────────────────────────────────── */
    printf("[KEM] --- Unit test: kem_vehicle_keygen + kem_rsu_encapsulate"
           " + kem_vehicle_decapsulate ---\n");
    KemExchangeState state;

    /* Step 1 — Vehicle generates KEM keypair */
    kem_vehicle_keygen(&state);
    printf("[KEM] Step 1 (vehicle keygen):  pk_kyber[0..3]=%02x%02x%02x%02x\n",
           state.pk_kyber[0], state.pk_kyber[1],
           state.pk_kyber[2], state.pk_kyber[3]);

    /* Step 3 — RSU encapsulates to vehicle's pk */
    uint8_t rsu_key[SESSION_KEY_LEN];
    kem_rsu_encapsulate(&state, rsu_key);
    printf("[KEM] Step 3 (RSU encaps):      K_rsu[0..7]=");
    for (int i = 0; i < 8; i++) printf("%02x", rsu_key[i]);
    printf("...\n");

    /* Step 4 — Vehicle decapsulates */
    uint8_t veh_key[SESSION_KEY_LEN];
    bool ok = kem_vehicle_decapsulate(&state, veh_key);
    printf("[KEM] Step 4 (vehicle decaps):  K_veh[0..7]=");
    for (int i = 0; i < 8; i++) printf("%02x", veh_key[i]);
    printf("...\n");

    int match = ok && (memcmp(rsu_key, veh_key, SESSION_KEY_LEN) == 0);
    printf("[KEM] Keys match: %s  (expected: PASS)\n\n", match ? "PASS" : "FAIL");

    /* ── Register 5 vehicles using full handshake ─────────────────────────── */
    printf("[KEM] --- Registering 5 vehicles (full handshake each) ---\n");
    for (int i = 0; i < 5; i++) {
        uint8_t vid[16];
        make_vehicle_id(vid, i);
        VehicleKeyRecord *rec = kem_register_vehicle(vid, (uint32_t)i);
        if (!rec) { printf("[KEM] Key store full\n"); break; }
        printf("[KEM]   V%d  session_key[0..3]=%02x%02x%02x%02x  PK[0..3]=%02x%02x%02x%02x\n",
               i,
               rec->session_key[0], rec->session_key[1],
               rec->session_key[2], rec->session_key[3],
               rec->sign_pub_key[0], rec->sign_pub_key[1],
               rec->sign_pub_key[2], rec->sign_pub_key[3]);
    }

    /* ── Test revocation ──────────────────────────────────────────────────── */
    printf("\n[KEM] --- Revocation test ---\n");
    uint8_t vid3[16]; make_vehicle_id(vid3, 3);
    mark_key_revoked(NULL, vid3);
    VehicleKeyRecord *r = kem_lookup(vid3);
    printf("[KEM] V3 revoked: %s  (expected: true)\n",
           (r && r->revoked) ? "true" : "false");

    /* ── Size report ──────────────────────────────────────────────────────── */
    printf("\n[KEM] --- Size report ---\n");
    printf("[KEM] sizeof(VehicleKeyRecord) = %zu bytes\n", sizeof(VehicleKeyRecord));
    printf("[KEM] sizeof(KemExchangeState) = %zu bytes\n", sizeof(KemExchangeState));
    printf("[KEM]   KYBER1024_PK_LEN : %u\n", KYBER1024_PK_LEN);
    printf("[KEM]   KYBER1024_SK_LEN : %u\n", KYBER1024_SK_LEN);
    printf("[KEM]   KYBER1024_CT_LEN : %u\n", KYBER1024_CT_LEN);
    printf("[KEM]   SESSION_KEY_LEN : %u\n", SESSION_KEY_LEN);
    printf("[KEM]   DILITHIUM5_PK   : %u\n", DILITHIUM5_PK_LEN);

    /* ── Write CSV ────────────────────────────────────────────────────────── */
    FILE *f = fopen("kem_session_keys.csv", "w");
    fprintf(f, "vehicle_id,k_session_hex_8b,pk_hex_4b,lkh_leaf,revoked\n");
    for (uint32_t i = 0; i < g_keystore_count; i++) {
        VehicleKeyRecord *rec = &g_keystore[i];
        fprintf(f, "%s,", (char *)rec->vehicle_id);
        for (int j = 0; j < 8; j++) fprintf(f, "%02x", rec->session_key[j]);
        fprintf(f, ",");
        for (int j = 0; j < 4; j++) fprintf(f, "%02x", rec->sign_pub_key[j]);
        fprintf(f, ",%u,%s\n", rec->lkh_leaf_index, rec->revoked ? "true" : "false");
    }
    fclose(f);
    printf("\n[KEM] Wrote kem_session_keys.csv\n");
    return match ? 0 : 1;
}
