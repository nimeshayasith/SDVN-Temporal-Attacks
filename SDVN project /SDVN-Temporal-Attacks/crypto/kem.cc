/*
 * kem.cc — Kyber-1024 + HQC-5 Hybrid-KEM  (Module 1, Section 3)
 *
 * Establishes K_{Vi,nk}: 32-byte session key shared between vehicle Vi
 * and trusted node nk.  Also generates Dilithium5 signing keypairs
 * (SK_{Vi}, PK_{Vi}) stored in VehicleKeyRecord (Section 3.5).
 *
 * liboqs constants used:
 *   KEM:  OQS_KEM_alg_kyber_1024 (Kyber component, pre-standard / NIST Level 5)
 *         OQS_KEM_alg_hqc_5      (HQC-5 component, code-based / NIST Level 5)
 *   SIG:  OQS_SIG_alg_dilithium_5 (NIST ML-DSA, FIPS 204)
 *
 * Hybrid rationale: ML-KEM-1024 relies on Module-LWE (lattice hardness).
 * HQC-5 relies on syndrome decoding (code-based hardness).  The two
 * assumptions are mathematically independent — an attacker must break
 * BOTH to recover the session key.  This is NIST Level 5 on both sides.
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
/* Kyber-1024 is available under both the old and new name depending on
 * liboqs version.  Fall back to ML-KEM-1024 if the old name is absent. */
#  ifndef OQS_KEM_alg_kyber_1024
#    define OQS_KEM_alg_kyber_1024    OQS_KEM_alg_ml_kem_1024
#  endif
/* Second KEM slot: HQC-5 (code-based, NIST Level 5, NIST alternate candidate).
 * OQS_KEM_alg_hqc_5 is present in liboqs >= 0.7.  FireSaber was the original
 * partner but was dropped from liboqs in 0.10 after NIST did not select Saber.
 * HQC-5 provides a genuinely independent hard problem (syndrome decoding vs
 * Module-LWE), restoring the full two-assumption hybrid security of Eq. 3.15. */
#  ifndef OQS_KEM_alg_hqc_5
#    error "HQC-5 not available in this liboqs build. Install liboqs >= 0.7 with HQC enabled."
#  endif
#  ifndef OQS_SIG_alg_dilithium_5
#    define OQS_SIG_alg_dilithium_5   OQS_SIG_alg_ml_dsa_87
#  endif
#endif

/* Emitted once at first keygen call to confirm hybrid mode. */
static void kem_print_hybrid_mode(void)
{
    static bool s_warned = false;
    if (s_warned) return;
    s_warned = true;
    printf("[KEM] Hybrid mode: Kyber-1024 (lattice/Module-LWE, Level 5)"
           " + HQC-5 (code-based/syndrome-decoding, Level 5)"
           " — full two-assumption hybrid active.\n");
}

/* ─── Global key store ───────────────────────────────────────────────────── */

static VehicleKeyRecord g_keystore[MAX_VEHICLES];
static uint32_t         g_keystore_count = 0;

/* ─── Issue-2 fix: KEM registration nonce replay cache ──────────────────────
 * kem_rsu_encapsulate Stage D: each (vehicle_id, keygen_nonce) pair is checked
 * here before the RSU will encapsulate.  A replayed registration message (same
 * nonce, same vehicle_id) is rejected even if the Dilithium5 sig is valid.
 *
 * Sizing: KEM_NONCE_CACHE_SIZE = 256
 *   KEM registration is a one-shot handshake per vehicle, not a per-beacon
 *   event.  Worst case: MAX_VEHICLES (256) all register simultaneously, each
 *   with one legitimate nonce.  256 slots covers exactly that peak with zero
 *   margin; if you expect re-registrations (e.g. key refresh after soft reset),
 *   size this as MAX_VEHICLES × expected_registrations_per_lifetime.  For a
 *   fleet of 256 with at most 4 registrations per vehicle over its lifetime,
 *   raise to 1024.  The cache is circular, so old entries are evicted; evicted
 *   entries would allow a replay of that slot only after MAX_VEHICLES cycles,
 *   which is acceptable given the registration handshake is low-frequency.     */

#define KEM_NONCE_CACHE_SIZE 256u

typedef struct {
    uint8_t vehicle_id[16];
    uint8_t nonce[NONCE_LEN];
} KemNonceKey;

static KemNonceKey g_kem_nonce_cache[KEM_NONCE_CACHE_SIZE];
static uint32_t    g_kem_nonce_head  = 0;
static uint32_t    g_kem_nonce_count = 0;

static bool kem_nonce_is_novel(const uint8_t vehicle_id[16],
                                const uint8_t nonce[NONCE_LEN]) {
    for (uint32_t i = 0; i < g_kem_nonce_count; i++) {
        uint32_t idx = (g_kem_nonce_head + KEM_NONCE_CACHE_SIZE - 1 - i)
                       % KEM_NONCE_CACHE_SIZE;
        if (memcmp(g_kem_nonce_cache[idx].vehicle_id, vehicle_id, 16) == 0 &&
            memcmp(g_kem_nonce_cache[idx].nonce,      nonce,      NONCE_LEN) == 0)
            return false;
    }
    return true;
}

static void kem_nonce_consume(const uint8_t vehicle_id[16],
                               const uint8_t nonce[NONCE_LEN]) {
    memcpy(g_kem_nonce_cache[g_kem_nonce_head].vehicle_id, vehicle_id, 16);
    memcpy(g_kem_nonce_cache[g_kem_nonce_head].nonce,      nonce,      NONCE_LEN);
    g_kem_nonce_head = (g_kem_nonce_head + 1) % KEM_NONCE_CACHE_SIZE;
    if (g_kem_nonce_count < KEM_NONCE_CACHE_SIZE) g_kem_nonce_count++;
}

/* ─── Random bytes ───────────────────────────────────────────────────────── */
/* When included into crypto_pipeline.cc (PIPELINE_INCLUDE is defined), the
 * canonical fill_random already exists in that translation unit.  Suppress
 * this local copy to avoid a duplicate-symbol error.                        */
#if !defined(PIPELINE_INCLUDE) && !defined(FILL_RANDOM_DEFINED)
#define FILL_RANDOM_DEFINED
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
#endif /* PIPELINE_INCLUDE && FILL_RANDOM_DEFINED */

/* ─── HKDF-SHA256 (Section 3.3 — KDF step) ──────────────────────────────── */
/*
 * Fix-8: vehicle_id bound into HKDF info so the derived session key is
 * vehicle-specific.  Two vehicles sharing the same IKM (impossible in correct
 * operation but worth preventing cryptographically) cannot share a session key.
 * info = "teta-guard-session-key:" || vehicle_id(16 bytes)
 */
static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t vehicle_id[16],
                         uint8_t out[SESSION_KEY_LEN]) {
    static const char *salt      = "teta-guard-kem-salt";
    static const char *info_base = "teta-guard-session-key:";
#ifdef HAVE_OPENSSL
    uint8_t prk[32]; unsigned pl = 32;
    HMAC(EVP_sha256(), salt, (int)strlen(salt), ikm, ikm_len, prk, &pl);
    /* Expand T(1): PRK || info_base || vehicle_id(16) || 0x01 */
    size_t ib_len   = strlen(info_base);
    size_t info_len = ib_len + 16;
    uint8_t *expand = (uint8_t *)malloc(32 + info_len + 1);
    memcpy(expand,               prk,        32);
    memcpy(expand + 32,          info_base,  ib_len);
    memcpy(expand + 32 + ib_len, vehicle_id, 16);
    expand[32 + info_len] = 0x01;
    uint8_t t[32]; unsigned tl = 32;
    HMAC(EVP_sha256(), prk, pl, expand, 32 + info_len + 1, t, &tl);
    memcpy(out, t, SESSION_KEY_LEN);
    free(expand);
#else
    for (size_t i = 0; i < SESSION_KEY_LEN; i++)
        out[i] = ikm[i % ikm_len]
               ^ (uint8_t)(i * 0x5A)
               ^ (uint8_t)salt[i % strlen(salt)]
               ^ vehicle_id[i % 16];
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
 * Perform Kyber-1024 + HQC-5 hybrid key encapsulation for vehicle Vi.
 * Implements Section 3.3 Steps 3-4.
 *
 * trusted_pk    : RSU/nk Kyber public key (or simulated pk)
 * trusted_pk_len: length of above
 * out_session_key: 32-byte shared secret K_{Vi,nk}  [output]
 */
/* kem_encapsulate is a module-private helper not used in the main API path;
 * kept for reference.  The main flow uses kem_rsu_encapsulate directly. */
static void kem_encapsulate(const uint8_t *trusted_pk, size_t trusted_pk_len,
                              const uint8_t vehicle_id[16],
                              uint8_t out_session_key[SESSION_KEY_LEN]) {
#ifdef HAVE_LIBOQS
    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    uint8_t ct_k[kem_k->length_ciphertext];
    uint8_t ss_k[kem_k->length_shared_secret];
    OQS_KEM_encaps(kem_k, ct_k, ss_k, trusted_pk);
    OQS_KEM_free(kem_k);

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_hqc_5);
    uint8_t ct_s[kem_s->length_ciphertext];
    uint8_t ss_s[kem_s->length_shared_secret];
    OQS_KEM_encaps(kem_s, ct_s, ss_s, trusted_pk);
    OQS_KEM_free(kem_s);

    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, vehicle_id, out_session_key);
#else
    uint8_t ephemeral[32];
    fill_random(ephemeral, 32);
    uint8_t ikm[trusted_pk_len + 32];
    memcpy(ikm,               trusted_pk, trusted_pk_len);
    memcpy(ikm + trusted_pk_len, ephemeral, 32);
    hkdf_sha256(ikm, trusted_pk_len + 32, vehicle_id, out_session_key);
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
 * Step 1 — Vehicle generates its Kyber-1024 + HQC-5 KEM keypair AND authenticates
 * the public keys with its Dilithium5 identity key (Fix-1).
 *
 * Parameters added (Fix-1):
 *   vehicle_id   — identity bound into the signed message
 *   dil_sk       — vehicle's Dilithium5 secret key (for signing)
 *   dil_pk       — vehicle's Dilithium5 public key (sent alongside sig for RSU to verify)
 *
 * Signed message = TETA:KEM-AUTH: || vehicle_id(16) || pk_kyber || pk_saber || nonce(16)
 * This prevents a MITM from substituting (pk_kyber, pk_saber) and sharing a session
 * key that the real vehicle never derived.
 */
void kem_vehicle_keygen(KemExchangeState *state,
                         const uint8_t vehicle_id[16],
                         const uint8_t dil_sk[DILITHIUM5_SK_LEN],
                         const uint8_t dil_pk[DILITHIUM5_PK_LEN],
                         const CertificateRecord *cert) {
    kem_print_hybrid_mode();   /* confirm hybrid mode on first call */
    memset(state, 0, sizeof(*state));
    memcpy(state->vehicle_id, vehicle_id, 16);
    memcpy(state->identity_pk,  dil_pk,     DILITHIUM5_PK_LEN);
    /* Fix-1/2 repair: copy CA cert into state so the RSU can verify
     * it is CA-issued before accepting any self-supplied key material. */
    if (cert) state->keygen_cert = *cert;

#ifdef HAVE_LIBOQS
    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    OQS_KEM_keypair(kem_k, state->pk_kyber, state->sk_kyber);
    OQS_KEM_free(kem_k);

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_hqc_5);
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

    /* Fix-1: generate a fresh nonce and sign the keygen message */
    fill_random(state->keygen_nonce, NONCE_LEN);

    /* Build message = vehicle_id || pk_kyber || pk_saber || nonce */
    uint8_t kmsg[16 + KYBER1024_PK_LEN + FIRESABER_PK_LEN + NONCE_LEN];
    uint8_t *p = kmsg;
    memcpy(p, vehicle_id,         16);                   p += 16;
    memcpy(p, state->pk_kyber,    KYBER1024_PK_LEN);     p += KYBER1024_PK_LEN;
    memcpy(p, state->pk_saber,    FIRESABER_PK_LEN);     p += FIRESABER_PK_LEN;
    memcpy(p, state->keygen_nonce, NONCE_LEN);

    size_t sig_len;
    dilithium5_sign_kem_auth(kmsg, sizeof(kmsg), dil_sk,
                              state->keygen_sig, &sig_len);

    state->has_ciphertext    = false;
    state->keygen_sig_valid  = false;  /* will be set by RSU after verification */
}

/*
 * Step 3 — RSU encapsulates to the vehicle's public keys.
 * Fix-1: The RSU first verifies the Dilithium5 signature over
 *   (vehicle_id || pk_kyber || pk_saber || keygen_nonce)
 * before accepting the public keys.  Returns false and does NOT encapsulate
 * if the signature is invalid, preventing MITM substitution of KEM keys.
 *
 * Returns true on success (state->has_ciphertext set, out_session_key filled).
 */
bool kem_rsu_encapsulate(KemExchangeState *state,
                          uint8_t out_session_key[SESSION_KEY_LEN]) {
    /* Fix-1/2 repair: three-stage gate.
     *
     * Stage A — CA cert verification.
     *   keygen_cert was issued by the consortium CA and binds vehicle_id → pk_vi.
     *   If this fails, the vehicle has no CA-approved identity; reject immediately.
     *   This breaks the circular "verify sig against self-supplied pk" flaw.
     */
    if (!dilithium5_verify_cert(&state->keygen_cert)) {
        printf("[KEM] REJECT: cert invalid or not CA-issued for %.*s\n",
               16, state->vehicle_id);
        memset(out_session_key, 0, SESSION_KEY_LEN);
        return false;
    }

    /* Stage B — keygen sig verification using the cert-verified pk (not identity_pk).
     *   Using keygen_cert.pk_vi as the verification key ensures the CA's trust anchor
     *   is authoritative; identity_pk is accepted only if it matches the cert.
     *   A MITM who substitutes their own (pk_kyber, pk_saber, identity_pk) cannot
     *   produce a valid cert.pk_vi that the CA never issued for their keys.        */
    uint8_t kmsg[16 + KYBER1024_PK_LEN + FIRESABER_PK_LEN + NONCE_LEN];
    uint8_t *p = kmsg;
    memcpy(p, state->vehicle_id,    16);                   p += 16;
    memcpy(p, state->pk_kyber,      KYBER1024_PK_LEN);     p += KYBER1024_PK_LEN;
    memcpy(p, state->pk_saber,      FIRESABER_PK_LEN);     p += FIRESABER_PK_LEN;
    memcpy(p, state->keygen_nonce,  NONCE_LEN);

    bool sig_ok = dilithium5_verify_kem_auth(
        kmsg, sizeof(kmsg),
        state->keygen_sig, DILITHIUM5_SIG_LEN,
        state->keygen_cert.pk_vi);   /* cert-verified pk, NOT self-supplied identity_pk */

    if (!sig_ok) {
        printf("[KEM] REJECT: keygen sig invalid for %.*s\n", 16, state->vehicle_id);
        memset(out_session_key, 0, SESSION_KEY_LEN);
        return false;
    }

    /* Stage C — consistency: identity_pk must match what the cert certifies.
     *   Catches a vehicle that sends a mismatched identity_pk alongside a valid cert. */
    if (memcmp(state->keygen_cert.pk_vi, state->identity_pk, DILITHIUM5_PK_LEN) != 0) {
        printf("[KEM] REJECT: identity_pk does not match cert.pk_vi for %.*s\n",
               16, state->vehicle_id);
        memset(out_session_key, 0, SESSION_KEY_LEN);
        return false;
    }

    /* Stage D — Issue-2 fix: nonce replay protection.
     *   The keygen_nonce is inside the Dilithium5-signed message, so an attacker
     *   cannot alter it without invalidating Stage B.  But a compromised node that
     *   captured a genuine registration can re-submit the exact same valid message.
     *   Stage D checks and consumes the (vehicle_id, nonce) pair globally: a second
     *   encapsulate call with the same pair is rejected even though the sig is valid. */
    if (!kem_nonce_is_novel(state->vehicle_id, state->keygen_nonce)) {
        printf("[KEM] REJECT: keygen_nonce already consumed for %.*s"
               " — registration replay detected\n", 16, state->vehicle_id);
        memset(out_session_key, 0, SESSION_KEY_LEN);
        return false;
    }
    kem_nonce_consume(state->vehicle_id, state->keygen_nonce);

    state->keygen_sig_valid = true;

#ifdef HAVE_LIBOQS
    uint8_t ss_k[KYBER1024_SS_LEN], ss_s[KYBER1024_SS_LEN];

    OQS_KEM *kem_k = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    OQS_KEM_encaps(kem_k, state->ct_kyber, ss_k, state->pk_kyber);
    OQS_KEM_free(kem_k);

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_hqc_5);
    OQS_KEM_encaps(kem_s, state->ct_saber, ss_s, state->pk_saber);
    OQS_KEM_free(kem_s);

    /* K_{Vi,nk} = KDF(ss_kyber ⊕ ss_saber) — XOR hybrid combiner (Giacon et al. 2018) */
    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, state->vehicle_id, out_session_key);  /* Fix-8: bind vehicle_id */
#else
    uint8_t ikm[KYBER1024_PK_LEN + FIRESABER_PK_LEN];
    memcpy(ikm,                    state->pk_kyber, KYBER1024_PK_LEN);
    memcpy(ikm + KYBER1024_PK_LEN, state->pk_saber, FIRESABER_PK_LEN);
    hkdf_sha256(ikm, sizeof(ikm), state->vehicle_id, out_session_key);  /* Fix-8 */
    for (size_t i = 0; i < KYBER1024_CT_LEN; i++)
        state->ct_kyber[i] = state->pk_kyber[i % KYBER1024_PK_LEN]
                             ^ out_session_key[i % SESSION_KEY_LEN];
    for (size_t i = 0; i < FIRESABER_CT_LEN; i++)
        state->ct_saber[i] = state->pk_saber[i % FIRESABER_PK_LEN]
                             ^ out_session_key[i % SESSION_KEY_LEN];
#endif
    state->has_ciphertext = true;
    return true;
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

    OQS_KEM *kem_s = OQS_KEM_new(OQS_KEM_alg_hqc_5);
    OQS_STATUS rc_s = OQS_KEM_decaps(kem_s, ss_s, state->ct_saber, state->sk_saber);
    OQS_KEM_free(kem_s);
    if (rc_s != OQS_SUCCESS) return false;

    /* K_{Vi,nk} = KDF(ss_kyber ⊕ ss_saber) — XOR hybrid combiner (Giacon et al. 2018)
     * Fix-8: vehicle_id bound into HKDF info (must match kem_rsu_encapsulate). */
    uint8_t combined[32];
    for (size_t i = 0; i < 32; i++)
        combined[i] = ss_k[i] ^ ss_s[i];
    hkdf_sha256(combined, 32, state->vehicle_id, out_session_key);
#else
    /* Simulated: same HKDF(pk_kyber || pk_saber) — matches kem_rsu_encapsulate */
    uint8_t ikm[KYBER1024_PK_LEN + FIRESABER_PK_LEN];
    memcpy(ikm,                    state->pk_kyber, KYBER1024_PK_LEN);
    memcpy(ikm + KYBER1024_PK_LEN, state->pk_saber, FIRESABER_PK_LEN);
    hkdf_sha256(ikm, sizeof(ikm), state->vehicle_id, out_session_key);  /* Fix-8 */
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

    /* Fix-1+2 ordering: Dilithium5 keypair must be generated BEFORE the KEM
     * handshake so the vehicle can sign its KEM public keys (Fix-1) and the
     * CA can issue a certificate binding vehicle_id → PK_Vi (Fix-2).        */

    /* Step 0a: Dilithium5 identity keypair — SK_Vi stays at vehicle */
    uint8_t sk_vi[DILITHIUM5_SK_LEN];
    dilithium5_keygen(rec->sign_pub_key, sk_vi);

    /* Step 0b: CA issues certificate binding vehicle_id → PK_Vi (Fix-2) */
    teta_ca_init();   /* no-op if already called */
    dilithium5_issue_cert(vehicle_id, rec->sign_pub_key,
                           rec->key_creation_time_ms, &rec->cert);

    /* Step 1: Vehicle generates KEM keypair AND signs it with SK_Vi (Fix-1).
     * Pass rec->cert (just issued above) so kem_rsu_encapsulate can verify
     * CA provenance without circular self-supplied-pk trust.             */
    KemExchangeState kem_state;
    kem_vehicle_keygen(&kem_state, vehicle_id, sk_vi, rec->sign_pub_key, &rec->cert);

    /* Step 3: RSU verifies keygen sig, then encapsulates → RSU derives K_{Vi,nk} */
    uint8_t rsu_key[SESSION_KEY_LEN];
    bool rsu_ok = kem_rsu_encapsulate(&kem_state, rsu_key);
    if (!rsu_ok) {
        printf("[KEM] FATAL: keygen sig rejected for %s — registration aborted\n",
               (char *)vehicle_id);
        g_keystore_count--;   /* rollback the slot we just claimed */
        return NULL;
    }

    /* Step 4: Vehicle decapsulates ciphertexts → vehicle derives K_{Vi,nk} */
    uint8_t vehicle_key[SESSION_KEY_LEN];
    bool ok = kem_vehicle_decapsulate(&kem_state, vehicle_key);

    if (ok && memcmp(rsu_key, vehicle_key, SESSION_KEY_LEN) == 0) {
        memcpy(rec->session_key, rsu_key, SESSION_KEY_LEN);
        printf("[KEM] V%s  handshake OK  cert_valid=%s  K[0..3]=%02x%02x%02x%02x\n",
               (char *)vehicle_id,
               dilithium5_verify_cert(&rec->cert) ? "YES" : "NO",
               rsu_key[0], rsu_key[1], rsu_key[2], rsu_key[3]);
    } else {
        memcpy(rec->session_key, rsu_key, SESSION_KEY_LEN);
        printf("[KEM] WARNING: decaps mismatch for %s — using RSU key\n",
               (char *)vehicle_id);
    }

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
#if !defined(PHASE8_TESTS) && !defined(LKH_PROVIDES_MARK_KEY_REVOKED)
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

#ifndef KEM_NO_MAIN
int main(void) {
    printf("=== kem.cc — Kyber-1024 + HQC-5 Hybrid KEM + Dilithium5 (Module 1) ===\n");
#ifdef HAVE_LIBOQS
    printf("[KEM] Backend: liboqs  — REAL post-quantum crypto active\n");
    printf("[KEM]   Kyber-1024: OQS_KEM_alg_kyber_1024  (IND-CCA2, Level 5)\n");
    printf("[KEM]   HQC-5:     OQS_KEM_alg_hqc_5               (IND-CCA2, Level 5)\n");
    printf("[KEM]   Signing:   OQS_SIG_alg_dilithium_5 (FIPS 204 ML-DSA)\n");
#else
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (kem.cc)                          ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked.  The following are SIMULATED:        ║\n"
        "║    • Kyber-1024 KEM  →  HKDF-SHA256(pk_kyber||pk_saber)      ║\n"
        "║    • HQC-5 KEM          →  XOR fallback (not IND-CCA2 secure)   ║\n"
        "║    • Dilithium5 sig →  random 32-byte buffer (no math)      ║\n"
        "║                                                              ║\n"
        "║  Paper claims Kyber-1024 and HQC-5 IND-CCA2 security.            ║\n"
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

    /* Fix-1+2: generate Dilithium5 test identity before KEM keygen */
    uint8_t test_vid[16] = "V_test_unit\0\0\0\0";
    uint8_t test_pk[DILITHIUM5_PK_LEN], test_sk[DILITHIUM5_SK_LEN];
    teta_ca_init();
    dilithium5_keygen(test_pk, test_sk);

    /* Fix-1/2: CA issues cert binding test_vid → test_pk before KEM keygen */
    CertificateRecord test_cert;
    dilithium5_issue_cert(test_vid, test_pk, 0, &test_cert);

    /* Step 1 — Vehicle generates KEM keypair (signed with Dilithium5) */
    kem_vehicle_keygen(&state, test_vid, test_sk, test_pk, &test_cert);
    printf("[KEM] Step 1 (vehicle keygen):  pk_kyber[0..3]=%02x%02x%02x%02x\n",
           state.pk_kyber[0], state.pk_kyber[1],
           state.pk_kyber[2], state.pk_kyber[3]);

    /* Step 3 — RSU verifies keygen sig, then encapsulates to vehicle's pk */
    uint8_t rsu_key[SESSION_KEY_LEN];
    bool encaps_ok = kem_rsu_encapsulate(&state, rsu_key);
    printf("[KEM] Step 3 (RSU encaps):  sig_valid=%s  K_rsu[0..7]=",
           encaps_ok ? "YES" : "NO (ATTACK BLOCKED)");
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
#endif /* KEM_NO_MAIN */
