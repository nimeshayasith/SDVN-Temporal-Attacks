/*
 * dilithium.cc — CRYSTALS-Dilithium Post-Quantum Signatures
 *
 * NIST FIPS 204 (ML-DSA), Dilithium5 variant.
 * Quantum-resistant under the Module-LWE hardness assumption.
 *
 * This is the SINGLE canonical Dilithium module for TETA-Guard.
 * It is shared by:
 *   threshold_sig.cc    — individual sigs for threshold aggregate
 *   location_binding.cc — location-bound report signing
 *   kem.cc              — keypair generation at vehicle registration
 *
 * Key sizes (liboqs OQS_SIG_alg_dilithium_5 / ML-DSA-44, FIPS 204):
 *   Signature : DILITHIUM5_SIG_LEN = 2420 bytes
 *   Public key: DILITHIUM5_PK_LEN  = 1312 bytes
 *   Secret key: DILITHIUM5_SK_LEN  = 2528 bytes
 *
 * Per-signature verification latency: ~1.6 ms (well within 100 ms SDVN budget).
 *
 * Role in TETA-Guard:
 *   Long-term identity keypair SKVk/PKVk — generated once at registration.
 *   SKVk stays at vehicle; PKVk stored in RSU key store (VehicleKeyRecord).
 *   Distinct from the Kyber+Saber session keys used for HMAC (kem.cc).
 *
 * Build:
 *   g++ -std=c++17 -O2 dilithium.cc -lssl -lcrypto -o dilithium_test
 *   g++ -std=c++17 -O2 -DHAVE_LIBOQS dilithium.cc -loqs -lssl -lcrypto -o dilithium_test
 *
 * Output: dilithium_test_result.csv
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
#  include <openssl/evp.h>
#endif

#ifdef HAVE_LIBOQS
#  include <oqs/oqs.h>
/* liboqs >= 0.10 standardized to ML-DSA-87 (FIPS 204); older builds used
 * OQS_SIG_alg_dilithium_5.  Provide a compat alias so code compiles on both. */
#  ifndef OQS_SIG_alg_dilithium_5
#    define OQS_SIG_alg_dilithium_5 OQS_SIG_alg_ml_dsa_87
#  endif
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Internal random-byte helper
 * ══════════════════════════════════════════════════════════════════════════ */

static void dil_fill_random(uint8_t *buf, size_t len) {
#ifdef HAVE_OPENSSL
    RAND_bytes(buf, (int)len);
#else
    static uint64_t s = 0x7A3F9C2D1B8E4056ULL;
    for (size_t i = 0; i < len; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(s >> 56);
    }
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * dilithium5_keygen  (Section 3.3 — keypair generation)
 *
 * Generates one long-term identity keypair for vehicle Vi:
 *   SKVk → stays at vehicle (passed to dilithium5_sign)
 *   PKVk → stored in VehicleKeyRecord.sign_pub_key at RSU key store
 *
 * Called once per vehicle at consortium CA registration.
 * ══════════════════════════════════════════════════════════════════════════ */

void dilithium5_keygen(uint8_t pk[DILITHIUM5_PK_LEN],
                        uint8_t sk[DILITHIUM5_SK_LEN]) {
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        /* Fallback if Dilithium5 not available — try ML-DSA-44 */
        sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    }
    if (sig) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_free(sig);
        return;
    }
#endif
    /* Stub: fill sk with pseudo-random bytes, derive pk via invertible XOR.
     * pk[i] = sk[i % SK_LEN] ^ 0xA5 so verify can recover sk[0..31] from pk. */
    dil_fill_random(sk, DILITHIUM5_SK_LEN);
    for (size_t i = 0; i < DILITHIUM5_PK_LEN; i++)
        pk[i] = sk[i % DILITHIUM5_SK_LEN] ^ 0xA5;
}

/* ══════════════════════════════════════════════════════════════════════════
 * dilithium5_sign  (Section 3.3 — σVk = Sign(SKVk, m'))
 *
 * Signs a message with the vehicle's long-term secret key.
 * Used by both:
 *   - vehicle_sign_report() in threshold_sig.cc   (Section 3.4)
 *   - create_location_bound_report() in location_binding.cc  (Section 3.5)
 *
 * sig_out     : output buffer, DILITHIUM5_SIG_LEN bytes
 * sig_len_out : actual signature length (≤ DILITHIUM5_SIG_LEN)
 * ══════════════════════════════════════════════════════════════════════════ */

void dilithium5_sign(const uint8_t *msg,    size_t msg_len,
                      const uint8_t  sk[DILITHIUM5_SK_LEN],
                      uint8_t        sig_out[DILITHIUM5_SIG_LEN],
                      size_t        *sig_len_out) {
    if (sig_len_out) *sig_len_out = DILITHIUM5_SIG_LEN;
    memset(sig_out, 0, DILITHIUM5_SIG_LEN);

#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (sig) {
        OQS_SIG_sign(sig, sig_out, sig_len_out, msg, msg_len, sk);
        OQS_SIG_free(sig);
        return;
    }
#endif
    /* Stub: HMAC-SHA256(sk[0..31], msg) padded to full signature size */
#ifdef HAVE_OPENSSL
    uint8_t mac[32]; unsigned ml = 32;
    HMAC(EVP_sha256(), sk, 32, msg, msg_len, mac, &ml);
    memcpy(sig_out, mac, 32);
    for (size_t i = 32; i < DILITHIUM5_SIG_LEN; i++)
        sig_out[i] = mac[i % 32] ^ (uint8_t)(i * 0x5A);
#else
    for (size_t i = 0; i < DILITHIUM5_SIG_LEN; i++)
        sig_out[i] = sk[i % DILITHIUM5_SK_LEN] ^ msg[i % msg_len] ^ (uint8_t)i;
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * dilithium5_verify  (Section 3.3 — Verify(σVk, PKVk) = 1)
 *
 * Returns true iff the signature is valid under the given public key.
 * ~1.6 ms latency per verification (within 100 ms SDVN budget).
 * ══════════════════════════════════════════════════════════════════════════ */

bool dilithium5_verify(const uint8_t *msg,      size_t msg_len,
                        const uint8_t  sig[DILITHIUM5_SIG_LEN],
                        size_t         sig_len,
                        const uint8_t  pk[DILITHIUM5_PK_LEN]) {
#ifdef HAVE_LIBOQS
    OQS_SIG *sig_obj = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig_obj) sig_obj = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (sig_obj) {
        OQS_STATUS rc = OQS_SIG_verify(sig_obj, msg, msg_len,
                                        sig, sig_len, pk);
        OQS_SIG_free(sig_obj);
        return rc == OQS_SUCCESS;
    }
#endif
    /* Issue-8 fix: fail the build loudly when stub mode is active.
     *
     * A build without HAVE_LIBOQS only checks 32 of 4595 sig bytes.
     * This is not a safe production configuration and must not be used in any
     * deployment that touches real vehicle identities or revocation state.
     *
     * To permit stub mode explicitly (simulation / CI without liboqs installed):
     *   g++ ... -DALLOW_DILITHIUM_STUB ...
     * Without that flag, the build fails so stub mode can never ship silently.  */
#if !defined(HAVE_LIBOQS) && !defined(ALLOW_DILITHIUM_STUB)
#  error "dilithium5_verify: HAVE_LIBOQS is not defined and ALLOW_DILITHIUM_STUB \
is not set. Stub mode (32/4595 bytes checked) must NOT be used in production. \
Pass -DALLOW_DILITHIUM_STUB to build deliberately in stub mode for simulation only."
#endif
    {
        static bool stub_warned = false;
        if (!stub_warned) {
            stub_warned = true;
            fprintf(stderr,
                "[DILITHIUM] STUB MODE: dilithium5_verify checks only 32/%d sig bytes. "
                "Build with -DHAVE_LIBOQS and link liboqs for production.\n",
                DILITHIUM5_SIG_LEN);
        }
    }

    /* Stub: invert the keygen XOR mapping (pk[i] = sk[i%SK_LEN]^0xA5)
     * to recover sk[0..31], then re-sign and compare the first 32 bytes. */
    uint8_t sk_derived[DILITHIUM5_SK_LEN];
    for (size_t i = 0; i < DILITHIUM5_SK_LEN; i++)
        sk_derived[i] = pk[i % DILITHIUM5_PK_LEN] ^ 0xA5;
    uint8_t expected[DILITHIUM5_SIG_LEN];
    dilithium5_sign(msg, msg_len, sk_derived, expected, NULL);

    /* Constant-time compare of first 32 bytes */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= sig[i] ^ expected[i];
    (void)sig_len;
    return diff == 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Fix-7 — Domain-separated sign / verify (Section 3.3 extension)
 *
 * Each wrapper prepends its ASCII domain tag before signing so that a
 * threshold sig over message M cannot be passed as a location-binding sig
 * over the same M, and vice-versa.  All three use-cases (THRESH, LOCBIND,
 * KEM_AUTH) call the canonical dilithium5_sign/verify underneath; only the
 * effective message differs.
 *
 * Heap allocation is avoided by splitting the HMAC over two calls
 * (domain || msg) using a scratch buffer capped at 4 KB + domain len.
 * ══════════════════════════════════════════════════════════════════════════ */

/* Internal helper: prepend domain tag, sign the concatenation */
static void dilithium5_sign_ds(const char *domain,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t  sk[DILITHIUM5_SK_LEN],
                                uint8_t sig[DILITHIUM5_SIG_LEN],
                                size_t *sig_len) {
    size_t dlen = strlen(domain);
    /* Stack buffer for domain || msg.  Max combined size: ~4 KB + 14 B domain. */
    static uint8_t buf[4096 + 16];
    size_t total = dlen + msg_len;
    uint8_t *p = (total <= sizeof(buf)) ? buf : (uint8_t *)malloc(total);
    if (!p) { memset(sig, 0, DILITHIUM5_SIG_LEN); if (sig_len) *sig_len = 0; return; }
    memcpy(p,         domain, dlen);
    memcpy(p + dlen,  msg,    msg_len);
    dilithium5_sign(p, total, sk, sig, sig_len);
    if (p != buf) free(p);
}

static bool dilithium5_verify_ds(const char *domain,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t  sig[DILITHIUM5_SIG_LEN],
                                   size_t sig_len,
                                   const uint8_t  pk[DILITHIUM5_PK_LEN]) {
    size_t dlen = strlen(domain);
    static uint8_t buf[4096 + 16];
    size_t total = dlen + msg_len;
    uint8_t *p = (total <= sizeof(buf)) ? buf : (uint8_t *)malloc(total);
    if (!p) return false;
    memcpy(p,        domain, dlen);
    memcpy(p + dlen, msg,    msg_len);
    bool ok = dilithium5_verify(p, total, sig, sig_len, pk);
    if (p != buf) free(p);
    return ok;
}

void dilithium5_sign_thresh(const uint8_t *msg, size_t msg_len,
                              const uint8_t  sk[DILITHIUM5_SK_LEN],
                              uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len) {
    dilithium5_sign_ds(TETA_DS_THRESH, msg, msg_len, sk, sig, sig_len);
}

bool dilithium5_verify_thresh(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                               const uint8_t  pk[DILITHIUM5_PK_LEN]) {
    return dilithium5_verify_ds(TETA_DS_THRESH, msg, msg_len, sig, sig_len, pk);
}

void dilithium5_sign_locbind(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sk[DILITHIUM5_SK_LEN],
                               uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len) {
    dilithium5_sign_ds(TETA_DS_LOCBIND, msg, msg_len, sk, sig, sig_len);
}

bool dilithium5_verify_locbind(const uint8_t *msg, size_t msg_len,
                                const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                                const uint8_t  pk[DILITHIUM5_PK_LEN]) {
    return dilithium5_verify_ds(TETA_DS_LOCBIND, msg, msg_len, sig, sig_len, pk);
}

void dilithium5_sign_kem_auth(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sk[DILITHIUM5_SK_LEN],
                               uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len) {
    dilithium5_sign_ds(TETA_DS_KEM_AUTH, msg, msg_len, sk, sig, sig_len);
}

bool dilithium5_verify_kem_auth(const uint8_t *msg, size_t msg_len,
                                 const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                                 const uint8_t  pk[DILITHIUM5_PK_LEN]) {
    return dilithium5_verify_ds(TETA_DS_KEM_AUTH, msg, msg_len, sig, sig_len, pk);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Fix-2 — Consortium CA for Dilithium5 public key binding
 *
 * CertificateRecord binds vehicle_id → PK_Vi under a CA signature so no
 * vehicle can substitute a different public key and impersonate another.
 *
 * CA keypair: static, generated once via teta_ca_init().
 * In simulation: teta_ca_init() is called at RSU startup and the keypair
 * lives in process memory.  In production the CA would run out-of-band at
 * vehicle enrolment and only ca_pk would be distributed to RSUs.
 *
 * Signed message = TETA_DS_CA_CERT || vehicle_id(16) || pk_vi || issued_at_ms(8)
 * ══════════════════════════════════════════════════════════════════════════ */

static uint8_t g_ca_pk[DILITHIUM5_PK_LEN];
static uint8_t g_ca_sk[DILITHIUM5_SK_LEN];
static bool    g_ca_initialized = false;

/* Issue-2 fix — Certificate Revocation List.
 * Module-static; populated by cert_revoke_vehicle(), checked by
 * dilithium5_verify_cert() before evaluating the CA signature.
 * A revoked vehicle_id is rejected even if its CA sig is valid — prevents
 * a compromised vehicle from continuing to authenticate after lkh_revoke_vehicle
 * has wiped its session key.  mark_key_revoked() calls cert_revoke_vehicle()
 * so a single revocation event atomically invalidates both layers.
 *
 * DEPLOYMENT SIZING — CRITICAL (Issue-1 fix):
 * The CRL uses MAX_CRL_ENTRIES (currently 4096), not MAX_VEHICLES.
 * These are different numbers for any long-lived deployment:
 *   MAX_VEHICLES  = active concurrent fleet / keystore size (256)
 *   MAX_CRL_ENTRIES = total lifetime revocations, monotonically growing (4096)
 * The fail-closed policy in cert_is_revoked() means that once
 * g_crl_count == MAX_CRL_ENTRIES every vehicle_id not explicitly in the CRL
 * is treated as revoked — including long-standing, never-compromised vehicles.
 * MAX_CRL_ENTRIES MUST be sized as:
 *   expected_total_revocations_over_lifetime × safety_margin (≥ 2×)
 * For a long-lived deployment (> 5 years) with high compromise rates, increase
 * MAX_CRL_ENTRIES in teta_guard_types.h before production build.            */
static uint8_t g_crl[MAX_CRL_ENTRIES][16];
static uint32_t g_crl_count = 0;

void cert_revoke_vehicle(const uint8_t vehicle_id[16]) {
    /* Idempotent: skip if already revoked */
    for (uint32_t i = 0; i < g_crl_count; i++) {
        if (memcmp(g_crl[i], vehicle_id, 16) == 0) return;
    }
    if (g_crl_count >= MAX_CRL_ENTRIES) {
        /* Fail-closed: CRL is full.  cert_is_revoked returns true for any
         * vehicle_id not explicitly found in the CRL when the table is full,
         * so this vehicle is effectively blocked even without an explicit entry.
         * Log the overflow so it is visible in audit output.                   */
        fprintf(stderr, "[CRL] cert_revoke_vehicle: CRL full (MAX_CRL_ENTRIES=%u)"
                " — %.16s not added; fail-closed policy applies\n",
                MAX_CRL_ENTRIES, (const char *)vehicle_id);
        return;
    }
    memcpy(g_crl[g_crl_count++], vehicle_id, 16);
    printf("[CRL] cert_revoke_vehicle: %.16s\n", (const char *)vehicle_id);
}

bool cert_is_revoked(const uint8_t vehicle_id[16]) {
    for (uint32_t i = 0; i < g_crl_count; i++) {
        if (memcmp(g_crl[i], vehicle_id, 16) == 0) return true;
    }
    /* Fail-closed: if the CRL is full, any vehicle_id NOT found in the table
     * is treated as revoked.  This prevents the overflow from becoming an
     * "allowlist bypass" where a new attacker can't be blocked because the
     * table is full of earlier revocations.                                   */
    if (g_crl_count >= MAX_CRL_ENTRIES) return true;
    return false;
}

void teta_ca_init(void) {
    if (g_ca_initialized) return;
    dilithium5_keygen(g_ca_pk, g_ca_sk);
    g_ca_initialized = true;
}

void teta_ca_get_pk(uint8_t ca_pk[DILITHIUM5_PK_LEN]) {
    if (!g_ca_initialized) teta_ca_init();
    memcpy(ca_pk, g_ca_pk, DILITHIUM5_PK_LEN);
}

/* Build the raw cert payload (no domain prefix): vehicle_id || pk_vi || issued_at_ms.
 * The domain prefix TETA_DS_CA_CERT is added by the sign/verify wrappers below,
 * keeping the same pattern as dilithium5_sign_ds for all other signing paths.   */
static void build_cert_payload(const uint8_t vehicle_id[16],
                                const uint8_t pk_vi[DILITHIUM5_PK_LEN],
                                uint64_t      issued_at_ms,
                                uint8_t      *out_payload,   /* caller allocates */
                                size_t       *out_len) {
    uint8_t *p = out_payload;
    memcpy(p, vehicle_id,    16);                p += 16;
    memcpy(p, pk_vi,         DILITHIUM5_PK_LEN); p += DILITHIUM5_PK_LEN;
    memcpy(p, &issued_at_ms, 8);                 p += 8;
    *out_len = (size_t)(p - out_payload);
}

/* Issue-4 fix — domain-separated CA cert wrappers.
 * Use dilithium5_sign_ds(TETA_DS_CA_CERT, ...) so cert signing has the same
 * domain separation as THRESH, LOCBIND, and KEM-AUTH paths.                   */
void dilithium5_sign_ca_cert(const uint8_t *payload, size_t payload_len,
                              const uint8_t sk[DILITHIUM5_SK_LEN],
                              uint8_t sig_out[DILITHIUM5_SIG_LEN]) {
    size_t sig_len;
    dilithium5_sign_ds(TETA_DS_CA_CERT, payload, payload_len, sk, sig_out, &sig_len);
}

bool dilithium5_verify_ca_cert(const uint8_t *payload, size_t payload_len,
                                const uint8_t sig[DILITHIUM5_SIG_LEN],
                                const uint8_t pk[DILITHIUM5_PK_LEN]) {
    /* Reuse dilithium5_sign_ds path: prepend domain and verify with provided pk */
    size_t dlen = strlen(TETA_DS_CA_CERT);
    /* Max payload: id(16) + pk(2592) + ts(8) = 2616; with domain(13) = 2629 */
    uint8_t msg[14 + 16 + DILITHIUM5_PK_LEN + 8];
    if (dlen + payload_len > sizeof(msg)) return false;
    memcpy(msg,         TETA_DS_CA_CERT, dlen);
    memcpy(msg + dlen,  payload,          payload_len);
    return dilithium5_verify(msg, dlen + payload_len, sig, DILITHIUM5_SIG_LEN, pk);
}

void dilithium5_issue_cert(const uint8_t vehicle_id[16],
                            const uint8_t pk_vi[DILITHIUM5_PK_LEN],
                            uint64_t      issued_at_ms,
                            CertificateRecord *cert_out) {
    if (!g_ca_initialized) teta_ca_init();
    memcpy(cert_out->vehicle_id, vehicle_id, 16);
    memcpy(cert_out->pk_vi,      pk_vi,       DILITHIUM5_PK_LEN);
    cert_out->issued_at_ms = issued_at_ms;

    /* Raw payload: id(16) + pk(2592) + ts(8) = 2616 bytes */
    uint8_t payload[16 + DILITHIUM5_PK_LEN + 8];
    size_t  payload_len;
    build_cert_payload(vehicle_id, pk_vi, issued_at_ms, payload, &payload_len);

    dilithium5_sign_ca_cert(payload, payload_len, g_ca_sk, cert_out->ca_sig);
}

bool dilithium5_verify_cert(const CertificateRecord *cert) {
    if (!g_ca_initialized) return false;
    /* Trust-anchor note: the verification key here is g_ca_pk — a module-static
     * buffer populated once by teta_ca_init() and NEVER updated from any network
     * message.  It is NOT taken from the CertificateRecord being verified, nor
     * from any field in the KemExchangeState or BeaconMessage.  There is no path
     * by which an attacker-supplied value reaches g_ca_pk; the circularity that
     * Fix-1/2 was designed to close is not re-introduced here.
     *
     * In production this would be a compile-time constant or HSM-provisioned key;
     * for simulation it is generated once at RSU startup via teta_ca_init().    */

    /* Issue-2 fix — CRL check: reject revoked vehicles before evaluating CA sig */
    if (cert_is_revoked(cert->vehicle_id)) return false;

    uint8_t payload[16 + DILITHIUM5_PK_LEN + 8];
    size_t  payload_len;
    build_cert_payload(cert->vehicle_id, cert->pk_vi, cert->issued_at_ms,
                       payload, &payload_len);
    return dilithium5_verify_ca_cert(payload, payload_len, cert->ca_sig, g_ca_pk);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Self-test + CSV output (standalone test binary)
 * ══════════════════════════════════════════════════════════════════════════ */

#ifndef DILITHIUM_NO_MAIN
int main(void) {
    printf("=== dilithium.cc — CRYSTALS-Dilithium5 (Section 3.3) ===\n");

#ifdef HAVE_LIBOQS
    printf("[DIL] Backend : liboqs — REAL FIPS 204 ML-DSA active\n");
    printf("[DIL]   Algorithm : OQS_SIG_alg_dilithium_5\n");
    printf("[DIL]   Security  : Module-LWE (quantum-resistant)\n");
#else
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (dilithium.cc)                    ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked.  Dilithium5 operations are stubs:    ║\n"
        "║    dilithium5_keygen  → deterministic pseudo-random bytes   ║\n"
        "║    dilithium5_sign    → HMAC-SHA256 padded to sig length     ║\n"
        "║    dilithium5_verify  → reverse-derive + compare 32 bytes   ║\n"
        "║                                                              ║\n"
        "║  NO lattice math is executed. Not quantum-resistant.        ║\n"
        "║                                                              ║\n"
        "║  To enable real Dilithium5:                                 ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    make PQC=1                                               ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
    printf("[DIL] Backend : STUB (HMAC-SHA256 fallback)\n");
#endif

    printf("[DIL] SIG_LEN=%u  PK_LEN=%u  SK_LEN=%u\n\n",
           DILITHIUM5_SIG_LEN, DILITHIUM5_PK_LEN, DILITHIUM5_SK_LEN);

    /* ── Test 1: keygen ─────────────────────────────────────────── */
    uint8_t pk[DILITHIUM5_PK_LEN], sk[DILITHIUM5_SK_LEN];
    dilithium5_keygen(pk, sk);
    printf("[DIL] keygen:  pk[0..3]=%02x%02x%02x%02x  sk[0..3]=%02x%02x%02x%02x\n",
           pk[0], pk[1], pk[2], pk[3], sk[0], sk[1], sk[2], sk[3]);

    /* ── Test 2: sign + verify (valid) ─────────────────────────── */
    const uint8_t msg[] = "TETA-Guard topology report";
    uint8_t sig[DILITHIUM5_SIG_LEN]; size_t sig_len;
    dilithium5_sign(msg, sizeof(msg) - 1, sk, sig, &sig_len);
    bool ok1 = dilithium5_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    printf("[DIL] sign+verify (valid):   %s  sig_len=%zu\n",
           ok1 ? "PASS" : "FAIL", sig_len);

    /* ── Test 3: tampered message → reject ─────────────────────── */
    uint8_t tampered[sizeof(msg)];
    memcpy(tampered, msg, sizeof(msg));
    tampered[0] ^= 0xFF;
    bool ok2 = dilithium5_verify(tampered, sizeof(tampered) - 1, sig, sig_len, pk);
    printf("[DIL] tampered message:      %s  (expected: FAIL → rejected)\n",
           !ok2 ? "PASS" : "FAIL");

    /* ── Test 4: wrong public key → reject ──────────────────────── */
    uint8_t pk2[DILITHIUM5_PK_LEN], sk2[DILITHIUM5_SK_LEN];
    dilithium5_keygen(pk2, sk2);
    bool ok3 = dilithium5_verify(msg, sizeof(msg) - 1, sig, sig_len, pk2);
    printf("[DIL] wrong public key:      %s  (expected: FAIL → rejected)\n",
           !ok3 ? "PASS" : "FAIL");

    /* ── Test 5: 5-vehicle round-trip ───────────────────────────── */
    printf("\n[DIL] 5-vehicle round-trip:\n");
    int all_pass = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t vpk[DILITHIUM5_PK_LEN], vsk[DILITHIUM5_SK_LEN];
        dilithium5_keygen(vpk, vsk);
        uint8_t vmsg[32]; memset(vmsg, (uint8_t)i, 32);
        uint8_t vsig[DILITHIUM5_SIG_LEN]; size_t vlen;
        dilithium5_sign(vmsg, 32, vsk, vsig, &vlen);
        bool v = dilithium5_verify(vmsg, 32, vsig, vlen, vpk);
        printf("[DIL]   V%d: %s\n", i, v ? "PASS" : "FAIL");
        if (!v) all_pass = 0;
    }

    /* ── Write CSV ───────────────────────────────────────────────── */
    FILE *f = fopen("dilithium_test_result.csv", "w");
    fprintf(f, "test,result\n");
    fprintf(f, "sign_verify_valid,%s\n",     ok1  ? "PASS" : "FAIL");
    fprintf(f, "tampered_msg_reject,%s\n",   !ok2 ? "PASS" : "FAIL");
    fprintf(f, "wrong_key_reject,%s\n",      !ok3 ? "PASS" : "FAIL");
    fprintf(f, "five_vehicle_roundtrip,%s\n", all_pass ? "PASS" : "FAIL");
    fclose(f);
    printf("\n[DIL] Wrote dilithium_test_result.csv\n");

    return (ok1 && !ok2 && !ok3 && all_pass) ? 0 : 1;
}
#endif /* DILITHIUM_NO_MAIN */
