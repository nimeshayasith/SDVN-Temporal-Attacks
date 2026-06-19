/*
 * dilithium.cc — CRYSTALS-Dilithium Post-Quantum Signatures  (Section 3.3)
 *
 * NIST FIPS 204 (ML-DSA), Dilithium2 variant.
 * Quantum-resistant under the Module-LWE hardness assumption.
 *
 * This is the SINGLE canonical Dilithium module for TETA-Guard.
 * It is shared by:
 *   threshold_sig.cc   — individual sigs for threshold aggregate (Section 3.4)
 *   location_binding.cc — m'_{Vk} signing for ME mitigation (Section 3.5)
 *   kem.cc             — keypair generation at vehicle registration (Section 3.1)
 *
 * Key sizes (liboqs OQS_SIG_alg_dilithium_2 / ML-DSA-44, FIPS 204):
 *   Signature : DILITHIUM2_SIG_LEN = 2420 bytes
 *   Public key: DILITHIUM2_PK_LEN  = 1312 bytes
 *   Secret key: DILITHIUM2_SK_LEN  = 2528 bytes
 *
 * Per-signature verification latency: ~1.6 ms (well within 100 ms SDVN budget).
 *
 * Role in TETA-Guard:
 *   SKVk  — long-term identity signing key (stays at vehicle)
 *   PKVk  — stored in VehicleKeyRecord at RSU key store
 *   σVk   — signs topology observation reports and heartbeats
 *   DISTINCT from Kyber+Saber session keys used for HMAC (kem.cc)
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
 * dilithium2_keygen  (Section 3.3 — keypair generation)
 *
 * Generates one long-term identity keypair for vehicle Vi:
 *   SKVk → stays at vehicle (passed to dilithium2_sign)
 *   PKVk → stored in VehicleKeyRecord.sign_pub_key at RSU key store
 *
 * Called once per vehicle at consortium CA registration.
 * ══════════════════════════════════════════════════════════════════════════ */

void dilithium2_keygen(uint8_t pk[DILITHIUM2_PK_LEN],
                        uint8_t sk[DILITHIUM2_SK_LEN]) {
#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig) {
        /* Fallback if Dilithium2 not available — try ML-DSA-44 */
        sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    }
    if (sig) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_free(sig);
        return;
    }
#endif
    /* Stub: fill with deterministic pseudo-random bytes */
    dil_fill_random(sk, DILITHIUM2_SK_LEN);
#ifdef HAVE_OPENSSL
    /* Derive pk as SHA-256(sk[0..31]) padded deterministically */
    SHA256(sk, 32, pk);
    for (size_t i = 32; i < DILITHIUM2_PK_LEN; i++)
        pk[i] = sk[(i * 7) % DILITHIUM2_SK_LEN] ^ 0xA5;
#else
    for (size_t i = 0; i < DILITHIUM2_PK_LEN; i++)
        pk[i] = sk[(i + 5) % DILITHIUM2_SK_LEN] ^ 0x3C;
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * dilithium2_sign  (Section 3.3 — σVk = Sign(SKVk, m'))
 *
 * Signs a message with the vehicle's long-term secret key.
 * Used by both:
 *   - vehicle_sign_report() in threshold_sig.cc   (Section 3.4)
 *   - create_location_bound_report() in location_binding.cc  (Section 3.5)
 *
 * sig_out     : output buffer, DILITHIUM2_SIG_LEN bytes
 * sig_len_out : actual signature length (≤ DILITHIUM2_SIG_LEN)
 * ══════════════════════════════════════════════════════════════════════════ */

void dilithium2_sign(const uint8_t *msg,    size_t msg_len,
                      const uint8_t  sk[DILITHIUM2_SK_LEN],
                      uint8_t        sig_out[DILITHIUM2_SIG_LEN],
                      size_t        *sig_len_out) {
    if (sig_len_out) *sig_len_out = DILITHIUM2_SIG_LEN;
    memset(sig_out, 0, DILITHIUM2_SIG_LEN);

#ifdef HAVE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig) sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
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
    for (size_t i = 32; i < DILITHIUM2_SIG_LEN; i++)
        sig_out[i] = mac[i % 32] ^ (uint8_t)(i * 0x5A);
#else
    for (size_t i = 0; i < DILITHIUM2_SIG_LEN; i++)
        sig_out[i] = sk[i % DILITHIUM2_SK_LEN] ^ msg[i % msg_len] ^ (uint8_t)i;
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * dilithium2_verify  (Section 3.3 — Verify(σVk, PKVk) = 1)
 *
 * Returns true iff the signature is valid under the given public key.
 * ~1.6 ms latency per verification (within 100 ms SDVN budget).
 * ══════════════════════════════════════════════════════════════════════════ */

bool dilithium2_verify(const uint8_t *msg,      size_t msg_len,
                        const uint8_t  sig[DILITHIUM2_SIG_LEN],
                        size_t         sig_len,
                        const uint8_t  pk[DILITHIUM2_PK_LEN]) {
#ifdef HAVE_LIBOQS
    OQS_SIG *sig_obj = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!sig_obj) sig_obj = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig_obj) {
        OQS_STATUS rc = OQS_SIG_verify(sig_obj, msg, msg_len,
                                        sig, sig_len, pk);
        OQS_SIG_free(sig_obj);
        return rc == OQS_SUCCESS;
    }
#endif
    /* Stub: reverse-derive sk from pk, re-sign, compare first 32 bytes */
    uint8_t sk_derived[DILITHIUM2_SK_LEN];
#ifdef HAVE_OPENSSL
    for (size_t i = 0; i < DILITHIUM2_SK_LEN; i++)
        sk_derived[i] = pk[(i + DILITHIUM2_PK_LEN - 5) % DILITHIUM2_PK_LEN] ^ 0x3C;
#else
    for (size_t i = 0; i < DILITHIUM2_SK_LEN; i++)
        sk_derived[i] = pk[(i + 5) % DILITHIUM2_PK_LEN] ^ 0xA5;
#endif
    uint8_t expected[DILITHIUM2_SIG_LEN];
    dilithium2_sign(msg, msg_len, sk_derived, expected, NULL);

    /* Constant-time compare of first 32 bytes */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= sig[i] ^ expected[i];
    (void)sig_len;
    return diff == 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Self-test + CSV output (standalone test binary)
 * ══════════════════════════════════════════════════════════════════════════ */

#ifndef DILITHIUM_NO_MAIN
int main(void) {
    printf("=== dilithium.cc — CRYSTALS-Dilithium2 (Section 3.3) ===\n");

#ifdef HAVE_LIBOQS
    printf("[DIL] Backend : liboqs — REAL FIPS 204 ML-DSA active\n");
    printf("[DIL]   Algorithm : OQS_SIG_alg_dilithium_2\n");
    printf("[DIL]   Security  : Module-LWE (quantum-resistant)\n");
#else
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (dilithium.cc)                    ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked.  Dilithium2 operations are stubs:    ║\n"
        "║    dilithium2_keygen  → deterministic pseudo-random bytes   ║\n"
        "║    dilithium2_sign    → HMAC-SHA256 padded to sig length     ║\n"
        "║    dilithium2_verify  → reverse-derive + compare 32 bytes   ║\n"
        "║                                                              ║\n"
        "║  NO lattice math is executed. Not quantum-resistant.        ║\n"
        "║                                                              ║\n"
        "║  To enable real Dilithium2:                                 ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    make PQC=1                                               ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
    printf("[DIL] Backend : STUB (HMAC-SHA256 fallback)\n");
#endif

    printf("[DIL] SIG_LEN=%u  PK_LEN=%u  SK_LEN=%u\n\n",
           DILITHIUM2_SIG_LEN, DILITHIUM2_PK_LEN, DILITHIUM2_SK_LEN);

    /* ── Test 1: keygen ─────────────────────────────────────────── */
    uint8_t pk[DILITHIUM2_PK_LEN], sk[DILITHIUM2_SK_LEN];
    dilithium2_keygen(pk, sk);
    printf("[DIL] keygen:  pk[0..3]=%02x%02x%02x%02x  sk[0..3]=%02x%02x%02x%02x\n",
           pk[0], pk[1], pk[2], pk[3], sk[0], sk[1], sk[2], sk[3]);

    /* ── Test 2: sign + verify (valid) ─────────────────────────── */
    const uint8_t msg[] = "TETA-Guard topology report";
    uint8_t sig[DILITHIUM2_SIG_LEN]; size_t sig_len;
    dilithium2_sign(msg, sizeof(msg) - 1, sk, sig, &sig_len);
    bool ok1 = dilithium2_verify(msg, sizeof(msg) - 1, sig, sig_len, pk);
    printf("[DIL] sign+verify (valid):   %s  sig_len=%zu\n",
           ok1 ? "PASS" : "FAIL", sig_len);

    /* ── Test 3: tampered message → reject ─────────────────────── */
    uint8_t tampered[sizeof(msg)];
    memcpy(tampered, msg, sizeof(msg));
    tampered[0] ^= 0xFF;
    bool ok2 = dilithium2_verify(tampered, sizeof(tampered) - 1, sig, sig_len, pk);
    printf("[DIL] tampered message:      %s  (expected: FAIL → rejected)\n",
           !ok2 ? "PASS" : "FAIL");

    /* ── Test 4: wrong public key → reject ──────────────────────── */
    uint8_t pk2[DILITHIUM2_PK_LEN], sk2[DILITHIUM2_SK_LEN];
    dilithium2_keygen(pk2, sk2);
    bool ok3 = dilithium2_verify(msg, sizeof(msg) - 1, sig, sig_len, pk2);
    printf("[DIL] wrong public key:      %s  (expected: FAIL → rejected)\n",
           !ok3 ? "PASS" : "FAIL");

    /* ── Test 5: 5-vehicle round-trip ───────────────────────────── */
    printf("\n[DIL] 5-vehicle round-trip:\n");
    int all_pass = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t vpk[DILITHIUM2_PK_LEN], vsk[DILITHIUM2_SK_LEN];
        dilithium2_keygen(vpk, vsk);
        uint8_t vmsg[32]; memset(vmsg, (uint8_t)i, 32);
        uint8_t vsig[DILITHIUM2_SIG_LEN]; size_t vlen;
        dilithium2_sign(vmsg, 32, vsk, vsig, &vlen);
        bool v = dilithium2_verify(vmsg, 32, vsig, vlen, vpk);
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
