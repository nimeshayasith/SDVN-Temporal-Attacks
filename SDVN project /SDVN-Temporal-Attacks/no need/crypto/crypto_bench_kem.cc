// crypto_bench_kem.cc — Kyber-1024 / ML-KEM-1024 KEM latency benchmark
//
// Build: make PQC=1 bench_kem
// Calls OQS KEM APIs directly — avoids KemExchangeState buffer-size conflicts.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include <openssl/rand.h>
#include "teta_guard_types.h"

#ifdef HAVE_LIBOQS
#  include <oqs/oqs.h>
#endif

using Clock = std::chrono::high_resolution_clock;
using us_t  = std::chrono::duration<double, std::micro>;

static double bench(int n_iter, std::function<void()> fn)
{
    for (int i = 0; i < 3; i++) fn();
    double sum = 0.0;
    for (int i = 0; i < n_iter; i++) {
        auto t0 = Clock::now();
        fn();
        sum += us_t(Clock::now() - t0).count();
    }
    return sum / n_iter;
}

static void row(const char *name, int n, double nist_ms, std::function<void()> fn)
{
    double us = bench(n, fn);
    char nist_str[16];
    if (nist_ms > 0) snprintf(nist_str, sizeof(nist_str), "%.4f", nist_ms);
    else              snprintf(nist_str, sizeof(nist_str), "<0.001");
    printf("  %-45s  %4d  %10.3f us  %8.4f ms  %8s ms\n",
           name, n, us, us / 1000.0, nist_str);
}

int main(void)
{
    printf("\n");
    printf("========================================================================\n");
    printf("  TETA-Guard — Kyber-1024 / ML-KEM-1024 + Hybrid KEM Latency\n");
    printf("  Mode : %s\n",
#ifdef HAVE_LIBOQS
        "PQC (real liboqs — actual post-quantum math)"
#else
        "STUB (liboqs not available)"
#endif
    );
    printf("  Platform : x86-64 Linux  (each row = mean over N iterations)\n");
    printf("========================================================================\n");
    printf("  %-45s  %4s  %12s  %10s  %8s\n",
           "Operation", "N", "Measured (us)", "Meas. (ms)", "NIST(ms)");
    printf("  %s\n", std::string(88, '-').c_str());

#ifdef HAVE_LIBOQS
    // ── ML-KEM-1024 (FIPS 203 = Kyber-1024 standardised) ─────────────────────
    printf("\n  ── ML-KEM-1024  (Kyber-1024 standardised, FIPS 203, NIST Level 5)\n");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) { printf("  ERROR: ML-KEM-1024 not available in this liboqs build.\n"); return 1; }

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss(kem->length_shared_secret);
    std::vector<uint8_t> ss2(kem->length_shared_secret);

    printf("  (PK=%zu B  SK=%zu B  CT=%zu B  SS=%zu B)\n",
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

    row("ML-KEM-1024 KeyGen  (vehicle registration)",
        1000, 0.97,
        [&]() { OQS_KEM_keypair(kem, pk.data(), sk.data()); });

    OQS_KEM_keypair(kem, pk.data(), sk.data());

    row("ML-KEM-1024 Encapsulate  (RSU→Vehicle)",
        2000, 1.08,
        [&]() { OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data()); });

    OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());

    row("ML-KEM-1024 Decapsulate  (Vehicle←RSU)",
        2000, 1.17,
        [&]() { OQS_KEM_decaps(kem, ss2.data(), ct.data(), sk.data()); });

    OQS_KEM_free(kem);

    // ── Kyber-1024 (pre-standard, if still available) ─────────────────────────
    printf("\n  ── Kyber-1024  (pre-standard — if available separately)\n");

    OQS_KEM *kem2 = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem2) {
        std::vector<uint8_t> pk2(kem2->length_public_key);
        std::vector<uint8_t> sk2(kem2->length_secret_key);
        std::vector<uint8_t> ct2(kem2->length_ciphertext);
        std::vector<uint8_t> ss3(kem2->length_shared_secret);

        OQS_KEM_keypair(kem2, pk2.data(), sk2.data());

        row("Kyber-1024 KeyGen",   500, 0.97, [&]() { OQS_KEM_keypair(kem2, pk2.data(), sk2.data()); });
        row("Kyber-1024 Encap",   1000, 1.08, [&]() { OQS_KEM_encaps(kem2, ct2.data(), ss3.data(), pk2.data()); });
        OQS_KEM_encaps(kem2, ct2.data(), ss3.data(), pk2.data());
        row("Kyber-1024 Decap",   1000, 1.17, [&]() { OQS_KEM_decaps(kem2, ss3.data(), ct2.data(), sk2.data()); });
        OQS_KEM_free(kem2);
    } else {
        printf("  (Kyber-1024 pre-standard not available — merged into ML-KEM-1024 above)\n");
    }

#else
    printf("  liboqs not available — build with PQC=1 to measure real KEM.\n");
    printf("  NIST reference values:\n");
    printf("    ML-KEM-1024 KeyGen    : 0.97 ms\n");
    printf("    ML-KEM-1024 Encap     : 1.08 ms\n");
    printf("    ML-KEM-1024 Decap     : 1.17 ms\n");
#endif

    // ── Summary ───────────────────────────────────────────────────────────────
    printf("\n========================================================================\n");
    printf("  KEM CONTEXT IN TETA-GUARD PIPELINE:\n");
    printf("  KEM runs ONCE per vehicle session join — NOT per-beacon or per-event.\n");
    printf("  Per-attack-event detection cost is only HMAC + Dilithium verify.\n");
    printf("\n");
    printf("  Per-attack-type crypto cost (NIST estimates):\n");
    printf("    TTW  : HMAC-SHA256 verify + Dilithium5 verify  =  ~1.69 ms/event\n");
    printf("    BSHH : HMAC-SHA256 verify + Dilithium5 verify  =  ~1.69 ms/event\n");
    printf("    ME   : HMAC + Dilithium verify x2 + Haversine  =  ~3.29 ms/event\n");
    printf("    All well within T_b = 100 ms beacon budget.\n");
    printf("========================================================================\n\n");

    return 0;
}
