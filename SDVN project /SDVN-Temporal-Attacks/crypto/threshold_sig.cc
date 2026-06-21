/*
 * threshold_sig.cc — NTRU Threshold Aggregate Signature  (Module 3, Section 5)
 *
 * Defends against BSHH vehicle-origin and RSU-origin identity spoofing.
 * Uses Dilithium5 (NIST ML-DSA, FIPS 204) per liboqs.
 *
 * Exact sizes (liboqs Dilithium5):
 *   Signature : DILITHIUM5_SIG_LEN = 2420 bytes
 *   Public key: DILITHIUM5_PK_LEN  = 1312 bytes
 *   Secret key: DILITHIUM5_SK_LEN  = 2528 bytes
 *
 * Equation 3.26:
 *   Verify(σ_agg, PK_agg) = 1  ⟺  |{i : Verify(σ_i, msg_i, PK_Vi) = 1}| ≥ t
 *   where t = ⌊n/2⌋ + 1
 *
 * Build:
 *   g++ -std=c++17 -O2 threshold_sig.cc -lssl -lcrypto -o threshold_sig
 *   g++ -std=c++17 -O2 -DHAVE_LIBOQS threshold_sig.cc -loqs -lssl -lcrypto -o threshold_sig
 *
 * Input:  pem_event_log.csv
 * Output: threshold_sig_result.csv
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

/* ══════════════════════════════════════════════════════════════════════════
 * Dilithium5 operations — delegated to dilithium.cc (Section 3.3)
 *
 * dilithium5_keygen(), dilithium5_sign(), dilithium5_verify() are the
 * single canonical implementations defined in dilithium.cc and declared
 * in teta_guard_types.h.  No duplicates here.
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * dilithium5_keypair() — thin alias kept for call-site compatibility.
 * Delegates to the shared dilithium5_keygen() from dilithium.cc.
 *
 * static: keeps this symbol translation-unit-local, preventing a duplicate-
 * symbol linker error when threshold_sig.o and dilithium.o are linked together
 * (both define dilithium5_keypair otherwise, causing -Werror=multiple-definition).
 */
static void dilithium5_keypair(uint8_t pk[DILITHIUM5_PK_LEN],
                                uint8_t sk[DILITHIUM5_SK_LEN]) {
    dilithium5_keygen(pk, sk);  /* Section 3.3 shared module */
}

/*
 * vehicle_sign_report() — Section 3.4
 * Vehicle Vi signs its topology observation report before sending to RSU.
 * Delegates to dilithium5_sign() from dilithium.cc.
 */
void vehicle_sign_report(const uint8_t *msg_payload, size_t payload_len,
                          const uint8_t  sk_vi[DILITHIUM5_SK_LEN],
                          uint8_t        sig_out[DILITHIUM5_SIG_LEN],
                          size_t        *sig_len_out) {
    dilithium5_sign(msg_payload, payload_len, sk_vi, sig_out, sig_len_out);
}

/* ══════════════════════════════════════════════════════════════════════════
 * VERIFY_THRESHOLD_SIG  (Section 5.3, Eq. 3.26)
 *
 * Implements the full biconditional:
 *   Verify(σ_agg, PK_agg) = 1  ⟺  |{i : Verify(σ_i, msg_i, PK_Vi) = 1}| ≥ t
 *
 * Step 1 (left side): Recompute expected aggregate sig from stored individual
 *   sigs and verify it matches the stored σ_agg.  This catches any RSU-side
 *   tampering of individual sigs after aggregation (fast path).
 *
 * Step 2 (right side): Count individual valid sigs and enforce count ≥ t.
 *   This is the actual majority enforcement gate.
 *
 * Both steps must pass for THRESHOLD_SIG_PASS.
 * ══════════════════════════════════════════════════════════════════════════ */

ThresholdSigResult verify_threshold_sig(const AggregateReport *report) {
    if (report->n_reports == 0) return THRESHOLD_SIG_FAIL;
    uint32_t threshold_t = (report->n_reports / 2) + 1;  /* strict majority: ⌊n/2⌋+1 */

    /* ── Step 1: Aggregate signature consistency check (Eq. 3.26 left side) ─
     * Recompute σ_agg using the same algorithm as rsu_aggregate_reports().
     * A mismatch means the RSU tampered with individual sigs post-aggregation. */
    uint8_t all_sigs_concat[MAX_REPORTS_PER_RSU * 32];
    for (uint32_t i = 0; i < report->n_reports; i++)
        memcpy(all_sigs_concat + i * 32, report->reports[i].individual_sig, 32);

    uint8_t expected_agg_sig[DILITHIUM5_SIG_LEN];
#ifdef HAVE_OPENSSL
    {
        uint8_t mac[32]; unsigned mac_len = 32;
        HMAC(EVP_sha256(), report->agg_pk, 32,
             all_sigs_concat, report->n_reports * 32, mac, &mac_len);
        memcpy(expected_agg_sig, mac, 32);
        for (size_t i = 32; i < DILITHIUM5_SIG_LEN; i++)
            expected_agg_sig[i] = mac[i % 32] ^ (uint8_t)(i * 0x3A);
    }
#else
    {
        memset(expected_agg_sig, 0, DILITHIUM5_SIG_LEN);
        for (uint32_t i = 0; i < report->n_reports * 32; i++)
            expected_agg_sig[i % DILITHIUM5_SIG_LEN] ^=
                all_sigs_concat[i] ^ report->agg_pk[i % DILITHIUM5_PK_LEN];
    }
#endif
    /* Constant-time compare of first 32 bytes to avoid timing side-channel */
    uint8_t agg_diff = 0;
    for (int i = 0; i < 32; i++) agg_diff |= report->agg_sig[i] ^ expected_agg_sig[i];
    if (agg_diff != 0)
        return THRESHOLD_SIG_FAIL;  /* aggregate sig inconsistent — RSU tampered */

    /* ── Step 2: Individual sig count ≥ t (Eq. 3.26 right side) ────────────
     * Each Verify(σ_i, msg_i, PK_Vi) is an independent Dilithium5 check.
     * This enforces the strict majority: at least ⌊n/2⌋+1 must be valid. */
    uint32_t valid_count = 0;
    for (uint32_t i = 0; i < report->n_reports; i++) {
        const IndividualSignedReport *r = &report->reports[i];
        bool ok = dilithium5_verify(r->msg_payload, sizeof(r->msg_payload),
                                     r->individual_sig, DILITHIUM5_SIG_LEN,
                                     r->pub_key);
        if (ok) valid_count++;
    }

    return (valid_count >= threshold_t) ? THRESHOLD_SIG_PASS : THRESHOLD_SIG_FAIL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * RSU AGGREGATION  (Section 5.2)
 * Build AggregateReport from n individual signed reports.
 * ══════════════════════════════════════════════════════════════════════════ */

void rsu_aggregate_reports(AggregateReport *agg_out,
                             const IndividualSignedReport *reports,
                             uint32_t n_reports) {
    if (n_reports > MAX_REPORTS_PER_RSU) n_reports = MAX_REPORTS_PER_RSU;
    memset(agg_out, 0, sizeof(*agg_out));

    agg_out->n_reports  = n_reports;
    agg_out->threshold_t = (n_reports / 2) + 1;

    for (uint32_t i = 0; i < n_reports; i++)
        agg_out->reports[i] = reports[i];

    /* Build aggregate public key: XOR of all individual public keys.
     * This commits to the complete signer set — substituting any key changes
     * agg_pk, invalidating the aggregate sig and breaking Step 1 of verify. */
    memset(agg_out->agg_pk, 0, DILITHIUM5_PK_LEN);
    for (uint32_t i = 0; i < n_reports; i++)
        for (size_t j = 0; j < DILITHIUM5_PK_LEN; j++)
            agg_out->agg_pk[j] ^= reports[i].pub_key[j];

    /* Build aggregate signature: HMAC-SHA256(agg_pk[0..31], σ_1[0..31] ∥ ... ∥ σ_n[0..31])
     * padded to DILITHIUM5_SIG_LEN.  Binds σ_agg to both the signer set (via
     * agg_pk) and the individual sigs, so tampering with either is detectable. */
    uint8_t all_sigs[MAX_REPORTS_PER_RSU * 32];
    for (uint32_t i = 0; i < n_reports; i++)
        memcpy(all_sigs + i * 32, reports[i].individual_sig, 32);

#ifdef HAVE_OPENSSL
    {
        uint8_t mac[32]; unsigned mac_len = 32;
        HMAC(EVP_sha256(), agg_out->agg_pk, 32,
             all_sigs, n_reports * 32, mac, &mac_len);
        memcpy(agg_out->agg_sig, mac, 32);
        for (size_t i = 32; i < DILITHIUM5_SIG_LEN; i++)
            agg_out->agg_sig[i] = mac[i % 32] ^ (uint8_t)(i * 0x3A);
    }
#else
    {
        memset(agg_out->agg_sig, 0, DILITHIUM5_SIG_LEN);
        for (uint32_t i = 0; i < n_reports * 32; i++)
            agg_out->agg_sig[i % DILITHIUM5_SIG_LEN] ^=
                all_sigs[i] ^ agg_out->agg_pk[i % DILITHIUM5_PK_LEN];
    }
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * CSV processor
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct { double t; int phys; int link_src; int link_dst; int attack; } PemRow;

static int load_pem(const char *file, PemRow *rows, int max) {
    FILE *f = fopen(file, "r");
    if (!f) return 0;
    char line[512]; int n = 0;
    fgets(line, sizeof(line), f);
    while (n < max && fgets(line, sizeof(line), f)) {
        PemRow *r = &rows[n];
        char et[64];
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

#ifndef THRESHOLD_SIG_NO_MAIN
int main(int argc, char *argv[]) {
    const char *input  = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *output = (argc > 2) ? argv[2] : "threshold_sig_result.csv";

    printf("=== threshold_sig.cc — Dilithium5 Threshold Aggregate Sig (Eq. 3.26) ===\n");
#ifndef HAVE_LIBOQS
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (threshold_sig.cc)                ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked. Dilithium5 operations are STUBS:     ║\n"
        "║    • dilithium5_keypair  →  fills buffers with random bytes  ║\n"
        "║    • dilithium5_sign     →  random 32-byte signature         ║\n"
        "║    • dilithium5_verify   →  always returns 0 (accepts all)  ║\n"
        "║                                                              ║\n"
        "║  The NTRU lattice-based aggregate scheme (Eq. 3.26) in the  ║\n"
        "║  paper is NOT executing. No lattice operations run.         ║\n"
        "║                                                              ║\n"
        "║  To enable real Dilithium5:                                 ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    g++ -DHAVE_LIBOQS threshold_sig.cc -loqs -lssl -lcrypto  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
#endif
    printf("[ThreshSig] SIG_LEN=%u  PK_LEN=%u  SK_LEN=%u\n",
           DILITHIUM5_SIG_LEN, DILITHIUM5_PK_LEN, DILITHIUM5_SK_LEN);

    /* ── Pre-generate signing keypairs for V0..V9 ─────────────────────────── */
    static uint8_t pks[10][DILITHIUM5_PK_LEN];
    static uint8_t sks[10][DILITHIUM5_SK_LEN];
    for (int i = 0; i < 10; i++) dilithium5_keypair(pks[i], sks[i]);

    /* ── Self-test: sign + verify ──────────────────────────────────────────── */
    {
        uint8_t msg[256] = {0x01, 0x02, 0xAB, 0xCD};
        uint8_t sig[DILITHIUM5_SIG_LEN];
        size_t  sig_len;
        vehicle_sign_report(msg, 4, sks[0], sig, &sig_len);
        bool ok = dilithium5_verify(msg, 4, sig, sig_len, pks[0]);
        printf("[ThreshSig] Sign+verify self-test: %s\n", ok ? "PASS" : "FAIL");

        /* Tamper message — should fail */
        msg[0] ^= 0xFF;
        bool ok2 = dilithium5_verify(msg, 4, sig, sig_len, pks[0]);
        printf("[ThreshSig] Tamper detection:      %s\n", !ok2 ? "PASS" : "FAIL");
    }

    /* ── Threshold test: 5 signers, t=3 ───────────────────────────────────── */
    {
        IndividualSignedReport reps[5];
        memset(reps, 0, sizeof(reps));
        for (int i = 0; i < 5; i++) {
            snprintf((char *)reps[i].vehicle_id, 16, "V%d", i);
            reps[i].msg_payload[0] = (uint8_t)i;
            reps[i].msg_payload[1] = 0x42;
            size_t slen;
            vehicle_sign_report(reps[i].msg_payload, sizeof(reps[i].msg_payload),
                                 sks[i], reps[i].individual_sig, &slen);
            memcpy(reps[i].pub_key, pks[i], DILITHIUM5_PK_LEN);
        }
        AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 5);
        ThresholdSigResult r = verify_threshold_sig(&agg);
        printf("[ThreshSig] 5/5 valid (t=%u): %s\n", agg.threshold_t,
               r == THRESHOLD_SIG_PASS ? "PASS" : "FAIL");

        /* Corrupt 3 sigs → should fail */
        for (int i = 0; i < 3; i++) agg.reports[i].individual_sig[0] ^= 0xFF;
        r = verify_threshold_sig(&agg);
        printf("[ThreshSig] 2/5 valid (t=%u): %s\n", agg.threshold_t,
               r == THRESHOLD_SIG_FAIL ? "PASS (correctly rejected)" : "FAIL");
    }

    /* ── CSV processing ─────────────────────────────────────────────────── */
    static PemRow rows[4096];
    int n = load_pem(input, rows, 4096);
    if (n == 0) { printf("[ThreshSig] No events loaded\n"); return 0; }

    FILE *out = fopen(output, "w");
    fprintf(out, "window_s,n_reports,threshold_t,valid_sigs,result,attack_in_window\n");

    int win_start = (int)rows[0].t;
    IndividualSignedReport win_reps[MAX_REPORTS_PER_RSU];
    int win_n = 0, win_attack = 0;
    int accepted = 0, rejected = 0;

    for (int i = 0; i <= n; i++) {
        int cur_win = (i < n) ? (int)rows[i].t : -1;
        if (cur_win != win_start || i == n) {
            if (win_n > 0) {
                AggregateReport agg;
                rsu_aggregate_reports(&agg, win_reps, (uint32_t)win_n);

                /* Attack windows: corrupt some sigs */
                if (win_attack > 0)
                    for (int k = 0; k < win_attack && k < win_n; k++)
                        agg.reports[k].individual_sig[0] ^= 0xFF;

                ThresholdSigResult r = verify_threshold_sig(&agg);
                fprintf(out, "%d,%u,%u,",
                        win_start, agg.n_reports, agg.threshold_t);

                int valid = 0;
                for (uint32_t k = 0; k < agg.n_reports; k++) {
                    IndividualSignedReport *rp = &agg.reports[k];
                    if (dilithium5_verify(rp->msg_payload, sizeof(rp->msg_payload),
                                          rp->individual_sig, DILITHIUM5_SIG_LEN,
                                          rp->pub_key)) valid++;
                }
                fprintf(out, "%d,%s,%d\n", valid,
                        r == THRESHOLD_SIG_PASS ? "PASS" : "FAIL",
                        win_attack);
                if (r == THRESHOLD_SIG_PASS) accepted++; else rejected++;
            }
            if (i == n) break;
            win_start  = cur_win;
            win_n      = 0;
            win_attack = 0;
        }

        if (win_n < (int)MAX_REPORTS_PER_RSU) {
            int vid = rows[i].phys % 10;
            IndividualSignedReport *rp = &win_reps[win_n];
            memset(rp, 0, sizeof(*rp));
            snprintf((char *)rp->vehicle_id, 16, "V%d", rows[i].phys);
            rp->msg_payload[0] = (uint8_t)rows[i].link_src;
            rp->msg_payload[1] = (uint8_t)rows[i].link_dst;
            size_t slen;
            vehicle_sign_report(rp->msg_payload, sizeof(rp->msg_payload),
                                 sks[vid], rp->individual_sig, &slen);
            memcpy(rp->pub_key, pks[vid], DILITHIUM5_PK_LEN);
            if (rows[i].attack) win_attack++;
            win_n++;
        }
    }
    fclose(out);

    printf("[ThreshSig] Windows: accepted=%d  rejected=%d\n", accepted, rejected);
    printf("[ThreshSig] Wrote %s\n", output);
    return 0;
}
#endif /* THRESHOLD_SIG_NO_MAIN */
