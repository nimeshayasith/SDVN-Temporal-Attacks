/*
 * threshold_sig.cc — NTRU Threshold Aggregate Signature  (Module 3, Section 5)
 *
 * Defends against BSHH vehicle-origin and RSU-origin identity spoofing.
 * Uses Dilithium2 (NIST ML-DSA, FIPS 204) per liboqs.
 *
 * Exact sizes (liboqs Dilithium2):
 *   Signature : DILITHIUM2_SIG_LEN = 2420 bytes
 *   Public key: DILITHIUM2_PK_LEN  = 1312 bytes
 *   Secret key: DILITHIUM2_SK_LEN  = 2528 bytes
 *
 * Equation 3.24:
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
 * Dilithium2 operations — delegated to dilithium.cc (Section 3.3)
 *
 * dilithium2_keygen(), dilithium2_sign(), dilithium2_verify() are the
 * single canonical implementations defined in dilithium.cc and declared
 * in teta_guard_types.h.  No duplicates here.
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * dilithium2_keypair() — thin alias kept for call-site compatibility.
 * Delegates to the shared dilithium2_keygen() from dilithium.cc.
 *
 * static: keeps this symbol translation-unit-local, preventing a duplicate-
 * symbol linker error when threshold_sig.o and dilithium.o are linked together
 * (both define dilithium2_keypair otherwise, causing -Werror=multiple-definition).
 */
static void dilithium2_keypair(uint8_t pk[DILITHIUM2_PK_LEN],
                                uint8_t sk[DILITHIUM2_SK_LEN]) {
    dilithium2_keygen(pk, sk);  /* Section 3.3 shared module */
}

/*
 * vehicle_sign_report() — Section 3.4
 * Vehicle Vi signs its topology observation report before sending to RSU.
 * Delegates to dilithium2_sign() from dilithium.cc.
 */
void vehicle_sign_report(const uint8_t *msg_payload, size_t payload_len,
                          const uint8_t  sk_vi[DILITHIUM2_SK_LEN],
                          uint8_t        sig_out[DILITHIUM2_SIG_LEN],
                          size_t        *sig_len_out) {
    dilithium2_sign(msg_payload, payload_len, sk_vi, sig_out, sig_len_out);
}

/* ══════════════════════════════════════════════════════════════════════════
 * VERIFY_THRESHOLD_SIG  (Section 5.3, Eq. 3.24)
 *
 * Called inside Algorithm 3 (hmac_filter) and Algorithm 4 (FS-MITIGATE).
 * Returns PASS iff ≥ t individual signatures are cryptographically valid.
 * ══════════════════════════════════════════════════════════════════════════ */

ThresholdSigResult verify_threshold_sig(const AggregateReport *report) {
    uint32_t threshold_t = (report->n_reports / 2) + 1;  /* ⌊n/2⌋ + 1 */
    uint32_t valid_count = 0;

    for (uint32_t i = 0; i < report->n_reports; i++) {
        const IndividualSignedReport *r = &report->reports[i];
        bool ok = dilithium2_verify(r->msg_payload, sizeof(r->msg_payload),
                                     r->individual_sig, DILITHIUM2_SIG_LEN,
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

    /* Aggregate signature = SHA-256(σ_1 ∥ ... ∥ σ_n) padded to Dilithium2 size */
    uint8_t all_sigs[MAX_REPORTS_PER_RSU * 32]; /* first 32 bytes of each sig */
    for (uint32_t i = 0; i < n_reports; i++)
        memcpy(all_sigs + i * 32, reports[i].individual_sig, 32);

#ifdef HAVE_OPENSSL
    uint8_t digest[32];
    SHA256(all_sigs, n_reports * 32, digest);
    memcpy(agg_out->agg_sig, digest, 32);
    for (size_t i = 32; i < DILITHIUM2_SIG_LEN; i++)
        agg_out->agg_sig[i] = digest[i % 32] ^ (uint8_t)(i * 0x3A);
#else
    memset(agg_out->agg_sig, 0, DILITHIUM2_SIG_LEN);
    for (uint32_t i = 0; i < n_reports * 32; i++)
        agg_out->agg_sig[i % DILITHIUM2_SIG_LEN] ^= all_sigs[i];
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

int main(int argc, char *argv[]) {
    const char *input  = (argc > 1) ? argv[1] : "pem_event_log.csv";
    const char *output = (argc > 2) ? argv[2] : "threshold_sig_result.csv";

    printf("=== threshold_sig.cc — Dilithium2 Threshold Aggregate Sig (Eq. 3.24) ===\n");
#ifndef HAVE_LIBOQS
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  WARNING — PQC STUB MODE  (threshold_sig.cc)                ║\n"
        "║                                                              ║\n"
        "║  liboqs is NOT linked. Dilithium2 operations are STUBS:     ║\n"
        "║    • dilithium2_keypair  →  fills buffers with random bytes  ║\n"
        "║    • dilithium2_sign     →  random 32-byte signature         ║\n"
        "║    • dilithium2_verify   →  always returns 0 (accepts all)  ║\n"
        "║                                                              ║\n"
        "║  The NTRU lattice-based aggregate scheme (Eq. 3.24) in the  ║\n"
        "║  paper is NOT executing. No lattice operations run.         ║\n"
        "║                                                              ║\n"
        "║  To enable real Dilithium2:                                 ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    g++ -DHAVE_LIBOQS threshold_sig.cc -loqs -lssl -lcrypto  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
#endif
    printf("[ThreshSig] SIG_LEN=%u  PK_LEN=%u  SK_LEN=%u\n",
           DILITHIUM2_SIG_LEN, DILITHIUM2_PK_LEN, DILITHIUM2_SK_LEN);

    /* ── Pre-generate signing keypairs for V0..V9 ─────────────────────────── */
    static uint8_t pks[10][DILITHIUM2_PK_LEN];
    static uint8_t sks[10][DILITHIUM2_SK_LEN];
    for (int i = 0; i < 10; i++) dilithium2_keypair(pks[i], sks[i]);

    /* ── Self-test: sign + verify ──────────────────────────────────────────── */
    {
        uint8_t msg[256] = {0x01, 0x02, 0xAB, 0xCD};
        uint8_t sig[DILITHIUM2_SIG_LEN];
        size_t  sig_len;
        vehicle_sign_report(msg, 4, sks[0], sig, &sig_len);
        bool ok = dilithium2_verify(msg, 4, sig, sig_len, pks[0]);
        printf("[ThreshSig] Sign+verify self-test: %s\n", ok ? "PASS" : "FAIL");

        /* Tamper message — should fail */
        msg[0] ^= 0xFF;
        bool ok2 = dilithium2_verify(msg, 4, sig, sig_len, pks[0]);
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
            memcpy(reps[i].pub_key, pks[i], DILITHIUM2_PK_LEN);
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
                    if (dilithium2_verify(rp->msg_payload, sizeof(rp->msg_payload),
                                          rp->individual_sig, DILITHIUM2_SIG_LEN,
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
            memcpy(rp->pub_key, pks[vid], DILITHIUM2_PK_LEN);
            if (rows[i].attack) win_attack++;
            win_n++;
        }
    }
    fclose(out);

    printf("[ThreshSig] Windows: accepted=%d  rejected=%d\n", accepted, rejected);
    printf("[ThreshSig] Wrote %s\n", output);
    return 0;
}
