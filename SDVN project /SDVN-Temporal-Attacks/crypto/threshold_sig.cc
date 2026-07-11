/*
 * threshold_sig.cc — Dilithium5 Threshold Aggregate Signature  (Module 3, Section 5)
 *
 * Defends against BSHH vehicle-origin and RSU-origin identity spoofing.
 * Uses Dilithium5 (NIST ML-DSA, FIPS 204) per-signer signatures with an
 * HMAC-SHA256 aggregate binding — NOT a BLS or NTRU aggregate.
 *
 * Construction:
 *   Individual sig: dilithium5_sign_thresh(TETA:THRESH: || msg || ts || nonce)
 *                   DILITHIUM5_SIG_LEN-byte Dilithium5 signature per signer
 *   Aggregate sig:  HMAC-SHA256(agg_pk, σ_1[0..31] ∥ ... ∥ σ_n[0..31])
 *                   32-byte HMAC — integrity binding over signer set only,
 *                   NOT a cryptographic aggregate signature (not verifiable
 *                   as a single sig against a combined public key).
 *   Aggregate pk:   XOR of all signers' Dilithium5 public keys (commit to signer set).
 *
 * This is explicitly NOT BLS aggregate signatures (which are pairing-based and
 * produce a single signature verifiable against a combined key).  It is also NOT
 * an NTRU-based scheme.  The HMAC binding is integrity-only, not authentication
 * of the aggregate; the actual authentication is per-signer Dilithium5 in Step 2.
 *
 * Uses Dilithium5 (NIST ML-DSA, FIPS 204) per liboqs.
 *
 * Exact sizes (liboqs Dilithium5):
 *   Signature : DILITHIUM5_SIG_LEN  = 4627 bytes  (OQS ML-DSA-87 / Dilithium5, liboqs >= 0.10)
 *   Public key: DILITHIUM5_PK_LEN  = 2592 bytes
 *   Secret key: DILITHIUM5_SK_LEN  = 4864 bytes
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

/* dilithium5_keypair() is only used by the standalone main() for test key
 * generation — not called from vehicle_sign_report / rsu_aggregate_reports /
 * verify_threshold_sig.  Guard it with THRESHOLD_SIG_NO_MAIN so it is not
 * compiled (and not flagged as unused) when included into routing.cc. */
#ifndef THRESHOLD_SIG_NO_MAIN
static void dilithium5_keypair(uint8_t pk[DILITHIUM5_PK_LEN],
                                uint8_t sk[DILITHIUM5_SK_LEN]) {
    dilithium5_keygen(pk, sk);  /* Section 3.3 shared module */
}
#endif /* THRESHOLD_SIG_NO_MAIN */

/* ══════════════════════════════════════════════════════════════════════════
 * Cross-aggregate nonce cache  (Section 5.3)
 *
 * Problem: seen_vids in verify_threshold_sig is stack-local (per-call).
 *   A compromised RSU that captures 3 valid IndividualSignedReports can
 *   replay the same set into multiple AggregateReports within the 5-second
 *   freshness window; each call to verify_threshold_sig would accept them
 *   independently (fresh seen_vids array each time), satisfying the threshold
 *   floor repeatedly using only 3 real signing events.
 *
 * Fix: module-static circular cache of (vehicle_id, nonce) pairs, keyed on
 *   the pair because nonces from different vehicles are independent signing
 *   events.  Once a (vid, nonce) pair is counted in any aggregate it is
 *   consumed here; the next aggregate attempting to reuse the same pair is
 *   rejected before valid_count is incremented.
 *
 * Size: THRESH_REPORT_CACHE_SIZE=4096 entries × 32 B per entry = 128 KB.
 *   At one report per vehicle per 100 ms beacon interval across 64 vehicles,
 *   the 5-second freshness window generates at most 64 × 50 = 3200 entries.
 *   4096 covers 3200 with a 28% safety margin, preventing premature eviction
 *   that would allow a replayed (vid, nonce) to re-enter the cache within the
 *   same 5-second window.
 *   Issue-6 fix: raised from 1024 (which only covered 1.6 s at full load). */

#define THRESH_REPORT_CACHE_SIZE 4096u

typedef struct {
    uint8_t vehicle_id[16];
    uint8_t nonce[NONCE_LEN];
} ThreshReportKey;

static ThreshReportKey g_thresh_nonce_cache[THRESH_REPORT_CACHE_SIZE];
static uint32_t        g_thresh_cache_head  = 0;
static uint32_t        g_thresh_cache_count = 0;

static bool thresh_report_is_novel(const uint8_t vehicle_id[16],
                                    const uint8_t nonce[NONCE_LEN]) {
    for (uint32_t i = 0; i < g_thresh_cache_count; i++) {
        uint32_t idx = (g_thresh_cache_head + THRESH_REPORT_CACHE_SIZE - 1 - i)
                       % THRESH_REPORT_CACHE_SIZE;
        if (memcmp(g_thresh_nonce_cache[idx].vehicle_id, vehicle_id, 16) == 0 &&
            memcmp(g_thresh_nonce_cache[idx].nonce,      nonce,      NONCE_LEN) == 0)
            return false;   /* already consumed in a prior aggregate */
    }
    return true;
}

static void thresh_report_consume(const uint8_t vehicle_id[16],
                                   const uint8_t nonce[NONCE_LEN]) {
    memcpy(g_thresh_nonce_cache[g_thresh_cache_head].vehicle_id, vehicle_id, 16);
    memcpy(g_thresh_nonce_cache[g_thresh_cache_head].nonce,      nonce,      NONCE_LEN);
    g_thresh_cache_head = (g_thresh_cache_head + 1) % THRESH_REPORT_CACHE_SIZE;
    if (g_thresh_cache_count < THRESH_REPORT_CACHE_SIZE) g_thresh_cache_count++;
}

/*
 * vehicle_sign_report() — Section 3.4
 * Vehicle Vi signs its topology observation report before sending to RSU.
 *
 * Signed buffer: msg_payload(payload_len) || timestamp_ms_le(8) || nonce(NONCE_LEN)
 * Both freshness fields are inside the signature so a compromised RSU cannot
 * strip or alter them without invalidating individual_sig.
 * Delegates to dilithium5_sign_thresh (Fix-7 domain-separated wrapper).
 */
void vehicle_sign_report(const uint8_t *msg_payload, size_t payload_len,
                          uint64_t       timestamp_ms,
                          const uint8_t  nonce[NONCE_LEN],
                          const uint8_t  sk_vi[DILITHIUM5_SK_LEN],
                          uint8_t        sig_out[DILITHIUM5_SIG_LEN],
                          size_t        *sig_len_out) {
    /* Build combined buffer: msg_payload || timestamp_ms_le || nonce */
    uint8_t combined[256 + 8 + NONCE_LEN];
    size_t  off = 0;
    if (payload_len > 256) payload_len = 256;
    memcpy(combined + off, msg_payload, payload_len); off += payload_len;
    /* Timestamp as 8-byte little-endian */
    for (int b = 0; b < 8; b++)
        combined[off++] = (uint8_t)(timestamp_ms >> (8 * b));
    memcpy(combined + off, nonce, NONCE_LEN); off += NONCE_LEN;
    dilithium5_sign_thresh(combined, off, sk_vi, sig_out, sig_len_out);
}

/* ══════════════════════════════════════════════════════════════════════════
 * VERIFY_THRESHOLD_SIG  (Section 5.3, Eq. 3.28)
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
    /* Safety: clamp n_reports to the struct array capacity.
     * A compromised RSU could set n_reports > MAX_REPORTS_PER_RSU without adding
     * matching report entries; the loop below would then read past reports[]
     * into agg_sig/agg_pk/timestamp_ms — undefined behaviour.  The garbage bytes
     * would fail all gates (A, B, D, C) so valid_count could not increase, but
     * UB is UB.  Reject immediately rather than iterate over nonsense.
     *
     * Note: a compromised RSU CANNOT win by manipulating n_reports:
     *   Inflate (n_reports > actual valid):  raises t = ⌊n/2⌋+1 → attacker needs
     *     MORE valid sigs, not fewer.  Self-defeating.
     *   Deflate (n_reports < actual valid):  loop skips real valid reports AND
     *     THRESHOLD_T_FLOOR prevents t falling below 3 regardless.
     * Either manipulation direction fails the attacker.  The bound check here is a
     * safety-only fix (prevent UB), not a security gate.                         */
    if (report->n_reports > MAX_REPORTS_PER_RSU) return THRESHOLD_SIG_FAIL;
    /* SECURITY: threshold_t is ALWAYS recomputed from n_reports.
     * report->threshold_t (the RSU-supplied field) is intentionally NEVER READ
     * here.  A compromised RSU setting that field to 1 has zero effect on the
     * quorum requirement enforced below.  See AggregateReport.threshold_t comment
     * in teta_guard_types.h for the full rationale.                             */
    uint32_t threshold_t = (report->n_reports / 2) + 1;  /* strict majority: ⌊n/2⌋+1 */
    /* Fix-4 — two-axis suppression defence.
     *
     * Axis A (IMPLEMENTED HERE): report-count suppression.
     *   An attacker who withholds enough legitimate reports reduces n, which
     *   lowers t = ⌊n/2⌋+1, requiring fewer colluding sigs to reach majority.
     *   THRESHOLD_T_FLOOR=3 blocks this axis: t can never drop below 3
     *   regardless of how many reports the attacker suppresses.
     *
     * Axis B (INTENTIONAL DESIGN DECISION — NOT implemented in the crypto layer):
     *   Colluding-majority attack: attackers who collectively control more than
     *   half the active reporters can produce t valid but fraudulent signatures.
     *   The floor on t does NOT prevent this when the attacker majority is large.
     *
     *   This is an explicit design boundary.  Colluding-majority detection is
     *   delegated to the PEM/TGN layer (ME-S1, signature index 6: "reporter count
     *   for a link exceeds expected density ρ > (1+μ)·2R·λ̂").  That layer has
     *   access to the full reporter-identity and position history needed to
     *   identify Sybil-colluding reporters; the crypto layer intentionally does
     *   not duplicate that check.  See CLAUDE.md §8, signature index 6.          */
    if (threshold_t < THRESHOLD_T_FLOOR) threshold_t = THRESHOLD_T_FLOOR;

    /* ── Step 1: Aggregate signature consistency check (Eq. 3.28 left side) ─
     * Recompute σ_agg using the same algorithm as rsu_aggregate_reports().
     * A mismatch means the RSU tampered with individual sigs post-aggregation.
     *
     * Issue-4 clarification: this step uses only the first 32 bytes of each
     * individual_sig (a prefix integrity check via HMAC-SHA256 over those 32-byte
     * prefixes).  It is NOT a full Dilithium5 aggregate — DILITHIUM5_SIG_LEN is
     * DILITHIUM5_SIG_LEN (4627) bytes per sig and those are stored individually, not combined into a
     * single mathematical aggregate.  AGG_SIG_LEN=32 is the HMAC binding over
     * sig[0..31] for each report, chosen to be fast and avoid a 4627×64-byte stack.
     * The actual per-sig Dilithium5 cryptographic verification happens in Step 2
     * (Gate C) where dilithium5_verify_thresh is called on each full signature.
     * Step 1 is a tamper-detection fast path; Step 2 is the real security gate.
     *
     * KNOWN WEAKNESS (documented, not closed here): a tampered sig byte outside
     * the first 32 would pass Step 1 but be caught by Step 2 Gate C.  Step 2 is
     * thus load-bearing for correctness.
     *
     * Crucially, this is a documented weakness and not an open vulnerability:
     * Step 1 failure means the RSU-side aggregate was tampered and we stop early;
     * Step 1 PASSING for a tampered sig does NOT mean a forged signature would be
     * accepted — Step 2 Gate C independently calls dilithium5_verify_thresh() on
     * every individual signature against its original payload, regardless of what
     * Step 1 found.  A byte-flip outside the first 32 is invisible to Step 1 but
     * fully detectable by the Dilithium5 verifier in Gate C.  The two steps are
     * independent checks; neither relies on the other's result for its own output.
     *
     * If Step 1 is ever promoted to a true integrity gate (removing Step 2's Gate
     * C as a backstop), replace the prefix binding with SHA-256(σ_i) per report:
     *   memcpy(all_sigs_concat + i*32, SHA256(report->reports[i].individual_sig,
     *          DILITHIUM5_SIG_LEN), 32);
     * That hashes all DILITHIUM5_SIG_LEN (4627) bytes into a 32-byte digest before the HMAC, making
     * any single-byte tampering detectable in Step 1.  Not done here because
     * Step 2 Gate C already performs full per-sig Dilithium5 verification.     */
    uint8_t all_sigs_concat[MAX_REPORTS_PER_RSU * 32];
    for (uint32_t i = 0; i < report->n_reports; i++)
        memcpy(all_sigs_concat + i * 32, report->reports[i].individual_sig, 32);

    /* AGG_SIG_LEN=32 matches HMAC-SHA256 output — exact comparison, no padding. */
    uint8_t expected_agg_sig[AGG_SIG_LEN];
#ifdef HAVE_OPENSSL
    {
        uint8_t mac[32]; unsigned mac_len = 32;
        HMAC(EVP_sha256(), report->agg_pk, 32,
             all_sigs_concat, report->n_reports * 32, mac, &mac_len);
        memcpy(expected_agg_sig, mac, AGG_SIG_LEN);
    }
#else
    {
        memset(expected_agg_sig, 0, AGG_SIG_LEN);
        for (uint32_t i = 0; i < report->n_reports * 32; i++)
            expected_agg_sig[i % AGG_SIG_LEN] ^=
                all_sigs_concat[i] ^ report->agg_pk[i % DILITHIUM5_PK_LEN];
    }
#endif
    /* Constant-time compare of all AGG_SIG_LEN bytes */
    uint8_t agg_diff = 0;
    for (int i = 0; i < (int)AGG_SIG_LEN; i++)
        agg_diff |= report->agg_sig[i] ^ expected_agg_sig[i];
    if (agg_diff != 0)
        return THRESHOLD_SIG_FAIL;  /* aggregate sig inconsistent — RSU tampered */

    /* ── Step 2: Individual sig count ≥ t (Eq. 3.28 right side) ────────────
     * Each Verify(σ_i, msg_i, PK_Vi) is an independent Dilithium5 check.
     * Issue-1 fix: add three-gate cert check before counting a sig as valid —
     *   Gate A: CA cert must verify for this vehicle_id (CRL + CA sig check).
     *   Gate B: cert.pk_vi must equal pub_key (consistency — same pattern as KEM).
     *   Gate C: Dilithium5 sig must verify against the cert-validated pub_key.
     * Without Gate A+B, an attacker could forge a report with a self-generated
     * pub_key — exact same circular-trust class as the KEM bug in Fix-1/2.     */
    uint32_t valid_count = 0;
    /* Dedup: track vehicle_ids already counted in this aggregate.
     * A compromised RSU can copy-paste one vehicle's valid, cert-checked,
     * freshness-passing report THRESHOLD_T_FLOOR times into reports[] to
     * satisfy valid_count >= threshold_t using a single real identity.
     * Dedup closes this independently of timestamp/nonce binding — those
     * prevent forgery; this prevents duplication of a genuine report.
     * Only entries that pass all four gates (A/B/D/C) are registered here,
     * so a failing report cannot poison the slot for a legitimate second
     * submission from the same vehicle_id.                                  */
    uint8_t seen_vids[MAX_REPORTS_PER_RSU][16];
    uint32_t seen_count = 0;

    for (uint32_t i = 0; i < report->n_reports; i++) {
        const IndividualSignedReport *r = &report->reports[i];
        /* Gate A: CA cert must be valid and not revoked */
        if (!dilithium5_verify_cert(&r->cert)) continue;
        /* Gate B: cert.pk_vi must match the pub_key in the report */
        if (memcmp(r->cert.pk_vi, r->pub_key, DILITHIUM5_PK_LEN) != 0) continue;
        /* Gate D: freshness — individual report timestamp must be within
         * THRESH_REPORT_WINDOW_MS of the aggregate's timestamp_ms.
         * Prevents a compromised RSU from injecting captured stale reports
         * into a new aggregate: the timestamp is inside the Dilithium5 sig
         * (vehicle_sign_report signs msg_payload||ts||nonce), so the attacker
         * cannot alter it without breaking Gate C.                            */
        uint64_t ts_delta = (r->timestamp_ms > report->timestamp_ms)
                            ? (r->timestamp_ms - report->timestamp_ms)
                            : (report->timestamp_ms - r->timestamp_ms);
        if (ts_delta > THRESH_REPORT_WINDOW_MS) continue;
        /* Gate C: rebuild the signed buffer and verify against the cert-trusted pk */
        uint8_t combined[256 + 8 + NONCE_LEN];
        size_t off = 0;
        memcpy(combined + off, r->msg_payload, sizeof(r->msg_payload));
        off += sizeof(r->msg_payload);
        for (int b = 0; b < 8; b++)
            combined[off++] = (uint8_t)(r->timestamp_ms >> (8 * b));
        memcpy(combined + off, r->nonce, NONCE_LEN); off += NONCE_LEN;
        bool ok = dilithium5_verify_thresh(combined, off,
                                            r->individual_sig, DILITHIUM5_SIG_LEN,
                                            r->pub_key);
        if (!ok) continue;
        /* Cross-aggregate replay gate: reject if (vehicle_id, nonce) was
         * already counted in any prior call to verify_threshold_sig.
         * Catches a compromised RSU reusing the same captured signed reports
         * across multiple AggregateReports within the 5-second freshness
         * window — each call to verify_threshold_sig would accept them
         * independently without this global state.
         * Checked BEFORE local seen_vids to avoid consuming a cache slot
         * for a report that would be discarded anyway by within-aggregate dedup. */
        if (!thresh_report_is_novel(r->vehicle_id, r->nonce)) continue;
        /* Within-aggregate dedup gate: one vehicle_id counts at most once
         * per aggregate regardless of nonce (one witness = one vote).     */
        bool already_seen = false;
        for (uint32_t j = 0; j < seen_count; j++) {
            if (memcmp(seen_vids[j], r->vehicle_id, 16) == 0) {
                already_seen = true;
                break;
            }
        }
        if (already_seen) continue;
        /* Both gates passed — consume (vehicle_id, nonce) globally and count. */
        thresh_report_consume(r->vehicle_id, r->nonce);
        memcpy(seen_vids[seen_count++], r->vehicle_id, 16);
        valid_count++;
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

    agg_out->n_reports   = n_reports;
    agg_out->threshold_t = (n_reports / 2) + 1;
    /* Fix-4: same floor as verify_threshold_sig to stay consistent. */
    if (agg_out->threshold_t < THRESHOLD_T_FLOOR)
        agg_out->threshold_t = THRESHOLD_T_FLOOR;

    for (uint32_t i = 0; i < n_reports; i++)
        agg_out->reports[i] = reports[i];

    /* Bug fix: timestamp_ms was left at its memset default of 0 and never set
     * anywhere in this function. verify_threshold_sig's Gate D compares each
     * report's timestamp_ms against report->timestamp_ms and rejects anything
     * more than THRESH_REPORT_WINDOW_MS (5s) away — with timestamp_ms stuck at
     * 0, every report whose real timestamp is more than 5s past the epoch fails
     * Gate D unconditionally, for legitimate AND attack reports alike. Use the
     * most recent individual report's timestamp as the aggregate's timestamp —
     * i.e. "when the RSU actually aggregated," which is what Gate D's freshness
     * check is meant to measure against. */
    agg_out->timestamp_ms = 0;
    for (uint32_t i = 0; i < n_reports; i++)
        if (reports[i].timestamp_ms > agg_out->timestamp_ms)
            agg_out->timestamp_ms = reports[i].timestamp_ms;

    /* Build aggregate public key: XOR of all individual public keys.
     * This commits to the complete signer set — substituting any key changes
     * agg_pk, invalidating the aggregate sig and breaking Step 1 of verify. */
    memset(agg_out->agg_pk, 0, DILITHIUM5_PK_LEN);
    for (uint32_t i = 0; i < n_reports; i++)
        for (size_t j = 0; j < DILITHIUM5_PK_LEN; j++)
            agg_out->agg_pk[j] ^= reports[i].pub_key[j];

    /* Build aggregate signature: HMAC-SHA256(agg_pk[0..31], σ_1[0..31] ∥ ... ∥ σ_n[0..31]).
     * Issue-3 fix: agg_sig is now AGG_SIG_LEN (32) bytes — exactly HMAC-SHA256 output.
     * The previous version wrote DILITHIUM5_SIG_LEN (4627) bytes using a padding scheme, then verify only
     * compared 32 — 4563 bytes were always zero-padded garbage.  Now the field and
     * computation match: 32 bytes in, 32 bytes out, 32 bytes compared.            */
    uint8_t all_sigs[MAX_REPORTS_PER_RSU * 32];
    for (uint32_t i = 0; i < n_reports; i++)
        memcpy(all_sigs + i * 32, reports[i].individual_sig, 32);

#ifdef HAVE_OPENSSL
    {
        uint8_t mac[32]; unsigned mac_len = 32;
        HMAC(EVP_sha256(), agg_out->agg_pk, 32,
             all_sigs, n_reports * 32, mac, &mac_len);
        memcpy(agg_out->agg_sig, mac, AGG_SIG_LEN);
    }
#else
    {
        memset(agg_out->agg_sig, 0, AGG_SIG_LEN);
        for (uint32_t i = 0; i < n_reports * 32; i++)
            agg_out->agg_sig[i % AGG_SIG_LEN] ^=
                all_sigs[i] ^ agg_out->agg_pk[i % DILITHIUM5_PK_LEN];
    }
#endif
}

/* ══════════════════════════════════════════════════════════════════════════
 * CSV processor and standalone entry point
 * (compiled only when building threshold_sig as a standalone binary;
 *  suppressed via THRESHOLD_SIG_NO_MAIN when included into routing.cc)
 * ══════════════════════════════════════════════════════════════════════════ */

#ifndef THRESHOLD_SIG_NO_MAIN

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

    printf("=== threshold_sig.cc — Dilithium5 Threshold Aggregate Sig (Eq. 3.28) ===\n");
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
        "║  The Dilithium5 t-of-n threshold scheme (Eq. 3.28) in the   ║\n"
        "║  paper is NOT executing. No Dilithium5 math runs.           ║\n"
        "║                                                              ║\n"
        "║  To enable real Dilithium5:                                 ║\n"
        "║    sudo apt-get install liboqs-dev                          ║\n"
        "║    g++ -DHAVE_LIBOQS threshold_sig.cc -loqs -lssl -lcrypto  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n");
#endif
    printf("[ThreshSig] SIG_LEN=%u  PK_LEN=%u  SK_LEN=%u\n",
           DILITHIUM5_SIG_LEN, DILITHIUM5_PK_LEN, DILITHIUM5_SK_LEN);

    /* ── CA init + signing keypairs for V0..V9 ─────────────────────────────── */
    teta_ca_init();
    static uint8_t pks[10][DILITHIUM5_PK_LEN];
    static uint8_t sks[10][DILITHIUM5_SK_LEN];
    static CertificateRecord certs[10];
    for (int i = 0; i < 10; i++) {
        dilithium5_keypair(pks[i], sks[i]);
        uint8_t vid[16];
        memset(vid, 0, 16);
        snprintf((char *)vid, 16, "V%d", i);
        dilithium5_issue_cert(vid, pks[i], (uint64_t)i * 1000, &certs[i]);
    }

    /* ── Self-test: sign + verify (freshness fields included) ─────────────── */
    {
        uint8_t  msg[256] = {0x01, 0x02, 0xAB, 0xCD};
        uint8_t  nonce[NONCE_LEN] = {0}; /* zero nonce for deterministic test */
        uint64_t ts = 10000;
        uint8_t sig[DILITHIUM5_SIG_LEN];
        size_t  sig_len;
        vehicle_sign_report(msg, 4, ts, nonce, sks[0], sig, &sig_len);
        /* rebuild combined buffer to verify */
        uint8_t combined[4+8+NONCE_LEN]; size_t off = 0;
        memcpy(combined, msg, 4); off = 4;
        for (int b = 0; b < 8; b++) combined[off++] = (uint8_t)(ts >> (8*b));
        memcpy(combined+off, nonce, NONCE_LEN); off += NONCE_LEN;
        bool ok = dilithium5_verify_thresh(combined, off, sig, sig_len, pks[0]);
        printf("[ThreshSig] Sign+verify self-test: %s\n", ok ? "PASS" : "FAIL");

        /* Tamper message — should fail */
        combined[0] ^= 0xFF;
        bool ok2 = dilithium5_verify_thresh(combined, off, sig, sig_len, pks[0]);
        printf("[ThreshSig] Tamper detection:      %s\n", !ok2 ? "PASS" : "FAIL");
    }

    /* ── Threshold test: 5 signers, t=3 ───────────────────────────────────── */
    {
        IndividualSignedReport reps[5];
        memset(reps, 0, sizeof(reps));
        uint64_t agg_ts = 20000;
        for (int i = 0; i < 5; i++) {
            snprintf((char *)reps[i].vehicle_id, 16, "V%d", i);
            reps[i].msg_payload[0] = (uint8_t)i;
            reps[i].msg_payload[1] = 0x42;
            reps[i].timestamp_ms   = agg_ts;  /* freshness: same window as aggregate */
            memset(reps[i].nonce, (uint8_t)i, NONCE_LEN);  /* deterministic test nonce */
            size_t slen;
            vehicle_sign_report(reps[i].msg_payload, sizeof(reps[i].msg_payload),
                                 reps[i].timestamp_ms, reps[i].nonce,
                                 sks[i], reps[i].individual_sig, &slen);
            memcpy(reps[i].pub_key, pks[i], DILITHIUM5_PK_LEN);
            reps[i].cert = certs[i];
        }
        AggregateReport agg;
        rsu_aggregate_reports(&agg, reps, 5);
        agg.timestamp_ms = agg_ts;  /* freshness: aggregate window matches reports */
        ThresholdSigResult r = verify_threshold_sig(&agg);
        printf("[ThreshSig] 5/5 valid (t=%u): %s\n", agg.threshold_t,
               r == THRESHOLD_SIG_PASS ? "PASS" : "FAIL");

        /* Corrupt 3 sigs → should fail */
        for (int i = 0; i < 3; i++) agg.reports[i].individual_sig[0] ^= 0xFF;
        r = verify_threshold_sig(&agg);
        printf("[ThreshSig] 2/5 valid (t=%u): %s\n", agg.threshold_t,
               r == THRESHOLD_SIG_FAIL ? "PASS (correctly rejected)" : "FAIL");
    }

    /* ── Dedup test: one vehicle_id copy-pasted 5 times — must fail ──────── */
    {
        /* Build one valid report from V0, then copy it 5 times into the aggregate.
         * valid_count after dedup = 1 (one unique vehicle_id), threshold_t = 3.
         * verify_threshold_sig must return THRESHOLD_SIG_FAIL. */
        IndividualSignedReport base;
        memset(&base, 0, sizeof(base));
        snprintf((char *)base.vehicle_id, 16, "V0");
        base.msg_payload[0] = 0xAA;
        uint64_t agg_ts = 30000;
        base.timestamp_ms = agg_ts;
        memset(base.nonce, 0x5A, NONCE_LEN);
        size_t slen;
        vehicle_sign_report(base.msg_payload, sizeof(base.msg_payload),
                             base.timestamp_ms, base.nonce,
                             sks[0], base.individual_sig, &slen);
        memcpy(base.pub_key, pks[0], DILITHIUM5_PK_LEN);
        base.cert = certs[0];

        IndividualSignedReport dup_reps[5];
        for (int i = 0; i < 5; i++) dup_reps[i] = base;  /* all identical */

        AggregateReport agg_dup;
        rsu_aggregate_reports(&agg_dup, dup_reps, 5);
        agg_dup.timestamp_ms = agg_ts;
        ThresholdSigResult rd = verify_threshold_sig(&agg_dup);
        printf("[ThreshSig] Dedup: 1 unique vid × 5 copies (t=%u): %s\n",
               agg_dup.threshold_t,
               rd == THRESHOLD_SIG_FAIL ? "PASS (duplicates correctly rejected)"
                                        : "FAIL (duplicate-copy attack succeeded)");
    }

    /* ── Cross-aggregate replay test ─────────────────────────────────────── */
    {
        /* Attacker captures 3 valid signed reports (V0/0xBB, V1/0xCC, V2/0xDD)
         * and replays the exact same IndividualSignedReports into a second
         * AggregateReport within the freshness window.
         * Aggregate #1 must PASS (first use of each signing event).
         * Aggregate #2 must FAIL (same (vid, nonce) pairs already consumed). */
        IndividualSignedReport r3[3];
        memset(r3, 0, sizeof(r3));
        uint64_t ca_ts = 40000;
        uint8_t  rep_nonces[3][NONCE_LEN];
        memset(rep_nonces[0], 0xBB, NONCE_LEN);
        memset(rep_nonces[1], 0xCC, NONCE_LEN);
        memset(rep_nonces[2], 0xDD, NONCE_LEN);
        for (int i = 0; i < 3; i++) {
            snprintf((char *)r3[i].vehicle_id, 16, "V%d", i);
            r3[i].msg_payload[0] = (uint8_t)(0x10 + i);
            r3[i].timestamp_ms   = ca_ts;
            memcpy(r3[i].nonce, rep_nonces[i], NONCE_LEN);
            size_t slen;
            vehicle_sign_report(r3[i].msg_payload, sizeof(r3[i].msg_payload),
                                 r3[i].timestamp_ms, r3[i].nonce,
                                 sks[i], r3[i].individual_sig, &slen);
            memcpy(r3[i].pub_key, pks[i], DILITHIUM5_PK_LEN);
            r3[i].cert = certs[i];
        }
        AggregateReport agg1, agg2;
        rsu_aggregate_reports(&agg1, r3, 3);
        agg1.timestamp_ms = ca_ts;
        rsu_aggregate_reports(&agg2, r3, 3);  /* same reports, different struct */
        agg2.timestamp_ms = ca_ts;

        ThresholdSigResult r1 = verify_threshold_sig(&agg1);
        ThresholdSigResult r2 = verify_threshold_sig(&agg2);
        printf("[ThreshSig] Cross-agg replay: agg#1: %s  agg#2: %s\n",
               r1 == THRESHOLD_SIG_PASS ? "PASS" : "FAIL",
               r2 == THRESHOLD_SIG_FAIL ? "PASS (replay correctly blocked)"
                                        : "FAIL (cross-aggregate replay succeeded)");
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
                agg.timestamp_ms = (uint64_t)win_start * 1000;

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
                    /* rebuild signed buffer for inline count */
                    uint8_t cb[256+8+NONCE_LEN]; size_t coff = 0;
                    memcpy(cb, rp->msg_payload, sizeof(rp->msg_payload));
                    coff = sizeof(rp->msg_payload);
                    for (int b = 0; b < 8; b++)
                        cb[coff++] = (uint8_t)(rp->timestamp_ms >> (8*b));
                    memcpy(cb+coff, rp->nonce, NONCE_LEN); coff += NONCE_LEN;
                    if (dilithium5_verify_thresh(cb, coff,
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
            rp->timestamp_ms   = (uint64_t)rows[i].t * 1000;
            memset(rp->nonce, (uint8_t)vid, NONCE_LEN);  /* deterministic in test */
            size_t slen;
            vehicle_sign_report(rp->msg_payload, sizeof(rp->msg_payload),
                                 rp->timestamp_ms, rp->nonce,
                                 sks[vid], rp->individual_sig, &slen);
            memcpy(rp->pub_key, pks[vid], DILITHIUM5_PK_LEN);
            rp->cert = certs[vid];
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
