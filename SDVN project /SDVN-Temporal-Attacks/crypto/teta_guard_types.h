/*
 * teta_guard_types.h — Shared struct definitions for TETA-Guard crypto layer
 *
 * All structs, enums, and constants that cross module boundaries are defined
 * here.  Every crypto .cc file includes this header.
 *
 * NIST Security Level 5 primitives:
 *   Dilithium5  (ML-DSA-87,   FIPS 204)  — long-term identity signatures
 *   Kyber-1024  (ML-KEM-1024, FIPS 203)  — KEM component 1
 *   HQC-5       (code-based, NIST Level 5) — KEM component 2 (hybrid partner)
 *
 * Three canonical interface structs (from the implementation guide):
 *   BeaconMessage       — vehicle wire format  (crypto input)
 *   CryptoVerifiedEvent — crypto → TGN boundary (Section 8.2)
 *   DetectionAlert      — TGN  → Blockchain boundary (Section 9.1, Eq. 3.36)
 *
 * Security fixes applied (see CRYPTO_LAYER.md §Security):
 *   Fix-1  KEM handshake authenticated: kem_vehicle_keygen signs (pk_kyber||pk_hqc||vid||nonce)
 *   Fix-2  PKI trust-root: CA issues CertificateRecord binding vehicle_id → PK_Vi
 *   Fix-3  Revocation unified: lkh_revoke_vehicle atomically calls mark_key_revoked
 *   Fix-4  Threshold floor: THRESHOLD_T_FLOOR=3 prevents t<3 under report suppression
 *   Fix-5  RSSI plausibility: verify_single_witness checks RSSI vs haversine distance
 *   Fix-6  IPC: crypto_pipeline reads /tmp/teta_guard_revoke.txt for blockchain callbacks
 *   Fix-7  Domain separation: THRESH/LOCBIND/KEM use distinct domain-prefixed signing
 *   Fix-8  HKDF binds vehicle_id: session key is vehicle-specific (no key aliasing)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * 1. CONSTANTS
 * ══════════════════════════════════════════════════════════════════════════ */

#define BEACON_INTERVAL_MS      100u        /* T_b = 100 ms (IEEE 802.11p)   */
// Gap 15 fix: was 10ms, disagreeing with routing.cc's live-path PEM_PROPAGATION_EPSILON_S
// (0.020s = 20ms, the epsilon actually enforced by TetaGuardCryptoFilter's Step 2 /
// Eq. 3.16 in the running simulation). Both represent the SAME physical constant
// epsilon and must agree; standardised on 20ms (the live value) so hmac_filter.cc's
// lw_mitigate() would compute the identical freshness bound if/when it is wired
// into the live path.
#define PROPAGATION_TOL_MS       20u        /* ε = 20 ms propagation budget  */
#define FRESHNESS_WINDOW_MS     (BEACON_INTERVAL_MS + PROPAGATION_TOL_MS)

#define NONCE_LEN                16u        /* 128-bit nonce                 */
#define NONCE_CACHE_SIZE       4096u        /* Circular nonce cache per sender*/
#define SESSION_KEY_LEN          32u        /* K_{Vi,nk} — 256-bit HMAC key  */
#define HMAC_SHA256_LEN          32u        /* HMAC-SHA256 tag               */

/* Aggregate signature length — HMAC-SHA256 (32 bytes), NOT a full Dilithium5
 * signature.  rsu_aggregate_reports() uses HMAC-SHA256(agg_pk, concat_sigs)
 * as a lightweight binding over the signer set; individual Dilithium5 sigs
 * are verified separately in Step 2 of verify_threshold_sig().
 * Sized independently so it cannot be confused with DILITHIUM5_SIG_LEN (4627).*/
#define AGG_SIG_LEN              32u

/* ML-DSA-87 (NIST FIPS 204, formerly Dilithium5) — NIST Security Level 5
 * Quantum-resistant under Module-LWE hardness assumption.
 * Sizes from liboqs OQS_SIG_alg_ml_dsa_87 (the standardised FIPS 204 form).
 * NOTE: liboqs >= 0.10 ships ML-DSA-87 (sig=4627, sk=4896), NOT the pre-FIPS
 * Dilithium5 (sig=4595, sk=4864).  Use ML-DSA-87 sizes to avoid 32-byte
 * buffer overflows on keygen, sign, and verify. */
#define DILITHIUM5_SIG_LEN     4627u        /* OQS_SIG_alg_ml_dsa_87 length_signature  */
#define DILITHIUM5_PK_LEN      2592u        /* OQS_SIG_alg_ml_dsa_87 length_public_key */
#define DILITHIUM5_SK_LEN      4896u        /* OQS_SIG_alg_ml_dsa_87 length_secret_key */

#define R_COMM_METERS          300.0f       /* DSRC communication range (m)  */
#define RSSI_MIN_DBM           -85.0f       /* RSSImin at r_comm, 5.9 GHz    */

/* Issue-1 split: MAX_VEHICLES sizes the active fleet (keystore, LKH tree);
 * MAX_CRL_ENTRIES sizes the CRL (monotonically growing over the system lifetime).
 * These are different numbers for any long-lived deployment: MAX_CRL_ENTRIES MUST
 * be ≥ total_expected_revocations_over_lifetime × 2.  Using one constant for both
 * is wrong: a low value caps the fleet; a high value wastes keystore memory.     */
#define MAX_VEHICLES            256u        /* Active concurrent fleet / keystore  */
#define MAX_CRL_ENTRIES        4096u        /* Lifetime revocations (monotonic CRL)*/
#define MAX_REPORTS_PER_RSU      64u        /* Max individual sigs per AggregateReport */
#define MAX_OBSERVATIONS_PER_RSU 200u       /* Max obs in BeaconEvidenceRecord */

/* Threshold floor — prevents t < 3 even when n is small (Fix-4).
 * An attacker who jams reports to reduce n cannot lower t below this.
 *
 * CROSS-MODULE DESIGN BOUNDARY (Fix-4):
 *   The floor blocks report-count suppression (Axis A) only.
 *   Colluding-majority attacks — where >⌊n/2⌋ reporters are all adversaries —
 *   are NOT blocked by this constant.  Detection of that pattern is explicitly
 *   delegated to the PEM/TGN layer: ME-S1 (PEM signature index 6),
 *   "reporter count ρ > (1+μ)·2R·λ̂".  Any future change to the PEM layer that
 *   removes or weakens ME-S1 must revisit whether this crypto boundary still
 *   holds.  See threshold_sig.cc verify_threshold_sig() for the full comment. */
#define THRESHOLD_T_FLOOR        3u

/* Domain-separation prefixes for Dilithium5 use-cases (Fix-7).
 * Prevents a signature for one use-case from being accepted as another. */
#define TETA_DS_THRESH    "TETA:THRESH:"    /* 12 bytes — threshold aggregate */
#define TETA_DS_LOCBIND   "TETA:LOCBIND:"   /* 13 bytes — location binding    */
#define TETA_DS_KEM_AUTH  "TETA:KEM-AUTH:"  /* 14 bytes — KEM pk authentication */
#define TETA_DS_CA_CERT   "TETA:CA-CERT:"   /* 13 bytes — CA certificate       */

/* Revocation IPC file — blockchain → C++ pipeline (Fix-6).
 * submit_alerts.py writes one vehicle_id per line when FS-MITIGATE Stage 3
 * confirms revocation on-chain.  crypto_pipeline reads and applies it at startup. */
#define TETA_REVOKE_FILE  "/tmp/teta_guard_revoke.txt"

/* RSSI-vs-distance margin for plausibility check (Fix-5).
 * A reporter whose claimed RSSI is more than 10 dB weaker than the
 * Friis-expected value at their claimed GPS distance is rejected.
 * (Catches distant attackers who forge GPS coordinates but cannot fake RSSI.) */
#define RSSI_DISTANCE_MARGIN_DB  10.0f

/* Kyber-1024 wire sizes (liboqs OQS_KEM_alg_kyber_1024 / ML-KEM-1024, FIPS 203)
 * NIST Security Level 5 */
#define KYBER1024_PK_LEN  1568u  /* OQS_KEM_kyber_1024_length_public_key    */
#define KYBER1024_SK_LEN  3168u  /* OQS_KEM_kyber_1024_length_secret_key    */
#define KYBER1024_CT_LEN  1568u  /* OQS_KEM_kyber_1024_length_ciphertext    */
#define KYBER1024_SS_LEN    32u  /* OQS_KEM_kyber_1024_length_shared_secret */

/* HQC-5 wire sizes (liboqs OQS_KEM_alg_hqc_5, code-based, NIST Security Level 5).
 * This is the second KEM in the Kyber-1024 + HQC-5 hybrid — kem.cc has never
 * used FireSaber/Saber; every OQS_KEM_new() call in kem.cc requests
 * OQS_KEM_alg_hqc_5 directly. There is no fallback path.
 *
 * BUG FIX: these constants previously held stale ML-KEM-1024-sized values
 * (1568/3168/1568), copied from a since-abandoned "FireSaber unavailable ->
 * fall back to ML-KEM-1024" plan that kem.cc never implements. Because kem.cc
 * unconditionally calls the real OQS_KEM_alg_hqc_5, every OQS_KEM_keypair/
 * encaps/decaps call on the pk_hqc/sk_hqc/ct_hqc fields below was overflowing
 * these undersized fixed buffers by 5.6-13 KB, corrupting the KemExchangeState
 * fields declared right after them (identity_pk, keygen_cert, keygen_sig).
 * That corruption is what caused kem_rsu_encapsulate() to reject every
 * keygen signature as invalid ("[KEM] REJECT: keygen sig invalid ..."): the
 * corrupted cert/sig bytes never matched what was actually signed. Sizes
 * below are liboqs's real OQS_KEM_hqc_5_length_* constants (kem_hqc.h). */
#define HQC5_PK_LEN   7237u  /* OQS_KEM_hqc_5_length_public_key    */
#define HQC5_SK_LEN   7333u  /* OQS_KEM_hqc_5_length_secret_key    */
#define HQC5_CT_LEN  14421u  /* OQS_KEM_hqc_5_length_ciphertext    */
#define HQC5_SS_LEN     32u  /* OQS_KEM_hqc_5_length_shared_secret */

/* ══════════════════════════════════════════════════════════════════════════
 * 2. CERTIFICATE RECORD  (Fix-2 — PKI trust-root for Dilithium public keys)
 *
 * Defined FIRST because KemExchangeState embeds it (Fix-1/Fix-2 repair).
 *
 * Binds vehicle_id → PK_Vi under a CA signature, so no vehicle can substitute
 * a different public key and impersonate another vehicle.
 *
 * Issued by: consortium CA (dilithium5_issue_cert in dilithium.cc).
 * Verified by: RSU in kem_rsu_encapsulate before accepting keygen sig.
 *
 * CA keypair: static simulation CA (g_ca_pk/g_ca_sk in dilithium.cc).
 * In production: provisioned by the consortium PKI at vehicle enrolment.
 *
 * Signed message = TETA_DS_CA_CERT || vehicle_id || pk_vi || issued_at_ms(8 bytes)
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  vehicle_id[16];               /* Bound identity                  */
    uint8_t  pk_vi[DILITHIUM5_PK_LEN];    /* Dilithium5 public key of Vi     */
    uint64_t issued_at_ms;                 /* Timestamp (prevents cert replay) */
    uint8_t  ca_sig[DILITHIUM5_SIG_LEN];  /* CA's Dilithium5 signature        */
} CertificateRecord;

/*
 * KemExchangeState — held by vehicle during Section 3.3 handshake.
 *
 * Step 1: kem_vehicle_keygen()  fills KEM keypairs, auth fields, AND keygen_cert.
 * Step 2: Vehicle transmits (pk_kyber, pk_hqc, keygen_nonce, keygen_sig,
 *         identity_pk, keygen_cert) to RSU.
 *         Note: identity_pk is the Dilithium5 identity public key (PK_Vi), NOT a KEM key.
 * Step 3: kem_rsu_encapsulate() FIRST verifies keygen_cert (CA trust-root),
 *         THEN verifies keygen_sig using keygen_cert.pk_vi, THEN encapsulates.
 * Step 4: kem_vehicle_decapsulate() consumes ct_* + sk_* → session key.
 *
 * Fix-1 (authenticated KEM):
 *   keygen_sig is over (TETA:KEM-AUTH: || vehicle_id || pk_kyber || pk_hqc || nonce).
 *   Without this, a MITM can substitute (pk_kyber, pk_hqc) freely.
 *
 * Fix-2 (CA trust-root) repair:
 *   keygen_cert embeds the CA-issued certificate binding (vehicle_id → identity_pk).
 *   kem_rsu_encapsulate calls dilithium5_verify_cert(&state->keygen_cert) BEFORE
 *   dilithium5_verify_kem_auth, and uses keygen_cert.pk_vi (not identity_pk) to
 *   verify the keygen sig — so the CA's trust anchor, not the vehicle's self-claim,
 *   is the verification key. This closes the circular "self-signed" gap from the
 *   prior implementation where only identity_pk was used.
 *
 * Issue-7 fix: renamed keygen_pk → identity_pk throughout to make clear that this
 *   field is the Dilithium5 identity key (PK_Vi), not a KEM public key. The KEM
 *   public keys are pk_kyber and pk_hqc.
 */
typedef struct {
    /* KEM keypairs */
    uint8_t pk_kyber[KYBER1024_PK_LEN]; /* Vehicle Kyber-1024 public key (sent to RSU)  */
    uint8_t sk_kyber[KYBER1024_SK_LEN]; /* Vehicle Kyber-1024 secret key (stays local)  */
    uint8_t pk_hqc[HQC5_PK_LEN]; /* Vehicle HQC-5 public key (sent to RSU)   */
    uint8_t sk_hqc[HQC5_SK_LEN]; /* Vehicle HQC-5 secret key (stays local)   */
    uint8_t ct_kyber[KYBER1024_CT_LEN]; /* Ciphertext from RSU (Kyber-1024 component)  */
    uint8_t ct_hqc[HQC5_CT_LEN]; /* Ciphertext from RSU (HQC-5 component)         */
    bool    has_ciphertext;             /* Set true after RSU calls kem_rsu_encapsulate */
    /* Authentication of KEM public keys — Fix-1 + Fix-2 repair */
    uint8_t          vehicle_id[16];                  /* identity bound into signed msg */
    uint8_t          keygen_nonce[NONCE_LEN];         /* freshness nonce                */
    uint8_t          keygen_sig[DILITHIUM5_SIG_LEN];  /* Dilithium5 sig over keygen msg */
    uint8_t          identity_pk[DILITHIUM5_PK_LEN];  /* PK_Vi (Dilithium5) — must match cert.pk_vi; NOT a KEM key */
    bool             keygen_sig_valid;                 /* Set true by kem_rsu_encapsulate*/
    CertificateRecord keygen_cert;                     /* CA cert: vehicle_id → PK_Vi    */
} KemExchangeState;

/* ══════════════════════════════════════════════════════════════════════════
 * 3. VEHICLE KEY RECORD  (Section 3.5)
 *    Stored at RSU key store, one per registered vehicle.
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t          vehicle_id[16];                  /* Unique vehicle identifier     */
    uint8_t          session_key[SESSION_KEY_LEN];    /* K_{Vi,nk} — HMAC session key  */
    uint8_t          sign_pub_key[DILITHIUM5_PK_LEN]; /* PK_{Vi} — Dilithium5 pub key  */
    uint32_t         lkh_leaf_index;                  /* Position in LKH tree          */
    uint64_t         key_creation_time_ms;            /* For key rotation tracking     */
    bool             revoked;                         /* Set by LKH revocation         */
    CertificateRecord cert;                           /* CA-issued cert binding id→pk  */
} VehicleKeyRecord;

/* ══════════════════════════════════════════════════════════════════════════
 * 3. BEACON MESSAGE  (Section 4.2)
 *    Wire format sent by every vehicle every 100 ms.
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* Standard beacon payload */
    uint8_t  vehicle_id[16];
    uint64_t sender_timestamp_ms;   /* τ_s */
    float    gps_lat;
    float    gps_lon;
    float    rssi_dbm;
    uint32_t sequence_number;
    uint8_t  link_id[8];            /* e_ij identifier */

    /* Cryptographic fields */
    uint8_t  nonce[NONCE_LEN];      /* 128-bit random nonce, fresh per message */
    uint8_t  mac[HMAC_SHA256_LEN];  /* HMAC-SHA256 over (payload || τ_s || nonce) */
} BeaconMessage;

/* ══════════════════════════════════════════════════════════════════════════
 * 4. NONCE CACHE  (Section 4.4)
 *    Per-sender circular cache of seen nonces (N_seen).
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  nonces[NONCE_CACHE_SIZE][NONCE_LEN];
    uint32_t head;
    uint32_t count;
} NonceCache;

/* ══════════════════════════════════════════════════════════════════════════
 * 5. CRYPTO VERIFY RESULT  (Section 4.4)
 * ══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    CRYPTO_ACCEPT               = 0,
    CRYPTO_DROP_INVALID_MAC     = 1,
    CRYPTO_DROP_STALE_TIMESTAMP = 2,
    CRYPTO_DROP_REPLAYED_NONCE  = 3,
    CRYPTO_DROP_REVOKED_KEY     = 4,
    /* Returned when provision_vehicle() cannot add a new vehicle because the
     * in-process key store is full (g_veh_count >= PIPELINE_MAX_VEH).
     * Every event must produce either a CryptoVerifiedEvent forwarded to the TGN
     * or a crypto_drop_log.csv entry with a reason code — KEYSTORE_FULL closes
     * the third option (silently vanishing from the audit trail on the 17th vehicle
     * when PIPELINE_MAX_VEH was 16). The handler must use continue, not break, so
     * remaining events in the batch are still processed.                          */
    CRYPTO_DROP_KEYSTORE_FULL   = 5
} CryptoVerifyResult;

/* ══════════════════════════════════════════════════════════════════════════
 * 6. THRESHOLD AGGREGATE SIGNATURE STRUCTS  (Section 5.2)
 * ══════════════════════════════════════════════════════════════════════════ */

/* Maximum time difference (ms) between an individual report's timestamp and
 * the enclosing AggregateReport.timestamp_ms.  A report outside this window
 * is rejected by verify_threshold_sig (Gate D) even if its Dilithium5 sig is
 * valid — prevents a compromised RSU from mixing stale individual reports into
 * a new aggregate.  Set to 5 s to cover the maximum beacon-interval jitter;
 * tighten this if the deployment uses a shorter aggregation period.           */
#define THRESH_REPORT_WINDOW_MS  5000u

/* Maximum time difference (ms) between a LocationBoundReport's
 * sender_timestamp_ms (inside the signed payload) and the RSU's recv_time_ms.
 * Applied by verify_single_witness (Gate D).  Same 5 s value as threshold
 * reports because both are generated at observation time and submitted within
 * the same aggregation window.                                                */
#define LOCBIND_FRESHNESS_WINDOW_MS  5000u

typedef struct {
    uint8_t  vehicle_id[16];
    uint8_t  msg_payload[256];                   /* Topology observation for Vi */
    /* Freshness fields — INCLUDED IN THE SIGNED PAYLOAD.
     * vehicle_sign_report signs msg_payload || timestamp_ms_le || nonce so both
     * are covered by individual_sig.  A compromised RSU cannot replay a captured
     * IndividualSignedReport into a new aggregate: the timestamp_ms gate in
     * verify_threshold_sig (Gate D) rejects it, and the nonce prevents identical
     * replays within the same window.  See threshold_sig.cc.                   */
    uint64_t timestamp_ms;                       /* ms since epoch, LE in signed buf */
    uint8_t  nonce[NONCE_LEN];                   /* 128-bit random per report   */
    uint8_t  individual_sig[DILITHIUM5_SIG_LEN]; /* Dilithium5 sig over msg_payload||ts||nonce */
    uint8_t  pub_key[DILITHIUM5_PK_LEN];         /* Dilithium5 public key       */
    /* Issue-1 fix: CA cert binding vehicle_id → pub_key.
     * verify_threshold_sig calls dilithium5_verify_cert(&cert) before trusting
     * pub_key — closes the same circular-trust gap that Fix-1/2 closed for KEM.
     * Also checks cert.pk_vi == pub_key as a consistency gate (Stage C).       */
    CertificateRecord cert;
} IndividualSignedReport;

typedef struct {
    IndividualSignedReport reports[MAX_REPORTS_PER_RSU];
    uint32_t n_reports;                         /* Actual count n              */
    /* threshold_t is set by the RSU in rsu_aggregate_reports() for logging.
     * SECURITY: verify_threshold_sig() IGNORES this field and recomputes t
     * from n_reports directly (see threshold_sig.cc line ~162).  A compromised
     * RSU that sets threshold_t = 1 has no effect on the verifier — the
     * recomputed value always enforces THRESHOLD_T_FLOOR regardless.           */
    uint32_t threshold_t;                       /* informational only — NOT used by verifier */
    /* agg_sig is HMAC-SHA256 (AGG_SIG_LEN = 32 bytes), NOT a Dilithium5 sig.
     * It binds agg_pk and individual sig prefixes; see rsu_aggregate_reports().
     * Sized as AGG_SIG_LEN, not DILITHIUM5_SIG_LEN, to avoid the prior
     * mismatch where 4563 bytes were always zero-padded garbage.
     *
     * SECURITY NOTE — integrity-only, NOT authentication:
     *   agg_pk is the XOR of all individual pub_key fields in this aggregate,
     *   each of which is embedded verbatim in the certs[] carried inside the
     *   same AggregateReport.  Any party who can read the report can compute
     *   agg_pk.  Because the HMAC key is fully public, agg_sig detects only
     *   ACCIDENTAL CORRUPTION of individual_sig bytes (Step 1 fast path in
     *   verify_threshold_sig) — it does NOT authenticate the aggregate against
     *   a deliberate forger who knows agg_pk.
     *   Only Step 2 / Gate C (dilithium5_verify_thresh on every full
     *   individual_sig) is the real cryptographic security gate.  Never skip
     *   or replace Gate C based on agg_sig verification alone.                 */
    uint8_t  agg_sig[AGG_SIG_LEN];
    uint8_t  agg_pk[DILITHIUM5_PK_LEN];         /* Aggregated public key       */
    uint64_t timestamp_ms;                       /* RSU-assigned window anchor; Gate D freshness anchor */
} AggregateReport;

typedef enum {
    THRESHOLD_SIG_PASS = 0,
    THRESHOLD_SIG_FAIL = 1
} ThresholdSigResult;

/* ══════════════════════════════════════════════════════════════════════════
 * 7. LOCATION-BINDING STRUCTS  (Section 6.2)
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  link_id[8];            /* e_ij identifier                        */
    float    reporter_lat;          /* pos_{Vk} latitude                      */
    float    reporter_lon;          /* pos_{Vk} longitude                     */
    float    reporter_alt;          /* pos_{Vk} altitude                      */
    float    rssi_from_vi_dbm;      /* RSSI_{Vk←Vi} in dBm                   */
    uint64_t sender_timestamp_ms;   /* τ_s                                    */
    uint8_t  nonce[NONCE_LEN];      /* Same nonce as HMAC module              */
    uint8_t  reporter_id[16];       /* V_k identity                           */
} LocationBindingPayload;

typedef struct {
    LocationBindingPayload payload;
    uint8_t signature[DILITHIUM5_SIG_LEN];  /* Dilithium5 sig over payload   */
    uint8_t pub_key[DILITHIUM5_PK_LEN];     /* PK_{Vk}                       */
    /* Fix-5 repair: RSU-measured RSSI (NOT from the signed payload).
     * The RSU fills these fields from its own physical-layer reception of Vk's
     * DSRC packet AFTER receipt; the vehicle never writes these fields.
     * verify_single_witness uses rsu_measured_rssi_dbm for the Friis check so
     * an attacker who forges reporter_lat/lon cannot also fake the RSU's
     * independently-measured signal strength.
     *
     * has_rsu_measurement must be set to true by the RSU whenever it populates
     * rsu_measured_rssi_dbm; the field is checked FIRST in verify_single_witness.
     * When false (stub / unit-test path), the signed payload value is used as a
     * fallback and a warning is emitted.  Do NOT leave has_rsu_measurement=false
     * in any live-radio build — doing so silently downgrades to the insecure
     * attacker-supplied RSSI path with no runtime indication.
     *
     * NOTE: 0.0f is NOT used as a "not populated" sentinel.  0.0f is a physically
     * plausible (if extreme) RSSI reading; using it as a sentinel would mask a
     * real RSU measurement near 0 dBm or a zero-initialised-but-not-set race.   */
    float rsu_measured_rssi_dbm;           /* RSU's own RSSI measurement (dBm) */
    bool  has_rsu_measurement;            /* true iff RSU populated the field  */
    /* Issue-1 fix: CA cert binding reporter_id → pub_key.
     * verify_single_witness calls dilithium5_verify_cert(&cert) before trusting
     * pub_key — same three-gate pattern as KEM (Fix-1/2) and threshold (above).
     * Passed in via create_location_bound_report(); RSU does NOT accept reports
     * whose pub_key isn't CA-certified for the claimed reporter_id.            */
    CertificateRecord cert;
} LocationBoundReport;

/* ══════════════════════════════════════════════════════════════════════════
 * 8. LKH TREE STRUCTS  (Section 7.2)
 * ══════════════════════════════════════════════════════════════════════════ */

#define LKH_MAX_LEAVES  1024u
#define LKH_KEY_LEN     SESSION_KEY_LEN

typedef struct {
    uint8_t  kek[LKH_KEY_LEN];           /* Key Encryption Key at this node  */
    uint32_t left;                        /* Index of left child (0 = none)   */
    uint32_t right;                       /* Index of right child             */
    uint32_t parent;                      /* Index of parent (UINT32_MAX=root)*/
    bool     is_leaf;
    uint8_t  vehicle_id[16];             /* Only set for leaf nodes           */
    uint8_t  session_key[LKH_KEY_LEN];   /* K_{Vi,nk} — only for leaves      */
    bool     revoked;
} LKHNode;

typedef struct {
    LKHNode  nodes[LKH_MAX_LEAVES * 2];  /* Complete binary tree (0-indexed)  */
    uint32_t n_leaves;
    uint32_t root_index;
    uint8_t  group_key[LKH_KEY_LEN];     /* K_G shared by all active vehicles */
} LKHTree;

/* ══════════════════════════════════════════════════════════════════════════
 * 9. CRYPTO → TGN INTERFACE STRUCT  (Section 8.2)
 *    ONLY data structure that crosses the Crypto→TGN boundary.
 *    Passed to tgn_ingest_event() after CRYPTO_ACCEPT.
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* Identity */
    uint8_t  vehicle_id[16];         /* id_v (Eq. 3.19)                     */
    uint8_t  link_id[8];             /* e_ij identifier                     */
    uint8_t  reporter_id[16];        /* V_k who reported (for ME analysis)  */

    /* Temporal features — direct inputs to TGN feature vector x_v (Eq.3.19)*/
    uint64_t sender_timestamp_ms;    /* τ_s^(v) — recency feature           */
    uint64_t recv_timestamp_ms;      /* τ_r — for edge weight A_{uv}(t)     */
    uint32_t sequence_number;        /* For Δs_v — sequence gap feature     */
    uint32_t beacon_count_in_window; /* c_v^W — liveness feature            */

    /* Location features (for ME-S3 and location-binding verification) */
    float    reporter_lat;           /* pos_{Vk}                            */
    float    reporter_lon;
    float    rssi_from_vi_dbm;       /* RSSI_{Vk←Vi}                        */

    /* Reporter density (for ME-S1) */
    uint32_t reporter_count;         /* ρ_v — current |R(e_ij, t)|          */

    /* Crypto metadata (informational — TGN does not use for inference) */
    bool     location_binding_verified;  /* true if Module 4 passed         */
    bool     threshold_sig_verified;     /* true if Module 3 passed         */
    uint8_t  crypto_filter_result;       /* Always CRYPTO_ACCEPT here       */

    /* Ground-truth label — set by pipeline from pem_event_log.csv attack_label.
     * Controller-origin attacks reach here with is_attack=true (crypto layer
     * cannot block them since the controller holds valid credentials). */
    bool     is_attack;
} CryptoVerifiedEvent;

/* ══════════════════════════════════════════════════════════════════════════
 * 10. TGN → BLOCKCHAIN INTERFACE STRUCTS  (Sections 9.1, 9.4)
 * ══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    ATTACK_TTW  = 0,
    ATTACK_BSHH = 1,
    ATTACK_ME   = 2
} AttackVariant;

/*
 * DetectionAlert — output of TGN (Algorithm 2), input to TemporalEchoMitigator.
 * ONLY data structure that crosses TGN→Blockchain boundary.
 *
 * triggered_sigs bitmask:
 *   bits 0–2 : TTW-S1, TTW-S2, TTW-S3
 *   bits 3–5 : BSHH-S1, BSHH-S2, BSHH-S3
 *   bits 6–8 : ME-S1, ME-S2, ME-S3
 */
typedef struct {
    uint8_t       vehicle_id[16];
    AttackVariant variant;           /* α ∈ {TTW, BSHH, ME}                */
    float         anomaly_score;     /* ŷ_v ∈ (0,1) from Eq.3.23 (FS)
                                        or s(e) from Eq.3.11 (LW)          */
    uint32_t      triggered_sigs;    /* S_trig bitmask                      */
    uint64_t      alert_timestamp;   /* t_alert in ms                       */
    bool          from_lw_path;      /* true = LW detector                  */
    bool          from_fs_path;      /* true = FS/TGN detector              */
} DetectionAlert;

/* RSU Beacon Evidence Record B_nk(t) — ground truth submitted to Fabric   */
typedef struct {
    uint8_t  rsu_id[16];
    uint64_t interval_timestamp_ms;
    uint32_t n_vehicles;
    struct {
        uint8_t  vehicle_id[16];
        uint64_t sender_ts_ms;       /* τ_s                                 */
        float    gps_lat;
        float    gps_lon;
        float    rssi_dbm;
        uint8_t  rsu_sig[DILITHIUM5_SIG_LEN]; /* RSU Dilithium5 sig over record */
    } observations[MAX_OBSERVATIONS_PER_RSU];
} BeaconEvidenceRecord;

/* ══════════════════════════════════════════════════════════════════════════
 * 11. DILITHIUM5 API — shared across all modules  (Section 3.3)
 *
 * Single canonical implementation in dilithium.cc.
 * Consumed by: kem.cc, threshold_sig.cc, location_binding.cc
 *
 * With liboqs: OQS_SIG_alg_dilithium_5 (FIPS 204 ML-DSA-87) — Level 5
 * Without:     HMAC-SHA256 stub (simulation only, NOT quantum-resistant)
 *
 * Fix-7 (domain separation): Use the domain-separated variants below for all
 * signing; the base dilithium5_sign/verify are for internal use only.
 * ══════════════════════════════════════════════════════════════════════════ */

/* Generate long-term identity keypair SKVk / PKVk (called once at registration) */
void dilithium5_keygen(uint8_t pk[DILITHIUM5_PK_LEN],
                        uint8_t sk[DILITHIUM5_SK_LEN]);

/* Base sign/verify — internal; use domain-separated wrappers below */
void dilithium5_sign(const uint8_t *msg,    size_t msg_len,
                      const uint8_t  sk[DILITHIUM5_SK_LEN],
                      uint8_t        sig_out[DILITHIUM5_SIG_LEN],
                      size_t        *sig_len_out);

bool dilithium5_verify(const uint8_t *msg,      size_t msg_len,
                        const uint8_t  sig[DILITHIUM5_SIG_LEN],
                        size_t         sig_len,
                        const uint8_t  pk[DILITHIUM5_PK_LEN]);

/* Fix-7 — Domain-separated signing/verification.
 *
 * Each variant prepends a distinct ASCII domain tag before signing, so a
 * threshold sig cannot be replayed as a location-bound sig and vice versa.
 *
 *   THRESH:   for IndividualSignedReport (threshold_sig.cc)
 *   LOCBIND:  for LocationBoundReport    (location_binding.cc)
 *   KEM_AUTH: for KemExchangeState keygen message (kem.cc)        Fix-1
 */
void dilithium5_sign_thresh(const uint8_t *msg, size_t msg_len,
                              const uint8_t  sk[DILITHIUM5_SK_LEN],
                              uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len);

bool dilithium5_verify_thresh(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                               const uint8_t  pk[DILITHIUM5_PK_LEN]);

void dilithium5_sign_locbind(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sk[DILITHIUM5_SK_LEN],
                               uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len);

bool dilithium5_verify_locbind(const uint8_t *msg, size_t msg_len,
                                const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                                const uint8_t  pk[DILITHIUM5_PK_LEN]);

void dilithium5_sign_kem_auth(const uint8_t *msg, size_t msg_len,
                               const uint8_t  sk[DILITHIUM5_SK_LEN],
                               uint8_t sig[DILITHIUM5_SIG_LEN], size_t *sig_len);

bool dilithium5_verify_kem_auth(const uint8_t *msg, size_t msg_len,
                                 const uint8_t  sig[DILITHIUM5_SIG_LEN], size_t sig_len,
                                 const uint8_t  pk[DILITHIUM5_PK_LEN]);

/* Fix-2 — CA certificate API (dilithium.cc).
 * teta_ca_init() must be called once before any cert operations.
 * In simulation: CA keypair is static (g_ca_pk/g_ca_sk in dilithium.cc).
 * In production: CA keypair is provisioned by the consortium PKI. */
void teta_ca_init(void);
void teta_ca_get_pk(uint8_t ca_pk[DILITHIUM5_PK_LEN]);
void dilithium5_issue_cert(const uint8_t vehicle_id[16],
                            const uint8_t pk_vi[DILITHIUM5_PK_LEN],
                            uint64_t      issued_at_ms,
                            CertificateRecord *cert_out);
bool dilithium5_verify_cert(const CertificateRecord *cert);

/* Issue-4 fix — domain-separated CA cert sign/verify wrappers.
 * These prepend TETA_DS_CA_CERT to the raw cert payload before signing,
 * matching the domain-separation pattern used by all other signing paths
 * (THRESH, LOCBIND, KEM-AUTH).  dilithium5_issue_cert and
 * dilithium5_verify_cert now use these internally instead of calling the
 * base dilithium5_sign/dilithium5_verify with a manually built message.  */
void dilithium5_sign_ca_cert(const uint8_t *payload, size_t payload_len,
                              const uint8_t sk[DILITHIUM5_SK_LEN],
                              uint8_t sig_out[DILITHIUM5_SIG_LEN]);
bool dilithium5_verify_ca_cert(const uint8_t *payload, size_t payload_len,
                                const uint8_t sig[DILITHIUM5_SIG_LEN],
                                const uint8_t pk[DILITHIUM5_PK_LEN]);

/* Issue-2 fix — certificate revocation list (CRL) in dilithium.cc.
 * cert_revoke_vehicle adds a vehicle_id to the module-static CRL;
 * dilithium5_verify_cert returns false for any revoked vehicle_id even
 * if the CA signature is valid.  Called by mark_key_revoked so a single
 * revocation event invalidates both the session key and the identity cert. */
void cert_revoke_vehicle(const uint8_t vehicle_id[16]);
bool cert_is_revoked(const uint8_t vehicle_id[16]);

/* ══════════════════════════════════════════════════════════════════════════
 * 12. FORWARD DECLARATIONS — cross-module function interfaces
 * ══════════════════════════════════════════════════════════════════════════ */

/* Legacy stub, unreachable in the routing.cc build: defined and called only
 * inside crypto_pipeline.cc, a fully standalone tool (own main(), separate
 * Makefile target) that is never #included by routing.cc. routing.cc pulls
 * in this header directly but never calls tgn_ingest_event(), so the extern
 * below resolves to nothing in that build — harmless as long as it stays
 * unreferenced there. (The "Section 8, Eq. 3.19" citation attached to this
 * boundary elsewhere in crypto_pipeline.cc does not correspond to anything
 * in the current thesis: this paper has no Section 8, and Eq. 3.19 is the
 * TGN graph-snapshot definition G_t = (V_t, E_t, X_t, A_t), not a crypto→TGN
 * handoff — treat that citation as stale, not as a spec reference.) */
extern void tgn_ingest_event(const CryptoVerifiedEvent *event);

/* Called from crypto_pipeline.cc / lkh_mgmt.cc after blockchain alert */
extern void lkh_init(LKHTree *tree, const uint8_t (*vehicle_ids)[16], uint32_t n);
extern void lkh_revoke_vehicle(LKHTree *tree, const uint8_t vehicle_id[16]);
extern void mark_key_revoked(VehicleKeyRecord *keystore, const uint8_t vehicle_id[16]);

/* Fix-3 — unified revocation: register the VehicleKeyRecord keystore with lkh_mgmt
 * so lkh_revoke_vehicle automatically calls mark_key_revoked on the same event. */
extern void lkh_set_keystore(VehicleKeyRecord *ks, uint32_t ks_size);

#ifdef __cplusplus
}
#endif
