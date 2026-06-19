/*
 * teta_guard_types.h — Shared struct definitions for TETA-Guard crypto layer
 *
 * All structs, enums, and constants that cross module boundaries are defined
 * here.  Every crypto .cc file includes this header.
 *
 * Three canonical interface structs (from the implementation guide):
 *   BeaconMessage       — vehicle wire format  (crypto input)
 *   CryptoVerifiedEvent — crypto → TGN boundary (Section 8.2)
 *   DetectionAlert      — TGN  → Blockchain boundary (Section 9.1, Eq. 3.36)
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
#define PROPAGATION_TOL_MS       10u        /* ε = 10 ms propagation budget  */
#define FRESHNESS_WINDOW_MS     (BEACON_INTERVAL_MS + PROPAGATION_TOL_MS)

#define NONCE_LEN                16u        /* 128-bit nonce                 */
#define NONCE_CACHE_SIZE       4096u        /* Circular nonce cache per sender*/
#define SESSION_KEY_LEN          32u        /* K_{Vi,nk} — 256-bit HMAC key  */
#define HMAC_SHA256_LEN          32u        /* HMAC-SHA256 tag               */

/* Dilithium2 (NIST ML-DSA, FIPS 204) — exact sizes per liboqs */
#define DILITHIUM2_SIG_LEN     2420u        /* OQS_SIG_dilithium_2_length_signature    */
#define DILITHIUM2_PK_LEN      1312u        /* OQS_SIG_dilithium_2_length_public_key   */
#define DILITHIUM2_SK_LEN      2528u        /* OQS_SIG_dilithium_2_length_secret_key   */

#define R_COMM_METERS          300.0f       /* DSRC communication range (m)  */
#define RSSI_MIN_DBM           -85.0f       /* RSSImin at r_comm, 5.9 GHz    */

#define MAX_VEHICLES            256u        /* Max vehicles per trusted node */
#define MAX_REPORTS_PER_RSU      64u        /* Max individual sigs per AggregateReport */
#define MAX_OBSERVATIONS_PER_RSU 200u       /* Max obs in BeaconEvidenceRecord */

/* Kyber-512 wire sizes (liboqs OQS_KEM_alg_kyber_512 / ML-KEM-512 FIPS 203) */
#define KYBER512_PK_LEN   800u   /* OQS_KEM_kyber_512_length_public_key    */
#define KYBER512_SK_LEN  1632u   /* OQS_KEM_kyber_512_length_secret_key    */
#define KYBER512_CT_LEN   768u   /* OQS_KEM_kyber_512_length_ciphertext    */
#define KYBER512_SS_LEN    32u   /* OQS_KEM_kyber_512_length_shared_secret */

/* Saber wire sizes (liboqs OQS_KEM_alg_saber — the actual paper KEM partner) */
#define SABER_PK_LEN      992u   /* OQS_KEM_saber_length_public_key        */
#define SABER_SK_LEN     2304u   /* OQS_KEM_saber_length_secret_key        */
#define SABER_CT_LEN     1088u   /* OQS_KEM_saber_length_ciphertext        */
#define SABER_SS_LEN       32u   /* OQS_KEM_saber_length_shared_secret     */

/*
 * KemExchangeState — held by vehicle during Section 3.3 handshake.
 * Step 1: kem_vehicle_keygen()  fills pk_sk_* fields.
 * Step 3: kem_rsu_encapsulate() fills ct_* fields (RSU side).
 * Step 4: kem_vehicle_decapsulate() consumes ct_* + sk_* → session key.
 *
 * Buffer sizes: Kyber-512 component uses KYBER512_* sizes.
 *               Saber component uses SABER_* sizes (larger — 992 vs 800 byte pk).
 */
typedef struct {
    uint8_t pk_kyber[KYBER512_PK_LEN]; /* Vehicle Kyber-512 public key (sent to RSU) */
    uint8_t sk_kyber[KYBER512_SK_LEN]; /* Vehicle Kyber-512 secret key (stays local) */
    uint8_t pk_saber[SABER_PK_LEN];   /* Vehicle Saber public key (sent to RSU)      */
    uint8_t sk_saber[SABER_SK_LEN];   /* Vehicle Saber secret key (stays local)      */
    uint8_t ct_kyber[KYBER512_CT_LEN]; /* Ciphertext from RSU (Kyber component)      */
    uint8_t ct_saber[SABER_CT_LEN];   /* Ciphertext from RSU (Saber component)       */
    bool    has_ciphertext;            /* Set true after RSU calls kem_rsu_encapsulate */
} KemExchangeState;

/* ══════════════════════════════════════════════════════════════════════════
 * 2. VEHICLE KEY RECORD  (Section 3.5)
 *    Stored at RSU key store, one per registered vehicle.
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  vehicle_id[16];                /* Unique vehicle identifier     */
    uint8_t  session_key[SESSION_KEY_LEN];  /* K_{Vi,nk} — HMAC session key  */
    uint8_t  sign_pub_key[DILITHIUM2_PK_LEN]; /* PK_{Vi} — Dilithium2 pub key*/
    uint32_t lkh_leaf_index;                /* Position in LKH tree          */
    uint64_t key_creation_time_ms;          /* For key rotation tracking     */
    bool     revoked;                       /* Set by LKH revocation         */
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
    CRYPTO_DROP_REVOKED_KEY     = 4
} CryptoVerifyResult;

/* ══════════════════════════════════════════════════════════════════════════
 * 6. THRESHOLD AGGREGATE SIGNATURE STRUCTS  (Section 5.2)
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t vehicle_id[16];
    uint8_t msg_payload[256];                   /* Topology observation for Vi */
    uint8_t individual_sig[DILITHIUM2_SIG_LEN]; /* Dilithium2 signature        */
    uint8_t pub_key[DILITHIUM2_PK_LEN];         /* Dilithium2 public key       */
} IndividualSignedReport;

typedef struct {
    IndividualSignedReport reports[MAX_REPORTS_PER_RSU];
    uint32_t n_reports;                         /* Actual count n              */
    uint32_t threshold_t;                       /* t = ⌊n/2⌋ + 1              */
    uint8_t  agg_sig[DILITHIUM2_SIG_LEN];       /* Aggregated signature        */
    uint8_t  agg_pk[DILITHIUM2_PK_LEN];         /* Aggregated public key       */
    uint64_t timestamp_ms;
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
    uint8_t signature[DILITHIUM2_SIG_LEN];  /* Dilithium2 sig over payload   */
    uint8_t pub_key[DILITHIUM2_PK_LEN];     /* PK_{Vk}                       */
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
        uint8_t  rsu_sig[DILITHIUM2_SIG_LEN]; /* RSU Dilithium2 sig over record */
    } observations[MAX_OBSERVATIONS_PER_RSU];
} BeaconEvidenceRecord;

/* ══════════════════════════════════════════════════════════════════════════
 * 11. DILITHIUM2 API — shared across all modules  (Section 3.3)
 *
 * Single canonical implementation in dilithium.cc.
 * Consumed by: kem.cc, threshold_sig.cc, location_binding.cc
 *
 * With liboqs: OQS_SIG_alg_dilithium_2 (FIPS 204 ML-DSA-44)
 * Without:     HMAC-SHA256 stub (simulation only, NOT quantum-resistant)
 * ══════════════════════════════════════════════════════════════════════════ */

/* Generate long-term identity keypair SKVk / PKVk (called once at registration) */
void dilithium2_keygen(uint8_t pk[DILITHIUM2_PK_LEN],
                        uint8_t sk[DILITHIUM2_SK_LEN]);

/* σVk = Sign(SKVk, m')  — sign a topology report or heartbeat */
void dilithium2_sign(const uint8_t *msg,    size_t msg_len,
                      const uint8_t  sk[DILITHIUM2_SK_LEN],
                      uint8_t        sig_out[DILITHIUM2_SIG_LEN],
                      size_t        *sig_len_out);

/* Verify(σVk, PKVk) = 1  — returns true iff signature is valid */
bool dilithium2_verify(const uint8_t *msg,      size_t msg_len,
                        const uint8_t  sig[DILITHIUM2_SIG_LEN],
                        size_t         sig_len,
                        const uint8_t  pk[DILITHIUM2_PK_LEN]);

/* ══════════════════════════════════════════════════════════════════════════
 * 12. FORWARD DECLARATIONS — cross-module function interfaces
 * ══════════════════════════════════════════════════════════════════════════ */

/* Called from crypto_pipeline.cc after CRYPTO_ACCEPT — TGN already implements this */
extern void tgn_ingest_event(const CryptoVerifiedEvent *event);

/* Called from crypto_pipeline.cc / lkh_mgmt.cc after blockchain alert */
extern void lkh_revoke_vehicle(LKHTree *tree, const uint8_t vehicle_id[16]);
extern void mark_key_revoked(VehicleKeyRecord *keystore, const uint8_t vehicle_id[16]);

#ifdef __cplusplus
}
#endif
