# TETA-Guard Cryptographic Layer — Complete Technical Guide

**Project:** Transfer-Learned GNN and Blockchain-Based Framework for Temporal Fraud Detection:
Countering Temporal-Echo Topology Poisoning Attacks in SDVNs
**Layer:** Layer 2 — Pre-Detection Cryptographic Filter
**Language:** C++17 (OpenSSL + optional liboqs post-quantum)
**Security Level:** NIST Level 5 (Kyber-1024, FireSaber, Dilithium5)
**Paper reference:** Sections 3.3, 4.4, 5.2, 6.2, 7.2, 8, 9

> **Purpose of this document:** Written for a teammate who has never touched cryptography before.
> Covers everything from first principles — what a hash is, what a key is — through every
> implementation detail of all six crypto modules, including all security fixes applied during
> development. Read Section 1 through 5 if you are new. Start at Section 6 if you already know
> basic crypto.

---

## Table of Contents

1. [Why Does the System Need Cryptography?](#1-why-does-the-system-need-cryptography)
2. [Beginner Concepts — Read This First](#2-beginner-concepts--read-this-first)
   - 2.1 [What is a Hash?](#21-what-is-a-hash)
   - 2.2 [What is an HMAC?](#22-what-is-an-hmac)
   - 2.3 [What is a Digital Signature?](#23-what-is-a-digital-signature)
   - 2.4 [What is a Key Encapsulation Mechanism (KEM)?](#24-what-is-a-key-encapsulation-mechanism-kem)
   - 2.5 [What is Post-Quantum Cryptography?](#25-what-is-post-quantum-cryptography)
   - 2.6 [What is a Nonce?](#26-what-is-a-nonce)
   - 2.7 [What is Key Revocation?](#27-what-is-key-revocation)
3. [System Position — Where Crypto Fits](#3-system-position--where-crypto-fits)
4. [File Structure](#4-file-structure)
5. [The Three Cryptographic Primitives Used](#5-the-three-cryptographic-primitives-used)
   - 5.1 [HMAC-SHA256 — Message Authentication](#51-hmac-sha256--message-authentication)
   - 5.2 [Dilithium5 — Digital Signatures](#52-dilithium5--digital-signatures)
   - 5.3 [Kyber-1024 + FireSaber — Hybrid KEM](#53-kyber-1024--firesaber--hybrid-kem)
6. [The Seven Verification Steps — Algorithm 3 (LW-MITIGATE)](#6-the-seven-verification-steps--algorithm-3-lw-mitigate)
7. [Module 0 — dilithium.cc (Shared Dilithium5 Module)](#7-module-0--dilithiumcc-shared-dilithium5-module)
   - 7.1 [What it does](#71-what-it-does)
   - 7.2 [Domain Separation — Fix-7](#72-domain-separation--fix-7)
   - 7.3 [CA Certificate API — Fix-2](#73-ca-certificate-api--fix-2)
   - 7.4 [CRL Revocation — Fix-3](#74-crl-revocation--fix-3)
   - 7.5 [Stub Mode](#75-stub-mode)
8. [Module 1 — kem.cc (Kyber-1024 + FireSaber Hybrid KEM)](#8-module-1--kemcc-kyber-1024--firesaber-hybrid-kem)
   - 8.1 [Why a Hybrid KEM?](#81-why-a-hybrid-kem)
   - 8.2 [KEM Handshake — Step by Step](#82-kem-handshake--step-by-step)
   - 8.3 [Session Key Derivation — HKDF](#83-session-key-derivation--hkdf)
   - 8.4 [Authenticated KEM — Fix-1](#84-authenticated-kem--fix-1)
   - 8.5 [Wire Sizes Reference](#85-wire-sizes-reference)
9. [Module 2 — hmac_filter.cc (HMAC + Freshness + Nonce)](#9-module-2--hmac_filtercc-hmac--freshness--nonce)
   - 9.1 [The Three Gates of lw_mitigate()](#91-the-three-gates-of-lw_mitigate)
   - 9.2 [beacon_sign() — Vehicle Side](#92-beacon_sign--vehicle-side)
   - 9.3 [Return Codes](#93-return-codes)
   - 9.4 [Latency Budget](#94-latency-budget)
10. [Module 3 — threshold_sig.cc (Dilithium5 Threshold Aggregate)](#10-module-3--threshold_sigcc-dilithium5-threshold-aggregate)
    - 10.1 [What is a Threshold Signature?](#101-what-is-a-threshold-signature)
    - 10.2 [Data Path — Vehicle to RSU to Controller](#102-data-path--vehicle-to-rsu-to-controller)
    - 10.3 [verify_threshold_sig() — Four Gates](#103-verify_threshold_sig--four-gates)
    - 10.4 [Threshold Floor — Fix-4](#104-threshold-floor--fix-4)
    - 10.5 [agg_sig Security Note](#105-agg_sig-security-note)
11. [Module 4 — location_binding.cc (ME Location Proof)](#11-module-4--location_bindingcc-me-location-proof)
    - 11.1 [Why Location Binding?](#111-why-location-binding)
    - 11.2 [verify_single_witness() — Four Checks](#112-verify_single_witness--four-checks)
    - 11.3 [RSU-Measured RSSI — Fix-5](#113-rsu-measured-rssi--fix-5)
    - 11.4 [Quorum Requirement — Eqs. 3.27–3.28](#114-quorum-requirement--eqs-327328)
12. [Module 5 — lkh_mgmt.cc (LKH Key Revocation)](#12-module-5--lkh_mgmtcc-lkh-key-revocation)
    - 12.1 [Why Not Just Delete the Key?](#121-why-not-just-delete-the-key)
    - 12.2 [Binary LKH Tree Structure](#122-binary-lkh-tree-structure)
    - 12.3 [O(log n) Revocation Proof](#123-olog-n-revocation-proof)
    - 12.4 [IPC Integration — Fix-6](#124-ipc-integration--fix-6)
    - 12.5 [Unified Revocation — Fix-3](#125-unified-revocation--fix-3)
13. [Module 6 — crypto_pipeline.cc (End-to-End Orchestrator)](#13-module-6--crypto_pipelinecc-end-to-end-orchestrator)
    - 13.1 [Input / Output Files](#131-input--output-files)
    - 13.2 [Pipeline Execution Order](#132-pipeline-execution-order)
    - 13.3 [CryptoVerifiedEvent — Crypto → TGN Boundary](#133-cryptoverifiedevent--crypto--tgn-boundary)
    - 13.4 [DetectionAlert — TGN → Blockchain Boundary](#134-detectionalert--tgn--blockchain-boundary)
14. [All Shared Structs — teta_guard_types.h](#14-all-shared-structs--teta_guard_typesh)
15. [Security Fixes — Complete Reference](#15-security-fixes--complete-reference)
16. [Cryptographic Effectiveness by Attack Variant](#16-cryptographic-effectiveness-by-attack-variant)
17. [Build System — Makefile Reference](#17-build-system--makefile-reference)
    - 17.1 [Stub Mode vs PQC Mode](#171-stub-mode-vs-pqc-mode)
    - 17.2 [Build Targets](#172-build-targets)
    - 17.3 [Object Dependencies](#173-object-dependencies)
18. [Phase 8 Test Suite — 47/47 Tests](#18-phase-8-test-suite--4747-tests)
    - 18.1 [What the Tests Cover](#181-what-the-tests-cover)
    - 18.2 [Running Tests](#182-running-tests)
    - 18.3 [ASan + UBSan Build](#183-asan--ubsan-build)
19. [Output Files Reference](#19-output-files-reference)
20. [Constants Reference — teta_guard_types.h](#20-constants-reference--teta_guard_typesh)
21. [Full Pipeline Walk-Through: A Single Beacon Arriving at the RSU](#21-full-pipeline-walk-through-a-single-beacon-arriving-at-the-rsu)
22. [Common Errors and Fixes](#22-common-errors-and-fixes)

---

## 1. Why Does the System Need Cryptography?

The SDVN (Software-Defined Vehicular Network) controller trusts topology updates it receives from vehicles and RSUs. Attackers exploit this trust by:

- **TTW:** Replaying old topology packets with forged future timestamps (link appears alive when it is dead)
- **BSHH:** Replaying old heartbeats impersonating another vehicle (controller thinks a vehicle is still present)
- **ME:** Echoing one real link observation through fake reporters (controller believes phantom paths exist)

Without cryptography, the controller has no way to tell a legitimate update from a forged one. The crypto layer sits **before** the PEM detector and TGN. It filters out packets that fail authentication — attackers who do not hold the correct session key are blocked entirely before the expensive detection logic even runs.

The core principle:

```
Crypto layer = "Does this packet come from a legitimate vehicle?"
TGN / PEM   = "Is this legitimate vehicle behaving suspiciously?"
Blockchain  = "Record the verdict and enforce mitigation"
```

Cryptography stops attacker vehicles (S1/S2 variants). It cannot stop a malicious controller (S3/S4) because the controller holds valid credentials. That is handled by the TGN and blockchain layer.

---

## 2. Beginner Concepts — Read This First

### 2.1 What is a Hash?

A hash function takes any input (a file, a packet, a string) and produces a fixed-length output called a **digest**. SHA-256 always produces 32 bytes (256 bits).

Key properties:
- Same input → always same output
- Change one byte of input → completely different output
- Cannot reverse: given the digest, you cannot recover the original input
- Collision-resistant: extremely hard to find two inputs with the same digest

```
SHA-256("hello") = 2cf24db...  (32 bytes)
SHA-256("hellO") = completely different 32 bytes
```

This is used in the system to detect if a packet was tampered with.

### 2.2 What is an HMAC?

**HMAC** (Hash-based Message Authentication Code) is SHA-256 with a secret key mixed in. Only someone who knows the key can produce the correct HMAC for a given message.

```
HMAC-SHA256(key, message) = 32-byte tag

Sender:   tag = HMAC(K_Vi, beacon_payload || timestamp || nonce)
Receiver: recompute tag, compare → if mismatch → REJECT
```

In this system, the key is `K_{Vi,nk}` — the session key established per-vehicle via KEM. An attacker who intercepts a beacon cannot forge a valid HMAC for a new one because they do not have the session key.

### 2.3 What is a Digital Signature?

A digital signature is like an HMAC but asymmetric: the **signer** uses a private key (only they hold), and anyone can **verify** using the matching public key.

```
Key generation: (public_key, secret_key) = keygen()
Sign:           signature = Sign(secret_key, message)
Verify:         true/false = Verify(public_key, message, signature)
```

This system uses **Dilithium5** (FIPS 204 ML-DSA-87), a post-quantum digital signature scheme, for:
- Signing individual vehicle topology reports
- RSU aggregate signatures
- Location-binding proofs
- CA certificate issuance

### 2.4 What is a Key Encapsulation Mechanism (KEM)?

A KEM lets two parties establish a shared secret without sending the secret over the network. Think of it as: the receiver locks an empty box (encapsulates), the sender puts a secret inside and sends it back (the ciphertext), and only the receiver's key can open it (decapsulate).

```
Receiver:  (public_key, secret_key) = KEM.KeyGen()
           Send public_key to sender

Sender:    (ciphertext, shared_secret) = KEM.Encapsulate(public_key)
           Send ciphertext back to receiver

Receiver:  shared_secret = KEM.Decapsulate(secret_key, ciphertext)
```

Both sides now hold the same `shared_secret` which becomes the HMAC session key. Nobody on the network ever saw the secret.

This system uses a **hybrid KEM**: Kyber-1024 + FireSaber combined, so if one algorithm is broken, the other still protects.

### 2.5 What is Post-Quantum Cryptography?

Classical public-key crypto (RSA, ECC, Diffie-Hellman) can be broken by a sufficiently powerful quantum computer using Shor's algorithm. **Post-quantum cryptography (PQC)** uses different mathematical problems that quantum computers cannot solve efficiently.

This system uses three NIST PQC standards (all at Security Level 5 — the highest):

| Primitive | Standard | Hardness assumption |
|-----------|----------|---------------------|
| Kyber-1024 | ML-KEM-1024 (FIPS 203) | Module-LWE |
| FireSaber | Saber family (NIST finalist) | Module-LWR |
| Dilithium5 | ML-DSA-87 (FIPS 204) | Module-LWE |

Without liboqs installed, the system falls back to HMAC-SHA256 stubs (simulation only). The stubs print prominent warnings at startup.

### 2.6 What is a Nonce?

A nonce ("number used once") is a random value included in every message. It prevents **replay attacks**: if an attacker captures and re-sends an old valid message, the receiver's nonce cache recognises the nonce was already seen and rejects it.

```
Vehicle generates: nonce = 128 random bits
Includes nonce in beacon, signs/MACs over it
Receiver checks: is this nonce in N_seen? → YES → DROP (replay)
                                            NO  → accept, add to N_seen
```

Nonce cache size: 4096 entries per sender (`NONCE_CACHE_SIZE`).

### 2.7 What is Key Revocation?

When a vehicle is caught attacking, you need to stop it from sending valid future packets. Revocation invalidates its session key so the HMAC filter will reject all its future messages.

The naive approach is to send a new key to every remaining vehicle — but with 1000 vehicles that is 1000 key transmissions. **LKH (Logical Key Hierarchy)** reduces this to O(log n) updates using a binary tree of keys. Only the nodes on the path from the revoked leaf to the root need to change.

---

## 3. System Position — Where Crypto Fits

```
┌──────────────────────────────────────────────────────────────────────┐
│  NS-3.35 Simulation (routing.cc)                                     │
│  3 attack families × 4 placements = 12 scenarios                    │
│  Output: pem_event_log.csv   tgn_alerts.json                         │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ pem_event_log.csv
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 2 — Pre-Detection Cryptographic Filter  (crypto/)             │
│                                                                      │
│  ① KEM lookup           kem.cc           Session key K_{Vi,nk}      │
│  ② HMAC integrity       hmac_filter.cc   Eq. 3.14                   │
│  ③ Timestamp freshness  hmac_filter.cc   Eq. 3.15                   │
│  ④ Nonce novelty        hmac_filter.cc   Eq. 3.16                   │
│  ⑤ Threshold aggregate  threshold_sig.cc Eq. 3.24 (RSU reports)     │
│  ⑥ Location binding     location_binding.cc Eqs. 3.25–3.28 (ME)    │
│  ⑦ LKH revocation       lkh_mgmt.cc      Eq. 3.17                  │
│                                                                      │
│  Orchestrated by: crypto_pipeline.cc                                 │
│                                                                      │
│  Output: crypto_verified_events.csv  (ACCEPT only)                   │
│          crypto_drop_log.csv          (REJECT with reason)           │
│          beacon_evidence.csv          (RSU GPS evidence)             │
│          tgn_alerts_crypto.json       (verified alerts → blockchain) │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ CryptoVerifiedEvent
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  TGN / PEM Detector  (tgn_detector.cc)                               │
│  Transfer-Learned GNN anomaly detection                              │
│  Output: tgn_alerts.json → tgn_alerts_crypto.json                   │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ DetectionAlert
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Hyperledger Fabric Blockchain                                        │
│  FS-MITIGATE smart contract                                           │
│  Immutable audit trail + FlowMod enforcement                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. File Structure

```
crypto/
├── teta_guard_types.h        ← ALL shared structs, constants, function declarations
│                               Every .cc file includes this — it is the contract
├── dilithium.cc              ← Section 3.3: Dilithium5 sign/verify + CA + CRL
├── kem.cc                    ← Module 1: Kyber-1024 + FireSaber Hybrid KEM
├── hmac_filter.cc            ← Module 2: HMAC + timestamp freshness + nonce
├── threshold_sig.cc          ← Module 3: Dilithium5 threshold aggregate signatures
├── location_binding.cc       ← Module 4: ME location-binding proofs
├── lkh_mgmt.cc               ← Module 5: LKH key revocation tree
├── crypto_pipeline.cc        ← Module 6: End-to-end orchestrator
├── Makefile                  ← Build system (stub/PQC modes, test targets)
│
├── phase8_tests              ← Built by make phase8_tests — 47-test harness
├── phase8_sanitize           ← Built by make phase8_sanitize — same under ASan+UBSan
├── fuzz_lw_mitigate          ← 500 K iteration byte-level fuzzer (Algorithm 3)
│
├── crypto_verified_events.csv  ← Events that passed all crypto gates → TGN
├── crypto_drop_log.csv         ← Rejected events with drop reason code
├── beacon_evidence.csv         ← RSU GPS + RSSI observations
├── tgn_alerts_crypto.json      ← Crypto-verified subset of tgn_alerts.json
├── crypto_layer_log.txt        ← Step-by-step per-packet trace with hex keys
├── lkh_revocation_log.csv      ← Per-revocation KEK update count
├── kem_session_keys.csv        ← KEM handshake records (test/debug)
└── dilithium_test_result.csv   ← Dilithium self-test results
```

---

## 5. The Three Cryptographic Primitives Used

### 5.1 HMAC-SHA256 — Message Authentication

Used for:
- Per-beacon MAC (Gate 1 of `lw_mitigate`)
- Aggregate signature binding in threshold module (`agg_sig`)

```cpp
// Vehicle side (beacon_sign in hmac_filter.cc):
m' = m || τs || nonce           // concatenate payload + timestamp + nonce
MAC = HMAC-SHA256(K_Vi,nk, m')  // sign with 256-bit session key

// RSU/Controller side (lw_mitigate in hmac_filter.cc):
expected = HMAC-SHA256(K_Vi,nk, m')
received == expected?  → ACCEPT   : DROP (CRYPTO_DROP_INVALID_MAC)
```

HMAC key size: 256 bits (`SESSION_KEY_LEN = 32` bytes)
Output size: 256 bits (`HMAC_SHA256_LEN = 32` bytes)
Latency: 1–2 µs on ARM Cortex-M — fits inside the 100 ms beacon budget.

### 5.2 Dilithium5 — Digital Signatures

Used for:
- Individual vehicle reports (threshold aggregate module)
- Location-binding reports (ME detection)
- KEM key authentication (Fix-1)
- CA certificate issuance (Fix-2)

Sizes:
```
Public key:  2592 bytes  (DILITHIUM5_PK_LEN)
Secret key:  4864 bytes  (DILITHIUM5_SK_LEN)
Signature:   4595 bytes  (DILITHIUM5_SIG_LEN)
```

These are much larger than RSA or ECDSA keys — this is the cost of post-quantum security. At NIST Level 5, breaking Dilithium5 requires computational effort equivalent to breaking AES-256.

Security assumption: Module Learning With Errors (Module-LWE) — believed quantum-resistant.

### 5.3 Kyber-1024 + FireSaber — Hybrid KEM

Used for: establishing per-vehicle session key `K_{Vi,nk}` at registration.

The session key is derived from both:
```
ss_kyber  = Kyber-1024 shared secret  (32 bytes)
ss_saber  = FireSaber  shared secret  (32 bytes)
K_Vi,nk   = HKDF-SHA256(ss_kyber XOR ss_saber)
```

Why hybrid? If Kyber-1024 is broken (by a future quantum attack), FireSaber still protects. If FireSaber has a bug, Kyber still protects. Both must be broken simultaneously for the session key to be compromised. This is called a **hybrid KEM**.

Wire sizes:
```
Kyber-1024:  PK=1568 B  SK=3168 B  CT=1568 B  SS=32 B
FireSaber:   PK=1312 B  SK=3040 B  CT=1472 B  SS=32 B
```

---

## 6. The Seven Verification Steps — Algorithm 3 (LW-MITIGATE)

Every incoming beacon at the RSU passes through seven gates **in strict sequential order**. A failure at any gate causes an immediate DROP — later gates are not run.

```
Incoming beacon from vehicle V_i
         │
         ▼
Gate 0: Key lookup (kem_lookup)
         Is vehicle_id in keystore?
         → NO  → provision new vehicle (KEM handshake)
         → revoked? → DROP (CRYPTO_DROP_REVOKED_KEY)
         │
         ▼
Gate 1: HMAC integrity (Eq. 3.14)
         Recompute HMAC-SHA256(K_Vi,nk, m')
         == received MAC?
         → NO  → DROP (CRYPTO_DROP_INVALID_MAC)     ← 450 dropped in test run
         │
Gate 2: Timestamp freshness (Eq. 3.15)
         |τr − τs| ≤ T_b + ε  (100 ms + 10 ms)
         → violated → DROP (CRYPTO_DROP_STALE_TIMESTAMP)
         │
Gate 3: Nonce novelty (Eq. 3.16)
         nonce ∉ N_seen?
         → already seen → DROP (CRYPTO_DROP_REPLAYED_NONCE)
         Add nonce to N_seen
         │
Gate 4: Threshold aggregate signature (Eq. 3.24)
         (Only for RSU-aggregated reports — topology updates)
         verify_threshold_sig() → THRESHOLD_SIG_FAIL → flag for TGN
         │
Gate 5: Location binding / quorum (Eqs. 3.25–3.30)
         (Only for ME-related reports)
         verify_single_witness() → outside comm range → flag for TGN
         verify_quorum() → insufficient honest witnesses → flag for TGN
         │
Gate 6: LKH revocation check (Eq. 3.17)
         (On confirmed alert from blockchain via /tmp/teta_guard_revoke.txt)
         lkh_revoke_vehicle() → key tree updated → future packets blocked
         │
         ▼
    CRYPTO_ACCEPT → construct CryptoVerifiedEvent → tgn_ingest_event()
```

**Critical design rule:** The HMAC MAC check (Gate 1) runs BEFORE the timestamp check (Gate 2). An attacker sending a forged MAC is rejected immediately without the system revealing any timing information (which could help the attacker probe freshness windows).

---

## 7. Module 0 — dilithium.cc (Shared Dilithium5 Module)

### 7.1 What it does

`dilithium.cc` is the **single canonical implementation** of Dilithium5 used by every other module. It is compiled once to `dilithium.o` and linked into all four modules that need signatures: `kem.cc`, `threshold_sig.cc`, `location_binding.cc`, `crypto_pipeline.cc`.

Functions exported (declared in `teta_guard_types.h`):
```cpp
void dilithium5_keygen(uint8_t pk[2592], uint8_t sk[4864]);
void dilithium5_sign(const uint8_t *msg, size_t len, const uint8_t sk[4864],
                     uint8_t sig[4595], size_t *sig_len);
bool dilithium5_verify(const uint8_t *msg, size_t len,
                       const uint8_t sig[4595], size_t sig_len,
                       const uint8_t pk[2592]);
```

Plus domain-separated variants, CA cert API, and CRL functions — all described below.

### 7.2 Domain Separation — Fix-7

**Problem:** A Dilithium5 signature is just `Sign(SK, message)`. If the same key is used for threshold reports and location-binding reports, an attacker could take a valid threshold signature and present it as a location-binding signature (signature re-use attack).

**Fix:** Every use case prepends a distinct ASCII tag before signing:

```cpp
#define TETA_DS_THRESH    "TETA:THRESH:"    // threshold aggregate
#define TETA_DS_LOCBIND   "TETA:LOCBIND:"   // location binding
#define TETA_DS_KEM_AUTH  "TETA:KEM-AUTH:"  // KEM key authentication
#define TETA_DS_CA_CERT   "TETA:CA-CERT:"   // CA certificate
```

Domain-separated wrappers prepend the tag, then call the base sign/verify:
```cpp
void dilithium5_sign_thresh(msg, len, sk, sig, sig_len)
  → internally signs "TETA:THRESH:" || msg

bool dilithium5_verify_thresh(msg, len, sig, sig_len, pk)
  → verifies "TETA:THRESH:" || msg against sig
```

A threshold signature cannot be replayed as a location-binding signature because the prefix is different.

### 7.3 CA Certificate API — Fix-2

**Problem:** Without a trust root, a vehicle can claim any public key. There is nothing preventing V0 from sending "I am V1, my public key is X" with a self-signed certificate.

**Fix:** A consortium CA (Certificate Authority) issues Dilithium5 certificates binding each vehicle's identity to its public key. The CA's own key pair is generated once (`teta_ca_init()`) and is the root of all trust.

```cpp
// CA issues cert at vehicle registration:
void dilithium5_issue_cert(
    const uint8_t vehicle_id[16],
    const uint8_t pk_vi[2592],     // vehicle's Dilithium5 public key
    uint64_t      issued_at_ms,
    CertificateRecord *cert_out    // filled with CA signature over (id||pk||time)
);

// Any verifier checks cert before trusting pk_vi:
bool dilithium5_verify_cert(const CertificateRecord *cert);
  // → verifies ca_sig over (TETA:CA-CERT: || vehicle_id || pk_vi || issued_at_ms)
  //   using the consortium CA's public key
  // → also checks cert_is_revoked(vehicle_id)
```

Without a valid CA cert, the RSU rejects the vehicle's public key entirely.

### 7.4 CRL Revocation — Fix-3

**Problem:** After a vehicle is caught attacking, its old valid CA certificate still exists. It could present that cert and gain trust again.

**Fix:** A Certificate Revocation List (CRL) is maintained inside `dilithium.cc`. When `cert_revoke_vehicle(vehicle_id)` is called, all future `dilithium5_verify_cert()` calls for that `vehicle_id` return `false`, even if the CA signature over the cert is valid.

```cpp
void cert_revoke_vehicle(const uint8_t vehicle_id[16]);
bool cert_is_revoked(const uint8_t vehicle_id[16]);
```

CRL size: up to `MAX_CRL_ENTRIES = 4096` revocations. This is separate from `MAX_VEHICLES = 256` (the active fleet size), because revocations are monotonically accumulating over the system lifetime.

### 7.5 Stub Mode

Without liboqs installed, all Dilithium5 operations fall back to HMAC-SHA256:

- `dilithium5_sign()` → writes HMAC-SHA256 into the signature buffer
- `dilithium5_verify()` → re-derives and compares the HMAC

This is NOT quantum-resistant. The stub exists only so the simulation can run without PQC libraries. A prominent `stderr` warning is printed at startup. The `ALLOW_DILITHIUM_STUB` compile flag must be explicitly set to acknowledge this — it cannot be silently enabled.

---

## 8. Module 1 — kem.cc (Kyber-1024 + FireSaber Hybrid KEM)

### 8.1 Why a Hybrid KEM?

A single KEM algorithm could have an undiscovered vulnerability. Kyber-1024 and FireSaber use different mathematical problems (Module-LWE vs Module-LWR). An attacker must break **both** to recover the session key.

```
Session key = HKDF-SHA256(ss_kyber XOR ss_saber, "TETA-Guard-Session-Key")
```

This XOR-then-HKDF combiner is IND-CCA2 secure if either component KEM is IND-CCA2 secure (standard hybrid KEM security proof).

### 8.2 KEM Handshake — Step by Step

```
VEHICLE (V_i)                          RSU
────────────────────────────────────────────────────────────
Step 1: kem_vehicle_keygen()
  Generate (pk_kyber, sk_kyber) ← Kyber-1024 keypair
  Generate (pk_saber,  sk_saber)  ← FireSaber  keypair
  Sign (TETA:KEM-AUTH: || vid || pk_kyber || pk_saber || nonce)
       → keygen_sig  (Dilithium5)
  Get CA cert: keygen_cert = CA.issue(vid, identity_pk)

  Send → (pk_kyber, pk_saber, keygen_nonce, keygen_sig,
           identity_pk, keygen_cert)

Step 3: kem_rsu_encapsulate()
                               Verify keygen_cert (CA trust root)
                               Verify keygen_sig against cert.pk_vi
                               (NOT against identity_pk — prevents circular trust)
                               Encapsulate(pk_kyber) → (ct_kyber, ss_kyber)
                               Encapsulate(pk_saber)  → (ct_saber,  ss_saber)
                               Derive: K_Vi,nk = HKDF(ss_kyber XOR ss_saber)
                               Store K_Vi,nk in VehicleKeyRecord keystore
                               Send → (ct_kyber, ct_saber)

Step 4: kem_vehicle_decapsulate()
  Decapsulate(sk_kyber, ct_kyber) → ss_kyber
  Decapsulate(sk_saber,  ct_saber)  → ss_saber
  Derive: K_Vi,nk = HKDF(ss_kyber XOR ss_saber)
  ← Now both sides hold K_Vi,nk without it ever crossing the network
```

### 8.3 Session Key Derivation — HKDF

HKDF (HMAC-based Key Derivation Function) produces a cryptographically strong key of exactly the needed size from arbitrary input material:

```cpp
// From kem.cc:
uint8_t ikm[32];  // ss_kyber XOR ss_saber
for (int i = 0; i < 32; i++) ikm[i] = ss_kyber[i] ^ ss_saber[i];

// HKDF-SHA256 with vehicle_id as context (Fix-8: vehicle-specific binding)
HKDF(ikm, 32, vehicle_id, 16, "TETA-Guard-Session-Key", session_key, 32);
```

Fix-8: The vehicle_id is bound into the HKDF context. Without this, two vehicles generating the same (ss_kyber XOR ss_saber) would get the same session key — a key aliasing vulnerability.

### 8.4 Authenticated KEM — Fix-1

**Problem:** Without authentication, a man-in-the-middle can substitute `pk_kyber` and `pk_saber` with their own keys. The RSU would then encapsulate to the attacker's keys, giving the attacker the session key.

**Fix:** The vehicle signs `(TETA:KEM-AUTH: || vehicle_id || pk_kyber || pk_saber || keygen_nonce)` with its long-term Dilithium5 secret key. The RSU verifies this signature using the CA-certified public key before encapsulating.

```cpp
// In kem_rsu_encapsulate():
// 1. Verify CA cert first (trust root — Fix-2)
if (!dilithium5_verify_cert(&state->keygen_cert)) → FAIL

// 2. Verify keygen_sig using cert.pk_vi (NOT state->identity_pk — Fix-2 closure)
if (!dilithium5_verify_kem_auth(auth_msg, auth_len,
                                 state->keygen_sig, sig_len,
                                 state->keygen_cert.pk_vi)) → FAIL

// Only after both checks pass: encapsulate
```

### 8.5 Wire Sizes Reference

| Component | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|-----------|-----------|-----------|--------------|
| Kyber-1024 | 1568 B | 3168 B | 1568 B | 32 B |
| FireSaber | 1312 B | 3040 B | 1472 B | 32 B |
| Dilithium5 (identity) | 2592 B | 4864 B | — | — |

All sizes are defined as constants in `teta_guard_types.h` for cross-module consistency.

---

## 9. Module 2 — hmac_filter.cc (HMAC + Freshness + Nonce)

### 9.1 The Three Gates of lw_mitigate()

`lw_mitigate()` is the main function called per beacon. It implements Equation 3.35 — Algorithm 3 from the paper:

```cpp
CryptoVerifyResult lw_mitigate(
    const BeaconMessage *msg,          // incoming beacon
    uint64_t recv_time_ms,             // current RSU clock (τ_r)
    const uint8_t session_key[32],     // K_{Vi,nk} from KEM keystore
    bool key_revoked,                  // from VehicleKeyRecord.revoked
    NonceCache *nonce_cache            // per-sender nonce history
);
```

**Gate 1 — HMAC integrity (Eq. 3.14)**
```
m' = msg.payload || msg.sender_timestamp_ms || msg.nonce
expected_mac = HMAC-SHA256(session_key, m')
if msg.mac != expected_mac → return CRYPTO_DROP_INVALID_MAC
```

Blocks: All attackers who do not hold `K_{Vi,nk}`. In the test run, this dropped 450 packets (DROP_INVALID_MAC) from V9999 (simulated attacker).

**Gate 2 — Timestamp freshness (Eq. 3.15)**
```
window = BEACON_INTERVAL_MS + PROPAGATION_TOL_MS = 100 + 10 = 110 ms
if |recv_time_ms - msg.sender_timestamp_ms| > window
    → return CRYPTO_DROP_STALE_TIMESTAMP
```

Blocks: TTW-class replays where the attacker reuses old packets with forged timestamps. Even if the attacker forges the timestamp field, the HMAC in Gate 1 already covers the timestamp — so a forged timestamp also fails Gate 1 first.

**Gate 3 — Nonce novelty (Eq. 3.16)**
```
if nonce ∈ nonce_cache.nonces → return CRYPTO_DROP_REPLAYED_NONCE
nonce_cache.nonces[head] = nonce
head = (head + 1) % NONCE_CACHE_SIZE
```

Blocks: BSHH intra-session replays where the exact same packet is resent. The nonce is included in the HMAC (Gate 1), so a forged nonce fails Gate 1. Gate 3 catches replays with the original, authentic nonce.

### 9.2 beacon_sign() — Vehicle Side

```cpp
void beacon_sign(BeaconMessage *msg, const uint8_t session_key[32]);
```

Called by the vehicle before transmitting:
1. Fill `msg.nonce` with 16 cryptographically random bytes (`RAND_bytes`)
2. Compute `m' = payload || sender_timestamp_ms || nonce`
3. Compute `msg.mac = HMAC-SHA256(session_key, m')`

The vehicle never transmits a beacon without a valid MAC. Attackers who intercept and replay a beacon will fail Gate 3 (same nonce) or fail Gate 1 if they modify any field.

### 9.3 Return Codes

```cpp
typedef enum {
    CRYPTO_ACCEPT               = 0,  // passed all gates
    CRYPTO_DROP_INVALID_MAC     = 1,  // wrong HMAC → no valid session key
    CRYPTO_DROP_STALE_TIMESTAMP = 2,  // TTW-class replay
    CRYPTO_DROP_REPLAYED_NONCE  = 3,  // exact replay (BSHH intra-session)
    CRYPTO_DROP_REVOKED_KEY     = 4,  // vehicle is revoked
    CRYPTO_DROP_KEYSTORE_FULL   = 5   // pipeline keystore at capacity
} CryptoVerifyResult;
```

All drops are logged to `crypto_drop_log.csv` with the vehicle ID, timestamp, and reason code.

### 9.4 Latency Budget

HMAC-SHA256 on a 100-byte message takes ~1–2 µs on ARM Cortex-M (the typical RSU processor). The beacon interval is 100 ms. So the HMAC filter consumes less than 0.002% of the beacon budget — negligible.

---

## 10. Module 3 — threshold_sig.cc (Dilithium5 Threshold Aggregate)

### 10.1 What is a Threshold Signature?

A threshold signature requires **at least t out of n** signers to agree before the aggregate is accepted. In this system:

```
n = number of vehicles reporting the same link observation to the RSU
t = ⌊n/2⌋ + 1  (strict majority), minimum THRESHOLD_T_FLOOR = 3

Accept ⟺ count of valid individual Dilithium5 signatures ≥ t
```

This eliminates BSHH attacks where a single attacker vehicle sends a forged heartbeat — it cannot produce a strict majority of Dilithium5 signatures from other legitimate vehicles.

Equation 3.24:
```
Verify(σ_agg, PK_agg) = 1  ⟺  |{i : Verify(σ_i, msg_i, PK_{Vi}) = 1}| ≥ t
```

### 10.2 Data Path — Vehicle to RSU to Controller

```
Each vehicle V_i:
  1. Signs its topology observation with Dilithium5:
     signed_msg = msg_payload || timestamp_ms || nonce
     individual_sig = Dilithium5Sign_THRESH(SK_Vi, signed_msg)
  2. Sends IndividualSignedReport to RSU

RSU (rsu_aggregate_reports()):
  1. Collects all reports into AggregateReport.reports[]
  2. Sets n_reports, threshold_t (informational only)
  3. Computes agg_pk = XOR of all individual pub_keys
  4. Computes agg_sig = HMAC-SHA256(agg_pk, concat of first 32 bytes of each sig)
     (integrity binding only — NOT a real aggregate signature)
  5. Sends AggregateReport to controller

Controller (verify_threshold_sig()):
  Verifies each individual report independently (see below)
```

### 10.3 verify_threshold_sig() — Four Gates

```
Gate A — agg_sig fast path:
  Recompute HMAC-SHA256(agg_pk, sig_prefixes)
  If mismatch → flag accidental corruption
  (NOT a security gate — an attacker who knows agg_pk can forge agg_sig)

Gate B — threshold_t floor:
  Recompute t = max(n/2 + 1, THRESHOLD_T_FLOOR)
  Ignore AggregateReport.threshold_t field entirely (compromise protection)

Gate C — individual Dilithium5 verification (the REAL security gate):
  For each report i:
    1. Verify CA cert: dilithium5_verify_cert(&report.cert)
       → checks cert.pk_vi == CA-signed, not revoked
    2. Check cert.pk_vi == report.pub_key (consistency)
    3. Build signed_buf = msg_payload || timestamp_ms_le || nonce
    4. dilithium5_verify_thresh(signed_buf, report.individual_sig, report.pub_key)
  Count valid_count of reports passing all four sub-checks

Gate D — threshold and freshness:
  valid_count >= t?     → THRESHOLD_SIG_PASS
  valid_count < t?      → THRESHOLD_SIG_FAIL
  Any report.timestamp_ms too old (> THRESH_REPORT_WINDOW_MS = 5 s from aggregate timestamp)?
    → reject that report (prevents mixing stale reports into new aggregates)

Result: THRESHOLD_SIG_PASS or THRESHOLD_SIG_FAIL
```

### 10.4 Threshold Floor — Fix-4

**Problem:** An attacker can suppress reports by jamming vehicles' DSRC transmissions. If only 2 legitimate vehicles report, and t = ⌊2/2⌋+1 = 2, the attacker only needs to compromise 1 to defeat the majority.

**Fix:** `THRESHOLD_T_FLOOR = 3`. Even if n=2 (two reporters), t is clamped to 3. This forces the attacker to suppress enough reports that fewer than 3 valid ones remain — a much harder physical attack.

This only defends against report-count suppression. Collusion (where more than half the reporters are attackers) is delegated to ME-S1 detection in the PEM layer.

### 10.5 agg_sig Security Note

`agg_sig` is `HMAC-SHA256(agg_pk, sig_prefixes)` with a fully public key (agg_pk is computed from the public individual keys — anyone can compute it). This means `agg_sig` provides **integrity-only** (detects accidental byte corruption) but NOT **authentication** (a deliberate forger who knows agg_pk can recompute agg_sig).

The real authentication comes entirely from Gate C — the individual Dilithium5 verifications. `agg_sig` is only a fast-path check to detect random bit flips before running the expensive individual verifications. Never skip Gate C based on `agg_sig` passing.

---

## 11. Module 4 — location_binding.cc (ME Location Proof)

### 11.1 Why Location Binding?

In a ME (Multipath Echo) attack, V3 and V4 echo the real V1↔V2 link to the controller, claiming they also observed it. The controller infers phantom paths V1→V3→V2 and V1→V4→V2.

Location binding detects this by requiring each reporter to **sign their own GPS position and measured RSSI**. If V3 is actually far from V1 and V2, it cannot produce a valid location-bound report claiming to be near them without:
1. Forging its GPS coordinates (but RSSI would not match)
2. Forging the RSSI (but RSU independently measures RSSI — Fix-5)

### 11.2 verify_single_witness() — Four Checks

Each reporter V_k submitting a link observation must provide a `LocationBoundReport`:

```cpp
// Signed by V_k:
payload = {
    link_id,           // which link e_ij they claim to have witnessed
    reporter_lat,      // their GPS latitude
    reporter_lon,      // their GPS longitude
    reporter_alt,
    rssi_from_vi_dbm,  // RSSI they measured from V_i
    sender_timestamp,  // when they saw it
    nonce,
    reporter_id
}
signature = Dilithium5Sign_LOCBIND(SK_Vk, payload)
```

`verify_single_witness()` checks:

**Check 1 — CA cert (same as threshold)**
```
dilithium5_verify_cert(&report.cert) → vehicle_id is legitimate
cert.pk_vi == report.pub_key → consistent
```

**Check 2 — Dilithium5 signature**
```
dilithium5_verify_locbind(payload, signature, pub_key) → authentic
```

**Check 3 — Spatial plausibility (300 m range)**
```
distance = haversineDistanceM(reporter_lat, reporter_lon,
                               link_midpoint_lat, link_midpoint_lon)
distance ≤ R_COMM_METERS (300 m)?
→ NO → reject (reporter claims to be near a link it cannot physically be near)
```

**Check 4 — RSSI plausibility (Friis model, Fix-5)**
```
expected_rssi = Friis_path_loss(distance, 5.9 GHz)
|rsu_measured_rssi_dbm - expected_rssi| ≤ RSSI_DISTANCE_MARGIN_DB (10 dB)?
→ NO → reject (RSSI does not match claimed position)
```

### 11.3 RSU-Measured RSSI — Fix-5

**Problem:** The original implementation used `rssi_from_vi_dbm` from the signed payload (filled by the vehicle) for the Friis plausibility check. An attacker can forge this value.

**Fix:** The RSU independently measures the signal strength of the incoming DSRC packet from its own physical layer and stores it in `rsu_measured_rssi_dbm` with `has_rsu_measurement = true`. `verify_single_witness()` uses this RSU-measured value for the Friis check, ignoring the vehicle's self-reported RSSI entirely.

The attacker cannot fake what the RSU's own antenna measured.

### 11.4 Quorum Requirement — Eqs. 3.27–3.28

A single witness passing all four checks is not sufficient for a link to be accepted. `verify_quorum()` requires a quorum of mutually consistent witnesses:

```
Quorum = at least t_q witnesses where:
  - All pass verify_single_witness()
  - Their reported positions are mutually consistent (pairwise distance check)
  - Their reported RSSI values agree within tolerance

t_q = THRESHOLD_T_FLOOR = 3  (same floor as threshold aggregate)
```

This blocks the ME attack where V3 and V4 collude — two non-consistent witnesses cannot form a quorum. Legitimate links observed by V1 and V2 (who are within range) easily form a quorum.

---

## 12. Module 5 — lkh_mgmt.cc (LKH Key Revocation)

### 12.1 Why Not Just Delete the Key?

When a vehicle is revoked, the RSU must stop accepting packets from it. Simply deleting its session key from the local keystore would work at that RSU — but other RSUs in the network also hold session keys for all vehicles.

To revoke a vehicle network-wide, you need to send updated keys to all other vehicles. With n=1000 vehicles, naïve full re-key requires 999 key transmissions. The beacon interval is 100 ms — this is too expensive.

### 12.2 Binary LKH Tree Structure

LKH uses a binary tree where:
- Leaves represent individual vehicles (each holds their own session key)
- Internal nodes hold **Key Encryption Keys (KEKs)** — keys used to encrypt other keys
- The root holds the **group key K_G** shared by all active vehicles

```
                    [K_G — root KEK]
                    /              \
         [KEK_left]              [KEK_right]
         /        \              /          \
    [V1]        [V2]        [V3]         [V4]
  leaf:K1      leaf:K2    leaf:K3       leaf:K4
```

### 12.3 O(log n) Revocation Proof

To revoke V3:
1. Generate new keys for every node on the path V3 → root: new KEK_right, new K_G
2. Transmit the new K_G encrypted under new KEK_right to all vehicles in the right subtree (V4)
3. Transmit the new K_G encrypted under the old KEK_left to all vehicles in the left subtree (V1, V2)

V1 and V2 receive 1 key update each. V4 receives 1 key update. V3 receives nothing — it is revoked.

Depth of tree = d = ⌈log₂ n⌉. Number of key updates = d = O(log n).

With n=1000: d ≈ 10 key transmissions vs. 999 naïve.

```cpp
void lkh_revoke_vehicle(LKHTree *tree, const uint8_t vehicle_id[16]) {
    // 1. Find leaf node for vehicle_id
    // 2. Mark leaf as revoked
    // 3. Walk up to root: regenerate KEK at each ancestor
    // 4. Log each KEK update to lkh_revocation_log.csv
    // 5. Call mark_key_revoked() to also revoke the session key (Fix-3)
}
```

The function also calls `cert_revoke_vehicle(vehicle_id)` — so a single revocation event atomically invalidates:
- The session key (HMAC filter will drop future packets)
- The identity certificate (Dilithium5 verifications will reject future reports)
- The LKH tree position (group key is refreshed without this vehicle)

### 12.4 IPC Integration — Fix-6

**Problem:** The blockchain confirms revocation asynchronously. The C++ pipeline needs to know when a blockchain-confirmed revocation occurs so it can call `lkh_revoke_vehicle()`.

**Fix:** The Python script `submit_alerts.py` writes revoked vehicle IDs to `/tmp/teta_guard_revoke.txt` (one ID per line) after `FS-MITIGATE` Stage 3 confirms the revocation on-chain. At pipeline startup, `crypto_pipeline.cc` reads this file and applies any pending revocations.

File path constant: `TETA_REVOKE_FILE = "/tmp/teta_guard_revoke.txt"`

Security: The pipeline uses `open(O_NOFOLLOW)` + `fstat()` to verify the file is owned by the correct user ID before reading it — prevents symlink attacks where an attacker creates a symlink at that path to cause revocations of innocent vehicles.

### 12.5 Unified Revocation — Fix-3

**Problem:** Original code called `lkh_revoke_vehicle()` and `mark_key_revoked()` as separate steps in different places. Missing either call left a vehicle partially revoked (session key still valid but cert revoked, or vice versa).

**Fix:** `lkh_revoke_vehicle()` now calls `mark_key_revoked()` internally via a registered keystore pointer. A single call atomically revokes everything.

```cpp
// Fix-3: register keystore at startup
lkh_set_keystore(g_keystore, g_keystore_size);

// One call revokes everything:
lkh_revoke_vehicle(&g_lkh_tree, vehicle_id);
  // internally calls mark_key_revoked(g_keystore, vehicle_id)
  // and cert_revoke_vehicle(vehicle_id)
```

---

## 13. Module 6 — crypto_pipeline.cc (End-to-End Orchestrator)

### 13.1 Input / Output Files

| Direction | File | Format | Contents |
|-----------|------|--------|---------|
| Input | `pem_event_log.csv` | CSV | All beacon events from NS-3 simulation |
| Input | `tgn_alerts.json` | JSON | TGN detection alerts (optional) |
| Output | `crypto_verified_events.csv` | CSV | Events passing all crypto gates → TGN |
| Output | `crypto_drop_log.csv` | CSV | Rejected events with reason code |
| Output | `beacon_evidence.csv` | CSV | RSU GPS/RSSI observations for blockchain |
| Output | `tgn_alerts_crypto.json` | JSON | Crypto-verified subset of tgn_alerts.json |
| Output | `crypto_layer_log.txt` | Text | Step-by-step trace with hex key material |
| Output | `lkh_revocation_log.csv` | CSV | Per-revocation KEK update counts |

### 13.2 Pipeline Execution Order

```cpp
main(argc, argv):
  1. Open input files (pem_event_log.csv, tgn_alerts.json)
  2. teta_ca_init()  — initialise CA keypair
  3. lkh_init()      — build LKH tree for initial fleet
  4. lkh_set_keystore() — register keystore with Fix-3 unification
  5. Read /tmp/teta_guard_revoke.txt — apply blockchain-confirmed revocations (Fix-6)

  For each row in pem_event_log.csv:
    6. Parse vehicle_id, sender_timestamp_ms, recv_timestamp_ms, etc.
    7. kem_lookup(vehicle_id) → VehicleKeyRecord
       If not found: provision_vehicle() → KEM handshake (stub in simulation)
       If revoked: log DROP_REVOKED_KEY, continue
    8. lw_mitigate(beacon, recv_time, session_key, revoked, nonce_cache)
       CRYPTO_ACCEPT → continue
       CRYPTO_DROP_*  → log to crypto_drop_log.csv, continue
    9. verify_threshold_sig(aggregate_report)
       THRESHOLD_SIG_FAIL → flag, continue to TGN anyway (informational)
    10. verify_quorum(location_bound_reports)
        fail → flag, continue
    11. Construct CryptoVerifiedEvent from beacon fields + crypto metadata
    12. tgn_ingest_event(&event)
        → write row to crypto_verified_events.csv
        → write row to pem_event_log_filtered.csv

  For each alert in tgn_alerts.json:
    13. Verify it matches a CRYPTO_ACCEPT event
    14. Write to tgn_alerts_crypto.json if verified
    15. lkh_revoke_vehicle() for confirmed attacker vehicles

  16. Write beacon_evidence.csv (RSU GPS observation log)
  17. Close all files, print summary
```

### 13.3 CryptoVerifiedEvent — Crypto → TGN Boundary

This is the **only** struct that crosses from the crypto layer to the TGN. It contains everything the TGN needs for graph-based anomaly detection:

```cpp
typedef struct {
    uint8_t  vehicle_id[16];         // identity
    uint8_t  link_id[8];             // e_ij
    uint8_t  reporter_id[16];        // V_k (for ME analysis)

    uint64_t sender_timestamp_ms;    // τ_s — recency feature
    uint64_t recv_timestamp_ms;      // τ_r — edge weight A_uv(t)
    uint32_t sequence_number;        // for Δs_v sequence gap feature
    uint32_t beacon_count_in_window; // c_v^W liveness feature

    float    reporter_lat;           // pos_{Vk} — for ME-S3 check
    float    reporter_lon;
    float    rssi_from_vi_dbm;       // RSSI_{Vk←Vi}
    uint32_t reporter_count;         // ρ_v for ME-S1 density bound

    bool     location_binding_verified;  // Module 4 result
    bool     threshold_sig_verified;     // Module 3 result
    uint8_t  crypto_filter_result;       // always CRYPTO_ACCEPT here

    bool     is_attack;              // ground truth from pem_event_log.csv
} CryptoVerifiedEvent;
```

Controller-origin attacks (S3/S4) reach the TGN with `is_attack=true` and `crypto_filter_result=CRYPTO_ACCEPT` — the crypto layer cannot block them because the controller holds valid credentials. The TGN must catch them via behavioural analysis.

### 13.4 DetectionAlert — TGN → Blockchain Boundary

After the TGN processes `CryptoVerifiedEvent`s, it emits `DetectionAlert`s:

```cpp
typedef struct {
    uint8_t       vehicle_id[16];
    AttackVariant variant;      // ATTACK_TTW=0, ATTACK_BSHH=1, ATTACK_ME=2
    float         anomaly_score; // ŷ_v ∈ (0,1) — from LW Eq.3.11 or TGN Eq.3.23
    uint32_t      triggered_sigs; // bitmask: bits 0-2=TTW, 3-5=BSHH, 6-8=ME
    uint64_t      alert_timestamp; // t_alert in ms
    bool          from_lw_path;   // lightweight filter triggered it
    bool          from_fs_path;   // full TGN triggered it
} DetectionAlert;
```

In `tgn_alerts_crypto.json`, these fields appear as:
- `v_id` = vehicle_id as string ("V9999")
- `alpha` = "TTW", "BSHH", or "ME"
- `y_hat` = anomaly_score
- `S_trig` = array of triggered signature indices
- `t_alert` = alert_timestamp
- `tdet_ms` = detection latency from attack injection
- `from_lw` / `from_fs` = booleans

---

## 14. All Shared Structs — teta_guard_types.h

`teta_guard_types.h` is the contract between all modules. Every `.cc` file includes it. The structs in order:

| Struct | Purpose | Used by |
|--------|---------|---------|
| `CertificateRecord` | CA-issued cert binding vehicle_id → Dilithium5 PK | All modules |
| `KemExchangeState` | Vehicle-side KEM handshake state | kem.cc |
| `VehicleKeyRecord` | RSU keystore entry: session key + Dilithium5 PK + LKH position | kem.cc, crypto_pipeline.cc |
| `BeaconMessage` | Wire format of every vehicle beacon | hmac_filter.cc |
| `NonceCache` | Per-sender circular nonce cache (4096 entries) | hmac_filter.cc |
| `CryptoVerifyResult` | Enum: ACCEPT / DROP_INVALID_MAC / etc. | hmac_filter.cc |
| `IndividualSignedReport` | One vehicle's signed topology observation | threshold_sig.cc |
| `AggregateReport` | RSU-aggregated collection of IndividualSignedReports | threshold_sig.cc |
| `ThresholdSigResult` | Enum: THRESHOLD_SIG_PASS / THRESHOLD_SIG_FAIL | threshold_sig.cc |
| `LocationBindingPayload` | Signed GPS + RSSI location proof | location_binding.cc |
| `LocationBoundReport` | Full report: payload + Dilithium5 sig + RSU RSSI | location_binding.cc |
| `LKHNode` | One node in the LKH binary tree | lkh_mgmt.cc |
| `LKHTree` | The full LKH tree (up to 1024 leaves × 2 nodes) | lkh_mgmt.cc |
| `CryptoVerifiedEvent` | Crypto → TGN boundary (Section 8.2) | crypto_pipeline.cc |
| `AttackVariant` | Enum: ATTACK_TTW / ATTACK_BSHH / ATTACK_ME | tgn_detector.cc, blockchain |
| `DetectionAlert` | TGN → Blockchain boundary (Section 9.1) | tgn_detector.cc, blockchain |
| `BeaconEvidenceRecord` | RSU GPS observation batch B_nk(t) | blockchain |

---

## 15. Security Fixes — Complete Reference

Eight security fixes were applied during implementation. Understanding these is essential if you modify the crypto layer.

| Fix | File(s) | Problem | Solution |
|-----|---------|---------|---------|
| **Fix-1** | `kem.cc`, `teta_guard_types.h` | MITM could substitute KEM public keys | KEM keygen message signed with Dilithium5 under domain prefix `TETA:KEM-AUTH:` |
| **Fix-2** | `dilithium.cc`, `kem.cc`, `threshold_sig.cc`, `location_binding.cc` | Circular trust: verifier used vehicle's self-claimed public key | CA issues Dilithium5 cert; verifier uses `cert.pk_vi` (CA-certified), NOT `identity_pk` |
| **Fix-3** | `lkh_mgmt.cc`, `dilithium.cc` | Session key and identity cert revoked separately → partial revocation | `lkh_revoke_vehicle()` calls `mark_key_revoked()` and `cert_revoke_vehicle()` atomically |
| **Fix-4** | `teta_guard_types.h`, `threshold_sig.cc` | Attacker suppresses reports to lower n → low t → easy majority | `THRESHOLD_T_FLOOR = 3`: t cannot drop below 3 regardless of n |
| **Fix-5** | `location_binding.cc`, `teta_guard_types.h` | Vehicle self-reports RSSI → attacker forges RSSI to pass Friis check | RSU independently measures RSSI from physical layer; `rsu_measured_rssi_dbm` is RSU-filled |
| **Fix-6** | `crypto_pipeline.cc` | No IPC from blockchain to crypto pipeline for revocation | Pipeline reads `/tmp/teta_guard_revoke.txt` with symlink-safe `open(O_NOFOLLOW)` + `fstat()` |
| **Fix-7** | `dilithium.cc`, `teta_guard_types.h` | Same key used for multiple purposes → signature re-use across domains | Domain-separated signing: `TETA:THRESH:`, `TETA:LOCBIND:`, `TETA:KEM-AUTH:`, `TETA:CA-CERT:` |
| **Fix-8** | `kem.cc` | HKDF without vehicle_id context → key aliasing between vehicles | `vehicle_id` bound as HKDF context → session key is vehicle-specific |

---

## 16. Cryptographic Effectiveness by Attack Variant

| Attack | Attacker | Crypto Blocks? | Why / Why Not |
|--------|----------|---------------|---------------|
| TTW-S1 | Malicious Vehicle | ✅ YES | Vehicle has no session key for victim → HMAC fails Gate 1 |
| TTW-S2 | Malicious RSU | ✅ YES | RSU can forge timestamps but nonce prevents exact replay; freshness gate catches stale replays |
| TTW-S3 | Malicious Controller | ❌ NO | Controller holds valid credentials from KEM; can produce correct HMACs |
| TTW-S4 | Malicious Controller + RSU | ❌ NO | Same as S3 |
| BSHH-S1 | Malicious Vehicle | ✅ YES | Replayed heartbeat has old nonce → blocked by Gate 3; different physical sender → MAC mismatch |
| BSHH-S2 | Malicious RSU | ✅ YES | RSU does not hold victim vehicle's session key → HMAC fails |
| BSHH-S3 | Malicious Controller | ❌ NO | Insider; TGN detects behavioural anomaly instead |
| BSHH-S4 | Malicious Controller + RSU | ❌ NO | Same as S3 |
| ME-S1 | Malicious Vehicles | ⚠️ PARTIAL | Location binding catches V3/V4 if they are outside range; colluding majority still possible |
| ME-S2 | Malicious RSU | ⚠️ PARTIAL | RSU can forge reporter IDs; location binding + TGN combined |
| ME-S3 | Malicious Controller | ❌ NO | Direct topology injection; TGN primary detection |
| ME-S4 | Malicious Controller + RSU | ❌ NO | Same as S3 |

**Core principle from the paper:** Crypto provides pre-detection value if and only if the attacker cannot pass cryptographic verification. For insider attacks (S3/S4), the TGN and blockchain are the primary defence.

---

## 17. Build System — Makefile Reference

### 17.1 Stub Mode vs PQC Mode

```bash
# Stub mode (default) — OpenSSL HMAC only, no liboqs
make

# PQC mode — real Kyber-1024, FireSaber, Dilithium5 via liboqs
make PQC=1
```

In stub mode:
- `HAVE_OPENSSL` is defined
- All Dilithium5 calls fall back to HMAC-SHA256
- All KEM calls fall back to HKDF of a random seed
- Prominent stderr warning printed at startup
- `ALLOW_DILITHIUM_STUB` must be explicitly set (acknowledgement flag)

In PQC mode:
- `HAVE_LIBOQS` and `HAVE_OPENSSL` are both defined
- Real `OQS_SIG_alg_dilithium_5` and `OQS_KEM_alg_kyber_1024` / `OQS_KEM_alg_saber_firesaber`
- Requires `sudo apt-get install liboqs-dev` or building liboqs from source

### 17.2 Build Targets

| Target | Output | What it builds |
|--------|--------|---------------|
| `make` or `make all` | 7 binaries | All 6 modules + dilithium standalone |
| `make test` | (runs binaries) | Build all then run self-tests for each module |
| `make phase8_tests` | `phase8_tests` | Full 47-test integration harness |
| `make phase8_sanitize` | `phase8_sanitize` | Same under ASan + UBSan instrumentation |
| `make fuzz_lw_mitigate` | `fuzz_lw_mitigate` | 500 K iteration fuzzer for Algorithm 3 |
| `make pipeline` | (runs pipeline) | Run `./crypto_pipeline ../pem_event_log.csv ../tgn_alerts.json` |
| `make clean` | (deletes files) | Remove all binaries + generated CSVs + JSONs |

### 17.3 Object Dependencies

```
dilithium.cc → dilithium.o        (compiled with -DDILITHIUM_NO_MAIN -DALLOW_DILITHIUM_STUB)
threshold_sig.cc → threshold_sig.o (compiled with -DTHRESHOLD_SIG_NO_MAIN)
location_binding.cc → location_binding.o (-DLOCATION_BINDING_NO_MAIN)
lkh_mgmt.cc → lkh_mgmt.o         (compiled with -DLKH_MGMT_NO_MAIN)

kem:           kem.cc + dilithium.o
hmac_filter:   hmac_filter.cc (no dilithium dependency)
threshold_sig: threshold_sig.cc + dilithium.o
location_binding: location_binding.cc + dilithium.o
lkh_mgmt:      lkh_mgmt.cc + dilithium.o
crypto_pipeline: crypto_pipeline.cc + dilithium.o + threshold_sig.o
                 + location_binding.o + lkh_mgmt.o
```

The `*_NO_MAIN` flags suppress the `main()` function in each module file so they can be linked as objects into `crypto_pipeline` without duplicate `main` symbols.

---

## 18. Phase 8 Test Suite — 47/47 Tests

### 18.1 What the Tests Cover

The 47 tests (T1–T47) cover all six modules and their interactions:

| Test range | Module | What is tested |
|-----------|--------|---------------|
| T1–T4 | hmac_filter | CRYPTO_ACCEPT, INVALID_MAC, STALE_TIMESTAMP, REPLAYED_NONCE |
| T5–T7 | hmac_filter | Revoked key, beacon_sign round-trip, nonce cache wrap-around |
| T8–T12 | location_binding | Signature valid, outside range, RSSI fail, quorum pass/fail |
| T13–T16 | lkh_mgmt | init, revoke, revoke second vehicle, verify revoked cannot re-enter |
| T17–T20 | threshold_sig | Pass with majority, fail below threshold, floor enforcement, stale report |
| T21–T25 | kem | keygen, encapsulate, decapsulate, session key match, Fix-1 auth |
| T26–T30 | dilithium | keygen, sign, verify, domain separation, CA cert |
| T31–T35 | Cross-module | Fix-3 unified revocation, Fix-6 IPC file, Fix-7 domain tags |
| T36–T40 | crypto_pipeline | Full pipeline accept, full pipeline drop, alert passthrough |
| T41–T47 | Edge cases | KEYSTORE_FULL, CRL lookup, nonce cache full, agg_sig corruption detected |

### 18.2 Running Tests

```bash
cd crypto/

# Build and run all 47 tests:
make phase8_tests
./phase8_tests

# Clean test output for supervisor screenshots:
./phase8_tests 2>/dev/null | grep -E "^\[T|PASS|FAIL|═══|---"

# Expected output:
# === Phase 8 Integration Tests ===
# [T1]  HMAC accept .................................... PASS
# [T2]  HMAC invalid MAC .............................. PASS
# ...
# [T47] CRL lookup after unified revoke .............. PASS
# ═══════════════════════════════════════════════
# 47/47 tests passed
```

### 18.3 ASan + UBSan Build

```bash
make phase8_sanitize
./phase8_sanitize

# Expected:
# 47/47 tests passed
# (no AddressSanitizer or UndefinedBehaviorSanitizer errors)
```

ASan detects: out-of-bounds reads/writes, use-after-free, heap buffer overflow.
UBSan detects: signed integer overflow, misaligned access, null dereference, invalid enum values.

Both passing means: the same 47 tests pass with zero memory safety or undefined behaviour errors.

---

## 19. Output Files Reference

| File | Created by | Contents | Used by |
|------|-----------|---------|---------|
| `crypto_verified_events.csv` | `tgn_ingest_event()` in crypto_pipeline | One row per CRYPTO_ACCEPT event. Columns: `recv_time_s`, `claimed_ts_s`, `vehicle_id`, `edge_freshness`, `seq_gap`, `reporter_count`, `reporter_lat`, `reporter_lon`, `rssi`, `loc_bound_ok`, `thresh_ok`, `is_attack` | `tgn_train.py`, `tgn_detector.cc` |
| `crypto_drop_log.csv` | Gate checks in crypto_pipeline | Dropped events. Columns: `sim_time_ms`, `vehicle_id`, `drop_reason` (int from CryptoVerifyResult enum) | RSU audit log — NOT sent to blockchain |
| `beacon_evidence.csv` | RSU observation loop | GPS + RSSI evidence. Columns: `rsu_id`, `interval_ts_ms`, `vehicle_id`, `sender_ts_ms`, `gps_lat`, `gps_lon`, `rssi_dbm` | `submitToFabric.js` (BC-4 fix loads this as CSV) |
| `tgn_alerts_crypto.json` | Alert filtering in crypto_pipeline | Crypto-verified subset of tgn_alerts.json. Fields: `v_id`, `alpha`, `y_hat`, `S_trig`, `t_alert`, `tdet_ms`, `from_lw`, `from_fs` | `submitToFabric.js` (BC-1 fix reads this, not tgn_alerts.json) |
| `crypto_layer_log.txt` | All modules | Per-packet step trace with hex key material | Debugging |
| `lkh_revocation_log.csv` | `lkh_revoke_vehicle()` | Columns: `sim_time_ms`, `revoked_vehicle_id`, `kek_updates_count`, `depth` | Analysis — verify O(log n) cost |
| `kem_session_keys.csv` | `kem_rsu_encapsulate()` | KEM handshake records for each vehicle | Test/debug only |
| `dilithium_test_result.csv` | `dilithium` binary self-test | Keygen/sign/verify result, timing | Verification |

---

## 20. Constants Reference — teta_guard_types.h

| Constant | Value | Meaning |
|----------|-------|---------|
| `BEACON_INTERVAL_MS` | 100 | T_b — IEEE 802.11p beacon period |
| `PROPAGATION_TOL_MS` | 10 | ε — DSRC propagation budget |
| `FRESHNESS_WINDOW_MS` | 110 | T_b + ε — Gate 2 window |
| `NONCE_LEN` | 16 | 128-bit nonce |
| `NONCE_CACHE_SIZE` | 4096 | Per-sender nonce history depth |
| `SESSION_KEY_LEN` | 32 | 256-bit HMAC session key |
| `HMAC_SHA256_LEN` | 32 | HMAC output size |
| `AGG_SIG_LEN` | 32 | Aggregate sig (HMAC binding, NOT Dilithium5) |
| `DILITHIUM5_SIG_LEN` | 4595 | Dilithium5 signature bytes |
| `DILITHIUM5_PK_LEN` | 2592 | Dilithium5 public key bytes |
| `DILITHIUM5_SK_LEN` | 4864 | Dilithium5 secret key bytes |
| `R_COMM_METERS` | 300.0 | DSRC communication range |
| `RSSI_MIN_DBM` | -85.0 | Minimum RSSI at 300 m (5.9 GHz) |
| `MAX_VEHICLES` | 256 | Active fleet size (keystore capacity) |
| `MAX_CRL_ENTRIES` | 4096 | Lifetime revocation list capacity |
| `MAX_REPORTS_PER_RSU` | 64 | Max IndividualSignedReports per AggregateReport |
| `MAX_OBSERVATIONS_PER_RSU` | 200 | Max observations per BeaconEvidenceRecord |
| `THRESHOLD_T_FLOOR` | 3 | Minimum threshold t (Fix-4) |
| `THRESH_REPORT_WINDOW_MS` | 5000 | Max age of individual report vs aggregate timestamp |
| `LOCBIND_FRESHNESS_WINDOW_MS` | 5000 | Max age of location-bound report (Gate D) |
| `LKH_MAX_LEAVES` | 1024 | Maximum vehicles in LKH tree |
| `LKH_KEY_LEN` | 32 | KEK size (same as session key) |
| `RSSI_DISTANCE_MARGIN_DB` | 10.0 | Friis plausibility tolerance (Fix-5) |
| `KYBER1024_PK_LEN` | 1568 | Kyber-1024 public key bytes |
| `KYBER1024_CT_LEN` | 1568 | Kyber-1024 ciphertext bytes |
| `FIRESABER_PK_LEN` | 1312 | FireSaber public key bytes |
| `FIRESABER_CT_LEN` | 1472 | FireSaber ciphertext bytes |
| `TETA_REVOKE_FILE` | `/tmp/teta_guard_revoke.txt` | IPC file for blockchain→pipeline revocation (Fix-6) |

---

## 21. Full Pipeline Walk-Through: A Single Beacon Arriving at the RSU

This traces the complete journey of one beacon from vehicle V_i through the crypto layer.

**Scenario:** Vehicle V150 sends a topology beacon at t=10000 ms.

```
1. NS-3 simulation generates:
   pem_event_log.csv row:
   10.000,TOPOLOGY_UPDATE,150,150,150,150,151,10000,10002,...,0
   (sim_time=10s, physical_sender=V150, sender_ts=10000, recv_ts=10002, attack=0)

2. crypto_pipeline reads this row.

3. kem_lookup("V150")
   → not in keystore yet → provision_vehicle("V150")
   → stub: generate random 32-byte session key K_{V150,1}
   → store in g_keystore[0]

4. construct BeaconMessage from CSV row:
   msg.vehicle_id       = "V150"
   msg.sender_timestamp = 10000
   msg.nonce            = (derived from row hash in pipeline stub)
   msg.mac              = HMAC-SHA256(K_{V150,1}, payload||10000||nonce)

5. lw_mitigate(msg, recv_time=10002, K_{V150,1}, revoked=false, nonce_cache)

   Gate 1 — HMAC:
     expected = HMAC-SHA256(K_{V150,1}, payload||10000||nonce) = msg.mac ✓ PASS

   Gate 2 — Freshness:
     |10002 - 10000| = 2 ms ≤ 110 ms ✓ PASS

   Gate 3 — Nonce:
     nonce not in cache → add to cache ✓ PASS

   → return CRYPTO_ACCEPT

6. verify_threshold_sig() — skipped for lightweight beacons (only for RSU aggregates)
   verify_quorum()        — skipped (no location-bound reports for this event)

7. Construct CryptoVerifiedEvent:
   vehicle_id = "V150"
   sender_timestamp_ms = 10000
   recv_timestamp_ms   = 10002
   reporter_count      = 1
   location_binding_verified = false (not an ME event)
   threshold_sig_verified    = false (lightweight beacon)
   crypto_filter_result = CRYPTO_ACCEPT
   is_attack = false (from pem_event_log.csv attack_label=0)

8. tgn_ingest_event(&event)
   → write to crypto_verified_events.csv
   → write to pem_event_log_filtered.csv

9. crypto_layer_log.txt entry:
   [V150 @ 10.000s] ACCEPT | HMAC=ok | Fresh=2ms | Nonce=new
   Session key (first 8 bytes): a3f9c21b...

10. beacon_evidence.csv entry:
    RSU0,10002,V150,10000,6.936575,79.865326,-62.00
```

V150 is now tracked. Its session key is cached. All future beacons from V150 are checked against the same key. If V150 is later confirmed as an attacker, `lkh_revoke_vehicle("V150")` is called and all future beacons will return `CRYPTO_DROP_REVOKED_KEY`.

---

## 22. Common Errors and Fixes

### Error: `HAVE_LIBOQS is not defined and ALLOW_DILITHIUM_STUB is not set`

**Cause:** Building `dilithium` standalone without the stub flag.
**Fix:** The Makefile now adds `-DALLOW_DILITHIUM_STUB` to the standalone `dilithium` target. If you add a new binary that uses dilithium.cc without liboqs, add the flag.

### Error: `undefined reference to cert_revoke_vehicle`

**Cause:** A module links against `lkh_mgmt.cc` but not `dilithium.cc`. `cert_revoke_vehicle` is defined in `dilithium.cc`.
**Fix:** Add `$(DILITHIUM_OBJ)` to the link command for any binary that uses lkh_mgmt.

### Error: Pipeline outputs empty `tgn_alerts_crypto.json`

**Cause:** `tgn_alerts.json` in the parent directory is empty or the path is wrong.
**Fix:**
```bash
# Verify the file exists and has content:
cat ../tgn_alerts.json | head -5
# If empty, run the simulation first with an ME attack:
cd ~/ns-3.35
./waf --run "scratch/routing --simTime=60 --N_Vehicles=4 --attack_scenario=9"
# Then run the pipeline from the crypto directory:
cd ~/ns-3.35/scratch/"SDVN project"/SDVN-Temporal-Attacks/crypto
./crypto_pipeline ../pem_event_log.csv ../tgn_alerts.json
```

### Error: `crypto_drop_log.csv` shows only KEYSTORE_FULL, no DROP_INVALID_MAC

**Cause:** `PIPELINE_MAX_VEH` is too small — the pipeline stops provisioning after 16 vehicles and silently drops all others with KEYSTORE_FULL instead of running HMAC checks.
**Fix:** Increase `PIPELINE_MAX_VEH` in `crypto_pipeline.cc` to match `MAX_VEHICLES = 256`.

### Warning: `has_rsu_measurement = false` in location binding

**Cause:** Unit tests or stub builds do not fill `rsu_measured_rssi_dbm` (it is filled by the real RSU radio layer).
**Fix:** In simulation stubs, `has_rsu_measurement = false` causes a fallback to the vehicle's self-reported RSSI with a warning. This is acceptable in simulation — never leave it false in a live-radio build.

### Error: `THRESHOLD_SIG_FAIL` on every report

**Cause:** Individual signatures are not being verified (stub mode issue) OR `threshold_t` exceeds `n_reports` because the pipeline is only providing 1-2 reports but the floor requires 3.
**Fix:** Check `n_reports` in your AggregateReport. If `n_reports < THRESHOLD_T_FLOOR`, the threshold can never be met. You need at least 3 independent vehicle reports to pass threshold verification.

### Error: All events in `tgn_alerts_crypto.json` missing `from_fs: true`

**Cause:** The full TGN (`from_fs_path`) was not run — only the lightweight filter (`from_lw_path`). This is normal: `from_lw=true, from_fs=false` means the lightweight filter was sufficient.
**Explanation:** The two-path design is intentional: the lightweight filter runs first (cheap, fast), and the full TGN only runs when the lightweight filter is uncertain. Most alerts come from the lightweight path.

---

*Last updated: TETA-Guard crypto layer, FYP — Department of EIE, University of Ruhuna*
*All 47 phase8_tests pass. All 47 phase8_sanitize tests pass (ASan + UBSan clean).*
*450 DROP_INVALID_MAC events confirmed in ME attack simulation run.*
