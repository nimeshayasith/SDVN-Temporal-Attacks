# Pre-Detection Cryptographic Filter — TETA-Guard Layer 2

**Files:** `kem.cc` · `hmac_filter.cc` · `threshold_sig.cc` · `location_binding.cc` · `lkh_mgmt.cc` · `crypto_pipeline.cc`
**Paper reference:** Section 4 (Eqs. 3.14–3.17, 3.24–3.28, 3.35)

---

## Overview

The Pre-Detection Cryptographic Filter sits between the data plane and the detection engine. Every beacon is authenticated before it reaches the PEM signature detector or the TGN. It uses a combined HMAC–timestamp–nonce triple.

```
Data Plane (routing.cc)
        │  pem_event_log.csv
        ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2 — Pre-Detection Cryptographic Filter       │
│                                                     │
│  ① KEM key lookup        (kem.cc)                  │
│  ② HMAC integrity         (hmac_filter.cc, Eq.3.14) │
│  ③ Timestamp freshness    (hmac_filter.cc, Eq.3.15) │
│  ④ Nonce novelty          (hmac_filter.cc, Eq.3.16) │
│  ⑤ Threshold aggregate sig(threshold_sig.cc,Eq.3.24)│
│  ⑥ Location binding       (location_binding.cc,     │
│                             Eqs.3.25–3.28)          │
│  ⑦ LKH revocation         (lkh_mgmt.cc, Eq.3.17)   │
│                                                     │
│  Orchestrated by: crypto_pipeline.cc               │
└─────────────────────────────────────────────────────┘
        │  crypto_verified_events.csv
        │  crypto_drop_log.csv
        │  beacon_evidence.csv
        ▼
TGN / PEM Detector (tgn_detector.cc)
```

---

## Three Conditions (Eq. 3.35 — Algorithm 3: LW-MITIGATE)

Every incoming beacon must satisfy all three simultaneously:

### 1. HMAC Integrity — Eq. 3.14
```
HMAC-SHA256(K_Vi,nk, nonce, m') = MAC_received
```
- `m' = m ∥ τs ∥ nonce_i`  (Eq. 3.35)
- Session key `K_Vi,nk` established via Kyber+Saber Hybrid-KEM
- Implemented in: `hmac_filter.cc:lw_mitigate()` Step 2

### 2. Timestamp Freshness — Eq. 3.15
```
|τr − τs| ≤ T_b + ε    (T_b = 100 ms, ε = 10 ms)
```
- Blocks TTW-class replays with stale timestamps
- Implemented in: `hmac_filter.cc:lw_mitigate()` Step 3
- Constants in `teta_guard_types.h`: `BEACON_INTERVAL_MS=100`, `PROPAGATION_TOL_MS=10`

### 3. Nonce Novelty — Eq. 3.16
```
nonce_i ∉ N_seen
```
- Blocks BSHH intra-session replays
- Implemented in: `hmac_filter.cc:lw_mitigate()` Step 4
- Nonce cache: `NONCE_CACHE_SIZE = 4096` entries per sender

### Algorithm 3 — Sequential Order (strictly enforced)

```
Step 1: Build m' = m ∥ τs ∥ nonce_i
Step 2: Recompute HMAC → mismatch → DROP (CRYPTO_DROP_INVALID_MAC)
Step 3: |τr − τs| > T_b + ε → DROP (CRYPTO_DROP_STALE_TIMESTAMP)
Step 4: nonce_i ∈ N_seen → DROP (CRYPTO_DROP_REPLAYED_NONCE)
Step 5: Add nonce to N_seen → ACCEPT (CRYPTO_ACCEPT)
```

The MAC check fires before freshness — a forged MAC is rejected immediately without revealing timing information.

---

## Module Files

### `kem.cc` — Key Encapsulation (Section 3.3)
- Kyber-512 + **Saber** Hybrid-KEM for session key establishment (`OQS_KEM_alg_kyber_512` + `OQS_KEM_alg_saber`)
- `VehicleKeyRecord` struct: vehicle_id, session_key, revoked flag
- Key lookup: `kem_lookup(vehicle_id)` → `VehicleKeyRecord*`
- Handshake latency: millisecond-level, within 10 ms V2X constraint
- **Wire sizes** (`teta_guard_types.h`):

| Component | PK | SK | CT | SS |
|-----------|----|----|----|----|
| Kyber-512 | 800 B | 1632 B | 768 B | 32 B |
| Saber | 992 B | 2304 B | 1088 B | 32 B |

- **Stub mode warning:** When compiled without `-DHAVE_LIBOQS`, a prominent `stderr` banner is printed at startup. The fallback uses HKDF-SHA256 — not IND-CCA2 secure.
- **Previous bug (fixed):** All four `kem_s` initialisations used `OQS_KEM_alg_kyber_512` instead of `OQS_KEM_alg_saber`, making the hybrid KEM Kyber⊕Kyber rather than Kyber⊕Saber as the paper claims.

### `hmac_filter.cc` — HMAC + Freshness + Nonce (Section 4.4)
- `lw_mitigate(msg, recv_time_ms, session_key, key_revoked, nonce_cache)` → `CryptoVerifyResult`
- `beacon_sign(msg, session_key)` — vehicle-side signing before transmission
- Return codes: `CRYPTO_ACCEPT`, `CRYPTO_DROP_INVALID_MAC`, `CRYPTO_DROP_STALE_TIMESTAMP`, `CRYPTO_DROP_REPLAYED_NONCE`, `CRYPTO_DROP_REVOKED_KEY`
- Per-message latency: 1–2 µs on ARM Cortex-M (< 2% of 100 ms beacon interval)

### `threshold_sig.cc` — RSU Aggregate Signatures (Eq. 3.24)
```
Verify(σagg, PKagg) = 1  ⟺  |{i : Verify(σi, msgi, PKVi) = 1}| ≥ t,   t ≥ ⌊n/2⌋ + 1
```
- NTRU lattice-based scheme (post-quantum secure)
- Requires strict majority of individual vehicle signatures
- Per-verification latency: ~1.6 ms — within SDVN latency budget
- Eliminates vehicle-origin and RSU-origin BSHH vectors
- **Stub mode warning:** When compiled without `-DHAVE_LIBOQS`, a prominent `stderr` banner is printed. Dilithium2 sign/verify are placeholders.

### `location_binding.cc` — ME Location Binding (Eqs. 3.25–3.28)
Each topology report is signed with the reporter's GPS position and RSSI:
```
m'_Vk = eij ∥ pos_Vk ∥ RSSI_Vk←Vi ∥ τs ∥ nonce
σ_Vk  = Sign(SK_Vk, m'_Vk)
```
Accept only if:
1. Signature valid
2. `d(pos_Vk, eij) ≤ r_comm` — spatial plausibility (300 m)
3. `RSSI_Vk←Vi ≥ RSSI_min` — signal plausibility (−85 dBm)
4. Quorum of ≥ t consistent witnesses (Eqs. 3.27–3.28)

### `lkh_mgmt.cc` — LKH Key Revocation (Eq. 3.17)
```
C_revoke = O(log n)    depth d = ⌈log₂n⌉
```
- Binary LKH tree: only d KEKs on the path leaf→root need updating
- 1,000 vehicles → ~10 key updates (vs. 1,000 under naïve full re-key)
- `lkh_revoke_vehicle(tree, vehicle_id)` — revokes and regenerates path KEKs
- `distribute_kek_updates(tree)` — schedules DSRC/CSMA delivery **within next T_b**
- Output: `lkh_revocation_log.csv`

### `crypto_pipeline.cc` — End-to-End Orchestrator (Section 8)
Wires all five modules:
```
pem_event_log.csv
    ↓
① KEM lookup
② lw_mitigate() — HMAC + freshness + nonce
③ verify_threshold_sig() — RSU-aggregated reports (Eq. 3.24)
④ verify_quorum() — ME witness check (Eqs. 3.27–3.28)
⑤ CryptoVerifiedEvent → tgn_ingest_event()
⑥ LKH revocation on confirmed alerts
    ↓
crypto_verified_events.csv
crypto_drop_log.csv
beacon_evidence.csv
```

---

## Cryptographic Placement Analysis

| Attack | Attacker Position | Crypto Effectiveness |
|--------|-------------------|----------------------|
| TTW | Vehicle / RSU | ✅ Eliminated — nonce + freshness fail replay |
| TTW | Controller | ❌ None — insider holds valid keys; TGN primary |
| BSHH | Vehicle / RSU | ✅ Eliminated — threshold aggregate signatures |
| BSHH | Controller | ❌ None — insider; TGN + liveness check required |
| ME | Vehicle | ⚠️ Partial — location-binding + RSSI check |
| ME | RSU (colluding) | ⚠️ Hybrid — crypto + TGN both required |
| ME | Controller | ❌ None — direct topology injection; TGN primary |

**Core principle:** Crypto provides pre-detection value if and only if the attacker cannot pass cryptographic verification. Controller/insider attackers hold valid credentials — enforcement must be post-detection (TGN + blockchain).

---

## Output Files

| File | Contents |
|------|----------|
| `crypto_verified_events.csv` | Events that passed all checks — fed to TGN |
| `crypto_drop_log.csv` | Dropped events with reason (STALE/REPLAY/REVOKED/BAD_MAC) |
| `beacon_evidence.csv` | `BeaconEvidenceRecord B_nk(t)` submitted to blockchain |
| `crypto_layer_log.txt` | Step-by-step trace per packet with hex key material |
| `lkh_revocation_log.csv` | Per-revocation KEK update counts |

---

## Blockchain Signature Verification (`verification.go`)

Split into three files using Go build tags:

| File | Build condition | Behaviour |
|------|----------------|-----------|
| `verification.go` | always | Shared: `verifyThresholdSig`, `verifyQuorum`, `haversineDistanceM`, `resolveDualPath` |
| `verification_stub.go` | `//go:build !liboqs` (default) | Stub: `verifyDilithium2Sig` accepts any non-empty sig; prints warning banner in `init()` |
| `verification_liboqs.go` | `//go:build liboqs` | Real: `verifyDilithium2Sig` calls liboqs-go `Signature.Verify("Dilithium2", ...)` |

Enable real Dilithium2:
```bash
go get github.com/open-quantum-safe/liboqs-go
go build -tags liboqs ./...
```

---

## Build and Run

```bash
# Step 0 — Install liboqs for real PQC (optional but required for paper claims)
sudo apt-get install cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && ninja && sudo ninja install && sudo ldconfig

# Build stub mode (OpenSSL only — warnings printed at runtime)
g++ -std=c++17 -O2 crypto_pipeline.cc -lssl -lcrypto -lm -o crypto_pipeline

# Build real PQC mode
g++ -std=c++17 -O2 -DHAVE_LIBOQS -DHAVE_OPENSSL \
    crypto_pipeline.cc -loqs -lssl -lcrypto -lm -o crypto_pipeline

# Run pipeline (after routing.cc simulation — see RUN_COMMANDS.md Step 2.5 for file handoff)
./crypto_pipeline pem_event_log_s1.csv tgn_alerts.json

# Run individual module tests (stub mode)
g++ -std=c++17 -O2 hmac_filter.cc       -lssl -lcrypto -DHMAC_TESTS      -o hmac_test    && ./hmac_test
g++ -std=c++17 -O2 kem.cc               -lssl -lcrypto -DKEM_TESTS        -o kem_test     && ./kem_test
g++ -std=c++17 -O2 threshold_sig.cc     -lssl -lcrypto -DTHRESHOLD_TESTS  -o thresh_test  && ./thresh_test
g++ -std=c++17 -O2 location_binding.cc  -lssl -lcrypto -DLOCATION_TESTS   -o loc_test     && ./loc_test
g++ -std=c++17 -O2 lkh_mgmt.cc          -lssl -lcrypto -DLKH_TESTS        -o lkh_test     && ./lkh_test
g++ -std=c++17 -O2 crypto_pipeline.cc   -lssl -lcrypto -DPHASE8_TESTS     -o phase8_test  && ./phase8_test
```
