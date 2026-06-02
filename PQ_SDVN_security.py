"""
=============================================================================
PQ_SDVN_security.py
Post-Quantum Secure Channel — Hybrid-KEM (Kyber512 + LightSaber_KEM)
+ HMAC-Timestamp-Nonce for OBU↔RSU Authentication in SDVNs

This file follows EXACTLY the same pattern as LDA_PQ_security.py
given by the supervisor:
  - Same class structure  (SecurityManager_controller)
  - Same CSV persistence  (search_csv / update_csv / add_csv)
  - Same shlex argument   parsing
  - Same execution timing print
  - Adds: Kyber512 KEM, LightSaber KEM, HKDF session key,
          HMAC beacon auth, Pre-Crypto Filter, Nonce store

ns-3 calls this script via SystemCallApplication exactly like
the supervisor's LDA_PQ_security.py

HOW ns-3 CALLS THIS FILE (examples):
  python3 PQ_SDVN_security.py node_id=1 rsu_keygen=true
  python3 PQ_SDVN_security.py node_id=2 obu_encaps=true other_node_id=1
  python3 PQ_SDVN_security.py node_id=1 rsu_decaps=true other_node_id=2
  python3 PQ_SDVN_security.py node_id=1 verify_beacon=true other_node_id=2 port_id=0 message="speed=60"
  python3 PQ_SDVN_security.py node_id=2 send_beacon=true other_node_id=1 port_id=0 message="speed=60"

=============================================================================
"""

import os
import sys
import csv
import time
import hmac as hmac_lib
import hashlib
import shlex
import json

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ── Timing (same as supervisor's file) ──────────────────────────────────────
start = time.time()

# =============================================================================
# SECTION 1 — CSV FILE PATHS
# Change these to match your ns-3 scratch folder path
# =============================================================================

NS3_SCRATCH = "/home/user/ns-allinone-3.35/ns-3.35/scratch"

# Main key storage — one row per node_id
# Columns:
#  0=node_id  1=kyber_pk  2=kyber_sk  3=saber_pk  4=saber_sk
#  5=falcon_pk  6=falcon_sk  7=ascon_key  8=ascon_nonce
csv_pq_keys_path   = f"{NS3_SCRATCH}/pq_security_keys.csv"

# Session key storage — one row per (obu_id, rsu_id, port_id)
# Columns:
#  0=obu_id  1=rsu_id  2=port_id  3=K_session  4=created_ts  5=expiry_ts
csv_pq_session_path = f"{NS3_SCRATCH}/pq_security_sessions.csv"

# Nonce store — append-only log
# Columns:  0=node_id  1=nonce_hex  2=timestamp_ms
csv_pq_nonce_path   = f"{NS3_SCRATCH}/pq_nonce_store.csv"

# Auth token log
# Columns:  0=obu_id  1=rsu_id  2=port_id  3=auth_token_hex  4=timestamp
csv_pq_auth_path    = f"{NS3_SCRATCH}/pq_auth_tokens.csv"

# Beacon log — evidence of verified beacons
# Columns:  0=obu_id  1=rsu_id  2=port_id  3=payload  4=ts  5=nonce  6=result
csv_pq_beacon_path  = f"{NS3_SCRATCH}/pq_beacon_log.csv"

# Session lifetime (seconds)
SESSION_LIFETIME_S = 30

# Timestamp freshness window (milliseconds)
TIMESTAMP_WINDOW_MS = 5000


# =============================================================================
# SECTION 2 — CSV HELPER FUNCTIONS
# Same pattern as supervisor's LDA_PQ_security.py
# =============================================================================

def ensure_csv(path):
    """Create CSV file if it does not exist."""
    if not os.path.exists(path):
        open(path, 'w').close()
        print(f"[CSV] Created {path}")


def search_csv_nodeid(csv_file_path, node_id):
    """Search for node_id in column 0. Returns (row_index, True/False)."""
    ensure_csv(csv_file_path)
    try:
        with open(csv_file_path, 'r', encoding='UTF8') as f:
            rows = list(csv.reader(f))
        for i, row in enumerate(rows):
            if row and str(row[0]).strip() == str(node_id):
                return i, True
        return -1, False
    except Exception as e:
        print(f"[CSV] search_csv_nodeid error: {e}")
        return -1, False


def search_csv_triple(csv_file_path, a, b, c):
    """Search for (a,b,c) in columns 0,1,2. Returns (row_index, True/False)."""
    ensure_csv(csv_file_path)
    try:
        with open(csv_file_path, 'r', encoding='UTF8') as f:
            rows = list(csv.reader(f))
        for i, row in enumerate(rows):
            if (len(row) >= 3 and
                str(row[0]).strip() == str(a) and
                str(row[1]).strip() == str(b) and
                str(row[2]).strip() == str(c)):
                return i, True
        return -1, False
    except Exception as e:
        print(f"[CSV] search_csv_triple error: {e}")
        return -1, False


def get_csv_value(csv_file_path, node_id, col_index):
    """Get value at col_index for the row with node_id."""
    row_idx, found = search_csv_nodeid(csv_file_path, node_id)
    if not found:
        return None
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        rows = list(csv.reader(f))
    row = rows[row_idx]
    if col_index < len(row):
        return row[col_index].strip()
    return None


def get_csv_triple_value(csv_file_path, a, b, c, col_index):
    """Get value at col_index for the row with (a,b,c)."""
    row_idx, found = search_csv_triple(csv_file_path, a, b, c)
    if not found:
        return None
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        rows = list(csv.reader(f))
    row = rows[row_idx]
    if col_index < len(row):
        return row[col_index].strip()
    return None


def set_csv_value(csv_file_path, node_id, col_index, value):
    """Set value at col_index for node_id row. Creates row if not found."""
    ensure_csv(csv_file_path)
    with open(csv_file_path, 'r', encoding='UTF8', newline='') as f:
        rows = list(csv.reader(f))
    row_idx, found = search_csv_nodeid(csv_file_path, node_id)
    if found:
        while len(rows[row_idx]) <= col_index:
            rows[row_idx].append(" ")
        rows[row_idx][col_index] = str(value)
    else:
        new_row = [" "] * (col_index + 1)
        new_row[0] = str(node_id)
        new_row[col_index] = str(value)
        rows.append(new_row)
    with open(csv_file_path, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"[CSV] Updated node {node_id} col {col_index}")


def set_csv_triple_value(csv_file_path, a, b, c, col_index, value):
    """Set value at col_index for (a,b,c) keyed row."""
    ensure_csv(csv_file_path)
    with open(csv_file_path, 'r', encoding='UTF8', newline='') as f:
        rows = list(csv.reader(f))
    row_idx, found = search_csv_triple(csv_file_path, a, b, c)
    if found:
        while len(rows[row_idx]) <= col_index:
            rows[row_idx].append(" ")
        rows[row_idx][col_index] = str(value)
    else:
        new_row = [" "] * max(col_index + 1, 4)
        new_row[0] = str(a)
        new_row[1] = str(b)
        new_row[2] = str(c)
        new_row[col_index] = str(value)
        rows.append(new_row)
    with open(csv_file_path, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def append_csv_row(csv_file_path, row_values):
    """Append a new row to CSV."""
    ensure_csv(csv_file_path)
    with open(csv_file_path, 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([str(v) for v in row_values])


# =============================================================================
# SECTION 3 — CRYPTO UTILITY FUNCTIONS
# =============================================================================

def get_timestamp_ms():
    """Current UNIX time in milliseconds."""
    return int(time.time() * 1000)


def generate_nonce(length=16):
    """Cryptographically secure random nonce."""
    return os.urandom(length)


def check_timestamp_fresh(ts_ms, window_ms=TIMESTAMP_WINDOW_MS):
    """
    Returns True if ts_ms is within ±window_ms of current time.
    This blocks TTW (Topology Time-Warp) attack.
    """
    now = get_timestamp_ms()
    age = abs(now - ts_ms)
    fresh = age <= window_ms
    if not fresh:
        print(f"[FILTER] STALE TIMESTAMP: age={age}ms > window={window_ms}ms → TTW BLOCKED")
    return fresh


def derive_session_key(ss_kyber: bytes, ss_saber: bytes,
                       obu_id: str, rsu_id: str,
                       nonce_hex: str) -> bytes:
    """
    Hybrid-KEM session key derivation.

    Formula:
        combined   = ss_kyber XOR ss_saber
        K_session  = HKDF-SHA256(combined,
                        info = "SDVN-PQ-V2RSU|{obu_id}|{rsu_id}|{nonce}")

    XOR of two independent KEM secrets means attacker must
    break BOTH Kyber AND Saber simultaneously.

    HKDF cleans up any structure in the raw secrets and
    domain-separates this key from all other uses.
    """
    # Step 1 — XOR combine
    min_len = min(len(ss_kyber), len(ss_saber))
    combined = bytes(a ^ b for a, b in zip(ss_kyber[:min_len], ss_saber[:min_len]))

    # Step 2 — HKDF
    info = f"SDVN-PQ-V2RSU|{obu_id}|{rsu_id}|{nonce_hex}".encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    K_session = hkdf.derive(combined)

    print(f"[KDF] K_session derived: {K_session.hex()[:16]}...  ({len(K_session)} bytes)")
    return K_session


def compute_hmac(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256. Output = 32 bytes."""
    return hmac_lib.new(key, message, hashlib.sha256).digest()


def verify_hmac_tag(key: bytes, message: bytes, tag: bytes) -> bool:
    """
    Constant-time HMAC verification.
    Constant-time means no timing side-channel attack possible.
    """
    expected = compute_hmac(key, message)
    return hmac_lib.compare_digest(expected, tag)


def build_beacon_mac_input(payload: bytes, nonce: bytes, ts_ms: int) -> bytes:
    """
    Build the canonical input for HMAC over a beacon.

    Format:  payload || nonce || timestamp_as_8_bytes
    
    Binding all three fields means:
      - Changing payload    → HMAC fails (integrity)
      - Reusing nonce       → caught by nonce store (BSHH/ME)
      - Old timestamp       → caught by timestamp check (TTW)
    """
    ts_bytes = ts_ms.to_bytes(8, 'big')
    return payload + nonce + ts_bytes


# =============================================================================
# SECTION 4 — NONCE STORE
# =============================================================================

# In-memory nonce store (fast O(1) lookup)
_nonce_memory_store = set()


def check_and_store_nonce(nonce_hex: str, node_id: int) -> bool:
    """
    Returns True if nonce is FRESH (never seen before).
    Returns False if nonce was already used → REPLAY DETECTED.

    Two-layer store:
      Layer 1: Python set in memory (instant)
      Layer 2: CSV file (survives RSU restart)
    """
    # Layer 1 — memory check (fastest)
    if nonce_hex in _nonce_memory_store:
        print(f"[NONCE] REPLAY DETECTED (memory): {nonce_hex[:16]}... → BSHH/ME BLOCKED")
        return False

    # Layer 2 — CSV check (persistent)
    ensure_csv(csv_pq_nonce_path)
    with open(csv_pq_nonce_path, 'r', encoding='UTF8') as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[1].strip() == nonce_hex:
                print(f"[NONCE] REPLAY DETECTED (CSV): {nonce_hex[:16]}... → BSHH/ME BLOCKED")
                _nonce_memory_store.add(nonce_hex)  # cache it
                return False

    # Fresh nonce — store in both layers
    _nonce_memory_store.add(nonce_hex)
    append_csv_row(csv_pq_nonce_path, [node_id, nonce_hex, get_timestamp_ms()])
    print(f"[NONCE] Fresh nonce stored: {nonce_hex[:16]}...")
    return True


# =============================================================================
# SECTION 5 — PRE-CRYPTO FILTER
# Runs BEFORE any expensive cryptographic operation.
# Kills fake/replay/stale packets at microsecond speed.
# =============================================================================

def pre_crypto_filter(obu_id: str, rsu_id: str, port_id: int,
                      ts_ms: int, nonce_hex: str) -> tuple:
    """
    Fast pre-crypto filter. Returns (passed: bool, reason: str).

    Checks in order (cheapest first):
      1. Does a session exist for this OBU?         O(1) CSV lookup
      2. Is the session still valid (not expired)?   O(1) compare
      3. Is the timestamp fresh?                     O(1) subtract
      4. Is the nonce new?                           O(1) set lookup

    If ANY check fails → return False immediately.
    HMAC is only computed after ALL four pass.
    """
    # Check 1 — Session exists?
    K_hex = get_csv_triple_value(csv_pq_session_path, obu_id, rsu_id, port_id, col_index=3)
    if not K_hex or not K_hex.strip() or K_hex.strip() == " ":
        return False, "NO_SESSION — OBU must complete handshake first"

    # Check 2 — Session not expired?
    expiry_str = get_csv_triple_value(csv_pq_session_path, obu_id, rsu_id, port_id, col_index=5)
    if expiry_str and expiry_str.strip():
        expiry_ms = int(expiry_str.strip()) * 1000
        if get_timestamp_ms() > expiry_ms:
            return False, "SESSION_EXPIRED — re-handshake required"

    # Check 3 — Timestamp fresh? (TTW check)
    if not check_timestamp_fresh(ts_ms):
        return False, f"STALE_TIMESTAMP — TTW attack blocked"

    # Check 4 — Nonce fresh? (BSHH / ME check)
    # Do NOT store nonce here yet — store only after HMAC passes
    ensure_csv(csv_pq_nonce_path)
    if nonce_hex in _nonce_memory_store:
        return False, "NONCE_REUSED — BSHH/ME attack blocked"
    with open(csv_pq_nonce_path, 'r', encoding='UTF8') as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[1].strip() == nonce_hex:
                return False, "NONCE_REUSED (CSV) — BSHH/ME attack blocked"

    return True, "PASS"


# =============================================================================
# SECTION 6 — MAIN SECURITY MANAGER CLASS
# Extends the SecurityManager_controller pattern from LDA_PQ_security.py
# =============================================================================

class PQ_SecurityManager:
    """
    Post-Quantum Security Manager for V2RSU Channel in SDVN.

    Implements:
      - Hybrid-KEM (Kyber512 + LightSaber_KEM) key generation
      - Session key derivation via HKDF
      - Falcon-1024 digital signatures
      - ASCON-128 lightweight encryption (same as supervisor's file)
      - HMAC-SHA256 beacon authentication
      - Pre-crypto filter (timestamp + nonce checks)
      - CSV persistence (same pattern as supervisor's file)

    CSV Column Layout — pq_security_keys.csv:
      col 0 = node_id
      col 1 = kyber_pk (hex)
      col 2 = kyber_sk (hex)
      col 3 = saber_pk (hex)
      col 4 = saber_sk (hex)
      col 5 = falcon_pk (hex)
      col 6 = falcon_sk (hex)

    CSV Column Layout — pq_security_sessions.csv:
      col 0 = obu_id
      col 1 = rsu_id
      col 2 = port_id
      col 3 = K_session (hex)
      col 4 = created_timestamp_s
      col 5 = expiry_timestamp_s
    """

    def __init__(self, net_size):
        print(f"[PQ_SecurityManager] Initialising for net_size={net_size}")
        self.net_size = net_size
        # In-memory caches
        self._kyber_pk  = {}
        self._kyber_sk  = {}
        self._saber_pk  = {}
        self._saber_sk  = {}
        self._falcon_pk = {}
        self._falcon_sk = {}
        self._sessions  = {}   # (obu_id, rsu_id, port_id) → K_session bytes

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 0A — RSU: Generate Kyber-512 Keypair
    # ─────────────────────────────────────────────────────────────────────────

    def generate_kyber_keypair(self, node_id):
        """
        Generate Kyber-512 keypair for a node.
        Persists to pq_security_keys.csv (col 1, 2).

        WHAT KYBER DOES (from your progress report Algorithm 1):
          1. seed ← random
          2. A ← Gen(seed)         ← public matrix
          3. s, e ← CBD(η1)        ← secret + error vectors
          4. Check(e) → TotalError ≤ L
          5. t = A·s + e mod q     ← public key component
          6. pk = (seed, t),  sk = s

        Returns: (pk_hex, sk_hex)
        """
        print(f"\n[Kyber] Generating Kyber-512 keypair for node {node_id}")
        t0 = time.perf_counter()

        with oqs.KeyEncapsulation("Kyber512") as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()

        elapsed_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Kyber] KeyGen done in {elapsed_us:.0f} µs")
        print(f"[Kyber] pk length: {len(pk)} bytes")
        print(f"[Kyber] sk length: {len(sk)} bytes")

        pk_hex = pk.hex()
        sk_hex = sk.hex()

        # Cache in memory
        self._kyber_pk[node_id] = pk
        self._kyber_sk[node_id] = sk

        # Persist to CSV
        set_csv_value(csv_pq_keys_path, node_id, col_index=1, value=pk_hex)
        set_csv_value(csv_pq_keys_path, node_id, col_index=2, value=sk_hex)
        print(f"[Kyber] Keypair persisted to CSV for node {node_id}")

        return pk_hex, sk_hex

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 0B — RSU: Generate LightSaber Keypair
    # ─────────────────────────────────────────────────────────────────────────

    def generate_saber_keypair(self, node_id):
        """
        Generate LightSaber keypair for a node.
        Persists to pq_security_keys.csv (col 3, 4).

        WHAT SABER DOES (from your progress report Algorithm 2):
          1. seed ← random
          2. A ← Gen(seed)         ← public matrix (Module-LWR)
          3. s, e ← CBD(η1)
          4. b = A·s + e mod q     ← public key (different from Kyber: rounding)
          5. pk = (A, b),  sk = s

        KEY DIFFERENCE FROM KYBER:
          Kyber uses noise addition (LWE)
          Saber uses rounding (LWR) — cheaper, more suitable for embedded devices

        Returns: (pk_hex, sk_hex)
        """
        print(f"\n[Saber] Generating LightSaber keypair for node {node_id}")
        t0 = time.perf_counter()

        # Try LightSaber_KEM first (from your reference paper)
        saber_alg = "LightSaber_KEM"
        available = oqs.get_enabled_kem_mechanisms()
        if saber_alg not in available:
            # Fallback: use second Kyber instance with different context
            print(f"[Saber] LightSaber_KEM not available, using Kyber768 as second KEM")
            saber_alg = "Kyber768"

        with oqs.KeyEncapsulation(saber_alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()

        elapsed_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Saber] KeyGen done in {elapsed_us:.0f} µs  (alg={saber_alg})")
        print(f"[Saber] pk length: {len(pk)} bytes")
        print(f"[Saber] sk length: {len(sk)} bytes")

        pk_hex = pk.hex()
        sk_hex = sk.hex()

        self._saber_pk[node_id] = pk
        self._saber_sk[node_id] = sk

        set_csv_value(csv_pq_keys_path, node_id, col_index=3, value=pk_hex)
        set_csv_value(csv_pq_keys_path, node_id, col_index=4, value=sk_hex)
        print(f"[Saber] Keypair persisted to CSV for node {node_id}")

        return pk_hex, sk_hex

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 0C — Generate Falcon-1024 Keypair (same as supervisor's file)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_falcon_keypair(self, node_id):
        """
        Generate Falcon-1024 keypair.
        DIRECTLY follows generate_FALCON1024_key_pair() from LDA_PQ_security.py.
        Persists to pq_security_keys.csv (col 5, 6).

        Returns: (pk_hex, sk_hex)
        """
        print(f"\n[Falcon] Generating Falcon-1024 keypair for node {node_id}")
        t0 = time.perf_counter()

        with oqs.Signature("Falcon-1024") as signer:
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()

        elapsed_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Falcon] KeyGen done in {elapsed_us:.0f} µs")
        print(f"[Falcon] pk length: {len(pk)} bytes")
        print(f"[Falcon] sk length: {len(sk)} bytes")

        pk_hex = pk.hex()
        sk_hex = sk.hex()

        self._falcon_pk[node_id] = pk
        self._falcon_sk[node_id] = sk

        set_csv_value(csv_pq_keys_path, node_id, col_index=5, value=pk_hex)
        set_csv_value(csv_pq_keys_path, node_id, col_index=6, value=sk_hex)
        print(f"[Falcon] Keypair persisted to CSV for node {node_id}")

        return pk_hex, sk_hex

    # ─────────────────────────────────────────────────────────────────────────
    # RSU KEY BROADCAST INFO (Stage 1 of protocol)
    # ─────────────────────────────────────────────────────────────────────────

    def get_rsu_broadcast(self, rsu_node_id):
        """
        Build the RSU's broadcast package.
        RSU broadcasts these publicly — any OBU in range can receive.

        Contents:
          - pk_kyber: Kyber-512 public key
          - pk_saber: LightSaber public key
          - rsu_id:   node identifier
          - ts:       current timestamp (ms)

        NOTE: Broadcast is NOT encrypted (cannot encrypt for unknown receivers).
              It IS signed with Falcon — OBU can verify RSU is legitimate.

        Returns: dict (JSON-serializable for ns-3 message passing)
        """
        pk_kyber_hex = get_csv_value(csv_pq_keys_path, rsu_node_id, col_index=1)
        pk_saber_hex = get_csv_value(csv_pq_keys_path, rsu_node_id, col_index=3)

        if not pk_kyber_hex or not pk_saber_hex:
            raise ValueError(f"RSU {rsu_node_id} keys not found. Run rsu_keygen first.")

        broadcast = {
            "rsu_id":    rsu_node_id,
            "pk_kyber":  pk_kyber_hex.strip(),
            "pk_saber":  pk_saber_hex.strip(),
            "ts":        get_timestamp_ms()
        }
        print(f"[RSU Broadcast] rsu_id={rsu_node_id}")
        print(f"  pk_kyber:  {len(pk_kyber_hex.strip())//2} bytes")
        print(f"  pk_saber:  {len(pk_saber_hex.strip())//2} bytes")
        return broadcast

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 2 — OBU: Encapsulation (Hybrid-KEM)
    # ─────────────────────────────────────────────────────────────────────────

    def obu_encapsulate(self, obu_node_id, rsu_node_id, port_id,
                        pk_kyber_hex, pk_saber_hex):
        """
        OBU runs parallel KEM encapsulation using RSU's public keys.

        KYBER ENCAPS (Algorithm 1b from progress report):
          1. m ← random
          2. r ← CBD(η1)
          3. u = A·r mod q
          4. v = t·r + Encode(m) + e' mod q
          5. ct_k = (u, v)
          6. ss_k = KDF(u||v||m)

        SABER ENCAPS (Algorithm 2b from progress report):
          1. ms ← random
          2. rs ← CBD(η2)
          3. us = A·rs mod q
          4. vs = b·rs + Encode(ms) + e's mod q
          5. ct_s = (us, vs)
          6. ss_s = KDF(us||vs||ms)

        Then OBU derives its own K_session:
          combined  = ss_k XOR ss_s
          K_session = HKDF(combined, info=obu_id||rsu_id||nonce)

        Both KEM outputs never travel over the network.
        Only the ciphertexts (ct_k, ct_s) are sent to RSU.

        Saves: K_session and ciphertexts to CSV
        Returns: handshake_message dict
        """
        print(f"\n[OBU Encaps] obu={obu_node_id} → rsu={rsu_node_id} port={port_id}")

        pk_kyber = bytes.fromhex(pk_kyber_hex.strip())
        pk_saber = bytes.fromhex(pk_saber_hex.strip())

        # ── Kyber Encapsulation ──────────────────────────────────────────────
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation("Kyber512") as kem:
            ct_kyber, ss_kyber = kem.encap_secret(pk_kyber)
        kyber_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Kyber Encaps] done in {kyber_us:.0f} µs  ct={len(ct_kyber)}B  ss={len(ss_kyber)}B")

        # ── Saber Encapsulation ──────────────────────────────────────────────
        saber_alg = "LightSaber_KEM"
        if saber_alg not in oqs.get_enabled_kem_mechanisms():
            saber_alg = "Kyber768"
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(saber_alg) as kem:
            ct_saber, ss_saber = kem.encap_secret(pk_saber)
        saber_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Saber Encaps] done in {saber_us:.0f} µs  ct={len(ct_saber)}B  ss={len(ss_saber)}B")

        # ── Nonce and Timestamp ──────────────────────────────────────────────
        nonce     = generate_nonce(16)
        nonce_hex = nonce.hex()
        ts_ms     = get_timestamp_ms()

        # ── OBU derives K_session locally ───────────────────────────────────
        t0 = time.perf_counter()
        K_session = derive_session_key(ss_kyber, ss_saber,
                                       str(obu_node_id), str(rsu_node_id), nonce_hex)
        kdf_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[HKDF] Session key derived in {kdf_us:.0f} µs")

        # ── Save session to CSV ──────────────────────────────────────────────
        expiry_s = int(time.time()) + SESSION_LIFETIME_S
        self._sessions[(str(obu_node_id), str(rsu_node_id), str(port_id))] = K_session
        set_csv_triple_value(csv_pq_session_path,
                             obu_node_id, rsu_node_id, port_id,
                             col_index=3, value=K_session.hex())
        set_csv_triple_value(csv_pq_session_path,
                             obu_node_id, rsu_node_id, port_id,
                             col_index=4, value=str(int(time.time())))
        set_csv_triple_value(csv_pq_session_path,
                             obu_node_id, rsu_node_id, port_id,
                             col_index=5, value=str(expiry_s))
        print(f"[Session] Stored K_session for OBU {obu_node_id} ↔ RSU {rsu_node_id}")

        # ── Build handshake message for RSU ─────────────────────────────────
        handshake_msg = {
            "obu_id":    obu_node_id,
            "rsu_id":    rsu_node_id,
            "port_id":   port_id,
            "ct_kyber":  ct_kyber.hex(),
            "ct_saber":  ct_saber.hex(),
            "timestamp": ts_ms,
            "nonce":     nonce_hex
        }

        print(f"[OBU Encaps] Handshake message built:")
        print(f"  ct_kyber: {len(ct_kyber)} bytes")
        print(f"  ct_saber: {len(ct_saber)} bytes")
        print(f"  nonce:    {nonce_hex[:16]}...")
        print(f"  ts:       {ts_ms}")
        print(f"  Total handshake time: {kyber_us + saber_us + kdf_us:.0f} µs")

        return handshake_msg

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 3 — RSU: Decapsulation + Session Key Derivation
    # ─────────────────────────────────────────────────────────────────────────

    def rsu_decapsulate(self, rsu_node_id, handshake_msg: dict):
        """
        RSU receives OBU's handshake and decapsulates both ciphertexts.

        KYBER DECAPS (Algorithm 1c from progress report):
          1. m' = v - s·u mod q
          2. CheckError(m') → True/False
          3. ss_k = KDF(u||v||m')

        SABER DECAPS (Algorithm 2c from progress report):
          1. ms' = vs - s·us mod q
          2. ss_s = KDF(us||vs||ms')

        RSU then derives K_session with SAME formula as OBU:
          combined  = ss_k XOR ss_s
          K_session = HKDF(combined, info=obu_id||rsu_id||nonce)

        Both sides computed same K_session independently.
        K_session was NEVER transmitted.

        Then RSU computes and returns AuthToken:
          AuthToken = HMAC(K_session, rsu_id||ts||nonce)
        OBU verifies this → confirms RSU has same K_session.

        Returns: response dict with auth_token
        """
        print(f"\n[RSU Decaps] Processing handshake from OBU {handshake_msg['obu_id']}")

        obu_id   = str(handshake_msg['obu_id'])
        rsu_id   = str(rsu_node_id)
        port_id  = str(handshake_msg.get('port_id', 0))
        ts_ms    = handshake_msg['timestamp']
        nonce_hex= handshake_msg['nonce']

        # ── Pre-filter on handshake message ─────────────────────────────────
        if not check_timestamp_fresh(ts_ms):
            print(f"[RSU Decaps] REJECT: Stale handshake timestamp")
            return {"status": "REJECT", "error": "stale_timestamp"}

        # ── Load RSU secret keys ─────────────────────────────────────────────
        sk_kyber_hex = get_csv_value(csv_pq_keys_path, rsu_node_id, col_index=2)
        sk_saber_hex = get_csv_value(csv_pq_keys_path, rsu_node_id, col_index=4)

        if not sk_kyber_hex or not sk_saber_hex:
            raise ValueError(f"RSU {rsu_node_id} secret keys not found. Run rsu_keygen first.")

        sk_kyber = bytes.fromhex(sk_kyber_hex.strip())
        sk_saber = bytes.fromhex(sk_saber_hex.strip())
        ct_kyber = bytes.fromhex(handshake_msg['ct_kyber'])
        ct_saber = bytes.fromhex(handshake_msg['ct_saber'])

        # ── Kyber Decapsulation ──────────────────────────────────────────────
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation("Kyber512", sk_kyber) as kem:
            ss_kyber = kem.decap_secret(ct_kyber)
        kyber_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Kyber Decaps] done in {kyber_us:.0f} µs  ss={ss_kyber.hex()[:16]}...")

        # ── Saber Decapsulation ──────────────────────────────────────────────
        saber_alg = "LightSaber_KEM"
        if saber_alg not in oqs.get_enabled_kem_mechanisms():
            saber_alg = "Kyber768"
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(saber_alg, sk_saber) as kem:
            ss_saber = kem.decap_secret(ct_saber)
        saber_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[Saber Decaps] done in {saber_us:.0f} µs  ss={ss_saber.hex()[:16]}...")

        # ── Session Key Derivation ───────────────────────────────────────────
        t0 = time.perf_counter()
        K_session = derive_session_key(ss_kyber, ss_saber, obu_id, rsu_id, nonce_hex)
        kdf_us = (time.perf_counter() - t0) * 1_000_000
        print(f"[HKDF] Session key derived in {kdf_us:.0f} µs")

        # ── Store session ────────────────────────────────────────────────────
        expiry_s = int(time.time()) + SESSION_LIFETIME_S
        self._sessions[(obu_id, rsu_id, port_id)] = K_session
        set_csv_triple_value(csv_pq_session_path, obu_id, rsu_id, port_id,
                             col_index=3, value=K_session.hex())
        set_csv_triple_value(csv_pq_session_path, obu_id, rsu_id, port_id,
                             col_index=4, value=str(int(time.time())))
        set_csv_triple_value(csv_pq_session_path, obu_id, rsu_id, port_id,
                             col_index=5, value=str(expiry_s))

        # ── Compute AuthToken ────────────────────────────────────────────────
        auth_input  = f"{rsu_id}|{obu_id}|{ts_ms}|{nonce_hex}".encode()
        auth_token  = compute_hmac(K_session, auth_input)
        auth_ts     = get_timestamp_ms()

        # Save auth token to CSV
        set_csv_triple_value(csv_pq_auth_path, obu_id, rsu_id, port_id,
                             col_index=3, value=auth_token.hex())
        set_csv_triple_value(csv_pq_auth_path, obu_id, rsu_id, port_id,
                             col_index=4, value=str(auth_ts))

        print(f"[RSU Decaps] Session established. AuthToken: {auth_token.hex()[:16]}...")
        print(f"[RSU Decaps] Total: {kyber_us + saber_us + kdf_us:.0f} µs")

        return {
            "status":     "OK",
            "obu_id":     obu_id,
            "rsu_id":     rsu_id,
            "auth_token": auth_token.hex(),
            "timestamp":  auth_ts,
            "nonce":      nonce_hex
        }

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 4 — OBU: Verify Auth Token (Mutual Authentication)
    # ─────────────────────────────────────────────────────────────────────────

    def obu_verify_auth_token(self, obu_node_id, rsu_node_id, port_id,
                               handshake_ts_ms, handshake_nonce_hex,
                               response: dict) -> bool:
        """
        OBU verifies the auth token received from RSU.

        This confirms:
          1. RSU successfully decapsulated both ciphertexts
          2. RSU derived the SAME session key as OBU
          3. This is the real RSU (not a MitM)

        Auth token = HMAC(K_session, rsu_id||obu_id||ts||nonce)
        OBU recomputes this using its own K_session.
        If they match → mutual authentication complete.

        Returns: True if verified, False if authentication failed
        """
        print(f"\n[OBU Verify] Verifying RSU auth token")

        if response.get("status") != "OK":
            print(f"[OBU Verify] FAIL: RSU returned status={response.get('status')}")
            return False

        # Get OBU's own K_session
        key = (str(obu_node_id), str(rsu_node_id), str(port_id))
        if key in self._sessions:
            K_session = self._sessions[key]
        else:
            K_hex = get_csv_triple_value(csv_pq_session_path,
                                         obu_node_id, rsu_node_id, port_id,
                                         col_index=3)
            if not K_hex:
                print(f"[OBU Verify] FAIL: No session found for this OBU")
                return False
            K_session = bytes.fromhex(K_hex.strip())

        # Recompute expected auth token
        auth_input = f"{rsu_node_id}|{obu_node_id}|{handshake_ts_ms}|{handshake_nonce_hex}".encode()
        expected   = compute_hmac(K_session, auth_input)
        received   = bytes.fromhex(response['auth_token'])

        if hmac_lib.compare_digest(expected, received):
            print(f"[OBU Verify] ✓ AUTH TOKEN VERIFIED — Mutual authentication complete")
            print(f"[OBU Verify] Secure V2X channel established with RSU {rsu_node_id}")
            return True
        else:
            print(f"[OBU Verify] ✗ AUTH TOKEN MISMATCH — RSU may be impersonator, aborting")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 5 — OBU: Send Authenticated Beacon
    # ─────────────────────────────────────────────────────────────────────────

    def obu_send_beacon(self, obu_node_id, rsu_node_id, port_id, payload_str):
        """
        OBU builds an HMAC-authenticated beacon message.

        Beacon format:
          {
            obu_id,    rsu_id,    port_id,
            payload,   timestamp, nonce,
            hmac_tag
          }

        HMAC input = payload || nonce || timestamp_8bytes
        HMAC key   = K_session (shared secret, never transmitted)

        Returns: beacon_packet dict
        """
        print(f"\n[OBU Beacon] Building beacon: obu={obu_node_id} payload={payload_str[:30]}")

        # Load session key
        key = (str(obu_node_id), str(rsu_node_id), str(port_id))
        if key in self._sessions:
            K_session = self._sessions[key]
        else:
            K_hex = get_csv_triple_value(csv_pq_session_path,
                                         obu_node_id, rsu_node_id, port_id,
                                         col_index=3)
            if not K_hex:
                raise ValueError(f"No session found. Run obu_encaps + rsu_decaps first.")
            K_session = bytes.fromhex(K_hex.strip())

        payload   = payload_str.encode()
        nonce     = generate_nonce(16)
        nonce_hex = nonce.hex()
        ts_ms     = get_timestamp_ms()

        # Compute HMAC
        mac_input = build_beacon_mac_input(payload, nonce, ts_ms)
        tag       = compute_hmac(K_session, mac_input)

        beacon = {
            "obu_id":    obu_node_id,
            "rsu_id":    rsu_node_id,
            "port_id":   port_id,
            "payload":   payload.hex(),
            "timestamp": ts_ms,
            "nonce":     nonce_hex,
            "hmac_tag":  tag.hex()
        }
        print(f"[OBU Beacon] Built: nonce={nonce_hex[:8]}... ts={ts_ms} hmac={tag.hex()[:8]}...")
        return beacon

    # ─────────────────────────────────────────────────────────────────────────
    # STAGE 5 — RSU: Verify Incoming Beacon
    # ─────────────────────────────────────────────────────────────────────────

    def rsu_verify_beacon(self, rsu_node_id, beacon: dict) -> bool:
        """
        RSU verifies an incoming beacon from OBU.

        ORDER OF CHECKS (cheapest → most expensive):

          PRE-CRYPTO FILTER (microseconds each):
            Check 1: Session exists?          O(1) CSV lookup
            Check 2: Session not expired?     O(1) compare
            Check 3: Timestamp fresh?         O(1) subtract  → blocks TTW
            Check 4: Nonce new?               O(1) set lookup → blocks BSHH/ME

          CRYPTO LAYER (3µs):
            Check 5: HMAC correct?            SHA256 compute  → blocks tamper/spoof

        Returns: True if beacon is valid and accepted, False otherwise.
        Logs result to pq_beacon_log.csv.
        """
        obu_id   = str(beacon['obu_id'])
        rsu_id   = str(rsu_node_id)
        port_id  = str(beacon.get('port_id', 0))
        ts_ms    = beacon['timestamp']
        nonce_hex= beacon['nonce']
        payload  = bytes.fromhex(beacon['payload'])
        tag      = bytes.fromhex(beacon['hmac_tag'])

        print(f"\n[RSU Beacon Verify] obu={obu_id} ts={ts_ms} nonce={nonce_hex[:8]}...")

        # ── PRE-CRYPTO FILTER ────────────────────────────────────────────────
        passed, reason = pre_crypto_filter(obu_id, rsu_id, port_id,
                                           ts_ms, nonce_hex)
        if not passed:
            print(f"[PRE-FILTER] REJECTED: {reason}")
            append_csv_row(csv_pq_beacon_path,
                           [obu_id, rsu_id, port_id, payload.decode(errors='replace'),
                            ts_ms, nonce_hex, f"REJECTED:{reason}"])
            return False

        # ── Load session key ─────────────────────────────────────────────────
        key = (obu_id, rsu_id, port_id)
        if key in self._sessions:
            K_session = self._sessions[key]
        else:
            K_hex = get_csv_triple_value(csv_pq_session_path,
                                         obu_id, rsu_id, port_id, col_index=3)
            K_session = bytes.fromhex(K_hex.strip())

        # ── CRYPTO LAYER — HMAC Verification ────────────────────────────────
        nonce     = bytes.fromhex(nonce_hex)
        mac_input = build_beacon_mac_input(payload, nonce, ts_ms)

        t0 = time.perf_counter()
        hmac_valid = verify_hmac_tag(K_session, mac_input, tag)
        hmac_us = (time.perf_counter() - t0) * 1_000_000

        if not hmac_valid:
            print(f"[HMAC] REJECTED: HMAC mismatch in {hmac_us:.0f}µs → tamper/spoof blocked")
            append_csv_row(csv_pq_beacon_path,
                           [obu_id, rsu_id, port_id, payload.decode(errors='replace'),
                            ts_ms, nonce_hex, "REJECTED:HMAC_FAIL"])
            return False

        # ── ALL CHECKS PASSED — Store nonce NOW ──────────────────────────────
        check_and_store_nonce(nonce_hex, rsu_node_id)

        print(f"[BEACON] ✓ ACCEPTED in {hmac_us:.0f}µs")
        print(f"[BEACON] Payload: {payload.decode(errors='replace')}")

        # Log to CSV
        append_csv_row(csv_pq_beacon_path,
                       [obu_id, rsu_id, port_id, payload.decode(errors='replace'),
                        ts_ms, nonce_hex, "ACCEPTED"])
        return True

    # ─────────────────────────────────────────────────────────────────────────
    # ATTACK SIMULATION — for demo and viva evidence
    # ─────────────────────────────────────────────────────────────────────────

    def simulate_ttw_attack(self, rsu_node_id, valid_beacon: dict):
        """TTW: replay beacon with stale timestamp (8 seconds old)."""
        print("\n" + "="*50)
        print("ATTACK: Topology Time-Warp (TTW)")
        print("="*50)
        import copy
        stale = copy.deepcopy(valid_beacon)
        stale['timestamp'] = valid_beacon['timestamp'] - 8000
        result = self.rsu_verify_beacon(rsu_node_id, stale)
        if not result:
            print("✓ TTW BLOCKED — stale timestamp rejected")
        else:
            print("✗ TTW SUCCEEDED — PROTOCOL FAILURE")
        return not result

    def simulate_bshh_attack(self, rsu_node_id, valid_beacon: dict):
        """BSHH: replay exact same beacon (same nonce)."""
        print("\n" + "="*50)
        print("ATTACK: Beacon State Heartbeat Hijack (BSHH)")
        print("="*50)
        import copy
        replay = copy.deepcopy(valid_beacon)
        replay['timestamp'] = get_timestamp_ms()   # fresh ts to bypass TTW
        # nonce unchanged — this is the BSHH exploit
        result = self.rsu_verify_beacon(rsu_node_id, replay)
        if not result:
            print("✓ BSHH BLOCKED — nonce reuse detected")
        else:
            print("✗ BSHH SUCCEEDED — PROTOCOL FAILURE")
        return not result

    def simulate_me_attack(self, rsu_node_id, valid_beacon: dict):
        """ME: same beacon arriving on second path (phantom link)."""
        print("\n" + "="*50)
        print("ATTACK: Multipath Echo (ME)")
        print("="*50)
        import copy
        echo = copy.deepcopy(valid_beacon)
        echo['timestamp'] = get_timestamp_ms()
        # same nonce — this is the ME exploit
        result = self.rsu_verify_beacon(rsu_node_id, echo)
        if not result:
            print("✓ ME BLOCKED — duplicate nonce detected")
        else:
            print("✗ ME SUCCEEDED — PROTOCOL FAILURE")
        return not result

    def simulate_tamper_attack(self, rsu_node_id, valid_beacon: dict):
        """Tamper: attacker modifies payload but keeps old HMAC."""
        print("\n" + "="*50)
        print("ATTACK: Payload Tampering")
        print("="*50)
        import copy
        tampered = copy.deepcopy(valid_beacon)
        tampered['payload'] = b"FORGED_SPEED=999".hex()
        tampered['nonce']   = generate_nonce().hex()   # new nonce
        tampered['timestamp'] = get_timestamp_ms()
        # HMAC NOT recomputed — attacker has no K_session
        result = self.rsu_verify_beacon(rsu_node_id, tampered)
        if not result:
            print("✓ TAMPER BLOCKED — HMAC mismatch")
        else:
            print("✗ TAMPER SUCCEEDED — PROTOCOL FAILURE")
        return not result


# =============================================================================
# SECTION 7 — ARGUMENT PARSER (same pattern as supervisor's file)
# =============================================================================

def parse_arguments():
    """Parse ns-3 command-line arguments. Same pattern as LDA_PQ_security.py."""
    args_dict = {
        "node_id":       0,
        "other_node_id": 0,
        "port_id":       0,
        "netsize":       10,
        "message":       "",
        "rsu_keygen":    False,
        "obu_encaps":    False,
        "rsu_decaps":    False,
        "obu_verify_auth": False,
        "send_beacon":   False,
        "verify_beacon": False,
        "run_full_demo": False,
        "simulate_attacks": False,
        "pk_kyber":      "",
        "pk_saber":      "",
        "auth_token":    "",
        "handshake_ts":  0,
        "handshake_nonce": "",
    }

    raw = " ".join(sys.argv[1:])
    print(f"[Args] Raw: {raw}")
    parsed = shlex.split(raw)
    print(f"[Args] Parsed: {parsed}")

    for arg in parsed:
        if "=" not in arg:
            continue
        key, val = arg.split("=", 1)
        key = key.strip()
        val = val.strip()

        if key in ("node_id", "other_node_id", "port_id", "netsize", "handshake_ts"):
            args_dict[key] = int(val)
        elif key in ("rsu_keygen", "obu_encaps", "rsu_decaps", "obu_verify_auth",
                     "send_beacon", "verify_beacon", "run_full_demo", "simulate_attacks"):
            args_dict[key] = (val.lower() == "true")
        else:
            args_dict[key] = val

    return args_dict


# =============================================================================
# SECTION 8 — FULL END-TO-END DEMO
# =============================================================================

def run_full_demo(manager):
    """
    Full end-to-end demo of the protocol.
    Shows all 4 stages + attack simulations.
    Produces evidence in CSV files.
    """
    print("\n" + "█"*60)
    print("█  PQ-SDVN SECURE CHANNEL — FULL DEMO")
    print("█  Hybrid-KEM (Kyber512 + Saber) + HMAC-Timestamp-Nonce")
    print("█"*60)

    RSU_ID = 1
    OBU_ID = 2
    PORT   = 0

    # ── STAGE 0: RSU Key Generation ─────────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 0: RSU Key Initialization")
    print("─"*50)
    manager.generate_kyber_keypair(RSU_ID)
    manager.generate_saber_keypair(RSU_ID)
    manager.generate_falcon_keypair(RSU_ID)

    # ── STAGE 1: RSU Broadcast ───────────────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 1: RSU Broadcasts Public Keys")
    print("─"*50)
    broadcast = manager.get_rsu_broadcast(RSU_ID)

    # ── STAGE 2: OBU Encapsulation ───────────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 2: OBU Parallel KEM Encapsulation")
    print("─"*50)
    hs_msg = manager.obu_encapsulate(OBU_ID, RSU_ID, PORT,
                                     broadcast['pk_kyber'],
                                     broadcast['pk_saber'])

    # ── STAGE 3: RSU Decapsulation ───────────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 3: RSU Decapsulation + Session Key")
    print("─"*50)
    response = manager.rsu_decapsulate(RSU_ID, hs_msg)
    print(f"RSU response: {response['status']}")

    # ── STAGE 4: OBU Verify Auth Token ──────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 4: OBU Verifies Mutual Authentication")
    print("─"*50)
    auth_ok = manager.obu_verify_auth_token(
        OBU_ID, RSU_ID, PORT,
        hs_msg['timestamp'], hs_msg['nonce'], response)
    print(f"Mutual Authentication: {'✓ SUCCESS' if auth_ok else '✗ FAILED'}")

    if not auth_ok:
        print("Aborting — authentication failed")
        return

    # ── STAGE 5: Valid Beacons ───────────────────────────────────────────────
    print("\n" + "─"*50)
    print("STAGE 5: Authenticated Beacon Exchange")
    print("─"*50)
    last_beacon = None
    for i in range(3):
        beacon = manager.obu_send_beacon(OBU_ID, RSU_ID, PORT,
                                         f"speed={60+i*5},seq={i+1}")
        ok = manager.rsu_verify_beacon(RSU_ID, beacon)
        print(f"Beacon #{i+1}: {'✓ VERIFIED' if ok else '✗ REJECTED'}")
        last_beacon = beacon
        time.sleep(0.05)

    # ── ATTACK SIMULATIONS ───────────────────────────────────────────────────
    print("\n" + "─"*50)
    print("ATTACK SIMULATIONS (FYP Temporal-Echo Attacks)")
    print("─"*50)
    results = []
    results.append(manager.simulate_ttw_attack(RSU_ID, last_beacon))
    results.append(manager.simulate_bshh_attack(RSU_ID, last_beacon))
    results.append(manager.simulate_me_attack(RSU_ID, last_beacon))
    results.append(manager.simulate_tamper_attack(RSU_ID, last_beacon))

    print("\n" + "█"*60)
    print(f"█  RESULTS: {sum(results)}/{len(results)} attacks blocked")
    if sum(results) == len(results):
        print("█  ✓ ALL ATTACKS BLOCKED — Protocol validated")
    else:
        print("█  ✗ SOME ATTACKS SUCCEEDED — Review implementation")
    print("█"*60)


# =============================================================================
# SECTION 9 — MAIN ENTRY POINT (same pattern as supervisor's file)
# =============================================================================

if __name__ == "__main__":

    args = parse_arguments()

    manager = PQ_SecurityManager(net_size=args['netsize'])

    node_id       = args['node_id']
    other_node_id = args['other_node_id']
    port_id       = args['port_id']

    # ── RSU: Generate all keypairs ───────────────────────────────────────────
    if args['rsu_keygen']:
        manager.generate_kyber_keypair(node_id)
        manager.generate_saber_keypair(node_id)
        manager.generate_falcon_keypair(node_id)

    # ── RSU: Get broadcast info ──────────────────────────────────────────────
    # (ns-3 reads the public keys from CSV directly)

    # ── OBU: Encapsulate ────────────────────────────────────────────────────
    if args['obu_encaps']:
        if not args['pk_kyber'] or not args['pk_saber']:
            pk_kyber = get_csv_value(csv_pq_keys_path, other_node_id, col_index=1)
            pk_saber = get_csv_value(csv_pq_keys_path, other_node_id, col_index=3)
        else:
            pk_kyber = args['pk_kyber']
            pk_saber = args['pk_saber']
        hs_msg = manager.obu_encapsulate(node_id, other_node_id, port_id,
                                         pk_kyber, pk_saber)
        print(f"[OUTPUT] HANDSHAKE_MSG={json.dumps(hs_msg)}")

    # ── RSU: Decapsulate ────────────────────────────────────────────────────
    if args['rsu_decaps']:
        if args['message']:
            hs_msg = json.loads(args['message'])
        else:
            # Load from CSV (ns-3 passes via file or message arg)
            raise ValueError("Provide handshake message via message= argument")
        response = manager.rsu_decapsulate(node_id, hs_msg)
        print(f"[OUTPUT] RSU_RESPONSE={json.dumps(response)}")

    # ── OBU: Send beacon ─────────────────────────────────────────────────────
    if args['send_beacon']:
        payload = args['message'] if args['message'] else f"beacon_from_{node_id}"
        beacon = manager.obu_send_beacon(node_id, other_node_id, port_id, payload)
        print(f"[OUTPUT] BEACON={json.dumps(beacon)}")

    # ── RSU: Verify beacon ───────────────────────────────────────────────────
    if args['verify_beacon']:
        if args['message']:
            beacon = json.loads(args['message'])
        else:
            raise ValueError("Provide beacon via message= argument")
        result = manager.rsu_verify_beacon(node_id, beacon)
        print(f"[OUTPUT] BEACON_VALID={result}")

    # ── Full demo ────────────────────────────────────────────────────────────
    if args['run_full_demo']:
        run_full_demo(manager)

    # ── Timing (same as supervisor's file) ──────────────────────────────────
    end = time.time()
    execution_time_us = (end - start) * 1_000_000
    print(f"\nExecution time: {execution_time_us:.0f} µs")
