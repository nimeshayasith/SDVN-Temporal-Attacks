# crypto/Makefile — Build all TETA-Guard Crypto Layer modules
#
# Section 3 of the TETA-Guard Technical Reference
#   dilithium.cc           — Section 3.3: shared Dilithium5 module (FIPS 204)
#                            SINGLE canonical implementation used by M1, M3, M4
#   Module 1 (kem.cc)              — Kyber+Saber Hybrid-KEM; calls dilithium.cc for keygen
#   Module 2 (hmac_filter.cc)      — HMAC-Timestamp-Nonce Pre-Detection Filter
#   Module 3 (threshold_sig.cc)    — Threshold Aggregate Sig; calls dilithium.cc sign/verify
#   Module 4 (location_binding.cc) — Location-Binding Sig; calls dilithium.cc sign/verify
#   Module 5 (lkh_mgmt.cc)        — LKH Session Key Revocation (O(log n))
#   Module 6 (crypto_pipeline.cc)  — End-to-end pipeline integrating M1–M5
#
# dilithium.cc dependency graph:
#   kem.cc            → dilithium.cc  (keygen at vehicle registration)
#   threshold_sig.cc  → dilithium.cc  (sign + verify for Eq. 3.24)
#   location_binding.cc → dilithium.cc (sign + verify for Eqs. 3.25–3.28)
#   crypto_pipeline.cc → (indirectly via threshold_sig + location_binding)
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt-get install libssl-dev
#   sudo apt-get install liboqs-dev   # optional — enables real PQC, else stubs
#
# Usage:
#   make              # build all modules (stub mode, no liboqs required)
#   make PQC=1        # build with real liboqs post-quantum crypto
#   make test         # run all self-tests
#   make pipeline     # run full pipeline on ../pem_event_log.csv
#   make clean        # remove binaries and output CSVs

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -I.

# OpenSSL is always used (SHA-256, HMAC, RAND_bytes)
LIBS     := -lssl -lcrypto -lm

# Optional: real post-quantum crypto via liboqs
ifeq ($(PQC),1)
  CXXFLAGS += -DHAVE_LIBOQS -DHAVE_OPENSSL
  LIBS     += -loqs
  $(info [Makefile] PQC=1 — building with liboqs real post-quantum ops)
else
  CXXFLAGS += -DHAVE_OPENSSL
  $(info [Makefile] PQC=0 (default) — building with OpenSSL HMAC stubs)
endif

MODULES := dilithium kem hmac_filter threshold_sig location_binding lkh_mgmt crypto_pipeline

# dilithium.cc compiles to a shared object linked into the modules that need it.
# We build it as dilithium.o so kem, threshold_sig, location_binding, and
# crypto_pipeline can all link against the single compiled copy.
DILITHIUM_OBJ := dilithium.o
THRESH_OBJ    := threshold_sig.o
LBS_OBJ       := location_binding.o

.PHONY: all clean test pipeline test_dilithium $(MODULES)

all: $(MODULES)

# ── Section 3.3: standalone Dilithium5 object (shared by M1, M3, M4, M6) ──────
$(DILITHIUM_OBJ): dilithium.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) -DDILITHIUM_NO_MAIN -c dilithium.cc -o $(DILITHIUM_OBJ)

# ── Section 3.3: Dilithium self-test binary ────────────────────────────────────
dilithium: dilithium.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) dilithium.cc $(LIBS) -o dilithium

# ── Module 1: KEM (links dilithium.o for keygen) ──────────────────────────────
kem: kem.cc $(DILITHIUM_OBJ) teta_guard_types.h
	$(CXX) $(CXXFLAGS) kem.cc $(DILITHIUM_OBJ) $(LIBS) -o kem

# ── Module 2: HMAC Filter (no Dilithium dependency) ───────────────────────────
hmac_filter: hmac_filter.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) hmac_filter.cc $(LIBS) -o hmac_filter

# ── Module 3: Threshold Aggregate Sig (links dilithium.o) ─────────────────────
threshold_sig: threshold_sig.cc $(DILITHIUM_OBJ) teta_guard_types.h
	$(CXX) $(CXXFLAGS) threshold_sig.cc $(DILITHIUM_OBJ) $(LIBS) -o threshold_sig

# Module 3 as linkable object (no main; used by crypto_pipeline)
$(THRESH_OBJ): threshold_sig.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) -DTHRESHOLD_SIG_NO_MAIN -c threshold_sig.cc -o $(THRESH_OBJ)

# ── Module 4: Location-Binding Sig (links dilithium.o) ────────────────────────
location_binding: location_binding.cc $(DILITHIUM_OBJ) teta_guard_types.h
	$(CXX) $(CXXFLAGS) location_binding.cc $(DILITHIUM_OBJ) $(LIBS) -lm -o location_binding

# Module 4 as linkable object (no main; used by crypto_pipeline)
$(LBS_OBJ): location_binding.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) -DLOCATION_BINDING_NO_MAIN -c location_binding.cc -o $(LBS_OBJ)

# ── Module 5: LKH Revocation (no Dilithium dependency) ────────────────────────
lkh_mgmt: lkh_mgmt.cc teta_guard_types.h
	$(CXX) $(CXXFLAGS) lkh_mgmt.cc $(LIBS) -o lkh_mgmt

# ── Module 6: Pipeline (links dilithium.o + M3 + M4 objects) ─────────────────
crypto_pipeline: crypto_pipeline.cc $(DILITHIUM_OBJ) $(THRESH_OBJ) $(LBS_OBJ) teta_guard_types.h
	$(CXX) $(CXXFLAGS) crypto_pipeline.cc $(DILITHIUM_OBJ) $(THRESH_OBJ) $(LBS_OBJ) $(LIBS) -lm -o crypto_pipeline

# ── Run all self-tests ─────────────────────────────────────────────────────────
test: all
	@echo "=== Section 3.3: CRYSTALS-Dilithium5 (shared module, Level 5) ==="
	./dilithium
	@echo ""
	@echo "=== Module 1: KEM (Kyber-1024+FireSaber Hybrid, Level 5) ==="
	./kem
	@echo ""
	@echo "=== Module 2: HMAC Pre-Detection Filter ==="
	./hmac_filter
	@echo ""
	@echo "=== Module 3: Threshold Aggregate Signature ==="
	./threshold_sig
	@echo ""
	@echo "=== Module 4: Location-Binding Signatures ==="
	./location_binding
	@echo ""
	@echo "=== Module 5: LKH Key Revocation ==="
	./lkh_mgmt
	@echo ""
	@echo "=== All self-tests done ==="

test_dilithium: dilithium
	./dilithium

# ── Run full crypto pipeline on pem_event_log.csv from project root ───────────
# Reads:  ../pem_event_log.csv   (produced by routing.cc simulation)
# Reads:  ../tgn_alerts.json     (produced by tgn_detector.cc — optional)
# Writes: crypto_verified_events.csv, crypto_drop_log.csv, beacon_evidence.csv
pipeline: crypto_pipeline
	./crypto_pipeline ../pem_event_log.csv ../tgn_alerts.json

clean:
	rm -f $(MODULES) $(DILITHIUM_OBJ) $(THRESH_OBJ) $(LBS_OBJ) *.csv *.log *.json
