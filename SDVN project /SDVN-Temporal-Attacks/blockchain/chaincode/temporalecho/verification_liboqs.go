//go:build !simstub

// Default build (no tag needed): real liboqs ML-DSA-87. Fabric's legacy
// golang chaincode build path (invoked automatically inside the ccenv image
// during `peer lifecycle chaincode install`) runs a plain `go build ./...`
// with no way to inject custom -tags, so the real implementation must be
// the default rather than opt-in. teta-ccenv (Dockerfile.ccenv) bundles the
// same liboqs.so + headers routing.cc already links against, so this
// compiles and links there without any extra flags.  Use `-tags simstub`
// (verification_stub.go) only for local dev without liboqs installed.
package main

// Real ML-DSA-87 (CRYSTALS-Dilithium5, NIST FIPS 204, Category 5) verification
// using liboqs-go, matching the PQC scheme specified throughout the report
// (location-binding signatures Eq. 3.28, threshold aggregate signatures
// Eq. 3.26, and the routing.cc/.crypto_src/dilithium.cc LW-layer signing).
//
// Build requirements:
//   go get github.com/open-quantum-safe/liboqs-go
//   go build -tags liboqs ./...
//
// liboqs-go wraps the C liboqs library via CGo. This chaincode is built inside
// the custom teta-ccenv image (see Dockerfile.ccenv), which bundles the same
// liboqs.so already used by routing.cc (~/liboqs-local on the host).
//
// ML-DSA-87 (NIST PQC Category 5):
//   Public key : 2592 bytes  (DILITHIUM5_PK_LEN,  .crypto_src/teta_guard_types.h)
//   Signature  : 4627 bytes  (DILITHIUM5_SIG_LEN, .crypto_src/teta_guard_types.h)
//   Algorithm name in this liboqs build: "ML-DSA-87" only — liboqs >= 0.10
//   standardised on this name; the older "Dilithium5" identifier does not
//   exist as a separate OQS_SIG_alg string in this build (confirmed via
//   liboqs-local/include/oqs/sig.h: OQS_SIG_alg_ml_dsa_87 "ML-DSA-87").
//
// Paper reference: Section 3.5, Eq. 3.24 (verifyThresholdSig),
//                  Eqs. 3.27-3.28 (verifyQuorum)

import (
	"fmt"
	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

func init() {
	fmt.Println("[TemporalEchoMitigator] PQC backend: liboqs-go ML-DSA-87 / Dilithium5 (NIST Category 5)")
}

// SimSign is a no-op stub in the liboqs build: real signing is performed
// client-side using the liboqs SDK before submitting to the chaincode.
// Returns nil so callers that check len(sig)==0 can distinguish no-key cases.
func SimSign(message string, pubKey []byte) []byte {
	_ = message
	_ = pubKey
	return nil
}

// verifyMLDSA87Sig verifies an ML-DSA-87 (Dilithium5, NIST Category 5) signature.
//
// sig     — ML-DSA-87 signature (4627 bytes)
// message — the signed message string
// pubKey  — 2592-byte ML-DSA-87 public key
//
// Returns true iff OQS_SIG_verify succeeds.
func verifyMLDSA87Sig(sig []byte, message string, pubKey []byte) bool {
	if len(sig) == 0 || len(pubKey) == 0 {
		return false
	}
	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init("ML-DSA-87", nil); err != nil {
		fmt.Printf("[verifyMLDSA87Sig] oqs.Signature.Init error: %v\n", err)
		return false
	}
	valid, err := signer.Verify([]byte(message), sig, pubKey)
	if err != nil {
		fmt.Printf("[verifyMLDSA87Sig] Verify error: %v\n", err)
		return false
	}
	return valid
}
