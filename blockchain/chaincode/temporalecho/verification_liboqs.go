//go:build liboqs

package main

// Real Dilithium2 verification using liboqs-go.
//
// Build requirements:
//   go get github.com/open-quantum-safe/liboqs-go
//   go build -tags liboqs ./...
//
// liboqs-go wraps the C liboqs library via CGo.  Requires:
//   sudo apt-get install liboqs-dev   (or build liboqs from source)
//
// Paper reference: Section 3.5, Eq. 3.24 (verifyThresholdSig),
//                  Eqs. 3.27–3.28 (verifyQuorum)

import (
	"fmt"
	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

func init() {
	fmt.Println("[TemporalEchoMitigator] PQC backend: liboqs-go Dilithium2 (FIPS 204 ML-DSA)")
}

// verifyDilithium2Sig verifies a Dilithium2 (NIST ML-DSA / FIPS 204) signature.
//
// sig     — 2420-byte Dilithium2 signature (OQS_SIG_dilithium_2_length_signature)
// message — the signed message string
// pubKey  — 1312-byte Dilithium2 public key (OQS_SIG_dilithium_2_length_public_key)
//
// Returns true iff OQS_SIG_verify succeeds.
func verifyDilithium2Sig(sig []byte, message string, pubKey []byte) bool {
	if len(sig) == 0 || len(pubKey) == 0 {
		return false
	}
	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init("Dilithium2", nil); err != nil {
		fmt.Printf("[verifyDilithium2Sig] oqs.Signature.Init error: %v\n", err)
		return false
	}
	valid, err := signer.Verify([]byte(message), sig, pubKey)
	if err != nil {
		fmt.Printf("[verifyDilithium2Sig] Verify error: %v\n", err)
		return false
	}
	return valid
}
