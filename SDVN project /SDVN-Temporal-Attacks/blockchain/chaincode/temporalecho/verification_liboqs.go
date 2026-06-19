//go:build liboqs

package main

// Real Falcon-1024 verification using liboqs-go.
//
// Build requirements:
//   go get github.com/open-quantum-safe/liboqs-go
//   go build -tags liboqs ./...
//
// liboqs-go wraps the C liboqs library via CGo.  Requires:
//   sudo apt-get install liboqs-dev   (or build liboqs from source)
//
// Falcon-1024: NIST PQC Level 5 (AES-256 equivalent), compact variable-length signatures.
//   Public key : 1793 bytes
//   Signature  : ~1280 bytes average (variable-length, fits one DSRC 802.11p frame)
//   Security   : NIST Level 5 — strongest standardised post-quantum level
//
// Paper reference: Section 3.5, Eq. 3.24 (verifyThresholdSig),
//                  Eqs. 3.27–3.28 (verifyQuorum)

import (
	"fmt"
	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

func init() {
	fmt.Println("[TemporalEchoMitigator] PQC backend: liboqs-go Falcon-1024 (NIST Level 5)")
}

// SimSign is a no-op stub in the liboqs build: real signing is performed
// client-side using the liboqs SDK before submitting to the chaincode.
// Returns nil so callers that check len(sig)==0 can distinguish no-key cases.
func SimSign(message string, pubKey []byte) []byte {
	_ = message
	_ = pubKey
	return nil
}

// verifyFalcon1024Sig verifies a Falcon-1024 (NIST Level 5) signature.
//
// sig     — Falcon-1024 signature (~1280 bytes, variable-length)
// message — the signed message string
// pubKey  — 1793-byte Falcon-1024 public key
//
// Returns true iff OQS_SIG_verify succeeds.
func verifyFalcon1024Sig(sig []byte, message string, pubKey []byte) bool {
	if len(sig) == 0 || len(pubKey) == 0 {
		return false
	}
	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init("Falcon-1024", nil); err != nil {
		fmt.Printf("[verifyFalcon1024] oqs.Signature.Init error: %v\n", err)
		return false
	}
	valid, err := signer.Verify([]byte(message), sig, pubKey)
	if err != nil {
		fmt.Printf("[verifyFalcon1024] Verify error: %v\n", err)
		return false
	}
	return valid
}
