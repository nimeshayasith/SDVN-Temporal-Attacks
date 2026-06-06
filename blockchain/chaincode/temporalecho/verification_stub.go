//go:build !liboqs

package main

import "fmt"

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  WARNING — PQC STUB MODE  (verification_stub.go)                        ║
// ║                                                                          ║
// ║  liboqs-go is NOT linked.  verifyDilithium2Sig accepts any non-empty    ║
// ║  byte slice as a valid signature.  The entire cryptographic trust        ║
// ║  model of the blockchain layer is bypassed in this build.               ║
// ║                                                                          ║
// ║  The paper claims Dilithium2 (FIPS 204 ML-DSA) signature verification   ║
// ║  for verifyThresholdSig (Eq. 3.24) and verifyQuorum (Eqs. 3.27–3.28).  ║
// ║  Neither is operative here.                                              ║
// ║                                                                          ║
// ║  To enable real Dilithium2:                                              ║
// ║    go get github.com/open-quantum-safe/liboqs-go                         ║
// ║    go build -tags liboqs ./...                                           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

func init() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  WARNING: TemporalEchoMitigator running in PQC STUB MODE         ║")
	fmt.Println("║  Dilithium2 verification is bypassed — any signature accepted.   ║")
	fmt.Println("║  Build with -tags liboqs to enable real post-quantum crypto.     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

// verifyDilithium2Sig — STUB implementation.
// Accepts any non-empty signature without cryptographic verification.
// Replace with verification_liboqs.go by building with -tags liboqs.
func verifyDilithium2Sig(sig []byte, message string, pubKey []byte) bool {
	_ = message // suppress unused warning
	return len(sig) > 0 || len(pubKey) == 0
}
