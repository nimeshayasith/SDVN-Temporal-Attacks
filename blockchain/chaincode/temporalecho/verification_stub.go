//go:build !liboqs

package main

import (
	"fmt"
	"os"
)

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
	// VF-01 FIX: panic if TETA_SIMULATION_MODE is not set to "1".
	// This prevents the PQC stub from being loaded in production builds
	// where a real Dilithium2 verifier is required. A developer who forgets
	// to build with -tags liboqs and deploys to production will get an
	// immediate crash rather than silently accepting all signatures.
	if os.Getenv("TETA_SIMULATION_MODE") != "1" {
		panic("verification_stub.go: PQC stub loaded outside simulation mode. " +
			"Build with -tags liboqs for production, or set TETA_SIMULATION_MODE=1 " +
			"for NS-3/SUMO simulation evaluation.")
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  WARNING: TemporalEchoMitigator running in PQC STUB MODE         ║")
	fmt.Println("║  Dilithium2 verification is bypassed — any signature accepted.   ║")
	fmt.Println("║  TETA_SIMULATION_MODE=1 confirmed — simulation use only.         ║")
	fmt.Println("║  Build with -tags liboqs to enable real post-quantum crypto.     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

// verifyDilithium2Sig — STUB implementation.
// Accepts any non-empty signature without cryptographic verification.
// Valid ONLY when TETA_SIMULATION_MODE=1 (enforced by init() above).
func verifyDilithium2Sig(sig []byte, message string, pubKey []byte) bool {
	_ = message
	return len(sig) > 0 || len(pubKey) == 0
}
