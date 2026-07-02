//go:build simstub

// Opt-in only (go build -tags simstub): HMAC-SHA256 simulation stand-in for
// local dev without liboqs installed. The default build (no tag,
// verification_liboqs.go) uses real ML-DSA-87 — see that file's header for
// why the default had to flip (Fabric's legacy golang build path can't be
// told to pass a custom -tags flag).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SIMULATION STUB MODE  (verification_stub.go)                           ║
// ║                                                                          ║
// ║  liboqs-go is NOT linked.  verifyMLDSA87Sig uses HMAC-SHA256 as         ║
// ║  a deterministic simulation-mode stand-in for ML-DSA-87 (FIPS 204).     ║
// ║  When a public key is registered on the ledger the HMAC is computed     ║
// ║  keyed by that public key, so forged or truncated signatures fail.      ║
// ║  When no public key is registered any non-empty signature passes         ║
// ║  (bootstrap phase before RegisterPeerKey is called).                    ║
// ║                                                                          ║
// ║  SimSign produces the matching HMAC-SHA256 signature for use by         ║
// ║  CreateAnchorCheckpoint and any other caller that needs to produce       ║
// ║  a verifiable signature in simulation mode.                              ║
// ║                                                                          ║
// ║  To enable real ML-DSA-87 (Dilithium5):                                 ║
// ║    go get github.com/open-quantum-safe/liboqs-go                         ║
// ║    go build -tags liboqs ./...                                           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

func init() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  TemporalEchoMitigator — simulation stub mode                    ║")
	fmt.Println("║  Signatures: HMAC-SHA256(pubKey, message) — not real ML-DSA-87   ║")
	fmt.Println("║  Build with -tags liboqs to enable real post-quantum crypto.     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

// SimSign returns HMAC-SHA256(key=pubKey, message) as the simulation-mode
// stand-in for a real ML-DSA-87 signature.
// When pubKey is empty it returns a constant sentinel so bootstrap-phase
// checkpoints are still serialisable (verified with the nil-key path below).
func SimSign(message string, pubKey []byte) []byte {
	if len(pubKey) == 0 {
		return []byte("SIM_NOSIG")
	}
	h := hmac.New(sha256.New, pubKey)
	h.Write([]byte(message))
	return h.Sum(nil)
}

// verifyMLDSA87Sig — HMAC-SHA256 stub.
// When pubKey is provided: verifies HMAC-SHA256(key=pubKey, message) == sig.
// When pubKey is empty (pre-registration): accepts any non-empty sig (bootstrap).
func verifyMLDSA87Sig(sig []byte, message string, pubKey []byte) bool {
	if len(pubKey) == 0 {
		return len(sig) > 0
	}
	expected := SimSign(message, pubKey)
	return hmac.Equal(sig, expected)
}
