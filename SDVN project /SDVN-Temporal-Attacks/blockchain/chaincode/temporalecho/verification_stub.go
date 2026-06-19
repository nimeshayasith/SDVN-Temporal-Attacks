//go:build !liboqs

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SIMULATION STUB MODE  (verification_stub.go)                           ║
// ║                                                                          ║
// ║  liboqs-go is NOT linked.  verifyFalcon1024Sig uses HMAC-SHA256 as       ║
// ║  a deterministic simulation-mode stand-in for Falcon-1024 (FIPS 204).   ║
// ║  When a public key is registered on the ledger the HMAC is computed     ║
// ║  keyed by that public key, so forged or truncated signatures fail.      ║
// ║  When no public key is registered any non-empty signature passes         ║
// ║  (bootstrap phase before RegisterPeerKey is called).                    ║
// ║                                                                          ║
// ║  SimSign produces the matching HMAC-SHA256 signature for use by         ║
// ║  CreateAnchorCheckpoint and any other caller that needs to produce       ║
// ║  a verifiable signature in simulation mode.                              ║
// ║                                                                          ║
// ║  To enable real Falcon-1024:                                              ║
// ║    go get github.com/open-quantum-safe/liboqs-go                         ║
// ║    go build -tags liboqs ./...                                           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

func init() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  TemporalEchoMitigator — simulation stub mode                    ║")
	fmt.Println("║  Signatures: HMAC-SHA256(pubKey, message) — not real Falcon-1024  ║")
	fmt.Println("║  Build with -tags liboqs to enable real post-quantum crypto.     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

// SimSign returns HMAC-SHA256(key=pubKey, message) as the simulation-mode
// stand-in for a real Falcon-1024 signature.
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

// verifyFalcon1024Sig — HMAC-SHA256 stub.
// When pubKey is provided: verifies HMAC-SHA256(key=pubKey, message) == sig.
// When pubKey is empty (pre-registration): accepts any non-empty sig (bootstrap).
func verifyFalcon1024Sig(sig []byte, message string, pubKey []byte) bool {
	if len(pubKey) == 0 {
		return len(sig) > 0
	}
	expected := SimSign(message, pubKey)
	return hmac.Equal(sig, expected)
}
