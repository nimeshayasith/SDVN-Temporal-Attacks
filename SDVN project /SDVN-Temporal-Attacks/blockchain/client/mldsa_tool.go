// mldsa_tool.go — small CLI helper wrapping liboqs-go's ML-DSA-87
// (Dilithium5) sign/keygen for submitToFabric.js to shell out to.
//
// Why this exists: liboqs-node (the npm binding) failed to build in this
// environment (its bundled node-gyp/liboqs submodule build errored out).
// This reuses the already-verified-working liboqs-go binding (the same one
// the chaincode's verification_liboqs.go links) instead of debugging a
// third-party native npm package's build system.
//
// Build:
//   PKG_CONFIG_PATH=<dir with liboqs-go.pc> LD_LIBRARY_PATH=~/liboqs-local/lib \
//     go build -o mldsa_tool mldsa_tool.go
//
// Usage:
//   mldsa_tool keygen                    -> prints "<pubkey_hex> <secretkey_hex>"
//   mldsa_tool sign <secretkey_hex> <msg> -> prints "<signature_hex>"
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

const algorithm = "ML-DSA-87"

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mldsa_tool <keygen|sign> [args...]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		signer := oqs.Signature{}
		defer signer.Clean()
		if err := signer.Init(algorithm, nil); err != nil {
			fail(err)
		}
		pk, err := signer.GenerateKeyPair()
		if err != nil {
			fail(err)
		}
		sk := signer.ExportSecretKey()
		fmt.Printf("%s %s\n", hex.EncodeToString(pk), hex.EncodeToString(sk))

	case "sign":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: mldsa_tool sign <secretkey_hex> <message>")
			os.Exit(1)
		}
		sk, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fail(err)
		}
		signer := oqs.Signature{}
		defer signer.Clean()
		if err := signer.Init(algorithm, sk); err != nil {
			fail(err)
		}
		sig, err := signer.Sign([]byte(os.Args[3]))
		if err != nil {
			fail(err)
		}
		fmt.Println(hex.EncodeToString(sig))

	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(1)
	}
}
