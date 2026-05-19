// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Command serialization demonstrates HQC key persistence: serialize a key
// to bytes, restore it, and verify the restored key produces matching
// shared secrets. Shows both full-key (Bytes/Parse) and compact-seed
// (Seed/New) round-trips.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shurlinet/go-hqc"
)

func main() {
	// Generate a keypair.
	dk, err := hqc.GenerateKey128()
	if err != nil {
		log.Fatal(err)
	}
	defer dk.Destroy()

	// --- Full-key serialization (NIST format) ---

	// Serialize the secret key (2321 bytes for HQC-128).
	skBytes := dk.Bytes()
	fmt.Printf("Full secret key: %d bytes\n", len(skBytes))

	// Restore from bytes. Parse validates that the embedded public key
	// matches the secret key seed (catches corruption).
	dk2, err := hqc.ParseDecapsulationKey128(skBytes)
	if err != nil {
		log.Fatal(err)
	}
	defer dk2.Destroy()

	// Verify: encapsulate with original, decapsulate with restored.
	ss1, ct := dk.EncapsulationKey().Encapsulate()
	ss2, err := dk2.Decapsulate(ct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Full-key round-trip: %v\n", bytes.Equal(ss1, ss2))

	// --- Compact seed serialization ---

	// The seed (32 bytes for HQC-128) is sufficient to regenerate the
	// full key deterministically. Smaller than the full 2321-byte key.
	seed := dk.Seed()
	fmt.Printf("Compact seed: %d bytes (vs %d full)\n", len(seed), len(skBytes))

	dk3, err := hqc.NewDecapsulationKey128(seed)
	if err != nil {
		log.Fatal(err)
	}
	defer dk3.Destroy()

	// The seed-derived key is byte-identical to the original.
	fmt.Printf("Seed round-trip identical: %v\n", bytes.Equal(dk.Bytes(), dk3.Bytes()))

	// --- Public key serialization ---

	ekBytes := dk.EncapsulationKey().Bytes()
	fmt.Printf("Public key: %d bytes\n", len(ekBytes))

	ek2, err := hqc.ParseEncapsulationKey128(ekBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("EK round-trip identical: %v\n", bytes.Equal(ekBytes, ek2.Bytes()))
}
