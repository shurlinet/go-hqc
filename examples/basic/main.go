// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Command basic demonstrates HQC-128 key encapsulation: generate a keypair,
// encapsulate a shared secret, and decapsulate it.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shurlinet/go-hqc"
)

func main() {
	// Generate a fresh HQC-128 keypair.
	dk, err := hqc.GenerateKey128()
	if err != nil {
		log.Fatal(err)
	}
	defer dk.Destroy() // Zero secret material when done.

	// The encapsulation (public) key would be sent to the peer.
	ek := dk.EncapsulationKey()

	fmt.Printf("Public key:  %d bytes\n", len(ek.Bytes()))
	fmt.Printf("Secret key:  %d bytes\n", len(dk.Bytes()))

	// Peer encapsulates: produces a shared secret and ciphertext.
	sharedSecret, ciphertext := ek.Encapsulate()

	fmt.Printf("Ciphertext:  %d bytes\n", len(ciphertext))
	fmt.Printf("Shared secret: %d bytes\n", len(sharedSecret))

	// Owner decapsulates: recovers the same shared secret from ciphertext.
	recovered, err := dk.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Secrets match: %v\n", bytes.Equal(sharedSecret, recovered))

	// Check which specification version this implementation uses.
	fmt.Printf("Spec version: %s\n", hqc.Version())
}
