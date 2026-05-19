package hqc_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shurlinet/go-hqc"
)

// ExampleGenerateKey128 demonstrates basic HQC-128 key exchange:
// generate a keypair, encapsulate a shared secret, and decapsulate it.
func ExampleGenerateKey128() {
	// Generate a fresh HQC-128 keypair.
	dk, err := hqc.GenerateKey128()
	if err != nil {
		log.Fatal(err)
	}
	defer dk.Destroy()

	// The encapsulation (public) key is sent to the peer.
	ek := dk.EncapsulationKey()

	// Peer encapsulates: produces a shared secret and ciphertext.
	sharedSecret, ciphertext := ek.Encapsulate()

	// Owner decapsulates: recovers the same shared secret.
	recovered, err := dk.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("shared secrets match: %v\n", bytes.Equal(sharedSecret, recovered))
	fmt.Printf("shared secret length: %d bytes\n", len(sharedSecret))
	// Output:
	// shared secrets match: true
	// shared secret length: 32 bytes
}

// ExampleDecapsulationKey128_Bytes demonstrates serializing and restoring HQC keys.
func ExampleDecapsulationKey128_Bytes() {
	dk, err := hqc.GenerateKey128()
	if err != nil {
		log.Fatal(err)
	}
	defer dk.Destroy()

	// Serialize the full secret key (2321 bytes for HQC-128).
	skBytes := dk.Bytes()
	fmt.Printf("secret key size: %d bytes\n", len(skBytes))

	// Restore from bytes.
	dk2, err := hqc.ParseDecapsulationKey128(skBytes)
	if err != nil {
		log.Fatal(err)
	}
	defer dk2.Destroy()

	// Compact seed (32 bytes for HQC-128) - sufficient to regenerate the full key.
	seed := dk.Seed()
	fmt.Printf("seed size: %d bytes\n", len(seed))

	dk3, err := hqc.NewDecapsulationKey128(seed)
	if err != nil {
		log.Fatal(err)
	}
	defer dk3.Destroy()

	// All three keys produce the same public key.
	pk1 := dk.EncapsulationKey().Bytes()
	pk2 := dk2.EncapsulationKey().Bytes()
	pk3 := dk3.EncapsulationKey().Bytes()
	fmt.Printf("public keys match: %v\n", bytes.Equal(pk1, pk2) && bytes.Equal(pk2, pk3))
	fmt.Printf("public key size: %d bytes\n", len(pk1))
	// Output:
	// secret key size: 2321 bytes
	// seed size: 32 bytes
	// public keys match: true
	// public key size: 2241 bytes
}

// ExampleGenerateKey256 demonstrates all three HQC parameter sets.
func ExampleGenerateKey256() {
	// HQC-128 (NIST Level 1)
	dk128, err := hqc.GenerateKey128()
	if err != nil {
		log.Fatal(err)
	}
	ss128, ct128 := dk128.EncapsulationKey().Encapsulate()
	dec128, err := dk128.Decapsulate(ct128)
	if err != nil {
		log.Fatal(err)
	}
	dk128.Destroy()

	// HQC-192 (NIST Level 3)
	dk192, err := hqc.GenerateKey192()
	if err != nil {
		log.Fatal(err)
	}
	ss192, ct192 := dk192.EncapsulationKey().Encapsulate()
	dec192, err := dk192.Decapsulate(ct192)
	if err != nil {
		log.Fatal(err)
	}
	dk192.Destroy()

	// HQC-256 (NIST Level 5)
	dk256, err := hqc.GenerateKey256()
	if err != nil {
		log.Fatal(err)
	}
	ss256, ct256 := dk256.EncapsulationKey().Encapsulate()
	dec256, err := dk256.Decapsulate(ct256)
	if err != nil {
		log.Fatal(err)
	}
	dk256.Destroy()

	fmt.Printf("HQC-128: ct=%d bytes, ss=%d bytes, match=%v\n",
		len(ct128), len(ss128), bytes.Equal(ss128, dec128))
	fmt.Printf("HQC-192: ct=%d bytes, ss=%d bytes, match=%v\n",
		len(ct192), len(ss192), bytes.Equal(ss192, dec192))
	fmt.Printf("HQC-256: ct=%d bytes, ss=%d bytes, match=%v\n",
		len(ct256), len(ss256), bytes.Equal(ss256, dec256))
	// Output:
	// HQC-128: ct=4433 bytes, ss=32 bytes, match=true
	// HQC-192: ct=8978 bytes, ss=32 bytes, match=true
	// HQC-256: ct=14421 bytes, ss=32 bytes, match=true
}
