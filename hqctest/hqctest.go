// Package hqctest provides deterministic encapsulation functions for testing.
//
// These functions accept an [io.Reader] for randomness, enabling reproducible
// ciphertexts and shared secrets from a known entropy source. This mirrors
// [crypto/mlkem/mlkemtest] in purpose: production code uses
// [hqc.EncapsulationKey128.Encapsulate] (which draws from crypto/rand),
// while test code uses these functions for deterministic vector generation.
//
// The reader must supply a fixed number of bytes per param set: 32 (HQC-128),
// 40 (HQC-192), or 48 (HQC-256). This covers the message m and salt.
//
// These functions are NOT intended for production use. Using a predictable
// entropy source in production completely defeats the IND-CCA2 security
// of the KEM.
package hqctest

import (
	"io"

	"github.com/shurlinet/go-hqc"
)

// Encapsulate128 performs deterministic HQC-128 encapsulation using the
// provided reader for randomness. Returns (sharedSecret, ciphertext).
//
// The reader must supply exactly 32 bytes (16 bytes m + 16 bytes salt).
// Panics if the reader fails, matching [hqc.EncapsulationKey128.Encapsulate]
// behavior on entropy failure.
func Encapsulate128(ek *hqc.EncapsulationKey128, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}

// Encapsulate192 performs deterministic HQC-192 encapsulation using the
// provided reader for randomness. Returns (sharedSecret, ciphertext).
//
// The reader must supply exactly 40 bytes (24 bytes m + 16 bytes salt).
// Panics if the reader fails. See [Encapsulate128] for security warnings.
func Encapsulate192(ek *hqc.EncapsulationKey192, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}

// Encapsulate256 performs deterministic HQC-256 encapsulation using the
// provided reader for randomness. Returns (sharedSecret, ciphertext).
//
// The reader must supply exactly 48 bytes (32 bytes m + 16 bytes salt).
// Panics if the reader fails. See [Encapsulate128] for security warnings.
func Encapsulate256(ek *hqc.EncapsulationKey256, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}
