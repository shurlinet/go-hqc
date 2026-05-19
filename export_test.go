package hqc

import (
	"crypto/sha3"
	"hash"
	"io"

	"github.com/shurlinet/go-hqc/internal/shake"
)

// Test-only exports for deterministic encapsulation and independent verification.

// newSHA3_256ForTest returns a fresh SHA3-256 hash for AI threat defense tests.
func newSHA3_256ForTest() hash.Hash {
	return sha3.New256()
}

// newSHA3_512ForTest returns a fresh SHA3-512 hash for AI threat defense tests.
func newSHA3_512ForTest() hash.Hash {
	return sha3.New512()
}

func EncapsulateForTest128(ek *EncapsulationKey128, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}

func EncapsulateForTest192(ek *EncapsulationKey192, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}

func EncapsulateForTest256(ek *EncapsulationKey256, rand io.Reader) (sharedSecret, ciphertext []byte) {
	return ek.EncapsulateWithEntropy(rand)
}

// katPRNGDomain is the domain separation byte for the HQC KAT PRNG (v5.0.0).
// Anti-tamper: tested by TestKATRNGDomain.
const katPRNGDomain = 0x00

// KATRNG replicates the HQC KAT RNG: SHAKE256(entropy[48] || domain).
// Direct squeeze (NO 8-byte alignment - different from the seedexpander).
type KATRNG struct {
	state *shake.State
}

// NewKATRNG creates a KAT RNG from a 48-byte entropy input.
func NewKATRNG(entropy []byte) *KATRNG {
	st := shake.New256()
	st.Write(entropy)
	st.Write([]byte{katPRNGDomain})
	return &KATRNG{state: st}
}

// Read squeezes bytes from the KAT RNG (direct, no alignment).
func (r *KATRNG) Read(p []byte) (int, error) {
	return r.state.Read(p)
}

// GenerateKeyForTest128 generates a key using a deterministic reader (for KAT).
func GenerateKeyForTest128(rand io.Reader) (*DecapsulationKey128, error) {
	dk, err := generateKey(params128, rand)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey128{dk: dk}, nil
}

func GenerateKeyForTest192(rand io.Reader) (*DecapsulationKey192, error) {
	dk, err := generateKey(params192, rand)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey192{dk: dk}, nil
}

func GenerateKeyForTest256(rand io.Reader) (*DecapsulationKey256, error) {
	dk, err := generateKey(params256, rand)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey256{dk: dk}, nil
}
