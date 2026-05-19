package hqc

import (
	"crypto/rand"
	"io"
)

// HQC-128 key and ciphertext sizes.
const (
	PublicKeySize128    = 2241 // 32 + ceil(17669/8)
	SecretKeySize128    = 2321 // 2241 + 32 + 16 + 32
	CiphertextSize128   = 4433 // ceil(17669/8) + ceil(17664/8) + 16
	SharedSecretSize128 = 32
	SeedSize128         = 32 // seed_kem (32 bytes)
)

// DecapsulationKey128 is an HQC-128 decapsulation (secret) key.
type DecapsulationKey128 struct {
	dk *decapsulationKey
}

// EncapsulationKey128 is an HQC-128 encapsulation (public) key.
type EncapsulationKey128 struct {
	ek *encapsulationKey
}

// GenerateKey128 generates a new HQC-128 keypair using crypto/rand.
// The error return exists for API consistency; it currently never errors
// (panics on entropy failure, matching crypto/mlkem).
func GenerateKey128() (*DecapsulationKey128, error) {
	dk, err := generateKeyFromRand(params128)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey128{dk: dk}, nil
}

// NewDecapsulationKey128 creates a decapsulation key from a 32-byte seed.
// The seed is seed_kem (32 bytes).
func NewDecapsulationKey128(seed []byte) (*DecapsulationKey128, error) {
	dk, err := newDecapsulationKeyFromSeed(params128, seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey128{dk: dk}, nil
}

// ParseDecapsulationKey128 parses a 2321-byte secret key.
// Validates that the embedded public key matches the secret key seed.
func ParseDecapsulationKey128(data []byte) (*DecapsulationKey128, error) {
	if len(data) != SecretKeySize128 {
		return nil, ErrInvalidKeySize
	}
	dk, err := parseDecapsulationKeyInternal(params128, data)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey128{dk: dk}, nil
}

// ParseEncapsulationKey128 parses a 2241-byte public key.
func ParseEncapsulationKey128(data []byte) (*EncapsulationKey128, error) {
	ek, err := parseEncapsulationKeyInternal(params128, data)
	if err != nil {
		return nil, err
	}
	return &EncapsulationKey128{ek: ek}, nil
}

// Encapsulate generates a shared key and an associated ciphertext.
// Panics if the system random number generator fails.
func (ek *EncapsulationKey128) Encapsulate() (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params128, ek.ek, rand.Reader)
	return ss, ct
}

// Decapsulate decrypts a ciphertext and returns the shared secret.
// Always returns a 32-byte shared secret (implicit rejection via sigma).
func (dk *DecapsulationKey128) Decapsulate(ciphertext []byte) ([]byte, error) {
	return decapsulate(params128, dk.dk, ciphertext)
}

// EncapsulationKey returns the public key corresponding to this secret key.
// The returned key is independent and survives Destroy.
func (dk *DecapsulationKey128) EncapsulationKey() *EncapsulationKey128 {
	return &EncapsulationKey128{ek: dk.dk.ek}
}

// Bytes returns the 2321-byte secret key (pk || seed_dk || sigma || seed_kem).
// Returns nil after [DecapsulationKey128.Destroy].
func (dk *DecapsulationKey128) Bytes() []byte {
	dk.dk.mu.RLock()
	defer dk.dk.mu.RUnlock()
	if dk.dk.destroyed {
		return nil
	}
	out := make([]byte, len(dk.dk.sk))
	copy(out, dk.dk.sk)
	return out
}

// Seed returns the 32-byte seed_kem (pk || seed_dk || sigma || seed_kem_seed).
// Returns nil after [DecapsulationKey128.Destroy].
func (dk *DecapsulationKey128) Seed() []byte {
	dk.dk.mu.RLock()
	defer dk.dk.mu.RUnlock()
	if dk.dk.destroyed {
		return nil
	}
	out := make([]byte, len(dk.dk.seedKem))
	copy(out, dk.dk.seedKem)
	return out
}

// Destroy zeroes all secret key material (seedDK, sigma, seedKem, x, y, sk).
// After Destroy, Decapsulate returns [ErrDestroyed] and Bytes/Seed return nil.
// The corresponding [EncapsulationKey128] remains valid (public data only).
// Dropping the key reference without calling Destroy leaves secret material
// in memory until garbage collected. Double Destroy is safe.
func (dk *DecapsulationKey128) Destroy() {
	dk.dk.destroy()
}

// Bytes returns the 2241-byte public key.
func (ek *EncapsulationKey128) Bytes() []byte {
	out := make([]byte, len(ek.ek.pk))
	copy(out, ek.ek.pk)
	return out
}

// EncapsulateWithEntropy performs deterministic encapsulation using the
// provided reader for randomness. For testing and vector generation only.
//
// The reader must supply exactly 32 bytes (16 bytes m + 16 bytes salt for
// HQC-128). Panics if the reader fails, matching
// [EncapsulationKey128.Encapsulate] behavior.
//
// Using a predictable entropy source in production completely defeats the
// IND-CCA2 security of the KEM.
func (ek *EncapsulationKey128) EncapsulateWithEntropy(r io.Reader) (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params128, ek.ek, r)
	return ss, ct
}
