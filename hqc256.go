package hqc

import (
	"crypto/rand"
	"io"
)

// HQC-256 key and ciphertext sizes.
const (
	PublicKeySize256    = 7245  // 40 + ceil(57637/8)
	SecretKeySize256    = 7317  // 40 + 32 + 7245
	CiphertextSize256   = 14421 // ceil(57637/8) + ceil(57600/8) + 16
	SharedSecretSize256 = 64
	SeedSize256         = 112 // sk_seed(40) + sigma(32) + pk_seed(40)
)

// DecapsulationKey256 is an HQC-256 decapsulation (secret) key.
type DecapsulationKey256 struct {
	dk *decapsulationKey
}

// EncapsulationKey256 is an HQC-256 encapsulation (public) key.
type EncapsulationKey256 struct {
	ek *encapsulationKey
}

// GenerateKey256 generates a new HQC-256 keypair using crypto/rand.
// The error return exists for API consistency; it currently never errors
// (panics on entropy failure, matching crypto/mlkem).
func GenerateKey256() (*DecapsulationKey256, error) {
	dk, err := generateKeyFromRand(params256)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey256{dk: dk}, nil
}

// NewDecapsulationKey256 creates a decapsulation key from a 112-byte seed.
// The seed is sk_seed(40) || sigma(32) || pk_seed(40).
func NewDecapsulationKey256(seed []byte) (*DecapsulationKey256, error) {
	dk, err := newDecapsulationKeyFromSeed(params256, seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey256{dk: dk}, nil
}

// ParseDecapsulationKey256 parses a 7317-byte NIST-format secret key.
// Validates that the embedded public key matches the secret key seed.
func ParseDecapsulationKey256(data []byte) (*DecapsulationKey256, error) {
	if len(data) != SecretKeySize256 {
		return nil, ErrInvalidKeySize
	}
	dk, err := parseDecapsulationKeyInternal(params256, data)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey256{dk: dk}, nil
}

// ParseEncapsulationKey256 parses a 7245-byte public key.
func ParseEncapsulationKey256(data []byte) (*EncapsulationKey256, error) {
	ek, err := parseEncapsulationKeyInternal(params256, data)
	if err != nil {
		return nil, err
	}
	return &EncapsulationKey256{ek: ek}, nil
}

// Encapsulate generates a shared key and an associated ciphertext.
// Panics if the system random number generator fails.
func (ek *EncapsulationKey256) Encapsulate() (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params256, ek.ek, rand.Reader)
	return ss, ct
}

// Decapsulate decrypts a ciphertext and returns the shared secret.
// Always returns a 64-byte shared secret (implicit rejection via sigma).
func (dk *DecapsulationKey256) Decapsulate(ciphertext []byte) ([]byte, error) {
	return decapsulate(params256, dk.dk, ciphertext)
}

// EncapsulationKey returns the public key corresponding to this secret key.
// The returned key is independent and survives Destroy.
func (dk *DecapsulationKey256) EncapsulationKey() *EncapsulationKey256 {
	return &EncapsulationKey256{ek: dk.dk.ek}
}

// Bytes returns the 7317-byte NIST-format secret key (sk_seed || sigma || pk).
// Returns nil after [DecapsulationKey256.Destroy].
func (dk *DecapsulationKey256) Bytes() []byte {
	dk.dk.mu.RLock()
	defer dk.dk.mu.RUnlock()
	if dk.dk.destroyed {
		return nil
	}
	out := make([]byte, len(dk.dk.sk))
	copy(out, dk.dk.sk)
	return out
}

// Seed returns the 112-byte compact seed (sk_seed || sigma || pk_seed).
// Returns nil after [DecapsulationKey256.Destroy].
func (dk *DecapsulationKey256) Seed() []byte {
	dk.dk.mu.RLock()
	defer dk.dk.mu.RUnlock()
	if dk.dk.destroyed {
		return nil
	}
	out := make([]byte, len(dk.dk.seed))
	copy(out, dk.dk.seed)
	return out
}

// Destroy zeroes all secret key material (skSeed, sigma, x, y, sk, seed).
// After Destroy, Decapsulate returns [ErrDestroyed] and Bytes/Seed return nil.
// The corresponding [EncapsulationKey256] remains valid (public data only).
// Dropping the key reference without calling Destroy leaves secret material
// in memory until garbage collected. Double Destroy is safe.
func (dk *DecapsulationKey256) Destroy() {
	dk.dk.destroy()
}

// Bytes returns the 7245-byte public key.
func (ek *EncapsulationKey256) Bytes() []byte {
	out := make([]byte, len(ek.ek.pk))
	copy(out, ek.ek.pk)
	return out
}

func (ek *EncapsulationKey256) encapsulateWithRandom(r io.Reader) (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params256, ek.ek, r)
	return ss, ct
}
