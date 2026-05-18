package hqc

import (
	"crypto/rand"
	"io"
)

// HQC-256 key and ciphertext sizes.
const (
	PublicKeySize256    = 7237  // 32 + ceil(57637/8)
	SecretKeySize256    = 7333  // 7237 + 32 + 32 + 32
	CiphertextSize256   = 14421 // ceil(57637/8) + ceil(57600/8) + 16
	SharedSecretSize256 = 32
	SeedSize256         = 32 // seed_kem (32 bytes)
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
// The seed is seed_kem (32 bytes).
func NewDecapsulationKey256(seed []byte) (*DecapsulationKey256, error) {
	dk, err := newDecapsulationKeyFromSeed(params256, seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey256{dk: dk}, nil
}

// ParseDecapsulationKey256 parses a 7333-byte secret key.
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

// ParseEncapsulationKey256 parses a 7237-byte public key.
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
// Always returns a 32-byte shared secret (implicit rejection via sigma).
func (dk *DecapsulationKey256) Decapsulate(ciphertext []byte) ([]byte, error) {
	return decapsulate(params256, dk.dk, ciphertext)
}

// EncapsulationKey returns the public key corresponding to this secret key.
// The returned key is independent and survives Destroy.
func (dk *DecapsulationKey256) EncapsulationKey() *EncapsulationKey256 {
	return &EncapsulationKey256{ek: dk.dk.ek}
}

// Bytes returns the 7333-byte secret key (pk || seed_dk || sigma || seed_kem).
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

// Seed returns the 112-byte compact seed (pk || seed_dk || sigma || seed_kem_seed).
// Returns nil after [DecapsulationKey256.Destroy].
func (dk *DecapsulationKey256) Seed() []byte {
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
