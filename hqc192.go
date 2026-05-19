package hqc

import (
	"crypto/rand"
	"io"
)

// HQC-192 key and ciphertext sizes.
const (
	PublicKeySize192    = 4514 // 32 + ceil(35851/8)
	SecretKeySize192    = 4602 // 4514 + 32 + 24 + 32
	CiphertextSize192   = 8978 // ceil(35851/8) + ceil(35840/8) + 16
	SharedSecretSize192 = 32
	SeedSize192         = 32 // seed_kem (32 bytes)
)

// DecapsulationKey192 is an HQC-192 decapsulation (secret) key.
type DecapsulationKey192 struct {
	dk *decapsulationKey
}

// EncapsulationKey192 is an HQC-192 encapsulation (public) key.
type EncapsulationKey192 struct {
	ek *encapsulationKey
}

// GenerateKey192 generates a new HQC-192 keypair using crypto/rand.
// The error return exists for API consistency; it currently never errors
// (panics on entropy failure, matching crypto/mlkem).
func GenerateKey192() (*DecapsulationKey192, error) {
	dk, err := generateKeyFromRand(params192)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey192{dk: dk}, nil
}

// NewDecapsulationKey192 creates a decapsulation key from a 32-byte seed.
// The seed is seed_kem (32 bytes).
func NewDecapsulationKey192(seed []byte) (*DecapsulationKey192, error) {
	dk, err := newDecapsulationKeyFromSeed(params192, seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey192{dk: dk}, nil
}

// ParseDecapsulationKey192 parses a 4602-byte secret key.
// Validates that the embedded public key matches the secret key seed.
func ParseDecapsulationKey192(data []byte) (*DecapsulationKey192, error) {
	if len(data) != SecretKeySize192 {
		return nil, ErrInvalidKeySize
	}
	dk, err := parseDecapsulationKeyInternal(params192, data)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey192{dk: dk}, nil
}

// ParseEncapsulationKey192 parses a 4514-byte public key.
func ParseEncapsulationKey192(data []byte) (*EncapsulationKey192, error) {
	ek, err := parseEncapsulationKeyInternal(params192, data)
	if err != nil {
		return nil, err
	}
	return &EncapsulationKey192{ek: ek}, nil
}

// Encapsulate generates a shared key and an associated ciphertext.
// Panics if the system random number generator fails.
func (ek *EncapsulationKey192) Encapsulate() (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params192, ek.ek, rand.Reader)
	return ss, ct
}

// Decapsulate decrypts a ciphertext and returns the shared secret.
// Always returns a 32-byte shared secret (implicit rejection via sigma).
func (dk *DecapsulationKey192) Decapsulate(ciphertext []byte) ([]byte, error) {
	return decapsulate(params192, dk.dk, ciphertext)
}

// EncapsulationKey returns the public key corresponding to this secret key.
// The returned key is independent and survives Destroy.
func (dk *DecapsulationKey192) EncapsulationKey() *EncapsulationKey192 {
	return &EncapsulationKey192{ek: dk.dk.ek}
}

// Bytes returns the 4602-byte secret key (pk || seed_dk || sigma || seed_kem).
// Returns nil after [DecapsulationKey192.Destroy].
func (dk *DecapsulationKey192) Bytes() []byte {
	dk.dk.mu.RLock()
	defer dk.dk.mu.RUnlock()
	if dk.dk.destroyed {
		return nil
	}
	out := make([]byte, len(dk.dk.sk))
	copy(out, dk.dk.sk)
	return out
}

// Seed returns the 32-byte seed_kem.
// Returns nil after [DecapsulationKey192.Destroy].
func (dk *DecapsulationKey192) Seed() []byte {
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
// The corresponding [EncapsulationKey192] remains valid (public data only).
// Dropping the key reference without calling Destroy leaves secret material
// in memory until garbage collected. Double Destroy is safe.
func (dk *DecapsulationKey192) Destroy() {
	dk.dk.destroy()
}

// Bytes returns the 4514-byte public key.
func (ek *EncapsulationKey192) Bytes() []byte {
	out := make([]byte, len(ek.ek.pk))
	copy(out, ek.ek.pk)
	return out
}

func (ek *EncapsulationKey192) encapsulateWithRandom(r io.Reader) (sharedSecret, ciphertext []byte) {
	ct, ss := encapsulate(params192, ek.ek, r)
	return ss, ct
}
