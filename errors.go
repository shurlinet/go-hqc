package hqc

import "errors"

// Sentinel errors returned by Parse and Decapsulate functions.
var (
	// ErrInvalidKeySize is returned when a key byte slice has the wrong length.
	ErrInvalidKeySize = errors.New("hqc: invalid key size")

	// ErrInvalidCiphertextSize is returned when a ciphertext byte slice has the wrong length.
	ErrInvalidCiphertextSize = errors.New("hqc: invalid ciphertext size")

	// ErrDestroyed is returned when operating on a key that has been destroyed.
	ErrDestroyed = errors.New("hqc: key has been destroyed")

	// ErrKeyMismatch is returned when the embedded public key in a secret key
	// does not match the public key derived from the seed. This indicates
	// key corruption.
	ErrKeyMismatch = errors.New("hqc: secret key internal consistency check failed")
)
