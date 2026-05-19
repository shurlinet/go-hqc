package hqctest

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/shurlinet/go-hqc"
)

// seededReader produces deterministic bytes from a SHA-256 chain.
// Each 32-byte block is SHA-256(previous_block). First block is SHA-256(seed).
type seededReader struct {
	block [32]byte
	off   int
}

func newSeeded(seed byte) *seededReader {
	var b [32]byte
	b[0] = seed
	b = sha256.Sum256(b[:])
	return &seededReader{block: b, off: 0}
}

func (r *seededReader) Read(p []byte) (int, error) {
	for i := range p {
		if r.off >= 32 {
			r.block = sha256.Sum256(r.block[:])
			r.off = 0
		}
		p[i] = r.block[r.off]
		r.off++
	}
	return len(p), nil
}

func TestEncapsulate128_Deterministic(t *testing.T) {
	seed := make([]byte, hqc.SeedSize128)
	seed[0] = 0x42
	dk, err := hqc.NewDecapsulationKey128(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng1 := newSeeded(0xAA)
	ss1, ct1 := Encapsulate128(ek, rng1)

	rng2 := newSeeded(0xAA)
	ss2, ct2 := Encapsulate128(ek, rng2)

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ between identical RNG runs")
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("ciphertexts differ between identical RNG runs")
	}

	// Decapsulate must recover the same shared secret
	ss3, err := dk.Decapsulate(ct1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss3) {
		t.Fatal("decapsulated shared secret differs from encapsulated")
	}

	// Different RNG seed must produce different output
	rng3 := newSeeded(0xBB)
	ss4, ct4 := Encapsulate128(ek, rng3)
	if bytes.Equal(ct1, ct4) {
		t.Fatal("different RNG seeds should produce different ciphertexts")
	}
	// Different ciphertext -> different shared secret (with overwhelming probability)
	if bytes.Equal(ss1, ss4) {
		t.Fatal("different ciphertexts should produce different shared secrets")
	}

	// Decapsulate the second ciphertext
	ss5, err := dk.Decapsulate(ct4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss4, ss5) {
		t.Fatal("decapsulated shared secret differs for second ciphertext")
	}
}

func TestEncapsulate192_Deterministic(t *testing.T) {
	seed := make([]byte, hqc.SeedSize192)
	seed[0] = 0x42
	dk, err := hqc.NewDecapsulationKey192(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng1 := newSeeded(0xAA)
	ss1, ct1 := Encapsulate192(ek, rng1)

	rng2 := newSeeded(0xAA)
	ss2, ct2 := Encapsulate192(ek, rng2)

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ between identical RNG runs")
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("ciphertexts differ between identical RNG runs")
	}

	ss3, err := dk.Decapsulate(ct1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss3) {
		t.Fatal("decapsulated shared secret differs from encapsulated")
	}

	// Different RNG seed must produce different output
	rng3 := newSeeded(0xBB)
	ss4, ct4 := Encapsulate192(ek, rng3)
	if bytes.Equal(ct1, ct4) {
		t.Fatal("different RNG seeds should produce different ciphertexts")
	}
	if bytes.Equal(ss1, ss4) {
		t.Fatal("different ciphertexts should produce different shared secrets")
	}

	ss5, err := dk.Decapsulate(ct4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss4, ss5) {
		t.Fatal("decapsulated shared secret differs for second ciphertext")
	}
}

func TestEncapsulate256_Deterministic(t *testing.T) {
	seed := make([]byte, hqc.SeedSize256)
	seed[0] = 0x42
	dk, err := hqc.NewDecapsulationKey256(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng1 := newSeeded(0xAA)
	ss1, ct1 := Encapsulate256(ek, rng1)

	rng2 := newSeeded(0xAA)
	ss2, ct2 := Encapsulate256(ek, rng2)

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ between identical RNG runs")
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("ciphertexts differ between identical RNG runs")
	}

	ss3, err := dk.Decapsulate(ct1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss3) {
		t.Fatal("decapsulated shared secret differs from encapsulated")
	}

	// Different RNG seed must produce different output
	rng3 := newSeeded(0xBB)
	ss4, ct4 := Encapsulate256(ek, rng3)
	if bytes.Equal(ct1, ct4) {
		t.Fatal("different RNG seeds should produce different ciphertexts")
	}
	if bytes.Equal(ss1, ss4) {
		t.Fatal("different ciphertexts should produce different shared secrets")
	}

	ss5, err := dk.Decapsulate(ct4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss4, ss5) {
		t.Fatal("decapsulated shared secret differs for second ciphertext")
	}
}

func TestEncapsulate128_SizesCorrect(t *testing.T) {
	dk, err := hqc.GenerateKey128()
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng := newSeeded(0x01)
	ss, ct := Encapsulate128(ek, rng)

	if len(ct) != hqc.CiphertextSize128 {
		t.Fatalf("ciphertext size: got %d, want %d", len(ct), hqc.CiphertextSize128)
	}
	if len(ss) != hqc.SharedSecretSize128 {
		t.Fatalf("shared secret size: got %d, want %d", len(ss), hqc.SharedSecretSize128)
	}
}

func TestEncapsulate192_SizesCorrect(t *testing.T) {
	dk, err := hqc.GenerateKey192()
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng := newSeeded(0x01)
	ss, ct := Encapsulate192(ek, rng)

	if len(ct) != hqc.CiphertextSize192 {
		t.Fatalf("ciphertext size: got %d, want %d", len(ct), hqc.CiphertextSize192)
	}
	if len(ss) != hqc.SharedSecretSize192 {
		t.Fatalf("shared secret size: got %d, want %d", len(ss), hqc.SharedSecretSize192)
	}
}

func TestEncapsulate256_SizesCorrect(t *testing.T) {
	dk, err := hqc.GenerateKey256()
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Destroy()
	ek := dk.EncapsulationKey()

	rng := newSeeded(0x01)
	ss, ct := Encapsulate256(ek, rng)

	if len(ct) != hqc.CiphertextSize256 {
		t.Fatalf("ciphertext size: got %d, want %d", len(ct), hqc.CiphertextSize256)
	}
	if len(ss) != hqc.SharedSecretSize256 {
		t.Fatalf("shared secret size: got %d, want %d", len(ss), hqc.SharedSecretSize256)
	}
}
