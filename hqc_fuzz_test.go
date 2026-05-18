package hqc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// FuzzDecapsulate128 feeds random ciphertexts to Decapsulate.
// The property: Decapsulate must NEVER panic and must ALWAYS return a
// 64-byte shared secret (implicit rejection via sigma).
func FuzzDecapsulate128(f *testing.F) {
	// Seed corpus: one valid ciphertext from KAT vectors.
	var vf encapsVectorFile
	data, err := os.ReadFile("testdata/encaps.json")
	if err != nil {
		f.Fatalf("read encaps.json: %v", err)
	}
	if err := json.Unmarshal(data, &vf); err != nil {
		f.Fatalf("parse encaps.json: %v", err)
	}
	if len(vf.HQC128.Tests) > 0 {
		ct, err := hex.DecodeString(vf.HQC128.Tests[0].CT)
		if err != nil {
			f.Fatalf("hex decode ct: %v", err)
		}
		f.Add(ct)
	}
	// Seed: all-zero ciphertext.
	f.Add(make([]byte, CiphertextSize128))

	// Fixed key for the entire fuzz campaign.
	dk, err := GenerateKey128()
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { dk.Destroy() })

	f.Fuzz(func(t *testing.T, ct []byte) {
		// Wrong-length ciphertexts must return ErrInvalidCiphertextSize, not panic.
		if len(ct) != CiphertextSize128 {
			_, err := dk.Decapsulate(ct)
			if err != ErrInvalidCiphertextSize {
				t.Fatalf("wrong-length ct (%d bytes): got err %v, want ErrInvalidCiphertextSize", len(ct), err)
			}
			return
		}
		ss, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("decapsulate error: %v", err)
		}
		if len(ss) != SharedSecretSize128 {
			t.Fatalf("ss length = %d, want %d", len(ss), SharedSecretSize128)
		}
	})
}

// FuzzKeyRoundTrip128 verifies that generate -> serialize -> parse -> decaps
// produces matching shared secrets. Seeds with random 96-byte values.
func FuzzKeyRoundTrip128(f *testing.F) {
	// Seed corpus: one KAT entropy (first 96 bytes from the 48-byte entropy doubled).
	var vf keygenVectorFile
	data, err := os.ReadFile("testdata/keygen.json")
	if err != nil {
		f.Fatalf("read keygen.json: %v", err)
	}
	if err := json.Unmarshal(data, &vf); err != nil {
		f.Fatalf("parse keygen.json: %v", err)
	}
	if len(vf.HQC128.Tests) > 0 {
		entropy, err := hex.DecodeString(vf.HQC128.Tests[0].Entropy)
		if err != nil {
			f.Fatalf("hex decode entropy: %v", err)
		}
		// Pad to SeedSize128 (96) if needed; KATRNG entropy is 48 bytes,
		// but NewDecapsulationKey128 needs exactly 96.
		seed := make([]byte, SeedSize128)
		copy(seed, entropy)
		f.Add(seed)
	}
	// Seed: all-zero.
	f.Add(make([]byte, SeedSize128))

	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) != SeedSize128 {
			// Skip seeds that aren't the right length.
			return
		}
		dk, err := NewDecapsulationKey128(seed)
		if err != nil {
			// NewDecapsulationKey128 with a 96-byte seed deterministically
			// generates a key and runs a consistency check against its own
			// output. This should never fail. If it does, it's a real bug.
			t.Fatalf("NewDecapsulationKey128 from 96-byte seed: %v", err)
		}

		// Serialize and re-parse the decapsulation key.
		skBytes := dk.Bytes()
		if len(skBytes) != SecretKeySize128 {
			t.Fatalf("Bytes() length = %d, want %d", len(skBytes), SecretKeySize128)
		}
		dk2, err := ParseDecapsulationKey128(skBytes)
		if err != nil {
			t.Fatalf("parse dk from Bytes: %v", err)
		}

		// Encapsulate with the original key's ek.
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		if len(ssEnc) != SharedSecretSize128 {
			t.Fatalf("Encapsulate ss length = %d, want %d", len(ssEnc), SharedSecretSize128)
		}
		if len(ct) != CiphertextSize128 {
			t.Fatalf("Encapsulate ct length = %d, want %d", len(ct), CiphertextSize128)
		}

		// Decapsulate with both original and parsed key.
		ssDec1, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("dk.Decapsulate: %v", err)
		}
		ssDec2, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatalf("dk2.Decapsulate: %v", err)
		}

		if !bytes.Equal(ssEnc, ssDec1) {
			t.Fatal("original dk: shared secret mismatch")
		}
		if !bytes.Equal(ssEnc, ssDec2) {
			t.Fatal("parsed dk: shared secret mismatch")
		}

		// Seed round-trip.
		seedOut := dk.Seed()
		if len(seedOut) != SeedSize128 {
			t.Fatalf("Seed() length = %d, want %d", len(seedOut), SeedSize128)
		}
		dk3, err := NewDecapsulationKey128(seedOut)
		if err != nil {
			t.Fatalf("NewDecapsulationKey128 from Seed: %v", err)
		}
		ssDec3, err := dk3.Decapsulate(ct)
		if err != nil {
			t.Fatalf("dk3.Decapsulate: %v", err)
		}
		if !bytes.Equal(ssEnc, ssDec3) {
			t.Fatal("seed-round-tripped dk: shared secret mismatch")
		}
	})
}
