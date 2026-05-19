package hqc

import (
	"bytes"
	"testing"
)

// TestPropertyRoundTripAllParams verifies Encaps->Decaps round-trip for all
// three parameter sets. Each subtest generates 5 fresh keypairs and verifies
// shared secret agreement and length.
func TestPropertyRoundTripAllParams(t *testing.T) {
	const iterations = 5

	t.Run("HQC-128", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			dk, err := GenerateKey128()
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			ssEnc, ct := dk.EncapsulationKey().Encapsulate()
			ssDec, err := dk.Decapsulate(ct)
			if err != nil {
				t.Fatalf("iter %d: decaps: %v", i, err)
			}
			if !bytes.Equal(ssEnc, ssDec) {
				t.Fatalf("iter %d: shared secret mismatch", i)
			}
			if len(ssEnc) != SharedSecretSize128 {
				t.Fatalf("iter %d: ss length = %d, want %d", i, len(ssEnc), SharedSecretSize128)
			}
		}
	})

	t.Run("HQC-192", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			dk, err := GenerateKey192()
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			ssEnc, ct := dk.EncapsulationKey().Encapsulate()
			ssDec, err := dk.Decapsulate(ct)
			if err != nil {
				t.Fatalf("iter %d: decaps: %v", i, err)
			}
			if !bytes.Equal(ssEnc, ssDec) {
				t.Fatalf("iter %d: shared secret mismatch", i)
			}
			if len(ssEnc) != SharedSecretSize192 {
				t.Fatalf("iter %d: ss length = %d, want %d", i, len(ssEnc), SharedSecretSize192)
			}
		}
	})

	t.Run("HQC-256", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			dk, err := GenerateKey256()
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			ssEnc, ct := dk.EncapsulationKey().Encapsulate()
			ssDec, err := dk.Decapsulate(ct)
			if err != nil {
				t.Fatalf("iter %d: decaps: %v", i, err)
			}
			if !bytes.Equal(ssEnc, ssDec) {
				t.Fatalf("iter %d: shared secret mismatch", i)
			}
			if len(ssEnc) != SharedSecretSize256 {
				t.Fatalf("iter %d: ss length = %d, want %d", i, len(ssEnc), SharedSecretSize256)
			}
		}
	})
}

// TestPropertyKeySerializationAllParams verifies Bytes/Parse round-trip for
// decapsulation keys across all three parameter sets. The parsed key must
// produce the same shared secret as the original.
func TestPropertyKeySerializationAllParams(t *testing.T) {
	t.Run("HQC-128", func(t *testing.T) {
		dk, err := GenerateKey128()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := ParseDecapsulationKey128(dk.Bytes())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("parsed key: shared secret mismatch")
		}

		// EK round-trip.
		ek2, err := ParseEncapsulationKey128(dk.EncapsulationKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.EncapsulationKey().Bytes(), ek2.Bytes()) {
			t.Fatal("ek Bytes round-trip mismatch")
		}
	})

	t.Run("HQC-192", func(t *testing.T) {
		dk, err := GenerateKey192()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := ParseDecapsulationKey192(dk.Bytes())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("parsed key: shared secret mismatch")
		}

		ek2, err := ParseEncapsulationKey192(dk.EncapsulationKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.EncapsulationKey().Bytes(), ek2.Bytes()) {
			t.Fatal("ek Bytes round-trip mismatch")
		}
	})

	t.Run("HQC-256", func(t *testing.T) {
		dk, err := GenerateKey256()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := ParseDecapsulationKey256(dk.Bytes())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("parsed key: shared secret mismatch")
		}

		ek2, err := ParseEncapsulationKey256(dk.EncapsulationKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.EncapsulationKey().Bytes(), ek2.Bytes()) {
			t.Fatal("ek Bytes round-trip mismatch")
		}
	})
}

// TestPropertySeedRoundTripAllParams verifies Seed() -> NewDecapsulationKey
// round-trip for all three parameter sets. The seed-derived key must produce
// identical Bytes() output and matching shared secrets.
func TestPropertySeedRoundTripAllParams(t *testing.T) {
	t.Run("HQC-128", func(t *testing.T) {
		dk, err := GenerateKey128()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := NewDecapsulationKey128(dk.Seed())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
			t.Fatal("seed round-trip: Bytes mismatch")
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("seed round-trip: shared secret mismatch")
		}
	})

	t.Run("HQC-192", func(t *testing.T) {
		dk, err := GenerateKey192()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := NewDecapsulationKey192(dk.Seed())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
			t.Fatal("seed round-trip: Bytes mismatch")
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("seed round-trip: shared secret mismatch")
		}
	})

	t.Run("HQC-256", func(t *testing.T) {
		dk, err := GenerateKey256()
		if err != nil {
			t.Fatal(err)
		}
		dk2, err := NewDecapsulationKey256(dk.Seed())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
			t.Fatal("seed round-trip: Bytes mismatch")
		}
		ssEnc, ct := dk.EncapsulationKey().Encapsulate()
		ssDec, err := dk2.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			t.Fatal("seed round-trip: shared secret mismatch")
		}
	})
}

// --- AI Threat Defense Tests ---

// TestAIThreatDomainBytesNotSwapped verifies that the four v5.0.0 hash
// function domain bytes are not transposed. A transposed pair would still
// produce valid-looking output but break interop with the reference C.
func TestAIThreatDomainBytesNotSwapped(t *testing.T) {
	// v5.0.0 symmetric.h: G=0, H=1, I=2, J=3.
	if gFctDomain != 0 {
		t.Fatalf("G domain byte = %d, want 0", gFctDomain)
	}
	if hFctDomain != 1 {
		t.Fatalf("H domain byte = %d, want 1", hFctDomain)
	}
	if iFctDomain != 2 {
		t.Fatalf("I domain byte = %d, want 2", iFctDomain)
	}
	if jFctDomain != 3 {
		t.Fatalf("J domain byte = %d, want 3", jFctDomain)
	}
	// Uniqueness: no two domains may be equal.
	domains := []byte{gFctDomain, hFctDomain, iFctDomain, jFctDomain}
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i] == domains[j] {
				t.Fatalf("domain collision: index %d and %d both = %d", i, j, domains[i])
			}
		}
	}
}

// TestAIThreatHashGIndependent verifies hashG via independent SHA3-512
// construction. hashG(hEK, m, salt) = SHA3-512(hEK || m || salt || domain=0).
// hashG is the most security-critical function: it produces K (shared secret
// source) and theta (encryption randomness).
func TestAIThreatHashGIndependent(t *testing.T) {
	hEK := []byte("hqc-test-h_ek-32-bytes-exactly!!")
	m := []byte("hqc-test-message-16")
	salt := []byte("hqc-test-salt16!")

	// Production path.
	got := hashG(params128, hEK, m, salt)

	// Independent construction: SHA3-512(hEK || m || salt || 0x00).
	h := newSHA3_512ForTest()
	h.Write(hEK)
	h.Write(m)
	h.Write(salt)
	h.Write([]byte{gFctDomain})
	want := h.Sum(nil)

	if !bytes.Equal(got[:], want) {
		t.Fatal("hashG output differs from independent SHA3-512(hEK || m || salt || domain)")
	}
}

// TestAIThreatHashHIndependent verifies hashH via independent SHA3-256
// construction. hashH(pk) = SHA3-256(pk || domain=1).
func TestAIThreatHashHIndependent(t *testing.T) {
	pk := []byte("hqc-test-public-key-for-hash-verification")

	// Production path.
	got := hashH(pk)

	// Independent construction: SHA3-256(pk || 0x01).
	h := newSHA3_256ForTest()
	h.Write(pk)
	h.Write([]byte{hFctDomain})
	want := h.Sum(nil)

	if !bytes.Equal(got[:], want) {
		t.Fatal("hashH output differs from independent SHA3-256(pk || domain)")
	}
}

// TestAIThreatNMuFormula verifies that the nMu and rejectionThreshold
// constants are correctly computed for all three parameter sets.
func TestAIThreatNMuFormula(t *testing.T) {
	paramSets := []*params{params128, params192, params256}
	names := []string{"HQC-128", "HQC-192", "HQC-256"}

	for idx, p := range paramSets {
		// nMu = floor(2^32 / n)
		expectedNMu := uint32(uint64(1<<32) / uint64(p.n))
		if p.nMu != expectedNMu {
			t.Fatalf("%s: nMu = %d, want %d (floor(2^32 / %d))",
				names[idx], p.nMu, expectedNMu, p.n)
		}

		// rejectionThreshold = floor(2^24 / n) * n
		expectedThresh := uint32((uint64(1<<24) / uint64(p.n)) * uint64(p.n))
		if p.rejectionThreshold != expectedThresh {
			t.Fatalf("%s: rejectionThreshold = %d, want %d (floor(2^24 / %d) * %d)",
				names[idx], p.rejectionThreshold, expectedThresh, p.n, p.n)
		}
	}
}

// TestVersion verifies the Version() function returns the expected spec version.
func TestVersion(t *testing.T) {
	v := Version()
	if v != "v5.0.0" {
		t.Fatalf("Version() = %q, want %q", v, "v5.0.0")
	}
}

// Benchmarks for all three parameter sets (Keygen, Encapsulate, Decapsulate).
// Package-level sinks prevent dead code elimination by the compiler.
var (
	benchSS []byte
	benchCT []byte
)

func BenchmarkKeygen128(b *testing.B) {
	for b.Loop() {
		dk, err := GenerateKey128()
		if err != nil {
			b.Fatal(err)
		}
		dk.Destroy()
	}
}

func BenchmarkEncapsulate128(b *testing.B) {
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for b.Loop() {
		benchSS, benchCT = ek.Encapsulate()
	}
}

func BenchmarkDecapsulate128(b *testing.B) {
	dk, _ := GenerateKey128()
	_, ct := dk.EncapsulationKey().Encapsulate()
	b.ResetTimer()
	for b.Loop() {
		benchSS, _ = dk.Decapsulate(ct)
	}
}

func BenchmarkKeygen192(b *testing.B) {
	for b.Loop() {
		dk, err := GenerateKey192()
		if err != nil {
			b.Fatal(err)
		}
		dk.Destroy()
	}
}

func BenchmarkEncapsulate192(b *testing.B) {
	dk, _ := GenerateKey192()
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for b.Loop() {
		benchSS, benchCT = ek.Encapsulate()
	}
}

func BenchmarkDecapsulate192(b *testing.B) {
	dk, _ := GenerateKey192()
	_, ct := dk.EncapsulationKey().Encapsulate()
	b.ResetTimer()
	for b.Loop() {
		benchSS, _ = dk.Decapsulate(ct)
	}
}

func BenchmarkKeygen256(b *testing.B) {
	for b.Loop() {
		dk, err := GenerateKey256()
		if err != nil {
			b.Fatal(err)
		}
		dk.Destroy()
	}
}

func BenchmarkEncapsulate256(b *testing.B) {
	dk, _ := GenerateKey256()
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for b.Loop() {
		benchSS, benchCT = ek.Encapsulate()
	}
}

func BenchmarkDecapsulate256(b *testing.B) {
	dk, _ := GenerateKey256()
	_, ct := dk.EncapsulationKey().Encapsulate()
	b.ResetTimer()
	for b.Loop() {
		benchSS, _ = dk.Decapsulate(ct)
	}
}
