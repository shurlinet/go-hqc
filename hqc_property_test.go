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

// TestAIThreatDomainBytesNotSwapped verifies that the G and K domain
// separation bytes are not transposed. A transposed pair would still produce
// valid-looking output but break interop with the reference C.
func TestAIThreatDomainBytesNotSwapped(t *testing.T) {
	// G function (theta derivation) uses domain 3.
	// K function (shared secret derivation) uses domain 4.
	// If these are swapped, KAT vectors would fail. But this test
	// catches a subtler bug: someone re-orders the constants file
	// and swaps the values without running KATs.
	if gFctDomain != 3 {
		t.Fatalf("G domain byte = %d, want 3 (v5.0.0 symmetric.h)", gFctDomain)
	}
	if kFctDomain != 4 {
		t.Fatalf("K domain byte = %d, want 4 (v5.0.0 symmetric.h)", kFctDomain)
	}
	if gFctDomain >= kFctDomain {
		t.Fatal("G domain must be less than K domain (3 < 4)")
	}
}

// TestAIThreatSHAKEInputOrder verifies that shake256_512DS absorbs input
// BEFORE the domain byte. Reversed order would produce valid-looking hashes
// but break interop.
func TestAIThreatSHAKEInputOrder(t *testing.T) {
	// Compute G(input, domain=3) two ways:
	// 1. Via shake256_512DS (production path)
	// 2. Via manual SHAKE256(input || domain) construction
	// They must match. If shake256_512DS absorbs domain before input,
	// the outputs diverge.
	input := []byte("hqc-test-input-for-ordering-verification")
	domain := byte(gFctDomain)

	// Production path.
	out1 := make([]byte, 64)
	shake256_512DS(out1, input, domain)

	// Independent construction: SHAKE256(input || domain), squeeze 64.
	out2 := make([]byte, 64)
	st := newSHAKE256ForTest()
	if n, _ := st.Write(input); n != len(input) {
		t.Fatalf("SHAKE Write(input): wrote %d, want %d", n, len(input))
	}
	if n, _ := st.Write([]byte{domain}); n != 1 {
		t.Fatalf("SHAKE Write(domain): wrote %d, want 1", n)
	}
	if n, _ := st.Read(out2); n != 64 {
		t.Fatalf("SHAKE Read: got %d bytes, want 64", n)
	}

	if !bytes.Equal(out1, out2) {
		t.Fatal("shake256_512DS input order differs from SHAKE256(input || domain)")
	}
}

// TestAIThreatMValFormula verifies that the mVal lookup table for each
// parameter set was computed correctly. mVal is used for Barrett reduction
// in rejection sampling. An off-by-one would cause silent sampling failures.
func TestAIThreatMValFormula(t *testing.T) {
	// mVal[i] = floor(2^32 / (n - i)) for i in [0, omegaR).
	// Barrett constant for rejection sampling: quotient must not overshoot.
	paramSets := []*params{params128, params192, params256}
	names := []string{"HQC-128", "HQC-192", "HQC-256"}

	for idx, p := range paramSets {
		if len(p.mVal) != int(p.omegaR) {
			t.Fatalf("%s: mVal length = %d, want omegaR = %d", names[idx], len(p.mVal), p.omegaR)
		}
		for i := 0; i < len(p.mVal); i++ {
			expected := uint32(uint64(1<<32) / uint64(p.n-uint32(i)))
			got := p.mVal[i]
			if got != expected {
				t.Fatalf("%s: mVal[%d] = %d, want %d (formula: 2^32 / (%d-%d))",
					names[idx], i, got, expected, p.n, i)
			}
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
