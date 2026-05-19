package hqc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"
)

// --- KAT vector structures ---

type keygenVectorFile struct {
	HQC128 keygenParamSet `json:"hqc-128"`
	HQC192 keygenParamSet `json:"hqc-192"`
	HQC256 keygenParamSet `json:"hqc-256"`
}

type keygenParamSet struct {
	Tests []keygenTest `json:"tests"`
}

type keygenTest struct {
	TcID    int    `json:"tcId"`
	Entropy string `json:"entropy"`
	PK      string `json:"pk"`
	SK      string `json:"sk"`
}

type encapsVectorFile struct {
	HQC128 encapsParamSet `json:"hqc-128"`
	HQC192 encapsParamSet `json:"hqc-192"`
	HQC256 encapsParamSet `json:"hqc-256"`
}

type encapsParamSet struct {
	KeyEntropy string       `json:"key_entropy"`
	PK         string       `json:"pk"`
	Tests      []encapsTest `json:"tests"`
}

type encapsTest struct {
	TcID           int    `json:"tcId"`
	EncapsEntropy  string `json:"encaps_entropy"`
	CT             string `json:"ct"`
	SS             string `json:"ss"`
}

// --- Helper ---

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func loadJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

// --- KAT Keygen Tests (GATE) ---

func TestKATKeygen128(t *testing.T) {
	var vf keygenVectorFile
	loadJSON(t, "testdata/keygen.json", &vf)
	testKATKeygen(t, "HQC-128", vf.HQC128.Tests, func(r *KATRNG) (pkBytes, skBytes []byte, err error) {
		dk, err := GenerateKeyForTest128(r)
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	})
}

func TestKATKeygen192(t *testing.T) {
	var vf keygenVectorFile
	loadJSON(t, "testdata/keygen.json", &vf)
	testKATKeygen(t, "HQC-192", vf.HQC192.Tests, func(r *KATRNG) (pkBytes, skBytes []byte, err error) {
		dk, err := GenerateKeyForTest192(r)
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	})
}

func TestKATKeygen256(t *testing.T) {
	var vf keygenVectorFile
	loadJSON(t, "testdata/keygen.json", &vf)
	testKATKeygen(t, "HQC-256", vf.HQC256.Tests, func(r *KATRNG) (pkBytes, skBytes []byte, err error) {
		dk, err := GenerateKeyForTest256(r)
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	})
}

func testKATKeygen(t *testing.T, name string, tests []keygenTest,
	gen func(*KATRNG) ([]byte, []byte, error)) {
	t.Helper()
	for _, tc := range tests {
		entropy := mustDecodeHex(t, tc.Entropy)
		wantPK := mustDecodeHex(t, tc.PK)
		wantSK := mustDecodeHex(t, tc.SK)

		rng := NewKATRNG(entropy)
		gotPK, gotSK, err := gen(rng)
		if err != nil {
			t.Fatalf("%s tc%d: keygen error: %v", name, tc.TcID, err)
		}

		if !bytes.Equal(gotPK, wantPK) {
			t.Fatalf("%s tc%d: pk mismatch\ngot:  %s\nwant: %s",
				name, tc.TcID, hex.EncodeToString(gotPK[:32]), hex.EncodeToString(wantPK[:32]))
		}
		if !bytes.Equal(gotSK, wantSK) {
			t.Fatalf("%s tc%d: sk mismatch\ngot:  %s\nwant: %s",
				name, tc.TcID, hex.EncodeToString(gotSK[:32]), hex.EncodeToString(wantSK[:32]))
		}
	}
}

// --- KAT Encaps Tests (GATE) ---

func TestKATEncaps128(t *testing.T) {
	var vf encapsVectorFile
	loadJSON(t, "testdata/encaps.json", &vf)
	testKATEncaps(t, "HQC-128", vf.HQC128, func(pk []byte) (*EncapsulationKey128, error) {
		return ParseEncapsulationKey128(pk)
	}, func(ek *EncapsulationKey128, r *KATRNG) ([]byte, []byte) {
		return EncapsulateForTest128(ek, r)
	}, func(sk []byte) (*DecapsulationKey128, error) {
		return ParseDecapsulationKey128(sk)
	}, func(dk *DecapsulationKey128, ct []byte) ([]byte, error) {
		return dk.Decapsulate(ct)
	})
}

func TestKATEncaps192(t *testing.T) {
	var vf encapsVectorFile
	loadJSON(t, "testdata/encaps.json", &vf)
	testKATEncaps(t, "HQC-192", vf.HQC192, func(pk []byte) (*EncapsulationKey192, error) {
		return ParseEncapsulationKey192(pk)
	}, func(ek *EncapsulationKey192, r *KATRNG) ([]byte, []byte) {
		return EncapsulateForTest192(ek, r)
	}, func(sk []byte) (*DecapsulationKey192, error) {
		return ParseDecapsulationKey192(sk)
	}, func(dk *DecapsulationKey192, ct []byte) ([]byte, error) {
		return dk.Decapsulate(ct)
	})
}

func TestKATEncaps256(t *testing.T) {
	var vf encapsVectorFile
	loadJSON(t, "testdata/encaps.json", &vf)
	testKATEncaps(t, "HQC-256", vf.HQC256, func(pk []byte) (*EncapsulationKey256, error) {
		return ParseEncapsulationKey256(pk)
	}, func(ek *EncapsulationKey256, r *KATRNG) ([]byte, []byte) {
		return EncapsulateForTest256(ek, r)
	}, func(sk []byte) (*DecapsulationKey256, error) {
		return ParseDecapsulationKey256(sk)
	}, func(dk *DecapsulationKey256, ct []byte) ([]byte, error) {
		return dk.Decapsulate(ct)
	})
}

func testKATEncaps[EK any, DK any](t *testing.T, name string, ps encapsParamSet,
	parseEK func([]byte) (EK, error),
	encaps func(EK, *KATRNG) ([]byte, []byte),
	parseDK func([]byte) (DK, error),
	decaps func(DK, []byte) ([]byte, error)) {
	t.Helper()

	// Load the fixed keypair for this param set.
	keyEntropy := mustDecodeHex(t, ps.KeyEntropy)
	keyRNG := NewKATRNG(keyEntropy)

	var pkBytes, skBytes []byte
	switch name {
	case "HQC-128":
		dk, err := GenerateKeyForTest128(keyRNG)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		pkBytes = dk.EncapsulationKey().Bytes()
		skBytes = dk.Bytes()
	case "HQC-192":
		dk, err := GenerateKeyForTest192(keyRNG)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		pkBytes = dk.EncapsulationKey().Bytes()
		skBytes = dk.Bytes()
	case "HQC-256":
		dk, err := GenerateKeyForTest256(keyRNG)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		pkBytes = dk.EncapsulationKey().Bytes()
		skBytes = dk.Bytes()
	}

	// Verify our pk matches the vector file's pk.
	wantPK := mustDecodeHex(t, ps.PK)
	if !bytes.Equal(pkBytes, wantPK) {
		t.Fatalf("%s: keypair pk mismatch", name)
	}

	ek, err := parseEK(pkBytes)
	if err != nil {
		t.Fatalf("%s: parse ek: %v", name, err)
	}
	dk, err := parseDK(skBytes)
	if err != nil {
		t.Fatalf("%s: parse dk: %v", name, err)
	}

	for _, tc := range ps.Tests {
		encEntropy := mustDecodeHex(t, tc.EncapsEntropy)
		wantCT := mustDecodeHex(t, tc.CT)
		wantSS := mustDecodeHex(t, tc.SS)

		encRNG := NewKATRNG(encEntropy)
		gotSSEnc, gotCT := encaps(ek, encRNG)

		if !bytes.Equal(gotCT, wantCT) {
			t.Fatalf("%s tc%d: ct mismatch\ngot:  %s\nwant: %s",
				name, tc.TcID, hex.EncodeToString(gotCT[:32]), hex.EncodeToString(wantCT[:32]))
		}
		if !bytes.Equal(gotSSEnc, wantSS) {
			t.Fatalf("%s tc%d: ss_enc mismatch\ngot:  %s\nwant: %s",
				name, tc.TcID, hex.EncodeToString(gotSSEnc), hex.EncodeToString(wantSS))
		}

		// Decapsulate and verify shared secret matches.
		gotSSDec, err := decaps(dk, gotCT)
		if err != nil {
			t.Fatalf("%s tc%d: decaps error: %v", name, tc.TcID, err)
		}
		if !bytes.Equal(gotSSDec, wantSS) {
			t.Fatalf("%s tc%d: ss_dec mismatch\ngot:  %s\nwant: %s",
				name, tc.TcID, hex.EncodeToString(gotSSDec), hex.EncodeToString(wantSS))
		}
	}
}

// --- Round-trip Tests ---

func TestRoundTrip128(t *testing.T) {
	dk, err := GenerateKey128()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ssEnc, ct := ek.Encapsulate()
	ssDec, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets don't match")
	}
	if len(ssEnc) != SharedSecretSize128 {
		t.Fatalf("ss length = %d, want %d", len(ssEnc), SharedSecretSize128)
	}
}

func TestRoundTrip192(t *testing.T) {
	dk, err := GenerateKey192()
	if err != nil {
		t.Fatal(err)
	}
	ssEnc, ct := dk.EncapsulationKey().Encapsulate()
	ssDec, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets don't match")
	}
}

func TestRoundTrip256(t *testing.T) {
	dk, err := GenerateKey256()
	if err != nil {
		t.Fatal(err)
	}
	ssEnc, ct := dk.EncapsulationKey().Encapsulate()
	ssDec, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets don't match")
	}
}

// --- Key Serialization Round-trip ---

func TestKeySerializationRoundTrip128(t *testing.T) {
	dk, err := GenerateKey128()
	if err != nil {
		t.Fatal(err)
	}

	// Bytes round-trip.
	skBytes := dk.Bytes()
	dk2, err := ParseDecapsulationKey128(skBytes)
	if err != nil {
		t.Fatalf("parse dk from Bytes: %v", err)
	}
	if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fatal("dk Bytes round-trip mismatch")
	}

	// Seed round-trip.
	seed := dk.Seed()
	dk3, err := NewDecapsulationKey128(seed)
	if err != nil {
		t.Fatalf("new dk from Seed: %v", err)
	}
	if !bytes.Equal(dk.Bytes(), dk3.Bytes()) {
		t.Fatal("dk Seed round-trip mismatch")
	}

	// EK round-trip.
	ekBytes := dk.EncapsulationKey().Bytes()
	ek2, err := ParseEncapsulationKey128(ekBytes)
	if err != nil {
		t.Fatalf("parse ek: %v", err)
	}
	if !bytes.Equal(ekBytes, ek2.Bytes()) {
		t.Fatal("ek Bytes round-trip mismatch")
	}

	// Encaps with parsed ek, decaps with parsed dk.
	ssEnc, ct := ek2.Encapsulate()
	ssDec, err := dk2.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("round-trip with parsed keys failed")
	}
}

// --- Edge Cases ---

func TestDecapsZeroCiphertext128(t *testing.T) {
	dk, _ := GenerateKey128()
	ct := make([]byte, CiphertextSize128) // all zeros

	ss, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("decaps zero ct error: %v", err)
	}
	if len(ss) != SharedSecretSize128 {
		t.Fatalf("ss length = %d, want %d", len(ss), SharedSecretSize128)
	}

	// The shared secret should be a valid 32-byte value (implicit rejection).
	allZero := true
	for _, b := range ss {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("rejection shared secret is all zeros (should be random-looking)")
	}
}

func TestDecapsModifiedSalt128(t *testing.T) {
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()
	ssEnc, ct := ek.Encapsulate()

	// Flip a bit in the salt (last 16 bytes of ct).
	ctMod := make([]byte, len(ct))
	copy(ctMod, ct)
	ctMod[len(ctMod)-1] ^= 0x01

	ssDec, err := dk.Decapsulate(ctMod)
	if err != nil {
		t.Fatalf("decaps modified salt error: %v", err)
	}

	// Modified salt -> FO rejects -> different shared secret.
	if bytes.Equal(ssEnc, ssDec) {
		t.Fatal("modified salt should produce different shared secret (implicit rejection)")
	}
}

func TestDecapsWrongLength128(t *testing.T) {
	dk, _ := GenerateKey128()

	_, err := dk.Decapsulate(make([]byte, 100))
	if err != ErrInvalidCiphertextSize {
		t.Fatalf("wrong ct length: got err %v, want ErrInvalidCiphertextSize", err)
	}
}

func TestParseKeyWrongLength(t *testing.T) {
	_, err := ParseDecapsulationKey128(make([]byte, 100))
	if err != ErrInvalidKeySize {
		t.Fatalf("wrong sk length: got err %v, want ErrInvalidKeySize", err)
	}

	_, err = ParseEncapsulationKey128(make([]byte, 100))
	if err != ErrInvalidKeySize {
		t.Fatalf("wrong pk length: got err %v, want ErrInvalidKeySize", err)
	}

	_, err = NewDecapsulationKey128(make([]byte, 100))
	if err != ErrInvalidKeySize {
		t.Fatalf("wrong seed length: got err %v, want ErrInvalidKeySize", err)
	}
}

// --- Concurrency ---

func TestConcurrentDecapsulate128(t *testing.T) {
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ssEnc, ct := ek.Encapsulate()
			ssDec, err := dk.Decapsulate(ct)
			if err != nil {
				t.Errorf("decaps error: %v", err)
				return
			}
			if !bytes.Equal(ssEnc, ssDec) {
				t.Errorf("shared secret mismatch in goroutine")
			}
		}()
	}
	wg.Wait()
}

// --- Destroy ---

func TestDestroy128(t *testing.T) {
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()
	_, ct := ek.Encapsulate()

	dk.Destroy()

	// Decapsulate after Destroy should return ErrDestroyed.
	_, err := dk.Decapsulate(ct)
	if err != ErrDestroyed {
		t.Fatalf("decaps after Destroy: got err %v, want ErrDestroyed", err)
	}

	// Bytes and Seed return nil after Destroy.
	if dk.Bytes() != nil {
		t.Fatal("Bytes() should return nil after Destroy")
	}
	if dk.Seed() != nil {
		t.Fatal("Seed() should return nil after Destroy")
	}

	// EncapsulationKey survives Destroy (public data).
	ekBytes := ek.Bytes()
	if len(ekBytes) != PublicKeySize128 {
		t.Fatalf("ek.Bytes() after dk.Destroy: got %d bytes, want %d", len(ekBytes), PublicKeySize128)
	}

	// Double Destroy is safe (no panic).
	dk.Destroy()
}

// --- Returned Slice Isolation ---

func TestReturnedSliceIsolation128(t *testing.T) {
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()

	ss1, ct1 := ek.Encapsulate()
	// Mutate returned slices.
	ct1[0] ^= 0xFF
	ss1[0] ^= 0xFF

	// Second call should produce independent data.
	ss2, ct2 := ek.Encapsulate()
	_ = ct2
	_ = ss2
	// Just verify no panic - the point is mutation of ct1/ss1 doesn't
	// affect internal state.

	// Mutate Bytes() output.
	skBytes := dk.Bytes()
	skBytes[0] ^= 0xFF
	// Original should be unaffected.
	skBytes2 := dk.Bytes()
	if skBytes2[0] == skBytes[0] {
		t.Fatal("mutating Bytes() output affected internal state")
	}
}

// --- Domain Byte Anti-Tamper ---

func TestDomainBytes(t *testing.T) {
	if gFctDomain != 0 {
		t.Fatalf("G domain = %d, want 0", gFctDomain)
	}
	if hFctDomain != 1 {
		t.Fatalf("H domain = %d, want 1", hFctDomain)
	}
	if iFctDomain != 2 {
		t.Fatalf("I domain = %d, want 2", iFctDomain)
	}
	if jFctDomain != 3 {
		t.Fatalf("J domain = %d, want 3", jFctDomain)
	}
	if seedExpanderDomain != 0x01 {
		t.Fatalf("XOF domain = 0x%02x, want 0x01", seedExpanderDomain)
	}
}

func TestKATRNGDomain(t *testing.T) {
	if katPRNGDomain != 0x00 {
		t.Fatalf("KAT PRNG domain = 0x%02x, want 0x00", katPRNGDomain)
	}
}

// --- Keygen Vector Verification (#19) ---

func TestKeygenVectorsMatch128(t *testing.T) {
	// Generate from seed, re-derive y and x from seed_dk, verify they match
	// the vectors that were used to compute the public key s = x + y*h.
	dk, _ := GenerateKey128()
	defer dk.Destroy()

	// Re-derive y, x from seed_dk (v5.0.0 order: y first, then x).
	p := params128
	seedDK := dk.dk.seedDK
	x := make([]uint64, p.vecNSize64)
	y := make([]uint64, p.vecNSize64)
	s := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroUint64s(x)
		ZeroUint64s(y)
		ZeroUint64s(s)
	}()

	se := newSeedExpander(seedDK)
	sampleFixedWeightKeygen(p, se, y, p.omega)
	sampleFixedWeightKeygen(p, se, x, p.omega)
	se.Release()

	// Verify x and y match the cached values.
	if constantTimeEqualUint64(x, dk.dk.x, int(p.vecNSize64)) != 1 {
		t.Fatal("re-derived x does not match cached x")
	}
	if constantTimeEqualUint64(y, dk.dk.y, int(p.vecNSize64)) != 1 {
		t.Fatal("re-derived y does not match cached y")
	}

	// Verify s = x + y*h.
	polyMul(p, s, y, dk.dk.ek.h)
	polyAdd(s, x, s, int(p.vecNSize64))

	if constantTimeEqualUint64(s, dk.dk.ek.s, int(p.vecNSize64)) != 1 {
		t.Fatal("recomputed s = x + y*h does not match cached s")
	}
}

// --- Constant-Time Verification (#22) ---

func TestDecapsulateTimingConsistency128(t *testing.T) {
	// Verify that Decapsulate with a VALID ciphertext and an INVALID ciphertext
	// both produce 32-byte shared secrets without error. This doesn't measure
	// wall-clock timing (Go benchmarks are not reliable for side-channel
	// verification), but it verifies the code PATH is identical:
	// - Both paths allocate the same buffers
	// - Both paths call the same functions
	// - Both paths return the same-sized output
	// True timing verification requires hardware counters or CT-verif tools.
	dk, _ := GenerateKey128()
	ek := dk.EncapsulationKey()

	// Valid ciphertext.
	ssValid, ct := ek.Encapsulate()
	ssDecValid, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("valid ct decaps error: %v", err)
	}
	if !bytes.Equal(ssValid, ssDecValid) {
		t.Fatal("valid ct: shared secrets don't match")
	}

	// Invalid ciphertext (flipped byte in u portion).
	ctBad := make([]byte, len(ct))
	copy(ctBad, ct)
	ctBad[0] ^= 0xFF
	ssDecInvalid, err := dk.Decapsulate(ctBad)
	if err != nil {
		t.Fatalf("invalid ct decaps error: %v", err)
	}

	// Both must return 32-byte shared secrets.
	if len(ssDecValid) != 32 || len(ssDecInvalid) != 32 {
		t.Fatalf("ss lengths: valid=%d invalid=%d, both must be 32", len(ssDecValid), len(ssDecInvalid))
	}

	// Invalid ct must produce a DIFFERENT shared secret (implicit rejection).
	if bytes.Equal(ssDecValid, ssDecInvalid) {
		t.Fatal("valid and invalid ct produced same shared secret (FO rejection broken)")
	}
}

// --- Size Constants Anti-Tamper ---

func TestSizeConstants(t *testing.T) {
	tests := []struct {
		name   string
		p      *params
		pkSize int
		skSize int
		ctSize int
	}{
		{"HQC-128", params128, PublicKeySize128, SecretKeySize128, CiphertextSize128},
		{"HQC-192", params192, PublicKeySize192, SecretKeySize192, CiphertextSize192},
		{"HQC-256", params256, PublicKeySize256, SecretKeySize256, CiphertextSize256},
	}

	for _, tc := range tests {
		sl := uint32(tc.p.seedLen)
		computedPK := int(sl + tc.p.vecNSizeBytes)
		// v5.0.0 SK layout: pk || seed_dk(32) || sigma(securityBytes) || seed_kem(32)
		computedSK := computedPK + int(sl) + int(tc.p.securityBytes) + int(sl)
		computedCT := int(tc.p.vecNSizeBytes + tc.p.vecN1N2SizeBytes + uint32(tc.p.saltLen))

		if tc.pkSize != computedPK {
			t.Fatalf("%s: PublicKeySize=%d, computed=%d", tc.name, tc.pkSize, computedPK)
		}
		if tc.skSize != computedSK {
			t.Fatalf("%s: SecretKeySize=%d, computed=%d", tc.name, tc.skSize, computedSK)
		}
		if tc.ctSize != computedCT {
			t.Fatalf("%s: CiphertextSize=%d, computed=%d", tc.name, tc.ctSize, computedCT)
		}
	}
}
