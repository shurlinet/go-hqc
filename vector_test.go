package hqc

import (
	"encoding/hex"
	"math/bits"
	"testing"
)

func TestSampler1KeygenHQC128(t *testing.T) {
	p := params128
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	v := make([]uint64, p.vecNSize64)
	sampleFixedWeightKeygen(p, se, v, p.omega)

	// Postcondition: Hamming weight must equal omega.
	weight := 0
	for _, w := range v {
		weight += bits.OnesCount64(w)
	}
	if weight != int(p.omega) {
		t.Fatalf("HQC-128 sampler1: got weight %d, want %d", weight, p.omega)
	}
}

func TestSampler1KeygenHQC192(t *testing.T) {
	p := params192
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	v := make([]uint64, p.vecNSize64)
	sampleFixedWeightKeygen(p, se, v, p.omega)

	weight := 0
	for _, w := range v {
		weight += bits.OnesCount64(w)
	}
	if weight != int(p.omega) {
		t.Fatalf("HQC-192 sampler1: got weight %d, want %d", weight, p.omega)
	}
}

func TestSampler1KeygenHQC256(t *testing.T) {
	p := params256
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	v := make([]uint64, p.vecNSize64)
	sampleFixedWeightKeygen(p, se, v, p.omega)

	weight := 0
	for _, w := range v {
		weight += bits.OnesCount64(w)
	}
	if weight != int(p.omega) {
		t.Fatalf("HQC-256 sampler1: got weight %d, want %d", weight, p.omega)
	}
}

func TestSampler2EncryptHQC128(t *testing.T) {
	p := params128
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	v := make([]uint64, p.vecNSize64)
	sampleFixedWeightEncrypt(p, se, v, p.omegaR)

	weight := 0
	for _, w := range v {
		weight += bits.OnesCount64(w)
	}
	if weight != int(p.omegaR) {
		t.Fatalf("HQC-128 sampler2: got weight %d, want %d", weight, p.omegaR)
	}
}

func TestSampler2Determinism(t *testing.T) {
	// Same seed must produce identical output (sampler2 is deterministic).
	p := params128
	seed := make([]byte, 32)
	seed[0] = 0x42

	se1 := newSeedExpander(seed)
	v1 := make([]uint64, p.vecNSize64)
	sampleFixedWeightEncrypt(p, se1, v1, p.omegaR)

	se2 := newSeedExpander(seed)
	v2 := make([]uint64, p.vecNSize64)
	sampleFixedWeightEncrypt(p, se2, v2, p.omegaR)

	if constantTimeEqualUint64(v1, v2, int(p.vecNSize64)) != 1 {
		t.Fatal("sampler2 with same seed produced different output")
	}
}

func TestConsecutiveKeygenCalls(t *testing.T) {
	// Verify that TWO consecutive sampler1 calls from the same seedexpander
	// produce DIFFERENT vectors. This exercises the keygen pattern where
	// y and x are generated sequentially from the same seed_dk expander.
	p := params128
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	v1 := make([]uint64, p.vecNSize64)
	v2 := make([]uint64, p.vecNSize64)
	sampleFixedWeightKeygen(p, se, v1, p.omega)
	sampleFixedWeightKeygen(p, se, v2, p.omega)

	// v1 and v2 must be different (same seed but different stream positions).
	same := true
	for i := range v1 {
		if v1[i] != v2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("consecutive sampler1 vectors are identical (SHAKE state not advancing)")
	}

	// Both must have correct weight.
	w1, w2 := 0, 0
	for _, w := range v1 {
		w1 += bits.OnesCount64(w)
	}
	for _, w := range v2 {
		w2 += bits.OnesCount64(w)
	}
	if w1 != int(p.omega) {
		t.Fatalf("v1 weight = %d, want %d", w1, p.omega)
	}
	if w2 != int(p.omega) {
		t.Fatalf("v2 weight = %d, want %d", w2, p.omega)
	}
}

func TestConsecutiveEncryptCalls(t *testing.T) {
	// v5.0.0 encrypt sampling order: r2, e, r1 from same XOF.
	// Verify all three are different and have correct weights.
	p := params128
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	r2 := make([]uint64, p.vecNSize64)
	e := make([]uint64, p.vecNSize64)
	r1 := make([]uint64, p.vecNSize64)
	sampleFixedWeightEncrypt(p, se, r2, p.omegaR)
	sampleFixedWeightEncrypt(p, se, e, p.omegaE)
	sampleFixedWeightEncrypt(p, se, r1, p.omegaR)

	checkWeight := func(name string, v []uint64, want uint16) {
		w := 0
		for _, word := range v {
			w += bits.OnesCount64(word)
		}
		if w != int(want) {
			t.Fatalf("%s weight = %d, want %d", name, w, want)
		}
	}
	checkWeight("r2", r2, p.omegaR)
	checkWeight("e", e, p.omegaE)
	checkWeight("r1", r1, p.omegaR)

	// All three must be different.
	if constantTimeEqualUint64(r2, e, int(p.vecNSize64)) == 1 {
		t.Fatal("r2 and e are identical")
	}
	if constantTimeEqualUint64(r2, r1, int(p.vecNSize64)) == 1 {
		t.Fatal("r2 and r1 are identical")
	}
	if constantTimeEqualUint64(e, r1, int(p.vecNSize64)) == 1 {
		t.Fatal("e and r1 are identical")
	}
}

func TestVectCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 5}
	c := []byte{1, 2, 3, 4, 6}

	if vectCompare(a, b, 5) != 0 {
		t.Fatal("vectCompare: equal slices should return 0")
	}
	if vectCompare(a, c, 5) != 1 {
		t.Fatal("vectCompare: different slices should return 1")
	}
}

func TestConstantTimeEqualUint64(t *testing.T) {
	a := []uint64{1, 2, 3}
	b := []uint64{1, 2, 3}
	c := []uint64{1, 2, 4}

	if constantTimeEqualUint64(a, b, 3) != 1 {
		t.Fatal("equal slices should return 1")
	}
	if constantTimeEqualUint64(a, c, 3) != 0 {
		t.Fatal("different slices should return 0")
	}
}

func TestLoad8Store8RoundTrip(t *testing.T) {
	// Verify load8Arr and store8Arr are exact inverses for both aligned
	// and non-aligned byte lengths.
	tests := []struct {
		name   string
		nBytes int
		nWords int
	}{
		{"aligned_16", 16, 2},
		{"aligned_2209", 2209, 277}, // HQC-128 vecNSizeBytes
		{"aligned_8", 8, 1},
		{"remainder_1", 1, 1},
		{"remainder_3", 3, 1},
		{"remainder_7", 7, 1},
		{"remainder_9", 9, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create known byte pattern.
			in := make([]byte, tt.nBytes)
			for i := range in {
				in[i] = byte(i*37 + 13) // arbitrary non-zero pattern
			}

			// Load into uint64 array.
			words := make([]uint64, tt.nWords)
			load8Arr(words, in)

			// Store back to bytes.
			out := make([]byte, tt.nBytes)
			store8Arr(out, words)

			// Compare.
			for i := range in {
				if in[i] != out[i] {
					t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, out[i], in[i])
				}
			}
		})
	}
}

func TestLoad8ArrKnownValue(t *testing.T) {
	// Verify exact little-endian behavior.
	in := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA}
	out := make([]uint64, 2)
	load8Arr(out, in)

	// First word: 0x0807060504030201 (LE)
	if out[0] != 0x0807060504030201 {
		t.Fatalf("word[0] = %016x, want 0807060504030201", out[0])
	}
	// Second word: just 0xAA (one remaining byte)
	if out[1] != 0xAA {
		t.Fatalf("word[1] = %016x, want 00000000000000AA", out[1])
	}
}

// helpers

func firstSetBits(v []uint64, count int) []int {
	var result []int
	for w := 0; w < len(v) && len(result) < count; w++ {
		for b := 0; b < 64 && len(result) < count; b++ {
			if v[w]&(uint64(1)<<uint(b)) != 0 {
				result = append(result, w*64+b)
			}
		}
	}
	return result
}

func vecToHex(v []uint64, nWords int) string {
	buf := make([]byte, nWords*8)
	for i := 0; i < nWords; i++ {
		for b := 0; b < 8; b++ {
			buf[i*8+b] = byte(v[i] >> (uint(b) * 8))
		}
	}
	return hex.EncodeToString(buf)
}
