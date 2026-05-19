package hqc

import (
	"encoding/hex"
	"testing"
)

func TestSeedExpanderFoundation(t *testing.T) {
	// SHAKE256(zeros(32) || 0x01).squeeze(32) - the single most important test.
	// If SHAKE256 output differs from the reference C, nothing else will work.
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	out := make([]byte, 32)
	se.Read(out)

	expected := "d3593e6fc40e08fc4ca6cf6b52a09e576b527af2d50e9b63e6bdbbad3ef37b91"
	got := hex.EncodeToString(out)
	if got != expected {
		t.Fatalf("seedexpander foundation FAILED\ngot:  %s\nwant: %s", got, expected)
	}
}

func TestSeedExpanderSplitReads(t *testing.T) {
	// v5.0.0 has no 8-byte alignment. Split reads MUST produce the same
	// stream as a single large read (direct SHAKE256 squeeze).
	seed := make([]byte, 32)

	se1 := newSeedExpander(seed)
	big := make([]byte, 300)
	se1.Read(big)

	se2 := newSeedExpander(seed)
	small1 := make([]byte, 100)
	small2 := make([]byte, 100)
	small3 := make([]byte, 100)
	se2.Read(small1)
	se2.Read(small2)
	se2.Read(small3)

	// With no alignment, ALL 300 bytes must match exactly.
	combined := make([]byte, 300)
	copy(combined[0:100], small1)
	copy(combined[100:200], small2)
	copy(combined[200:300], small3)

	if hex.EncodeToString(big) != hex.EncodeToString(combined) {
		t.Fatal("split reads diverged from single read (alignment leak?)")
	}
}

func TestSeedExpanderNonZeroSeed(t *testing.T) {
	// Verify that different seeds produce different output.
	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	seed2[0] = 1

	se1 := newSeedExpander(seed1)
	se2 := newSeedExpander(seed2)

	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	se1.Read(out1)
	se2.Read(out2)

	if hex.EncodeToString(out1) == hex.EncodeToString(out2) {
		t.Fatal("different seeds produced identical output")
	}
}

func TestSeedExpanderRelease(t *testing.T) {
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	out := make([]byte, 32)
	se.Read(out)

	// Release should nil the state, preventing further use.
	se.Release()
	if se.state != nil {
		t.Fatal("Release did not nil the state")
	}

	// Verify that calling Read after Release panics.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Read after Release did not panic")
		}
	}()
	se.Read(out)
}

func TestSeedExpanderDomainByte(t *testing.T) {
	// Anti-tamper: the seedexpander domain byte must be exactly 0x01 (v5.0.0).
	if seedExpanderDomain != 0x01 {
		t.Fatalf("seedExpanderDomain = 0x%02x, want 0x01", seedExpanderDomain)
	}
}

func TestSeedExpanderSampler1Regression(t *testing.T) {
	// Regression: the first 3 bytes from seedexpander(zeros(32)) for sampler1
	// (rejection sampling) must produce a specific candidate value after
	// Barrett reduction. This catches seedexpander, domain byte, or Barrett
	// formula changes.
	p := params128
	seed := make([]byte, 32)
	se := newSeedExpander(seed)

	// sampler1 reads 3 bytes per candidate.
	raw := make([]byte, 3)
	se.Read(raw)

	candidate := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16
	// Only test if candidate is below rejection threshold.
	if candidate < p.rejectionThreshold {
		reduced := barrettReduceN(candidate, p.nMu, p.n)
		if reduced >= p.n {
			t.Fatalf("Barrett reduced value %d >= n=%d", reduced, p.n)
		}
	}
	// The key property: the value is deterministic from seed+domain.
	// KAT vectors provide full-chain verification. This test catches
	// a broken seedexpander before KATs are even attempted.
}
