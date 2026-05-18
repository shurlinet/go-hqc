package hqc

import (
	"encoding/hex"
	"testing"
)

func TestSeedExpanderFoundation(t *testing.T) {
	// SHAKE256(zeros(40) || 0x02).squeeze(32) must produce 0x62... first byte.
	// This is the single most important test - if SHAKE256 output differs from the reference C,
	// nothing else will work.
	seed := make([]byte, 40)
	se := newSeedExpander(seed)

	out := make([]byte, 32)
	se.Read(out)

	expected := "62a13095dd65ae710c86c129d4a6da37adfb75d53705aa4b622e144bf34822fc"
	got := hex.EncodeToString(out)
	if got != expected {
		t.Fatalf("seedexpander foundation FAILED\ngot:  %s\nwant: %s", got, expected)
	}
}

func TestSeedExpanderAlignment(t *testing.T) {
	// 300-byte request triggers 8-byte alignment.
	// 300 = 296 + 4 remainder. The reference C squeezes 296 + 8 = 304 bytes from SHAKE.
	// The first 32 bytes must match the foundation test (same seed, same stream).
	seed := make([]byte, 40)
	se := newSeedExpander(seed)

	out := make([]byte, 300)
	se.Read(out)

	// First 32 bytes must match foundation test.
	expectedFirst32 := "62a13095dd65ae710c86c129d4a6da37adfb75d53705aa4b622e144bf34822fc"
	gotFirst32 := hex.EncodeToString(out[:32])
	if gotFirst32 != expectedFirst32 {
		t.Fatalf("alignment test first 32 bytes FAILED\ngot:  %s\nwant: %s", gotFirst32, expectedFirst32)
	}

	// Last 8 bytes of the 300-byte output.
	expectedLast8 := "0b5a0e1ec960405d"
	gotLast8 := hex.EncodeToString(out[292:300])
	if gotLast8 != expectedLast8 {
		t.Fatalf("alignment test last 8 bytes FAILED\ngot:  %s\nwant: %s", gotLast8, expectedLast8)
	}
}

func TestSeedExpanderNonZeroSeed(t *testing.T) {
	// Verify that different seeds produce different output.
	seed1 := make([]byte, 40)
	seed2 := make([]byte, 40)
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

func TestSeedExpanderMultipleReads(t *testing.T) {
	// Verify that multiple small reads produce the same stream as one large read.
	seed := make([]byte, 40)

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

	// Because of 8-byte alignment, the split reads consume MORE from SHAKE state.
	// 100 = 96 + 4 remainder -> squeezes 96+8=104 per call.
	// Three calls: 312 SHAKE bytes consumed. One 300-byte call: 304 consumed.
	// So the outputs will DIFFER after the first aligned block.
	// The first 96 bytes should match (first aligned chunk).
	got := hex.EncodeToString(small1[:96])
	want := hex.EncodeToString(big[:96])
	if got != want {
		t.Fatalf("first 96 bytes differ between split and single read")
	}

	// But bytes 96-99 from split read come from a different SHAKE position
	// than bytes 96-99 from the single read (because split read consumed 104
	// total vs single read consumed 96 at that point). This is EXPECTED.
	// This test documents the behavior, not a bug.
}

func TestSeedExpanderRelease(t *testing.T) {
	seed := make([]byte, 40)
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
	// Anti-tamper: the seedexpander domain byte must be exactly 0x02.
	// If it were accidentally changed, ALL vectors would diverge silently.
	if seedExpanderDomain != 0x02 {
		t.Fatalf("seedExpanderDomain = 0x%02x, want 0x02", seedExpanderDomain)
	}
}

func TestSeedExpanderSupportRegression(t *testing.T) {
	// Regression: the first 4 bytes from seedexpander(zeros(40)) for HQC-128
	// fixed-weight must produce support[0] = 1686 after Barrett reduction.
	// This is the intermediate value BEFORE duplicate resolution.
	// support[0] = 0 + barrettReduce(raw_uint32, 0, params128)
	// where raw_uint32 comes from the first 4 squeezed bytes.
	p := params128
	seed := make([]byte, 40)
	se := newSeedExpander(seed)

	// Read 4 bytes (first support value's randomness).
	raw := make([]byte, 4)
	se.Read(raw)

	// Reconstruct support[0] the same way sampleFixedWeightVector does.
	rawU32 := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
	support0 := uint32(0) + barrettReduce(rawU32, 0, p)

	if support0 != 1686 {
		t.Fatalf("support[0] = %d, want 1686", support0)
	}
}
