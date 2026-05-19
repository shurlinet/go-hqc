package hqc

import (
	"math/bits"
	"testing"
)

func TestRMRoundTripAllBytes(t *testing.T) {
	// Encode then decode every byte value (0x00-0xFF) with no noise.
	// Must round-trip perfectly for all three param sets.
	for _, p := range []*params{params128, params192, params256} {
		cdw := make([]uint64, p.vecN1N2Size64)
		var decoded [1]uint8

		for b := 0; b < 256; b++ {
			msg := []uint8{uint8(b)}

			// Zero the codeword.
			for i := range cdw {
				cdw[i] = 0
			}

			// Encode just this one byte into the first slot.
			mult := int(p.multiplicity)
			rmEncodeWord(cdw[:2], msg[0])
			for c := 1; c < mult; c++ {
				cdw[2*c] = cdw[0]
				cdw[2*c+1] = cdw[1]
			}

			// Decode.
			var expanded [128]uint16
			var transform [128]uint16
			expandAndSum(expanded[:], cdw, mult)
			hadamard(expanded[:], transform[:])
			transform[0] -= 64 * uint16(mult)
			decoded[0] = findPeaks(transform[:])

			if decoded[0] != uint8(b) {
				t.Fatalf("param_n=%d: RM round-trip failed for byte 0x%02x, got 0x%02x",
					p.n, b, decoded[0])
			}
		}
	}
}

func TestRMConcreteVector(t *testing.T) {
	// Verify RM encode of byte 0x71 (= 113) matches pre-computed reference.
	// RM(1,7) encoding is spec-version-independent (pure combinatorics).
	// We verify that the first 128-bit codeword (2 uint64s) matches the expected
	// pattern, and that all MULTIPLICITY copies are identical.
	for _, tc := range []struct {
		name string
		p    *params
	}{
		{"HQC-128", params128},
		{"HQC-192", params192},
		{"HQC-256", params256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mult := int(tc.p.multiplicity)
			cdw := make([]uint64, 2*mult)
			rmEncodeWord(cdw[:2], 0x71)
			for c := 1; c < mult; c++ {
				cdw[2*c] = cdw[0]
				cdw[2*c+1] = cdw[1]
			}

			// The first 128-bit codeword for 0x71 must be:
			// 0x5555aaaa5555aaaa (LE) and 0x5555aaaaaaaa5555 (LE).
			// Pre-computed: "aaaa55555555aaaa5555aaaaaaaa5555"
			// which in LE uint64 is 0xaaaa55555555aaaa and 0x5555aaaaaaaa5555.
			wantW0 := uint64(0xaaaa55555555aaaa)
			wantW1 := uint64(0x5555aaaaaaaa5555)

			if cdw[0] != wantW0 {
				t.Fatalf("cword[0] = %016x, want %016x", cdw[0], wantW0)
			}
			if cdw[1] != wantW1 {
				t.Fatalf("cword[1] = %016x, want %016x", cdw[1], wantW1)
			}

			// All copies must be identical.
			for c := 1; c < mult; c++ {
				if cdw[2*c] != cdw[0] || cdw[2*c+1] != cdw[1] {
					t.Fatalf("copy %d differs from original", c)
				}
			}
		})
	}
}

func TestRMBitCountAntiTamper(t *testing.T) {
	// RM(1,7) codeword weights per 128-bit block:
	// - byte 0x00: weight 0 (all zeros)
	// - byte 0x80: weight 128 (all ones, the repetition codeword)
	// - all other bytes: weight 64 (balanced, minimum distance property)
	// With MULTIPLICITY copies, total weight scales linearly.
	for _, p := range []*params{params128, params192, params256} {
		mult := int(p.multiplicity)
		cdw := make([]uint64, 2*mult)

		for b := 0; b < 256; b++ {
			rmEncodeWord(cdw[:2], uint8(b))
			for c := 1; c < mult; c++ {
				cdw[2*c] = cdw[0]
				cdw[2*c+1] = cdw[1]
			}

			weight := 0
			for _, w := range cdw {
				weight += bits.OnesCount64(w)
			}

			var want int
			switch {
			case b == 0:
				want = 0
			case b == 0x80:
				want = 128 * mult
			default:
				want = 64 * mult
			}

			if weight != want {
				t.Fatalf("param_n=%d byte=0x%02x: RM codeword weight=%d, want %d",
					p.n, b, weight, want)
			}
		}
	}
}

func TestRMEncodeZero(t *testing.T) {
	// Encoding 0x00 produces the all-zeros codeword.
	var cdw [2]uint64
	rmEncodeWord(cdw[:], 0x00)
	if cdw[0] != 0 || cdw[1] != 0 {
		t.Fatalf("RM encode 0x00: [%016x, %016x], want [0, 0]", cdw[0], cdw[1])
	}
}
