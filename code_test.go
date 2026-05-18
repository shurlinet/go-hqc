package hqc

import "testing"

func TestCodeRoundTrip(t *testing.T) {
	// Verify codeEncode -> codeDecode recovers the original message
	// for all three param sets.
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k)
		for i := range msg {
			msg[i] = uint8(i*53 + 7)
		}

		em := make([]uint64, p.vecN1N2Size64)
		codeEncode(p, em, msg)

		decoded := make([]uint8, p.k)
		codeDecode(p, decoded, em)

		for i := range msg {
			if decoded[i] != msg[i] {
				t.Fatalf("param_n=%d: code round-trip byte %d: got 0x%02x, want 0x%02x",
					p.n, i, decoded[i], msg[i])
			}
		}
	}
}

func TestCodeRoundTripZeroMessage(t *testing.T) {
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k) // all zeros

		em := make([]uint64, p.vecN1N2Size64)
		codeEncode(p, em, msg)

		decoded := make([]uint8, p.k)
		codeDecode(p, decoded, em)

		for i := range msg {
			if decoded[i] != 0 {
				t.Fatalf("param_n=%d: zero message round-trip byte %d: got 0x%02x, want 0x00",
					p.n, i, decoded[i])
			}
		}
	}
}

func TestCodeRoundTripAllOnes(t *testing.T) {
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k)
		for i := range msg {
			msg[i] = 0xFF
		}

		em := make([]uint64, p.vecN1N2Size64)
		codeEncode(p, em, msg)

		decoded := make([]uint8, p.k)
		codeDecode(p, decoded, em)

		for i := range msg {
			if decoded[i] != 0xFF {
				t.Fatalf("param_n=%d: all-ones message round-trip byte %d: got 0x%02x, want 0xFF",
					p.n, i, decoded[i])
			}
		}
	}
}

func TestCodeEncodeDecodeIdempotent(t *testing.T) {
	// Verify that encoding the same message twice produces identical codewords,
	// and that two independent decodes of the same codeword produce the same message.
	// Catches any uninitialized memory or nondeterminism.
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k)
		msg[0] = 0x42
		msg[int(p.k)-1] = 0xFF

		em1 := make([]uint64, p.vecN1N2Size64)
		em2 := make([]uint64, p.vecN1N2Size64)
		codeEncode(p, em1, msg)
		codeEncode(p, em2, msg)

		for i := range em1 {
			if em1[i] != em2[i] {
				t.Fatalf("param_n=%d: codeEncode not deterministic at word %d", p.n, i)
			}
		}

		dec1 := make([]uint8, p.k)
		dec2 := make([]uint8, p.k)
		codeDecode(p, dec1, em1)
		codeDecode(p, dec2, em1)

		for i := range dec1 {
			if dec1[i] != dec2[i] {
				t.Fatalf("param_n=%d: codeDecode not deterministic at byte %d", p.n, i)
			}
			if dec1[i] != msg[i] {
				t.Fatalf("param_n=%d: codeDecode byte %d: got 0x%02x, want 0x%02x",
					p.n, i, dec1[i], msg[i])
			}
		}
	}
}

func TestCodeRoundTripSingleByte(t *testing.T) {
	// Test every possible single-byte message (all other bytes zero).
	// This exercises the RS encoder with minimal non-zero input and the
	// RM encoder with every possible byte value in a full encode chain.
	for _, p := range []*params{params128, params192, params256} {
		for b := 0; b < 256; b++ {
			msg := make([]uint8, p.k)
			msg[0] = uint8(b)

			em := make([]uint64, p.vecN1N2Size64)
			codeEncode(p, em, msg)

			decoded := make([]uint8, p.k)
			codeDecode(p, decoded, em)

			for i := range msg {
				if decoded[i] != msg[i] {
					t.Fatalf("param_n=%d byte=0x%02x: code round-trip pos %d: got 0x%02x, want 0x%02x",
						p.n, b, i, decoded[i], msg[i])
				}
			}
		}
	}
}
