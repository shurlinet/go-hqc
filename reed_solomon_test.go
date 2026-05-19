package hqc

import (
	"encoding/hex"
	"testing"
)

func TestRSEncodeConcreteVector(t *testing.T) {
	// Verify RS encode of msg=[0x42, 0, ..., 0] matches pre-computed reference.
	// RS encode uses the same GF(2^8) arithmetic in all HQC spec versions.
	for _, tc := range []struct {
		name   string
		p      *params
		wantCW string
		wantP0 uint8
	}{
		{"HQC-128", params128, "711aa6a466e61ca12517af170f070376364f8b208d07895ee31a6a9dd23142000000000000000000000000000000", 0x71},
		{"HQC-192", params192, "d5a9867e56cfb8820978f407b90b7f75627d7542c4279d44f955ba21781b2955420000000000000000000000000000000000000000000000", 0xd5},
		{"HQC-256", params256, "bee1be7bfdd98ef52b05db9e5f5dcab2a850379ebf77a707c8b5e7eb5d3faded736fe48623e715ba9fce2a5551b8e7e21e4d8e517b59a9fc048a4200000000000000000000000000000000000000000000000000000000000000", 0xbe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := make([]uint8, tc.p.k)
			msg[0] = 0x42

			cdw := make([]uint8, tc.p.n1)
			rsEncode(tc.p, cdw, msg)

			got := hex.EncodeToString(cdw)
			if got != tc.wantCW {
				t.Fatalf("RS encode codeword:\ngot:  %s\nwant: %s", got, tc.wantCW)
			}

			if cdw[0] != tc.wantP0 {
				t.Fatalf("parity[0] = 0x%02x, want 0x%02x", cdw[0], tc.wantP0)
			}
		})
	}
}

func TestRSRoundTrip(t *testing.T) {
	// Encode then decode with no errors. Must recover the original message.
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k)
		for i := range msg {
			msg[i] = uint8(i*37 + 13) // arbitrary non-zero pattern
		}

		cdw := make([]uint8, p.n1)
		rsEncode(p, cdw, msg)

		decoded := make([]uint8, p.k)
		rsDecode(p, decoded, cdw)

		for i := range msg {
			if decoded[i] != msg[i] {
				t.Fatalf("param_n=%d: RS round-trip byte %d: got 0x%02x, want 0x%02x",
					p.n, i, decoded[i], msg[i])
			}
		}
	}
}

func TestRSAlphaIjPowRecompute(t *testing.T) {
	// Anti-tamper: independently recompute alpha_ij_pow and verify against
	// the precomputed table in params.
	for _, p := range []*params{params128, params192, params256} {
		rows := int(2 * p.delta)
		cols := int(p.n1 - 1)

		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				expected := gfExp[((i+1)*(j+1))%paramGFMulOrd]
				got := p.alphaIjPow[i][j]
				if got != expected {
					t.Fatalf("param_n=%d: alphaIjPow[%d][%d] = %d, recomputed = %d",
						p.n, i, j, got, expected)
				}
			}
		}
	}

	// Cross-check against known reference values (breaks self-consistency).
	// HQC-128 row 0: alpha^(1*(j+1)) for j=0..4 = gfExp[1..5] = {2, 4, 8, 16, 32}.
	refRow0 := []uint16{2, 4, 8, 16, 32}
	for j, want := range refRow0 {
		if params128.alphaIjPow[0][j] != want {
			t.Fatalf("HQC-128 alphaIjPow[0][%d] = %d, reference = %d",
				j, params128.alphaIjPow[0][j], want)
		}
	}

	// HQC-128 row 14 (last for delta=15): period-17 sequence starting with alpha^15=38.
	if params128.alphaIjPow[14][0] != 38 {
		t.Fatalf("HQC-128 alphaIjPow[14][0] = %d, reference = 38",
			params128.alphaIjPow[14][0])
	}
	// Entry [14][16] = alpha^(15*17) = alpha^(255) = 1 (period hit).
	if params128.alphaIjPow[14][16] != 1 {
		t.Fatalf("HQC-128 alphaIjPow[14][16] = %d, want 1 (period 17)",
			params128.alphaIjPow[14][16])
	}
}

func TestRSPolyRootVerification(t *testing.T) {
	// Anti-tamper: the RS generator polynomial g(x) must have g(alpha^r) = 0
	// for r = 1, 2, ..., 2*delta.
	for _, p := range []*params{params128, params192, params256} {
		paramG := int(p.g)
		for r := 1; r <= int(2*p.delta); r++ {
			// Evaluate g(alpha^r).
			val := uint16(0)
			alphaR := gfExp[r]
			xpow := uint16(1)
			for i := 0; i < paramG; i++ {
				val ^= gfMul(uint16(p.rsPolyCoefs[i]), xpow)
				xpow = gfMul(xpow, alphaR)
			}
			if val != 0 {
				t.Fatalf("param_n=%d: g(alpha^%d) = %d, want 0", p.n, r, val)
			}
		}
	}
}

func TestRSDecodeWithErrors(t *testing.T) {
	// Introduce up to delta errors and verify RS decode corrects them.
	// Errors are placed in BOTH parity AND message positions to ensure
	// the error correction actually runs (not just extracting uncorrupted
	// systematic bytes).
	for _, p := range []*params{params128, params192, params256} {
		msg := make([]uint8, p.k)
		for i := range msg {
			msg[i] = uint8(i*37 + 13)
		}

		cdw := make([]uint8, p.n1)
		rsEncode(p, cdw, msg)

		// Save the clean codeword for comparison.
		cleanCdw := make([]uint8, p.n1)
		copy(cleanCdw, cdw)

		// Introduce delta errors spread across parity AND message positions.
		nErrors := int(p.delta)
		paramG := int(p.g)
		for e := 0; e < nErrors; e++ {
			// Alternate between parity region and message region.
			var pos int
			if e%2 == 0 {
				pos = e / 2 // parity positions: 0, 1, 2, ...
			} else {
				pos = paramG - 1 + e/2 // message positions: G-1, G, G+1, ...
			}
			if pos >= int(p.n1) {
				pos = e // fallback
			}
			cdw[pos] ^= uint8(e + 1)
		}

		decoded := make([]uint8, p.k)
		rsDecode(p, decoded, cdw)

		// Verify decoded message matches original.
		for i := range msg {
			if decoded[i] != msg[i] {
				t.Fatalf("param_n=%d: RS decode with %d errors, message byte %d: got 0x%02x, want 0x%02x",
					p.n, nErrors, i, decoded[i], msg[i])
			}
		}

		// Verify the corrected codeword matches the original clean codeword.
		// rsDecode modifies cdw in place via correctErrors. After correction,
		// cdw must equal the original error-free codeword byte-for-byte.
		for i := range cleanCdw {
			if cdw[i] != cleanCdw[i] {
				t.Fatalf("param_n=%d: corrected codeword byte %d: got 0x%02x, want 0x%02x",
					p.n, i, cdw[i], cleanCdw[i])
			}
		}
	}
}

func TestRSDecodeVaryingErrorCounts(t *testing.T) {
	// Test RS decode with 1, delta/2, and delta errors to exercise
	// the Forney mask at different deltaRealValue points.
	for _, p := range []*params{params128, params192, params256} {
		for _, nErr := range []int{1, int(p.delta) / 2, int(p.delta)} {
			msg := make([]uint8, p.k)
			for i := range msg {
				msg[i] = uint8(i*41 + 7)
			}

			cdw := make([]uint8, p.n1)
			rsEncode(p, cdw, msg)
			cleanCdw := make([]uint8, p.n1)
			copy(cleanCdw, cdw)

			// Place errors at spread-out positions across the codeword.
			for e := 0; e < nErr; e++ {
				pos := (e * int(p.n1)) / nErr
				cdw[pos] ^= uint8(e + 1)
			}

			decoded := make([]uint8, p.k)
			rsDecode(p, decoded, cdw)

			for i := range msg {
				if decoded[i] != msg[i] {
					t.Fatalf("param_n=%d nErr=%d: message byte %d: got 0x%02x, want 0x%02x",
						p.n, nErr, i, decoded[i], msg[i])
				}
			}
			for i := range cleanCdw {
				if cdw[i] != cleanCdw[i] {
					t.Fatalf("param_n=%d nErr=%d: codeword byte %d: got 0x%02x, want 0x%02x",
						p.n, nErr, i, cdw[i], cleanCdw[i])
				}
			}
		}
	}
}

func TestFFTDoesNotMutateSigma(t *testing.T) {
	// Verify that fft() does not modify the input sigma array.
	// This is critical because rsDecode calls computeRoots (which calls fft)
	// and then computeZPoly which reads sigma. If fft mutated sigma,
	// the z polynomial would be computed from corrupted coefficients.
	for _, p := range []*params{params128, params192, params256} {
		fSize := 1 << p.fft
		sigma := make([]uint16, fSize)
		sigma[0] = 1
		sigma[1] = 42
		sigma[2] = 137
		if int(p.delta) >= 3 {
			sigma[3] = 200
		}

		// Save a copy.
		sigmaBefore := make([]uint16, fSize)
		copy(sigmaBefore, sigma)

		// Run FFT (which internally calls radix on sigma).
		w := make([]uint16, 1<<paramM)
		fft(p, w, sigma, 4)

		// Verify sigma is unchanged.
		for i := range sigma {
			if sigma[i] != sigmaBefore[i] {
				t.Fatalf("param_n=%d: fft mutated sigma[%d]: got %d, was %d",
					p.n, i, sigma[i], sigmaBefore[i])
			}
		}
	}
}
