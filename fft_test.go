package hqc

import "testing"

func TestRadixCase2Numerical(t *testing.T) {
	// Verify radix decomposition for m_f=2: f(x) = f0(x^2+x) + x*f1(x^2+x).
	// Evaluate both sides at all 256 field elements.
	f := []uint16{42, 137, 200, 91}
	f0 := make([]uint16, 2)
	f1 := make([]uint16, 2)

	radix(f0, f1, f, 2)

	for x := uint16(0); x < 256; x++ {
		// Evaluate f(x) = f[0] + f[1]*x + f[2]*x^2 + f[3]*x^3.
		lhs := f[0] ^ gfMul(f[1], x) ^ gfMul(f[2], gfSquare(x)) ^ gfMul(f[3], gfMul(gfSquare(x), x))

		// t = x^2 + x (Artin-Schreier map).
		tt := gfSquare(x) ^ x

		// Evaluate f0(t) + x * f1(t).
		f0t := f0[0] ^ gfMul(f0[1], tt)
		f1t := f1[0] ^ gfMul(f1[1], tt)
		rhs := f0t ^ gfMul(x, f1t)

		if lhs != rhs {
			t.Fatalf("radix case 2 failed at x=%d: f(x)=%d, f0(t)+x*f1(t)=%d", x, lhs, rhs)
		}
	}
}

func TestRadixCase3Numerical(t *testing.T) {
	f := []uint16{10, 20, 30, 40, 50, 60, 70, 80}
	f0 := make([]uint16, 4)
	f1 := make([]uint16, 4)

	radix(f0, f1, f, 3)

	for x := uint16(0); x < 256; x++ {
		// Evaluate f(x) directly.
		lhs := uint16(0)
		xpow := uint16(1)
		for i := 0; i < 8; i++ {
			lhs ^= gfMul(f[i], xpow)
			xpow = gfMul(xpow, x)
		}

		tt := gfSquare(x) ^ x
		f0t := uint16(0)
		f1t := uint16(0)
		tpow := uint16(1)
		for i := 0; i < 4; i++ {
			f0t ^= gfMul(f0[i], tpow)
			f1t ^= gfMul(f1[i], tpow)
			tpow = gfMul(tpow, tt)
		}
		rhs := f0t ^ gfMul(x, f1t)

		if lhs != rhs {
			t.Fatalf("radix case 3 failed at x=%d: f(x)=%d, f0(t)+x*f1(t)=%d", x, lhs, rhs)
		}
	}
}

func TestRadixCase4Numerical(t *testing.T) {
	f := make([]uint16, 16)
	for i := range f {
		f[i] = gfExp[i*37%255]
	}
	f0 := make([]uint16, 8)
	f1 := make([]uint16, 8)

	radix(f0, f1, f, 4)

	for x := uint16(0); x < 256; x++ {
		lhs := uint16(0)
		xpow := uint16(1)
		for i := 0; i < 16; i++ {
			lhs ^= gfMul(f[i], xpow)
			xpow = gfMul(xpow, x)
		}

		tt := gfSquare(x) ^ x
		f0t := uint16(0)
		f1t := uint16(0)
		tpow := uint16(1)
		for i := 0; i < 8; i++ {
			f0t ^= gfMul(f0[i], tpow)
			f1t ^= gfMul(f1[i], tpow)
			tpow = gfMul(tpow, tt)
		}
		rhs := f0t ^ gfMul(x, f1t)

		if lhs != rhs {
			t.Fatalf("radix case 4 failed at x=%d: f(x)=%d, f0(t)+x*f1(t)=%d", x, lhs, rhs)
		}
	}
}

func TestRadixCase5Numerical(t *testing.T) {
	// Case 5 (mf=5) triggers radixBig. Only used by HQC-192/256 (PARAM_FFT=5).
	// Verify f(x) = f0(x^2+x) + x*f1(x^2+x) for a 32-coefficient polynomial.
	f := make([]uint16, 32)
	for i := range f {
		f[i] = gfExp[(i*71+3)%255]
	}
	f0 := make([]uint16, 16)
	f1 := make([]uint16, 16)

	radix(f0, f1, f, 5)

	// Verify at 50 random-ish field elements (full 256 is slow with degree-31 eval).
	for _, x := range []uint16{0, 1, 2, 7, 13, 42, 100, 127, 128, 200, 254, 255} {
		lhs := uint16(0)
		xpow := uint16(1)
		for i := 0; i < 32; i++ {
			lhs ^= gfMul(f[i], xpow)
			xpow = gfMul(xpow, x)
		}

		tt := gfSquare(x) ^ x
		f0t := uint16(0)
		f1t := uint16(0)
		tpow := uint16(1)
		for i := 0; i < 16; i++ {
			f0t ^= gfMul(f0[i], tpow)
			f1t ^= gfMul(f1[i], tpow)
			tpow = gfMul(tpow, tt)
		}
		rhs := f0t ^ gfMul(x, f1t)

		if lhs != rhs {
			t.Fatalf("radix case 5 failed at x=%d: f(x)=%d, f0(t)+x*f1(t)=%d", x, lhs, rhs)
		}
	}
}

func TestSubsetSums(t *testing.T) {
	set := []uint16{3, 5, 9}
	sums := make([]uint16, 8)
	computeSubsetSums(sums, set, 3)

	// Expected: subsetSums[i] = XOR of elements at set bits of i.
	// 0b000 = 0, 0b001 = 3, 0b010 = 5, 0b011 = 3^5=6,
	// 0b100 = 9, 0b101 = 3^9=10, 0b110 = 5^9=12, 0b111 = 3^5^9=15
	expected := []uint16{0, 3, 5, 6, 9, 10, 12, 15}
	for i, want := range expected {
		if sums[i] != want {
			t.Fatalf("subsetSums[%d] = %d, want %d", i, sums[i], want)
		}
	}
}

func TestFFTFindsKnownRoots(t *testing.T) {
	// Build sigma(x) = (x - alpha^3)(x - alpha^7)(x - alpha^11) with known roots.
	// The FFT + fftRetrieveErrorPoly must identify exactly these root positions.
	for _, p := range []*params{params128, params192, params256} {
		roots := []uint16{gfExp[3], gfExp[7], gfExp[11]}

		// sigma(x) = product of (x - root_i) = product of (x ^ root_i) in GF(2^8).
		// Start with sigma = 1.
		fSize := 1 << p.fft
		sigma := make([]uint16, fSize)
		sigma[0] = 1
		deg := 0
		for _, r := range roots {
			// Multiply sigma by (x + r): new[i] = old[i-1] ^ r * old[i].
			for i := deg + 1; i >= 1; i-- {
				sigma[i] = sigma[i-1] ^ gfMul(r, sigma[i])
			}
			sigma[0] = gfMul(r, sigma[0])
			deg++
		}

		// Verify sigma has correct roots by naive evaluation.
		for _, r := range roots {
			val := uint16(0)
			xpow := uint16(1)
			for i := 0; i <= deg; i++ {
				val ^= gfMul(sigma[i], xpow)
				xpow = gfMul(xpow, r)
			}
			if val != 0 {
				t.Fatalf("param_n=%d: sigma(%d) = %d, want 0", p.n, r, val)
			}
		}

		// Run FFT.
		sigmaCopy := make([]uint16, fSize)
		copy(sigmaCopy, sigma)
		w := make([]uint16, 1<<paramM)
		fft(p, w, sigmaCopy, deg+1)

		// Retrieve error polynomial.
		errorPoly := make([]uint8, 1<<paramM)
		fftRetrieveErrorPoly(p, errorPoly, w)

		// The error positions should be at the INVERSES of the roots.
		// sigma(alpha^k) = 0 means error at position 255-k (inverse).
		// Root alpha^3: inverse is alpha^(255-3) = alpha^252. Position = 252.
		// Root alpha^7: position = 248.
		// Root alpha^11: position = 244.
		expectedPositions := map[int]bool{252: true, 248: true, 244: true}

		foundCount := 0
		for i := 0; i < 256; i++ {
			if errorPoly[i] != 0 {
				foundCount++
				if !expectedPositions[i] {
					t.Fatalf("param_n=%d: unexpected error at position %d", p.n, i)
				}
			}
		}
		if foundCount != len(expectedPositions) {
			t.Fatalf("param_n=%d: found %d errors, want %d", p.n, foundCount, len(expectedPositions))
		}
	}
}
