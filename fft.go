package hqc

// Additive FFT over GF(2^8) for Reed-Solomon root finding.
// Based on Gao-Mateer with Bernstein-Chou-Schwabe improvements.
// Additive FFT for Reed-Solomon decoding.

// computeFFTBetas computes the canonical basis for the additive FFT.
// betas[i] = 1 << (PARAM_M - 1 - i) for i in [0, PARAM_M-2].
func computeFFTBetas(betas []uint16) {
	for i := 0; i < paramM-1; i++ {
		betas[i] = 1 << (paramM - 1 - i)
	}
}

// computeSubsetSums builds the subset-sum table for a set of field elements.
// subsetSums[i] = XOR of elements whose indices correspond to set bits in i.
func computeSubsetSums(subsetSums []uint16, set []uint16, setSize uint16) {
	subsetSums[0] = 0
	for i := uint16(0); i < setSize; i++ {
		for j := uint16(0); j < (1 << i); j++ {
			subsetSums[(1<<i)+j] = set[i] ^ subsetSums[j]
		}
	}
}

// radix computes the radix decomposition f(x) = f0(x^2+x) + x*f1(x^2+x).
// Cases 1-4 are hardcoded; larger polynomials use radixBig.
func radix(f0, f1, f []uint16, mf uint32) {
	switch mf {
	case 4:
		f0[4] = f[8] ^ f[12]
		f0[6] = f[12] ^ f[14]
		f0[7] = f[14] ^ f[15]
		f1[5] = f[11] ^ f[13]
		f1[6] = f[13] ^ f[14]
		f1[7] = f[15]
		f0[5] = f[10] ^ f[12] ^ f1[5]
		f1[4] = f[9] ^ f[13] ^ f0[5]

		f0[0] = f[0]
		f1[3] = f[7] ^ f[11] ^ f[15]
		f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3]
		f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3]
		f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3]
		f1[2] = f[3] ^ f1[1] ^ f0[3]
		f0[1] = f[2] ^ f0[2] ^ f1[1]
		f1[0] = f[1] ^ f0[1]

	case 3:
		f0[0] = f[0]
		f0[2] = f[4] ^ f[6]
		f0[3] = f[6] ^ f[7]
		f1[1] = f[3] ^ f[5] ^ f[7]
		f1[2] = f[5] ^ f[6]
		f1[3] = f[7]
		f0[1] = f[2] ^ f0[2] ^ f1[1]
		f1[0] = f[1] ^ f0[1]

	case 2:
		f0[0] = f[0]
		f0[1] = f[2] ^ f[3]
		f1[0] = f[1] ^ f0[1]
		f1[1] = f[3]

	case 1:
		f0[0] = f[0]
		f1[0] = f[1]

	default:
		radixBig(f0, f1, f, mf)
	}
}

// radixBig handles the general radix decomposition for m_f > 4.
// Only called for HQC-192/256 where PARAM_FFT = 5.
func radixBig(f0, f1, f []uint16, mf uint32) {
	n := 1 << (mf - 2) // element count, NOT byte count

	Q := make([]uint16, 2*n+1)
	R := make([]uint16, 2*n+1)
	Q0 := make([]uint16, n)
	Q1 := make([]uint16, n)
	R0 := make([]uint16, n)
	R1 := make([]uint16, n)

	// C memcpy operates on BYTES. f is uint16*, so pointer arithmetic
	// uses element offsets. "2*n bytes" = n uint16 elements.
	copy(Q[:n], f[3*n:4*n])   // Q[0..n-1] = f[3n..4n-1]
	copy(Q[n:2*n], f[3*n:4*n]) // Q[n..2n-1] = f[3n..4n-1] (duplicate)
	copy(R[:2*n], f[:2*n])     // R[0..2n-1] = f[0..2n-1]

	for i := 0; i < n; i++ {
		Q[i] ^= f[2*n+i]
		R[n+i] ^= Q[i]
	}

	radix(Q0, Q1, Q, mf-1)
	radix(R0, R1, R, mf-1)

	copy(f0[:n], R0[:n])
	copy(f0[n:2*n], Q0[:n])
	copy(f1[:n], R1[:n])
	copy(f1[n:2*n], Q1[:n])
}

// fftRec recursively evaluates f at all subset sums of betas.
// w receives the evaluations, f is modified in place (twisted at each level).
func fftRec(p *params, w, f []uint16, fCoeffs int, m uint8, mf uint32, betas []uint16) {
	// Base case: f is linear (degree <= 1).
	if mf == 1 {
		tmp := make([]uint16, m)
		defer ZeroUint16s(tmp)
		for i := 0; i < int(m); i++ {
			tmp[i] = gfMul(betas[i], f[1])
		}

		w[0] = f[0]
		x := 1
		for j := 0; j < int(m); j++ {
			for k := 0; k < x; k++ {
				w[x+k] = w[k] ^ tmp[j]
			}
			x <<= 1
		}
		return
	}

	halfFFT := 1 << (p.fft - 2) // max size for f0, f1 local arrays

	// Step 2: twist f by powers of beta_m.
	if betas[m-1] != 1 {
		betaMPow := uint16(1)
		x := 1 << mf
		for i := 1; i < x; i++ {
			betaMPow = gfMul(betaMPow, betas[m-1])
			f[i] = gfMul(betaMPow, f[i])
		}
	}

	// Step 3: radix decomposition.
	f0 := make([]uint16, halfFFT)
	f1 := make([]uint16, halfFFT)

	// Step 4: compute gammas and deltas.
	gammas := make([]uint16, paramM-2)
	deltas := make([]uint16, paramM-2)

	// Compute gamma subset sums.
	gammasSums := make([]uint16, 1<<(paramM-2))

	// Step 5: recurse on f0.
	u := make([]uint16, 1<<(paramM-2))

	// Zero all sigma-derived intermediates on exit.
	defer func() {
		ZeroUint16s(f0)
		ZeroUint16s(f1)
		ZeroUint16s(u)
	}()

	radix(f0, f1, f, mf)

	for i := 0; i+1 < int(m); i++ {
		gammas[i] = gfMul(betas[i], gfInverse(betas[m-1]))
		deltas[i] = gfSquare(gammas[i]) ^ gammas[i]
	}

	computeSubsetSums(gammasSums, gammas, uint16(m-1))

	fftRec(p, u, f0, (fCoeffs+1)/2, m-1, mf-1, deltas)

	k := 1 << ((m - 1) & 0xf) // & 0xf is a compiler hint, not computation

	if fCoeffs <= 3 {
		// f1 is constant: skip recursion.
		w[0] = u[0]
		w[k] = u[0] ^ f1[0]
		for i := 1; i < k; i++ {
			w[i] = u[i] ^ gfMul(gammasSums[i], f1[0])
			w[k+i] = w[i] ^ f1[0]
		}
	} else {
		// Step 5b: recurse on f1.
		v := make([]uint16, 1<<(paramM-2))
		defer ZeroUint16s(v)
		fftRec(p, v, f1, fCoeffs/2, m-1, mf-1, deltas)

		// Step 6: recombine.
		copy(w[k:2*k], v[:k])
		w[0] = u[0]
		w[k] ^= u[0]
		for i := 1; i < k; i++ {
			w[i] = u[i] ^ gfMul(gammasSums[i], v[i])
			w[k+i] ^= w[i]
		}
	}
}

// fft evaluates polynomial f at all 2^PARAM_M field elements using the additive FFT.
// f has fCoeffs coefficients (degree = fCoeffs - 1).
// w receives 2^PARAM_M = 256 evaluations.
func fft(p *params, w []uint16, f []uint16, fCoeffs int) {
	betas := make([]uint16, paramM-1)
	betasSums := make([]uint16, 1<<(paramM-1))
	halfFFT := 1 << (p.fft - 1)
	f0 := make([]uint16, halfFFT)
	f1 := make([]uint16, halfFFT)
	deltas := make([]uint16, paramM-1)
	u := make([]uint16, 1<<(paramM-1))
	v := make([]uint16, 1<<(paramM-1))

	// f0, f1, u, v contain sigma-derived data (secret-adjacent).
	defer func() {
		ZeroUint16s(f0)
		ZeroUint16s(f1)
		ZeroUint16s(u)
		ZeroUint16s(v)
	}()

	computeFFTBetas(betas)

	// At top level, gammas == betas (beta_m = 1, no twist needed).
	computeSubsetSums(betasSums, betas, paramM-1)

	// Step 2: beta_m = 1 at top level, no twist.

	// Step 3: radix decomposition.
	radix(f0, f1, f, uint32(p.fft))

	// Step 4: compute deltas (gammas = betas at top level).
	for i := 0; i < paramM-1; i++ {
		deltas[i] = gfSquare(betas[i]) ^ betas[i]
	}

	// Step 5: recurse.
	fftRec(p, u, f0, (fCoeffs+1)/2, paramM-1, uint32(p.fft-1), deltas)
	fftRec(p, v, f1, fCoeffs/2, paramM-1, uint32(p.fft-1), deltas)

	k := 1 << (paramM - 1) // 128

	// Step 6: recombine.
	copy(w[k:2*k], v[:k])
	w[0] = u[0]
	w[k] ^= u[0]
	for i := 1; i < k; i++ {
		w[i] = u[i] ^ gfMul(betasSums[i], v[i])
		w[k+i] ^= w[i]
	}
}

// fftRetrieveErrorPoly converts FFT evaluations to the error polynomial.
// For each evaluation point where sigma(x) = 0 (root), the corresponding
// error position is set to 1.
func fftRetrieveErrorPoly(p *params, errorPoly []uint8, w []uint16) {
	gammas := make([]uint16, paramM-1)
	gammasSums := make([]uint16, 1<<(paramM-1))

	computeFFTBetas(gammas)
	computeSubsetSums(gammasSums, gammas, paramM-1)

	k := uint16(1 << (paramM - 1)) // 128

	// Check if 0 is a root (w[0] == 0).
	// (uint16(0) - w[0]) >> 15 is 0 when w[0]==0 (making 1^0 = 1), 1 otherwise (1^1 = 0).
	errorPoly[0] ^= 1 ^ uint8((uint16(0)-w[0])>>15)

	// Check if 1 is a root (w[k] == 0).
	errorPoly[0] ^= 1 ^ uint8((uint16(0)-w[k])>>15)

	for i := uint16(1); i < k; i++ {
		// Map subset-sum index to field element position via gf_log.
		index := paramGFMulOrd - gfLog[gammasSums[i]]
		errorPoly[index] ^= 1 ^ uint8((uint16(0)-w[i])>>15)

		index = paramGFMulOrd - gfLog[gammasSums[i]^1]
		errorPoly[index] ^= 1 ^ uint8((uint16(0)-w[k+i])>>15)
	}
}
