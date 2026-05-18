package hqc

// Reed-Solomon encoding and decoding over GF(2^8).
// Constant-time Berlekamp algorithm for error-locator polynomial.
// Reed-Solomon encoding and decoding over GF(2^8).

// rsEncode performs systematic RS encoding using an LFSR shift register.
// Message bytes go into high positions, parity into low positions.
func rsEncode(p *params, cdw []uint8, msg []uint8) {
	paramK := int(p.k)
	paramN1 := int(p.n1)
	paramG := int(p.g)

	// Zero the codeword.
	for i := 0; i < paramN1; i++ {
		cdw[i] = 0
	}

	tmp := make([]uint16, paramG)
	defer ZeroUint16s(tmp)

	for i := 0; i < paramK; i++ {
		// Message processed in reverse order (high-degree terms first).
		gateValue := msg[paramK-1-i] ^ cdw[paramN1-paramK-1]

		for j := 0; j < paramG; j++ {
			tmp[j] = gfMul(uint16(gateValue), uint16(p.rsPolyCoefs[j]))
		}

		// Shift the register.
		for k := paramN1 - paramK - 1; k > 0; k-- {
			cdw[k] = cdw[k-1] ^ uint8(tmp[k])
		}
		cdw[0] = uint8(tmp[0])
	}

	// Copy message into systematic positions.
	copy(cdw[paramN1-paramK:paramN1], msg[:paramK])
}

// computeSyndromes computes 2*delta syndromes from the received codeword.
// syndromes[i] = sum_{j=0}^{N1-1} cdw[j] * alpha^((i+1)*j).
// cdw[0] is handled separately (multiplied by alpha^0 = 1).
func computeSyndromes(p *params, syndromes []uint16, cdw []uint8) {
	paramN1 := int(p.n1)
	nSynd := int(2 * p.delta)

	for i := 0; i < nSynd; i++ {
		for j := 1; j < paramN1; j++ {
			syndromes[i] ^= gfMul(uint16(cdw[j]), p.alphaIjPow[i][j-1])
		}
		syndromes[i] ^= uint16(cdw[0])
	}
}

// computeElp computes the error-locator polynomial sigma using Berlekamp's
// constant-time algorithm. Returns the degree of sigma.
func computeElp(p *params, sigma []uint16, syndromes []uint16) uint16 {
	paramDelta := int(p.delta)

	degSigma := uint16(0)
	degSigmaP := uint16(0)
	degSigmaCopy := uint16(0)
	sigmaCopy := make([]uint16, paramDelta+1)
	xSigmaP := make([]uint16, paramDelta+1)
	defer func() {
		ZeroUint16s(sigmaCopy)
		ZeroUint16s(xSigmaP)
	}()
	xSigmaP[1] = 1
	pp := uint16(0xFFFF)   // 2*rho, initialized to (uint16)-1
	dP := uint16(1)
	d := syndromes[0]

	sigma[0] = 1

	for mu := uint16(0); mu < 2*uint16(paramDelta); mu++ {
		// Save sigma in case we need to update X_sigma_p.
		copy(sigmaCopy[:paramDelta], sigma[:paramDelta])
		degSigmaCopy = degSigma

		dd := gfMul(d, gfInverse(dP))

		limit := int(mu + 1)
		if limit > paramDelta {
			limit = paramDelta
		}
		for i := 1; i <= limit; i++ {
			sigma[i] ^= gfMul(dd, xSigmaP[i])
		}

		degX := mu - pp
		degXSigmaP := degX + degSigmaP

		// mask1 = 0xFFFF if d != 0, else 0.
		// C: -((uint16_t) - d >> 15). Precedence: cast(-d) then >>15 then negate.
		mask1 := uint16(0) - ((uint16(0) - d) >> 15)

		// mask2 = 0xFFFF if degXSigmaP > degSigma, else 0.
		mask2 := uint16(0) - ((degSigma - degXSigmaP) >> 15)

		mask12 := mask1 & mask2
		degSigma ^= mask12 & (degXSigmaP ^ degSigma)

		if mu == 2*uint16(paramDelta)-1 {
			break
		}

		pp ^= mask12 & (mu ^ pp)
		dP ^= mask12 & (d ^ dP)

		for i := paramDelta; i >= 1; i-- {
			xSigmaP[i] = (mask12 & sigmaCopy[i-1]) ^ (^mask12 & xSigmaP[i-1])
		}

		degSigmaP ^= mask12 & (degSigmaCopy ^ degSigmaP)
		d = syndromes[mu+1]

		limit = int(mu + 1)
		if limit > paramDelta {
			limit = paramDelta
		}
		for i := 1; i <= limit; i++ {
			d ^= gfMul(sigma[i], syndromes[mu+1-uint16(i)])
		}
	}

	return degSigma
}

// computeRoots finds the roots of sigma using the additive FFT.
// errorPoly[i] = 1 if alpha^i is a root of sigma (error at position i).
func computeRoots(p *params, errorPoly []uint8, sigma []uint16) {
	w := make([]uint16, 1<<paramM)
	fft(p, w, sigma, int(p.delta)+1)
	fftRetrieveErrorPoly(p, errorPoly, w)
}

// computeZPoly computes the polynomial z(x) = sigma(x) * S(x) mod x^(delta+1).
// Used in the Forney formula for error values.
func computeZPoly(p *params, z []uint16, sigma []uint16, degree uint16, syndromes []uint16) {
	paramDelta := int(p.delta)

	z[0] = 1

	for i := 1; i < paramDelta+1; i++ {
		// mask: 0xFFFF if i <= degree, 0 otherwise.
		// (i - degree - 1) >> 15: when i <= degree, i-degree-1 is negative
		// in signed interpretation, so bit 15 is set.
		mask := uint16(0) - (uint16(i-int(degree)-1) >> 15)
		z[i] = mask & sigma[i]
	}

	z[1] ^= syndromes[0]

	for i := 2; i <= paramDelta; i++ {
		mask := uint16(0) - (uint16(i-int(degree)-1) >> 15)
		z[i] ^= mask & syndromes[i-1]

		for j := 1; j < i; j++ {
			z[i] ^= mask & gfMul(sigma[j], syndromes[i-j-1])
		}
	}
}

// ctNonZeroMask returns 0xFFFF if x != 0, 0 otherwise (constant-time).
// Matches the C reference (uint16_t)(-((int32_t)x) >> 31) which sign-extends
// the negation's MSB into a full mask via arithmetic right shift.
func ctNonZeroMask(x uint8) uint16 {
	v := int32(x)
	return uint16((-v) >> 31)
}

// ctEqualMask returns 0xFFFF if a == b, 0 otherwise (constant-time).
// Matches the C reference ~((uint16_t)(-((int32_t)j ^ delta_counter) >> 31)).
func ctEqualMask(a, b uint16) uint16 {
	cmp := a ^ b
	// (0 - cmp | cmp) >> 15 is 1 if cmp != 0, 0 if cmp == 0.
	// Negate to get 0xFFFF for equal, 0 for different.
	return ^(uint16(0) - (((uint16(0) - cmp) | cmp) >> 15))
}

// computeErrorValues computes the error magnitudes at error positions
// using the Forney-like formula. Fully constant-time.
func computeErrorValues(p *params, errorValues []uint16, z []uint16, errorPoly []uint8) {
	paramDelta := int(p.delta)
	paramN1 := int(p.n1)

	betaJ := make([]uint16, paramDelta)
	eJ := make([]uint16, paramDelta)
	defer func() {
		ZeroUint16s(betaJ)
		ZeroUint16s(eJ)
	}()

	// Compute beta_{j_i}: the field elements at error positions.
	deltaCounter := uint16(0)
	for i := 0; i < paramN1; i++ {
		found := uint16(0)
		mask1 := ctNonZeroMask(errorPoly[i])

		for j := 0; j < paramDelta; j++ {
			mask2 := ctEqualMask(uint16(j), deltaCounter)
			betaJ[j] += mask1 & mask2 & gfExp[i]
			found += mask1 & mask2 & 1
		}
		deltaCounter += found
	}
	deltaRealValue := deltaCounter

	// Compute e_{j_i}: the error values via Forney formula.
	for i := 0; i < paramDelta; i++ {
		tmp1 := uint16(1)
		tmp2 := uint16(1)
		inverse := gfInverse(betaJ[i])
		inversePowerJ := uint16(1)

		for j := 1; j <= paramDelta; j++ {
			inversePowerJ = gfMul(inversePowerJ, inverse)
			tmp1 ^= gfMul(inversePowerJ, z[j])
		}
		for k := 1; k < paramDelta; k++ {
			tmp2 = gfMul(tmp2, 1^gfMul(inverse, betaJ[(i+k)%paramDelta]))
		}

		// mask1 = 0xFFFF if i < deltaRealValue (signed arithmetic right shift).
		// Go's >> on int16 is arithmetic (sign-extending), matching C exactly.
		mask1 := uint16((int16(i) - int16(deltaRealValue)) >> 15)
		eJ[i] = mask1 & gfMul(tmp1, gfInverse(tmp2))
	}

	// Place error values at the correct positions.
	deltaCounter = 0
	for i := 0; i < paramN1; i++ {
		found := uint16(0)
		mask1 := ctNonZeroMask(errorPoly[i])

		for j := 0; j < paramDelta; j++ {
			mask2 := ctEqualMask(uint16(j), deltaCounter)
			errorValues[i] += mask1 & mask2 & eJ[j]
			found += mask1 & mask2 & 1
		}
		deltaCounter += found
	}
}

// correctErrors XORs error values into the codeword to correct errors.
// errorValues[i] is uint16 but always <= 255 (GF(2^8) element).
func correctErrors(p *params, cdw []uint8, errorValues []uint16) {
	for i := 0; i < int(p.n1); i++ {
		cdw[i] ^= uint8(errorValues[i])
	}
}

// rsDecode decodes a received RS codeword using the 6-step procedure:
// 1. Compute syndromes
// 2. Compute error-locator polynomial (Berlekamp)
// 3. Find roots (additive FFT)
// 4. Compute z polynomial
// 5. Compute error values (Forney)
// 6. Correct errors
// Then extract the message from the corrected systematic codeword.
func rsDecode(p *params, msg []uint8, cdw []uint8) {
	paramDelta := int(p.delta)
	paramN1 := int(p.n1)

	syndromes := make([]uint16, 2*paramDelta)
	sigma := make([]uint16, 1<<p.fft)
	errorPoly := make([]uint8, 1<<paramM)
	z := make([]uint16, paramN1)
	errorValues := make([]uint16, paramN1)

	// Zero all intermediate buffers on exit. These contain data derived
	// from the secret key's interaction with the ciphertext (noise pattern).
	defer func() {
		ZeroUint16s(syndromes)
		ZeroUint16s(sigma)
		ZeroBytes(errorPoly)
		ZeroUint16s(z)
		ZeroUint16s(errorValues)
	}()

	computeSyndromes(p, syndromes, cdw)
	deg := computeElp(p, sigma, syndromes)
	computeRoots(p, errorPoly, sigma)
	computeZPoly(p, z, sigma, deg, syndromes)
	computeErrorValues(p, errorValues, z, errorPoly)
	correctErrors(p, cdw, errorValues)

	// Extract message from corrected systematic codeword.
	// Message is at cdw[PARAM_G-1 .. PARAM_G-1+PARAM_K-1].
	copy(msg[:p.k], cdw[p.g-1:p.g-1+p.k])
}
