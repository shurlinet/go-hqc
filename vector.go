package hqc

// Vector operations: sampling, addition, comparison, truncation.

// compareU32 returns 1 if v1 == v2, 0 otherwise (constant-time).
func compareU32(v1, v2 uint32) uint32 {
	return 1 ^ (((v1 - v2) | (v2 - v1)) >> 31)
}

// singleBitMask returns a uint64 with exactly bit `pos` set (constant-time).
// Iterates all 64 positions to avoid secret-dependent indexing.
func singleBitMask(pos uint32) uint64 {
	var ret uint64
	mask := uint64(1)
	for i := uint32(0); i < 64; i++ {
		tmp := uint64(pos) - uint64(i)
		sel := uint64(0) - (1 - ((tmp | (0 - tmp)) >> 63))
		ret |= mask & sel
		mask <<= 1
	}
	return ret
}

// condSub subtracts n from r if r >= n (constant-time).
func condSub(r, n uint32) uint32 {
	r -= n
	mask := uint32(0) - (r >> 31)
	return r + (n & mask)
}

// barrettReduceN reduces x mod n using precomputed nMu = floor(2^32 / n).
// Constant-time Barrett reduction with conditional correction.
// Used by sampler1 (rejection sampling for keygen).
func barrettReduceN(x, nMu, n uint32) uint32 {
	q := uint32((uint64(x) * uint64(nMu)) >> 32)
	r := x - q*n
	return condSub(r, n)
}

// writeSupport sets bits at the given support positions in the output vector.
// Constant-time over all words (no secret-dependent branching on positions).
func writeSupport(v []uint64, support []uint32, weight uint16, vecNSize64 uint32) {
	indexTab := make([]uint32, weight)
	bitTab := make([]uint64, weight)
	defer func() {
		ZeroUint32s(indexTab)
		ZeroUint64s(bitTab)
	}()

	for i := 0; i < int(weight); i++ {
		indexTab[i] = support[i] >> 6
		bitTab[i] = singleBitMask(support[i] & 0x3f)
	}

	for i := uint32(0); i < vecNSize64; i++ {
		var val uint64
		for j := 0; j < int(weight); j++ {
			tmp := i - indexTab[j]
			eq := 1 ^ ((tmp | (0 - tmp)) >> 31)
			mask64 := uint64(0) - uint64(eq)
			val |= bitTab[j] & mask64
		}
		v[i] = val
	}
}

// sampleFixedWeightKeygen generates a fixed-weight vector using rejection
// sampling (sampler1). Squeezes 3 bytes per candidate from the XOF, rejects
// candidates >= rejectionThreshold, Barrett reduces accepted candidates.
// NOT constant-time (variable-time rejection loop, acceptable for keygen).
// Used for y and x in keygen.
func sampleFixedWeightKeygen(p *params, se *seedExpander, v []uint64, weight uint16) {
	for i := range v {
		v[i] = 0
	}

	support := make([]uint32, weight)
	defer ZeroUint32s(support)

	randBytes := make([]byte, 3)
	defer ZeroBytes(randBytes)

	for i := uint16(0); i < weight; {
		se.Read(randBytes)
		candidate := uint32(randBytes[0]) | uint32(randBytes[1])<<8 | uint32(randBytes[2])<<16

		if candidate >= p.rejectionThreshold {
			continue
		}
		candidate = barrettReduceN(candidate, p.nMu, p.n)

		// Linear scan for duplicates (not constant-time, acceptable for keygen).
		duplicate := false
		for j := uint16(0); j < i; j++ {
			if candidate == support[j] {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}

		support[i] = candidate
		i++
	}

	writeSupport(v, support, weight, p.vecNSize64)
}

// sampleFixedWeightEncrypt generates a fixed-weight vector using the
// Fisher-Yates / Algorithm 5 sampler (sampler2). Squeezes exactly 4*weight
// bytes from the XOF (deterministic consumption). Constant-time duplicate
// resolution via backward scan.
// Used for r2, e, r1 in encrypt.
func sampleFixedWeightEncrypt(p *params, se *seedExpander, v []uint64, weight uint16) {
	for i := range v {
		v[i] = 0
	}

	randBytes := make([]byte, 4*int(weight))
	se.Read(randBytes)

	support := make([]uint32, weight)

	defer func() {
		ZeroBytes(randBytes)
		ZeroUint32s(support)
	}()

	// Fixed-point modular reduction: pos = i + floor(buff * (n-i) / 2^32).
	for i := 0; i < int(weight); i++ {
		buff := uint32(randBytes[4*i]) |
			uint32(randBytes[4*i+1])<<8 |
			uint32(randBytes[4*i+2])<<16 |
			uint32(randBytes[4*i+3])<<24
		support[i] = uint32(i) + uint32((uint64(buff)*uint64(p.n-uint32(i)))>>32)
	}

	// Constant-time duplicate resolution (backward scan).
	for i := int(weight) - 2; i >= 0; i-- {
		var found uint32
		for j := i + 1; j < int(weight); j++ {
			found |= compareU32(support[j], support[i])
		}
		mask32 := uint32(0) - found
		support[i] = (mask32 & uint32(i)) ^ (^mask32 & support[i])
	}

	writeSupport(v, support, weight, p.vecNSize64)
}

// sampleRandomVector generates a random binary vector of dimension n.
func sampleRandomVector(p *params, se *seedExpander, v []uint64) {
	if p == nil {
		panic("hqc: nil params")
	}
	randBytes := make([]byte, p.vecNSizeBytes)
	defer ZeroBytes(randBytes)
	se.Read(randBytes)
	load8Arr(v[:p.vecNSize64], randBytes)
	v[p.vecNSize64-1] &= p.redMask
}

// polyAdd XORs two vectors: o = v1 ^ v2.
func polyAdd(o, v1, v2 []uint64, size int) {
	for i := 0; i < size; i++ {
		o[i] = v1[i] ^ v2[i]
	}
}

// vectCompare compares two byte slices in constant time.
// Returns 0 if equal, 1 if different.
func vectCompare(v1, v2 []byte, size int) uint8 {
	r := uint16(0x0100)
	for i := 0; i < size; i++ {
		r |= uint16(v1[i] ^ v2[i])
	}
	return uint8((r - 1) >> 8)
}

// constantTimeEqualUint64 compares two uint64 slices up to nWords words.
// Returns 1 if equal, 0 if different (matches crypto/subtle convention).
func constantTimeEqualUint64(a, b []uint64, nWords int) int {
	var acc uint64
	for i := 0; i < nWords; i++ {
		acc |= a[i] ^ b[i]
	}
	nonzero := (acc | (0 - acc)) >> 63
	return int(1 - nonzero)
}

// vectTruncate zeros all bits beyond n1n2 in the vector (in-place).
// Matches v5.0.0 vect_truncate: clears bits [n1n2, vecNSize64*64).
func vectTruncate(p *params, v []uint64) {
	lastWord := p.n1n2 / 64
	lastBits := p.n1n2 % 64
	if lastBits != 0 {
		v[lastWord] &= (1 << lastBits) - 1
		lastWord++
	}
	for i := lastWord; i < p.vecNSize64; i++ {
		v[i] = 0
	}
}

// vectResize copies a vector truncating or zero-extending to the target size in bits.
func vectResize(o []uint64, sizeO uint32, v []uint64, sizeV uint32) {
	if sizeO < sizeV {
		nWords := int(ceilDiv(sizeO, 64))
		copy(o[:nWords], v[:nWords])
		tail := sizeO % 64
		if tail != 0 {
			o[nWords-1] &= (1 << tail) - 1
		}
	} else {
		nWords := int(ceilDiv(sizeV, 64))
		copy(o[:nWords], v[:nWords])
	}
}
