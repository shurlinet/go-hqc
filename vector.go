package hqc

// Vector operations: sampling, addition, comparison, resize.

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

// barrettReduce reduces a mod (n - i) using precomputed Barrett reciprocal.
// mVal[i] = floor(2^32 / (n-i)). The uint64 cast is mandatory to get the
// full 64-bit product before extracting the high 32 bits.
func barrettReduce(a uint32, i int, p *params) uint32 {
	q := uint32((uint64(a) * uint64(p.mVal[i])) >> 32)
	n := p.n - uint32(i)
	r := a - q*n
	return condSub(r, n)
}

// sampleFixedWeightVector generates a vector of the given Hamming weight
// using the seed expander. Constant-time implementation.
func sampleFixedWeightVector(p *params, se *seedExpander, v []uint64, weight uint16) {
	if p == nil {
		panic("hqc: nil params")
	}

	// Zero the output vector to ensure clean state (matches the reference C
	// callers which always pass zero-initialized arrays).
	for i := range v {
		v[i] = 0
	}

	randBytes := make([]byte, 4*int(weight))
	se.Read(randBytes)

	support := make([]uint32, weight)
	indexTab := make([]uint32, weight)
	bitTab := make([]uint64, weight)

	defer func() {
		ZeroBytes(randBytes)
		ZeroUint32s(support)
		ZeroUint32s(indexTab)
		ZeroUint64s(bitTab)
	}()

	// Build support array with Barrett reduction.
	for i := 0; i < int(weight); i++ {
		// Each byte must be cast to uint32 before shifting; Go does not
		// promote uint8 to a wider type on shift (unlike C).
		support[i] = uint32(randBytes[4*i]) |
			uint32(randBytes[4*i+1])<<8 |
			uint32(randBytes[4*i+2])<<16 |
			uint32(randBytes[4*i+3])<<24
		support[i] = uint32(i) + barrettReduce(support[i], i, p)
	}

	// Constant-time duplicate resolution (scan backward).
	for i := int(weight) - 2; i >= 0; i-- {
		var found uint32
		for j := i + 1; j < int(weight); j++ {
			found |= compareU32(support[j], support[i])
		}
		mask32 := uint32(0) - found
		support[i] = (mask32 & uint32(i)) ^ (^mask32 & support[i])
	}

	// Compute word index and bit mask for each support position.
	for i := 0; i < int(weight); i++ {
		indexTab[i] = support[i] >> 6
		pos := support[i] & 0x3f
		bitTab[i] = singleBitMask(pos)
	}

	// Set bits in the output vector (constant-time over all words).
	vecN := int(p.vecNSize64)
	for i := 0; i < vecN; i++ {
		var val uint64
		for j := 0; j < int(weight); j++ {
			tmp := uint32(i) - indexTab[j]
			eq := 1 ^ ((tmp | (0 - tmp)) >> 31)
			mask64 := uint64(0) - uint64(eq)
			val |= bitTab[j] & mask64
		}
		v[i] = val
	}
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
	// acc == 0 means equal. Convert: (acc | -acc) >> 63 is 1 if acc != 0.
	nonzero := (acc | (0 - acc)) >> 63
	return int(1 - nonzero)
}

// vectResize copies a vector truncating or zero-extending to the target size in bits.
func vectResize(o []uint64, sizeO uint32, v []uint64, sizeV uint32) {
	if sizeO < sizeV {
		// Truncate: copy the words needed for sizeO bits, then mask the top word.
		nWords := int(ceilDiv(sizeO, 64))
		copy(o[:nWords], v[:nWords])
		tail := sizeO % 64
		if tail != 0 {
			o[nWords-1] &= (1 << tail) - 1
		}
	} else {
		// Extend: copy ceil(sizeV/64) words.
		nWords := int(ceilDiv(sizeV, 64))
		copy(o[:nWords], v[:nWords])
	}
}
