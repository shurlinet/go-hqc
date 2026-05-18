package hqc

// Polynomial multiplication in GF(2)[x] modulo X^n - 1.
// Uses Karatsuba with a constant-time 64x64 bit base multiplication.

// baseMul computes the 128-bit carryless product of two 64-bit values.
// Constant-time: no secret-dependent branches or indexing.
func baseMul(c []uint64, a, b uint64) {
	var h, l, g uint64
	var u [16]uint64
	var maskTab [4]uint64

	// Step 1: build lookup table for 4-bit chunks of b.
	u[0] = 0
	u[1] = b & ((uint64(1) << 60) - 1)
	u[2] = u[1] << 1
	u[3] = u[2] ^ u[1]
	u[4] = u[2] << 1
	u[5] = u[4] ^ u[1]
	u[6] = u[3] << 1
	u[7] = u[6] ^ u[1]
	u[8] = u[4] << 1
	u[9] = u[8] ^ u[1]
	u[10] = u[5] << 1
	u[11] = u[10] ^ u[1]
	u[12] = u[6] << 1
	u[13] = u[12] ^ u[1]
	u[14] = u[7] << 1
	u[15] = u[14] ^ u[1]

	// First 4-bit chunk of a.
	g = 0
	tmp1 := a & 0x0f
	for i := uint64(0); i < 16; i++ {
		tmp2 := tmp1 - i
		mask := uint64(0 - (1 - ((tmp2 | (0 - tmp2)) >> 63)))
		g ^= u[i] & mask
	}
	l = g
	h = 0

	// Step 2: remaining 4-bit chunks.
	for i := uint(4); i < 64; i += 4 {
		g = 0
		tmp1 = (a >> i) & 0x0f
		for j := uint64(0); j < 16; j++ {
			tmp2 := tmp1 - j
			mask := uint64(0 - (1 - ((tmp2 | (0 - tmp2)) >> 63)))
			g ^= u[j] & mask
		}
		l ^= g << i
		h ^= g >> (64 - i)
	}

	// Step 3: handle top 4 bits of b.
	maskTab[0] = 0 - ((b >> 60) & 1)
	maskTab[1] = 0 - ((b >> 61) & 1)
	maskTab[2] = 0 - ((b >> 62) & 1)
	maskTab[3] = 0 - ((b >> 63) & 1)

	l ^= (a << 60) & maskTab[0]
	h ^= (a >> 4) & maskTab[0]
	l ^= (a << 61) & maskTab[1]
	h ^= (a >> 3) & maskTab[1]
	l ^= (a << 62) & maskTab[2]
	h ^= (a >> 2) & maskTab[2]
	l ^= (a << 63) & maskTab[3]
	h ^= (a >> 1) & maskTab[3]

	c[0] = l
	c[1] = h
}

func karatsubaAdd1(alh, blh []uint64, a, b []uint64, sizeL, sizeH int) {
	for i := 0; i < sizeH; i++ {
		alh[i] = a[i] ^ a[i+sizeL]
		blh[i] = b[i] ^ b[i+sizeL]
	}
	if sizeH < sizeL {
		alh[sizeH] = a[sizeH]
		blh[sizeH] = b[sizeH]
	}
}

func karatsubaAdd2(o, tmp1, tmp2 []uint64, sizeL, sizeH int) {
	for i := 0; i < 2*sizeL; i++ {
		tmp1[i] ^= o[i]
	}
	for i := 0; i < 2*sizeH; i++ {
		tmp1[i] ^= tmp2[i]
	}
	for i := 0; i < 2*sizeL; i++ {
		o[i+sizeL] ^= tmp1[i]
	}
}

func karatsuba(o, a, b []uint64, size int, stack []uint64) {
	if size == 1 {
		baseMul(o, a[0], b[0])
		return
	}

	sizeH := size / 2
	sizeL := (size + 1) / 2

	alh := stack[:sizeL]
	blh := stack[sizeL : 2*sizeL]
	tmp1 := stack[2*sizeL : 4*sizeL]
	tmp2 := o[2*sizeL:]

	nextStack := stack[4*sizeL:]

	karatsuba(o, a, b, sizeL, nextStack)
	karatsuba(tmp2, a[sizeL:], b[sizeL:], sizeH, nextStack)
	karatsubaAdd1(alh, blh, a, b, sizeL, sizeH)
	karatsuba(tmp1, alh, blh, sizeL, nextStack)
	karatsubaAdd2(o, tmp1, tmp2, sizeL, sizeH)
}

// polyReduce computes o(x) = a(x) mod (X^n - 1).
func polyReduce(p *params, o, a []uint64) {
	if p == nil {
		panic("hqc: nil params")
	}
	shift := p.n & 0x3F // n mod 64
	vecN := int(p.vecNSize64)

	for i := 0; i < vecN; i++ {
		r := a[i+vecN-1] >> shift
		carry := a[i+vecN] << (64 - shift)
		o[i] = a[i] ^ r ^ carry
	}
	o[vecN-1] &= p.redMask
}

// polyMul multiplies two polynomials modulo X^n - 1.
// Allocates fresh workspace per call, zeroed via defer on all exit paths.
func polyMul(p *params, o, v1, v2 []uint64) {
	if p == nil {
		panic("hqc: nil params")
	}
	vecN := int(p.vecNSize64)

	stack := make([]uint64, vecN<<3)
	oKarat := make([]uint64, vecN<<1)
	defer func() {
		ZeroUint64s(stack)
		ZeroUint64s(oKarat)
	}()

	karatsuba(oKarat, v1[:vecN], v2[:vecN], vecN, stack)
	polyReduce(p, o, oKarat)
}
