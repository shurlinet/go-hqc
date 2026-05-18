package hqc

// GF(2^8) arithmetic using the primitive polynomial 0x11D.
// All operations are constant-time (no secret-dependent branching or indexing).

const (
	paramM         = 8
	paramGFPoly    = 0x11D
	paramGFPolyWt  = 5
	paramGFPolyM2  = 4
	paramGFMulOrd  = 255
)

// trailingZeroBitsCount returns the number of trailing zero bits in a (constant-time).
func trailingZeroBitsCount(a uint16) uint16 {
	var tmp uint16
	mask := uint16(0xFFFF)
	for i := uint16(0); i < 14; i++ {
		bit := 1 - ((a >> i) & 1)
		tmp += bit & mask
		mask &= -bit
	}
	return tmp
}

// gfReduce reduces polynomial x modulo the primitive polynomial.
// degX must be >= paramM-1 (i.e., the polynomial must have degree >= 7).
// For inputs already within the field (degX < paramM), no reduction is needed.
func gfReduce(x uint64, degX uint32) uint16 {
	if degX < paramM-1 {
		return uint16(x)
	}
	steps := ceilDiv(degX-(paramM-1), paramGFPolyM2)

	for i := uint32(0); i < steps; i++ {
		mod := x >> paramM
		x &= (1 << paramM) - 1
		x ^= mod

		var z1 uint16
		rmdr := uint16(paramGFPoly ^ 1)
		for j := paramGFPolyWt - 2; j > 0; j-- {
			z2 := trailingZeroBitsCount(rmdr)
			dist := z2 - z1
			mod <<= uint(dist)
			x ^= mod
			rmdr ^= 1 << z2
			z1 = z2
		}
	}

	return uint16(x)
}

// gfCarrylessMul computes the carryless multiplication of a and b.
// Returns the 16-bit product as a uint16 (low byte in bits 0-7, high in 8-15).
func gfCarrylessMul(a, b uint8) uint16 {
	var h, l, g uint16
	var u [4]uint16
	u[0] = 0
	u[1] = uint16(b) & 0x7F
	u[2] = u[1] << 1
	u[3] = u[2] ^ u[1]

	tmp1 := uint32(a) & 3
	for i := uint32(0); i < 4; i++ {
		tmp2 := tmp1 - i
		// Constant-time select: mask is all-ones if tmp1 == i, else all-zeros.
		mask := uint32(0 - (1 - ((tmp2 | (0 - tmp2)) >> 31)))
		g ^= u[i] & uint16(mask)
	}

	l = g
	h = 0

	for i := uint32(2); i < 8; i += 2 {
		g = 0
		tmp1 = (uint32(a) >> i) & 3
		for j := uint32(0); j < 4; j++ {
			tmp2 := tmp1 - j
			mask := uint32(0 - (1 - ((tmp2 | (0 - tmp2)) >> 31)))
			g ^= u[j] & uint16(mask)
		}
		l ^= g << i
		h ^= g >> (8 - i)
	}

	// Handle top bit of b.
	bmask := uint16(-((uint16(b) >> 7) & 1))
	l ^= (uint16(a) << 7) & bmask
	h ^= (uint16(a) >> 1) & bmask

	return l | (h << 8)
}

// gfMul multiplies two elements of GF(2^8).
func gfMul(a, b uint16) uint16 {
	product := gfCarrylessMul(uint8(a), uint8(b))
	return gfReduce(uint64(product), 2*(paramM-1))
}

// gfSquare squares an element of GF(2^8).
func gfSquare(a uint16) uint16 {
	b := uint32(a)
	s := b & 1
	for i := uint32(1); i < paramM; i++ {
		b <<= 1
		// Explicit parentheses required: Go's << has lower precedence than *,
		// opposite of C. Without parens this silently computes (1<<2)*i.
		s ^= b & (1 << (2 * i))
	}
	return gfReduce(uint64(s), 2*(paramM-1))
}

// gfInverse computes the inverse of a in GF(2^8).
// Uses addition chain: 1 2 3 4 7 11 15 30 60 120 127 254.
// Returns 0 for input 0 (convention).
func gfInverse(a uint16) uint16 {
	inv := gfSquare(a)            // a^2
	tmp1 := gfMul(inv, a)         // a^3
	inv = gfSquare(inv)           // a^4
	tmp2 := gfMul(inv, tmp1)      // a^7
	tmp1 = gfMul(inv, tmp2)       // a^11
	inv = gfMul(tmp1, inv)        // a^15
	inv = gfSquare(inv)           // a^30
	inv = gfSquare(inv)           // a^60
	inv = gfSquare(inv)           // a^120
	inv = gfMul(inv, tmp2)        // a^127
	inv = gfSquare(inv)           // a^254
	return inv
}
