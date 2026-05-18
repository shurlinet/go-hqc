package hqc

// Reed-Muller RM(1,7) code: [128, 8, 64].
// Each byte is encoded into a 128-bit codeword, duplicated MULTIPLICITY times.
// Reed-Muller RM(1,7) encoding and decoding.

// bit0mask copies bit 0 of x into all 32 bits.
func bit0mask(x uint32) uint32 {
	return uint32(-int32(x & 1))
}

// rmEncodeWord encodes a single byte into a 128-bit RM(1,7) codeword (2 uint64s).
func rmEncodeWord(cword []uint64, message uint8) {
	// Bit 7 flips all bits (start with all-ones or all-zeros).
	firstWord := bit0mask(uint32(message) >> 7)

	// Bits 0-4 are the same for all four 32-bit quarters.
	firstWord ^= bit0mask(uint32(message)>>0) & 0xaaaaaaaa
	firstWord ^= bit0mask(uint32(message)>>1) & 0xcccccccc
	firstWord ^= bit0mask(uint32(message)>>2) & 0xf0f0f0f0
	firstWord ^= bit0mask(uint32(message)>>3) & 0xff00ff00
	firstWord ^= bit0mask(uint32(message)>>4) & 0xffff0000

	// Store first quarter.
	cword[0] = uint64(firstWord)

	// Bit 5 flips entries 1 and 3; bit 6 flips 2 and 3.
	firstWord ^= bit0mask(uint32(message) >> 5)
	cword[0] |= uint64(firstWord) << 32

	firstWord ^= bit0mask(uint32(message) >> 6)
	cword[1] = uint64(firstWord) << 32

	firstWord ^= bit0mask(uint32(message) >> 5)
	cword[1] |= uint64(firstWord)
}

// hadamard performs a 7-pass Hadamard transform in place.
// src is the input (overwritten), dst receives the result.
// After 7 passes (odd count), the result is in dst.
func hadamard(src, dst []uint16) {
	p1 := src
	p2 := dst
	for pass := 0; pass < 7; pass++ {
		for i := 0; i < 64; i++ {
			// uint16 addition/subtraction wraps mod 2^16.
			// Subtraction produces "negative" values via two's complement
			// wrapping - this is intentional. findPeaks extracts the sign
			// via bit 15 manipulation.
			p2[i] = p1[2*i] + p1[2*i+1]
			p2[i+64] = p1[2*i] - p1[2*i+1]
		}
		p1, p2 = p2, p1
	}
	// 7 passes (odd): each pass writes to p2 then swaps p1/p2.
	// After 7 swaps starting from p1=src: p1=dst, and pass 6
	// wrote the final result into what is now p1 (= dst's backing array).
	// The caller's dst slice has the result.
}

// expandAndSum sums MULTIPLICITY copies of a 128-bit codeword into
// a uint16[128] array (values 0..MULTIPLICITY).
func expandAndSum(dest []uint16, src []uint64, multiplicity int) {
	// First copy: extract each bit.
	for part := 0; part < 2; part++ {
		for bit := 0; bit < 64; bit++ {
			dest[part*64+bit] = uint16((src[part] >> uint(bit)) & 1)
		}
	}
	// Sum remaining copies.
	for c := 1; c < multiplicity; c++ {
		for part := 0; part < 2; part++ {
			for bit := 0; bit < 64; bit++ {
				dest[part*64+bit] += uint16((src[2*c+part] >> uint(bit)) & 1)
			}
		}
	}
}

// findPeaks finds the position of the largest absolute value in the
// Hadamard transform, returning the decoded byte. Constant-time.
//
// Sign convention (derived from 0/1 Hadamard on balanced codewords):
//   - Negative peak (bit 15 set) -> bit 7 = 0
//   - Positive peak (bit 15 clear) -> bit 7 = 1
func findPeaks(transform []uint16) uint8 {
	peakAbs := uint16(0)
	peak := uint16(0)
	pos := uint16(0)

	for i := uint16(0); i < 128; i++ {
		t := transform[i]

		// Constant-time abs using uint16 two's complement.
		// If t has bit 15 set (negative), negate it. Otherwise keep it.
		// -(t >> 15) is 0xFFFF when negative, 0x0000 when positive.
		// -t is the two's complement negation (0 - t as uint16).
		neg := uint16(0) - (t >> 15)  // 0xFFFF if negative, 0 if positive
		abs := t ^ (neg & (t ^ (uint16(0) - t)))

		// Update peak if abs > peakAbs (constant-time conditional swap).
		// mask is 0xFFFF when peakAbs < abs (new peak found).
		mask := uint16(0) - ((peakAbs - abs) >> 15)
		peak ^= mask & (peak ^ t)
		pos ^= mask & (pos ^ i)
		peakAbs ^= mask & (peakAbs ^ abs)
	}

	// Set bit 7 based on the sign of the peak.
	// Positive peak (bit 15 = 0): (0 - 1) = 0xFFFF, 128 & 0xFFFF = 128 -> bit 7 set.
	// Negative peak (bit 15 = 1): (1 - 1) = 0, 128 & 0 = 0 -> bit 7 not set.
	pos |= 128 & ((peak >> 15) - 1)

	return uint8(pos)
}

// rmEncode encodes N1 message bytes into a concatenated RM codeword.
// Each byte becomes 128 bits * MULTIPLICITY, stored as uint64 words.
// Output cdw has vecN1N2Size64 elements.
func rmEncode(p *params, cdw []uint64, msg []uint8) {
	mult := int(p.multiplicity)
	for i := 0; i < int(p.vecN1SizeBytes); i++ {
		// Encode the byte into the first 128-bit slot.
		rmEncodeWord(cdw[2*i*mult:], msg[i])
		// Copy to the remaining MULTIPLICITY-1 slots (16 bytes = 2 uint64s each).
		for c := 1; c < mult; c++ {
			cdw[2*i*mult+2*c] = cdw[2*i*mult]
			cdw[2*i*mult+2*c+1] = cdw[2*i*mult+1]
		}
	}
}

// rmDecode decodes a concatenated RM codeword back to N1 message bytes.
// Uses expand_and_sum + Hadamard transform + find_peaks per byte.
func rmDecode(p *params, msg []uint8, cdw []uint64) {
	mult := int(p.multiplicity)
	var expanded [128]uint16
	var transform [128]uint16

	for i := 0; i < int(p.vecN1SizeBytes); i++ {
		// Zero the arrays for each byte (they're reused).
		for j := range expanded {
			expanded[j] = 0
		}
		for j := range transform {
			transform[j] = 0
		}

		expandAndSum(expanded[:], cdw[2*i*mult:], mult)
		hadamard(expanded[:], transform[:])

		// Fix the first entry: remove the DC bias from 0/1 representation.
		transform[0] -= 64 * uint16(mult)

		msg[i] = findPeaks(transform[:])
	}
}
