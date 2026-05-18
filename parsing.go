package hqc

import "encoding/binary"

// load8Arr converts a byte slice to a uint64 slice (little-endian).
// Loads 8 bytes at a time using encoding/binary, handles remainder.
func load8Arr(out []uint64, in []byte) {
	indexIn := 0
	indexOut := 0

	// Load full 8-byte blocks via encoding/binary (compiler-optimized).
	for indexOut < len(out) && indexIn+8 <= len(in) {
		out[indexOut] = binary.LittleEndian.Uint64(in[indexIn : indexIn+8])
		indexIn += 8
		indexOut++
	}

	// Handle remaining bytes (< 8).
	if indexIn >= len(in) || indexOut >= len(out) {
		return
	}
	remaining := len(in) - indexIn
	out[indexOut] = uint64(in[len(in)-1])
	for i := remaining - 2; i >= 0; i-- {
		out[indexOut] <<= 8
		out[indexOut] |= uint64(in[indexIn+i])
	}
}

// store8Arr converts a uint64 slice to a byte slice (little-endian).
func store8Arr(out []byte, in []uint64) {
	indexOut := 0
	indexIn := 0

	// Store full 8-byte blocks via encoding/binary.
	for indexIn < len(in) && indexOut+8 <= len(out) {
		binary.LittleEndian.PutUint64(out[indexOut:indexOut+8], in[indexIn])
		indexOut += 8
		indexIn++
	}

	// Handle remaining bytes (< 8 at the tail).
	if indexIn < len(in) {
		for indexOut < len(out) {
			out[indexOut] = byte(in[indexIn] >> (uint(indexOut%8) * 8))
			indexOut++
		}
	}
}
