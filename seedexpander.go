package hqc

import "github.com/shurlinet/go-hqc/internal/shake"

const seedExpanderDomain = 0x02

// seedExpander is a SHAKE256-based deterministic PRNG that squeezes
// in 8-byte aligned blocks to match the reference C implementation's behavior.
type seedExpander struct {
	state *shake.State
}

// newSeedExpander creates a seed expander from a seed.
// It absorbs seed || domain_byte, then transitions to squeeze mode on first Read.
func newSeedExpander(seed []byte) *seedExpander {
	st := shake.New256()
	if n, _ := st.Write(seed); n != len(seed) {
		panic("hqc: SHAKE256 short write")
	}
	if n, _ := st.Write([]byte{seedExpanderDomain}); n != 1 {
		panic("hqc: SHAKE256 short write")
	}
	return &seedExpander{state: st}
}

// Release resets the internal SHAKE state, clearing absorbed seed material.
// After Release, the seedExpander must not be used.
func (se *seedExpander) Release() {
	se.state.Reset()
	se.state = nil
}

// Read squeezes output from the seed expander with 8-byte alignment.
// For requests not a multiple of 8, it squeezes the aligned portion first,
// then squeezes a full 8-byte block and copies only the remainder.
// The extra bytes are consumed from the SHAKE state (matching the reference C exactly).
func (se *seedExpander) Read(output []byte) {
	outlen := len(output)
	remainder := outlen % 8
	mainLen := outlen - remainder

	if mainLen > 0 {
		n, _ := se.state.Read(output[:mainLen])
		if n != mainLen {
			panic("hqc: SHAKE256 short read")
		}
	}

	if remainder > 0 {
		var tmp [8]byte
		n, _ := se.state.Read(tmp[:])
		if n != 8 {
			panic("hqc: SHAKE256 short read")
		}
		copy(output[mainLen:], tmp[:remainder])
		// Zero the alignment buffer (includes discarded SHAKE output bytes).
		// Must use noinline-protected zeroing to prevent dead-store elimination.
		ZeroBytes(tmp[:])
	}
}
