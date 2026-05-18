package hqc

import "github.com/shurlinet/go-hqc/internal/shake"

const seedExpanderDomain = 0x01

// seedExpander is a SHAKE256-based XOF with domain separation.
// Absorbs seed || domain_byte, then squeezes arbitrary output.
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

// Read squeezes output from the seed expander. Direct squeeze with no alignment
// padding - each byte consumed from the SHAKE state maps 1:1 to output bytes.
func (se *seedExpander) Read(output []byte) {
	n, _ := se.state.Read(output)
	if n != len(output) {
		panic("hqc: SHAKE256 short read")
	}
}
