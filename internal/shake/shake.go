// Package shake provides a thin wrapper around Go's standard library
// crypto/sha3 SHAKE256 implementation. This exists so go-hqc has zero
// external dependencies while maintaining a clean internal API boundary.
package shake

import "crypto/sha3"

// State wraps a SHAKE256 instance. After Write calls are complete,
// call Read to squeeze output. Write after Read panics (per SHAKE spec).
type State struct {
	s *sha3.SHAKE
}

// New256 returns a new SHAKE256 state ready for absorbing.
func New256() *State {
	return &State{s: sha3.NewSHAKE256()}
}

// Write absorbs data into the SHAKE state.
// It never returns an error.
func (st *State) Write(p []byte) (int, error) {
	return st.s.Write(p)
}

// Read squeezes output from the SHAKE state.
// It never returns an error; n always equals len(p).
func (st *State) Read(p []byte) (int, error) {
	return st.s.Read(p)
}

// Reset resets the state to a fresh SHAKE256, discarding all absorbed data.
func (st *State) Reset() {
	st.s.Reset()
}
