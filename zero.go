package hqc

// ZeroBytes zeroes a byte slice.
// The noinline directive prevents the compiler from optimizing away
// zeroing of buffers that are about to go out of scope (dead-store elimination).
//
//go:noinline
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroUint64s zeroes a uint64 slice.
//
//go:noinline
func ZeroUint64s(s []uint64) {
	for i := range s {
		s[i] = 0
	}
}

// ZeroUint32s zeroes a uint32 slice.
//
//go:noinline
func ZeroUint32s(s []uint32) {
	for i := range s {
		s[i] = 0
	}
}

// ZeroUint16s zeroes a uint16 slice.
//
//go:noinline
func ZeroUint16s(s []uint16) {
	for i := range s {
		s[i] = 0
	}
}
