package hqc

import (
	"math/bits"
	"testing"
)

func TestPolyMulCommutativity(t *testing.T) {
	// polyMul(a, b) == polyMul(b, a) for random-looking polynomials.
	p := params128

	// Create two test polynomials with known bits set.
	a := make([]uint64, p.vecNSize64)
	b := make([]uint64, p.vecNSize64)
	a[0] = 0xDEADBEEFCAFEBABE
	a[1] = 0x0123456789ABCDEF
	a[10] = 0xFFFFFFFFFFFFFFFF
	b[0] = 0x1111111111111111
	b[5] = 0xAAAAAAAAAAAAAAAA
	b[p.vecNSize64-1] = 0x1F // within RED_MASK

	ab := make([]uint64, p.vecNSize64)
	ba := make([]uint64, p.vecNSize64)

	polyMul(p, ab, a, b)
	polyMul(p, ba, b, a)

	for i := range ab {
		if ab[i] != ba[i] {
			t.Fatalf("polyMul not commutative at word %d: %016x != %016x", i, ab[i], ba[i])
		}
	}
}

func TestPolyMulRedMask(t *testing.T) {
	// After polyMul, the top word must be masked by RED_MASK.
	for _, p := range []*params{params128, params192, params256} {
		a := make([]uint64, p.vecNSize64)
		b := make([]uint64, p.vecNSize64)
		// Set many bits to exercise reduction.
		for i := range a {
			a[i] = 0xFFFFFFFFFFFFFFFF
		}
		a[p.vecNSize64-1] = p.redMask // keep a valid
		b[0] = 3                       // simple multiplier

		o := make([]uint64, p.vecNSize64)
		polyMul(p, o, a, b)

		topWord := o[p.vecNSize64-1]
		if topWord & ^p.redMask != 0 {
			t.Fatalf("param_n=%d: top word %016x exceeds RED_MASK %016x",
				p.n, topWord, p.redMask)
		}
	}
}

func TestPolyMulZero(t *testing.T) {
	// Multiplying by zero produces zero.
	p := params128
	a := make([]uint64, p.vecNSize64)
	a[0] = 0xDEADBEEF
	zero := make([]uint64, p.vecNSize64)
	o := make([]uint64, p.vecNSize64)

	polyMul(p, o, a, zero)

	for i, v := range o {
		if v != 0 {
			t.Fatalf("polyMul(a, 0) != 0 at word %d: %016x", i, v)
		}
	}
}

func TestPolyMulIdentity(t *testing.T) {
	// Multiplying by 1 (polynomial with only x^0 set) returns the input.
	p := params128
	a := make([]uint64, p.vecNSize64)
	a[0] = 0xCAFEBABEDEADC0DE
	a[3] = 0x42
	one := make([]uint64, p.vecNSize64)
	one[0] = 1 // x^0

	o := make([]uint64, p.vecNSize64)
	polyMul(p, o, a, one)

	for i := range o {
		if o[i] != a[i] {
			t.Fatalf("polyMul(a, 1) != a at word %d: got %016x want %016x", i, o[i], a[i])
		}
	}
}

func TestBaseMulKnownValue(t *testing.T) {
	// Verify base_mul(3, 5) = 15 (carryless: 0b11 * 0b101 = 0b1111).
	var c [2]uint64
	baseMul(c[:], 3, 5)
	if c[0] != 15 || c[1] != 0 {
		t.Fatalf("baseMul(3, 5) = [%016x, %016x], want [f, 0]", c[0], c[1])
	}

	// baseMul(0xFF...F, 0xFF...F) should produce a 128-bit result.
	baseMul(c[:], ^uint64(0), ^uint64(0))
	totalBits := bits.OnesCount64(c[0]) + bits.OnesCount64(c[1])
	if totalBits == 0 {
		t.Fatal("baseMul(max, max) produced zero")
	}
}

func TestRedMaskAntiTamper(t *testing.T) {
	// Anti-tamper: RED_MASK must equal (1 << (n%64)) - 1 for each param set.
	// Independent recomputation that doesn't use initDerived.
	tests := []struct {
		name string
		p    *params
		n    uint32
		want uint64
	}{
		{"HQC-128", params128, 17669, 0x1f},       // 17669 % 64 = 5
		{"HQC-192", params192, 35851, 0x7ff},      // 35851 % 64 = 11
		{"HQC-256", params256, 57637, 0x1fffffffff}, // 57637 % 64 = 37
	}

	for _, tt := range tests {
		nbits := tt.n % 64
		computed := (uint64(1) << nbits) - 1
		if computed != tt.want {
			t.Fatalf("%s: independently computed RED_MASK %016x != expected %016x", tt.name, computed, tt.want)
		}
		if tt.p.redMask != computed {
			t.Fatalf("%s: params.redMask %016x != computed %016x", tt.name, tt.p.redMask, computed)
		}
	}
}
