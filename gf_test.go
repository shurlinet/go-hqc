package hqc

import "testing"

func TestGfMulExhaustive(t *testing.T) {
	// Verify all 65536 multiplications produce results in GF(2^8).
	// Also verify commutativity and identity.
	for a := uint16(0); a < 256; a++ {
		for b := uint16(0); b < 256; b++ {
			r := gfMul(a, b)
			if r >= 256 {
				t.Fatalf("gfMul(%d, %d) = %d, exceeds field size", a, b, r)
			}
			// Commutativity.
			r2 := gfMul(b, a)
			if r != r2 {
				t.Fatalf("gfMul(%d, %d)=%d != gfMul(%d, %d)=%d", a, b, r, b, a, r2)
			}
		}
		// Identity: a * 1 = a.
		if gfMul(a, 1) != a {
			t.Fatalf("gfMul(%d, 1) != %d", a, a)
		}
		// Zero: a * 0 = 0.
		if gfMul(a, 0) != 0 {
			t.Fatalf("gfMul(%d, 0) != 0", a)
		}
	}
}

func TestGfSquare(t *testing.T) {
	// Verify gfSquare matches gfMul(a, a) for all elements.
	for a := uint16(0); a < 256; a++ {
		got := gfSquare(a)
		want := gfMul(a, a)
		if got != want {
			t.Fatalf("gfSquare(%d) = %d, gfMul(%d,%d) = %d", a, got, a, a, want)
		}
	}
}

func TestGfInverse(t *testing.T) {
	// Verify a * a^-1 = 1 for all non-zero elements.
	for a := uint16(1); a < 256; a++ {
		inv := gfInverse(a)
		product := gfMul(a, inv)
		if product != 1 {
			t.Fatalf("gfMul(%d, gfInverse(%d)) = %d, want 1", a, a, product)
		}
	}
	// Convention: inverse of 0 is 0.
	if gfInverse(0) != 0 {
		t.Fatal("gfInverse(0) != 0")
	}
}

func TestGfTablesAntiTamper(t *testing.T) {
	// Recompute gfExp from the primitive polynomial 0x11D independently.
	// This catches any corruption of the hardcoded tables.
	var computedExp [258]uint16
	computedExp[0] = 1
	for i := 1; i < 258; i++ {
		v := uint16(computedExp[i-1]) << 1
		if v >= 256 {
			v ^= 0x11D
		}
		computedExp[i] = v
	}

	for i := 0; i < 258; i++ {
		if gfExp[i] != computedExp[i] {
			t.Fatalf("gfExp[%d] = %d, computed = %d", i, gfExp[i], computedExp[i])
		}
	}

	// Verify gfLog is the inverse of gfExp.
	for i := 0; i < 255; i++ {
		if gfLog[gfExp[i]] != uint16(i) {
			t.Fatalf("gfLog[gfExp[%d]] = %d, want %d", i, gfLog[gfExp[i]], i)
		}
	}

	// Verify multiplicative order: gfExp[255] == 1.
	if gfExp[255] != 1 {
		t.Fatalf("gfExp[255] = %d, want 1 (multiplicative order)", gfExp[255])
	}

	// Verify wraparound entries.
	if gfExp[256] != 2 || gfExp[257] != 4 {
		t.Fatalf("gfExp wraparound wrong: [256]=%d [257]=%d", gfExp[256], gfExp[257])
	}
}

func TestGfInverseViaExpLog(t *testing.T) {
	// Anti-tamper: verify gfInverse(gfExp[i]) == gfExp[255-i] for all i in [1, 254].
	for i := 1; i < 255; i++ {
		got := gfInverse(gfExp[i])
		want := gfExp[255-i]
		if got != want {
			t.Fatalf("gfInverse(gfExp[%d]) = %d, want gfExp[%d] = %d", i, got, 255-i, want)
		}
	}
}
