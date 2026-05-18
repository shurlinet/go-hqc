package hqc

// params holds all HQC parameters for a given security level.
// Three package-level singletons (params128, params192, params256) are
// validated at init time. This type is never exported.
type params struct {
	n       uint32 // ambient polynomial space
	n1      uint32 // RS code length
	n2      uint32 // RM code length (128 or 640)
	n1n2    uint32 // concatenated code length (n1 * n2)
	omega   uint16 // secret key weight
	omegaE  uint16 // error weight
	omegaR  uint16 // encryption randomness weight
	delta   uint16 // RS correcting capacity
	k       uint16 // RS information symbols (bytes)
	g       uint16 // RS generator polynomial degree (2*delta+1)
	fft     uint16 // additive FFT size (log2)
	m       uint16 // GF extension degree (always 8)
	gfPoly  uint16 // primitive polynomial (always 0x11D)
	seedLen uint16 // seed byte length (32)
	saltLen uint16 // salt byte length (16)

	// v5.0.0 sampling parameters
	nMu                uint32 // floor(2^32 / n), Barrett multiplier for rejection sampler
	rejectionThreshold uint32 // floor(2^24 / n) * n, rejection bound for sampler1
	securityBytes      uint16 // PARAM_SECURITY_BYTES (16/24/32), sigma size

	// Derived sizes (computed at init)
	vecNSize64       uint32 // ceil(n / 64)
	vecN1N2Size64    uint32 // ceil(n1n2 / 64)
	vecNSizeBytes    uint32 // ceil(n / 8)
	vecN1N2SizeBytes uint32 // ceil(n1n2 / 8)
	redMask          uint64 // bitmask for top word: (1 << (n%64)) - 1
	multiplicity     uint16 // ceil(n2 / 128), RM repetition count

	// Reed-Solomon generator polynomial coefficients
	rsPolyCoefs []uint8

	// Derived sizes for RS/RM code (byte-count based, NOT bit-count based).
	// PARAM_K and PARAM_N1 are byte counts (GF(2^8) symbols).
	// VEC_K_SIZE_64 = ceil(K/8), VEC_N1_SIZE_64 = ceil(N1/8).
	// This is DIFFERENT from VEC_N_SIZE_64 = ceil(N/64) which divides BIT count.
	vecKSizeBytes  uint32 // = k (byte count, same value)
	vecN1SizeBytes uint32 // = n1 (byte count, same value)
	vecKSize64     uint32 // ceil(k / 8), NOT ceil(k / 64)
	vecN1Size64    uint32 // ceil(n1 / 8), NOT ceil(n1 / 64)

	// Precomputed alpha^((i+1)*(j+1)) table for RS syndrome computation.
	// Dimensions: [2*delta][n1-1]. Computed at init from gfExp.
	alphaIjPow [][]uint16
}

// ceilDiv returns ceil(a / b).
func ceilDiv(a, b uint32) uint32 {
	return (a + b - 1) / b
}

var (
	params128 *params
	params192 *params
	params256 *params
)

func init() {
	params128 = &params{
		n: 17669, n1: 46, n2: 384, n1n2: 17664,
		omega: 66, omegaE: 75, omegaR: 75,
		delta: 15, k: 16, g: 31, fft: 4,
		m: 8, gfPoly: 0x11D, seedLen: 32, saltLen: 16,
		nMu: 243079, rejectionThreshold: 16767881, securityBytes: 16,
		rsPolyCoefs: []uint8{89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1},
	}

	params192 = &params{
		n: 35851, n1: 56, n2: 640, n1n2: 35840,
		omega: 100, omegaE: 114, omegaR: 114,
		delta: 16, k: 24, g: 33, fft: 5,
		m: 8, gfPoly: 0x11D, seedLen: 32, saltLen: 16,
		nMu: 119800, rejectionThreshold: 16742417, securityBytes: 24,
		rsPolyCoefs: []uint8{45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1},
	}

	params256 = &params{
		n: 57637, n1: 90, n2: 640, n1n2: 57600,
		omega: 131, omegaE: 149, omegaR: 149,
		delta: 29, k: 32, g: 59, fft: 5,
		m: 8, gfPoly: 0x11D, seedLen: 32, saltLen: 16,
		nMu: 74517, rejectionThreshold: 16772367, securityBytes: 32,
		rsPolyCoefs: []uint8{49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1},
	}

	// Compute derived fields and validate all three param sets.
	for _, p := range []*params{params128, params192, params256} {
		initDerived(p)
		validateParams(p)
	}
}

func initDerived(p *params) {
	p.vecNSize64 = ceilDiv(p.n, 64)
	p.vecN1N2Size64 = ceilDiv(p.n1n2, 64)
	p.vecNSizeBytes = ceilDiv(p.n, 8)
	p.vecN1N2SizeBytes = ceilDiv(p.n1n2, 8)

	nbits := p.n % 64
	if nbits == 0 {
		p.redMask = ^uint64(0)
	} else {
		p.redMask = (1 << nbits) - 1
	}

	p.multiplicity = uint16(ceilDiv(uint32(p.n2), 128))

	// RS/RM byte-count sizes.
	p.vecKSizeBytes = uint32(p.k)
	p.vecN1SizeBytes = p.n1
	p.vecKSize64 = ceilDiv(uint32(p.k), 8)
	p.vecN1Size64 = ceilDiv(p.n1, 8)

	// Compute alpha_ij_pow[i][j] = gfExp[((i+1)*(j+1)) % 255].
	rows := int(2 * p.delta)
	cols := int(p.n1 - 1)
	p.alphaIjPow = make([][]uint16, rows)
	for i := 0; i < rows; i++ {
		p.alphaIjPow[i] = make([]uint16, cols)
		for j := 0; j < cols; j++ {
			p.alphaIjPow[i][j] = gfExp[((i+1)*(j+1))%paramGFMulOrd]
		}
	}
}

func validateParams(p *params) {
	if p.n1*p.n2 != p.n1n2 {
		panic("hqc: n1*n2 != n1n2")
	}
	if p.g != 2*p.delta+1 {
		panic("hqc: g != 2*delta+1")
	}
	if p.n <= p.n1n2 {
		panic("hqc: n must be > n1n2")
	}
	if p.n%64 == 0 {
		panic("hqc: n must not be divisible by 64")
	}
	if (1 << p.fft) < uint16(p.delta)+1 {
		panic("hqc: (1<<fft) must be >= delta+1")
	}
	if uint16(len(p.rsPolyCoefs)) != p.g {
		panic("hqc: rsPolyCoefs length must equal g")
	}
	if p.seedLen != 32 {
		panic("hqc: seedLen must be 32")
	}

	// Verify nMu = floor(2^32 / n).
	expectedNMu := uint32(uint64(1<<32) / uint64(p.n))
	if p.nMu != expectedNMu {
		panic("hqc: nMu does not match floor(2^32 / n)")
	}

	// Verify rejectionThreshold = floor(2^24 / n) * n.
	expectedThresh := uint32((uint64(1<<24) / uint64(p.n)) * uint64(p.n))
	if p.rejectionThreshold != expectedThresh {
		panic("hqc: rejectionThreshold does not match floor(2^24 / n) * n")
	}

	// Verify securityBytes matches k (current invariant).
	if p.securityBytes != p.k {
		panic("hqc: securityBytes must equal k")
	}

	// Verify alpha_ij_pow dimensions.
	if len(p.alphaIjPow) != int(2*p.delta) {
		panic("hqc: alphaIjPow row count != 2*delta")
	}
	for i := range p.alphaIjPow {
		if len(p.alphaIjPow[i]) != int(p.n1-1) {
			panic("hqc: alphaIjPow column count != n1-1")
		}
	}
}
