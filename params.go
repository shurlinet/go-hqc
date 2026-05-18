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
	seedLen uint16 // seed byte length (always 40)
	saltLen uint16 // salt byte length (always 16)

	// Derived sizes (computed at init)
	vecNSize64      uint32 // ceil(n / 64)
	vecN1N2Size64   uint32 // ceil(n1n2 / 64)
	vecNSizeBytes   uint32 // ceil(n / 8)
	vecN1N2SizeBytes uint32 // ceil(n1n2 / 8)
	redMask         uint64 // bitmask for top word: (1 << (n%64)) - 1
	multiplicity    uint16 // ceil(n2 / 128), RM repetition count

	// Barrett reduction table for fixed-weight sampling
	mVal []uint32

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
		m: 8, gfPoly: 0x11D, seedLen: 40, saltLen: 16,
		mVal: []uint32{243079, 243093, 243106, 243120, 243134, 243148, 243161, 243175, 243189, 243203, 243216, 243230, 243244, 243258, 243272, 243285, 243299, 243313, 243327, 243340, 243354, 243368, 243382, 243396, 243409, 243423, 243437, 243451, 243465, 243478, 243492, 243506, 243520, 243534, 243547, 243561, 243575, 243589, 243603, 243616, 243630, 243644, 243658, 243672, 243686, 243699, 243713, 243727, 243741, 243755, 243769, 243782, 243796, 243810, 243824, 243838, 243852, 243865, 243879, 243893, 243907, 243921, 243935, 243949, 243962, 243976, 243990, 244004, 244018, 244032, 244046, 244059, 244073, 244087, 244101},
		rsPolyCoefs: []uint8{89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1},
	}

	params192 = &params{
		n: 35851, n1: 56, n2: 640, n1n2: 35840,
		omega: 100, omegaE: 114, omegaR: 114,
		delta: 16, k: 24, g: 33, fft: 5,
		m: 8, gfPoly: 0x11D, seedLen: 40, saltLen: 16,
		mVal: []uint32{119800, 119803, 119807, 119810, 119813, 119817, 119820, 119823, 119827, 119830, 119833, 119837, 119840, 119843, 119847, 119850, 119853, 119857, 119860, 119864, 119867, 119870, 119874, 119877, 119880, 119884, 119887, 119890, 119894, 119897, 119900, 119904, 119907, 119910, 119914, 119917, 119920, 119924, 119927, 119930, 119934, 119937, 119941, 119944, 119947, 119951, 119954, 119957, 119961, 119964, 119967, 119971, 119974, 119977, 119981, 119984, 119987, 119991, 119994, 119997, 120001, 120004, 120008, 120011, 120014, 120018, 120021, 120024, 120028, 120031, 120034, 120038, 120041, 120044, 120048, 120051, 120054, 120058, 120061, 120065, 120068, 120071, 120075, 120078, 120081, 120085, 120088, 120091, 120095, 120098, 120101, 120105, 120108, 120112, 120115, 120118, 120122, 120125, 120128, 120132, 120135, 120138, 120142, 120145, 120149, 120152, 120155, 120159, 120162, 120165, 120169, 120172, 120175, 120179},
		rsPolyCoefs: []uint8{45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1},
	}

	params256 = &params{
		n: 57637, n1: 90, n2: 640, n1n2: 57600,
		omega: 131, omegaE: 149, omegaR: 149,
		delta: 29, k: 32, g: 59, fft: 5,
		m: 8, gfPoly: 0x11D, seedLen: 40, saltLen: 16,
		mVal: []uint32{74517, 74518, 74520, 74521, 74522, 74524, 74525, 74526, 74527, 74529, 74530, 74531, 74533, 74534, 74535, 74536, 74538, 74539, 74540, 74542, 74543, 74544, 74545, 74547, 74548, 74549, 74551, 74552, 74553, 74555, 74556, 74557, 74558, 74560, 74561, 74562, 74564, 74565, 74566, 74567, 74569, 74570, 74571, 74573, 74574, 74575, 74577, 74578, 74579, 74580, 74582, 74583, 74584, 74586, 74587, 74588, 74590, 74591, 74592, 74593, 74595, 74596, 74597, 74599, 74600, 74601, 74602, 74604, 74605, 74606, 74608, 74609, 74610, 74612, 74613, 74614, 74615, 74617, 74618, 74619, 74621, 74622, 74623, 74625, 74626, 74627, 74628, 74630, 74631, 74632, 74634, 74635, 74636, 74637, 74639, 74640, 74641, 74643, 74644, 74645, 74647, 74648, 74649, 74650, 74652, 74653, 74654, 74656, 74657, 74658, 74660, 74661, 74662, 74663, 74665, 74666, 74667, 74669, 74670, 74671, 74673, 74674, 74675, 74676, 74678, 74679, 74680, 74682, 74683, 74684, 74685, 74687, 74688, 74689, 74691, 74692, 74693, 74695, 74696, 74697, 74698, 74700, 74701, 74702, 74704, 74705, 74706, 74708, 74709},
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
	if uint32(len(p.mVal)) != uint32(p.omegaR) {
		panic("hqc: mVal length must equal omegaR")
	}
	if uint16(len(p.rsPolyCoefs)) != p.g {
		panic("hqc: rsPolyCoefs length must equal g")
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

	// Verify ALL mVal entries match floor(2^32 / (n-i)).
	// FLOOR division, not ceil. Using ceil would cause Barrett quotient overshoot,
	// producing negative remainders that cond_sub cannot fix.
	for i := 0; i < len(p.mVal); i++ {
		expected := uint32(uint64(1<<32) / uint64(p.n-uint32(i)))
		if p.mVal[i] != expected {
			panic("hqc: mVal[i] does not match floor(2^32 / (n-i))")
		}
	}
}
