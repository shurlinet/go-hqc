package hqc

// HQC-PKE IND-CPA scheme: keygen, encrypt, decrypt.
// Internal functions only. The public API is in hqc128.go/192/256.

// hqcPKEKeygen generates a PKE keypair.
// Returns serialized pk and sk byte slices.
// rand is used for sk_seed (40), sigma (vecKSizeBytes), pk_seed (40).
func hqcPKEKeygen(p *params, randReader func([]byte)) (pk, sk []byte) {
	seedLen := uint32(p.seedLen)
	vecKBytes := p.vecKSizeBytes

	skSeed := make([]byte, seedLen)
	sigma := make([]byte, vecKBytes)
	pkSeed := make([]byte, seedLen)

	x := make([]uint64, p.vecNSize64)
	y := make([]uint64, p.vecNSize64)
	h := make([]uint64, p.vecNSize64)
	s := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroBytes(skSeed)
		ZeroBytes(sigma)
		ZeroUint64s(x)
		ZeroUint64s(y)
	}()

	// Generate randomness: sk_seed first, sigma second, pk_seed third.
	randReader(skSeed)
	randReader(sigma)
	skSE := newSeedExpander(skSeed)
	defer skSE.Release()

	randReader(pkSeed)
	pkSE := newSeedExpander(pkSeed)
	defer pkSE.Release()

	// Secret key vectors: x then y from sk_seedexpander (order matters for SHAKE state).
	sampleFixedWeightVector(p, skSE, x, p.omega)
	sampleFixedWeightVector(p, skSE, y, p.omega)

	// Public key: h from pk_seedexpander, s = x + y*h.
	sampleRandomVector(p, pkSE, h)
	polyMul(p, s, y, h)
	polyAdd(s, x, s, int(p.vecNSize64))

	// Serialize: pk first because sk embeds a copy of pk.
	pk = make([]byte, seedLen+p.vecNSizeBytes)
	copy(pk[:seedLen], pkSeed)
	store8Arr(pk[seedLen:], s[:p.vecNSize64])

	sk = make([]byte, seedLen+vecKBytes+uint32(len(pk)))
	copy(sk, skSeed)
	copy(sk[seedLen:], sigma)
	copy(sk[seedLen+vecKBytes:], pk)

	return pk, sk
}

// hqcPKEEncryptCached encrypts using pre-parsed h, s vectors.
// theta must be at least seedLen bytes (only the first seedLen bytes are used).
// Avoids re-parsing pk bytes when h, s are already cached.
func hqcPKEEncryptCached(p *params, u, v []uint64, m, theta []byte, h, s []uint64) {
	if len(theta) < int(p.seedLen) {
		panic("hqc: theta too short for seedexpander")
	}
	r1 := make([]uint64, p.vecNSize64)
	r2 := make([]uint64, p.vecNSize64)
	e := make([]uint64, p.vecNSize64)
	tmp1 := make([]uint64, p.vecNSize64)
	tmp2 := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroUint64s(r1)
		ZeroUint64s(r2)
		ZeroUint64s(e)
		ZeroUint64s(tmp1)
		ZeroUint64s(tmp2)
	}()

	vecSE := newSeedExpander(theta[:uint32(p.seedLen)])
	defer vecSE.Release()

	// Sample r1, r2, e in that exact order (SHAKE state consumed sequentially).
	sampleFixedWeightVector(p, vecSE, r1, p.omegaR)
	sampleFixedWeightVector(p, vecSE, r2, p.omegaR)
	sampleFixedWeightVector(p, vecSE, e, p.omegaE)

	// u = r1 + r2*h
	polyMul(p, u, r2, h)
	polyAdd(u, r1, u, int(p.vecNSize64))

	// v = encode(m) expanded to N bits, + s*r2 + e, truncated back to N1N2 bits.
	codeEncode(p, v, m)
	vectResize(tmp1, p.n, v, p.n1n2)

	polyMul(p, tmp2, r2, s)
	polyAdd(tmp2, e, tmp2, int(p.vecNSize64))
	polyAdd(tmp2, tmp1, tmp2, int(p.vecNSize64))
	vectResize(v, p.n1n2, tmp2, p.n)
}

// hqcPKEDecryptCached decrypts a ciphertext (u, v) using pre-cached y vector.
// sigma is copied from the caller's cached sigma (not re-parsed from sk).
// This avoids regenerating x, y from sk_seed on every Decapsulate call.
func hqcPKEDecryptCached(p *params, m []byte, y, u, v []uint64) {
	tmp1 := make([]uint64, p.vecNSize64)
	tmp2 := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroUint64s(tmp1)
		ZeroUint64s(tmp2)
	}()

	// Compute v - u*y (in GF(2), subtraction = addition = XOR).
	vectResize(tmp1, p.n, v, p.n1n2)
	polyMul(p, tmp2, y, u)
	polyAdd(tmp2, tmp1, tmp2, int(p.vecNSize64))

	// Decode to recover m.
	codeDecode(p, m, tmp2)
}

// hqcPublicKeyFromBytes parses a public key: regenerates h from pk_seed,
// loads s from the remaining bytes.
func hqcPublicKeyFromBytes(p *params, h, s []uint64, pk []byte) {
	sl := uint32(p.seedLen)
	pkSE := newSeedExpander(pk[:sl])
	sampleRandomVector(p, pkSE, h)
	pkSE.Release()

	load8Arr(s[:p.vecNSize64], pk[sl:sl+p.vecNSizeBytes])
}

// hqcSecretKeyFromBytes parses a secret key: extracts sigma, regenerates x and y
// from sk_seed, copies embedded pk.
func hqcSecretKeyFromBytes(p *params, x, y []uint64, sigma, pk []byte, sk []byte) {
	sl := uint32(p.seedLen)
	vk := p.vecKSizeBytes

	// Extract sigma before seedexpander init (sigma is at a fixed offset, not derived from SHAKE).
	copy(sigma, sk[sl:sl+vk])

	skSE := newSeedExpander(sk[:sl])
	sampleFixedWeightVector(p, skSE, x, p.omega)
	sampleFixedWeightVector(p, skSE, y, p.omega)
	skSE.Release()

	copy(pk, sk[sl+vk:])
}
