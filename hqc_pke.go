package hqc

// HQC-PKE IND-CPA scheme: keygen, encrypt, decrypt.
// Internal functions only. The public API is in hqc128.go/192/256.

// hqcPKEKeygen generates a PKE keypair from seed_pke.
// v5.0.0: hash_i(seed_pke) -> keypair_seed[64] = seed_dk[32] || seed_ek[32].
// Returns serialized pk and seed_dk.
func hqcPKEKeygen(p *params, seedPKE []byte) (pk []byte, seedDK []byte) {
	// hash_i: SHA3-512(seed_pke || domain=2) -> 64 bytes.
	keypairSeed := hashI(seedPKE)
	seedDKLocal := keypairSeed[:32]
	seedEK := keypairSeed[32:]

	x := make([]uint64, p.vecNSize64)
	y := make([]uint64, p.vecNSize64)
	h := make([]uint64, p.vecNSize64)
	s := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroUint64s(x)
		ZeroUint64s(y)
		ZeroBytes(keypairSeed[:])
	}()

	// Secret key vectors from seed_dk: y FIRST, then x (v5.0.0 order).
	dkXOF := newSeedExpander(seedDKLocal)
	sampleFixedWeightKeygen(p, dkXOF, y, p.omega)
	sampleFixedWeightKeygen(p, dkXOF, x, p.omega)
	dkXOF.Release()

	// Public key: h from seed_ek, s = x + y*h.
	ekXOF := newSeedExpander(seedEK)
	sampleRandomVector(p, ekXOF, h)
	ekXOF.Release()

	polyMul(p, s, y, h)
	polyAdd(s, x, s, int(p.vecNSize64))

	// pk = seed_ek || store8(s)
	pk = make([]byte, int(p.seedLen)+int(p.vecNSizeBytes))
	copy(pk[:p.seedLen], seedEK)
	store8Arr(pk[p.seedLen:], s[:p.vecNSize64])

	// Return seed_dk for inclusion in SK.
	seedDK = make([]byte, 32)
	copy(seedDK, seedDKLocal)

	return pk, seedDK
}

// hqcPKEEncryptCached encrypts using pre-parsed h, s vectors.
// theta is 32 bytes (seed for the encryption XOF).
// v5.0.0 sampling order: r2, e, r1 (NOT r1, r2, e).
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

	vecSE := newSeedExpander(theta[:p.seedLen])
	defer vecSE.Release()

	// v5.0.0 sampling order: r2 FIRST, then e, then r1.
	sampleFixedWeightEncrypt(p, vecSE, r2, p.omegaR)
	sampleFixedWeightEncrypt(p, vecSE, e, p.omegaE)
	sampleFixedWeightEncrypt(p, vecSE, r1, p.omegaR)

	// u = r1 + r2*h
	polyMul(p, u, r2, h)
	polyAdd(u, r1, u, int(p.vecNSize64))

	// v = encode(m) + truncate(s*r2 + e)
	// Compute s*r2 + e in full N-bit space, then truncate to N1N2.
	polyMul(p, tmp2, r2, s)
	polyAdd(tmp2, e, tmp2, int(p.vecNSize64))

	// Encode m into N1N2-sized vector, expand to N bits for addition.
	codeEncode(p, v, m)
	vectResize(tmp1, p.n, v, p.n1n2)

	polyAdd(tmp2, tmp1, tmp2, int(p.vecNSize64))

	// Truncate result to N1N2 bits and store in v.
	// v is passed as vecNSize64 words to hold the full intermediate.
	vectTruncate(p, tmp2)
	copy(v[:p.vecN1N2Size64], tmp2[:p.vecN1N2Size64])
}

// hqcPKEDecryptCached decrypts a ciphertext (u, v) using pre-cached y vector.
func hqcPKEDecryptCached(p *params, m []byte, y, u, v []uint64) {
	tmp1 := make([]uint64, p.vecNSize64)
	tmp2 := make([]uint64, p.vecNSize64)

	defer func() {
		ZeroUint64s(tmp1)
		ZeroUint64s(tmp2)
	}()

	// tmp1 = u*y (full N-bit product).
	polyMul(p, tmp1, y, u)
	// Truncate to N1N2 bits.
	vectTruncate(p, tmp1)
	// tmp2 = v - truncate(u*y) (XOR in GF(2)).
	polyAdd(tmp2, v, tmp1, int(p.vecN1N2Size64))

	// Decode to recover m.
	codeDecode(p, m, tmp2)
}
