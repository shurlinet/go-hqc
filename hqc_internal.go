package hqc

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"io"
	"sync"
)

// Domain separation bytes (v5.0.0 symmetric.h).
const (
	gFctDomain = 0 // hash_g: SHA3-512
	hFctDomain = 1 // hash_h: SHA3-256
	iFctDomain = 2 // hash_i: SHA3-512
	jFctDomain = 3 // hash_j: SHA3-256
)

// hashG computes G(h_ek, m, salt) = SHA3-512(h_ek || m || salt || domain=0).
// Returns 64 bytes: K = output[0:32], theta = output[32:64].
func hashG(p *params, hEK, m, salt []byte) [64]byte {
	h := sha3.New512()
	h.Write(hEK)
	h.Write(m)
	h.Write(salt)
	h.Write([]byte{gFctDomain})
	var out [64]byte
	result := h.Sum(nil)
	if len(result) != 64 {
		panic("hqc: SHA3-512 produced wrong output length")
	}
	copy(out[:], result)
	return out
}

// hashH computes H(pk) = SHA3-256(pk || domain=1).
// Returns 32 bytes. Compresses the full public key to a fixed-size hash.
func hashH(pk []byte) [32]byte {
	h := sha3.New256()
	h.Write(pk)
	h.Write([]byte{hFctDomain})
	var out [32]byte
	result := h.Sum(nil)
	if len(result) != 32 {
		panic("hqc: SHA3-256 produced wrong output length")
	}
	copy(out[:], result)
	return out
}

// hashI computes I(seed) = SHA3-512(seed || domain=2).
// Returns 64 bytes: seed_dk = output[0:32], seed_ek = output[32:64].
func hashI(seed []byte) [64]byte {
	h := sha3.New512()
	h.Write(seed)
	h.Write([]byte{iFctDomain})
	var out [64]byte
	result := h.Sum(nil)
	if len(result) != 64 {
		panic("hqc: SHA3-512 produced wrong output length")
	}
	copy(out[:], result)
	return out
}

// hashJ computes J(h_ek, sigma, u_bytes, v_bytes, salt) = SHA3-256(...||domain=3).
// Returns 32 bytes. This is the rejection key hash for implicit rejection.
func hashJ(p *params, hEK, sigma, uBytes, vBytes, salt []byte) [32]byte {
	h := sha3.New256()
	h.Write(hEK)
	h.Write(sigma)
	h.Write(uBytes)
	h.Write(vBytes)
	h.Write(salt)
	h.Write([]byte{jFctDomain})
	var out [32]byte
	result := h.Sum(nil)
	if len(result) != 32 {
		panic("hqc: SHA3-256 produced wrong output length")
	}
	copy(out[:], result)
	return out
}

// encapsulationKey holds the parsed public key data (immutable after construction).
type encapsulationKey struct {
	p    *params
	h    []uint64 // cached from seed_ek
	s    []uint64 // loaded from pk bytes
	hEK  [32]byte // H(pk) cached at parse time
	pk   []byte   // full serialized public key
}

// decapsulationKey holds the parsed secret key data.
type decapsulationKey struct {
	p       *params
	seedDK  []byte   // seed_dk (32 bytes, derived from seed_pke via hash_i)
	sigma   []byte   // FO rejection key (securityBytes)
	seedKem []byte   // seed_kem (32 bytes, root seed)
	y       []uint64 // secret vector y (only y needed for decrypt)
	x       []uint64 // secret vector x (for consistency check)
	ek      *encapsulationKey
	sk      []byte // full serialized secret key

	mu        sync.RWMutex
	destroyed bool
}

// generateKey creates a new keypair from the given randomness source.
// v5.0.0 keygen: single 32-byte seed_kem -> XOF -> seed_pke, sigma -> hash_i -> seed_dk, seed_ek.
func generateKey(p *params, randSource io.Reader) (*decapsulationKey, error) {
	if p == nil {
		panic("hqc: nil params")
	}

	// Single 32-byte random draw for seed_kem.
	seedKem := make([]byte, p.seedLen)
	if _, err := io.ReadFull(randSource, seedKem); err != nil {
		panic("hqc: system entropy unavailable: " + err.Error())
	}

	// XOF(seed_kem || domain=1) -> squeeze seed_pke[32], sigma[securityBytes].
	kemXOF := newSeedExpander(seedKem)
	seedPKE := make([]byte, p.seedLen)
	kemXOF.Read(seedPKE)
	sigma := make([]byte, p.securityBytes)
	kemXOF.Read(sigma)
	kemXOF.Release()

	// PKE keygen from seed_pke.
	pk, seedDK := hqcPKEKeygen(p, seedPKE)

	// SK = pk || seed_dk || sigma || seed_kem
	sk := make([]byte, len(pk)+int(p.seedLen)+int(p.securityBytes)+int(p.seedLen))
	copy(sk, pk)
	copy(sk[len(pk):], seedDK)
	copy(sk[len(pk)+int(p.seedLen):], sigma)
	copy(sk[len(pk)+int(p.seedLen)+int(p.securityBytes):], seedKem)

	ZeroBytes(seedPKE)

	return parseDecapsulationKeyInternal(p, sk)
}

// newDecapsulationKeyFromSeed creates a key from a 32-byte seed_kem.
func newDecapsulationKeyFromSeed(p *params, seed []byte) (*decapsulationKey, error) {
	if p == nil {
		panic("hqc: nil params")
	}
	if len(seed) != int(p.seedLen) {
		return nil, ErrInvalidKeySize
	}

	// Replay seed_kem as deterministic randomness.
	rng := &bytesReader{data: seed}
	return generateKey(p, rng)
}

// bytesReader is a simple io.Reader that reads from a byte slice once.
type bytesReader struct {
	data []byte
	off  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// parseDecapsulationKeyInternal parses sk bytes, validates consistency.
// v5.0.0 SK layout: pk || seed_dk || sigma || seed_kem.
func parseDecapsulationKeyInternal(p *params, sk []byte) (*decapsulationKey, error) {
	pkLen := int(p.seedLen + p.vecNSizeBytes)
	expectedSK := pkLen + int(p.seedLen) + int(p.securityBytes) + int(p.seedLen)
	if len(sk) != expectedSK {
		return nil, ErrInvalidKeySize
	}

	// Parse fields from SK.
	pkBytes := sk[:pkLen]
	seedDK := make([]byte, p.seedLen)
	copy(seedDK, sk[pkLen:pkLen+int(p.seedLen)])
	sigma := make([]byte, p.securityBytes)
	copy(sigma, sk[pkLen+int(p.seedLen):pkLen+int(p.seedLen)+int(p.securityBytes)])
	seedKem := make([]byte, p.seedLen)
	copy(seedKem, sk[pkLen+int(p.seedLen)+int(p.securityBytes):])

	// Build encapsulation key from pk bytes.
	ek, err := parseEncapsulationKeyInternal(p, pkBytes)
	if err != nil {
		ZeroBytes(seedDK)
		ZeroBytes(sigma)
		ZeroBytes(seedKem)
		return nil, err
	}

	// Regenerate y and x from seed_dk for consistency check.
	y := make([]uint64, p.vecNSize64)
	x := make([]uint64, p.vecNSize64)
	dkXOF := newSeedExpander(seedDK)
	sampleFixedWeightKeygen(p, dkXOF, y, p.omega)
	sampleFixedWeightKeygen(p, dkXOF, x, p.omega)
	dkXOF.Release()

	// Consistency check: s == x + y*h.
	s2 := make([]uint64, p.vecNSize64)
	polyMul(p, s2, y, ek.h)
	polyAdd(s2, x, s2, int(p.vecNSize64))

	if constantTimeEqualUint64(s2, ek.s, int(p.vecNSize64)) != 1 {
		ZeroBytes(seedDK)
		ZeroBytes(sigma)
		ZeroBytes(seedKem)
		ZeroUint64s(x)
		ZeroUint64s(y)
		ZeroUint64s(s2)
		return nil, ErrKeyMismatch
	}
	ZeroUint64s(s2)

	skCopy := make([]byte, len(sk))
	copy(skCopy, sk)

	return &decapsulationKey{
		p:       p,
		seedDK:  seedDK,
		sigma:   sigma,
		seedKem: seedKem,
		x:       x,
		y:       y,
		ek:      ek,
		sk:      skCopy,
	}, nil
}

// parseEncapsulationKeyInternal parses pk bytes into an encapsulationKey.
// Caches H(pk) at parse time for constant-time encaps/decaps.
func parseEncapsulationKeyInternal(p *params, pk []byte) (*encapsulationKey, error) {
	expectedSize := int(p.seedLen + p.vecNSizeBytes)
	if len(pk) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	seedEK := pk[:p.seedLen]
	h := make([]uint64, p.vecNSize64)
	s := make([]uint64, p.vecNSize64)

	// Regenerate h from seed_ek via XOF.
	ekXOF := newSeedExpander(seedEK)
	sampleRandomVector(p, ekXOF, h)
	ekXOF.Release()

	// Load s from pk bytes.
	load8Arr(s[:p.vecNSize64], pk[p.seedLen:p.seedLen+p.vecNSizeBytes])

	pkCopy := make([]byte, len(pk))
	copy(pkCopy, pk)

	// Cache H(pk) at parse time.
	hEK := hashH(pkCopy)

	return &encapsulationKey{
		p:   p,
		h:   h,
		s:   s,
		hEK: hEK,
		pk:  pkCopy,
	}, nil
}

// encapsulate performs KEM encapsulation.
// v5.0.0: G(H(pk), m, salt) -> K[32] || theta[32]. SS = K (first 32 bytes of G).
func encapsulate(p *params, ek *encapsulationKey, randSource io.Reader) (ct, ss []byte) {
	secBytes := int(p.securityBytes)
	saltBytes := int(p.saltLen)

	m := make([]byte, secBytes)
	salt := make([]byte, saltBytes)

	// Generate m first, then salt (matches v5.0.0 C ordering).
	if _, err := io.ReadFull(randSource, m); err != nil {
		panic("hqc: system entropy unavailable: " + err.Error())
	}
	if _, err := io.ReadFull(randSource, salt); err != nil {
		panic("hqc: system entropy unavailable: " + err.Error())
	}

	u := make([]uint64, p.vecNSize64)
	v := make([]uint64, p.vecNSize64) // full N-size for intermediate computation

	defer func() {
		ZeroBytes(m)
		ZeroUint64s(u)
		ZeroUint64s(v)
	}()

	// G(H(pk), m, salt) -> 64 bytes: K = first 32, theta = second 32.
	kTheta := hashG(p, ek.hEK[:], m, salt)
	K := kTheta[:32]
	theta := kTheta[32:]

	// Encrypt using cached h, s.
	hqcPKEEncryptCached(p, u, v, m, theta, ek.h, ek.s)

	// Ciphertext: store8(u) || store8(v)[truncated to n1n2 bytes] || salt.
	ctLen := int(p.vecNSizeBytes) + int(p.vecN1N2SizeBytes) + saltBytes
	ct = make([]byte, ctLen)
	store8Arr(ct[:p.vecNSizeBytes], u[:p.vecNSize64])
	store8Arr(ct[p.vecNSizeBytes:p.vecNSizeBytes+p.vecN1N2SizeBytes], v[:p.vecN1N2Size64])
	copy(ct[p.vecNSizeBytes+p.vecN1N2SizeBytes:], salt)

	// Shared secret = K (first 32 bytes of G output).
	ss = make([]byte, 32)
	copy(ss, K)

	ZeroBytes(kTheta[:])
	return ct, ss
}

// decapsulate performs KEM decapsulation with FO transform.
// Always returns a 32-byte shared secret (implicit rejection via sigma).
func decapsulate(p *params, dk *decapsulationKey, ct []byte) ([]byte, error) {
	dk.mu.RLock()
	if dk.destroyed {
		dk.mu.RUnlock()
		return nil, ErrDestroyed
	}
	defer dk.mu.RUnlock()

	ctLen := int(p.vecNSizeBytes + p.vecN1N2SizeBytes + uint32(p.saltLen))
	if len(ct) != ctLen {
		return nil, ErrInvalidCiphertextSize
	}

	secBytes := int(p.securityBytes)
	saltBytes := int(p.saltLen)

	// Parse ciphertext: u, v, salt.
	u := make([]uint64, p.vecNSize64)
	v := make([]uint64, p.vecN1N2Size64)
	salt := make([]byte, saltBytes)

	load8Arr(u, ct[:p.vecNSizeBytes])
	load8Arr(v, ct[p.vecNSizeBytes:p.vecNSizeBytes+p.vecN1N2SizeBytes])
	copy(salt, ct[p.vecNSizeBytes+p.vecN1N2SizeBytes:])

	// Decrypt using cached y vector.
	m := make([]byte, secBytes)
	hqcPKEDecryptCached(p, m, dk.y, u, v)

	u2 := make([]uint64, p.vecNSize64)
	v2 := make([]uint64, p.vecNSize64) // full N-size

	defer func() {
		ZeroBytes(m)
		ZeroUint64s(u2)
		ZeroUint64s(v2)
	}()

	// G(H(pk), m', salt) -> K' || theta'.
	kThetaPrime := hashG(p, dk.ek.hEK[:], m, salt)
	KPrime := kThetaPrime[:32]
	thetaPrime := kThetaPrime[32:]

	// Re-encrypt with decrypted m using cached h, s.
	hqcPKEEncryptCached(p, u2, v2, m, thetaPrime, dk.ek.h, dk.ek.s)

	// FO comparison: u, v, AND salt (3 comparisons, all constant-time).
	// Serialize u2, v2 for byte-level comparison matching the C pattern.
	u2Bytes := make([]byte, p.vecNSizeBytes)
	v2Bytes := make([]byte, p.vecN1N2SizeBytes)
	store8Arr(u2Bytes, u2[:p.vecNSize64])
	vectTruncate(p, v2)
	store8Arr(v2Bytes, v2[:p.vecN1N2Size64])

	uCTBytes := ct[:p.vecNSizeBytes]
	vCTBytes := ct[p.vecNSizeBytes : p.vecNSizeBytes+p.vecN1N2SizeBytes]
	saltCT := ct[p.vecNSizeBytes+p.vecN1N2SizeBytes:]

	// Copy salt from ct for re-encryption comparison.
	salt2 := make([]byte, saltBytes)
	copy(salt2, salt)

	var result uint8
	result |= vectCompare(uCTBytes, u2Bytes, int(p.vecNSizeBytes))
	result |= vectCompare(vCTBytes, v2Bytes, int(p.vecN1N2SizeBytes))
	result |= vectCompare(saltCT, salt2, saltBytes)

	// result: 0 = all match (success), nonzero = mismatch (failure).
	// After -= 1: 0xFF (success), some other value (failure).
	result -= 1

	// Rejection key: J(H(pk), sigma, u, v, salt).
	KBar := hashJ(p, dk.ek.hEK[:], dk.sigma, uCTBytes, vCTBytes, saltCT)

	// Constant-time select: K' if success, K_bar if failure.
	selectBit := int(result & 1) // 1 = success, 0 = failure
	ss := make([]byte, 32)
	for i := 0; i < 32; i++ {
		ss[i] = byte(subtle.ConstantTimeSelect(selectBit, int(KPrime[i]), int(KBar[i])))
	}

	ZeroBytes(kThetaPrime[:])
	ZeroBytes(u2Bytes)
	ZeroBytes(v2Bytes)
	ZeroBytes(KBar[:])

	return ss, nil
}

// destroy zeroes all secret material in the decapsulation key.
func (dk *decapsulationKey) destroy() {
	dk.mu.Lock()
	defer dk.mu.Unlock()

	if dk.destroyed {
		return
	}

	ZeroBytes(dk.seedDK)
	ZeroBytes(dk.sigma)
	ZeroBytes(dk.seedKem)
	ZeroUint64s(dk.x)
	ZeroUint64s(dk.y)
	ZeroBytes(dk.sk)
	dk.destroyed = true
}

// generateKeyFromRand is used by GenerateKeyNNN() functions.
func generateKeyFromRand(p *params) (*decapsulationKey, error) {
	return generateKey(p, rand.Reader)
}

// Version returns the specification version this implementation conforms to.
func Version() string {
	return "v5.0.0"
}
