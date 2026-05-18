package hqc

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"sync"

	"github.com/shurlinet/go-hqc/internal/shake"
)

// Domain separation bytes (domains.h).
const (
	gFctDomain = 3
	kFctDomain = 4
)

// shake256_512DS absorbs input + domain byte, squeezes exactly 64 bytes.
// Panics if output is not exactly 64 bytes (SHA3-512 produces 64 bytes).
func shake256_512DS(output, input []byte, domain byte) {
	if len(output) != 64 {
		panic("hqc: shake256_512DS output must be exactly 64 bytes")
	}
	st := shake.New256()
	st.Write(input)
	st.Write([]byte{domain})
	n, _ := st.Read(output)
	if n != 64 {
		panic("hqc: SHAKE256 short read in shake256_512DS")
	}
	st.Reset()
}

// encapsulationKey holds the parsed public key data (immutable after construction).
type encapsulationKey struct {
	p      *params
	h      []uint64 // cached from pk_seed
	s      []uint64 // loaded from pk bytes
	pkSeed []byte   // raw pk_seed (seedLen bytes)
	pk     []byte   // full serialized public key
}

// decapsulationKey holds the parsed secret key data.
type decapsulationKey struct {
	p       *params
	skSeed  []byte   // sk_seed (seedLen bytes)
	sigma   []byte   // FO rejection key (vecKSizeBytes)
	x       []uint64 // secret vector x
	y       []uint64 // secret vector y
	ek      *encapsulationKey
	sk      []byte // full serialized secret key
	seed    []byte // compact seed (96 bytes: sk_seed || sigma || pk_seed)

	mu        sync.RWMutex
	destroyed bool
}

// generateKey creates a new keypair from the given randomness source.
func generateKey(p *params, randSource io.Reader) (*decapsulationKey, error) {
	if p == nil {
		panic("hqc: nil params")
	}

	readRand := func(buf []byte) {
		if _, err := io.ReadFull(randSource, buf); err != nil {
			panic("hqc: system entropy unavailable: " + err.Error())
		}
	}

	_, sk := hqcPKEKeygen(p, readRand)

	return parseDecapsulationKeyInternal(p, sk)
}

// newDecapsulationKeyFromSeed creates a key from a deterministic 96-byte seed
// (sk_seed[40] || sigma[16..32] || pk_seed[40]).
func newDecapsulationKeyFromSeed(p *params, seed []byte) (*decapsulationKey, error) {
	if p == nil {
		panic("hqc: nil params")
	}
	expectedSeedSize := int(uint32(p.seedLen) + p.vecKSizeBytes + uint32(p.seedLen))
	if len(seed) != expectedSeedSize {
		return nil, ErrInvalidKeySize
	}

	// Use the seed bytes as the deterministic randomness source.
	offset := 0
	readRand := func(buf []byte) {
		copy(buf, seed[offset:offset+len(buf)])
		offset += len(buf)
	}

	_, sk := hqcPKEKeygen(p, readRand)

	return parseDecapsulationKeyInternal(p, sk)
}

// parseDecapsulationKeyInternal parses sk bytes, validates that the embedded pk matches sk_seed.
func parseDecapsulationKeyInternal(p *params, sk []byte) (*decapsulationKey, error) {
	sl := uint32(p.seedLen)
	expectedSK := int(sl + p.vecKSizeBytes + sl + p.vecNSizeBytes) // sk_seed + sigma + pk
	if len(sk) != expectedSK {
		return nil, ErrInvalidKeySize
	}

	skSeed := make([]byte, sl)
	sigma := make([]byte, p.vecKSizeBytes)
	x := make([]uint64, p.vecNSize64)
	y := make([]uint64, p.vecNSize64)
	embeddedPK := make([]byte, sl+p.vecNSizeBytes)

	// Parse the secret key.
	hqcSecretKeyFromBytes(p, x, y, sigma, embeddedPK, sk)
	copy(skSeed, sk[:sl])

	// Build the encapsulation key from the embedded pk.
	ek, err := parseEncapsulationKeyInternal(p, embeddedPK)
	if err != nil {
		ZeroBytes(skSeed)
		ZeroBytes(sigma)
		ZeroUint64s(x)
		ZeroUint64s(y)
		return nil, err
	}

	// Consistency check: verify s == x + y*h.
	// x, y are already derived from sk_seed above. Compute s' = x + y*h
	// and compare against the s embedded in the public key portion of sk.
	// This catches corrupted sk where the pk portion doesn't match sk_seed.
	s2 := make([]uint64, p.vecNSize64)
	polyMul(p, s2, y, ek.h)
	polyAdd(s2, x, s2, int(p.vecNSize64))

	if constantTimeEqualUint64(s2, ek.s, int(p.vecNSize64)) != 1 {
		ZeroBytes(skSeed)
		ZeroBytes(sigma)
		ZeroUint64s(x)
		ZeroUint64s(y)
		ZeroUint64s(s2)
		return nil, ErrKeyMismatch
	}

	ZeroUint64s(s2)

	// Build compact seed.
	seedSize := int(sl + p.vecKSizeBytes + sl)
	compactSeed := make([]byte, seedSize)
	copy(compactSeed, skSeed)
	copy(compactSeed[sl:], sigma)
	copy(compactSeed[sl+p.vecKSizeBytes:], ek.pkSeed)

	skCopy := make([]byte, len(sk))
	copy(skCopy, sk)

	return &decapsulationKey{
		p:      p,
		skSeed: skSeed,
		sigma:  sigma,
		x:      x,
		y:      y,
		ek:     ek,
		sk:     skCopy,
		seed:   compactSeed,
	}, nil
}

// parseEncapsulationKeyInternal parses pk bytes into an encapsulationKey.
func parseEncapsulationKeyInternal(p *params, pk []byte) (*encapsulationKey, error) {
	expectedSize := int(uint32(p.seedLen) + p.vecNSizeBytes)
	if len(pk) != expectedSize {
		return nil, ErrInvalidKeySize
	}

	psl := uint32(p.seedLen)
	pkSeed := make([]byte, psl)
	copy(pkSeed, pk[:psl])

	h := make([]uint64, p.vecNSize64)
	s := make([]uint64, p.vecNSize64)
	hqcPublicKeyFromBytes(p, h, s, pk)

	pkCopy := make([]byte, len(pk))
	copy(pkCopy, pk)

	return &encapsulationKey{
		p:      p,
		h:      h,
		s:      s,
		pkSeed: pkSeed,
		pk:     pkCopy,
	}, nil
}

// encapsulate performs KEM encapsulation using the given randomness source.
// Returns ciphertext and shared secret.
func encapsulate(p *params, ek *encapsulationKey, randSource io.Reader) (ct, ss []byte) {
	vecKBytes := int(p.vecKSizeBytes)
	pkBytes := int(uint32(p.seedLen) + p.vecNSizeBytes)
	saltBytes := int(p.saltLen)

	// tmp = m || pk || salt (for G hash input).
	tmpLen := vecKBytes + pkBytes + saltBytes
	tmp := make([]byte, tmpLen)
	m := tmp[:vecKBytes]
	salt := tmp[vecKBytes+pkBytes:]

	theta := make([]byte, 64)

	u := make([]uint64, p.vecNSize64)
	v := make([]uint64, p.vecN1N2Size64)

	// mc = m || store8(u) || store8(v) (for K hash input).
	mcLen := vecKBytes + int(p.vecNSizeBytes) + int(p.vecN1N2SizeBytes)
	mc := make([]byte, mcLen)

	defer func() {
		ZeroBytes(tmp)
		ZeroBytes(theta)
		ZeroBytes(mc[:vecKBytes]) // mc[0:16] contains m
		ZeroUint64s(u)           // public, but zero for consistency
		ZeroUint64s(v)
	}()

	// Generate m first, then salt (ordering matches the reference C implementation).
	if _, err := io.ReadFull(randSource, m); err != nil {
		panic("hqc: system entropy unavailable: " + err.Error())
	}
	if _, err := io.ReadFull(randSource, salt); err != nil {
		panic("hqc: system entropy unavailable: " + err.Error())
	}

	// Copy pk into tmp (between m and salt).
	copy(tmp[vecKBytes:], ek.pk)

	// theta = G(m || pk || salt) with domain byte 3.
	shake256_512DS(theta, tmp, gFctDomain)

	// Encrypt using cached h, s (avoids re-parsing pk).
	hqcPKEEncryptCached(p, u, v, m, theta, ek.h, ek.s)

	// Shared secret: K(m || store8(u) || store8(v)) with domain byte 4.
	copy(mc, m)
	store8Arr(mc[vecKBytes:vecKBytes+int(p.vecNSizeBytes)], u[:p.vecNSize64])
	store8Arr(mc[vecKBytes+int(p.vecNSizeBytes):], v[:p.vecN1N2Size64])

	ss = make([]byte, 64)
	shake256_512DS(ss, mc, kFctDomain)

	// Ciphertext: store8(u) || store8(v) || salt.
	ctLen := int(p.vecNSizeBytes) + int(p.vecN1N2SizeBytes) + saltBytes
	ct = make([]byte, ctLen)
	store8Arr(ct[:p.vecNSizeBytes], u[:p.vecNSize64])
	store8Arr(ct[p.vecNSizeBytes:p.vecNSizeBytes+p.vecN1N2SizeBytes], v[:p.vecN1N2Size64])
	copy(ct[p.vecNSizeBytes+p.vecN1N2SizeBytes:], salt)

	return ct, ss
}

// decapsulate performs KEM decapsulation with FO transform.
// Always returns a 64-byte shared secret (implicit rejection via sigma).
func decapsulate(p *params, dk *decapsulationKey, ct []byte) ([]byte, error) {
	dk.mu.RLock()
	if dk.destroyed {
		dk.mu.RUnlock()
		return nil, ErrDestroyed
	}
	// Hold read lock for the duration of decapsulation.
	defer dk.mu.RUnlock()

	ctLen := int(p.vecNSizeBytes + p.vecN1N2SizeBytes + uint32(p.saltLen))
	if len(ct) != ctLen {
		return nil, ErrInvalidCiphertextSize
	}

	vecKBytes := int(p.vecKSizeBytes)
	pkBytes := int(uint32(p.seedLen) + p.vecNSizeBytes)
	saltBytes := int(p.saltLen)

	// Parse ciphertext: u, v, salt.
	u := make([]uint64, p.vecNSize64)
	v := make([]uint64, p.vecN1N2Size64)
	salt := make([]byte, saltBytes)

	load8Arr(u, ct[:p.vecNSizeBytes])
	load8Arr(v, ct[p.vecNSizeBytes:p.vecNSizeBytes+p.vecN1N2SizeBytes])
	copy(salt, ct[p.vecNSizeBytes+p.vecN1N2SizeBytes:])

	// Decrypt using cached y vector (only y is needed; x is unused in decrypt).
	// sigma comes from dk.sigma (cached at key load time, not re-parsed).
	m := make([]byte, vecKBytes)
	hqcPKEDecryptCached(p, m, dk.y, u, v)

	// ALL allocations above this line. Below uses defer for panic-safe zeroing.
	theta := make([]byte, 64)
	tmp := make([]byte, vecKBytes+pkBytes+saltBytes)
	u2 := make([]uint64, p.vecNSize64)
	v2 := make([]uint64, p.vecN1N2Size64)
	mcLen := vecKBytes + int(p.vecNSizeBytes) + int(p.vecN1N2SizeBytes)
	mc := make([]byte, mcLen)

	defer func() {
		ZeroBytes(m)
		ZeroBytes(theta)
		ZeroBytes(tmp)
		ZeroBytes(mc[:vecKBytes]) // mc[0:vecK] contains m or sigma
		ZeroUint64s(u2)
		ZeroUint64s(v2)
	}()

	// Compute theta = G(m || pk || salt).
	copy(tmp, m)
	copy(tmp[vecKBytes:], dk.ek.pk)
	copy(tmp[vecKBytes+pkBytes:], salt)
	shake256_512DS(theta, tmp, gFctDomain)

	// Re-encrypt with decrypted m using cached h, s (avoids re-parsing pk).
	hqcPKEEncryptCached(p, u2, v2, m, theta, dk.ek.h, dk.ek.s)

	// Compare u vs u2 and v vs v2 directly on uint64 words (constant-time).
	// Both u/u2 and v/v2 went through polyMul which applies RED_MASK to
	// the last word, so high bits are zero in both. Word-level comparison
	// is equivalent to the C reference vect_compare but avoids
	// serializing to temporary byte buffers.
	// constantTimeEqualUint64 returns 1=equal, 0=different.
	// We need 0=equal for the FO logic, so invert.
	uMatch := constantTimeEqualUint64(u, u2, int(p.vecNSize64))
	vMatch := constantTimeEqualUint64(v, v2, int(p.vecN1N2Size64))
	// result: 0 if both match, 1 if either differs.
	result := uint8(1 - (uMatch & vMatch))

	// result: 0 = both match (success), 1 = mismatch (failure).
	// After -= 1: 0xFF (success), 0x00 (failure).
	result -= 1

	// Constant-time select: mc = m if success, sigma if failure.
	// subtle.ConstantTimeSelect(v, x, y) returns x if v==1, y if v==0.
	selectBit := int(result & 1) // 0xFF & 1 = 1 (success), 0x00 & 1 = 0 (failure)
	for i := 0; i < vecKBytes; i++ {
		mc[i] = byte(subtle.ConstantTimeSelect(selectBit, int(m[i]), int(dk.sigma[i])))
	}

	// Shared secret uses ORIGINAL u, v from the ciphertext (NOT re-encrypted u2, v2).
	store8Arr(mc[vecKBytes:vecKBytes+int(p.vecNSizeBytes)], u[:p.vecNSize64])
	store8Arr(mc[vecKBytes+int(p.vecNSizeBytes):], v[:p.vecN1N2Size64])

	ss := make([]byte, 64)
	shake256_512DS(ss, mc, kFctDomain)

	return ss, nil
}

// destroy zeroes all secret material in the decapsulation key.
func (dk *decapsulationKey) destroy() {
	dk.mu.Lock()
	defer dk.mu.Unlock()

	if dk.destroyed {
		return
	}

	ZeroBytes(dk.skSeed)
	ZeroBytes(dk.sigma)
	ZeroUint64s(dk.x)
	ZeroUint64s(dk.y)
	ZeroBytes(dk.sk)
	ZeroBytes(dk.seed)
	dk.destroyed = true
}

// generateKeyFromRand is used by GenerateKeyNNN() functions.
func generateKeyFromRand(p *params) (*decapsulationKey, error) {
	return generateKey(p, rand.Reader)
}

// Version returns the specification version this implementation conforms to.
// Consumers can use this to programmatically verify which HQC variant they
// are using. This will change when FIPS 207 is published and go-hqc is
// updated to match.
func Version() string {
	return "v5.0.0"
}
