# go-hqc

[![Go Tests](https://github.com/shurlinet/go-hqc/actions/workflows/ci.yml/badge.svg)](https://github.com/shurlinet/go-hqc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-hqc.svg)](https://pkg.go.dev/github.com/shurlinet/go-hqc)
[![Go Report Card](https://goreportcard.com/badge/github.com/shurlinet/go-hqc)](https://goreportcard.com/report/github.com/shurlinet/go-hqc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Pure Go implementation of **HQC** (Hamming Quasi-Cyclic), a code-based
Key Encapsulation Mechanism selected by NIST for standardization as a backup
to ML-KEM (lattice-based). Different cryptographic foundation: if lattice
assumptions break, HQC remains secure.

NIST [selected HQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
for standardization (March 2025) as
[FIPS 207](https://csrc.nist.gov/presentations/2025/fips-207-hqc-kem).
The formal standard is expected but not yet finalized. The standard adjusts parameter sizes
(seed 40->32, shared secret 64->32) from the submission. The core cryptographic
construction (code-based KEM with Fujisaki-Okamoto transform, Reed-Solomon/
Reed-Muller error correction) is mature (published 2017, 7+ years of
cryptanalysis). go-hqc tracks the current
the official HQC v5.0.0 reference and will be updated
when FIPS 207 is published.

> **Warning**
>
> * This library has not received any formal audit
> * While we use Go's standard library cryptographic primitives (`crypto/sha3`, `crypto/subtle`), it is up to **you** to evaluate whether they meet your security and integrity requirements
> * **Pre-FIPS:** implements HQC v5.0.0 specification. API may change with FIPS 207. v0.x API is explicitly unstable

## Install

```
go get github.com/shurlinet/go-hqc
```

Requires Go 1.26+ (for `crypto/sha3`).

## Usage

```go
package main

import (
    "bytes"
    "fmt"
    "log"

    "github.com/shurlinet/go-hqc"
)

func main() {
    // Generate a keypair.
    dk, err := hqc.GenerateKey128()
    if err != nil {
        log.Fatal(err)
    }
    defer dk.Destroy()

    // Encapsulate: peer gets the public key and produces shared secret + ciphertext.
    sharedSecret, ciphertext := dk.EncapsulationKey().Encapsulate()

    // Decapsulate: owner recovers the shared secret from ciphertext.
    recovered, err := dk.Decapsulate(ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("match: %v, length: %d bytes\n",
        bytes.Equal(sharedSecret, recovered), len(sharedSecret))
}
```

## Features

- Pure Go, zero external dependencies (uses `crypto/sha3` from stdlib)
- Three parameter sets: HQC-128 (Level 1), HQC-192 (Level 3), HQC-256 (Level 5)
- API follows Go `crypto/mlkem` pattern (typed per-param-set keys)
- Constant-time FO transform using `crypto/subtle`
- Secret key zeroing via `Destroy()` (all persistent secret material)
- Deterministic key generation from seed (`NewDecapsulationKey128(seed)`)
- Deterministic encapsulation for testing (`EncapsulateWithEntropy` / `hqctest` sub-package, mirrors `crypto/mlkem/mlkemtest`)
- Key consistency validation on parse (`ParseDecapsulationKey128`)
- Concurrent-safe: `Decapsulate` is safe for concurrent use
- Specification version check via `Version()`

## Size Constants

| Parameter Set | Public Key | Secret Key | Ciphertext | Shared Secret | Seed |
|--------------|-----------|-----------|------------|--------------|------|
| HQC-128 | 2,241 | 2,321 | 4,433 | 32 | 32 |
| HQC-192 | 4,514 | 4,602 | 8,978 | 32 | 32 |
| HQC-256 | 7,237 | 7,333 | 14,421 | 32 | 32 |

All sizes in bytes.

## Security

- **Implicit rejection**: invalid ciphertexts produce a random-looking shared
  secret derived from sigma (never an error that reveals decryption success/failure)
- **Constant-time FO comparison**: uses `crypto/subtle.ConstantTimeSelect`
- **Key zeroing**: `Destroy()` zeroes seedDK, sigma, seedKem, x, y, sk via
  `//go:noinline` zero functions
- **Parse validation**: `ParseDecapsulationKey` verifies the embedded public key
  matches seed_dk (catches corruption)
- **WASM caveat**: constant-time guarantees hold for native targets (amd64,
  arm64). WASM compilation does not provide timing guarantees.
- **No fault injection countermeasures**: this implementation does not defend
  against voltage glitch or rowhammer attacks. See the package documentation
  for details.

## Consumer Responsibilities

* **Call `Destroy()` on decapsulation keys** when they are no longer needed. `Destroy()` zeroes secret material. The Go garbage collector does not guarantee timely zeroing of freed memory. Dropping the key reference without calling `Destroy()` leaves secrets in memory until GC collects them.
* **Do not reuse ciphertexts.** Each `Encapsulate()` call produces a fresh shared secret and ciphertext. Replaying a ciphertext to a different decapsulation key is not meaningful.
* **Validate ciphertext source.** The KEM provides implicit rejection (invalid ciphertexts produce random shared secrets), but it does not authenticate the sender. Use the shared secret to key an authenticated channel.
* **Check `Version()` programmatically** if your application needs to track which HQC specification is in use. The version string will change when FIPS 207 is implemented.

## Testing

```sh
make test              # KAT + property + AI threat + accumulated-100 (~30s total)
make bench             # benchmarks for all 3 param sets (~15s)
make fuzz              # 30s fuzz per target, 2 targets (~1 min total)
make fuzz-long         # 5 min fuzz per target, 2 targets (~10 min total)
make lint              # go vet + staticcheck (~5s)
```

### Accumulated verification tiers

Verifies N complete KEM cycles (keygen + encaps + decaps) against SHAKE128
accumulated hashes generated by v5.0.0 C. One hash proves N cycles byte-correct.

```sh
make accumulated-100   # 100 iterations   (~10s total, runs in make test)
make accumulated-1k    # 1,000 iterations (~2 min total)
make accumulated-10k   # 10,000 iterations (~17 min total)
make accumulated-100k  # 100,000 iterations (~2.5 hours total, pre-release)
make accumulated-1m    # 1,000,000 iterations (~28 hours total, auditor)
```

Timings on M3 Max. HQC-256 is ~6x slower than HQC-128 (larger polynomials).
All 3 param sets run sequentially.

Or directly: `GOHQC_ACCUMULATED=10000 go test -run=TestAccumulated -v ./...`

### Test inventory

| Category | Count | Description |
|----------|-------|-------------|
| KAT keygen | 30 | v5.0.0 vectors, byte-for-byte (10 per param set) |
| KAT encaps | 30 | v5.0.0 vectors with decaps verification (10 per param set) |
| Round-trip | 3 | Encaps/Decaps agreement per param set |
| Key serialization | 1 | Bytes/Parse/Seed round-trip (HQC-128) |
| Edge cases | 4 | Zero ct, modified salt, wrong lengths |
| Concurrency | 1 | 8-goroutine parallel Decapsulate |
| Destroy lifecycle | 1 | Post-Destroy errors, double Destroy safety |
| Slice isolation | 1 | Returned slices independent of internal state |
| Constant-time | 1 | Valid vs invalid ct path equivalence |
| Size constants | 1 | Computed from params, anti-tamper |
| Property: round-trip | 3 | 5 iterations per param set |
| Property: key serial | 3 | DK + EK round-trip per param set |
| Property: seed | 3 | Seed round-trip per param set |
| AI threat defense | 4 | Domain bytes (G/H/I/J/XOF/PRNG), hashG + hashH independent, nMu/rejThreshold formula |
| Version | 1 | Version() returns expected spec string |
| Keygen verification | 1 | Re-derive y,x from seed_dk, verify s = x + y*h |
| Accumulated | 3 | SHAKE128 accumulated hashes vs v5.0.0 C (100-1M tiers) |
| Benchmarks | 9 | Keygen/Encaps/Decaps per param set |
| Fuzz | 2 | FuzzDecapsulate128, FuzzKeyRoundTrip128 |
| Godoc examples | 3 | Basic, serialization, all param sets |
| hqctest deterministic | 6 | Deterministic encaps reproducibility + size check (all 3 param sets) |
| **Component tests** | 50 | GF, seedexpander, gf2x, vector, RM, RS, FFT, code |

## Verification

go-hqc is verified by:

* [KAT vectors](testdata/) - 60 Known Answer Tests (30 keygen + 30 encaps/decaps) across all 3 parameter sets, byte-for-byte match against the official HQC v5.0.0 C reference. Generated using HQC's custom SHAKE256 DRBG ([tools/gen-vectors/](tools/gen-vectors/)).
* [Accumulated hash anchors](testdata/accumulated.json) - SHA256 hashes over 1M keygen/encaps iterations per parameter set. Go tests verify up to 100K; 1M hashes are reference data for external verifiers.
* [Property tests](hqc_property_test.go) - 15 round-trip iterations (5 per param set), 3 key serialization round-trips (Bytes/Parse + Seed/New + EK), 3 seed determinism proofs
* [Fuzz tests](hqc_fuzz_test.go) - 2 targets: `FuzzDecapsulate128` (random ciphertexts, no panics, always 32-byte implicit rejection) and `FuzzKeyRoundTrip128` (random seeds, generate/serialize/parse/decaps agreement with 5 VP1 length assertions)
* [AI threat defense](hqc_property_test.go) - 4 independent verifications: domain separation bytes (G/H/I/J/XOF/PRNG uniqueness + pinned values), hashG via independent SHA3-512, hashH via independent SHA3-256, nMu/rejectionThreshold formula recomputation for all 3 param sets
* [Component tests](gf_test.go) - 50 tests across 8 subsystems: GF(2^m) exhaustive 65,536-multiply oracle, seedexpander direct squeeze + pinned regression, karatsuba polynomial multiply, Reed-Muller RM(1,7) all-256-byte round-trip, Reed-Solomon LFSR encode + Berlekamp decode with varying error counts, Gao-Mateer additive FFT root finding, concatenated code round-trip, sampler1/sampler2 weight + determinism + consecutive calls
* 9 [benchmarks](hqc_property_test.go) - Keygen/Encapsulate/Decapsulate for all 3 parameter sets

```
make test
```

Or equivalently: `go test -race -count=1 ./...`

## Examples

| Example | Description |
|---------|-------------|
| [`examples/basic/`](examples/basic/) | HQC-128 key exchange (generate, encapsulate, decapsulate) |
| [`examples/serialization/`](examples/serialization/) | Key persistence (Bytes/Parse, Seed/New, EK round-trip) |

## Dependencies

None. go-hqc uses only the Go standard library (`crypto/sha3`, `crypto/subtle`,
`crypto/rand`). Zero external module dependencies.

| Dependency | Purpose |
|-----------|---------|
| Go 1.26+ | Required for `crypto/sha3` |

## Upstream Tracking

Source: official HQC v5.0.0 (https://gitlab.com/pqc-hqc/hqc/). See [UPSTREAM.md](UPSTREAM.md) for full
tracking details and FIPS 207 status.

## AI Transparency

This library was developed with AI assistance ([Claude](https://claude.ai)).
All cryptographic decisions were verified against the official v5.0.0 C reference.
KAT vectors are generated from v5.0.0 harnesses and verified byte-for-byte.
The test suite includes AI threat defense tests designed to catch both human and
AI-introduced errors. The AI generated code; the human made every design
decision, reviewed every line, and owns every bug.

## Acknowledgments

- The HQC authors and former PQClean contributors for the clean
  portable C reference implementations (public domain)
- Carlos Aguilar Melchor, Nicolas Aragon, Slim Bettaieb, Loic Bidoux, Olivier
  Blazy, Jurjen Bos, Jean-Christophe Deneuville, Philippe Gaborit, Edoardo
  Persichetti, Jean-Marc Robert, Pascal Veron, Gilles Zemor, and the HQC
  design team for creating the algorithm

## Future: Go Standard Library

When FIPS 207 is finalized, Go will likely add `crypto/hqc` to the standard
library (as it did with `crypto/mlkem` for ML-KEM). When that happens:

- `crypto/hqc` becomes the official Go implementation
- go-hqc continues to work as a separate module (no breakage)
- Migration is an import path change (API follows the same `crypto/mlkem` pattern)
- go-hqc may still be useful for pre-FIPS deployment or environments pinned to
  older Go versions

This is the same lifecycle as [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa)
(pre-stdlib ML-DSA used by [go-clatter](https://github.com/shurlinet/go-clatter)),
which will migrate to `crypto/mldsa` when Go ships it.

## References

- [HQC specification](https://pqc-hqc.org) - official HQC website with the algorithm specification, design rationale, and parameter selection
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - NIST PQC standardization project (HQC selected as backup KEM alongside ML-KEM)
- [FIPS 207](https://csrc.nist.gov/presentations/2025/fips-207-hqc-kem) - HQC standardization (not yet finalized, expected late 2026 / early 2027)
- [HQC official](https://gitlab.com/pqc-hqc/hqc/) - official reference implementation (v5.0.0)
- [PQNoise paper](https://doi.org/10.1145/3548606.3560577) - PQNoise extensions (ACM CCS 2022) that use KEMs like HQC in Noise handshakes (implemented by [go-clatter](https://github.com/shurlinet/go-clatter))

## License

MIT. See [LICENSE](LICENSE).

HQC reference code is public domain (CC0). See
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
