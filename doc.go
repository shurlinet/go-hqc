// Package hqc implements the HQC (Hamming Quasi-Cyclic) Key Encapsulation
// Mechanism, a code-based post-quantum KEM selected by NIST for
// standardization as a backup to ML-KEM.
//
// This implements HQC as specified in the official v5.0.0 reference implementation
// (NIST round 4). It does NOT implement the FIPS 207 standard, which is
// not yet published. Call [Version] to check the specification version
// programmatically.
//
// Three parameter sets are provided:
//   - HQC-128 (NIST Level 1): [GenerateKey128], [DecapsulationKey128], [EncapsulationKey128]
//   - HQC-192 (NIST Level 3): [GenerateKey192], [DecapsulationKey192], [EncapsulationKey192]
//   - HQC-256 (NIST Level 5): [GenerateKey256], [DecapsulationKey256], [EncapsulationKey256]
//
// The API follows Go's crypto/mlkem pattern: typed per-parameter-set keys,
// [EncapsulationKey128.Encapsulate] that cannot fail (panics on entropy
// failure), and implicit rejection via sigma for invalid ciphertexts.
//
// # Key Lifecycle
//
// Call [DecapsulationKey128.Destroy] when a decapsulation key is no longer
// needed. Destroy zeroes all secret material (skSeed, sigma, x, y, sk, seed).
// Dropping a DecapsulationKey reference without calling Destroy leaves secret
// material in memory until the garbage collector reclaims the object and the
// OS overwrites the pages. Go does not provide deterministic destructors.
// The corresponding [EncapsulationKey128] (public data only) remains valid
// after Destroy.
//
// # Security Properties
//
// Constant-time operations use [crypto/subtle.ConstantTimeSelect] for the
// Fujisaki-Okamoto comparison. All secret intermediate buffers are zeroed
// via //go:noinline defers that survive panics.
//
// This implementation does not include fault injection countermeasures
// (voltage glitch, rowhammer). For environments where an attacker has
// physical access to the hardware, additional double-verification of the
// FO comparison should be added.
//
// Constant-time guarantees hold for native compilation targets (amd64, arm64).
// WASM compilation does not provide timing guarantees because the VM
// interpreter may optimize, reorder, or cache operations differently. Do not
// rely on timing safety when compiling to WASM.
//
// # Pre-FIPS Status
//
// go-hqc v0.x is explicitly unstable. When FIPS 207 publishes (expected late
// 2026 / early 2027), seed sizes and shared secret sizes will change. v1.0.0
// ships only after FIPS.
package hqc
