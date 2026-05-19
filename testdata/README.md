# Test Vectors

All vectors generated from the official HQC v5.0.0 C reference implementation
(https://gitlab.com/pqc-hqc/hqc/ tag v5.0.0) using harnesses in `tools/gen-vectors/`.

## KEM Vectors

| File | Description | Param Sets |
|------|-------------|------------|
| keygen.json | 10 keygen vectors per param set (entropy, pk, sk) | HQC-128/192/256 |
| encaps.json | 10 encaps vectors per param set (key_entropy, pk, encaps_entropy, ct, ss) | HQC-128/192/256 |
| accumulated.json | SHAKE128 accumulated hashes at tiers 10/100/1K/10K/100K/1M | HQC-128/192/256 |

## Component Vectors (HQC-128)

| File | Description |
|------|-------------|
| intermediates.json | Seedexpander outputs, RS encode, RM encode, code roundtrip |
| edge_cases.json | GF multiply, RS decode with errors, hash G/H/I/J, implicit rejection |
| samplers.json | Sampler1 rejection positions, sampler2 Fisher-Yates, fixed-point multiply |
| missing_vectors.json | Barrett reduce, vect_compare, vect_truncate, SK corruption |

## Verification

- **Forward**: C generates vectors, Go tests match them byte-for-byte (KAT tests).
- **Reverse**: Go generates output, C verifies it (see `tools/reverse-verify/`).
- **Accumulated**: Both C and Go produce identical SHAKE128 hashes over N KEM cycles.

## Regeneration

```sh
cd /tmp/hqc-official
# Build harness for each param set (P=1,3,5):
cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
  -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
  -Ilib -Ilib/fips202 \
  /path/to/tools/gen-vectors/harness.c [source files] -o harness_hqcP
./harness_hqcP > vectors_hqcP.json 2> accumulated_hqcP.txt
```

Then convert to the Go test JSON structure using the conversion script.
