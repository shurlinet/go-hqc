# Vector Generation Harnesses

C programs that generate test vectors from the official HQC v5.0.0 reference.
Each harness links against the v5.0.0 C code and outputs JSON to stdout.

## Harnesses

| File | Output | Description |
|------|--------|-------------|
| harness.c | KAT vectors + accumulated hashes | Keygen/encaps vectors, SHAKE128 accumulated hashes at 6 tiers |
| intermediates.c | Component vectors | Seedexpander, RS encode, RM encode, code roundtrip |
| edge_cases.c | Edge case vectors | GF multiply, RS decode with errors, hash G/H/I/J, implicit rejection |
| samplers.c | Sampler vectors | Sampler1 rejection, sampler2 Fisher-Yates, fixed-point multiply |
| missing_vectors.c | Gap-fill vectors | Barrett reduce, vect_compare, vect_truncate, SK corruption |

## Build

Requires the official HQC v5.0.0 source at `/tmp/hqc-official/`.

```sh
cd /tmp/hqc-official
# For each param set P=1,3,5 and harness H:
cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
  -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
  -Ilib -Ilib/fips202 \
  /path/to/tools/gen-vectors/H.c \
  src/ref/gf.c src/ref/gf2x.c src/ref/hqc.c src/ref/parsing.c \
  src/ref/reed_muller.c src/ref/reed_solomon.c src/ref/vector.c \
  src/common/code.c src/common/crypto_memset.c src/common/fft.c \
  src/common/kem.c src/common/symmetric.c lib/fips202/fips202.c \
  -o H_hqcP
```

## ARM/macOS Note

The v5.0.0 ref code includes `<immintrin.h>` in 3 headers but uses zero x86
intrinsics. An empty stub at `compat/immintrin.h` in the official repo fixes
the build on ARM.
