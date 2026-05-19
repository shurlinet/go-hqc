# Reverse Verification

Proves that Go-generated HQC output is accepted by the v5.0.0 C reference.

## What It Tests

1. **Keygen match**: Go and C produce identical pk/sk from the same PRNG entropy.
2. **Cross-decaps**: C decapsulates Go-generated ciphertexts and recovers the same shared secret.

This is the reverse direction of KAT tests (KAT: C generates, Go matches).
Together they prove bidirectional interoperability.

## Usage

```sh
# Build the C verifier (from /tmp/hqc-official, for each P=1,3,5):
cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
  -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
  -Ilib -Ilib/fips202 \
  /path/to/tools/reverse-verify/reverse_verify.c \
  src/ref/gf.c src/ref/gf2x.c src/ref/hqc.c src/ref/parsing.c \
  src/ref/reed_muller.c src/ref/reed_solomon.c src/ref/vector.c \
  src/common/code.c src/common/crypto_memset.c src/common/fft.c \
  src/common/kem.c src/common/symmetric.c lib/fips202/fips202.c \
  -o reverse_verify_hqcP

# Run (generates Go vectors, pipes to C verifier):
go run tools/reverse-verify/gen_go_vectors.go -param 128 | ./reverse_verify_hqc1
go run tools/reverse-verify/gen_go_vectors.go -param 192 | ./reverse_verify_hqc3
go run tools/reverse-verify/gen_go_vectors.go -param 256 | ./reverse_verify_hqc5
```

## Expected Output

```
PASS keygen 1
PASS cross-decaps 2
...
reverse-verify: pk=2241 sk=2321 ct=4433 ss=32
reverse-verify: 10/10 passed
```

5 keygen + 5 cross-decaps per param set = 10 tests. All 3 param sets = 30 total.
