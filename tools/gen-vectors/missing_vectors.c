/*
 * missing_vectors.c - Generate the remaining test vectors from HQC v5.0.0.
 *
 *   1. Barrett reduction: sample inputs -> reduced outputs
 *   2. vect_compare: constant-time byte comparison vectors
 *   3. vect_truncate: truncation to PARAM_N1N2 bits
 *   4. SK corruption: modified secret key -> decaps still returns 32-byte ss
 *
 * Build: same flags as edge_cases.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"

static void print_hex_bytes(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) fprintf(stdout, "%02x", data[i]);
}

/* Barrett reduce reimplemented here since it's static inline in vector.c */
static uint32_t barrett_reduce_test(uint32_t x) {
    uint64_t q = ((uint64_t)x * PARAM_N_MU) >> 32;
    uint32_t r = x - (uint32_t)(q * PARAM_N);
    uint32_t reduce_flag = (((r - PARAM_N) >> 31) ^ 1);
    uint32_t mask = -reduce_flag;
    r -= mask & PARAM_N;
    return r;
}

/* 1. Barrett reduction vectors */
static void gen_barrett(void) {
    printf("  \"barrett_reduce\": [\n");

    /* Test boundary values around PARAM_N, 0, max, and the rejection threshold */
    uint32_t inputs[] = {
        0, 1, PARAM_N - 1, PARAM_N, PARAM_N + 1,
        2 * PARAM_N - 1, 2 * PARAM_N, 2 * PARAM_N + 1,
        UTILS_REJECTION_THRESHOLD - 1, UTILS_REJECTION_THRESHOLD,
        0xFFFFFF, /* 24-bit max (sampling range) */
        12345, 67890, 100000, 1000000
    };
    int n = sizeof(inputs) / sizeof(inputs[0]);

    for (int i = 0; i < n; i++) {
        uint32_t x = inputs[i];
        uint32_t r = barrett_reduce_test(x);

        if (i > 0) printf(",\n");
        printf("    {\"input\": %u, \"output\": %u, \"param_n\": %u}", x, r, (uint32_t)PARAM_N);
    }
    printf("\n  ],\n");
}

/* 2. vect_compare vectors */
static void gen_vect_compare(void) {
    printf("  \"vect_compare\": [\n");

    /* Equal vectors */
    {
        uint8_t a[32], b[32];
        memset(a, 0x42, 32);
        memset(b, 0x42, 32);
        uint8_t result = vect_compare(a, b, 32);
        printf("    {\"description\": \"equal\", \"size\": 32, \"result\": %d},\n", result);
    }

    /* Differ at first byte */
    {
        uint8_t a[32], b[32];
        memset(a, 0x42, 32);
        memset(b, 0x42, 32);
        b[0] = 0x43;
        uint8_t result = vect_compare(a, b, 32);
        printf("    {\"description\": \"differ_first\", \"size\": 32, \"result\": %d},\n", result);
    }

    /* Differ at last byte */
    {
        uint8_t a[32], b[32];
        memset(a, 0x42, 32);
        memset(b, 0x42, 32);
        b[31] = 0x43;
        uint8_t result = vect_compare(a, b, 32);
        printf("    {\"description\": \"differ_last\", \"size\": 32, \"result\": %d},\n", result);
    }

    /* All zeros vs all zeros */
    {
        uint8_t a[32], b[32];
        memset(a, 0, 32);
        memset(b, 0, 32);
        uint8_t result = vect_compare(a, b, 32);
        printf("    {\"description\": \"zeros_equal\", \"size\": 32, \"result\": %d},\n", result);
    }

    /* All 0xFF vs all 0xFF */
    {
        uint8_t a[32], b[32];
        memset(a, 0xFF, 32);
        memset(b, 0xFF, 32);
        uint8_t result = vect_compare(a, b, 32);
        printf("    {\"description\": \"ones_equal\", \"size\": 32, \"result\": %d},\n", result);
    }

    /* Single byte differ */
    {
        uint8_t a[1] = {0x00}, b[1] = {0x01};
        uint8_t result = vect_compare(a, b, 1);
        printf("    {\"description\": \"single_differ\", \"size\": 1, \"result\": %d}\n", result);
    }
    printf("  ],\n");
}

/* 3. vect_truncate vectors */
static void gen_vect_truncate(void) {
    printf("  \"vect_truncate\": [\n");

    /* Fill with all-ones, truncate, check which bits remain */
    {
        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0xFF, sizeof(v));
        vect_truncate(v);

        /* Count set bits after truncation */
        int bits = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { bits++; x &= x - 1; }
        }
        printf("    {\"description\": \"all_ones_truncated\", \"bits_set\": %d, \"param_n1n2\": %d},\n", bits, PARAM_N1N2);
    }

    /* Fill with pattern, truncate, verify last word mask */
    {
        uint64_t v[VEC_N_SIZE_64];
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) v[i] = 0xAAAAAAAAAAAAAAAAULL;
        vect_truncate(v);

        size_t last_word = (PARAM_N1N2 - 1) / 64;
        printf("    {\"description\": \"pattern_truncated\", \"last_word_idx\": %zu, \"last_word_hex\": \"", last_word);
        /* Print last word as hex */
        for (int b = 0; b < 8; b++) fprintf(stdout, "%02x", (uint8_t)(v[last_word] >> (8 * b)));
        printf("\"}\n");
    }
    printf("  ],\n");
}

/* 4. SK corruption */
static void gen_sk_corruption(void) {
    printf("  \"sk_corruption\": [\n");

    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_valid[CRYPTO_BYTES];
    static uint8_t ss_corrupt[CRYPTO_BYTES];

    uint8_t entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (uint8_t)(i + 100);
    prng_init(entropy, NULL, 48, 0);
    crypto_kem_keypair(pk, sk);

    for (int i = 0; i < 48; i++) entropy[i] = (uint8_t)(i + 148);
    prng_init(entropy, NULL, 48, 0);
    crypto_kem_enc(ct, ss_valid, pk);
    crypto_kem_dec(ss_valid, ct, sk);

    /* Corrupt SK at structurally meaningful positions for v5.0.0 layout:
     * sk = pk[CRYPTO_PUBLICKEYBYTES] || seed_dk[SEED_BYTES] || sigma[PARAM_SECURITY_BYTES] || seed_kem[SEED_BYTES]
     * Positions: inside pk, at seed_dk boundary, inside sigma, inside seed_kem, last byte */
    int positions[] = {
        0,                                                              /* inside pk (first byte) */
        CRYPTO_PUBLICKEYBYTES,                                          /* seed_dk start */
        CRYPTO_PUBLICKEYBYTES + SEED_BYTES,                             /* sigma start */
        CRYPTO_PUBLICKEYBYTES + SEED_BYTES + PARAM_SECURITY_BYTES,      /* seed_kem start */
        CRYPTO_SECRETKEYBYTES - 1                                       /* last byte (inside seed_kem) */
    };
    int num_positions = sizeof(positions) / sizeof(positions[0]);
    for (int t = 0; t < num_positions; t++) {
        static uint8_t sk_mod[CRYPTO_SECRETKEYBYTES];
        memcpy(sk_mod, sk, CRYPTO_SECRETKEYBYTES);
        sk_mod[positions[t]] ^= 0x01;

        crypto_kem_dec(ss_corrupt, ct, sk_mod);

        int different = (memcmp(ss_valid, ss_corrupt, CRYPTO_BYTES) != 0);

        printf("    {\"modified_pos\": %d, \"different_ss\": %s, \"ss_32_bytes\": true}%s\n",
               positions[t], different ? "true" : "false",
               t < num_positions - 1 ? "," : "");
    }
    /* Zero SK (contains sigma and seed_kem) */
    memset(sk, 0, CRYPTO_SECRETKEYBYTES);
    printf("  ]\n");
}

int main(void) {
#if HQC_PARAM == 1
    const char *name = "hqc-1";
#elif HQC_PARAM == 3
    const char *name = "hqc-3";
#elif HQC_PARAM == 5
    const char *name = "hqc-5";
#else
    #error "Define HQC_PARAM to 1, 3, or 5"
#endif

    printf("{\n");
    printf("  \"algorithm\": \"HQC\",\n");
    printf("  \"version\": \"v5.0.0\",\n");
    printf("  \"param_set\": \"%s\",\n", name);
    printf("  \"type\": \"missing_vectors\",\n");

    gen_barrett();
    gen_vect_compare();
    gen_vect_truncate();
    gen_sk_corruption();

    printf("}\n");
    return 0;
}
