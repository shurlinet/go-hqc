/*
 * intermediates.c - Generate intermediate/component test vectors from HQC v5.0.0.
 *
 * Tests individual building blocks independently of the KEM API:
 *   1. Seedexpander (XOF): deterministic byte stream from seed
 *   2. vect_set_random: XOF -> full N-bit random vector (NOT fixed-weight)
 *   3. Reed-Solomon encode: systematic codeword from message
 *   4. Reed-Muller encode: RM(1,7) codeword from byte
 *   5. Code encode/decode round-trip
 *
 * Official HQC repo: https://gitlab.com/pqc-hqc/hqc/ tag v5.0.0
 *
 * Build (from /tmp/hqc-official, for param set P=1,3,5):
 *   cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
 *     -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
 *     -Ilib -Ilib/fips202 \
 *     /path/to/intermediates.c \
 *     src/ref/gf.c src/ref/gf2x.c src/ref/hqc.c src/ref/parsing.c \
 *     src/ref/reed_muller.c src/ref/reed_solomon.c src/ref/vector.c \
 *     src/common/code.c src/common/crypto_memset.c src/common/fft.c \
 *     src/common/kem.c src/common/symmetric.c lib/fips202/fips202.c \
 *     -o intermediates_hqcP
 *
 *   ./intermediates_hqcP > intermediates_hqcP.json
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"
#include "reed_muller.h"
#include "code.h"

/* No header for RS in v5.0.0; forward-declare */
extern void reed_solomon_encode(uint64_t *cdw, const uint64_t *msg);
extern void reed_solomon_decode(uint64_t *msg, uint64_t *cdw);

static void print_hex_bytes(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) fprintf(stdout, "%02x", data[i]);
}

/* 1. Seedexpander / XOF vectors */
static void gen_seedexpander_vectors(void) {
    printf("  \"seedexpander\": [\n");

    /* Test with incrementing seed bytes */
    for (int t = 0; t < 3; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 32 + i);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        /* Squeeze 3 blocks of different sizes to test split reads */
        uint8_t out1[8], out2[16], out3[32];
        xof_get_bytes(&ctx, out1, 8);
        xof_get_bytes(&ctx, out2, 16);
        xof_get_bytes(&ctx, out3, 32);

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"out_8\": \"");
        print_hex_bytes(out1, 8);
        printf("\", \"out_16\": \"");
        print_hex_bytes(out2, 16);
        printf("\", \"out_32\": \"");
        print_hex_bytes(out3, 32);
        printf("\"}%s\n", t < 2 ? "," : "");
    }
    printf("  ],\n");
}

/* 2. vect_set_random: XOF -> full N-bit random vector (NOT fixed-weight) */
static void gen_vect_set_random_vectors(void) {
    printf("  \"vect_set_random\": [\n");

    for (int t = 0; t < 3; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 10 + i + 100);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0, sizeof(v));
        vect_set_random(&ctx, v);

        /* Count weight (number of set bits) - expected ~n/2 for random vector */
        int weight = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { weight++; x &= x - 1; }
        }

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"weight\": %d", weight);
        printf(", \"vector_hex\": \"");
        print_hex_bytes((uint8_t *)v, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 2 ? "," : "");
    }
    printf("  ],\n");
}

/* 3. Reed-Solomon encode */
static void gen_rs_encode_vectors(void) {
    printf("  \"reed_solomon_encode\": [\n");

    for (int t = 0; t < 3; t++) {
        /* Create a message as uint64 words */
        uint64_t msg[VEC_N1_SIZE_64];
        memset(msg, 0, sizeof(msg));
        /* Fill PARAM_K bytes of message data */
        uint8_t *msg_bytes = (uint8_t *)msg;
        for (int i = 0; i < PARAM_K; i++) {
            msg_bytes[i] = (uint8_t)(t * 37 + i + 1);
        }

        uint64_t cdw[VEC_N1_SIZE_64];
        memcpy(cdw, msg, sizeof(msg));
        reed_solomon_encode(cdw, msg);

        printf("    {\"message\": \"");
        print_hex_bytes(msg_bytes, PARAM_K);
        printf("\", \"codeword\": \"");
        print_hex_bytes((uint8_t *)cdw, PARAM_N1);
        printf("\"}%s\n", t < 2 ? "," : "");
    }
    printf("  ],\n");
}

/* 4. Reed-Muller encode */
static void gen_rm_encode_vectors(void) {
    printf("  \"reed_muller_encode\": [\n");

    /* Test all 256 possible single-byte inputs for RM(1,7) */
    for (int t = 0; t < 256; t++) {
        uint64_t msg[VEC_N1_SIZE_64];
        memset(msg, 0, sizeof(msg));
        ((uint8_t *)msg)[0] = (uint8_t)t;

        uint64_t cdw[VEC_N1N2_SIZE_64];
        memset(cdw, 0, sizeof(cdw));
        reed_muller_encode(cdw, msg);

        /* Only output first 16 bytes of codeword (128 bits = one RM block) */
        if (t == 0 || t == 1 || t == 127 || t == 128 || t == 255) {
            printf("    {\"byte\": %d, \"codeword_prefix\": \"", t);
            print_hex_bytes((uint8_t *)cdw, 16);
            printf("\"}%s\n", (t == 255) ? "" : ",");
        }
    }
    printf("  ],\n");
}

/* 5. Code encode/decode round-trip */
static void gen_code_roundtrip_vectors(void) {
    printf("  \"code_roundtrip\": [\n");

    for (int t = 0; t < 3; t++) {
        uint64_t msg[VEC_K_SIZE_BYTES / 8 + 1];
        memset(msg, 0, sizeof(msg));
        uint8_t *msg_bytes = (uint8_t *)msg;
        for (int i = 0; i < VEC_K_SIZE_BYTES; i++) {
            msg_bytes[i] = (uint8_t)(t * 53 + i);
        }

        uint64_t encoded[VEC_N1N2_SIZE_64];
        memset(encoded, 0, sizeof(encoded));
        code_encode(encoded, msg);

        uint64_t decoded[VEC_K_SIZE_BYTES / 8 + 1];
        memset(decoded, 0, sizeof(decoded));
        code_decode(decoded, encoded);

        int match = (memcmp(msg_bytes, (uint8_t *)decoded, VEC_K_SIZE_BYTES) == 0);

        printf("    {\"message\": \"");
        print_hex_bytes(msg_bytes, VEC_K_SIZE_BYTES);
        printf("\", \"encoded_prefix\": \"");
        print_hex_bytes((uint8_t *)encoded, 32);
        printf("\", \"decoded\": \"");
        print_hex_bytes((uint8_t *)decoded, VEC_K_SIZE_BYTES);
        printf("\", \"match\": %s}%s\n", match ? "true" : "false", t < 2 ? "," : "");
    }
    printf("  ],\n");
}

/* 6. Parameters (for cross-checking) */
static void gen_parameters(void) {
    printf("  \"parameters\": {\n");
    printf("    \"n\": %d,\n", PARAM_N);
    printf("    \"n1\": %d,\n", PARAM_N1);
    printf("    \"n2\": %d,\n", PARAM_N2);
    printf("    \"n1n2\": %d,\n", PARAM_N1N2);
    printf("    \"k\": %d,\n", PARAM_K);
    printf("    \"delta\": %d,\n", PARAM_DELTA);
    printf("    \"omega\": %d,\n", PARAM_OMEGA);
    printf("    \"omega_e\": %d,\n", PARAM_OMEGA_E);
    printf("    \"omega_r\": %d,\n", PARAM_OMEGA_R);
    printf("    \"seed_bytes\": %d,\n", SEED_BYTES);
    printf("    \"salt_bytes\": %d,\n", SALT_BYTES);
    printf("    \"pk_bytes\": %d,\n", CRYPTO_PUBLICKEYBYTES);
    printf("    \"sk_bytes\": %d,\n", CRYPTO_SECRETKEYBYTES);
    printf("    \"ct_bytes\": %d,\n", CRYPTO_CIPHERTEXTBYTES);
    printf("    \"ss_bytes\": %d,\n", CRYPTO_BYTES);
    printf("    \"vec_n_size_64\": %d,\n", VEC_N_SIZE_64);
    printf("    \"vec_n_size_bytes\": %d,\n", VEC_N_SIZE_BYTES);
    printf("    \"vec_n1n2_size_64\": %d,\n", VEC_N1N2_SIZE_64);
    printf("    \"vec_k_size_bytes\": %d\n", VEC_K_SIZE_BYTES);
    printf("  }\n");
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
    printf("  \"source\": \"https://gitlab.com/pqc-hqc/hqc/ tag v5.0.0\",\n");
    printf("  \"param_set\": \"%s\",\n", name);
    printf("  \"type\": \"intermediates\",\n");

    gen_seedexpander_vectors();
    gen_vect_set_random_vectors();
    gen_rs_encode_vectors();
    gen_rm_encode_vectors();
    gen_code_roundtrip_vectors();
    gen_parameters();

    printf("}\n");
    return 0;
}
