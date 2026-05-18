/*
 * samplers.c - Generate test vectors for both HQC v5.0.0 vector samplers.
 *
 * Two distinct samplers exist in v5.0.0:
 *   1. vect_sample_fixed_weight1 (rejection sampling, keygen only)
 *   2. vect_sample_fixed_weight2 (Fisher-Yates / Algorithm 5, encrypt only)
 *
 * Vectors include support positions and the resulting bitvector for each.
 * Multiple seeds per sampler, all 3 param sets.
 *
 * Build (from /tmp/hqc-official, for param set P=1,3,5):
 *   cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
 *     -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
 *     -Ilib -Ilib/fips202 \
 *     /path/to/samplers.c \
 *     src/ref/gf.c src/ref/gf2x.c src/ref/hqc.c src/ref/parsing.c \
 *     src/ref/reed_muller.c src/ref/reed_solomon.c src/ref/vector.c \
 *     src/common/code.c src/common/crypto_memset.c src/common/fft.c \
 *     src/common/kem.c src/common/symmetric.c lib/fips202/fips202.c \
 *     -o samplers_hqcP
 *
 *   ./samplers_hqcP > samplers_hqcP.json
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

static void print_support(const uint32_t *support, uint16_t weight) {
    printf("[");
    for (uint16_t i = 0; i < weight; i++) {
        if (i > 0) printf(", ");
        printf("%u", support[i]);
    }
    printf("]");
}

/* Sampler 1: rejection sampling (keygen) */
static void gen_sampler1_vectors(void) {
    printf("  \"sampler1_rejection\": [\n");

    /* 4 different seeds, test at PARAM_OMEGA weight (keygen weight) */
    for (int t = 0; t < 4; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 41 + i);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        uint32_t support[PARAM_OMEGA];
        vect_generate_random_support1(&ctx, support, PARAM_OMEGA);

        /* Write support positions to bitvector */
        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0, sizeof(v));
        vect_write_support_to_vector(v, support, PARAM_OMEGA);

        /* Verify weight */
        int weight = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { weight++; x &= x - 1; }
        }

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"weight\": %d, \"actual_weight\": %d", PARAM_OMEGA, weight);
        printf(", \"positions\": ");
        print_support(support, PARAM_OMEGA);
        printf(", \"vector_hex\": \"");
        print_hex_bytes((uint8_t *)v, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 3 ? "," : "");
    }
    printf("  ],\n");
}

/* Sampler 2: Fisher-Yates / Algorithm 5 (encrypt) */
static void gen_sampler2_vectors(void) {
    printf("  \"sampler2_fisher_yates\": [\n");

    /* 4 different seeds, test at PARAM_OMEGA_R weight (encrypt weight for r1, r2) */
    for (int t = 0; t < 4; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 53 + i + 100);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        uint32_t support[PARAM_OMEGA_R];
        vect_generate_random_support2(&ctx, support, PARAM_OMEGA_R);

        /* Write support positions to bitvector */
        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0, sizeof(v));
        vect_write_support_to_vector(v, support, PARAM_OMEGA_R);

        /* Verify weight */
        int weight = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { weight++; x &= x - 1; }
        }

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"weight\": %d, \"actual_weight\": %d", PARAM_OMEGA_R, weight);
        printf(", \"positions\": ");
        print_support(support, PARAM_OMEGA_R);
        printf(", \"vector_hex\": \"");
        print_hex_bytes((uint8_t *)v, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 3 ? "," : "");
    }
    printf("  ],\n");
}

/* Sampler 2 at PARAM_OMEGA_E weight (error vector weight) */
static void gen_sampler2_omega_e_vectors(void) {
    printf("  \"sampler2_omega_e\": [\n");

    for (int t = 0; t < 2; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 71 + i + 200);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        uint32_t support[PARAM_OMEGA_E];
        vect_generate_random_support2(&ctx, support, PARAM_OMEGA_E);

        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0, sizeof(v));
        vect_write_support_to_vector(v, support, PARAM_OMEGA_E);

        int weight = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { weight++; x &= x - 1; }
        }

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"weight\": %d, \"actual_weight\": %d", PARAM_OMEGA_E, weight);
        printf(", \"positions\": ");
        print_support(support, PARAM_OMEGA_E);
        printf(", \"vector_hex\": \"");
        print_hex_bytes((uint8_t *)v, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 1 ? "," : "");
    }
    printf("  ],\n");
}

/* Verify combined vect_sample_fixed_weight1 matches manual decomposition.
 * Go calls the combined function, so verify the harness decomposition is faithful. */
static void gen_combined_sampler_check(void) {
    printf("  \"combined_sampler_check\": [\n");

    /* Sampler 1: combined vs decomposed */
    {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)i;

        /* Decomposed: support + write */
        shake256_xof_ctx ctx1;
        xof_init(&ctx1, seed, SEED_BYTES);
        uint32_t support[PARAM_OMEGA];
        vect_generate_random_support1(&ctx1, support, PARAM_OMEGA);
        uint64_t v_decomposed[VEC_N_SIZE_64];
        memset(v_decomposed, 0, sizeof(v_decomposed));
        vect_write_support_to_vector(v_decomposed, support, PARAM_OMEGA);

        /* Combined: vect_sample_fixed_weight1 */
        shake256_xof_ctx ctx2;
        xof_init(&ctx2, seed, SEED_BYTES);
        uint64_t v_combined[VEC_N_SIZE_64];
        memset(v_combined, 0, sizeof(v_combined));
        vect_sample_fixed_weight1(&ctx2, v_combined, PARAM_OMEGA);

        int match = (memcmp(v_decomposed, v_combined, sizeof(v_decomposed)) == 0);
        printf("    {\"sampler\": 1, \"weight\": %d, \"match\": %s},\n",
               PARAM_OMEGA, match ? "true" : "false");
    }

    /* Sampler 2: combined vs decomposed */
    {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(i + 100);

        shake256_xof_ctx ctx1;
        xof_init(&ctx1, seed, SEED_BYTES);
        uint32_t support[PARAM_OMEGA_R];
        vect_generate_random_support2(&ctx1, support, PARAM_OMEGA_R);
        uint64_t v_decomposed[VEC_N_SIZE_64];
        memset(v_decomposed, 0, sizeof(v_decomposed));
        vect_write_support_to_vector(v_decomposed, support, PARAM_OMEGA_R);

        shake256_xof_ctx ctx2;
        xof_init(&ctx2, seed, SEED_BYTES);
        uint64_t v_combined[VEC_N_SIZE_64];
        memset(v_combined, 0, sizeof(v_combined));
        vect_sample_fixed_weight2(&ctx2, v_combined, PARAM_OMEGA_R);

        int match = (memcmp(v_decomposed, v_combined, sizeof(v_decomposed)) == 0);
        printf("    {\"sampler\": 2, \"weight\": %d, \"match\": %s}\n",
               PARAM_OMEGA_R, match ? "true" : "false");
    }

    printf("  ],\n");
}

/* Two consecutive sampler1 calls on the same XOF (keygen pattern: y then x).
 * This catches byte-consumption mismatches between Go and C. */
static void gen_consecutive_sampler1(void) {
    printf("  \"consecutive_sampler1\": [\n");

    for (int t = 0; t < 2; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 37 + i + 10);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        /* First call: y (weight = PARAM_OMEGA) */
        uint32_t support_y[PARAM_OMEGA];
        vect_generate_random_support1(&ctx, support_y, PARAM_OMEGA);
        uint64_t v_y[VEC_N_SIZE_64];
        memset(v_y, 0, sizeof(v_y));
        vect_write_support_to_vector(v_y, support_y, PARAM_OMEGA);

        /* Second call on SAME ctx: x (weight = PARAM_OMEGA) */
        uint32_t support_x[PARAM_OMEGA];
        vect_generate_random_support1(&ctx, support_x, PARAM_OMEGA);
        uint64_t v_x[VEC_N_SIZE_64];
        memset(v_x, 0, sizeof(v_x));
        vect_write_support_to_vector(v_x, support_x, PARAM_OMEGA);

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"y_positions\": ");
        print_support(support_y, PARAM_OMEGA);
        printf(", \"x_positions\": ");
        print_support(support_x, PARAM_OMEGA);
        printf(", \"y_vector_hex\": \"");
        print_hex_bytes((uint8_t *)v_y, VEC_N_SIZE_BYTES);
        printf("\", \"x_vector_hex\": \"");
        print_hex_bytes((uint8_t *)v_x, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 1 ? "," : "");
    }
    printf("  ],\n");
}

/* Three consecutive sampler2 calls on the same XOF (encrypt pattern: r2, e, r1).
 * Sampler2 consumes exactly 4*weight bytes per call, so XOF state is deterministic. */
static void gen_consecutive_sampler2(void) {
    printf("  \"consecutive_sampler2\": [\n");

    for (int t = 0; t < 2; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(t * 59 + i + 20);

        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);

        /* r2: weight = PARAM_OMEGA_R */
        uint32_t sup_r2[PARAM_OMEGA_R];
        vect_generate_random_support2(&ctx, sup_r2, PARAM_OMEGA_R);
        uint64_t v_r2[VEC_N_SIZE_64];
        memset(v_r2, 0, sizeof(v_r2));
        vect_write_support_to_vector(v_r2, sup_r2, PARAM_OMEGA_R);

        /* e: weight = PARAM_OMEGA_E */
        uint32_t sup_e[PARAM_OMEGA_E];
        vect_generate_random_support2(&ctx, sup_e, PARAM_OMEGA_E);
        uint64_t v_e[VEC_N_SIZE_64];
        memset(v_e, 0, sizeof(v_e));
        vect_write_support_to_vector(v_e, sup_e, PARAM_OMEGA_E);

        /* r1: weight = PARAM_OMEGA_R */
        uint32_t sup_r1[PARAM_OMEGA_R];
        vect_generate_random_support2(&ctx, sup_r1, PARAM_OMEGA_R);
        uint64_t v_r1[VEC_N_SIZE_64];
        memset(v_r1, 0, sizeof(v_r1));
        vect_write_support_to_vector(v_r1, sup_r1, PARAM_OMEGA_R);

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"r2_positions\": ");
        print_support(sup_r2, PARAM_OMEGA_R);
        printf(", \"e_positions\": ");
        print_support(sup_e, PARAM_OMEGA_E);
        printf(", \"r1_positions\": ");
        print_support(sup_r1, PARAM_OMEGA_R);
        printf(", \"r2_vector_hex\": \"");
        print_hex_bytes((uint8_t *)v_r2, VEC_N_SIZE_BYTES);
        printf("\", \"e_vector_hex\": \"");
        print_hex_bytes((uint8_t *)v_e, VEC_N_SIZE_BYTES);
        printf("\", \"r1_vector_hex\": \"");
        print_hex_bytes((uint8_t *)v_r1, VEC_N_SIZE_BYTES);
        printf("\"}%s\n", t < 1 ? "," : "");
    }
    printf("  ],\n");
}

/* Fixed-point multiply vectors for sampler 2's reduction formula */
static void gen_fixed_point_multiply(void) {
    printf("  \"fixed_point_multiply\": [\n");

    /* Test the formula: i + ((buff * (PARAM_N - i)) >> 32) */
    struct { uint32_t buff; uint32_t i; } cases[] = {
        {0, 0},
        {0xFFFFFFFF, 0},
        {0, PARAM_OMEGA_R - 1},
        {0xFFFFFFFF, PARAM_OMEGA_R - 1},
        {0, PARAM_OMEGA_E - 1},
        {0xFFFFFFFF, PARAM_OMEGA_E - 1},
        {0x80000000, 0},
        {0x80000000, PARAM_OMEGA_R / 2},
        {12345678, 0},
        {12345678, 10},
        {12345678, 50},
        {0xDEADBEEF, 0},
        {0xDEADBEEF, PARAM_OMEGA_R - 1},
        {1, 0},
        {PARAM_N - 1, 0},
    };
    int n = sizeof(cases) / sizeof(cases[0]);

    for (int t = 0; t < n; t++) {
        uint32_t buff = cases[t].buff;
        uint32_t i = cases[t].i;
        uint32_t result = i + (uint32_t)(((uint64_t)buff * (PARAM_N - i)) >> 32);

        if (t > 0) printf(",\n");
        printf("    {\"buff\": %u, \"i\": %u, \"param_n\": %u, \"result\": %u}",
               buff, i, (uint32_t)PARAM_N, result);
    }
    printf("\n  ],\n");
}

/* Parameters for cross-checking */
static void gen_params(void) {
    printf("  \"parameters\": {\n");
    printf("    \"param_n\": %d,\n", PARAM_N);
    printf("    \"param_omega\": %d,\n", PARAM_OMEGA);
    printf("    \"param_omega_e\": %d,\n", PARAM_OMEGA_E);
    printf("    \"param_omega_r\": %d,\n", PARAM_OMEGA_R);
    printf("    \"param_n_mu\": %llu,\n", (unsigned long long)PARAM_N_MU);
    printf("    \"rejection_threshold\": %u,\n", (uint32_t)UTILS_REJECTION_THRESHOLD);
    printf("    \"seed_bytes\": %d\n", SEED_BYTES);
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
    printf("  \"param_set\": \"%s\",\n", name);
    printf("  \"type\": \"samplers\",\n");

    gen_sampler1_vectors();
    gen_sampler2_vectors();
    gen_sampler2_omega_e_vectors();
    gen_combined_sampler_check();
    gen_consecutive_sampler1();
    gen_consecutive_sampler2();
    gen_fixed_point_multiply();
    gen_params();

    printf("}\n");
    return 0;
}
