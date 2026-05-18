/*
 * edge_cases.c - Generate edge case and error path vectors from HQC v5.0.0.
 *
 * Tests error paths and boundary conditions:
 *   1. GF(2^m) multiplication exhaustive sample (81 pairs)
 *   2. RS decode with injected errors (varying error counts)
 *   3. vect_set_random: XOF -> full N-bit random vector
 *   4. Implicit rejection: modified ct -> different ss, cross-verified with hash_j
 *   5. Hash function G/H/I/J outputs for known inputs (J includes raw u/v/salt)
 *
 * Build: same as intermediates.c but with this file instead.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "parameters.h"
#include "data_structures.h"
#include "symmetric.h"
#include "vector.h"
#include "gf.h"
#include "code.h"

extern void reed_solomon_encode(uint64_t *cdw, const uint64_t *msg);
extern void reed_solomon_decode(uint64_t *msg, uint64_t *cdw);

static void print_hex_bytes(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) fprintf(stdout, "%02x", data[i]);
}

/* 1. GF multiply sample - 9x9 = 81 pairs covering edge cases */
static void gen_gf_multiply(void) {
    printf("  \"gf_multiply\": [\n");
    int count = 0;
    /* Test: 0*x, 1*x, x*x, generator poly cases, and random sample */
    uint16_t test_a[] = {0, 1, 2, 3, 127, 128, 255, 0x100, 0x1FF};
    uint16_t test_b[] = {0, 1, 2, 3, 127, 128, 255, 0x100, 0x1FF};
    int na = sizeof(test_a)/sizeof(test_a[0]);
    int nb = sizeof(test_b)/sizeof(test_b[0]);

    for (int i = 0; i < na; i++) {
        for (int j = 0; j < nb; j++) {
            uint16_t a = test_a[i];
            uint16_t b = test_b[j];
            uint16_t product = gf_mul(a, b);

            if (count > 0) printf(",\n");
            printf("    {\"a\": %d, \"b\": %d, \"product\": %d}", a, b, product);
            count++;
        }
    }
    printf("\n  ],\n");
}

/* 2. RS decode with injected errors */
static void gen_rs_error_correction(void) {
    printf("  \"reed_solomon_decode_errors\": [\n");

    int error_counts[] = {1, PARAM_DELTA/2, PARAM_DELTA};
    int num_tests = 3;

    for (int t = 0; t < num_tests; t++) {
        int num_errors = error_counts[t];

        /* Create a message */
        uint64_t msg[VEC_N1_SIZE_64];
        memset(msg, 0, sizeof(msg));
        uint8_t *msg_bytes = (uint8_t *)msg;
        for (int i = 0; i < PARAM_K; i++) {
            msg_bytes[i] = (uint8_t)(t * 41 + i + 7);
        }

        /* Encode */
        uint64_t cdw[VEC_N1_SIZE_64];
        memcpy(cdw, msg, sizeof(msg));
        reed_solomon_encode(cdw, msg);

        /* Inject errors at deterministic positions */
        uint8_t *cdw_bytes = (uint8_t *)cdw;
        for (int e = 0; e < num_errors; e++) {
            int pos = (e * 7 + 3) % PARAM_N1; /* deterministic positions */
            cdw_bytes[pos] ^= (uint8_t)(e + 1); /* non-zero error value */
        }

        /* Decode */
        uint64_t decoded[VEC_N1_SIZE_64];
        memcpy(decoded, cdw, sizeof(cdw));
        reed_solomon_decode(decoded, decoded);

        /* Check if decoded matches original message */
        int match = (memcmp(msg_bytes, (uint8_t *)decoded, PARAM_K) == 0);

        printf("    {\"errors\": %d, \"delta\": %d, \"message\": \"", num_errors, PARAM_DELTA);
        print_hex_bytes(msg_bytes, PARAM_K);
        printf("\", \"decoded\": \"");
        print_hex_bytes((uint8_t *)decoded, PARAM_K);
        printf("\", \"corrected\": %s}%s\n", match ? "true" : "false", t < num_tests - 1 ? "," : "");
    }
    printf("  ],\n");
}

/* 3. vect_set_random: XOF -> full random N-bit vector (tests XOF squeeze of VEC_N_SIZE_BYTES) */
static void gen_vect_set_random(void) {
    printf("  \"vect_set_random\": [\n");

    uint8_t seeds[][1] = {{200}, {150}};
    for (int t = 0; t < 2; t++) {
        uint8_t seed[SEED_BYTES];
        for (int i = 0; i < SEED_BYTES; i++) seed[i] = (uint8_t)(i + seeds[t][0]);
        shake256_xof_ctx ctx;
        xof_init(&ctx, seed, SEED_BYTES);
        uint64_t v[VEC_N_SIZE_64];
        memset(v, 0, sizeof(v));
        vect_set_random(&ctx, v);

        int weight = 0;
        for (size_t i = 0; i < VEC_N_SIZE_64; i++) {
            uint64_t x = v[i];
            while (x) { weight++; x &= x - 1; }
        }

        printf("    {\"seed\": \"");
        print_hex_bytes(seed, SEED_BYTES);
        printf("\", \"weight\": %d, \"param_n\": %d, \"first_64_bytes\": \"", weight, PARAM_N);
        print_hex_bytes((uint8_t *)v, 64);
        printf("\"}%s\n", t < 1 ? "," : "");
    }
    printf("  ],\n");
}

/* 4. Implicit rejection: modified ct -> different ss */
static void gen_implicit_rejection(void) {
    printf("  \"implicit_rejection\": [\n");

    /* Generate a keypair (static to avoid stack overflow on large param sets) */
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_valid[CRYPTO_BYTES];
    static uint8_t ss_reject[CRYPTO_BYTES];

    /* Use deterministic PRNG - fresh init for keygen */
    uint8_t entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (uint8_t)(i + 200);
    prng_init(entropy, NULL, 48, 0);
    if (crypto_kem_keypair(pk, sk) != 0) {
        printf("    {\"error\": \"keypair failed\"}]\n");
        return;
    }

    /* Fresh init for encaps */
    for (int i = 0; i < 48; i++) entropy[i] = (uint8_t)(i + 248);
    prng_init(entropy, NULL, 48, 0);
    if (crypto_kem_enc(ct, ss_valid, pk) != 0) {
        printf("    {\"error\": \"enc failed\"}]\n");
        return;
    }

    /* Valid decaps */
    crypto_kem_dec(ss_valid, ct, sk);

    /* Compute H(pk) and extract sigma for hash_j cross-verification */
    uint8_t ir_h_ek[SEED_BYTES];
    hash_h(ir_h_ek, pk);
    uint8_t ir_sigma[PARAM_SECURITY_BYTES];
    memcpy(ir_sigma, sk + CRYPTO_PUBLICKEYBYTES + SEED_BYTES, PARAM_SECURITY_BYTES);

    /* Modify ct at different positions and verify rejection.
     * Cross-verify: reject_ss must equal hash_j(h_ek, sigma, modified_ct). */
    int positions[] = {0, CRYPTO_CIPHERTEXTBYTES/2, CRYPTO_CIPHERTEXTBYTES - 1};
    for (int t = 0; t < 3; t++) {
        static uint8_t ct_mod[CRYPTO_CIPHERTEXTBYTES];
        memcpy(ct_mod, ct, CRYPTO_CIPHERTEXTBYTES);
        ct_mod[positions[t]] ^= 0x01;

        crypto_kem_dec(ss_reject, ct_mod, sk);

        /* Independently compute hash_j for this modified ciphertext */
        ciphertext_kem_t c_kem_ir;
        memset(&c_kem_ir, 0, sizeof(c_kem_ir));
        memcpy(c_kem_ir.c_pke.u, ct_mod, VEC_N_SIZE_BYTES);
        memcpy(c_kem_ir.c_pke.v, ct_mod + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES);
        memcpy(c_kem_ir.salt, ct_mod + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, SALT_BYTES);
        uint8_t j_expected[32]; /* SHA3-256 always 32 bytes */
        hash_j(j_expected, ir_h_ek, ir_sigma, &c_kem_ir);

        int different = (memcmp(ss_valid, ss_reject, CRYPTO_BYTES) != 0);
        int ss_nonzero = 0;
        for (int i = 0; i < CRYPTO_BYTES; i++) {
            if (ss_reject[i] != 0) { ss_nonzero = 1; break; }
        }
        int j_matches = (memcmp(ss_reject, j_expected, 32) == 0);

        printf("    {\"modified_pos\": %d, \"different_ss\": %s, \"ss_nonzero\": %s, \"j_cross_check\": %s, \"reject_ss\": \"",
               positions[t], different ? "true" : "false", ss_nonzero ? "true" : "false",
               j_matches ? "true" : "false");
        print_hex_bytes(ss_reject, CRYPTO_BYTES);
        printf("\"}%s\n", t < 2 ? "," : "");
    }
    /* Zero SK (contains sigma and seed_kem) */
    memset(sk, 0, CRYPTO_SECRETKEYBYTES);
    printf("  ],\n");
}

/* 5. Hash function outputs for known inputs */
static void gen_hash_outputs(void) {
    printf("  \"hash_functions\": {\n");

    /* hash_g: G(h_ek, m, salt) */
    uint8_t h_ek[SEED_BYTES];
    uint8_t m[VEC_K_SIZE_BYTES];
    uint8_t salt[SALT_BYTES];
    uint8_t output_g[64]; /* SHA3-512 output */

    for (int i = 0; i < SEED_BYTES; i++) h_ek[i] = (uint8_t)i;
    for (int i = 0; i < VEC_K_SIZE_BYTES; i++) m[i] = (uint8_t)(i + 32);
    for (int i = 0; i < SALT_BYTES; i++) salt[i] = (uint8_t)(i + 64);

    hash_g(output_g, h_ek, m, salt);

    printf("    \"G\": {\"h_ek\": \"");
    print_hex_bytes(h_ek, SEED_BYTES);
    printf("\", \"m\": \"");
    print_hex_bytes(m, VEC_K_SIZE_BYTES);
    printf("\", \"salt\": \"");
    print_hex_bytes(salt, SALT_BYTES);
    printf("\", \"output\": \"");
    print_hex_bytes(output_g, 64);
    printf("\"},\n");

    /* hash_h: H(pk) */
    static uint8_t pk_h[CRYPTO_PUBLICKEYBYTES];
    memset(pk_h, 0x42, CRYPTO_PUBLICKEYBYTES);
    uint8_t output_h[32]; /* SHA3-256 always 32 bytes */
    hash_h(output_h, pk_h);

    printf("    \"H\": {\"pk_fill\": \"0x42\", \"pk_bytes\": %d, \"output\": \"", CRYPTO_PUBLICKEYBYTES);
    print_hex_bytes(output_h, 32);
    printf("\"},\n");

    /* hash_i: I(seed) - SHA3-512, outputs 64 bytes */
    uint8_t seed_i[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++) seed_i[i] = (uint8_t)(i + 128);
    uint8_t output_i[64]; /* SHA3-512 produces 64 bytes */
    hash_i(output_i, seed_i);

    printf("    \"I\": {\"seed\": \"");
    print_hex_bytes(seed_i, SEED_BYTES);
    printf("\", \"output\": \"");
    print_hex_bytes(output_i, 64);
    printf("\"},\n");

    /* hash_j: J(h_ek, sigma, c_kem) - SHA3-256, outputs 32 bytes */
    /* Generate a keypair and ciphertext to construct a valid ciphertext_kem_t */
    {
        static uint8_t j_pk[CRYPTO_PUBLICKEYBYTES];
        static uint8_t j_sk[CRYPTO_SECRETKEYBYTES];
        static uint8_t j_ct[CRYPTO_CIPHERTEXTBYTES];
        static uint8_t j_ss[CRYPTO_BYTES];

        uint8_t j_entropy[48];
        for (int i = 0; i < 48; i++) j_entropy[i] = (uint8_t)(i + 50);
        prng_init(j_entropy, NULL, 48, 0);
        crypto_kem_keypair(j_pk, j_sk);

        for (int i = 0; i < 48; i++) j_entropy[i] = (uint8_t)(i + 98);
        prng_init(j_entropy, NULL, 48, 0);
        crypto_kem_enc(j_ct, j_ss, j_pk);

        /* Zero shared secret immediately - not needed after encaps */
        memset(j_ss, 0, CRYPTO_BYTES);

        /* Parse ciphertext into ciphertext_kem_t struct.
         * Zero-init first: u[VEC_N_SIZE_64] and v[VEC_N_SIZE_64] are larger than
         * the serialized VEC_N_SIZE_BYTES and VEC_N1N2_SIZE_BYTES. Padding must be zero. */
        ciphertext_kem_t c_kem_j;
        memset(&c_kem_j, 0, sizeof(c_kem_j));
        memcpy(c_kem_j.c_pke.u, j_ct, VEC_N_SIZE_BYTES);
        memcpy(c_kem_j.c_pke.v, j_ct + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES);
        memcpy(c_kem_j.salt, j_ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, SALT_BYTES);

        /* Compute H(pk) for hash_j input */
        uint8_t j_h_ek[SEED_BYTES];
        hash_h(j_h_ek, j_pk);

        /* Extract sigma from SK: sk = pk || seed_dk || sigma || seed_kem */
        uint8_t j_sigma[PARAM_SECURITY_BYTES];
        memcpy(j_sigma, j_sk + CRYPTO_PUBLICKEYBYTES + SEED_BYTES, PARAM_SECURITY_BYTES);

        uint8_t output_j[32]; /* SHA3-256 output */
        hash_j(output_j, j_h_ek, j_sigma, &c_kem_j);

        /* Output all hash_j inputs so Go can verify independently without
         * reproducing the full KEM pipeline */
        printf("    \"J\": {\"h_ek\": \"");
        print_hex_bytes(j_h_ek, SEED_BYTES);
        printf("\", \"sigma\": \"");
        print_hex_bytes(j_sigma, PARAM_SECURITY_BYTES);
        printf("\", \"u\": \"");
        print_hex_bytes((uint8_t *)c_kem_j.c_pke.u, VEC_N_SIZE_BYTES);
        printf("\", \"v\": \"");
        print_hex_bytes((uint8_t *)c_kem_j.c_pke.v, VEC_N1N2_SIZE_BYTES);
        printf("\", \"salt\": \"");
        print_hex_bytes(c_kem_j.salt, SALT_BYTES);
        printf("\", \"u_bytes\": %d, \"v_bytes\": %d, \"salt_bytes\": %d", VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, SALT_BYTES);
        printf(", \"keygen_entropy\": \"");
        for (int i = 0; i < 48; i++) fprintf(stdout, "%02x", (uint8_t)(i + 50));
        printf("\", \"encaps_entropy\": \"");
        for (int i = 0; i < 48; i++) fprintf(stdout, "%02x", (uint8_t)(i + 98));
        printf("\", \"output\": \"");
        print_hex_bytes(output_j, 32);
        printf("\"}\n");

        /* Zero SK (contains sigma and seed_kem) */
        memset(j_sk, 0, CRYPTO_SECRETKEYBYTES);
    }
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
    printf("  \"type\": \"edge_cases\",\n");

    gen_gf_multiply();
    gen_rs_error_correction();
    gen_vect_set_random();
    gen_implicit_rejection();
    gen_hash_outputs();

    printf("}\n");
    return 0;
}
