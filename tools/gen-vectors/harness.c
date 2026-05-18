/*
 * harness.c - Generate KAT vectors + accumulated hashes from HQC v5.0.0.
 *
 * Official HQC repo: https://gitlab.com/pqc-hqc/hqc/ (tag v5.0.0)
 *
 * Outputs:
 *   1. KAT vectors (keygen + encaps) as JSON to stdout
 *   2. Accumulated hashes (SHAKE128) at tiers 10..1M to stderr
 *
 * Build (from /tmp/hqc-official, for each param set P=1,3,5):
 *   cc -O2 -std=c11 -DHQC_PARAM=P -Icompat \
 *     -Isrc/ref/hqc-P -Isrc/ref -Isrc/common/hqc-P -Isrc/common \
 *     -Ilib -Ilib/fips202 \
 *     /path/to/harness.c \
 *     src/ref/gf.c src/ref/gf2x.c src/ref/hqc.c src/ref/parsing.c \
 *     src/ref/reed_muller.c src/ref/reed_solomon.c src/ref/vector.c \
 *     src/common/code.c src/common/crypto_memset.c src/common/fft.c \
 *     src/common/kem.c src/common/symmetric.c lib/fips202/fips202.c \
 *     -o harness_hqcP
 *
 *   ./harness_hqcP > vectors_hqcP.json 2> accumulated_hqcP.txt
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "symmetric.h"
#include "fips202.h"

/* --- KAT vectors (10 keygen + 10 encaps) --- */

#define KAT_COUNT 10

static void print_hex(FILE *f, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
}

static void generate_kat_vectors(void) {
    uint8_t entropy_master[48];
    uint8_t seed[48];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];

    /* Master PRNG: entropy = [0..47] */
    for (int i = 0; i < 48; i++) entropy_master[i] = (uint8_t)i;
    prng_init(entropy_master, NULL, 48, 0);

    /* Keygen vectors */
    printf("  \"keygen\": [\n");
    for (int i = 0; i < KAT_COUNT; i++) {
        prng_get_bytes(seed, 48);

        /* Per-vector PRNG from this seed */
        prng_init(seed, NULL, 48, 0);
        crypto_kem_keypair(pk, sk);

        printf("    {\"tcId\": %d, \"entropy\": \"", i + 1);
        print_hex(stdout, seed, 48);
        printf("\", \"pk\": \"");
        print_hex(stdout, pk, CRYPTO_PUBLICKEYBYTES);
        printf("\", \"sk\": \"");
        print_hex(stdout, sk, CRYPTO_SECRETKEYBYTES);
        printf("\"}%s\n", i < KAT_COUNT - 1 ? "," : "");
    }
    printf("  ],\n");

    /* Encaps vectors: use the LAST keypair from keygen */
    /* Re-init master for encaps seeds */
    for (int i = 0; i < 48; i++) entropy_master[i] = (uint8_t)(i + 48);
    prng_init(entropy_master, NULL, 48, 0);

    printf("  \"key_entropy\": \"");
    print_hex(stdout, seed, 48); /* last keygen seed */
    printf("\",\n");
    printf("  \"pk\": \"");
    print_hex(stdout, pk, CRYPTO_PUBLICKEYBYTES);
    printf("\",\n");

    printf("  \"encaps\": [\n");
    for (int i = 0; i < KAT_COUNT; i++) {
        uint8_t enc_seed[48];
        prng_get_bytes(enc_seed, 48);

        prng_init(enc_seed, NULL, 48, 0);
        crypto_kem_enc(ct, ss, pk);
        crypto_kem_dec(ss_dec, ct, sk);

        if (memcmp(ss, ss_dec, CRYPTO_BYTES) != 0) {
            fprintf(stderr, "FATAL: ss mismatch at encaps vector %d\n", i + 1);
            return;
        }

        printf("    {\"tcId\": %d, \"encaps_entropy\": \"", i + 1);
        print_hex(stdout, enc_seed, 48);
        printf("\", \"ct\": \"");
        print_hex(stdout, ct, CRYPTO_CIPHERTEXTBYTES);
        printf("\", \"ss\": \"");
        print_hex(stdout, ss, CRYPTO_BYTES);
        printf("\"}%s\n", i < KAT_COUNT - 1 ? "," : "");
    }
    printf("  ]\n");
}

/* --- Accumulated hashes (SHAKE128, Filippo pattern) --- */

static void generate_accumulated(void) {
    int tiers[] = {10, 100, 1000, 10000, 100000, 1000000};
    int num_tiers = 6;
    int tier_idx = 0;

    /* SHAKE128 entropy source (empty init, deterministic) */
    shake128incctx source;
    shake128_inc_init(&source);
    shake128_inc_finalize(&source);

    /* SHAKE128 accumulator */
    shake128incctx accum;
    shake128_inc_init(&accum);

    uint8_t entropy[48];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];

    int max_tier = tiers[num_tiers - 1];

    for (int i = 0; i < max_tier; i++) {
        /* Keygen entropy from source */
        shake128_inc_squeeze(entropy, 48, &source);
        prng_init(entropy, NULL, 48, 0);
        crypto_kem_keypair(pk, sk);

        shake128_inc_absorb(&accum, pk, CRYPTO_PUBLICKEYBYTES);
        shake128_inc_absorb(&accum, sk, CRYPTO_SECRETKEYBYTES);

        /* Encaps entropy from source */
        shake128_inc_squeeze(entropy, 48, &source);
        prng_init(entropy, NULL, 48, 0);
        crypto_kem_enc(ct, ss_enc, pk);

        shake128_inc_absorb(&accum, ct, CRYPTO_CIPHERTEXTBYTES);
        shake128_inc_absorb(&accum, ss_enc, CRYPTO_BYTES);

        /* Decaps */
        crypto_kem_dec(ss_dec, ct, sk);
        shake128_inc_absorb(&accum, ss_dec, CRYPTO_BYTES);

        /* Check tier completion */
        if (tier_idx < num_tiers && (i + 1) == tiers[tier_idx]) {
            /* Snapshot: clone accum, finalize clone, squeeze hash */
            shake128incctx snapshot;
            memcpy(&snapshot, &accum, sizeof(shake128incctx));
            shake128_inc_finalize(&snapshot);
            uint8_t hash[32];
            shake128_inc_squeeze(hash, 32, &snapshot);

            fprintf(stderr, "  %d: ", tiers[tier_idx]);
            for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", hash[j]);
            fprintf(stderr, "\n");
            fflush(stderr);

            tier_idx++;
        }

        if ((i + 1) % 10000 == 0) {
            fprintf(stderr, "  progress: %d/%d\n", i + 1, max_tier);
            fflush(stderr);
        }
    }
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

    fprintf(stderr, "=== %s (pk=%d sk=%d ct=%d ss=%d) ===\n",
            name, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
            CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES);

    /* JSON output */
    printf("{\n");
    printf("  \"algorithm\": \"HQC\",\n");
    printf("  \"version\": \"v5.0.0\",\n");
    printf("  \"source\": \"https://gitlab.com/pqc-hqc/hqc/ tag v5.0.0\",\n");
    printf("  \"param_set\": \"%s\",\n", name);
    printf("  \"pk_bytes\": %d,\n", CRYPTO_PUBLICKEYBYTES);
    printf("  \"sk_bytes\": %d,\n", CRYPTO_SECRETKEYBYTES);
    printf("  \"ct_bytes\": %d,\n", CRYPTO_CIPHERTEXTBYTES);
    printf("  \"ss_bytes\": %d,\n", CRYPTO_BYTES);

    generate_kat_vectors();

    printf("}\n");

    /* Accumulated hashes to stderr */
    fprintf(stderr, "Accumulated hashes:\n");
    generate_accumulated();
    fprintf(stderr, "DONE\n");

    return 0;
}
