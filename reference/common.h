#pragma once

#define shr(x,n) (x >> n)
#define shl(x,n) (x << n)

#define NUM_SBOXES 4                    /* number of sboxes */
#define DIGEST_LEN SHA512_DIGEST_LENGTH /* digest length */
#define PUF_N 16                        /* number of subkeys */
#define KEYSIZ DIGEST_LEN / sizeof (uint64_t)

typedef struct pufferfish_context
{
        uint64_t P[PUF_N + 2];          /* p-array */
        uint64_t *S[NUM_SBOXES];        /* s-boxes */
        uint64_t key[KEYSIZ];           /* generated key */
        uint64_t salt[KEYSIZ];          /* hashed salt */
        unsigned int m_cost;            /* in KiB  */
        unsigned int sbox_words;        /* words per sbox */
} puf_ctx;

