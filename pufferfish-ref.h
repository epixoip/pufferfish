#pragma once

#define shr(x,n) (x >> n)
#define shl(x,n) (x << n)
#define rotr64(x,n) (shr(x,n) | (x << (64 - n)))
#define rotl64(x,n) (shl(x,n) | (x >> (64 - n)))

#define quarter(a,b,c,d) \
    v[a] += v[b]; t = v[d]^v[a]; v[d] = rotl64(t,32); \
    v[c] += v[d]; t = v[b]^v[c]; v[b] = rotl64(t,24); \
    v[a] += v[b]; t = v[d]^v[a]; v[d] = rotl64(t,16); \
    v[c] += v[d]; t = v[b]^v[c]; v[b] = rotl64(t,63);


#define uint8_to_uint64(n,b,c)             \
{                                          \
    (n) = ( (uint64_t) (b)[(c)  ] << 56 )  \
        | ( (uint64_t) (b)[(c)+1] << 48 )  \
        | ( (uint64_t) (b)[(c)+2] << 40 )  \
        | ( (uint64_t) (b)[(c)+3] << 32 )  \
        | ( (uint64_t) (b)[(c)+4] << 24 )  \
        | ( (uint64_t) (b)[(c)+5] << 16 )  \
        | ( (uint64_t) (b)[(c)+6] <<  8 )  \
        | ( (uint64_t) (b)[(c)+7]       ); \
}

#define uint64_to_uchar(n,b,c)                          \
{                                                       \
    (b)[(c)  ] = (unsigned char) ( (n) >> 56 & 0xff );  \
    (b)[(c)+1] = (unsigned char) ( (n) >> 48 & 0xff );  \
    (b)[(c)+2] = (unsigned char) ( (n) >> 40 & 0xff );  \
    (b)[(c)+3] = (unsigned char) ( (n) >> 32 & 0xff );  \
    (b)[(c)+4] = (unsigned char) ( (n) >> 24 & 0xff );  \
    (b)[(c)+5] = (unsigned char) ( (n) >> 16 & 0xff );  \
    (b)[(c)+6] = (unsigned char) ( (n) >>  8 & 0xff );  \
    (b)[(c)+7] = (unsigned char) ( (n)       & 0xff );  \
}

#define NUM_SBOXES 4			/* number of sboxes */
#define WORDSIZ	sizeof (uint64_t)	/* number of bytes per word */
#define PUF_N 16			/* number of subkeys */
#define STATE_N 16			/* number of words in state */
#define BLOCKSIZ 16			/* number of bytes in a block */
#define DIGEST_LEN SHA512_DIGEST_LENGTH	/* digest length */

typedef enum { false, true } bool;

typedef struct pufferfish_context
{
	uint64_t P[PUF_N + 2];          /* p-array */
	uint64_t *S[NUM_SBOXES];	/* s-boxes */
	uint64_t state[STATE_N];	/* sbox fill state */
	uint64_t key[4];		/* generated key */
	uint64_t salt[4];		/* hashed salt */
	unsigned int m_cost;		/* in MiB  */
	unsigned int sbox_words;	/* words per sbox */
} puf_ctx;

