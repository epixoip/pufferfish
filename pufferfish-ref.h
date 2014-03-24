#pragma once

#define char64(c)((c) > 127 ? 255 : index64[(c)])

#define shr(x,n) (x >> n)
#define shl(x,n) (x << n)
#define rotr64(x,n) (shr(x,n) | (x << (64 - n)))
#define rotl64(x,n) (shl(x,n) | (x >> (64 - n)))

#define uint8_to_uint64(n,b,c)		   \
{					   \
    (n) = ( (uint64_t) (b)[(c)  ] << 56 )  \
	| ( (uint64_t) (b)[(c)+1] << 48 )  \
	| ( (uint64_t) (b)[(c)+2] << 40 )  \
	| ( (uint64_t) (b)[(c)+3] << 32 )  \
	| ( (uint64_t) (b)[(c)+4] << 24 )  \
	| ( (uint64_t) (b)[(c)+5] << 16 )  \
	| ( (uint64_t) (b)[(c)+6] <<  8 )  \
	| ( (uint64_t) (b)[(c)+7]       ); \
}

#define uint64_to_uchar(n,b,c)				\
{							\
    (b)[(c)  ] = (unsigned char) ( (n) >> 56 & 0xff );  \
    (b)[(c)+1] = (unsigned char) ( (n) >> 48 & 0xff );  \
    (b)[(c)+2] = (unsigned char) ( (n) >> 40 & 0xff );  \
    (b)[(c)+3] = (unsigned char) ( (n) >> 32 & 0xff );  \
    (b)[(c)+4] = (unsigned char) ( (n) >> 24 & 0xff );  \
    (b)[(c)+5] = (unsigned char) ( (n) >> 16 & 0xff );  \
    (b)[(c)+6] = (unsigned char) ( (n) >>  8 & 0xff );  \
    (b)[(c)+7] = (unsigned char) ( (n)       & 0xff );  \
}

#define PUF_ID "$PF$"			/* hash identification str */
#define PUF_ID_LEN strlen (PUF_ID)	/* length of the identifier */
#define NUM_SBOXES 4			/* number of sboxes */
#define WORDSIZ	sizeof (uint64_t)	/* number of bytes per word */
#define PUF_N 16			/* number of subkeys */
#define STATE_N 8			/* number of words in state */
#define BLOCKSIZ 16			/* number of bytes in a block */
#define DIGEST_LEN SHA512_DIGEST_LENGTH	/* digest length */
#define KEYSIZ DIGEST_LEN / sizeof (uint64_t)

typedef enum { false, true } bool;

typedef struct pufferfish_context
{
	uint64_t P[PUF_N + 2];		/* p-array */
	uint64_t *S[NUM_SBOXES];	/* s-boxes */
//	uint64_t state[STATE_N];	/* sbox fill state */
	unsigned char *state;
	uint64_t key[KEYSIZ];		/* generated key */
	uint64_t salt[KEYSIZ];		/* hashed salt */
	unsigned int m_cost;		/* in KiB  */
	unsigned int sbox_words;	/* words per sbox */
} puf_ctx;

const static unsigned char itoa64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static unsigned char index64[128] = {
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
	255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	255, 255, 255, 255, 255, 255, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 255, 255, 255, 255, 255
};

