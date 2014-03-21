#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "pufferfish-ref.h"


void __chacha64 (uint64_t v[16])
{
	/* chacha8 modified to use 64-bit words */

        uint64_t t = 0;
        int rounds = 8;

        for (; rounds; rounds -= 2)
        {
                quarter (0,4, 8,12)
                quarter (1,5, 9,13)
                quarter (2,6,10,14)
                quarter (3,7,11,15)
                quarter (0,5,10,15)
                quarter (1,6,11,12)
                quarter (2,7, 8,13)
                quarter (3,4, 9,14)
        }
}

void pufferfish_initstate (puf_ctx *context, const void *password, size_t password_len, const void *salt, size_t salt_len, unsigned int m_cost)
{
	/* this function is absolutely nothing like Blowfish_initstate(),
	   and is really what defines pufferfish. */

	int i, j, k;
	unsigned char *state_left, *state_right, *key_hash;
	unsigned char salt_hash[DIGEST_LEN];

	/* initialize the P-array with digits of Pi. this is the only part
	   of the function that resembles Blowfish_initstate() */
	puf_ctx initstate =
	{
		{
			0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0,
			0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
			0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917, 0x9216d5d98979fb1b,
			0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
			0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16,
			0x636920d871574e69, 0xa458fea3f4933d7e, 0x0d95748f728eb658
		}
	};

        uint8_t *state_ptr = (uint8_t *) initstate.state;

	/* calculate number of words per s-box */
	initstate.m_cost = m_cost;
	initstate.sbox_words = (m_cost * 1024) / NUM_SBOXES / WORDSIZ;


	/* the following steps initialize the dynamic s-boxes: */

	/* step 1: hash the salt with sha512 to generate the hmac key */
	SHA512 ((const unsigned char *) salt, salt_len, salt_hash);

	/* step 2: hmac-sha512 the password using the hashed salt as
	   the key to derive the first half of the initial state */
	state_right = HMAC (EVP_sha512(), salt_hash, DIGEST_LEN, (const unsigned char *) password, password_len, NULL, NULL);

	/* step 3: hmac-sha512 the password again, this time using
	   the initial state as the key, to derive the second half */
	state_left = HMAC (EVP_sha512(), state_right, DIGEST_LEN, (const unsigned char *) password, password_len, NULL, NULL);

	/* step 4: initialize the state with the two hmac hashes */
	memmove (state_ptr, state_left, DIGEST_LEN);
	memmove (state_ptr + DIGEST_LEN, state_right, DIGEST_LEN);

	/* step 5: allocate memory for each of the four s-boxes */
	for (i = 0; i < 4; i++)
		initstate.S[i] = (uint64_t *) calloc (initstate.sbox_words, WORDSIZ);

	/* step 6: fill the s-boxes by iterating over the state with chacha64 */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < initstate.sbox_words; j+=STATE_N)
		{
			__chacha64 (initstate.state);

			for (k = 0; k < STATE_N; k++)
				initstate.S[i][j+k] = initstate.state[k];
		}
	}


	/* the following steps derive the initial pufferfish encryption key: */

	/* step 1: iterate over the state with chacha64 a few more times */
	for (i = 0; i < 64; i++)
		__chacha64 (initstate.state);

	/* step 2: hmac-sha512 the password yet again,
	   using the first half the state as the key */
	key_hash = HMAC (EVP_sha512(), initstate.state, DIGEST_LEN, (const unsigned char *) password, password_len, NULL, NULL);

	/* step 3: copy the truncated hmac hash into the key buffer */
	memmove (initstate.key, key_hash, DIGEST_LEN/2);	

	/* step 4: copy the truncated salt hash into the salt buffer */
	memmove (initstate.salt, salt_hash, DIGEST_LEN/2);


	/* set the context */
	*context = initstate;
}


uint64_t pufferfish_f (puf_ctx *context, uint64_t x)
{
	/* modified substantially from the original blowfish implementation,
	   to use dynamic s-box size and to improve the distribution of the
	   random accesses. probably some room for improvement here. */

        uint64_t h = context->S[0][rotr64(x,61) % context->sbox_words]
		   + context->S[1][rotr64(x,22) % context->sbox_words];

        return ( h ^ context->S[2][rotr64(x,53) % context->sbox_words] )
		   + context->S[3][rotr64(x,33) % context->sbox_words];
}


void pufferfish_encipher (puf_ctx *context, uint64_t *LL, uint64_t *RR)
{
	/* this function is identical to Blowfish_encipher(), except
	   it has been modified to use 64-bit words. */

        int i = 0;
        uint64_t L = *LL, R = *RR;

        for (i = 0; i < PUF_N; i+=2)
        {
                L ^= context->P[i];
                R ^= pufferfish_f (context, L);
                R ^= context->P[i+1];
                L ^= pufferfish_f (context, R);
        }

        L ^= context->P[16];
        R ^= context->P[17];

        *LL = R;
        *RR = L;
}


void pufferfish_ecb_encrypt (puf_ctx *context, uint8_t *data, size_t len)
{
        /* this function is identical to blf_ecb_encrypt(), except it has
           been modified to use 64-bit words and a 128-bit blocksize. */

        uint64_t i, L = 0, R = 0;

        for (i = 0; i < len; i+=BLOCKSIZ)
        {
                uint8_to_uint64 (L, data, 0);
                uint8_to_uint64 (R, data, 8);

                pufferfish_encipher (context, &L, &R);

                uint64_to_uchar (L, data, 0);
                uint64_to_uchar (R, data, 8);

                data+=BLOCKSIZ;
        }
}


void pufferfish_expandkey (puf_ctx *context, const uint64_t data[4], const uint64_t key[4])
{
	/* this function is largely identical to Blowfish_expandstate(), except it has been
	   modified to use 64-bit words, dynamic s-box size, and a fixed key and data size
	   of 256 bits. */

        int i, j;
        uint64_t L = 0, R = 0;

        for (i = 0; i < PUF_N + 2; i++)
                context->P[i] ^= key[i%4];

        for (i = 0; i < PUF_N + 2; i+=2)
        {
                L ^= data[i%4];
                R ^= data[i%4];

                pufferfish_encipher (context, &L, &R);

                context->P[i]   = L;
                context->P[i+1] = R;
        }

        for (i = 0; i < 4; i++)
        {
                for (j = 0; j < context->sbox_words; j+=2)
                {
	                /* since we use dynamic s-boxes, this ends up being more expensive than
        	           blowfish for m_cost > 8 because encipher is called $sbox_words times.
                	   in blowfish, encipher is always called 256 times here. in pufferfish,
	                   this is called m_cost*32 times. so for m_cost == 256, this ends up
        	           being 32 times more expensive than blowfish. but this also means that
                	   for e.g. m_cost == 8, this is equally expensive to blowfish at twice
	                   the memory. this should be taken into consideration when selecting an
        	           appropriate t_cost value. */

                        L ^= data[j%4];
                        R ^= data[j%4];

                        pufferfish_encipher (context, &L, &R);

                        context->S[i][j]   = L;
                        context->S[i][j+1] = R;
                }
        }
}


void pufferfish (void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, bool raw)
{
	int i, j, blockcnt;
	uint64_t null_data[4] = { 0 };

	puf_ctx context;

	unsigned char *outbuf;
	unsigned char ctext[] = "Drab as a fool, aloof as a bard.";


	/* initialize the context */
	pufferfish_initstate (&context, in, inlen, salt, saltlen, m_cost);

	/* expand the key */
	pufferfish_expandkey (&context, context.salt, context.key);

	for (i = 0; i < ( 1U << t_cost ); i++)
	{
	        /* this is structurally identical to eksblowfish; however, per above,
        	   t_cost is only identical to eksblowfish's t_cost when m_cost == 8.
	           but all this really means is, don't compare apples and oranges. */

		pufferfish_expandkey (&context, null_data, context.salt);
		pufferfish_expandkey (&context, null_data, context.key);
	}


	/* to support variable output sizes, we essentially treat the encrypt loop
	   below as a prng, encrypting + hashing the context $blockcnt times. with
	   this method, we could generate very long outputs for a very long time
	   without the drawbacks of e.g. pbkdf2 */

	blockcnt = ceil ((float) outlen / DIGEST_LEN);
	outbuf = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));

	for (i = 0; i < blockcnt; i++)
	{
		/* repeatedly encrypt the ciphertext */
		for (j = 0; j < 64; j++)
			pufferfish_ecb_encrypt (&context, ctext, 32);

		/* hash and output the state */
		SHA512 ((const unsigned char *) ctext, 32, outbuf + (i * DIGEST_LEN));
	}

	if (raw == true)
	{
		for (i = 0; i < outlen; i++)
			printf ("%02x", outbuf[i]);
		printf ("\n"); /* remove this */
	}
}

int main()
{
	unsigned char out[DIGEST_LEN/2];
	size_t outlen = DIGEST_LEN/2;
	char *pass = "passw0rd";
	char *salt = "salty";
	unsigned int t_cost = 16;
	unsigned int m_cost = 8;

	pufferfish (out, outlen, pass, strlen(pass), salt, strlen(salt), t_cost, m_cost, true);

	return (0);
}
