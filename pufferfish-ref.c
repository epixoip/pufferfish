/* PHC Candidate pufferfish
   Authored by Jeremi Gosney, 2014
   Placed in the public domain.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "pufferfish-ref.h"


static int pf_encode64 (char *dst, unsigned char *src, int size)
{
	/* this function is identical to encode_base64() */

	char *dptr = dst;
	unsigned char *sptr = src;
	unsigned char *end  = sptr + size;
	unsigned char c1, c2;

	do {
		c1 = *sptr++;
		*dptr++ = itoa64[shr(c1, 2)];
		c1 = shl((c1 & 0x03), 4);

		if (sptr >= end)
		{
			*dptr++ = itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= shr(c2, 4) & 0x0f;
		*dptr++ = itoa64[c1];
		c1 = shl((c2 & 0x0f), 2);

		if (sptr >= end)
		{
			*dptr++ = itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= shr(c2, 6) & 0x03;
		*dptr++ = itoa64[c1];
		*dptr++ = itoa64[c2 & 0x3f];
	} while (sptr < end);

	*dptr = '\0';

	return (dptr - dst);
}


static int pf_decode64 (unsigned char *dst, int size, char *src)
{
	/* this function is identical to decode_base64() */

	unsigned char *sptr = (unsigned char *) src;
	unsigned char *dptr = dst;
	unsigned char *end  = dst + size;
	unsigned char c1, c2, c3, c4;

	do
	{
		c1 = char64(*sptr);
		c2 = char64(*(sptr + 1));

		if (c1 == 255 || c2 == 255) break;

		*dptr++ = shl(c1, 2) | shr((c2 & 0x30), 4);
		if (dptr >= end) break;

		c3 = char64(*(sptr + 2));
		if (c3 == 255) break;

		*dptr++ = shl((c2 & 0x0f), 4) | shr((c3 & 0x3c), 2);
		if (dptr >= end) break;

		c4 = char64(*(sptr + 3));
		if (c4 == 255) break;

		*dptr++ = shl((c3 & 0x03), 6) | c4;
		sptr += 4;
	} while (dptr < end);

	return (dptr - dst);
}


static void pf_initstate (puf_ctx *context, const void *password, size_t password_len, const void *salt, size_t salt_len, unsigned int m_cost)
{
	/* this function is absolutely nothing like Blowfish_initstate(),
	   and is really what defines pufferfish. */

	int i, j;
	unsigned char *key_hash;
	unsigned char salt_hash[DIGEST_LEN];
	uint64_t *state;

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

	/* calculate number of words per s-box */
	initstate.m_cost = m_cost;
	initstate.sbox_words = (m_cost * 1024) / NUM_SBOXES / WORDSIZ;

	/* the following steps initialize the dynamic s-boxes: */

	/* step 1: hash the salt with sha512 to generate the hmac key */
	SHA512 (salt, salt_len, salt_hash);

	/* step 2: hmac-sha512 the password using the hashed salt as
	   the key to initialize the state */
	state = (uint64_t*) HMAC_SHA512 (salt_hash, DIGEST_LEN, password, password_len);

	/* step 3: fill the s-boxes by iterating over the state with sha512 */
	for (i = 0; i < NUM_SBOXES; i++)
	{
		initstate.S[i] = (uint64_t *) calloc (initstate.sbox_words, WORDSIZ);

		for (j = 0; j < initstate.sbox_words; j+=STATE_N)
		{
			SHA512 ((const unsigned char *) state, DIGEST_LEN, (unsigned char *)(initstate.S[i] + j));
			state = initstate.S[i] + j;
		}
	}

	/* hmac-sha512 the password again using the resulting
	   state as the key to generate the encryption key */
	key_hash = HMAC_SHA512 ((const unsigned char *) state, DIGEST_LEN, password, password_len);

	/* set the context */
	*context = initstate;
	memmove (context->key, key_hash, DIGEST_LEN);
	memmove (context->salt, salt_hash, DIGEST_LEN);

	/* clean up openssl static data */
	memset (key_hash, 0, DIGEST_LEN);
}


static uint64_t pf_f (puf_ctx *context, uint64_t x)
{
	/* modified substantially from the original blowfish implementation,
	   to use dynamic s-box size and to improve the distribution of the
	   random accesses. probably some room for improvement here. */

	uint64_t h = context->S[0][rotr64(x,61) % context->sbox_words]
		   + context->S[1][rotr64(x,22) % context->sbox_words];

	return ( h ^ context->S[2][rotr64(x,53) % context->sbox_words] )
		   + context->S[3][rotr64(x,33) % context->sbox_words];
}


static void pf_encipher (puf_ctx *context, uint64_t *LL, uint64_t *RR)
{
	/* this function is identical to Blowfish_encipher(), except
	   it has been modified to use 64-bit words. */

	int i = 0;
	uint64_t L = *LL, R = *RR;

	for (i = 0; i < PUF_N; i+=2)
	{
		L ^= context->P[i];
		R ^= pf_f (context, L);
		R ^= context->P[i+1];
		L ^= pf_f (context, R);
	}

	L ^= context->P[16];
	R ^= context->P[17];
	*LL = R;
	*RR = L;
}


static void pf_ecb_encrypt (puf_ctx *context, uint8_t *data, size_t len)
{
	/* this function is identical to blf_ecb_encrypt(), except it has
	   been modified to use 64-bit words and a 128-bit blocksize. */

	uint64_t i, L = 0, R = 0;

	for (i = 0; i < len; i+=BLOCKSIZ)
	{
		uint8_to_uint64 (L, data, 0);
		uint8_to_uint64 (R, data, 8);

		pf_encipher (context, &L, &R);

		uint64_to_uchar (L, data, 0);
		uint64_to_uchar (R, data, 8);

		data+=BLOCKSIZ;
	}
}


static void pf_expandkey (puf_ctx *context, const uint64_t data[KEYSIZ], const uint64_t key[KEYSIZ])
{
	/* this function is largely identical to Blowfish_expandstate(), except
	   it has been modified to use 64-bit words, dynamic s-box size, and a
	   fixed key and data size of 256 bits. */

	int i, j;
	uint64_t L = 0, R = 0;

	for (i = 0; i < PUF_N + 2; i++)
		context->P[i] ^= key[i%KEYSIZ];

	for (i = 0; i < PUF_N + 2; i+=2)
	{
		L ^= data[i%KEYSIZ];
		R ^= data[i%KEYSIZ];

		pf_encipher (context, &L, &R);

		context->P[i]   = L;
		context->P[i+1] = R;
	}

	for (i = 0; i < NUM_SBOXES; i++)
	{
		for (j = 0; j < context->sbox_words; j+=2)
		{
			/* since we use dynamic s-boxes, this ends up being more expensive than
			   blowfish for m_cost > 8 because encipher is called $sbox_words times.
			   in blowfish, encipher is always called 256 times here. in pufferfish,
			   this is called m_cost*32 times. so for m_cost == 256, this ends up
			   being 32 times more expensive than blowfish. but this also means that
			   for e.g. m_cost == 8, this is equally expensive as blowfish at twice
			   the memory. this should be taken into consideration when selecting an
			   appropriate t_cost value. */

			L ^= data[j%KEYSIZ];
			R ^= data[j%KEYSIZ];

			pf_encipher (context, &L, &R);

			context->S[i][j]   = L;
			context->S[i][j+1] = R;
		}
	}
}


static char *pf_gensalt (const unsigned char *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	/* simple function to generate a salt and build the settings string.
	   string format is $id$itoa64(hex(t_cost).hex(m_cost).salt)$ */

	FILE *fp;
	unsigned char *buf;
	static char *out;
	int bytes;

	buf = (unsigned char *) calloc (10 + saltlen, sizeof (unsigned char));

	/* we have two cost parameters, so in an effort to keep the hash
	   string relatively clean, we convert them to hex and concatenate
	   them so we always know their length. */

	snprintf ((char *) buf, 11, "%02x%08x", t_cost, m_cost);

	/* if the user didn't supply a salt, generate one for them */
	if (salt == NULL)
	{
		fp = fopen ("/dev/urandom", "r");
		bytes = fread  (buf + 10, sizeof (unsigned char), saltlen, fp);
		fclose (fp);
	}
	else
	{
		memmove (buf + 10, salt, saltlen);
	}

	/* the output buffer is a bit large, but better too big than too small */
	out = (char *) calloc (PUF_ID_LEN + ((10 + saltlen) * 2), sizeof (char));

	/* copy hash identifer to the output string */
	memmove (out, PUF_ID, PUF_ID_LEN);

	/* encode the buffer and copy it to the output string */
	bytes = pf_encode64 (&out[PUF_ID_LEN], buf, saltlen + 10);

	/* add the trailing $ to the output string */
	out[PUF_ID_LEN + bytes] = '$';

	/* cleanup */
	free (buf);

	return out;
}


static unsigned char *pf_main (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw)
{
	/* the main pufferfish function. probably shouldn't call this directly */

	static unsigned char *out;

	puf_ctx context;

	long t_cost = 0, m_cost = 0, count = 0;
	uint64_t null_data[8] = { 0 };

	int i, j, settingslen, saltlen, blockcnt, bytes = 0, pos = 0;

	char *sptr;
	char tcost_str[5] = { '0', 'x', 0 };
	char mcost_str[11] = { '0', 'x', 0 };

	unsigned char *rawbuf;
	unsigned char decoded[255] = { 0 };
	unsigned char rawsalt[255] = { 0 };
	unsigned char ctext[] = "Drab as a fool, aloof as a bard.";

	/* parse the settings string */

	/* make sure we have a pufferfish hash */
	if (strncmp (PUF_ID, settings, PUF_ID_LEN))
		return NULL;

	settingslen = strlen (settings);
	sptr = settings + PUF_ID_LEN;

	/* find where the settings string ends */
	while (*sptr++ != '$' && pos < settingslen) pos++;

	/* decode the settings string */
	bytes = pf_decode64 (decoded, pos, settings + PUF_ID_LEN);
	saltlen = bytes - 10;

	/* unpack t_cost value */
	memmove (tcost_str + 2, decoded, 2);
	t_cost = strtol (tcost_str, NULL, 16);

	/* unpack the m_cost value */
	memmove (mcost_str + 2, decoded + 2, 8);
	if (0 == (m_cost = strtol (mcost_str, NULL, 16)))
		return NULL;

	/* unpack the raw salt value */
	memmove (rawsalt, decoded + 10, saltlen);

	/* the follwing steps are identical to the eksblowfish algorithm */

	/* initialize the context */
	pf_initstate (&context, pass, passlen, rawsalt, saltlen, m_cost);

	/* expand the key ... */
	pf_expandkey (&context, context.salt, context.key);

	/* ... again and again */
	count = 1 << t_cost; 
	do
	{
		pf_expandkey (&context, null_data, context.salt);
		pf_expandkey (&context, null_data, context.key);
	}
	while (--count);

	/* to support a variable output length (e.g., when used as a kdf)
	   at minimal cost while still providing good security, we treat
	   the following loop like a simple prng: we repeatedly encrypt
	   the ciphertext as the inner state, and hash the output. */
	
	blockcnt = (outlen + DIGEST_LEN - 1) / DIGEST_LEN;
	rawbuf = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));

	for (i = 0; i < blockcnt; i++)
	{
		for (j = 0; j < 64; j++)
			pf_ecb_encrypt (&context, ctext, 32);

		SHA512 ((const unsigned char *) ctext, 32, rawbuf + (i * DIGEST_LEN));
	}

	/* if the user just wants the raw bytes (e.g. when used as a kdf)
	   then just fill the output buffer with the raw bytes. otherwise,
	   generate a full ascii string to place in a database. */

	if (raw == true)
	{
		out = (unsigned char *) calloc (blockcnt * DIGEST_LEN, sizeof (unsigned char));
		memmove (out, rawbuf, outlen);
	}
	else
	{
		out = (unsigned char *) calloc (settingslen + 1 + (blockcnt * DIGEST_LEN * 2), sizeof (unsigned char));
		memmove (out, settings, settingslen);
		pf_encode64 ((char *) &out[settingslen], rawbuf, outlen);
	}

	/* cleanup */

	for (i = 0; i < NUM_SBOXES; i++)
	{
		for (j = 0; j < context.sbox_words; j++)
			context.S[i][j] = 0;
		free (context.S[i]);
	}
	
	memset (&context, 0, sizeof (puf_ctx));
	memset (ctext, 0, 32);
	free (rawbuf);

	return out;
}


static char *pufferfish (const char *pass, unsigned int t_cost, unsigned int m_cost)
{
	/* this is the simple api for password hashing */

	const unsigned int saltlen = 16;
	const unsigned int outlen  = 32;
	static char *hash;
	char *settings;

	settings = pf_gensalt (NULL, saltlen, t_cost, m_cost);
	hash = (char *) pf_main (pass, strlen (pass), settings, outlen, false);
	free (settings);

	return hash;
}

static unsigned char *pfkdf (unsigned int outlen, const char *pass, unsigned int t_cost, unsigned int m_cost)
{
	/* this is the simple api for deriving a key.
	   outlen is specified in BITS, not bytes! */

	const unsigned int saltlen = 16;
	static unsigned char *key;
	unsigned int len;
	char *settings;

	len = outlen / 8;

	settings = pf_gensalt (NULL, saltlen, t_cost, m_cost);
	key = pf_main (pass, strlen (pass), settings, len, true);
	free (settings);

	return key;
}


static int PHS (void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
	/* required PHS api */

	char *hash;
	char *settings = pf_gensalt (salt, saltlen, t_cost, m_cost);

	if (! (hash = (char *) pf_main (in, inlen, settings, outlen, false)))
	{
		free (settings);
		return 1;
	}

	memmove (out, hash, strlen (hash));
	free (settings);
	free (hash);

	return 0;
}


int main()
{
	const unsigned int t_cost = 4;   /* 2^4 rounds */
	const unsigned int m_cost = 64;  /* 64 KiB of memory */
	const unsigned int outlen = 32;  /* 32 bytes */
	const unsigned int keylen = 256; /* 256 bits */
	const char *password = "password";
	const char *salt = "salty";

	char out[1024] = { 0 };
	unsigned char *key;
	char *hash;
	int i, ret;

	puts ("\nsimple api:");
	hash = (char *) pufferfish (password, t_cost, m_cost);
	if (hash)
	{
		printf ("%s\n\n", hash);
		free (hash);
	}
	else
	{
		puts ("Error\n");
	}

	puts ("kdf api:");
	key = pfkdf (keylen, password, t_cost, m_cost);
	if (key)
	{
		for (i=0; i < keylen/8; i++)
			printf ("%02x ", key[i]);
		printf ("\n\n");
		free (key);
	}
	else
	{
		puts ("Error\n");
	}

	puts ("phc api:");
	ret = PHS (out, outlen, password, strlen (password), salt, strlen (salt), t_cost, m_cost);
	if (ret)
	{
		puts ("Error\n");
	}
	else
	{
		printf ("%s\n\n", out);
	}

	return ret;
}

