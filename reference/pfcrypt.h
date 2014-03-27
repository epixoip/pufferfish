#pragma once

#include "common.h"

#define char64(c)((c) > 127 ? 255 : index64[(c)])

#define PUF_ID "$PF$"			/* hash identification str */
#define PUF_ID_LEN strlen (PUF_ID)	/* length of the identifier */

typedef enum { false, true } bool;

const static unsigned char itoa64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static unsigned char index64[0x80] = {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,  0,  1,
	 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,255,255,255,255,255,255,
	255,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
	 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,255,255,255,255,255,
	255, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,255,255,255,255,255
};

extern int PHS (void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);
extern unsigned char *pfkdf (unsigned int outlen, const char *pass, unsigned int t_cost, unsigned int m_cost);
extern char *pfcrypt_easy (const char *pass, unsigned int t_cost, unsigned int m_cost);
extern unsigned char *pfcrypt (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw);
extern char *pf_gensalt (const unsigned char *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);
