/*
 * Pufferfish2 - an adaptive password hashing scheme
 *
 * Copyright 2015, Jeremi M Gosney. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
*/

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#define PF_ID "$PF2$"
#define PF_ID_SZ strlen(PF_ID)
#define PF_SBOX_N 4
#define PF_SALT_SZ 16
#define PF_SALTSPACE (2 + PF_ID_SZ + bin2enc_len(sizeof(pf_salt)))
#define PF_HASHSPACE (PF_SALTSPACE + bin2enc_len(PF_DIGEST_LENGTH))

#define PF_DIGEST EVP_sha512()
#define PF_DIGEST_LENGTH SHA512_DIGEST_LENGTH

typedef struct pf_salt
{
    uint8_t cost_t;
    uint8_t cost_m;
    char salt[PF_SALT_SZ];
} pf_salt;

#define PF_HMAC(a,b,c,d,e)                                                               \
    HMAC(PF_DIGEST,(a),(b),(const unsigned char *)(c),(d),(unsigned char *)(e),NULL)
  
#define ENCRYPT_P                                                                        \
    EXPANDSTATE(salt_u64[0], salt_u64[1], P[ 0], P[ 1]);                                 \
    EXPANDSTATE(salt_u64[2], salt_u64[3], P[ 2], P[ 3]);                                 \
    EXPANDSTATE(salt_u64[4], salt_u64[5], P[ 4], P[ 5]);                                 \
    EXPANDSTATE(salt_u64[6], salt_u64[7], P[ 6], P[ 7]);                                 \
    EXPANDSTATE(salt_u64[0], salt_u64[1], P[ 8], P[ 9]);                                 \
    EXPANDSTATE(salt_u64[2], salt_u64[3], P[10], P[11]);                                 \
    EXPANDSTATE(salt_u64[4], salt_u64[5], P[12], P[13]);                                 \
    EXPANDSTATE(salt_u64[6], salt_u64[7], P[14], P[15]);                                 \
    EXPANDSTATE(salt_u64[0], salt_u64[1], P[16], P[17]);

#define ENCRYPT_S                                                                        \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE(salt_u64[i & 7], salt_u64[(i + 1) & 7], S[0][i], S[0][i + 1]);       \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE(salt_u64[i & 7], salt_u64[(i + 1) & 7], S[1][i], S[1][i + 1]);       \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE(salt_u64[i & 7], salt_u64[(i + 1) & 7], S[2][i], S[2][i + 1]);       \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE(salt_u64[i & 7], salt_u64[(i + 1) & 7], S[3][i], S[3][i + 1]);

#define HASH_SBOX(x)                                                                     \
    PF_HMAC(x, PF_DIGEST_LENGTH, S[0], sbox_sz * sizeof(uint64_t), x);                   \
    PF_HMAC(x, PF_DIGEST_LENGTH, S[1], sbox_sz * sizeof(uint64_t), x);                   \
    PF_HMAC(x, PF_DIGEST_LENGTH, S[2], sbox_sz * sizeof(uint64_t), x);                   \
    PF_HMAC(x, PF_DIGEST_LENGTH, S[3], sbox_sz * sizeof(uint64_t), x);

#define F(x)                                                                             \
(                                                                                        \
    ((S[0][(x >> (64 - log2_sbox_sz))] ^                                                 \
      S[1][(x >> 35) & (sbox_sz - 1)]) +                                                 \
      S[2][(x >> 19) & (sbox_sz - 1)]) ^                                                 \
      S[3][(x >>  3) & (sbox_sz - 1)]                                                    \
)

#define ENCIPHER                                                                         \
    L ^= P[0];                                                                           \
    R = (R ^ F(L)) ^ P[ 1];                                                              \
    L = (L ^ F(R)) ^ P[ 2];                                                              \
    R = (R ^ F(L)) ^ P[ 3];                                                              \
    L = (L ^ F(R)) ^ P[ 4];                                                              \
    R = (R ^ F(L)) ^ P[ 5];                                                              \
    L = (L ^ F(R)) ^ P[ 6];                                                              \
    R = (R ^ F(L)) ^ P[ 7];                                                              \
    L = (L ^ F(R)) ^ P[ 8];                                                              \
    R = (R ^ F(L)) ^ P[ 9];                                                              \
    L = (L ^ F(R)) ^ P[10];                                                              \
    R = (R ^ F(L)) ^ P[11];                                                              \
    L = (L ^ F(R)) ^ P[12];                                                              \
    R = (R ^ F(L)) ^ P[13];                                                              \
    L = (L ^ F(R)) ^ P[14];                                                              \
    R = (R ^ F(L)) ^ P[15];                                                              \
    L = (L ^ F(R)) ^ P[16];                                                              \
    R ^= P[17];                                                                          \
    LL = R;                                                                              \
    RR = L;                                                                              \
    L  = LL;                                                                             \
    R  = RR

#define EXPANDSTATE(a,b,c,d)                                                             \
{                                                                                        \
    L ^= a;                                                                              \
    R ^= b;                                                                              \
    ENCIPHER;                                                                            \
    c = L;                                                                               \
    d = R;                                                                               \
}

#define EXPANDSTATE_NULL(a,b)                                                            \
{                                                                                        \
    ENCIPHER;                                                                            \
    a = L;                                                                               \
    b = R;                                                                               \
}

#define REKEY(x)                                                                         \
{                                                                                        \
    P[ 0] ^= key_u64[0];                                                                 \
    P[ 1] ^= key_u64[1];                                                                 \
    P[ 2] ^= key_u64[2];                                                                 \
    P[ 3] ^= key_u64[3];                                                                 \
    P[ 4] ^= key_u64[4];                                                                 \
    P[ 5] ^= key_u64[5];                                                                 \
    P[ 6] ^= key_u64[6];                                                                 \
    P[ 7] ^= key_u64[7];                                                                 \
    P[ 8] ^= key_u64[0];                                                                 \
    P[ 9] ^= key_u64[1];                                                                 \
    P[10] ^= key_u64[2];                                                                 \
    P[11] ^= key_u64[3];                                                                 \
    P[12] ^= key_u64[4];                                                                 \
    P[13] ^= key_u64[5];                                                                 \
    P[14] ^= key_u64[6];                                                                 \
    P[15] ^= key_u64[7];                                                                 \
    P[16] ^= key_u64[0];                                                                 \
    P[17] ^= key_u64[1];                                                                 \
                                                                                         \
    EXPANDSTATE_NULL(P[ 0], P[ 1]);                                                      \
    EXPANDSTATE_NULL(P[ 2], P[ 3]);                                                      \
    EXPANDSTATE_NULL(P[ 4], P[ 5]);                                                      \
    EXPANDSTATE_NULL(P[ 6], P[ 7]);                                                      \
    EXPANDSTATE_NULL(P[ 8], P[ 9]);                                                      \
    EXPANDSTATE_NULL(P[10], P[11]);                                                      \
    EXPANDSTATE_NULL(P[12], P[13]);                                                      \
    EXPANDSTATE_NULL(P[14], P[15]);                                                      \
    EXPANDSTATE_NULL(P[16], P[17]);                                                      \
                                                                                         \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE_NULL(S[0][i], S[0][i + 1]);                                          \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE_NULL(S[1][i], S[1][i + 1]);                                          \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE_NULL(S[2][i], S[2][i + 1]);                                          \
    for (i = 0; i < sbox_sz; i += 2)                                                     \
        EXPANDSTATE_NULL(S[3][i], S[3][i + 1]);                                          \
}

#define bin2enc_len(x) (((x) + 2) / 3 * 4)
#define chr64(c)((c) > 127 ? 255 : idx64[(c)])
#define shr(x,n) (x >> n)
#define shl(x,n) (x << n)

const static unsigned char itoa64[] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static unsigned char idx64[0x80] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,  0,  1,
     54, 55, 56, 57, 58, 59, 60, 61, 62, 63,255,255,255,255,255,255,
    255,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,255,255,255,255,255,
    255, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
     43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,255,255,255,255,255
};

size_t pf_encode(char *dst, void *src, size_t size);

size_t pf_decode(void *dst, char *src, size_t size);

void pf_hashpass(const void *salt_r, const size_t salt_sz, const uint8_t cost_t,
                 const uint8_t cost_m, const void *key_r, const size_t key_sz,
                 uint8_t *out);

int pf_mksalt(const void *salt_r, const size_t salt_sz, const uint8_t cost_t,
              const uint8_t cost_m, char *salt);

int pf_crypt(const char *salt, const void *pass, const size_t pass_sz, char *hash);

int pf_newhash(const void *pass, const size_t pass_sz, const size_t cost_t,
                const size_t cost_m, char *hash);

int pf_checkpass(const char *valid, const void *pass, const size_t pass_sz);

