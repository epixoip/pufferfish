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

#include "pufferfish.h"


size_t pf_encode(char *dst, void *src, size_t size)
{
    uint8_t *dptr = (uint8_t *) dst;
    uint8_t *sptr = (uint8_t *) src;
    uint8_t *end  = (uint8_t *) sptr + size;
    uint8_t c1, c2;

    do
    {
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
    }
    while (sptr < end);

    return ((char *)dptr - dst);
}

size_t pf_decode(void *dst, char *src, size_t size)
{
    uint8_t *sptr = (uint8_t *) src;
    uint8_t *dptr = (uint8_t *) dst;
    uint8_t *end = (uint8_t *) dst + size;
    uint8_t c1, c2, c3, c4;

    do
    {
        c1 = chr64(*sptr);
        c2 = chr64(*(sptr + 1));

        if (c1 == 255 || c2 == 255)
            break;

        *dptr++ = shl(c1, 2) | shr((c2 & 0x30), 4);
        if (dptr >= end)
            break;

        c3 = chr64(*(sptr + 2));
        if (c3 == 255)
            break;

        *dptr++ = shl((c2 & 0x0f), 4) | shr((c3 & 0x3c), 2);
        if (dptr >= end)
            break;

        c4 = chr64(*(sptr + 3));
        if (c4 == 255)
            break;

        *dptr++ = shl((c3 & 0x03), 6) | c4;
        sptr += 4;
    }
    while (dptr < end);

    return (dptr - (uint8_t *) dst);
}

void pf_hashpass(const void *salt_r, const size_t salt_sz, const uint8_t cost_t, const uint8_t cost_m,
                 const void *key_r, const size_t key_sz, uint8_t *out)
{
    unsigned char key[PF_DIGEST_LENGTH]  = { 0 };
    unsigned char salt[PF_DIGEST_LENGTH] = { 0 };

    uint64_t *salt_u64, *key_u64;
    uint64_t *S[PF_SBOX_N], P[18];
    uint64_t L  = 0, R =  0;
    uint64_t LL = 0, RR = 0;
    uint64_t count = 0, sbox_sz = 0;

    uint8_t log2_sbox_sz = 0;
    int i, j, k;

    key_u64  = (uint64_t *) &key;
    salt_u64 = (uint64_t *) &salt;

    log2_sbox_sz = cost_m + 5;
    sbox_sz = 1ULL << log2_sbox_sz;

    PF_HMAC("", 0, salt_r, salt_sz, salt);
    PF_HMAC(key_r, key_sz, salt, PF_DIGEST_LENGTH, key);

    for (i = 0; i < PF_SBOX_N; i++)
    {
        S[i] = (uint64_t *) calloc(sbox_sz, sizeof(uint64_t));

        for (j = 0; j < sbox_sz; j += (PF_DIGEST_LENGTH / sizeof(uint64_t)))
        {
            PF_HMAC(key, PF_DIGEST_LENGTH, salt, PF_DIGEST_LENGTH, key);

            for (k = 0; k < (PF_DIGEST_LENGTH / sizeof(uint64_t)); k++)
                S[i][j + k] = key_u64[k];
        }
    }

    HASH_SBOX(key);

    P[ 0] = 0x243f6a8885a308d3ULL ^ key_u64[0];
    P[ 1] = 0x13198a2e03707344ULL ^ key_u64[1];
    P[ 2] = 0xa4093822299f31d0ULL ^ key_u64[2];
    P[ 3] = 0x082efa98ec4e6c89ULL ^ key_u64[3];
    P[ 4] = 0x452821e638d01377ULL ^ key_u64[4];
    P[ 5] = 0xbe5466cf34e90c6cULL ^ key_u64[5];
    P[ 6] = 0xc0ac29b7c97c50ddULL ^ key_u64[6];
    P[ 7] = 0x3f84d5b5b5470917ULL ^ key_u64[7];
    P[ 8] = 0x9216d5d98979fb1bULL ^ key_u64[0];
    P[ 9] = 0xd1310ba698dfb5acULL ^ key_u64[1];
    P[10] = 0x2ffd72dbd01adfb7ULL ^ key_u64[2];
    P[11] = 0xb8e1afed6a267e96ULL ^ key_u64[3];
    P[12] = 0xba7c9045f12c7f99ULL ^ key_u64[4];
    P[13] = 0x24a19947b3916cf7ULL ^ key_u64[5];
    P[14] = 0x0801f2e2858efc16ULL ^ key_u64[6];
    P[15] = 0x636920d871574e69ULL ^ key_u64[7];
    P[16] = 0xa458fea3f4933d7eULL ^ key_u64[0];
    P[17] = 0x0d95748f728eb658ULL ^ key_u64[1];

    ENCRYPT_P;
    ENCRYPT_S;

    count = (1ULL << cost_t) + 1;
    do
    {
        L = R = 0;
        HASH_SBOX(key);
        REKEY(key);
    }
    while (--count);

    HASH_SBOX(key);
    memcpy(out, key, PF_DIGEST_LENGTH);

    for (i = 0; i < PF_SBOX_N; i++)
        free(S[i]);
}

int pf_mksalt(const void *salt_r, const size_t salt_sz, const uint8_t cost_t, const uint8_t cost_m, char *salt)
{
    FILE *fp;
    size_t bytes = 0;
    pf_salt settings;

    settings.cost_t = cost_t;
    settings.cost_m = cost_m;
    memset(settings.salt, 0, PF_SALT_SZ);

    if (!salt_r)
    {
        if ((fp = fopen("/dev/urandom", "r")) == NULL)
            return errno;

        bytes = fread(&settings.salt, sizeof(uint8_t), PF_SALT_SZ, fp);
        fclose(fp);

        if (bytes != PF_SALT_SZ)
            return ENODATA;
    }
    else
    {
        memcpy(settings.salt, salt_r, (salt_sz > PF_SALT_SZ) ? PF_SALT_SZ : salt_sz);
    }

    memset(salt, 0, PF_SALTSPACE);
    memmove(salt, PF_ID, PF_ID_SZ);

    bytes = pf_encode(salt + PF_ID_SZ, (void *)&settings, sizeof(pf_salt));
    salt[PF_ID_SZ + bytes] = '$';

    return 0;
}

int pf_crypt(const char *salt, const void *pass, const size_t pass_sz, char *hash)
{
    uint8_t buf[PF_DIGEST_LENGTH] = { 0 };
    size_t bytes = 0;
    pf_salt settings;
    char *p;

    if (strncmp(salt, PF_ID, PF_ID_SZ))
        return EINVAL;

    if ((p = strrchr(salt, '$')) == NULL)
        return EINVAL;

    memset(hash, 0, PF_HASHSPACE);
    memmove(hash, salt, p - salt + 1);

    if ((bytes = pf_decode((void *)&settings, (char *)(salt + PF_ID_SZ), p - salt - PF_ID_SZ)) != sizeof(pf_salt))
        return EINVAL;

    pf_hashpass(settings.salt, PF_SALT_SZ, settings.cost_t, settings.cost_m, pass, pass_sz, buf);
    pf_encode(hash + PF_SALTSPACE - 1, buf, PF_DIGEST_LENGTH);

    return 0;
}

int pf_newhash(const void *pass, const size_t pass_sz, const size_t cost_t, const size_t cost_m, char *hash)
{
    char salt[PF_SALTSPACE];
    int ret = 0;

    if (cost_t > 63 || cost_m > 53)
        return EOVERFLOW;

    if ((ret = pf_mksalt(NULL, 0, cost_t, cost_m, salt)) != 0)
        return ret;

    if ((ret = pf_crypt(salt, pass, pass_sz, hash)) != 0)
        return ret;

    return 0;
}

int pf_checkpass(const char *valid, const void *pass, const size_t pass_sz)
{
    char hash[PF_HASHSPACE];
    int i, ret = 0, diff = 0;

    if ((ret = pf_crypt(valid, pass, pass_sz, hash)) != 0)
        return 1;

    diff = strlen(hash) ^ strlen(valid);

    for (i = 0; i < strlen(hash) && i < strlen(valid); i++)
        diff |= hash[i] ^ valid[i];

    return (diff != 0);
}

#ifdef TEST
int main(int argc, char **argv)
{
    char hash[PF_HASHSPACE];
    int ret = 0;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s [t_cost] [m_cost] <passwd>\n", argv[0]);
        return 1;
    }

    if ((ret = pf_newhash(argv[3], strlen(argv[3]), atoi(argv[1]), atoi(argv[2]), hash)) != 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(ret));
        return ret;
    }

    printf("%s\n", hash);
/*
    if ((ret = pf_checkpass(hash, argv[3], strlen(argv[3]))) != 0)
    {
        fprintf(stderr, "Error: hash failed to validate!\n");
        return ret;
    }
*/
    return 0;
}
#endif

