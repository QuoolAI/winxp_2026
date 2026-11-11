/* XP25 AI runtime: SHA-256 and HMAC-SHA256. Portable C89, 32-bit arithmetic only. */
#include <string.h>
#include "xp25_sha256.h"

#define ROR(x, n) ((((x) >> (n)) | ((x) << (32 - (n)))) & 0xFFFFFFFFUL)

static const unsigned long K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static void compress(XP25_SHA256 *ctx, const unsigned char *p)
{
    unsigned long w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; ++i)
        w[i] = ((unsigned long)p[4 * i] << 24) | ((unsigned long)p[4 * i + 1] << 16) |
               ((unsigned long)p[4 * i + 2] << 8) | (unsigned long)p[4 * i + 3];
    for (i = 16; i < 64; ++i) {
        unsigned long s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned long s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFUL;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = (h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) & 0xFFFFFFFFUL;
        t2 = ((ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFFUL;
        h = g; g = f; f = e; e = (d + t1) & 0xFFFFFFFFUL;
        d = c; c = b; b = a; a = (t1 + t2) & 0xFFFFFFFFUL;
    }
    ctx->state[0] = (ctx->state[0] + a) & 0xFFFFFFFFUL; ctx->state[1] = (ctx->state[1] + b) & 0xFFFFFFFFUL;
    ctx->state[2] = (ctx->state[2] + c) & 0xFFFFFFFFUL; ctx->state[3] = (ctx->state[3] + d) & 0xFFFFFFFFUL;
    ctx->state[4] = (ctx->state[4] + e) & 0xFFFFFFFFUL; ctx->state[5] = (ctx->state[5] + f) & 0xFFFFFFFFUL;
    ctx->state[6] = (ctx->state[6] + g) & 0xFFFFFFFFUL; ctx->state[7] = (ctx->state[7] + h) & 0xFFFFFFFFUL;
}

void xp25_sha256_init(XP25_SHA256 *ctx)
{
    static const unsigned long iv[8] = { 0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
                                         0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->bits_hi = ctx->bits_lo = 0;
    ctx->used = 0;
}

void xp25_sha256_update(XP25_SHA256 *ctx, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    while (len) {
        size_t take = 64 - ctx->used;
        unsigned long add;
        if (take > len) take = len;
        memcpy(ctx->block + ctx->used, p, take);
        ctx->used += take;
        p += take;
        len -= take;
        add = (unsigned long)take * 8UL;
        ctx->bits_lo = (ctx->bits_lo + add) & 0xFFFFFFFFUL;
        if (ctx->bits_lo < add) ctx->bits_hi = (ctx->bits_hi + 1) & 0xFFFFFFFFUL;
        if (ctx->used == 64) { compress(ctx, ctx->block); ctx->used = 0; }
    }
}

void xp25_sha256_final(XP25_SHA256 *ctx, unsigned char digest[32])
{
    unsigned char tail[8];
    unsigned long hi = ctx->bits_hi, lo = ctx->bits_lo;
    static const unsigned char pad = 0x80, zero = 0;
    int i;
    for (i = 0; i < 4; ++i) {
        tail[i] = (unsigned char)(hi >> (24 - 8 * i));
        tail[4 + i] = (unsigned char)(lo >> (24 - 8 * i));
    }
    xp25_sha256_update(ctx, &pad, 1);
    while (ctx->used != 56) xp25_sha256_update(ctx, &zero, 1);
    xp25_sha256_update(ctx, tail, 8);
    for (i = 0; i < 8; ++i) {
        digest[4 * i] = (unsigned char)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (unsigned char)ctx->state[i];
    }
    memset(ctx, 0, sizeof(*ctx));
}

void xp25_sha256(const void *data, size_t len, unsigned char digest[32])
{
    XP25_SHA256 ctx;
    xp25_sha256_init(&ctx);
    xp25_sha256_update(&ctx, data, len);
    xp25_sha256_final(&ctx, digest);
}

void xp25_hmac_sha256(const unsigned char *key, size_t key_len, const void *data, size_t len,
                      unsigned char mac[32])
{
    unsigned char k[64], pad[64], inner[32];
    XP25_SHA256 ctx;
    size_t i;
    memset(k, 0, sizeof(k));
    if (key_len > 64) xp25_sha256(key, key_len, k);
    else if (key_len) memcpy(k, key, key_len);
    for (i = 0; i < 64; ++i) pad[i] = (unsigned char)(k[i] ^ 0x36);
    xp25_sha256_init(&ctx);
    xp25_sha256_update(&ctx, pad, 64);
    xp25_sha256_update(&ctx, data, len);
    xp25_sha256_final(&ctx, inner);
    for (i = 0; i < 64; ++i) pad[i] = (unsigned char)(k[i] ^ 0x5c);
    xp25_sha256_init(&ctx);
    xp25_sha256_update(&ctx, pad, 64);
    xp25_sha256_update(&ctx, inner, 32);
    xp25_sha256_final(&ctx, mac);
    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

int xp25_mem_equal_ct(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t xp25_hex_decode(const char *hex, unsigned char *out, size_t out_max)
{
    size_t n = strlen(hex), i;
    if (n % 2 || n / 2 > out_max) return 0;
    for (i = 0; i < n / 2; ++i) {
        int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return n / 2;
}
