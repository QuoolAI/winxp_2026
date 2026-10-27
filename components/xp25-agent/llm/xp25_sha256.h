/* XP25 AI runtime: SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104). Portable C89. */
#ifndef XP25_SHA256_H
#define XP25_SHA256_H
#include <stddef.h>

typedef struct {
    unsigned long state[8];
    unsigned long bits_hi, bits_lo;
    unsigned char block[64];
    size_t used;
} XP25_SHA256;

void xp25_sha256_init(XP25_SHA256 *ctx);
void xp25_sha256_update(XP25_SHA256 *ctx, const void *data, size_t len);
void xp25_sha256_final(XP25_SHA256 *ctx, unsigned char digest[32]);
void xp25_sha256(const void *data, size_t len, unsigned char digest[32]);
void xp25_hmac_sha256(const unsigned char *key, size_t key_len, const void *data, size_t len,
                      unsigned char mac[32]);
/* Constant-time comparison of equal-length byte strings. */
int xp25_mem_equal_ct(const unsigned char *a, const unsigned char *b, size_t n);
/* Lowercase hex decode; returns bytes written or 0 on malformed input. */
size_t xp25_hex_decode(const char *hex, unsigned char *out, size_t out_max);
#endif
