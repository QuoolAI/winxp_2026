/* MerlinAI portable core: XP25-MERLIN1 request and response authentication
   (see merlin_core.h). C89. */
#include <string.h>
#include "merlin_core.h"
#include "../../xp25-agent/llm/xp25_sha256.h"

int merlin_token_valid(const char *s, size_t max)
{
    size_t n = 0;
    if (!s || !*s) return 0;
    for (; s[n]; ++n) {
        char c = s[n];
        if (n >= max) return 0;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int merlin_hex_valid(const char *s, size_t len)
{
    size_t i;
    if (!s || strlen(s) != len) return 0;
    for (i = 0; i < len; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

void merlin_body_hash(const void *body, size_t len, char out[MERLIN_SIG_SIZE])
{
    unsigned char digest[32];
    xp25_sha256(body ? body : "", body ? len : 0, digest);
    out[0] = 0;
    merlin_append_hex(out, MERLIN_SIG_SIZE, digest, 32);
}

/* Paths are ASCII without spaces, starting with '/'. */
static int path_valid(const char *path)
{
    const char *c;
    if (!path || path[0] != '/' || strlen(path) > 200 || strstr(path, "..")) return 0;
    for (c = path; *c; ++c)
        if ((unsigned char)*c <= ' ' || (unsigned char)*c >= 0x7F) return 0;
    return 1;
}

int merlin_sign_request(const char *label, const unsigned char *key, size_t key_len, const char *method,
                        const char *path, const char *installation, const char *challenge, const char *nonce,
                        const void *body, size_t body_len, char out[MERLIN_SIG_SIZE])
{
    char canonical[700], hash[MERLIN_SIG_SIZE];
    unsigned char mac[32];
    out[0] = 0;
    if (key_len < 16 || (strcmp(method, "GET") && strcmp(method, "POST")) || !path_valid(path) ||
        !merlin_token_valid(installation, 64) || !merlin_hex_valid(challenge, 64) || !merlin_hex_valid(nonce, 32))
        return 0;
    merlin_body_hash(body, body_len, hash);
    canonical[0] = 0;
    if (!merlin_append(canonical, sizeof(canonical), label) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), method) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), path) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), installation) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), challenge) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), nonce) || !merlin_append(canonical, sizeof(canonical), "\n") ||
        !merlin_append(canonical, sizeof(canonical), hash))
        return 0;
    xp25_hmac_sha256(key, key_len, canonical, strlen(canonical), mac);
    merlin_append_hex(out, MERLIN_SIG_SIZE, mac, 32);
    return 1;
}

int merlin_verify_response(const char *label, const unsigned char *key, size_t key_len, const char *nonce,
                           unsigned status, const void *body, size_t body_len, const char *mac_hex)
{
    char canonical[300], hash[MERLIN_SIG_SIZE];
    unsigned char mac[32], given[32];
    if (key_len < 16 || !merlin_hex_valid(nonce, 32) || !merlin_hex_valid(mac_hex, 64) || status > 999) return 0;
    if (xp25_hex_decode(mac_hex, given, sizeof(given)) != 32) return 0;
    merlin_body_hash(body, body_len, hash);
    canonical[0] = 0;
    merlin_append(canonical, sizeof(canonical), label);
    merlin_append(canonical, sizeof(canonical), "-RESPONSE\n");
    merlin_append(canonical, sizeof(canonical), nonce);
    merlin_append(canonical, sizeof(canonical), "\n");
    merlin_append_ulong(canonical, sizeof(canonical), status);
    merlin_append(canonical, sizeof(canonical), "\n");
    merlin_append(canonical, sizeof(canonical), hash);
    xp25_hmac_sha256(key, key_len, canonical, strlen(canonical), mac);
    return xp25_mem_equal_ct(mac, given, 32);
}
