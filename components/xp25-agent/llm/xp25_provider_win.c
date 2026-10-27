/* XP25 AI runtime: network providers.
   - gateway: XP25 companion gateway over HTTP. Every request is signed with
     HMAC-SHA256 over a single-use server challenge, a client nonce and the
     body digest; every response must carry a valid gateway signature. The
     OpenAI API key stays on the gateway, which verifies TLS certificates.
   - local: an explicitly configured OpenAI-compatible server (plain HTTP).
   - openai: direct HTTPS. NT 5.1 SChannel offers neither TLS 1.2 nor modern
     cipher suites, and this build carries no TLS stack, so it is refused
     rather than downgraded. */
#include <windows.h>
#include <wincrypt.h>
#include <string.h>
#include "../runtime/xp25_win.h"
#include "xp25_llm.h"
#include "xp25_http.h"
#include "xp25_sha256.h"

typedef struct {
    XP25_PROVIDER base;
    XP25_CONFIG config;
    unsigned char *secret;
    DWORD secret_len;
    unsigned char *api_key;
    DWORD api_key_len;
    char label[48];
} NET;

static void random_hex(char *out, size_t bytes)
{
    HCRYPTPROV prov;
    unsigned char data[32];
    XP25_BUF hex;
    if (bytes > sizeof(data)) bytes = sizeof(data);
    memset(data, 0, sizeof(data));
    if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(prov, (DWORD)bytes, data);
        CryptReleaseContext(prov, 0);
    }
    xp25_buf_init(&hex);
    xp25_buf_hex(&hex, data, bytes);
    lstrcpynA(out, xp25_buf_cstr(&hex), (int)(bytes * 2 + 1));
    xp25_buf_free(&hex);
}

static void join_url(char *out, size_t size, const char *base, const char *path)
{
    size_t n;
    lstrcpynA(out, base, (int)size);
    n = strlen(out);
    while (n && out[n - 1] == '/') out[--n] = 0;
    if (strlen(out) + strlen(path) < size) lstrcatA(out, path);
}

static int network_error(XP25_REPLY *reply, const char *code)
{
    const char *message = !strcmp(code, "timeout") || !strcmp(code, "connect_timeout") ? "The AI service did not answer in time." :
                          !strcmp(code, "dns_failed") ? "The AI service name could not be resolved." :
                          !strcmp(code, "connect_failed") ? "The AI service refused or blocked the connection." :
                          "The AI service could not be reached.";
    xp25_reply_error(reply, code, message, 1);
    return 0;
}

/* Get a single-use challenge from the gateway. */
static int challenge(NET *n, char *out, size_t size, XP25_REPLY *reply)
{
    char url[400], error[64];
    XP25_HTTP_RESPONSE r;
    XP25_JDOC doc;
    const char *value;
    join_url(url, sizeof(url), n->config.endpoint, "/xp25/v1/challenge");
    if (!xp25w_http(url, "GET", NULL, NULL, 0, n->config.timeout_seconds, &r, error, sizeof(error))) return network_error(reply, error);
    if (r.status != 200 || !xp25_json_parse(&doc, r.body.data, r.body.len)) {
        xp25w_http_free(&r);
        xp25_reply_error(reply, "gateway_unavailable", "The XP25 gateway did not issue a challenge.", 1);
        return 0;
    }
    value = xp25_json_string(doc.root, "challenge");
    if (!value || strlen(value) < 32 || strlen(value) >= size) {
        xp25_json_free(&doc);
        xp25w_http_free(&r);
        xp25_reply_error(reply, "gateway_malformed", "The XP25 gateway challenge is malformed.", 0);
        return 0;
    }
    lstrcpynA(out, value, (int)size);
    xp25_json_free(&doc);
    xp25w_http_free(&r);
    return 1;
}

static int post(NET *n, const char *path, const XP25_BUF *body, XP25_REPLY *reply)
{
    char url[400], error[64], nonce[65], chal[130], sig[65], digest[65], given[80], retry_after[16];
    XP25_BUF headers;
    XP25_HTTP_RESPONSE r;
    long attempt;
    int gateway = n->config.provider == XP25_PROVIDER_GATEWAY;
    for (attempt = 0; attempt <= n->config.retries; ++attempt) {
        int ok;
        if (attempt) {
            DWORD delay = 1000UL << (attempt - 1);
            Sleep(delay > 8000 ? 8000 : delay);
            xp25_reply_free(reply);
        }
        xp25_buf_init(&headers);
        join_url(url, sizeof(url), n->config.endpoint, path);
        if (gateway) {
            if (!challenge(n, chal, sizeof(chal), reply)) { xp25_buf_free(&headers); if (reply->retryable) continue; return 0; }
            random_hex(nonce, 16);
            xp25_gateway_sign(n->secret, n->secret_len, "POST", path, chal, nonce, body->data, body->len, sig, digest);
            xp25_buf_puts(&headers, "X-XP25-Client: "); xp25_buf_puts(&headers, n->config.gateway_client);
            xp25_buf_puts(&headers, "\r\nX-XP25-Challenge: "); xp25_buf_puts(&headers, chal);
            xp25_buf_puts(&headers, "\r\nX-XP25-Nonce: "); xp25_buf_puts(&headers, nonce);
            xp25_buf_puts(&headers, "\r\nX-XP25-Content-SHA256: "); xp25_buf_puts(&headers, digest);
            xp25_buf_puts(&headers, "\r\nX-XP25-Signature: "); xp25_buf_puts(&headers, sig);
            xp25_buf_puts(&headers, "\r\n");
        } else if (n->api_key && n->api_key_len) {
            xp25_buf_puts(&headers, "Authorization: Bearer ");
            xp25_buf_append(&headers, (const char *)n->api_key, n->api_key_len);
            xp25_buf_puts(&headers, "\r\n");
        }
        ok = xp25w_http(url, "POST", xp25_buf_cstr(&headers), body->data, body->len, n->config.timeout_seconds, &r, error, sizeof(error));
        xp25w_wipe(headers.data, headers.cap);
        xp25_buf_free(&headers);
        if (!ok) { network_error(reply, error); continue; }
        if (gateway && (!xp25w_http_header(&r, "X-XP25-Response-Signature", given, sizeof(given)) ||
                        !xp25_gateway_verify(n->secret, n->secret_len, nonce, r.status, r.body.data, r.body.len, given))) {
            xp25w_http_free(&r);
            xp25_reply_error(reply, "gateway_auth_failed",
                             "The gateway response failed authentication and was discarded. Check the shared secret.", 0);
            return 0;
        }
        ok = xp25_llm_parse_response((XP25_API)n->config.api, r.body.data, r.body.len, r.status, reply);
        if (!ok && reply->retryable && xp25w_http_header(&r, "Retry-After", retry_after, sizeof(retry_after))) {
            xp25_u64 seconds;
            if (xp25_parse_u64(retry_after, strlen(retry_after), &seconds) && seconds <= 10) Sleep((DWORD)seconds * 1000);
        }
        xp25w_http_free(&r);
        if (ok || !reply->retryable) return ok;
    }
    return 0;
}

static const char *api_path(const NET *n)
{
    if (n->config.provider == XP25_PROVIDER_GATEWAY)
        return n->config.api ? "/xp25/v1/chat/completions" : "/xp25/v1/responses";
    return n->config.api ? "/v1/chat/completions" : "/v1/responses";
}

static int net_complete(XP25_PROVIDER *self, const XP25_CONVERSATION *c, const XP25_REGISTRY *registry,
                        const char *instructions, XP25_REPLY *reply)
{
    NET *n = (NET *)self;
    XP25_BUF body;
    int ok;
    xp25_buf_init(&body);
    if (!xp25_llm_build_request((XP25_API)n->config.api, n->config.model, c, registry, instructions, 1,
                                n->config.max_output_tokens, &body)) {
        xp25_buf_free(&body);
        xp25_reply_error(reply, "request_encoding_failed", "The request could not be encoded.", 0);
        return 0;
    }
    ok = post(n, api_path(n), &body, reply);
    xp25_buf_free(&body);
    return ok;
}

int xp25w_provider_ask(XP25_PROVIDER *provider, const char *instructions, const char *question, XP25_REPLY *reply)
{
    NET *n = (NET *)provider;
    XP25_BUF body;
    int ok;
    if (!provider || provider->complete != net_complete) return 0;
    xp25_buf_init(&body);
    if (!xp25_llm_build_simple((XP25_API)n->config.api, n->config.model, instructions, question, &body)) {
        xp25_buf_free(&body);
        return 0;
    }
    ok = post(n, api_path(n), &body, reply);
    xp25_buf_free(&body);
    return ok;
}

XP25_PROVIDER *xp25w_provider_create(const XP25_CONFIG *config, char *reason, size_t size)
{
    NET *n;
    char host[256], path[512];
    unsigned short port;
    if (config->provider == XP25_PROVIDER_OFFLINE) { lstrcpynA(reason, "offline", (int)size); return NULL; }
    if (config->provider == XP25_PROVIDER_OPENAI) {
        lstrcpynA(reason, "Direct HTTPS to OpenAI needs TLS 1.2, which Windows XP does not provide. Configure the XP25 "
                          "gateway instead; TLS validation is never weakened.", (int)size);
        return NULL;
    }
    if (!xp25w_parse_url(config->endpoint, host, sizeof(host), &port, path, sizeof(path))) {
        lstrcpynA(reason, "The endpoint must be an http:// URL of the XP25 gateway or a local AI server.", (int)size);
        return NULL;
    }
    n = (NET *)xp25_alloc(sizeof(NET));
    if (!n) { lstrcpynA(reason, "Out of memory.", (int)size); return NULL; }
    n->config = *config;
    if (config->provider == XP25_PROVIDER_GATEWAY) {
        /* The shared secret is the hexadecimal key from the gateway's clients file. */
        unsigned char *text = NULL, *key;
        DWORD text_len = 0, i, n_hex = 0;
        size_t got = 0;
        char hex[257];
        if (xp25w_secret_get(L"GatewaySecret", &text, &text_len)) {
            for (i = 0; i < text_len && n_hex < sizeof(hex) - 1; ++i)
                if (!xp25_is_space(text[i])) hex[n_hex++] = (char)text[i];
            hex[n_hex] = 0;
            key = (unsigned char *)xp25_alloc(128);
            if (key && n_hex >= 32 && (got = xp25_hex_decode(hex, key, 128)) >= 16) {
                n->secret = key;
                n->secret_len = (DWORD)got;
            } else xp25_free(key);
            xp25w_wipe(hex, sizeof(hex));
            xp25w_secret_free(text, text_len);
        }
        if (!n->secret) {
            xp25_free(n);
            lstrcpynA(reason, "The gateway shared secret is not set or is not the hexadecimal key (at least 32 hex digits) "
                              "from the gateway's clients file. Enter it in ClippyAI Settings.", (int)size);
            return NULL;
        }
    }
    if (config->provider == XP25_PROVIDER_LOCAL) xp25w_secret_get(L"LocalApiKey", &n->api_key, &n->api_key_len);
    lstrcpynA(n->label, config->provider == XP25_PROVIDER_GATEWAY ? "XP25 gateway" : "local AI server", sizeof(n->label));
    n->base.name = n->label;
    n->base.remote = 1;
    n->base.complete = net_complete;
    n->base.context = n;
    return &n->base;
}

void xp25w_provider_destroy(XP25_PROVIDER *provider)
{
    NET *n = (NET *)provider;
    if (!n) return;
    xp25w_secret_free(n->secret, n->secret_len);
    xp25w_secret_free(n->api_key, n->api_key_len);
    xp25_free(n);
}
