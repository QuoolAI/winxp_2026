/* XP25 AI runtime: buffers, strings and the JSON writer. Portable C89. */
#include <stdlib.h>
#include <string.h>
#include "xp25_base.h"

void *xp25_alloc(size_t size) { return calloc(1, size ? size : 1); }
void *xp25_realloc(void *block, size_t size) { return realloc(block, size ? size : 1); }
void xp25_free(void *block) { free(block); }

void xp25_buf_init(XP25_BUF *b) { b->data = NULL; b->len = b->cap = 0; b->failed = 0; }
void xp25_buf_free(XP25_BUF *b) { xp25_free(b->data); xp25_buf_init(b); }
void xp25_buf_reset(XP25_BUF *b) { b->len = 0; b->failed = 0; if (b->data) b->data[0] = 0; }
int xp25_buf_ok(const XP25_BUF *b) { return !b->failed; }

static int reserve(XP25_BUF *b, size_t extra)
{
    size_t need, cap;
    char *data;
    if (b->failed) return 0;
    if (extra > (size_t)-1 / 2 - b->len) { b->failed = 1; return 0; }
    need = b->len + extra + 1;
    if (need <= b->cap) return 1;
    cap = b->cap ? b->cap : 64;
    while (cap < need) cap *= 2;
    data = (char *)xp25_realloc(b->data, cap);
    if (!data) { b->failed = 1; return 0; }
    b->data = data;
    b->cap = cap;
    return 1;
}

int xp25_buf_append(XP25_BUF *b, const char *s, size_t n)
{
    if (!reserve(b, n)) return 0;
    if (n) memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
    return 1;
}

int xp25_buf_puts(XP25_BUF *b, const char *s) { return xp25_buf_append(b, s ? s : "", s ? strlen(s) : 0); }
int xp25_buf_putc(XP25_BUF *b, char c) { return xp25_buf_append(b, &c, 1); }

int xp25_buf_u64(XP25_BUF *b, xp25_u64 v)
{
    char digits[24];
    int n = 0;
    do { digits[n++] = (char)('0' + (int)(v % 10)); v /= 10; } while (v && n < 24);
    while (n) if (!xp25_buf_putc(b, digits[--n])) return 0;
    return 1;
}

int xp25_buf_i64(XP25_BUF *b, xp25_i64 v)
{
    if (v < 0) {
        if (!xp25_buf_putc(b, '-')) return 0;
        return xp25_buf_u64(b, (xp25_u64)(-(v + 1)) + 1);
    }
    return xp25_buf_u64(b, (xp25_u64)v);
}

int xp25_buf_hex(XP25_BUF *b, const unsigned char *bytes, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        char pair[2];
        pair[0] = hex[bytes[i] >> 4];
        pair[1] = hex[bytes[i] & 15];
        if (!xp25_buf_append(b, pair, 2)) return 0;
    }
    return 1;
}

int xp25_buf_fixed1(XP25_BUF *b, xp25_u64 value, xp25_u64 unit)
{
    xp25_u64 tenths = unit ? (value * 10 + unit / 2) / unit : 0;
    if (!xp25_buf_u64(b, tenths / 10) || !xp25_buf_putc(b, '.')) return 0;
    return xp25_buf_putc(b, (char)('0' + (int)(tenths % 10)));
}

int xp25_buf_size(XP25_BUF *b, xp25_u64 bytes)
{
    static const char *units[] = { "KB", "MB", "GB", "TB" };
    xp25_u64 unit = 1024;
    int i;
    if (bytes < 1024) { xp25_buf_u64(b, bytes); return xp25_buf_puts(b, " bytes"); }
    for (i = 0; i < 3 && bytes >= unit * 1024; ++i) unit *= 1024;
    xp25_buf_fixed1(b, bytes, unit);
    xp25_buf_putc(b, ' ');
    return xp25_buf_puts(b, units[i]);
}

const char *xp25_buf_cstr(XP25_BUF *b)
{
    if (b->failed || !b->data) return "";
    return b->data;
}

char *xp25_buf_detach(XP25_BUF *b)
{
    char *data;
    if (b->failed) { xp25_buf_free(b); return NULL; }
    if (!b->data && !reserve(b, 0)) return NULL;
    data = b->data;
    data[b->len] = 0;
    xp25_buf_init(b);
    return data;
}

char *xp25_strndup(const char *s, size_t n)
{
    char *copy = (char *)xp25_alloc(n + 1);
    if (copy && n) memcpy(copy, s, n);
    return copy;
}

char *xp25_strdup(const char *s) { return s ? xp25_strndup(s, strlen(s)) : NULL; }
int xp25_lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
int xp25_is_space(int c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; }
int xp25_is_digit(int c) { return c >= '0' && c <= '9'; }
int xp25_is_alpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

int xp25_strnieq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        if (xp25_lower((unsigned char)a[i]) != xp25_lower((unsigned char)b[i])) return 0;
        if (!a[i]) return 1;
    }
    return 1;
}

int xp25_strieq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && xp25_lower((unsigned char)*a) == xp25_lower((unsigned char)*b)) { ++a; ++b; }
    return *a == *b;
}

const char *xp25_stristr(const char *haystack, const char *needle)
{
    size_t n;
    if (!haystack || !needle) return NULL;
    n = strlen(needle);
    if (!n) return haystack;
    for (; *haystack; ++haystack)
        if (xp25_strnieq(haystack, needle, n)) return haystack;
    return NULL;
}

int xp25_starts_with_i(const char *s, const char *prefix)
{
    return s && prefix && xp25_strnieq(s, prefix, strlen(prefix)) && strlen(s) >= strlen(prefix);
}

int xp25_ends_with_i(const char *s, const char *suffix)
{
    size_t a, b;
    if (!s || !suffix) return 0;
    a = strlen(s);
    b = strlen(suffix);
    return a >= b && xp25_strieq(s + a - b, suffix);
}

int xp25_parse_u64(const char *s, size_t n, xp25_u64 *out)
{
    xp25_u64 value = 0;
    size_t i;
    if (!n) return 0;
    for (i = 0; i < n; ++i) {
        if (!xp25_is_digit((unsigned char)s[i])) return 0;
        if (value > ((xp25_u64)-1 - 9) / 10) return 0;
        value = value * 10 + (xp25_u64)(s[i] - '0');
    }
    *out = value;
    return 1;
}

size_t xp25_utf8_clip(const char *s, size_t max)
{
    size_t n = strlen(s);
    if (n <= max) return n;
    n = max;
    while (n && ((unsigned char)s[n] & 0xC0) == 0x80) --n;
    return n;
}

int xp25_json_escape(XP25_BUF *b, const char *s, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i, start = 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        const char *rep = NULL;
        char u[6];
        if (c == '"') rep = "\\\"";
        else if (c == '\\') rep = "\\\\";
        else if (c == '\n') rep = "\\n";
        else if (c == '\r') rep = "\\r";
        else if (c == '\t') rep = "\\t";
        else if (c < 0x20 || c == 0x7f) {
            u[0] = '\\'; u[1] = 'u'; u[2] = '0'; u[3] = '0';
            u[4] = hex[c >> 4]; u[5] = hex[c & 15];
        } else continue;
        xp25_buf_append(b, s + start, i - start);
        if (rep) xp25_buf_puts(b, rep);
        else xp25_buf_append(b, u, 6);
        start = i + 1;
    }
    return xp25_buf_append(b, s + start, n - start);
}

void xp25_jw_init(XP25_JW *w, XP25_BUF *out)
{
    w->out = out;
    w->depth = 0;
    w->count[0] = 0;
    w->after_key = 0;
    w->failed = 0;
}

static void value_prefix(XP25_JW *w)
{
    if (w->after_key) { w->after_key = 0; return; }
    if (w->depth > 0 && w->count[w->depth]++) xp25_buf_putc(w->out, ',');
}

static void open(XP25_JW *w, char c)
{
    value_prefix(w);
    if (w->depth + 1 >= XP25_JW_DEPTH) { w->failed = 1; return; }
    xp25_buf_putc(w->out, c);
    ++w->depth;
    w->count[w->depth] = 0;
    w->closer[w->depth] = (char)(c == '{' ? '}' : ']');
}

void xp25_jw_obj(XP25_JW *w) { open(w, '{'); }
void xp25_jw_arr(XP25_JW *w) { open(w, '['); }

void xp25_jw_end(XP25_JW *w)
{
    if (w->depth <= 0 || w->after_key) { w->failed = 1; return; }
    xp25_buf_putc(w->out, w->closer[w->depth]);
    --w->depth;
}

void xp25_jw_key(XP25_JW *w, const char *key)
{
    if (w->depth > 0 && w->count[w->depth]++) xp25_buf_putc(w->out, ',');
    xp25_buf_putc(w->out, '"');
    xp25_json_escape(w->out, key, strlen(key));
    xp25_buf_append(w->out, "\":", 2);
    w->after_key = 1;
}

void xp25_jw_strn(XP25_JW *w, const char *value, size_t n)
{
    value_prefix(w);
    xp25_buf_putc(w->out, '"');
    xp25_json_escape(w->out, value, n);
    xp25_buf_putc(w->out, '"');
}

void xp25_jw_str(XP25_JW *w, const char *value)
{
    if (!value) { xp25_jw_null(w); return; }
    xp25_jw_strn(w, value, strlen(value));
}

void xp25_jw_i64(XP25_JW *w, xp25_i64 value) { value_prefix(w); xp25_buf_i64(w->out, value); }
void xp25_jw_u64(XP25_JW *w, xp25_u64 value) { value_prefix(w); xp25_buf_u64(w->out, value); }
void xp25_jw_bool(XP25_JW *w, int value) { value_prefix(w); xp25_buf_puts(w->out, value ? "true" : "false"); }
void xp25_jw_null(XP25_JW *w) { value_prefix(w); xp25_buf_puts(w->out, "null"); }
void xp25_jw_raw(XP25_JW *w, const char *json) { value_prefix(w); xp25_buf_puts(w->out, json); }
int xp25_jw_ok(const XP25_JW *w) { return !w->failed && w->depth == 0 && xp25_buf_ok(w->out); }
