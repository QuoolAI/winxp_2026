/* MerlinAI portable core: bounded text and time helpers. C89. */
#include <string.h>
#include "merlin_core.h"

int merlin_copy(char *dst, size_t size, const char *src)
{
    size_t n;
    if (!size) return 0;
    if (!src) src = "";
    n = strlen(src);
    if (n >= size) {
        memcpy(dst, src, size - 1);
        dst[size - 1] = 0;
        return 0;
    }
    memcpy(dst, src, n + 1);
    return 1;
}

int merlin_append(char *dst, size_t size, const char *src)
{
    size_t used;
    if (!size) return 0;
    used = strlen(dst);
    if (used >= size) return 0;
    return merlin_copy(dst + used, size - used, src);
}

int merlin_append_ulong(char *dst, size_t size, unsigned long value)
{
    char digits[24];
    int i = (int)sizeof(digits) - 1;
    digits[i] = 0;
    do {
        digits[--i] = (char)('0' + value % 10);
        value /= 10;
    } while (value && i > 0);
    return merlin_append(dst, size, digits + i);
}

int merlin_append_hex(char *dst, size_t size, const unsigned char *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    char pair[3];
    size_t i;
    pair[2] = 0;
    for (i = 0; i < len; ++i) {
        pair[0] = hex[data[i] >> 4];
        pair[1] = hex[data[i] & 15];
        if (!merlin_append(dst, size, pair)) return 0;
    }
    return 1;
}

static int lower_char(int c)
{
    return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

int merlin_lower_equal(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && *b && lower_char((unsigned char)*a) == lower_char((unsigned char)*b)) {
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

void merlin_lower(char *s)
{
    for (; *s; ++s) *s = (char)lower_char((unsigned char)*s);
}

size_t merlin_utf8_length(const unsigned char *s)
{
    size_t n, i;
    unsigned long cp;
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xC2 && s[0] <= 0xDF) { n = 2; cp = s[0] & 0x1F; }
    else if (s[0] >= 0xE0 && s[0] <= 0xEF) { n = 3; cp = s[0] & 0x0F; }
    else if (s[0] >= 0xF0 && s[0] <= 0xF4) { n = 4; cp = s[0] & 0x07; }
    else return 0;
    for (i = 1; i < n; ++i) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

void merlin_sanitize_line(char *s)
{
    unsigned char *p = (unsigned char *)s;
    size_t n;
    while (*p) {
        if (*p < 0x20 || *p == 0x7F) {
            *p++ = '?';
            continue;
        }
        n = merlin_utf8_length(p);
        if (!n) {
            *p++ = '?';
            continue;
        }
        p += n;
    }
}

static int leap(unsigned long y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static const unsigned char month_days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static void two(char *out, unsigned long v)
{
    out[0] = (char)('0' + v / 10 % 10);
    out[1] = (char)('0' + v % 10);
}

void merlin_format_time(unsigned long seconds, char out[MERLIN_TIME_SIZE])
{
    unsigned long days = seconds / 86400, rem = seconds % 86400, y = 1970, m = 0, dim;
    for (;;) {
        unsigned long yd = leap(y) ? 366 : 365;
        if (days < yd) break;
        days -= yd;
        ++y;
    }
    for (;;) {
        dim = month_days[m] + (m == 1 && leap(y) ? 1 : 0);
        if (days < dim) break;
        days -= dim;
        ++m;
    }
    out[0] = (char)('0' + y / 1000 % 10);
    out[1] = (char)('0' + y / 100 % 10);
    two(out + 2, y % 100);
    out[4] = '-';
    two(out + 5, m + 1);
    out[7] = '-';
    two(out + 8, days + 1);
    out[10] = 'T';
    two(out + 11, rem / 3600);
    out[13] = ':';
    two(out + 14, rem / 60 % 60);
    out[16] = ':';
    two(out + 17, rem % 60);
    out[19] = 'Z';
    out[20] = 0;
}

static int digits(const char *s, int n, unsigned long *v)
{
    int i;
    *v = 0;
    for (i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') return 0;
        *v = *v * 10 + (unsigned long)(s[i] - '0');
    }
    return 1;
}

int merlin_parse_time(const char *t, unsigned long *seconds)
{
    unsigned long y, mo, d, h, mi, s, days = 0, i;
    if (!t || strlen(t) != 20 || t[4] != '-' || t[7] != '-' || t[10] != 'T' || t[13] != ':' || t[16] != ':' || t[19] != 'Z')
        return 0;
    if (!digits(t, 4, &y) || !digits(t + 5, 2, &mo) || !digits(t + 8, 2, &d) || !digits(t + 11, 2, &h) ||
        !digits(t + 14, 2, &mi) || !digits(t + 17, 2, &s))
        return 0;
    if (y < 1970 || y > 2105 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return 0;
    if (d > (unsigned long)month_days[mo - 1] + (mo == 2 && leap(y) ? 1 : 0)) return 0;
    for (i = 1970; i < y; ++i) days += leap(i) ? 366 : 365;
    for (i = 0; i + 1 < mo; ++i) days += month_days[i] + (i == 1 && leap(y) ? 1 : 0);
    days += d - 1;                   /* 2105-12-31T23:59:59Z still fits 32 bits */
    *seconds = days * 86400UL + h * 3600UL + mi * 60UL + s;
    return 1;
}

int merlin_time_valid(const char *text)
{
    unsigned long ignored;
    return merlin_parse_time(text, &ignored);
}
