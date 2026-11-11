/* XP25 AI runtime: bounded JSON parser. Input is untrusted (model output,
   gateway responses, tool arguments); every path is length checked. */
#include <string.h>
#include "xp25_base.h"

struct XP25_ARENA_BLOCK {
    struct XP25_ARENA_BLOCK *next;
    size_t used;
    size_t size;
};

typedef struct {
    XP25_JDOC *doc;
    const char *p;
    const char *end;
    int depth;
} PARSER;

#define ARENA_HEADER ((sizeof(XP25_ARENA_BLOCK) + 7) & ~(size_t)7)

static void *arena(XP25_JDOC *doc, size_t size)
{
    XP25_ARENA_BLOCK *block = doc->blocks;
    size = (size + 7) & ~(size_t)7;
    if (!block || block->size - block->used < size) {
        size_t want = size > 16384 ? size : 16384;
        block = (XP25_ARENA_BLOCK *)xp25_alloc(ARENA_HEADER + want);
        if (!block) return NULL;
        block->size = want;
        block->next = doc->blocks;
        doc->blocks = block;
    }
    block->used += size;
    return (char *)block + ARENA_HEADER + block->used - size;
}

static int fail(PARSER *ps, const char *message)
{
    size_t n = strlen(message);
    if (n >= sizeof(ps->doc->error)) n = sizeof(ps->doc->error) - 1;
    memcpy(ps->doc->error, message, n);
    ps->doc->error[n] = 0;
    return 0;
}

static void skip(PARSER *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\r' || *ps->p == '\n')) ++ps->p;
}

static int hex4(const char *p, unsigned long *out)
{
    int i;
    unsigned long v = 0;
    for (i = 0; i < 4; ++i) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned long)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

static size_t put_utf8(char *out, unsigned long cp)
{
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) { out[0] = (char)(0xC0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F)); return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static int string(PARSER *ps, const char **out, size_t *len)
{
    const char *start = ++ps->p, *scan;
    char *dest, *d;
    for (scan = start; scan < ps->end && *scan != '"'; ++scan) {
        if ((unsigned char)*scan < 0x20) return fail(ps, "control character in string");
        if (*scan == '\\') { if (++scan >= ps->end) break; }
    }
    if (scan >= ps->end) return fail(ps, "unterminated string");
    dest = d = (char *)arena(ps->doc, (size_t)(scan - start) + 4);
    if (!dest) return fail(ps, "out of memory");
    while (ps->p < scan) {
        char c = *ps->p++;
        if (c != '\\') { *d++ = c; continue; }
        c = *ps->p++;
        switch (c) {
        case '"': *d++ = '"'; break;
        case '\\': *d++ = '\\'; break;
        case '/': *d++ = '/'; break;
        case 'b': *d++ = '\b'; break;
        case 'f': *d++ = '\f'; break;
        case 'n': *d++ = '\n'; break;
        case 'r': *d++ = '\r'; break;
        case 't': *d++ = '\t'; break;
        case 'u': {
            unsigned long cp, low;
            if (scan - ps->p < 4 || !hex4(ps->p, &cp)) return fail(ps, "bad unicode escape");
            ps->p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (scan - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u' || !hex4(ps->p + 2, &low) ||
                    low < 0xDC00 || low > 0xDFFF) return fail(ps, "unpaired surrogate");
                ps->p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) return fail(ps, "unpaired surrogate");
            if (!cp) return fail(ps, "NUL in string");
            d += put_utf8(d, cp);
            break;
        }
        default: return fail(ps, "bad escape");
        }
    }
    *d = 0;
    ps->p = scan + 1;
    *out = dest;
    *len = (size_t)(d - dest);
    return 1;
}

static int value(PARSER *ps, XP25_JNODE *node);

static int container(PARSER *ps, XP25_JNODE *node, char close)
{
    XP25_JNODE **tail = &node->child;
    if (++ps->depth > XP25_JSON_MAX_DEPTH) return fail(ps, "nesting too deep");
    ++ps->p;
    skip(ps);
    if (ps->p < ps->end && *ps->p == close) { ++ps->p; --ps->depth; return 1; }
    for (;;) {
        XP25_JNODE *child = (XP25_JNODE *)arena(ps->doc, sizeof(XP25_JNODE));
        if (!child) return fail(ps, "out of memory");
        memset(child, 0, sizeof(*child));
        skip(ps);
        if (close == '}') {
            size_t keylen;
            if (ps->p >= ps->end || *ps->p != '"') return fail(ps, "expected member name");
            if (!string(ps, &child->key, &keylen)) return 0;
            skip(ps);
            if (ps->p >= ps->end || *ps->p != ':') return fail(ps, "expected colon");
            ++ps->p;
        }
        if (!value(ps, child)) return 0;
        *tail = child;
        tail = &child->next;
        ++node->count;
        skip(ps);
        if (ps->p < ps->end && *ps->p == ',') { ++ps->p; continue; }
        if (ps->p < ps->end && *ps->p == close) { ++ps->p; break; }
        return fail(ps, close == '}' ? "expected , or }" : "expected , or ]");
    }
    --ps->depth;
    return 1;
}

static int literal(PARSER *ps, const char *word)
{
    size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n)) return fail(ps, "invalid literal");
    ps->p += n;
    return 1;
}

static int number(PARSER *ps, XP25_JNODE *node)
{
    const char *start = ps->p;
    if (ps->p < ps->end && *ps->p == '-') ++ps->p;
    if (ps->p >= ps->end || !xp25_is_digit((unsigned char)*ps->p)) return fail(ps, "invalid number");
    if (*ps->p == '0') ++ps->p;
    else while (ps->p < ps->end && xp25_is_digit((unsigned char)*ps->p)) ++ps->p;
    if (ps->p < ps->end && *ps->p == '.') {
        ++ps->p;
        if (ps->p >= ps->end || !xp25_is_digit((unsigned char)*ps->p)) return fail(ps, "invalid fraction");
        while (ps->p < ps->end && xp25_is_digit((unsigned char)*ps->p)) ++ps->p;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ++ps->p;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ++ps->p;
        if (ps->p >= ps->end || !xp25_is_digit((unsigned char)*ps->p)) return fail(ps, "invalid exponent");
        while (ps->p < ps->end && xp25_is_digit((unsigned char)*ps->p)) ++ps->p;
    }
    node->type = XP25_JNUM;
    node->len = (size_t)(ps->p - start);
    {
        char *text = (char *)arena(ps->doc, node->len + 1);
        if (!text) return fail(ps, "out of memory");
        memcpy(text, start, node->len);
        text[node->len] = 0;
        node->str = text;
    }
    return 1;
}

static int value(PARSER *ps, XP25_JNODE *node)
{
    skip(ps);
    if (ps->p >= ps->end) return fail(ps, "unexpected end");
    switch (*ps->p) {
    case '{': node->type = XP25_JOBJ; return container(ps, node, '}');
    case '[': node->type = XP25_JARR; return container(ps, node, ']');
    case '"': node->type = XP25_JSTR; return string(ps, &node->str, &node->len);
    case 't': node->type = XP25_JBOOL; node->boolean = 1; return literal(ps, "true");
    case 'f': node->type = XP25_JBOOL; return literal(ps, "false");
    case 'n': node->type = XP25_JNULL; return literal(ps, "null");
    default: return number(ps, node);
    }
}

int xp25_json_parse(XP25_JDOC *doc, const char *text, size_t len)
{
    PARSER ps;
    memset(doc, 0, sizeof(*doc));
    ps.doc = doc;
    ps.p = text;
    ps.end = text + len;
    ps.depth = 0;
    if (!text) return fail(&ps, "no input");
    if (len >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF)
        ps.p += 3;
    doc->root = (XP25_JNODE *)arena(doc, sizeof(XP25_JNODE));
    if (!doc->root) return fail(&ps, "out of memory");
    memset(doc->root, 0, sizeof(XP25_JNODE));
    if (!value(&ps, doc->root)) { doc->root = NULL; return 0; }
    skip(&ps);
    if (ps.p != ps.end) { doc->root = NULL; return fail(&ps, "trailing data"); }
    return 1;
}

void xp25_json_free(XP25_JDOC *doc)
{
    while (doc->blocks) {
        XP25_ARENA_BLOCK *next = doc->blocks->next;
        xp25_free(doc->blocks);
        doc->blocks = next;
    }
    doc->root = NULL;
}

const XP25_JNODE *xp25_json_get(const XP25_JNODE *object, const char *key)
{
    const XP25_JNODE *child;
    if (!object || object->type != XP25_JOBJ) return NULL;
    for (child = object->child; child; child = child->next)
        if (child->key && !strcmp(child->key, key)) return child;
    return NULL;
}

const XP25_JNODE *xp25_json_at(const XP25_JNODE *array, size_t index)
{
    const XP25_JNODE *child;
    if (!array || (array->type != XP25_JARR && array->type != XP25_JOBJ)) return NULL;
    for (child = array->child; child && index; child = child->next) --index;
    return child;
}

const char *xp25_json_string(const XP25_JNODE *object, const char *key)
{
    const XP25_JNODE *node = xp25_json_get(object, key);
    return node && node->type == XP25_JSTR ? node->str : NULL;
}

int xp25_json_node_i64(const XP25_JNODE *node, xp25_i64 *out)
{
    xp25_u64 magnitude;
    const char *s;
    size_t n;
    int negative;
    if (!node || node->type != XP25_JNUM) return 0;
    s = node->str;
    n = node->len;
    negative = n && s[0] == '-';
    if (negative) { ++s; --n; }
    /* Accept integral values written as 12 or 12.0; reject fractions and exponents. */
    if (n > 2 && s[n - 2] == '.' && s[n - 1] == '0') n -= 2;
    if (!xp25_parse_u64(s, n, &magnitude) || magnitude > (xp25_u64)0x7fffffffffffffff) return 0;
    *out = negative ? -(xp25_i64)magnitude : (xp25_i64)magnitude;
    return 1;
}

int xp25_json_i64(const XP25_JNODE *object, const char *key, xp25_i64 *out)
{
    return xp25_json_node_i64(xp25_json_get(object, key), out);
}

int xp25_json_flag(const XP25_JNODE *object, const char *key, int fallback)
{
    const XP25_JNODE *node = xp25_json_get(object, key);
    return node && node->type == XP25_JBOOL ? node->boolean : fallback;
}

int xp25_json_write(XP25_BUF *b, const XP25_JNODE *node)
{
    const XP25_JNODE *child;
    if (!node) return xp25_buf_puts(b, "null");
    switch (node->type) {
    case XP25_JNULL: return xp25_buf_puts(b, "null");
    case XP25_JBOOL: return xp25_buf_puts(b, node->boolean ? "true" : "false");
    case XP25_JNUM: return xp25_buf_append(b, node->str, node->len);
    case XP25_JSTR:
        xp25_buf_putc(b, '"');
        xp25_json_escape(b, node->str, node->len);
        return xp25_buf_putc(b, '"');
    case XP25_JARR:
    case XP25_JOBJ:
        xp25_buf_putc(b, node->type == XP25_JARR ? '[' : '{');
        for (child = node->child; child; child = child->next) {
            if (child != node->child) xp25_buf_putc(b, ',');
            if (node->type == XP25_JOBJ) {
                xp25_buf_putc(b, '"');
                xp25_json_escape(b, child->key, strlen(child->key));
                xp25_buf_append(b, "\":", 2);
            }
            xp25_json_write(b, child);
        }
        return xp25_buf_putc(b, node->type == XP25_JARR ? ']' : '}');
    }
    return 0;
}
