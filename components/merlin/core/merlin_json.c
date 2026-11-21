/* MerlinAI portable core: bounded JSON writer and strict JSON reader. C89.
   The reader keeps token spans into the caller's text (no allocation); a
   MERLIN_JSON_DOC is large, so callers keep it static or on the heap. */
#include <string.h>
#include "merlin_core.h"

/* ---- writer ---- */
static void raw(MERLIN_JSON_OUT *j, const char *s, size_t n)
{
    if (j->overflow || j->used + n >= j->size) {
        j->overflow = 1;
        return;
    }
    memcpy(j->data + j->used, s, n);
    j->used += n;
    j->data[j->used] = 0;
}

static void separator(MERLIN_JSON_OUT *j)
{
    if (j->need_comma) raw(j, ",", 1);
    j->need_comma = 0;
}

void merlin_json_begin(MERLIN_JSON_OUT *j, char *buffer, size_t size)
{
    j->data = buffer;
    j->size = size;
    j->used = 0;
    j->overflow = size == 0;
    j->need_comma = 0;
    if (size) buffer[0] = 0;
}

void merlin_json_object(MERLIN_JSON_OUT *j) { separator(j); raw(j, "{", 1); }
void merlin_json_end_object(MERLIN_JSON_OUT *j) { raw(j, "}", 1); j->need_comma = 1; }
void merlin_json_array(MERLIN_JSON_OUT *j) { separator(j); raw(j, "[", 1); }
void merlin_json_end_array(MERLIN_JSON_OUT *j) { raw(j, "]", 1); j->need_comma = 1; }

static void quoted(MERLIN_JSON_OUT *j, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    char esc[6];
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    raw(j, "\"", 1);
    while (*p) {
        size_t n;
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\';
            esc[1] = (char)*p;
            raw(j, esc, 2);
            ++p;
            continue;
        }
        if (*p < 0x20 || *p == 0x7F) {
            esc[0] = '\\';
            esc[1] = 'u';
            esc[2] = '0';
            esc[3] = '0';
            esc[4] = hex[*p >> 4];
            esc[5] = hex[*p & 15];
            raw(j, esc, 6);
            ++p;
            continue;
        }
        n = merlin_utf8_length(p);
        if (!n) {
            raw(j, "?", 1);                              /* never emit invalid UTF-8 */
            ++p;
            continue;
        }
        raw(j, (const char *)p, n);
        p += n;
    }
    raw(j, "\"", 1);
}

void merlin_json_key(MERLIN_JSON_OUT *j, const char *key)
{
    separator(j);
    quoted(j, key);
    raw(j, ":", 1);
}

void merlin_json_string(MERLIN_JSON_OUT *j, const char *value)
{
    separator(j);
    quoted(j, value);
    j->need_comma = 1;
}

void merlin_json_ulong(MERLIN_JSON_OUT *j, unsigned long value)
{
    char digits[24];
    digits[0] = 0;
    merlin_append_ulong(digits, sizeof(digits), value);
    separator(j);
    raw(j, digits, strlen(digits));
    j->need_comma = 1;
}

void merlin_json_bool(MERLIN_JSON_OUT *j, int value)
{
    separator(j);
    raw(j, value ? "true" : "false", value ? 4 : 5);
    j->need_comma = 1;
}

static void member(MERLIN_JSON_OUT *j, const char *key, const char *value)
{
    merlin_json_key(j, key);
    merlin_json_string(j, value);
}

void merlin_json_problem(MERLIN_JSON_OUT *j, const MERLIN_PROBLEM *p)
{
    unsigned i;
    merlin_json_object(j);
    member(j, "id", p->id);
    member(j, "signature", p->signature);
    member(j, "kind", p->kind);
    member(j, "component", p->component);
    member(j, "title", p->title);
    member(j, "severity", p->severity);
    member(j, "impact", p->impact);
    merlin_json_key(j, "count");
    merlin_json_ulong(j, p->count);
    member(j, "first", p->first);
    member(j, "last", p->last);
    merlin_json_key(j, "submitted");
    merlin_json_bool(j, p->submitted);
    merlin_json_key(j, "dump_consent");
    merlin_json_bool(j, p->dump_consent);
    member(j, "app", p->app);
    member(j, "app_version", p->app_version);
    member(j, "module", p->module);
    member(j, "module_version", p->module_version);
    member(j, "offset", p->offset);
    member(j, "code", p->code);
    merlin_json_key(j, "evidence");
    merlin_json_array(j);
    for (i = 0; i < p->evidence_count && i < MERLIN_MAX_EVIDENCE; ++i) merlin_json_string(j, p->evidence[i]);
    merlin_json_end_array(j);
    merlin_json_key(j, "occurrences");
    merlin_json_array(j);
    for (i = 0; i < p->occurrence_count && i < MERLIN_MAX_OCCURRENCES; ++i) {
        merlin_json_object(j);
        member(j, "time", p->occurrences[i].time);
        member(j, "ref", p->occurrences[i].ref);
        merlin_json_end_object(j);
    }
    merlin_json_end_array(j);
    merlin_json_end_object(j);
}

int merlin_json_done(MERLIN_JSON_OUT *j) { return !j->overflow; }

/* ---- reader ---- */
typedef struct {
    MERLIN_JSON_DOC *doc;
    size_t pos;
} PARSER;

static void ws(PARSER *p)
{
    while (p->pos < p->doc->len) {
        char c = p->doc->text[p->pos];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++p->pos;
    }
}

static int add(PARSER *p, MERLIN_JSON_TYPE type, int parent, int key, size_t start)
{
    MERLIN_JSON_NODE *n;
    if (p->doc->count >= MERLIN_JSON_MAX_NODES) return -1;
    n = &p->doc->nodes[p->doc->count];
    n->type = type;
    n->parent = parent;
    n->key = key;
    n->start = start;
    n->len = 0;
    n->children = 0;
    if (parent >= 0) ++p->doc->nodes[parent].children;
    return p->doc->count++;
}

static int hex4(const char *s)
{
    int i, v = 0;
    for (i = 0; i < 4; ++i) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    return v;
}

static int parse_string(PARSER *p, int parent, int key)
{
    const char *t = p->doc->text;
    size_t start;
    int node;
    if (p->pos >= p->doc->len || t[p->pos] != '"') return -1;
    start = ++p->pos;
    while (p->pos < p->doc->len && t[p->pos] != '"') {
        unsigned char c = (unsigned char)t[p->pos];
        if (c < 0x20) return -1;
        if (c == '\\') {
            char e;
            if (p->pos + 1 >= p->doc->len) return -1;
            e = t[p->pos + 1];
            if (e == 'u') {
                if (p->pos + 6 > p->doc->len || hex4(t + p->pos + 2) < 0) return -1;
                p->pos += 6;
                continue;
            }
            if (!strchr("\"\\/bfnrt", e) || !e) return -1;
            p->pos += 2;
            continue;
        }
        if (c >= 0x80) {
            size_t n;
            char seq[5];
            size_t k;
            for (k = 0; k < 4 && p->pos + k < p->doc->len; ++k) seq[k] = t[p->pos + k];
            seq[k] = 0;
            n = merlin_utf8_length((const unsigned char *)seq);
            if (!n) return -1;
            p->pos += n;
            continue;
        }
        ++p->pos;
    }
    if (p->pos >= p->doc->len) return -1;
    node = add(p, MerlinJsonString, parent, key, start);
    if (node < 0) return -1;
    p->doc->nodes[node].len = p->pos - start;
    ++p->pos;
    return node;
}

static int parse_value(PARSER *p, int parent, int key, int depth);

static int parse_container(PARSER *p, int parent, int key, int depth, int object)
{
    const char *t = p->doc->text;
    int node = add(p, object ? MerlinJsonObject : MerlinJsonArray, parent, key, p->pos);
    if (node < 0 || depth > MERLIN_JSON_MAX_DEPTH) return -1;
    ++p->pos;
    ws(p);
    if (p->pos < p->doc->len && t[p->pos] == (object ? '}' : ']')) {
        ++p->pos;
        return node;
    }
    for (;;) {
        int member_key = -1;
        ws(p);
        if (object) {
            member_key = parse_string(p, -1, -1);
            if (member_key < 0) return -1;
            ws(p);
            if (p->pos >= p->doc->len || t[p->pos] != ':') return -1;
            ++p->pos;
            ws(p);
        }
        if (parse_value(p, node, member_key, depth + 1) < 0) return -1;
        ws(p);
        if (p->pos >= p->doc->len) return -1;
        if (t[p->pos] == ',') {
            ++p->pos;
            continue;
        }
        if (t[p->pos] == (object ? '}' : ']')) {
            ++p->pos;
            return node;
        }
        return -1;
    }
}

static int parse_number(PARSER *p, int parent, int key)
{
    const char *t = p->doc->text;
    size_t start = p->pos, digits = 0;
    int node;
    if (p->pos < p->doc->len && t[p->pos] == '-') ++p->pos;
    if (p->pos < p->doc->len && t[p->pos] == '0') {
        ++p->pos;
        digits = 1;
    } else
        while (p->pos < p->doc->len && t[p->pos] >= '0' && t[p->pos] <= '9') {
            ++p->pos;
            ++digits;
        }
    if (!digits) return -1;
    if (p->pos < p->doc->len && t[p->pos] == '.') {
        ++p->pos;
        digits = 0;
        while (p->pos < p->doc->len && t[p->pos] >= '0' && t[p->pos] <= '9') {
            ++p->pos;
            ++digits;
        }
        if (!digits) return -1;
    }
    if (p->pos < p->doc->len && (t[p->pos] == 'e' || t[p->pos] == 'E')) {
        ++p->pos;
        if (p->pos < p->doc->len && (t[p->pos] == '+' || t[p->pos] == '-')) ++p->pos;
        digits = 0;
        while (p->pos < p->doc->len && t[p->pos] >= '0' && t[p->pos] <= '9') {
            ++p->pos;
            ++digits;
        }
        if (!digits) return -1;
    }
    node = add(p, MerlinJsonNumber, parent, key, start);
    if (node >= 0) p->doc->nodes[node].len = p->pos - start;
    return node;
}

static int literal(PARSER *p, const char *word, MERLIN_JSON_TYPE type, int parent, int key)
{
    size_t n = strlen(word);
    int node;
    if (p->pos + n > p->doc->len || memcmp(p->doc->text + p->pos, word, n)) return -1;
    node = add(p, type, parent, key, p->pos);
    if (node >= 0) p->doc->nodes[node].len = n;
    p->pos += n;
    return node;
}

static int parse_value(PARSER *p, int parent, int key, int depth)
{
    char c;
    if (p->pos >= p->doc->len) return -1;
    c = p->doc->text[p->pos];
    if (c == '{') return parse_container(p, parent, key, depth, 1);
    if (c == '[') return parse_container(p, parent, key, depth, 0);
    if (c == '"') return parse_string(p, parent, key);
    if (c == 't') return literal(p, "true", MerlinJsonBool, parent, key);
    if (c == 'f') return literal(p, "false", MerlinJsonBool, parent, key);
    if (c == 'n') return literal(p, "null", MerlinJsonNull, parent, key);
    return parse_number(p, parent, key);
}

int merlin_json_parse(MERLIN_JSON_DOC *doc, const char *text, size_t len)
{
    PARSER p;
    doc->text = text;
    doc->len = len;
    doc->count = 0;
    p.doc = doc;
    p.pos = 0;
    ws(&p);
    if (parse_value(&p, -1, -1, 0) != 0) return 0;
    ws(&p);
    return p.pos == len;
}

static int span_equal(const MERLIN_JSON_DOC *doc, int node, const char *key)
{
    char decoded[256];
    if (!merlin_json_get_string(doc, node, decoded, sizeof(decoded))) return 0;
    return !strcmp(decoded, key);
}

int merlin_json_member(const MERLIN_JSON_DOC *doc, int object, const char *key)
{
    int i;
    if (object < 0 || object >= doc->count || doc->nodes[object].type != MerlinJsonObject) return -1;
    for (i = object + 1; i < doc->count; ++i)
        if (doc->nodes[i].parent == object && doc->nodes[i].key >= 0 && span_equal(doc, doc->nodes[i].key, key)) return i;
    return -1;
}

int merlin_json_element(const MERLIN_JSON_DOC *doc, int array, int index)
{
    int i, seen = 0;
    if (array < 0 || array >= doc->count || doc->nodes[array].type != MerlinJsonArray || index < 0) return -1;
    for (i = array + 1; i < doc->count; ++i)
        if (doc->nodes[i].parent == array && seen++ == index) return i;
    return -1;
}

static int put_utf8(char *out, size_t size, size_t *o, unsigned long cp)
{
    unsigned char b[4];
    size_t n, k;
    if (cp < 0x80) { b[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800) { b[0] = (unsigned char)(0xC0 | (cp >> 6)); b[1] = (unsigned char)(0x80 | (cp & 0x3F)); n = 2; }
    else if (cp < 0x10000) {
        b[0] = (unsigned char)(0xE0 | (cp >> 12));
        b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        b[2] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        b[0] = (unsigned char)(0xF0 | (cp >> 18));
        b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        b[3] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    if (*o + n >= size) return 0;
    for (k = 0; k < n; ++k) out[(*o)++] = (char)b[k];
    return 1;
}

int merlin_json_get_string(const MERLIN_JSON_DOC *doc, int node, char *out, size_t size)
{
    const char *s;
    size_t i, o = 0, len;
    if (!size) return 0;
    out[0] = 0;
    if (node < 0 || node >= doc->count || doc->nodes[node].type != MerlinJsonString) return 0;
    s = doc->text + doc->nodes[node].start;
    len = doc->nodes[node].len;
    for (i = 0; i < len;) {
        if (s[i] == '\\') {
            char e = s[i + 1];
            if (e == 'u') {
                unsigned long cp = (unsigned long)hex4(s + i + 2);
                i += 6;
                if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 <= len && s[i] == '\\' && s[i + 1] == 'u') {
                    int low = hex4(s + i + 2);
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (unsigned long)(low - 0xDC00);
                        i += 6;
                    }
                }
                if ((cp >= 0xD800 && cp <= 0xDFFF) || cp == 0) cp = '?';
                if (!put_utf8(out, size, &o, cp)) { out[o] = 0; return 0; }
                continue;
            }
            e = e == 'n' ? '\n' : e == 'r' ? '\r' : e == 't' ? '\t' : e == 'b' ? '\b' : e == 'f' ? '\f' : e;
            if (o + 1 >= size) { out[o] = 0; return 0; }
            out[o++] = e;
            i += 2;
            continue;
        }
        if (o + 1 >= size) { out[o] = 0; return 0; }
        out[o++] = s[i++];
    }
    out[o] = 0;
    return 1;
}

int merlin_json_get_ulong(const MERLIN_JSON_DOC *doc, int node, unsigned long *value)
{
    size_t i;
    unsigned long v = 0;
    const char *s;
    if (node < 0 || node >= doc->count || doc->nodes[node].type != MerlinJsonNumber) return 0;
    s = doc->text + doc->nodes[node].start;
    if (doc->nodes[node].len > 9) return 0;
    for (i = 0; i < doc->nodes[node].len; ++i) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    *value = v;
    return 1;
}

int merlin_json_get_bool(const MERLIN_JSON_DOC *doc, int node, int *value)
{
    if (node < 0 || node >= doc->count || doc->nodes[node].type != MerlinJsonBool) return 0;
    *value = doc->text[doc->nodes[node].start] == 't';
    return 1;
}

int merlin_json_member_string(const MERLIN_JSON_DOC *doc, int object, const char *key, char *out, size_t size)
{
    return merlin_json_get_string(doc, merlin_json_member(doc, object, key), out, size);
}
