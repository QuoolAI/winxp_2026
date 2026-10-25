/* XP25 AI runtime: portable C89 base shared by ClippyAI and RoverAI.
   No Windows headers; the same code is compiled on the Linux host for tests. */
#ifndef XP25_BASE_H
#define XP25_BASE_H
#include <stddef.h>

#if defined(_MSC_VER)
typedef unsigned __int64 xp25_u64;
typedef __int64 xp25_i64;
#else
__extension__ typedef unsigned long long xp25_u64;
__extension__ typedef long long xp25_i64;
#endif

/* Callbacks handed to the C runtime (qsort) must be cdecl; NT builds compile
   with __stdcall as the default convention. */
#if defined(_MSC_VER)
#define XP25_CDECL __cdecl
#else
#define XP25_CDECL
#endif

void *xp25_alloc(size_t size);           /* zero-filled; NULL on failure */
void *xp25_realloc(void *block, size_t size);
void xp25_free(void *block);

/* Growable byte buffer. Any allocation failure is sticky: later appends are
   ignored and xp25_buf_ok() reports it, so callers check once at the end. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int failed;
} XP25_BUF;

void xp25_buf_init(XP25_BUF *b);
void xp25_buf_free(XP25_BUF *b);
void xp25_buf_reset(XP25_BUF *b);
int xp25_buf_ok(const XP25_BUF *b);
int xp25_buf_append(XP25_BUF *b, const char *s, size_t n);
int xp25_buf_puts(XP25_BUF *b, const char *s);
int xp25_buf_putc(XP25_BUF *b, char c);
int xp25_buf_u64(XP25_BUF *b, xp25_u64 v);
int xp25_buf_i64(XP25_BUF *b, xp25_i64 v);
int xp25_buf_hex(XP25_BUF *b, const unsigned char *bytes, size_t n);
/* One decimal place, e.g. 1536 bytes with unit 1024 -> "1.5". */
int xp25_buf_fixed1(XP25_BUF *b, xp25_u64 value, xp25_u64 unit);
int xp25_buf_size(XP25_BUF *b, xp25_u64 bytes); /* "12.3 MB" */
const char *xp25_buf_cstr(XP25_BUF *b);          /* NUL-terminated view, "" on failure */
char *xp25_buf_detach(XP25_BUF *b);              /* caller frees; NULL on failure */

char *xp25_strdup(const char *s);
char *xp25_strndup(const char *s, size_t n);
int xp25_lower(int c);
int xp25_strieq(const char *a, const char *b);
int xp25_strnieq(const char *a, const char *b, size_t n);
const char *xp25_stristr(const char *haystack, const char *needle);
int xp25_starts_with_i(const char *s, const char *prefix);
int xp25_ends_with_i(const char *s, const char *suffix);
int xp25_is_space(int c);
int xp25_is_digit(int c);
int xp25_is_alpha(int c);
int xp25_parse_u64(const char *s, size_t n, xp25_u64 *out);
size_t xp25_utf8_clip(const char *s, size_t max); /* longest prefix <= max bytes on a code point boundary */

/* Minimal JSON writer that inserts commas itself. */
#define XP25_JW_DEPTH 32
typedef struct {
    XP25_BUF *out;
    int depth;
    unsigned char count[XP25_JW_DEPTH];
    char closer[XP25_JW_DEPTH];
    int after_key;
    int failed;
} XP25_JW;

void xp25_jw_init(XP25_JW *w, XP25_BUF *out);
void xp25_jw_obj(XP25_JW *w);
void xp25_jw_arr(XP25_JW *w);
void xp25_jw_end(XP25_JW *w);
void xp25_jw_key(XP25_JW *w, const char *key);
void xp25_jw_str(XP25_JW *w, const char *value);   /* NULL writes null */
void xp25_jw_strn(XP25_JW *w, const char *value, size_t n);
void xp25_jw_i64(XP25_JW *w, xp25_i64 value);
void xp25_jw_u64(XP25_JW *w, xp25_u64 value);
void xp25_jw_bool(XP25_JW *w, int value);
void xp25_jw_null(XP25_JW *w);
void xp25_jw_raw(XP25_JW *w, const char *json);    /* caller guarantees valid JSON */
int xp25_jw_ok(const XP25_JW *w);
int xp25_json_escape(XP25_BUF *b, const char *s, size_t n);

/* JSON DOM. Strings are decoded UTF-8; numbers keep their literal text. */
typedef enum { XP25_JNULL, XP25_JBOOL, XP25_JNUM, XP25_JSTR, XP25_JARR, XP25_JOBJ } XP25_JTYPE;

typedef struct XP25_JNODE {
    XP25_JTYPE type;
    int boolean;
    const char *str;      /* string value or number text */
    size_t len;
    const char *key;      /* member name inside an object */
    size_t count;         /* children of arrays/objects */
    struct XP25_JNODE *child;
    struct XP25_JNODE *next;
} XP25_JNODE;

typedef struct XP25_ARENA_BLOCK XP25_ARENA_BLOCK;
typedef struct {
    XP25_JNODE *root;
    XP25_ARENA_BLOCK *blocks;
    char error[96];
} XP25_JDOC;

#define XP25_JSON_MAX_DEPTH 48
int xp25_json_parse(XP25_JDOC *doc, const char *text, size_t len);
void xp25_json_free(XP25_JDOC *doc);
const XP25_JNODE *xp25_json_get(const XP25_JNODE *object, const char *key);
const XP25_JNODE *xp25_json_at(const XP25_JNODE *array, size_t index);
const char *xp25_json_string(const XP25_JNODE *object, const char *key); /* NULL unless string */
int xp25_json_i64(const XP25_JNODE *object, const char *key, xp25_i64 *out);
int xp25_json_flag(const XP25_JNODE *object, const char *key, int fallback);
int xp25_json_node_i64(const XP25_JNODE *node, xp25_i64 *out);
/* Serialize a parsed node back to compact JSON (keys in document order). */
int xp25_json_write(XP25_BUF *b, const XP25_JNODE *node);
#endif
