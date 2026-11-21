/* MerlinAI portable core: redaction of report text before it is shown in a
   preview or leaves the machine. C89.

   One left-to-right pass; at each position the first matching rule wins:
   1. <drive>:\Documents and Settings\<name>  -> %USERPROFILE% for the current
      account, %PROFILES%\* for any other account (All Users, Default User,
      LocalService and NetworkService are kept: they identify nobody);
   2. "Bearer <token>"                         -> Bearer <redacted>;
   3. credential keywords followed by = or :   -> keyword=<redacted>;
   4. "sk-" followed by 16+ key characters     -> <redacted-key>;
   5. e-mail addresses                          -> <email>;
   6. 32+ character runs of mixed-case base64   -> <redacted-token>
      (pure hexadecimal, e.g. file hashes, is kept);
   7. the account and computer names as whole words -> <user>, <computer>,
      unless the name is a well-known default (XP25, Administrator, Guest,
      SYSTEM) that identifies nobody and also appears in product names.
   The output never exceeds the buffer; a rule whose replacement would not fit
   truncates the text rather than leaving the secret in place. */
#include <string.h>
#include "merlin_core.h"

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c; }
static int alnum(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }

/* Case-insensitive prefix test of word at s. */
static size_t starts(const char *s, const char *word)
{
    size_t i;
    for (i = 0; word[i]; ++i)
        if (!s[i] || lower((unsigned char)s[i]) != lower((unsigned char)word[i])) return 0;
    return i;
}

typedef struct {
    char *out;
    size_t size, used;
    int full;
} OUT;

static void emit(OUT *o, const char *s, size_t n)
{
    if (o->full) return;
    if (o->used + n >= o->size) {
        n = o->size - 1 - o->used;
        o->full = 1;
    }
    memcpy(o->out + o->used, s, n);
    o->used += n;
}

static void emit_str(OUT *o, const char *s) { emit(o, s, strlen(s)); }

static int path_char(int c) { return c && c != '\\' && c != '/' && c != '"' && c != '\'' && c != '\r' && c != '\n' && c != '\t'; }

static int default_name(const char *name, size_t n)
{
    static const char *const keep[] = { "xp25", "administrator", "guest", "system", "all users", "default user",
                                        "localservice", "networkservice", "local service", "network service" };
    unsigned i;
    for (i = 0; i < sizeof(keep) / sizeof(keep[0]); ++i)
        if (strlen(keep[i]) == n && starts(name, keep[i]) == n) return 1;
    return 0;
}

static int key_char(int c) { return alnum(c) || c == '_' || c == '-'; }
static int b64_char(int c) { return alnum(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'; }

static size_t email_at(const char *s)
{
    size_t i = 0, at, dot = 0;
    while (alnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '_' || s[i] == '%' || s[i] == '+' || s[i] == '-') ++i;
    if (!i || s[i] != '@') return 0;
    at = i++;
    while (alnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '-') {
        if (s[i] == '.') dot = i;
        ++i;
    }
    if (!dot || dot <= at + 1 || i - dot < 3) return 0;
    while (i > dot && s[i - 1] == '.') --i;
    return i;
}

unsigned merlin_redact(char *text, size_t size, const MERLIN_REDACT *ctx)
{
    static const char *const creds[] = { "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key",
                                         "access_key", "secret_key", "private_key", "authorization", "credential",
                                         "passphrase", "client_secret" };
    char out[MERLIN_LONG * 4];
    OUT o;
    size_t i = 0, n, j;
    unsigned count = 0, k;
    const char *user = ctx && ctx->user && strlen(ctx->user) >= 2 ? ctx->user : NULL;
    const char *computer = ctx && ctx->computer && strlen(ctx->computer) >= 2 ? ctx->computer : NULL;
    if (!size) return 0;
    if (size > sizeof(out)) size = sizeof(out);
    o.out = out;
    o.size = size;
    o.used = 0;
    o.full = 0;
    while (text[i] && !o.full) {
        const char *s = text + i;
        int boundary = i == 0 || !key_char((unsigned char)text[i - 1]);
        /* 1. profile paths, with or without a drive letter */
        n = 0;
        if ((s[0] | 32) >= 'a' && (s[0] | 32) <= 'z' && s[1] == ':') {
            n = starts(s + 2, "\\documents and settings\\");
            if (n) n += 2;
        }
        if (!n) n = starts(s, "\\documents and settings\\");
        if (n) {
            const char *name = s + n;
            size_t len = 0;
            while (path_char((unsigned char)name[len])) ++len;
            if (len && !default_name(name, len)) {
                if (user && strlen(user) == len && starts(name, user) == len) emit_str(&o, "%USERPROFILE%");
                else emit_str(&o, "%PROFILES%\\*");
                i += n + len;
                ++count;
                continue;
            }
        }
        /* 2. bearer tokens */
        if (boundary && (n = starts(s, "bearer ")) != 0 && key_char((unsigned char)s[n])) {
            emit(&o, s, n);
            emit_str(&o, "<redacted>");
            i += n;
            while (text[i] && text[i] != ' ' && text[i] != '"' && text[i] != '\'' && text[i] != ',' && text[i] != ';') ++i;
            ++count;
            continue;
        }
        /* 3. credential keywords */
        if (boundary) {
            for (k = 0; k < sizeof(creds) / sizeof(creds[0]); ++k) {
                n = starts(s, creds[k]);
                if (!n || key_char((unsigned char)s[n])) continue;
                j = n;
                while (s[j] == ' ') ++j;
                if (s[j] != '=' && s[j] != ':') continue;
                ++j;
                while (s[j] == ' ' || s[j] == '"' || s[j] == '\'') ++j;
                if (!s[j] || s[j] == ';' || s[j] == '&' || s[j] == ',') continue;
                /* "Authorization: Bearer x" / "Basic x": keep the scheme, redact the credential after it. */
                if ((n = starts(s + j, "bearer ")) != 0 || (n = starts(s + j, "basic ")) != 0) j += n;
                emit(&o, s, j);
                emit_str(&o, "<redacted>");
                while (s[j] && s[j] != ' ' && s[j] != ';' && s[j] != '&' && s[j] != ',' && s[j] != '"' && s[j] != '\'' &&
                       s[j] != '\r' && s[j] != '\n')
                    ++j;
                i += j;
                ++count;
                break;
            }
            if (k < sizeof(creds) / sizeof(creds[0])) continue;
        }
        /* 4. API-key shaped strings */
        if (boundary && s[0] == 's' && s[1] == 'k' && s[2] == '-') {
            j = 3;
            while (key_char((unsigned char)s[j])) ++j;
            if (j >= 19) {
                emit_str(&o, "<redacted-key>");
                i += j;
                ++count;
                continue;
            }
        }
        /* 5. e-mail addresses */
        if (boundary && (n = email_at(s)) != 0) {
            emit_str(&o, "<email>");
            i += n;
            ++count;
            continue;
        }
        /* 6. long mixed-case base64 runs */
        if (boundary && b64_char((unsigned char)s[0])) {
            int has_upper = 0, has_lower = 0, has_digit = 0, non_hex = 0;
            for (j = 0; b64_char((unsigned char)s[j]); ++j) {
                int c = (unsigned char)s[j];
                if (c >= 'A' && c <= 'Z') has_upper = 1;
                if (c >= 'a' && c <= 'z') has_lower = 1;
                if (c >= '0' && c <= '9') has_digit = 1;
                if (!((c >= '0' && c <= '9') || (lower(c) >= 'a' && lower(c) <= 'f'))) non_hex = 1;
            }
            if (j >= 32 && has_upper && has_lower && has_digit && non_hex) {
                emit_str(&o, "<redacted-token>");
                i += j;
                ++count;
                continue;
            }
        }
        /* 7. account and computer names as whole words */
        if (boundary && alnum((unsigned char)s[0])) {
            const char *names[2];
            const char *labels[2];
            names[0] = user;
            labels[0] = "<user>";
            names[1] = computer;
            labels[1] = "<computer>";
            for (k = 0; k < 2; ++k) {
                if (!names[k] || default_name(names[k], strlen(names[k]))) continue;
                n = starts(s, names[k]);
                if (n && n == strlen(names[k]) && !key_char((unsigned char)s[n])) break;
            }
            if (k < 2) {
                emit_str(&o, labels[k]);
                i += n;
                ++count;
                continue;
            }
        }
        emit(&o, s, 1);
        ++i;
    }
    out[o.used] = 0;
    memcpy(text, out, o.used + 1);
    return count;
}
