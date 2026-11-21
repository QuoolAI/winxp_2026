/* MerlinAI portable core: problem records, redaction, event classification,
   deduplication, JSON and builder-request signing.

   Strict C89 without Windows headers, so every rule is tested on the host
   under AddressSanitizer/UBSan (tests/merlin_core.c). Native code supplies
   facts (event records, crash details, file contents) and stores what this
   core produces. Every input that reaches this core is untrusted: report
   files can be edited by users, event strings are written by any program,
   and builder replies arrive over the network. All parsers are bounded and
   reject rather than truncate silently where truncation would change meaning. */
#ifndef MERLIN_CORE_H
#define MERLIN_CORE_H
#include <stddef.h>

#define MERLIN_ID_SIZE 40            /* P-<16 hex>, C-<16 hex>, J-YYYYMMDD-HHMMSS-<6 hex> (24) plus NUL */
#define MERLIN_SIG_SIZE 65           /* 64 hex + NUL */
#define MERLIN_TIME_SIZE 21          /* 2026-11-21T10:00:00Z + NUL */
#define MERLIN_SHORT 64
#define MERLIN_NAME 128
#define MERLIN_TEXT 256
#define MERLIN_LONG 1024
#define MERLIN_MAX_EVIDENCE 24
#define MERLIN_MAX_OCCURRENCES 32
#define MERLIN_RECORD_MAX 65536      /* largest problem file accepted */

/* Event types as NT's event log reports them (winnt.h values). */
#define MERLIN_EVENT_ERROR 0x0001
#define MERLIN_EVENT_WARNING 0x0002
#define MERLIN_EVENT_INFORMATION 0x0004
#define MERLIN_EVENT_AUDIT_SUCCESS 0x0008
#define MERLIN_EVENT_AUDIT_FAILURE 0x0010

typedef struct {
    char time[MERLIN_TIME_SIZE];
    char ref[MERLIN_SHORT];          /* crash:C-..., event:System:1234, winlogon:<offset> */
} MERLIN_OCCURRENCE;

typedef struct {
    char id[MERLIN_ID_SIZE];
    char signature[MERLIN_SIG_SIZE];
    char kind[16];                   /* crash hang service kernel shutdown storage driver winlogon security event */
    char component[MERLIN_NAME];
    char title[MERLIN_TEXT];
    char severity[12];               /* critical error warning */
    char impact[MERLIN_TEXT];
    unsigned long count;
    char first[MERLIN_TIME_SIZE];
    char last[MERLIN_TIME_SIZE];
    char status[20];                 /* see merlin_status_valid */
    int submitted;                   /* the user chose Send to MerlinAI */
    int transfer_consent;            /* the user allowed transfer to the builder */
    int dump_consent;                /* the user allowed the memory dump to leave the machine */
    int transferred;                 /* accepted by the builder */
    char job[MERLIN_ID_SIZE];
    char analysis[MERLIN_LONG];      /* builder analysis summary; untrusted display text */
    char app[MERLIN_NAME];
    char app_version[MERLIN_SHORT];
    char module[MERLIN_NAME];
    char module_version[MERLIN_SHORT];
    char offset[16];
    char code[16];
    char dump[MERLIN_SHORT];         /* minidump file name next to the report */
    char owner[MERLIN_SHORT];        /* account that reported it (redacted form) */
    unsigned evidence_count;
    char evidence[MERLIN_MAX_EVIDENCE][MERLIN_TEXT];
    unsigned occurrence_count;
    MERLIN_OCCURRENCE occurrences[MERLIN_MAX_OCCURRENCES];
} MERLIN_PROBLEM;

/* ---- bounded text helpers (merlin_text.c) ---- */
/* Copy with truncation; always NUL-terminates when size > 0. Returns 1 if it fit. */
int merlin_copy(char *dst, size_t size, const char *src);
/* Append; returns 1 if it fit (dst stays terminated either way). */
int merlin_append(char *dst, size_t size, const char *src);
int merlin_append_ulong(char *dst, size_t size, unsigned long value);
int merlin_append_hex(char *dst, size_t size, const unsigned char *data, size_t len);
int merlin_lower_equal(const char *a, const char *b);
void merlin_lower(char *s);
/* Replace control characters and invalid UTF-8 with '?', in place. */
void merlin_sanitize_line(char *s);
/* Length of the valid UTF-8 sequence starting at s (1 for ASCII), or 0. */
size_t merlin_utf8_length(const unsigned char *s);
/* Seconds since 1970-01-01T00:00:00Z <-> "YYYY-MM-DDTHH:MM:SSZ". */
void merlin_format_time(unsigned long seconds, char out[MERLIN_TIME_SIZE]);
int merlin_parse_time(const char *text, unsigned long *seconds);
int merlin_time_valid(const char *text);

/* ---- problem records (merlin_record.c) ---- */
void merlin_problem_init(MERLIN_PROBLEM *p);
int merlin_status_valid(const char *status);
int merlin_kind_valid(const char *kind);
int merlin_severity_valid(const char *severity);
/* Serialize to the line format "XP25-MERLIN-PROBLEM 1". Returns bytes written
   (excluding NUL) or 0 when out is too small. */
size_t merlin_problem_write(const MERLIN_PROBLEM *p, char *out, size_t size);
/* Parse; returns 1 on success. Unknown keys are ignored, malformed lines,
   oversize values, duplicate scalars and bad enums are rejected. */
int merlin_problem_read(const char *text, size_t len, MERLIN_PROBLEM *p, char *error, size_t error_size);
/* Record one occurrence; idempotent per ref. Keeps the newest
   MERLIN_MAX_OCCURRENCES references while count keeps the full total.
   Returns 1 if it was new. */
int merlin_problem_add_occurrence(MERLIN_PROBLEM *p, const char *time, const char *ref);
int merlin_problem_add_evidence(MERLIN_PROBLEM *p, const char *line);
/* Merge src (same signature) into dst: occurrences, counts, first/last,
   consent flags (only ever set, never cleared by a merge). Returns 1 on success. */
int merlin_problem_merge(MERLIN_PROBLEM *dst, const MERLIN_PROBLEM *src);
/* Set id ("P-" + first 16 hex of the signature) from the signature. */
void merlin_problem_set_id(MERLIN_PROBLEM *p);

/* ---- signatures and classification (merlin_classify.c) ---- */
/* SHA-256 hex of the normalized key fields joined by '\n'. */
void merlin_signature(const char *const *fields, unsigned count, char out[MERLIN_SIG_SIZE]);
/* Crash bucket: application, its version, faulting module, its version and
   the offset in that module (names case-insensitive, offset normalized to 8
   lowercase hex digits). These are exactly the five strings of XP's
   "Application Error" event 1000, so a MerlinCrash report and the event it
   writes land in the same problem. The exception code is kept as a field,
   not in the bucket, because event 1000 does not carry it. kind is "crash"
   or "hang". */
void merlin_crash_signature(const char *kind, const char *app, const char *app_version, const char *module,
                            const char *module_version, const char *offset, char out[MERLIN_SIG_SIZE]);
/* Normalize "0x0001A2b3" / "1a2b3" to "0001a2b3"; 0 if not hex or longer than 8 digits. */
int merlin_normalize_offset(const char *in, char out[16]);
const char *merlin_exception_name(unsigned long code);

typedef struct {
    const char *log;                 /* Application, System, Security */
    const char *source;
    unsigned long event_id;          /* full EventID; the low 16 bits are the event number */
    unsigned type;                   /* MERLIN_EVENT_* */
    const char *const *strings;
    unsigned string_count;
    const char *message;             /* formatted message, may be NULL */
} MERLIN_EVENT;

/* Returns 1 and fills p (kind, component, title, severity, impact, signature,
   crash fields, one evidence line) when the event is a problem; 0 when it is
   informational or otherwise not a problem. */
int merlin_classify_event(const MERLIN_EVENT *e, MERLIN_PROBLEM *p);
/* One JSON line of the XP25 Winlogon log ({"xp25_winlogon":"...","status":N,...}).
   Returns 1 for a lifecycle failure. */
int merlin_classify_winlogon(const char *line, MERLIN_PROBLEM *p);

/* ---- redaction (merlin_redact.c) ---- */
typedef struct {
    const char *user;                /* current account name, may be NULL */
    const char *computer;            /* computer name, may be NULL */
} MERLIN_REDACT;
/* Rewrite in place (the result is never longer than size-1):
   C:\Documents and Settings\<name>\ -> %USERPROFILE%\ (or %PROFILES%\<other>\ ->
   %PROFILES%\*\), the account and computer names, e-mail addresses,
   key=value credentials, Bearer tokens and API-key shaped strings.
   Returns the number of redactions. */
unsigned merlin_redact(char *text, size_t size, const MERLIN_REDACT *ctx);

/* ---- JSON (merlin_json.c) ---- */
typedef struct {
    char *data;
    size_t size;
    size_t used;
    int overflow;
    int need_comma;
} MERLIN_JSON_OUT;
void merlin_json_begin(MERLIN_JSON_OUT *j, char *buffer, size_t size);
void merlin_json_object(MERLIN_JSON_OUT *j);
void merlin_json_end_object(MERLIN_JSON_OUT *j);
void merlin_json_array(MERLIN_JSON_OUT *j);
void merlin_json_end_array(MERLIN_JSON_OUT *j);
void merlin_json_key(MERLIN_JSON_OUT *j, const char *key);
void merlin_json_string(MERLIN_JSON_OUT *j, const char *value);
void merlin_json_ulong(MERLIN_JSON_OUT *j, unsigned long value);
void merlin_json_bool(MERLIN_JSON_OUT *j, int value);
void merlin_json_problem(MERLIN_JSON_OUT *j, const MERLIN_PROBLEM *p);
/* 1 if complete and not truncated. */
int merlin_json_done(MERLIN_JSON_OUT *j);

#define MERLIN_JSON_MAX_NODES 4096
#define MERLIN_JSON_MAX_DEPTH 24
typedef enum { MerlinJsonNull, MerlinJsonBool, MerlinJsonNumber, MerlinJsonString, MerlinJsonArray, MerlinJsonObject } MERLIN_JSON_TYPE;
typedef struct {
    MERLIN_JSON_TYPE type;
    int parent;
    int key;                         /* index of the key string node for object members, else -1 */
    size_t start, len;               /* raw token span in the input (strings without quotes) */
    int children;
} MERLIN_JSON_NODE;
typedef struct {
    const char *text;
    size_t len;
    int count;
    MERLIN_JSON_NODE nodes[MERLIN_JSON_MAX_NODES];
} MERLIN_JSON_DOC;
/* Parse strictly (RFC 8259 grammar, depth and node limits). Returns 1 on success. */
int merlin_json_parse(MERLIN_JSON_DOC *doc, const char *text, size_t len);
/* Member of an object node by key, or -1. */
int merlin_json_member(const MERLIN_JSON_DOC *doc, int object, const char *key);
/* i-th element of an array node, or -1. */
int merlin_json_element(const MERLIN_JSON_DOC *doc, int array, int index);
/* Decoded string value (escapes resolved, \u to UTF-8). Returns 1 if it fit and the node is a string. */
int merlin_json_get_string(const MERLIN_JSON_DOC *doc, int node, char *out, size_t size);
int merlin_json_get_ulong(const MERLIN_JSON_DOC *doc, int node, unsigned long *value);
int merlin_json_get_bool(const MERLIN_JSON_DOC *doc, int node, int *value);
/* Convenience: string member of an object. */
int merlin_json_member_string(const MERLIN_JSON_DOC *doc, int object, const char *key, char *out, size_t size);

/* ---- builder protocol (merlin_proto.c) ---- */
/* XP25-MERLIN1 request authentication (challenge-response, no clock):
     mac = HMAC-SHA256(key, "XP25-MERLIN1\n" METHOD "\n" path "\n" installation "\n"
                            challenge "\n" nonce "\n" hex(sha256(body)))
   Replies are authenticated with
     HMAC-SHA256(key, "XP25-MERLIN1-RESPONSE\n" nonce "\n" status "\n" hex(sha256(body))).
   The deployment agent uses the same construction with the "XP25-MERLIN-DEPLOY1"
   label and a different key, so a builder key can never authorize a deployment. */
#define MERLIN_LABEL_BUILDER "XP25-MERLIN1"
#define MERLIN_LABEL_DEPLOY "XP25-MERLIN-DEPLOY1"
void merlin_body_hash(const void *body, size_t len, char out[MERLIN_SIG_SIZE]);
int merlin_sign_request(const char *label, const unsigned char *key, size_t key_len, const char *method,
                        const char *path, const char *installation, const char *challenge, const char *nonce,
                        const void *body, size_t body_len, char out[MERLIN_SIG_SIZE]);
int merlin_verify_response(const char *label, const unsigned char *key, size_t key_len, const char *nonce,
                           unsigned status, const void *body, size_t body_len, const char *mac_hex);
/* Identifiers that may appear in a URL path or a header: [A-Za-z0-9_-], 1..max chars. */
int merlin_token_valid(const char *s, size_t max);
int merlin_hex_valid(const char *s, size_t len);
#endif
