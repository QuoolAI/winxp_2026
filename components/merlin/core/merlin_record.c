/* MerlinAI portable core: problem records and their line format. C89.

   A problem file is UTF-8 text:
     XP25-MERLIN-PROBLEM 1
     key=value            (scalars at most once; evidence= and occurrence= repeat)
     end
   Values are single lines; '\\' escapes \\ \n \r \t and \xHH. The final "end"
   line makes a truncated file detectable. */
#include <stddef.h>
#include <string.h>
#include "merlin_core.h"

#define HEADER "XP25-MERLIN-PROBLEM 1"

enum { FIELD_TEXT, FIELD_FLAG, FIELD_COUNT };
typedef struct {
    const char *key;
    int type;
    size_t offset;
    size_t size;
} FIELD;

#define TEXT_FIELD(name) { #name, FIELD_TEXT, offsetof(MERLIN_PROBLEM, name), sizeof(((MERLIN_PROBLEM *)0)->name) }
#define FLAG_FIELD(name) { #name, FIELD_FLAG, offsetof(MERLIN_PROBLEM, name), sizeof(int) }
static const FIELD fields[] = {
    TEXT_FIELD(id), TEXT_FIELD(signature), TEXT_FIELD(kind), TEXT_FIELD(component), TEXT_FIELD(title),
    TEXT_FIELD(severity), TEXT_FIELD(impact),
    { "count", FIELD_COUNT, offsetof(MERLIN_PROBLEM, count), sizeof(unsigned long) },
    TEXT_FIELD(first), TEXT_FIELD(last), TEXT_FIELD(status),
    FLAG_FIELD(submitted), FLAG_FIELD(transfer_consent), FLAG_FIELD(dump_consent), FLAG_FIELD(transferred),
    TEXT_FIELD(job), TEXT_FIELD(analysis), TEXT_FIELD(app), TEXT_FIELD(app_version), TEXT_FIELD(module),
    TEXT_FIELD(module_version), TEXT_FIELD(offset), TEXT_FIELD(code), TEXT_FIELD(dump), TEXT_FIELD(owner)
};
#define FIELD_COUNT_ALL (sizeof(fields) / sizeof(fields[0]))

static const char *const statuses[] = { "new", "included", "fixed", "mitigated", "not_reproducible", "unresolved",
                                        "not_applicable", "excluded" };
static const char *const kinds[] = { "crash", "hang", "service", "kernel", "shutdown", "storage", "driver", "winlogon",
                                     "security", "event" };
static const char *const severities[] = { "critical", "error", "warning" };

static int one_of(const char *value, const char *const *list, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (!strcmp(value, list[i])) return 1;
    return 0;
}

int merlin_status_valid(const char *s) { return one_of(s, statuses, sizeof(statuses) / sizeof(statuses[0])); }
int merlin_kind_valid(const char *s) { return one_of(s, kinds, sizeof(kinds) / sizeof(kinds[0])); }
int merlin_severity_valid(const char *s) { return one_of(s, severities, sizeof(severities) / sizeof(severities[0])); }

void merlin_problem_init(MERLIN_PROBLEM *p)
{
    memset(p, 0, sizeof(*p));
    merlin_copy(p->status, sizeof(p->status), "new");
    merlin_copy(p->severity, sizeof(p->severity), "error");
    merlin_copy(p->kind, sizeof(p->kind), "event");
}

void merlin_problem_set_id(MERLIN_PROBLEM *p)
{
    char id[MERLIN_ID_SIZE];
    merlin_copy(id, sizeof(id), "P-");
    memcpy(id + 2, p->signature, 16);
    id[18] = 0;
    merlin_copy(p->id, sizeof(p->id), id);
}

/* ---- writer ---- */
typedef struct {
    char *out;
    size_t size, used;
    int overflow;
} SINK;

static void put(SINK *s, const char *text, size_t n)
{
    if (s->overflow || s->used + n >= s->size) {
        s->overflow = 1;
        return;
    }
    memcpy(s->out + s->used, text, n);
    s->used += n;
    s->out[s->used] = 0;
}

static void put_str(SINK *s, const char *text) { put(s, text, strlen(text)); }

static void put_value(SINK *s, const char *v)
{
    static const char hex[] = "0123456789abcdef";
    char esc[4];
    for (; *v; ++v) {
        unsigned char c = (unsigned char)*v;
        if (c == '\\') put(s, "\\\\", 2);
        else if (c == '\n') put(s, "\\n", 2);
        else if (c == '\r') put(s, "\\r", 2);
        else if (c == '\t') put(s, "\\t", 2);
        else if (c < 0x20 || c == 0x7F) {
            esc[0] = '\\';
            esc[1] = 'x';
            esc[2] = hex[c >> 4];
            esc[3] = hex[c & 15];
            put(s, esc, 4);
        } else put(s, (const char *)v, 1);
    }
}

static void put_line(SINK *s, const char *key, const char *value)
{
    put_str(s, key);
    put(s, "=", 1);
    put_value(s, value);
    put(s, "\n", 1);
}

size_t merlin_problem_write(const MERLIN_PROBLEM *p, char *out, size_t size)
{
    SINK s;
    size_t i;
    char number[24];
    s.out = out;
    s.size = size;
    s.used = 0;
    s.overflow = 0;
    if (size) out[0] = 0;
    put_str(&s, HEADER "\n");
    for (i = 0; i < FIELD_COUNT_ALL; ++i) {
        const char *base = (const char *)p + fields[i].offset;
        number[0] = 0;
        if (fields[i].type == FIELD_TEXT) put_line(&s, fields[i].key, base);
        else if (fields[i].type == FIELD_FLAG) put_line(&s, fields[i].key, *(const int *)base ? "1" : "0");
        else {
            merlin_append_ulong(number, sizeof(number), *(const unsigned long *)base);
            put_line(&s, fields[i].key, number);
        }
    }
    for (i = 0; i < p->evidence_count && i < MERLIN_MAX_EVIDENCE; ++i) put_line(&s, "evidence", p->evidence[i]);
    for (i = 0; i < p->occurrence_count && i < MERLIN_MAX_OCCURRENCES; ++i) {
        put_str(&s, "occurrence=");
        put_value(&s, p->occurrences[i].time);
        put(&s, " ", 1);
        put_value(&s, p->occurrences[i].ref);
        put(&s, "\n", 1);
    }
    put_str(&s, "end\n");
    if (s.overflow) {
        if (size) out[0] = 0;
        return 0;
    }
    return s.used;
}

/* ---- reader ---- */
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode an escaped value of n bytes into out; 0 on malformed or oversize input. */
static int decode(const char *v, size_t n, char *out, size_t size)
{
    size_t i = 0, o = 0;
    while (i < n) {
        char c = v[i++];
        if (c == '\\') {
            if (i >= n) return 0;
            c = v[i++];
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            else if (c == 'x') {
                int hi, lo;
                if (i + 2 > n || (hi = hexval(v[i])) < 0 || (lo = hexval(v[i + 1])) < 0) return 0;
                c = (char)(hi * 16 + lo);
                i += 2;
                if (!c) return 0;
            } else if (c != '\\') return 0;
        } else if ((unsigned char)c < 0x20) return 0;
        if (o + 1 >= size) return 0;
        out[o++] = c;
    }
    out[o] = 0;
    return 1;
}

static int fail(char *error, size_t size, const char *why, unsigned long line)
{
    if (error && size) {
        merlin_copy(error, size, why);
        merlin_append(error, size, " (line ");
        merlin_append_ulong(error, size, line);
        merlin_append(error, size, ")");
    }
    return 0;
}

static int ref_valid(const char *ref)
{
    const char *c;
    if (!*ref || strlen(ref) >= MERLIN_SHORT) return 0;
    for (c = ref; *c; ++c)
        if ((unsigned char)*c <= ' ' || (unsigned char)*c >= 0x7F) return 0;
    return 1;
}

/* A plain file name next to the report: [A-Za-z0-9_.-], no "..", no leading dot. */
static int file_name_valid(const char *name)
{
    const char *c;
    if (!*name || *name == '.' || strlen(name) >= MERLIN_SHORT || strstr(name, "..")) return 0;
    for (c = name; *c; ++c)
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_' ||
              *c == '-' || *c == '.'))
            return 0;
    return 1;
}

int merlin_problem_read(const char *text, size_t len, MERLIN_PROBLEM *p, char *error, size_t error_size)
{
    size_t pos = 0, i;
    unsigned long line = 0;
    unsigned char seen[FIELD_COUNT_ALL];
    int ended = 0;
    char value[MERLIN_LONG];
    merlin_problem_init(p);
    memset(seen, 0, sizeof(seen));
    if (error && error_size) error[0] = 0;
    if (len > MERLIN_RECORD_MAX) return fail(error, error_size, "record too large", 0);
    while (pos < len) {
        size_t start = pos, end, eq, klen;
        while (pos < len && text[pos] != '\n') ++pos;
        end = pos;
        if (pos < len) ++pos;
        else if (!ended) return fail(error, error_size, "missing end line", line + 1);
        if (end > start && text[end - 1] == '\r') --end;
        ++line;
        if (ended) {
            if (end > start) return fail(error, error_size, "data after end", line);
            continue;
        }
        if (line == 1) {
            if (end - start != strlen(HEADER) || memcmp(text + start, HEADER, end - start))
                return fail(error, error_size, "not a MerlinAI problem record", line);
            continue;
        }
        if (end - start == 3 && !memcmp(text + start, "end", 3)) {
            ended = 1;
            continue;
        }
        for (eq = start; eq < end && text[eq] != '='; ++eq) {}
        if (eq == end) return fail(error, error_size, "line without '='", line);
        klen = eq - start;
        if (!decode(text + eq + 1, end - eq - 1, value, sizeof(value)))
            return fail(error, error_size, "malformed or oversize value", line);
        if (klen == 8 && !memcmp(text + start, "evidence", 8)) {
            if (p->evidence_count >= MERLIN_MAX_EVIDENCE || strlen(value) >= MERLIN_TEXT)
                return fail(error, error_size, "too much evidence", line);
            merlin_copy(p->evidence[p->evidence_count++], MERLIN_TEXT, value);
            continue;
        }
        if (klen == 10 && !memcmp(text + start, "occurrence", 10)) {
            MERLIN_OCCURRENCE *o;
            char *space = strchr(value, ' ');
            if (p->occurrence_count >= MERLIN_MAX_OCCURRENCES) return fail(error, error_size, "too many occurrences", line);
            if (!space) return fail(error, error_size, "malformed occurrence", line);
            *space = 0;
            if (!merlin_time_valid(value) || !ref_valid(space + 1)) return fail(error, error_size, "malformed occurrence", line);
            o = &p->occurrences[p->occurrence_count++];
            merlin_copy(o->time, sizeof(o->time), value);
            merlin_copy(o->ref, sizeof(o->ref), space + 1);
            continue;
        }
        for (i = 0; i < FIELD_COUNT_ALL; ++i)
            if (strlen(fields[i].key) == klen && !memcmp(fields[i].key, text + start, klen)) break;
        if (i == FIELD_COUNT_ALL) continue;              /* a later version's key */
        if (seen[i]) return fail(error, error_size, "duplicate key", line);
        seen[i] = 1;
        if (fields[i].type == FIELD_TEXT) {
            if (strlen(value) >= fields[i].size) return fail(error, error_size, "value too long", line);
            merlin_copy((char *)p + fields[i].offset, fields[i].size, value);
        } else if (fields[i].type == FIELD_FLAG) {
            if (strcmp(value, "0") && strcmp(value, "1")) return fail(error, error_size, "flag must be 0 or 1", line);
            *(int *)((char *)p + fields[i].offset) = value[0] == '1';
        } else {
            unsigned long n = 0;
            const char *c = value;
            if (!*c || strlen(c) > 9) return fail(error, error_size, "bad count", line);
            for (; *c; ++c) {
                if (*c < '0' || *c > '9') return fail(error, error_size, "bad count", line);
                n = n * 10 + (unsigned long)(*c - '0');
            }
            *(unsigned long *)((char *)p + fields[i].offset) = n;
        }
    }
    if (!ended) return fail(error, error_size, "missing end line", line);
    if (!merlin_token_valid(p->id, MERLIN_ID_SIZE - 1) || (strncmp(p->id, "P-", 2) && strncmp(p->id, "C-", 2)))
        return fail(error, error_size, "bad id", 0);
    if (!merlin_hex_valid(p->signature, 64)) return fail(error, error_size, "bad signature", 0);
    if (!strncmp(p->id, "P-", 2) && (strlen(p->id) != 18 || memcmp(p->id + 2, p->signature, 16)))
        return fail(error, error_size, "id does not match signature", 0);
    if (!merlin_kind_valid(p->kind) || !merlin_severity_valid(p->severity) || !merlin_status_valid(p->status))
        return fail(error, error_size, "bad kind, severity or status", 0);
    if (!merlin_time_valid(p->first) || !merlin_time_valid(p->last) || strcmp(p->first, p->last) > 0)
        return fail(error, error_size, "bad first/last time", 0);
    if (p->count < p->occurrence_count || !p->count) return fail(error, error_size, "count below occurrences", 0);
    if (p->job[0] && !merlin_token_valid(p->job, MERLIN_ID_SIZE - 1)) return fail(error, error_size, "bad job id", 0);
    if (p->dump[0] && !file_name_valid(p->dump)) return fail(error, error_size, "bad dump name", 0);
    return 1;
}

int merlin_problem_add_occurrence(MERLIN_PROBLEM *p, const char *time, const char *ref)
{
    unsigned i, oldest = 0;
    if (!merlin_time_valid(time) || !ref_valid(ref)) return 0;
    for (i = 0; i < p->occurrence_count; ++i)
        if (!strcmp(p->occurrences[i].ref, ref)) return 0;
    if (p->occurrence_count == MERLIN_MAX_OCCURRENCES) {
        for (i = 1; i < p->occurrence_count; ++i)
            if (strcmp(p->occurrences[i].time, p->occurrences[oldest].time) < 0) oldest = i;
        if (strcmp(time, p->occurrences[oldest].time) < 0) {
            /* Older than everything kept: count it, keep the newer references. */
            ++p->count;
            if (strcmp(time, p->first) < 0) merlin_copy(p->first, sizeof(p->first), time);
            return 1;
        }
        memmove(&p->occurrences[oldest], &p->occurrences[oldest + 1],
                (p->occurrence_count - oldest - 1) * sizeof(MERLIN_OCCURRENCE));
        --p->occurrence_count;
    }
    merlin_copy(p->occurrences[p->occurrence_count].time, MERLIN_TIME_SIZE, time);
    merlin_copy(p->occurrences[p->occurrence_count].ref, MERLIN_SHORT, ref);
    ++p->occurrence_count;
    ++p->count;
    if (!p->first[0] || strcmp(time, p->first) < 0) merlin_copy(p->first, sizeof(p->first), time);
    if (!p->last[0] || strcmp(time, p->last) > 0) merlin_copy(p->last, sizeof(p->last), time);
    return 1;
}

int merlin_problem_add_evidence(MERLIN_PROBLEM *p, const char *line)
{
    unsigned i;
    char clean[MERLIN_TEXT];
    merlin_copy(clean, sizeof(clean), line);
    merlin_sanitize_line(clean);
    if (!clean[0]) return 0;
    for (i = 0; i < p->evidence_count; ++i)
        if (!strcmp(p->evidence[i], clean)) return 0;
    if (p->evidence_count >= MERLIN_MAX_EVIDENCE) return 0;
    merlin_copy(p->evidence[p->evidence_count++], MERLIN_TEXT, clean);
    return 1;
}

int merlin_problem_merge(MERLIN_PROBLEM *dst, const MERLIN_PROBLEM *src)
{
    unsigned i;
    if (strcmp(dst->signature, src->signature)) return 0;
    for (i = 0; i < src->occurrence_count; ++i)
        merlin_problem_add_occurrence(dst, src->occurrences[i].time, src->occurrences[i].ref);
    for (i = 0; i < src->evidence_count; ++i) merlin_problem_add_evidence(dst, src->evidence[i]);
    dst->submitted |= src->submitted;
    dst->transfer_consent |= src->transfer_consent;
    dst->dump_consent |= src->dump_consent;
    if (!dst->dump[0] && src->dump[0] && src->dump_consent) merlin_copy(dst->dump, sizeof(dst->dump), src->dump);
    return 1;
}
