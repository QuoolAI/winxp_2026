/* MerlinAI portable core: problem signatures and the classification of event
   log records and XP25 Winlogon log lines. C89.

   Only failures become problems. Informational and success-audit records,
   warnings from unknown sources and MerlinAI's own records are never
   problems, and nothing here calls a record a vulnerability: the kinds are
   crash, hang, service, kernel, shutdown, storage, driver, winlogon,
   security (a failure of a security component) and event (any other error). */
#include <string.h>
#include "merlin_core.h"
#include "../../xp25-agent/llm/xp25_sha256.h"

void merlin_signature(const char *const *f, unsigned count, char out[MERLIN_SIG_SIZE])
{
    XP25_SHA256 ctx;
    unsigned char digest[32];
    char lowered[MERLIN_TEXT];
    unsigned i;
    xp25_sha256_init(&ctx);
    for (i = 0; i < count; ++i) {
        merlin_copy(lowered, sizeof(lowered), f[i] ? f[i] : "");
        merlin_lower(lowered);
        xp25_sha256_update(&ctx, lowered, strlen(lowered));
        xp25_sha256_update(&ctx, "\n", 1);
    }
    xp25_sha256_final(&ctx, digest);
    out[0] = 0;
    merlin_append_hex(out, MERLIN_SIG_SIZE, digest, 32);
}

int merlin_normalize_offset(const char *in, char out[16])
{
    size_t n, i;
    if (!in) return 0;
    if (in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) in += 2;
    n = strlen(in);
    if (!n || n > 8) return 0;
    for (i = 0; i < n; ++i) {
        char c = in[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    for (i = 0; i < 8 - n; ++i) out[i] = '0';
    for (i = 0; i < n; ++i) out[8 - n + i] = (char)(in[i] >= 'A' && in[i] <= 'F' ? in[i] - 'A' + 'a' : in[i]);
    out[8] = 0;
    return 1;
}

void merlin_crash_signature(const char *kind, const char *app, const char *app_version, const char *module,
                            const char *module_version, const char *offset, char out[MERLIN_SIG_SIZE])
{
    char normalized[16];
    const char *f[6];
    if (!merlin_normalize_offset(offset, normalized)) merlin_copy(normalized, sizeof(normalized), offset ? offset : "");
    f[0] = kind;
    f[1] = app;
    f[2] = app_version;
    f[3] = module;
    f[4] = module_version;
    f[5] = normalized;
    merlin_signature(f, 6, out);
}

const char *merlin_exception_name(unsigned long code)
{
    switch (code) {
    case 0xC0000005UL: return "Access violation";
    case 0xC000001DUL: return "Illegal instruction";
    case 0xC0000025UL: return "Non-continuable exception";
    case 0xC0000026UL: return "Invalid disposition";
    case 0xC000008CUL: return "Array bounds exceeded";
    case 0xC000008DUL: case 0xC000008EUL: case 0xC000008FUL: case 0xC0000090UL:
    case 0xC0000091UL: case 0xC0000092UL: case 0xC0000093UL: return "Floating-point error";
    case 0xC0000094UL: return "Integer division by zero";
    case 0xC0000095UL: return "Integer overflow";
    case 0xC0000096UL: return "Privileged instruction";
    case 0xC00000FDUL: return "Stack overflow";
    case 0xC0000006UL: return "In-page I/O error";
    case 0xC0000409UL: return "Stack buffer overrun";
    case 0x80000003UL: return "Breakpoint";
    case 0x80000002UL: return "Data type misalignment";
    case 0xE06D7363UL: return "C++ exception";
    default: return "Unhandled exception";
    }
}

static const char *string_at(const MERLIN_EVENT *e, unsigned i)
{
    return i < e->string_count && e->strings[i] ? e->strings[i] : "";
}

static void set_text(char *dst, size_t size, const char *a, const char *b, const char *c)
{
    merlin_copy(dst, size, a);
    if (b) merlin_append(dst, size, b);
    if (c) merlin_append(dst, size, c);
    merlin_sanitize_line(dst);
}

static int contains_lower(const char *haystack, const char *needle)
{
    char low[MERLIN_TEXT];
    merlin_copy(low, sizeof(low), haystack);
    merlin_lower(low);
    return strstr(low, needle) != NULL;
}

/* Services whose failure leaves a security function down. */
static int security_service(const char *name)
{
    static const char *const words[] = { "firewall", "security", "event log", "ipsec", "cryptographic", "xp25",
                                         "protected storage", "audit" };
    unsigned i;
    for (i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
        if (contains_lower(name, words[i])) return 1;
    return 0;
}

static void evidence_from(const MERLIN_EVENT *e, MERLIN_PROBLEM *p)
{
    char line[MERLIN_TEXT];
    unsigned i;
    merlin_copy(line, sizeof(line), e->log);
    merlin_append(line, sizeof(line), "/");
    merlin_append(line, sizeof(line), e->source);
    merlin_append(line, sizeof(line), " ");
    merlin_append_ulong(line, sizeof(line), e->event_id & 0xFFFFUL);
    merlin_append(line, sizeof(line), ": ");
    if (e->message && e->message[0]) merlin_append(line, sizeof(line), e->message);
    else
        for (i = 0; i < e->string_count && i < 8; ++i) {
            if (i) merlin_append(line, sizeof(line), " | ");
            merlin_append(line, sizeof(line), string_at(e, i));
        }
    merlin_problem_add_evidence(p, line);
}

static void finish(MERLIN_PROBLEM *p, const char *kind, const char *severity, const char *const *key, unsigned keys)
{
    merlin_copy(p->kind, sizeof(p->kind), kind);
    merlin_copy(p->severity, sizeof(p->severity), severity);
    merlin_signature(key, keys, p->signature);
    merlin_problem_set_id(p);
    merlin_sanitize_line(p->component);
    merlin_sanitize_line(p->title);
    merlin_sanitize_line(p->impact);
}

static int classify_fault(const MERLIN_EVENT *e, MERLIN_PROBLEM *p, int hang)
{
    char offset[16];
    if (e->string_count < 5) return 0;
    merlin_copy(p->app, sizeof(p->app), string_at(e, 0));
    merlin_copy(p->app_version, sizeof(p->app_version), string_at(e, 1));
    merlin_copy(p->module, sizeof(p->module), string_at(e, 2));
    merlin_copy(p->module_version, sizeof(p->module_version), string_at(e, 3));
    if (!merlin_normalize_offset(string_at(e, 4), offset)) merlin_copy(offset, sizeof(offset), "unknown");
    merlin_copy(p->offset, sizeof(p->offset), offset);
    merlin_copy(p->component, sizeof(p->component), p->app);
    if (hang) {
        set_text(p->title, sizeof(p->title), p->app, " stopped responding", NULL);
        set_text(p->impact, sizeof(p->impact), "The program stopped responding and was ended.", NULL, NULL);
    } else {
        set_text(p->title, sizeof(p->title), p->app, " crashed in ", p->module);
        set_text(p->impact, sizeof(p->impact), "The program closed unexpectedly; unsaved work in it was lost.", NULL, NULL);
    }
    merlin_crash_signature(hang ? "hang" : "crash", p->app, p->app_version, p->module, p->module_version, p->offset,
                           p->signature);
    merlin_problem_set_id(p);
    merlin_copy(p->kind, sizeof(p->kind), hang ? "hang" : "crash");
    merlin_copy(p->severity, sizeof(p->severity), "error");
    merlin_sanitize_line(p->app);
    merlin_sanitize_line(p->module);
    merlin_sanitize_line(p->title);
    merlin_sanitize_line(p->component);
    evidence_from(e, p);
    return 1;
}

/* name: the insert string holding the service's display name (7009 and 7011
   start with the timeout in milliseconds). */
static const struct {
    unsigned long id;
    unsigned name;
    const char *what;
} scm_failures[] = {
    { 7000, 0, " failed to start" },
    { 7001, 0, " did not start because a service it depends on failed" },
    { 7009, 1, " did not respond to the start request in time" },
    { 7011, 1, " timed out on a control request" },
    { 7022, 0, " hung on starting" },
    { 7023, 0, " terminated with an error" },
    { 7024, 0, " terminated with a service-specific error" },
    { 7031, 0, " terminated unexpectedly" },
    { 7034, 0, " terminated unexpectedly" },
};

static const struct {
    const char *source;
    unsigned long id;
} storage_errors[] = {
    { "disk", 7 }, { "disk", 9 }, { "disk", 11 }, { "disk", 15 }, { "disk", 51 }, { "atapi", 9 }, { "atapi", 11 },
    { "atapi", 15 }, { "ntfs", 50 }, { "ntfs", 55 }, { "ntfs", 57 }, { "ftdisk", 57 }, { "cdrom", 7 }, { "cdrom", 11 },
};

int merlin_classify_event(const MERLIN_EVENT *e, MERLIN_PROBLEM *p)
{
    unsigned long id = e->event_id & 0xFFFFUL;
    char number[16];
    const char *key[5];
    unsigned i;
    merlin_problem_init(p);
    number[0] = 0;
    merlin_append_ulong(number, sizeof(number), id);
    key[0] = "event";
    key[1] = e->log;
    key[2] = e->source;
    key[3] = number;
    if (!e->source || !e->log || merlin_lower_equal(e->source, "MerlinAI")) return 0;
    if (merlin_lower_equal(e->log, "Security")) {
        /* Audit records are about user activity, not failures of the system,
           except the two that mean auditing itself was lost or reset. */
        if (id == 516) {
            merlin_copy(p->component, sizeof(p->component), "Security auditing");
            merlin_copy(p->title, sizeof(p->title), "Security audit records were discarded");
            merlin_copy(p->impact, sizeof(p->impact), "Some security audit events were not recorded.");
            finish(p, "security", "error", key, 4);
        } else if (id == 517) {
            merlin_copy(p->component, sizeof(p->component), "Security auditing");
            merlin_copy(p->title, sizeof(p->title), "The security audit log was cleared");
            merlin_copy(p->impact, sizeof(p->impact), "Earlier security audit records are no longer available.");
            finish(p, "security", "warning", key, 4);
        } else return 0;
        evidence_from(e, p);
        return 1;
    }
    if (merlin_lower_equal(e->source, "Application Error") && id == 1000) return classify_fault(e, p, 0);
    if (merlin_lower_equal(e->source, "Application Hang") && (id == 1002 || id == 1001) && e->string_count >= 5)
        return classify_fault(e, p, 1);
    if (merlin_lower_equal(e->source, "DrWatson") && id == 4097) {
        merlin_copy(p->app, sizeof(p->app), string_at(e, 0));
        merlin_copy(p->component, sizeof(p->component), p->app);
        set_text(p->title, sizeof(p->title), p->app, " crashed (Dr. Watson)", NULL);
        merlin_copy(p->impact, sizeof(p->impact), "The program closed unexpectedly.");
        key[1] = p->app;
        key[2] = string_at(e, 3);
        finish(p, "crash", "error", key, 3);
        evidence_from(e, p);
        return 1;
    }
    if (merlin_lower_equal(e->source, "Service Control Manager")) {
        if (id == 7026) {
            merlin_copy(p->component, sizeof(p->component), "Drivers: ");
            merlin_append(p->component, sizeof(p->component), string_at(e, 0));
            merlin_copy(p->title, sizeof(p->title), "Boot or system drivers failed to load");
            merlin_copy(p->impact, sizeof(p->impact),
                        "A device or function provided by these drivers is unavailable (on a virtual machine this can be expected virtual hardware).");
            key[3] = string_at(e, 0);
            finish(p, "driver", "error", key, 4);
            evidence_from(e, p);
            return 1;
        }
        for (i = 0; i < sizeof(scm_failures) / sizeof(scm_failures[0]); ++i)
            if (scm_failures[i].id == id) {
                const char *service = string_at(e, scm_failures[i].name);
                int security = security_service(service);
                merlin_copy(p->component, sizeof(p->component), service);
                set_text(p->title, sizeof(p->title), "Service \"", service, "\"");
                merlin_append(p->title, sizeof(p->title), scm_failures[i].what);
                merlin_copy(p->impact, sizeof(p->impact),
                            security ? "A security component is not running; the protection it provides may be missing."
                                     : "Programs and features that depend on this service may not work.");
                key[0] = "service";
                key[1] = service;
                key[2] = number;
                finish(p, security ? "security" : "service", security ? "critical" : "error", key, 3);
                evidence_from(e, p);
                return 1;
            }
    }
    if ((merlin_lower_equal(e->source, "Save Dump") && id == 1001) || (merlin_lower_equal(e->source, "System Error") && id == 1003)) {
        merlin_copy(p->component, sizeof(p->component), "Windows kernel");
        merlin_copy(p->title, sizeof(p->title), "The computer restarted after a system error (bugcheck)");
        merlin_copy(p->impact, sizeof(p->impact), "Windows stopped unexpectedly; unsaved work in every program was lost.");
        key[0] = "kernel";
        key[1] = string_at(e, 0);
        finish(p, "kernel", "critical", key, 2);
        evidence_from(e, p);
        return 1;
    }
    if (merlin_lower_equal(e->source, "EventLog") && id == 6008) {
        merlin_copy(p->component, sizeof(p->component), "Windows shutdown");
        merlin_copy(p->title, sizeof(p->title), "The previous shutdown was unexpected");
        merlin_copy(p->impact, sizeof(p->impact), "Windows was not shut down normally (power loss, reset or a system error).");
        key[0] = "shutdown";
        finish(p, "shutdown", "warning", key, 1);
        evidence_from(e, p);
        return 1;
    }
    for (i = 0; i < sizeof(storage_errors) / sizeof(storage_errors[0]); ++i)
        if (merlin_lower_equal(e->source, storage_errors[i].source) && storage_errors[i].id == id) {
            merlin_copy(p->component, sizeof(p->component), e->source);
            set_text(p->title, sizeof(p->title), "Storage error reported by ", e->source, NULL);
            merlin_copy(p->impact, sizeof(p->impact),
                        "Data on a disk may be unreadable or damaged (on a virtual machine, check the host storage).");
            finish(p, "storage", "error", key, 4);
            evidence_from(e, p);
            return 1;
        }
    if (e->type == MERLIN_EVENT_ERROR ||
        (e->type == MERLIN_EVENT_WARNING && (contains_lower(e->source, "xp25") || contains_lower(e->source, "merlin")))) {
        merlin_copy(p->component, sizeof(p->component), e->source);
        set_text(p->title, sizeof(p->title), e->source, e->type == MERLIN_EVENT_ERROR ? " reported error " : " reported warning ",
                 number);
        merlin_copy(p->impact, sizeof(p->impact), "Logged by the component; the effect depends on the component.");
        finish(p, "event", e->type == MERLIN_EVENT_ERROR ? "error" : "warning",
               key, 4);
        evidence_from(e, p);
        return 1;
    }
    return 0;
}

/* Value of "key":"..." or "key":123 in one flat JSON line; bounded copy. */
static int flat_value(const char *line, const char *key, char *out, size_t size)
{
    char pattern[48];
    const char *at, *end;
    size_t n;
    merlin_copy(pattern, sizeof(pattern), "\"");
    merlin_append(pattern, sizeof(pattern), key);
    merlin_append(pattern, sizeof(pattern), "\":");
    at = strstr(line, pattern);
    if (!at) return 0;
    at += strlen(pattern);
    if (*at == '"') {
        ++at;
        for (end = at; *end && *end != '"'; ++end)
            if (*end == '\\') return 0;                  /* names written by the XP25 Winlogon never need escapes */
        if (*end != '"') return 0;
    } else
        for (end = at; *end >= '0' && *end <= '9'; ++end) {}
    n = (size_t)(end - at);
    if (!n || n >= size) return 0;
    memcpy(out, at, n);
    out[n] = 0;
    return 1;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && !strcmp(s + a - b, suffix);
}

int merlin_classify_winlogon(const char *line, MERLIN_PROBLEM *p)
{
    char name[MERLIN_NAME], status[16], phase[MERLIN_SHORT], readable[MERLIN_NAME];
    const char *key[3];
    size_t i;
    int failure;
    merlin_problem_init(p);
    if (strncmp(line, "{\"xp25_winlogon\":", 17) || !flat_value(line, "xp25_winlogon", name, sizeof(name)) ||
        !flat_value(line, "status", status, sizeof(status)))
        return 0;
    if (!flat_value(line, "phase", phase, sizeof(phase))) phase[0] = 0;
    failure = ends_with(name, "_failed") || ends_with(name, "_rejected") || ends_with(name, "_unsupported") ||
              strstr(name, "rolled_back") != NULL || !strcmp(name, "shell_recovered") ||
              !strcmp(name, "user_process_still_running");
    if (!failure) return 0;
    merlin_copy(readable, sizeof(readable), name);
    for (i = 0; readable[i]; ++i)
        if (readable[i] == '_') readable[i] = ' ';
    merlin_copy(p->component, sizeof(p->component), "XP25 Winlogon");
    set_text(p->title, sizeof(p->title), "Winlogon: ", readable, NULL);
    merlin_append(p->title, sizeof(p->title), " (status ");
    merlin_append(p->title, sizeof(p->title), status);
    merlin_append(p->title, sizeof(p->title), ")");
    merlin_copy(p->impact, sizeof(p->impact),
                !strcmp(name, "shell_recovered") ? "The desktop (Explorer) ended and was restarted by Winlogon."
                                                 : "A logon, logoff, lock or power operation did not complete normally.");
    key[0] = "winlogon";
    key[1] = name;
    key[2] = status;
    finish(p, "winlogon", ends_with(name, "_failed") || ends_with(name, "_rejected") ? "error" : "warning", key, 3);
    merlin_copy(readable, sizeof(readable), "native-winlogon.log: ");
    merlin_append(readable, sizeof(readable), name);
    merlin_append(readable, sizeof(readable), " status=");
    merlin_append(readable, sizeof(readable), status);
    if (phase[0]) {
        merlin_append(readable, sizeof(readable), " phase=");
        merlin_append(readable, sizeof(readable), phase);
    }
    merlin_problem_add_evidence(p, readable);
    return 1;
}
