/* XP25 AI runtime: eventlog_read through the NT 5.1 Event Logging API
   (OpenEventLog/ReadEventLog) with messages formatted from each source's
   registered EventMessageFile, as Event Viewer does. Log text is data. */
#include <windows.h>
#include <string.h>
#include "win_tools.h"

#define MAX_INSERTS 100

typedef struct { WCHAR source[128]; HMODULE modules[4]; int count; } MESSAGE_SOURCE;

static const char *type_name(WORD type)
{
    switch (type) {
    case EVENTLOG_ERROR_TYPE: return "error";
    case EVENTLOG_WARNING_TYPE: return "warning";
    case EVENTLOG_AUDIT_SUCCESS: return "audit_success";
    case EVENTLOG_AUDIT_FAILURE: return "audit_failure";
    default: return "information";
    }
}

static WORD type_mask(const XP25_JNODE *types)
{
    const XP25_JNODE *t;
    WORD mask = 0;
    if (!types || types->type != XP25_JARR || !types->count)
        return EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE | EVENTLOG_AUDIT_SUCCESS | EVENTLOG_AUDIT_FAILURE;
    for (t = types->child; t; t = t->next) {
        if (t->type != XP25_JSTR) continue;
        if (!strcmp(t->str, "error")) mask |= EVENTLOG_ERROR_TYPE;
        else if (!strcmp(t->str, "warning")) mask |= EVENTLOG_WARNING_TYPE;
        else if (!strcmp(t->str, "information")) mask |= EVENTLOG_INFORMATION_TYPE;
        else if (!strcmp(t->str, "audit_success")) mask |= EVENTLOG_AUDIT_SUCCESS;
        else if (!strcmp(t->str, "audit_failure")) mask |= EVENTLOG_AUDIT_FAILURE;
    }
    return mask;
}

static void load_modules(MESSAGE_SOURCE *s, const WCHAR *log, const WCHAR *source)
{
    WCHAR key[400], files[1024], expanded[2048], *p;
    HKEY h;
    DWORD type, bytes = sizeof(files) - sizeof(WCHAR);
    lstrcpynW(s->source, source, 128);
    s->count = 0;
    if (lstrlenW(log) + lstrlenW(source) > 300) return;
    lstrcpyW(key, L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\");
    lstrcatW(key, log);
    lstrcatW(key, L"\\");
    lstrcatW(key, source);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &h) != ERROR_SUCCESS) return;
    if (RegQueryValueExW(h, L"EventMessageFile", NULL, &type, (BYTE *)files, &bytes) == ERROR_SUCCESS &&
        (type == REG_EXPAND_SZ || type == REG_SZ)) {
        files[bytes / sizeof(WCHAR)] = 0;
        if (ExpandEnvironmentStringsW(files, expanded, 2048) && expanded[0]) {
            for (p = expanded; p && *p && s->count < 4;) {
                WCHAR *semi = wcschr(p, L';');
                if (semi) *semi = 0;
                s->modules[s->count] = LoadLibraryExW(p, NULL, LOAD_LIBRARY_AS_DATAFILE);
                if (s->modules[s->count]) ++s->count;
                p = semi ? semi + 1 : NULL;
            }
        }
    }
    RegCloseKey(h);
}

static void format_message(MESSAGE_SOURCE *cache, size_t *cached, const WCHAR *log, const EVENTLOGRECORD *r, XP25_BUF *out)
{
    const WCHAR *source = (const WCHAR *)((const BYTE *)r + sizeof(EVENTLOGRECORD));
    const WCHAR *strings[MAX_INSERTS];
    const WCHAR *s = (const WCHAR *)((const BYTE *)r + r->StringOffset);
    MESSAGE_SOURCE *ms = NULL;
    WCHAR *text = NULL;
    size_t i;
    int k;
    for (i = 0; i < MAX_INSERTS; ++i) strings[i] = L"";
    for (i = 0; i < r->NumStrings && i < MAX_INSERTS; ++i) { strings[i] = s; s += lstrlenW(s) + 1; }
    for (i = 0; i < *cached; ++i) if (!lstrcmpiW(cache[i].source, source)) { ms = &cache[i]; break; }
    if (!ms && *cached < 32) { ms = &cache[(*cached)++]; load_modules(ms, log, source); }
    for (k = 0; ms && k < ms->count && !text; ++k)
        if (!FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                            ms->modules[k], r->EventID, 0, (WCHAR *)&text, 0, (va_list *)strings)) text = NULL;
    if (text) {
        size_t n = lstrlenW(text);
        WCHAR *c;
        while (n && (text[n - 1] == L'\r' || text[n - 1] == L'\n' || text[n - 1] == L' ')) text[--n] = 0;
        for (c = text; *c; ++c) if (*c == L'\r') *c = L' ';
        xp25w_buf_wide(out, text);
        LocalFree(text);
        return;
    }
    xp25_buf_puts(out, "(No message text registered for this event.)");
    for (i = 0; i < r->NumStrings && i < 8; ++i) {
        xp25_buf_puts(out, i ? " | " : " Details: ");
        xp25w_buf_wide(out, strings[i]);
    }
}

int tool_eventlog(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    const char *log = tool_arg(args, "log", "System"), *source_filter = tool_arg(args, "source", "");
    long max_records = tool_int(args, "max_records", 20, 1, 100), since = tool_int(args, "since_hours", 168, 1, 8760);
    WORD mask = type_mask(xp25_json_get(args, "types"));
    WCHAR wlog[32];
    HANDLE h;
    BYTE *buffer;
    DWORD size = 64 * 1024, got, needed, scanned = 0, matched = 0, errors = 0, warnings = 0, infos = 0, total = 0;
    unsigned long cutoff = xp25w_now() - (unsigned long)since * 3600UL;
    MESSAGE_SOURCE *cache;
    size_t cached = 0, i;
    int done = 0;
    XP25_JW w;
    (void)tool;
    *egress = XP25_EGRESS_SENSITIVE;
    if (strcmp(log, "System") && strcmp(log, "Application") && strcmp(log, "Security")) {
        xp25_result_error(out, "bad_log", "Only the System, Application and Security logs can be read.");
        return 0;
    }
    xp25w_copy_wide(wlog, 32, log);
    h = OpenEventLogW(NULL, wlog);
    if (!h) return tool_win32_error(out, "open_failed", "Could not open the event log", GetLastError());
    GetNumberOfEventLogRecords(h, &total);
    buffer = (BYTE *)xp25_alloc(size);
    cache = (MESSAGE_SOURCE *)xp25_alloc(32 * sizeof(MESSAGE_SOURCE));
    if (!buffer || !cache) {
        xp25_free(buffer); xp25_free(cache); CloseEventLog(h);
        xp25_result_error(out, "out_of_memory", "Out of memory.");
        return 0;
    }
    tool_ok_begin(&w, out);
    xp25_jw_key(&w, "log"); xp25_jw_str(&w, log);
    xp25_jw_key(&w, "total_records"); xp25_jw_u64(&w, total);
    xp25_jw_key(&w, "since_hours"); xp25_jw_i64(&w, since);
    xp25_jw_key(&w, "records");
    xp25_jw_arr(&w);
    while (!done && scanned < 20000) {
        BYTE *p;
        if (!ReadEventLogW(h, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, buffer, size, &got, &needed)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed < 1024 * 1024) {
                BYTE *bigger = (BYTE *)xp25_realloc(buffer, needed);
                if (bigger) { buffer = bigger; size = needed; continue; }
            }
            break;
        }
        for (p = buffer; p < buffer + got && !done; p += ((EVENTLOGRECORD *)p)->Length) {
            const EVENTLOGRECORD *r = (const EVENTLOGRECORD *)p;
            char source[256], stamp[20];
            FILETIME ft;
            ULARGE_INTEGER v;
            if (r->Length < sizeof(EVENTLOGRECORD) || p + r->Length > buffer + got) { done = 1; break; }
            ++scanned;
            if ((unsigned long)r->TimeGenerated < cutoff) { done = 1; break; }
            if (r->EventType == EVENTLOG_ERROR_TYPE) ++errors;
            else if (r->EventType == EVENTLOG_WARNING_TYPE) ++warnings;
            else ++infos;
            if (!(r->EventType & mask) && !(r->EventType == 0 && (mask & EVENTLOG_INFORMATION_TYPE))) continue;
            xp25w_copy_utf8(source, sizeof(source), (const WCHAR *)(p + sizeof(EVENTLOGRECORD)));
            if (*source_filter && !xp25_stristr(source, source_filter)) continue;
            if (matched >= (DWORD)max_records) continue;
            ++matched;
            v.QuadPart = (ULONGLONG)r->TimeGenerated * 10000000UL + ((((ULONGLONG)0x019DB1DEUL) << 32) | 0xD53E8000UL);
            ft.dwLowDateTime = v.LowPart;
            ft.dwHighDateTime = v.HighPart;
            xp25w_format_filetime(&ft, stamp);
            xp25_jw_obj(&w);
            xp25_jw_key(&w, "record"); xp25_jw_u64(&w, r->RecordNumber);
            xp25_jw_key(&w, "time"); xp25_jw_str(&w, stamp);
            xp25_jw_key(&w, "type"); xp25_jw_str(&w, type_name(r->EventType));
            xp25_jw_key(&w, "source"); xp25_jw_str(&w, source);
            xp25_jw_key(&w, "event_id"); xp25_jw_u64(&w, r->EventID & 0xFFFF);
            xp25_jw_key(&w, "category"); xp25_jw_u64(&w, r->EventCategory);
            {
                XP25_BUF message;
                xp25_buf_init(&message);
                format_message(cache, &cached, wlog, r, &message);
                xp25_jw_key(&w, "message");
                xp25_jw_strn(&w, xp25_buf_cstr(&message), xp25_utf8_clip(xp25_buf_cstr(&message), 1500));
                xp25_buf_free(&message);
            }
            xp25_jw_end(&w);
        }
    }
    xp25_jw_end(&w);
    xp25_jw_key(&w, "scanned"); xp25_jw_u64(&w, scanned);
    xp25_jw_key(&w, "counts");
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "error"); xp25_jw_u64(&w, errors);
    xp25_jw_key(&w, "warning"); xp25_jw_u64(&w, warnings);
    xp25_jw_key(&w, "information"); xp25_jw_u64(&w, infos);
    xp25_jw_end(&w);
    for (i = 0; i < cached; ++i) {
        int k;
        for (k = 0; k < cache[i].count; ++k) FreeLibrary(cache[i].modules[k]);
    }
    xp25_free(cache);
    xp25_free(buffer);
    CloseEventLog(h);
    return tool_finish(&w, out);
}
