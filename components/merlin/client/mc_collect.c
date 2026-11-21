/* MerlinClient.dll: local problem discovery.

   Reads the Application, System and Security event logs (OpenEventLogW /
   ReadEventLogW, NT 5.1 APIs), the XP25 Winlogon log and the crash reports
   MerlinCrash left in the queue, classifies them with the portable core and
   merges occurrences into P- problem records. Administrators only. Nothing
   collected here is transmitted: transfer is a separate, consented action. */
#include <windows.h>
#include "mc_internal.h"

#define LOG_BUFFER (64 * 1024)
#define MAX_TOUCHED 128
#define WINLOGON_LOG L"C:\\xp25\\native-winlogon.log"

typedef struct {
    MERLIN_PROBLEM *items;           /* problems loaded or created during this run */
    int count;
    BYTE dirty[MAX_TOUCHED];
    MERLIN_COLLECT_STATS *stats;
} TOUCHED;

static MERLIN_PROBLEM *problem_for(TOUCHED *t, const MERLIN_PROBLEM *candidate)
{
    int i;
    MERLIN_PROBLEM *p;
    for (i = 0; i < t->count; ++i)
        if (!lstrcmpA(t->items[i].signature, candidate->signature)) return &t->items[i];
    if (t->count >= MAX_TOUCHED) return NULL;
    p = &t->items[t->count];
    if (MerlinQueueLoad(candidate->id, p) != 0) {
        CopyMemory(p, candidate, sizeof(*p));
        p->count = 0;
        p->occurrence_count = 0;
        p->first[0] = p->last[0] = 0;
        merlin_problem_set_id(p);
        merlin_copy(p->status, sizeof(p->status), "new");
        p->submitted = p->transfer_consent = p->dump_consent = p->transferred = 0;
        p->job[0] = p->analysis[0] = p->dump[0] = 0;
        ++t->stats->new_problems;
    }
    return &t->items[t->count++];
}

static int index_of(TOUCHED *t, MERLIN_PROBLEM *p) { return (int)(p - t->items); }

/* Did MerlinCrash already report this event's crash (within 10 s)? */
static BOOL near_crash_report(const MERLIN_PROBLEM *p, unsigned long when)
{
    unsigned i;
    unsigned long t;
    for (i = 0; i < p->occurrence_count; ++i)
        if (!memcmp(p->occurrences[i].ref, "crash:", 6) && merlin_parse_time(p->occurrences[i].time, &t) &&
            (t > when ? t - when : when - t) <= 10)
            return TRUE;
    return FALSE;
}

static void record(TOUCHED *t, const MERLIN_PROBLEM *candidate, unsigned long when, const char *ref, BOOL check_crash)
{
    MERLIN_PROBLEM *p = problem_for(t, candidate);
    char time[MERLIN_TIME_SIZE];
    unsigned i;
    if (!p) {
        ++t->stats->errors;
        return;
    }
    if (check_crash && near_crash_report(p, when)) return;
    merlin_format_time(when, time);
    if (merlin_problem_add_occurrence(p, time, ref)) {
        ++t->stats->new_occurrences;
        for (i = 0; i < candidate->evidence_count; ++i) merlin_problem_add_evidence(p, candidate->evidence[i]);
        t->dirty[index_of(t, p)] = 1;
    }
}

/* ---- event logs ---- */
typedef struct {
    WCHAR source[128];
    HMODULE modules[4];
} MSGFILE;

static void load_message_files(const WCHAR *log, const WCHAR *source, MSGFILE *mf)
{
    WCHAR key[300], value[512], expanded[1024];
    WCHAR *part, *next;
    int n = 0;
    ZeroMemory(mf->modules, sizeof(mf->modules));
    lstrcpynW(mf->source, source, 128);
    if (lstrlenW(log) + lstrlenW(source) > 200) return;
    lstrcpyW(key, L"SYSTEM\\CurrentControlSet\\Services\\Eventlog\\");
    lstrcatW(key, log);
    lstrcatW(key, L"\\");
    lstrcatW(key, source);
    if (mc_reg_read_string(HKEY_LOCAL_MACHINE, key, L"EventMessageFile", value, 512)) return;
    if (!ExpandEnvironmentStringsW(value, expanded, 1024)) return;
    for (part = expanded; part && *part && n < 4; part = next) {
        next = part;
        while (*next && *next != L';') ++next;
        if (*next) *next++ = 0;
        else next = NULL;
        mf->modules[n] = LoadLibraryExW(part, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (mf->modules[n]) ++n;
    }
}

static void free_message_files(MSGFILE *mf)
{
    int i;
    for (i = 0; i < 4; ++i)
        if (mf->modules[i]) FreeLibrary(mf->modules[i]);
    ZeroMemory(mf, sizeof(*mf));
}

static void format_event(MSGFILE *mf, const EVENTLOGRECORD *r, const WCHAR **strings, char *out, int size)
{
    WCHAR *text = NULL;
    DWORD_PTR args[99];                             /* %1..%99: every insert a message can name */
    int i;
    out[0] = 0;
    for (i = 0; i < 99; ++i) args[i] = (DWORD_PTR)(i < r->NumStrings && i < 32 ? strings[i] : L"");
    for (i = 0; i < 4 && mf->modules[i] && !text; ++i)
        if (!FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
                                FORMAT_MESSAGE_MAX_WIDTH_MASK,
                            mf->modules[i], r->EventID, 0, (LPWSTR)&text, 0, (va_list *)args))
            text = NULL;
    if (text) {
        MerlinWideToUtf8(text, out, size);
        LocalFree(text);
    }
}

/* Administrators hold SeSecurityPrivilege disabled; reading the Security log needs it enabled. */
static BOOL enable_security_privilege(void)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    BOOL ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &tp.Privileges[0].Luid) &&
         AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static void collect_log(TOUCHED *t, const WCHAR *log, char letter)
{
    HANDLE h;
    BYTE *buffer;
    DWORD size = LOG_BUFFER, got = 0, needed, oldest = 0, total = 0, last = 0, last_time = 0, skip_through = 0;
    DWORD max_record = 0, max_time = 0;
    BOOL have = FALSE;
    WCHAR name[64];
    char log8[32];
    MSGFILE mf;
    ZeroMemory(&mf, sizeof(mf));
    MerlinWideToUtf8(log, log8, sizeof(log8));
    h = OpenEventLogW(NULL, log);
    if (!h && letter == 'E' && enable_security_privilege()) h = OpenEventLogW(NULL, log);
    if (!h) {
        ++t->stats->errors;                        /* the Security log needs SeSecurityPrivilege */
        return;
    }
    GetOldestEventLogRecord(h, &oldest);
    GetNumberOfEventLogRecords(h, &total);
    lstrcpyW(name, log);
    lstrcatW(name, L"Record");
    mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, name, &last);
    lstrcpyW(name, log);
    lstrcatW(name, L"Time");
    mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, name, &last_time);
    buffer = (BYTE *)mc_alloc(size);
    if (!buffer) {
        CloseEventLog(h);
        return;
    }
    /* The bookmark holds when the record it names still carries the same time
       (a cleared log restarts numbering at 1). */
    /* A seek read returns the bookmarked record and as many following ones as fit, and the next
       sequential read continues after all of them: that first buffer is processed like any other. */
    if (last && last >= oldest && last < oldest + total &&
        ReadEventLogW(h, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ, last, buffer, size, &got, &needed) &&
        ((EVENTLOGRECORD *)buffer)->TimeGenerated == last_time) {
        skip_through = last;
        have = TRUE;
    }
    for (;;) {
        DWORD offset = 0;
        if (have)
            have = FALSE;
        else if (!ReadEventLogW(h, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, buffer, size, &got, &needed)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > size && needed < 1024 * 1024) {
                mc_free(buffer);
                size = needed;
                buffer = (BYTE *)mc_alloc(size);
                if (!buffer) break;
                continue;
            }
            break;                                     /* ERROR_HANDLE_EOF */
        }
        while (offset + sizeof(EVENTLOGRECORD) <= got) {
            EVENTLOGRECORD *r = (EVENTLOGRECORD *)(buffer + offset);
            const WCHAR *strings[32];
            char source8[128], strings8[32][MERLIN_TEXT], message[MERLIN_TEXT], ref[MERLIN_SHORT];
            const char *string_ptrs[32];
            MERLIN_EVENT e;
            MERLIN_PROBLEM *candidate;
            const WCHAR *s;
            DWORD i;
            if (r->Length < sizeof(EVENTLOGRECORD) || offset + r->Length > got) break;
            offset += r->Length;
            if (r->RecordNumber > max_record || !max_record) {
                max_record = r->RecordNumber;
                max_time = r->TimeGenerated;
            }
            ++t->stats->events_read;
            if (r->RecordNumber <= skip_through) continue;
            if (r->EventType == EVENTLOG_INFORMATION_TYPE || r->EventType == EVENTLOG_SUCCESS) {
                if (letter != 'E') continue;               /* Security keeps success audits 516/517 */
            }
            MerlinWideToUtf8((const WCHAR *)(r + 1), source8, sizeof(source8));
            s = (const WCHAR *)((BYTE *)r + r->StringOffset);
            for (i = 0; i < r->NumStrings && i < 32; ++i) {
                if ((const BYTE *)s >= (const BYTE *)r + r->Length) break;
                strings[i] = s;
                MerlinWideToUtf8(s, strings8[i], MERLIN_TEXT);
                merlin_sanitize_line(strings8[i]);
                string_ptrs[i] = strings8[i];
                s += lstrlenW(s) + 1;
            }
            ZeroMemory(&e, sizeof(e));
            e.log = log8;
            e.source = source8;
            e.event_id = r->EventID;
            e.type = r->EventType;
            e.strings = string_ptrs;
            e.string_count = (unsigned)i;
            candidate = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
            if (!candidate) continue;
            if (merlin_classify_event(&e, candidate)) {
                if (lstrcmpiW(mf.source, (const WCHAR *)(r + 1))) {
                    free_message_files(&mf);
                    load_message_files(log, (const WCHAR *)(r + 1), &mf);
                }
                format_event(&mf, r, strings, message, sizeof(message));
                if (message[0]) {
                    e.message = message;
                    merlin_classify_event(&e, candidate);      /* evidence with the formatted text */
                }
                ref[0] = 0;
                merlin_append(ref, sizeof(ref), letter == 'A' ? "event:A:" : letter == 'S' ? "event:S:" : "event:E:");
                merlin_append_ulong(ref, sizeof(ref), r->RecordNumber);
                merlin_append(ref, sizeof(ref), ":");
                merlin_append_ulong(ref, sizeof(ref), r->TimeGenerated);
                record(t, candidate, r->TimeGenerated, ref,
                       lstrcmpiW((const WCHAR *)(r + 1), L"Application Error") == 0 && (r->EventID & 0xFFFF) == 1000);
            }
            mc_free(candidate);
        }
    }
    free_message_files(&mf);
    mc_free(buffer);
    CloseEventLog(h);
    if (max_record) {
        lstrcpyW(name, log);
        lstrcatW(name, L"Record");
        mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, name, max_record);
        lstrcpyW(name, log);
        lstrcatW(name, L"Time");
        mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, name, max_time);
    }
}

/* ---- XP25 Winlogon log ---- */
static void collect_winlogon(TOUCHED *t)
{
    HANDLE f;
    DWORD size, offset = 0, got = 0, start, i, chunk;
    FILETIME written;
    char *data;
    MERLIN_PROBLEM *candidate;
    f = CreateFileW(WINLOGON_LOG, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    size = GetFileSize(f, NULL);
    GetFileTime(f, NULL, NULL, &written);
    mc_reg_read_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, L"WinlogonOffset", &offset);
    if (size == INVALID_FILE_SIZE || offset > size) offset = 0;          /* the log was replaced */
    chunk = size - offset > 1024 * 1024 ? 1024 * 1024 : size - offset;
    data = (char *)mc_alloc(chunk + 1);
    candidate = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
    if (data && candidate && chunk && SetFilePointer(f, (LONG)offset, NULL, FILE_BEGIN) == offset &&
        ReadFile(f, data, chunk, &got, NULL)) {
        data[got] = 0;
        for (start = 0, i = 0; i < got; ++i) {
            if (data[i] != '\n') continue;
            data[i] = 0;
            if (i > start && data[i - 1] == '\r') data[i - 1] = 0;
            ++t->stats->winlogon_lines;
            if (merlin_classify_winlogon(data + start, candidate)) {
                char ref[MERLIN_SHORT];
                ref[0] = 0;
                merlin_append(ref, sizeof(ref), "winlogon:");
                merlin_append_ulong(ref, sizeof(ref), offset + start);
                merlin_append(ref, sizeof(ref), ":");
                merlin_append_ulong(ref, sizeof(ref), mc_filetime_seconds(&written));
                /* Winlogon lines carry no time; the log file's write time bounds them. */
                record(t, candidate, mc_filetime_seconds(&written), ref, FALSE);
            }
            start = i + 1;
        }
        mc_reg_write_dword(HKEY_LOCAL_MACHINE, MERLIN_REG_COLLECTOR, L"WinlogonOffset", offset + start);
    }
    mc_free(data);
    mc_free(candidate);
    CloseHandle(f);
}

/* ---- crash reports ---- */
static void collect_crash_reports(TOUCHED *t)
{
    WCHAR pattern[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    MERLIN_PROBLEM *report = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
    char err[96];
    if (!report || !MerlinQueueDirectory(pattern, MAX_PATH)) {
        mc_free(report);
        return;
    }
    lstrcatW(pattern, L"\\C-*.txt");
    find = FindFirstFileW(pattern, &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            char *data;
            DWORD len, error;
            MerlinQueueDirectory(path, MAX_PATH);
            if (lstrlenW(path) + lstrlenW(fd.cFileName) + 2 > MAX_PATH) continue;
            lstrcatW(path, L"\\");
            lstrcatW(path, fd.cFileName);
            data = mc_read_file(path, MERLIN_RECORD_MAX, &len, &error);
            if (!data) continue;
            if (merlin_problem_read(data, len, report, err, sizeof(err)) && report->id[0] == 'C') {
                MERLIN_PROBLEM *candidate = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
                if (candidate) {
                    MERLIN_PROBLEM *p;
                    CopyMemory(candidate, report, sizeof(*candidate));
                    merlin_problem_set_id(candidate);
                    p = problem_for(t, candidate);
                    if (p) {
                        unsigned long before = p->count;
                        merlin_problem_merge(p, report);
                        if (p->count != before) {
                            ++t->stats->crash_reports;
                            t->dirty[index_of(t, p)] = 1;
                        }
                    }
                    mc_free(candidate);
                }
            }
            mc_free(data);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }
    mc_free(report);
}

static void apply_retention(MERLIN_COLLECT_STATS *stats)
{
    MERLIN_CONFIG config;
    MERLIN_LIST list;
    unsigned long now = mc_now(), last;
    int i;
    MerlinGetConfig(&config);
    if (MerlinQueueList(&list)) return;
    for (i = 0; i < list.count; ++i) {
        MERLIN_PROBLEM *p = &list.items[i];
        if (p->job[0] || !lstrcmpA(p->status, "included") || !merlin_parse_time(p->last, &last)) continue;
        if (now > last && (now - last) / 86400UL > config.retention_days && !MerlinQueueRemove(p->id)) ++stats->removed;
    }
    MerlinFreeList(&list);
}

DWORD MERLINAPI MerlinCollect(MERLIN_COLLECT_STATS *stats)
{
    TOUCHED t;
    HANDLE lock;
    DWORD wait, error = 0;
    int i;
    ZeroMemory(stats, sizeof(*stats));
    if (!MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    lock = CreateMutexW(NULL, FALSE, L"Global\\XP25MerlinCollector");
    if (!lock) return GetLastError();
    wait = WaitForSingleObject(lock, 30000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        CloseHandle(lock);
        return ERROR_BUSY;
    }
    ZeroMemory(&t, sizeof(t));
    t.stats = stats;
    t.items = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM) * MAX_TOUCHED);
    if (!t.items) error = ERROR_NOT_ENOUGH_MEMORY;
    else {
        /* Crash reports first, so their own event 1000 records are not counted twice. */
        collect_crash_reports(&t);
        collect_log(&t, L"Application", 'A');
        collect_log(&t, L"System", 'S');
        collect_log(&t, L"Security", 'E');
        collect_winlogon(&t);
        for (i = 0; i < t.count; ++i)
            if (t.dirty[i] && MerlinQueueSave(&t.items[i])) ++stats->errors;
        mc_free(t.items);
        apply_retention(stats);
    }
    ReleaseMutex(lock);
    CloseHandle(lock);
    return error;
}
