/* MerlinClient.dll: the local problem queue.

   <All Users>\Application Data\XP25\MerlinAI\Queue holds
     P-<16 hex>.txt  aggregated problems (written by administrators' collection),
     C-<16 hex>.txt  crash reports written by MerlinCrash for the user who crashed,
     C-<16 hex>.dmp  their minidumps.
   The installer gives the directory a protected DACL: SYSTEM and
   Administrators full control, Users may only list it and add files, and
   CREATOR OWNER gets full control of the files a user adds. A standard user
   therefore sees and removes only their own reports. */
#include <windows.h>
#include "mc_internal.h"

void MERLINAPI MerlinNewReportId(char id[MERLIN_ID_SIZE])
{
    char rnd[17];
    unsigned long now = mc_now();
    unsigned char t[4];
    t[0] = (unsigned char)(now >> 24);
    t[1] = (unsigned char)(now >> 16);
    t[2] = (unsigned char)(now >> 8);
    t[3] = (unsigned char)now;
    mc_random_hex(rnd, 4);
    if (!rnd[0]) {
        DWORD tick = GetTickCount() ^ GetCurrentProcessId();
        unsigned char b[4];
        b[0] = (unsigned char)(tick >> 24);
        b[1] = (unsigned char)(tick >> 16);
        b[2] = (unsigned char)(tick >> 8);
        b[3] = (unsigned char)tick;
        merlin_append_hex(rnd, sizeof(rnd), b, 4);
    }
    merlin_copy(id, MERLIN_ID_SIZE, "C-");
    merlin_append_hex(id, MERLIN_ID_SIZE, t, 4);
    merlin_append(id, MERLIN_ID_SIZE, rnd);
}

static BOOL id_valid(const char *id)
{
    return merlin_token_valid(id, MERLIN_ID_SIZE - 1) && (id[0] == 'P' || id[0] == 'C') && id[1] == '-';
}

DWORD MERLINAPI MerlinQueueLoad(const char *id, MERLIN_PROBLEM *p)
{
    WCHAR path[MAX_PATH];
    char name[MERLIN_ID_SIZE + 8], err[96];
    char *data;
    DWORD len, error;
    if (!id_valid(id)) return ERROR_INVALID_PARAMETER;
    merlin_copy(name, sizeof(name), id);
    merlin_append(name, sizeof(name), ".txt");
    if (!mc_queue_path(name, path, MAX_PATH)) return ERROR_PATH_NOT_FOUND;
    data = mc_read_file(path, MERLIN_RECORD_MAX, &len, &error);
    if (!data) return error;
    error = merlin_problem_read(data, len, p, err, sizeof(err)) && !lstrcmpA(p->id, id) ? 0 : ERROR_INVALID_DATA;
    mc_free(data);
    return error;
}

DWORD MERLINAPI MerlinQueueSave(const MERLIN_PROBLEM *p)
{
    WCHAR path[MAX_PATH];
    char name[MERLIN_ID_SIZE + 8];
    char *text;
    size_t n;
    DWORD error;
    if (!id_valid(p->id)) return ERROR_INVALID_PARAMETER;
    if (p->id[0] == 'P' && !MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    text = (char *)mc_alloc(MERLIN_RECORD_MAX);
    if (!text) return ERROR_NOT_ENOUGH_MEMORY;
    n = merlin_problem_write(p, text, MERLIN_RECORD_MAX);
    merlin_copy(name, sizeof(name), p->id);
    merlin_append(name, sizeof(name), ".txt");
    if (!n) error = ERROR_INSUFFICIENT_BUFFER;
    else if (!mc_queue_path(name, path, MAX_PATH)) error = ERROR_PATH_NOT_FOUND;
    else error = mc_write_file_atomic(path, text, (DWORD)n);
    mc_free(text);
    return error;
}

static void delete_report_files(const char *crash_id)
{
    WCHAR path[MAX_PATH];
    char name[MERLIN_ID_SIZE + 8];
    if (!id_valid(crash_id) || crash_id[0] != 'C') return;
    merlin_copy(name, sizeof(name), crash_id);
    merlin_append(name, sizeof(name), ".txt");
    if (mc_queue_path(name, path, MAX_PATH)) DeleteFileW(path);
    merlin_copy(name, sizeof(name), crash_id);
    merlin_append(name, sizeof(name), ".dmp");
    if (mc_queue_path(name, path, MAX_PATH)) DeleteFileW(path);
}

DWORD MERLINAPI MerlinQueueRemove(const char *id)
{
    MERLIN_PROBLEM *p;
    WCHAR path[MAX_PATH];
    char name[MERLIN_ID_SIZE + 8];
    unsigned i;
    DWORD error;
    if (!id_valid(id)) return ERROR_INVALID_PARAMETER;
    if (id[0] == 'C') {
        merlin_copy(name, sizeof(name), id);
        merlin_append(name, sizeof(name), ".txt");
        if (!mc_queue_path(name, path, MAX_PATH)) return ERROR_PATH_NOT_FOUND;
        if (!DeleteFileW(path)) return GetLastError();
        delete_report_files(id);
        return 0;
    }
    if (!MerlinIsAdmin()) return ERROR_ACCESS_DENIED;
    p = (MERLIN_PROBLEM *)mc_alloc(sizeof(*p));
    if (!p) return ERROR_NOT_ENOUGH_MEMORY;
    error = MerlinQueueLoad(id, p);
    if (!error) {
        for (i = 0; i < p->occurrence_count; ++i)
            if (!memcmp(p->occurrences[i].ref, "crash:", 6))
                delete_report_files(p->occurrences[i].ref + 6);
        merlin_copy(name, sizeof(name), id);
        merlin_append(name, sizeof(name), ".txt");
        if (!mc_queue_path(name, path, MAX_PATH)) error = ERROR_PATH_NOT_FOUND;
        else if (!DeleteFileW(path)) error = GetLastError();
    }
    mc_free(p);
    return error;
}

static int newer_first(const MERLIN_PROBLEM *a, const MERLIN_PROBLEM *b)
{
    return lstrcmpA(a->last, b->last) > 0;
}

/* Is crash report id referenced by any aggregated problem in the list? */
static BOOL merged(const MERLIN_LIST *list, const char *crash_id)
{
    char ref[MERLIN_SHORT];
    int i;
    unsigned k;
    merlin_copy(ref, sizeof(ref), "crash:");
    merlin_append(ref, sizeof(ref), crash_id);
    for (i = 0; i < list->count; ++i)
        if (list->items[i].id[0] == 'P')
            for (k = 0; k < list->items[i].occurrence_count; ++k)
                if (!lstrcmpA(list->items[i].occurrences[k].ref, ref)) return TRUE;
    return FALSE;
}

DWORD MERLINAPI MerlinQueueList(MERLIN_LIST *list)
{
    WCHAR pattern[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE find;
    char err[96];
    int pass, i, j;
    list->items = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM) * MC_MAX_LIST);
    list->count = 0;
    if (!list->items) return ERROR_NOT_ENOUGH_MEMORY;
    if (!MerlinQueueDirectory(pattern, MAX_PATH)) return ERROR_PATH_NOT_FOUND;
    /* Pass 0 reads aggregated problems, pass 1 crash reports, so merged reports can be skipped. */
    for (pass = 0; pass < 2; ++pass) {
        if (!MerlinQueueDirectory(pattern, MAX_PATH)) break;
        lstrcatW(pattern, pass ? L"\\C-*.txt" : L"\\P-*.txt");
        find = FindFirstFileW(pattern, &fd);
        if (find == INVALID_HANDLE_VALUE) continue;
        do {
            char *data;
            DWORD len, error;
            MERLIN_PROBLEM *p;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY || list->count >= MC_MAX_LIST) continue;
            MerlinQueueDirectory(path, MAX_PATH);
            if (lstrlenW(path) + lstrlenW(fd.cFileName) + 2 > MAX_PATH) continue;
            lstrcatW(path, L"\\");
            lstrcatW(path, fd.cFileName);
            data = mc_read_file(path, MERLIN_RECORD_MAX, &len, &error);
            if (!data) continue;                          /* another user's report: access denied */
            p = &list->items[list->count];
            if (merlin_problem_read(data, len, p, err, sizeof(err)) && (pass ? p->id[0] == 'C' : p->id[0] == 'P')) {
                if (pass && merged(list, p->id)) {
                    mc_free(data);
                    continue;
                }
                /* A standard user's own unmerged reports of the same bucket are shown as one problem. */
                for (j = 0; pass && j < list->count; ++j)
                    if (list->items[j].id[0] == 'C' && !lstrcmpA(list->items[j].signature, p->signature)) break;
                if (pass && j < list->count) merlin_problem_merge(&list->items[j], p);
                else ++list->count;
            }
            mc_free(data);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }
    /* Insertion sort, newest first (the list is small). */
    for (i = 1; i < list->count; ++i) {
        MERLIN_PROBLEM *tmp = (MERLIN_PROBLEM *)mc_alloc(sizeof(MERLIN_PROBLEM));
        if (!tmp) break;
        CopyMemory(tmp, &list->items[i], sizeof(MERLIN_PROBLEM));
        for (j = i - 1; j >= 0 && newer_first(tmp, &list->items[j]); --j)
            CopyMemory(&list->items[j + 1], &list->items[j], sizeof(MERLIN_PROBLEM));
        CopyMemory(&list->items[j + 1], tmp, sizeof(MERLIN_PROBLEM));
        mc_free(tmp);
    }
    return 0;
}

void MERLINAPI MerlinFreeList(MERLIN_LIST *list)
{
    mc_free(list->items);
    list->items = NULL;
    list->count = 0;
}

static void line(char *out, DWORD size, const char *a, const char *b)
{
    merlin_append(out, size, a);
    merlin_append(out, size, b);
    merlin_append(out, size, "\r\n");
}

DWORD MERLINAPI MerlinReportText(const MERLIN_PROBLEM *p, char *out, DWORD size)
{
    char number[24];
    unsigned i;
    if (!size) return ERROR_INSUFFICIENT_BUFFER;
    out[0] = 0;
    line(out, size, "Problem: ", p->title);
    line(out, size, "Component: ", p->component);
    line(out, size, "Kind: ", p->kind);
    line(out, size, "Severity: ", p->severity);
    line(out, size, "Impact: ", p->impact);
    number[0] = 0;
    merlin_append_ulong(number, sizeof(number), p->count);
    merlin_append(out, size, "Occurrences: ");
    merlin_append(out, size, number);
    merlin_append(out, size, " (first ");
    merlin_append(out, size, p->first);
    merlin_append(out, size, ", last ");
    merlin_append(out, size, p->last);
    merlin_append(out, size, ")\r\n");
    if (p->app[0]) {
        merlin_append(out, size, "Application: ");
        merlin_append(out, size, p->app);
        line(out, size, " version ", p->app_version[0] ? p->app_version : "unknown");
    }
    if (p->module[0]) {
        merlin_append(out, size, "Faulting module: ");
        merlin_append(out, size, p->module);
        merlin_append(out, size, " version ");
        merlin_append(out, size, p->module_version[0] ? p->module_version : "unknown");
        line(out, size, " at offset 0x", p->offset);
    }
    if (p->code[0]) {
        unsigned long code = 0;
        const char *c;
        for (c = p->code; *c; ++c) code = code * 16 + (unsigned long)(*c <= '9' ? *c - '0' : (*c | 32) - 'a' + 10);
        merlin_append(out, size, "Exception: ");
        merlin_append(out, size, merlin_exception_name(code));
        line(out, size, " 0x", p->code);
    }
    line(out, size, "Status: ", p->status);
    line(out, size, "Submitted to MerlinAI: ", p->submitted ? "yes" : "no (discovered locally)");
    line(out, size, "Transfer to the builder allowed: ", p->transfer_consent ? "yes" : "no");
    if (p->dump[0])
        line(out, size, "Memory dump: ", p->dump_consent ? "allowed to leave this computer" : "kept on this computer");
    if (p->job[0]) line(out, size, "Build job: ", p->job);
    if (p->analysis[0]) line(out, size, "MerlinAI analysis: ", p->analysis);
    if (p->evidence_count) merlin_append(out, size, "Evidence:\r\n");
    for (i = 0; i < p->evidence_count; ++i) line(out, size, "  - ", p->evidence[i]);
    if (p->occurrence_count) merlin_append(out, size, "Recorded occurrences:\r\n");
    for (i = 0; i < p->occurrence_count; ++i) {
        merlin_append(out, size, "  - ");
        merlin_append(out, size, p->occurrences[i].time);
        line(out, size, " ", p->occurrences[i].ref);
    }
    MerlinRedact(out, size);
    return 0;
}
